"""
VCF Readiness Tool — BaseRedfishCollector (Layer A, core HTTP + OEM hooks).

This is the DMTF-standard Redfish HTTP layer plus a set of OEM hook methods
that subclasses (DellCollector, HPECollector, etc.) override to add
vendor-specific behaviour without touching the shared collection logic.

Collection methods live in the mixin files imported below; the final
UniversalRedfishCollector assembles everything via multiple inheritance.
"""
import atexit
import base64
import json
import logging
import socket
import ssl
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.error import HTTPError

from vcf_hci.tls_utils import (
    StdlibHTTPConnectionPool,
    build_pinned_opener,
    build_ssl_context,
    hosts_equal,
    parse_target_authority,
)

logger = logging.getLogger("vcf_assess")

from vcf_hci.logging_utils import get_nested, strip_url_userinfo
from vcf_hci.security.contract import empty_security_evidence

from .async_helpers import _safe_result, _timed
from .collect_bmc_security import _BmcSecurityMixin
from .collect_gpu import _GPUMixin
from .collect_logs import _LogsMixin
from .collect_network import _NetworkMixin
from .collect_power import _PowerMixin
from .collect_storage import _StorageMixin
from .collect_system import _SystemMixin
from .collect_telemetry import _TelemetryMixin
from .crawler import RedfishCrawler
from .discovery import DiscoveryMixin
from .http_session import (
    _BMC_INNER_WORKERS,
    RedfishSessionManager,
    _HttpGetMixin,
    _thread_local,
    clear_auth_lockout,
    compute_request_pacing,
    is_host_auth_locked,
    record_auth_lockout,
    redfish_get,
)
from .ops_collect import resolve_scan_profile
from .os_eval import _evaluate_os_info
from .pci_utils import pcie_has_fc_candidates, pcie_has_gpu_candidates

# ---------------------------------------------------------------------------
# §7  Universal Redfish Collector (Layer A)
# ---------------------------------------------------------------------------


class ExpandableCollectionsMap(dict):
    """Dictionary of collection names to endpoints supporting membership checks by URI and expansion levels."""

    def __init__(
        self,
        mapping: Optional[Dict[str, str]] = None,
        levels: Optional[Dict[str, int]] = None,
        **kwargs: Any,
    ):
        base_dict = dict(mapping or {})
        base_dict.update(kwargs)
        super().__init__(base_dict)
        self._levels: Dict[str, int] = dict(levels or {})

    def __contains__(self, item: Any) -> bool:
        return super().__contains__(item) or item in self.values()

    def get_levels(self, endpoint_or_key: str, default: int = 1) -> int:
        """Return the supported expansion level for a key or endpoint."""
        if endpoint_or_key in self._levels:
            return self._levels[endpoint_or_key]
        for k, v in self.items():
            if (k == endpoint_or_key or v == endpoint_or_key) and (k in self._levels or v in self._levels):
                return self._levels.get(k, self._levels.get(v, default))
        return default


class BaseRedfishCollector(
    _HttpGetMixin,
    DiscoveryMixin,
    _SystemMixin,
    _BmcSecurityMixin,
    _StorageMixin,
    _NetworkMixin,
    _PowerMixin,
    _TelemetryMixin,
    _GPUMixin,
    _LogsMixin,
):
    """DMTF-standard Redfish collector and OEM Extension Base Class.

    Assembles domain mixin classes (_SystemMixin, _BmcSecurityMixin, _StorageMixin,
    _NetworkMixin, _PowerMixin, _TelemetryMixin, _GPUMixin, _LogsMixin) into a unified collector.

    To add support for a new server OEM vendor, subclass ``GenericCollector``
    (in ``vcf_hci/collector/oem/<vendor>.py``) and override only the ``oem_*``
    hook methods that differ from standard DMTF Redfish specifications.
    """

    vendor: str = "generic"

    # ── OEM hook defaults (pure DMTF, override in subclasses) ───────────────

    def oem_bios_date(self, sys_data: dict) -> str:
        """Extract vendor-specific BIOS release date string from system JSON.

        Args:
            sys_data: Raw JSON dictionary from the Redfish ComputerSystem resource.

        Returns:
            Formatted release date string (e.g. "2024-05-15") or "N/A" default.
        """
        return "N/A"

    def oem_extract_bios_attributes(self, bios_data: dict) -> dict:
        """Extract raw BIOS attributes dictionary from vendor-specific locations.

        Args:
            bios_data: Raw JSON dictionary from the Redfish Bios resource.

        Returns:
            Raw attributes dictionary or empty dict if not found.
        """
        if not isinstance(bios_data, dict):
            return {}
        attrs = bios_data.get("Attributes")
        if isinstance(attrs, dict) and attrs:
            return attrs
        # Legacy flat BIOS attributes (e.g. HPE iLO 4 / Gen9 top-level attributes)
        flat = {
            k: v for k, v in bios_data.items()
            if not k.startswith("@") and k not in (
                "Id", "Name", "Description", "Type", "Actions", "Links", "links", "Oem", "Status", "Members", "attribute_count"
            ) and isinstance(v, (str, int, float, bool))
        }
        return flat

    def oem_normalize_bios_attributes(self, raw_attrs: dict) -> dict:
        """Normalize vendor-specific BIOS attribute names across hardware generations.

        Args:
            raw_attrs: Raw vendor BIOS attributes dictionary.

        Returns:
            Normalized dictionary containing standard canonical keys.
        """
        return {}

    def oem_storage_endpoints(self) -> list:
        """Return extra non-standard storage URIs to scan for controllers and drives.

        Returns:
            List of endpoint URI strings (e.g. HPE SmartStorage URIs).
            Default: []
        """
        return []

    def oem_storage_fallback(self) -> list:
        """OEM hook called when standard Redfish storage collections return empty.

        Subclasses (e.g. CiscoCollector) can query vendor XML APIs (/nuova) or
        alternate proprietary endpoints to construct storage controller and drive structures.

        Returns:
            List of normalized storage controller dictionaries, or empty list.
        """
        return []

    def oem_drive_endurance(self, drive_json: dict) -> Optional[float]:
        """Extract remaining write endurance percentage (0.0 to 100.0) from OEM fields.

        Args:
            drive_json: Raw JSON dictionary from a Redfish Drive resource.

        Returns:
            Percentage float (e.g. 98.5) if reported by vendor OEM extension, else None.
        """
        return None

    def oem_nic_firmware(self, adapter_json: dict) -> str:
        """Extract NIC firmware version string from standard or OEM extension fields.

        Args:
            adapter_json: Raw JSON dictionary from a NetworkAdapter resource.

        Returns:
            Firmware version string or "N/A".
        """
        if not isinstance(adapter_json, dict):
            return "N/A"
        dell_oem = (adapter_json.get("Oem") or {}).get("Dell") or {}
        dell_fw = (dell_oem.get("DellNIC") or {}).get("FirmwareVersion") or (dell_oem.get("DellFC") or {}).get("FirmwareVersion")
        hpe_oem = (adapter_json.get("Oem") or {}).get("Hpe") or {}
        hpe_fw = hpe_oem.get("FirmwareVersion") or get_nested(hpe_oem, "AdapterDetails", "FirmwareVersion")
        ctrl_fw = None
        controllers = adapter_json.get("Controllers")
        if isinstance(controllers, list):
            for c in controllers:
                if isinstance(c, dict):
                    ctrl_fw = (
                        c.get("FirmwarePackageVersion")
                        or c.get("FirmwareVersion")
                        or get_nested(c, "Firmware", "Current", "VersionString")
                    )
                    if ctrl_fw:
                        break
        return str(
            adapter_json.get("FirmwarePackageVersion")
            or adapter_json.get("FirmwareVersion")
            or get_nested(adapter_json, "Firmware", "Current", "VersionString")
            or ctrl_fw
            or dell_fw
            or hpe_fw
            or "N/A"
        ).strip() or "N/A"

    def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict:
        """Extract BMC license name, tier badge, and vendor notes.

        Args:
            mgr_data: Raw JSON dictionary from the Redfish Manager resource.
            sys_data: Raw JSON dictionary from the Redfish ComputerSystem resource.

        Returns:
            Dictionary containing 'license_name', 'badge', and 'vendor_note'.
        """
        return {"license_name": "N/A", "badge": "", "vendor_note": ""}

    def oem_handle_retry(self, data: dict, endpoint: str) -> bool:
        """Determine if a transient Redfish response requires a retry delay.

        Args:
            data: Raw JSON dictionary returned from a Redfish GET call.
            endpoint: Target Redfish URI string.

        Returns:
            True if the collection loop should pause (3s) and retry, else False.
        """
        return False

    def oem_os_info(self, sys_data: dict) -> dict:
        """Extract vendor-specific OS metadata or uptime from manager/system attributes.

        Args:
            sys_data: Raw JSON dictionary from the Redfish ComputerSystem resource.

        Returns:
            Dictionary with optional keys: name, version, description, source,
            powered_on_seconds, uptime_days, uptime_human.
        """
        return {}

    def oem_cpu_cache(self, proc_json: dict) -> list:
        """Extract L1/L2/L3 CPU cache hierarchy details from processor JSON.

        Args:
            proc_json: Raw JSON dictionary from a Processor resource.

        Returns:
            List of cache dictionaries (e.g. [{'level': 'L3', 'size_kb': 32768}]).
        """
        return []

    def oem_manager_paths(self) -> list:
        """Return non-standard Manager resource URIs (e.g. Cisco `/Managers/CIMC`).

        Returns:
            List of non-standard Manager URI strings to probe during root discovery.
        """
        return []

    def oem_sku(self, sys_data: dict) -> str:
        """Extract server model SKU / part number string.

        Args:
            sys_data: Raw JSON dictionary from the Redfish ComputerSystem resource.

        Returns:
            Part number / SKU string.
        """
        return str(
            sys_data.get("SKU")
            or ((sys_data.get("Oem") or {}).get("Hpe") or {}).get("ProductId")
            or ""
        )

    def oem_memory_usage(self, sys_data: dict) -> dict:
        """Extract vendor-specific memory bus utilization telemetry.

        Args:
            sys_data: Raw JSON dictionary from the Redfish ComputerSystem resource.

        Returns:
            Memory utilization telemetry dict containing metrics like 'MemoryBusUtilization'.
        """
        return {}

    def oem_drive_metrics(self, drive_json: dict) -> dict:
        """Extract vendor-specific NVMe/SSD drive telemetry and SMART attributes.

        Args:
            drive_json: Raw JSON dictionary from a Redfish Drive resource.

        Returns:
            Dictionary of drive telemetry metrics (e.g., power_on_hours, temperature_c).
        """
        return {}

    def oem_port_transceiver(self, port_json: dict) -> Dict[str, Any]:
        """Extract vendor-specific network transceiver metadata (SFP28, DAC, optics) & DDM telemetry.

        Args:
            port_json: Raw JSON dictionary from a Redfish NetworkPort or Port resource.

        Returns:
            Dictionary with keys: identifier_type, interface_type, vendor_name, part_number, serial_number,
            rx_power_dbm, tx_power_dbm, temperature_c, laser_bias_current_ma, voltage_v.
        """
        return {}

    def oem_pcie_link_status(self, dev_dict: dict) -> Optional[Dict[str, Any]]:
        """Extract vendor-specific PCIe link width and speed telemetry.

        Args:
            dev_dict: Raw JSON dictionary from a Redfish PCIeDevice or NetworkAdapter resource.

        Returns:
            Dictionary with keys current_pcie_type, max_pcie_type, current_pcie_width, max_pcie_width,
            or None if standard DMTF properties should be used.
        """
        return None

    def oem_vnic_capabilities(self, ndf_json: dict) -> Dict[str, Any]:
        """Extract vendor-specific virtual NIC / virtual HBA configuration capabilities.

        Args:
            ndf_json: Raw JSON dictionary from a Redfish NetworkDeviceFunction resource.

        Returns:
            Dictionary with keys: cdn, uplink_port, pci_order, cos, vlan_mode, geneve_offload,
            vxlan_offload, rocev2, multiqueue, tso_enabled, lro_enabled, rx_csum, tx_csum,
            rss_enabled, vhba_type, max_data_field_size, fc_work_queue_ring_size, fc_recv_queue_ring_size.
        """
        return {}

    def oem_gpu_sensors(self) -> List[Dict[str, Any]]:
        """Extract vendor-specific GPU sensors (thermal, power brake, slot).

        Returns:
            List of dictionaries with keys: device_id, slot, slot_number, primary_temp_c,
            max_operating_temp_c, slowdown_temp_c, shutdown_temp_c, power_brake_status, thermal_alert_status.
        """
        return []

    def oem_security_evidence(self) -> Dict[str, Any]:
        """Extract vendor-specific security evidence (DellAttributes, HPE SecurityService, etc.).

        Returns:
            Dictionary of OEM-specific security evidence or empty dict if not supported or not collected.
            Subclasses override this to collect OEM attributes without evaluation verdicts.
        """
        return {}

    def oem_fastpath_roots(self) -> Optional[Tuple[list, list, list]]:
        """Optional hook for vendor-specific root URI shortcuts (sys_uris, chassis_uris, mgr_uris).
        Return (sys_uris, chassis_uris, mgr_uris) or None to perform standard OData collection enumeration.
        """
        return None

    def oem_psu_capacity(self, psu_json: dict) -> Optional[int]:
        """OEM hook: derive PSU wattage capacity (Watts) from vendor-specific part numbers or OEM fields.
        Returns None by default (falls back to DMTF PowerCapacityWatts/LastPowerOutputWatts).
        """
        return None

    def oem_job_queue(self, now_dt: Optional[datetime] = None) -> Dict[str, Any]:
        """OEM hook: collect and audit Lifecycle Controller / BMC job queue status.

        Subclasses (e.g. DellCollector) override this to inspect vendor-specific
        job queues for failed, stale, or pending-reboot lifecycle tasks.
        Returns empty dictionary by default.
        """
        return {}

    def collect_job_queue(self, now_dt: Optional[datetime] = None) -> Dict[str, Any]:
        """Collect and audit Lifecycle Controller / BMC job queue status."""
        try:
            return self.oem_job_queue(now_dt=now_dt) or {}
        except Exception as exc:
            logger.debug("[%s] oem_job_queue failed: %s", self.host, exc)
            return {}

    def oem_expandable_collections(self) -> Dict[str, str]:
        """OEM hook: map of collection paths known to support OData $expand query optimization.

        Subclasses (e.g. DellCollector) override this to return endpoints known to support
        $expand=*($levels=1) or $expand=.($levels=1).
        """
        return {}

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        ssl_context: Optional[ssl.SSLContext] = None,
        verify_ssl: bool = False,
        ca_bundle: Optional[str] = None,
        server_hostname: Optional[str] = None,
        scheme: str = "https",
        port: Optional[int] = None,
        pinned_thumbprints: Optional[Dict[str, str]] = None,
        tls_min_version: Optional[str] = None,
        legacy_ciphers: bool = False,
    ):
        raw_host = str(host or "").strip()
        if raw_host.startswith("http://"):
            scheme = "http"
            raw_host = raw_host[7:]
        elif raw_host.startswith("https://"):
            scheme = "https"
            raw_host = raw_host[8:]
        clean_host = strip_url_userinfo(raw_host.rstrip("/"))

        _dial_scheme, dial_host, embedded_port = parse_target_authority(
            clean_host, default_scheme=scheme
        )
        if port is None:
            port = embedded_port
        self.host = dial_host or clean_host
        self.scheme = scheme
        self.port = port or (443 if scheme == "https" else 80)
        url_host = f"[{self.host}]" if ":" in self.host else self.host
        if (self.scheme == "https" and self.port != 443) or (self.scheme == "http" and self.port != 80):
            port_suffix = f":{self.port}"
        else:
            port_suffix = ""
        self.host_url = f"{self.scheme}://{url_host}{port_suffix}"
        self.base_url = f"{self.host_url}/redfish/v1"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.ca_bundle = ca_bundle
        self.server_hostname = server_hostname
        self.tls_min_version = tls_min_version
        self.legacy_ciphers = bool(legacy_ciphers)
        self.ssl_context = ssl_context or build_ssl_context(
            verify_ssl=verify_ssl,
            ca_bundle=ca_bundle,
            tls_min_version=tls_min_version,
            legacy_ciphers=legacy_ciphers,
        )
        self.pinned_thumbprints = pinned_thumbprints or {}
        self._opener = build_pinned_opener(ssl_context=self.ssl_context, pinned_thumbprints=self.pinned_thumbprints) if self.pinned_thumbprints else None
        self._max_inner_workers: int = _BMC_INNER_WORKERS
        self._base_max_inner_workers: int = _BMC_INNER_WORKERS
        self._initial_get_latency_ms: Optional[float] = None
        self.silicon_generation: str = ""
        self._conn_pool = StdlibHTTPConnectionPool(
            host=self.host,
            port=self.port,
            scheme=self.scheme,
            ssl_context=self.ssl_context,
            pinned_thumbprints=self.pinned_thumbprints,
            max_connections=self._max_inner_workers,
            server_hostname=self.server_hostname,
        )
        self.ssl_error = None
        self.sys_uri: Optional[str] = None
        self.chassis_uri: Optional[str] = None
        self.mgr_uri: Optional[str] = None
        self.sys_uris = []
        self.chassis_uris = []
        self.mgr_uris = []
        self.chassis_management_info = {}
        self.sys_sku   = ""   # populated by collect_system_summary; used by collect_storage_subsystem
        self.sys_model = ""   # normalized model string; used for DELL_MODEL_CHASSIS_DB lookup
        self._auth_header = base64.b64encode(
            f"{username}:{password}".encode()
        ).decode()
        self._cache_lock = threading.RLock()
        self._inner_cv = threading.Condition(self._cache_lock)
        self._active_inner_workers = 0
        self._throttled = False
        self._request_cache = {}
        self._preserve_all_raw = False
        self._crawler = None
        self.multiple_http_requests: bool = False
        self._request_pacing_s: float = 0.0 if self.multiple_http_requests else 0.05
        self._last_req_finish_time: float = 0.0
        self._last_http_status: Optional[int] = None
        self._negative_endpoints = set()
        self._negative_endpoint_counts: Dict[str, int] = {}
        self._consecutive_timeouts = 0
        self._consecutive_successes = 0
        self.auth_failed = False
        self.expand_supported = False
        self.expand_syntax: Optional[str] = None
        self.expand_max_levels: int = 1
        self._unsupported_expand_endpoints: Set[str] = set()
        self.skip_host_set = None
        self.cancel_event = None
        self.skipped = False
        self.timed_out = False
        if socket.getdefaulttimeout() is None:
            socket.setdefaulttimeout(15.0)
        self.host_timeout = 300  # Default 5-minute max runtime limit per host (0 to disable)
        self.scan_start_time = None
        self.stage_callback = None
        self._request_count = 0
        self._total_timeouts_encountered = 0
        self._throttle_engaged_count = 0
        self._phase1_duration_s = 0.0
        self._phase2_duration_s = 0.0
        self._last_active_time = time.time()
        self._current_stage = "Connecting & Starting Scan..."
        self._last_stage_broadcast_time = 0.0
        self._last_broadcast_stage = ""
        self.session_uri = ""
        self.session_token = ""
        self.metadata = {}
        self.active_sessions_count: Optional[int] = None
        self.bmc_session_warning: Optional[str] = None
        self.session_warning: Optional[str] = None
        self._phase1_expired = False
        self._phase2_expired = False
        self._assessment_complete = False
        self._failed_sections = []
        self._timed_out_sections = []
        self._telemetry_service_supported = None
        self._closed = False
        atexit.register(self.close)

    def _is_cancelled_or_skipped(self) -> bool:
        """Centralized check for cancellation, user skip, runtime timeout, or unresponsive BMC."""
        if getattr(self, "cancel_event", None) is not None and self.cancel_event.is_set():
            if not getattr(self, "skipped", False):
                self.skipped = True
            return True

        if getattr(self, "skip_host_set", None) is not None and self.host in self.skip_host_set:
            if not getattr(self, "skipped", False):
                self.skipped = True
                logger.info("[%s] Host scan skipped by user request", self.host)
            return True

        if getattr(self, "skipped", False):
            return True

        if getattr(self, "host_timeout", 0) > 0 and self.scan_start_time is not None:
            if (time.time() - self.scan_start_time) > self.host_timeout:
                if not getattr(self, "skipped", False):
                    self.skipped = True
                    self.timed_out = True
                    logger.warning(
                        "[%s] Host scan exceeded max total runtime limit (%ds / %.1fm) — skipping remaining endpoints.",
                        self.host, self.host_timeout, self.host_timeout / 60
                    )
                return True

        with self._cache_lock:
            consec = getattr(self, "_consecutive_timeouts", 0)
            if consec >= 4:
                if not getattr(self, "skipped", False):
                    self.skipped = True
                    self.timed_out = True
                    logger.warning(
                        "[%s] BMC unresponsive (%d consecutive timeouts) — skipping remaining endpoints.",
                        self.host, consec
                    )
                return True

        return False

    def _get_phase_worker_count(self, default_workers: int = 3) -> int:
        """Cap nested worker pools at 1 when already running inside a phase worker to prevent BMC overload."""
        if getattr(_thread_local, "is_phase1", False) or getattr(_thread_local, "is_phase2", False):
            return 1
        return default_workers

    def _wrap_phase_task(self, fn):
        """Wrap a callable to inherit the calling thread's phase context in sub-pools."""
        is_p1 = getattr(_thread_local, "is_phase1", False)
        is_p2 = getattr(_thread_local, "is_phase2", False)
        if not is_p1 and not is_p2:
            return fn
        def _wrapped(*args, **kwargs):
            if is_p1:
                _thread_local.is_phase1 = True
            if is_p2:
                _thread_local.is_phase2 = True
            try:
                return fn(*args, **kwargs)
            finally:
                if is_p1:
                    _thread_local.is_phase1 = False
                if is_p2:
                    _thread_local.is_phase2 = False
        return _wrapped

    def _is_safe_session_redirect(self, redirect_url: str) -> bool:
        """Validate redirect URL is safe, targeting the same host and Redfish Sessions path."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(redirect_url)
            if not parsed.netloc:
                # Relative URL, e.g. /redfish/v1/SessionService/Sessions/
                return redirect_url.startswith("/redfish/") and "Sessions" in redirect_url
            _scheme, dial_host, _embedded_port = parse_target_authority(
                self.host, default_scheme=self.scheme
            )
            if parsed.port is not None and parsed.port != self.port:
                return False
            return (
                parsed.scheme in ("https", self.scheme)
                and hosts_equal(parsed.hostname or "", dial_host)
                and parsed.path.startswith("/redfish/")
                and "Sessions" in parsed.path
            )
        except Exception:
            return False

    def _accepted_session_uri(self, location: str) -> str:
        """Return a session URI on this BMC, or "" when Location leaves the target."""
        loc = str(location or "").strip()
        if not loc:
            return ""
        lower = loc.lower()
        if lower.startswith("http://") or lower.startswith("https://"):
            if not self._is_safe_session_redirect(loc):
                logger.debug("Refusing off-target Redfish session Location")
                return ""
            return loc
        if loc.startswith("/") and "://" not in loc:
            return f"{self.host_url}{loc}"
        return ""

    def _close_session(self) -> None:
        """Safely send DELETE to terminate active Redfish session and clear token."""
        if self.session_uri and self.session_token:
            try:
                mgr = RedfishSessionManager(
                    self.host,
                    self.session_uri,
                    self.session_token,
                    self.ssl_context,
                    pinned_thumbprints=getattr(self, "pinned_thumbprints", None),
                )
                mgr.close()
            except Exception as e:
                logger.debug(f"Redfish session close error: {e}")
            finally:
                self.session_uri = ""
                self.session_token = ""

    def create_session(self) -> Optional[dict]:
        """Create a Redfish session via POST /redfish/v1/SessionService/Sessions (with legacy fallback)."""
        if self.session_uri and self.session_token:
            self._close_session()

        url = f"{self.base_url}/SessionService/Sessions"
        url_fallback = f"{self.base_url}/Sessions"
        payload = json.dumps({"UserName": self.username, "Password": self.password})
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            is_mocked = not hasattr(urllib.request.urlopen, "__code__") or "Mock" in type(urllib.request.urlopen).__name__ or hasattr(urllib.request.urlopen, "mock")
            if not is_mocked and hasattr(self, "_conn_pool") and self._conn_pool is not None:
                status, resp_headers, raw_bytes = self._conn_pool.request(
                    "POST", url, headers=headers, body=payload, timeout=10
                )
                if status == 404:
                    logger.debug(f"POST {url} returned 404; probing legacy fallback {url_fallback}")
                    status, resp_headers, raw_bytes = self._conn_pool.request(
                        "POST", url_fallback, headers=headers, body=payload, timeout=10
                    )
                if status in (301, 302, 307, 308):
                    redir = resp_headers.get("Location") or resp_headers.get("location") or ""
                    if redir and self._is_safe_session_redirect(redir):
                        redir_url = redir if redir.startswith("http") else f"{self.host_url}{redir}"
                        logger.debug(f"Following session creation redirect (HTTP {status}) -> {redir_url}")
                        status, resp_headers, raw_bytes = self._conn_pool.request(
                            "POST", redir_url, headers=headers, body=payload, timeout=10
                        )
                token = resp_headers.get("X-Auth-Token") or resp_headers.get("x-auth-token")
                location = resp_headers.get("Location") or resp_headers.get("location") or ""
                if token:
                    self.session_token = token
                    self.session_uri = self._accepted_session_uri(location)
                    logger.debug(f"Created Redfish session {self.session_uri}")
                    return {"session_token": self.session_token, "session_uri": self.session_uri}
                logger.debug(f"Could not create Redfish session: HTTP {status} (falling back to Basic Auth)")
            else:
                def _do_post(endpoint_url: str):
                    req = urllib.request.Request(endpoint_url, data=payload.encode("utf-8"), method="POST", headers=headers)
                    try:
                        return self._opener.open(req, timeout=10) if self._opener is not None else urllib.request.urlopen(req, timeout=10, context=self.ssl_context)
                    except HTTPError as e:
                        if e.code in (301, 302, 307, 308):
                            redir = e.headers.get("Location") or e.headers.get("location") or ""
                            if redir and self._is_safe_session_redirect(redir):
                                redir_url = redir if redir.startswith("http") else f"{self.host_url}{redir}"
                                logger.debug(f"Following session creation redirect (HTTP {e.code}) -> {redir_url}")
                                req_r = urllib.request.Request(redir_url, data=payload.encode("utf-8"), method="POST", headers=headers)
                                return self._opener.open(req_r, timeout=10) if self._opener is not None else urllib.request.urlopen(req_r, timeout=10, context=self.ssl_context)
                        raise

                try:
                    resp_cm = _do_post(url)
                except HTTPError as e:
                    if e.code == 404:
                        logger.debug(f"POST {url} returned 404; probing legacy fallback {url_fallback}")
                        resp_cm = _do_post(url_fallback)
                    else:
                        raise

                with resp_cm as r:
                    headers_dict = getattr(r, "headers", None) or {}
                    token = headers_dict.get("X-Auth-Token") or headers_dict.get("x-auth-token") if hasattr(headers_dict, "get") else getattr(r, "getheader", lambda k: None)("X-Auth-Token")
                    location = headers_dict.get("Location") or headers_dict.get("location") or "" if hasattr(headers_dict, "get") else (getattr(r, "getheader", lambda k: "")("Location") or "")
                    if token:
                        self.session_token = token
                        self.session_uri = self._accepted_session_uri(location)
                        logger.debug(f"Created Redfish session {self.session_uri}")
                        return {"session_token": self.session_token, "session_uri": self.session_uri}
        except HTTPError as e:
            logger.debug(f"Could not create Redfish session: HTTP {e.code} (falling back to Basic Auth)")
        except Exception as e:
            logger.debug(f"Could not create Redfish session: {e} (falling back to Basic Auth)")
        return None

    def audit_active_sessions(self) -> Optional[int]:
        """Audit active BMC Redfish sessions and check against capacity threshold (>12).

        Queries GET /redfish/v1/SessionService/Sessions (or fallback /redfish/v1/Sessions).
        If active sessions > 12 (or > 75% of known 16-session ceiling), records a BMC session warning in collector metadata:
        "BMC Active Sessions High: [N] active sessions detected. Leaked sessions may cause intermittent HTTP 503 lockouts."

        Returns:
            Count of active sessions, or None if query failed.
        """
        resp = self._get("/redfish/v1/SessionService/Sessions")
        if not resp or not isinstance(resp, dict):
            resp = self._get("/redfish/v1/Sessions")
        if not resp or not isinstance(resp, dict):
            return None

        count = resp.get("Members@odata.count")
        if count is None:
            members = resp.get("Members")
            if isinstance(members, list):
                count = len(members)

        if count is None:
            return None

        try:
            active_count = int(count)
        except (ValueError, TypeError):
            return None

        self.active_sessions_count = active_count
        self.metadata["active_sessions_count"] = active_count

        if active_count > 12:
            warning_msg = (
                f"BMC Active Sessions High: {active_count} active sessions detected. "
                f"Leaked sessions may cause intermittent HTTP 503 lockouts."
            )
            self.bmc_session_warning = warning_msg
            self.session_warning = warning_msg
            self.metadata["bmc_session_warning"] = warning_msg
            self.metadata["session_warning"] = warning_msg
            self.metadata.setdefault("warnings", []).append(warning_msg)
            logger.warning("[%s] %s", self.host, warning_msg)

        return active_count

    _audit_bmc_active_sessions = audit_active_sessions

    def close(self):
        """Cleanly terminate active Redfish session and close connection pool."""
        if getattr(self, "_closed", False):
            return
        self._closed = True
        self._assessment_complete = True
        try:
            atexit.unregister(self.close)
        except Exception:
            pass
        with self._inner_cv:
            self._throttled = False
            self._inner_cv.notify_all()
        self._close_session()
        if hasattr(self, "_conn_pool") and self._conn_pool is not None:
            try:
                self._conn_pool.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_effective_pacing(self) -> float:
        """Return the effective inter-request pacing delay in seconds."""
        return compute_request_pacing(self)

    def _handle_429_or_503(self, status_code: int = 429, demote_to: int = 1) -> None:
        """Circuit breaker handler for HTTP 429 / 503: demotes workers to 1-2, engages throttle, escalates pacing."""
        with self._inner_cv:
            throttled = getattr(self, "_throttled", False)
            self._last_http_status = None
            target_workers = max(1, demote_to)
            self._max_inner_workers = target_workers
            if getattr(self, "_conn_pool", None) is not None:
                self._conn_pool.max_connections = self._max_inner_workers
            if not throttled:
                self._throttled = True
                self._throttle_engaged_count = getattr(self, "_throttle_engaged_count", 0) + 1
                self._consecutive_successes = 0
                current_pacing = getattr(self, "_request_pacing_s", 0.05)
                self._request_pacing_s = max(current_pacing, 0.10)
                logger.warning(
                    "[%s] BMC congestion detected (HTTP %s) — "
                    "stepping down concurrency from %d to %d worker(s), pacing set to %.2fs.",
                    self.host, status_code, getattr(self, "_base_max_inner_workers", _BMC_INNER_WORKERS),
                    self._max_inner_workers, self._request_pacing_s
                )
            else:
                current_pacing = getattr(self, "_request_pacing_s", 0.10)
                self._request_pacing_s = min(current_pacing * 2.0, 2.0)
                logger.warning(
                    "[%s] Continued BMC congestion (HTTP %s) — escalating request pacing to %.2fs.",
                    self.host, status_code, self._request_pacing_s
                )

    def _handle_timeout(self, timeouts: Optional[int] = None, demote_to: int = 1) -> None:
        """Circuit breaker handler for repeated timeouts: demotes workers to 1-2, engages throttle, sets pacing."""
        with self._inner_cv:
            t_count = timeouts if timeouts is not None else getattr(self, "_consecutive_timeouts", 0)
            throttled = getattr(self, "_throttled", False)
            target_workers = max(1, demote_to)
            self._max_inner_workers = target_workers
            if getattr(self, "_conn_pool", None) is not None:
                self._conn_pool.max_connections = self._max_inner_workers
            if not throttled:
                self._throttled = True
                self._throttle_engaged_count = getattr(self, "_throttle_engaged_count", 0) + 1
                self._consecutive_successes = 0
                current_pacing = getattr(self, "_request_pacing_s", 0.05)
                self._request_pacing_s = max(current_pacing, 0.10)
                logger.info(
                    "[%s] BMC latency/timeout detected (%d consecutive timeouts) — "
                    "stepping down concurrency from %d to %d worker(s), pacing set to %.2fs.",
                    self.host, t_count, getattr(self, "_base_max_inner_workers", _BMC_INNER_WORKERS),
                    self._max_inner_workers, self._request_pacing_s
                )

    def _check_adaptive_throttle(self, status_code: Optional[int] = None) -> None:
        """Check if adaptive throttling should step down (on timeouts/congestion) or step back up (on recovery)."""
        with self._inner_cv:
            timeouts = getattr(self, "_consecutive_timeouts", 0)
            successes = getattr(self, "_consecutive_successes", 0)
            throttled = getattr(self, "_throttled", False)

            code = status_code if status_code is not None else getattr(self, "_last_http_status", None)

            # Congestion signals (HTTP 429 / 503): immediate step-down and exponential backoff
            if code in (429, 503):
                self._handle_429_or_503(code)
            elif timeouts >= 2 and not throttled:
                self._handle_timeout(timeouts)
            elif throttled and successes >= 4:
                self._throttled = False
                self._consecutive_timeouts = 0
                self._consecutive_successes = 0
                self._last_http_status = None
                restored_workers = getattr(self, "_base_max_inner_workers", _BMC_INNER_WORKERS)
                self._max_inner_workers = restored_workers
                if getattr(self, "_conn_pool", None) is not None:
                    self._conn_pool.max_connections = self._max_inner_workers
                if getattr(self, "multiple_http_requests", False):
                    self._request_pacing_s = 0.0
                else:
                    self._request_pacing_s = 0.05
                logger.info(
                    "[%s] BMC recovered (%d consecutive successful GETs) — "
                    "stepping up concurrency back to %d workers, pacing restored to %.2fs.",
                    self.host, successes, restored_workers, self._request_pacing_s
                )
                self._inner_cv.notify_all()

    def _get(self, endpoint: str, _retry: bool = True, timeout: int = 15, critical: bool = True) -> Optional[dict]:
        return redfish_get(self, endpoint, _retry=_retry, timeout=timeout, critical=critical)

    def _populate_request_cache(self, uri: str, data: dict) -> None:
        """Pre-populate self._request_cache with pre-expanded Redfish resources."""
        if not uri or not isinstance(data, dict):
            return
        keys = []
        if uri.startswith("http"):
            keys.append(uri)
        else:
            host = getattr(self, "host", "")
            host_url = getattr(self, "host_url", "")
            base_url = getattr(self, "base_url", "")
            if uri.startswith("/redfish/v1"):
                if host_url:
                    keys.append(f"{host_url}{uri}")
                if host:
                    keys.append(f"https://{host}{uri}")
            else:
                if base_url:
                    keys.append(f"{base_url}/{uri.lstrip('/')}")
                if host:
                    keys.append(f"https://{host}/redfish/v1/{uri.lstrip('/')}")
            keys.append(uri)

        cache_lock = getattr(self, "_cache_lock", None)
        if hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
            if cache_lock:
                with cache_lock:
                    for k in keys:
                        self._request_cache[k] = data
            else:
                for k in keys:
                    self._request_cache[k] = data

    def _fetch_expanded_collection(self, endpoint: str, levels: int = 1) -> Optional[dict]:
        """Safely fetch a Redfish collection with OData $expand query optimization.

        Populates self._request_cache with every expanded member resource keyed by @odata.id,
        eliminating subsequent individual HTTP GET round-trips.

        Falls back seamlessly to an unexpanded GET if $expand is unsupported, rejected by the BMC
        (e.g. 400 Bad Request, 404, 406 Not Acceptable, 501 Not Implemented), or if the payload is invalid.
        """
        if not endpoint:
            return None

        # Check cache before doing any network operations
        if hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
            cached = self._request_cache.get(endpoint)
            if isinstance(cached, dict) and not cached.get("error") and (cached.get("Members") is not None or len(cached) > 1):
                return cached

        unsupported_endpoints = getattr(self, "_unsupported_expand_endpoints", None)
        if unsupported_endpoints is None:
            self._unsupported_expand_endpoints = set()
            unsupported_endpoints = self._unsupported_expand_endpoints

        if not getattr(self, "expand_supported", False) or endpoint in unsupported_endpoints:
            return self._get(endpoint)

        sep = "&" if "?" in endpoint else "?"
        syntax = getattr(self, "expand_syntax", None) or "*"
        alt_syntax = "." if syntax == "*" else "*"

        max_levels = getattr(self, "expand_max_levels", None)
        effective_levels = min(levels, max_levels) if isinstance(max_levels, int) and max_levels > 0 else levels

        expand_ep = f"{endpoint}{sep}$expand={syntax}($levels={effective_levels})"
        if hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
            cached_exp = self._request_cache.get(expand_ep)
            if isinstance(cached_exp, dict) and not cached_exp.get("error"):
                return cached_exp

        coll = self._get(expand_ep, critical=False)
        if not coll or (isinstance(coll, dict) and coll.get("error")):
            # Try alternate syntax if preferred syntax returned error or empty
            expand_ep_alt = f"{endpoint}{sep}$expand={alt_syntax}($levels={effective_levels})"
            coll = self._get(expand_ep_alt, critical=False)

        if not coll or not isinstance(coll, dict) or coll.get("error"):
            # BMC rejected $expand on this collection — mark unsupported and fallback
            unsupported_endpoints.add(endpoint)
            return self._get(endpoint)

        # Successful expanded collection — populate cache for each member
        members = coll.get("Members")
        if isinstance(members, list):
            for m in members:
                if isinstance(m, dict):
                    m_uri = m.get("@odata.id")
                    if m_uri and len(m) > 1:
                        self._populate_request_cache(m_uri, m)
                    for nested_key in (
                        "Drives",
                        "StorageControllers",
                        "Ports",
                        "NetworkPorts",
                        "NetworkDeviceFunctions",
                        "Controllers",
                        "PCIeFunctions",
                        "PCIeDevices",
                    ):
                        nested_items = m.get(nested_key)
                        if isinstance(nested_items, dict):
                            sub_uri = nested_items.get("@odata.id")
                            if sub_uri and len(nested_items) > 1:
                                self._populate_request_cache(sub_uri, nested_items)
                            sub_members = nested_items.get("Members")
                            if isinstance(sub_members, list):
                                for child in sub_members:
                                    if isinstance(child, dict) and child.get("@odata.id") and len(child) > 1:
                                        self._populate_request_cache(child["@odata.id"], child)
                        elif isinstance(nested_items, list):
                            for child in nested_items:
                                if isinstance(child, dict) and child.get("@odata.id") and len(child) > 1:
                                    self._populate_request_cache(child["@odata.id"], child)

        # Pre-cache collection endpoint itself
        self._populate_request_cache(endpoint, coll)
        self._populate_request_cache(expand_ep, coll)
        return coll

    def _get_members(self, endpoint_or_data, limit: int = 0, max_pages: int = 100) -> list:
        """Return all Members from a Redfish collection, following pagination links.

        The OData spec (on which Redfish is built) allows a service to split a
        large collection across multiple pages.  Each page may carry a
        'Members@odata.nextLink' key pointing at the next page URL.  Callers
        that used to do  (self._get(ep) or {}).get("Members", [])  silently
        truncated to the first page.  This method fetches every page.

        endpoint_or_data: either a URL string (fetched fresh) or an already-
            fetched dict (used as the first page, avoids a redundant GET when
            the caller already holds the response for other checks).
        limit: stop collecting once this many members are in hand.  0 = no
            limit.  Useful for log-entry fetches that only need recent items.
        max_pages: safety ceiling on pagination requests (default 100).
        """
        if isinstance(endpoint_or_data, dict):
            data = endpoint_or_data
        elif isinstance(endpoint_or_data, list):
            data = {"Members": endpoint_or_data}
        else:
            data = self._get(endpoint_or_data) or {}
            if isinstance(data, list):
                data = {"Members": data}
        collected: list = list(data.get("Members", []))
        if not collected:
            collected = list(
                data.get("members")
                or data.get("Member")
                or (data.get("links") or {}).get("Member")
                or (data.get("links") or {}).get("Members")
                or (data.get("links") or {}).get("members")
                or (data.get("Links") or {}).get("Member")
                or (data.get("Links") or {}).get("Members")
                or []
            )
        visited = set()
        if isinstance(endpoint_or_data, str) and endpoint_or_data:
            visited.add(endpoint_or_data)
        pages_fetched = 0

        while True:
            if limit and len(collected) >= limit:
                break
            if self._is_cancelled_or_skipped():
                break
            next_link = (
                data.get("Members@odata.nextLink")
                or data.get("@odata.nextLink")
            )
            if not next_link:
                break
            if next_link in visited:
                logger.warning("Circular pagination link detected: %s", next_link)
                break
            visited.add(next_link)
            pages_fetched += 1
            if max_pages and pages_fetched > max_pages:
                logger.warning("Exceeded max_pages (%d) limit fetching members", max_pages)
                break
            data = self._get(next_link) or {}
            if isinstance(data, list):
                collected.extend(data)
            elif isinstance(data, dict):
                collected.extend(data.get("Members", []))
        if hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
            for m in collected:
                if isinstance(m, dict):
                    m_uri = m.get("@odata.id")
                    if m_uri and len(m) > 2:
                        self._populate_request_cache(m_uri, m)
        return collected[:limit] if limit else collected

    def _update_stage(self, stage: str, force_broadcast: bool = False) -> None:
        if getattr(self, "_assessment_complete", False) or getattr(self, "_closed", False):
            return
        if stage:
            self._current_stage = stage
        now = time.time()
        last_bcast = getattr(self, "_last_stage_broadcast_time", 0.0)
        stage_changed = bool(stage and getattr(self, "_last_broadcast_stage", "") != stage)
        if force_broadcast or stage_changed or (now - last_bcast) >= 0.5:
            self._last_stage_broadcast_time = now
            if stage:
                self._last_broadcast_stage = stage
            info = {
                "ip": self.host,
                "stage": getattr(self, "_current_stage", "Scanning…"),
                "req_count": getattr(self, "_request_count", 0),
                "last_active_time": getattr(self, "_last_active_time", now),
                "throttled": getattr(self, "_throttled", False),
                "consecutive_timeouts": getattr(self, "_consecutive_timeouts", 0),
            }
            if getattr(self, "stage_callback", None):
                try:
                    self.stage_callback(self.host, info)
                except TypeError:
                    try:
                        self.stage_callback(self.host, stage)
                    except Exception:
                        pass
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Collection methods
    # ------------------------------------------------------------------

    def run_assessment(
        self,
        quick_mode: bool = False,
        capture_raw: bool = False,
        lean_mode: bool = False,
        allow_partial: bool = False,
        scan_profile: Optional[str] = None,
        crawl_endpoints: bool = False,
    ) -> Union[dict, list, None]:
        """Collect Redfish data for this host (or all sleds on modular chassis).

        scan_profile options:
          • 'readiness-full' (default): Exhaustive audit (Phase 1 + Phase 2 + HCL + PCIe + Telemetry + Interleaving).
          • 'readiness-lean': High-speed VCF 9.1 / vSAN ESA audit (skips historical telemetry logs & secondary member scans).
          • 'inventory-lite': Rapid hardware inventory pre-screening (Systems, Power/Thermal rollup, Storage rollup, NIC summary — no deep port/DIMM/PCIe/FW walk).
          • 'ops-inventory': VMware Aria / VCF Operations collection (Phase 1 + SEL + FW + Phase 2 hardware, no crawler/util telemetry).
        """
        prof_cfg = resolve_scan_profile(
            scan_profile=scan_profile,
            quick_mode=quick_mode,
            lean_mode=lean_mode,
            crawl=crawl_endpoints,
        )
        scan_profile = prof_cfg["name"]
        quick_mode = prof_cfg["quick_mode"]
        lean_mode = prof_cfg["lean_mode"]
        crawl_endpoints = prof_cfg["crawl"]

        self.scan_profile = scan_profile
        self.lean_mode = lean_mode
        self._preserve_all_raw = bool(capture_raw or crawl_endpoints)
        if self._is_cancelled_or_skipped():
            return None

        start_time = time.time()
        self.scan_start_time = start_time
        is_mocked = not hasattr(urllib.request.urlopen, "__code__") or "Mock" in type(urllib.request.urlopen).__name__ or hasattr(urllib.request.urlopen, "mock")
        if not is_mocked and is_host_auth_locked(self.host):
            logger.warning("[%s] Host is currently in auth lockout circuit-breaker — skipping assessment to protect BMC credentials", self.host)
            self.auth_failed = True
            return None
        self._update_stage("Connecting & Session Auth")
        logger.info(f"  [→] {self.host} — connecting...")
        self.create_session()
        self.audit_active_sessions()
        self._update_stage("Discovering Redfish Endpoints")
        self._discover_roots(capture_raw=(capture_raw or crawl_endpoints))

        if len(self.sys_uris) > 1:
            multi_results = []
            orig_sys_uris = list(self.sys_uris)
            for idx, s_uri in enumerate(orig_sys_uris):
                if self._is_cancelled_or_skipped():
                    break
                self.sys_uri = s_uri
                logger.info("[%s] Modular chassis: assessing sled %d/%d (%s)", self.host, idx + 1, len(orig_sys_uris), s_uri)
                sled_res = self._run_single_system_assessment(
                    quick_mode=quick_mode,
                    capture_raw=capture_raw,
                    lean_mode=lean_mode,
                    allow_partial=allow_partial,
                    start_time=start_time,
                    scan_profile=scan_profile,
                    crawl_endpoints=crawl_endpoints,
                )
                if sled_res:
                    if isinstance(sled_res, dict):
                        sled_res["chassis_management"] = self.chassis_management_info
                        (sled_res.setdefault("system", {}))["system_uri"] = s_uri
                    multi_results.append(sled_res)
            self._assessment_complete = True
            return multi_results if multi_results else None

        return self._run_single_system_assessment(
            quick_mode=quick_mode,
            capture_raw=capture_raw,
            lean_mode=lean_mode,
            allow_partial=allow_partial,
            start_time=start_time,
            scan_profile=scan_profile,
            crawl_endpoints=crawl_endpoints,
        )

    def _phase_wait_budgets(self, elapsed_s: float) -> Tuple[float, float]:
        """Compute bounded wait timeouts for Phase 1 and Phase 2 based on remaining budget."""
        ht = float(getattr(self, "host_timeout", 300) or 300)
        if ht < 60.0:
            ht = 60.0
        remaining = max(60.0, ht - float(elapsed_s or 0) - 15.0)  # 15s slack for eval/build after phases
        raw_p1 = min(180.0, max(60.0, ht * 0.4))
        raw_p2 = min(300.0, max(90.0, ht * 0.6))
        if raw_p1 + raw_p2 <= remaining:
            return raw_p1, raw_p2
        scale = remaining / (raw_p1 + raw_p2)
        p1 = max(30.0, raw_p1 * scale)
        p2 = max(60.0, remaining - p1)
        return p1, p2

    def _run_single_system_assessment(
        self,
        quick_mode: bool = False,
        capture_raw: bool = False,
        lean_mode: bool = False,
        allow_partial: bool = False,
        start_time: Optional[float] = None,
        scan_profile: Optional[str] = None,
        crawl_endpoints: bool = False,
    ) -> Optional[dict]:
        if scan_profile is None:
            scan_profile = getattr(self, "scan_profile", "readiness-full")
        prof_cfg = resolve_scan_profile(
            scan_profile=scan_profile,
            quick_mode=quick_mode,
            lean_mode=lean_mode,
            crawl=crawl_endpoints,
        )
        scan_profile = prof_cfg["name"]
        quick_mode = prof_cfg["quick_mode"]
        lean_mode = prof_cfg["lean_mode"]
        crawl_endpoints = prof_cfg["crawl"]
        collect_sel = prof_cfg["collect_sel"]
        collect_firmware = prof_cfg["collect_firmware"]
        collect_util_telemetry = prof_cfg["collect_util_telemetry"]
        if start_time is None:
            start_time = time.time()
        self._update_stage("Collecting System & CPU Info")
        sys_summary = self.collect_system_summary()
        self.sys_summary = sys_summary
        if not sys_summary or self._is_cancelled_or_skipped():
            if getattr(self, "auth_failed", False):
                logger.warning(f"  [✗] {self.host} — bad credentials (HTTP 401/403)")
            elif not sys_summary:
                logger.warning(f"  [✗] {self.host} — no system data (check IP / network)")
            return None

        # Dell AMD platform pacing & concurrency tuning (R7525, R7515, R6525, R6625, R7625, C6525, etc.)
        # Prevent iDRAC web server saturation and 28-timeout spikes caused by PLDM latency.
        _vendor = str(sys_summary.get("vendor") or getattr(self, "vendor", "") or "").lower()
        _model = str(sys_summary.get("model") or getattr(self, "sys_model", "") or "").upper()
        _cpu_model = str(sys_summary.get("cpu_summary", {}).get("model") or "").lower()
        _is_dell_amd = ("dell" in _vendor) and (
            any(m in _model for m in ("R7525", "R7515", "R6525", "R6625", "R7625", "C6525"))
            or ("epyc" in _cpu_model)
        )
        if _is_dell_amd:
            self._max_inner_workers = 2
            self._base_max_inner_workers = 2
            self._request_pacing_s = max(getattr(self, "_request_pacing_s", 0.0), 0.05)
            if getattr(self, "_conn_pool", None) is not None:
                self._conn_pool.max_connections = self._max_inner_workers
            logger.debug("[%s] Dell AMD platform detected (%s). Capping inner workers to 2 with 50ms pacing.", self.host, _model)

        # Local helper to build result dictionary safely even on partial timeouts
        def _build_result_dict(p2_data=None, is_partial=False) -> dict:
            if p2_data is None:
                p2_data = {}
            res = {
                "system":              sys_summary,
                "host_os":             host_os if 'host_os' in locals() else {},
                "bios_checks":         bios_info if 'bios_info' in locals() else {},
                "sel_alarms":          sel_alarms if 'sel_alarms' in locals() else [],
                "bmc_license":         bmc_license if 'bmc_license' in locals() else {},
                "secure_boot":         secure_boot if 'secure_boot' in locals() else {},
                "bmc_firmware":        bmc_fw_info if 'bmc_fw_info' in locals() else {},
                "bmc_security_config": bmc_sec_cfg if 'bmc_sec_cfg' in locals() else {},
                "bmc_security_evidence": bmc_sec_evidence if 'bmc_sec_evidence' in locals() and bmc_sec_evidence else empty_security_evidence(getattr(self, "vendor", "generic") or "generic"),
                "bmc_net_proto":       bmc_net_proto if 'bmc_net_proto' in locals() else {},
                "firmware_inventory":  fw_inventory if 'fw_inventory' in locals() else [],
                "job_queue":           p2_data.get("job_queue") or (job_queue if 'job_queue' in locals() and job_queue else {}),
                "pcie_lane_budget":    pcie_lane_budget if 'pcie_lane_budget' in locals() else {},
                "memory_subsystem":    p2_data.get("memory_subsystem") or {},
                "memory_telemetry":    p2_data.get("memory_telemetry") or {},
                "cpu_telemetry":       p2_data.get("cpu_telemetry") or {},
                "io_telemetry":        p2_data.get("io_telemetry") or {},
                "thermal_telemetry":   p2_data.get("thermal_telemetry") or {},
                "network_adapters":    p2_data.get("network_adapters") or [],
                "storage_subsystem":   p2_data.get("storage_subsystem") or [],
                "gpu_accelerators":    p2_data.get("gpu_accelerators") or [],
                "fc_hbas":             p2_data.get("fc_hbas") or [],
                "lldp_neighbors":      p2_data.get("lldp_neighbors") or [],
                "psu_status":          p2_data.get("psu_status") or {},
                "pcie_slots":          p2_data.get("pcie_slots") or [],
            }
            res["memory_topology"] = {}
            if capture_raw or crawl_endpoints:
                raw_capture = {}
                with self._cache_lock:
                    cache_copy = dict(self._request_cache)
                for url, payload in cache_copy.items():
                    path = url
                    if "://" in path:
                        path = "/" + path.split("://", 1)[1].split("/", 1)[-1]
                    raw_capture[path] = payload
                res["raw_redfish_capture"] = raw_capture

            res["scan_duration_sec"] = round(time.time() - start_time, 1)
            res["scan_profile"] = scan_profile
            res["collector_class"] = type(self).__name__
            res["adaptive_throttled"] = getattr(self, "_throttled", False)

            conn_stats = self._conn_pool.get_stats() if hasattr(self, "_conn_pool") and self._conn_pool is not None else {}
            try:
                effective_pacing = float(self.get_effective_pacing()) if hasattr(self, "get_effective_pacing") else float(getattr(self, "_request_pacing_s", 0.05))
            except Exception:
                effective_pacing = 0.05
            try:
                max_levels = int(getattr(self, "expand_max_levels", 1) or 1)
            except Exception:
                max_levels = 1
            unsupported_expand = sorted(list(getattr(self, "_unsupported_expand_endpoints", set()) or []))

            res["diagnostics"] = {
                "scan_profile": scan_profile,
                "request_count": getattr(self, "_request_count", 0),
                "timeout_count": getattr(self, "_total_timeouts_encountered", 0),
                "throttle_engaged_count": getattr(self, "_throttle_engaged_count", 0),
                "max_inner_workers": getattr(self, "_max_inner_workers", _BMC_INNER_WORKERS),
                "silicon_generation": getattr(self, "silicon_generation", ""),
                "phase1_duration_s": round(getattr(self, "_phase1_duration_s", 0.0), 2),
                "phase2_duration_s": round(getattr(self, "_phase2_duration_s", 0.0), 2),
                "total_scan_duration_s": round(time.time() - start_time, 2),
                "avg_get_latency_ms": conn_stats.get("avg_request_time_ms", 0.0),
                "tls_handshake_avg_ms": conn_stats.get("avg_tls_handshake_ms", 0.0),
                "tls_reuse_ratio": conn_stats.get("tls_reuse_ratio", 0.0),
                "connection_pool": conn_stats,
                "expand_supported": bool(getattr(self, "expand_supported", False)),
                "expand_syntax": getattr(self, "expand_syntax", None),
                "expand_max_levels": max_levels,
                "multiple_http_requests": bool(getattr(self, "multiple_http_requests", False)),
                "request_pacing_s": round(effective_pacing, 3),
                "unsupported_expand_endpoints": unsupported_expand,
            }

            failed_sec = list(getattr(self, "_failed_sections", []) or getattr(self, "_timed_out_sections", []))
            critical_missing = [s for s in failed_sec if s in (
                "storage_subsystem", "network_adapters", "firmware_inventory", "pcie_devices", "bios_checks", "memory_subsystem", "psu_status"
            )]

            if is_partial or bool(getattr(self, "_timed_out_sections", [])) or bool(critical_missing):
                stg = getattr(self, "_current_stage", "Collection")
                res["partial_scan"] = True
                res["partial_stage"] = stg
                res["partial_sections"] = failed_sec
                sec_desc = f" (missing: {', '.join(failed_sec)})" if failed_sec else ""
                res["partial_reason"] = f"Collection incomplete or timed out during {stg}{sec_desc}"
                if getattr(self, "timed_out", False) or bool(getattr(self, "_timed_out_sections", [])):
                    res["timed_out"] = True
            else:
                res["partial_scan"] = False
                res["partial_sections"] = []
                res["partial_stage"] = ""
                res["partial_reason"] = ""

            if getattr(self, "metadata", None):
                res["collector_metadata"] = dict(self.metadata)
            if getattr(self, "bmc_session_warning", None):
                res["bmc_session_warning"] = self.bmc_session_warning
                res.setdefault("warnings", []).append(self.bmc_session_warning)
            return res

        # ── Phase 1: run bios / SEL / license concurrently ─────────────────────
        # pcie_devices joins the same pool in full mode; it queues behind one of
        # the first three tasks since we have exactly _BMC_INNER_WORKERS workers.
        # License is cheap (1-3 GETs) but always collected — even quick mode needs
        # it to surface e.g. XCC Standard vs Enterprise warnings.
        with self._cache_lock:
            self._consecutive_timeouts = 0
            self._consecutive_successes = 0
            user_cancelled = bool(getattr(self, "cancel_event", None) is not None and getattr(self.cancel_event, "is_set", lambda: False)())
            user_skipped = bool(getattr(self, "skip_host_set", None) is not None and self.skip_host_set and self.host in self.skip_host_set)
            host_timeout_exceeded = bool(getattr(self, "host_timeout", 0) > 0 and self.scan_start_time is not None and (time.time() - self.scan_start_time) > self.host_timeout)
            if not user_cancelled and not user_skipped and not host_timeout_exceeded:
                self.skipped = False
                self.timed_out = False
            if getattr(self, "_throttled", False):
                self._throttled = False
                if getattr(self, "multiple_http_requests", False):
                    self._request_pacing_s = 0.0
                self._inner_cv.notify_all()
        self._phase1_expired = False
        def _p1_run(fn, *args, **kwargs):
            _thread_local.is_phase1 = True
            try:
                return fn(*args, **kwargs)
            finally:
                _thread_local.is_phase1 = False

        logger.info("[%s] Phase 1: Collecting system summary, BIOS, SEL, OS & firmware inventory...", self.host)
        self._update_stage("Phase 1: BIOS, SEL & Firmware Inventory")
        _p1_start = time.time()
        _p1_workers = 1 if getattr(self, "_throttled", False) else max(1, getattr(self, "_max_inner_workers", _BMC_INNER_WORKERS))
        _p1 = ThreadPoolExecutor(max_workers=_p1_workers)
        job_queue = {}
        try:
            _f_bios     = _p1.submit(_p1_run, _timed, "bios_attrs",    self.check_bios_attributes)
            _f_sel      = _p1.submit(_p1_run, _timed, "sel",            self.collect_system_event_log) if collect_sel else None
            _f_lic      = _p1.submit(_p1_run, _timed, "bmc_license",   self.collect_bmc_license)
            _f_sec_cfg  = _p1.submit(_p1_run, _timed, "bmc_sec_cfg",   self.collect_bmc_security_config)
            _f_sec_ev   = _p1.submit(_p1_run, _timed, "bmc_security_evidence", self.collect_bmc_security_evidence)
            _f_swos     = _p1.submit(_p1_run, _timed, "sw_inv_os",     self.collect_software_inventory_os)
            _f_net_proto= _p1.submit(_p1_run, _timed, "bmc_net_proto", self.collect_bmc_network_protocol)
            _f_pcie     = _p1.submit(_p1_run, _timed, "pcie_devices",  self.collect_pcie_devices) if not quick_mode else None
            _f_fw_inv   = _p1.submit(_p1_run, _timed, "fw_inventory",  self.collect_firmware_inventory) if collect_firmware else None

            _p1_futures = [f for f in [_f_bios, _f_sel, _f_lic, _f_sec_cfg, _f_sec_ev, _f_swos, _f_net_proto, _f_pcie, _f_fw_inv] if f is not None]
            if _p1_futures:
                elapsed = 0.0
                if getattr(self, "scan_start_time", None):
                    elapsed = time.time() - self.scan_start_time
                p1_timeout, _p2_ignored = self._phase_wait_budgets(elapsed)
                wait(_p1_futures, timeout=p1_timeout)

            bios_info         = _safe_result(_f_bios,     "bios_checks", self.host, timeout=0.5, collector=self)
            sel_alarms        = _safe_result(_f_sel,      "sel_alarms",  self.host, timeout=0.5, collector=self)
            bmc_license       = _safe_result(_f_lic,      "bmc_license", self.host, timeout=0.5, collector=self)
            bmc_sec_cfg       = _safe_result(_f_sec_cfg,  "bmc_sec_cfg", self.host, timeout=0.5, collector=self)
            bmc_sec_evidence  = _safe_result(_f_sec_ev,   "bmc_security_evidence", self.host, timeout=0.5, collector=self)
            sw_inv_os         = _safe_result(_f_swos,     "sw_inv_os",   self.host, timeout=0.5, collector=self)
            bmc_net_proto     = _safe_result(_f_net_proto, "bmc_net_proto", self.host, timeout=0.5, collector=self)
            pcie_cache        = (_safe_result(_f_pcie, "pcie_devices", self.host, timeout=0.5, collector=self) or []) if not quick_mode else []
            fw_inventory      = _safe_result(_f_fw_inv,   "firmware_inventory", self.host, timeout=0.5, collector=self) if collect_firmware else []
        finally:
            self._phase1_expired = True
            _p1.shutdown(wait=False, cancel_futures=True)
            self._phase1_duration_s = time.time() - _p1_start
            with self._inner_cv:
                self._inner_cv.wait_for(lambda: getattr(self, "_active_inner_workers", 0) == 0, timeout=3.0)

        host_os        = _evaluate_os_info(sys_summary.get("os_raw", {}), sw_inv_os or {})
        # Secure Boot and BMC firmware — lightweight (1 GET each), run sequentially here
        secure_boot    = self.collect_secure_boot_redfish()
        bmc_fw_info    = self.collect_bmc_firmware()

        if quick_mode:
            is_timed_out = getattr(self, "timed_out", False) or getattr(self, "_consecutive_timeouts", 0) >= 4 or bool(getattr(self, "_timed_out_sections", []))
            is_user_skip = (getattr(self, "skipped", False) or self._is_cancelled_or_skipped()) and not is_timed_out
            if is_timed_out or getattr(self, "skipped", False):
                can_harvest = bool(sys_summary) and not is_user_skip
                if allow_partial or can_harvest:
                    harvest_note = " (harvested without allow_partial)" if (can_harvest and not allow_partial) else ""
                    logger.warning(f"  [⚠️] {self.host} — scan incomplete/timed out, returning partial assessment data{harvest_note}")
                    self._assessment_complete = True
                    return _build_result_dict(is_partial=True)
                self._assessment_complete = True
                return None
            self._assessment_complete = True
            return _build_result_dict(is_partial=False)
        else:
            pcie_cache      = pcie_cache if 'pcie_cache' in locals() else []
            cpu_count       = sys_summary["cpu_summary"]["count"]
            chan_per_socket  = sys_summary["cpu_summary"]["channels_per_socket"]
            total_ram       = sys_summary.get("total_memory_gb", 256)

            # Reset Phase 1 accumulated timeouts & circuit-breaker flags before evaluating Phase 2 entry
            with self._cache_lock:
                self._consecutive_timeouts = 0
                self._consecutive_successes = 0
                user_cancelled = bool(getattr(self, "cancel_event", None) is not None and getattr(self.cancel_event, "is_set", lambda: False)())
                user_skipped = bool(getattr(self, "skip_host_set", None) is not None and self.skip_host_set and self.host in self.skip_host_set)
                host_timeout_exceeded = bool(getattr(self, "host_timeout", 0) > 0 and self.scan_start_time is not None and (time.time() - self.scan_start_time) > self.host_timeout)
                if not user_cancelled and not user_skipped and not host_timeout_exceeded:
                    self.skipped = False
                    self.timed_out = False

            if self._is_cancelled_or_skipped():
                can_harvest_mid = bool(getattr(self, "timed_out", False) or getattr(self, "_timed_out_sections", None)) and bool(sys_summary)
                if allow_partial or can_harvest_mid:
                    self._assessment_complete = True
                    return _build_result_dict(is_partial=True)
                self._assessment_complete = True
                return None

            # ── Phase 2: 12 independent collectors, 3 at a time ──────────────
            # Peak concurrent connections to this BMC = _BMC_INNER_WORKERS (3).
            # pcie_slots is included here; pcie_lane_budget is derived from it
            # with a pure-Python call after Phase 2 completes.
            with self._inner_cv:
                self._consecutive_timeouts = 0
                self._consecutive_successes = 0
                self._throttled = False
                if getattr(self, "multiple_http_requests", False):
                    self._request_pacing_s = 0.0
                self._inner_cv.notify_all()
            self._phase2_expired = False
            def _p2_run(fn, *args, **kwargs):
                _thread_local.is_phase2 = True
                try:
                    return fn(*args, **kwargs)
                finally:
                    _thread_local.is_phase2 = False

            logger.info("[%s] Phase 2: Collecting storage, network, memory, thermal & GPU subsystems...", self.host)
            self._update_stage("Phase 2: Storage, NICs, Memory & Telemetry")
            _p2_start = time.time()
            _p2_workers = 1 if getattr(self, "_throttled", False) else max(1, getattr(self, "_max_inner_workers", _BMC_INNER_WORKERS))
            _p2 = ThreadPoolExecutor(max_workers=_p2_workers)
            has_fc = pcie_has_fc_candidates(pcie_cache)
            has_gpu = pcie_has_gpu_candidates(pcie_cache)
            try:
                _f = {
                    "storage_subsystem":_p2.submit(_p2_run, _timed, "storage",          self.collect_storage_subsystem, pcie_cache),
                    "network_adapters": _p2.submit(_p2_run, _timed, "nics",             self.collect_network_adapters,  pcie_cache),
                    "memory_subsystem": _p2.submit(_p2_run, _timed, "memory_details",   self.collect_memory_details,   cpu_count, chan_per_socket),
                    "psu_status":       _p2.submit(_p2_run, _timed, "psu",              self.collect_psu_status),
                    "pcie_slots":       _p2.submit(_p2_run, _timed, "pcie_slots",       self.collect_pcie_slots),
                    "thermal_telemetry":_p2.submit(_p2_run, _timed, "thermal",          self.collect_thermal_telemetry),
                    "fc_hbas":          _p2.submit(_p2_run, _timed, "fc_hbas",          self.collect_fc_hbas,           pcie_cache) if has_fc else _p2.submit(lambda: []),
                    "gpu_accelerators": _p2.submit(_p2_run, _timed, "gpus",             self.collect_gpu_accelerators,  pcie_cache) if has_gpu else _p2.submit(lambda: []),
                    "lldp_neighbors":   _p2.submit(_p2_run, _timed, "lldp",             self.collect_lldp_neighbors),
                    "memory_telemetry": _p2.submit(_p2_run, _timed, "memory_telemetry", self.collect_memory_telemetry, installed_gb=total_ram) if (not lean_mode and collect_util_telemetry) else _p2.submit(lambda: {}),
                    "cpu_telemetry":    _p2.submit(_p2_run, _timed, "cpu_telemetry",    self.collect_cpu_telemetry) if (not lean_mode and collect_util_telemetry) else _p2.submit(lambda: {}),
                    "io_telemetry":     _p2.submit(_p2_run, _timed, "io_telemetry",     self.collect_io_telemetry) if (not lean_mode and collect_util_telemetry) else _p2.submit(lambda: {}),
                    "pcie_switches":    _p2.submit(_p2_run, _timed, "pcie_switches",    self._scan_pcie_switches,       pcie_cache),
                    "job_queue":        _p2.submit(_p2_run, _timed, "job_queue",        self.collect_job_queue) if not lean_mode else _p2.submit(lambda: {}),
                }
                _p2_futures = [f for f in _f.values() if f is not None]
                if _p2_futures:
                    elapsed = 0.0
                    if getattr(self, "scan_start_time", None):
                        elapsed = time.time() - self.scan_start_time
                    _p1_ignored, p2_timeout = self._phase_wait_budgets(elapsed)
                    wait(_p2_futures, timeout=p2_timeout)

                _phase2 = {k: _safe_result(f, k, self.host, timeout=0.5, collector=self) for k, f in _f.items()}
            finally:
                self._phase2_expired = True
                _p2.shutdown(wait=False, cancel_futures=True)
                self._phase2_duration_s = time.time() - _p2_start
                with self._inner_cv:
                    self._inner_cv.wait_for(lambda: getattr(self, "_active_inner_workers", 0) == 0, timeout=3.0)
            mem_sub = _phase2.get("memory_subsystem") or {}
            if not sys_summary.get("total_memory_gb"):
                dimms = mem_sub.get("dimm_list") or []
                calculated_gb = sum(int(d.get("capacity_gb") or 0) for d in dimms)
                if calculated_gb > 0:
                    sys_summary["total_memory_gb"] = calculated_gb
            pcie_slots_result = _phase2.get("pcie_slots") or []
            pcie_lane_budget = {}

        is_timed_out = getattr(self, "timed_out", False) or getattr(self, "_consecutive_timeouts", 0) >= 4
        failed_sec = list(getattr(self, "_failed_sections", []) or getattr(self, "_timed_out_sections", []))
        critical_missing = [s for s in failed_sec if s in (
            "storage_subsystem", "network_adapters", "firmware_inventory", "pcie_devices", "bios_checks", "memory_subsystem", "psu_status"
        )]
        has_partial = is_timed_out or bool(getattr(self, "_timed_out_sections", [])) or bool(critical_missing)

        if has_partial:
            can_harvest = bool(allow_partial) or (
                bool(getattr(self, "timed_out", False) or getattr(self, "_timed_out_sections", None))
                and bool(sys_summary)
            )
            if can_harvest:
                p_msg = f" (missing: {', '.join(failed_sec)})" if failed_sec else ""
                logger.warning(f"  [⚠️] {self.host} — scan incomplete/timed out, returning partial assessment data{p_msg}")
                result = _build_result_dict(_phase2 if '_phase2' in locals() else {}, is_partial=True)
            else:
                self._assessment_complete = True
                return None
        else:
            self._update_stage("Evaluating Compatibility Baseline")
            result = _build_result_dict(_phase2 if '_phase2' in locals() else {}, is_partial=False)
            logger.info(f"  [✓] {self.host} — {sys_summary['vendor']} {sys_summary['model']}")

        if crawl_endpoints and not self._is_cancelled_or_skipped():
            self._update_stage("Deep Redfish Crawling (All Endpoints)")
            try:
                crawler = RedfishCrawler(
                    get_fn=self._get,
                    host_label=str(getattr(self, "host", "host")),
                    is_cancelled_fn=self._is_cancelled_or_skipped,
                    progress_callback=lambda msg, v, q: self._update_stage(msg),
                )
                with self._cache_lock:
                    cached_items = dict(self._request_cache)
                crawler.preseed_cache(cached_items)

                entry_points = ["/redfish", "/redfish/v1"]
                if getattr(self, "sys_uris", None):
                    entry_points.extend(self.sys_uris)
                if getattr(self, "chassis_uris", None):
                    entry_points.extend(self.chassis_uris)
                if getattr(self, "mgr_uris", None):
                    entry_points.extend(self.mgr_uris)

                crawler.crawl(entry_points=entry_points)
                self._crawler = crawler
                if result is not None and isinstance(result, dict):
                    result["endpoint_manifest"] = crawler.generate_manifest_summary()
                    result["actions_manifest"] = crawler.generate_actions_summary()
                    raw_capture = result.get("raw_redfish_capture") or {}
                    for u, p in crawler.crawl_results.items():
                        raw_capture[u] = p
                    result["raw_redfish_capture"] = raw_capture
            except Exception as crawl_err:
                logger.warning("[%s] Deep crawl encountered an error: %s", getattr(self, "host", "host"), crawl_err)

        self._assessment_complete = True
        return result

    def rescan_partial_sections(self, prior_data: dict, sections_to_rescan: Optional[list] = None) -> Optional[dict]:
        """Perform a targeted differential rescan of only missing or failed sections.

        Connects to the BMC, runs only the methods corresponding to the missing
        sections in `sections_to_rescan` (or `prior_data['partial_sections']`),
        and patches them into a copy of `prior_data`.
        """
        if not prior_data or not isinstance(prior_data, dict):
            return None

        import copy
        merged = copy.deepcopy(prior_data)
        missing_sections = list(sections_to_rescan if sections_to_rescan is not None else prior_data.get("partial_sections", []))
        if not missing_sections:
            merged["partial_scan"] = False
            merged["partial_sections"] = []
            merged["partial_reason"] = ""
            return merged

        # Authenticate and discover roots
        self._is_rescan = True
        with self._inner_cv:
            self._throttled = True
            self._consecutive_timeouts = 0
            self._consecutive_successes = 0

        self.scan_start_time = time.time()
        self._current_stage = "Connecting for Targeted Rescan..."
        self._update_stage("Connecting for Targeted Rescan...", force_broadcast=True)

        if not self.create_session():
            logger.warning("[%s] Failed creating Redfish session for targeted rescan", self.host)
            return None
        self._update_stage("Discovering Endpoints for Rescan...", force_broadcast=True)
        self._discover_roots()

        cpu_summary = (merged.get("system") or {}).get("cpu_summary") or {}
        cpu_count = int(cpu_summary.get("count") or 1)
        channels_per_socket = int(cpu_summary.get("channels_per_socket") or 8)
        total_ram = int((merged.get("system") or {}).get("total_memory_gb") or 256)

        def _get_mem():
            return self.collect_memory_details(cpu_count, channels_per_socket)

        def _get_mem_tel():
            return self.collect_memory_telemetry(installed_gb=total_ram)

        def _get_os():
            sw_os = self.collect_software_inventory_os()
            return _evaluate_os_info((merged.get("system") or {}).get("os_raw", {}), sw_os or {})

        section_dispatch = {
            "pcie_slots":          ("pcie_slots", self.collect_pcie_slots),
            "pcie_switches":       ("pcie_switches", self._scan_pcie_switches),
            "firmware_inventory":  ("firmware_inventory", self.collect_firmware_inventory),
            "storage_subsystem":   ("storage_subsystem", self.collect_storage_subsystem),
            "network_adapters":    ("network_adapters", self.collect_network_adapters),
            "memory_subsystem":    ("memory_subsystem", _get_mem),
            "thermal_telemetry":   ("thermal_telemetry", self.collect_thermal_telemetry),
            "gpu_accelerators":    ("gpu_accelerators", self.collect_gpu_accelerators),
            "fc_hbas":             ("fc_hbas", self.collect_fc_hbas),
            "lldp_neighbors":      ("lldp_neighbors", self.collect_lldp_neighbors),
            "psu_status":          ("psu_status", self.collect_psu_status),
            "pcie_devices":        ("pcie_devices", self.collect_pcie_devices),
            "memory_telemetry":    ("memory_telemetry", _get_mem_tel),
            "cpu_telemetry":       ("cpu_telemetry", self.collect_cpu_telemetry),
            "io_telemetry":        ("io_telemetry", self.collect_io_telemetry),
            "sel_alarms":          ("sel_alarms", self.collect_system_event_log),
            "bios_checks":         ("bios_checks", self.check_bios_attributes),
            "bmc_license":         ("bmc_license", self.collect_bmc_license),
            "bmc_security_config": ("bmc_security_config", self.collect_bmc_security_config),
            "bmc_sec_cfg":         ("bmc_security_config", self.collect_bmc_security_config),
            "bmc_security_evidence": ("bmc_security_evidence", self.collect_bmc_security_evidence),
            "bmc_net_proto":       ("bmc_net_proto", self.collect_bmc_network_protocol),
            "bmc_firmware":        ("bmc_firmware", self.collect_bmc_firmware),
            "secure_boot":         ("secure_boot", self.collect_secure_boot_redfish),
            "sw_inv_os":           ("host_os", _get_os),
        }

        friendly_section_names = {
            "pcie_slots": "PCIe Slots",
            "pcie_switches": "PCIe Switches",
            "firmware_inventory": "Firmware Inventory",
            "storage_subsystem": "Storage Subsystem",
            "network_adapters": "Network Adapters",
            "memory_subsystem": "Memory Subsystem",
            "thermal_telemetry": "Thermal Telemetry",
            "gpu_accelerators": "GPU Accelerators",
            "fc_hbas": "FC HBAs",
            "lldp_neighbors": "LLDP Neighbors",
            "psu_status": "PSU Status",
            "pcie_devices": "PCIe Devices",
            "memory_telemetry": "Memory Telemetry",
            "cpu_telemetry": "CPU Telemetry",
            "io_telemetry": "I/O Telemetry",
            "sel_alarms": "System Event Log",
            "bios_checks": "BIOS Attributes",
            "bmc_license": "BMC License",
            "bmc_security_config": "BMC Security Config",
            "bmc_sec_cfg": "BMC Security Config",
            "bmc_security_evidence": "BMC Security Evidence",
            "bmc_net_proto": "BMC Network Protocol",
            "bmc_firmware": "BMC Firmware",
            "secure_boot": "Secure Boot",
            "sw_inv_os": "Host OS Inventory",
        }

        resolved_sections = set()
        for sec in missing_sections:
            if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                break
            handler = section_dispatch.get(sec)
            if not handler:
                continue
            key, fn = handler
            try:
                sec_label = friendly_section_names.get(sec, sec.replace("_", " ").title())
                self._update_stage(f"Rescanning: {sec_label}", force_broadcast=True)
                res = fn()
                if res is not None:
                    if isinstance(res, (list, dict)):
                        merged[key] = res
                        resolved_sections.add(sec)
                        logger.info("[%s] Targeted rescan resolved section: %s", self.host, sec)
            except Exception as err:
                logger.warning("[%s] Targeted rescan error for section '%s': %s", self.host, sec, err)

        remaining_missing = [s for s in missing_sections if s not in resolved_sections]

        if "pcie_slots" in resolved_sections:
            merged.setdefault("pcie_lane_budget", {})

        if "memory_subsystem" in resolved_sections:
            merged.setdefault("memory_topology", {})

        resolved_list = sorted(list(resolved_sections))
        merged["remediation"] = {
            "is_rescan": True,
            "original_missing": list(missing_sections),
            "resolved_sections": resolved_list,
            "remaining_sections": list(remaining_missing),
            "status": "fully_remediated" if not remaining_missing else "partially_remediated",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        if not remaining_missing:
            merged["partial_scan"] = False
            merged["partial_sections"] = []
            merged["partial_stage"] = ""
            merged["partial_reason"] = ""
            merged.pop("timed_out", None)
        else:
            merged["partial_scan"] = True
            merged["partial_sections"] = remaining_missing
            merged["partial_reason"] = f"Collection incomplete (missing: {', '.join(remaining_missing)})"

        self._assessment_complete = True
        return merged


__all__ = [
    "BaseRedfishCollector",
    "clear_auth_lockout",
    "is_host_auth_locked",
    "record_auth_lockout",
]


# ---------------------------------------------------------------------------
