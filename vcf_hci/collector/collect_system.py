"""
VCF Readiness Tool — system/memory/BIOS/BMC collection mixin.
"""
import ipaddress
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    class _CollectorBase:
        sys_uri: Optional[str]
        chassis_uri: Optional[str]
        mgr_uri: Optional[str]
        sys_sku: str
        host: str
        port: int
        username: str
        password: str
        session_token: Optional[str]
        verify_ssl: bool
        ca_bundle: Optional[str]
        timeout: float
        host_timeout: float
        scan_start_time: Optional[float]
        cancel_event: Any
        skip_host_set: Any
        skipped: bool
        timed_out: bool
        auth_failed: bool
        chassis_management_info: dict
        stage_callback: Any
        _PCIE_SWITCH_NAMES: tuple
        def _get(self, endpoint: str, _retry: bool = True, timeout: int = 15, critical: bool = True) -> Optional[dict]: ...
        def _get_members(self, endpoint_or_data: Any, limit: int = 0, max_pages: int = 100) -> list: ...
        def _get_oem_raw(self, uri: str, timeout: Optional[float] = None) -> Optional[dict]: ...
        def _is_cancelled_or_skipped(self) -> bool: ...
        @staticmethod
        def _is_license_blocked(data: Optional[dict]) -> Optional[str]: ...
        def _resolve_product_name(self, raw_obj: dict, pcie_cache: Optional[list] = None) -> str: ...
        def oem_bios_date(self, sys_data: dict) -> str: ...
        def oem_sku(self, sys_data: dict) -> str: ...
        def oem_storage_endpoints(self) -> list: ...
        def oem_drive_endurance(self, drive_json: dict) -> Optional[float]: ...
        def oem_drive_metrics(self, drive_json: dict) -> dict: ...
        def oem_nic_firmware(self, adapter_json: dict) -> str: ...
        def oem_cpu_cache(self, proc_json: dict) -> list: ...
        def oem_memory_usage(self, sys_data: dict) -> dict: ...
        def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict: ...
        def oem_pcie_link_status(self, dev_dict: dict) -> Optional[dict]: ...
        def oem_os_info(self, sys_data: dict) -> dict: ...
        def oem_handle_retry(self, data: dict, endpoint: str) -> bool: ...
        def oem_manager_paths(self) -> list: ...
        def oem_fastpath_roots(self) -> Optional[Tuple[list, list, list]]: ...
        def oem_job_queue(self, now_dt: Any = None) -> dict: ...
        def collect_job_queue(self, now_dt: Any = None) -> dict: ...
else:
    _CollectorBase = object

logger = logging.getLogger("vcf_assess")

_CPU_SUMMARY_PLACEHOLDERS = frozenset({
    "",
    "n/a",
    "na",
    "none",
    "unknown",
    "available for assignment",
    "not available",
    "not specified",
    "null",
})


def _normalize_cpu_summary_model(raw: Optional[Any]) -> str:
    """Map BMC placeholder ProcessorSummary.Model strings to Unknown.

    AMI MegaRAC / some RackScale implementations send
    'Available for assignment' instead of a CPU name.
    """
    s = str(raw or "").strip()
    if not s or s.lower() in _CPU_SUMMARY_PLACEHOLDERS:
        return "Unknown"
    return s


KNOWN_XEON_E5_E7_CORES: Dict[str, Tuple[int, int]] = {
    # Xeon E5 v4 (Broadwell-EP) — (cores_per_socket, threads_per_socket)
    "E5-2603 V4": (6, 6),
    "E5-2609 V4": (8, 8),
    "E5-2620 V4": (8, 16),
    "E5-2623 V4": (4, 8),
    "E5-2630 V4": (10, 20),
    "E5-2630L V4": (10, 20),
    "E5-2637 V4": (4, 8),
    "E5-2640 V4": (10, 20),
    "E5-2643 V4": (6, 12),
    "E5-2650 V4": (12, 24),
    "E5-2650L V4": (14, 28),
    "E5-2660 V4": (14, 28),
    "E5-2667 V4": (8, 16),
    "E5-2680 V4": (14, 28),
    "E5-2683 V4": (16, 32),
    "E5-2687W V4": (12, 24),
    "E5-2690 V4": (14, 28),
    "E5-2695 V4": (18, 36),
    "E5-2697 V4": (18, 36),
    "E5-2697A V4": (16, 32),
    "E5-2698 V4": (20, 40),
    "E5-2699 V4": (22, 44),
    "E5-2699A V4": (22, 44),
    "E5-4610 V4": (10, 10),
    "E5-4620 V4": (10, 20),
    "E5-4627 V4": (10, 10),
    "E5-4640 V4": (12, 24),
    "E5-4650 V4": (14, 28),
    "E5-4660 V4": (16, 32),
    "E5-4669 V4": (22, 44),
    # Xeon E5 v3 (Haswell-EP)
    "E5-2603 V3": (6, 6),
    "E5-2609 V3": (6, 6),
    "E5-2620 V3": (6, 12),
    "E5-2623 V3": (4, 8),
    "E5-2630 V3": (8, 16),
    "E5-2630L V3": (8, 16),
    "E5-2637 V3": (4, 8),
    "E5-2640 V3": (8, 16),
    "E5-2643 V3": (6, 12),
    "E5-2650 V3": (10, 20),
    "E5-2650L V3": (12, 24),
    "E5-2660 V3": (10, 20),
    "E5-2667 V3": (8, 16),
    "E5-2670 V3": (12, 24),
    "E5-2680 V3": (12, 24),
    "E5-2683 V3": (14, 28),
    "E5-2687W V3": (10, 20),
    "E5-2690 V3": (12, 24),
    "E5-2695 V3": (14, 28),
    "E5-2697 V3": (14, 28),
    "E5-2698 V3": (16, 32),
    "E5-2699 V3": (18, 36),
    # Xeon E7 v3/v4 (Broadwell/Haswell-EX)
    "E7-4809 V3": (8, 16),
    "E7-4809 V4": (8, 16),
    "E7-4820 V3": (10, 20),
    "E7-4820 V4": (10, 20),
    "E7-4830 V3": (12, 24),
    "E7-4830 V4": (14, 28),
    "E7-4850 V3": (14, 28),
    "E7-4850 V4": (16, 32),
    "E7-8860 V3": (16, 32),
    "E7-8860 V4": (18, 36),
    "E7-8870 V3": (18, 36),
    "E7-8870 V4": (20, 40),
    "E7-8880 V3": (18, 36),
    "E7-8880 V4": (22, 44),
    "E7-8890 V3": (18, 36),
    "E7-8890 V4": (24, 48),
}


def lookup_xeon_e5_e7_cores(model: str) -> Optional[Tuple[int, int]]:
    """Look up (cores_per_socket, threads_per_socket) for known Xeon E5/E7 v3/v4 CPUs."""
    if not model:
        return None
    m_clean = re.sub(r"\s+", " ", model.upper()).strip()
    for k, v in KNOWN_XEON_E5_E7_CORES.items():
        if k in m_clean:
            return v
    match = re.search(r"\b(E[57]-\d{4}[A-Z]?(?:\s*L)?)\s*(V[34])\b", m_clean)
    if match:
        key = f"{match.group(1)} {match.group(2)}"
        if key in KNOWN_XEON_E5_E7_CORES:
            return KNOWN_XEON_E5_E7_CORES[key]
    return None


def _parse_iso_datetime(dt_str: str) -> Optional[datetime]:
    if not dt_str or not isinstance(dt_str, str):
        return None
    s = dt_str.strip()
    if not s or s.upper() in ("UNKNOWN", "N/A", "NONE"):
        return None
    try:
        if s.endswith('Z') or s.endswith('z'):
            s = s[:-1] + '+00:00'
        if not re.search(r'[+-]\d{2}:?\d{2}$', s):
            s += '+00:00'
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        pass

    m = re.match(
        r'^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([+-]\d{2}):?(\d{2})|Z)?$',
        s, re.I
    )
    if m:
        try:
            year, month, day, hour, minute, second = map(int, m.groups()[:6])
            tz = timezone.utc
            if m.group(8) and m.group(9):
                tz_h = int(m.group(8))
                tz_m = int(m.group(9))
                if tz_h < 0:
                    tz_m = -tz_m
                tz = timezone(timedelta(hours=tz_h, minutes=tz_m))
            return datetime(year, month, day, hour, minute, second, tzinfo=tz)
        except (ValueError, TypeError):
            pass
    return None


def _extract_ntp_servers(net_proto: dict) -> list:
    servers = []
    def _add(s):
        if s is not None and isinstance(s, (str, int)):
            st = str(s).strip()
            if st and st.lower() not in ("none", "null", "0.0.0.0", "disabled", "false", "") and st not in servers:
                servers.append(st)

    if not isinstance(net_proto, dict):
        return servers

    ntp = net_proto.get("NTP") or {}
    if isinstance(ntp, dict):
        for key in ("NTPServers", "NetworkSuppliedServers", "StaticNTPServers", "Servers", "PrimaryNTP", "SecondaryNTP"):
            val = ntp.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        _add(item)
                    elif isinstance(item, dict):
                        _add(item.get("Address") or item.get("IPAddress") or item.get("Server") or item.get("HostName"))
            elif isinstance(val, (str, int)):
                _add(val)

        n_oem = ntp.get("Oem") or {}
        if isinstance(n_oem, dict):
            for v_val in n_oem.values():
                if isinstance(v_val, dict):
                    for k, v in v_val.items():
                        if isinstance(v, (str, int)) and ("ntp" in k.lower() or "server" in k.lower()):
                            _add(v)
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, (str, int)):
                                    _add(item)

    p_oem = net_proto.get("Oem") or {}
    if isinstance(p_oem, dict):
        for v_val in p_oem.values():
            if isinstance(v_val, dict):
                ntp_blk = v_val.get("NTP") or v_val.get("Ntp") or v_val.get("DellNetworkProtocol") or {}
                if isinstance(ntp_blk, dict):
                    for k, v in ntp_blk.items():
                        if isinstance(v, (str, int)) and ("ntp" in k.lower() or "server" in k.lower()):
                            _add(v)
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, (str, int)):
                                    _add(item)
    return servers


def _extract_dns_servers(net_proto: dict) -> list:
    servers = []
    def _add(s):
        if s is not None and isinstance(s, (str, int)):
            st = str(s).strip()
            if st and st.lower() not in ("none", "null", "0.0.0.0", "disabled", "false", "") and st not in servers:
                servers.append(st)

    if not isinstance(net_proto, dict):
        return servers

    dns = net_proto.get("DNS") or net_proto.get("Dns") or {}
    if isinstance(dns, dict):
        for key in ("NameServers", "StaticNameServers", "DomainNameServers", "Servers", "PrimaryDNS", "SecondaryDNS", "DNS"):
            val = dns.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        _add(item)
                    elif isinstance(item, dict):
                        _add(item.get("Address") or item.get("IPAddress") or item.get("Server") or item.get("HostName"))
            elif isinstance(val, (str, int)):
                _add(val)

        d_oem = dns.get("Oem") or {}
        if isinstance(d_oem, dict):
            for v_val in d_oem.values():
                if isinstance(v_val, dict):
                    for k, v in v_val.items():
                        if isinstance(v, (str, int)) and ("dns" in k.lower() or "nameserver" in k.lower() or "server" in k.lower()):
                            _add(v)
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, (str, int)):
                                    _add(item)

    p_oem = net_proto.get("Oem") or {}
    if isinstance(p_oem, dict):
        for v_val in p_oem.values():
            if isinstance(v_val, dict):
                dns_blk = v_val.get("DNS") or v_val.get("Dns") or v_val.get("DellNetworkProtocol") or {}
                if isinstance(dns_blk, dict):
                    for k, v in dns_blk.items():
                        if isinstance(v, (str, int)) and ("dns" in k.lower() or "nameserver" in k.lower() or "server" in k.lower()):
                            _add(v)
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, (str, int)):
                                    _add(item)
    return servers


def _extract_bmc_timezone_info(mgr_data: dict, bmc_dt_str: Optional[str] = None) -> dict:
    """Extract timezone offset, timezone name, and UTC compliance from BMC Manager data."""
    raw_offset = mgr_data.get("DateTimeLocalOffset") if isinstance(mgr_data, dict) else None
    tz_name = (mgr_data.get("TimeZone") or mgr_data.get("Timezone")) if isinstance(mgr_data, dict) else None

    offset_str = str(raw_offset).strip() if raw_offset is not None else ""
    if not offset_str and bmc_dt_str and isinstance(bmc_dt_str, str):
        s = bmc_dt_str.strip()
        if s.endswith(('Z', 'z')):
            offset_str = "+00:00"
        else:
            m = re.search(r'([+-]\d{2}:?\d{2})$', s)
            if m:
                offset_str = m.group(1)

    offset_minutes = 0
    is_utc = True
    if offset_str:
        m = re.match(r'^([+-])(\d{2}):?(\d{2})', offset_str)
        if m:
            sign = 1 if m.group(1) == '+' else -1
            hrs = int(m.group(2))
            mins = int(m.group(3))
            offset_minutes = sign * (hrs * 60 + mins)
            offset_str = f"{m.group(1)}{m.group(2)}:{m.group(3)}"
            is_utc = (offset_minutes == 0)
        elif offset_str in ("00:00", "0", "+0", "-0"):
            offset_str = "+00:00"
            is_utc = True

    if tz_name and isinstance(tz_name, str):
        tz_clean = tz_name.strip().upper()
        if tz_clean not in ("UTC", "GMT", "ETC/UTC", "ETC/GMT", "Z", ""):
            is_utc = False

    return {
        "offset_str": offset_str or ("+00:00" if is_utc else "Unknown"),
        "offset_minutes": offset_minutes,
        "is_utc": is_utc,
        "timezone_name": str(tz_name).strip() if tz_name else None,
    }


from vcf_hci.bios import (
    _detect_cpu_power_mode,
    _detect_memory_ras_modes,
    _detect_side_channel_settings,
)
from vcf_hci.constants import (
    DELL_MODEL_CHASSIS_DB,
    DELL_SKU_CHASSIS_DB,
    HCI_APPLIANCE_PATTERNS,
    HPE_SKU_CHASSIS_DB,
    LENOVO_MODEL_CHASSIS_DB,
)
from vcf_hci.logging_utils import get_nested


class _SystemMixin(_CollectorBase):
    """Collection methods: system summary, memory, BIOS, BMC, secure boot."""

    def _collect_enclosure_details(self) -> dict:
        """Inspect Chassis Links.ContainedBy or Enclosure Chassis for blade enclosure telemetry."""
        result = {
            "is_enclosure_contained": False,
            "enclosure_uri": "",
            "enclosure_name": "",
            "enclosure_model": "",
            "enclosure_serial": "",
            "enclosure_part_number": "",
            "tray_id": "",
            "node_power_watts": None,
            "chassis_power_watts": None,
            "chassis_input_power_watts": None,
        }
        enc_uri = None
        c1 = self._get(self.chassis_uri) if getattr(self, "chassis_uri", None) else {}
        if isinstance(c1, dict):
            c_links = c1.get("Links") or {}
            contained_by = c_links.get("ContainedBy")
            if isinstance(contained_by, dict) and contained_by.get("@odata.id"):
                enc_uri = contained_by.get("@odata.id")

        if not enc_uri:
            for cu in (getattr(self, "chassis_uris", None) or []):
                if cu and "enclosure" in cu.lower() and cu != getattr(self, "chassis_uri", None):
                    enc_uri = cu
                    break

        if not enc_uri:
            return result

        enc_data = self._get(enc_uri)
        if not isinstance(enc_data, dict) or enc_data.get("error"):
            # Try case-insensitive fallback if needed
            for cu in (getattr(self, "chassis_uris", None) or []):
                if cu.lower() == enc_uri.lower():
                    enc_data = self._get(cu)
                    if isinstance(enc_data, dict) and not enc_data.get("error"):
                        enc_uri = cu
                        break

        if not isinstance(enc_data, dict) or enc_data.get("error"):
            return result

        result["is_enclosure_contained"] = True
        result["enclosure_uri"] = enc_uri
        raw_name = str(enc_data.get("Name") or "").strip()
        pn = str(enc_data.get("PartNumber") or "").strip()
        sn = str(enc_data.get("SerialNumber") or (enc_data.get("Oem") or {}).get("Dell", {}).get("ServiceTag") or "").strip()
        model = str(enc_data.get("Model") or "").strip()

        # Known enclosure Part Numbers / Models
        if pn in ("P12783-001", "P12783-B21") or "e910" in raw_name.lower():
            if not raw_name or raw_name.lower() in ("computer system chassis", "chassis", "enclosure"):
                raw_name = "HPE Edgeline EL8000 5U Blade Infrastructure"
            if not model:
                model = "Edgeline EL8000"

        result["enclosure_name"] = raw_name or model or "Blade Enclosure"
        result["enclosure_model"] = model or raw_name
        result["enclosure_serial"] = sn
        result["enclosure_part_number"] = pn

        # OEM telemetry (HPE TrayID, Power)
        hpe_oem = (enc_data.get("Oem") or {}).get("Hpe") or {}
        if isinstance(hpe_oem, dict):
            result["tray_id"] = str(hpe_oem.get("TrayID") or "").strip()
            result["node_power_watts"] = hpe_oem.get("NodePowerWatts")
            result["chassis_power_watts"] = hpe_oem.get("ChassisPowerWatts")
            result["chassis_input_power_watts"] = hpe_oem.get("ChassisInputPowerWatts")

        return result

    def collect_system_summary(self) -> Optional[dict]:
        chassis_mgmt = getattr(self, "chassis_management_info", {}) or {}
        if not self.sys_uri:
            if chassis_mgmt and chassis_mgmt.get("is_modular_chassis"):
                dns_name = None
                try:
                    ipaddress.ip_address(self.host)
                    dns_name = socket.gethostbyaddr(self.host)[0]
                except (ValueError, socket.herror, socket.gaierror, OSError):
                    pass
                m_model = chassis_mgmt.get("chassis_model") or "Modular Server Chassis"
                m_vendor = chassis_mgmt.get("vendor") or "Modular Chassis"
                m_mgr_name = chassis_mgmt.get("chassis_manager_name") or "Enclosure Management Controller"
                return {
                    "ip": self.host,
                    "hostname": chassis_mgmt.get("enclosure_name") or self.host,
                    "dns_name": dns_name,
                    "vendor": m_vendor,
                    "model": f"{m_model} ({m_mgr_name})",
                    "sku": "",
                    "chassis_label": m_model,
                    "hci_appliance": False,
                    "serial_number": chassis_mgmt.get("chassis_serial") or "",
                    "bios_version": "N/A (Chassis Management Module)",
                    "bios_release_date": "N/A",
                    "bios_eval": {"badge": "<span class='badge info'>ℹ️ Chassis Management Module</span>", "verdict": "CHASSIS_MANAGER"},
                    "boot_mode": "N/A",
                    "boot_eval": {"badge": "<span class='badge info'>ℹ️ Chassis Manager</span>", "verdict": "N/A"},
                    "boot_target": "N/A",
                    "persistent_boot_target": "N/A",
                    "boot_order": [],
                    "boot_order_details": [],
                    "boot_override": {"is_active": False, "target": "None", "enabled": "Disabled", "mode": ""},
                    "total_memory_gb": 0,
                    "tpm_status_badge": "<span class='badge info'>ℹ️ Chassis Management Controller</span>",
                    "os_raw": {
                        "name": m_mgr_name,
                        "version": "",
                        "description": "Modular Enclosure Controller",
                        "source": "Chassis Manager",
                    },
                    "cpu_summary": {
                        "count": 0,
                        "core_count": "N/A",
                        "logical_count": "N/A",
                        "cores_per_socket": None,
                        "threads_per_socket": None,
                        "ht_enabled": None,
                        "base_freq_ghz": None,
                        "max_freq_ghz": None,
                        "model": f"Chassis Manager ({chassis_mgmt.get('sled_count', 0)} Sleds Managed)",
                        "architecture": "Chassis Management Controller",
                        "channels_per_socket": 0,
                        "max_ram_speed_mhz": 0,
                        "max_pcie_lanes_per_socket": 0,
                        "verdict": "Modular Chassis Enclosure (Compute Sleds Assessed Separately)",
                        "processor_id": None,
                        "cache_list": [],
                        "socket_label": "",
                        "processors": [],
                        "asymmetry_detected": False,
                        "asymmetry_note": None,
                    },
                    "chassis_management_info": chassis_mgmt,
                }
            return None
        data = self._get(self.sys_uri) or {}
        if not data:
            return None
        self.sys_data = data
        model = data.get("Model") or "Unknown Server"
        vendor = data.get("Manufacturer") or "Unknown Vendor"
        proc_summary = data.get("ProcessorSummary") or {}
        cpu_model = _normalize_cpu_summary_model(proc_summary.get("Model"))
        if cpu_model == "Unknown" and isinstance(data.get("Processors"), dict):
            p_fam = data["Processors"].get("ProcessorFamily") or data["Processors"].get("Model")
            if p_fam:
                cpu_model = _normalize_cpu_summary_model(p_fam)
        cpu_count = proc_summary.get("Count") or (data.get("Processors", {}).get("Count") if isinstance(data.get("Processors"), dict) else None) or 1
        cpu_verdict = ""
        arch_label = ""
        channels_per_socket = 8
        max_ram_speed_mhz = None
        max_pcie_lanes_per_socket = 0

        # ── Per-socket CPU specs from Processors collection ─────────────────────
        total_cores   = proc_summary.get("CoreCount")
        total_threads = proc_summary.get("LogicalProcessorCount")
        max_speed_mhz = None
        operating_speed_mhz = None
        per_socket_cores = None
        per_socket_threads = None
        processor_id_str = None
        cache_list: list = []
        socket_label: str = ""
        processors_list: list = []
        asymmetry_detected = False
        asymmetry_note = None

        if self.sys_uri:
            members = self._get_members(f"{self.sys_uri}/Processors")
            for _m in members:
                _mid = str(_m.get("@odata.id", ""))
                if re.search(r'/Video\.|/Accelerator\.|/GPU\.|\.GPU\.|\.Video\.', _mid, re.I):
                    self._has_gpu_processors = True
                    continue
                proc = self._get(_mid) or {}
                if not proc:
                    continue
                _ptype = str(proc.get("ProcessorType") or "").upper()
                if _ptype and _ptype not in ("CPU", "DSP", "OEM", ""):
                    if _ptype in ("GPU", "ACCELERATOR"):
                        self._has_gpu_processors = True
                    continue

                p_model = str(proc.get("Model") or "").strip()
                p_max_speed = proc.get("MaxSpeedMHz")
                p_op_speed = proc.get("OperatingSpeedMHz")
                p_cores = proc.get("TotalCores")
                p_threads = proc.get("TotalThreads")
                p_socket = str(proc.get("Socket", "") or "").strip()
                p_status = proc.get("Status") or {}
                p_state = str(p_status.get("State", "") or "").strip()
                p_health = str(p_status.get("Health", "") or "").strip()

                # ProcessorId — VCG/BCG CPU search helper
                _pid = proc.get("ProcessorId", {}) or {}
                _id_reg = _pid.get("IdentificationRegisters", "")
                _eff_fam = _pid.get("EffectiveFamily", "")
                _eff_mod = _pid.get("EffectiveModel", "")
                _step    = _pid.get("Step", "")
                p_proc_id_str = None
                if _id_reg:
                    p_proc_id_str = _id_reg.strip()
                elif _eff_fam or _eff_mod:
                    _parts = []
                    if _eff_fam:
                        _parts.append(f"Fam {_eff_fam}")
                    if _eff_mod:
                        _parts.append(f"Mod {_eff_mod}")
                    if _step:
                        _parts.append(f"Step {_step}")
                    p_proc_id_str = " · ".join(_parts)

                # Cache hierarchy — DMTF standard field with OEM hook fallback
                p_cache_list = []
                _cache_raw = proc.get("Cache") or self.oem_cpu_cache(proc) or []
                for _c in _cache_raw:
                    if not isinstance(_c, dict):
                        continue
                    _raw_kb = _c.get("CacheSize") or _c.get("MaximumSizeKB") or 0
                    try:
                        _raw_kb = int(_raw_kb)
                    except (TypeError, ValueError):
                        _raw_kb = 0
                    _size_mib = (
                        _c.get("CacheSizeMiB")
                        or _c.get("MaxCacheSizeMiB")
                        or (round(_raw_kb / 1024, 2) if _raw_kb else 0)
                    )
                    try:
                        _size_mib = float(_size_mib or 0)
                        if _size_mib.is_integer():
                            _size_mib = int(_size_mib)
                    except (TypeError, ValueError):
                        _size_mib = 0
                    p_cache_list.append({
                        "level": str(_c.get("CacheMemoryType") or _c.get("Name") or _c.get("Level") or "").strip(),
                        "size_mib": _size_mib,
                        "associativity": str(_c.get("Associativity") or "").strip(),
                    })

                processors_list.append({
                    "socket": p_socket,
                    "model": p_model,
                    "cores": p_cores,
                    "threads": p_threads,
                    "max_speed_mhz": p_max_speed,
                    "operating_speed_mhz": p_op_speed,
                    "health": p_health,
                    "state": p_state,
                    "processor_id": p_proc_id_str,
                    "cache_list": p_cache_list,
                })

            populated_procs = [
                p for p in processors_list
                if p.get("state", "").lower() != "absent" and (p.get("model") or p.get("cores") is not None)
            ]
            first_proc = populated_procs[0] if populated_procs else (processors_list[0] if processors_list else None)

            if first_proc:
                _fp_model = first_proc["model"]
                if _fp_model and _fp_model != cpu_model:
                    if (
                        cpu_model == "Unknown"
                        or re.search(r"\bprocessor\b", cpu_model, re.I)
                        or len(_fp_model) > len(cpu_model)
                    ):
                        cpu_model = _fp_model

                max_speed_mhz       = first_proc["max_speed_mhz"]
                operating_speed_mhz = first_proc["operating_speed_mhz"]
                per_socket_cores    = first_proc["cores"]
                per_socket_threads  = first_proc["threads"]
                socket_label        = first_proc["socket"]
                processor_id_str    = first_proc["processor_id"]
                cache_list          = first_proc["cache_list"]

            # If some sockets are absent and populated_procs reflects the actual installed CPUs,
            # align cpu_count to the populated count.
            if populated_procs and len(populated_procs) < (cpu_count or 1):
                cpu_count = len(populated_procs)

            if len(populated_procs) > 1:
                models_set = {p["model"].lower() for p in populated_procs if p.get("model")}
                cores_set = {p["cores"] for p in populated_procs if p.get("cores") is not None}
                max_speeds_set = {p["max_speed_mhz"] for p in populated_procs if p.get("max_speed_mhz") is not None}
                op_speeds_set = {p["operating_speed_mhz"] for p in populated_procs if p.get("operating_speed_mhz") is not None}
                states_set = {p["state"].lower() for p in populated_procs if p.get("state")}

                if (
                    len(models_set) > 1
                    or len(cores_set) > 1
                    or len(max_speeds_set) > 1
                    or len(op_speeds_set) > 1
                    or ("disabled" in states_set)
                ):
                    asymmetry_detected = True
                    asymmetry_note = "CPU socket asymmetry detected: mismatched processor model, core count, speed, or socket state."
                    if "Asymmetry" not in cpu_verdict:
                        cpu_verdict += " (⚠️ Socket Asymmetry Detected)"

        # Prefer per-socket values from Processors; fall back to dividing summary totals
        _safe_count = max(cpu_count or 1, 1)
        if not total_cores and not per_socket_cores:
            known_cores = lookup_xeon_e5_e7_cores(cpu_model)
            if known_cores:
                per_socket_cores, per_socket_threads = known_cores
                total_cores = per_socket_cores * _safe_count
                total_threads = per_socket_threads * _safe_count

        if not total_cores and per_socket_cores:
            total_cores = per_socket_cores * _safe_count
        if not total_threads and per_socket_threads:
            total_threads = per_socket_threads * _safe_count

        cores_ps   = per_socket_cores   or (total_cores   // _safe_count if total_cores   else None)
        threads_ps = per_socket_threads or (total_threads // _safe_count if total_threads else None)
        ht_enabled = (threads_ps // cores_ps >= 2) if (cores_ps and threads_ps) else None

        # Base frequency: prefer string in model name, then OperatingSpeedMHz
        _freq_m = re.search(r'@\s*([\d.]+)\s*GHz', cpu_model, re.I)
        base_freq_ghz = float(_freq_m.group(1)) if _freq_m else (
            round(operating_speed_mhz / 1000, 2) if operating_speed_mhz else None
        )
        max_freq_ghz = round(max_speed_mhz / 1000, 2) if max_speed_mhz else None

        trusted_modules = data.get("TrustedModules") or []
        tpm_state = "Disabled"
        if trusted_modules and isinstance(trusted_modules[0], dict):
            tpm_state = (trusted_modules[0].get("Status") or {}).get("State") or "Disabled"
        if tpm_state in ["Enabled", "EnabledAndActivated"]:
            tpm_badge = "<span class='badge success'>🟢 Enabled (TPM 2.0 Active)</span>"
        elif tpm_state in ["Absent", "NotPresent"]:
            tpm_badge = "<span class='badge danger'>🔴 Not Present (Hardware Missing)</span>"
        else:
            tpm_badge = f"<span class='badge warning'>🟡 {tpm_state} (Action Required)</span>"

        bios_version = data.get("BiosVersion", "Unknown")
        bios_date = self.oem_bios_date(data)

        # ── OS detection from OEM fields (requires host-side agent) ──────────
        # Dell iDRAC: iSM (iDRAC Service Module) must be installed on host OS.
        # HPE iLO: AMS (Agentless Management Service) must be running on host.
        # Cisco CIMC: Intersight Device Connector or host driver integration.
        _oem_blk  = data.get("Oem") or {}
        _dell_oem = _oem_blk.get("Dell") or {}
        _hpe_oem  = _oem_blk.get("Hpe") or {}
        _csc_oem  = _oem_blk.get("Cisco") or {}
        # Dell exposes OS info under Oem.Dell.DSI (iSM path) or Oem.Dell.DellSystem
        _dsi      = _dell_oem.get("DSI") or {}
        _dell_sys = _dell_oem.get("DellSystem") or {}
        _hpe_host_os = _hpe_oem.get("HostOS") or {}
        _csc_os_info = _csc_oem.get("OsInfo") or {}

        # Allow OEM hook to query vendor-specific OS endpoints (e.g. Dell $select attribute filtering)
        _oem_os = self.oem_os_info(data) if hasattr(self, "oem_os_info") else {}

        raw_os_name = str(
            _oem_os.get("name")
            or _dsi.get("OSName")
            or _dell_sys.get("OSName")
            or _hpe_host_os.get("OsName")
            or _csc_os_info.get("OSName")
            or data.get("OSName")
            or ""
        ).strip()
        raw_os_ver = str(
            _oem_os.get("version")
            or _dsi.get("OSVersion")
            or _dell_sys.get("OSVersion")
            or _hpe_host_os.get("OsVersion")
            or _csc_os_info.get("OSVersion")
            or data.get("OSVersion")
            or ""
        ).strip()
        # HPE AMS provides a richer description string (e.g. "Build 20348.2227")
        raw_os_desc = str(_oem_os.get("description") or _hpe_host_os.get("OsDescription") or "").strip()

        powered_on_sec = _oem_os.get("powered_on_seconds")
        uptime_days = _oem_os.get("uptime_days")
        uptime_human = _oem_os.get("uptime_human")

        if _oem_os.get("source"):
            os_src = _oem_os.get("source")
        elif _dsi.get("OSName"):
            os_src = "Dell iSM"
        elif _dell_sys.get("OSName"):
            os_src = "Dell OEM"
        elif _hpe_host_os.get("OsName"):
            os_src = "HPE AMS"
        elif _csc_os_info.get("OSName"):
            os_src = "Cisco OEM"
        elif data.get("OSName"):
            os_src = "Redfish"
        else:
            os_src = ""

        # Attempt reverse-DNS PTR lookup when the target is a bare IP address.
        # Silently skipped if the target is already an FQDN or if no PTR record exists.
        dns_name = None
        try:
            ipaddress.ip_address(self.host)
            dns_name = socket.gethostbyaddr(self.host)[0]
        except (ValueError, socket.herror, socket.gaierror, OSError):
            pass

        serial_num = str(data.get("SerialNumber", "Unknown")).strip()

        # Fallback for partitioned or scale-up systems where Model / Serial / Manufacturer are missing in Partition0
        chassis_candidates = []
        if getattr(self, "chassis_uri", None):
            chassis_candidates.append(self.chassis_uri)
        if getattr(self, "chassis_uris", None):
            for cu in self.chassis_uris:
                if cu not in chassis_candidates:
                    chassis_candidates.append(cu)

        if (model in ("Unknown Server", "", None) or vendor in ("Unknown Vendor", "", None) or serial_num in ("Unknown", "", None)) and chassis_candidates:
            for c_uri in chassis_candidates:
                c_obj = self._get(c_uri) or {}
                if model in ("Unknown Server", "", None):
                    c_model = c_obj.get("Model") or c_obj.get("Name")
                    if c_model and str(c_model).lower() not in ("chassis", "enclosure", "unknown"):
                        model = str(c_model).strip()
                if vendor in ("Unknown Vendor", "", None):
                    c_vendor = c_obj.get("Manufacturer") or c_obj.get("Vendor")
                    if c_vendor:
                        vendor = str(c_vendor).strip()
                if serial_num in ("Unknown", "", None):
                    c_sn = c_obj.get("SerialNumber")
                    if c_sn and str(c_sn).lower() not in ("unknown", "none", ""):
                        serial_num = str(c_sn).strip()
                if model not in ("Unknown Server", "", None) and vendor not in ("Unknown Vendor", "", None) and serial_num not in ("Unknown", "", None):
                    break

        # ── Server SKU / product number ───────────────────────────────────────
        # DMTF standard: System.SKU  |  HPE OEM fallback: Oem.Hpe.ProductId
        sku_raw = (
            self.oem_sku(data)
            or data.get("SKU")
            or ((data.get("Oem") or {}).get("Hpe") or {}).get("ProductId")
            or ""
        ).strip().upper()
        if sku_raw.upper() == serial_num.upper():
            sku_raw = ""
        self.sys_sku   = sku_raw
        self.sys_model = model

        # Chassis label — HPE/Dell: look up by SKU; Dell/Lenovo fallback: look up by model suffix
        _sku_db = HPE_SKU_CHASSIS_DB.get(sku_raw) or DELL_SKU_CHASSIS_DB.get(sku_raw)
        if _sku_db:
            chassis_label = _sku_db[1]
        else:
            _mkey = re.sub(r'^(?:PowerEdge|ProLiant|ThinkSystem)\s+', '', model, flags=re.I).upper().strip()
            _mkey = re.sub(r'[-]\d+$', '', _mkey)   # strip "-10" / "-24" XC variant suffixes
            _dell_db = DELL_MODEL_CHASSIS_DB.get(_mkey)
            if _dell_db:
                chassis_label = _dell_db[1]
            else:
                _lenovo_entry = LENOVO_MODEL_CHASSIS_DB.get(_mkey)
                if _lenovo_entry:
                    chassis_label = _lenovo_entry.get("label", f"ThinkSystem {_mkey} · {_lenovo_entry.get('form_factor', '')}")
                else:
                    chassis_label = ""

        # HCI appliance detection — iLO reports "ProLiant DX…"; iDRAC "XCxxx" / "VxRail Exxx"
        _model_vendor_str = f"{model} {vendor}".upper()
        hci_appliance = any(p.upper() in _model_vendor_str for p in HCI_APPLIANCE_PATTERNS)

        # Boot mode & boot target extraction
        boot_obj = data.get("Boot") or {}
        raw_boot_mode = str(boot_obj.get("BootSourceOverrideMode") or boot_obj.get("BootMode") or "").strip()
        boot_mode = raw_boot_mode or "Unknown"
        override_target = str(boot_obj.get("BootSourceOverrideTarget") or "").strip()
        override_enabled = str(boot_obj.get("BootSourceOverrideEnabled") or "Disabled").strip()
        override_mode = str(boot_obj.get("BootSourceOverrideMode") or raw_boot_mode or "").strip()

        is_override_active = (
            override_enabled.lower() not in ("disabled", "", "none", "null")
            and override_target.lower() not in ("none", "n/a", "", "null", "nonespecified")
        )
        boot_override = {
            "is_active": is_override_active,
            "target": override_target if is_override_active else "None",
            "enabled": override_enabled,
            "mode": override_mode,
        }

        boot_order = boot_obj.get("BootOrder") or []
        boot_order_details: List[Dict[str, Any]] = []
        persistent_boot_target = ""

        def _clean_boot_name(raw_name: str) -> str:
            cleaned = re.sub(r"^(?:Unavailable:\s*)+", "", str(raw_name or "").strip(), flags=re.I).strip()
            return cleaned or str(raw_name or "").strip()

        boot_opts_ref = boot_obj.get("BootOptions") or {}
        opts_uri = (
            boot_opts_ref.get("@odata.id")
            if isinstance(boot_opts_ref, dict) and boot_opts_ref.get("@odata.id")
            else f"{self.sys_uri}/BootOptions" if getattr(self, "sys_uri", None) else None
        )

        if opts_uri:
            clean_opts_uri = opts_uri.rstrip("/")
            members = self._get_members(opts_uri, limit=50)

            # Pre-index collection members by BootOptionReference, Id, and URI tail
            # so servers indexing BootOptions by number (e.g. /BootOptions/1 -> BootOptionReference: Boot0005)
            # resolve EFI BootOrder entries correctly.
            boot_opts_by_ref: Dict[str, Dict[str, Any]] = {}
            for m in members:
                m_uri = m.get("@odata.id") if isinstance(m, dict) else (m if isinstance(m, str) else None)
                if not m_uri:
                    continue
                if isinstance(m, dict) and len(m) > 2 and (m.get("DisplayName") or m.get("Name") or m.get("BootOptionReference")):
                    opt_data = m
                else:
                    opt_data = self._get(m_uri, critical=False)
                if not isinstance(opt_data, dict):
                    continue

                for k in [
                    str(opt_data.get("BootOptionReference") or "").strip(),
                    str(opt_data.get("Id") or "").strip(),
                    str(m_uri).rstrip("/").split("/")[-1].strip(),
                ]:
                    if k:
                        boot_opts_by_ref[k] = opt_data
                        boot_opts_by_ref[k.lower()] = opt_data
                        boot_opts_by_ref[k.upper()] = opt_data

            opt_ids_to_fetch = [str(x).strip() for x in boot_order if str(x).strip()] if isinstance(boot_order, list) else []
            if not opt_ids_to_fetch:
                for m in members:
                    if isinstance(m, dict):
                        m_uri = m.get("@odata.id") or ""
                        m_id = m.get("Id") or (m_uri.rstrip("/").split("/")[-1] if m_uri else None)
                        if m_id:
                            opt_ids_to_fetch.append(str(m_id))
                    elif isinstance(m, str) and m:
                        opt_ids_to_fetch.append(m.rstrip("/").split("/")[-1])

            target_cand = None
            for b_opt_id in opt_ids_to_fetch[:30]:
                opt_data = (
                    boot_opts_by_ref.get(b_opt_id)
                    or boot_opts_by_ref.get(b_opt_id.lower())
                    or boot_opts_by_ref.get(b_opt_id.upper())
                )
                if not opt_data:
                    item_uri = b_opt_id if b_opt_id.startswith("/") else f"{clean_opts_uri}/{b_opt_id}"
                    opt_data = self._get(item_uri, critical=False)
                if not isinstance(opt_data, dict):
                    continue
                is_enabled = opt_data.get("BootOptionEnabled") is not False
                raw_dname = opt_data.get("DisplayName") or opt_data.get("Name") or opt_data.get("Description") or b_opt_id
                clean_dname = _clean_boot_name(raw_dname)
                uefi_path = opt_data.get("UefiDevicePath") or ""
                opt_ref = opt_data.get("BootOptionReference") or opt_data.get("Id") or b_opt_id

                is_current = False
                if is_enabled and not target_cand:
                    target_cand = clean_dname
                    is_current = True

                boot_order_details.append({
                    "id": str(opt_ref),
                    "name": clean_dname,
                    "raw_name": str(raw_dname),
                    "enabled": is_enabled,
                    "uefi_path": str(uefi_path),
                    "is_current": is_current,
                })

            if target_cand:
                persistent_boot_target = target_cand

        if not persistent_boot_target:
            if override_target and override_target.lower() not in ("none", "n/a", "null", "nonespecified"):
                persistent_boot_target = _clean_boot_name(override_target)

        if is_override_active:
            boot_target = _clean_boot_name(override_target)
        elif persistent_boot_target:
            boot_target = persistent_boot_target
        else:
            raw_target = str(boot_obj.get("BootSourceOverrideTarget") or "N/A").strip()
            boot_target = _clean_boot_name(raw_target) if raw_target.lower() not in ("none", "n/a", "null", "nonespecified") else "None"

        # Infer UEFI boot mode if Redfish did not report explicit BootSourceOverrideMode/BootMode
        if not boot_mode or boot_mode.lower() in ("unknown", "none", "n/a"):
            has_uefi_entry = any(
                ("uefi" in str(b.get("uefi_path", "")).lower())
                or ("uefi" in str(b.get("name", "")).lower())
                or ("uefi" in str(b.get("raw_name", "")).lower())
                for b in boot_order_details
            )
            has_secure_boot = bool(data.get("SecureBoot"))
            if has_uefi_entry or has_secure_boot:
                boot_mode = "UEFI"

        enclosure_info = self._collect_enclosure_details()
        is_blade = bool(
            enclosure_info.get("is_enclosure_contained")
            or "e910" in str(model).lower()
            or "blade" in str(model).lower()
            or "sled" in str(model).lower()
        )
        if not chassis_label and enclosure_info.get("is_enclosure_contained"):
            chassis_label = f"Blade Sled · {enclosure_info.get('enclosure_name')}"
            if enclosure_info.get("tray_id"):
                chassis_label += f" (Tray {enclosure_info['tray_id']})"

        return {
            "ip": self.host,
            "hostname": data.get("HostName", self.host),
            "dns_name": dns_name,
            "vendor": vendor,
            "model": model,
            "sku": sku_raw,
            "chassis_label": chassis_label,
            "is_blade": is_blade,
            "enclosure_info": enclosure_info,
            "hci_appliance": hci_appliance,
            "chassis_management_info": chassis_mgmt,
            "serial_number": serial_num,
            "system_uuid": str(data.get("UUID") or "").strip(),
            "bios_version": bios_version,
            "bios_release_date": bios_date,
            "bios_eval": {},
            "raw_boot_mode": raw_boot_mode,
            "boot_mode": boot_mode,
            "boot_eval": {},
            "boot_target": boot_target,
            "persistent_boot_target": persistent_boot_target,
            "boot_order": boot_order,
            "boot_order_details": boot_order_details,
            "boot_override": boot_override,
            "total_memory_gb": (
                (data.get("MemorySummary") or {}).get("TotalSystemMemoryGiB")
                or (round(((data.get("MemorySummary") or {}).get("TotalSystemMemoryKiB") or 0) / 1048576) if (data.get("MemorySummary") or {}).get("TotalSystemMemoryKiB") else 0)
                or (round(((data.get("MemorySummary") or {}).get("TotalSystemMemoryMiB") or 0) / 1024) if (data.get("MemorySummary") or {}).get("TotalSystemMemoryMiB") else 0)
                or 0
            ),
            "tpm_status_badge": tpm_badge,
            "os_raw": {
                "name":               raw_os_name,
                "version":            raw_os_ver,
                "description":        raw_os_desc,
                "source":             os_src,
                "powered_on_seconds": powered_on_sec,
                "uptime_days":        uptime_days,
                "uptime_human":       uptime_human,
            },
            "cpu_summary": {
                "count":             cpu_count,
                "core_count":        total_cores   if total_cores is not None else 0,
                "logical_count":     total_threads if total_threads is not None else 0,
                "cores_per_socket":  cores_ps      if cores_ps is not None else 0,
                "threads_per_socket": threads_ps   if threads_ps is not None else 0,
                "ht_enabled":        ht_enabled,
                "base_freq_ghz":     base_freq_ghz,
                "max_freq_ghz":      max_freq_ghz,
                "model":             cpu_model,
                "architecture":      arch_label,
                "channels_per_socket": channels_per_socket,
                "max_ram_speed_mhz": max_ram_speed_mhz,
                "max_pcie_lanes_per_socket": max_pcie_lanes_per_socket,
                "verdict":           cpu_verdict,
                "processor_id":      processor_id_str,
                "cache_list":        cache_list,
                "socket_label":      socket_label,
                "processors":        processors_list,
                "asymmetry_detected": asymmetry_detected,
                "asymmetry_note":    asymmetry_note,
            },
        }


    def collect_memory_details(self, cpu_count: int, channels_per_socket: int) -> dict:
        empty = {"total_dimms_populated": 0, "dimm_size_breakdown": {}, "active_channels_count": 0, "expected_channels_total": 0, "channel_display": "Unknown", "low_dimm_warning": False, "failed_dimms": [], "dimm_list": []}
        if not self.sys_uri:
            return empty
        active_channels, dimm_sizes, total_dimms = set(), {}, 0
        failed_dimms = []
        dimm_list = []
        expected = cpu_count * channels_per_socket
        mem_uri = f"{self.sys_uri}/Memory"
        fetch_expand_fn = getattr(self, "_fetch_expanded_collection", None)
        if callable(fetch_expand_fn) and getattr(self, "expand_supported", False):
            mem_coll = fetch_expand_fn(mem_uri)
            mem_members = self._get_members(mem_coll) if mem_coll else []
        else:
            mem_members = self._get_members(mem_uri)
        if not mem_members:
            sys_obj = getattr(self, "sys_data", {}) or {}
            mem_href = (
                get_nested(sys_obj, "Oem", "Hp", "links", "Memory", "href")
                or get_nested(sys_obj, "Oem", "Hpe", "links", "Memory", "href")
            )
            if mem_href:
                if callable(fetch_expand_fn) and getattr(self, "expand_supported", False):
                    mem_coll = fetch_expand_fn(mem_href)
                    mem_members = self._get_members(mem_coll) if mem_coll else []
                else:
                    mem_members = self._get_members(mem_href)
        total_slots = len(mem_members)

        # Concurrently fetch DIMM details via sub-threadpool
        dimm_uris = []
        dimm_jsons = []
        for m in mem_members:
            m_uri = m.get("@odata.id") if isinstance(m, dict) else (m if isinstance(m, str) else "")
            if isinstance(m, dict) and (m.get("CapacityMiB") is not None or m.get("DeviceLocator") or m.get("MemoryDeviceType") or len(m) > 2):
                dimm_jsons.append(m)
            elif m_uri and hasattr(self, "_request_cache") and m_uri in self._request_cache:
                cached_dimm = self._request_cache[m_uri]
                if isinstance(cached_dimm, dict) and len(cached_dimm) > 1:
                    dimm_jsons.append(cached_dimm)
                else:
                    dimm_uris.append(m_uri)
            elif m_uri:
                dimm_uris.append(m_uri)

        if dimm_uris:
            max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(3), len(dimm_uris))
            _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
            pool = ThreadPoolExecutor(max_workers=max_w)
            try:
                futures = [pool.submit(_wrap_task(self._get), uri) for uri in dimm_uris]
                wait(futures, timeout=15.0)
                for f in futures:
                    if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                        break
                    try:
                        if f.done():
                            res = f.result()
                            if res:
                                dimm_jsons.append(res)
                    except Exception as exc:
                        logger.debug(f"Error fetching DIMM URI: {exc}")
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

        for dimm in dimm_jsons:
            status = dimm.get("Status")
            if not isinstance(status, dict):
                status = {}
            raw_state = status.get("State")
            state = str(raw_state).strip() if raw_state is not None else ""
            raw_health = status.get("Health")
            health = str(raw_health).strip() if raw_health is not None else "OK"
            slot = str(dimm.get("DeviceLocator") or dimm.get("Id") or "Unknown")
            cap_mib = int(dimm.get("CapacityMiB") or 0)

            is_populated = cap_mib > 0 and (state in ("Enabled", "OK", "StandbyOnline", "Unknown", "") or raw_state is None) and health.upper() not in ("CRITICAL", "FAILED")

            if is_populated:
                total_dimms += 1
                cap_gb = cap_mib // 1024
                label = f"{cap_gb} GB {dimm.get('MemoryType', 'DRAM')}"
                dimm_sizes[label] = dimm_sizes.get(label, 0) + 1

                mem_loc = dimm.get("MemoryLocation") or {}
                ml_socket = mem_loc.get("Socket")
                ml_channel = mem_loc.get("Channel")

                loc = str(dimm.get("DeviceLocator") or dimm.get("Id") or "").upper().strip()
                parsed_sock = None
                parsed_chan = None

                # Socket detection — three patterns in priority order:
                #
                # P1: Named CPU/PROC/SOCKET prefix (HPE "PROC 1 DIMM 1A",
                #     Lenovo "CPU1_DIMM_A1", Cisco "CPU2_DIMM_D2")
                #     Use [._\s-] delimiter instead of \b so "CPU2_" (underscore) works.
                m_named = re.search(r"(?:PROC|CPU|SOCKET)[._\s-]*([1-4])(?:[._\s-]|$)", loc)
                if m_named:
                    parsed_sock = int(m_named.group(1))
                else:
                    # P2: Standalone "P{N}" prefix (Supermicro "P1-DIMMA1", "P1_DIMM_A1";
                    #     Cisco inverted "DIMM_P2_B1") — must be bounded by delimiters.
                    m_pnum = re.search(r"(?:^|[._\s-])P([1-4])(?:[._\s-])", loc)
                    if m_pnum:
                        parsed_sock = int(m_pnum.group(1))

                # Channel detection — depends on which socket pattern fired:
                if parsed_sock is not None:
                    m_cpu = m_named or m_pnum
                    # Style A: letter immediately after DIMM keyword
                    #   Lenovo/Cisco "CPU1_DIMM_A1", Supermicro "P1-DIMMA1"
                    #   No \b before DIMM — underscore is \w so word-boundary fails on _DIMM_
                    m_ch = re.search(r"DIMM[_\s]*([A-L])(?:\d|\b)", loc)
                    if m_ch:
                        parsed_chan = m_ch.group(1)
                    else:
                        # Style B: digit precedes channel letter — HPE iLO4 "PROC 1 DIMM 1A"
                        m_ch = re.search(r"\b\d+([A-L])\b", loc)
                        if m_ch:
                            parsed_chan = m_ch.group(1)
                        else:
                            # Style C: Cisco "DIMM_P2_B1" — letter after the P{N} block
                            if m_cpu:
                                rest = loc[m_cpu.end():]
                                m_ch = re.search(r"\b([A-L])\d?\b", rest)
                                if m_ch:
                                    parsed_chan = m_ch.group(1)
                else:
                    # P3: Dell iDRAC — "DIMM A1", "DIMM B4" — space-separated, no CPU prefix.
                    #   Socket letter: A=1, B=2, C=3, D=4.
                    #   Slot number maps sequentially across channels within that socket.
                    #   Guard: only fire when there is no preceding CPU/P qualifier.
                    m_dell = re.search(r"\bDIMM\s+([A-D])\s*(\d+)\b", loc)
                    if m_dell:
                        parsed_sock = ord(m_dell.group(1)) - ord('A') + 1
                        slot_num = int(m_dell.group(2))
                        parsed_chan = chr(ord('A') + (slot_num - 1) % max(1, channels_per_socket))

                # Last resort: any standalone channel letter A-L in the string
                if parsed_chan is None:
                    m_ch = re.search(r"\b([A-L])\d?\b", loc)
                    if m_ch:
                        parsed_chan = m_ch.group(1)

                if ml_socket is not None:
                    final_sock = int(ml_socket)
                elif parsed_sock is not None:
                    final_sock = parsed_sock
                else:
                    final_sock = 1

                if ml_channel is not None:
                    if isinstance(ml_channel, int):
                        final_chan = chr(ord('A') + (ml_channel % max(1, channels_per_socket)))
                    else:
                        final_chan = str(ml_channel).strip().upper()
                elif parsed_chan is not None:
                    final_chan = parsed_chan
                else:
                    raw_slot = mem_loc.get("Slot")
                    if raw_slot is None and loc.isdigit():
                        raw_slot = int(loc)
                    if isinstance(raw_slot, int) and raw_slot > 0 and channels_per_socket > 0:
                        # Map numeric slots (e.g. 1..32 on dual-socket Lenovo ThinkSystem SR650 V4)
                        # Dual-rank / 2-DPC layouts with 16 slots per socket and 8 channels:
                        # S1 pairs (1,2)->A, (3,4)->B, (5,6)->C, (7,8)->D, (9,10)->E, (11,12)->F, (13,14)->G, (15,16)->H
                        # S2 pairs (17,18)->A, (19,20)->B, ... (31,32)->H
                        slot_in_sock = (raw_slot - 1) % (channels_per_socket * 2)
                        chan_idx = slot_in_sock // 2
                        final_chan = chr(ord('A') + (chan_idx % channels_per_socket))
                    else:
                        final_chan = "A"

                active_channels.add(f"S{final_sock}-Ch{final_chan}")

                operating_spd = int(dimm.get("OperatingSpeedMhz") or dimm.get("ConfiguredSpeedMhz") or 0)
                _allowed = [s for s in (dimm.get("AllowedSpeedsMHz") or [])
                            if isinstance(s, (int, float)) and s > 0]
                rated_spd = int(max(_allowed)) if _allowed else operating_spd
                if not operating_spd:
                    operating_spd = rated_spd

                _part_number = str(dimm.get("PartNumber") or "N/A").strip()
                _serial_number = str(
                    dimm.get("SerialNumber")
                    or get_nested(dimm, "Oem", "Dell", "DellMemory", "SerialNumber")
                    or get_nested(dimm, "Oem", "Hpe", "SerialNumber")
                    or ""
                ).strip()

                metrics_raw = dimm.get("Metrics")
                correctable_ecc = None
                uncorrectable_ecc = None
                if isinstance(metrics_raw, dict):
                    correctable_ecc = metrics_raw.get("CorrectableECCErrorCount")
                    uncorrectable_ecc = metrics_raw.get("UncorrectableECCErrorCount")
                elif isinstance(metrics_raw, str) and metrics_raw:
                    m_data = self._get(metrics_raw) or {}
                    correctable_ecc = m_data.get("CorrectableECCErrorCount")
                    uncorrectable_ecc = m_data.get("UncorrectableECCErrorCount")
                if correctable_ecc is None:
                    dell_mem = ((dimm.get("Oem") or {}).get("Dell") or {}).get("DellMemory") or {}
                    correctable_ecc = dell_mem.get("CorrectableECCErrorCount")
                    uncorrectable_ecc = dell_mem.get("UncorrectableECCErrorCount")

                # High ECC error count flag
                if (correctable_ecc and isinstance(correctable_ecc, (int, float)) and correctable_ecc > 100) or \
                   (uncorrectable_ecc and isinstance(uncorrectable_ecc, (int, float)) and uncorrectable_ecc > 0):
                    if health in ("OK", "Ok", ""):
                        health = "Warning"

                dimm_list.append({
                    "slot": slot,
                    "capacity_gb": cap_gb,
                    "type": dimm.get("MemoryType", "DRAM"),
                    "speed_mhz": operating_spd,
                    "max_speed_mhz": rated_spd,
                    "manufacturer": str(dimm.get("Manufacturer") or "Unknown").strip(),
                    "part_number": _part_number,
                    "serial_number": _serial_number,
                    "socket": final_sock,
                    "channel": final_chan,
                    "slot_num": mem_loc.get("Slot"),
                    "state": state if state else "Enabled",
                    "health": health if health else "OK",
                    "correctable_ecc": correctable_ecc,
                    "uncorrectable_ecc": uncorrectable_ecc,
                })

                if health not in ("OK", "Ok", ""):
                    failed_dimms.append({
                        "slot": slot, "state": state or "Enabled", "health": health,
                        "part_number": _part_number,
                        "serial_number": _serial_number,
                    })
            elif state not in ("Absent", ""):
                _failed_sn = str(
                    dimm.get("SerialNumber")
                    or get_nested(dimm, "Oem", "Dell", "DellMemory", "SerialNumber")
                    or get_nested(dimm, "Oem", "Hpe", "SerialNumber")
                    or ""
                ).strip()
                failed_dimms.append({
                    "slot": slot, "state": state or "Unknown", "health": health,
                    "part_number": str(dimm.get("PartNumber") or "N/A").strip(),
                    "serial_number": _failed_sn,
                })
        active_chan = len(active_channels) if active_channels else (total_dimms // 2 if total_dimms > 0 else 1)
        return {
            "total_dimms_populated": total_dimms,
            "slot_count": total_slots,
            "dimm_size_breakdown": dimm_sizes,
            "active_channels_count": active_chan,
            "expected_channels_total": expected,
            "channel_display": f"{total_dimms} DIMMs across {active_chan} Active Channel(s)",
            "low_dimm_warning": total_dimms <= 2,
            "failed_dimms": failed_dimms,
            "dimm_list": dimm_list,
        }


    def collect_bmc_license(self) -> dict:
        """Detect BMC license tier and surface any restrictions on data collection.

        Vendors covered and what their licensing means for this tool:

          Dell iDRAC    — all inventory accessible at every iDRAC tier;
                          Enterprise/Datacenter adds KVM + virtual media only
          HPE iLO       — Standard tier provides full inventory; Advanced adds
                          KVM, Federation, Directory auth, power regulation
          Lenovo XCC    — Standard provides full inventory; Advanced/Enterprise
                          add remote console, virtual media, LXCA integration
          Supermicro    — DCMS (SFT-DCMS-SINGLE) can gate Storage + Network
                          collection; probed live so a Quick run warns first
          Cisco IMC     — no inventory license gate; Intersight management
                          requires a separate Intersight licence
          Intel BMC /
          others        — generic LicenseService fallback
        """
        result = {"license_name": "N/A", "badge": "", "vendor_note": ""}
        if not self.mgr_uri:
            return result
        mgr_data = self._get(self.mgr_uri) or {}
        sys_data = (self._get(self.sys_uri) if self.sys_uri else {}) or {}

        # ── Dispatch to OEM hook method ────────────────────────────────────
        oem_lic = self.oem_license_info(mgr_data, sys_data)
        if oem_lic and oem_lic.get("license_name") != "N/A":
            return oem_lic

        mgr_oem = mgr_data.get("Oem", {})
        sys_oem = (sys_data or {}).get("Oem", {})
        vendor_up = str((sys_data or {}).get("Manufacturer", "")).upper()

        # ── HPE iLO ────────────────────────────────────────────────────────
        ilo_license = (mgr_oem.get("Hpe") or {}).get("License") or {}
        if ilo_license:
            tier = ilo_license.get("LicenseType") or ilo_license.get("License", "Standard")
            result["license_name"] = tier
            tier_low = str(tier).lower()
            if "advanced" in tier_low or "essentials" in tier_low:
                result["badge"] = f"<span class='badge success'>🟢 HPE iLO {tier}</span>"
                result["vendor_note"] = (
                    "iLO Advanced enables KVM remote console, Federation, Directory "
                    "authentication, and advanced power regulation. All hardware inventory "
                    "in this report is available at the Standard tier."
                )
            elif "expired" in tier_low:
                # iLO reports "Expired" specifically when a license WAS installed
                # but the subscription or trial period has since lapsed.
                result["license_name"] = "iLO Advanced — License expired"
                result["badge"] = (
                    "<span class='badge warning'>🟡 HPE iLO Advanced — License expired</span>"
                )
                result["vendor_note"] = (
                    "An iLO Advanced license was previously installed but has expired. "
                    "Hardware inventory (Storage, Memory, NICs, Thermal, PSU) remains fully "
                    "accessible. Performance telemetry (CPU/memory/PCIe utilisation metrics), "
                    "KVM remote console, Federation, and Directory auth are unavailable until "
                    "the license is renewed."
                )
            elif tier_low in ("unlicensed", "", "none"):
                result["license_name"] = "iLO — No activation key"
                result["badge"] = (
                    "<span class='badge warning'>🟡 HPE iLO — No activation key installed</span>"
                )
                result["vendor_note"] = (
                    "No iLO Advanced license key is installed. "
                    "Hardware inventory (Storage, Memory, NICs, Thermal, PSU) is fully "
                    "accessible at the base tier. Performance telemetry (TelemetryService — "
                    "CPU/memory/PCIe utilisation metrics), KVM remote console, Federation, "
                    "and Directory auth require an iLO Advanced license."
                )
            else:
                result["badge"] = f"<span class='badge warning'>🟡 HPE iLO {tier}</span>"
                result["vendor_note"] = (
                    "iLO Standard: hardware inventory (Storage, Memory, NICs, Thermal, "
                    "PSU) is fully accessible. Upgrade to iLO Advanced to enable KVM "
                    "remote console, Federation, Directory auth, performance telemetry "
                    "(CPU/memory/PCIe utilisation), and detailed power regulation."
                )
            return result

        # ── Dell iDRAC ─────────────────────────────────────────────────────
        if "Dell" in mgr_oem or "DELL" in vendor_up:
            mgr_name = str(mgr_data.get("Name", "") or mgr_data.get("Model", "")).upper()
            if "ENTERPRISE" in mgr_name or "DATACENTER" in mgr_name:
                tier, cls, icon = "Enterprise", "success", "🟢"
            elif "EXPRESS" in mgr_name or "BASIC" in mgr_name:
                tier, cls, icon = "Express", "warning", "🟡"
            else:
                tier, cls, icon = "iDRAC", "info", "ℹ️"
            result["license_name"] = f"Dell {tier}"
            result["badge"] = f"<span class='badge {cls}'>{icon} Dell {tier}</span>"
            result["vendor_note"] = (
                "All hardware inventory (Storage, Memory, NICs, Thermal, PSU) is "
                "fully accessible at every iDRAC license tier. iDRAC Enterprise / "
                "Datacenter adds remote KVM console, virtual media, and advanced "
                "configuration management."
            )
            return result

        # ── Cisco IMC ──────────────────────────────────────────────────────
        if self.mgr_uri.endswith("/CIMC") or "CISCO" in vendor_up:
            result["license_name"] = "Cisco IMC"
            result["badge"] = (
                "<span class='badge success'>🟢 Cisco IMC — no inventory license required</span>"
            )
            result["vendor_note"] = (
                "Cisco IMC provides full Redfish inventory access without additional "
                "licensing. Centralised management via Cisco Intersight requires a "
                "separate Intersight Infrastructure Service license."
            )
            return result

        # ── Supermicro ─────────────────────────────────────────────────────
        if "Supermicro" in sys_oem or "SUPERMICRO" in vendor_up:
            # Probe the Storage collection now (Quick run skips it) so an SE
            # knows DCMS is missing before committing to a full run.
            lic_msg = None
            if self.sys_uri:
                storage_coll = self._get(f"{self.sys_uri}/Storage") or {}
                lic_msg = self._is_license_blocked(storage_coll)
            if lic_msg:
                result["license_name"] = "Supermicro (DCMS required)"
                result["badge"] = (
                    "<span class='badge danger'>🔴 Supermicro DCMS License Required</span>"
                )
                result["vendor_note"] = (
                    "Storage and network adapter inventory require the "
                    "SFT-DCMS-SINGLE (DataCenter Management Suite) license. "
                    "System info, BIOS version, and event log are accessible "
                    "without DCMS. Purchase SFT-DCMS-SINGLE and activate it via "
                    "the BMC web interface or Supermicro Update Manager (SUM) "
                    "to enable full inventory collection."
                )
            else:
                result["license_name"] = "Supermicro (DCMS / OOB)"
                result["badge"] = (
                    "<span class='badge success'>🟢 Supermicro — Redfish access OK</span>"
                )
                result["vendor_note"] = (
                    "Basic inventory is accessible. If storage or network data is "
                    "missing, the SFT-DCMS-SINGLE license (DataCenter Management "
                    "Suite) may be required on older firmware versions."
                )
            return result

        # ── Lenovo XCC / XCC2 / XCC3 ───────────────────────────────────────
        xcc_tier_ids = {
            "XCC_Enterprised":  ("Enterprise", 3),
            "XCC_Advanced":     ("Advanced",   2),
            "XCC2_Platinum":    ("Platinum",   3),
            "BMC_Premier":      ("Premier",    3),
        }
        lic_svc = self._get("/redfish/v1/LicenseService/Licenses", timeout=5) or {}
        if lic_svc.get("Members") is not None:
            best_tier, best_rank = "Standard", 1
            for member in self._get_members(lic_svc):
                lic_id = str(member.get("@odata.id", "")).split("/")[-1]
                lic_detail = self._get(member.get("@odata.id"), timeout=5) or {}
                state = (lic_detail.get("Status") or {}).get("State", "")
                if state not in ("Enabled", ""):
                    continue
                if lic_id in xcc_tier_ids:
                    name, rank = xcc_tier_ids[lic_id]
                    if rank > best_rank:
                        best_tier, best_rank = name, rank
            result["license_name"] = f"XCC {best_tier}"
            if best_rank >= 3:
                result["badge"] = (
                    f"<span class='badge success'>"
                    f"🟢 XCC {best_tier} (full telemetry enabled)</span>"
                )
            elif best_rank == 2:
                result["badge"] = (
                    f"<span class='badge success'>🟢 XCC {best_tier}</span>"
                )
                result["vendor_note"] = (
                    "XCC Advanced installed. Remote console and OS deployment "
                    "via LXCA also require XCC Enterprise."
                )
            else:
                result["badge"] = (
                    "<span class='badge warning'>"
                    "🟡 XCC Standard (Advanced / Enterprise upgrade available)</span>"
                )
                result["vendor_note"] = (
                    "Hardware inventory is fully accessible at Standard tier. "
                    "Remote console, virtual media, and OS deployment via LXCA "
                    "require XCC Advanced + Enterprise upgrades."
                )
            return result

        # ── Generic LicenseService fallback ────────────────────────────────
        lic_ep = (mgr_data.get("Links") or {}).get("LicenseService") or {}
        if isinstance(lic_ep, dict) and lic_ep.get("@odata.id"):
            lic_data = self._get(lic_ep["@odata.id"]) or {}
            tier = lic_data.get("Name") or lic_data.get("LicenseType", "")
            if tier:
                result["license_name"] = tier
                result["badge"] = f"<span class='badge info'>ℹ️ License: {tier}</span>"
        return result


    def check_bios_attributes(self) -> dict:
        if not self.sys_uri:
            return {
                "attributes": {},
                "normalized_attributes": {},
                "vmd_keys_found": {},
                "vmd_enabled_flag": False,
                "vmd_pending_flag": None,
                "pending_vmd_keys": {},
                "pending_attributes": {},
                "bios_pending_reboot": False,
                "memory_ras": [],
                "cpu_power": [],
                "side_channel": [],
            }
        bios_data = self._get(f"{self.sys_uri}/Bios") or {}
        attrs = bios_data.get("Attributes")
        if not isinstance(attrs, dict) or not attrs:
            oem_attrs = self.oem_extract_bios_attributes(bios_data) if hasattr(self, "oem_extract_bios_attributes") else {}
            attrs = oem_attrs if isinstance(oem_attrs, dict) else {}
            if not attrs and isinstance(bios_data, dict):
                # Flat attributes fallback (e.g. HPE iLO 4 / Gen9)
                attrs = {
                    k: v for k, v in bios_data.items()
                    if not k.startswith("@") and k not in (
                        "Id", "Name", "Description", "Type", "Actions", "Links", "links", "Oem", "Status", "Members", "attribute_count"
                    ) and isinstance(v, (str, int, float, bool))
                }
        else:
            attrs = dict(attrs)
        found = {}
        for key, val in attrs.items():
            if any(s in key.lower() for s in ["vmd", "vroc", "nvmeraid", "nvme_raid"]):
                found[key] = val
        enabled = any(str(v).lower() in ["enabled", "true", "auto", "1"] for v in found.values())

        # Check for pending BIOS settings (@Redfish.Settings)
        settings_info = bios_data.get("@Redfish.Settings")
        settings_uri = None
        if isinstance(settings_info, dict):
            settings_obj = settings_info.get("SettingsObject")
            if isinstance(settings_obj, dict):
                settings_uri = settings_obj.get("@odata.id")
            elif "@odata.id" in settings_info:
                settings_uri = settings_info.get("@odata.id")
        if not settings_uri and "@Redfish.Settings" in bios_data:
            settings_uri = f"{self.sys_uri}/Bios/Settings"

        pending_data = self._get(settings_uri) if settings_uri else None
        pending_attrs = pending_data.get("Attributes") if isinstance(pending_data, dict) else {}
        if not pending_attrs and isinstance(pending_data, dict):
            pending_attrs = {
                k: v for k, v in pending_data.items()
                if not k.startswith("@") and k not in (
                    "Id", "Name", "Description", "Type", "Actions", "Links", "links", "Oem", "Status", "Members", "attribute_count"
                ) and isinstance(v, (str, int, float, bool))
            }
        pending_attrs = pending_attrs if isinstance(pending_attrs, dict) else {}

        bios_pending_reboot = False
        vmd_pending_flag = None
        pending_found = {}

        if pending_attrs:
            for k, v in pending_attrs.items():
                if k not in attrs or attrs.get(k) != v:
                    bios_pending_reboot = True
                    break

            for key, val in pending_attrs.items():
                if any(s in key.lower() for s in ["vmd", "vroc", "nvmeraid", "nvme_raid"]):
                    pending_found[key] = val

            if pending_found:
                vmd_pending_flag = any(str(v).lower() in ["enabled", "true", "auto", "1"] for v in pending_found.values())

        v_oem = getattr(self, "vendor", None)
        if not v_oem and hasattr(self, "VENDOR_MATCH") and self.VENDOR_MATCH:
            v_oem = str(self.VENDOR_MATCH[0]).lower()
        sys_sum = getattr(self, "sys_summary", {}) or {}
        if not v_oem and sys_sum.get("vendor"):
            v_oem = str(sys_sum["vendor"]).lower()
        c_arch = (sys_sum.get("cpu_summary") or {}).get("architecture")

        normalized_attrs = self.oem_normalize_bios_attributes(attrs) if hasattr(self, "oem_normalize_bios_attributes") else {}
        if not isinstance(normalized_attrs, dict):
            normalized_attrs = {}

        return {
            "attributes": attrs,
            "normalized_attributes": normalized_attrs,
            "vmd_keys_found": found,
            "vmd_enabled_flag": enabled,
            "vmd_pending_flag": vmd_pending_flag,
            "pending_vmd_keys": pending_found,
            "pending_attributes": pending_attrs,
            "bios_pending_reboot": bios_pending_reboot,
            "memory_ras": _detect_memory_ras_modes(attrs, vendor=v_oem, architecture=c_arch),
            "cpu_power":  _detect_cpu_power_mode(attrs, vendor=v_oem, architecture=c_arch),
            "side_channel": _detect_side_channel_settings(attrs),
        }


    def collect_secure_boot_redfish(self) -> dict:
        """Retrieve Secure Boot status from the DMTF standard /Systems/{id}/SecureBoot endpoint.

        Supported by Dell iDRAC 9, HPE iLO 5/6, Lenovo XCC, Cisco IMC.
        Falls back gracefully (info badge) when the endpoint is absent or the BMC
        firmware is too old to expose it.
        """
        empty = {"enabled": None, "current_boot": None, "badge": "<span class='badge info'>ℹ️ Secure Boot: Not Exposed</span>"}
        if not self.sys_uri:
            return empty
        sb = self._get(f"{self.sys_uri}/SecureBoot") or {}
        if not sb or sb.get("error"):
            return empty
        enabled = sb.get("SecureBootEnable")
        current_boot = sb.get("SecureBootCurrentBoot")
        if enabled is True and current_boot is True:
            badge = "<span class='badge success'>🟢 Secure Boot: Enabled &amp; Active</span>"
        elif enabled is True and current_boot is False:
            badge = "<span class='badge warning'>🟡 Secure Boot: Enabled but Inactive Last Boot — check DB/MOK keys</span>"
        elif enabled is True and current_boot is None:
            badge = "<span class='badge success'>🟢 Secure Boot: Enabled</span>"
        elif enabled is False:
            badge = "<span class='badge warning'>🟡 Secure Boot: Disabled — enable for VCF 9.1 security baseline</span>"
        else:
            badge = "<span class='badge info'>ℹ️ Secure Boot: Unknown (check BMC firmware)</span>"
        return {"enabled": enabled, "current_boot": current_boot, "badge": badge}


    def collect_bmc_firmware(self) -> dict:
        """Read BMC/management-controller firmware version from /Managers/{id}.

        Returns 'bmc_model', 'bmc_fw_version', and default placeholder structures
        for 'bmc_fw_eval' and 'badge' to be enriched post-collection.
        """
        empty = {"bmc_model": "N/A", "bmc_fw_version": "N/A", "bmc_fw_eval": {"badge": "<span class='badge info'>ℹ️ N/A</span>"}, "badge": "<span class='badge info'>ℹ️ BMC FW: N/A</span>"}
        if not self.mgr_uri:
            return empty
        mgr_data = self._get(self.mgr_uri) or {}
        if not mgr_data or mgr_data.get("error"):
            return empty
        fw_ver   = str(mgr_data.get("FirmwareVersion", "")).strip() or "N/A"
        mgr_model = str(mgr_data.get("Model", "") or mgr_data.get("Name", "") or "").strip().upper()
        return {
            "bmc_model": mgr_model or "BMC",
            "bmc_fw_version": fw_ver,
            "bmc_fw_eval": {"badge": f"<span class='badge info'>ℹ️ {fw_ver}</span>"},
            "badge": f"<span class='badge info'>ℹ️ BMC FW: {fw_ver}</span>",
        }


    def collect_software_inventory_os(self) -> dict:
        """Scan /redfish/v1/UpdateService/SoftwareInventory for a VMware ESXi entry.

        Dell iDRAC and HPE iLO often publish an ESXi component in the software
        inventory even when the iSM/AMS host agent is not installed, providing a
        reliable build number.  Returns the first matching entry as a dict with
        keys: os_name, os_version, os_build, source.  Returns {} on failure or
        when no ESXi entry is found.
        """
        upd = self._get("/redfish/v1/UpdateService", timeout=5) or {}
        inv_ref = upd.get("SoftwareInventory") or {}
        inv_link = inv_ref.get("@odata.id") if isinstance(inv_ref, dict) else None
        if not inv_link:
            return {}
        members = self._get_members(inv_link)
        _esxi_kw = {"ESXI", "VMWARE", "VSPHERE", "VMW_ESXI"}
        for m in members:
            item = self._get(m.get("@odata.id", "")) or {}
            name    = str(item.get("Name") or item.get("Id") or "").strip()
            name_up = name.upper().replace("-", "").replace("_", "")
            if any(kw in name_up for kw in _esxi_kw):
                version  = str(item.get("Version") or "").strip()
                # SoftwareId sometimes carries the full build number for Dell/HPE
                sw_id    = str(item.get("SoftwareId") or "").strip()
                # Attempt to extract a pure numeric build from Version or SoftwareId
                _build   = ""
                for _candidate in (sw_id, version):
                    _m = re.search(r'\b(\d{7,9})\b', _candidate)
                    if _m:
                        _build = _m.group(1)
                        break
                return {
                    "os_name":    name,
                    "os_version": version,
                    "os_build":   _build,
                    "source":     "SoftwareInventory",
                }
        return {}

    def collect_bmc_network_protocol(self) -> dict:
        """Collect NTP sync status, management network protocols, and VirtualMedia status."""
        result = {
            "ntp_enabled": False,
            "ntp_servers": [],
            "ntp_configured": False,
            "has_ntp_servers": False,
            "dns_enabled": False,
            "dns_servers": [],
            "dns_configured": False,
            "protocols": {},
            "virtual_media_inserted": False,
            "bmc_datetime": None,
            "datetime_local_offset": None,
            "is_utc": True,
            "timezone_name": None,
            "time_drift_seconds": None,
            "time_drift_detected": False,
            "badge": "<span class='badge info'>ℹ️ Network Protocol: N/A</span>",
        }
        if not self.mgr_uri:
            return result

        mgr_data = self._get(self.mgr_uri) or {}
        tz_info = {"offset_str": "+00:00", "offset_minutes": 0, "is_utc": True, "timezone_name": None}
        if isinstance(mgr_data, dict):
            bmc_dt_raw = mgr_data.get("DateTime")
            if bmc_dt_raw:
                result["bmc_datetime"] = str(bmc_dt_raw).strip()
                tz_info = _extract_bmc_timezone_info(mgr_data, result["bmc_datetime"])
                result["datetime_local_offset"] = tz_info["offset_str"]
                result["is_utc"] = tz_info["is_utc"]
                result["timezone_name"] = tz_info["timezone_name"]
                bmc_dt = _parse_iso_datetime(result["bmc_datetime"])
                if bmc_dt:
                    now_utc = datetime.now(timezone.utc)
                    drift_sec = int(round((bmc_dt - now_utc).total_seconds()))
                    result["time_drift_seconds"] = drift_sec
                    if abs(drift_sec) > 300:  # > 5 minutes threshold
                        result["time_drift_detected"] = True
            else:
                tz_info = _extract_bmc_timezone_info(mgr_data, None)
                result["datetime_local_offset"] = tz_info["offset_str"]
                result["is_utc"] = tz_info["is_utc"]
                result["timezone_name"] = tz_info["timezone_name"]

        net_proto = self._get(f"{self.mgr_uri}/NetworkProtocol") or {}
        if net_proto and not net_proto.get("error"):
            ntp = net_proto.get("NTP") or {}
            ntp_enabled = bool(
                ntp.get("ProtocolEnabled", False)
                or ntp.get("Enabled", False)
                or ntp.get("ServiceEnabled", False)
            )
            ntp_servers = _extract_ntp_servers(net_proto)
            result["ntp_enabled"] = ntp_enabled
            result["ntp_servers"] = ntp_servers
            result["has_ntp_servers"] = bool(ntp_servers)
            result["ntp_configured"] = bool(ntp_enabled and ntp_servers)

            dns = net_proto.get("DNS") or net_proto.get("Dns") or {}
            dns_enabled = bool(
                dns.get("ProtocolEnabled", False)
                or dns.get("Enabled", False)
                or dns.get("ServiceEnabled", False)
            ) if isinstance(dns, dict) else False
            dns_servers = _extract_dns_servers(net_proto)
            result["dns_enabled"] = dns_enabled
            result["dns_servers"] = dns_servers
            result["dns_configured"] = bool(dns_servers or (dns_enabled and dns_servers))

            protos = {}
            for proto_key in ("HTTP", "HTTPS", "SSH", "IPMI", "Telnet", "SNMP", "VirtualMedia"):
                p_obj = net_proto.get(proto_key) or {}
                if isinstance(p_obj, dict):
                    protos[proto_key] = {
                        "enabled": bool(p_obj.get("ProtocolEnabled", False)),
                        "port": p_obj.get("Port"),
                    }
            result["protocols"] = protos

        vm_coll = self._get(f"{self.mgr_uri}/VirtualMedia") or {}
        if vm_coll and isinstance(vm_coll.get("Members"), list):
            for m in self._get_members(vm_coll):
                vm_item = self._get(m.get("@odata.id", "")) or {}
                if vm_item.get("Inserted") or vm_item.get("Image"):
                    result["virtual_media_inserted"] = True
                    break

        if result["time_drift_detected"] and result["time_drift_seconds"] is not None:
            d_sec = abs(result["time_drift_seconds"])
            mins = d_sec // 60
            secs = d_sec % 60
            drift_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
            tz_tag = f" [{result['datetime_local_offset']}]" if (not result.get("is_utc") and result.get("datetime_local_offset") and result.get("datetime_local_offset") != "Unknown") else ""
            result["badge"] = f"<span class='badge danger'>🔴 Time Skew Detected ({drift_str}{tz_tag})</span>"
        elif result["ntp_enabled"] and result["ntp_servers"]:
            result["badge"] = f"<span class='badge success'>🟢 NTP Active ({', '.join(result['ntp_servers'][:2])})</span>"
        elif result["ntp_enabled"]:
            result["badge"] = "<span class='badge warning'>🟡 NTP Enabled (No Servers)</span>"
        else:
            result["badge"] = "<span class='badge warning'>🟡 NTP Disabled (Time Skew Risk)</span>"
        return result


    def collect_firmware_inventory(self) -> list:
        """Fetch complete hardware firmware inventory from /redfish/v1/UpdateService/FirmwareInventory."""
        fw_uri_base = "/redfish/v1/UpdateService/FirmwareInventory"
        fetch_expand_fn = getattr(self, "_fetch_expanded_collection", None)
        if callable(fetch_expand_fn) and getattr(self, "expand_supported", False):
            fw_inv = fetch_expand_fn(fw_uri_base) or {}
        else:
            fw_inv = self._get(fw_uri_base, timeout=15) or {}
        if not fw_inv or not isinstance(fw_inv.get("Members"), list):
            return []
        items = []
        _skip_sw_keywords = [
            "oscollector", "driverpack", "servicemodule", "diagnostics",
            "lc.embedded", "bootstrapos", "dellos", "dellsoftware", "lifecyclecontroller",
            "flexutil", "internal-sd", "mezzanine-stub"
        ]
        members_to_fetch = []
        for member in self._get_members(fw_inv):
            if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                break
            try:
                fw_uri = member.get("@odata.id") if isinstance(member, dict) else None
                if not fw_uri:
                    continue
                fw_uri_low = fw_uri.lower()
                # Skip inactive rollback firmware versions and non-hardware software packages
                if "/previous-" in fw_uri_low or "previous" in fw_uri_low:
                    continue
                if any(sw in fw_uri_low for sw in _skip_sw_keywords):
                    continue

                if isinstance(member, dict) and member.get("Name") and member.get("Version"):
                    items.append(member)
                else:
                    members_to_fetch.append(fw_uri)
            except Exception as exc:
                logger.debug("Error inspecting firmware inventory member %s: %s", member, exc)

        # Deduplicate Installed-* vs Current-* entries for pre-expanded components
        if items:
            current_suffixes = set()
            for itm in items:
                uri = str(itm.get("@odata.id") or itm.get("Id") or "")
                last_seg = uri.rsplit('/', 1)[-1]
                if last_seg.startswith("Current-"):
                    suffix = last_seg.rsplit("__", 1)[-1] if "__" in last_seg else last_seg.replace("Current-", "", 1)
                    current_suffixes.add(suffix)
            if current_suffixes:
                deduped_items = []
                for itm in items:
                    uri = str(itm.get("@odata.id") or itm.get("Id") or "")
                    last_seg = uri.rsplit('/', 1)[-1]
                    if last_seg.startswith("Installed-"):
                        suffix = last_seg.rsplit("__", 1)[-1] if "__" in last_seg else last_seg.replace("Installed-", "", 1)
                        if suffix in current_suffixes:
                            continue
                    deduped_items.append(itm)
                items = deduped_items

        if members_to_fetch and not (callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped()):
            # Deduplicate Installed-* vs Current-* entries (Dell iDRAC exposes both for every component)
            current_suffixes = set()
            for uri in members_to_fetch:
                last_seg = uri.rsplit('/', 1)[-1]
                if last_seg.startswith("Current-"):
                    suffix = last_seg.rsplit("__", 1)[-1] if "__" in last_seg else last_seg.replace("Current-", "", 1)
                    current_suffixes.add(suffix)

            deduped_uris = []
            for uri in members_to_fetch:
                last_seg = uri.rsplit('/', 1)[-1]
                if last_seg.startswith("Installed-"):
                    suffix = last_seg.rsplit("__", 1)[-1] if "__" in last_seg else last_seg.replace("Installed-", "", 1)
                    if suffix in current_suffixes:
                        continue
                deduped_uris.append(uri)

            def _fw_uri_prio(uri: str) -> int:
                u_low = uri.lower()
                if any(k in u_low for k in ("bios", "idrac", "ilo", "bmc", "xcc", "cpld", "system", "nic", "embedded", "integrated", "raid", "controller")):
                    return 0
                if any(k in u_low for k in ("psu", "power", "fan", "backplane")):
                    return 1
                return 2

            deduped_uris.sort(key=_fw_uri_prio)

            if len(deduped_uris) >= 75:
                # Pathological collection ceiling: BMC has 75+ components (matching fishymetrics scale guardrail)
                logger.warning(
                    "[%s] Pathological firmware inventory count (%d >= 75). Enforcing priority ceiling of 35 items to prevent BMC exhaustion.",
                    getattr(self, "host", "unknown"),
                    len(deduped_uris),
                )
                members_to_fetch = [u for u in deduped_uris if _fw_uri_prio(u) <= 1][:35]
            elif getattr(self, "_throttled", False):
                members_to_fetch = deduped_uris[:25]
            else:
                members_to_fetch = deduped_uris[:40]

            if len(deduped_uris) > len(members_to_fetch):
                logger.warning("[%s] Capping firmware inventory members from %d to %d prioritized items to reduce BMC load", getattr(self, "host", "unknown"), len(deduped_uris), len(members_to_fetch))

            def _fetch_fw_obj(uri: str) -> Optional[dict]:
                return self._get(uri, critical=False)

            max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(3), max(1, len(members_to_fetch)))
            _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
            fetched_objs = []
            pool = ThreadPoolExecutor(max_workers=max_w)
            try:
                futures = [pool.submit(_wrap_task(_fetch_fw_obj), uri) for uri in members_to_fetch]
                wait(futures, timeout=25.0)
                for fut in futures:
                    if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                        break
                    try:
                        if fut.done():
                            res = fut.result()
                            if res and not res.get("error"):
                                fetched_objs.append(res)
                    except Exception as err:
                        logger.debug("Error fetching firmware inventory member: %s", err)

                items.extend(fetched_objs)
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

        parsed_items = []
        for fw_obj in items:
            if not isinstance(fw_obj, dict):
                continue
            name = str(fw_obj.get("Name") or fw_obj.get("Id") or "Unknown").strip()
            version = str(fw_obj.get("Version") or "N/A").strip()
            updateable = fw_obj.get("Updateable")
            comp_id = str(fw_obj.get("SoftwareId") or fw_obj.get("ComponentId") or fw_obj.get("Manufacturer") or "").strip()
            desc = str(fw_obj.get("Description") or "").strip()
            dev_ctx = str(
                get_nested(fw_obj, "Oem", "Hpe", "DeviceContext")
                or get_nested(fw_obj, "Oem", "Dell", "DeviceContext")
                or fw_obj.get("DeviceContext")
                or ""
            ).strip()
            parsed_items.append({
                "id": str(fw_obj.get("Id") or "").strip(),
                "name": name,
                "version": version,
                "updateable": updateable,
                "component_id": comp_id,
                "description": desc,
                "device_context": dev_ctx,
            })
        return parsed_items




