"""
VCF Readiness Tool — Root endpoint discovery and chassis management mixin.
"""
import html
import logging
import re
import time
from typing import TYPE_CHECKING, Any, Optional, Set, Tuple, Union

if TYPE_CHECKING:
    class _CollectorBase:
        sys_uri: Optional[str]
        chassis_uri: Optional[str]
        mgr_uri: Optional[str]
        sys_sku: str
        sys_model: str
        vendor: str
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
        expand_supported: bool
        expand_syntax: Optional[str]
        expand_max_levels: int
        multiple_http_requests: bool
        _request_pacing_s: float
        _unsupported_expand_endpoints: Set[str]
        chassis_management_info: dict
        stage_callback: Any
        _PCIE_SWITCH_NAMES: tuple
        _max_inner_workers: int
        _base_max_inner_workers: int
        _initial_get_latency_ms: Optional[float]
        silicon_generation: str
        _conn_pool: Any
        _request_cache: dict
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
        def oem_handle_retry(self, data: dict, endpoint: str) -> bool: ...
        def oem_manager_paths(self) -> list: ...
        def oem_fastpath_roots(self) -> Optional[Tuple[list, list, list]]: ...
else:
    _CollectorBase = object

from vcf_hci.collector.pci_utils import extract_pci_ids_from_dict, match_pcie_cache
from vcf_hci.constants import GENERIC_NAME_BLOCKLIST
from vcf_hci.logging_utils import get_nested

logger = logging.getLogger("vcf_assess")


def classify_bmc_silicon(
    vendor: Union[str, dict] = "",
    product: str = "",
    model: str = "",
    description: str = "",
    firmware: str = "",
    raw_text: str = "",
) -> str:
    """Classify BMC controller silicon architecture based on Redfish root/manager metadata.

    Recognizes 5 primary enterprise silicon eras:
      - Nuvoton Arbel (Dell 17G / iDRAC10: R670, R770, R7725, R870, R970)
      - HPE Gen12 Custom 64-bit (DL380 Gen12 / iLO 7)
      - AST2600 (Lenovo V3/V4 SR650 V3/V4, Supermicro X13/X14, Cisco M6/M7)
      - AST2500 (Dell 14G/15G, Cisco M5, Lenovo V1/V2, Supermicro X11/X12, Quanta)
      - Pilot-3 (Dell 13G R730xd/R630, Cisco M4, HPE Gen9) / AST2400 (Supermicro X10)
    """
    if isinstance(vendor, dict):
        d = vendor
        vendor = str(d.get("Manufacturer") or d.get("Vendor") or "")
        product = str(d.get("Product") or "")
        model = str(d.get("Model") or "")
        description = str(d.get("Description") or "")
        firmware = str(d.get("FirmwareVersion") or "")
        redfish_ver = str(d.get("RedfishVersion") or "")
        oem = d.get("Oem")
        oem_text = " ".join(str(k) for k in oem) if isinstance(oem, dict) else ""
        raw_text = f"{raw_text} {oem_text} {redfish_ver}".strip()

    base_str = f"{vendor} {product} {model} {description} {firmware} {raw_text}".lower()
    search_str = f"{base_str} {re.sub(r'[-_]+', ' ', base_str)}"

    # 1. Nuvoton Arbel (Dell 17G / iDRAC10)
    if any(k in search_str for k in ("arbel", "idrac10", "idrac 10", "remote access controller 10")):
        return "Nuvoton Arbel"
    if any(m in search_str for m in ("r670", "r770", "r7725", "r870", "r970", "c670", "poweredge 17g")):
        return "Nuvoton Arbel"
    if "dell" in search_str and "idrac" in search_str and firmware and firmware.startswith("10."):
        return "Nuvoton Arbel"

    # 2. HPE Gen12 Custom 64-bit (iLO 7)
    if any(k in search_str for k in ("ilo 7", "ilo7", "gen12")):
        return "HPE Gen12 Custom 64-bit"

    # 3. AST2600 (Lenovo V3/V4, Supermicro X13/X14, Cisco M6/M7)
    if "ast2600" in search_str:
        return "AST2600"
    if any(k in search_str for k in ("sr650 v3", "sr630 v3", "sr650 v4", "sr630 v4", "sr675 v3", "vx650 v3", "xcc2", "xcc3")):
        return "AST2600"
    if any(k in search_str for k in ("x13", "x14", "h13", "h14")):
        return "AST2600"
    if any(k in search_str for k in ("c220 m6", "c240 m6", "c220 m7", "c240 m7")):
        return "AST2600"

    # 4. Pilot-3 / AST2400 (Legacy)
    if "pilot-3" in search_str or "pilot3" in search_str:
        return "Pilot-3"
    if "ast2400" in search_str:
        return "AST2400"
    if any(k in search_str for k in ("r730xd", "r730", "r630", "r930", "idrac8", "idrac 8", "remote access controller 8")):
        return "Pilot-3"
    if any(k in search_str for k in ("c220 m4", "c240 m4", "gen9", "ilo 4", "ilo4")):
        return "Pilot-3"
    if "x10" in search_str and ("supermicro" in search_str or "smc" in search_str):
        return "AST2400"

    # 5. AST2500 / Pilot-4
    if "ast2500" in search_str or "pilot-4" in search_str or "pilot4" in search_str:
        return "AST2500"
    if any(k in search_str for k in ("r740", "r640", "r750", "r650", "r760", "r660", "r7525", "r6525", "r7515", "r7415", "r7425", "r7615", "r7625", "r6415", "r6515", "r840", "r940", "r960", "idrac9", "idrac 9", "remote access controller 9")):
        return "AST2500"
    if any(k in search_str for k in ("c220 m5", "c240 m5")):
        return "AST2500"
    if any(k in search_str for k in ("sr650", "sr630")):
        return "AST2500"
    if any(k in search_str for k in ("gen10", "gen11", "ilo 5", "ilo 6")):
        return "AST2500"
    if any(k in search_str for k in ("x11", "x12")):
        return "AST2500"
    if any(k in search_str for k in ("quanta", "d42a")):
        return "AST2500"

    return ""


def determine_inner_worker_ceiling(
    multiple_http_requests: bool,
    silicon_generation: str = "",
    initial_latency_ms: float = 0.0,
    model: str = "",
) -> int:
    """Determine safe concurrent inner worker count aligned with BMC silicon generation and network latency.

    Rules derived from empirical benchmark (Test 6) and fleet telemetry:
      - Pipelined (MultipleHTTPRequests: true) + Modern Silicon (Arbel / iLO 7): 5 workers
      - Pipelined (MultipleHTTPRequests: true) + AST2600: 4 workers
      - Pipelined (MultipleHTTPRequests: true) + Fast Response (< 350ms): 4 workers
      - Non-pipelined or Legacy (Pilot-3 / AST2400) or High Latency (>= 350ms): 2 workers
      - Dell 14G/15G AMD (R7525, R6525, R7515, R7415, R7425, etc.): 2 workers
      - Standard fallback: 3 workers
    """
    silicon_clean = (silicon_generation or "").strip()
    silicon_lower = silicon_clean.lower()
    model_lower = (model or "").lower()

    if multiple_http_requests:
        if "arbel" in silicon_lower or "ilo 7" in silicon_lower or "gen12" in silicon_lower:
            return 5
        if "ast2600" in silicon_lower:
            return 4
        if 0 < initial_latency_ms < 350.0:
            return 4
        return 3

    # Non-pipelined or legacy platforms
    if "pilot-3" in silicon_lower or "pilot3" in silicon_lower or "ast2400" in silicon_lower:
        return 2

    # Dell 14G/15G AMD platforms have higher internal BMC-to-SoC latency under concurrent load
    if any(m in model_lower for m in ("r7525", "r6525", "r7515", "r7415", "r7425", "r6415", "r6515")):
        return 2

    if initial_latency_ms >= 350.0 and ("pilot" in silicon_lower or not silicon_lower or "ast" in silicon_lower):
        return 2

    return 3


class DiscoveryMixin(_CollectorBase):
    """Mixin providing root endpoint discovery and chassis management detection."""

    @staticmethod
    def _is_license_blocked(data: Optional[dict]) -> Optional[str]:
        """Returns a human-readable license message if an OEM license gate blocks the response."""
        if not isinstance(data, dict):
            return None
        raw_ext = data.get("@Message.ExtendedInfo") or (data.get("error") or {}).get("@Message.ExtendedInfo") or []
        if isinstance(raw_ext, dict):
            ext_list = [raw_ext]
        elif isinstance(raw_ext, list):
            ext_list = [m for m in raw_ext if isinstance(m, dict)]
        else:
            ext_list = []

        for msg in ext_list:
            msg_id = str(msg.get("MessageId", ""))
            if "OemLicenseNotPassed" in msg_id:
                raw_args = msg.get("MessageArgs")
                args = [str(a) for a in raw_args] if isinstance(raw_args, (list, tuple)) else ["Unknown"]
                needed = ", ".join(args)
                return f"Requires {needed} license (contact vendor)"
        return None

    @staticmethod
    def _format_chassis_switch(sw_obj: dict, uri: str) -> dict:
        ports_uri = get_nested(sw_obj, "Ports", "@odata.id") or f"{uri}/Ports"
        ports_data = sw_obj.get("Ports")
        ports_count = len(ports_data) if isinstance(ports_data, list) else (ports_data.get("Members@odata.count", 0) if isinstance(ports_data, dict) else 0)
        return {
            "id": str(sw_obj.get("Id") or uri.split("/")[-1]),
            "name": str(sw_obj.get("Name") or "Internal Fabric Switch").strip(),
            "model": str(sw_obj.get("Model") or sw_obj.get("PartNumber") or "").strip(),
            "manufacturer": str(sw_obj.get("Manufacturer") or "").strip(),
            "switch_type": str(sw_obj.get("SwitchType") or sw_obj.get("ActiveLinkTechnology") or "Ethernet / Fabric").strip(),
            "ports_count": ports_count,
            "health": str((sw_obj.get("Status") or {}).get("Health") or "OK").strip(),
            "uri": uri,
        }

    def _detect_chassis_management(self) -> dict:
        """Inspect Managers, Chassis, and Fabrics to classify modular chassis BMCs.

        Identifies Dell OME-Modular (MX7000), HPE Synergy (FLM/Composer),
        Cisco UCS Manager / Fabric Interconnects, Dell CMC (VRTX, M1000e, FX2),
        Lenovo CMM (Flex System), and Supermicro Blade CMMs.
        """
        info = {
            "is_modular_chassis": False,
            "manager_type": "",
            "chassis_manager_name": "",
            "chassis_model": "",
            "chassis_serial": "",
            "vendor": "",
            "enclosure_name": "",
            "sled_count": 0,
            "sleds": [],
            "fabric_switches": [],
            "summary_badge": "",
        }

        # 1. Inspect Managers
        mgr_objs = []
        for m_uri in (getattr(self, "mgr_uris", None) or ([self.mgr_uri] if getattr(self, "mgr_uri", None) else [])):
            m_data = self._get(m_uri) or {}
            if m_data and not m_data.get("error"):
                mgr_objs.append((m_uri, m_data))

        is_modular = False
        mgr_type = ""
        mgr_name = ""
        mgr_vendor = ""
        mgr_model = ""

        for m_uri, m_data in mgr_objs:
            m_type = str(m_data.get("ManagerType") or "").strip()
            m_model = str(m_data.get("Model") or m_data.get("Description") or m_data.get("Name") or "").strip()
            m_text = f"{m_type} {m_model} {m_uri}".lower()

            if m_type in ("EnclosureManager", "ChassisManager", "AuxiliaryController") or any(
                k in m_text for k in (
                    "ome-modular", "openmanage enterprise modular", "chassis management controller",
                    "vrtx", "m1000e", "fx2", "synergy frame link module", "synergy composer",
                    "flm", "ucs manager", "fabric interconnect", "intersight", "flex system cmm",
                    "superblade", "microblade"
                )
            ):
                is_modular = True
                mgr_type = m_type or "EnclosureManager"
                mgr_model = m_model

                if any(k in m_text for k in ("ome-modular", "openmanage enterprise modular", "poweredge mx")):
                    mgr_name = "Dell OpenManage Enterprise Modular (OME-M)"
                    mgr_vendor = "Dell"
                elif any(k in m_text for k in ("vrtx", "m1000e", "fx2", "dell chassis management")):
                    mgr_name = "Dell Chassis Management Controller (CMC)"
                    mgr_vendor = "Dell"
                elif any(k in m_text for k in ("synergy", "frame link module", "composer", "flm")):
                    mgr_name = "HPE Synergy Frame Link Module (FLM)"
                    mgr_vendor = "HPE"
                elif any(k in m_text for k in ("ucs", "fabric interconnect", "intersight", "cimc")):
                    mgr_name = "Cisco UCS Fabric Interconnect / Manager"
                    mgr_vendor = "Cisco"
                elif "flex system" in m_text or "cmm" in m_text:
                    mgr_name = "Lenovo Flex System CMM"
                    mgr_vendor = "Lenovo"
                else:
                    mgr_name = f"Modular Chassis Manager ({m_model or m_type})"
                    mgr_vendor = str(m_data.get("Manufacturer") or "")
                break

        # 2. Inspect Chassis collection
        enclosure_model = ""
        enclosure_serial = ""
        enclosure_name = ""
        chassis_objs = []
        for c_uri in (getattr(self, "chassis_uris", None) or ([self.chassis_uri] if getattr(self, "chassis_uri", None) else [])):
            c_data = self._get(c_uri) or {}
            if c_data and not c_data.get("error"):
                chassis_objs.append((c_uri, c_data))
                c_type = str(c_data.get("ChassisType") or "").strip()
                c_model = str(c_data.get("Model") or c_data.get("Name") or "").strip()
                c_ser = str(c_data.get("SerialNumber") or (c_data.get("Oem") or {}).get("Dell", {}).get("ServiceTag") or "").strip()
                c_vendor = str(c_data.get("Manufacturer") or "").strip()
                if c_type in ("Enclosure", "RackGroup", "Blade", "Drawer", "Module") or any(
                    k in f"{c_type} {c_model}".lower() for k in ("mx7000", "synergy", "vrtx", "m1000e", "fx2", "ucs 5108")
                ):
                    is_modular = True
                    if not enclosure_model and c_model and c_model.lower() not in ("chassis", "enclosure", "unknown"):
                        enclosure_model = c_model
                    if not enclosure_serial and c_ser:
                        enclosure_serial = c_ser
                    if not enclosure_name:
                        enclosure_name = str(c_data.get("Name") or c_model or "").strip()
                    if not mgr_vendor and c_vendor:
                        mgr_vendor = c_vendor

        # 3. Check for multiple compute systems (sleds/blades)
        sleds = []
        sys_uris = getattr(self, "sys_uris", []) or []
        if len(sys_uris) > 1 or is_modular:
            for s_uri in sys_uris:
                s_data = self._get(s_uri) or {}
                if s_data and not s_data.get("error"):
                    sled_id = str(s_data.get("Id") or s_uri.split("/")[-1]).strip()
                    sled_name = str(s_data.get("Name") or s_data.get("HostName") or sled_id).strip()
                    sled_model = str(s_data.get("Model") or "").strip()
                    sled_ser = str(s_data.get("SerialNumber") or "").strip()
                    sled_power = str(s_data.get("PowerState") or "Unknown").strip()
                    sled_health = str((s_data.get("Status") or {}).get("Health") or "OK").strip()
                    sleds.append({
                        "id": sled_id,
                        "name": sled_name,
                        "uri": s_uri,
                        "model": sled_model,
                        "serial_number": sled_ser,
                        "power_state": sled_power,
                        "health": sled_health,
                    })

        # 4. Check for internal chassis fabric switches / IOMs
        fabric_switches = []
        switch_eps = ["/redfish/v1/Fabrics", "/redfish/v1/Switches"]
        for c_uri, c_data in chassis_objs:
            for sw_link in ("Switches", "NetworkAdapters"):
                sw_uri = (c_data.get(sw_link) or {}).get("@odata.id")
                if sw_uri and sw_uri not in switch_eps:
                    switch_eps.append(sw_uri)

        for sw_ep in switch_eps:
            sw_members = self._get_members(sw_ep)
            for sm in sw_members:
                sm_uri = sm.get("@odata.id") if isinstance(sm, dict) else sm
                if not sm_uri:
                    continue
                # Skip PCIe fabric topologies (motherboard/bridge switches, scanned in Phase 2)
                if "/PCIe" in sm_uri or "/pcie" in sm_uri.lower():
                    continue
                if "/Fabrics/" in sm_uri and "/Switches" not in sm_uri:
                    inner_sws = self._get_members(f"{sm_uri}/Switches")
                    for isw in inner_sws:
                        isw_uri = isw.get("@odata.id") if isinstance(isw, dict) else isw
                        if isw_uri:
                            sw_obj = self._get(isw_uri) or {}
                            if sw_obj and not sw_obj.get("error"):
                                st = str(sw_obj.get("SwitchType") or sw_obj.get("@odata.type") or "").lower()
                                s_name = str(sw_obj.get("Name") or sw_obj.get("Model") or "").strip().lower()
                                s_id = str(sw_obj.get("Id") or "").strip().lower()
                                if st == "pcie" or "pcie" in st or "p2pbridge" in s_name or "p2pbridge" in s_id or "pcie switch" in s_name:
                                    continue
                                fabric_switches.append(self._format_chassis_switch(sw_obj, isw_uri))
                else:
                    sw_obj = self._get(sm_uri) or {}
                    if sw_obj and not sw_obj.get("error"):
                        st = str(sw_obj.get("SwitchType") or sw_obj.get("@odata.type") or "").lower()
                        s_name = str(sw_obj.get("Name") or sw_obj.get("Model") or "").strip().lower()
                        s_id = str(sw_obj.get("Id") or "").strip().lower()
                        if st == "pcie" or "pcie" in st or "p2pbridge" in s_name or "p2pbridge" in s_id or "pcie switch" in s_name:
                            continue
                        if "switch" in st or "switch" in s_name or any(
                            k in s_name for k in ("mx9116", "mx7116", "mxg610", "virtual connect", "iom", "fex")
                        ):
                            fabric_switches.append(self._format_chassis_switch(sw_obj, sm_uri))

        if is_modular or len(sleds) > 1 or len(fabric_switches) > 0:
            is_modular = True
            if not mgr_name:
                mgr_name = "Modular Chassis Management Controller"
            if not enclosure_model:
                if "mx" in mgr_name.lower():
                    enclosure_model = "PowerEdge MX7000"
                elif "synergy" in mgr_name.lower():
                    enclosure_model = "Synergy 12000 Frame"
                elif "vrtx" in mgr_name.lower():
                    enclosure_model = "PowerEdge VRTX"
                elif "ucs" in mgr_name.lower():
                    enclosure_model = "UCS 5108 Blade Chassis"
                else:
                    enclosure_model = "Modular Server Chassis"

            sled_info_str = f"{len(sleds)} Compute Sled{'s' if len(sleds) != 1 else ''}" if sleds else ""
            sw_info_str = f"{len(fabric_switches)} Fabric Switch{'es' if len(fabric_switches) != 1 else ''}" if fabric_switches else ""
            detail_parts = [p for p in (sled_info_str, sw_info_str) if p]
            detail_str = f" ({', '.join(detail_parts)})" if detail_parts else ""

            summary_badge = (
                f"<span class='badge info'>🏢 Modular Chassis: {html.escape(enclosure_model)}{html.escape(detail_str)}</span>"
            )

            info.update({
                "is_modular_chassis": True,
                "manager_type": mgr_type,
                "chassis_manager_name": mgr_name,
                "chassis_model": enclosure_model,
                "chassis_serial": enclosure_serial,
                "vendor": mgr_vendor,
                "enclosure_name": enclosure_name,
                "sled_count": len(sleds),
                "sleds": sleds,
                "fabric_switches": fabric_switches,
                "summary_badge": summary_badge,
            })

        return info

    def _configure_inner_worker_sizing(
        self,
        root_json: Optional[dict] = None,
        root_latency_ms: float = 0.0,
    ) -> int:
        """Dynamically evaluate and configure safe inner worker count and persistent connection pool capacity."""
        conn_pool = getattr(self, "_conn_pool", None)
        eff_lat = root_latency_ms
        if conn_pool is not None and getattr(conn_pool, "requests_served", 0) > 0:
            eff_lat = conn_pool.total_request_time_ms / conn_pool.requests_served
        self._initial_get_latency_ms = eff_lat

        model = str(
            get_nested(root_json, "Model", default="")
            or getattr(self, "sys_model", "")
            or ""
        )
        silicon = getattr(self, "silicon_generation", "")
        if not silicon:
            vendor = str(getattr(self, "vendor", "") or "")
            product = str(get_nested(root_json, "Product", default="") or "")
            description = str(get_nested(root_json, "Description", default="") or "")
            rf_ver = str(get_nested(root_json, "RedfishVersion", default="") or "")
            raw_parts = []
            if rf_ver:
                raw_parts.append(rf_ver)
            oem = (root_json or {}).get("Oem")
            if isinstance(oem, dict):
                raw_parts.extend(str(k) for k in oem)

            # Check chassis management details if available
            chassis_info = getattr(self, "chassis_management_info", {}) or {}
            if chassis_info:
                raw_parts.append(str(chassis_info.get("chassis_model", "")))
                raw_parts.append(str(chassis_info.get("manager_type", "")))
                raw_parts.append(str(chassis_info.get("vendor", "")))

            # Check request cache for manager/system data if already probed
            req_cache = getattr(self, "_request_cache", {}) or {}
            bmc_fw = ""
            for k, val in req_cache.items():
                if isinstance(val, dict):
                    raw_parts.append(str(val.get("Model", "")))
                    fw = str(val.get("FirmwareVersion", ""))
                    if fw and not bmc_fw:
                        bmc_fw = fw
                    raw_parts.append(fw)
                    raw_parts.append(str(val.get("Description", "")))
                    raw_parts.append(str(val.get("Name", "")))

            raw_text = " ".join(raw_parts)
            silicon = classify_bmc_silicon(
                vendor=vendor,
                product=product,
                model=model,
                description=description,
                firmware=bmc_fw,
                raw_text=raw_text,
            )
            if silicon:
                self.silicon_generation = silicon

        ceiling = determine_inner_worker_ceiling(
            multiple_http_requests=bool(getattr(self, "multiple_http_requests", False)),
            silicon_generation=getattr(self, "silicon_generation", ""),
            initial_latency_ms=getattr(self, "_initial_get_latency_ms", 0.0) or eff_lat,
            model=model,
        )

        self._max_inner_workers = ceiling
        self._base_max_inner_workers = ceiling
        if conn_pool is not None:
            conn_pool.max_connections = self._max_inner_workers

        logger.debug(
            "[%s] Configured adaptive inner workers: workers=%d, conn_pool=%d, silicon='%s', pipelining=%s, latency=%.1fms",
            getattr(self, "host", "unknown"),
            self._max_inner_workers,
            conn_pool.max_connections if conn_pool is not None else self._max_inner_workers,
            getattr(self, "silicon_generation", "unknown"),
            getattr(self, "multiple_http_requests", False),
            getattr(self, "_initial_get_latency_ms", 0.0) or 0.0,
        )
        return ceiling

    def _discover_roots(self, capture_raw: bool = False):
        t0 = time.time()
        try:
            root_json = self._get("/redfish/v1")
        except Exception:
            root_json = None
        root_latency_ms = (time.time() - t0) * 1000.0

        expand_feature = (
            get_nested(root_json, "ProtocolFeaturesSupported", "ExpandQuery")
            or get_nested(root_json, "ProtocolFeaturesSupported", "Expand")
        )
        self.multiple_http_requests = bool(
            get_nested(root_json, "ProtocolFeaturesSupported", "MultipleHTTPRequests", default=False)
        )
        if self.multiple_http_requests:
            self._request_pacing_s = 0.0
        else:
            self._request_pacing_s = 0.05

        self._configure_inner_worker_sizing(root_json=root_json, root_latency_ms=root_latency_ms)
        if isinstance(expand_feature, dict):
            expand_all = bool(expand_feature.get("ExpandAll", False))
            no_links = bool(expand_feature.get("NoLinks", False))
            try:
                raw_max_levels = int(expand_feature.get("MaxLevels", 1))
            except (ValueError, TypeError):
                raw_max_levels = 1
            self.expand_syntax = "*" if expand_all else ("." if no_links else None)
            # Clamp expansion depth: Lenovo ThinkSystem strictly limits levels to 2 (returns 400 on >2).
            # HPE Gen12 and MegaRAC support up to 5 levels.
            max_ceiling = 2 if getattr(self, "vendor", "") == "lenovo" else 5
            self.expand_max_levels = max(1, min(max_ceiling, raw_max_levels))
            self.expand_supported = self.expand_syntax is not None
        elif isinstance(expand_feature, bool) and expand_feature:
            self.expand_syntax = "*"
            self.expand_max_levels = 1
            self.expand_supported = True
        else:
            self.expand_syntax = None
            self.expand_max_levels = 1
            self.expand_supported = False

        if getattr(self, "vendor", "") in ("supermicro", "quanta"):
            self.expand_syntax = None
            self.expand_supported = False

        fast_roots = self.oem_fastpath_roots()
        if fast_roots and isinstance(fast_roots, (list, tuple)) and len(fast_roots) == 3:
            s_uris, c_uris, m_uris = fast_roots
            if s_uris and c_uris and m_uris:
                self.sys_uris = [u.rstrip("/") for u in s_uris if u]
                self.chassis_uris = [u.rstrip("/") for u in c_uris if u]
                self.mgr_uris = [u.rstrip("/") for u in m_uris if u]
                self.sys_uri = self.sys_uris[0] if self.sys_uris else None
                self.chassis_uri = self.chassis_uris[0] if self.chassis_uris else None
                self.mgr_uri = self.mgr_uris[0] if self.mgr_uris else None
                self.chassis_management_info = self._detect_chassis_management()
                if capture_raw:
                    if self.sys_uri:
                        self._get(self.sys_uri)
                    if self.chassis_uri:
                        self._get(self.chassis_uri)
                    if self.mgr_uri:
                        self._get(self.mgr_uri)
                    for ep in ["/redfish/v1/UpdateService", "/redfish/v1/TelemetryService", "/redfish/v1/LicenseService"]:
                        self._get(ep, timeout=5, critical=False)
                self._configure_inner_worker_sizing(root_json=root_json, root_latency_ms=root_latency_ms)
                logger.debug(f"Roots (fast-path): sys={self.sys_uri}, chassis={self.chassis_uri}, mgr={self.mgr_uri}, modular={self.chassis_management_info.get('is_modular_chassis')}")
                return

        self.sys_uris = [m.get("@odata.id").rstrip("/") for m in self._get_members("/Systems") if isinstance(m, dict) and m.get("@odata.id")]
        self.chassis_uris = [m.get("@odata.id").rstrip("/") for m in self._get_members("/Chassis") if isinstance(m, dict) and m.get("@odata.id")]
        self.mgr_uris = [m.get("@odata.id").rstrip("/") for m in self._get_members("/Managers") if isinstance(m, dict) and m.get("@odata.id")]

        # Handle scale-up / partitioned servers (e.g. BullSequana SH120, Superdome Flex)
        # where members may not be exposed under standard collections or /Systems/Partition0 is used
        if not self.sys_uris:
            for fallback_sys in ("/redfish/v1/Systems/Partition0", "/redfish/v1/Systems/1", "/redfish/v1/Systems/System.Embedded.1", "/redfish/v1/Systems/Self"):
                probe = self._get(fallback_sys)
                if probe and not probe.get("error"):
                    self.sys_uris.append(fallback_sys.rstrip("/"))
                    logger.debug(f"Discovered fallback system URI: {fallback_sys}")
                    break

        if self.sys_uris:
            self.sys_uri = self.sys_uris[0]
        if self.chassis_uris:
            self.chassis_uri = self.chassis_uris[0]
        if self.mgr_uris:
            self.mgr_uri = self.mgr_uris[0]

        # Fallback to ManagedBy links if /Managers collection was empty or omitted (e.g. Huawei, whiteboxes)
        if not self.mgr_uris and self.sys_uri:
            sys_obj = self._get(self.sys_uri) or {}
            mb = (sys_obj.get("Links") or {}).get("ManagedBy") or []
            if isinstance(mb, dict):
                mb = [mb]
            for m_ref in (mb if isinstance(mb, list) else []):
                m_uri = m_ref.get("@odata.id") if isinstance(m_ref, dict) else (m_ref if isinstance(m_ref, str) else None)
                if m_uri and m_uri not in self.mgr_uris:
                    self.mgr_uris.append(m_uri)

        if not self.mgr_uris and self.chassis_uri:
            cha_obj = self._get(self.chassis_uri) or {}
            mb = (cha_obj.get("Links") or {}).get("ManagedBy") or []
            if isinstance(mb, dict):
                mb = [mb]
            for m_ref in (mb if isinstance(mb, list) else []):
                m_uri = m_ref.get("@odata.id") if isinstance(m_ref, dict) else (m_ref if isinstance(m_ref, str) else None)
                if m_uri and m_uri not in self.mgr_uris:
                    self.mgr_uris.append(m_uri)

        if self.mgr_uris and not self.mgr_uri:
            self.mgr_uri = self.mgr_uris[0]

        # Check OEM-specific manager paths (e.g. Cisco IMC at /Managers/CIMC)
        extra_mgr_paths = self.oem_manager_paths()
        if extra_mgr_paths:
            mgr_test = self._get(self.mgr_uri) if self.mgr_uri else None
            if not self.mgr_uri or (isinstance(mgr_test, dict) and mgr_test.get("error")):
                for alt_path in extra_mgr_paths:
                    alt_test = self._get(alt_path)
                    if alt_test and isinstance(alt_test, dict) and not alt_test.get("error"):
                        self.mgr_uri = alt_path
                        if alt_path not in self.mgr_uris:
                            self.mgr_uris.append(alt_path)
                        logger.debug(f"Discovered OEM manager path: {self.mgr_uri}")
                        break

        # Discover Modular Chassis / Enclosure Manager details
        self.chassis_management_info = self._detect_chassis_management()

        if capture_raw:
            # Ensure top-level root objects and service managers are in raw request cache
            if self.sys_uri:
                self._get(self.sys_uri)
            if self.chassis_uri:
                self._get(self.chassis_uri)
            if self.mgr_uri:
                self._get(self.mgr_uri)
            for ep in ["/redfish/v1/UpdateService", "/redfish/v1/TelemetryService", "/redfish/v1/LicenseService"]:
                self._get(ep, timeout=5, critical=False)
        self._configure_inner_worker_sizing(root_json=root_json, root_latency_ms=root_latency_ms)
        logger.debug(f"Roots: sys={self.sys_uri}, chassis={self.chassis_uri}, mgr={self.mgr_uri}, modular={self.chassis_management_info.get('is_modular_chassis')}")

    def _resolve_product_name(self, raw_obj: dict, pcie_cache: Optional[list] = None) -> str:
        if not raw_obj:
            return "PCIe Network Adapter"
        for key in ["Name", "Description", "Model"]:
            val = str(raw_obj.get(key, "") or "").strip()
            if val and val.lower() not in GENERIC_NAME_BLOCKLIST:
                return val
        # Dell OEM NIC product name check
        dell_nic = ((raw_obj.get("Oem") or {}).get("Dell") or {}).get("DellNIC") or {}
        dell_name = str(dell_nic.get("ProductName") or dell_nic.get("DeviceDescription") or "").strip()
        if not dell_name and callable(getattr(self, "_get", None)):
            ndf_links = (raw_obj.get("Links") or {}).get("NetworkDeviceFunctions") or raw_obj.get("NetworkDeviceFunctions") or []
            if isinstance(ndf_links, dict):
                ndf_uri = ndf_links.get("@odata.id")
                if ndf_uri:
                    ndf_coll = self._get(ndf_uri) or {}
                    ndf_links = ndf_coll.get("Members") or []
            if isinstance(ndf_links, list):
                for ndf_ref in ndf_links:
                    if isinstance(ndf_ref, dict) and ndf_ref.get("@odata.id"):
                        ndf_data = self._get(ndf_ref.get("@odata.id")) or {}
                        d_nic = ((ndf_data.get("Oem") or {}).get("Dell") or {}).get("DellNIC") or {}
                        p_name = str(d_nic.get("ProductName") or "").strip()
                        if p_name and p_name.lower() not in GENERIC_NAME_BLOCKLIST:
                            dell_name = p_name
                            break

        if dell_name and dell_name.lower() not in GENERIC_NAME_BLOCKLIST:
            dell_clean = re.sub(r"\s*-\s*([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", "", dell_name).strip()
            if dell_clean and dell_clean.lower() not in GENERIC_NAME_BLOCKLIST:
                return dell_clean

        # HPE iLO 5+: AdapterDetails.Name carries the human-readable product name
        # for PCIe NICs (e.g. "HPE Ethernet 1Gb 4-port 331i Adapter") even when
        # the top-level Name is the generic "Ethernet Network Adapter".
        hpe_details = ((raw_obj.get("Oem") or {}).get("Hpe") or {}).get("AdapterDetails") or {}
        hpe_name = str(hpe_details.get("Name") or hpe_details.get("Model") or "").strip()
        if hpe_name and hpe_name.lower() not in GENERIC_NAME_BLOCKLIST:
            return hpe_name

        raw_pn = raw_obj.get("PartNumber") or raw_obj.get("part_number") or ""
        pn = str(raw_pn or "").strip().upper()
        if pcie_cache:
            if pn and pn not in ("N/A", "NONE", "UNKNOWN", "NULL", ""):
                for dev in pcie_cache:
                    dev_name = str(dev.get("name", "")).strip()
                    dev_pn = str(dev.get("part_number") or "").strip().upper()
                    if dev_pn and dev_pn not in ("N/A", "NONE", "UNKNOWN", "NULL", "") and (pn in dev_pn or dev_pn in pn):
                        if dev_name and dev_name.lower() not in GENERIC_NAME_BLOCKLIST:
                            return dev_name
            # Try matching by exact VID:DID from extract_pci_ids_from_dict
            pci_info = extract_pci_ids_from_dict(raw_obj, get_fn=getattr(self, "_get", None))
            c_vid = pci_info.get("vendor_id")
            c_did = pci_info.get("device_id")
            if c_vid and c_did:
                for dev in pcie_cache:
                    dev_name = str(dev.get("name", "")).strip()
                    p_vid = dev.get("vendor_id", "")
                    p_did = dev.get("device_id", "")
                    if c_vid == p_vid and c_did == p_did:
                        if dev_name and dev_name.lower() not in GENERIC_NAME_BLOCKLIST:
                            return dev_name
            # Fallback to match_pcie_cache (links, slot location, model tokens)
            matched_dev = match_pcie_cache(raw_obj, pcie_cache, get_fn=getattr(self, "_get", None))
            if matched_dev:
                m_vid = matched_dev.get("vendor_id")
                m_did = matched_dev.get("device_id")
                for dev in pcie_cache:
                    if (m_vid and m_did and dev.get("vendor_id") == m_vid and dev.get("device_id") == m_did) or dev.get("id") == matched_dev.get("id"):
                        dev_name = str(dev.get("name", "")).strip()
                        if dev_name and dev_name.lower() not in GENERIC_NAME_BLOCKLIST:
                            return dev_name

        mfr = str(raw_obj.get("Manufacturer", "Ethernet") or "Ethernet").strip()
        return f"{mfr} Network Adapter"
