"""
VCF Readiness Tool — storage / drive collection mixin.
"""
import logging
import re
from concurrent.futures import ThreadPoolExecutor, wait
from typing import TYPE_CHECKING, Any, Optional, Tuple

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
        def oem_storage_fallback(self) -> list: ...
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

logger = logging.getLogger("vcf_assess")


from vcf_hci.collector.pci_utils import (
    extract_pci_ids_from_dict,
    match_firmware_inventory_pci,
    match_pcie_cache,
    normalize_pcie_errors,
)
from vcf_hci.constants import (
    DELL_MODEL_CHASSIS_DB,
    DELL_SKU_CHASSIS_DB,
    HPE_SKU_CHASSIS_DB,
    LENOVO_MODEL_CHASSIS_DB,
)
from vcf_hci.logging_utils import get_nested

from .collect_storage_drive import parse_drive_details


class _StorageMixin(_CollectorBase):
    """Collection methods: storage controllers, drives, enclosures."""

    # Known Tri-Mode controller name substrings (fallback when protocol lists are absent)
    _TRIMODE_NAMES = [
        # Broadcom / Avago / LSI MegaRAID Tri-Mode series
        "9460", "9480", "9560", "9580", "9600", "SAS3916", "SAS3908", "SAS 940", "SAS 960",
        "940-16I", "940-8I", "940-32I", "RAID 940", "THINKSYSTEM RAID 940",
        # HPE MR Gen10 Plus (Broadcom OEM)
        "MR GEN10", "MR216I", "MR408I",
        # HPE SmartHBA (tri-mode pass-through)
        "SMARTHBA",
        # Dell PERC H-series Gen14+ (tri-mode capable)
        "H750", "H755",
        # Generic
        "TRI-MODE", "TRI MODE", "TRIMODE",
    ]

    # Known Software RAID controller name/ID substrings (chipset/CPU-assisted RAID; not physical Tri-Mode or HW RAID)
    _SOFTWARE_RAID_NAMES = [
        # Dell PERC S-series software RAID
        "PERC S", "PERC S100", "PERC S110", "PERC S120", "PERC S130", "PERC S140", "PERC S150", "PERC S160",
        "S100", "S110", "S120", "S130", "S140", "S150", "S160",
        # HPE Dynamic Smart Array / Smart Array B-series / SR-series
        "DYNAMIC SMART ARRAY", "SMART ARRAY B", "SR100I", "SR100", "B110I", "B120I", "B140I", "B320I",
        # Intel RSTe / VROC / Generic Software RAID
        "RSTE", "RAPID STORAGE", "ESRT2", "MEGASR", "SOFTWARE RAID", "SW RAID",
        "EMBEDDED SATA RAID", "INTEL EMBEDDED SERVER RAID",
    ]

    # Known PCIe switch vendor/model patterns
    _PCIE_SWITCH_NAMES = [
        "PLX ", "PEX8", "SWITCHTEC", "PSX", "PAX ", "MICROSEMI", "BROADCOM SWITC",
    ]

    @staticmethod
    def _parse_controller_bbu(ctrl: dict) -> dict:
        """Extract Storage Controller Battery / Supercap (BBU) status."""
        cache_summary = ctrl.get("CacheSummary") or {}
        bbu_health = None

        dell_ctrl = get_nested(ctrl, "Oem", "Dell", "DellController", default={})
        if dell_ctrl and isinstance(dell_ctrl, dict):
            bbu_health = dell_ctrl.get("BatteryStatus")

        hpe_ctrl = get_nested(ctrl, "Oem", "Hpe", default={})
        if not bbu_health and hpe_ctrl and isinstance(hpe_ctrl, dict):
            batt = hpe_ctrl.get("Battery") or hpe_ctrl.get("CacheModule") or {}
            if isinstance(batt, dict):
                bbu_health = (batt.get("Status") or {}).get("Health") or batt.get("Condition")

        if not bbu_health and cache_summary and isinstance(cache_summary, dict):
            bbu_health = (cache_summary.get("Status") or {}).get("Health")

        if not bbu_health:
            return {
                "bbu_health": "N/A",
                "bbu_badge": None,
            }

        bbu_str = str(bbu_health).strip()
        bbu_upper = bbu_str.upper()

        if bbu_upper in ("OK", "GOOD", "HEALTHY", "READY"):
            badge = "<span class='badge success'>🟢 BBU / Supercap: Healthy</span>"
        elif bbu_upper in ("WARNING", "DEGRADED", "RECHARGING", "CHARGING"):
            badge = f"<span class='badge warning'>🟡 BBU / Supercap: {bbu_str}</span>"
        elif bbu_upper in ("CRITICAL", "FAILED", "ERROR"):
            badge = f"<span class='badge danger'>🔴 BBU / Supercap: {bbu_str} (Write-Through Mode Risk)</span>"
        else:
            badge = None

        return {
            "bbu_health": bbu_str,
            "bbu_badge": badge,
        }

    @staticmethod
    def _extract_fw_version(fw_raw) -> str:
        """Extract a string version from string or HPE dict FirmwareVersion."""
        if isinstance(fw_raw, dict):
            res = (
                get_nested(fw_raw, "Current", "VersionString")
                or fw_raw.get("VersionString")
                or fw_raw.get("Version")
                or ""
            )
            return str(res).strip()
        if fw_raw is not None:
            s = str(fw_raw).strip()
            if s.startswith("{"):
                m = re.search(r"['\"]VersionString['\"]\s*:\s*['\"]([^'\"]+)['\"]", s)
                if m:
                    return m.group(1).strip()
            return s
        return ""

    @staticmethod
    def _parse_enclosure(enc: dict, ctrl_id: str, ctrl_name: str) -> dict:
        """Normalise a Redfish Chassis or StorageEnclosure resource into a flat dict.

        Handles Dell Oem paths (DellEnclosure.Version, DellChassis.SubType),
        HPE SmartStorage paths (FirmwareVersion.Current.VersionString, DriveBayCount,
        EnclosureType), and the baseline DMTF Chassis schema.

        Returns:
            name             str
            model            str
            manufacturer     str
            serial_number    str
            firmware_version str   — backplane / SAS expander firmware
            slot_count       int|None
            enclosure_type   str   — "SAS Expander", "PCIe Backplane",
                                     "Backplane", "JBOD", "Enclosure"
            has_sas_expander bool
            lane_split_hint  bool  — PCIe switch / bridge present in path
            linked_ctrl_id   str
            linked_ctrl_name str
        """
        name         = str(enc.get("Name")         or "Unknown Enclosure").strip()
        model        = str(enc.get("Model")        or "").strip()
        manufacturer = str(enc.get("Manufacturer") or "").strip()
        serial       = str(enc.get("SerialNumber") or "").strip()
        chassis_type = str(enc.get("ChassisType")  or "").strip()

        # HPE SmartStorage returns Name = "HpeSmartStorageEnclosure" (resource-type
        # name, not a human-readable label).  Prefer the Model field which carries
        # the actual backplane description, e.g. "HPE 10SFF NVMe/SAS 10/8 Bkpln".
        _HPE_GENERIC_ENC = {"hpesmartstorageenclosure", "smartstorageenclosure", "storageenclosure"}
        if name.lower() in _HPE_GENERIC_ENC and model:
            name = model

        # ── Firmware: DMTF string → HPE nested object → Dell OEM ──────────────
        fw_raw = enc.get("FirmwareVersion")
        if isinstance(fw_raw, str):
            fw = fw_raw.strip()
        elif isinstance(fw_raw, dict):
            # HPE: {"Current": {"VersionString": "1.36"}}
            fw = str(get_nested(fw_raw, "Current", "VersionString") or "").strip()
        else:
            fw = ""
        if not fw:
            fw = str(get_nested(enc, "Oem", "Dell", "DellEnclosure", "Version") or "").strip()

        # ── Slot count ────────────────────────────────────────────────────────
        slot_raw = (
            enc.get("DriveBayCount")        # HPE SmartStorage
            or enc.get("DriveCount")        # DMTF generic
            or get_nested(enc, "Oem", "Dell", "DellEnclosure", "SlotCount")
        )
        slot_count = int(slot_raw) if isinstance(slot_raw, (int, float)) and slot_raw else None

        # Name-based fallback: parse bay count from patterns like "10SFF", "8LFF",
        # "HPE 10SFF NVMe/SAS 10/8 Bkpln", "12LFF backplane".
        # The API often reports only the SAS/SATA segment (e.g. 6 or 8), while the
        # backplane label advertises the full physical bay count.
        if not slot_count:
            _nc = f"{name} {model}"
            # Primary: leading digit before a form-factor token ("10SFF", "8LFF", "24U.2")
            _m = re.search(r'\b(\d+)\s*(?:SFF|LFF|U\.?2|U\.?3|NVMe)\b', _nc, re.I)
            if _m:
                slot_count = int(_m.group(1))
            else:
                # Secondary: "10/8 Bkpln" style — first number is total bays
                _m2 = re.search(r'\b(\d+)/\d+\b', _nc)
                if _m2:
                    slot_count = int(_m2.group(1))

        # ── Type classification ───────────────────────────────────────────────
        dell_sub   = str(get_nested(enc, "Oem", "Dell", "DellChassis", "SubType") or "").upper()
        hpe_type   = str(enc.get("EnclosureType") or "").upper()
        combined   = f"{name.upper()} {model.upper()} {dell_sub} {hpe_type} {chassis_type.upper()}"

        # "+EXP" = Dell BPxxG+EXP backplane-with-expander naming (BP14G+EXP, BP15G+EXP, BP16G+EXP…)
        # "BPN-EXP" = Supermicro expander backplane boards (BPN-EXP-847DR1EL1, BPN-EXP-847DR1EL2…)
        if any(k in combined for k in ["SASEXPANDER", "SAS EXPANDER", "SAS_EXPANDER", "EXPANDER", "+EXP", "BPN-EXP"]):
            enclosure_type   = "SAS Expander"
            has_sas_expander = True
        elif "JBOD" in combined:
            enclosure_type   = "JBOD"
            has_sas_expander = True   # JBODs use SAS expanders internally
        elif "SES" in combined and "BACKPLANE" not in combined:
            enclosure_type   = "SAS Enclosure (SES)"
            has_sas_expander = True
        elif any(k in combined for k in ["PCIE", "NVME", "BRIDGE"]):
            enclosure_type   = "PCIe Backplane"
            has_sas_expander = False
        elif any(k in combined for k in ["BACKPLANE", "DRIVEBACKPLANE", "MIDPLANE"]):
            enclosure_type   = "Backplane"
            has_sas_expander = False
        else:
            enclosure_type   = "Enclosure"
            has_sas_expander = False

        lane_split_hint = any(
            k in combined for k in ["PCIE SWITCH", "PCIE BRIDGE", "PLX", "PEX8", "SWITCHTEC"]
        )

        return {
            "name":              name,
            "model":             model,
            "manufacturer":      manufacturer,
            "serial_number":     serial,
            "firmware_version":  fw or "N/A",
            "slot_count":        slot_count,
            "enclosure_type":    enclosure_type,
            "has_sas_expander":  has_sas_expander,
            "lane_split_hint":   lane_split_hint,
            "linked_ctrl_id":    ctrl_id,
            "linked_ctrl_name":  ctrl_name,
        }


    def _expand_odata_stubs(self, items: Any) -> list:
        """Expand OData link stubs (dict with @odata.id or URI string) into full objects."""
        if items is None:
            return []
        raw_list = items if isinstance(items, list) else [items]
        expanded = []
        for it in raw_list:
            if isinstance(it, str):
                full = self._get(it)
                if isinstance(full, dict):
                    expanded.append(full)
                continue
            if not isinstance(it, dict):
                continue
            odata_id = it.get("@odata.id") or it.get("href")
            has_full_keys = any(
                k in it for k in (
                    "SupportedDeviceProtocols", "SupportedControllerProtocols",
                    "CapacityBytes", "CapacityGiB", "CapacityGB", "CapacityMiB",
                    "CapacityLogicalBlocks", "BlockSizeBytes",
                    "SerialNumber", "MediaType", "InterfaceType", "InterfaceSpeedMbps",
                    "DiskDriveUse", "EncryptedDrive", "Location", "Model",
                    "Manufacturer", "PartNumber",
                )
            ) or bool(it.get("Id") and (it.get("Name") or it.get("Model")))
            if odata_id and not has_full_keys:
                if hasattr(self, "_request_cache") and odata_id in self._request_cache:
                    full = self._request_cache[odata_id]
                else:
                    full = self._get(odata_id)
                if isinstance(full, dict):
                    expanded.append(full)
                else:
                    expanded.append(it)
            else:
                expanded.append(it)
        return expanded

    def _parse_ctrl_pcie(self, ctrl_json: dict) -> dict:
        """Extract PCIe interface and device protocol info from a Storage resource.

        Handles both the inline StorageControllers array (common on older firmware)
        and the newer Controllers sub-collection link (iLO 5.304+, iDRAC9 7+).

        Returns a dict with:
            device_protocols  list[str]  e.g. ["NVMe"] or ["NVMe","SAS","SATA"]
            ctrl_protocols    list[str]  e.g. ["PCIe"]
            is_trimode        bool       NVMe + SAS/SATA in device_protocols
            pcie_lanes_in_use int|None   current negotiated lanes (controller level)
            pcie_max_lanes    int|None
            pcie_gen          str|None   e.g. "Gen4"
            pcie_gen_max      str|None
        """
        result: dict = {
            "device_protocols": [],
            "ctrl_protocols":   [],
            "is_trimode":       False,
            "is_software_raid": False,
            "pcie_lanes_in_use": None,
            "pcie_max_lanes":    None,
            "pcie_gen":          None,
            "pcie_gen_max":      None,
        }

        # 1. Try inline StorageControllers array or inline Controllers array
        sc_raw = ctrl_json.get("StorageControllers")
        ctrls_raw = ctrl_json.get("Controllers")
        if isinstance(sc_raw, list) and sc_raw:
            sc_list = self._expand_odata_stubs(sc_raw)
        elif isinstance(ctrls_raw, list) and ctrls_raw:
            sc_list = self._expand_odata_stubs(ctrls_raw)
        elif isinstance(ctrls_raw, dict) and ctrls_raw.get("@odata.id"):
            # 2. Try sub-collection link (newer Redfish schema)
            sub_uri = ctrls_raw.get("@odata.id")
            raw_members = self._get_members(sub_uri)
            sc_list = self._expand_odata_stubs(raw_members)
        else:
            sc_list = []

        for sc in sc_list:
            if not isinstance(sc, dict):
                continue
            for proto in sc.get("SupportedDeviceProtocols") or []:
                if proto not in result["device_protocols"]:
                    result["device_protocols"].append(proto)
            for proto in sc.get("SupportedControllerProtocols") or []:
                if proto not in result["ctrl_protocols"]:
                    result["ctrl_protocols"].append(proto)
            pcie_if = sc.get("PCIeInterface") or {}
            if pcie_if.get("LanesInUse") is not None and result["pcie_lanes_in_use"] is None:
                result["pcie_lanes_in_use"] = pcie_if["LanesInUse"]
            if pcie_if.get("MaxLanes") is not None and result["pcie_max_lanes"] is None:
                result["pcie_max_lanes"] = pcie_if["MaxLanes"]
            if pcie_if.get("PCIeType") and not result["pcie_gen"]:
                result["pcie_gen"] = pcie_if["PCIeType"]
            if pcie_if.get("MaxPCIeType") and not result["pcie_gen_max"]:
                result["pcie_gen_max"] = pcie_if["MaxPCIeType"]

        # Check for Host Software RAID identifiers
        ctrl_ident_str = f"{ctrl_json.get('Name', '')} {ctrl_json.get('Id', '')} {ctrl_json.get('Model', '')}".upper()
        for sc in sc_list:
            if isinstance(sc, dict):
                ctrl_ident_str += f" {sc.get('Name', '')} {sc.get('Id', '')} {sc.get('Model', '')}".upper()

        is_sw_raid = any(p in ctrl_ident_str for p in self._SOFTWARE_RAID_NAMES)
        result["is_software_raid"] = is_sw_raid

        # Tri-mode: device protocols include NVMe alongside SAS or SATA (never software RAID)
        dp_up = {p.upper() for p in result["device_protocols"]}
        result["is_trimode"] = "NVME" in dp_up and bool(dp_up & {"SAS", "SATA"}) and not is_sw_raid
        return result

    def _collect_ctrl_port_pcie_errors(self, ctrl: dict, sc_candidates: list) -> Tuple[Optional[dict], list]:
        """Discover and aggregate PortMetrics PCIeErrors across controller ports."""
        port_metrics_list = []
        collected_errs = []
        seen_port_uris: set = set()

        # Check direct controller PCIeErrors or Metrics
        for direct_obj in [ctrl] + (sc_candidates or []):
            if not isinstance(direct_obj, dict):
                continue
            if "PCIeErrors" in direct_obj:
                ne = normalize_pcie_errors(direct_obj["PCIeErrors"])
                if ne:
                    collected_errs.append(ne)
            metrics_uri = (direct_obj.get("Metrics") or {}).get("@odata.id") if isinstance(direct_obj.get("Metrics"), dict) else None
            if metrics_uri and metrics_uri not in seen_port_uris:
                seen_port_uris.add(metrics_uri)
                m_data = self._get(metrics_uri) or {}
                if "PCIeErrors" in m_data:
                    ne = normalize_pcie_errors(m_data["PCIeErrors"])
                    if ne:
                        collected_errs.append(ne)

        # Look for Ports collection in ctrl or StorageControllers
        port_refs = []
        for obj in [ctrl] + (sc_candidates or []):
            if not isinstance(obj, dict):
                continue
            p = obj.get("Ports")
            if isinstance(p, dict) and p.get("@odata.id"):
                port_refs.append(p.get("@odata.id"))
            elif isinstance(p, list):
                for item in p:
                    if isinstance(item, dict) and item.get("@odata.id"):
                        port_refs.append(item.get("@odata.id"))

        for p_col_uri in port_refs:
            if p_col_uri in seen_port_uris:
                continue
            seen_port_uris.add(p_col_uri)
            port_members = self._get_members(p_col_uri, limit=8)
            for pm in port_members:
                pm_uri = pm.get("@odata.id") if isinstance(pm, dict) else (pm if isinstance(pm, str) else None)
                if not pm_uri or pm_uri in seen_port_uris:
                    continue
                seen_port_uris.add(pm_uri)
                p_data = self._get(pm_uri) or {}
                m_uri = (p_data.get("Metrics") or {}).get("@odata.id") if isinstance(p_data.get("Metrics"), dict) else f"{pm_uri}/Metrics"
                m_data = self._get(m_uri) or {}
                p_errs = None
                if "PCIeErrors" in m_data:
                    p_errs = normalize_pcie_errors(m_data["PCIeErrors"])
                elif "PCIeErrors" in p_data:
                    p_errs = normalize_pcie_errors(p_data["PCIeErrors"])
                if p_errs:
                    collected_errs.append(p_errs)
                    port_metrics_list.append({
                        "port_id": p_data.get("Id") or pm_uri.split("/")[-1],
                        "name": p_data.get("Name") or "Port",
                        "uri": pm_uri,
                        "pcie_errors": p_errs,
                    })

        if not collected_errs:
            return None, port_metrics_list

        agg = {
            "correctable_errors": None,
            "l0_to_recovery_count": None,
            "replay_count": None,
            "replay_rollover_count": None,
            "non_fatal_errors": None,
            "fatal_errors": None,
            "nak_received_count": None,
            "nak_sent_count": None,
            "unsupported_requests": None,
            "total_errors": 0,
        }
        for err in collected_errs:
            for k in (
                "correctable_errors", "l0_to_recovery_count", "replay_count",
                "replay_rollover_count", "non_fatal_errors", "fatal_errors",
                "nak_received_count", "nak_sent_count", "unsupported_requests",
            ):
                val = err.get(k)
                if val is not None:
                    agg[k] = (agg[k] or 0) + val
            t = err.get("total_errors")
            if t is not None:
                agg["total_errors"] = (agg["total_errors"] or 0) + t

        return agg, port_metrics_list


    def _parse_drive_details(self, *args: Any, **kwargs: Any) -> Optional[dict]:
        """Parse a single drive Redfish resource into a normalized drive dict.

        ctrl_pcie (from _parse_ctrl_pcie) supplies controller-level PCIe info —
        lane width, generation, and the tri-mode flag.  These are augmented by
        any PCIeInterface fields present directly on the drive resource itself.
        """
        return parse_drive_details(self, *args, **kwargs)

    def _populate_request_cache(self, uri: str, data: dict) -> None:
        """Pre-populate self._request_cache with pre-expanded Redfish resources."""
        pop_fn = getattr(super(), "_populate_request_cache", None)
        if callable(pop_fn):
            pop_fn(uri, data)
            return
        if not uri or not isinstance(data, dict):
            return
        if uri.startswith("http"):
            url = uri
        elif uri.startswith("/redfish/v1"):
            url = f"{getattr(self, 'host_url', '')}{uri}"
        else:
            url = f"{getattr(self, 'base_url', '')}/{uri.lstrip('/')}"

        cache_lock = getattr(self, "_cache_lock", None)
        if hasattr(self, "_request_cache"):
            if cache_lock:
                with cache_lock:
                    self._request_cache[url] = data
            else:
                self._request_cache[url] = data

    def collect_storage_subsystem(self, pcie_cache: Optional[list] = None) -> list:
        storage_data = []

        # Collect controller URIs in priority order: /Storage first, then
        # /SimpleStorage, then /SmartStorage. Using an insertion-ordered dict
        # (not a set) so Storage URIs are always processed before SimpleStorage
        # URIs when both expose the same physical controller.  The seen_ctrl_ids
        # dedup that follows ensures we take whichever representation we see
        # first — which will be the richer /Storage one.
        ordered_uris: dict = {}   # uri -> endpoint label, preserves order

        if getattr(self, "vendor", "") == "supermicro":
            self.expand_supported = False
            # Route directly to SimpleStorage, avoiding DCMS license blocks on /Storage
            primary_eps = [f"{self.sys_uri}/SimpleStorage"]
            for extra in self.oem_storage_endpoints():
                if extra and extra not in primary_eps:
                    primary_eps.append(extra)
        else:
            if getattr(self, "vendor", "") in ("quanta",):
                self.expand_supported = False
            primary_eps = [f"{self.sys_uri}/Storage"]
            for extra in self.oem_storage_endpoints():
                if extra and extra not in primary_eps:
                    primary_eps.append(extra)

        unsupported_endpoints = getattr(self, "_unsupported_expand_endpoints", None)
        if unsupported_endpoints is None:
            self._unsupported_expand_endpoints = set()
            unsupported_endpoints = self._unsupported_expand_endpoints

        for ep in primary_eps:
            if not self.sys_uri:
                continue
            coll = None
            fetch_expand_fn = getattr(self, "_fetch_expanded_collection", None)
            if (
                callable(fetch_expand_fn)
                and getattr(self, "expand_supported", False)
                and "/Storage" in ep
                and ep not in unsupported_endpoints
            ):
                coll = fetch_expand_fn(ep, levels=1)
            elif (
                getattr(self, "expand_supported", False)
                and "/Storage" in ep
                and ep not in unsupported_endpoints
            ):
                syntax = getattr(self, "expand_syntax", None) or "."
                expand_ep = f"{ep}?$expand={syntax}($levels=1)"
                coll = self._get(expand_ep, critical=False)
                if not coll or not isinstance(coll, dict) or coll.get("error"):
                    alt_syntax = "*" if syntax == "." else "."
                    expand_ep_alt = f"{ep}?$expand={alt_syntax}($levels=1)"
                    coll = self._get(expand_ep_alt, critical=False)
                if not coll or not isinstance(coll, dict) or coll.get("error"):
                    unsupported_endpoints.add(ep)
                    coll = None

            if coll is None:
                coll = self._get(ep) or {}

            # Supermicro DCMS license gate
            lic_msg = self._is_license_blocked(coll)
            if lic_msg:
                idx = primary_eps.index(ep) if ep in primary_eps else len(primary_eps)
                has_pending_simple = any("/SimpleStorage" in p for p in primary_eps[idx + 1 :])
                if ordered_uris or has_pending_simple:
                    continue
                storage_data.append({
                    "id": "license-blocked",
                    "name": f"⚠️ Storage API Unavailable — {lic_msg}",
                    "has_logical_volumes": False,
                    "drives": [],
                })
                return storage_data

            # If coll contains expanded members or controllers, cache them for fast lookup
            members = self._get_members(coll)
            for m in members:
                uri = (m.get("@odata.id") or m.get("href")) if isinstance(m, dict) else (m if isinstance(m, str) else None)
                if uri and uri not in ordered_uris:
                    ordered_uris[uri] = ep
                # Cache pre-expanded controller objects
                if isinstance(m, dict) and uri and len(m) > 2 and any(k in m for k in ("Id", "Name", "StorageControllers", "Drives", "PhysicalDrives", "DiskDrives")):
                    self._populate_request_cache(uri, m)
                    for drv_key in ("Drives", "PhysicalDrives", "DiskDrives"):
                        drvs = m.get(drv_key)
                        if isinstance(drvs, list):
                            for d in drvs:
                                d_uri = (d.get("@odata.id") or d.get("href")) if isinstance(d, dict) else None
                                if d_uri and len(d) > 2:
                                    self._populate_request_cache(d_uri, d)
                    for lnk_drv_key in ("PhysicalDrives", "DiskDrives", "Drives"):
                        lnk_drvs = get_nested(m, "Links", lnk_drv_key) or get_nested(m, "links", lnk_drv_key)
                        if isinstance(lnk_drvs, list):
                            for d in lnk_drvs:
                                d_uri = (d.get("@odata.id") or d.get("href")) if isinstance(d, dict) else None
                                if d_uri and len(d) > 2:
                                    self._populate_request_cache(d_uri, d)

            # Discover HPE SmartStorage links and inline controller arrays
            for oem_ctrl_key in ("ArrayControllers", "HostBusAdapters"):
                ctrl_ref = (
                    (coll.get(oem_ctrl_key) if isinstance(coll, dict) else None)
                    or get_nested(coll, "Links", oem_ctrl_key)
                    or get_nested(coll, "links", oem_ctrl_key)
                )
                if isinstance(ctrl_ref, dict):
                    ctrl_link_uri = ctrl_ref.get("@odata.id") or ctrl_ref.get("href")
                    if ctrl_link_uri and ctrl_link_uri not in primary_eps and ctrl_link_uri not in ordered_uris:
                        primary_eps.append(ctrl_link_uri)
                elif isinstance(ctrl_ref, list):
                    for idx, inline_c in enumerate(ctrl_ref):
                        if not isinstance(inline_c, dict):
                            continue
                        c_uri = inline_c.get("@odata.id") or inline_c.get("href") or f"{ep}/{inline_c.get('Id', idx)}"
                        if c_uri not in ordered_uris:
                            ordered_uris[c_uri] = ep
                        self._populate_request_cache(c_uri, inline_c)
                        for drv_key in ("Drives", "PhysicalDrives", "DiskDrives"):
                            drvs = inline_c.get(drv_key) or get_nested(inline_c, "Links", drv_key) or get_nested(inline_c, "links", drv_key)
                            if isinstance(drvs, list):
                                for d in drvs:
                                    d_uri = (d.get("@odata.id") or d.get("href")) if isinstance(d, dict) else None
                                    if d_uri and len(d) > 2:
                                        self._populate_request_cache(d_uri, d)

            # Direct controller endpoint (e.g. Cisco Storage/MRAID) without collection Members
            if not members and isinstance(coll, dict) and any(k in coll for k in ("StorageControllers", "Drives", "Controllers", "PhysicalDrives", "DiskDrives")):
                direct_uri = coll.get("@odata.id") or coll.get("href") or ep
                if direct_uri and direct_uri not in ordered_uris:
                    ordered_uris[direct_uri] = ep
                    self._populate_request_cache(direct_uri, coll)
                    for drv_key in ("Drives", "PhysicalDrives", "DiskDrives"):
                        drvs = coll.get(drv_key)
                        if isinstance(drvs, list):
                            for d in drvs:
                                d_uri = (d.get("@odata.id") or d.get("href")) if isinstance(d, dict) else None
                                if d_uri and len(d) > 2:
                                    self._populate_request_cache(d_uri, d)

        # Fall back to /SimpleStorage or /SmartStorage/ArrayControllers if no controllers found yet
        if not ordered_uris and self.sys_uri:
            fallback_eps = [
                f"{self.sys_uri}/SimpleStorage",
                f"{self.sys_uri}/SmartStorage/ArrayControllers",
                f"{self.sys_uri}/SmartStorage/HostBusAdapters",
                f"{self.sys_uri}/SmartStorage",
            ]
            for ep in fallback_eps:
                if ep in primary_eps:
                    continue
                coll = self._get(ep) or {}
                lic_msg = self._is_license_blocked(coll)
                if lic_msg:
                    storage_data.append({
                        "id": "license-blocked",
                        "name": f"⚠️ Storage API Unavailable — {lic_msg}",
                        "has_logical_volumes": False,
                        "drives": [],
                    })
                    return storage_data
                for m in self._get_members(coll):
                    uri = (m.get("@odata.id") or m.get("href")) if isinstance(m, dict) else (m if isinstance(m, str) else None)
                    if uri and uri not in ordered_uris:
                        ordered_uris[uri] = ep

                # Check inline/links ArrayControllers under SmartStorage root
                for oem_ctrl_key in ("ArrayControllers", "HostBusAdapters"):
                    ctrl_ref = (
                        (coll.get(oem_ctrl_key) if isinstance(coll, dict) else None)
                        or get_nested(coll, "Links", oem_ctrl_key)
                        or get_nested(coll, "links", oem_ctrl_key)
                    )
                    if isinstance(ctrl_ref, dict):
                        ctrl_link_uri = ctrl_ref.get("@odata.id") or ctrl_ref.get("href")
                        if ctrl_link_uri:
                            for ac_m in self._get_members(ctrl_link_uri):
                                ac_uri = (ac_m.get("@odata.id") or ac_m.get("href")) if isinstance(ac_m, dict) else (ac_m if isinstance(ac_m, str) else None)
                                if ac_uri and ac_uri not in ordered_uris:
                                    ordered_uris[ac_uri] = ep

        seen_ctrl_ids: set = set()
        seen_ctrl_serials: set = set()
        seen_ctrl_pci_quads: set = set()
        seen_ctrl_models: set = set()
        seen_drive_serials: set = set()

        for uri in ordered_uris:
            ctrl = self._get(uri)
            if not ctrl:
                continue
            ctrl_id   = str(ctrl.get("Id", "Unknown"))
            ctrl_name = str(ctrl.get("Name") or ctrl.get("Id") or "Storage Controller").strip()
            ctrl_sn   = str(
                ctrl.get("SerialNumber")
                or get_nested(ctrl, "Oem", "Hpe", "SerialNumber")
                or get_nested(ctrl, "Oem", "Dell", "SerialNumber")
                or ""
            ).strip()

            # Deduplicate by ctrl_id or serial number
            if ctrl_id in seen_ctrl_ids:
                continue
            if ctrl_sn and ctrl_sn in seen_ctrl_serials:
                logger.debug("Skipping duplicate storage controller by serial %s (ID: %s)", ctrl_sn, ctrl_id)
                continue

            vols_ref = ctrl.get("Volumes") or {}
            if isinstance(vols_ref, dict):
                _v_uri = vols_ref.get("@odata.id") or vols_ref.get("href")
                if _v_uri:
                    vols = self._get_members(_v_uri)
                else:
                    vols = vols_ref.get("Members", [])
            else:
                vols = vols_ref if isinstance(vols_ref, list) else []
            if not isinstance(vols, list):
                vols = []

            # HPE SmartStorage: LogicalDrives is a link ({@odata.id} or {href}),
            # not an inline Members list.  Follow the link to check for volumes.
            hpe_ld_ref = (
                ctrl.get("LogicalDrives")
                or get_nested(ctrl, "Links", "LogicalDrives")
                or get_nested(ctrl, "links", "LogicalDrives")
                or get_nested(ctrl, "links", "logicaldrives")
                or {}
            )
            if isinstance(hpe_ld_ref, dict):
                _ld_uri = hpe_ld_ref.get("@odata.id") or hpe_ld_ref.get("href")
                if _ld_uri:
                    hpe_ld = self._get_members(_ld_uri)
                else:
                    hpe_ld = hpe_ld_ref.get("Members") or hpe_ld_ref.get("members", [])
            else:
                hpe_ld = hpe_ld_ref if isinstance(hpe_ld_ref, list) else []
            if not isinstance(hpe_ld, list):
                hpe_ld = []
            has_lv = len(vols) > 0 or len(hpe_ld) > 0

            is_boot_ctrl = any(
                k in ctrl_id.upper() or k in ctrl_name.upper()
                for k in ["BOSS", "NS204I", "AHCI.SLOT"]
            )

            # Check for drive references before expanding enclosures or PCI cache
            raw_drives = ctrl.get("Drives", [])
            if isinstance(raw_drives, dict) and (raw_drives.get("@odata.id") or raw_drives.get("href")):
                raw_drives = self._get_members(raw_drives.get("@odata.id") or raw_drives.get("href"))
            elif isinstance(raw_drives, list) and raw_drives:
                raw_drives = self._expand_odata_stubs(raw_drives)
            if not raw_drives:
                _pd_ref = (
                    ctrl.get("PhysicalDrives")
                    or ctrl.get("DiskDrives")
                    or (ctrl.get("Links") or {}).get("PhysicalDrives")
                    or (ctrl.get("Links") or {}).get("DiskDrives")
                    or (ctrl.get("Links") or {}).get("Drives")
                    or (ctrl.get("links") or {}).get("PhysicalDrives")
                    or (ctrl.get("links") or {}).get("DiskDrives")
                    or (ctrl.get("links") or {}).get("Drives")
                    or (ctrl.get("links") or {}).get("physicaldrives")
                    or (ctrl.get("links") or {}).get("diskdrives")
                    or {}
                )
                if isinstance(_pd_ref, dict):
                    _pd_uri = _pd_ref.get("@odata.id") or _pd_ref.get("href")
                    if _pd_uri:
                        if hasattr(self, "_request_cache") and _pd_uri in self._request_cache:
                            pd_cached = self._request_cache[_pd_uri]
                            raw_drives = pd_cached if isinstance(pd_cached, list) else (
                                (pd_cached.get("Members") or pd_cached.get("members") or []) if isinstance(pd_cached, dict) else []
                            )
                        else:
                            raw_drives = self._get_members(_pd_uri)
                    else:
                        raw_drives = _pd_ref.get("Members") or _pd_ref.get("members") or []
                elif isinstance(_pd_ref, list) and _pd_ref:
                    raw_drives = _pd_ref
            drives = (raw_drives or ctrl.get("Devices", []))
            if isinstance(drives, list) and drives:
                drives = self._expand_odata_stubs(drives)
            drive_items = [dr for dr in drives if isinstance(dr, dict)]

            # Bypass PCI matching and enclosure expansion for unused 0-drive storage controllers
            if not drive_items and not has_lv and not is_boot_ctrl:
                logger.debug(
                    "Bypassing expansion for unused storage controller %s (ID: %s, 0 drives, 0 volumes)",
                    ctrl_name, ctrl_id,
                )
                continue

            # ── Controller firmware + model ────────────────────────────────
            ctrl_fw    = self._extract_fw_version(ctrl.get("FirmwareVersion"))
            ctrl_model = str(ctrl.get("Model") or "").strip()
            _generic_names = {
                "STORAGE CONTROLLER", "HPE SMART STORAGE ARRAY CONTROLLER",
                "ARRAY CONTROLLER", "SMART ARRAY CONTROLLER", "SMARTSTORAGE ARRAY CONTROLLER",
                "CONTROLLER", "STORAGE",
            }
            # Fall back into Controllers or StorageControllers if top-level is absent or generic
            sc_candidates = []
            if isinstance(ctrl.get("Controllers"), list):
                sc_candidates.extend(self._expand_odata_stubs(ctrl.get("Controllers")))
            if isinstance(ctrl.get("StorageControllers"), list):
                sc_candidates.extend(self._expand_odata_stubs(ctrl.get("StorageControllers")))

            for sc in sc_candidates:
                if isinstance(sc, dict):
                    if not ctrl_fw:
                        ctrl_fw = self._extract_fw_version(sc.get("FirmwareVersion") or sc.get("FirmwarePackageVersion"))
                    if not ctrl_model:
                        ctrl_model = str(sc.get("Model") or sc.get("PartNumber") or "").strip()
                    sc_name = str(sc.get("Name") or "").strip()
                    if sc_name and sc_name.upper() not in _generic_names:
                        if (
                            not ctrl_name
                            or ctrl_name == "Storage Controller"
                            or ctrl_name.upper() in _generic_names
                            or ctrl_name == ctrl_id
                            or ctrl_name.lower().startswith("controller_")
                        ):
                            ctrl_name = sc_name
                if ctrl_fw and ctrl_model:
                    break

            if ctrl_model and (
                ctrl_name.upper() in _generic_names
                or ctrl_name.upper().startswith("HPE SMART STORAGE ARRAY")
                or ctrl_name.upper().startswith("SMART STORAGE ARRAY")
                or ctrl_name == ctrl_id
                or ctrl_name.lower().startswith("controller_")
            ):
                ctrl_name = ctrl_model

            # ── PCIe / tri-mode analysis for this controller ───────────────
            ctrl_pcie = self._parse_ctrl_pcie(ctrl)
            # Name-based tri-mode / software RAID fallback when device protocol list is absent
            ctrl_name_up_local = ctrl_name.upper()
            ctrl_id_up_local = ctrl_id.upper()
            ctrl_model_up_local = str(ctrl.get("Model") or ctrl_model).upper()
            ctrl_full_str = f"{ctrl_name_up_local} {ctrl_id_up_local} {ctrl_model_up_local}"

            _is_sw_raid = ctrl_pcie.get("is_software_raid", False) or any(p in ctrl_full_str for p in self._SOFTWARE_RAID_NAMES)
            if _is_sw_raid:
                ctrl_pcie["is_software_raid"] = True
                ctrl_pcie["is_trimode"] = False

            _is_known_non_trimode = any(
                p in ctrl_name_up_local or p in ctrl_id_up_local
                for p in ["AHCI", "SATA", "INTEL", "VMD", "CPU", "DIRECT", "CHIPSET", "ASMEDIA", "AMD", "ASROCK", "ASUS", "EXTENDER", "EXPANDER", "RETIMER", "SWITCH", "BRIDGE", "UNMANAGED", "HBA3", "HBA 3", "HBA330", "HBA350", "HBA355"]
            ) or _is_sw_raid
            if not ctrl_pcie["is_trimode"] and not _is_sw_raid:
                ctrl_pcie["is_trimode"] = (
                    any(p.upper() in ctrl_name_up_local or p.upper() in ctrl_full_str for p in self._TRIMODE_NAMES)
                    and not _is_known_non_trimode
                )
            elif _is_known_non_trimode and not any(p.upper() in ctrl_name_up_local for p in self._TRIMODE_NAMES):
                ctrl_pcie["is_trimode"] = False

            # ── Enclosure / backplane discovery ───────────────────────────
            seen_enc_uris: set = set()
            enclosures: list = []

            # Path 1 — DMTF Links.Enclosures (Dell iDRAC, generic Redfish)
            for enc_ref in (get_nested(ctrl, "Links", "Enclosures", default=[]) or []):
                enc_uri = enc_ref.get("@odata.id") if isinstance(enc_ref, dict) else None
                if not enc_uri or enc_uri in seen_enc_uris:
                    continue
                seen_enc_uris.add(enc_uri)
                enc = self._get(enc_uri) or {}
                if enc.get("Id") or enc.get("Name"):
                    enclosures.append(
                        self._parse_enclosure(enc, ctrl_id, ctrl_name)
                    )

            # Path 2 — HPE SmartStorage Links.StorageEnclosures collection
            hpe_enc_coll_uri = (
                get_nested(ctrl, "Links", "StorageEnclosures", "@odata.id")
                or get_nested(ctrl, "Links", "StorageEnclosures", "href")
                or get_nested(ctrl, "links", "StorageEnclosures", "@odata.id")
                or get_nested(ctrl, "links", "StorageEnclosures", "href")
                or get_nested(ctrl, "links", "storageenclosures", "href")
            )
            if hpe_enc_coll_uri:
                for enc_ref in self._get_members(hpe_enc_coll_uri):
                    enc_uri = (enc_ref.get("@odata.id") or enc_ref.get("href")) if isinstance(enc_ref, dict) else (enc_ref if isinstance(enc_ref, str) else None)
                    if not enc_uri or enc_uri in seen_enc_uris:
                        continue
                    seen_enc_uris.add(enc_uri)
                    enc = self._get(enc_uri) or {}
                    if enc.get("Id") or enc.get("Name"):
                        enclosures.append(
                            self._parse_enclosure(enc, ctrl_id, ctrl_name)
                        )

            ctrl_pci = extract_pci_ids_from_dict(ctrl, get_fn=self._get)
            if not ctrl_pci["pci_quad"] and pcie_cache:
                ctrl_pci = match_pcie_cache(ctrl, pcie_cache, get_fn=self._get)
            if not ctrl_pci["pci_quad"]:
                ctrl_pci = match_firmware_inventory_pci(ctrl_name or ctrl_model, get_fn=self._get)

            ctrl_pci_quad = ctrl_pci.get("pci_quad") or ""
            if ctrl_pci_quad and ctrl_pci_quad not in ("N/A", "0000:0000:0000:0000") and ctrl_pci_quad in seen_ctrl_pci_quads:
                logger.debug("Skipping duplicate storage controller by PCI quad %s (ID: %s)", ctrl_pci_quad, ctrl_id)
                continue

            # Volume / Virtual Disk details
            volumes_list = []
            vol_members = vols if vols else hpe_ld
            if not vol_members and get_nested(ctrl, "Volumes", "@odata.id"):
                vol_members = self._get_members(ctrl["Volumes"]["@odata.id"])

            if vol_members:
                for v_item in (vol_members if isinstance(vol_members, list) else []):
                    v_uri = v_item.get("@odata.id") if isinstance(v_item, dict) else (v_item if isinstance(v_item, str) else None)
                    if not v_uri:
                        continue
                    v_obj = self._get(v_uri) or {}
                    if not v_obj or v_obj.get("error"):
                        continue
                    v_name = str(v_obj.get("LogicalDriveName") or v_obj.get("Name") or v_obj.get("Id") or "Volume").strip()
                    v_type = str(v_obj.get("VolumeType") or v_obj.get("RAIDType") or (f"RAID {v_obj['Raid']}" if v_obj.get("Raid") else "") or v_obj.get("LogicalDriveType") or "RAID").strip()
                    cap_bytes = v_obj.get("CapacityBytes")
                    cap_gib = v_obj.get("CapacityGiB")
                    cap_mib = v_obj.get("CapacityMiB")
                    cap_b = 0
                    if isinstance(cap_bytes, (int, float)) and cap_bytes > 0:
                        cap_b = int(cap_bytes)
                    elif isinstance(cap_gib, (int, float)) and cap_gib > 0:
                        cap_b = int(cap_gib * (1024**3))
                    elif isinstance(cap_mib, (int, float)) and cap_mib > 0:
                        cap_b = int(cap_mib * (1024**2))
                    v_cap_gb = round(cap_b / (1024**3), 1) if cap_b else 0
                    v_health = str((v_obj.get("Status") or {}).get("Health") or "OK").strip()
                    v_bootable = bool(v_obj.get("Bootable") or v_obj.get("IsBootDisk") or "BOOT" in v_name.upper())

                    volumes_list.append({
                        "id": str(v_obj.get("Id") or v_name),
                        "name": v_name,
                        "volume_type": v_type,
                        "capacity_gb": v_cap_gb,
                        "health": v_health,
                        "bootable": v_bootable,
                    })

            _NON_RAID_VOL_TYPES = {
                "RAWDEVICE", "RAW", "PASSTHROUGH", "PASS-THROUGH",
                "NONRAID", "NON-RAID", "NONREDUNDANTRAW", "DIRECT",
            }
            if volumes_list:
                has_lv = any(
                    str(v.get("volume_type", "")).upper() not in _NON_RAID_VOL_TYPES
                    for v in volumes_list
                )
            elif vol_members:
                _is_passthrough_ctrl = any(
                    k in ctrl_name.upper() or k in ctrl_id.upper()
                    for k in ["EXTENDER", "EXPANDER", "RETIMER", "SWITCH", "BRIDGE", "DIRECT", "AHCI", "HBA", "NONRAID", "UNMANAGED"]
                )
                has_lv = not _is_passthrough_ctrl
            else:
                has_lv = False

            bbu_info = self._parse_controller_bbu(ctrl)
            ctrl_pcie_errs, ctrl_port_metrics = self._collect_ctrl_port_pcie_errors(ctrl, sc_candidates)

            ctrl_info = {
                "id":                  ctrl_id,
                "name":                ctrl_name,
                "ctrl_firmware":       ctrl_fw or "N/A",
                "ctrl_model":          ctrl_model,
                "has_logical_volumes": has_lv,
                "bbu_health":          bbu_info["bbu_health"],
                "bbu_badge":           bbu_info["bbu_badge"],
                "volumes":             volumes_list,
                "is_trimode":          ctrl_pcie["is_trimode"],
                "is_software_raid":    ctrl_pcie.get("is_software_raid", False),
                "device_protocols":    ctrl_pcie["device_protocols"],
                "pcie_lanes_in_use":   ctrl_pcie["pcie_lanes_in_use"],
                "pcie_max_lanes":      ctrl_pcie["pcie_max_lanes"],
                "pcie_gen":            ctrl_pcie["pcie_gen"],
                "pcie_errors":         ctrl_pcie_errs,
                "port_metrics":        ctrl_port_metrics,
                "enclosures":          enclosures,
                "drives":              [],
                # BOSS-S1/S2 and NS204I are M.2 boot-device cards, not standard drive bays.
                # Flag them so bay-count logic and Drive Bay UI can exclude them.
                "is_boot_ctrl":        any(
                    k in ctrl_id.upper() or k in ctrl_name.upper()
                    for k in ["BOSS", "NS204I", "AHCI.SLOT"]
                ),
                "vendor_id":           ctrl_pci["vendor_id"],
                "device_id":           ctrl_pci["device_id"],
                "subsystem_vendor_id": ctrl_pci["subsystem_vendor_id"],
                "subsystem_id":        ctrl_pci["subsystem_id"],
                "pci_quad":            ctrl_pci["pci_quad"],
                "pci_pair":            ctrl_pci["pci_pair"],
            }
            # Concurrently fetch drive details via sub-threadpool
            drive_jsons = []
            drives_to_fetch = []
            for dr in drive_items:
                if not isinstance(dr, dict):
                    continue
                # If drive item is already populated with specification details from $expand or inline array:
                has_full = any(
                    k in dr
                    for k in (
                        "CapacityBytes",
                        "CapacityGiB",
                        "CapacityGB",
                        "CapacityMiB",
                        "MediaType",
                        "Model",
                        "SerialNumber",
                        "InterfaceType",
                        "InterfaceSpeedMbps",
                        "DiskDriveUse",
                        "EncryptedDrive",
                        "BlockSizeBytes",
                        "Manufacturer",
                        "PartNumber",
                    )
                ) and len(dr) > 2
                if has_full:
                    drive_jsons.append(dr)
                elif dr.get("@odata.id") and hasattr(self, "_request_cache") and dr["@odata.id"] in self._request_cache:
                    cached_dr = self._request_cache[dr["@odata.id"]]
                    if isinstance(cached_dr, dict) and len(cached_dr) > 1:
                        drive_jsons.append(cached_dr)
                    else:
                        drives_to_fetch.append(dr)
                elif dr.get("@odata.id"):
                    drives_to_fetch.append(dr)
                else:
                    drive_jsons.append(dr)

            if drives_to_fetch:
                max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(3), len(drives_to_fetch))
                _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
                pool = ThreadPoolExecutor(max_workers=max_w)
                try:
                    futures = [
                        pool.submit(_wrap_task(self._get), dr["@odata.id"]) if dr.get("@odata.id") else None
                        for dr in drives_to_fetch
                    ]
                    active_futs = [f for f in futures if f is not None]
                    if active_futs:
                        wait(active_futs, timeout=20.0)
                    for fut, dr in zip(futures, drives_to_fetch):
                        if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                            break
                        if fut is None:
                            if isinstance(dr, dict):
                                drive_jsons.append(dr)
                        else:
                            try:
                                if fut.done():
                                    res = fut.result()
                                    if isinstance(res, dict):
                                        drive_jsons.append(res)
                            except Exception as exc:
                                logger.debug(f"Error fetching drive data: {exc}")
                finally:
                    pool.shutdown(wait=False, cancel_futures=True)

            for dr_data in drive_jsons:
                if isinstance(dr_data, dict):
                    parsed = self._parse_drive_details(
                        ctrl_id, ctrl_name, dr_data, has_lv,
                        ctrl_pcie=ctrl_pcie, pcie_cache=pcie_cache)
                    if parsed:
                        ctrl_info["drives"].append(parsed)

            # Record seen controller identifiers
            seen_ctrl_ids.add(ctrl_id)
            if ctrl_sn:
                seen_ctrl_serials.add(ctrl_sn)
            if ctrl_pci_quad and ctrl_pci_quad not in ("N/A", "0000:0000:0000:0000"):
                seen_ctrl_pci_quads.add(ctrl_pci_quad)

            # Record non-empty drive serial numbers from this controller to catch
            # dual-endpoint controllers that lack serial/PCI quad.
            ctrl_drive_sns = {
                d.get("serial_number")
                for d in ctrl_info["drives"]
                if d.get("populated", True) and d.get("serial_number")
            }
            if ctrl_drive_sns and ctrl_drive_sns.issubset(seen_drive_serials):
                logger.debug(
                    "Skipping duplicate storage controller %s (ID: %s) — all attached drives (%s) already processed",
                    ctrl_name, ctrl_id, ctrl_drive_sns
                )
                continue
            seen_drive_serials.update(ctrl_drive_sns)

            storage_data.append(ctrl_info)

        # ── OEM storage fallback (e.g. Cisco nuova XML plugin) ───────────
        if not storage_data or all(len(c.get("drives", [])) == 0 for c in storage_data):
            fallback_storage = self.oem_storage_fallback()
            if fallback_storage:
                logger.info(
                    "OEM storage fallback yielded %d controller(s)",
                    len(fallback_storage),
                )
                if not storage_data:
                    storage_data = fallback_storage
                else:
                    # Filter out empty placeholder controllers if fallback has populated controllers
                    storage_data = [c for c in storage_data if len(c.get("drives", [])) > 0]
                    storage_data.extend(fallback_storage)

        # ── Globalized Synthetic empty bays per enclosure ────────────────────
        # If the enclosures report slot_counts but we have no absent-bay
        # records from the BMC across any controller, generate placeholder empties
        # ONCE globally for the main chassis so the bay-utilization view can show
        # accurate free-slot counts without multiplying empty bays across controllers.
        non_boot_ctrls = [c for c in storage_data if isinstance(c, dict) and not c.get("is_boot_ctrl")]
        if non_boot_ctrls:
            total_bmc_absent = 0
            for c in non_boot_ctrls:
                c_drives = c.get("drives")
                if isinstance(c_drives, list):
                    for d in c_drives:
                        if isinstance(d, dict) and not d.get("populated", True):
                            total_bmc_absent += 1

            if total_bmc_absent == 0:
                total_populated = 0
                for c in non_boot_ctrls:
                    c_drives = c.get("drives")
                    if isinstance(c_drives, list):
                        for d in c_drives:
                            if isinstance(d, dict) and d.get("populated", True):
                                total_populated += 1

                total_slots = 0
                for c in non_boot_ctrls:
                    c_encs = c.get("enclosures")
                    enc_slots = 0
                    if isinstance(c_encs, list):
                        for e in c_encs:
                            if isinstance(e, dict) and not e.get("has_sas_expander"):
                                s_cnt = e.get("slot_count")
                                if isinstance(s_cnt, (int, float)):
                                    enc_slots += int(s_cnt)
                    if enc_slots > total_slots:
                        total_slots = enc_slots

                _sku_sys = getattr(self, "sys_sku", "").upper()
                _sku_entry = HPE_SKU_CHASSIS_DB.get(_sku_sys) or DELL_SKU_CHASSIS_DB.get(_sku_sys)
                if _sku_entry and _sku_entry[0] > total_slots:
                    total_slots = _sku_entry[0]
                    logger.debug(
                        "Slot count overridden by SKU DB: SKU=%s → %d bays (%s)",
                        self.sys_sku, total_slots, _sku_entry[1],
                    )
                elif not _sku_entry and total_slots == 0:
                    _raw_model = getattr(self, "sys_model", "")
                    _mkey = re.sub(r'^(?:PowerEdge|ProLiant|ThinkSystem)\s+', '', _raw_model, flags=re.I).upper().strip()
                    _mkey = re.sub(r'[-]\d+$', '', _mkey)
                    _dell_entry = DELL_MODEL_CHASSIS_DB.get(_mkey)
                    if _dell_entry and _dell_entry[0] > total_slots:
                        total_slots = _dell_entry[0]
                        logger.debug(
                            "Slot count fallback from Dell model DB: model=%s → %d bays (%s)",
                            _raw_model, total_slots, _dell_entry[1],
                        )
                    else:
                        _lenovo_entry = LENOVO_MODEL_CHASSIS_DB.get(_mkey)
                        if isinstance(_lenovo_entry, dict):
                            _bays_val = _lenovo_entry.get("bays", 0)
                            if isinstance(_bays_val, int) and _bays_val > total_slots:
                                total_slots = _bays_val
                                logger.debug(
                                    "Slot count fallback from Lenovo model DB: model=%s → %d bays (%s)",
                                    _raw_model, total_slots, _lenovo_entry.get("label", ""),
                                )

                synthetic_needed = max(0, total_slots - total_populated)
                if synthetic_needed > 0:
                    target_ctrl = None
                    for c in non_boot_ctrls:
                        c_drives = c.get("drives")
                        if isinstance(c_drives, list) and any(isinstance(d, dict) and d.get("populated", True) for d in c_drives):
                            target_ctrl = c
                            break
                    if target_ctrl is None and non_boot_ctrls:
                        target_ctrl = non_boot_ctrls[0]

                    if target_ctrl is not None:
                        ctrl_drives = target_ctrl.get("drives")
                        if not isinstance(ctrl_drives, list):
                            ctrl_drives = []
                            target_ctrl["drives"] = ctrl_drives
                        for _i in range(synthetic_needed):
                            ctrl_drives.append({
                            "populated":           False,
                            "bay_slot":            None,
                            "bay_position":        "Front",
                            "is_edsff":            False,
                            "form_factor_label":   "",
                            "nvme_connector":      "",
                            "id":                  f"synthetic-empty-{_i}",
                            "name":               "Empty Bay",
                            "model":               "",
                            "product_id":          "",
                            "media_type":          "",
                            "protocol":            "",
                            "capacity_gb":         0,
                            "firmware":            "",
                            "endurance_remaining_pct": "N/A",
                            "drive_health":        "",
                            "category":            "Empty",
                            "vsan_eligible":       False,
                            "status_badge":        "<span style='color:var(--text-muted)'>&#9675; Empty</span>",
                            "behind_trimode":      False,
                            "single_lane_alert":   False,
                            "pcie_lanes_in_use":   None,
                            "pcie_max_lanes":      None,
                            "pcie_gen":            None,
                            "is_qlc":              False,
                        })

        return storage_data

    # ------------------------------------------------------------------
    # Main assessment entry point
    # ------------------------------------------------------------------
