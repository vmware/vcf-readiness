"""
VCF Readiness Tool — GPU / accelerator / PCIe collection mixin.
"""
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, wait
from typing import TYPE_CHECKING, Any, Optional, Tuple

from ..logging_utils import get_nested

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
        def oem_gpu_sensors(self) -> list: ...
        def oem_handle_retry(self, data: dict, endpoint: str) -> bool: ...
        def oem_manager_paths(self) -> list: ...
        def oem_fastpath_roots(self) -> Optional[Tuple[list, list, list]]: ...
else:
    _CollectorBase = object

logger = logging.getLogger("vcf_assess")


from vcf_hci.collector.pci_utils import (
    extract_pci_ids_from_dict,
    extract_pcie_functions,
    extract_pcie_link_status,
    match_pcie_cache,
    normalize_pcie_errors,
    pcie_has_gpu_candidates,
)


class _GPUMixin(_CollectorBase):
    """Collection methods: PCIe devices, PCIe slots, GPU accelerators."""

    def collect_pcie_devices(self) -> list:
        pcie_list = []
        seen_ids: set = set()

        def _append_dev(dev: dict) -> None:
            dev_id = dev.get("Id") or dev.get("@odata.id", "")
            if dev_id in seen_ids:
                return
            seen_ids.add(dev_id)
            pci_info = extract_pci_ids_from_dict(dev, get_fn=self._get)
            link_info = extract_pcie_link_status(dev)

            slot = dev.get("Slot") or {}
            slot_loc = slot.get("Location") or {}
            part_loc = slot_loc.get("PartLocation") or {}
            slot_ordinal = part_loc.get("LocationOrdinalValue")
            slot_label = f"PCIe Slot {slot_ordinal}" if slot_ordinal is not None else ""
            if not slot_label:
                slot_label = slot_loc.get("ServiceLabel") or part_loc.get("ServiceLabel") or ""

            pcie_if = dev.get("PCIeInterface") or {}
            lanes = pcie_if.get("LanesInUse") or pcie_if.get("MaxLanes") or slot.get("Lanes")
            pcie_type = pcie_if.get("PCIeType") or pcie_if.get("MaxPCIeType") or slot.get("PCIeType") or ""
            health = str((dev.get("Status") or {}).get("Health") or "").strip()

            funcs = extract_pcie_functions(dev, get_fn=self._get)

            f0 = funcs[0] if funcs else {}
            v_id = pci_info["vendor_id"] or f0.get("vendor_id", "")
            d_id = pci_info["device_id"] or f0.get("device_id", "")
            sv_id = pci_info["subsystem_vendor_id"] or f0.get("subsystem_vendor_id", "")
            ss_id = pci_info["subsystem_id"] or f0.get("subsystem_id", "")
            p_quad = pci_info["pci_quad"] or f0.get("pci_quad", "")
            p_pair = pci_info["pci_pair"] or (f"{v_id}:{d_id}" if v_id and d_id else "")

            pcie_list.append({
                "id":                  dev_id,
                "name":                dev.get("Name") or dev.get("Model") or "",
                "manufacturer":        dev.get("Manufacturer") or "",
                "part_number":         dev.get("PartNumber") or "",
                "serial_number":       dev.get("SerialNumber") or "",
                "health":              health,
                "slot_label":          slot_label,
                "pcie_type":           pcie_type,
                "lanes":               lanes,
                "device_class":        str(
                    dev.get("DeviceClass")
                    or (dev.get("PCIeInterface") or {}).get("DeviceClass")
                    or ""
                ).upper(),
                "functions":           funcs,
                "function_count":      len(funcs),
                "vendor_id":           v_id,
                "device_id":           d_id,
                "subsystem_vendor_id": sv_id,
                "subsystem_id":        ss_id,
                "pci_quad":            p_quad,
                "pci_pair":            p_pair,
                "current_pcie_type":   link_info.get("current_pcie_type"),
                "max_pcie_type":       link_info.get("max_pcie_type"),
                "current_pcie_width":  link_info.get("current_pcie_width"),
                "max_pcie_width":      link_info.get("max_pcie_width"),
                "downgraded":          link_info["downgraded"],
                "downgrade_reason":    link_info["reason"],
                "downgrade_badge":     link_info["badge"],
                "_raw":                dev,
            })

        def _fetch_member_devs(members: list) -> list:
            if not members or (callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped()):
                return []

            results = []
            member_uris = []
            for m in members:
                if not isinstance(m, dict):
                    continue
                # If member is already an embedded device dictionary with specification details
                if any(k in m for k in ("PCIeFunctions", "PCIeInterface", "DeviceClass", "Manufacturer", "Model")) and len(m) > 2:
                    results.append(m)
                elif m.get("@odata.id"):
                    m_uri = str(m.get("@odata.id")).strip()
                    if m_uri and m_uri.lower() not in ("/empty", "empty", "none", "null", "n/a", "/"):
                        member_uris.append(m_uri)

            if not member_uris:
                return results

            _prio_high = ("slot", "integrated", "raid", "nic", "storage", "adapter", "gpu", "hba", "proc", "mezz", "perc", "ocp")
            _prio_low = ("bridge", "rootport", "internalbus", "virtualswitch")

            def _uri_priority_key(uri: str) -> int:
                u_lower = uri.lower()
                if any(kw in u_lower for kw in _prio_high):
                    return 0
                if any(kw in u_lower for kw in _prio_low):
                    return 2
                return 1

            member_uris.sort(key=_uri_priority_key)

            if len(member_uris) > 30:
                logger.debug("[%s] Capping PCIe device members from %d to 30 sorted items", getattr(self, "host", "unknown"), len(member_uris))
                member_uris = member_uris[:30]

            start_time = time.time()
            max_duration = 15.0
            chunk_size = 10

            for i in range(0, len(member_uris), chunk_size):
                if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                    break
                elapsed = time.time() - start_time
                remaining = max_duration - elapsed
                if remaining <= 0:
                    logger.debug("[%s] PCIe device collection reached 15s deadline; stopping chunk fetches", getattr(self, "host", "unknown"))
                    break

                chunk = member_uris[i:i + chunk_size]
                max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(3), max(1, len(chunk)))
                _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
                pool = ThreadPoolExecutor(max_workers=max_w)
                try:
                    futures = [pool.submit(_wrap_task(self._get), uri) for uri in chunk]
                    wait(futures, timeout=remaining)
                    for f in futures:
                        if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                            break
                        try:
                            if f.done():
                                dev = f.result()
                                if dev:
                                    results.append(dev)
                        except Exception as err:
                            logger.warning("[%s] Error fetching PCIe device URI: %s", getattr(self, "host", "unknown"), err)
                finally:
                    pool.shutdown(wait=False, cancel_futures=True)

            return results

        # DMTF standard path: /Chassis/{id}/PCIeDevices (Dell, Lenovo, Cisco)
        if self.chassis_uri and not (callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped()):
            pcie_ep = f"{self.chassis_uri}/PCIeDevices"
            fetch_expand_fn = getattr(self, "_fetch_expanded_collection", None)
            if callable(fetch_expand_fn) and getattr(self, "expand_supported", False):
                coll = fetch_expand_fn(pcie_ep)
                members = self._get_members(coll) if coll else []
            else:
                members = self._get_members(pcie_ep)
            for dev in _fetch_member_devs(members):
                _append_dev(dev)

        # HPE iLO path: /Systems/{id}/PCIeDevices (Gen10 / iLO 5+) or /Systems/{id}/PCIDevices (Gen9 / iLO 4)
        if self.sys_uri and not pcie_list and not (callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped()):
            members = self._get_members(f"{self.sys_uri}/PCIeDevices")
            if not members:
                sys_obj = getattr(self, "sys_data", {}) or {}
                pci_href = (
                    get_nested(sys_obj, "Oem", "Hp", "links", "PCIDevices", "href")
                    or get_nested(sys_obj, "Oem", "Hpe", "links", "PCIDevices", "href")
                    or f"{self.sys_uri}/PCIDevices"
                )
                members = self._get_members(pci_href)
            for dev in _fetch_member_devs(members):
                _append_dev(dev)

        # Embedded PCIeDevices fallback: check inline PCIeDevices arrays in System and Chassis roots
        if not pcie_list and not (callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped()):
            candidate_roots = []
            if self.sys_uri:
                candidate_roots.append(self.sys_uri)
            if self.chassis_uri:
                candidate_roots.append(self.chassis_uri)

            for root_uri in candidate_roots:
                root_data = self._get(root_uri)
                if isinstance(root_data, dict):
                    raw_devs = root_data.get("PCIeDevices")
                    if isinstance(raw_devs, list) and raw_devs:
                        for dev in _fetch_member_devs(raw_devs):
                            _append_dev(dev)
                        if not pcie_list:
                            for dev in raw_devs:
                                if isinstance(dev, dict):
                                    _append_dev(dev)
                if pcie_list:
                    break

        return pcie_list


    def collect_pcie_slots(self) -> list:
        """Enumerate physical PCIe slots from /Chassis/{id}/PCIeSlots.

        Returns one dict per slot regardless of population state so the report
        can show empty vs occupied at a glance.  Device detail is resolved by
        following the Links.PCIeDevice reference.

        Fields per slot:
            slot_label        str   "PCIe Slot 1" or "Slot N" (1-based index)
            lanes             int|None  max lane width from spec (e.g. 16)
            pcie_type         str|None  "Gen3", "Gen4", "Gen5" …
            slot_type         str|None  "FullLength", "HalfLength", "M2" …
            hot_pluggable     bool
            state             str       "Enabled", "Absent", "Disabled" …
            populated         bool
            device_name       str       name of installed device, or ""
            device_manufacturer str     ""
            device_part_number  str     ""
            device_serial       str     ""
            device_health       str     "OK", "Warning", "Critical", or ""
        """
        slots: list = []
        if not self.chassis_uri:
            return slots
        data = self._get(f"{self.chassis_uri}/PCIeSlots") or {}
        raw_slots = data.get("Slots") or []
        if not raw_slots:
            return slots

        # Collect unique linked PCIeDevice URIs across all slots
        dev_uris = set()
        for s in raw_slots:
            links = s.get("Links") or {}
            dev_refs = (
                links.get("PCIeDevice")
                or links.get("PCIeDevices")
                or s.get("PCIeDevice")
                or s.get("PCIeDevices")
                or []
            )
            if isinstance(dev_refs, dict):
                dev_refs = [dev_refs]
            for d_ref in dev_refs:
                if isinstance(d_ref, dict) and d_ref.get("@odata.id"):
                    dev_uris.add(d_ref.get("@odata.id"))

        # Pre-fetch uncached slot devices concurrently to eliminate serial latency
        if dev_uris and not (callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped()):
            max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(3), max(1, len(dev_uris)))
            _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
            pool = ThreadPoolExecutor(max_workers=max_w)
            try:
                futures = [pool.submit(_wrap_task(self._get), uri) for uri in dev_uris]
                wait(futures, timeout=15.0)
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

        for idx, s in enumerate(raw_slots, start=1):
            pcie_type_raw = s.get("PCIeType") or ""
            # Normalise "Gen3" / "PCIeGen3" / "Generation3" → "Gen3"
            gen_match = re.search(r"(\d)", pcie_type_raw)
            pcie_type = f"Gen{gen_match.group(1)}" if gen_match else (pcie_type_raw or None)

            lanes_raw = s.get("Lanes")
            lanes = int(lanes_raw) if isinstance(lanes_raw, (int, float)) and lanes_raw else None

            slot_type = s.get("SlotType") or None
            hot_pluggable = bool(s.get("HotPluggable", False))
            state = (s.get("Status") or {}).get("State") or "Unknown"

            # Build a human-readable label — vendors sometimes put it in Location
            location = s.get("Location") or {}
            loc_info = location.get("PartLocation") or {}
            label_raw = (
                loc_info.get("ServiceLabel")
                or location.get("ServiceLabel")
                or s.get("PhysicalLocation", {}).get("PartLocation", {}).get("ServiceLabel")
                or ""
            )
            slot_label = label_raw.strip() if label_raw else f"PCIe Slot {idx}"

            # Resolve linked PCIe device (if any)
            links = s.get("Links") or {}
            # The DMTF schema uses "PCIeDevice" (singular) as an array
            dev_refs = (
                links.get("PCIeDevice")
                or links.get("PCIeDevices")
                or s.get("PCIeDevice")
                or s.get("PCIeDevices")
                or []
            )
            if isinstance(dev_refs, dict):
                dev_refs = [dev_refs]

            populated = bool(dev_refs)
            device_name = device_manufacturer = device_part_number = device_serial = device_health = ""
            pci_info = {"vendor_id": "", "device_id": "", "subsystem_vendor_id": "", "subsystem_id": "", "pci_quad": "", "pci_pair": ""}
            link_info = {"downgraded": False, "reason": "", "badge": ""}
            funcs = []

            if dev_refs:
                dev_uri = dev_refs[0].get("@odata.id") if isinstance(dev_refs[0], dict) else None
                if dev_uri:
                    dev = self._get(dev_uri) or {}
                    device_name = str(dev.get("Name") or dev.get("Model") or "").strip()
                    device_manufacturer = str(dev.get("Manufacturer") or "").strip()
                    device_part_number = str(dev.get("PartNumber") or "").strip()
                    device_serial = str(dev.get("SerialNumber") or "").strip()
                    device_health = str((dev.get("Status") or {}).get("Health") or "").strip()
                    pci_info = extract_pci_ids_from_dict(dev, get_fn=self._get)
                    link_info = extract_pcie_link_status(dev)
                    funcs = extract_pcie_functions(dev, get_fn=self._get)

            slots.append({
                "slot_label":          slot_label,
                "lanes":               lanes,
                "pcie_type":           pcie_type,
                "slot_type":           slot_type,
                "hot_pluggable":       hot_pluggable,
                "state":               state,
                "populated":           populated,
                "device_name":         device_name,
                "device_manufacturer": device_manufacturer,
                "device_part_number":  device_part_number,
                "device_serial":       device_serial,
                "device_health":       device_health,
                "functions":           funcs,
                "function_count":      len(funcs),
                "vendor_id":           pci_info["vendor_id"],
                "device_id":           pci_info["device_id"],
                "subsystem_vendor_id": pci_info["subsystem_vendor_id"],
                "subsystem_id":        pci_info["subsystem_id"],
                "pci_quad":            pci_info["pci_quad"],
                "pci_pair":            pci_info["pci_pair"],
                "current_pcie_type":   link_info.get("current_pcie_type") if populated else None,
                "max_pcie_type":       link_info.get("max_pcie_type") or pcie_type,
                "current_pcie_width":  link_info.get("current_pcie_width") if populated else None,
                "max_pcie_width":      link_info.get("max_pcie_width") or lanes,
                "downgraded":          link_info["downgraded"],
                "downgrade_reason":    link_info["reason"],
                "downgrade_badge":     link_info["badge"],
            })

        return slots


    def _scan_pcie_switches(self, pcie_cache: Optional[list] = None) -> list:
        """Scan the PCIe device list for known PCIe switch chips.

        Returns a list of dicts with 'name' and 'note' for any switches found.
        vSAN can operate through PCIe switches but they should be flagged.
        """
        switches = []
        for dev in (pcie_cache or []):
            name = str(dev.get("name") or "").upper()
            mfr  = str(dev.get("manufacturer") or "").upper()
            combined = f"{name} {mfr}"
            if any(p.upper() in combined for p in self._PCIE_SWITCH_NAMES):
                switches.append({
                    "name": dev.get("name") or dev.get("id") or "PCIe Switch",
                    "manufacturer": dev.get("manufacturer") or "Unknown",
                    "note": (
                        "PCIe switch detected. vSAN can operate through PCIe switches "
                        "(e.g. NVMe-oF JBOFs, U.2 expansion shelves), but the switch "
                        "adds latency and may mask individual drive faults. Verify the "
                        "switch is in the Broadcom HCL."
                    ),
                })
        return switches


    def _extract_gpu_details(self, dev: dict, pcie_cache: Optional[list] = None) -> Optional[dict]:
        """Extract normalized GPU dictionary including ProcessorMetrics and PCIeErrors."""
        if not dev or not isinstance(dev, dict):
            return None
        model = dev.get("Model") or ""
        raw_name = dev.get("Name") or ""
        if model and (not raw_name or re.search(r'^(Video\.|GPU\.|Slot\.|Processor\b)', raw_name, re.I)):
            name = model
        elif raw_name:
            name = raw_name
        else:
            name = model or "Unknown GPU"
        mfr  = dev.get("Manufacturer") or ""

        pci_info = extract_pci_ids_from_dict(dev, get_fn=self._get)
        if not pci_info["pci_quad"] and pcie_cache:
            pci_info = match_pcie_cache(dev, pcie_cache, get_fn=self._get)

        # Strictly exclude network adapters / Mellanox DPUs from GPU accelerators
        vid = str(pci_info.get("vendor_id") or dev.get("VendorId") or "").lower().replace("0x", "")
        if vid == "15b3":  # Mellanox Technologies / NVIDIA Networking
            return None

        sub_vid = str(pci_info.get("subsystem_vendor_id") or dev.get("SubsystemVendorId") or "").lower().replace("0x", "")
        if sub_vid == "15b3":
            return None

        name_up = name.upper()
        mfr_up = mfr.upper()
        if "MELLANOX" in name_up or "MELLANOX" in mfr_up or "CONNECTX" in name_up or "BLUEFIELD" in name_up:
            return None
        if any(k in name_up for k in (" NIC", "OCP NIC", "NETWORK ADAPTER", "ETHERNET ADAPTER")):
            return None

        fw   = str(dev.get("FirmwareVersion") or "").strip()
        health = str((dev.get("Status") or {}).get("Health") or "").strip()

        # Try to get VRAM from onboard Memory collection or CapacityMiB field
        memory_gib = 0
        mem_list = dev.get("Memory") or []
        if isinstance(mem_list, list) and mem_list:
            first_mem_link = mem_list[0].get("@odata.id") if isinstance(mem_list[0], dict) else None
            if first_mem_link:
                mem_obj = self._get(first_mem_link) or {}
                cap_mib = mem_obj.get("CapacityMiB") or 0
                try:
                    memory_gib = round(int(cap_mib) / 1024, 1)
                except (ValueError, TypeError):
                    memory_gib = 0
            else:
                # Inline CapacityMiB on the accelerator object itself
                cap_mib = dev.get("CapacityMiB") or dev.get("MemoryMiB") or 0
                try:
                    memory_gib = round(int(cap_mib) / 1024, 1)
                except (ValueError, TypeError):
                    memory_gib = 0
        elif dev.get("CapacityMiB") or dev.get("MemoryMiB"):
            cap_mib = dev.get("CapacityMiB") or dev.get("MemoryMiB") or 0
            try:
                memory_gib = round(int(cap_mib) / 1024, 1)
            except (ValueError, TypeError):
                memory_gib = 0

        # Slot and PCIe interface detection
        slot_label = ""
        pcie_type = ""
        lanes = None
        slot = dev.get("Slot") or {}
        if isinstance(slot, dict):
            slot_loc = slot.get("Location") or {}
            part_loc = slot_loc.get("PartLocation") or {}
            s_ord = part_loc.get("LocationOrdinalValue")
            if s_ord is not None:
                slot_label = f"PCIe Slot {s_ord}"
            pcie_type = slot.get("PCIeType") or ""
            lanes = slot.get("Lanes")

        dev_id = str(dev.get("Id") or "")
        if not slot_label and ("Slot." in dev_id or "Slot" in dev_id):
            slot_m = re.search(r"Slot\.?(\d+)", dev_id, re.I)
            if slot_m:
                slot_label = f"PCIe Slot {slot_m.group(1)}"

        # Query Metrics / ProcessorMetrics / PCIeErrors
        temp_c = None
        pwr_w = None
        raw_pcie_errs = dev.get("PCIeErrors")
        m_link = (dev.get("Metrics") or dev.get("ProcessorMetrics") or {}).get("@odata.id")
        if not m_link and dev.get("@odata.id") and "/Processors/" in str(dev.get("@odata.id")):
            m_link = f"{dev.get('@odata.id')}/ProcessorMetrics"

        if m_link:
            pm_data = self._get(m_link, critical=False) or {}
            if not pm_data.get("error"):
                raw_pcie_errs = raw_pcie_errs or pm_data.get("PCIeErrors")
                if pm_data.get("TemperatureCelsius") is not None:
                    try:
                        temp_c = float(pm_data.get("TemperatureCelsius"))
                    except (ValueError, TypeError):
                        pass
                if pm_data.get("ConsumedPowerWatt") is not None:
                    try:
                        pwr_w = float(pm_data.get("ConsumedPowerWatt"))
                    except (ValueError, TypeError):
                        pass

        pcie_errors = normalize_pcie_errors(raw_pcie_errs)
        total_errs = pcie_errors.get("total_errors", 0) if pcie_errors else 0

        return {
            "name": name, "manufacturer": mfr, "id": dev.get("Id", ""),
            "part_number": dev.get("PartNumber", "") or "",
            "serial_number": dev.get("SerialNumber", "") or "",
            "firmware": fw, "health": health, "memory_gib": memory_gib,
            "slot_label": slot_label, "pcie_type": pcie_type, "lanes": lanes,
            "downgraded": False, "downgrade_reason": "", "downgrade_badge": "",
            "vendor_id": pci_info["vendor_id"], "device_id": pci_info["device_id"],
            "subsystem_vendor_id": pci_info["subsystem_vendor_id"], "subsystem_id": pci_info["subsystem_id"],
            "pci_quad": pci_info["pci_quad"], "pci_pair": pci_info["pci_pair"],
            "pcie_errors": pcie_errors,
            "pcie_bus_errors": total_errs,
            "temperature_c": temp_c,
            "power_watts": pwr_w,
            "max_operating_temp_c": None,
            "slowdown_temp_c": None,
            "shutdown_temp_c": None,
            "power_brake_status": "N/A",
            "thermal_alert_status": "N/A",
        }

    def collect_gpu_accelerators(self, pcie_cache: Optional[list] = None) -> list:
        """Discover GPU / hardware accelerators from PCIe device list or dedicated endpoint.

        For each GPU found via Redfish collections (/Accelerators, /Processors, or /PCIeDevices)
        the method also fetches live telemetry fields when available:
          firmware  — FirmwareVersion string (or "" if not exposed)
          health    — Status.Health  ("OK" / "Warning" / "Critical" / "")
          memory_gib — onboard VRAM in GiB from Memory[0].CapacityMiB (or 0)
          pcie_errors — normalized PCIeErrors dictionary with replay and recovery counters
        """
        gpus = []
        if not self.chassis_uri and not self.sys_uri:
            return gpus

        if pcie_cache and not pcie_has_gpu_candidates(pcie_cache):
            if not getattr(self, "_has_gpu_processors", False):
                acc_members = self._get_members(f"{self.sys_uri}/Accelerators") if self.sys_uri else []
                if not acc_members:
                    return gpus

        # 1. Try dedicated Accelerators endpoint (some vendors)
        if self.sys_uri:
            for m in self._get_members(f"{self.sys_uri}/Accelerators"):
                dev = self._get(m.get("@odata.id"))
                gpu_obj = self._extract_gpu_details(dev, pcie_cache)
                if gpu_obj:
                    gpus.append(gpu_obj)

        # 2. Try Processors endpoint for GPU processors (Dell iDRAC Video.Slot.*, Supermicro, etc.)
        if self.sys_uri:
            seen_ids = {g.get("id") for g in gpus}
            proc_members = self._get_members(f"{self.sys_uri}/Processors")
            for m in proc_members:
                m_uri = str(m.get("@odata.id", ""))
                is_gpu_uri = bool(re.search(r'/Video\.|/Accelerator\.|/GPU\.|\.GPU\.|\.Video\.', m_uri, re.I))
                if not is_gpu_uri and not getattr(self, "_has_gpu_processors", False):
                    continue
                dev = self._get(m_uri)
                if not dev:
                    continue
                ptype = str(dev.get("ProcessorType") or "").upper()
                if ptype in ("GPU", "ACCELERATOR", "DSP") or is_gpu_uri:
                    gpu_obj = self._extract_gpu_details(dev, pcie_cache)
                    if gpu_obj and gpu_obj.get("id") not in seen_ids:
                        seen_ids.add(gpu_obj.get("id"))
                        gpus.append(gpu_obj)
        # Fallback: scan PCIe cache for GPU device class codes
        if not gpus and pcie_cache:
            gpu_keywords = ["DISPLAY", "3D", "GPU", "NVIDIA", "AMD RADEON", "TESLA",
                            "H100", "H200", "A100", "A30", "A40", "L40", "V100",
                            "MI300", "MI250", "MI210", "GAUDI", "FLEX"]
            for dev in pcie_cache:
                # Use `or ""` so None values (null in Redfish JSON) don't become "NONE"
                dc   = str(dev.get("device_class") or "").upper()
                name = str(dev.get("name") or "").upper()
                mfr  = str(dev.get("manufacturer") or "").upper()

                # Exclude network devices, storage controllers, and Mellanox networking
                pci_info = match_pcie_cache(dev, pcie_cache, get_fn=getattr(self, "_get", None))
                vid = str(pci_info.get("vendor_id") or dev.get("vendor_id") or "").lower().replace("0x", "")
                if vid == "15b3":  # Mellanox Technologies / NVIDIA Networking
                    continue

                sub_vid = str(pci_info.get("subsystem_vendor_id") or dev.get("subsystem_vendor_id") or "").lower().replace("0x", "")
                if sub_vid == "15b3":
                    continue

                if "MELLANOX" in mfr:
                    continue

                if any(k in dc for k in ("NETWORK", "ETHERNET", "INFINIBAND", "STORAGE", "FIBRECHANNEL", "MASSSTORAGE")):
                    continue

                if any(k in name for k in ("CONNECTX", "BLUEFIELD", "ETHERNET", " NIC", "OCP NIC", "NETWORK ADAPTER", "FLR NIC", "MELLANOX")):
                    continue

                funcs = dev.get("functions") or []
                if isinstance(funcs, list):
                    if any(str(f.get("vendor_id") or "").lower().replace("0x", "") == "15b3" for f in funcs if isinstance(f, dict)):
                        continue
                    if any(str(f.get("subsystem_vendor_id") or "").lower().replace("0x", "") == "15b3" for f in funcs if isinstance(f, dict)):
                        continue
                    if any(any(k in str(f.get("device_class") or "").upper() for k in ("NETWORK", "ETHERNET", "INFINIBAND", "STORAGE")) for f in funcs if isinstance(f, dict)):
                        continue

                combined = f"{dc} {name} {mfr}"
                if any(k in combined for k in gpu_keywords):
                    raw_dev = dev.get("_raw") if isinstance(dev, dict) else dev
                    pn = dev.get("part_number") or (raw_dev.get("PartNumber") if isinstance(raw_dev, dict) else "") or ""
                    sn = dev.get("serial_number") or (raw_dev.get("SerialNumber") if isinstance(raw_dev, dict) else "") or ""
                    fw = dev.get("firmware") or (str(raw_dev.get("FirmwareVersion") or "").strip() if isinstance(raw_dev, dict) else "") or ""
                    health = dev.get("health") or (str((raw_dev.get("Status") or {}).get("Health") or "").strip() if isinstance(raw_dev, dict) else "") or ""
                    slot_label = dev.get("slot_label") or ""
                    pcie_type = dev.get("pcie_type") or ""
                    lanes = dev.get("lanes")
                    if not slot_label and isinstance(raw_dev, dict):
                        slot = raw_dev.get("Slot") or {}
                        slot_loc = slot.get("Location") or {}
                        part_loc = slot_loc.get("PartLocation") or {}
                        s_ord = part_loc.get("LocationOrdinalValue")
                        if s_ord is not None:
                            slot_label = f"PCIe Slot {s_ord}"
                        if not pcie_type:
                            pcie_type = slot.get("PCIeType") or ""
                        if lanes is None:
                            lanes = slot.get("Lanes")

                    gpus.append({
                        "name":                dev.get("name") or "Unknown GPU",
                        "manufacturer":        dev.get("manufacturer") or "",
                        "id":                  dev.get("id") or "",
                        "part_number":         pn,
                        "serial_number":       sn,
                        "firmware":            fw,
                        "health":              health,
                        "memory_gib":          0,
                        "slot_label":          slot_label,
                        "pcie_type":           pcie_type,
                        "lanes":               lanes,
                        "downgraded":          dev.get("downgraded", False),
                        "downgrade_reason":    dev.get("downgrade_reason", ""),
                        "downgrade_badge":     dev.get("downgrade_badge", ""),
                        "vendor_id":           pci_info["vendor_id"],
                        "device_id":           pci_info["device_id"],
                        "subsystem_vendor_id": pci_info["subsystem_vendor_id"],
                        "subsystem_id":        pci_info["subsystem_id"],
                        "pci_quad":            pci_info["pci_quad"],
                        "pci_pair":            pci_info["pci_pair"],
                        "pcie_errors":         normalize_pcie_errors(
                            dev.get("PCIeErrors") or (raw_dev.get("PCIeErrors") if isinstance(raw_dev, dict) else None)
                        ),
                        "pcie_bus_errors":     (
                            normalize_pcie_errors(
                                dev.get("PCIeErrors") or (raw_dev.get("PCIeErrors") if isinstance(raw_dev, dict) else None)
                            ) or {}
                        ).get("total_errors", 0),
                        "temperature_c":       None,
                        "power_watts":         None,
                        "max_operating_temp_c": None,
                        "slowdown_temp_c":     None,
                        "shutdown_temp_c":     None,
                        "power_brake_status":  "N/A",
                        "thermal_alert_status": "N/A",
                    })

        # Enrich with OEM GPU sensor telemetry (thermal, power brake, slot)
        if hasattr(self, "oem_gpu_sensors") and gpus:
            try:
                gpu_sensors = self.oem_gpu_sensors() or []
                for s in gpu_sensors:
                    s_dev_id = str(s.get("device_id") or "").upper()
                    s_slot_num = s.get("slot_number")
                    for g in gpus:
                        g_id = str(g.get("id") or "").upper()
                        g_slot = str(g.get("slot_label") or "").upper()
                        matched = (
                            (s_dev_id and (s_dev_id in g_id or s_dev_id in str(g.get("name", "")).upper()))
                            or (s_slot_num is not None and f"SLOT {s_slot_num}" in g_slot)
                            or (len(gpus) == 1 and len(gpu_sensors) == 1)
                        )
                        if matched:
                            if not g.get("slot_label") and s.get("slot"):
                                g["slot_label"] = s["slot"]
                            g["temperature_c"] = s.get("primary_temp_c")
                            g["max_operating_temp_c"] = s.get("max_operating_temp_c")
                            g["slowdown_temp_c"] = s.get("slowdown_temp_c")
                            g["shutdown_temp_c"] = s.get("shutdown_temp_c")
                            g["power_brake_status"] = s.get("power_brake_status")
                            g["thermal_alert_status"] = s.get("thermal_alert_status")
                            break
            except Exception as s_exc:
                logger.debug("Error mapping OEM GPU sensors: %s", s_exc)

        return gpus

