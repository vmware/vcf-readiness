"""
VCF Readiness Tool — network adapter / NIC / HBA / LLDP collection mixin.
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
        def oem_drive_endurance(self, drive_json: dict) -> Optional[float]: ...
        def oem_drive_metrics(self, drive_json: dict) -> dict: ...
        def oem_nic_firmware(self, adapter_json: dict) -> str: ...
        def oem_cpu_cache(self, proc_json: dict) -> list: ...
        def oem_memory_usage(self, sys_data: dict) -> dict: ...
        def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict: ...
        def oem_port_transceiver(self, port_json: dict) -> dict: ...
        def oem_pcie_link_status(self, dev_dict: dict) -> Optional[dict]: ...
        def oem_handle_retry(self, data: dict, endpoint: str) -> bool: ...
        def oem_manager_paths(self) -> list: ...
        def oem_fastpath_roots(self) -> Optional[Tuple[list, list, list]]: ...
else:
    _CollectorBase = object

logger = logging.getLogger("vcf_assess")


from vcf_hci.collector.network_identity import _clean_mac_address as _clean_mac_address
from vcf_hci.collector.network_identity import classify_cna_adapter as classify_cna_adapter
from vcf_hci.collector.network_identity import infer_nic_manufacturer as infer_nic_manufacturer
from vcf_hci.collector.network_members import collect_network_adapter_member
from vcf_hci.collector.network_ports import (
    _evaluate_npar_partitions as _evaluate_npar_partitions,
)
from vcf_hci.collector.network_ports import (
    extract_nic_speed_gbps,
    finalize_network_adapters,
)
from vcf_hci.collector.network_ports import (
    link_fields_from_payload as link_fields_from_payload,
)
from vcf_hci.collector.network_resources import (
    fetch_network_collection,
    network_adapter_endpoints,
    prime_network_cache,
)
from vcf_hci.collector.network_resources import (
    linked_adapter_ports as linked_adapter_ports,
)
from vcf_hci.collector.pci_utils import (
    extract_pci_ids_from_dict,
    extract_pcie_link_status,
    match_pcie_cache,
    pcie_has_fc_candidates,
)
from vcf_hci.constants import is_generic_name, normalize_component_manufacturer
from vcf_hci.fc_inventory import normalize_fc_ports
from vcf_hci.logging_utils import get_nested

_STORAGE_ARRAY_OUI_TABLE = [
    # Dell EMC
    (re.compile(r"^50:00:14:4[0-9a-f]", re.I), "Dell EMC", "PowerStore / EqualLogic"),
    (re.compile(r"^50:06:01:6[0-9a-f]", re.I), "Dell EMC", "Unity / VNX / Clariion"),
    (re.compile(r"^50:00:09:7[0-9a-f]", re.I), "Dell EMC", "PowerMax / VMAX / Symmetrix"),
    (re.compile(r"^50:01:43:8[0-9a-f]", re.I), "Dell EMC", "Compellent SC Series"),
    (re.compile(r"^50:06:04:8[0-9a-f]", re.I), "Dell EMC", "XtremIO / EMC SAN"),

    # Pure Storage
    (re.compile(r"^52:4a:93:7[0-9a-f]", re.I), "Pure Storage", "FlashArray (FA-Series //X //C //XL)"),
    (re.compile(r"^52:4a:93:[0-9a-f]{2}", re.I), "Pure Storage", "FlashArray"),

    # NetApp
    (re.compile(r"^50:0a:09:8[0-9a-f]", re.I), "NetApp", "ONTAP / AFF / FAS"),
    (re.compile(r"^50:0a:09:[0-9a-f]{2}", re.I), "NetApp", "ONTAP / FAS"),
    (re.compile(r"^50:08:0e:8[0-9a-f]", re.I), "NetApp", "E-Series / EF-Series"),

    # HPE
    (re.compile(r"^50:06:0e:8[0-9a-f]", re.I), "HPE", "3PAR StoreServ / Primera / Alletra 9000"),
    (re.compile(r"^50:01:43:8[0-9a-f]", re.I), "HPE", "Nimble Storage / Alletra 6000"),
    (re.compile(r"^50:00:14:4[0-9a-f]", re.I), "HPE", "MSA / StoreVirtual"),
    (re.compile(r"^50:00:2a:c[0-9a-f]", re.I), "HPE", "XP Storage / Hitachi OEM"),

    # IBM
    (re.compile(r"^50:05:07:6[0-9a-f]", re.I), "IBM", "FlashSystem / Storwize / SVC"),
    (re.compile(r"^50:01:73:8[0-9a-f]", re.I), "IBM", "DS8000 Series"),

    # Hitachi Vantara (HDS)
    (re.compile(r"^50:06:0e:8[0-9a-f]", re.I), "Hitachi Vantara", "VSP (Virtual Storage Platform)"),
    (re.compile(r"^50:00:87:6[0-9a-f]", re.I), "Hitachi Vantara", "VSP Series"),
    (re.compile(r"^50:01:10:a[0-9a-f]", re.I), "Hitachi Vantara", "Hitachi Universal Storage"),

    # SAN Fabric Switches
    (re.compile(r"^(?:10:00:00:05:33|10:00:00:05:1e|10:00:50:eb|20:00:00:05:33|20:00:00:2a)", re.I), "Brocade / Broadcom", "Fibre Channel SAN Switch"),
    (re.compile(r"^(?:50:00:0c|20:00:00:0d|20:00:00:de)", re.I), "Cisco", "MDS SAN Switch"),
]


def _is_valid_wwpn(val: Optional[str]) -> bool:
    """Check if string is a genuine 8-byte (16 hex char) WWPN / WWNN, not a 6-byte MAC or all zeros."""
    if not val or str(val).strip().upper() in ("N/A", "NONE", ""):
        return False
    clean = re.sub(r"[:\-\.]", "", str(val)).strip().lower()
    if len(clean) != 16 or not all(c in "0123456789abcdef" for c in clean):
        return False
    return clean not in ("0000000000000000", "ffffffffffffffff")


def lookup_storage_array_vendor(wwpn: str) -> dict:
    """Map a Fibre Channel WWPN to known storage array vendor and family via IEEE OUI prefix."""
    s = str(wwpn or "").strip()
    if not s or s.upper() in ("N/A", "NONE", "UNKNOWN", "—", ""):
        return {"vendor": "Unknown Array", "family": "", "is_known_array": False}
    clean = re.sub(r"[^0-9A-Fa-f:]", "", s)
    if ":" not in clean and len(clean) == 16:
        clean = ":".join(clean[i:i+2] for i in range(0, 16, 2))
    for pat, vendor, family in _STORAGE_ARRAY_OUI_TABLE:
        if pat.search(clean):
            return {
                "vendor": vendor,
                "family": family,
                "is_known_array": True,
            }
    return {
        "vendor": "Unknown Array",
        "family": "",
        "is_known_array": False,
    }


def parse_fc_netdev_function(fc: Optional[dict]) -> dict:
    """Extract initiator WWPN/WWNN and SAN boot targets from a FibreChannel object.

    Handles DMTF keys (WWNN, LUN) and Dell iDRAC aliases (LUNID; PermanentWWN*).
    """
    fc = fc or {}
    fn_wwpn = str(fc.get("WWPN") or fc.get("PermanentWWPN") or "").strip()
    fn_wwnn = str(
        fc.get("WWNN") or fc.get("PermanentWWNN") or fc.get("WWN") or ""
    ).strip()
    boot_targets = []
    for bt in (fc.get("BootTargets") or []):
        if not isinstance(bt, dict):
            continue
        t_wwpn = str(bt.get("WWPN") or bt.get("TargetWWPN") or "").strip()
        if not t_wwpn:
            continue
        arr_info = lookup_storage_array_vendor(t_wwpn)
        lun_raw = bt.get("LUNID") or bt.get("LUN") or bt.get("BootLUN") or "0"
        boot_targets.append({
            "target_wwpn": t_wwpn,
            "lun": str(lun_raw).strip(),
            "priority": int(bt.get("BootPriority", 0) or 0),
            "target_array_vendor": arr_info["vendor"],
            "target_array_family": arr_info["family"],
        })
    return {
        "wwpn": fn_wwpn,
        "wwnn": fn_wwnn,
        "boot_targets": boot_targets,
    }


def _usable_lldp_system_desc(text: Any) -> str:
    s = str(text or "").strip()
    if not s:
        return ""
    s_low = s.lower()
    if "dellswitchconnection" in s_low or "will have the switch connection" in s_low or s_low.startswith("an instance of"):
        return ""
    return s[:120]


class _NetworkMixin(_CollectorBase):
    """Collection methods: NICs, FC HBAs, LLDP neighbors."""

    @staticmethod
    def _extract_nic_speed_gbps(port: dict, adapter: dict, resolved_name: str = "") -> float:
        return extract_nic_speed_gbps(port, adapter, resolved_name)

    def collect_network_adapters(self, pcie_cache: Optional[list] = None) -> list:
        """Return a list of physical NICs with port-level speed data.

        Endpoint strategy (tried in order):
          Chassis/NetworkAdapters      — HPE, Dell, Lenovo (physical adapter view
                                         with Manufacturer/PN/NetworkPorts)
          Systems/{id}/NetworkInterfaces — Cisco IMC primary path; Redfish 1.5+
          Systems/{id}/EthernetInterfaces — Cisco, Intel, others (logical port view)

        Deduplication notes
        -------------------
        EthernetInterfaces returns one entry *per port partition*, using IDs like
        ``NIC.Integrated.1-1-1``.  NetworkAdapters for the same hardware uses
        ``NIC.Integrated.1`` (without the port/partition suffix).  Without prefix
        deduplication these show up as separate "link-down, no data" rows even
        though the physical adapter is already represented with full details.

        The helper ``_get_parent_iface_id`` associates logical interfaces
        with observed adapters using MAC, guarded ID-prefix and PCIe evidence.
        Member processing merges their useful facts into the selected parent.

        EthernetInterfaces port data
        ----------------------------
        EthernetInterface resources *are* a port — they don't have a NetworkPorts
        sub-collection.  For entries that survive deduplication (Cisco, Intel,
        standalone onboard NICs), we synthesise a port entry from the top-level
        ``LinkStatus`` / ``SpeedMbps`` fields.

        License gating
        --------------
        When an endpoint returns OemLicenseNotPassed (Supermicro DCMS) a sentinel
        entry is injected so the HTML report shows a specific warning instead of
        an empty table.
        """

        nic_list = []
        seen_ids = set()
        license_blocked_note = None
        endpoints = network_adapter_endpoints(self.chassis_uri, self.sys_uri)
        fetch_expand_fn = prime_network_cache(self)

        expandable_map = self.oem_expandable_collections() if hasattr(self, "oem_expandable_collections") else {}
        for ep in endpoints:
            coll = fetch_network_collection(self, ep, fetch_expand_fn, expandable_map)
            lic_msg = self._is_license_blocked(coll)
            if lic_msg:
                license_blocked_note = lic_msg
                continue
            is_eth_iface_ep = "EthernetInterfaces" in ep
            for member in self._get_members(coll):
                try:
                    collect_network_adapter_member(self, member, is_eth_iface_ep, pcie_cache, nic_list, seen_ids)
                except Exception as m_exc:
                    logger.debug("Error processing network adapter member %s: %s", member, m_exc)

        return finalize_network_adapters(nic_list, license_blocked_note)

    def collect_fc_hbas(self, pcie_cache: Optional[list] = None) -> list:
        """Detect FC HBAs: WWPNs, WWNNs, firmware, link state, and SAN boot config.

        Three-pass approach per adapter:
          Pass 1 — NetworkPorts          → WWPN + link speed + LinkStatus
                                           + RemoteConnectedPorts (switch WWPN)
          Pass 2 — NetworkDeviceFunctions → WWNN + FibreChannel.BootTargets

        BootTargets are only populated when the HBA BIOS has a SAN boot entry
        configured (primary or alternate target WWPN + LUN).  They come from the
        NetworkDeviceFunction FibreChannel block, not from NetworkPorts.
        Cisco VIC FC personalities may only appear in NetworkDeviceFunctions.

        Each returned entry dict carries:
          vendor_class        "emulex" | "marvell" | ""
          link_status         "Up" | "Down" | "NoLink" | "Unknown"
          remote_switch_wwpn  switch-port WWPN from RemoteConnectedPorts (or "")
        """
        hbas: list = []
        if pcie_cache and not pcie_has_fc_candidates(pcie_cache):
            return hbas
        if not self.chassis_uri and not self.sys_uri:
            return hbas
        endpoints = []
        if self.chassis_uri:
            endpoints.append(f"{self.chassis_uri}/NetworkAdapters")
        if self.sys_uri:
            endpoints.append(f"{self.sys_uri}/NetworkInterfaces")
            endpoints.append(f"{self.sys_uri}/BaseNetworkAdapters")

        for ep in endpoints:
            coll = None
            if hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
                coll = self._request_cache.get(ep)
                if not coll and hasattr(self, "host_url"):
                    coll = self._request_cache.get(f"{self.host_url}{ep}")
            if not coll and hasattr(self, "_fetch_expanded_collection") and getattr(self, "expand_supported", False):
                coll = self._fetch_expanded_collection(ep, levels=1)
            members = self._get_members(coll if coll else ep)

            for member in members:
                adapter_uri = member.get("@odata.id") if isinstance(member, dict) else (member if isinstance(member, str) else None)
                adapter = None
                if isinstance(member, dict) and len(member) > 2 and any(k in member for k in ("Name", "Model", "Controllers", "Id", "Description")):
                    adapter = member
                elif adapter_uri and hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
                    adapter = self._request_cache.get(adapter_uri)
                    if not adapter and hasattr(self, "host_url"):
                        adapter = self._request_cache.get(f"{self.host_url}{adapter_uri}")
                if not adapter and adapter_uri:
                    adapter = self._get(adapter_uri)
                if not adapter or not isinstance(adapter, dict):
                    continue
                raw_name = str(adapter.get("Name") or "").strip()
                model_str = str(adapter.get("Model") or adapter.get("PartNumber") or "").strip()
                desc_str = str(adapter.get("Description") or "").strip()
                adapter_id = str(adapter.get("Id") or "").strip()
                name_lower = f"{raw_name} {desc_str} {model_str} {adapter_id}".lower()
                cna_info = classify_cna_adapter(
                    name_lower,
                    str(adapter.get("Manufacturer", "")),
                    model_str,
                    str(adapter.get("PartNumber", "")),
                )
                is_fc_by_name = (
                    "fibre" in name_lower
                    or "fibre channel" in name_lower
                    or "fc hba" in name_lower
                    or bool(re.search(r"\bFC\s+Adapter\b|\bFC\s+HBA\b", name_lower, re.I))
                    or bool(re.search(r"\bFC\.", adapter_id))
                    or cna_info["is_cna"]
                    # Emulex Prism/Prism+ and Marvell QLogic model numbers in name
                    or bool(re.search(r"\bLPe3[125678]\d{3}\b", name_lower, re.I))
                    or bool(re.search(r"\bQLE2[5678]\d{2}\b", name_lower, re.I))
                )

                # Early-exit if adapter is clearly non-FC (standard Ethernet NIC without FC capability)
                has_fc_ports = bool(adapter.get("FcPorts"))
                if not is_fc_by_name and not cna_info["is_cna"] and not has_fc_ports:
                    pci_ids = extract_pci_ids_from_dict(adapter, get_fn=lambda u, **kw: None)
                    v_id = str(pci_ids.get("vendor_id") or "").lower().replace("0x", "")
                    if v_id and v_id not in ("10df", "1077", "1137"):
                        continue
                    if any(t in name_lower for t in ("ethernet", "10gbe", "25gbe", "100gbe", "gigabit", "i350", "x710", "e810", "connectx", "tg3", "bnxt")):
                        continue

                mfg_raw = str(adapter.get("Manufacturer") or "").strip()
                mfg_clean = normalize_component_manufacturer(mfg_raw) if mfg_raw else ""
                if mfg_clean.lower() in ("unknown", "n/a", "none"):
                    mfg_clean = ""

                if model_str and not is_generic_name(model_str):
                    resolved_hba_name = model_str
                elif raw_name and not is_generic_name(raw_name):
                    resolved_hba_name = raw_name
                elif mfg_clean:
                    resolved_hba_name = f"{mfg_clean} FC HBA"
                else:
                    resolved_hba_name = "Fibre Channel HBA"

                # ── Firmware: adapter-level, shared across all ports ──────────
                # Try progressively broader fallback paths so Emulex, QLogic,
                # HPE, and Dell all surface a version string when available.
                _ctrl_fw = next(
                    (
                        str(c.get("FirmwareVersion") or "")
                        for c in (adapter.get("Controllers") or [])
                        if c.get("FirmwareVersion")
                    ),
                    None,
                )
                adapter_fw = _ctrl_fw or self.oem_nic_firmware(adapter)

                # ── Vendor classification (Emulex vs Marvell QLogic) ──────────
                _model_str = str(adapter.get("Model") or adapter.get("PartNumber") or "")
                _search_str = (
                    f"{adapter.get('Name', '')} "
                    f"{adapter.get('Manufacturer', '')} "
                    f"{_model_str}"
                )
                if re.search(r"\bLPe3[125678]\d{3}\b", _search_str, re.I):
                    vendor_class = "emulex"
                elif re.search(r"\bQLE2[5678]\d{2}\b", _search_str, re.I) or "qlogic" in _search_str.lower():
                    vendor_class = "marvell"
                else:
                    vendor_class = ""

                # ── Adapter-level PCI & PCIe Link Telemetry ───────────────────
                pci_info = extract_pci_ids_from_dict(adapter, get_fn=self._get)
                if not pci_info["pci_quad"] and pcie_cache:
                    pci_info = match_pcie_cache(adapter, pcie_cache, get_fn=self._get)

                fc_link = extract_pcie_link_status(adapter)
                if not fc_link.get("max_gen") and not fc_link.get("max_lanes") and hasattr(self, "oem_pcie_link_status"):
                    oem_link = self.oem_pcie_link_status(adapter)
                    if oem_link:
                        for k, v in oem_link.items():
                            if v is not None:
                                fc_link[k] = v

                # ── Pass 1: NetworkPorts → WWPN + speed + link state ──────────
                port_entries: list = []
                raw_fc_ports = (
                    adapter.get("FcPorts")
                    or adapter.get("PhysicalPorts")
                    or adapter.get("NetworkPorts")
                    or adapter.get("Ports")
                    or get_nested(adapter, "Oem", "Cisco", "NetworkPorts")
                    or get_nested(adapter, "Oem", "Cisco", "Ports")
                    or get_nested(adapter, "Oem", "CIMC", "NetworkPorts")
                    or get_nested(adapter, "Oem", "CIMC", "Ports")
                )
                if isinstance(raw_fc_ports, list):
                    port_members = raw_fc_ports
                elif isinstance(raw_fc_ports, dict) and isinstance(raw_fc_ports.get("Members"), list):
                    port_members = raw_fc_ports.get("Members", [])
                elif isinstance(raw_fc_ports, dict) and isinstance(raw_fc_ports.get("Ports"), list):
                    port_members = raw_fc_ports.get("Ports", [])
                else:
                    ports_uri = (
                        get_nested(adapter, "NetworkPorts", "@odata.id")
                        or get_nested(adapter, "Ports", "@odata.id")
                        or get_nested(adapter, "Oem", "Cisco", "NetworkPorts", "@odata.id")
                        or get_nested(adapter, "Oem", "Cisco", "Ports", "@odata.id")
                        or get_nested(adapter, "Oem", "CIMC", "NetworkPorts", "@odata.id")
                        or get_nested(adapter, "Oem", "CIMC", "Ports", "@odata.id")
                        or f"{adapter_uri}/NetworkPorts"
                    )
                    cached_p_coll = None
                    if hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
                        cached_p_coll = self._request_cache.get(ports_uri)
                        if not cached_p_coll and hasattr(self, "host_url"):
                            cached_p_coll = self._request_cache.get(f"{self.host_url}{ports_uri}")
                    port_members = self._get_members(cached_p_coll if cached_p_coll else ports_uri)
                port_jsons = []
                if port_members:
                    def _fetch_fc_p(pm):
                        uri = pm.get("@odata.id") if isinstance(pm, dict) else (pm if isinstance(pm, str) else None)
                        return self._get(uri) if uri else (pm if isinstance(pm, dict) else None)

                    fc_ports_to_fetch = []
                    for pm in port_members:
                        if isinstance(pm, dict) and len(pm) > 2 and (
                            pm.get("LinkStatus")
                            or pm.get("ActiveLinkTechnology")
                            or pm.get("LinkNetworkTechnology")
                            or pm.get("WWN")
                            or pm.get("WWPN")
                            or pm.get("AssociatedNetworkAddresses")
                            or get_nested(pm, "Oem", "Cisco")
                            or get_nested(pm, "Oem", "CIMC")
                        ):
                            port_jsons.append(pm)
                        else:
                            p_uri = pm.get("@odata.id") if isinstance(pm, dict) else (pm if isinstance(pm, str) else None)
                            if p_uri and hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
                                cached_p = self._request_cache.get(p_uri)
                                if not cached_p and hasattr(self, "host_url"):
                                    cached_p = self._request_cache.get(f"{self.host_url}{p_uri}")
                                if isinstance(cached_p, dict) and len(cached_p) > 2:
                                    port_jsons.append(cached_p)
                                    continue
                            fc_ports_to_fetch.append(pm)

                    if fc_ports_to_fetch:
                        max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(4), max(1, len(fc_ports_to_fetch)))
                        _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
                        pool = ThreadPoolExecutor(max_workers=max_w)
                        try:
                            futures = [pool.submit(_wrap_task(_fetch_fc_p), pm) for pm in fc_ports_to_fetch]
                            wait(futures, timeout=15.0)
                            for fut in futures:
                                if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                                    break
                                try:
                                    if fut.done():
                                        res = fut.result()
                                        if res:
                                            port_jsons.append(res)
                                except Exception as err:
                                    logger.debug("Error fetching FC port: %s", err)
                        finally:
                            pool.shutdown(wait=False, cancel_futures=True)

                for port in port_jsons:
                    proto = str(
                        port.get("ActiveLinkTechnology")
                        or port.get("LinkNetworkTechnology", "")
                    ).upper()
                    is_pure_fc_proto = ("FIBRE" in proto or "FC" in proto) and not ("ETHERNET" in proto or "FCOE" in proto)
                    raw_wwpn = (
                        port.get("WWPN")
                        or port.get("WWN")
                    )
                    if not raw_wwpn:
                        for addr in (port.get("AssociatedNetworkAddresses") or []):
                            if _is_valid_wwpn(addr):
                                raw_wwpn = addr
                                break

                    should_register = False
                    if cna_info["is_cna"]:
                        if is_pure_fc_proto and _is_valid_wwpn(raw_wwpn):
                            should_register = True
                    else:
                        if (is_pure_fc_proto or is_fc_by_name) and _is_valid_wwpn(raw_wwpn):
                            should_register = True

                    if should_register:
                        speed = (
                            port.get("CurrentSpeedGbps")
                            or port.get("MaxSpeedGbps")
                            or "N/A"
                        )
                        # LinkStatus — normalise to Up / Down / NoLink / Unknown
                        _ls_raw = str(port.get("LinkStatus") or "").strip()
                        if _ls_raw.lower() == "up" or _ls_raw.lower() == "linkup":
                            link_status = "Up"
                        elif _ls_raw.lower() in ("nolink", "no_link", "notconnected"):
                            link_status = "NoLink"
                        elif _ls_raw.lower() in ("down", "linkdown"):
                            link_status = "Down"
                        elif _ls_raw:
                            link_status = _ls_raw  # pass through vendor-specific value
                        else:
                            link_status = "Unknown"

                        # RemoteConnectedPorts — one-hop fabric: the switch-port
                        # WWPN this HBA port is physically cabled into.
                        remote_switch_wwpn = ""
                        _rcp = port.get("RemoteConnectedPorts") or []
                        if _rcp:
                            _first = _rcp[0] if isinstance(_rcp, list) else {}
                            # Some BMCs inline WWPN directly on the link object
                            remote_switch_wwpn = str(
                                _first.get("WWPN") or _first.get("WWN") or ""
                            ).strip()
                            # If not inlined, fetch the linked Port resource
                            if not remote_switch_wwpn:
                                _rcp_uri = _first.get("@odata.id") if isinstance(_first, dict) else None
                                if _rcp_uri:
                                    _rcp_port = self._get(_rcp_uri) or {}
                                    remote_switch_wwpn = str(
                                        _rcp_port.get("WWPN")
                                        or _rcp_port.get("WWN")
                                        or (_rcp_port.get("AssociatedNetworkAddresses") or [None])[0]
                                        or ""
                                    ).strip()

                        sw_vendor = lookup_storage_array_vendor(remote_switch_wwpn)["vendor"] if remote_switch_wwpn else ""

                        pci_info = extract_pci_ids_from_dict(adapter, get_fn=self._get)
                        if not pci_info["pci_quad"] and pcie_cache:
                            pci_info = match_pcie_cache(adapter, pcie_cache, get_fn=self._get)

                        fc_link = extract_pcie_link_status(adapter)
                        if not fc_link.get("max_gen") and not fc_link.get("max_lanes") and hasattr(self, "oem_pcie_link_status"):
                            oem_link = self.oem_pcie_link_status(adapter)
                            if oem_link:
                                for k, v in oem_link.items():
                                    if v is not None:
                                        fc_link[k] = v

                        port_entries.append({
                            "adapter_id":        adapter.get("Id") or str(adapter.get("@odata.id") or "").rstrip("/").rsplit("/", 1)[-1],
                            "adapter_name":      resolved_hba_name,
                            "manufacturer":      normalize_component_manufacturer(
                                adapter.get("Manufacturer", "Unknown")
                            ),
                            "firmware_version":  adapter_fw,
                            "vendor_class":      vendor_class,
                            "physical_port_id":  port.get("Id") or str(port.get("@odata.id") or "").rstrip("/").rsplit("/", 1)[-1],
                            "port_id":           port.get("Id", "Unknown"),
                            "wwpn":              str(raw_wwpn) if raw_wwpn else "N/A",
                            "wwnn":              "",
                            "speed_gbps":        speed,
                            "link_status":       link_status,
                            "remote_switch_wwpn": remote_switch_wwpn,
                            "remote_switch_vendor": sw_vendor,
                            "boot_targets":      [],
                            "vendor_id":           pci_info["vendor_id"],
                            "device_id":           pci_info["device_id"],
                            "subsystem_vendor_id": pci_info["subsystem_vendor_id"],
                            "subsystem_id":        pci_info["subsystem_id"],
                            "pci_quad":            pci_info["pci_quad"],
                            "pci_pair":            pci_info["pci_pair"],
                            "current_pcie_type":   fc_link.get("current_pcie_type"),
                            "max_pcie_type":       fc_link.get("max_pcie_type"),
                            "current_pcie_width":  fc_link.get("current_pcie_width"),
                            "max_pcie_width":      fc_link.get("max_pcie_width"),
                            "downgraded":          fc_link["downgraded"],
                            "downgrade_reason":    fc_link["reason"],
                            "downgrade_badge":     fc_link["badge"],
                            "is_cna":              cna_info["is_cna"],
                            "cna_family":          cna_info["cna_family"],
                            "cna_family_label":    cna_info["family_label"],
                            "cna_fc_driver":       cna_info["fc_driver"],
                        })

                # ── Pass 2: NetworkDeviceFunctions → WWNN + BootTargets ───────
                raw_func_ndf = (
                    adapter.get("NetworkDeviceFunctions")
                    or get_nested(adapter, "Oem", "Cisco", "NetworkDeviceFunctions")
                    or get_nested(adapter, "Oem", "CIMC", "NetworkDeviceFunctions")
                )
                if isinstance(raw_func_ndf, dict) and isinstance(raw_func_ndf.get("Members"), list):
                    func_members = raw_func_ndf.get("Members", [])
                elif isinstance(raw_func_ndf, list):
                    func_members = raw_func_ndf
                else:
                    funcs_uri = (
                        get_nested(adapter, "NetworkDeviceFunctions", "@odata.id")
                        or get_nested(adapter, "Oem", "Cisco", "NetworkDeviceFunctions", "@odata.id")
                        or get_nested(adapter, "Oem", "CIMC", "NetworkDeviceFunctions", "@odata.id")
                        or f"{adapter_uri}/NetworkDeviceFunctions"
                    )
                    cached_f_coll = None
                    if hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
                        cached_f_coll = self._request_cache.get(funcs_uri)
                        if not cached_f_coll and hasattr(self, "host_url"):
                            cached_f_coll = self._request_cache.get(f"{self.host_url}{funcs_uri}")
                    func_members = self._get_members(cached_f_coll if cached_f_coll else funcs_uri)

                func_jsons = []
                if func_members:
                    def _fetch_fc_f(fm):
                        uri = fm.get("@odata.id") if isinstance(fm, dict) else (fm if isinstance(fm, str) else None)
                        return self._get(uri) if uri else (fm if isinstance(fm, dict) else None)

                    funcs_to_fetch = []
                    for fm in func_members:
                        if isinstance(fm, dict) and len(fm) > 2 and (
                            fm.get("NetDevFuncType")
                            or fm.get("Ethernet")
                            or fm.get("FibreChannel")
                            or fm.get("AssignablePhysicalNetworkPorts")
                            or get_nested(fm, "Oem", "Cisco")
                            or get_nested(fm, "Oem", "CIMC")
                        ):
                            func_jsons.append(fm)
                        else:
                            f_uri = fm.get("@odata.id") if isinstance(fm, dict) else (fm if isinstance(fm, str) else None)
                            if f_uri and hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
                                cached_f = self._request_cache.get(f_uri)
                                if not cached_f and hasattr(self, "host_url"):
                                    cached_f = self._request_cache.get(f"{self.host_url}{f_uri}")
                                if isinstance(cached_f, dict) and len(cached_f) > 2:
                                    func_jsons.append(cached_f)
                                    continue
                            funcs_to_fetch.append(fm)

                    if funcs_to_fetch:
                        max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(4), max(1, len(funcs_to_fetch)))
                        _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
                        pool = ThreadPoolExecutor(max_workers=max_w)
                        try:
                            futures = [pool.submit(_wrap_task(_fetch_fc_f), fm) for fm in funcs_to_fetch]
                            wait(futures, timeout=15.0)
                            for fut in futures:
                                if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                                    break
                                try:
                                    if fut.done():
                                        res = fut.result()
                                        if res:
                                            func_jsons.append(res)
                                except Exception as err:
                                    logger.debug("Error fetching FC device function: %s", err)
                        finally:
                            pool.shutdown(wait=False, cancel_futures=True)

                pci_info = extract_pci_ids_from_dict(adapter, get_fn=self._get)
                if not pci_info["pci_quad"] and pcie_cache:
                    pci_info = match_pcie_cache(adapter, pcie_cache, get_fn=self._get)

                for fn in func_jsons:
                    fc = fn.get("FibreChannel", {})
                    fn_type = str(fn.get("NetDevFuncType") or "").upper()
                    is_fc_fn = fn_type in (
                        "FIBRE_CHANNEL", "FIBRECHANNEL", "FC", "FIBRECOUNEROVERETHERNET", "FIBRECHANNELOVERETHERNET"
                    ) or is_fc_by_name
                    if not fc and not is_fc_fn:
                        continue
                    if not fc:
                        continue
                    _fc_id = parse_fc_netdev_function(fc)
                    fn_wwpn = _fc_id["wwpn"]
                    fn_wwnn = _fc_id["wwnn"]
                    if not _is_valid_wwpn(fn_wwpn):
                        continue
                    boot_targets = _fc_id["boot_targets"]

                    fn_speed = "N/A"
                    fn_link_status = "Unknown"
                    fn_remote_wwpn = ""
                    fn_remote_vendor = ""
                    p_assign = (
                        get_nested(fn, "Links", "PhysicalPortAssignment", "@odata.id")
                        or get_nested(fn, "PhysicalPortAssignment", "@odata.id")
                    )
                    matched_p = None
                    if p_assign:
                        for p in port_jsons:
                            if p.get("@odata.id") == p_assign:
                                matched_p = p
                                break
                    if not matched_p:
                        cisco_oem = get_nested(fn, "Oem", "Cisco", default={}) or get_nested(fn, "Oem", "CIMC", default={})
                        u_idx = (cisco_oem.get("VnicConfiguration") or {}).get("UplinkPort")
                        if isinstance(u_idx, int) and 0 <= u_idx < len(port_jsons):
                            matched_p = port_jsons[u_idx]

                    if matched_p:
                        extracted_spd = self._extract_nic_speed_gbps(matched_p, adapter, str(adapter.get("Name") or ""))
                        if extracted_spd > 0:
                            fn_speed = extracted_spd
                        else:
                            fn_speed = matched_p.get("CurrentSpeedGbps") or matched_p.get("MaxSpeedGbps") or "N/A"
                        ls_raw = str(matched_p.get("LinkStatus") or "").strip().lower()
                        if ls_raw in ("up", "linkup"):
                            fn_link_status = "Up"
                        elif ls_raw in ("down", "linkdown"):
                            fn_link_status = "Down"
                        elif ls_raw in ("nolink", "no_link", "notconnected"):
                            fn_link_status = "NoLink"

                    matched = False
                    for pe in port_entries:
                        if fn_wwpn and pe["wwpn"] == fn_wwpn:
                            if pe.get("speed_gbps") in (None, "", "N/A", 0):
                                pe["speed_gbps"] = fn_speed
                            pe["wwnn"] = fn_wwnn
                            pe["boot_targets"] = boot_targets
                            matched = True
                            break
                    if not matched and (fn_wwpn or fn_wwnn):
                        port_entries.append({
                            "adapter_id":        adapter.get("Id") or str(adapter.get("@odata.id") or "").rstrip("/").rsplit("/", 1)[-1],
                            "adapter_name":      resolved_hba_name,
                            "manufacturer":      normalize_component_manufacturer(
                                adapter.get("Manufacturer", "Unknown")
                            ),
                            "firmware_version":  adapter_fw,
                            "vendor_class":      vendor_class,
                            "physical_port_id":  (matched_p or {}).get("Id") or str((matched_p or {}).get("@odata.id") or "").rstrip("/").rsplit("/", 1)[-1],
                            "port_id":           fn.get("Id", "Unknown"),
                            "wwpn":              fn_wwpn or "N/A",
                            "wwnn":              fn_wwnn,
                            "speed_gbps":        fn_speed,
                            "link_status":       fn_link_status,
                            "remote_switch_wwpn": fn_remote_wwpn,
                            "remote_switch_vendor": fn_remote_vendor,
                            "boot_targets":      boot_targets,
                            "vendor_id":           pci_info["vendor_id"],
                            "device_id":           pci_info["device_id"],
                            "subsystem_vendor_id": pci_info["subsystem_vendor_id"],
                            "subsystem_id":        pci_info["subsystem_id"],
                            "pci_quad":            pci_info["pci_quad"],
                            "pci_pair":            pci_info["pci_pair"],
                            "current_pcie_type":   fc_link.get("current_pcie_type"),
                            "max_pcie_type":       fc_link.get("max_pcie_type"),
                            "current_pcie_width":  fc_link.get("current_pcie_width"),
                            "max_pcie_width":      fc_link.get("max_pcie_width"),
                            "downgraded":          fc_link["downgraded"],
                            "downgrade_reason":    fc_link["reason"],
                            "downgrade_badge":     fc_link["badge"],
                            "is_cna":              cna_info["is_cna"],
                            "cna_family":          cna_info["cna_family"],
                            "cna_family_label":    cna_info["family_label"],
                            "cna_fc_driver":       cna_info["fc_driver"],
                        })

                if not port_entries and is_fc_by_name and not cna_info.get("is_cna"):
                    fc_link = extract_pcie_link_status(adapter)
                    if not fc_link.get("max_gen") and not fc_link.get("max_lanes") and hasattr(self, "oem_pcie_link_status"):
                        oem_link = self.oem_pcie_link_status(adapter)
                        if oem_link:
                            for k, v in oem_link.items():
                                if v is not None:
                                    fc_link[k] = v

                    pci_info = extract_pci_ids_from_dict(adapter, get_fn=self._get)
                    if not pci_info["pci_quad"] and pcie_cache:
                        pci_info = match_pcie_cache(adapter, pcie_cache, get_fn=self._get)

                    speed = "N/A"
                    spd_match = re.search(r"\b(\d+)\s*Gb\b", str(adapter.get("Name") or ""), re.I)
                    if spd_match:
                        try:
                            speed = float(spd_match.group(1))
                        except (ValueError, TypeError):
                            pass

                    raw_mfg = adapter.get("Manufacturer") or ""
                    mfg = infer_nic_manufacturer(raw_mfg, pci_info, str(adapter.get("Name") or ""))

                    port_entries.append({
                        "adapter_name": resolved_hba_name,
                        "manufacturer": mfg,
                        "firmware_version": adapter_fw,
                        "vendor_class": vendor_class,
                        "port_id": str(adapter.get("Id") or "1"),
                        "wwpn": "N/A",
                        "wwnn": "",
                        "speed_gbps": speed,
                        "link_status": "Unknown",
                        "remote_switch_wwpn": "",
                        "remote_switch_vendor": "",
                        "boot_targets": [],
                        "vendor_id": pci_info["vendor_id"],
                        "device_id": pci_info["device_id"],
                        "subsystem_vendor_id": pci_info["subsystem_vendor_id"],
                        "subsystem_id": pci_info["subsystem_id"],
                        "pci_quad": pci_info["pci_quad"],
                        "pci_pair": pci_info["pci_pair"],
                        "current_pcie_type": fc_link.get("current_pcie_type"),
                        "max_pcie_type": fc_link.get("max_pcie_type"),
                        "current_pcie_width": fc_link.get("current_pcie_width"),
                        "max_pcie_width": fc_link.get("max_pcie_width"),
                        "downgraded": fc_link.get("downgraded", False),
                        "downgrade_reason": fc_link.get("reason", ""),
                        "downgrade_badge": fc_link.get("badge", ""),
                        "is_cna": False,
                        "cna_family": "",
                        "cna_family_label": "",
                        "cna_fc_driver": "",
                    })

                hbas.extend(port_entries)

        return normalize_fc_ports(hbas)


    def collect_lldp_neighbors(self) -> list:
        """Collect LLDP / CDP neighbor data from BMC management port(s) and host NICs.

        Sources queried (in order):
          {mgr_uri}/EthernetInterfaces               — BMC management port (source="mgmt")
          {sys_uri}/EthernetInterfaces               — Host/production NICs (source="nic")
          {sys_uri}/NetworkInterfaces                — Cisco IMC / Redfish 1.5+
          {chassis_uri}/NetworkAdapters/{id}/NetworkPorts — Dell, HPE, Lenovo, Cisco port-level
          {sys_uri}/NetworkPorts/Oem/Dell/DellSwitchConnections — Dell switch connections

        Supports:
          • Standard DMTF Redfish LLDP / LldpData (EthernetInterface v1.6+, DSP8010)
          • Dell iDRAC DellSwitchConnections & Oem.Dell.DellNetworkPort
          • HPE iLO LldpData.Receiving & /HpeLLDP endpoint
          • Cisco IMC Oem.Cisco.CDP / Oem.Cisco.LLDP / Oem.CIMC.CDP
          • Lenovo XCC Oem.Lenovo.LLDP & Oem.Lenovo.NeighborInformation

        Only entries where at least one of switch_name, switch_port, or chassis_id
        is non-empty are returned.

        Returns list of:
          {
            "source":      "mgmt" | "nic",
            "protocol":    "LLDP" | "CDP",
            "local_iface": str,   # local interface ID
            "local_mac":   str,   # local port MAC address
            "switch_name": str,   # Neighbor switch / device name
            "switch_port": str,   # Switch port identifier
            "chassis_id":  str,   # Switch chassis / MAC identifier
            "mgmt_ipv4":   str,   # Switch management IPv4 address
            "system_desc": str,   # Switch OS/firmware description (truncated to 120 chars)
          }
        """
        results: list = []
        seen_keys: set = set()
        port_mac_map: dict = {}

        def _add_entry(entry: dict):
            sw_name = str(entry.get("switch_name") or "").strip()
            sw_port = str(entry.get("switch_port") or "").strip()
            ch_id = str(entry.get("chassis_id") or "").strip()
            if not (sw_name or sw_port or ch_id):
                return
            if sw_name.upper() in ("N/A", "NONE", "UNKNOWN", "NULL", "NO LINK", "00:00:00:00:00:00", "00-00-00-00-00-00"):
                sw_name = ""
            if sw_port.upper() in ("N/A", "NONE", "UNKNOWN", "NULL", "NO LINK"):
                sw_port = ""
            if ch_id.upper() in ("N/A", "NONE", "UNKNOWN", "NULL", "00:00:00:00:00:00", "00-00-00-00-00-00"):
                ch_id = ""
            if not (sw_name or sw_port or ch_id):
                return

            local_iface = str(entry.get("local_iface") or "").strip()
            local_mac = str(entry.get("local_mac") or "").strip()
            dedup_key = (local_iface, sw_name.lower(), sw_port.lower(), ch_id.lower())
            if dedup_key in seen_keys:
                return
            seen_keys.add(dedup_key)

            results.append({
                "source":             entry.get("source", "nic"),
                "protocol":           entry.get("protocol", "LLDP"),
                "local_iface":        local_iface,
                "local_mac":          local_mac,
                "switch_name":        sw_name,
                "switch_port":        sw_port,
                "chassis_id":         ch_id,
                "mgmt_ipv4":          str(entry.get("mgmt_ipv4") or "").strip(),
                "mgmt_ipv6":          str(entry.get("mgmt_ipv6") or "").strip(),
                "mgmt_mac":           str(entry.get("mgmt_mac") or "").strip(),
                "management_vlan_id": entry.get("management_vlan_id"),
                "capabilities":       entry.get("capabilities") or [],
                "system_desc":        _usable_lldp_system_desc(entry.get("system_desc")),
            })

        def _extract(res: dict, source: str, default_iface: str = ""):
            if not isinstance(res, dict):
                return

            local_iface = str(res.get("Id") or res.get("FQDD") or default_iface or "").strip()
            local_mac = _clean_mac_address(
                res.get("MACAddress")
                or res.get("PermanentMACAddress")
                or (res.get("AssociatedNetworkAddresses", [None])[0] if isinstance(res.get("AssociatedNetworkAddresses"), list) and res.get("AssociatedNetworkAddresses") else "")
                or get_nested(res, "Oem", "Dell", "DellSwitchConnection", "MACAddress")
                or (get_nested(res, "Oem", "Dell", "DellSwitchConnection", "AssociatedNetworkAddresses", [None])[0] if isinstance(get_nested(res, "Oem", "Dell", "DellSwitchConnection", "AssociatedNetworkAddresses"), list) and get_nested(res, "Oem", "Dell", "DellSwitchConnection", "AssociatedNetworkAddresses") else "")
            )

            # Check for Dell FQDD override
            fqdd = str(res.get("FQDD") or get_nested(res, "Oem", "Dell", "DellSwitchConnection", "FQDD") or "").strip()
            if fqdd:
                local_iface = fqdd
                if any(k in fqdd.lower() for k in ("idrac", "embedded.1", "dedicated")):
                    source = "mgmt"

            if not local_mac:
                local_mac = port_mac_map.get(local_iface) or port_mac_map.get(fqdd) or ""

            # ── 1. Standard DMTF LLDP ──────────────────────────────────────────
            lldp_rx = (
                get_nested(res, "LLDP", "Receive", default={})
                or get_nested(res, "LLDP", "Receiving", default={})
                or get_nested(res, "LLDPData", "Receiving", default={})
                or get_nested(res, "LldpData", "Receiving", default={})
                or (res.get("LLDP") if isinstance(res.get("LLDP"), dict) else {})
            )
            if isinstance(lldp_rx, dict) and lldp_rx:
                vlan_id = lldp_rx.get("ManagementVlanId") or lldp_rx.get("ManagementVLANID") or lldp_rx.get("VlanId") or lldp_rx.get("VLANID")
                mgmt_vlan = int(vlan_id) if isinstance(vlan_id, (int, float)) and vlan_id > 0 else (int(vlan_id) if isinstance(vlan_id, str) and vlan_id.isdigit() and int(vlan_id) > 0 else None)
                _add_entry({
                    "source":             source,
                    "protocol":           "LLDP",
                    "local_iface":        local_iface,
                    "local_mac":          local_mac,
                    "switch_name":        str(lldp_rx.get("SystemName") or lldp_rx.get("SysName") or "").strip(),
                    "switch_port":        str(lldp_rx.get("PortId") or lldp_rx.get("PortID") or "").strip(),
                    "chassis_id":         str(lldp_rx.get("ChassisId") or lldp_rx.get("ChassisID") or "").strip(),
                    "mgmt_ipv4":          str(lldp_rx.get("ManagementAddressIPv4") or lldp_rx.get("ManagementIPv4") or "").strip(),
                    "mgmt_ipv6":          str(lldp_rx.get("ManagementAddressIPv6") or lldp_rx.get("ManagementIPv6") or "").strip(),
                    "mgmt_mac":           str(lldp_rx.get("ManagementAddressMAC") or "").strip(),
                    "management_vlan_id": mgmt_vlan,
                    "capabilities":       lldp_rx.get("SystemCapabilities") or [],
                    "system_desc":        str(lldp_rx.get("SystemDescription") or lldp_rx.get("SysDesc") or "").strip(),
                })

            # ── 2. Cisco IMC CDP / LLDP OEM ────────────────────────────────────
            cisco_cdp = (
                get_nested(res, "Oem", "Cisco", "CDP", default={})
                or get_nested(res, "Oem", "CIMC", "CDP", default={})
                or get_nested(res, "Oem", "Cisco", "Cdp", default={})
            )
            if isinstance(cisco_cdp, dict) and cisco_cdp:
                _add_entry({
                    "source":      source,
                    "protocol":    "CDP",
                    "local_iface": local_iface,
                    "local_mac":   local_mac,
                    "switch_name": str(cisco_cdp.get("DeviceId") or cisco_cdp.get("DeviceName") or cisco_cdp.get("SystemName") or "").strip(),
                    "switch_port": str(cisco_cdp.get("Interface") or cisco_cdp.get("PortId") or "").strip(),
                    "chassis_id":  str(cisco_cdp.get("ChassisId") or cisco_cdp.get("ChassisID") or "").strip(),
                    "mgmt_ipv4":   str(cisco_cdp.get("Address") or cisco_cdp.get("MgmtAddress") or cisco_cdp.get("ManagementAddressIPv4") or "").strip(),
                    "system_desc": str(cisco_cdp.get("Platform") or cisco_cdp.get("SystemDescription") or cisco_cdp.get("Version") or "").strip(),
                })

            cisco_lldp = (
                get_nested(res, "Oem", "Cisco", "LLDP", default={})
                or get_nested(res, "Oem", "CIMC", "LLDP", default={})
                or get_nested(res, "Oem", "Cisco", "NeighborInfo", default={})
            )
            if isinstance(cisco_lldp, dict) and cisco_lldp:
                _add_entry({
                    "source":      source,
                    "protocol":    "LLDP",
                    "local_iface": local_iface,
                    "local_mac":   local_mac,
                    "switch_name": str(cisco_lldp.get("SystemName") or cisco_lldp.get("DeviceId") or "").strip(),
                    "switch_port": str(cisco_lldp.get("PortId") or cisco_lldp.get("Interface") or "").strip(),
                    "chassis_id":  str(cisco_lldp.get("ChassisId") or cisco_lldp.get("ChassisID") or "").strip(),
                    "mgmt_ipv4":   str(cisco_lldp.get("ManagementAddressIPv4") or cisco_lldp.get("Address") or "").strip(),
                    "system_desc": str(cisco_lldp.get("SystemDescription") or cisco_lldp.get("Platform") or "").strip(),
                })

            # ── 3. Dell iDRAC OEM ──────────────────────────────────────────────
            dell_oem = (
                get_nested(res, "Oem", "Dell", "DellNetworkPort", default={})
                or get_nested(res, "Oem", "Dell", "DellNIC", default={})
                or get_nested(res, "Oem", "Dell", "DellSwitchConnection", default={})
                or (res.get("Oem", {}).get("Dell") if isinstance(res.get("Oem", {}).get("Dell"), dict) else {})
            )
            sw_name = str(
                res.get("SwitchConnectionID")
                or (dell_oem.get("SwitchConnectionID") if isinstance(dell_oem, dict) else "")
                or (dell_oem.get("SwitchName") if isinstance(dell_oem, dict) else "")
                or (dell_oem.get("FQDNExtension") if isinstance(dell_oem, dict) else "")
                or ""
            ).strip()
            sw_port = str(
                res.get("SwitchPortConnectionID")
                or (dell_oem.get("SwitchPortConnectionID") if isinstance(dell_oem, dict) else "")
                or (dell_oem.get("SwitchPort") if isinstance(dell_oem, dict) else "")
                or ""
            ).strip()
            ch_id = str(
                res.get("ChassisID")
                or res.get("ChassisId")
                or (dell_oem.get("ChassisID") if isinstance(dell_oem, dict) else "")
                or ""
            ).strip()
            # If sw_name is a MAC address, also treat as chassis_id
            if not ch_id and sw_name and re.match(r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$', sw_name):
                ch_id = sw_name

            if sw_name or sw_port or ch_id:
                _add_entry({
                    "source":      source,
                    "protocol":    "LLDP",
                    "local_iface": local_iface,
                    "local_mac":   local_mac,
                    "switch_name": sw_name,
                    "switch_port": sw_port,
                    "chassis_id":  ch_id,
                    "mgmt_ipv4":   str(res.get("ManagementAddressIPv4") or (dell_oem.get("ManagementAddressIPv4") if isinstance(dell_oem, dict) else "") or "").strip(),
                    "system_desc": str(
                        res.get("SystemDescription")
                        or (dell_oem.get("SystemDescription") if isinstance(dell_oem, dict) else "")
                        or (dell_oem.get("SwitchDescription") if isinstance(dell_oem, dict) else "")
                        or res.get("Description")
                        or (dell_oem.get("Description") if isinstance(dell_oem, dict) else "")
                        or ""
                    ).strip(),
                })

            # ── 4. Lenovo XCC OEM ──────────────────────────────────────────────
            lenovo_lldp = (
                get_nested(res, "Oem", "Lenovo", "LLDP", default={})
                or get_nested(res, "Oem", "Lenovo", "NeighborInformation", default={})
                or get_nested(res, "Oem", "Lenovo", "NetworkConfiguration", "LLDP", default={})
            )
            if isinstance(lenovo_lldp, dict) and lenovo_lldp:
                _add_entry({
                    "source":      source,
                    "protocol":    "LLDP",
                    "local_iface": local_iface,
                    "local_mac":   local_mac,
                    "switch_name": str(lenovo_lldp.get("SystemName") or lenovo_lldp.get("ChassisId") or "").strip(),
                    "switch_port": str(lenovo_lldp.get("PortId") or lenovo_lldp.get("PortID") or "").strip(),
                    "chassis_id":  str(lenovo_lldp.get("ChassisId") or lenovo_lldp.get("ChassisID") or "").strip(),
                    "mgmt_ipv4":   str(lenovo_lldp.get("ManagementIPv4") or lenovo_lldp.get("ManagementAddressIPv4") or "").strip(),
                    "system_desc": str(lenovo_lldp.get("SystemDescription") or "").strip(),
                })

            # ── 5. HPE iLO OEM / HpeLLDP sub-resource ──────────────────────────
            hpe_rx = (
                get_nested(res, "Oem", "Hpe", "LldpData", "Receiving", default={})
                or get_nested(res, "Oem", "Hpe", "LLDP", "Receiving", default={})
                or get_nested(res, "Oem", "Hpe", "Lldp", "Receiving", default={})
                or get_nested(res, "Oem", "Hpe", "LldpData", default={})
            )
            if isinstance(hpe_rx, dict) and hpe_rx:
                _add_entry({
                    "source":      source,
                    "protocol":    "LLDP",
                    "local_iface": local_iface,
                    "local_mac":   local_mac,
                    "switch_name": str(hpe_rx.get("SysName") or hpe_rx.get("SystemName") or "").strip(),
                    "switch_port": str(hpe_rx.get("PortID") or hpe_rx.get("PortId") or "").strip(),
                    "chassis_id":  str(hpe_rx.get("ChassisID") or hpe_rx.get("ChassisId") or "").strip(),
                    "mgmt_ipv4":   str(hpe_rx.get("ManagementAddressIPv4") or hpe_rx.get("ManagementIPv4") or hpe_rx.get("ManagementAddress") or "").strip(),
                    "system_desc": str(hpe_rx.get("SysDesc") or hpe_rx.get("SystemDescription") or "").strip(),
                })

            hpe_lldp_ref = (
                get_nested(res, "Lldp", "odataId")
                or get_nested(res, "Lldp", "@odata.id")
                or get_nested(res, "Links", "Oem", "Hpe", "HpeLLDP", "@odata.id")
            )
            if hpe_lldp_ref and isinstance(hpe_lldp_ref, str) and "LLDP" in hpe_lldp_ref.upper():
                hpe_data = self._get(hpe_lldp_ref)
                if isinstance(hpe_data, dict):
                    hpe_rx_sub = (
                        get_nested(hpe_data, "Receiving", default={})
                        or get_nested(hpe_data, "LldpData", "Receiving", default={})
                        or hpe_data
                    )
                    if isinstance(hpe_rx_sub, dict) and hpe_rx_sub:
                        _add_entry({
                            "source":      source,
                            "protocol":    "LLDP",
                            "local_iface": local_iface,
                            "local_mac":   local_mac,
                            "switch_name": str(hpe_rx_sub.get("SysName") or hpe_rx_sub.get("SystemName") or "").strip(),
                            "switch_port": str(hpe_rx_sub.get("PortID") or hpe_rx_sub.get("PortId") or "").strip(),
                            "chassis_id":  str(hpe_rx_sub.get("ChassisID") or hpe_rx_sub.get("ChassisId") or "").strip(),
                            "mgmt_ipv4":   str(hpe_rx_sub.get("ManagementAddressIPv4") or hpe_rx_sub.get("ManagementIPv4") or hpe_rx_sub.get("ManagementAddress") or "").strip(),
                            "system_desc": str(hpe_rx_sub.get("SysDesc") or hpe_rx_sub.get("SystemDescription") or "").strip(),
                        })

        # ── 1. BMC management interface(s) ─────────────────────────────────────
        if self.mgr_uri:
            for m in self._get_members(f"{self.mgr_uri}/EthernetInterfaces"):
                iface = self._get(m.get("@odata.id") if isinstance(m, dict) else m)
                if iface:
                    _extract(iface, "mgmt")

        # ── 2. Host / production NIC EthernetInterfaces ────────────────────────
        if self.sys_uri:
            eth_uri = f"{self.sys_uri}/EthernetInterfaces"
            fetch_expand_fn = getattr(self, "_fetch_expanded_collection", None)
            if callable(fetch_expand_fn) and getattr(self, "expand_supported", False):
                eth_coll = fetch_expand_fn(eth_uri)
                eth_members = self._get_members(eth_coll) if eth_coll else []
            else:
                eth_members = self._get_members(eth_uri)
            for m in eth_members:
                if isinstance(m, dict) and len(m) > 2 and (m.get("Id") or m.get("MACAddress")):
                    iface = m
                else:
                    iface = self._get(m.get("@odata.id") if isinstance(m, dict) else m)
                if iface:
                    _extract(iface, "nic")

        # ── 3. Host NetworkInterfaces (Cisco IMC & DMTF 1.5+) ─────────────────
        if self.sys_uri:
            for m in self._get_members(f"{self.sys_uri}/NetworkInterfaces"):
                nif = self._get(m.get("@odata.id") if isinstance(m, dict) else m)
                if nif:
                    _extract(nif, "nic")

        # ── 4. Chassis NetworkAdapters -> NetworkPorts ─────────────────────────
        if self.chassis_uri:
            for a_mem in self._get_members(f"{self.chassis_uri}/NetworkAdapters"):
                adapter_uri = a_mem.get("@odata.id") if isinstance(a_mem, dict) else a_mem
                if isinstance(a_mem, dict) and len(a_mem) > 2:
                    adapter = a_mem
                else:
                    adapter = self._get(adapter_uri)
                if not adapter:
                    continue
                _extract(adapter, "nic")

                ports_uri = get_nested(adapter, "NetworkPorts", "@odata.id") or get_nested(adapter, "Ports", "@odata.id") or f"{adapter_uri}/NetworkPorts"
                raw_ports = adapter.get("NetworkPorts") or adapter.get("Ports")
                if isinstance(raw_ports, dict) and isinstance(raw_ports.get("Members"), list):
                    p_members = raw_ports.get("Members", [])
                elif isinstance(raw_ports, list):
                    p_members = raw_ports
                else:
                    p_members = self._get_members(ports_uri)
                for p_mem in p_members:
                    if isinstance(p_mem, dict) and len(p_mem) > 2:
                        port_obj = p_mem
                    else:
                        port_uri = p_mem.get("@odata.id") if isinstance(p_mem, dict) else p_mem
                        port_obj = self._get(port_uri)
                    if port_obj:
                        p_mac = _clean_mac_address(
                            (port_obj.get("AssociatedNetworkAddresses", [None])[0] if isinstance(port_obj.get("AssociatedNetworkAddresses"), list) and port_obj.get("AssociatedNetworkAddresses") else "")
                            or port_obj.get("MACAddress")
                            or port_obj.get("PermanentMACAddress")
                        )
                        if p_mac:
                            for key in (port_obj.get("FQDD"), port_obj.get("Id")):
                                if key:
                                    port_mac_map[str(key).strip()] = p_mac
                        _extract(port_obj, "nic", default_iface=str(adapter.get("Id", "")))

        # ── 5. Dell SwitchConnections collection ──────────────────────────────
        if self.sys_uri:
            dell_sw_conns = self._get(f"{self.sys_uri}/NetworkPorts/Oem/Dell/DellSwitchConnections")
            if isinstance(dell_sw_conns, dict):
                for m in self._get_members(dell_sw_conns):
                    sw_obj = self._get(m.get("@odata.id") if isinstance(m, dict) else m)
                    if sw_obj:
                        _extract(sw_obj, "nic")

        for r in results:
            if not r.get("local_mac") and r.get("local_iface") in port_mac_map:
                r["local_mac"] = port_mac_map[r["local_iface"]]

        return results

