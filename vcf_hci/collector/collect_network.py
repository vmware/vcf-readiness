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


from vcf_hci.collector.pci_utils import (
    extract_pci_ids_from_dict,
    extract_pcie_link_status,
    match_firmware_inventory_pci,
    match_pcie_cache,
    normalize_pci_id,
    pcie_has_fc_candidates,
)
from vcf_hci.constants import GENERIC_NAME_BLOCKLIST
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


def _evaluate_npar_partitions(partitions: list, port_count: int = 1, is_vic: bool = False) -> bool:
    """Determine if a list of partition/function dicts represents genuine NPAR.

    True NPAR is present when:
      1. Multiple distinct functions/partitions map to the SAME physical port
         (e.g., NIC.Slot.2-1-1 and NIC.Slot.2-1-2, or partition index >= 2).
      2. Any partition has a carved, non-standard speed
         (e.g., 2, 4, 6, 8 Gbps; not standard 1/2.5/5/10/25/40/50/100/200/400 GbE).
      3. Sibling partitions share a physical port with explicit bandwidth allocations < 100%.

    Cisco VIC virtual interfaces (vNIC/vHBA) are hardware-virtualized ASIC endpoints with
    dedicated queues and native nenic/fnic drivers, and are excluded from NPAR classification.
    """
    if is_vic or not partitions or len(partitions) < 2:
        return False

    # Check if partitions follow Cisco VIC naming and architecture
    if all(re.match(r"^(?:eth|fc|vnic|vhba)\d+$", str(p.get("partition_id") or "").strip(), re.I) for p in partitions):
        return False

    # Check for carved non-standard Ethernet speeds
    standard_speeds = {1.0, 2.5, 5.0, 10.0, 25.0, 40.0, 50.0, 100.0, 200.0, 400.0}
    for p in partitions:
        spd = float(p.get("speed_gbps") or 0.0)
        if spd > 0.0 and spd not in standard_speeds:
            return True

    # Group partitions by physical port identifier
    port_map = {}
    port_distinct_nums = {}
    port_distinct_ids = {}

    for p in partitions:
        pid = str(p.get("partition_id") or "").strip()
        if not pid:
            continue
        p_port = str(p.get("physical_port") or p.get("physical_port_assignment") or "").strip()
        if p_port:
            phys_port = p_port.split("/")[-1].upper()
            part_num = pid
        else:
            # Match standard vendor partition schemes:
            # Dell: NIC.Slot.2-1-1 -> port "NIC.Slot.2-1", part "1"
            # HPE: LOM:1:1 -> port "LOM:1", part "1"
            # Cisco: Port-1-1 -> port "Port-1", part "1"
            m = re.match(r"^(.*?[-_.:](?:P|Port|p)?\d+)[-_.:](\d+)$", pid, re.I)
            if not m:
                m = re.match(r"^(.*?)[-_.:](\d+)$", pid, re.I)
            if m:
                phys_port = m.group(1).upper()
                part_num = m.group(2)
            else:
                phys_port = pid.upper()
                part_num = "1"

        port_map.setdefault(phys_port, []).append((part_num, p))
        port_distinct_nums.setdefault(phys_port, set()).add(part_num)
        port_distinct_ids.setdefault(phys_port, set()).add(pid.upper())

    # If any physical port has 2 or more distinct partitions, or partition index > 1, it is genuine NPAR
    for phys_port, distinct_nums in port_distinct_nums.items():
        if len(distinct_nums) >= 2:
            return True
        if len(port_distinct_ids.get(phys_port, set())) >= 2:
            return True
        for pnum in distinct_nums:
            try:
                if int(pnum) > 1:
                    return True
            except (ValueError, TypeError):
                pass

        plist = port_map.get(phys_port, [])
        for pnum, pdata in plist:
            bw = pdata.get("allocated_pct")
            if bw is not None:
                try:
                    if 0 < float(bw) < 100 and (len(port_distinct_ids.get(phys_port, set())) > 1 or len(partitions) > port_count):
                        return True
                except (ValueError, TypeError):
                    pass

    return False


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


def classify_cna_adapter(name: str, manufacturer: str = "", model: str = "", part_number: str = "", net_dev_funcs: Optional[list] = None) -> dict:
    """Detect if an adapter is a Converged Network Adapter (CNA) and classify its dual personas.

    Covers Cisco VIC (1200/1300/1400/1500), HPE FlexFabric (580/620/630/650),
    Marvell FastLinQ / QLogic 57810S/57840S, and Emulex OneConnect.
    """
    s_comb = f"{name} {manufacturer} {model} {part_number}".strip()

    # 1. Cisco VIC
    vic_match = re.search(r"\bVIC[-\s]?(\d{4,5}[A-Za-z0-9\-]*)", s_comb, re.I)
    is_cisco_vic = (
        bool(vic_match)
        or "cisco virtual interface card" in s_comb.lower()
        or ("cisco" in s_comb.lower() and "vic" in s_comb.lower())
        or ("cisco" in s_comb.lower() and any(f.get("Oem", {}).get("Cisco") for f in (net_dev_funcs or [])))
    )
    if is_cisco_vic:
        vic_num = vic_match.group(1) if vic_match else ""
        return {
            "is_cna": True,
            "is_vic": True,
            "cna_family": "cisco_vic",
            "family_label": f"Cisco VIC {vic_num}".strip() or "Cisco Virtual Interface Card",
            "eth_driver": "nenic",
            "fc_driver": "fnic",
            "protocols": ["Ethernet (vNIC)", "Fibre Channel / FCoE (vHBA)"],
            "eth_bcg_keyword": f"VIC {vic_num} nenic".strip() if vic_num else "VIC nenic",
            "fc_bcg_keyword": f"VIC {vic_num} fnic".strip() if vic_num else "VIC fnic",
        }

    # 2. HPE FlexFabric / StoreFabric
    ff_match = re.search(r"(?:FlexFabric|StoreFabric)[-\s]?(\d{3,4}[A-Za-z0-9\-\+]*)", s_comb, re.I)
    if ff_match or "flexfabric" in s_comb.lower() or any(k in s_comb.upper() for k in ("580FLB", "650FLB", "630FLB", "620FLB", "534FLR", "554FLR", "556FLR")):
        ff_mod = ff_match.group(1) if ff_match else ""
        return {
            "is_cna": True,
            "cna_family": "hpe_flexfabric",
            "family_label": f"HPE FlexFabric {ff_mod}".strip() or "HPE FlexFabric CNA",
            "eth_driver": "qfle3",
            "fc_driver": "qfle3f",
            "protocols": ["Ethernet (NIC)", "Fibre Channel / FCoE (HBA)"],
            "eth_bcg_keyword": f"FlexFabric {ff_mod} qfle3".strip() if ff_mod else "FlexFabric qfle3",
            "fc_bcg_keyword": f"FlexFabric {ff_mod} qfle3f".strip() if ff_mod else "FlexFabric qfle3f",
        }

    # 3. Marvell FastLinQ / QLogic 57810S / 57840S (Explicit CNA/FCoE families)
    # Note: BCM57414/57454/57504 is pure NetXtreme-E Ethernet, NOT FastLinQ/578xx CNA
    if any(k in s_comb.upper() for k in ("FASTLINQ", "57810S", "57840S", "BCM57810", "BCM57840")) or (
        "QL41" in s_comb.upper() and any(c in s_comb.upper() for c in ("CNA", "FCOE", "HBA", "FABRIC"))
    ):
        ql_match = re.search(r"\b(QL\d{5}[A-Za-z0-9\-]*|578\d{2}S?)\b", s_comb, re.I)
        ql_mod = ql_match.group(1) if ql_match else "FastLinQ"
        return {
            "is_cna": True,
            "cna_family": "marvell_fastlinq",
            "family_label": f"Marvell FastLinQ / QLogic {ql_mod}",
            "eth_driver": "qfle3",
            "fc_driver": "qfle3f",
            "protocols": ["Ethernet (NIC)", "FCoE / iSCSI Offload (HBA)"],
            "eth_bcg_keyword": f"{ql_mod} qfle3",
            "fc_bcg_keyword": f"{ql_mod} qfle3f",
        }

    # 4. Emulex OneConnect (OCe14000 / OCe11000)
    if any(k in s_comb.upper() for k in ("ONECONNECT", "OCE14", "OCE11", "CN1100R", "CN1200R")):
        oce_match = re.search(r"\b(OCe\d{5}[A-Za-z0-9\-]*|CN\d{4}R)\b", s_comb, re.I)
        oce_mod = oce_match.group(1) if oce_match else "OneConnect"
        return {
            "is_cna": True,
            "cna_family": "emulex_oneconnect",
            "family_label": f"Broadcom Emulex OneConnect {oce_mod}",
            "eth_driver": "elxnet",
            "fc_driver": "lpfc",
            "protocols": ["Ethernet (NIC)", "Fibre Channel / FCoE (HBA)"],
            "eth_bcg_keyword": f"{oce_mod} elxnet",
            "fc_bcg_keyword": f"{oce_mod} lpfc",
        }

    # 5. Check NetworkDeviceFunctions ONLY for active, configured FC/FCoE
    # Standard Ethernet NICs with dormant schema objects (null WWPNs) are NOT CNAs
    if net_dev_funcs:
        has_eth = False
        has_active_fc = False
        for fn in net_dev_funcs:
            ftype = str(fn.get("NetDevFuncType") or "").upper()
            if "ETH" in ftype:
                has_eth = True

            fc_blk = fn.get("FibreChannel")
            if isinstance(fc_blk, dict):
                wwpn = str(fc_blk.get("WWPN") or fc_blk.get("PermanentWWPN") or "").strip()
                clean_wwpn = re.sub(r"[^0-9a-fA-F]", "", wwpn)
                has_valid_wwpn = len(clean_wwpn) == 16 and clean_wwpn != "0000000000000000"

                has_boot_target = False
                for bt in (fc_blk.get("BootTargets") or []):
                    bt_w = str(bt.get("WWPN") or bt.get("TargetWWPN") or "").strip()
                    clean_bt_w = re.sub(r"[^0-9a-fA-F]", "", bt_w)
                    if len(clean_bt_w) == 16 and clean_bt_w != "0000000000000000":
                        has_boot_target = True
                        break

                vlan = fc_blk.get("FCoEActiveVLANId")
                has_fcoe_vlan = isinstance(vlan, int) and vlan > 0

                if has_valid_wwpn or has_boot_target or has_fcoe_vlan:
                    has_active_fc = True

            if ("FIBRE" in ftype or "FCOE" in ftype) and ("ETH" not in ftype):
                has_active_fc = True

        if has_eth and has_active_fc:
            return {
                "is_cna": True,
                "is_vic": False,
                "cna_family": "generic_cna",
                "family_label": "Converged Network Adapter (CNA)",
                "eth_driver": "Standard NIC Driver",
                "fc_driver": "Standard FC/FCoE Driver",
                "protocols": ["Ethernet", "Fibre Channel / FCoE"],
                "eth_bcg_keyword": name,
                "fc_bcg_keyword": name,
            }

    return {
        "is_cna": False,
        "is_vic": False,
        "cna_family": "",
        "family_label": "",
        "eth_driver": "",
        "fc_driver": "",
        "protocols": [],
        "eth_bcg_keyword": "",
        "fc_bcg_keyword": "",
    }


def _clean_mac_address(mac_val: Any) -> str:
    s = str(mac_val or "").strip()
    if not s or s.upper() in ("N/A", "NONE", "UNKNOWN", "NULL", "00:00:00:00:00:00", "00-00-00-00-00-00", "0000.0000.0000"):
        return ""
    return s


def _usable_lldp_system_desc(text: Any) -> str:
    s = str(text or "").strip()
    if not s:
        return ""
    s_low = s.lower()
    if "dellswitchconnection" in s_low or "will have the switch connection" in s_low or s_low.startswith("an instance of"):
        return ""
    return s[:120]


def infer_nic_manufacturer(raw_mfg: str, pci_info: Optional[dict] = None, adapter_name: str = "") -> str:
    """Infer manufacturer when BMC returns 'Unknown', empty, or unhelpful string."""
    mfg = str(raw_mfg or "").strip()
    if mfg and mfg.lower() not in ("unknown", "n/a", "none", "", "null"):
        return mfg

    pci = pci_info or {}
    vid = normalize_pci_id(pci.get("vendor_id", ""))
    svid = normalize_pci_id(pci.get("subsystem_vendor_id", ""))
    name = str(adapter_name or "").strip()
    name_lower = name.lower()

    # 1. Check adapter name prefix/keywords
    if name_lower.startswith("hpe ") or "hewlett packard" in name_lower:
        return "HPE"
    if name_lower.startswith("dell ") or "poweredge" in name_lower:
        return "Dell"
    if name_lower.startswith("qlogic ") or "qlogic" in name_lower:
        return "QLogic / Marvell" if "marvell" not in name_lower else "Marvell"
    if name_lower.startswith("marvell ") or "marvell" in name_lower or "fastlinq" in name_lower:
        return "Marvell"
    if name_lower.startswith("intel ") or "intel" in name_lower:
        return "Intel"
    if name_lower.startswith("broadcom ") or "broadcom" in name_lower or "netxtreme" in name_lower:
        return "Broadcom"
    if name_lower.startswith("mellanox ") or "mellanox" in name_lower or "connectx" in name_lower:
        return "Mellanox"
    if name_lower.startswith("cisco ") or "cisco" in name_lower:
        return "Cisco"
    if name_lower.startswith("emulex ") or "emulex" in name_lower:
        return "Emulex"
    if name_lower.startswith("solarflare ") or "solarflare" in name_lower or "xilinx" in name_lower:
        return "Solarflare"

    # 2. Check PCI Vendor ID
    if vid:
        pci_vid_map = {
            "14e4": "Broadcom",
            "1077": "QLogic / Marvell",
            "8086": "Intel",
            "15b3": "Mellanox",
            "1137": "Cisco",
            "10df": "Emulex",
            "1924": "Solarflare",
            "1d0f": "Amazon Annapurna Labs",
            "1000": "Broadcom / LSI",
            "102b": "Matrox",
        }
        if vid in pci_vid_map:
            return pci_vid_map[vid]

    # 3. Check Subsystem Vendor ID
    if svid:
        pci_svid_map = {
            "103c": "HPE",
            "1590": "HPE",
            "1028": "Dell",
            "17aa": "Lenovo",
            "1137": "Cisco",
            "15d9": "Supermicro",
        }
        if svid in pci_svid_map:
            return pci_svid_map[svid]

    return "Unknown"


class _NetworkMixin(_CollectorBase):
    """Collection methods: NICs, FC HBAs, LLDP neighbors."""

    @staticmethod
    def _extract_nic_speed_gbps(port: dict, adapter: dict, resolved_name: str = "") -> float:
        """Extract NIC speed in Gbps with fallbacks for down links / rated speeds."""
        # 1. Active current link speed
        cur_gbps = port.get("CurrentSpeedGbps")
        if cur_gbps and float(cur_gbps) > 0:
            return float(cur_gbps)
        cur_mbps = port.get("CurrentLinkSpeedMbps")
        if cur_mbps and float(cur_mbps) > 0:
            return float(cur_mbps) / 1000.0

        # Cisco VIC Port OEM telemetry
        cisco_vic = get_nested(port, "Oem", "Cisco", "VicPort", default={}) or get_nested(port, "Oem", "CIMC", "VicPort", default={})
        if isinstance(cisco_vic, dict) and cisco_vic:
            oper_mbps = cisco_vic.get("OperatingLinkSpeedMbps") or cisco_vic.get("OperLinkSpeedMbps")
            if oper_mbps and float(oper_mbps) > 0:
                return float(oper_mbps) / 1000.0
            admin_spd = str(cisco_vic.get("AdminLinkSpeed") or "").strip().upper()
            m_admin = re.search(r"\b(100|40|25|10|1)\s*G?\b", admin_spd)
            if m_admin:
                return float(m_admin.group(1))
            conn_type = str(cisco_vic.get("ConnectorType") or "").strip().upper()
            if "100" in conn_type:
                return 100.0
            if "40" in conn_type:
                return 40.0
            if "25" in conn_type:
                return 25.0
            if "10" in conn_type:
                return 10.0

        # 2. Max capability speed on port or adapter
        max_gbps = port.get("MaxSpeedGbps") or adapter.get("MaxSpeedGbps")
        if max_gbps and float(max_gbps) > 0:
            return float(max_gbps)
        max_mbps = (
            port.get("MaxSpeedMbps")
            or adapter.get("MaxSpeedMbps")
            or port.get("SpeedMbps")
            or adapter.get("SpeedMbps")
        )
        if max_mbps and float(max_mbps) > 0:
            return float(max_mbps) / 1000.0

        # 3. Supported speeds list
        supp = port.get("SupportedSpeedsGbps") or adapter.get("SupportedSpeedsGbps") or []
        if isinstance(supp, list) and supp:
            valid = []
            for s in supp:
                try:
                    if float(s or 0) > 0:
                        valid.append(float(s))
                except Exception:
                    pass
            if valid:
                return max(valid)

        # 4. Name regex matching for common NIC speeds (25G, 10G, 100G, 40G, 1G)
        port_id_str = str(port.get("Id") or port.get("port_id") or "")
        search_str = f"{resolved_name} {adapter.get('Name','')} {adapter.get('Model','')} {adapter.get('Id','')} {adapter.get('Description','')} {port.get('Name','')} {port.get('Description','')} {port_id_str}"

        # Dual-rate combo NDC ports (e.g. Dell "2P X550/2P I350" -> ports 1-2 are 10G, ports 3-4 are 1G)
        if "X550" in search_str and "I350" in search_str:
            if re.search(r"[-_.]?[34]$", port_id_str):
                return 1.0
            if re.search(r"[-_.]?[12]$", port_id_str):
                return 10.0

        matches = re.findall(r"\b(400|200|100|50|40|25|10|1)\s*(?:G(?:bE|b|E)?|Gigabit)\b", search_str, re.IGNORECASE)
        if matches:
            try:
                return max(float(x) for x in matches)
            except Exception:
                pass

        # 5. Bare Gigabit, GbE, 1000Base
        if re.search(r"\b(?:Gigabit|GbE|1000Base(?:-[A-Z0-9]+)?)\b", search_str, re.IGNORECASE):
            return 1.0

        # 6. Controller family heuristics for down-link ports
        # 1GbE: Intel I350, I340, I210, I211; Broadcom BCM5720, BCM5719, 5720-t, NetXtreme
        if re.search(r"\b(?:I350[A-Z0-9]*|I340[A-Z0-9]*|I210[A-Z0-9]*|I211[A-Z0-9]*|BCM5720|BCM5719|5720[-_]?[tT]|NetXtreme)\b", search_str, re.IGNORECASE):
            return 1.0

        # 10GbE: Intel X550, X540, X520; Broadcom BCM57810
        if re.search(r"\b(?:X550[A-Z0-9]*|X540[A-Z0-9]*|X520[A-Z0-9]*|BCM57810)\b", search_str, re.IGNORECASE):
            return 10.0

        # 100GbE / 25GbE Mellanox / Intel controllers
        if re.search(r"\b(?:ConnectX[-_]?6|CX[-_]?6)\b", search_str, re.IGNORECASE):
            return 100.0
        if re.search(r"\b(?:ConnectX[-_]?5|CX[-_]?5)\b", search_str, re.IGNORECASE):
            return 100.0
        if re.search(r"\b(?:ConnectX[-_]?4|CX[-_]?4)\b", search_str, re.IGNORECASE):
            return 25.0
        if re.search(r"\bE810\b", search_str, re.IGNORECASE):
            return 100.0

        # Cisco VIC model rated speeds
        if re.search(r"\b(?:VIC\s*149[57]|VIC[-_]?149[57]|MLOM[-_]?C100|1497)\b", search_str, re.IGNORECASE):
            return 100.0
        if re.search(r"\b(?:VIC\s*15[24]\d{2}|VIC[-_]?15[24]\d{2})\b", search_str, re.IGNORECASE):
            return 100.0
        if re.search(r"\b(?:VIC\s*145[57]|VIC[-_]?145[57])\b", search_str, re.IGNORECASE):
            return 25.0
        if re.search(r"\b(?:VIC\s*138[57]|VIC[-_]?138[57]|VIC\s*1440|VIC\s*1340)\b", search_str, re.IGNORECASE):
            return 40.0
        if re.search(r"\b(?:VIC\s*122[57]|VIC[-_]?122[57])\b", search_str, re.IGNORECASE):
            return 10.0

        return 0.0

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

        The helper ``_is_sub_iface`` catches these by checking whether the
        candidate ID is a ``-``/``_``/``.``-separated extension of an already-seen
        adapter ID, and skips it.

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
        def _find_parent_pcie_device(uid_val: str, iface_uri_val: str, pcie_c: Optional[list]) -> Optional[Tuple[dict, Optional[dict]]]:
            if not pcie_c:
                return None
            for dev in pcie_c:
                if not isinstance(dev, dict):
                    continue
                dev_id = str(dev.get("Id") or dev.get("id") or "").strip()
                raw_dev = dev.get("_raw") if isinstance(dev.get("_raw"), dict) else dev
                dev_funcs = raw_dev.get("_expanded_func_objects") or []
                if not dev_funcs and isinstance(raw_dev.get("PCIeFunctions"), list):
                    dev_funcs = raw_dev.get("PCIeFunctions")
                if not dev_funcs and isinstance(dev.get("functions"), list):
                    dev_funcs = dev.get("functions")
                for fn in dev_funcs:
                    if not isinstance(fn, dict):
                        continue
                    fn_links = fn.get("Links") or {}
                    for ei in fn_links.get("EthernetInterfaces") or []:
                        if isinstance(ei, dict):
                            ref = str(ei.get("@odata.id") or "").strip()
                            if (iface_uri_val and ref == iface_uri_val) or (uid_val and ref.endswith("/" + uid_val)):
                                return dev, fn
                dev_links = raw_dev.get("Links") or dev.get("Links") or {}
                for ei in dev_links.get("EthernetInterfaces") or []:
                    if isinstance(ei, dict):
                        ref = str(ei.get("@odata.id") or "").strip()
                        if (iface_uri_val and ref == iface_uri_val) or (uid_val and ref.endswith("/" + uid_val)):
                            return dev, (dev_funcs[0] if dev_funcs else None)
                if dev_id and len(dev_id) <= 6:
                    for sep in (".", "-", "_"):
                        if uid_val.startswith(dev_id + sep):
                            return dev, (dev_funcs[0] if dev_funcs else None)
            return None

        def _get_parent_iface_id(
            uid: str,
            seen: set,
            nics: Optional[list] = None,
            eth_mac: str = "",
            iface_uri: str = "",
            pcie_cache: Optional[list] = None,
        ) -> Optional[str]:
            """Return parent adapter UID if uid is a partition / sub-port of an already-seen adapter or port."""
            # 1. MAC match against already collected adapters in nics
            if nics and eth_mac:
                for p_nic in nics:
                    for port in p_nic.get("ports") or []:
                        p_mac = _clean_mac_address(port.get("mac_address"))
                        if p_mac and eth_mac and p_mac.lower() == eth_mac.lower():
                            return p_nic.get("id")
                    for part in p_nic.get("npar_partitions") or p_nic.get("vic_virtual_interfaces") or []:
                        p_mac = _clean_mac_address(part.get("mac_address"))
                        if p_mac and eth_mac and p_mac.lower() == eth_mac.lower():
                            return p_nic.get("id")

            # 2. String prefix match on seen IDs
            for s in seen:
                if len(s) < 3:
                    continue
                for sep in ("-", "_", "."):
                    if uid.startswith(s + sep):
                        return s

            # 3. Port ID prefix match & MLOM matching on already collected adapters
            if nics:
                for p_nic in nics:
                    p_id = p_nic.get("id") or ""
                    for port in p_nic.get("ports") or []:
                        p_port_id = port.get("port_id") or ""
                        if len(p_port_id) >= 3:
                            for sep in ("-", "_", "."):
                                if uid.startswith(p_port_id + sep):
                                    return p_id
                    # Cisco UCS MLOM sub-devices (MLOM.0, MLOM.1 mapping to MLOM card)
                    p_id_raw = str(p_id).upper()
                    p_name_raw = str(p_nic.get("name") or "").upper()
                    is_mlom_adapter = (
                        "MLOM" in p_id_raw
                        or "MLOM" in p_name_raw
                        or "UCSC-M-" in p_id_raw
                        or p_nic.get("cna_family") == "cisco_vic"
                        or "VIC" in p_name_raw
                    )
                    if is_mlom_adapter and (uid.upper().startswith("MLOM.") or uid.upper().startswith("MLOM-")):
                        return p_id

            # 4. PCIe Device Link Correlation against existing adapters (for MLOM / VIC deduplication)
            if pcie_cache and nics:
                pdev_match = _find_parent_pcie_device(uid, iface_uri, pcie_cache)
                if pdev_match:
                    parent_dev, _ = pdev_match
                    pdev_id = str(parent_dev.get("Id") or "").strip()
                    if pdev_id == "MLOM":
                        for p_nic in nics:
                            p_name = str(p_nic.get("name") or "").strip()
                            if "VIC" in p_name.upper() or p_nic.get("cna_family") == "cisco_vic":
                                return p_nic.get("id")
            return None

        nic_list = []
        seen_ids = set()
        license_blocked_note = None
        endpoints = []
        if self.chassis_uri:
            endpoints.append(f"{self.chassis_uri}/NetworkAdapters")
        if self.sys_uri:
            endpoints.append(f"{self.sys_uri}/BaseNetworkAdapters")
            endpoints.append(f"{self.sys_uri}/NetworkInterfaces")
            endpoints.append(f"{self.sys_uri}/EthernetInterfaces")

        # Fast-path: probe expanded EthernetInterfaces early to populate request cache
        fetch_expand_fn = getattr(self, "_fetch_expanded_collection", None)
        if getattr(self, "vendor", "") in ("supermicro", "quanta"):
            self.expand_supported = False
        if callable(fetch_expand_fn) and getattr(self, "expand_supported", False) and self.sys_uri:
            fetch_expand_fn(f"{self.sys_uri}/EthernetInterfaces")

        # Fast-path: probe expanded Chassis NetworkAdapters early if supported
        if callable(fetch_expand_fn) and getattr(self, "expand_supported", False) and self.chassis_uri:
            chassis_net_ep = f"{self.chassis_uri}/NetworkAdapters"
            expandable_map = self.oem_expandable_collections() if hasattr(self, "oem_expandable_collections") else {}
            req_levels = 1
            if hasattr(expandable_map, "get_levels"):
                req_levels = expandable_map.get_levels(chassis_net_ep, 1)
            elif getattr(self, "expand_max_levels", 1) >= 2 and ("NetworkAdapters" in expandable_map or chassis_net_ep in expandable_map):
                req_levels = 2
            net_coll = fetch_expand_fn(chassis_net_ep, levels=req_levels)
            if isinstance(net_coll, dict) and isinstance(net_coll.get("Members"), list):
                for m in net_coll["Members"]:
                    if not isinstance(m, dict):
                        continue
                    m_uri = m.get("@odata.id")
                    if m_uri and len(m) > 1 and hasattr(self, "_populate_request_cache"):
                        self._populate_request_cache(m_uri, m)

                    # Cache NetworkPorts collection and subordinate port items
                    raw_np = (
                        m.get("NetworkPorts")
                        or m.get("Ports")
                        or m.get("PhysicalPorts")
                        or get_nested(m, "Oem", "Cisco", "NetworkPorts")
                        or get_nested(m, "Oem", "Cisco", "Ports")
                        or get_nested(m, "Oem", "CIMC", "NetworkPorts")
                        or get_nested(m, "Oem", "CIMC", "Ports")
                    )
                    if isinstance(raw_np, dict):
                        np_uri = raw_np.get("@odata.id")
                        if np_uri and len(raw_np) > 1 and hasattr(self, "_populate_request_cache"):
                            self._populate_request_cache(np_uri, raw_np)
                        p_members = raw_np.get("Members") or raw_np.get("Ports") or []
                        if isinstance(p_members, list):
                            for p in p_members:
                                if isinstance(p, dict) and p.get("@odata.id") and len(p) > 1 and hasattr(self, "_populate_request_cache"):
                                    if not p.get("AssociatedNetworkAddresses"):
                                        oem_addrs = (
                                            get_nested(p, "Oem", "Cisco", "AssociatedNetworkAddresses")
                                            or get_nested(p, "Oem", "CIMC", "AssociatedNetworkAddresses")
                                            or get_nested(p, "Oem", "Cisco", "VicPort", "AssociatedNetworkAddresses")
                                            or get_nested(p, "Oem", "CIMC", "VicPort", "AssociatedNetworkAddresses")
                                        )
                                        if oem_addrs:
                                            p["AssociatedNetworkAddresses"] = oem_addrs if isinstance(oem_addrs, list) else [oem_addrs]
                                        else:
                                            v_mac = (
                                                get_nested(p, "Oem", "Cisco", "VicPort", "MacAddress")
                                                or get_nested(p, "Oem", "CIMC", "VicPort", "MacAddress")
                                                or get_nested(p, "Oem", "Cisco", "MacAddress")
                                                or get_nested(p, "Oem", "CIMC", "MacAddress")
                                            )
                                            if v_mac:
                                                p["AssociatedNetworkAddresses"] = [v_mac] if isinstance(v_mac, str) else v_mac
                                    self._populate_request_cache(p["@odata.id"], p)
                    elif isinstance(raw_np, list):
                        for p in raw_np:
                            if isinstance(p, dict) and p.get("@odata.id") and len(p) > 1 and hasattr(self, "_populate_request_cache"):
                                if not p.get("AssociatedNetworkAddresses"):
                                    oem_addrs = (
                                        get_nested(p, "Oem", "Cisco", "AssociatedNetworkAddresses")
                                        or get_nested(p, "Oem", "CIMC", "AssociatedNetworkAddresses")
                                        or get_nested(p, "Oem", "Cisco", "VicPort", "AssociatedNetworkAddresses")
                                        or get_nested(p, "Oem", "CIMC", "VicPort", "AssociatedNetworkAddresses")
                                    )
                                    if oem_addrs:
                                        p["AssociatedNetworkAddresses"] = oem_addrs if isinstance(oem_addrs, list) else [oem_addrs]
                                    else:
                                        v_mac = (
                                            get_nested(p, "Oem", "Cisco", "VicPort", "MacAddress")
                                            or get_nested(p, "Oem", "CIMC", "VicPort", "MacAddress")
                                            or get_nested(p, "Oem", "Cisco", "MacAddress")
                                            or get_nested(p, "Oem", "CIMC", "MacAddress")
                                        )
                                        if v_mac:
                                            p["AssociatedNetworkAddresses"] = [v_mac] if isinstance(v_mac, str) else v_mac
                                self._populate_request_cache(p["@odata.id"], p)

                    # Cache NetworkDeviceFunctions collection and subordinate function items
                    raw_ndf = (
                        m.get("NetworkDeviceFunctions")
                        or get_nested(m, "Oem", "Cisco", "NetworkDeviceFunctions")
                        or get_nested(m, "Oem", "CIMC", "NetworkDeviceFunctions")
                    )
                    if isinstance(raw_ndf, dict):
                        ndf_uri = raw_ndf.get("@odata.id")
                        if ndf_uri and len(raw_ndf) > 1 and hasattr(self, "_populate_request_cache"):
                            self._populate_request_cache(ndf_uri, raw_ndf)
                        f_members = raw_ndf.get("Members") or raw_ndf.get("NetworkDeviceFunctions") or []
                        if isinstance(f_members, list):
                            for f in f_members:
                                if isinstance(f, dict) and f.get("@odata.id") and len(f) > 1 and hasattr(self, "_populate_request_cache"):
                                    self._populate_request_cache(f["@odata.id"], f)
                    elif isinstance(raw_ndf, list):
                        for f in raw_ndf:
                            if isinstance(f, dict) and f.get("@odata.id") and len(f) > 1 and hasattr(self, "_populate_request_cache"):
                                self._populate_request_cache(f["@odata.id"], f)

        expandable_map = self.oem_expandable_collections() if hasattr(self, "oem_expandable_collections") else {}
        for ep in endpoints:
            if callable(fetch_expand_fn) and getattr(self, "expand_supported", False):
                if "EthernetInterfaces" in ep:
                    coll = fetch_expand_fn(ep) or {}
                elif ep in expandable_map or (ep.endswith("/NetworkAdapters") and not ep.endswith("/BaseNetworkAdapters")):
                    req_levels = 1
                    if hasattr(expandable_map, "get_levels"):
                        req_levels = expandable_map.get_levels(ep, 1)
                    elif getattr(self, "expand_max_levels", 1) >= 2:
                        req_levels = 2
                    coll = fetch_expand_fn(ep, levels=req_levels) or {}
                else:
                    coll = self._get(ep) or {}
            else:
                coll = self._get(ep) or {}
            lic_msg = self._is_license_blocked(coll)
            if lic_msg:
                license_blocked_note = lic_msg
                continue
            is_eth_iface_ep = "EthernetInterfaces" in ep
            for member in self._get_members(coll):
                try:
                    adapter_uri = member.get("@odata.id") if isinstance(member, dict) else (member if isinstance(member, str) else None)
                    if not adapter_uri:
                        continue
                    if isinstance(member, dict) and len(member) > 2 and (member.get("Id") or member.get("MACAddress")):
                        adapter = member
                    else:
                        adapter = self._get(adapter_uri)
                    if not adapter:
                        continue
                    if adapter_uri and len(adapter) > 2 and hasattr(self, "_populate_request_cache"):
                        self._populate_request_cache(adapter_uri, adapter)
                    uid = adapter.get("Id", adapter_uri)
                    # Exact duplicate
                    if uid in seen_ids:
                        continue
                    # Sub-interface / partition of a NetworkAdapter already captured
                    adapter_mac = _clean_mac_address(adapter.get("MACAddress"))
                    parent_uid = _get_parent_iface_id(
                        uid, seen_ids, nic_list,
                        eth_mac=adapter_mac,
                        iface_uri=adapter_uri,
                        pcie_cache=pcie_cache,
                    )
                    if parent_uid:
                        # Append or merge partition details to parent adapter if present in nic_list
                        for p_nic in nic_list:
                            if p_nic.get("id") == parent_uid:
                                if p_nic.get("is_vic_virtual") or p_nic.get("cna_family") == "cisco_vic":
                                    logger.debug("Deduplicated duplicate logical interface %s on Cisco VIC %s", uid, parent_uid)
                                    seen_ids.add(uid)
                                    break
                                sub_speed = self._extract_nic_speed_gbps(adapter, adapter, "")
                                sub_link = adapter.get("LinkStatus") or "Down"
                                sub_mac = _clean_mac_address(adapter.get("MACAddress"))
                                sub_parts_raw = p_nic.setdefault("npar_partitions", [])
                                sub_parts = sub_parts_raw if isinstance(sub_parts_raw, list) else []
                                # Deduplicate / merge by partition_id
                                existing_part = None
                                for sp in sub_parts:
                                    if isinstance(sp, dict) and sp.get("partition_id") == uid:
                                        existing_part = sp
                                        break
                                if existing_part is not None:
                                    if sub_speed > 0:
                                        existing_part["speed_gbps"] = int(sub_speed) if sub_speed == int(sub_speed) else round(sub_speed, 2)
                                    if (sub_link and sub_link != "Down") or not existing_part.get("link_status"):
                                        existing_part["link_status"] = sub_link
                                    if sub_mac and not existing_part.get("mac_address"):
                                        existing_part["mac_address"] = sub_mac
                                else:
                                    sub_parts.append({
                                        "partition_id": uid,
                                        "speed_gbps": int(sub_speed) if sub_speed == int(sub_speed) else round(sub_speed, 2),
                                        "link_status": sub_link,
                                        "mac_address": sub_mac,
                                    })
                                p_ports = p_nic.get("ports")
                                p_ports_len = len(p_ports) if isinstance(p_ports, (list, tuple)) else 0
                                p_nic["is_npar"] = _evaluate_npar_partitions(sub_parts, p_ports_len)
                                seen_ids.add(uid)
                                break
                        continue

                    # Correlate standalone EthernetInterfaces with PCIeDevice (e.g. onboard LOM)
                    if is_eth_iface_ep and pcie_cache:
                        pdev_match = _find_parent_pcie_device(uid, adapter_uri, pcie_cache)
                        if pdev_match:
                            parent_dev, parent_fn = pdev_match
                            parent_adapter_id = str(parent_dev.get("Id") or parent_dev.get("id") or "").strip()
                            raw_pdev = parent_dev.get("_raw") if isinstance(parent_dev.get("_raw"), dict) else parent_dev
                            if parent_adapter_id == "MLOM" or any(adapter_mac and p.get("mac_address") and adapter_mac.lower() == str(p.get("mac_address")).lower() for n in nic_list for p in n.get("ports", [])):
                                logger.debug("Deduplicated logical interface %s to parent adapter", uid)
                                seen_ids.add(uid)
                                continue

                            existing_parent = next((n for n in nic_list if n.get("id") == parent_adapter_id), None)
                            sub_speed = self._extract_nic_speed_gbps(adapter, adapter, "")
                            sub_link = adapter.get("LinkStatus") or "Down"
                            sub_mac = _clean_mac_address(adapter.get("MACAddress"))

                            if existing_parent:
                                if sub_speed <= 0:
                                    if "X550" in str(existing_parent.get("name", "")).upper() or "1563" in str(existing_parent.get("device_id", "")).lower():
                                        sub_speed = 10.0
                                existing_parent["ports"].append({
                                    "port_id": uid,
                                    "link_status": sub_link,
                                    "current_speed_gbps": int(sub_speed) if sub_speed == int(sub_speed) else round(sub_speed, 2),
                                    "mac_address": sub_mac,
                                })
                                seen_ids.add(uid)
                                continue
                            else:
                                p_name = str(parent_dev.get("Name") or parent_dev.get("name") or "").strip() or f"PCIe Device {parent_adapter_id}"
                                p_pci = {
                                    "vendor_id": parent_dev.get("vendor_id", ""),
                                    "device_id": parent_dev.get("device_id", ""),
                                    "subsystem_vendor_id": parent_dev.get("subsystem_vendor_id", ""),
                                    "subsystem_id": parent_dev.get("subsystem_id", ""),
                                    "pci_quad": parent_dev.get("pci_quad", ""),
                                    "pci_pair": parent_dev.get("pci_pair", ""),
                                }
                                if not p_pci["pci_quad"]:
                                    p_pci = extract_pci_ids_from_dict(parent_fn or parent_dev, get_fn=self._get)
                                if not p_pci["pci_quad"]:
                                    p_pci = match_pcie_cache(parent_dev, pcie_cache, get_fn=self._get)
                                if not p_pci["pci_quad"]:
                                    p_pci = match_firmware_inventory_pci(p_name, get_fn=self._get)

                                vid = str(p_pci.get("vendor_id") or "").lower()
                                if vid in ("8086", "0x8086") or "intel" in p_name.lower():
                                    p_mfg = "Intel"
                                elif vid in ("14e4", "0x14e4") or "broadcom" in p_name.lower():
                                    p_mfg = "Broadcom"
                                elif vid in ("15b3", "0x15b3") or "mellanox" in p_name.lower():
                                    p_mfg = "Mellanox"
                                elif vid in ("1137", "0x1137") or "cisco" in p_name.lower():
                                    p_mfg = "Cisco Systems Inc"
                                else:
                                    p_mfg = str(parent_dev.get("Manufacturer") or parent_dev.get("manufacturer") or "Unknown")

                                if sub_speed <= 0:
                                    if "X550" in p_name.upper() or "1563" in str(p_pci.get("device_id", "")).lower():
                                        sub_speed = 10.0
                                p_fw = parent_dev.get("firmware_version") or raw_pdev.get("FirmwareVersion") or parent_dev.get("FirmwareVersion") or "N/A"
                                p_link = extract_pcie_link_status(raw_pdev)
                                new_nic = {
                                    "id": parent_adapter_id,
                                    "name": p_name,
                                    "manufacturer": p_mfg,
                                    "part_number": parent_dev.get("part_number") or raw_pdev.get("PartNumber") or parent_dev.get("PartNumber") or "N/A",
                                    "firmware_version": p_fw,
                                    "ports": [{
                                        "port_id": uid,
                                        "link_status": sub_link,
                                        "current_speed_gbps": int(sub_speed) if sub_speed == int(sub_speed) else round(sub_speed, 2),
                                        "mac_address": sub_mac,
                                    }],
                                    "speed_gbps": int(sub_speed) if sub_speed == int(sub_speed) else round(sub_speed, 2),
                                    "vendor_id": p_pci["vendor_id"],
                                    "device_id": p_pci["device_id"],
                                    "subsystem_vendor_id": p_pci["subsystem_vendor_id"],
                                    "subsystem_id": p_pci["subsystem_id"],
                                    "pci_quad": p_pci["pci_quad"],
                                    "pci_pair": p_pci["pci_pair"],
                                    "current_pcie_type": p_link.get("current_pcie_type"),
                                    "max_pcie_type": p_link.get("max_pcie_type"),
                                    "current_pcie_width": p_link.get("current_pcie_width"),
                                    "max_pcie_width": p_link.get("max_pcie_width"),
                                    "downgraded": p_link["downgraded"],
                                    "downgrade_reason": p_link["reason"],
                                    "downgrade_badge": p_link["badge"],
                                    "is_cna": False,
                                    "is_npar": False,
                                    "is_vic_virtual": False,
                                    "meets_esa_25g": (sub_speed >= 25.0),
                                }
                                nic_list.append(new_nic)
                                seen_ids.add(uid)
                                seen_ids.add(parent_adapter_id)
                                continue
                    seen_ids.add(uid)
                    dynamic_ports = []

                    # ── Resolve display name and OEM model info ─────────────────────
                    resolved_name = self._resolve_product_name(adapter, pcie_cache)
                    # For EthernetInterfaces, supplement bare names with OEM fields
                    if is_eth_iface_ep and (resolved_name.lower() in GENERIC_NAME_BLOCKLIST or not resolved_name.strip()):
                        dell_nic = get_nested(adapter, "Oem", "Dell", "DellNIC", default={})
                        oem_name = dell_nic.get("ProductName") or dell_nic.get("BusProtocol") or ""
                        if not oem_name:
                            # HPE iLO: AdapterDetails carries human-readable product name
                            hpe_det = get_nested(adapter, "Oem", "Hpe", "AdapterDetails", default={})
                            oem_name = hpe_det.get("Name") or hpe_det.get("Model") or ""
                        if oem_name and oem_name.lower() not in GENERIC_NAME_BLOCKLIST:
                            resolved_name = oem_name

                    # Exclude pure Fibre Channel controllers (handled by collect_fc_hbas)
                    cna_check = classify_cna_adapter(
                        resolved_name,
                        str(adapter.get("Manufacturer") or ""),
                        str(adapter.get("Model") or ""),
                        str(adapter.get("PartNumber") or ""),
                    )
                    _name_fc_check = f"{resolved_name} {adapter.get('Name', '')} {adapter.get('Description', '')} {adapter.get('Model', '')} {adapter.get('Id', '')} {uid}".lower()
                    is_pure_fc = (
                        not cna_check.get("is_cna")
                        and (
                            "fibre channel" in _name_fc_check
                            or bool(re.search(r"\bFC\s+(?:Adapter|HBA|Port)\b", _name_fc_check, re.I))
                            or bool(re.search(r"\bQLE2[5678]\d{2}\b|\bLPe3[125678]\d{3}\b", _name_fc_check, re.I))
                            or bool(re.search(r"\bFC\.", str(uid)))
                            or bool(re.search(r"\bFC\.", str(adapter.get("Id", ""))))
                            or bool(adapter.get("FcPorts"))
                        )
                    )
                    if is_pure_fc:
                        continue

                    manufacturer = (adapter.get("Manufacturer")
                                    or get_nested(adapter, "Oem", "Dell", "DellNIC", "BusProtocol")
                                    or "Unknown")
                    part_number  = adapter.get("PartNumber") or "N/A"

                    # ── Physical adapter path (NetworkAdapters / NetworkInterfaces / BaseNetworkAdapters) ──
                    raw_ports = (
                        adapter.get("PhysicalPorts")
                        or adapter.get("FcPorts")
                        or adapter.get("NetworkPorts")
                        or adapter.get("Ports")
                        or get_nested(adapter, "Oem", "Cisco", "NetworkPorts")
                        or get_nested(adapter, "Oem", "Cisco", "Ports")
                        or get_nested(adapter, "Oem", "CIMC", "NetworkPorts")
                        or get_nested(adapter, "Oem", "CIMC", "Ports")
                    )
                    if isinstance(raw_ports, dict) and isinstance(raw_ports.get("Members"), list):
                        port_members = raw_ports.get("Members", [])
                    elif isinstance(raw_ports, dict) and isinstance(raw_ports.get("Ports"), list):
                        port_members = raw_ports.get("Ports", [])
                    elif isinstance(raw_ports, list):
                        port_members = raw_ports
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
                        port_members = self._get_members(ports_uri)

                    if port_members:
                        def _fetch_port(pm):
                            port_uri = pm.get("@odata.id") if isinstance(pm, dict) else (pm if isinstance(pm, str) else None)
                            return self._get(port_uri) if port_uri else (pm if isinstance(pm, dict) else None)

                        port_jsons = []
                        ports_to_fetch = []
                        for pm in port_members:
                            if isinstance(pm, dict) and len(pm) > 2 and (
                                pm.get("LinkStatus")
                                or pm.get("CurrentLinkSpeedMbps")
                                or pm.get("AssociatedNetworkAddresses")
                                or pm.get("MACAddress")
                                or pm.get("Status")
                                or pm.get("Id")
                                or get_nested(pm, "Oem", "Cisco")
                                or get_nested(pm, "Oem", "CIMC")
                            ):
                                port_jsons.append(pm)
                            else:
                                p_uri = pm.get("@odata.id") if isinstance(pm, dict) else (pm if isinstance(pm, str) else None)
                                if p_uri and hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
                                    cached_p = self._request_cache.get(p_uri)
                                    if not cached_p and getattr(self, "host_url", ""):
                                        cached_p = self._request_cache.get(f"{self.host_url}{p_uri}")
                                    if isinstance(cached_p, dict) and len(cached_p) > 2:
                                        port_jsons.append(cached_p)
                                        continue
                                ports_to_fetch.append(pm)

                        if ports_to_fetch:
                            max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(4), max(1, len(ports_to_fetch)))
                            _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
                            pool = ThreadPoolExecutor(max_workers=max_w)
                            try:
                                futures = [pool.submit(_wrap_task(_fetch_port), pm) for pm in ports_to_fetch]
                                wait(futures, timeout=15.0)
                                for fut in futures:
                                    if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                                        break
                                    try:
                                        if fut.done():
                                            res = fut.result()
                                            if res:
                                                port_jsons.append(res)
                                    except Exception as p_exc:
                                        logger.debug("Error processing NIC port: %s", p_exc)
                            finally:
                                pool.shutdown(wait=False, cancel_futures=True)

                        for idx, port in enumerate(port_jsons, start=1):
                            try:
                                final_speed = self._extract_nic_speed_gbps(port, adapter, resolved_name)
                                assoc_macs = (
                                    port.get("AssociatedNetworkAddresses")
                                    or get_nested(port, "Oem", "Cisco", "AssociatedNetworkAddresses")
                                    or get_nested(port, "Oem", "CIMC", "AssociatedNetworkAddresses")
                                    or get_nested(port, "Oem", "Cisco", "VicPort", "AssociatedNetworkAddresses")
                                    or get_nested(port, "Oem", "CIMC", "VicPort", "AssociatedNetworkAddresses")
                                    or []
                                )
                                if isinstance(assoc_macs, str):
                                    assoc_macs = [assoc_macs]
                                port_mac = _clean_mac_address(
                                    assoc_macs[0]
                                    if (isinstance(assoc_macs, list) and assoc_macs)
                                    else (
                                        port.get("MACAddress")
                                        or port.get("MacAddress")
                                        or get_nested(port, "Oem", "Cisco", "VicPort", "MacAddress")
                                        or get_nested(port, "Oem", "CIMC", "VicPort", "MacAddress")
                                        or get_nested(port, "Oem", "Cisco", "MacAddress")
                                        or get_nested(port, "Oem", "CIMC", "MacAddress")
                                        or ""
                                    )
                                )
                                t_info = self.oem_port_transceiver(port) if hasattr(self, "oem_port_transceiver") else {}
                                port_id = str(
                                    port.get("Id")
                                    or get_nested(port, "Oem", "Hpe", "PortNumber")
                                    or port.get("PortNumber")
                                    or port.get("PhysicalPortNumber")
                                    or idx
                                )
                                link_status_raw = str(port.get("LinkStatus") or "Down").strip()
                                link_status = (
                                    "Up" if link_status_raw.lower() in ("up", "linkup")
                                    else ("Down" if link_status_raw.lower() in ("down", "linkdown", "nolink", "no_link", "notconnected")
                                    else link_status_raw)
                                )
                                dynamic_ports.append({
                                    "port_id": port_id,
                                    "link_status": link_status,
                                    "current_speed_gbps": int(final_speed) if final_speed == int(final_speed) else round(final_speed, 2),
                                    "mac_address": port_mac,
                                    "transceiver_identifier": t_info.get("identifier_type", "N/A"),
                                    "transceiver_interface": t_info.get("interface_type", "N/A"),
                                    "transceiver_vendor": t_info.get("vendor_name", "N/A"),
                                    "transceiver_part_number": t_info.get("part_number", "N/A"),
                                    "transceiver_serial": t_info.get("serial_number", "N/A"),
                                    "rx_power_dbm": t_info.get("rx_power_dbm"),
                                    "tx_power_dbm": t_info.get("tx_power_dbm"),
                                    "temperature_c": t_info.get("temperature_c"),
                                    "transceiver_temperature_c": t_info.get("temperature_c"),
                                    "laser_bias_current_ma": t_info.get("laser_bias_current_ma"),
                                    "voltage_v": t_info.get("voltage_v"),
                                })
                            except Exception as p_exc:
                                logger.debug("Error parsing NIC port detail: %s", p_exc)

                    # ── EthernetInterface path (logical port view) ──────────────────
                    # These resources ARE a port: link status and speed live at the
                    # top level, not in a NetworkPorts sub-collection.
                    if is_eth_iface_ep and not dynamic_ports:
                        link_status = adapter.get("LinkStatus") or ""
                        final_speed = self._extract_nic_speed_gbps(adapter, adapter, resolved_name)
                        eth_mac = _clean_mac_address(adapter.get("MACAddress"))
                        if link_status or final_speed > 0 or eth_mac:
                            t_info = self.oem_port_transceiver(adapter) if hasattr(self, "oem_port_transceiver") else {}
                            dynamic_ports.append({
                                "port_id": uid,
                                "link_status": link_status or "Down",
                                "current_speed_gbps": int(final_speed) if final_speed == int(final_speed) else round(final_speed, 2),
                                "mac_address": eth_mac,
                                "transceiver_identifier": t_info.get("identifier_type", "N/A"),
                                "transceiver_interface": t_info.get("interface_type", "N/A"),
                                "transceiver_vendor": t_info.get("vendor_name", "N/A"),
                                "transceiver_part_number": t_info.get("part_number", "N/A"),
                                "transceiver_serial": t_info.get("serial_number", "N/A"),
                                "rx_power_dbm": t_info.get("rx_power_dbm"),
                                "tx_power_dbm": t_info.get("tx_power_dbm"),
                                "temperature_c": t_info.get("temperature_c"),
                                "transceiver_temperature_c": t_info.get("temperature_c"),
                                "laser_bias_current_ma": t_info.get("laser_bias_current_ma"),
                                "voltage_v": t_info.get("voltage_v"),
                            })

                    # ── Check NetworkDeviceFunctions for NPAR partitions & CNA functions ──
                    raw_ndf = (
                        adapter.get("NetworkDeviceFunctions")
                        or get_nested(adapter, "Oem", "Cisco", "NetworkDeviceFunctions")
                        or get_nested(adapter, "Oem", "CIMC", "NetworkDeviceFunctions")
                    )
                    if isinstance(raw_ndf, dict) and isinstance(raw_ndf.get("Members"), list):
                        ndf_members = raw_ndf.get("Members", [])
                    elif isinstance(raw_ndf, list):
                        ndf_members = raw_ndf
                    else:
                        ndf_uri = (
                            get_nested(adapter, "NetworkDeviceFunctions", "@odata.id")
                            or get_nested(adapter, "Oem", "Cisco", "NetworkDeviceFunctions", "@odata.id")
                            or get_nested(adapter, "Oem", "CIMC", "NetworkDeviceFunctions", "@odata.id")
                            or f"{adapter_uri}/NetworkDeviceFunctions"
                        )
                        ndf_members = self._get_members(ndf_uri)

                    ndf_jsons = []
                    if ndf_members:
                        def _fetch_ndf(nm):
                            n_uri = nm.get("@odata.id") if isinstance(nm, dict) else (nm if isinstance(nm, str) else None)
                            return self._get(n_uri) if n_uri else (nm if isinstance(nm, dict) else None)

                        ndf_to_fetch = []
                        for nm in ndf_members:
                            if isinstance(nm, dict) and len(nm) > 2 and (
                                nm.get("NetDevFuncType")
                                or nm.get("Ethernet")
                                or nm.get("FibreChannel")
                                or nm.get("AssignablePhysicalNetworkPorts")
                                or get_nested(nm, "Oem", "Cisco")
                                or get_nested(nm, "Oem", "CIMC")
                            ):
                                ndf_jsons.append(nm)
                            else:
                                n_uri = nm.get("@odata.id") if isinstance(nm, dict) else (nm if isinstance(nm, str) else None)
                                if n_uri and hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
                                    cached_n = self._request_cache.get(n_uri)
                                    if not cached_n and getattr(self, "host_url", ""):
                                        cached_n = self._request_cache.get(f"{self.host_url}{n_uri}")
                                    if isinstance(cached_n, dict) and len(cached_n) > 2:
                                        ndf_jsons.append(cached_n)
                                        continue
                                ndf_to_fetch.append(nm)

                        if ndf_to_fetch:
                            max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(4), max(1, len(ndf_to_fetch)))
                            _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
                            pool = ThreadPoolExecutor(max_workers=max_w)
                            try:
                                futures = [pool.submit(_wrap_task(_fetch_ndf), nm) for nm in ndf_to_fetch]
                                wait(futures, timeout=15.0)
                                for fut in futures:
                                    if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                                        break
                                    try:
                                        if fut.done():
                                            res = fut.result()
                                            if res:
                                                ndf_jsons.append(res)
                                    except Exception as n_exc:
                                        logger.debug("Error processing NDF: %s", n_exc)
                            finally:
                                pool.shutdown(wait=False, cancel_futures=True)

                    # ── Classify CNA Dual-Persona (VIC / FlexFabric / FastLinQ / OneConnect) ──
                    cna_info = classify_cna_adapter(
                        resolved_name,
                        manufacturer,
                        str(adapter.get("Model") or ""),
                        part_number,
                        net_dev_funcs=ndf_jsons
                    )
                    is_vic = bool(
                        cna_info.get("is_vic")
                        or cna_info.get("cna_family") == "cisco_vic"
                        or "VIC" in resolved_name.upper()
                        or "VIC" in str(adapter.get("Model") or "").upper()
                    )

                    npar_partitions = []
                    is_npar = False
                    is_vic_virtual = False
                    adapter_max_speed = max((p.get("current_speed_gbps") or 0 for p in dynamic_ports), default=0)
                    if ndf_jsons and (len(ndf_jsons) > len(dynamic_ports) or len(ndf_jsons) >= 2 or is_vic):
                        for fn in ndf_jsons:
                            fn_id = str(fn.get("Id") or "").strip()
                            fn_type = str(fn.get("NetDevFuncType") or "").strip()
                            eth_blk = fn.get("Ethernet") or {}
                            fc_blk = fn.get("FibreChannel") or {}
                            fn_mac = _clean_mac_address(eth_blk.get("MACAddress"))
                            fn_bw_pct = (
                                get_nested(fn, "Oem", "Dell", "DellNIC", "BandwidthAllocationPercent")
                                or get_nested(fn, "Oem", "Dell", "DellNIC", "MaxBandwidthPercent")
                                or fn.get("MaxBandwidthPercent")
                            )
                            fn_speed_mbps = (
                                get_nested(fn, "Oem", "Dell", "DellNIC", "SpeedMbps")
                                or fn.get("MaxSpeedMbps")
                                or eth_blk.get("MaxSpeedMbps")
                            )
                            fn_speed_gbps = round(float(fn_speed_mbps) / 1000.0, 2) if fn_speed_mbps else 0.0
                            phys_port_ref = (
                                get_nested(fn, "Links", "PhysicalPortAssignment", "@odata.id")
                                or get_nested(fn, "PhysicalPortAssignment", "@odata.id")
                                or ""
                            )

                            # Cisco VIC & OEM VnicConfiguration extraction
                            oem_caps = self.oem_vnic_capabilities(fn)
                            if not oem_caps:
                                cisco_oem = (
                                    get_nested(fn, "Oem", "Cisco", default={})
                                    or get_nested(fn, "Oem", "CIMC", default={})
                                )
                                if isinstance(cisco_oem, dict) and cisco_oem.get("VnicConfiguration"):
                                    vnic_cfg = cisco_oem.get("VnicConfiguration") or {}
                                    eth_cfg = vnic_cfg.get("EthConfiguration") or {}
                                    vhba_cfg = vnic_cfg.get("VHBAConfiguration") or {}
                                    features = eth_cfg.get("Features") or {}
                                    offload = eth_cfg.get("OffloadProfile") or {}
                                    rss = eth_cfg.get("RssProfile") or {}
                                    oem_caps = {
                                        "cdn": eth_cfg.get("Cdn") or "",
                                        "uplink_port": vnic_cfg.get("UplinkPort"),
                                        "pci_order": vnic_cfg.get("PCIOrder") or "",
                                        "cos": vnic_cfg.get("ClassOfService"),
                                        "vlan_mode": vnic_cfg.get("VlanMode") or "",
                                        "geneve_offload": bool(features.get("GeneveEnabled")),
                                        "vxlan_offload": bool(features.get("VxlanEnabled")),
                                        "rocev2": bool(features.get("Rocev2Enabled")),
                                        "multiqueue": bool(features.get("MultiQueueEnabled")),
                                        "tso_enabled": bool(offload.get("TcpSegmentEnabled")),
                                        "lro_enabled": bool(offload.get("TcpLargeReceiveEnabled")),
                                        "rx_csum": bool(offload.get("TcpRxChecksumEnabled")),
                                        "tx_csum": bool(offload.get("TcpTxChecksumEnabled")),
                                        "rss_enabled": bool(rss.get("RssEnabled")),
                                        "vhba_type": vhba_cfg.get("VHBAType") or [],
                                        "max_data_field_size": vhba_cfg.get("MaxDataFieldSize"),
                                        "fc_work_queue_ring_size": vhba_cfg.get("FcWorkQueueRingSize"),
                                        "fc_recv_queue_ring_size": vhba_cfg.get("FcRecvQueueRingSize"),
                                    }

                            # Sub-interface speed inheritance from physical uplink
                            if fn_speed_gbps <= 0.0:
                                matched_port = None
                                if phys_port_ref:
                                    for p in dynamic_ports:
                                        p_uri = p.get("_uri") or ""
                                        p_id = str(p.get("port_id") or "")
                                        if (p_uri and phys_port_ref == p_uri) or (p_id and phys_port_ref.endswith("/" + p_id)):
                                            matched_port = p
                                            break
                                if not matched_port and "uplink_port" in oem_caps:
                                    u_idx = oem_caps.get("uplink_port")
                                    if isinstance(u_idx, int) and 0 <= u_idx < len(dynamic_ports):
                                        matched_port = dynamic_ports[u_idx]
                                if matched_port and matched_port.get("current_speed_gbps"):
                                    fn_speed_gbps = float(matched_port["current_speed_gbps"])
                                elif adapter_max_speed > 0:
                                    fn_speed_gbps = float(adapter_max_speed)

                            mtu = eth_blk.get("MTUSize") or 0
                            vlan_blk = eth_blk.get("VLAN") or {}
                            vlan_id = vlan_blk.get("VLANId") if vlan_blk.get("VLANEnable") else None
                            wwnn = fc_blk.get("WWNN") or ""
                            wwpn = fc_blk.get("WWPN") or ""

                            if fn_id:
                                npar_partitions.append({
                                    "partition_id": fn_id,
                                    "protocol": fn_type or ("FibreChannel" if fc_blk else "Ethernet"),
                                    "mac_address": fn_mac,
                                    "allocated_pct": fn_bw_pct,
                                    "speed_gbps": fn_speed_gbps,
                                    "physical_port": phys_port_ref,
                                    "cdn": oem_caps.get("cdn", ""),
                                    "mtu": mtu,
                                    "vlan_id": vlan_id,
                                    "vlan_mode": oem_caps.get("vlan_mode", ""),
                                    "geneve_offload": oem_caps.get("geneve_offload", False),
                                    "vxlan_offload": oem_caps.get("vxlan_offload", False),
                                    "rocev2": oem_caps.get("rocev2", False),
                                    "multiqueue": oem_caps.get("multiqueue", False),
                                    "tso_enabled": oem_caps.get("tso_enabled", False),
                                    "lro_enabled": oem_caps.get("lro_enabled", False),
                                    "rx_csum": oem_caps.get("rx_csum", False),
                                    "tx_csum": oem_caps.get("tx_csum", False),
                                    "rss_enabled": oem_caps.get("rss_enabled", False),
                                    "wwnn": wwnn,
                                    "wwpn": wwpn,
                                    "cos": oem_caps.get("cos"),
                                    "pci_order": oem_caps.get("pci_order", ""),
                                    "vhba_type": oem_caps.get("vhba_type", []),
                                })
                    if is_vic:
                        is_npar = False
                        is_vic_virtual = bool(npar_partitions)
                    else:
                        is_npar = _evaluate_npar_partitions(npar_partitions, len(dynamic_ports), is_vic=is_vic)
                        is_vic_virtual = False

                    # Skip BMC virtual management NICs — generic name + no port data
                    if resolved_name.lower() in GENERIC_NAME_BLOCKLIST and not dynamic_ports:
                        continue

                    # Firmware version: standard field first, then OEM hook fallbacks
                    fw_version = self.oem_nic_firmware(adapter)

                    adapter["resolved_name"] = resolved_name
                    pci_info = extract_pci_ids_from_dict(adapter, get_fn=self._get)
                    if not pci_info["pci_quad"] and pcie_cache:
                        pci_info = match_pcie_cache(adapter, pcie_cache, get_fn=self._get)
                    if not pci_info["pci_quad"]:
                        pci_info = match_firmware_inventory_pci(str(resolved_name or adapter.get("Name") or ""), get_fn=self._get)

                    # Suppress orphaned generic EthernetInterfaces when physical NICs are already present
                    is_generic_or_partition = (
                        resolved_name.lower() in GENERIC_NAME_BLOCKLIST
                        or bool(re.search(r"\b(?:Partition\s+\d+|Embedded NIC\s+\d+\s+Port\s+\d+)\b", resolved_name, re.IGNORECASE))
                    )
                    if (is_eth_iface_ep
                            and is_generic_or_partition
                            and manufacturer in ("Unknown", "N/A", "")
                            and part_number in ("N/A", "Unknown", "")
                            and not pci_info["pci_quad"]
                            and any(n.get("pci_quad") or n.get("manufacturer") not in ("Unknown", "") for n in nic_list)):
                        logger.debug("Suppressing orphaned generic EthernetInterface %s (%s)", uid, resolved_name)
                        continue

                    link_info = extract_pcie_link_status(adapter)
                    if not link_info.get("max_gen") and not link_info.get("max_lanes"):
                        if hasattr(self, "oem_pcie_link_status"):
                            oem_link = self.oem_pcie_link_status(adapter)
                            if oem_link:
                                for k, v in oem_link.items():
                                    if v is not None:
                                        link_info[k] = v

                    # If link status is missing width or type, inherit from parent/matching PCIeDevice in pcie_cache
                    if (link_info.get("current_pcie_width") is None or link_info.get("current_pcie_type") is None) and pcie_cache:
                        pdev_match = _find_parent_pcie_device(uid, adapter_uri, pcie_cache)
                        if pdev_match:
                            p_dev, _ = pdev_match
                            p_raw = p_dev.get("_raw") if isinstance(p_dev.get("_raw"), dict) else p_dev
                            p_link = extract_pcie_link_status(p_raw)
                            for k in (
                                "current_pcie_type", "max_pcie_type",
                                "current_pcie_width", "max_pcie_width",
                                "downgraded", "badge", "reason",
                                "max_gen", "negotiated_gen", "max_lanes", "negotiated_lanes",
                            ):
                                if p_link.get(k) is not None and link_info.get(k) is None:
                                    link_info[k] = p_link[k]

                    logger.debug(
                        f"NIC '{resolved_name}' ({uid}): PCI IDs -> VID='{pci_info['vendor_id']}', "
                        f"DID='{pci_info['device_id']}', SVID='{pci_info['subsystem_vendor_id']}', "
                        f"SSID='{pci_info['subsystem_id']}' (quad='{pci_info['pci_quad']}')"
                    )

                    adapter_max_speed = max((p.get("current_speed_gbps") or 0 for p in dynamic_ports), default=0)
                    adapter_speed = adapter_max_speed if adapter_max_speed > 0 else None
                    mfg_resolved = infer_nic_manufacturer(manufacturer, pci_info, resolved_name)

                    # Safeguard: do not add pure Fibre Channel HBAs to Ethernet nic_list
                    if not cna_info["is_cna"] and (
                        bool(re.search(r"\bFC\.", str(uid)))
                        or (dynamic_ports and all(str(p.get("port_id", "")).startswith("FC.") for p in dynamic_ports))
                    ):
                        logger.debug("Skipping pure Fibre Channel adapter %s from network_adapters list", uid)
                        continue

                    nic_list.append({
                        "id": uid,
                        "name": resolved_name,
                        "manufacturer": mfg_resolved,
                        "part_number": part_number,
                        "firmware_version": str(fw_version).strip() or "N/A",
                        "ports": dynamic_ports,
                        "speed_gbps": adapter_speed,
                        "vendor_id": pci_info["vendor_id"],
                        "device_id": pci_info["device_id"],
                        "subsystem_vendor_id": pci_info["subsystem_vendor_id"],
                        "subsystem_id": pci_info["subsystem_id"],
                        "pci_quad": pci_info["pci_quad"],
                        "pci_pair": pci_info["pci_pair"],
                        "current_pcie_type": link_info.get("current_pcie_type"),
                        "max_pcie_type": link_info.get("max_pcie_type"),
                        "current_pcie_width": link_info.get("current_pcie_width"),
                        "max_pcie_width": link_info.get("max_pcie_width"),
                        "downgraded": link_info["downgraded"],
                        "downgrade_reason": link_info["reason"],
                        "downgrade_badge": link_info["badge"],
                        "is_cna": cna_info["is_cna"],
                        "cna_family": cna_info["cna_family"],
                        "cna_family_label": cna_info["family_label"],
                        "cna_eth_driver": cna_info["eth_driver"],
                        "cna_fc_driver": cna_info["fc_driver"],
                        "cna_eth_bcg_url": "",
                        "cna_fc_bcg_url": "",
                        "is_npar": is_npar,
                        "npar_partitions": npar_partitions,
                        "is_vic_virtual": is_vic_virtual,
                        "vic_virtual_interfaces": npar_partitions if is_vic else [],
                    })
                except Exception as m_exc:
                    logger.debug("Error processing network adapter member %s: %s", member, m_exc)

        # Clean up npar_partitions on unpartitioned adapters so native NICs don't retain partition artifacts
        for nic in nic_list:
            nic_parts = nic.get("npar_partitions")
            nic_parts_list = nic_parts if isinstance(nic_parts, list) else []
            nic_ports = nic.get("ports")
            nic_ports_len = len(nic_ports) if isinstance(nic_ports, (list, tuple)) else 0
            if nic.get("is_vic_virtual") or nic.get("cna_family") == "cisco_vic" or "VIC" in str(nic.get("name", "")).upper():
                nic["is_npar"] = False
                nic["is_vic_virtual"] = bool(nic_parts_list)
                nic["vic_virtual_interfaces"] = nic_parts_list
            else:
                nic["is_npar"] = _evaluate_npar_partitions(nic_parts_list, nic_ports_len)
                if not nic["is_npar"]:
                    nic["npar_partitions"] = []
            if isinstance(nic.get("ports"), list):
                nic["ports"].sort(key=lambda p: str(p.get("port_id") or ""))

        # Surface a license-blocked sentinel so the HTML renderer can show a
        # specific warning instead of the generic "no NICs discovered" message.
        if license_blocked_note and not nic_list:
            nic_list.append({
                "id": "_license_blocked",
                "name": f"⚠️ Network API Unavailable — {license_blocked_note}",
                "_license_blocked": True,
                "manufacturer": "",
                "part_number": "",
                "firmware_version": "N/A",
                "ports": [],
            })
        return nic_list


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

        seen_wwpns: set = set()

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

                resolved_hba_name = (
                    model_str if (raw_name.lower() in GENERIC_NAME_BLOCKLIST or not raw_name) and model_str
                    else (raw_name or model_str or adapter_id or "FC HBA")
                )

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
                        port.get("WWN")
                        or port.get("WWPN")
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
                            "adapter_name":      resolved_hba_name,
                            "manufacturer":      adapter.get("Manufacturer", "Unknown"),
                            "firmware_version":  adapter_fw,
                            "vendor_class":      vendor_class,
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
                    fn_wwpn = str(fc.get("WWPN") or "").strip()
                    fn_wwnn = str(fc.get("WWN") or "").strip()
                    if not _is_valid_wwpn(fn_wwpn):
                        continue
                    boot_targets = []
                    for bt in (fc.get("BootTargets") or []):
                        t_wwpn = str(bt.get("WWPN") or bt.get("TargetWWPN") or "").strip()
                        if not t_wwpn:
                            continue
                        arr_info = lookup_storage_array_vendor(t_wwpn)
                        boot_targets.append({
                            "target_wwpn": t_wwpn,
                            "lun": str(bt.get("LUN") or bt.get("BootLUN") or "0").strip(),
                            "priority": int(bt.get("BootPriority", 0) or 0),
                            "target_array_vendor": arr_info["vendor"],
                            "target_array_family": arr_info["family"],
                        })

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
                            pe["wwnn"] = fn_wwnn
                            pe["boot_targets"] = boot_targets
                            matched = True
                            break
                    if not matched and (fn_wwpn or fn_wwnn):
                        port_entries.append({
                            "adapter_name":      resolved_hba_name,
                            "manufacturer":      adapter.get("Manufacturer", "Unknown"),
                            "firmware_version":  adapter_fw,
                            "vendor_class":      vendor_class,
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

                for entry in port_entries:
                    w = entry.get("wwpn", "")
                    if _is_valid_wwpn(w):
                        if w not in seen_wwpns:
                            seen_wwpns.add(w)
                            hbas.append(entry)
                    elif entry.get("adapter_name"):
                        ad_key = f"{entry.get('adapter_name')}_{entry.get('port_id')}"
                        if ad_key not in seen_wwpns:
                            seen_wwpns.add(ad_key)
                            hbas.append(entry)

        return hbas


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

