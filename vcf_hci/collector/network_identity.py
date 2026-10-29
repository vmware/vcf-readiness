"""Pure network identity and parent/partition matching over observed evidence."""
import re
from typing import Any, Optional, Tuple

from vcf_hci.collector.pci_utils import normalize_pci_id
from vcf_hci.constants import normalize_component_manufacturer


def _clean_mac_address(mac_val: Any) -> str:
    s = str(mac_val or "").strip()
    if not s or s.upper() in ("N/A", "NONE", "UNKNOWN", "NULL", "00:00:00:00:00:00", "00-00-00-00-00-00", "0000.0000.0000"):
        return ""
    return s


def classify_cna_adapter(name: str, manufacturer: str = "", model: str = "", part_number: str = "", net_dev_funcs: Optional[list] = None, adapter_id: str = "") -> dict:
    """Detect if an adapter is a Converged Network Adapter (CNA) and classify its dual personas.

    Covers Cisco VIC (1200/1300/1400/1500), HPE FlexFabric (580/620/630/650),
    Marvell FastLinQ / QLogic 57810S/57840S, and Emulex OneConnect.
    """
    s_comb = f"{name} {manufacturer} {model} {part_number} {adapter_id}".strip()

    # 1. Cisco VIC
    vic_match = re.search(r"\bVIC[-\s]?(\d{4,5}[A-Za-z0-9\-]*)", s_comb, re.I)
    mlom_blade_match = re.search(r"\bUCS[BX]-(?:MLOM|VIC|V[45]|MEZZ)[-\s]?([A-Za-z0-9\-]+)", s_comb, re.I)
    is_cisco_vic = (
        bool(vic_match)
        or bool(mlom_blade_match)
        or "73-19235" in s_comb
        or "73-16181" in s_comb
        or "73-18341" in s_comb
        or "73-14986" in s_comb
        or "cisco virtual interface card" in s_comb.lower()
        or ("cisco" in s_comb.lower() and "vic" in s_comb.lower())
        or ("cisco" in s_comb.lower() and any(f.get("Oem", {}).get("Cisco") for f in (net_dev_funcs or [])))
    )
    if is_cisco_vic:
        vic_num = vic_match.group(1) if vic_match else ""
        if not vic_num:
            if "73-19235" in s_comb or "73-16181" in s_comb or re.search(r"\bUCSB-MLOM-40G-0[34]\b", s_comb, re.I):
                vic_num = "1340"
            elif "73-18341" in s_comb or re.search(r"\bUCSB-MLOM-100G\b", s_comb, re.I):
                vic_num = "1440"
            elif "73-14986" in s_comb or re.search(r"\bUCSB-MLOM-40G-01\b", s_comb, re.I):
                vic_num = "1240"
            elif re.search(r"\bUCSX-V4-Q25G\b", s_comb, re.I):
                vic_num = "14425"
            elif re.search(r"\bUCSX-V5-Q50G\b", s_comb, re.I):
                vic_num = "15428"
            elif mlom_blade_match:
                vic_num = mlom_blade_match.group(1)
        return {
            "is_cna": True,
            "is_vic": True,
            "cna_family": "cisco_vic",
            "family_label": f"Cisco VIC {vic_num}".strip() if vic_num else "Cisco Virtual Interface Card",
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


def infer_nic_manufacturer(raw_mfg: str, pci_info: Optional[dict] = None, adapter_name: str = "") -> str:
    """Infer manufacturer when BMC returns 'Unknown', empty, or unhelpful string."""
    mfg = str(raw_mfg or "").strip()
    pci = pci_info or {}
    vid = normalize_pci_id(pci.get("vendor_id", ""))
    svid = normalize_pci_id(pci.get("subsystem_vendor_id", ""))
    name = str(adapter_name or "").strip()
    name_lower = name.lower()

    # If OEM system integrator brand is reported (e.g. LNV/Lenovo/Dell/HPE), check if adapter is third-party silicon
    is_oem_label = mfg.lower() in ("unknown", "n/a", "none", "", "null", "lnv", "lnvo", "lenovo")
    if not is_oem_label and mfg.lower() in ("dell", "hpe", "cisco", "supermicro"):
        if vid in ("15b3", "14e4", "8086", "1077", "10df", "1924") or any(
            kw in name_lower for kw in ("mellanox", "connectx", "broadcom", "netxtreme", "intel", "qlogic", "fastlinq", "solarflare")
        ):
            is_oem_label = True

    if not is_oem_label and mfg:
        return normalize_component_manufacturer(mfg)

    # 1. Check adapter name prefix/keywords
    if name_lower.startswith("mellanox ") or "mellanox" in name_lower or "connectx" in name_lower:
        return "Mellanox"
    if name_lower.startswith("broadcom ") or "broadcom" in name_lower or "netxtreme" in name_lower:
        return "Broadcom"
    if name_lower.startswith("intel ") or "intel" in name_lower:
        return "Intel"
    if name_lower.startswith("qlogic ") or "qlogic" in name_lower or "fastlinq" in name_lower:
        return "QLogic / Marvell" if "marvell" not in name_lower else "Marvell"
    if name_lower.startswith("marvell ") or "marvell" in name_lower:
        return "Marvell"
    if name_lower.startswith("emulex ") or "emulex" in name_lower:
        return "Emulex"
    if name_lower.startswith("solarflare ") or "solarflare" in name_lower or "xilinx" in name_lower:
        return "Solarflare"
    if name_lower.startswith("hpe ") or "hewlett packard" in name_lower:
        return "HPE"
    if name_lower.startswith("dell ") or "poweredge" in name_lower:
        return "Dell"
    if name_lower.startswith("cisco ") or "cisco" in name_lower:
        return "Cisco"

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
                or "UCSB-M" in p_id_raw
                or p_nic.get("cna_family") == "cisco_vic"
                or "VIC" in p_name_raw
            )
            if is_mlom_adapter:
                uid_u = uid.upper()
                if uid_u.startswith(("MLOM.", "MLOM-", "UCSB-MLOM", "UCSC-MLOM", "UCSB-VIC", "UCSC-VIC", "UCSX-MLOM", "UCSX-VIC", "UCSX-V4", "UCSX-V5", "UCSX-MEZZ")):
                    return p_id
                for sep in ("_", "-", "."):
                    if p_id_raw.startswith(uid_u + sep) or uid_u.startswith(p_id_raw + sep):
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
