"""
VCF Readiness Tool — PCI ID extraction, normalization, and caching helpers.
"""
import re
from typing import Any, Callable, Optional, Union

from vcf_hci.logging_utils import get_nested


def normalize_pci_id(hex_str: Optional[str]) -> str:
    """Normalize PCI hex strings (VendorId, DeviceId, SubsystemVendorId, SubsystemId).

    Strips 0x/0X prefix, whitespace, zero-pads to 4 lowercase hex digits.
    Validates input against standard PCI notation patterns to avoid false matches.
    Returns "" if None or invalid.
    Examples:
      "0x15B3" -> "15b3"
      "VEN_15B3" -> "15b3"
      "16"     -> "0016"
      "0016"   -> "0016"
      "0"      -> "0000"
      "" / None -> ""
    """
    if hex_str is None:
        return ""
    s = str(hex_str).strip()
    if not s or s.upper() in ("N/A", "NONE", "UNKNOWN", "0X0", "0X0000"):
        return ""

    pci_pattern = re.compile(r'^(?:pci\\|0x|ven_|dev_|subsys_)*([0-9a-fA-F]{1,4})$', re.IGNORECASE)
    match = pci_pattern.fullmatch(s)
    if match:
        try:
            val = int(match.group(1), 16)
            if 0 <= val <= 0xFFFF:
                return f"{val:04x}"
        except ValueError:
            pass

    s_clean = s.lower().strip()
    if s_clean.startswith("0x"):
        s_clean = s_clean[2:]
    try:
        val = int(s_clean, 16)
        if 0 <= val <= 0xFFFF:
            return f"{val:04x}"
    except ValueError:
        pass

    return ""


_VID_KEYS = ("VendorId", "VendorID", "PCIeVendorId", "PCIeVendorID", "PCIeVendor", "PCIVendorId", "PCIVendorID")
_DID_KEYS = ("DeviceId", "DeviceID", "PCIeDeviceId", "PCIeDeviceID", "PCIeDevice", "PCIDeviceId", "PCIDeviceID")
_SVID_KEYS = (
    "SubsystemVendorId", "SubsystemVendorID", "PCIeSubsystemVendorId", "PCIeSubsystemVendorID",
    "SubVendorId", "SubVendorID", "PCIeSubVendorId", "PCIeSubVendorID", "PCISubVendorId", "PCISubVendorID", "SVID"
)
_SSID_KEYS = (
    "SubsystemId", "SubsystemID", "PCIeSubsystemId", "PCIeSubsystemID",
    "PCIeSubsystemDeviceId", "PCIeSubsystemDeviceID",
    "SubDeviceId", "SubDeviceID", "PCIeSubDeviceId", "PCIeSubDeviceID", "PCISubDeviceId", "PCISubDeviceID", "SSID"
)


def _get_val(d: dict, keys: tuple) -> str:
    if not isinstance(d, dict):
        return ""
    for k in keys:
        if k in d and d[k] is not None:
            val = normalize_pci_id(d[k])
            if val:
                return val
    return ""


def extract_pci_ids_from_dict(dev: dict, get_fn: Optional[Callable] = None) -> dict:
    """Extract VendorId, DeviceId, SubsystemVendorId, SubsystemId from a Redfish resource dict.

    Checks top-level fields, PCIeInterface, Controllers array, Oem nests,
    linked PCIeDevice resources, and linked PCIeFunctions (filtering out SR-IOV VFs).
    Supports all standard and OEM field variations (VendorId, PCIeVendorID, SubsystemVendorId, etc.).
    """
    if not isinstance(dev, dict):
        return {
            "vendor_id": "",
            "device_id": "",
            "subsystem_vendor_id": "",
            "subsystem_id": "",
            "pci_quad": "",
            "pci_pair": "",
        }

    vid = _get_val(dev, _VID_KEYS)
    did = _get_val(dev, _DID_KEYS)
    svid = _get_val(dev, _SVID_KEYS)
    ssid = _get_val(dev, _SSID_KEYS)

    # PCIeInterface block
    pcie_if = dev.get("PCIeInterface")
    if isinstance(pcie_if, dict):
        if not vid:
            vid = _get_val(pcie_if, _VID_KEYS)
        if not did:
            did = _get_val(pcie_if, _DID_KEYS)
        if not svid:
            svid = _get_val(pcie_if, _SVID_KEYS)
        if not ssid:
            ssid = _get_val(pcie_if, _SSID_KEYS)

    # Controllers array (DMTF Redfish NetworkAdapter / Storage standard schema)
    controllers = dev.get("Controllers") or []
    if isinstance(controllers, dict):
        controllers = [controllers]
    if isinstance(controllers, list) and controllers:
        for ctrl in controllers:
            if isinstance(ctrl, dict):
                c_vid = _get_val(ctrl, _VID_KEYS)
                c_did = _get_val(ctrl, _DID_KEYS)
                c_svid = _get_val(ctrl, _SVID_KEYS)
                c_ssid = _get_val(ctrl, _SSID_KEYS)
                c_if = ctrl.get("PCIeInterface")
                if isinstance(c_if, dict):
                    if not c_vid:
                        c_vid = _get_val(c_if, _VID_KEYS)
                    if not c_did:
                        c_did = _get_val(c_if, _DID_KEYS)
                    if not c_svid:
                        c_svid = _get_val(c_if, _SVID_KEYS)
                    if not c_ssid:
                        c_ssid = _get_val(c_if, _SSID_KEYS)
                ctrl_pci = extract_pci_ids_from_dict(ctrl, get_fn) if not (c_vid and c_did and c_svid and c_ssid) else {
                    "vendor_id": c_vid, "device_id": c_did, "subsystem_vendor_id": c_svid, "subsystem_id": c_ssid
                }
                if not vid and ctrl_pci["vendor_id"]:
                    vid = ctrl_pci["vendor_id"]
                if not did and ctrl_pci["device_id"]:
                    did = ctrl_pci["device_id"]
                if not svid and ctrl_pci["subsystem_vendor_id"]:
                    svid = ctrl_pci["subsystem_vendor_id"]
                if not ssid and ctrl_pci["subsystem_id"]:
                    ssid = ctrl_pci["subsystem_id"]

    # Walk Oem nests if any ID is missing
    if not (vid and did and svid and ssid) and "Oem" in dev and isinstance(dev["Oem"], dict):
        for oem_vendor, oem_data in dev["Oem"].items():
            if isinstance(oem_data, dict):
                for key, val in oem_data.items():
                    if isinstance(val, dict):
                        if not vid:
                            vid = _get_val(val, _VID_KEYS)
                        if not did:
                            did = _get_val(val, _DID_KEYS)
                        if not svid:
                            svid = _get_val(val, _SVID_KEYS)
                        if not ssid:
                            ssid = _get_val(val, _SSID_KEYS)
                if not vid:
                    vid = _get_val(oem_data, _VID_KEYS)
                if not did:
                    did = _get_val(oem_data, _DID_KEYS)
                if not svid:
                    svid = _get_val(oem_data, _SVID_KEYS)
                if not ssid:
                    ssid = _get_val(oem_data, _SSID_KEYS)

    # Linked PCIeDevice check if any ID missing
    if not (vid and did and svid and ssid):
        pcie_refs = (
            dev.get("PCIeDevice") or dev.get("PCIeDevices")
            or (dev.get("Links") or {}).get("PCIeDevice")
            or (dev.get("Links") or {}).get("PCIeDevices")
        )
        if isinstance(pcie_refs, dict):
            pcie_refs = [pcie_refs]
        if isinstance(pcie_refs, list) and pcie_refs:
            for p_ref in pcie_refs:
                if isinstance(p_ref, dict):
                    p_uri = p_ref.get("@odata.id")
                    if p_uri and callable(get_fn) and not (_get_val(p_ref, _VID_KEYS) or _get_val(p_ref, _DID_KEYS)):
                        p_data = get_fn(p_uri)
                    else:
                        p_data = p_ref
                    if isinstance(p_data, dict):
                        p_pci = extract_pci_ids_from_dict(p_data, get_fn)
                        if not vid and p_pci["vendor_id"]:
                            vid = p_pci["vendor_id"]
                        if not did and p_pci["device_id"]:
                            did = p_pci["device_id"]
                        if not svid and p_pci["subsystem_vendor_id"]:
                            svid = p_pci["subsystem_vendor_id"]
                        if not ssid and p_pci["subsystem_id"]:
                            ssid = p_pci["subsystem_id"]

    # Walk PCIeFunctions if SVID/SSID or VID/DID missing
    if not (vid and did and svid and ssid):
        raw_funcs = []
        for src in (dev.get("PCIeFunctions"), (dev.get("Links") or {}).get("PCIeFunctions")):
            if isinstance(src, list):
                raw_funcs.extend(src)
            elif isinstance(src, dict):
                raw_funcs.append(src)

        expanded_funcs = []
        for f_item in raw_funcs:
            if not isinstance(f_item, dict):
                continue
            f_uri = str(f_item.get("@odata.id") or "").strip()
            if f_uri and f_uri.lower() in ("/empty", "empty", "none", "null", "n/a", "/"):
                continue
            if f_uri and callable(get_fn) and not (vid and did) and (f_uri.endswith("/PCIeFunctions") or "Collection" in str(f_item.get("@odata.type", ""))):
                f_coll = get_fn(f_uri) or {}
                m_list = f_coll.get("Members") or (f_coll.get("Links") or {}).get("PCIeFunctions") or []
                if isinstance(m_list, list):
                    for m in m_list:
                        if isinstance(m, dict):
                            m_uri = str(m.get("@odata.id") or "").strip()
                            if m_uri and m_uri.lower() not in ("/empty", "empty", "none", "null", "n/a", "/"):
                                expanded_funcs.append(m)
            else:
                expanded_funcs.append(f_item)

        for f_ref in expanded_funcs:
            f_data = None
            if isinstance(f_ref, dict):
                f_uri = str(f_ref.get("@odata.id") or "").strip()
                if f_uri and f_uri.lower() in ("/empty", "empty", "none", "null", "n/a", "/"):
                    continue
                if f_uri and callable(get_fn) and not (vid and did) and not (_get_val(f_ref, _VID_KEYS) or _get_val(f_ref, _DID_KEYS)):
                    f_data = get_fn(f_uri)
                else:
                    f_data = f_ref
            if isinstance(f_data, dict):
                if "Members" in f_data and isinstance(f_data["Members"], list):
                    for sm in f_data["Members"]:
                        sm_data = get_fn(sm.get("@odata.id")) if (isinstance(sm, dict) and sm.get("@odata.id") and callable(get_fn)) else sm
                        if isinstance(sm_data, dict):
                            f_type = str(sm_data.get("FunctionType") or "").upper()
                            if "VIRTUAL" in f_type or "VF" in f_type:
                                continue
                            f_vid = _get_val(sm_data, _VID_KEYS)
                            f_did = _get_val(sm_data, _DID_KEYS)
                            f_svid = _get_val(sm_data, _SVID_KEYS)
                            f_ssid = _get_val(sm_data, _SSID_KEYS)
                            if not vid and f_vid:
                                vid = f_vid
                            if not did and f_did:
                                did = f_did
                            if not svid and f_svid:
                                svid = f_svid
                            if not ssid and f_ssid:
                                ssid = f_ssid
                    continue

                f_type = str(f_data.get("FunctionType") or "").upper()
                if "VIRTUAL" in f_type or "VF" in f_type:
                    continue  # Filter SR-IOV VFs
                f_vid = _get_val(f_data, _VID_KEYS)
                f_did = _get_val(f_data, _DID_KEYS)
                f_svid = _get_val(f_data, _SVID_KEYS)
                f_ssid = _get_val(f_data, _SSID_KEYS)
                if not vid and f_vid:
                    vid = f_vid
                if not did and f_did:
                    did = f_did
                if not svid and f_svid:
                    svid = f_svid
                if not ssid and f_ssid:
                    ssid = f_ssid
                if vid and did:
                    break

    # Walk NetworkDeviceFunctions if VID/DID missing
    if not (vid and did):
        ndf_refs = dev.get("NetworkDeviceFunctions") or (dev.get("Links") or {}).get("NetworkDeviceFunctions") or []
        if isinstance(ndf_refs, dict):
            if isinstance(ndf_refs.get("Members"), list):
                ndf_refs = ndf_refs.get("Members", [])
            elif ndf_refs.get("@odata.id") and callable(get_fn):
                ndf_coll = get_fn(ndf_refs["@odata.id"]) or {}
                members = ndf_coll.get("Members") or []
                ndf_refs = members if isinstance(members, list) else []
            else:
                ndf_refs = [ndf_refs]
        if isinstance(ndf_refs, list) and ndf_refs:
            for ndf_ref in ndf_refs:
                ndf_data = None
                if isinstance(ndf_ref, dict):
                    if len(ndf_ref) > 2:
                        ndf_data = ndf_ref
                    elif ndf_ref.get("@odata.id") and callable(get_fn):
                        ndf_data = get_fn(ndf_ref["@odata.id"])
                    else:
                        ndf_data = ndf_ref
                if isinstance(ndf_data, dict):
                    ndf_pci = extract_pci_ids_from_dict(ndf_data, get_fn)
                    if not vid and ndf_pci["vendor_id"]:
                        vid = ndf_pci["vendor_id"]
                    if not did and ndf_pci["device_id"]:
                        did = ndf_pci["device_id"]
                    if not svid and ndf_pci["subsystem_vendor_id"]:
                        svid = ndf_pci["subsystem_vendor_id"]
                    if not ssid and ndf_pci["subsystem_id"]:
                        ssid = ndf_pci["subsystem_id"]
                    if vid and did:
                        break

    # Walk NetworkPorts if VID/DID missing
    if not (vid and did):
        np_refs = dev.get("NetworkPorts") or (dev.get("Links") or {}).get("NetworkPorts") or []
        if isinstance(np_refs, dict):
            if isinstance(np_refs.get("Members"), list):
                np_refs = np_refs.get("Members", [])
            elif np_refs.get("@odata.id") and callable(get_fn):
                np_coll = get_fn(np_refs["@odata.id"]) or {}
                members = np_coll.get("Members") or []
                np_refs = members if isinstance(members, list) else []
            else:
                np_refs = [np_refs]
        if isinstance(np_refs, list) and np_refs:
            for np_ref in np_refs:
                np_data = None
                if isinstance(np_ref, dict):
                    if len(np_ref) > 2:
                        np_data = np_ref
                    elif np_ref.get("@odata.id") and callable(get_fn):
                        np_data = get_fn(np_ref["@odata.id"])
                    else:
                        np_data = np_ref
                if isinstance(np_data, dict):
                    np_pci = extract_pci_ids_from_dict(np_data, get_fn)
                    if not vid and np_pci["vendor_id"]:
                        vid = np_pci["vendor_id"]
                    if not did and np_pci["device_id"]:
                        did = np_pci["device_id"]
                    if not svid and np_pci["subsystem_vendor_id"]:
                        svid = np_pci["subsystem_vendor_id"]
                    if not ssid and np_pci["subsystem_id"]:
                        ssid = np_pci["subsystem_id"]
                    if vid and did:
                        break

    # Check Redfish Identifiers (common on NVMe drives where standard PCIeFunctions are not exposed)
    # e.g. DurableName: "1179010E41303150545A354400000000" (VID: 1179 Toshiba, DID: 010e PX04P)
    # or "144DA8044E58304A3530303136390000" (VID: 144d Samsung, DID: a804 PM963/PM983)
    if not (vid and did):
        idents = dev.get("Identifiers") or []
        if isinstance(idents, dict):
            idents = [idents]
        if isinstance(idents, list):
            for ident in idents:
                if isinstance(ident, dict):
                    d_name = str(ident.get("DurableName") or "").strip().upper()
                    if d_name.startswith("0X"):
                        d_name = d_name[2:]
                    if len(d_name) == 32 and d_name.startswith("0000000000000000"):
                        d_name = d_name[16:]
                    if len(d_name) >= 8 and re.match(r"^[0-9A-F]{8}", d_name):
                        cand_vid = d_name[:4].lower()
                        cand_did = d_name[4:8].lower()
                        _KNOWN_NVME_VIDS = {
                            "1179", "144d", "1344", "8086", "15b7",
                            "1c5c", "1e0f", "1d9b", "1014", "1000",
                        }
                        if cand_vid in _KNOWN_NVME_VIDS:
                            if not vid:
                                vid = cand_vid
                            if not did:
                                did = cand_did
                            if vid and did:
                                break

    pci_quad = f"{vid}:{did}:{svid}:{ssid}" if (vid and did and svid and ssid) else ""
    pci_pair = f"{vid}:{did}" if (vid and did) else ""
    return {
        "vendor_id": vid,
        "device_id": did,
        "subsystem_vendor_id": svid,
        "subsystem_id": ssid,
        "pci_quad": pci_quad,
        "pci_pair": pci_pair,
    }


def _normalize_slot_id(s: str) -> str:
    """Normalize slot/location ID strings by stripping vendor/resource prefixes."""
    if not s:
        return ""
    return re.sub(r"^(?:NIC|PCIeDevice|System\.Embedded|System)\.", "", str(s).strip(), flags=re.I).strip().lower()


def _extract_model_token(s: str) -> str:
    """Extract normalized core hardware model token for PCIe cache matching."""
    if not s:
        return ""
    # Mellanox/NVIDIA ConnectX: ConnectX4LX, ConnectX-4, ConnectX4, ConnectX5, ConnectX-5, ConnectX6, ConnectX-6, ConnectX7, etc.
    m = re.search(r"\bConnectX[-\s]?(\d+)\s*([A-Za-z]+)?\b", s, re.I)
    if m:
        num = m.group(1)
        raw_sfx = (m.group(2) or "").upper()
        sfx = {"LX": "lx", "DX": "dx", "EX": "ex", "VX": "vx"}.get(raw_sfx, "")
        return f"connectx-{num}{('-' + sfx) if sfx else ''}"
    # Intel: E810, XXV710, XL710, X710, X550, X540, X520, I350, I210, X722
    m = re.search(r"\b(E\d{3,4}|XXV\d{3,4}|XL\d{3,4}|X\d{3,4}|I\d{3,4})\b", s, re.I)
    if m:
        return m.group(1).lower()
    # Broadcom: BCM57xxx or 57xxx
    m = re.search(r"\b(BCM\d{4,6}|57\d{3})\b", s, re.I)
    if m:
        val = m.group(1).lower()
        return val if val.startswith("bcm") else f"bcm{val}"
    # QLogic / Marvell: QL41xxx, QLE2xxx
    m = re.search(r"\b(QL\d{4,6}|QLE?\d{4,6})\b", s, re.I)
    if m:
        return m.group(1).lower()
    return ""


def _is_internal_host_bridge(dev_dict: dict) -> bool:
    """Check if a PCIeDevice is an internal CPU/chipset bridge or root complex that does not host drives."""
    if not isinstance(dev_dict, dict):
        return False
    raw_val = dev_dict.get("_raw")
    raw = raw_val if isinstance(raw_val, dict) else dev_dict
    name = str(raw.get("Name") or dev_dict.get("name") or "").upper()
    model = str(raw.get("Model") or dev_dict.get("model") or "").upper()
    desc = str(raw.get("Description") or dev_dict.get("description") or "").upper()
    combined = f"{name} {model} {desc}"

    bridge_keywords = (
        "DUMMY HOST BRIDGE",
        "ROOT COMPLEX",
        "ROOT PORT",
        "SMBUS CONTROLLER",
        "HOST BRIDGE",
        "GPP BRIDGE",
        "PCI EXPRESS ROOT",
        "PCI PORT",
    )
    return any(kw in combined for kw in bridge_keywords)


def _is_non_storage_pcie_dev(pcie_dev: dict) -> bool:
    """Check if a PCIeDevice is definitely not a storage device (e.g. NIC, GPU, Bridge, USB)."""
    if not isinstance(pcie_dev, dict):
        return True
    if _is_internal_host_bridge(pcie_dev):
        return True
    raw_val = pcie_dev.get("_raw")
    raw = raw_val if isinstance(raw_val, dict) else pcie_dev
    dev_class = str(
        pcie_dev.get("device_class")
        or raw.get("DeviceClass")
        or (raw.get("PCIeInterface") or {}).get("DeviceClass")
        or ""
    ).upper()
    if dev_class and any(dc in dev_class for dc in (
        "NETWORK", "ETHERNET", "DISPLAY", "GRAPHICS", "VIDEO", "AUDIO", "COMMUNICATION", "BRIDGE"
    )):
        return True

    name = str(raw.get("Name") or pcie_dev.get("name") or "").upper()
    model = str(raw.get("Model") or pcie_dev.get("model") or "").upper()
    desc = str(raw.get("Description") or pcie_dev.get("description") or "").upper()
    combined = f"{name} {model} {desc}"

    non_storage_keywords = (
        "ETHERNET",
        "NETWORK CONTROLLER",
        "GIGABIT",
        "FAST ETHERNET",
        "MELLANOX",
        "CONNECTX",
        "BROADCOM NETXTREME",
        "INTEL ETHERNET",
        "SOLARFLARE",
        "GRAPHICS",
        "MATROX",
        "NVIDIA",
        "RADEON",
        "VGA",
        "USB CONTROLLER",
        "XHCI",
        "EHCI",
        "AUDIO CONTROLLER",
        "SERIAL CONTROLLER",
        "LPC INTERFACE",
        "ISA BRIDGE",
        "MANAGEMENT CONTROLLER",
    )
    return any(kw in combined for kw in non_storage_keywords)


def _is_drive_or_storage_dev(d: dict) -> bool:
    """Check if a device dictionary represents a drive or storage component."""
    if not isinstance(d, dict):
        return False
    dev_type = str(d.get("@odata.type") or "").lower()
    dev_uri = str(d.get("@odata.id") or "").lower()
    dev_id = str(d.get("id") or d.get("Id") or "").lower()
    if "drive" in dev_type or "storage" in dev_type or "volume" in dev_type:
        return True
    if "/drives/" in dev_uri or "/storage/" in dev_uri or "/volumes/" in dev_uri:
        return True
    if dev_id.startswith(("disk.", "drive.", "harddisk.", "raid.", "nonraid.")):
        return True
    return any(k in d for k in ("media_type", "protocol", "drive_json", "storage_controller"))


def build_pcie_cache_index(pcie_cache: Union[list, dict]) -> dict:
    """Build or return an O(1) lookup index dictionary from pcie_cache."""
    if isinstance(pcie_cache, dict) and "raw_cache" in pcie_cache:
        return pcie_cache

    cache_list = pcie_cache if isinstance(pcie_cache, list) else []
    index = {
        "by_vid_did": {},        # "vid:did" -> list[pcie_dev]
        "by_part_number": {},    # "part_number" -> pcie_dev
        "by_id": {},             # "id" -> pcie_dev
        "by_clean_id": {},       # "clean_id" -> pcie_dev
        "by_model_token": {},    # "model_token" -> pcie_dev
        "by_uri": {},            # "@odata.id" -> pcie_dev
        "raw_cache": cache_list,
    }

    for pcie_dev in cache_list:
        if not isinstance(pcie_dev, dict):
            continue

        p_uri = str(pcie_dev.get("uri") or (pcie_dev.get("_raw") or {}).get("@odata.id") or "").strip().lower()
        if p_uri:
            index["by_uri"][p_uri] = pcie_dev

        p_vid = pcie_dev.get("vendor_id", "")
        p_did = pcie_dev.get("device_id", "")
        if p_vid and p_did:
            pair = f"{p_vid}:{p_did}"
            if pair not in index["by_vid_did"]:
                index["by_vid_did"][pair] = []
            index["by_vid_did"][pair].append(pcie_dev)

        p_pn = str(pcie_dev.get("part_number") or "").strip().upper()
        if p_pn and len(p_pn) >= 4:
            if p_pn not in index["by_part_number"]:
                index["by_part_number"][p_pn] = pcie_dev

        p_id = str(pcie_dev.get("id") or "").strip()
        if p_id:
            index["by_id"][p_id] = pcie_dev
            index["by_id"][p_id.lower()] = pcie_dev
            clean_p_id = _normalize_slot_id(p_id)
            if clean_p_id:
                index["by_clean_id"][clean_p_id] = pcie_dev

        p_raw_name = str(pcie_dev.get("name") or "").strip()
        t = _extract_model_token(p_raw_name)
        if t:
            index["by_model_token"][t] = pcie_dev

    return index


def match_pcie_cache(dev_dict: dict, pcie_cache: Union[list, dict], get_fn: Optional[Callable] = None) -> dict:
    """Find matching PCIe device in pcie_cache or extract PCI IDs from dev_dict directly."""
    if not isinstance(dev_dict, dict):
        return {
            "vendor_id": "",
            "device_id": "",
            "subsystem_vendor_id": "",
            "subsystem_id": "",
            "pci_quad": "",
            "pci_pair": "",
        }

    pci_info = extract_pci_ids_from_dict(dev_dict, get_fn)
    # If we already have the complete 4-part quad, return immediately
    if pci_info["pci_quad"]:
        return pci_info

    if not pcie_cache:
        return pci_info

    index = build_pcie_cache_index(pcie_cache)
    cache_list = index["raw_cache"]
    if not cache_list:
        return pci_info

    pn = str(
        dev_dict.get("part_number") or dev_dict.get("PartNumber") or dev_dict.get("product_id") or ""
    ).strip().upper()
    raw_name = str(
        dev_dict.get("resolved_name") or dev_dict.get("name") or dev_dict.get("Name") or dev_dict.get("Model") or ""
    ).strip()
    name = raw_name.lower()
    dev_id = str(dev_dict.get("id") or dev_dict.get("Id") or "").strip()
    c_vid = pci_info["vendor_id"]
    c_did = pci_info["device_id"]

    _GENERIC_NAMES = {"network adapter", "ethernet network adapter", "pcie device", "unknown", "n/a", ""}

    best_match = None

    # Check direct PCIeDevice links on dev_dict (e.g. Drives or Controllers directly linked to PCIeDevice)
    direct_pcie_links = (dev_dict.get("Links") or {}).get("PCIeDevice") or (dev_dict.get("Links") or {}).get("PCIeDevices") or []
    if isinstance(direct_pcie_links, dict):
        direct_pcie_links = [direct_pcie_links]
    if isinstance(direct_pcie_links, list):
        for plink in direct_pcie_links:
            if isinstance(plink, dict):
                puri = str(plink.get("@odata.id") or "").strip().lower()
                pid = puri.rstrip("/").split("/")[-1] if puri else ""
                match = index.get("by_uri", {}).get(puri) or index.get("by_id", {}).get(pid)
                if match:
                    best_match = match
                    break

    # 0. Drive / Device URI & OEM link matching (for NVMe drives and PCIe controllers ONLY)
    dev_uri = str(dev_dict.get("@odata.id") or "").strip().lower()
    dev_id_raw = str(dev_dict.get("id") or dev_dict.get("Id") or "").strip()
    if not best_match and _is_drive_or_storage_dev(dev_dict) and (dev_id_raw or dev_uri):
        for pcie_dev in cache_list:
            if not isinstance(pcie_dev, dict):
                continue
            # Skip non-storage PCIe devices (Host Bridges, CPU roots, NICs, GPUs, USB, etc.)
            if _is_non_storage_pcie_dev(pcie_dev):
                continue
            raw_dev = pcie_dev.get("_raw")
            if not isinstance(raw_dev, dict):
                continue

            # Check direct Links.Drives, EthernetInterfaces, NetworkDeviceFunctions on PCIeDevice
            links_dict = raw_dev.get("Links") or {}
            d_links = links_dict.get("Drives") or []
            if isinstance(d_links, list):
                found_match = False
                for d_ref in d_links:
                    if not isinstance(d_ref, dict):
                        continue
                    ref_uri = str(d_ref.get("@odata.id") or "").strip().lower()
                    if (dev_uri and ref_uri and dev_uri == ref_uri) or (dev_id_raw and ref_uri.endswith("/" + dev_id_raw.lower())):
                        found_match = True
                        break
                if found_match:
                    best_match = pcie_dev
                    break

            for net_key in ("EthernetInterfaces", "NetworkDeviceFunctions", "NetworkAdapters", "NetworkInterfaces"):
                net_links = links_dict.get(net_key) or []
                if isinstance(net_links, list):
                    found_match = False
                    for n_ref in net_links:
                        if not isinstance(n_ref, dict):
                            continue
                        ref_uri = str(n_ref.get("@odata.id") or "").strip().lower()
                        if (dev_uri and ref_uri and (dev_uri == ref_uri or ref_uri.startswith(dev_uri + "/"))) or (dev_id_raw and ref_uri.endswith("/" + dev_id_raw.lower())):
                            found_match = True
                            break
                    if found_match:
                        best_match = pcie_dev
                        break
            if best_match:
                break

            # Check PCIeFunctions on PCIeDevice (cached on raw_dev["_expanded_func_objects"] to avoid repeated network calls)
            if "_expanded_func_objects" not in raw_dev:
                raw_funcs = []
                for src in (raw_dev.get("PCIeFunctions"), (raw_dev.get("Links") or {}).get("PCIeFunctions")):
                    if isinstance(src, list):
                        raw_funcs.extend(src)
                    elif isinstance(src, dict):
                        raw_funcs.append(src)

                expanded_funcs = []
                for f_item in raw_funcs:
                    if not isinstance(f_item, dict):
                        continue
                    f_uri = str(f_item.get("@odata.id") or "").strip()
                    if f_uri and f_uri.lower() in ("/empty", "empty", "none", "null", "n/a", "/"):
                        continue
                    if f_uri and callable(get_fn) and (f_uri.endswith("/PCIeFunctions") or "Collection" in str(f_item.get("@odata.type", ""))):
                        f_coll = get_fn(f_uri) or {}
                        m_list = f_coll.get("Members") or (f_coll.get("Links") or {}).get("PCIeFunctions") or []
                        if isinstance(m_list, list):
                            for m in m_list:
                                if isinstance(m, dict):
                                    m_uri = str(m.get("@odata.id") or "").strip()
                                    if m_uri and m_uri.lower() not in ("/empty", "empty", "none", "null", "n/a", "/"):
                                        expanded_funcs.append(m)
                    else:
                        expanded_funcs.append(f_item)

                # Cap function lookups to at most 8 functions to prevent unbounded crawls
                func_objects = []
                for f_item in expanded_funcs[:8]:
                    if not isinstance(f_item, dict):
                        continue
                    f_uri = f_item.get("@odata.id")
                    f_data = None
                    if f_uri and callable(get_fn) and len(f_item) <= 2:
                        f_data = get_fn(f_uri)
                    if not isinstance(f_data, dict):
                        f_data = f_item
                    func_objects.append(f_data)
                raw_dev["_expanded_func_objects"] = func_objects

            func_objects = raw_dev.get("_expanded_func_objects") or []
            if func_objects:
                found_match = False
                for f_data in func_objects:
                    if not isinstance(f_data, dict):
                        continue
                    f_links = f_data.get("Links") or {}
                    f_drives = f_links.get("Drives") or []
                    if isinstance(f_drives, list):
                        for d_ref in f_drives:
                            if isinstance(d_ref, dict):
                                ref_uri = str(d_ref.get("@odata.id") or "").strip().lower()
                                if (dev_uri and ref_uri and dev_uri == ref_uri) or (dev_id_raw and ref_uri.endswith("/" + dev_id_raw.lower())):
                                    found_match = True
                                    break
                    if found_match:
                        break

                    for net_key in ("EthernetInterfaces", "NetworkDeviceFunctions", "NetworkAdapters", "NetworkInterfaces"):
                        net_refs = f_links.get(net_key) or []
                        if isinstance(net_refs, list):
                            for n_ref in net_refs:
                                if isinstance(n_ref, dict):
                                    ref_uri = str(n_ref.get("@odata.id") or "").strip().lower()
                                    if (dev_uri and ref_uri and (dev_uri == ref_uri or ref_uri.startswith(dev_uri + "/"))) or (dev_id_raw and ref_uri.endswith("/" + dev_id_raw.lower())):
                                        found_match = True
                                        break
                        if found_match:
                            break
                    if found_match:
                        break

                    dell_func = get_nested(f_data, "Oem", "Dell", "DellPCIeFunction", default={})
                    if isinstance(dell_func, dict):
                        dell_id = str(dell_func.get("Id") or dell_func.get("FQDD") or dell_func.get("InstanceID") or "").strip()
                        if dev_id_raw and dell_id and dev_id_raw.lower() == dell_id.lower():
                            found_match = True
                            break
                if found_match:
                    best_match = pcie_dev
                    break

    # Fast O(1) indexed matching steps
    if not best_match and c_vid and c_did:
        pair_key = f"{c_vid}:{c_did}"
        vid_did_matches = index["by_vid_did"].get(pair_key)
        if vid_did_matches and len(vid_did_matches) == 1:
            best_match = vid_did_matches[0]

    if not best_match and pn and len(pn) >= 4:
        best_match = index["by_part_number"].get(pn)

    if not best_match and dev_id:
        best_match = index["by_id"].get(dev_id)
        if not best_match:
            clean_dev_id = _normalize_slot_id(dev_id)
            if clean_dev_id:
                best_match = index["by_clean_id"].get(clean_dev_id)

    if not best_match and name not in _GENERIC_NAMES:
        t1 = _extract_model_token(name)
        if t1:
            best_match = index["by_model_token"].get(t1)

    # Linear fallback scan if indexed lookup did not find a match
    if not best_match:
        for pcie_dev in cache_list:
            if not isinstance(pcie_dev, dict):
                continue
            p_pn = str(pcie_dev.get("part_number") or "").strip().upper()
            p_raw_name = str(pcie_dev.get("name") or "").strip()
            p_name = p_raw_name.lower()
            p_id = str(pcie_dev.get("id") or "").strip()
            p_vid = pcie_dev.get("vendor_id", "")
            p_did = pcie_dev.get("device_id", "")

            # 1. Exact VID:DID match
            if c_vid and c_did and p_vid and p_did and c_vid == p_vid and c_did == p_did:
                best_match = pcie_dev
                break
            # 2. Part number match
            if pn and len(pn) >= 4 and p_pn and (pn in p_pn or p_pn in pn):
                best_match = pcie_dev
                break
            # 3. ID / location substring match
            if dev_id and p_id:
                if dev_id == p_id:
                    best_match = pcie_dev
                    break
                if not dev_id.isdigit() and not p_id.isdigit():
                    if len(dev_id) >= 3 and len(p_id) >= 3 and (dev_id in p_id or p_id in dev_id):
                        best_match = pcie_dev
                        break
                clean_dev_id = _normalize_slot_id(dev_id)
                clean_p_id = _normalize_slot_id(p_id)
                if clean_dev_id and clean_p_id:
                    if clean_dev_id == clean_p_id:
                        best_match = pcie_dev
                        break
                    if clean_dev_id.split(".")[0] == clean_p_id or clean_p_id.split(".")[0] == clean_dev_id:
                        best_match = pcie_dev
                        break
                    if len(clean_dev_id) >= 3 and len(clean_p_id) >= 3:
                        if clean_dev_id in clean_p_id or clean_p_id in clean_dev_id:
                            best_match = pcie_dev
                            break
            # 4. Name match (filtering generic strings)
            if name not in _GENERIC_NAMES and p_name not in _GENERIC_NAMES:
                if (name in p_name or p_name in name) and len(name) >= 4:
                    best_match = pcie_dev
                    break
                t1 = _extract_model_token(name)
                t2 = _extract_model_token(p_name)
                if t1 and t2:
                    if t1 == t2 or (t1.startswith("connectx-") and t2.startswith("connectx-") and t1.split("-")[1] == t2.split("-")[1]):
                        best_match = pcie_dev
                        break

    if best_match:
        m_vid = pci_info["vendor_id"] or best_match.get("vendor_id", "")
        m_did = pci_info["device_id"] or best_match.get("device_id", "")
        m_svid = pci_info["subsystem_vendor_id"] or best_match.get("subsystem_vendor_id", "")
        m_ssid = pci_info["subsystem_id"] or best_match.get("subsystem_id", "")
        m_quad = f"{m_vid}:{m_did}:{m_svid}:{m_ssid}" if (m_vid and m_did and m_svid and m_ssid) else ""
        m_pair = f"{m_vid}:{m_did}" if (m_vid and m_did) else ""
        return {
            "vendor_id": m_vid,
            "device_id": m_did,
            "subsystem_vendor_id": m_svid,
            "subsystem_id": m_ssid,
            "pci_quad": m_quad,
            "pci_pair": m_pair,
        }

    return pci_info


def match_firmware_inventory_pci(device_name: str, get_fn: Optional[Callable] = None) -> dict:
    """Extract PCI IDs from /redfish/v1/UpdateService/FirmwareInventory on BMCs that encode PCI quads in Description.

    HPE iLO 5/6 encodes 16-hex PCI quads (e.g. '80861572103c22fc') in FirmwareInventory Description fields.
    """
    empty_res = {
        "vendor_id": "",
        "device_id": "",
        "subsystem_vendor_id": "",
        "subsystem_id": "",
        "pci_quad": "",
        "pci_pair": "",
    }
    if not device_name or not callable(get_fn):
        return empty_res

    collector = getattr(get_fn, "__self__", None)
    req_cache = getattr(collector, "_request_cache", None)
    host_url = getattr(collector, "host_url", "")
    is_lean = getattr(collector, "lean_mode", False)

    # In lean mode or when req_cache is present but empty for FirmwareInventory, avoid uncached network calls
    if isinstance(req_cache, dict):
        fw_inv_uri = "/redfish/v1/UpdateService/FirmwareInventory"
        fw_inv_url = f"{host_url}{fw_inv_uri}" if host_url else fw_inv_uri
        if is_lean and fw_inv_uri not in req_cache and fw_inv_url not in req_cache:
            return empty_res

    fw_inv = get_fn("/redfish/v1/UpdateService/FirmwareInventory") or {}
    members = fw_inv.get("Members") or []
    if not isinstance(members, list):
        return empty_res

    dev_name_clean = re.sub(r"\s+", " ", str(device_name)).strip().lower()
    dev_name_base = re.sub(r"\s*-\s*[0-9a-f]{2}(?::[0-9a-f]{2}){5}", "", dev_name_clean, flags=re.I).strip()

    pci_hex_regex = re.compile(r"^[0-9a-fA-F]{16}$")

    for m in members:
        if not isinstance(m, dict):
            continue
        m_uri = m.get("@odata.id")
        m_item = None
        if isinstance(req_cache, dict) and m_uri:
            m_url = f"{host_url}{m_uri}" if host_url else m_uri
            if m_uri in req_cache:
                m_item = req_cache[m_uri]
            elif m_url in req_cache:
                m_item = req_cache[m_url]
            elif "Description" in m or "Name" in m:
                m_item = m
            else:
                # Member URI is not in cache, skip uncached HTTP call
                continue
        else:
            m_item = get_fn(m_uri) if m_uri else m

        if not isinstance(m_item, dict):
            continue

        item_name = re.sub(r"\s+", " ", str(m_item.get("Name", ""))).strip().lower()
        item_desc = str(m_item.get("Description", "")).strip()

        if not pci_hex_regex.match(item_desc):
            continue

        item_name_base = re.sub(r"\s*-\s*[0-9a-f]{2}(?::[0-9a-f]{2}){5}", "", item_name, flags=re.I).strip()

        if (
            dev_name_base == item_name_base
            or (len(dev_name_base) >= 8 and dev_name_base in item_name_base)
            or (len(item_name_base) >= 8 and item_name_base in dev_name_base)
        ):
            vid = item_desc[0:4].lower()
            did = item_desc[4:8].lower()
            svid = item_desc[8:12].lower()
            ssid = item_desc[12:16].lower()
            return {
                "vendor_id": vid,
                "device_id": did,
                "subsystem_vendor_id": svid,
                "subsystem_id": ssid,
                "pci_quad": f"{vid}:{did}:{svid}:{ssid}",
                "pci_pair": f"{vid}:{did}",
            }

    return empty_res


def normalize_pcie_gen(val: Any) -> Optional[int]:
    """Normalize PCIe generation to an integer (e.g. 'Gen4' -> 4, 'PCIExpressGen3X16' -> 3, 'PCIe 4.0' -> 4)."""
    if val is None:
        return None
    s = str(val).strip()
    if not s or s.lower() in ("unknown", "n/a", "none", "null", ""):
        return None
    m = re.search(r"(?:Gen(?:eration)?|PCIExpressGen|PCIe(?:Type)?)\s*(\d)", s, re.I)
    if m:
        return int(m.group(1))
    m = re.search(r"\b(\d)(?:\.0)?\b", s)
    if m and int(m.group(1)) in (1, 2, 3, 4, 5, 6, 7):
        return int(m.group(1))
    return None


def normalize_pcie_type(val: Any) -> Optional[str]:
    """Normalize PCIe generation to standard DMTF string format (e.g. 4 -> 'Gen4', 'PCIExpressGen4' -> 'Gen4')."""
    gen = normalize_pcie_gen(val)
    return f"Gen{gen}" if gen is not None else None


def normalize_pcie_width(val: Any) -> Optional[int]:
    """Normalize PCIe link lane width to an integer (e.g. '16XOrX16' -> 16, 'x8' -> 8, 4 -> 4)."""
    if val is None:
        return None
    if isinstance(val, (int, float)):
        v = int(val)
        return v if v > 0 else None
    s = str(val).strip()
    if not s or s.lower() in ("unknown", "n/a", "none", "null", ""):
        return None
    # Dell format: '16XOrX16', '8XOrX8', '4XOrX4'
    m = re.search(r"^(\d+)[Xx]Or", s)
    if m:
        return int(m.group(1))
    # Suffix format: 'PCIExpressGen3X16', 'Gen4x8'
    m = re.search(r"[Xx](\d+)$", s)
    if m:
        return int(m.group(1))
    # Prefix format: 'x16', 'X8'
    m = re.search(r"^[Xx](\d+)$", s)
    if m:
        return int(m.group(1))
    # Pure integer string: '16'
    if s.isdigit():
        v = int(s)
        return v if v > 0 else None
    # Fallback pattern: '16 lanes', 'width 8'
    m = re.search(r"\b(\d+)\s*(?:lanes?|width)\b", s, re.I)
    if m:
        return int(m.group(1))
    return None


def extract_pcie_link_status(dev_dict: dict) -> dict:
    """Extract PCIe link capabilities vs negotiated operational status.

    Checks top-level fields, PCIeInterface block, Controllers array, Slot, or Oem nests.
    Returns dict with keys:
      max_gen, negotiated_gen, max_lanes, negotiated_lanes,
      current_pcie_type, max_pcie_type, current_pcie_width, max_pcie_width,
      downgraded, badge, reason
    """
    if not isinstance(dev_dict, dict):
        return {
            "max_gen": None, "negotiated_gen": None,
            "max_lanes": None, "negotiated_lanes": None,
            "current_pcie_type": None, "max_pcie_type": None,
            "current_pcie_width": None, "max_pcie_width": None,
            "downgraded": False, "badge": "", "reason": "",
        }

    pcie_if = dev_dict.get("PCIeInterface")
    if not isinstance(pcie_if, dict):
        controllers = dev_dict.get("Controllers")
        if isinstance(controllers, list):
            for c in controllers:
                if isinstance(c, dict) and isinstance(c.get("PCIeInterface"), dict):
                    pcie_if = c.get("PCIeInterface")
                    break
    if not isinstance(pcie_if, dict):
        pcie_if = {}

    slot = dev_dict.get("Slot") if isinstance(dev_dict.get("Slot"), dict) else {}

    oem = dev_dict.get("Oem") if isinstance(dev_dict.get("Oem"), dict) else {}
    dell = oem.get("Dell") if isinstance(oem.get("Dell"), dict) else {}
    dell_nic = dell.get("DellNIC") or dell.get("DellFC") or {}
    if not isinstance(dell_nic, dict):
        dell_nic = {}
    if not dell_nic:
        controllers = dev_dict.get("Controllers")
        if isinstance(controllers, list):
            for c in controllers:
                if isinstance(c, dict):
                    c_dell = (c.get("Oem") or {}).get("Dell", {}).get("DellNIC")
                    if isinstance(c_dell, dict) and c_dell:
                        dell_nic = c_dell
                        break

    # Max capability
    max_gen = (
        normalize_pcie_gen(pcie_if.get("MaxPCIeType"))
        or normalize_pcie_gen(pcie_if.get("MaxPCIeGeneration"))
        or normalize_pcie_gen(slot.get("MaxPCIeType"))
        or normalize_pcie_gen(slot.get("PCIeType"))
        or normalize_pcie_gen(dev_dict.get("MaxPCIeType"))
        or normalize_pcie_gen(dev_dict.get("MaxPCIeGeneration"))
    )
    max_lanes = (
        normalize_pcie_width(pcie_if.get("MaxLanes"))
        or normalize_pcie_width(pcie_if.get("MaxPCIeLanes"))
        or normalize_pcie_width(slot.get("MaxLanes"))
        or normalize_pcie_width(slot.get("Lanes"))
        or normalize_pcie_width(dev_dict.get("MaxLanes"))
        or normalize_pcie_width(dev_dict.get("MaxPCIeLanes"))
    )

    # Negotiated / current operating status
    neg_gen = (
        normalize_pcie_gen(pcie_if.get("NegotiatedPCIeType"))
        or normalize_pcie_gen(pcie_if.get("OperatingPCIeType"))
        or normalize_pcie_gen(pcie_if.get("PCIeType"))
        or normalize_pcie_gen(dell_nic.get("SlotType"))
        or normalize_pcie_gen(dev_dict.get("NegotiatedPCIeType"))
        or normalize_pcie_gen(dev_dict.get("OperatingPCIeType"))
        or normalize_pcie_gen(dev_dict.get("PCIeType"))
    )
    neg_lanes = (
        normalize_pcie_width(pcie_if.get("NegotiatedLanes"))
        or normalize_pcie_width(pcie_if.get("NegotiatedLanesCount"))
        or normalize_pcie_width(pcie_if.get("LanesInUse"))
        or normalize_pcie_width(pcie_if.get("OperatingLanes"))
        or normalize_pcie_width(dell_nic.get("DataBusWidth"))
        or normalize_pcie_width(dev_dict.get("LanesInUse"))
        or normalize_pcie_width(dev_dict.get("NegotiatedLanes"))
        or normalize_pcie_width(dev_dict.get("OperatingLanes"))
    )

    if max_gen is None and neg_gen is not None:
        max_gen = neg_gen
    if max_lanes is None and neg_lanes is not None:
        max_lanes = neg_lanes

    current_pcie_type = f"Gen{neg_gen}" if neg_gen is not None else None
    max_pcie_type = f"Gen{max_gen}" if max_gen is not None else None
    current_pcie_width = neg_lanes
    max_pcie_width = max_lanes

    downgraded = False
    reason = ""
    badge = ""

    if (max_gen and neg_gen and neg_gen < max_gen) or (max_lanes and neg_lanes and neg_lanes < max_lanes):
        downgraded = True
        g_str = f"Gen{neg_gen}" if neg_gen else ""
        l_str = f"x{neg_lanes}" if neg_lanes else ""
        max_g_str = f"Gen{max_gen}" if max_gen else ""
        max_l_str = f"x{max_lanes}" if max_lanes else ""
        reason = f"Link Downgraded: Operating at {g_str} {l_str} (Capable: {max_g_str} {max_l_str})".strip()
        badge = f"<span class='badge warning'>⚠️ PCIe Link Downgraded ({l_str} {g_str})</span>"

    return {
        "max_gen": max_gen,
        "negotiated_gen": neg_gen,
        "max_lanes": max_lanes,
        "negotiated_lanes": neg_lanes,
        "current_pcie_type": current_pcie_type,
        "max_pcie_type": max_pcie_type,
        "current_pcie_width": current_pcie_width,
        "max_pcie_width": max_pcie_width,
        "downgraded": downgraded,
        "badge": badge,
        "reason": reason,
    }


def extract_pcie_functions(dev: dict, get_fn: Optional[Callable] = None) -> list:
    """Extract PCIeFunction schema objects (FunctionId, DeviceClass, FunctionType, BDF)."""
    if not isinstance(dev, dict):
        return []

    raw_funcs = []
    for src in (dev.get("PCIeFunctions"), (dev.get("Links") or {}).get("PCIeFunctions")):
        if isinstance(src, list):
            raw_funcs.extend(src)
        elif isinstance(src, dict):
            raw_funcs.append(src)

    expanded_funcs = []
    for f_item in raw_funcs:
        if not isinstance(f_item, dict):
            continue
        f_uri = str(f_item.get("@odata.id") or "").strip()
        if f_uri and f_uri.lower() in ("/empty", "empty", "none", "null", "n/a", "/"):
            continue
        if f_uri and callable(get_fn) and (f_uri.endswith("/PCIeFunctions") or "Collection" in str(f_item.get("@odata.type", ""))):
            f_coll = get_fn(f_uri) or {}
            m_list = f_coll.get("Members") or (f_coll.get("Links") or {}).get("PCIeFunctions") or []
            if isinstance(m_list, list):
                for m in m_list:
                    if isinstance(m, dict):
                        m_uri = str(m.get("@odata.id") or "").strip()
                        if m_uri and m_uri.lower() not in ("/empty", "empty", "none", "null", "n/a", "/"):
                            expanded_funcs.append(m)
        else:
            expanded_funcs.append(f_item)

    parsed_funcs = []
    seen_func_ids = set()
    for f_ref in expanded_funcs:
        if not isinstance(f_ref, dict):
            continue
        f_uri = str(f_ref.get("@odata.id") or "").strip()
        if f_uri and f_uri.lower() in ("/empty", "empty", "none", "null", "n/a", "/"):
            continue
        f_data = None
        if f_uri and callable(get_fn) and len(f_ref) <= 2:
            f_data = get_fn(f_uri)
        if not isinstance(f_data, dict):
            f_data = f_ref

        if "Members" in f_data and isinstance(f_data["Members"], list):
            candidates = [m for m in f_data["Members"] if isinstance(m, dict)]
        else:
            candidates = [f_data]

        for cand in candidates:
            c_uri = str(cand.get("@odata.id") or "").strip()
            if c_uri and c_uri.lower() in ("/empty", "empty", "none", "null", "n/a", "/"):
                continue
            if c_uri and callable(get_fn) and len(cand) <= 2:
                c_data = get_fn(c_uri) or cand
            else:
                c_data = cand

            fn_id = str(c_data.get("FunctionId") or c_data.get("Id") or "").strip()
            fn_type = str(c_data.get("FunctionType") or "").strip()
            dev_class = str(c_data.get("DeviceClass") or "").strip()
            bdf = str(c_data.get("PCIeAddress") or c_data.get("BDF") or "").strip()
            vid = normalize_pci_id(_get_val(c_data, _VID_KEYS))
            did = normalize_pci_id(_get_val(c_data, _DID_KEYS))
            svid = normalize_pci_id(_get_val(c_data, _SVID_KEYS))
            ssid = normalize_pci_id(_get_val(c_data, _SSID_KEYS))
            pci_quad = f"{vid}:{did}:{svid}:{ssid}" if (vid and did and svid and ssid) else f"{vid}:{did}" if (vid and did) else ""

            dedup = (fn_id, bdf, vid, did)
            if dedup in seen_func_ids:
                continue
            seen_func_ids.add(dedup)

            parsed_funcs.append({
                "function_id": fn_id or str(len(parsed_funcs)),
                "function_type": fn_type,
                "device_class": dev_class,
                "bdf": bdf,
                "vendor_id": vid,
                "device_id": did,
                "subsystem_vendor_id": svid,
                "subsystem_id": ssid,
                "pci_quad": pci_quad,
                "uri": c_uri,
            })

    return parsed_funcs


def select_best_pci_pair_entry(
    res_list: list,
    model_name: str = "",
    svid: str = "",
    ssid: str = "",
) -> Optional[dict]:
    """Select the best matching HCL device dictionary from a list of PCI pair candidates.

    Resolution strategy:
    1. If svid and ssid are provided, look for an exact subsystem match.
    2. If model_name is provided, score candidates by token overlap, generic family indicators,
       and vendor alignment (e.g. QL41xxx family vs Dell OEM KR mezzanine cards).
    3. Prefer generic family entries (subsystem_id in '0000', '', '0').
    4. Fall back to the first candidate.
    """
    if not res_list:
        return None
    if not isinstance(res_list, list):
        return res_list if isinstance(res_list, dict) else None
    if len(res_list) == 1:
        return res_list[0] if isinstance(res_list[0], dict) else None

    # 1. Exact subsystem match if svid and ssid are provided
    norm_sv = normalize_pci_id(svid)
    norm_ss = normalize_pci_id(ssid)
    if norm_sv and norm_ss:
        for entry in res_list:
            if isinstance(entry, dict):
                e_sv = normalize_pci_id(entry.get("subsystem_vendor_id", ""))
                e_ss = normalize_pci_id(entry.get("subsystem_id", ""))
                if e_sv == norm_sv and e_ss == norm_ss:
                    return entry

    # 2. Score candidates if model_name is provided
    if model_name:
        mn_lower = str(model_name).lower()
        tokens = [t for t in re.split(r"[\s\-_/]+", mn_lower) if len(t) > 2]
        best_cand = None
        best_score = -100

        for entry in res_list:
            if not isinstance(entry, dict):
                continue
            e_model = str(entry.get("model", "")).lower()
            score = 0

            # Generic family baseline preference when SSID doesn't match
            e_ssid = str(entry.get("subsystem_id", "")).strip().lower()
            is_generic_family = e_ssid in ("0000", "0", "") or ":0000:0000" in str(entry.get("pci_quad", "")).lower()
            if is_generic_family:
                score += 10

            # Token overlap
            for t in tokens:
                if t in e_model:
                    score += 2

            # QL41xxx family handling: "ql41262" or "ql41xxx" in model
            if "ql41" in mn_lower and "ql41xxx" in e_model:
                score += 15

            # Penalize OEM-specific blade / mezzanine identifiers if not present in adapter name
            if ("hmkr" in e_model or "mezz" in e_model) and "hmkr" not in mn_lower and "mezz" not in mn_lower:
                score -= 10
            if "dell" in e_model and "dell" not in mn_lower:
                score -= 5

            if score > best_score:
                best_score = score
                best_cand = entry

        if best_cand and best_score > 0:
            return best_cand

    # 3. Prefer generic family entry (subsystem_id == "0000")
    for entry in res_list:
        if isinstance(entry, dict):
            e_ssid = str(entry.get("subsystem_id", "")).strip().lower()
            if e_ssid in ("0000", "0", "") or ":0000:0000" in str(entry.get("pci_quad", "")).lower():
                return entry

    return res_list[0] if isinstance(res_list[0], dict) else None


def pcie_has_fc_candidates(pcie_cache: Union[list, dict]) -> bool:
    """Return True if pcie_cache contains candidate Fibre Channel HBAs or if cache is unavailable."""
    if not pcie_cache:
        return True
    devs = pcie_cache if isinstance(pcie_cache, list) else pcie_cache.get("raw_cache", [])
    if not devs:
        return True

    fc_terms = ("fibre", "fibrechannel", "fc hba", "fc adapter", "lpe", "qle", "emulex", "qlogic", "cisco vic")
    for dev in devs:
        if not isinstance(dev, dict):
            continue
        dc = str(dev.get("device_class") or "").upper()
        if "FIBRE" in dc or "FC" in dc:
            return True
        name = str(dev.get("name") or dev.get("Model") or "").lower()
        if any(t in name for t in fc_terms):
            return True
        vid = str(dev.get("vendor_id") or "").lower().replace("0x", "")
        if vid in ("10df", "1077"):
            return True
        funcs = dev.get("functions") or []
        if isinstance(funcs, list):
            for fn in funcs:
                if not isinstance(fn, dict):
                    continue
                f_dc = str(fn.get("device_class") or "").upper()
                if "FIBRE" in f_dc or "FC" in f_dc:
                    return True
                f_vid = str(fn.get("vendor_id") or "").lower().replace("0x", "")
                if f_vid in ("10df", "1077"):
                    return True
                f_name = str(fn.get("name") or "").lower()
                if any(t in f_name for t in fc_terms):
                    return True
    return False


def pcie_has_gpu_candidates(pcie_cache: Union[list, dict]) -> bool:
    """Return True if pcie_cache contains candidate GPUs/accelerators or if cache is unavailable."""
    if not pcie_cache:
        return True
    devs = pcie_cache if isinstance(pcie_cache, list) else pcie_cache.get("raw_cache", [])
    if not devs:
        return True

    gpu_keywords = (
        "DISPLAY", "3D", "GPU", "NVIDIA", "AMD RADEON", "TESLA",
        "H100", "H200", "A100", "A30", "A40", "L40", "V100",
        "MI300", "MI250", "MI210", "GAUDI", "FLEX",
    )
    for dev in devs:
        if not isinstance(dev, dict):
            continue
        dc = str(dev.get("device_class") or "").upper()
        if any(k in dc for k in ("DISPLAY", "3D")):
            return True
        name = str(dev.get("name") or dev.get("Model") or "").upper()
        if any(k in name for k in gpu_keywords):
            if not any(n in name for n in ("CONNECTX", "BLUEFIELD", "ETHERNET", " NIC", "OCP NIC")):
                return True
        vid = str(dev.get("vendor_id") or "").lower().replace("0x", "")
        if vid in ("10de",):  # NVIDIA
            return True
        funcs = dev.get("functions") or []
        if isinstance(funcs, list):
            for fn in funcs:
                if not isinstance(fn, dict):
                    continue
                f_dc = str(fn.get("device_class") or "").upper()
                if any(k in f_dc for k in ("DISPLAY", "3D")):
                    return True
                f_vid = str(fn.get("vendor_id") or "").lower().replace("0x", "")
                if f_vid in ("10de",):
                    return True
    return False


def normalize_pcie_errors(raw_errors: Any) -> Optional[dict]:
    """Normalize PCIeErrors payload (dict, scalar, or nested) into a structured schema.

    Standard DMTF Redfish PCIeErrors properties:
      - CorrectableErrorCount: int | None
      - L0ToRecoveryCount: int | None
      - ReplayCount: int | None
      - ReplayRolloverCount: int | None
      - NonFatalErrorCount: int | None
      - FatalErrorCount: int | None
      - NAKReceivedCount: int | None
      - NAKSentCount: int | None
      - UnsupportedRequestCount: int | None

    Normalized output schema:
      {
        "correctable_errors": Optional[int],
        "l0_to_recovery_count": Optional[int],
        "replay_count": Optional[int],
        "replay_rollover_count": Optional[int],
        "non_fatal_errors": Optional[int],
        "fatal_errors": Optional[int],
        "nak_received_count": Optional[int],
        "nak_sent_count": Optional[int],
        "unsupported_requests": Optional[int],
        "total_errors": Optional[int],
      }
    """
    if raw_errors is None:
        return None

    def _to_int(val: Any) -> Optional[int]:
        if val is None or val == "" or str(val).strip().lower() in ("none", "null", "n/a"):
            return None
        try:
            return int(float(val))
        except (ValueError, TypeError):
            return None

    # Handle numeric scalar
    if isinstance(raw_errors, (int, float)):
        val = int(raw_errors)
        return {
            "correctable_errors": val,
            "l0_to_recovery_count": None,
            "replay_count": None,
            "replay_rollover_count": None,
            "non_fatal_errors": None,
            "fatal_errors": None,
            "nak_received_count": None,
            "nak_sent_count": None,
            "unsupported_requests": None,
            "total_errors": val,
        }

    if isinstance(raw_errors, str):
        v = _to_int(raw_errors)
        if v is not None:
            return {
                "correctable_errors": v,
                "l0_to_recovery_count": None,
                "replay_count": None,
                "replay_rollover_count": None,
                "non_fatal_errors": None,
                "fatal_errors": None,
                "nak_received_count": None,
                "nak_sent_count": None,
                "unsupported_requests": None,
                "total_errors": v,
            }
        return None

    if not isinstance(raw_errors, dict):
        return None

    # If it's a dict, handle both DMTF PascalCase and lowercase/underscore variants
    corr = _to_int(
        raw_errors.get("CorrectableErrorCount")
        if raw_errors.get("CorrectableErrorCount") is not None
        else (
            raw_errors.get("correctable_errors")
            if raw_errors.get("correctable_errors") is not None
            else (
                raw_errors.get("CorrectableErrors")
                if raw_errors.get("CorrectableErrors") is not None
                else (
                    raw_errors.get("PCIeCorrectableErrorCount")
                    if raw_errors.get("PCIeCorrectableErrorCount") is not None
                    else raw_errors.get("Correctable")
                )
            )
        )
    )
    l0 = _to_int(
        raw_errors.get("L0ToRecoveryCount")
        if raw_errors.get("L0ToRecoveryCount") is not None
        else (
            raw_errors.get("l0_to_recovery_count")
            if raw_errors.get("l0_to_recovery_count") is not None
            else (
                raw_errors.get("L0ToRecovery")
                if raw_errors.get("L0ToRecovery") is not None
                else raw_errors.get("RecoveryCount")
            )
        )
    )
    replay = _to_int(
        raw_errors.get("ReplayCount")
        if raw_errors.get("ReplayCount") is not None
        else (
            raw_errors.get("replay_count")
            if raw_errors.get("replay_count") is not None
            else raw_errors.get("Replays")
        )
    )
    rollover = _to_int(
        raw_errors.get("ReplayRolloverCount")
        if raw_errors.get("ReplayRolloverCount") is not None
        else (
            raw_errors.get("replay_rollover_count")
            if raw_errors.get("replay_rollover_count") is not None
            else raw_errors.get("ReplayRollovers")
        )
    )
    non_fatal = _to_int(
        raw_errors.get("NonFatalErrorCount")
        if raw_errors.get("NonFatalErrorCount") is not None
        else (
            raw_errors.get("non_fatal_errors")
            if raw_errors.get("non_fatal_errors") is not None
            else (
                raw_errors.get("NonFatalErrors")
                if raw_errors.get("NonFatalErrors") is not None
                else raw_errors.get("NonFatal")
            )
        )
    )
    fatal = _to_int(
        raw_errors.get("FatalErrorCount")
        if raw_errors.get("FatalErrorCount") is not None
        else (
            raw_errors.get("fatal_errors")
            if raw_errors.get("fatal_errors") is not None
            else (
                raw_errors.get("FatalErrors")
                if raw_errors.get("FatalErrors") is not None
                else raw_errors.get("Fatal")
            )
        )
    )
    nak_rx = _to_int(raw_errors.get("NAKReceivedCount") if raw_errors.get("NAKReceivedCount") is not None else raw_errors.get("nak_received_count"))
    nak_tx = _to_int(raw_errors.get("NAKSentCount") if raw_errors.get("NAKSentCount") is not None else raw_errors.get("nak_sent_count"))
    unsupp = _to_int(raw_errors.get("UnsupportedRequestCount") if raw_errors.get("UnsupportedRequestCount") is not None else raw_errors.get("unsupported_requests"))

    explicit_total = _to_int(raw_errors.get("total_errors") if raw_errors.get("total_errors") is not None else raw_errors.get("TotalErrors"))

    # If all fields are None and no explicit total, return None
    all_fields = (corr, l0, replay, rollover, non_fatal, fatal, nak_rx, nak_tx, unsupp)
    if all(f is None for f in all_fields) and explicit_total is None:
        return None

    if explicit_total is not None:
        total = explicit_total
    else:
        err_candidates = [v for v in (corr, non_fatal, fatal) if v is not None]
        if err_candidates:
            total = sum(err_candidates)
        else:
            other_candidates = [v for v in (l0, rollover, replay) if v is not None]
            total = sum(other_candidates) if other_candidates else 0

    return {
        "correctable_errors": corr,
        "l0_to_recovery_count": l0,
        "replay_count": replay,
        "replay_rollover_count": rollover,
        "non_fatal_errors": non_fatal,
        "fatal_errors": fatal,
        "nak_received_count": nak_rx,
        "nak_sent_count": nak_tx,
        "unsupported_requests": unsupp,
        "total_errors": total,
    }



