"""Conservative firmware-to-NIC association; inventory titles remain authoritative."""
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit


def _uri(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("@odata.id")
    try:
        return urlsplit(str(value or "").strip()).path.rstrip("/").casefold()
    except ValueError:
        return ""


def _token(text: str, value: Any) -> bool:
    value = str(value or "").strip().upper()
    if len(value) < 4 or value in ("UNKNOWN", "NONE", "N/A", "SUPERMICRO", "NIC", "NETWORK ADAPTER"):
        return False
    return re.search(r"(?<![A-Z0-9])" + re.escape(value) + r"(?![A-Z0-9])", text) is not None


def _consistent(matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """A shared image can cover identical adapters, not arbitrary PCI identities."""
    identities = {tuple(str(n.get(key) or "").casefold() for key in
                        ("vendor_id", "device_id", "subsystem_vendor_id", "subsystem_id", "model")) for n in matches}
    return matches if len(identities) <= 1 else []


def match_firmware_nics(record: Dict[str, Any], nics: List[Dict[str, Any]],
                        raw_capture: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Require network-specific resource or component evidence, never substring IDs."""
    nics = [n for n in nics if isinstance(n, dict)]
    text = " ".join(str(record.get(k) or "") for k in ("id", "name", "description", "device_context")).upper()
    if re.search(r"\b(?:BIOS|BMC|CPLD|BACKPLANE|CAPSULE|IDRAC|ILO|CIMC|POWER[ _]*SUPPLY|POWERSUPPLY\d*)\b", text):
        return []
    related = record.get("related_items") or []
    if not related and isinstance(raw_capture, dict):
        raw = raw_capture.get('/redfish/v1/UpdateService/FirmwareInventory/' + str(record.get('id') or ''))
        if isinstance(raw, dict):
            related = raw.get("RelatedItem") or []
    uris = {_uri(value) for value in related if isinstance(value, (str, dict))}
    uris.discard("")
    matches = []
    for nic in nics:
        raw = nic.get("_raw")
        paths = {_uri(nic.get(key)) for key in ("uri", "resource_uri", "@odata.id")}
        if isinstance(raw, dict):
            paths.add(_uri(raw.get("@odata.id")))
        paths.discard("")
        nid = str(nic.get("id") or "").strip().casefold()
        if paths & uris or any(
            nid and '/' in path and path.rsplit('/', 1)[-1] == nid and path.rsplit('/', 2)[-2] in
            ("networkadapters", "basenetworkadapters") for path in uris
        ) or any(
            nid and not nid.isdecimal() and path.rsplit('/', 1)[-1] == nid
            and '/pciedevices/' in path for path in uris
        ):
            matches.append(nic)
    if matches:
        return _consistent(matches)
    component = str(record.get("component_id") or "")
    if component in ("115076", "114493"):
        subsystem = "4422" if component == "115076" else "4432"
        return _consistent([n for n in nics if str(n.get("subsystem_id") or "").lower()==subsystem])
    matches = [n for n in nics if any(_token(text, n.get(key)) for key in ("part_number", "model"))]
    if matches:
        return _consistent(matches)
    network = bool(re.search(r"\b(?:NIC(?:[. _-]*\d+|[.]SLOT|[.]EMBEDDED)?|NETWORK|ETHERNET|CONNECTX)\b", text))
    if not network:
        return []
    matches = [n for n in nics if not str(n.get("id") or "").isdecimal() and _token(text, n.get("id"))]
    if matches:
        return _consistent(matches)
    slot = re.search(r"\b(?:NIC[.]Slot[.]|Slot[._\s]*)([0-9A-Z]+)\b", text)
    if slot:
        target = slot.group(1)
        matches = [n for n in nics if re.search(r"\bSlot[. _]*" + re.escape(target) + r"(?![A-Z0-9])",
                    str(n.get("slot") or "") + ' ' + str(n.get("id") or ""), re.I)]
    return _consistent(matches)
