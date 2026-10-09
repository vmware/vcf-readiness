"""PCI-first family match for the FC HBA E+ and M+ badges.

Match order:
  1. PCI vendor + device id (subsystem id is ignored, so Dell and HPE boards match).
  2. A known older Fibre Channel device id stops the match. The name is not used.
  3. Model text, including an HCL model string passed in by the caller.
"""

from __future__ import annotations

import re
from typing import Any, Optional

FC_PLUS_MODULE = "fc-improvement-1"

_EMULEX_VID = 0x10DF
_EMULEX_PLUS_FLOOR = 0xF400
_EMULEX_DENY = {0xE300}

_MARVELL_VID = 0x1077
_MARVELL_ALLOW = {0x2081, 0x2089, 0x2281, 0x2289}
_MARVELL_DENY = {0x2031, 0x2061, 0x2071, 0x2261, 0x2271}

_EMULEX_NAME = re.compile(
    r"\bLPe(?:3[5-9]\d{3,}|[4-9]\d{4,})[A-Z0-9\-]*\b",
    re.IGNORECASE,
)
_EMULEX_OEM = re.compile(
    r"\b(?:SN1610E|SN1620E|SN1700E|SN1720E|5331C|7330C)\b",
    re.IGNORECASE,
)
_MARVELL_NAME = re.compile(
    r"\bQLE2[7-9]7\d[A-Z0-9\-]*\b",
    re.IGNORECASE,
)
_MARVELL_OEM = re.compile(
    r"\b(?:SN1610Q|SN1700Q)\b",
    re.IGNORECASE,
)

_NAME_KEYS = (
    "adapter_name",
    "name",
    "model",
    "manufacturer",
    "part_number",
)


def _pci_int(value: Any) -> Optional[int]:
    text = str(value or "").strip().lower().replace("0x", "")
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def _name_blob(hba: dict, hcl_model: str) -> str:
    parts = [hcl_model]
    for key in _NAME_KEYS:
        parts.append(hba.get(key))
    return " ".join(str(part) for part in parts if part)


def classify_fc_plus(hba: dict, hcl_model: str = "") -> str:
    """Return ``E+``, ``M+``, or ``""``.

    ``hba`` is one ``fc_hbas`` entry. ``hcl_model`` is optional model text from
    an HCL lookup. Callers keep CNA rows off this badge.
    """
    if not isinstance(hba, dict):
        return ""

    vid = _pci_int(hba.get("vendor_id"))
    did = _pci_int(hba.get("device_id"))
    if vid is not None and did is not None:
        if vid == _EMULEX_VID:
            if did >= _EMULEX_PLUS_FLOOR:
                return "E+"
            if did in _EMULEX_DENY:
                return ""
        elif vid == _MARVELL_VID:
            if did in _MARVELL_ALLOW:
                return "M+"
            if did in _MARVELL_DENY:
                return ""

    blob = _name_blob(hba, hcl_model)
    if _EMULEX_NAME.search(blob) or _EMULEX_OEM.search(blob):
        return "E+"
    if _MARVELL_NAME.search(blob) or _MARVELL_OEM.search(blob):
        return "M+"
    return ""
