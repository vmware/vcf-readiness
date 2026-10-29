"""Pure drive location, empty-slot shape and firmware candidate resolution."""
import re
from typing import Any, List, Optional

from vcf_hci.logging_utils import get_nested


def is_invalid_drive_firmware(fw: Any) -> bool:
    """Return True if fw string is empty, placeholder, or a protocol/specification string."""
    if not fw:
        return True
    if isinstance(fw, dict):
        s = str(
            get_nested(fw, "Current", "VersionString")
            or fw.get("VersionString")
            or fw.get("Version")
            or ""
        ).strip()
    else:
        s = str(fw).strip()
    if not s or s.lower() in ("n/a", "none", "unknown", "null", "not available", "not_available"):
        return True
    if re.match(r"^0+(?:[._-]0+)*$", s):
        return True
    if re.search(r"^(?:NVMe\s+Spec|Supports\s+ATA|ATA\d*[-_]ACS|SCSI|SPC[-_]\d+|SBC[-_]\d+|AHCI|CPLD)", s, re.I):
        return True
    return bool(re.search(r"\b(?:spec|specification|cpld)\b", s, re.I))


def _extract_fw_candidate(val: Any) -> str:
    """Extract clean string firmware version from string or nested dict."""
    if isinstance(val, dict):
        res = (
            get_nested(val, "Current", "VersionString")
            or val.get("VersionString")
            or val.get("Version")
            or ""
        )
        return str(res).strip()
    if val is not None:
        s = str(val).strip()
        if s.startswith("{"):
            m = re.search(r"['\"]VersionString['\"]\s*:\s*['\"]([^'\"]+)['\"]", s)
            if m:
                return m.group(1).strip()
        return s
    return ""


def parse_drive_location(drive_json: dict, ctrl_id: str, ctrl_name: str) -> dict:
    """Decode bay/form-factor evidence before any Metrics or OEM request."""
    ctrl_id_up, ctrl_name_up = str(ctrl_id or "").upper(), str(ctrl_name or "").upper()
    # ── Bay / slot location ────────────────────────────────────────────────
    # Priority: DMTF PhysicalLocation ordinal → HPE Location string → Dell Id parse
    _bay_slot: Optional[int] = None
    _phys = drive_json.get("PhysicalLocation") or {}
    _part_loc = _phys.get("PartLocation") or {}
    _ordinal = _part_loc.get("LocationOrdinalValue")
    if isinstance(_ordinal, (int, float)):
        _bay_slot = int(_ordinal)
    if _bay_slot is None:
        # HPE SmartStorage: "Location" string like "1I:Box 1:Bay 3" or "1I:1:3" (ControllerPort:Box:Bay)
        _hpe_loc = str(drive_json.get("Location") or "")
        _bay_m = re.search(r"[Bb]ay\s*:?\s*(\d+)", _hpe_loc)
        if _bay_m:
            _bay_slot = int(_bay_m.group(1))
        else:
            _colon_m = re.search(r"^[\w\d]+:\d+:(\d+)$", _hpe_loc)
            if _colon_m:
                _bay_slot = int(_colon_m.group(1))
    if _bay_slot is None:
        # Dell: Id like "Disk.Bay.4:Enclosure.Internal.0-1:AHCI.Embedded.1-1"
        _id_m = re.search(r"[Bb]ay\.(\d+)", str(drive_json.get("Id") or ""))
        if _id_m:
            _bay_slot = int(_id_m.group(1))
    if _bay_slot is None:
        # Dell / NVMe drive Name/Id/Location with "Slot X" (e.g. "PCIe SSD in Slot 6 in Bay 1")
        _comb_str = f"{drive_json.get('Name') or ''} {drive_json.get('Id') or ''} {drive_json.get('Location') or ''}"
        _slot_m = re.search(r"[Ss]lot\s*(\d+)", _comb_str)
        if _slot_m:
            _bay_slot = int(_slot_m.group(1))
    if _bay_slot is None:
        # Dell PERC/HBA drive Name like "Solid State Disk 0:1:0" (Enclosure:Slot:Target -> middle token is slot)
        _comb_str = f"{drive_json.get('Name') or ''} {drive_json.get('Id') or ''}"
        _perc_m = re.search(r"\b\d+:(\d+):\d+\b", _comb_str)
        if _perc_m:
            _bay_slot = int(_perc_m.group(1))

    # ── EDSFF / form-factor detection ─────────────────────────────────────
    # EDSFF drives (E1.S, E3.S, E1.L) are always NVMe and can be much
    # denser than 2.5" U.2/U.3 bays.  Detect from the FormFactor field
    # (DMTF Redfish 1.12+) and common model/PartNumber substrings.
    _ff_raw = str(drive_json.get("FormFactor") or "").upper()
    _id_str = str(drive_json.get("Id") or "")
    _nm_str = str(drive_json.get("Name") or "")
    _model_probe = str(
        drive_json.get("Model") or drive_json.get("PartNumber") or ""
    ).upper()
    # FormFactor values seen in practice: "EDSFF_1U_Long", "EDSFF_1U_Short",
    # "EDSFF", "E1.S", "E3.S" (HPE), "E1.L" etc.
    _EDSFF_FF = {"EDSFF", "E1.S", "E3.S", "E1.L", "E3.L",
                 "EDSFF_1U_SHORT", "EDSFF_1U_LONG", "E1_SHORT", "E3_SHORT"}
    _EDSFF_MDL = ["E3.S", "E1.S", "E1.L", "E3.L", "EDSFF", "ESFF"]
    is_edsff = (
        any(tok in _ff_raw for tok in _EDSFF_FF)
        or any(pat.upper() in _model_probe for pat in _EDSFF_MDL)
    )
    if is_edsff:
        # Narrow down the label: prefer the most specific marker in ff field
        if "E3" in _ff_raw or "E3.S" in _model_probe or "E3.L" in _model_probe:
            form_factor_label = "E3.S"
        elif "E1" in _ff_raw or "E1.S" in _model_probe or "E1.L" in _model_probe:
            form_factor_label = "E1.S"
        else:
            form_factor_label = "EDSFF"
    elif "M.2" in _ff_raw or "M2" in _ff_raw or "NGFF" in _ff_raw or "M.2" in _model_probe or any(k in ctrl_id_up or k in ctrl_name_up for k in ["BOSS", "NS204I", "MARVELL"]):
        form_factor_label = "M.2"
    elif "2.5" in _ff_raw or "SFF" in _ff_raw:
        form_factor_label = '2.5"'
    elif "3.5" in _ff_raw or "LFF" in _ff_raw:
        form_factor_label = '3.5"'
    else:
        form_factor_label = ""

    # ── Bay position (Front / Rear / Internal) ────────────────────────────
    # Combine all textual signals that may indicate physical position.
    _service_label = str(_part_loc.get("ServiceLabel") or "").upper()
    _hpe_loc_up    = str(drive_json.get("Location") or "").upper()
    _id_up         = _id_str.upper()
    _name_up       = _nm_str.upper()
    _combined_pos  = f"{_service_label} {_name_up} {_id_up} {_hpe_loc_up}"
    if any(k in _combined_pos for k in ["REAR", "BACK BAY", "BACKBAY",
                                         "BOX 2:", "BOX 3:", "BOX2", "BOX3",
                                         "R-BAY", "RBAY"]):
        bay_position = "Rear"
    elif any(k in _combined_pos for k in ["BOSS", "M.2", "M2", "INTERNAL",
                                           "EMBEDDED", "AHCI.SLOT"]):
        bay_position = "Internal"
    else:
        bay_position = "Front"

    return {'bay_slot': _bay_slot, 'is_edsff': is_edsff, 'form_factor_label': form_factor_label, 'bay_position': bay_position, 'id': _id_str, 'raw_form_factor': _ff_raw}


def empty_drive_record(drive_json: dict, location: dict) -> Optional[dict]:
    """Retain the distinct empty-slot schema and early exit."""
    _bay_slot = location['bay_slot']
    is_edsff = location['is_edsff']
    form_factor_label = location['form_factor_label']
    bay_position = location['bay_position']
    _id_str = location['id']
    _ff_raw = location['raw_form_factor']
    # ── Absent / empty bay detection ──────────────────────────────────────
    # Dell iDRAC returns Status.State="Absent" for unpopulated drive bays.
    # Capture these as empty-slot records rather than dropping them.
    _slot_state = str((drive_json.get("Status") or {}).get("State") or "").strip()
    if _slot_state.upper() in ("ABSENT", "NOTINSTALLED", "UNAVAILABLEOFFLINE"):
        _slot_label = (
            drive_json.get("Name")
            or (f"Bay {_bay_slot}" if _bay_slot is not None else "Empty Slot")
        )
        return {
            "populated":           False,
            "bay_slot":            _bay_slot,
            "bay_position":        bay_position,
            "is_edsff":            is_edsff,
            "form_factor":         form_factor_label,
            "form_factor_label":   form_factor_label,
            "nvme_connector":      "",
            "id":                  _id_str,
            "name":                _slot_label,
            "model":               "",
            "product_id":          "",
            "media_type":          "",
            "protocol":            "",
            "serial_number":       "",
            "capacity_gb":         0,
            "firmware":            "",
            "endurance_remaining_pct": "N/A",
            "drive_health":        "",
            "temperature_c":        None,
            "power_on_hours":       None,
            "failure_predicted":   False,
            "category":            "Empty",
            "vsan_eligible":       False,
            "status_badge":        "<span style='color:var(--text-muted)'>&#9675; Empty</span>",
            "behind_trimode":      False,
            "single_lane_alert":   False,
            "pcie_lanes_in_use":   None,
            "pcie_max_lanes":      None,
            "pcie_gen":            None,
            "is_qlc":              False,
            "unsafe_shutdowns":          None,
            "media_errors":              None,
            "thermal_throttled":         None,
            "plp_capacitor_health":      None,
            "tbw_written":               None,
            "pcie_bus_errors":           None,
            "pcie_errors":               None,
            "write_amplification":       None,
            "bad_nand_blocks":           None,
            "uncorrectable_read_errors": None,
            "end_to_end_crc_errors":     None,
            "available_spare_pct":       None,
            "plp_start_count":           None,
            "security_status":           "N/A",
            "usage_role":                "N/A",
            "pending_firmware":          "N/A",
            "negotiated_speed_gbs":     None,
            "capable_speed_gbs":        None,
            "oem_metrics":              {},
        }

    return None


def resolve_drive_firmware(drive_json: dict, controller_json: Optional[dict], serial_number: str, model: str, is_nvme: bool) -> str:
    """Keep drive/controller identity checks, candidate priority and sentinel filtering."""
    # Drive Firmware version extraction with controller fallback
    candidates: List[Any] = [
        drive_json.get("Revision"),
        drive_json.get("FirmwareVersion"),
    ]
    if controller_json and isinstance(controller_json, dict):
        ctrl_sn = str(controller_json.get("SerialNumber") or "").strip()
        ctrl_model = str(controller_json.get("Model") or "").strip()
        sn_match = bool(
            ctrl_sn
            and serial_number
            and ctrl_sn.lower() not in ("not available", "none", "unknown", "n/a")
            and ctrl_sn.lower() == serial_number.lower()
        )
        model_match = bool(
            ctrl_model
            and model
            and ctrl_model.lower() not in ("not available", "none", "unknown", "n/a")
            and (ctrl_model.lower() in model.lower() or model.lower() in ctrl_model.lower())
        )
        if is_nvme or sn_match or model_match:
            candidates.append(controller_json.get("FirmwareVersion"))
            candidates.append(controller_json.get("FirmwarePackageVersion"))

    drive_fw = "N/A"
    for cand in candidates:
        extracted = _extract_fw_candidate(cand)
        if not is_invalid_drive_firmware(extracted):
            drive_fw = extracted
            break

    return drive_fw
