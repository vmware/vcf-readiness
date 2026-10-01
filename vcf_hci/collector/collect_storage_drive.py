"""
VCF Readiness Tool — storage drive Redfish resource parsing.
"""
import re
from typing import Any, Optional

from vcf_hci.collector.pci_utils import extract_pci_ids_from_dict, match_pcie_cache
from vcf_hci.constants import KB_TRIMODE
from vcf_hci.hcl import detect_qlc_nvme
from vcf_hci.logging_utils import get_nested

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


def _parse_lanes(val: Any) -> Optional[int]:
    if isinstance(val, int):
        return val
    if isinstance(val, str) and val.lower().startswith("x"):
        try:
            return int(val[1:])
        except ValueError:
            pass
    return None


def parse_drive_details(
    coll: Any,
    ctrl_id: str,
    ctrl_name: str,
    drive_json: dict,
    has_logical_vols: bool = False,
    ctrl_pcie: Optional[dict] = None,
    pcie_cache: Optional[list] = None,
) -> Optional[dict]:
    """Parse a single drive Redfish resource into a normalized drive dict.

    ctrl_pcie (from _parse_ctrl_pcie) supplies controller-level PCIe info —
    lane width, generation, and the tri-mode flag.  These are augmented by
    any PCIeInterface fields present directly on the drive resource itself.
    """
    if not drive_json:
        return None

    ctrl_id_up = str(ctrl_id or "").upper()
    ctrl_name_up = str(ctrl_name or "").upper()

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

    dell_oem_raw  = get_nested(drive_json, "Oem", "Dell", "DellPhysicalDisk", default={})
    dell_oem  = dell_oem_raw if isinstance(dell_oem_raw, dict) else {}
    hpe_oem_raw   = get_nested(drive_json, "Oem", "Hpe", default={})
    hpe_oem   = hpe_oem_raw if isinstance(hpe_oem_raw, dict) else {}
    lnv_oem_raw   = get_nested(drive_json, "Oem", "Lenovo", "Drive", default={})
    lnv_oem   = lnv_oem_raw if isinstance(lnv_oem_raw, dict) else {}
    smc_oem_raw   = get_nested(drive_json, "Oem", "Supermicro", default={})
    smc_oem   = smc_oem_raw if isinstance(smc_oem_raw, dict) else {}
    cisco_oem_raw = get_nested(drive_json, "Oem", "Cisco", default={}) or get_nested(drive_json, "Oem", "CIMC", default={})
    cisco_oem = cisco_oem_raw if isinstance(cisco_oem_raw, dict) else {}
    metrics_raw = drive_json.get("Metrics")
    metrics: dict = metrics_raw if isinstance(metrics_raw, dict) else {}
    oem_metrics_raw = coll.oem_drive_metrics(drive_json) if (coll and hasattr(coll, "oem_drive_metrics")) else {}
    oem_metrics = oem_metrics_raw if isinstance(oem_metrics_raw, dict) else {}

    model = str(
        drive_json.get("Model")
        or hpe_oem.get("Model")
        or hpe_oem.get("Description")
        or hpe_oem.get("DriveName")
        or drive_json.get("PartNumber", "Unknown")
    ).strip()
    model_up = model.upper()
    drive_name = str(drive_json.get("Name") or drive_json.get("Id") or "").strip()
    drive_name_up = drive_name.upper()
    ctrl_id_up, ctrl_name_up = str(ctrl_id).upper(), str(ctrl_name).upper()

    serial_number = str(
        drive_json.get("SerialNumber")
        or dell_oem.get("SerialNumber")
        or hpe_oem.get("SerialNumber")
        or lnv_oem.get("SerialNumber")
        or ""
    ).strip()

    # Extract OEM interface / protocol fields
    oem_proto = str(
        drive_json.get("InterfaceType")
        or hpe_oem.get("InterfaceType")
        or hpe_oem.get("Protocol")
        or hpe_oem.get("DriveType")
        or dell_oem.get("BusProtocol")
        or lnv_oem.get("Protocol")
        or ""
    ).strip()

    raw_proto = (drive_json.get("Protocol") or drive_json.get("BusInfo") or "").strip()

    # Model heuristics for SAS drive families (e.g. HPE MM1000GBKAL, EG0300, AL14)
    is_sas_model = any(model_up.startswith(p) for p in ["MM", "EG", "AL", "MB", "MC", "MH"])

    if is_sas_model or ("SAS" in oem_proto.upper() and (not raw_proto or raw_proto.upper() in ("SATA", "PCIE/NVME", "UNKNOWN"))):
        raw_proto = "SAS"
    elif "SATA" in oem_proto.upper() and (not raw_proto or raw_proto.upper() in ("SAS", "PCIE/NVME", "UNKNOWN")):
        raw_proto = "SATA"
    elif not raw_proto and oem_proto:
        raw_proto = oem_proto

    media = str(drive_json.get("MediaType", "SSD")).upper()
    # Magnetic (spinning) drives have no flash-endurance metric; some BMCs
    # return 0 for RemainingRatedWriteEndurancePercent on HDDs instead of
    # null, which would otherwise render as "0%" — always force N/A.
    is_magnetic = media in ("HDD", "SMR") or is_sas_model

    if not raw_proto:
        if is_magnetic:
            raw_proto = "SAS" if is_sas_model else "SATA"
        elif drive_json.get("PCIeInterface") or "NVME" in _ff_raw or "PCIE" in _ff_raw:
            raw_proto = "PCIe/NVMe"
        else:
            raw_proto = "Unknown"

    proto = str(raw_proto).upper()
    endurance = None
    if not is_magnetic:
        endurance = drive_json.get("PredictedMediaLifeLeftPercent")
        if endurance is None and coll and hasattr(coll, "oem_drive_endurance"):
            endurance = coll.oem_drive_endurance(drive_json)
        hpe_endurance = (
            drive_json.get("SSDEnduranceUtilizationPercentage")
            if drive_json.get("SSDEnduranceUtilizationPercentage") is not None
            else hpe_oem.get("SSDEnduranceUtilizationPercentage")
        )
        if endurance is None and hpe_endurance is not None:
            try:
                endurance = 100 - int(hpe_endurance)
            except (ValueError, TypeError):
                pass
        if endurance is None:
            # Lenovo XCC: RemainingDriveLife is already a percentage remaining
            endurance = lnv_oem.get("RemainingDriveLife") or oem_metrics.get("endurance_remaining_pct")
    product_id = (drive_json.get("PartNumber")
                  or oem_metrics.get("part_number")
                  or hpe_oem.get("SparePartNumber")
                  or hpe_oem.get("OptionPartNumber")
                  or hpe_oem.get("AssemblyPartNumber")
                  or hpe_oem.get("PartNumber")
                  or dell_oem.get("DellPartNumber")
                  or dell_oem.get("PPID")
                  or dell_oem.get("PartNumber")
                  or dell_oem.get("ProductID")
                  or lnv_oem.get("PartNumber")
                  or smc_oem.get("PartNumber")
                  or cisco_oem.get("PartNumber")
                  or "N/A")
    if product_id == "N/A" and model and model not in ("Unknown", "N/A", "Unknown Drive"):
        product_id = model
    # Capacity calculation: check CapacityBytes, CapacityGB, CapacityMiB, or CapacityLogicalBlocks
    cap_bytes = drive_json.get("CapacityBytes")
    cap_gb_raw = drive_json.get("CapacityGB")
    cap_mib_raw = drive_json.get("CapacityMiB")
    if cap_bytes and isinstance(cap_bytes, (int, float)) and cap_bytes > 0:
        cap_gb = round(cap_bytes / (1024 ** 3), 2)
    elif cap_gb_raw is not None and isinstance(cap_gb_raw, (int, float)) and cap_gb_raw > 0:
        cap_gb = round(float(cap_gb_raw), 2)
    elif cap_mib_raw is not None and isinstance(cap_mib_raw, (int, float)) and cap_mib_raw > 0:
        cap_gb = round(float(cap_mib_raw) / 1024, 2)
    elif drive_json.get("CapacityLogicalBlocks") and drive_json.get("BlockSizeBytes"):
        try:
            blocks = int(drive_json["CapacityLogicalBlocks"])
            block_size = int(drive_json["BlockSizeBytes"])
            cap_gb = round((blocks * block_size) / (1024 ** 3), 2)
        except (ValueError, TypeError):
            cap_gb = 0
    else:
        cap_gb = 0

    # Fall back to drive model / name / description regex if capacity is 0 or missing
    if cap_gb <= 0:
        desc_text = f"{model} {drive_name} {drive_json.get('Description', '')} {product_id}"
        cap_m = re.search(r'(\d+(?:\.\d+)?)\s*(TB|GB)\b', desc_text, re.IGNORECASE)
        if cap_m:
            try:
                val = float(cap_m.group(1))
                unit = cap_m.group(2).upper()
                if unit == "TB":
                    cap_gb = round(val * 1000, 2)
                elif unit == "GB":
                    cap_gb = round(val, 2)
            except (ValueError, TypeError):
                pass

    is_boot = (
        bool(drive_json.get("Bootable") or drive_json.get("IsBootDisk"))
        or any(k in ctrl_id_up or k in ctrl_name_up for k in ["BOSS", "NS204I", "M.2", "AHCI.SLOT", "MARVELL", "SATADOM", "IDSDM"])
        or "MTFDDAV240TCB" in model_up
        or any(k in model_up or k in drive_name_up for k in ["BOOT", "BOSS", "NS204I", "SATADOM", "DOM", "IDSDM"])
        or ("SATA" in proto and 0 < cap_gb <= 240 and any(k in model_up or k in drive_name_up for k in ["OS", "SYS", "HYPERVISOR", "M.2"]))
    )
    _PASS_THROUGH_CTRL_PATTERNS = [
        "HBA", "NONRAID", "NON-RAID", "PASS", "CPU", "EXTENDER", "EXPANDER",
        "RETIMER", "SWITCH", "BRIDGE", "DIRECT", "AHCI", "CHIPSET", "UNMANAGED",
        "HBA3", "HBA 3", "JBOD",
    ]
    is_hba = any(k in ctrl_name_up or k in ctrl_id_up for k in _PASS_THROUGH_CTRL_PATTERNS)
    _EXPLICIT_RAID_NAMES = ["RAID", "SMART ARRAY", "MEGA", "MR", "PERC H7", "PERC H8", "PERC H9", "PERC S", "PERC FD"]
    is_raid_ctrl = (has_logical_vols or any(k in ctrl_name_up for k in _EXPLICIT_RAID_NAMES)) and not is_hba
    is_nvme = "NVME" in proto or "PCIE" in proto

    # ── PCIe topology ──────────────────────────────────────────────────────
    cp = ctrl_pcie or {}
    # Prefer per-drive PCIeInterface when the firmware exposes it
    drive_pcie_if = drive_json.get("PCIeInterface") or {}
    pcie_lanes = drive_pcie_if.get("LanesInUse") if drive_pcie_if.get("LanesInUse") is not None else cp.get("pcie_lanes_in_use")
    pcie_max   = drive_pcie_if.get("MaxLanes")   if drive_pcie_if.get("MaxLanes")   is not None else cp.get("pcie_max_lanes")
    pcie_gen   = drive_pcie_if.get("PCIeType")   or cp.get("pcie_gen")

    _is_m2 = (
        "M2" in _ff_raw or "M.2" in _ff_raw
        or any(k in ctrl_id_up or k in ctrl_name_up
               for k in ["BOSS", "NS204I", "MARVELL"])
    )

    sw_raid_names = getattr(coll, "_SOFTWARE_RAID_NAMES", _SOFTWARE_RAID_NAMES) if coll else _SOFTWARE_RAID_NAMES
    trimode_names = getattr(coll, "_TRIMODE_NAMES", _TRIMODE_NAMES) if coll else _TRIMODE_NAMES

    # Software RAID: Host/chipset CPU-assisted RAID (e.g. Dell PERC S140/S150, HPE Dynamic Smart Array)
    is_software_raid = (
        cp.get("is_software_raid", False)
        or any(p in ctrl_name_up or p in ctrl_id_up for p in sw_raid_names)
    )

    # Tri-mode: controller supports both NVMe and SAS/SATA devices.
    # Also catch via well-known name patterns when the protocol list is absent.
    is_trimode_by_proto = cp.get("is_trimode", False) and not is_software_raid
    is_trimode_by_name  = (
        any(p in ctrl_name_up for p in [t.upper() for t in trimode_names])
        and not is_software_raid
    )

    # Exclude motherboard chipset/AHCI/VMD/direct PCIe/extender/HBA/software RAID controllers from tri-mode false positives
    _NON_TRIMODE_CTRL_PATTERNS = [
        "AHCI", "SATA", "INTEL", "VMD", "CPU", "DIRECT", "CHIPSET", "ASMEDIA", "AMD", "ASROCK", "ASUS",
        "EXTENDER", "EXPANDER", "RETIMER", "SWITCH", "BRIDGE", "UNMANAGED", "HBA3", "HBA 3", "HBA330", "HBA350", "HBA355",
    ] + list(sw_raid_names)
    _is_known_non_trimode_ctrl = (
        any(p in ctrl_name_up or p in ctrl_id_up for p in _NON_TRIMODE_CTRL_PATTERNS)
        and not is_trimode_by_name
    )

    # M.2 drives and direct CPU/PCIe-attached drives on non-Tri-Mode controllers are never behind Tri-Mode RAID
    behind_trimode = (
        is_nvme and not is_boot and not _is_m2 and not is_software_raid
        and (is_trimode_by_name or (is_trimode_by_proto and not _is_known_non_trimode_ctrl))
    )
    behind_software_raid = is_nvme and not is_boot and not _is_m2 and is_software_raid

    # Do not inherit controller-level PCIe uplink lanes (e.g. x8 slot uplink on RAID controllers) onto individual drives
    if drive_pcie_if.get("LanesInUse") is None and (behind_trimode or is_raid_ctrl or cp.get("is_trimode")):
        pcie_lanes = 4 if is_nvme else None
    if drive_pcie_if.get("MaxLanes") is None and (behind_trimode or is_raid_ctrl or cp.get("is_trimode")):
        pcie_max = 4 if is_nvme else None

    # Single-lane: x1 PCIe on a non-boot NVMe drive (performance risk)
    single_lane_alert = (
        is_nvme and not is_boot
        and isinstance(pcie_lanes, int) and pcie_lanes == 1
    )

    # ── NVMe connector type (U.2 / U.3 / M.2) ────────────────────────────
    # Redfish FormFactor does NOT distinguish U.2 from U.3 — both show as
    # 2.5" SFF (SFF-8639 connector).  The difference is tri-mode capability:
    # U.3 slots can switch between NVMe, SAS, and SATA on the same connector.
    # Detection strategy (in priority order):
    #   1. EDSFF form factor → use the E3.S / E1.S / EDSFF label directly
    #   2. M.2 → from FormFactor "M2*" or controller name (BOSS, NS204I, MARVELL)
    #   3. Known U.3 model prefixes (vendor datasheets confirm SFF-8639 tri-mode)
    #   4. Behind a tri-mode HBA → U.3 backplane (drive itself may be U.2 or U.3)
    #   5. All other NVMe 2.5" → U.2 (statistically the most common deployment)
    #   SAS / SATA drives: connector type irrelevant for vSAN ESA; leave blank.
    _U3_MODEL_PREFIXES = (
        "KCD8",    # Kioxia CD8P-V / CD8 family — explicitly marketed as U.3
        "KCM6",    # Kioxia CM6-V U.3 enterprise read-optimised
        "MTFDKCC", # Micron 6500 ION U.3 (SFF-8639, tri-mode backplane)
    )
    _is_m2 = (
        "M2" in _ff_raw or "M.2" in _ff_raw
        or any(k in ctrl_id_up or k in ctrl_name_up
               for k in ["BOSS", "NS204I", "MARVELL"])
    )
    if is_edsff:
        nvme_connector = form_factor_label          # "E3.S" / "E1.S" / "EDSFF"
    elif _is_m2:
        nvme_connector = "M.2"
    elif is_nvme and not is_boot:
        if any(model_up.startswith(p) for p in _U3_MODEL_PREFIXES):
            nvme_connector = "U.3"
        elif behind_trimode:
            # Tri-mode HBA implies a U.3-capable backplane; the physical drive
            # plugged in may itself be U.2 or U.3 — label the slot, not the drive.
            nvme_connector = "U.3 slot"
        else:
            nvme_connector = "U.2"
    else:
        nvme_connector = ""

    # ── vSAN compatibility badge ───────────────────────────────────────────
    is_qlc = False  # overridden below for direct-attached NVMe only
    if is_boot:
        badge, category, vsan_ok = (
            "<span class='badge info'>⚙️ Boot Device Only (Non-vSAN)</span>",
            "Boot Device", False,
        )
    elif behind_trimode:
        badge, category, vsan_ok = (
            f"<span class='badge danger'>🔴 NOT Supported — NVMe Behind Tri-Mode RAID</span>"
            f"<br><a href='{KB_TRIMODE}' target='_blank' "
            f"style='font-size:.78rem;color:var(--danger)'>KB314305 ↗</a>",
            "Unsupported NVMe Tri-Mode", False,
        )
    elif behind_software_raid:
        badge, category, vsan_ok = (
            f"<span class='badge warning'>⚠️ Software RAID ({ctrl_name})</span>"
            f"<br><small style='font-size:.76rem;color:var(--warning)'>Bypass in BIOS (AHCI/Non-RAID) for direct vSAN ESA</small>",
            "vSAN ESA/OSA NVMe", True,
        )
    elif is_nvme and is_raid_ctrl and not is_hba and not is_software_raid:
        badge, category, vsan_ok = (
            "<span class='badge danger'>🔴 NOT Supported (NVMe Behind RAID)</span>",
            "Unsupported NVMe RAID", False,
        )
    elif any(k in model_up for k in ["OPTANE", "P4800X", "P4801X", "P5800X", "P1600X", "MEMPEK"]):
        badge, category, vsan_ok = (
            "<span class='badge danger'>🔴 Not vSAN Compatible</span>"
            "<br><span class='badge info' style='margin-top:4px;'>🔵 Memory Tiering Candidate</span>",
            "Optane Memory Tiering", False,
        )
    elif is_magnetic or "HDD" in media:
        badge, category, vsan_ok = (
            "<span class='badge' style='background:#78716c;color:#fff'>🧲 Magnetic HDD</span>",
            "Magnetic HDD", False,
        )
    elif "SAS" in proto or "SATA" in proto:
        badge, category, vsan_ok = (
            "<span class='badge warning'>🟡 vSAN OSA Only</span>",
            "vSAN OSA Only", True,
        )
    elif is_nvme:
        is_qlc = detect_qlc_nvme(model)
        if cap_gb > 0 and cap_gb < 1400:
            badge, category, vsan_ok = (
                "<span class='badge warning'>🟡 vSAN OSA Only (< 1.6TB NVMe — ESA requires ≥1.6TB)</span>",
                "vSAN OSA Only", True,
            )
        else:
            badge, category, vsan_ok = (
                "<span class='badge success'>🟢 ESA Compatible</span>",
                "vSAN ESA/OSA NVMe", True,
            )
    else:
        badge, category, vsan_ok = (
            "<span class='badge warning'>⚠️ Unknown / Unverified</span>",
            "Unknown", False,
        )

    # Append single-lane warning into the vSAN badge column
    if single_lane_alert:
        badge += (
            "<br><span class='badge danger' style='margin-top:4px;font-size:.78rem'>"
            "⚠️ Single PCIe Lane (x1) — severe performance limitation</span>"
        )

    # SMART Telemetry (20 Metrics)
    temp_c = (
        drive_json.get("TemperatureCelsius")
        or drive_json.get("CurrentTemperatureCelsius")
        or (drive_json.get("Metrics") or {}).get("TemperatureCelsius")
        or oem_metrics.get("temperature_c")
        or dell_oem.get("TemperatureCelsius")
        or hpe_oem.get("CurrentTemperatureCelsius")
        or lnv_oem.get("Temperature")
        or smc_oem.get("TemperatureCelsius")
    )
    poh = (
        drive_json.get("PowerOnHours")
        or (drive_json.get("Metrics") or {}).get("PowerOnHours")
        or oem_metrics.get("power_on_hours")
        or dell_oem.get("PowerOnHours") or dell_oem.get("OperationHours") or dell_oem.get("PowerOnHoursCount")
        or hpe_oem.get("PowerOnHours")
        or lnv_oem.get("PowerOnHours") or lnv_oem.get("OperationHours")
        or smc_oem.get("PowerOnHours") or smc_oem.get("OperationHours")
        or cisco_oem.get("PowerOnHours") or cisco_oem.get("OperationHours")
    )
    critical_warnings = (
        oem_metrics.get("critical_warnings")
        or drive_json.get("CriticalWarnings") or drive_json.get("CriticalWarningsCount")
        or metrics.get("CriticalWarnings") or metrics.get("CriticalWarningsCount")
    )

    failure_predicted = bool(
        drive_json.get("FailurePredicted")
        or (drive_json.get("Status") or {}).get("HealthRollup") in ("Critical", "Warning")
        or (drive_json.get("Status") or {}).get("Health") in ("Critical", "Warning")
        or oem_metrics.get("predictive_failure")
        or dell_oem.get("PredictiveFailure")
        or lnv_oem.get("FailurePredicted")
        or (isinstance(critical_warnings, (int, float)) and critical_warnings > 0)
    )

    unsafe_shutdowns = (
        drive_json.get("UnsafeShutdowns")
        or metrics.get("UnsafeShutdowns")
        or oem_metrics.get("unsafe_shutdowns")
        or dell_oem.get("UnsafeShutdowns") or dell_oem.get("AbruptPowerOffCount")
        or hpe_oem.get("UnsafeShutdowns")
        or lnv_oem.get("UnsafeShutdowns")
        or cisco_oem.get("UnsafeShutdowns")
    )
    media_errors = (
        drive_json.get("MediaAndDataIntegrityErrors") or drive_json.get("MediaErrors")
        or metrics.get("MediaAndDataIntegrityErrors") or metrics.get("LifeTimeErrorCount")
        or oem_metrics.get("media_errors")
        or dell_oem.get("MediaAndDataIntegrityErrors") or dell_oem.get("MediaErrorCount")
        or hpe_oem.get("UncorrectableReadErrors") or hpe_oem.get("MediaErrors")
        or lnv_oem.get("DriveErrorCount")
        or cisco_oem.get("MediaErrors")
    )
    thermal_throttled_raw = (
        drive_json.get("ThermalThrottling")
        or metrics.get("ThermalThrottling")
        or dell_oem.get("ThermalThrottled")
        or hpe_oem.get("ThermalThrottled")
    )
    thermal_throttled = None
    if thermal_throttled_raw is not None:
        if isinstance(thermal_throttled_raw, bool):
            thermal_throttled = thermal_throttled_raw
        elif isinstance(thermal_throttled_raw, (int, float)):
            thermal_throttled = thermal_throttled_raw > 0
        elif isinstance(thermal_throttled_raw, str):
            thermal_throttled = thermal_throttled_raw.lower() not in ("none", "false", "0", "unthrottled", "ok")

    plp_cap = (
        drive_json.get("CapacitorHealth") or drive_json.get("PowerLossProtectionStatus")
        or metrics.get("CapacitorHealth")
        or dell_oem.get("PowerLossProtectionStatus") or dell_oem.get("CapacitorHealth")
        or hpe_oem.get("PowerLossProtection")
    )

    tbw_val = oem_metrics.get("tbw_written")
    if tbw_val is None:
        raw_tbw = (
            drive_json.get("DataUnitsWritten") or drive_json.get("BytesWritten") or drive_json.get("LifetimeWritesBytes")
            or metrics.get("DataUnitsWritten") or metrics.get("BytesWritten")
            or dell_oem.get("DataUnitsWritten")
            or hpe_oem.get("TotalBytesWritten")
        )
        if isinstance(raw_tbw, (int, float)) and raw_tbw > 0:
            if raw_tbw > 1_000_000_000_000:
                tbw_val = round(raw_tbw / (1024 ** 4), 2)
            elif raw_tbw > 100_000_000:
                tbw_val = round((raw_tbw * 512 * 1000) / (1024 ** 4), 2)
            else:
                tbw_val = round(raw_tbw, 2)

    tbr_val = oem_metrics.get("tbr_read")
    if tbr_val is None:
        raw_tbr = (
            drive_json.get("DataUnitsRead") or drive_json.get("BytesRead") or drive_json.get("LifetimeReadsBytes")
            or metrics.get("DataUnitsRead") or metrics.get("BytesRead")
            or dell_oem.get("DataUnitsRead")
            or hpe_oem.get("TotalBytesRead")
        )
        if isinstance(raw_tbr, (int, float)) and raw_tbr > 0:
            if raw_tbr > 1_000_000_000_000:
                tbr_val = round(raw_tbr / (1024 ** 4), 2)
            elif raw_tbr > 100_000_000:
                tbr_val = round((raw_tbr * 512 * 1000) / (1024 ** 4), 2)
            else:
                tbr_val = round(raw_tbr, 2)

    power_cycles = (
        oem_metrics.get("power_cycles")
        or drive_json.get("PowerCycleCount") or drive_json.get("PowerCycles")
        or metrics.get("PowerCycles") or metrics.get("PowerCycleCount")
        or dell_oem.get("PowerCycleCount")
    )
    controller_busy_time = (
        oem_metrics.get("controller_busy_time")
        or drive_json.get("ControllerBusyTimeMinutes") or drive_json.get("ControllerBusyTime")
        or metrics.get("ControllerBusyTime") or metrics.get("ControllerBusyTimeMinutes")
    )
    controller_duty_cycle_pct = None
    if isinstance(controller_busy_time, (int, float)) and isinstance(poh, (int, float)) and poh > 0:
        controller_duty_cycle_pct = round(min(100.0, max(0.0, (float(controller_busy_time) / (float(poh) * 60.0)) * 100.0)), 1)

    host_read_commands = (
        oem_metrics.get("host_read_commands")
        or drive_json.get("HostReadCommandsCount") or drive_json.get("HostReadCommands")
        or metrics.get("HostReadCommands")
    )
    host_write_commands = (
        oem_metrics.get("host_write_commands")
        or drive_json.get("HostWriteCommandsCount") or drive_json.get("HostWriteCommands")
        or metrics.get("HostWriteCommands")
    )
    avail_spare_thresh = (
        oem_metrics.get("available_spare_threshold")
        or drive_json.get("AvailableSpareThresholdPercent") or drive_json.get("AvailableSpareThreshold")
        or metrics.get("AvailableSpareThresholdPercent") or metrics.get("AvailableSpareThreshold")
    )
    error_log_entries = (
        oem_metrics.get("error_log_entries")
        or drive_json.get("ErrorInfoCount") or drive_json.get("NumOfErrorInfoLogEntries")
        or metrics.get("NumOfErrorInfoLogEntries")
    )
    max_temp_c = (
        oem_metrics.get("max_temp_c")
        or drive_json.get("MaximumTemperatureCelsius")
        or hpe_oem.get("MaximumTemperatureCelsius")
    )

    pcie_errs = (
        drive_json.get("PCIeErrors") or drive_json.get("PCIeCorrectableErrorCount")
        or metrics.get("PCIeErrors") or metrics.get("PCIeCorrectableErrors")
        or dell_oem.get("PCIeErrors")
    )
    waf_val = (
        drive_json.get("WriteAmplificationFactor")
        or metrics.get("WriteAmplificationFactor")
    )
    bad_nand = (
        drive_json.get("BadUserNANDBlocks") or drive_json.get("BadNANDBlockCount") or drive_json.get("RetiredBlockCount")
        or metrics.get("BadNANDBlockCount")
        or dell_oem.get("BadNANDBlockCount") or dell_oem.get("RetiredBlockCount")
    )
    uncorr_reads = (
        drive_json.get("UncorrectableReadErrors")
        or metrics.get("UncorrectableReadErrors")
        or hpe_oem.get("UncorrectableReadErrors")
        or oem_metrics.get("uncorrectable_read_errors")
    )
    e2e_crc = (
        drive_json.get("EndToEndCorrectionCounts") or drive_json.get("EndToEndErrors")
        or metrics.get("EndToEndErrors")
    )
    avail_spare = (
        drive_json.get("AvailableSparePercent") or drive_json.get("PercentFreeBlocks")
        or metrics.get("AvailableSparePercent")
        or dell_oem.get("AvailableSparePercent")
        or oem_metrics.get("available_spare_pct")
    )
    plp_starts = (
        drive_json.get("PLPStartCount")
        or metrics.get("PLPStartCount")
    )
    sec_status = str(
        drive_json.get("SecurityStatus") or drive_json.get("EncryptionStatus")
        or oem_metrics.get("security_status")
        or dell_oem.get("SecurityStatus") or dell_oem.get("SecurityState") or dell_oem.get("EncryptionStatus")
        or hpe_oem.get("EncrypStatus") or hpe_oem.get("EncryptionStatus")
        or "N/A"
    ).strip()
    usage_role = str(
        drive_json.get("UsageAttribute")
        or dell_oem.get("UsageAttribute")
        or hpe_oem.get("CarrierStatus")
        or ("Boot Drive" if is_boot else "Data Drive")
    ).strip()
    pending_fw = str(
        drive_json.get("PendingFirmwareVersion")
        or dell_oem.get("ComponentStagingState")
        or hpe_oem.get("PendingFirmwareVersion")
        or "N/A"
    ).strip()

    crypto_erase_capable = bool(
        oem_metrics.get("crypto_erase_capable")
        or drive_json.get("CryptographicEraseCapable") == "Capable"
        or "crypto" in str(drive_json.get("SystemEraseCapability", "")).lower()
    )
    erase_capability = str(
        oem_metrics.get("erase_capability")
        or drive_json.get("SystemEraseCapability")
        or drive_json.get("CryptographicEraseCapable")
        or "N/A"
    ).strip()
    error_description = str(
        oem_metrics.get("error_description")
        or drive_json.get("ErrorDescription")
        or ""
    ).strip()
    if error_description.lower() in ("none", "null", "n/a"):
        error_description = ""

    pcie_cap_width = (
        oem_metrics.get("pcie_capable_width")
        or (f"x{pcie_max}" if isinstance(pcie_max, int) else None)
    )
    pcie_neg_width = (
        oem_metrics.get("pcie_negotiated_width")
        or (f"x{pcie_lanes}" if isinstance(pcie_lanes, int) else None)
    )

    n_lanes = _parse_lanes(pcie_neg_width)
    c_lanes = _parse_lanes(pcie_cap_width)
    if isinstance(n_lanes, int) and pcie_lanes is None:
        pcie_lanes = n_lanes
    if isinstance(c_lanes, int) and pcie_max is None:
        pcie_max = c_lanes

    pcie_downshifted = bool(
        is_nvme
        and not is_boot
        and not _is_m2
        and isinstance(n_lanes, int)
        and isinstance(c_lanes, int)
        and n_lanes < c_lanes
    )

    is_nvme_pcie = any(k in proto.upper() for k in ("NVME", "PCIE", "CXL"))
    if is_nvme_pcie:
        get_fn = getattr(coll, "_get", None) if coll else None
        pci_info = extract_pci_ids_from_dict(drive_json, get_fn=get_fn)
        if not pci_info["pci_quad"] and pcie_cache:
            pci_info = match_pcie_cache(drive_json, pcie_cache, get_fn=get_fn)
    else:
        pci_info = {
            "vendor_id": "",
            "device_id": "",
            "subsystem_vendor_id": "",
            "subsystem_id": "",
            "pci_quad": "",
            "pci_pair": "",
        }

    # Drive Firmware version extraction
    fw_raw = drive_json.get("Revision") or drive_json.get("FirmwareVersion")
    if isinstance(fw_raw, dict):
        # HPE SmartStorage: {"Current": {"VersionString": "HPG2"}}
        drive_fw = str(
            get_nested(fw_raw, "Current", "VersionString")
            or fw_raw.get("VersionString")
            or fw_raw.get("Version")
            or "N/A"
        ).strip()
    elif fw_raw:
        drive_fw = str(fw_raw).strip()
    else:
        drive_fw = "N/A"

    return {
        "populated":           True,
        "bay_slot":            _bay_slot,
        "bay_position":        bay_position,
        "is_edsff":            is_edsff,
        "form_factor":         form_factor_label,
        "form_factor_label":   form_factor_label,
        "nvme_connector":      nvme_connector,
        "id":                  drive_json.get("Id", "Unknown"),
        "name":                drive_json.get("Name", "Unknown Drive"),
        "model":               model,
        "product_id":      product_id,
        "media_type":      media,
        "is_magnetic":     is_magnetic,
        "protocol":        proto,
        "serial_number":   serial_number,
        "capacity_gb":     cap_gb,
        "firmware":        drive_fw,
        "endurance_remaining_pct": endurance if endurance is not None else "N/A",
        "drive_health":    (drive_json.get("Status") or {}).get("Health") or "OK",
        "temperature_c":        temp_c,
        "power_on_hours":       poh,
        "failure_predicted":   failure_predicted,
        "category":        category,
        "is_boot":         is_boot,
        "vsan_eligible":   vsan_ok,
        "status_badge":    badge,
        # PCIe topology fields
        "behind_trimode":       behind_trimode,
        "behind_software_raid": behind_software_raid,
        "single_lane_alert":    single_lane_alert,
        "pcie_lanes_in_use": pcie_lanes,
        "pcie_max_lanes":    pcie_max,
        "pcie_gen":          pcie_gen,
        "is_qlc":            is_qlc,
        "vendor_id":           pci_info["vendor_id"],
        "device_id":           pci_info["device_id"],
        "subsystem_vendor_id": pci_info["subsystem_vendor_id"],
        "subsystem_id":        pci_info["subsystem_id"],
        "pci_quad":            pci_info["pci_quad"],
        "pci_pair":            pci_info["pci_pair"],
        # 20 Extended SMART Telemetry Fields
        "unsafe_shutdowns":          unsafe_shutdowns,
        "media_errors":              media_errors,
        "thermal_throttled":         thermal_throttled,
        "plp_capacitor_health":      plp_cap,
        "tbw_written":               tbw_val,
        "tbr_read":                  tbr_val,
        "critical_warnings":         critical_warnings,
        "power_cycles":              power_cycles,
        "controller_busy_time":      controller_busy_time,
        "controller_duty_cycle_pct": controller_duty_cycle_pct,
        "host_read_commands":        host_read_commands,
        "host_write_commands":       host_write_commands,
        "available_spare_threshold": avail_spare_thresh,
        "error_log_entries":         error_log_entries,
        "max_temperature_c":         max_temp_c,
        "pcie_bus_errors":           pcie_errs,
        "write_amplification":       waf_val,
        "bad_nand_blocks":           bad_nand,
        "uncorrectable_read_errors": uncorr_reads,
        "end_to_end_crc_errors":     e2e_crc,
        "available_spare_pct":       avail_spare,
        "plp_start_count":           plp_starts,
        "security_status":           sec_status,
        "usage_role":                usage_role,
        "pending_firmware":          pending_fw,
        "negotiated_speed_gbs":     drive_json.get("NegotiatedSpeedGbs") or oem_metrics.get("link_speed"),
        "capable_speed_gbs":        drive_json.get("CapableSpeedGbs"),
        "pcie_capable_width":       pcie_cap_width,
        "pcie_negotiated_width":    pcie_neg_width,
        "pcie_downshifted":         pcie_downshifted,
        "crypto_erase_capable":     crypto_erase_capable,
        "erase_capability":         erase_capability,
        "error_description":        error_description,
        "oem_metrics":              oem_metrics,
    }


_parse_drive_details = parse_drive_details

__all__ = ["parse_drive_details", "_parse_drive_details"]
