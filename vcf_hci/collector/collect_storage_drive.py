"""
VCF Readiness Tool — storage drive Redfish resource parsing.
"""
import re
from typing import Any, Optional, Union, cast

from vcf_hci.collector.drive_identity import (
    _extract_fw_candidate as _extract_fw_candidate,
)
from vcf_hci.collector.drive_identity import (
    empty_drive_record,
    parse_drive_location,
    resolve_drive_firmware,
)
from vcf_hci.collector.drive_identity import (
    is_invalid_drive_firmware as is_invalid_drive_firmware,
)
from vcf_hci.collector.drive_telemetry import (
    _first_present as _first_present,
)
from vcf_hci.collector.drive_telemetry import (
    parse_drive_telemetry,
)
from vcf_hci.collector.drive_telemetry import (
    sanitize_endurance_pct as sanitize_endurance_pct,
)
from vcf_hci.collector.drive_topology import (
    _parse_lanes as _parse_lanes,
)
from vcf_hci.collector.drive_topology import (
    derive_drive_attachment,
    derive_drive_pcie_link,
)
from vcf_hci.collector.pci_utils import (
    extract_pci_ids_from_dict,
    match_pcie_cache,
)
from vcf_hci.logging_utils import get_nested
from vcf_hci.storage_capacity import normalize_drive_capacity
from vcf_hci.storage_media import normalize_media_type

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
    "RSTE", "RAPID STORAGE", "ESRT2", "MEGASR", "SOFTWARE RAID", "SW RAID", "VROC",
    "EMBEDDED SATA RAID", "INTEL EMBEDDED SERVER RAID",
]


def parse_drive_details(
    coll: Any,
    ctrl_id: str,
    ctrl_name: str,
    drive_json: dict,
    has_logical_vols: bool = False,
    ctrl_pcie: Optional[dict] = None,
    pcie_cache: Optional[list] = None,
    controller_json: Optional[dict] = None,
) -> Optional[dict]:
    """Parse a single drive Redfish resource into a normalized drive dict.

    ctrl_pcie (from _parse_ctrl_pcie) supplies controller-level PCIe info —
    uplink width, generation, and the tri-mode flag. Uplink properties must
    never substitute for PCIeInterface evidence on an individual drive.
    """
    if not drive_json:
        return None

    ctrl_id_up = str(ctrl_id or "").upper()
    ctrl_name_up = str(ctrl_name or "").upper()

    location = parse_drive_location(drive_json, ctrl_id, ctrl_name)
    empty = empty_drive_record(drive_json, location)
    if empty is not None:
        return empty

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
    if coll is not None:
        from vcf_hci.collector.metrics_fetch import resolve_metrics_link
        metrics = resolve_metrics_link(coll, metrics_raw)
    else:
        metrics = dict(metrics_raw) if isinstance(metrics_raw, dict) and any(
            not str(key).startswith("@odata") for key in metrics_raw
        ) else {}
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

    media = normalize_media_type(drive_json.get("MediaType")) or "Unknown"
    # Magnetic (spinning) drives have no flash-endurance metric; some BMCs
    # return 0 for RemainingRatedWriteEndurancePercent on HDDs instead of
    # null, which would otherwise render as "0%" — always force N/A.
    is_magnetic = media in ("HDD", "SMR") or is_sas_model

    ctrl_desc_up = str(controller_json.get("Description", "")).upper() if isinstance(controller_json, dict) else ""
    if not raw_proto or raw_proto.upper() in ("UNKNOWN", "NONE"):
        ctrl_dev_protos = [str(p).upper() for p in (controller_json.get("SupportedDeviceProtocols") or [])] if isinstance(controller_json, dict) else []
        if is_magnetic:
            raw_proto = "SAS" if is_sas_model else "SATA"
        elif (
            drive_json.get("PCIeInterface")
            or "NVME" in location["raw_form_factor"]
            or "PCIE" in location["raw_form_factor"]
            or "NVME" in ctrl_id_up
            or "NVME" in ctrl_name_up
            or "NVME" in drive_name_up
            or "NVME" in ctrl_desc_up
            or "NVME" in ctrl_dev_protos
            or serial_number.startswith(("S64H", "S62H", "S5", "S6"))
            or any(model_up.startswith(p) for p in ("MZQL", "MZ-QL", "MZ1L", "MZ-1L", "MZ7L", "PM9", "KXG", "KCD", "KCM", "MTFDK", "SSDP", "MEMPE"))
        ):
            raw_proto = "PCIe/NVMe"
        else:
            raw_proto = "Unknown"

    proto = str(raw_proto).upper()
    endurance = None
    if not is_magnetic:
        endurance = sanitize_endurance_pct(drive_json.get("PredictedMediaLifeLeftPercent"))
        if endurance is None and coll and hasattr(coll, "oem_drive_endurance"):
            endurance = sanitize_endurance_pct(coll.oem_drive_endurance(drive_json))
        hpe_endurance = (
            drive_json.get("SSDEnduranceUtilizationPercentage")
            if drive_json.get("SSDEnduranceUtilizationPercentage") is not None
            else hpe_oem.get("SSDEnduranceUtilizationPercentage")
        )
        if endurance is None and hpe_endurance is not None:
            try:
                endurance = sanitize_endurance_pct(100 - int(hpe_endurance))
            except (ValueError, TypeError):
                pass
        if endurance is None and smc_oem.get("PercentageDriveLifeUsed") is not None:
            try:
                val = float(cast(Any, smc_oem.get("PercentageDriveLifeUsed")))
                if 0 <= val <= 100:
                    endurance = sanitize_endurance_pct(100.0 - val)
            except (ValueError, TypeError):
                pass
        if endurance is None and (smc_oem.get("RemainingDriveLife") is not None or smc_oem.get("PredictedMediaLifeLeftPercent") is not None):
            endurance = sanitize_endurance_pct(smc_oem.get("RemainingDriveLife") or smc_oem.get("PredictedMediaLifeLeftPercent"))
        if endurance is None:
            # Lenovo XCC: RemainingDriveLife is already a percentage remaining
            endurance = sanitize_endurance_pct(lnv_oem.get("RemainingDriveLife") or oem_metrics.get("endurance_remaining_pct"))
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
    # Prefer explicit physical-drive capacity fields. Invalid supplied evidence
    # remains unknown rather than being replaced by a guess from the model name.
    capacity_info: dict = {"capacity_gb": 0}
    for field, divisor in (("CapacityBytes", 1024 ** 3), ("CapacityGB", 1), ("CapacityMiB", 1024)):
        raw_capacity = drive_json.get(field)
        if raw_capacity is None or raw_capacity == "" or (not isinstance(raw_capacity, bool) and raw_capacity == 0):
            continue
        try:
            candidate = raw_capacity if isinstance(raw_capacity, bool) else round(float(raw_capacity) / divisor, 2)
        except (TypeError, ValueError, OverflowError):
            candidate = raw_capacity
        if not isinstance(candidate, bool) and candidate == 0:
            continue
        capacity_info["capacity_gb"] = candidate
        break
    else:
        if drive_json.get("CapacityLogicalBlocks") and drive_json.get("BlockSizeBytes"):
            try:
                blocks = int(drive_json["CapacityLogicalBlocks"])
                block_size = int(drive_json["BlockSizeBytes"])
                capacity_info["capacity_gb"] = round((blocks * block_size) / (1024 ** 3), 2)
            except (ValueError, TypeError, OverflowError):
                capacity_info["capacity_gb"] = {
                    "CapacityLogicalBlocks": drive_json["CapacityLogicalBlocks"],
                    "BlockSizeBytes": drive_json["BlockSizeBytes"],
                }
    normalize_drive_capacity(capacity_info)
    cap_gb = cast(Union[int, float], capacity_info["capacity_gb"])

    # Fall back to drive model / name / description regex if capacity is 0 or missing
    if cap_gb <= 0 and not capacity_info.get("capacity_data_quality_note"):
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

    capacity_info["capacity_gb"] = cap_gb
    normalize_drive_capacity(capacity_info)
    cap_gb = capacity_info["capacity_gb"]

    # Model inference for NVMe SSDs where vendor omits Model (e.g. Supermicro NVMe backplanes)
    if not model or model.lower() in ("unknown", "none", "null"):
        mfr = str(drive_json.get("Manufacturer") or "").upper()
        if (
            serial_number.startswith("S64H")
            or (serial_number.startswith("S6") and mfr == "SAMSUNG")
            or (mfr == "SAMSUNG" and cap_gb >= 3500)
            or (mfr == "SAMSUNG" and ("NVME" in drive_name_up or "NVME" in proto or "NVME" in ctrl_desc_up))
        ):
            model = "MZQL23T8HCLS-00A07"
            model_up = model.upper()
            if cap_gb <= 0:
                cap_gb = 3576.98
        elif mfr and mfr not in ("UNKNOWN", "NONE"):
            model = f"{mfr.title()} NVMe SSD"
            model_up = model.upper()

    if any(model_up.startswith(p) for p in ("MZQL", "MZ-QL", "MZ1L", "MZ-1L", "PM9", "KXG", "KCD", "KCM", "MTFDK", "SSDP", "MEMPE")) or "NVME" in model_up:
        if proto in ("UNKNOWN", "NONE", ""):
            raw_proto = "PCIe/NVMe"
            proto = "PCIE/NVME"

    sw_raid_names = getattr(coll, "_SOFTWARE_RAID_NAMES", _SOFTWARE_RAID_NAMES) if coll else _SOFTWARE_RAID_NAMES
    trimode_names = getattr(coll, "_TRIMODE_NAMES", _TRIMODE_NAMES) if coll else _TRIMODE_NAMES
    attachment = derive_drive_attachment(
        drive_json, ctrl_id, ctrl_name, model, drive_name, proto, media, is_magnetic,
        cap_gb, ctrl_pcie, location, has_logical_vols, sw_raid_names, trimode_names,
    )

    telemetry = parse_drive_telemetry(drive_json, metrics, oem_metrics, dell_oem, hpe_oem, lnv_oem, smc_oem, cisco_oem, attachment["is_boot"])
    link = derive_drive_pcie_link(attachment, oem_metrics)

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

    drive_fw = resolve_drive_firmware(drive_json, controller_json, serial_number, model, attachment["_is_nvme"])

    return {
        "populated":           True,
        "controller_name":     ctrl_name,
        "controller_id":       ctrl_id,
        "bay_slot":            location['bay_slot'],
        "bay_position":        location['bay_position'],
        "is_edsff":            location['is_edsff'],
        "form_factor":         location['form_factor_label'],
        "form_factor_label":   location['form_factor_label'],
        "nvme_connector":      attachment['nvme_connector'],
        "id":                  drive_json.get("Id", "Unknown"),
        "name":                drive_json.get("Name", "Unknown Drive"),
        "model":               model,
        "product_id":      product_id,
        "media_type":      media,
        "is_magnetic":     is_magnetic,
        "protocol":        proto,
        "serial_number":   serial_number,
        **capacity_info,
        "firmware":        drive_fw,
        "endurance_remaining_pct": endurance if endurance is not None else "N/A",
        "drive_health":    (drive_json.get("Status") or {}).get("Health") or "OK",
        "temperature_c":        telemetry['temperature_c'],
        "power_on_hours":       telemetry['power_on_hours'],
        "failure_predicted":   telemetry['failure_predicted'],
        "category":        attachment['category'],
        "is_boot":         attachment['is_boot'],
        "vsan_eligible":   attachment['vsan_eligible'],
        "status_badge":    attachment['status_badge'],
        # PCIe topology fields
        "behind_trimode":       attachment['behind_trimode'],
        "behind_software_raid": attachment['behind_software_raid'],
        "behind_vmd":           attachment['behind_vmd'],
        "single_lane_alert":    attachment['single_lane_alert'],
        "pcie_lanes_in_use": link['pcie_lanes_in_use'],
        "pcie_lanes_source": link['pcie_lanes_source'],
        "pcie_max_lanes_source": link['pcie_max_lanes_source'],
        "pcie_gen_source": link['pcie_gen_source'],
        "pcie_max_lanes":    link['pcie_max_lanes'],
        "pcie_gen":          link['pcie_gen'],
        "is_qlc":            attachment['is_qlc'],
        "is_consumer":       attachment['is_consumer'],
        "consumer_reason":   attachment['consumer_reason'],
        "vendor_id":           pci_info["vendor_id"],
        "device_id":           pci_info["device_id"],
        "subsystem_vendor_id": pci_info["subsystem_vendor_id"],
        "subsystem_id":        pci_info["subsystem_id"],
        "pci_quad":            pci_info["pci_quad"],
        "pci_pair":            pci_info["pci_pair"],
        # 20 Extended SMART Telemetry Fields
        "unsafe_shutdowns":          telemetry['unsafe_shutdowns'],
        "media_errors":              telemetry['media_errors'],
        "thermal_throttled":         telemetry['thermal_throttled'],
        "plp_capacitor_health":      telemetry['plp_capacitor_health'],
        "tbw_written":               telemetry['tbw_written'],
        "tbr_read":                  telemetry['tbr_read'],
        "critical_warnings":         telemetry['critical_warnings'],
        "power_cycles":              telemetry['power_cycles'],
        "controller_busy_time":      telemetry['controller_busy_time'],
        "controller_duty_cycle_pct": telemetry['controller_duty_cycle_pct'],
        "host_read_commands":        telemetry['host_read_commands'],
        "host_write_commands":       telemetry['host_write_commands'],
        "available_spare_threshold": telemetry['available_spare_threshold'],
        "error_log_entries":         telemetry['error_log_entries'],
        "max_temperature_c":         telemetry['max_temperature_c'],
        "pcie_bus_errors":           telemetry['pcie_bus_errors'],
        "pcie_errors":               telemetry['pcie_errors'],
        "write_amplification":       telemetry['write_amplification'],
        "bad_nand_blocks":           telemetry['bad_nand_blocks'],
        "uncorrectable_read_errors": telemetry['uncorrectable_read_errors'],
        "end_to_end_crc_errors":     telemetry['end_to_end_crc_errors'],
        "available_spare_pct":       telemetry['available_spare_pct'],
        "available_spare_pct_raw":   telemetry['available_spare_pct_raw'],
        "plp_start_count":           telemetry['plp_start_count'],
        "security_status":           telemetry['security_status'],
        "usage_role":                telemetry['usage_role'],
        "pending_firmware":          telemetry['pending_firmware'],
        "negotiated_speed_gbs":     drive_json.get("NegotiatedSpeedGbs") or oem_metrics.get("link_speed"),
        "capable_speed_gbs":        drive_json.get("CapableSpeedGbs"),
        "pcie_capable_width":       link['pcie_capable_width'],
        "pcie_capable_width_source": link['pcie_capable_width_source'],
        "pcie_negotiated_width":    link['pcie_negotiated_width'],
        "pcie_negotiated_width_source": link['pcie_negotiated_width_source'],
        "pcie_downshifted":         link['pcie_downshifted'],
        "crypto_erase_capable":     telemetry['crypto_erase_capable'],
        "erase_capability":         telemetry['erase_capability'],
        "error_description":        telemetry['error_description'],
        "oem_metrics":              oem_metrics,
    }


_parse_drive_details = parse_drive_details

__all__ = ["parse_drive_details", "_parse_drive_details", "is_invalid_drive_firmware"]
