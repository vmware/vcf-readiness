"""Keep drive PCIe evidence separate from shared controller uplinks.

Older collectors substituted x4 behind RAID and labelled it controller-sourced.
Render those summaries conservatively without rewriting their source files.
"""
import re
from typing import Any, Dict, Optional


def _lanes(value: Any) -> Optional[int]:
    match = re.fullmatch(r"x?([1-9][0-9]*)", str(value or "").strip(), re.I)
    return int(match.group(1)) if match else None


def drive_pcie_view(drive: dict, controller: Optional[dict] = None) -> dict:
    """Return a copy with only drive-specific negotiated/capability evidence."""
    result = dict(drive)
    ctrl = controller or {}
    trimode = bool(drive.get("behind_trimode") or ctrl.get("is_trimode")
                   or drive.get("pcie_link_topology") == "tri-mode")
    raid_path = bool(trimode or drive.get("behind_software_raid") or drive.get("behind_vmd")
                     or ctrl.get("has_logical_volumes")
                     or re.search(r"RAID|PERC|SMART ARRAY|MEGARAID", str(ctrl.get("name") or ""), re.I))
    if trimode:
        result["pcie_link_topology"] = "tri-mode"
    oem = drive.get("oem_metrics") or {}
    if not isinstance(oem, dict):
        oem = {}

    def observed(field: str, source: str, legacy_source: str = "") -> Any:
        provenance = str(drive.get(source) or drive.get(legacy_source) or "").lower()
        if provenance in ("drive", "oem"):
            return drive.get(field)
        if provenance or raid_path:
            return None
        # Older direct-attached summaries have no provenance; retain their evidence.
        return drive.get(field)

    width = observed("pcie_negotiated_width", "pcie_negotiated_width_source", "pcie_lanes_source")
    lanes = _lanes(width) or _lanes(observed("pcie_lanes_in_use", "pcie_lanes_source"))
    oem_lanes = _lanes(oem.get("pcie_negotiated_width"))
    if oem_lanes and not lanes:
        lanes = oem_lanes
    maximum = _lanes(observed("pcie_capable_width", "pcie_capable_width_source", "pcie_max_lanes_source"))
    maximum = maximum or _lanes(observed("pcie_max_lanes", "pcie_max_lanes_source"))
    oem_maximum = _lanes(oem.get("pcie_capable_width"))
    if oem_maximum and not maximum:
        maximum = oem_maximum
    gen = observed("pcie_gen", "pcie_gen_source")
    result.update(pcie_lanes_in_use=lanes, pcie_max_lanes=maximum, pcie_gen=gen,
                  pcie_negotiated_width=f"x{lanes}" if lanes else None,
                  pcie_capable_width=f"x{maximum}" if maximum else None)
    boot = bool(drive.get("is_boot") or drive.get("usage_role") == "Boot Drive"
                or "boot" in str(drive.get("category") or "").lower())
    boot = boot or str(drive.get("form_factor") or "").upper() in ("M.2", "M2")
    nvme = bool(re.search(r"NVME|PCIE", str(drive.get("protocol") or ""), re.I))
    result["single_lane_alert"] = bool(nvme and lanes == 1 and not boot and not trimode)
    result["pcie_downshifted"] = bool(nvme and lanes and maximum and lanes < maximum and not boot and not trimode)
    if not result["single_lane_alert"] and drive.get("single_lane_alert"):
        result["status_badge"] = re.sub(
            r"<br>\s*<span[^>]*>[^<]*Single PCIe Lane[^<]*</span>", "",
            str(drive.get("status_badge") or ""), flags=re.I)
    return result


def storage_pcie_view(host: Dict[str, Any]) -> Dict[str, Any]:
    """Copy storage containers so rendering cannot overwrite saved link evidence."""
    result = dict(host)
    storage = host.get("storage_subsystem")
    if isinstance(storage, list):
        result["storage_subsystem"] = [
            dict(ctrl, drives=[drive_pcie_view(drive, ctrl) for drive in ctrl.get("drives") or []])
            for ctrl in storage
        ]
    return result


def drive_link_description(drive: dict) -> str:
    """Describe negotiated evidence separately from device capability."""
    evidence = drive_pcie_view(drive)
    link = " ".join(str(value) for value in
                    (evidence.get("pcie_gen"), evidence.get("pcie_negotiated_width")) if value)
    if not evidence.get("pcie_negotiated_width"):
        link = f"{link}; width not reported" if link else "Not reported"
    text = f"Drive link: {link}"
    if evidence.get("pcie_capable_width"):
        text += f" · Capability: {evidence['pcie_capable_width']}"
    return text
