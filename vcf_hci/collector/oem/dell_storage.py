"""Repair Dell SimpleStorage backplane entries misclassified as physical drives."""
import math
from typing import Any, Dict


def normalize_dell_backplanes(host: Dict[str, Any]) -> None:
    """Retain explicit backplane evidence under enclosures, never infer a healthy SSD.

    Dell SimpleStorage Devices can contain a PCIe SSD backplane with null capacity.
    Old summaries normalized that to an SSD with zero capacity. Require the explicit
    backplane name/model pair, no positive/invalid capacity and no drive protocol.
    Real NVMe drives with missing capacity remain drives and retain their findings.
    """
    if "DELL" not in str((host.get("system") or {}).get("vendor") or "").upper():
        return
    moved = set()
    for ctrl in host.get("storage_subsystem") or []:
        if not isinstance(ctrl, dict) or not isinstance(ctrl.get("drives"), list):
            continue
        retained = []
        for drive in ctrl["drives"]:
            if not isinstance(drive, dict):
                retained.append(drive)
                continue
            try:
                capacity = float(drive.get("capacity_gb") or drive.get("capacity_bytes") or 0)
            except (TypeError, ValueError, OverflowError):
                capacity = -1
            name, model = str(drive.get("name") or ""), str(drive.get("model") or "")
            explicit = name.lower().startswith("backplane ") and model.upper().startswith("PCIE SSD BP ")
            protocol = str(drive.get("protocol") or "").upper()
            if not (explicit and math.isfinite(capacity) and capacity == 0
                    and protocol in ("", "UNKNOWN", "N/A") and not drive.get("capacity_data_quality_note")):
                retained.append(drive)
                continue
            note = "Backplane reported by SimpleStorage; physical drive capacity and inventory are not established by this entry."
            enclosures = ctrl.setdefault("enclosures", [])
            if not any(e.get("name") == name and e.get("model") == model for e in enclosures if isinstance(e, dict)):
                enclosures.append({
                    "name": name, "model": model, "manufacturer": "Dell", "enclosure_type": "PCIe Backplane",
                    "serial_number": drive.get("serial_number") or "", "firmware_version": drive.get("firmware") or "",
                    "linked_ctrl_id": ctrl.get("id") or "", "linked_ctrl_name": ctrl.get("name") or "",
                    "inventory_note": note, "source_record": dict(drive),
                })
            moved.add(model)
        ctrl["drives"] = retained
    if moved and isinstance(host.get("hardware_findings"), list):
        host["hardware_findings"] = [f for f in host["hardware_findings"] if not (
            isinstance(f, dict) and f.get("tag") == "ZERO_CAPACITY_DRIVE" and f.get("detail") in moved
        )]
