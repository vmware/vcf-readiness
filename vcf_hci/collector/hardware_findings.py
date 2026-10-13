"""Host-level hardware findings shared by the report.

Tags are the contract names in Lab-plans-outbox/README.md.
"""
from __future__ import annotations

from typing import Any, Dict, List

TAGS = (
    "NVME_BEHIND_RAID",
    "UNKNOWN_BOOT_DEVICE",
    "UNLINKED_PCIE_DRIVE",
    "ZERO_CAPACITY_DRIVE",
    "UNKNOWN_NIC_SPEED",
)

_MGMT_TOKENS = ("IDRAC", "ILO", "BMC", "MGMT", "MANAGEMENT", "DEDICATED")


def _add(findings: List[Dict[str, str]], tag: str, section: str, detail: str) -> None:
    if any(item.get("tag") == tag and item.get("detail") == detail for item in findings):
        return
    findings.append({"tag": tag, "section": section, "detail": detail})


def _is_management(port: Dict[str, Any], adapter: Dict[str, Any]) -> bool:
    blob = " ".join(
        str(port.get(key) or "")
        for key in ("port_id", "name", "id", "description")
    )
    blob += " " + str(adapter.get("name") or "") + " " + str(adapter.get("id") or "")
    upper = blob.upper()
    return any(tok in upper for tok in _MGMT_TOKENS)


def annotate_port_contract(adapters: List[Dict[str, Any]]) -> None:
    """Fill speed_gbps, speed_source, and is_management on each port."""
    for adapter in adapters or []:
        if not isinstance(adapter, dict):
            continue
        for port in adapter.get("ports") or []:
            if not isinstance(port, dict):
                continue
            if port.get("speed_gbps") in (None, ""):
                current = port.get("current_speed_gbps")
                try:
                    port["speed_gbps"] = float(current or 0)
                except (TypeError, ValueError):
                    port["speed_gbps"] = 0.0
            if not port.get("speed_source"):
                if float(port.get("speed_gbps") or 0) > 0 and str(port.get("link_status") or "").lower() == "up":
                    port["speed_source"] = "current_speed_gbps"
                else:
                    port["speed_source"] = "unreported"
            if "is_management" not in port:
                port["is_management"] = _is_management(port, adapter)


def annotate_hardware_findings(host: Dict[str, Any]) -> List[Dict[str, str]]:
    """Write hardware_findings on the host dict and return the list."""
    findings: List[Dict[str, str]] = []
    system = host.get("system") if isinstance(host.get("system"), dict) else {}
    boot = str(system.get("boot_target") or system.get("persistent_boot_target") or "").strip()
    if not boot or boot.lower().startswith("none"):
        _add(findings, "UNKNOWN_BOOT_DEVICE", "boot", "persistent UEFI target missing")

    data_speeds = []
    for adapter in host.get("network_adapters") or []:
        if not isinstance(adapter, dict) or adapter.get("_license_blocked"):
            continue
        annotate_port_contract([adapter])
        for port in adapter.get("ports") or []:
            if not isinstance(port, dict) or port.get("is_management"):
                continue
            try:
                data_speeds.append(float(port.get("speed_gbps") or 0))
            except (TypeError, ValueError):
                data_speeds.append(0.0)
    if data_speeds and max(data_speeds) <= 0:
        _add(findings, "UNKNOWN_NIC_SPEED", "network", "no data-port speed was reported")

    for ctrl in host.get("storage_subsystem") or []:
        if not isinstance(ctrl, dict):
            continue
        name = str(ctrl.get("name") or ctrl.get("controller_name") or "")
        drives = ctrl.get("drives") or []
        raid = "RAID" in name.upper()
        for drive in drives:
            if not isinstance(drive, dict):
                continue
            protocol = str(drive.get("protocol") or "").upper()
            if raid and "NVME" in protocol:
                _add(findings, "NVME_BEHIND_RAID", "storage", f"NVMe drive on {name or 'RAID controller'}")
            try:
                capacity = float(drive.get("capacity_gb") or drive.get("capacity_bytes") or 0)
            except (TypeError, ValueError):
                capacity = 0.0
            if capacity <= 0 and drive.get("model"):
                _add(findings, "ZERO_CAPACITY_DRIVE", "storage", str(drive.get("model")))
            if "NVME" in protocol and not (drive.get("controller") or ctrl.get("name")):
                _add(findings, "UNLINKED_PCIE_DRIVE", "storage", str(drive.get("model") or drive.get("id") or "NVMe"))

    host["hardware_findings"] = findings
    return findings
