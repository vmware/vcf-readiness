"""Topology-aware x2APIC advice; BIOS evidence alone is not a compatibility failure."""
from typing import Any, Dict

LEGACY_X2APIC_WARNING = (
    "BIOS: Processor x2APIC Mode is Disabled on a multi-socket / high-core server. "
    "Must be Enabled in BIOS for vSphere 9.1 interrupt scaling."
)


def x2apic_recommendation(cpu: Dict[str, Any]) -> str:
    """Keep a performance recommendation distinct from large-topology review."""
    logical = 0
    for key in ("logical_count", "threads", "logical_processor_count"):
        try:
            value = int(cpu.get(key) or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        if value > 0:
            logical = value
            break
    topology = f" ({logical} logical processors reported)" if logical else ""
    if logical >= 256:
        return (
            f"BIOS: x2APIC is disabled{topology}. Review CPU addressing and interrupt-remapping "
            "support with the server vendor before deployment; legacy xAPIC has an 8-bit APIC ID limit. "
            "The collected BIOS setting does not establish the active ESX interrupt mode."
        )
    return (
        f"BIOS: x2APIC is disabled{topology}. Consider enabling it where supported by the server vendor "
        "for interrupt-delivery performance and CPU scaling. This is a tuning recommendation, "
        "not a blanket vSphere 9 requirement; confirm the active ESX mode before changing BIOS."
    )


def refresh_x2apic_guidance(host: Dict[str, Any]) -> None:
    """Refresh recognized legacy recommendations while retaining BIOS observations."""
    cpu = (host.get("system") or {}).get("cpu_summary") or {}
    if isinstance(host.get("readiness_warnings"), list):
        host["readiness_warnings"] = [
            x2apic_recommendation(cpu) if item == LEGACY_X2APIC_WARNING else item
            for item in host["readiness_warnings"]
        ]
    for item in (host.get("bios_checks") or {}).get("cpu_power") or []:
        if not isinstance(item, dict) or item.get("feature") != "Processor x2APIC Mode":
            continue
        if item.get("note") == "Standard APIC limits interrupt delivery to 255 processors. Must be enabled on high-core-count servers.":
            item["note"] = x2apic_recommendation(cpu)
        elif item.get("note") == "Extended interrupt controller active. Required for systems with >255 logical processors.":
            item["note"] = "BIOS reports x2APIC enabled. Supports extended CPU addressing and interrupt delivery; verify the active ESX mode separately."
