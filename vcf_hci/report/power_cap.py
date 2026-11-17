"""Evidence-aware BMC power-cap presentation for saved and current host reports."""
from typing import Any, Dict, Optional

from vcf_hci.report.helpers import _h

POWER_CAP_GUIDANCE_URL = (
    "https://knowledge.broadcom.com/external/article/459067/"
    "high-vsan-latency-and-esx-host-degradati.html"
)


def normalize_power_cap_evidence(psu: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Copy PSU evidence and apply the existing saved-summary provenance rule."""
    result = dict(psu or {})
    if not result:
        return result
    evidence = str(result.get("power_limit_evidence") or "").strip()
    enforced = result.get("power_limit_enforced")
    if not evidence or evidence.casefold() == "unknown" or not isinstance(enforced, bool):
        result["power_limit_enforced"] = None
        result["power_limit_evidence"] = "Unknown"
        watts = result.get("power_limit_watts")
        threshold = f"configured ({_h(str(watts))} W)" if isinstance(watts, (int, float)) and watts > 0 else "threshold unknown"
        result["power_cap_badge"] = f"<span class='badge info'>Power cap {threshold}; enforcement unknown</span>"
    return result


def render_power_cap_review(psu: Optional[Dict[str, Any]]) -> str:
    """Render a BMC performance check without changing BIOS attribute scoring."""
    psu = normalize_power_cap_evidence(psu)
    if not psu:
        return ""
    watts = psu.get("power_limit_watts")
    threshold = f"{watts} W" if isinstance(watts, (int, float)) and watts > 0 else "Not reported"
    enforced = psu.get("power_limit_enforced")
    if enforced is True:
        tone, status = "warning", "Enforced — performance risk"
        recommendation = (
            "An enforced hardware power cap can restrict CPU frequency and increase vSAN latency under load. "
            "Review the cap with the infrastructure owner; remove restrictive caps for performance-sensitive "
            "workloads when the site's power budget permits. Enforcement alone does not prove active throttling."
        )
    elif enforced is False:
        tone, status = "success", "Enforcement disabled"
        recommendation = "The BMC explicitly reports power-cap enforcement disabled."
    else:
        tone, status = "info", "Enforcement not verified"
        recommendation = (
            "The saved telemetry does not establish whether the BMC is enforcing this power limit. "
            "Verify the enable state in the BMC before assessing throttling risk."
        )
    return (
        f"<section class='bios-power-cap-review alert alert-{tone}'>"
        "<h4>BMC power-cap performance check</h4>"
        f"<p><span class='badge {tone}'>{_h(status)}</span></p>"
        f"<p>Power limit: <strong>{_h(threshold)}</strong></p>"
        f"<p>{_h(recommendation)}</p>"
        "<p>BIOS compliance covers BIOS attributes; this additional check uses BMC power-control evidence.</p>"
        f"<p><a href='{_h(POWER_CAP_GUIDANCE_URL)}' target='_blank' rel='noopener noreferrer'>"
        "Broadcom KB 459067: hardware power caps, CPU throttling and vSAN latency</a></p>"
        "</section>"
    )
