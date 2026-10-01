"""Cross-host BMC Security Scoring & Rollup Module.

Defines deterministic, pure-function scoring aggregations for BMC security audit findings
across individual hosts and fleets.

Guarantees:
- Pure stdlib implementation (Python 3.9+ compatible).
- Zero secret retention.
- Honesty rule: Unknown never counts as pass; high unknown counts yield "Partially Assessed".
- Excludes OUT_OF_SCOPE_FLEET assets (e.g. LXCA, UCSM/FI) from host denominator calculations.
- Deterministic, stable ordering and outputs.
"""

from typing import Any, Dict, List, Set

# Fleet managers that are explicitly out-of-scope for host BMC scoring
OUT_OF_SCOPE_FLEET_MANAGERS: Set[str] = {
    "lxca",
    "lenovo xclarity administrator",
    "ucsm",
    "cisco ucs manager",
    "intersight",
    "oneview",
    "hpe oneview",
}

# Posture classifications
POSTURE_BASELINE_MET = "Baseline Met"
POSTURE_PARTIALLY_ASSESSED = "Partially Assessed"
POSTURE_ACTION_REQUIRED = "Action Required"
POSTURE_NOT_ASSESSED = "Not Assessed"


def is_fleet_manager_asset(host_data: Dict[str, Any]) -> bool:
    """Check if a host dictionary represents a central fleet management appliance rather than a server BMC.

    Checks system model, vendor, and asset metadata against known central managers
    (LXCA, UCSM, Intersight, OneView) per G-LXCA-SCOPE and G-UCSM-SCOPE rules.
    """
    if not isinstance(host_data, dict):
        return False

    system = host_data.get("system") or {}
    model = str(system.get("model") or "").lower()
    vendor = str(system.get("vendor") or "").lower()
    role = str(host_data.get("role") or system.get("role") or "").lower()
    device_type = str(host_data.get("device_type") or system.get("device_type") or "").lower()

    if any(mgr in model for mgr in OUT_OF_SCOPE_FLEET_MANAGERS):
        return True
    if any(mgr in role for mgr in OUT_OF_SCOPE_FLEET_MANAGERS):
        return True
    if any(mgr in device_type for mgr in ("fleet_manager", "central_manager", "management_plane")):
        return True
    return bool("cisco" in vendor and ("ucs manager" in model or "fi" in model or "fabric interconnect" in model))


def score_host_security(host_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate deterministic security audit score and status counts for a single host.

    Args:
        host_data: Single host scan dictionary, expected to contain 'bmc_security_audit'.

    Returns:
        Dictionary with:
          - is_fleet_manager: bool (True if excluded from host denominators)
          - assessed: bool (True if audit findings exist)
          - pass_count: int
          - fail_count: int
          - unknown_count: int
          - na_count: int
          - total_controls: int
          - compliance_pct: float (0.0 to 100.0, evaluated as pass / (pass + fail) if pass+fail > 0 else 0.0)
          - coverage_pct: float (0.0 to 100.0, evaluated as (pass + fail) / (total - na) if total - na > 0 else 0.0)
          - posture: str ('Baseline Met', 'Partially Assessed', 'Action Required', 'Not Assessed')
    """
    if is_fleet_manager_asset(host_data):
        return {
            "is_fleet_manager": True,
            "assessed": False,
            "pass_count": 0,
            "fail_count": 0,
            "unknown_count": 0,
            "na_count": 0,
            "total_controls": 0,
            "compliance_pct": 0.0,
            "coverage_pct": 0.0,
            "posture": POSTURE_NOT_ASSESSED,
            "reason": "OUT_OF_SCOPE_FLEET: Central fleet orchestrator excluded from host BMC scoring",
        }

    audit = host_data.get("bmc_security_audit")
    if not isinstance(audit, dict):
        return {
            "is_fleet_manager": False,
            "assessed": False,
            "pass_count": 0,
            "fail_count": 0,
            "unknown_count": 0,
            "na_count": 0,
            "total_controls": 0,
            "compliance_pct": 0.0,
            "coverage_pct": 0.0,
            "posture": POSTURE_NOT_ASSESSED,
            "reason": "No BMC security audit evaluated",
        }

    summary = audit.get("summary") or {}
    findings = audit.get("findings") or []

    if findings and (not summary or "total" not in summary):
        p_cnt = sum(1 for f in findings if f.get("status") == "pass")
        f_cnt = sum(1 for f in findings if f.get("status") == "fail")
        na_cnt = sum(1 for f in findings if f.get("status") == "not_applicable")
        u_cnt = sum(1 for f in findings if str(f.get("status", "")).startswith("unknown"))
        tot = len(findings)
    else:
        p_cnt = int(summary.get("pass", 0))
        f_cnt = int(summary.get("fail", 0))
        u_cnt = int(summary.get("unknown", 0))
        na_cnt = int(summary.get("not_applicable", 0))
        tot = int(summary.get("total", len(findings)))

    if tot == 0:
        return {
            "is_fleet_manager": False,
            "assessed": False,
            "pass_count": 0,
            "fail_count": 0,
            "unknown_count": 0,
            "na_count": 0,
            "total_controls": 0,
            "compliance_pct": 0.0,
            "coverage_pct": 0.0,
            "posture": POSTURE_NOT_ASSESSED,
            "reason": "Zero audit findings evaluated",
        }

    # Strict compliance %: pass / (pass + fail) if any determinate findings exist
    determinate = p_cnt + f_cnt
    compliance_pct = round((p_cnt / determinate) * 100.0, 1) if determinate > 0 else 0.0

    # Coverage %: (pass + fail) / (total - not_applicable)
    applicable = tot - na_cnt
    coverage_pct = round((determinate / applicable) * 100.0, 1) if applicable > 0 else 0.0

    # Posture classification rule:
    # 1. Any fails -> Action Required
    # 2. No fails, but unknowns exist -> Partially Assessed (NEVER Baseline Met)
    # 3. No fails, no unknowns, pass > 0 -> Baseline Met
    if f_cnt > 0:
        posture = POSTURE_ACTION_REQUIRED
    elif u_cnt > 0:
        posture = POSTURE_PARTIALLY_ASSESSED
    elif p_cnt > 0:
        posture = POSTURE_BASELINE_MET
    else:
        posture = POSTURE_NOT_ASSESSED

    return {
        "is_fleet_manager": False,
        "assessed": True,
        "pass_count": p_cnt,
        "fail_count": f_cnt,
        "unknown_count": u_cnt,
        "na_count": na_cnt,
        "total_controls": tot,
        "compliance_pct": compliance_pct,
        "coverage_pct": coverage_pct,
        "posture": posture,
    }


def aggregate_fleet_security(all_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate cross-host security statistics across a fleet of scan results.

    Filters out OUT_OF_SCOPE_FLEET assets (e.g. LXCA, UCSM).
    Returns pure numeric summaries, posture breakdowns, and per-host summaries.

    Args:
        all_results: List of host scan dictionaries.

    Returns:
        Dictionary containing:
          - total_hosts: int (all scanned items)
          - eligible_hosts: int (hosts excluding central fleet managers)
          - excluded_fleet_managers: int
          - assessed_hosts: int (eligible hosts with an audit)
          - baseline_met_hosts: int
          - partially_assessed_hosts: int
          - action_required_hosts: int
          - not_assessed_hosts: int
          - total_passes: int
          - total_fails: int
          - total_unknowns: int
          - total_nas: int
          - fleet_compliance_pct: float
          - host_scores: List[Dict[str, Any]] (in same order as input)
    """
    total_hosts = len(all_results)
    eligible_hosts = 0
    excluded_managers = 0
    assessed_hosts = 0

    baseline_met = 0
    partially_assessed = 0
    action_required = 0
    not_assessed = 0

    total_passes = 0
    total_fails = 0
    total_unknowns = 0
    total_nas = 0

    host_scores = []

    for host in all_results:
        score = score_host_security(host)
        host_scores.append(score)

        if score["is_fleet_manager"]:
            excluded_managers += 1
            continue

        eligible_hosts += 1
        if not score["assessed"]:
            not_assessed += 1
            continue

        assessed_hosts += 1
        total_passes += score["pass_count"]
        total_fails += score["fail_count"]
        total_unknowns += score["unknown_count"]
        total_nas += score["na_count"]

        posture = score["posture"]
        if posture == POSTURE_BASELINE_MET:
            baseline_met += 1
        elif posture == POSTURE_PARTIALLY_ASSESSED:
            partially_assessed += 1
        elif posture == POSTURE_ACTION_REQUIRED:
            action_required += 1
        else:
            not_assessed += 1

    total_determinate = total_passes + total_fails
    fleet_compliance_pct = (
        round((total_passes / total_determinate) * 100.0, 1)
        if total_determinate > 0
        else 0.0
    )

    return {
        "total_hosts": total_hosts,
        "eligible_hosts": eligible_hosts,
        "excluded_fleet_managers": excluded_managers,
        "assessed_hosts": assessed_hosts,
        "baseline_met_hosts": baseline_met,
        "partially_assessed_hosts": partially_assessed,
        "action_required_hosts": action_required,
        "not_assessed_hosts": not_assessed,
        "total_passes": total_passes,
        "total_fails": total_fails,
        "total_unknowns": total_unknowns,
        "total_nas": total_nas,
        "fleet_compliance_pct": fleet_compliance_pct,
        "host_scores": host_scores,
    }
