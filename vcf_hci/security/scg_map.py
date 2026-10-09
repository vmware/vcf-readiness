"""SCG ID ↔ internal control ID mapping for Avenue 1 Salt / audit API.

Maps VMware Cloud Foundation Security Configuration Guide (SCG 9.1)
hardware-management control IDs to the internal C01–C59 catalog used by
vcf_hci.security evaluators.

Profiles:
  - scg8: the eight public SCG BMC controls
  - full84: all C/O/I controls returned by the evaluator
  - custom: caller-supplied SCG or C-IDs
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

# SCG ID → ordered primary internal control IDs contributing to the SCG outcome.
SCG_TO_CONTROLS: Dict[str, List[str]] = {
    "esx-9.hardware-management-tls": ["C01", "C02", "C03", "C04"],
    "esx-9.hardware-management-certificates": ["C05", "C44", "C45"],
    "esx-9.hardware-management-ssh-cryptography": ["C09", "C11"],
    "esx-9.hardware-management-security": ["C21", "C23", "C24", "C37", "C20", "C22"],
    "esx-9.hardware-management-authentication": ["C43"],
    "esx-9.hardware-management-time": ["C28"],
    "esx-9.hardware-management-log-forwarding": ["C07"],
    "esx-9.hardware-secureboot": ["C53", "C54"],
}

SCG8_IDS: List[str] = list(SCG_TO_CONTROLS.keys())

# Status priority when rolling C-findings up to one SCG outcome (worst wins among
# determinate results; unknowns preserved when no fail).
_STATUS_RANK = {
    "fail": 100,
    "unknown_ambiguous": 80,
    "unknown_insufficient_privilege": 70,
    "unknown_unlicensed": 65,
    "unknown_unsupported": 60,
    "unknown_write_only": 55,
    "unknown_not_exposed": 50,
    "unknown_not_collected": 45,
    "pass": 20,
    "not_applicable": 10,
}


def profile_control_ids(profile: str = "scg8") -> List[str]:
    """Return ordered internal control IDs for a named profile."""
    p = (profile or "scg8").strip().lower()
    if p in ("scg8", "scg", "scg-8"):
        seen: Set[str] = set()
        ordered: List[str] = []
        for scg_id in SCG8_IDS:
            for cid in SCG_TO_CONTROLS[scg_id]:
                if cid not in seen:
                    seen.add(cid)
                    ordered.append(cid)
        return ordered
    if p in ("full84", "full", "all", "c84"):
        # Caller should use evaluator output as-is; empty means "no filter".
        return []
    return profile_control_ids("scg8")


def filter_findings_by_profile(
    findings: Sequence[Dict[str, Any]],
    profile: str = "scg8",
    control_ids: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Filter C/O/I findings by profile or explicit control_ids."""
    if control_ids:
        wanted = {str(c).strip() for c in control_ids if str(c).strip()}
        # Allow SCG IDs in control_ids — expand them.
        expanded: Set[str] = set()
        for item in wanted:
            if item in SCG_TO_CONTROLS:
                expanded.update(SCG_TO_CONTROLS[item])
            else:
                expanded.add(item)
        return [f for f in findings if f.get("control_id") in expanded]

    ids = profile_control_ids(profile)
    if not ids:
        return list(findings)
    wanted_set = set(ids)
    return [f for f in findings if f.get("control_id") in wanted_set]


def _pick_status(statuses: List[str]) -> str:
    if not statuses:
        return "unknown_not_exposed"
    # Prefer fail if any
    if "fail" in statuses:
        return "fail"
    # If any real pass and no unknown → pass; else worst unknown
    unknowns = [s for s in statuses if str(s).startswith("unknown")]
    determinate = [s for s in statuses if s in ("pass", "not_applicable")]
    if unknowns:
        return max(unknowns, key=lambda s: _STATUS_RANK.get(s, 0))
    if "pass" in determinate:
        return "pass"
    if "not_applicable" in determinate and len(determinate) == len(statuses):
        return "not_applicable"
    return statuses[0]


def findings_to_scg(
    findings: Sequence[Dict[str, Any]],
    scg_ids: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Roll internal findings up to SCG-normalized finding objects.

    Each result includes:
      scg_id, status, contributing_controls, expected, observed, reason_code
    """
    by_id: Dict[str, Dict[str, Any]] = {
        str(f.get("control_id")): f for f in findings if f.get("control_id")
    }
    targets = list(scg_ids) if scg_ids else list(SCG8_IDS)
    results: List[Dict[str, Any]] = []

    for scg_id in targets:
        cids = SCG_TO_CONTROLS.get(scg_id, [])
        contrib = []
        statuses: List[str] = []
        for cid in cids:
            f = by_id.get(cid)
            if not f:
                continue
            contrib.append({
                "control_id": cid,
                "status": f.get("status"),
                "observed": f.get("observed"),
                "expected": f.get("expected"),
                "reason_code": f.get("reason_code"),
            })
            if f.get("status"):
                statuses.append(str(f["status"]))

        if not contrib:
            results.append({
                "scg_id": scg_id,
                "status": "unknown_not_exposed",
                "expected": "Assessed via contributing controls",
                "observed": None,
                "reason_code": "PROPERTY_NOT_EXPOSED",
                "contributing_controls": [],
            })
            continue

        status = _pick_status(statuses)
        # Find matching contributing control for the chosen rolled-up status
        matching_contrib = next((c for c in contrib if c.get("status") == status and c.get("observed") is not None), None)
        narrative_src = matching_contrib if matching_contrib else contrib[0]
        results.append({
            "scg_id": scg_id,
            "status": status,
            "expected": narrative_src.get("expected"),
            "observed": narrative_src.get("observed"),
            "reason_code": narrative_src.get("reason_code"),
            "contributing_controls": contrib,
        })

    return results


def normalize_audit_profile(
    profile: str = "scg8",
    control_ids: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Return a normalized profile descriptor for audit_api / Salt."""
    p = (profile or "scg8").strip().lower()
    if control_ids:
        return {
            "profile": "custom",
            "scg_ids": [c for c in control_ids if str(c).startswith("esx-9.")],
            "control_ids": list(control_ids),
        }
    if p in ("full84", "full", "all", "c84"):
        return {"profile": "full84", "scg_ids": list(SCG8_IDS), "control_ids": []}
    return {"profile": "scg8", "scg_ids": list(SCG8_IDS), "control_ids": profile_control_ids("scg8")}
