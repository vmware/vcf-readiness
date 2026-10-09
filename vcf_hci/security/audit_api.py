"""Thin BMC security audit entry point for Salt / external callers.

Keeps Salt modules off enrichment internals. Collects evidence via the OEM
collector, evaluates controls, maps SCG IDs, and returns posture + support label.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Iterable, Optional, Sequence

from vcf_hci.security.evaluation import evaluate_security_controls
from vcf_hci.security.redaction import redact_security_evidence
from vcf_hci.security.scg_map import (
    SCG8_IDS,
    filter_findings_by_profile,
    findings_to_scg,
    normalize_audit_profile,
)
from vcf_hci.security.scoring import score_host_security

OEM_SUPPORT_LABELS = {
    "dell": "supported",
    "hpe": "supported",
    "hewlett": "supported",
    "hewlett packard enterprise": "supported",
    "lenovo": "experimental",
    "cisco": "experimental",
}

OEM_SUPPORT_REASONS = {
    "supported": "Full OEM security evaluator coverage (C01–C59 where applicable).",
    "experimental": (
        "DMTF standard Redfish / SCG-mappable controls only. No Tier-2 OEM "
        "security fixtures. Unknowns never count as pass."
    ),
    "limited": "Generic / unknown OEM — standard Redfish eight-control path only.",
}


def resolve_oem_support(vendor: Optional[str]) -> Dict[str, str]:
    """Return oem_support label and reason for a vendor string."""
    v = str(vendor or "").strip().lower()
    label = OEM_SUPPORT_LABELS.get(v)
    if label is None:
        if "hewlett" in v or v == "hpe":
            label = "supported"
        elif "lenovo" in v or "cisco" in v:
            label = "experimental"
        elif "dell" in v:
            label = "supported"
        else:
            label = "limited"
    return {
        "oem_support": label,
        "oem_support_reason": OEM_SUPPORT_REASONS.get(label, OEM_SUPPORT_REASONS["limited"]),
        "vendor": vendor or "unknown",
    }


def _score_from_findings(findings: Sequence[Dict[str, Any]], vendor: str = "") -> Dict[str, Any]:
    host_data = {
        "system": {"vendor": vendor},
        "bmc_security_audit": {"findings": list(findings)},
    }
    return score_host_security(host_data)


def evaluate_evidence(
    evidence: Dict[str, Any],
    profile: str = "scg8",
    control_ids: Optional[Iterable[str]] = None,
    include_scg: bool = True,
) -> Dict[str, Any]:
    """Evaluate pre-collected evidence (fixture-friendly, no network)."""
    vendor = str(evidence.get("vendor") or "generic")
    support = resolve_oem_support(vendor)
    raw_findings = evaluate_security_controls(evidence)
    prof = normalize_audit_profile(profile, control_ids)
    filtered = filter_findings_by_profile(
        raw_findings,
        profile=prof["profile"],
        control_ids=control_ids,
    )
    # full84: no filter
    if prof["profile"] == "full84" and not control_ids:
        filtered = list(raw_findings)

    if control_ids or prof["profile"] == "scg8":
        out_findings = filtered
    else:
        out_findings = list(raw_findings)

    posture = _score_from_findings(out_findings if out_findings else raw_findings, vendor)
    scg_findings = findings_to_scg(raw_findings, prof.get("scg_ids") or SCG8_IDS) if include_scg else []

    return {
        "status": "success",
        "vendor": vendor,
        "oem_support": support["oem_support"],
        "oem_support_reason": support["oem_support_reason"],
        "profile": prof["profile"],
        "findings": out_findings,
        "all_findings": raw_findings,
        "scg_findings": scg_findings,
        "posture": posture,
        "evidence_schema_version": evidence.get("schema_version") or evidence.get("evidence_schema_version"),
    }


def audit_bmc(
    host: str,
    username: str,
    password: str,
    profile: str = "scg8",
    control_ids: Optional[Iterable[str]] = None,
    host_timeout: int = 120,
    verify_ssl: bool = False,
    include_evidence: bool = False,
    redact: bool = True,
) -> Dict[str, Any]:
    """Live BMC audit: collect evidence + evaluate + SCG map.

    Args:
        host: BMC address
        username / password: Redfish credentials
        profile: scg8 | full84 | custom
        control_ids: optional explicit SCG or C-IDs
        include_evidence: include (optionally redacted) evidence blob
        redact: redact secrets from evidence when included
    """
    started = time.monotonic()
    try:
        from vcf_hci.collector.oem import create_collector
    except Exception as exc:
        return {
            "status": "error",
            "host": host,
            "error": f"collector import failed: {exc}",
        }

    collector = None
    try:
        collector = create_collector(
            host=host,
            username=username,
            password=password,
            host_timeout=host_timeout,
            verify_ssl=verify_ssl,
        )
        if not hasattr(collector, "collect_bmc_security_evidence"):
            return {
                "status": "error",
                "host": host,
                "error": "Collector does not implement collect_bmc_security_evidence",
            }
        evidence = collector.collect_bmc_security_evidence()
    except Exception as exc:
        return {
            "status": "error",
            "host": host,
            "error": str(exc),
            "elapsed_seconds": round(time.monotonic() - started, 2),
        }
    finally:
        try:
            if collector is not None and hasattr(collector, "close"):
                collector.close()
        except Exception:
            pass

    result = evaluate_evidence(evidence, profile=profile, control_ids=control_ids)
    result["host"] = host
    result["elapsed_seconds"] = round(time.monotonic() - started, 2)
    if include_evidence:
        result["evidence"] = redact_security_evidence(evidence) if redact else evidence
    return result


def assert_scg(
    audit_result: Dict[str, Any],
    strict: bool = True,
    fail_on_statuses: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Assert SCG (or filtered) findings. Fails only on listed statuses (default: fail).

    Returns dict with ok, failed_controls, unknown_controls, summary.
    """
    fail_statuses = set(fail_on_statuses or ("fail",))
    scg = audit_result.get("scg_findings") or []
    # Prefer SCG rollup; fall back to findings
    items = scg if scg else (audit_result.get("findings") or [])
    failed = []
    unknowns = []
    for item in items:
        status = str(item.get("status") or "")
        key = item.get("scg_id") or item.get("control_id")
        if status in fail_statuses:
            failed.append(item)
        elif status.startswith("unknown"):
            unknowns.append(item)

    ok = len(failed) == 0 if strict else True
    return {
        "ok": ok,
        "strict": strict,
        "failed_controls": failed,
        "unknown_controls": unknowns,
        "failed_count": len(failed),
        "unknown_count": len(unknowns),
        "oem_support": audit_result.get("oem_support"),
        "posture": audit_result.get("posture"),
        "summary": (
            f"{'PASS' if ok else 'FAIL'}: {len(failed)} fail(s), "
            f"{len(unknowns)} unknown(s); oem_support={audit_result.get('oem_support')}"
        ),
    }
