"""Experimental Cisco CIMC security evaluator (Avenue 1).

Support label: experimental.

Why experimental:
- No Tier-2 OEM attribute maps; SUDI/KMIP/ManagerMode may be collected but
  are not scored as C-control passes.
- No sanitized cisco_*_security.json fixtures yet.
- Redfish exposure is uneven across C220/C240 generations.
- XML/nuova inventory fallbacks are out of scope for SCG.
- Evaluates standard DMTF Redfish controls only; never invents pass.
"""

from __future__ import annotations

from typing import Any, Dict, List

from vcf_hci.security.contract import ReasonCode, control_finding
from vcf_hci.security.evaluation import evaluate_standard_security_controls

OEM_SUPPORT = "experimental"
OEM_SUPPORT_REASON = (
    "Cisco CIMC SCG uses DMTF standard Redfish only; Tier-2 OEM evaluators "
    "and security fixtures are not yet proven. SUDI/KMIP evidence is annotated "
    "but does not invent compliance. Unknowns never count as pass."
)


def _annotate_oem_evidence(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build non-scoring annotations from Cisco OEM security evidence.

    These are informational only — not C/O/I control findings.
    """
    oem = evidence.get("oem") or {}
    if not isinstance(oem, dict):
        return []

    notes: List[Dict[str, Any]] = []
    for key in ("sudi", "SUDI", "kmip", "KMIP", "ManagerMode", "manager_mode"):
        if key in oem and oem.get(key) is not None:
            notes.append({
                "annotation": f"cisco_oem_{key}",
                "observed": oem.get(key),
                "status": "unknown_not_exposed",
                "reason_code": ReasonCode.EXTERNAL_PROCESS_REQUIRED,
                "note": "Collected OEM evidence; not scored as a C-control in experimental mode.",
            })
    return notes


def evaluate_cisco_security_controls(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate Cisco CIMC via standard Redfish eight-control path."""
    findings = list(evaluate_standard_security_controls(evidence))
    for f in findings:
        f.setdefault("oem_support", OEM_SUPPORT)
        f.setdefault("oem_support_reason", OEM_SUPPORT_REASON)
        f.setdefault("vendor", evidence.get("vendor") or "cisco")

    # Attach OEM annotations on the first finding for operator visibility
    annotations = _annotate_oem_evidence(evidence)
    if annotations and findings:
        findings[0].setdefault("oem_annotations", annotations)

    oem = evidence.get("oem") if isinstance(evidence.get("oem"), dict) else {}
    if not oem:
        oem = evidence.get("cisco") if isinstance(evidence.get("cisco"), dict) else {}
    sudi = oem.get("hardware_sudi") if isinstance(oem, dict) else None
    if isinstance(sudi, dict) and sudi.get("present"):
        findings.append(control_finding(
            control_id="I01",
            status="pass",
            expected="SUDI certificate present",
            observed="ACT2 ECC SUDI present",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[{"identity_type": str(sudi.get("identity_type") or "")}],
        ))
    elif isinstance(sudi, dict):
        findings.append(control_finding(
            control_id="I01",
            status="fail",
            expected="SUDI certificate present",
            observed="SUDI block present without a certificate",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[{"present": bool(sudi.get("present"))}],
        ))
    kmip = oem.get("kmip_client") if isinstance(oem, dict) else None
    if isinstance(kmip, dict):
        enabled = bool(kmip.get("enabled"))
        findings.append(control_finding(
            control_id="I02",
            status="pass" if enabled else "not_applicable",
            expected="KMIP client settings readable",
            observed=f"enabled={enabled} servers={kmip.get('server_count', 0)}",
            reason_code=ReasonCode.OEM_REDFISH_PASS if enabled else ReasonCode.NOT_APPLICABLE,
            evidence=[{"enabled": enabled, "server_count": int(kmip.get("server_count") or 0)}],
        ))
    return findings
