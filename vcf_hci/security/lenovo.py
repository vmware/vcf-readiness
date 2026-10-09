"""Experimental Lenovo XCC security evaluator (Avenue 1).

Support label: experimental.

Why experimental:
- No Tier-2 OEM attribute maps (Security Mode / FoD / cipher catalogs).
- No sanitized lenovo_*_security.json fixtures yet.
- Syslog/TLS OEM paths are not fully parsed for XCC.
- Evaluates standard DMTF Redfish controls only; everything else stays
  unknown_not_exposed. Never invents pass from missing OEM evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List

from vcf_hci.security.evaluation import evaluate_standard_security_controls

OEM_SUPPORT = "experimental"
OEM_SUPPORT_REASON = (
    "Lenovo XCC SCG uses DMTF standard Redfish only; Tier-2 OEM evaluators "
    "and security fixtures are not yet proven. Results may contain many "
    "unknown_not_exposed findings — never treat unknowns as pass."
)


def evaluate_lenovo_security_controls(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate Lenovo XCC via standard Redfish eight-control path.

    Annotates each finding with oem_support metadata for Salt / audit_api.
    """
    findings = evaluate_standard_security_controls(evidence)
    for f in findings:
        f.setdefault("oem_support", OEM_SUPPORT)
        f.setdefault("oem_support_reason", OEM_SUPPORT_REASON)
        # Preserve vendor annotation for operators
        f.setdefault("vendor", evidence.get("vendor") or "lenovo")
    return findings
