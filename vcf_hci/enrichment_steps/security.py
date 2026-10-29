"""Security evaluation and redaction at the post-collection boundary."""
import logging
from typing import Any, Dict

from vcf_hci.security.contract import empty_security_evidence
from vcf_hci.security.evaluation import evaluate_security_controls
from vcf_hci.security.redaction import redact_security_evidence, redact_security_findings

logger = logging.getLogger("vcf_assess")


def enrich_security_posture(host_data: Dict[str, Any], vendor: str) -> None:
    """Evaluate and redact security evidence, retaining imported audits and error policy."""
    # 9. BMC Security Audit Evaluation
    try:
        # Preserve existing bmc_security_config for backward compatibility
        if "bmc_security_config" not in host_data:
            host_data["bmc_security_config"] = {}

        sec_evidence = host_data.get("bmc_security_evidence")
        existing_audit = host_data.get("bmc_security_audit")

        if isinstance(existing_audit, dict) and existing_audit.get("findings") and not sec_evidence:
            # Preserved from an imported summary where raw evidence was omitted
            pass
        else:
            norm_vendor = "dell" if vendor and "dell" in vendor.lower() else (vendor or "generic")
            if not isinstance(sec_evidence, dict) or not sec_evidence:
                sec_evidence = empty_security_evidence(norm_vendor)
                host_data["bmc_security_evidence"] = sec_evidence
            elif not sec_evidence.get("vendor") or sec_evidence.get("vendor") == "generic":
                sec_evidence["vendor"] = norm_vendor

            raw_findings = evaluate_security_controls(sec_evidence)
            findings = redact_security_findings(raw_findings)
            host_data["bmc_security_evidence"] = redact_security_evidence(sec_evidence)

            pass_count = sum(1 for f in findings if f.get("status") == "pass")
            fail_count = sum(1 for f in findings if f.get("status") == "fail")
            na_count = sum(1 for f in findings if f.get("status") == "not_applicable")
            unknown_count = sum(1 for f in findings if str(f.get("status", "")).startswith("unknown"))

            host_data["bmc_security_audit"] = {
                "schema_version": sec_evidence.get("schema_version", 1),
                "vendor": sec_evidence.get("vendor", norm_vendor),
                "matrix_id": sec_evidence.get("_matrix_id") or "dmtf-8",
                "findings": findings,
                "summary": {
                    "pass": pass_count,
                    "fail": fail_count,
                    "unknown": unknown_count,
                    "not_applicable": na_count,
                    "total": len(findings),
                },
            }
    except Exception as exc:
        logger.debug("Failed evaluating BMC security audit: %s", exc)
        if "bmc_security_audit" not in host_data:
            host_data["bmc_security_audit"] = {
                "schema_version": 1,
                "vendor": vendor or "generic",
                "findings": [],
                "summary": {"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0, "total": 0},
            }
