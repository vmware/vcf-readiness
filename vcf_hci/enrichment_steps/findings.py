"""Job queue findings and final hardware-blocker verdicts."""
from typing import Any, Dict

from vcf_hci.compat_engine import decode_dell_message_id


def enrich_job_queue(host_data: Dict[str, Any]) -> None:
    """Append job readiness findings without replacing caller-owned lists."""
    # 12. Lifecycle Controller / BMC Job Queue Pre-Flight Evaluation
    job_q = host_data.get("job_queue")
    if isinstance(job_q, dict) and job_q:
        failed_jobs = int(job_q.get("failed_jobs") or 0)
        stale_jobs = int(job_q.get("stale_jobs") or 0)
        pending_reboot_jobs = int(job_q.get("pending_reboot_jobs") or 0)

        if failed_jobs > 0 or stale_jobs > 0:
            finding = f"Stale/Failed LC Jobs Detected ({failed_jobs} failed, {stale_jobs} stale). May block VCF host staging or reboot."
            remediation = "Log into iDRAC Web UI or run RACADM `jobqueue delete` to clear stalled tasks prior to VCF commissioning."
            eval_dict = {
                "severity": "WARNING",
                "finding": finding,
                "remediation": remediation,
                "failed_jobs": failed_jobs,
                "stale_jobs": stale_jobs,
                "pending_reboot_jobs": pending_reboot_jobs,
                "status": "warning",
            }
            job_q["evaluation"] = eval_dict
            if finding not in host_data.setdefault("readiness_findings", []):
                host_data["readiness_findings"].append(finding)
            if finding not in host_data.setdefault("readiness_warnings", []):
                host_data["readiness_warnings"].append(finding)
            rem_warn = f"{finding} Remediation: {remediation}"
            if rem_warn not in host_data.setdefault("warnings", []):
                host_data["warnings"].append(rem_warn)
        elif pending_reboot_jobs > 0:
            finding = f"Lifecycle Controller has {pending_reboot_jobs} job(s) pending reboot."
            eval_dict = {
                "severity": "INFO",
                "finding": finding,
                "remediation": "Power-cycle or reboot host to allow staged configuration jobs to complete.",
                "failed_jobs": 0,
                "stale_jobs": 0,
                "pending_reboot_jobs": pending_reboot_jobs,
                "status": "info",
            }
            job_q["evaluation"] = eval_dict
        else:
            job_q["evaluation"] = {
                "severity": "OK",
                "finding": "LC Job Queue clean (0 failed, 0 stale).",
                "remediation": "",
                "failed_jobs": 0,
                "stale_jobs": 0,
                "pending_reboot_jobs": 0,
                "status": "ok",
            }


def enrich_event_blockers(host_data: Dict[str, Any], system: Dict[str, Any]) -> None:
    """Decode events in order and share verdict/blocker aliases with the host."""
    # 13. System Event Log (SEL / FaultList) EEMS Decoding & Blocker Prioritization
    sel_events = host_data.get("sel_alarms") or host_data.get("sel") or host_data.get("system_event_log") or []
    vcf_blockers = list(host_data.get("vcf_blockers") or [])
    if isinstance(sel_events, list) and sel_events:
        for event in sel_events:
            if not isinstance(event, dict):
                continue
            msg_id = event.get("message_id")
            msg_text = event.get("message")
            decoded = decode_dell_message_id(msg_id, msg_text)
            if decoded:
                event["eems"] = decoded.to_dict()
                event["is_vcf_blocker"] = decoded.is_vcf_blocker
                event["vcf_impact"] = decoded.vcf_impact
                event["explanation"] = decoded.explanation
                event["remediation"] = decoded.remediation
                event["doc_url"] = decoded.doc_url
                event["domain"] = decoded.domain
                event["eems_code"] = decoded.code

                if decoded.is_vcf_blocker:
                    blocker_info = {
                        "code": decoded.code,
                        "domain": decoded.domain,
                        "severity": decoded.severity,
                        "vcf_impact": decoded.vcf_impact,
                        "explanation": decoded.explanation,
                        "remediation": decoded.remediation,
                        "doc_url": decoded.doc_url,
                        "message": str(msg_text or ""),
                        "timestamp": str(event.get("timestamp") or ""),
                    }
                    if not any(b.get("code") == decoded.code and b.get("message") == blocker_info["message"] for b in vcf_blockers):
                        vcf_blockers.append(blocker_info)

                    finding = f"VCF Hardware Blocker ({decoded.code}): {decoded.vcf_impact} — {decoded.explanation}"
                    if finding not in host_data.setdefault("readiness_findings", []):
                        host_data["readiness_findings"].append(finding)
                    if finding not in host_data.setdefault("readiness_warnings", []):
                        host_data["readiness_warnings"].append(finding)
                    rem_warn = f"{finding} Remediation: {decoded.remediation}"
                    if rem_warn not in host_data.setdefault("warnings", []):
                        host_data["warnings"].append(rem_warn)

    if vcf_blockers:
        blocker_codes = [b["code"] for b in vcf_blockers]
        blocker_summary_str = f"BLOCKED: {len(vcf_blockers)} Critical Hardware Blocker(s) Detected ({', '.join(blocker_codes)})"
        host_data["vcf_blockers"] = vcf_blockers
        host_data["hardware_fault_blockers"] = vcf_blockers
        host_data["overall_verdict"] = "NON_COMPLIANT (Hardware Blocker)"
        host_data["vcf9_verdict"] = "NON_COMPLIANT (Hardware Blocker)"
        eval_summary = {
            "status": "BLOCKED",
            "is_blocked": True,
            "blocker_count": len(vcf_blockers),
            "blockers": vcf_blockers,
            "summary": blocker_summary_str,
        }
        host_data["assessment_verdict"] = eval_summary
        system["assessment_verdict"] = eval_summary
    else:
        eval_summary = {
            "status": "PASSED",
            "is_blocked": False,
            "blocker_count": 0,
            "blockers": [],
            "summary": "No hardware fault blockers detected.",
        }
        host_data["assessment_verdict"] = eval_summary
        system["assessment_verdict"] = eval_summary
