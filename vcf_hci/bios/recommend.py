"""VMware golden BIOS recommend view (Avenue 1) — read-only.

Builds a canonical Tier A/B/C recommendation report from existing OEM
baseline engines. Does not mutate BMC state.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

TIER_A = (
    "BootMode",
    "SecureBoot",
    "TpmPresentActive",
    "ProcVirtualization",
    "VtdSupport",
    "VmdSupport",
)

TIER_B = (
    "SriovGlobalEnable",
    "LogicalProc",
    "ProcTurboMode",
    "NodeInterleave",
)

TIER_C_POWER = (
    "SysProfile",
    "WorkloadProfile",
    "ProcCStates",
    "ProcC1E",
    "PcieAspm",
    "PowerRegulator",
    "MinProcIdlePower",
)

# Map baseline attribute names → canonical / tier
_ATTR_TIER = {
    "BootMode": "A",
    "SecureBoot": "A",
    "SecureBootEnable": "A",
    "TpmPresentActive": "A",
    "ProcVirtualization": "A",
    "VtdSupport": "A",
    "IntelProcVtd": "A",
    "VmdSupport": "A",
    "SriovGlobalEnable": "B",
    "Sriov": "B",
    "LogicalProc": "B",
    "ProcTurboMode": "B",
    "ProcTurbo": "B",
    "NodeInterleave": "B",
    "NodeInterleaving": "B",
    "SysProfile": "C",
    "WorkloadProfile": "C",
    "ProcCStates": "C",
    "ProcC1E": "C",
    "PcieAspm": "C",
    "PowerRegulator": "C",
    "MinProcIdlePower": "C",
    "CollaborativePowerControl": "C",
    "EnergyEfficientTurbo": "C",
}

CANONICAL_RECOMMENDED = {
    "BootMode": "UEFI",
    "SecureBoot": "Enabled",
    "TpmPresentActive": "Present+Active (TPM 2.0)",
    "ProcVirtualization": "Enabled",
    "VtdSupport": "Enabled",
    "VmdSupport": "Disabled",
    "SriovGlobalEnable": "Enabled",
    "LogicalProc": "Enabled",
    "ProcTurboMode": "Enabled",
    "NodeInterleave": "Disabled",
}


def _vendor_key(vendor: Optional[str]) -> str:
    v = str(vendor or "").strip().lower()
    if "dell" in v:
        return "dell"
    if "hpe" in v or "hewlett" in v:
        return "hpe"
    if "lenovo" in v:
        return "lenovo"
    if "cisco" in v:
        return "cisco"
    return "generic"


def _run_baseline(
    vendor: str,
    bios_attrs: Dict[str, Any],
    cpu_info: Optional[Dict[str, Any]],
    is_esa_candidate: bool,
    model: Optional[str],
    bios_version: Optional[str],
) -> Dict[str, Any]:
    vk = _vendor_key(vendor)
    if vk == "dell":
        from vcf_hci.bios.dell_baseline import evaluate_dell_bios_baseline, get_dell_tuning_guide
        drift = evaluate_dell_bios_baseline(
            bios_attrs, cpu_info=cpu_info, is_esa_candidate=is_esa_candidate,
            model=model, bios_version=bios_version,
        )
        guide = get_dell_tuning_guide(model=model, bios_version=bios_version, cpu_info=cpu_info)
    elif vk == "hpe":
        from vcf_hci.bios.hpe_baseline import evaluate_hpe_bios_baseline, get_hpe_tuning_guide
        drift = evaluate_hpe_bios_baseline(
            bios_attrs, cpu_info=cpu_info, is_esa_candidate=is_esa_candidate,
            model=model, bios_version=bios_version,
        )
        guide = get_hpe_tuning_guide(model=model, bios_version=bios_version, cpu_info=cpu_info)
    elif vk == "lenovo":
        from vcf_hci.bios.lenovo_baseline import evaluate_lenovo_bios_baseline, get_lenovo_tuning_guide
        drift = evaluate_lenovo_bios_baseline(
            bios_attrs, cpu_info=cpu_info, is_esa_candidate=is_esa_candidate,
            model=model, bios_version=bios_version,
        )
        guide = get_lenovo_tuning_guide(model=model, bios_version=bios_version, cpu_info=cpu_info)
    elif vk == "cisco":
        from vcf_hci.bios.cisco_baseline import evaluate_cisco_bios_baseline, get_cisco_tuning_guide
        drift = evaluate_cisco_bios_baseline(
            bios_attrs, cpu_info=cpu_info, is_esa_candidate=is_esa_candidate,
            model=model, bios_version=bios_version,
        )
        guide = get_cisco_tuning_guide(model=model, bios_version=bios_version, cpu_info=cpu_info)
    else:
        from vcf_hci.bios.generic_baseline import evaluate_generic_bios_baseline
        drift = evaluate_generic_bios_baseline(
            bios_attrs, cpu_info=cpu_info, is_esa_candidate=is_esa_candidate,
            model=model, bios_version=bios_version,
        )
        guide = {
            "title": "VMware vSphere Performance Best Practices",
            "url": "https://www.vmware.com/docs/vsphere-esxi-vcenter-server-90-performance-best-practices",
        }
    return {"drift": drift or {}, "guide": guide or {}, "vendor_key": vk}


def _infer_power_path(rules: Sequence[Dict[str, Any]], attrs: Dict[str, Any]) -> str:
    """Return maxperf | os_control | suboptimal | unknown."""
    profile_vals = []
    for key in ("SysProfile", "WorkloadProfile", "PowerRegulator"):
        if attrs.get(key) is not None:
            profile_vals.append(str(attrs.get(key)).lower())
    joined = " ".join(profile_vals)
    if any(x in joined for x in ("perfoptimized", "maxperformance", "statichigh", "maximum performance", "densecfg")):
        return "maxperf"
    if any(x in joined for x in ("custom", "oscontrol", "os control", "osdbpm", "collaborative")):
        return "os_control"
    if any(x in joined for x in ("power", "efficiency", "balanced", "dapc", "perfperwatt")):
        return "suboptimal"
    # Inspect rule compliance for power attrs
    for r in rules:
        attr = str(r.get("attribute") or "")
        if attr in ("SysProfile", "WorkloadProfile") and r.get("status") == "compliant":
            cur = str(r.get("current_value") or "").lower()
            if "custom" in cur:
                return "os_control"
            if "perf" in cur or "max" in cur:
                return "maxperf"
    if not profile_vals:
        return "unknown"
    return "suboptimal"


def build_recommend_report(
    bios_attrs: Optional[Dict[str, Any]],
    vendor: Optional[str] = None,
    cpu_info: Optional[Dict[str, Any]] = None,
    is_esa_candidate: bool = False,
    model: Optional[str] = None,
    bios_version: Optional[str] = None,
    power_path: str = "either",
    secure_boot: Optional[Dict[str, Any]] = None,
    tpm_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build Tier A/B/C golden BIOS awareness + recommend deltas."""
    attrs = dict(bios_attrs or {})
    baseline = _run_baseline(vendor or "generic", attrs, cpu_info, is_esa_candidate, model, bios_version)
    drift = baseline["drift"]
    rules = list(drift.get("rules") or drift.get("drift_details") or [])
    # Some engines use "details" / "drifts"
    if not rules:
        rules = list(drift.get("details") or drift.get("drifts") or [])

    # Inject SecureBoot / TPM side-channels into Tier A when provided
    if isinstance(secure_boot, dict):
        en = secure_boot.get("SecureBootEnable")
        cur = secure_boot.get("SecureBootCurrentBoot")
        ok = en is True and (cur is None or str(cur).lower() in ("enabled", "on", "true", "1"))
        rules.append({
            "attribute": "SecureBoot",
            "current_value": f"Enable={en}, CurrentBoot={cur}",
            "expected_value": "Enabled",
            "status": "compliant" if ok else ("drift" if en is not None else "unknown"),
            "severity": None if ok else "critical",
        })
    if isinstance(tpm_info, dict):
        present = tpm_info.get("present") or tpm_info.get("tpm_present")
        active = tpm_info.get("active") or tpm_info.get("tpm_active")
        ok = bool(present) and (active is True or active is None)
        rules.append({
            "attribute": "TpmPresentActive",
            "current_value": tpm_info,
            "expected_value": "TPM 2.0 present+active",
            "status": "compliant" if ok else "drift",
            "severity": None if ok else "warning",
        })

    tiers: Dict[str, List[Dict[str, Any]]] = {"A": [], "B": [], "C": [], "other": []}
    deltas: List[Dict[str, Any]] = []

    for r in rules:
        attr = str(r.get("attribute") or r.get("setting_name") or "")
        tier = _ATTR_TIER.get(attr, "other")
        item = {
            "attribute": attr,
            "tier": tier,
            "current_value": r.get("current_value"),
            "expected_value": r.get("expected_value") or CANONICAL_RECOMMENDED.get(attr),
            "status": r.get("status"),
            "severity": r.get("severity"),
            "rationale": r.get("rationale"),
            "citation": r.get("citation"),
            "citation_url": r.get("citation_url"),
        }
        tiers.setdefault(tier, []).append(item)
        status = str(r.get("status") or "").lower()
        if status in ("drifted", "drift", "non_compliant", "fail", "warning") or (status not in (
            "compliant", "pass", "ok", "unknown", "info", "n/a",
            "not_applicable", "",
        ) and r.get("severity")):
            deltas.append(item)

    cleaned_deltas = []
    for d in deltas:
        st = str(d.get("status") or "").lower()
        if st in ("compliant", "pass", "ok", "not_applicable"):
            continue
        cleaned_deltas.append(d)

    inferred_path = _infer_power_path(rules, attrs)
    path_policy = (power_path or "either").strip().lower()
    tier_c_ok = True
    if path_policy == "either":
        tier_c_ok = inferred_path in ("maxperf", "os_control")
    elif path_policy in ("maxperf", "os_control"):
        tier_c_ok = inferred_path == path_policy
    else:
        tier_c_ok = inferred_path in ("maxperf", "os_control")

    apply_candidates = [
        d for d in cleaned_deltas
        if d.get("tier") in ("A", "B") and d.get("attribute") not in ("SecureBoot", "TpmPresentActive")
    ]

    return {
        "status": "success",
        "vendor": vendor,
        "vendor_key": baseline["vendor_key"],
        "oem_guide": baseline["guide"],
        "power_path": {
            "inferred": inferred_path,
            "policy": path_policy,
            "compliant": tier_c_ok,
            "note": "MaxPerf and OS-control are both valid when policy=either (KB 1018206 dual-path).",
        },
        "tiers": tiers,
        "deltas": cleaned_deltas,
        "apply_candidates": apply_candidates,
        "baseline_summary": {
            "compliance_pct": drift.get("compliance_pct") or drift.get("compliance_percent"),
            "badge": drift.get("badge"),
            "drift_count": drift.get("drift_count") or drift.get("total_drift"),
        },
        "canonical_recommended": dict(CANONICAL_RECOMMENDED),
        "mutates_bmc": False,
    }


def report_from_collector(
    collector: Any,
    power_path: str = "either",
    is_esa_candidate: bool = False,
) -> Dict[str, Any]:
    """Convenience: pull BIOS attrs from a live collector and recommend."""
    bios_info = {}
    if hasattr(collector, "check_bios_attributes"):
        bios_info = collector.check_bios_attributes() or {}
    attrs = bios_info.get("normalized_attributes") or bios_info.get("attributes") or {}
    vendor = getattr(collector, "vendor", None) or ""
    model = None
    bios_version = None
    sys_sum = getattr(collector, "sys_summary", None) or {}
    if isinstance(sys_sum, dict):
        model = sys_sum.get("model") or sys_sum.get("Model")
        bios_version = sys_sum.get("bios_version")
    return build_recommend_report(
        attrs,
        vendor=vendor,
        model=model,
        bios_version=bios_version,
        power_path=power_path,
        is_esa_candidate=is_esa_candidate,
        secure_boot=None,
        tpm_info=None,
    )
