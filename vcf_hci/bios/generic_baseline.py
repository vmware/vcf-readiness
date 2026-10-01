"""
VCF Readiness Tool — Generic & Supermicro BIOS Golden Baseline Drift Engine.

Canonical fallback baseline evaluation for Supermicro, Quanta, Gigabyte, and unlisted
enterprise server OEMs against VMware Cloud Foundation 9.1, vSAN ESA, and VMware
vSphere 9.0/9.1 Performance Best Practices.

Clean-room implementation using Python 3.9+ standard library only.
Strictly non-destructive and read-only.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vcf_assess")

VMWARE_PERF_GUIDE_TITLE = "VMware vSphere 9.0 Performance Best Practices"
VMWARE_PERF_GUIDE_URL = "https://www.vmware.com/docs/vsphere-esxi-vcenter-server-90-performance-best-practices"
VMWARE_LATENCY_KB_TITLE = "VMware KB 1018206: Performance Best Practices for Low-Latency Applications"
VMWARE_LATENCY_KB_URL = "https://kb.vmware.com/s/article/1018206"
VMWARE_ESA_GUIDE_TITLE = "VMware vSAN Express Storage Architecture (ESA) Hardware Guidance"
VMWARE_ESA_GUIDE_URL = "https://core.vmware.com/resource/vmware-vsan-esa-hardware-guidance"


def evaluate_generic_bios_baseline(
    bios_attrs: Optional[Dict[str, Any]],
    cpu_info: Optional[Dict[str, Any]] = None,
    is_esa_candidate: bool = False,
    model: Optional[str] = None,
    bios_version: Optional[str] = None,
    vendor: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate BIOS configuration attributes of Generic/Supermicro/unlisted servers against VCF 9.1 Baseline.

    Evaluates virtualization essentials:
      1. Hardware Virtualization (VT-x / SVM): Expected Enabled (Critical Blocker if disabled)
      2. Directed I/O (Intel VT-d / AMD IOMMU): Expected Enabled (Critical Blocker if disabled)
      3. SR-IOV: Expected Enabled (Info if disabled)
      4. Intel VMD: Expected Disabled for native NVMe pass-through (Blocker if ESA candidate)
      5. Hyper-Threading / SMT: Expected Enabled (Warning if disabled)
      6. CPU Turbo Mode: Expected Enabled (Warning if disabled)
      7. CPU C-States: Expected Disabled (MaxPerf / KB 1018206) or Enabled/Autonomous (OS DBPM)
      8. Sub-NUMA Clustering (SNC) / AMD NPS: Expected Disabled / NPS1 (general)
      9. Boot Mode: Expected UEFI (Critical Blocker if legacy BIOS)

    Args:
        bios_attrs: Dictionary of BIOS attributes (raw or normalized).
        cpu_info: CPU summary information dictionary.
        is_esa_candidate: Boolean indicating whether server is targeted for vSAN ESA.
        model: Optional hardware model string.
        bios_version: Optional BIOS firmware release string.
        vendor: Optional OEM vendor name string.

    Returns:
        Dictionary with compliance percentage, total drift count, severity counts,
        badge, and detailed per-attribute drift breakdown with VMware best practice citations.
    """
    raw_attrs = bios_attrs if isinstance(bios_attrs, dict) else {}
    attrs: Dict[str, Any] = {}
    for k, v in raw_attrs.items():
        if isinstance(v, (str, int, float, bool)):
            attrs[str(k).strip()] = v

    rules: List[Dict[str, Any]] = []

    # ── Rule 1: Hardware-Assisted Virtualization (VT-x / SVM) ───────────────
    vtx_val = None
    for k in ("ProcVirtualization", "IntelVirtualizationTechnology", "SVMMode", "SvmMode", "VT-x", "Virtualization"):
        for attr_k, attr_v in attrs.items():
            if k.lower() in attr_k.lower():
                vtx_val = attr_v
                break
        if vtx_val is not None:
            break

    if vtx_val is not None and str(vtx_val).strip():
        val = str(vtx_val).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["enable", "enabled", "1", "true"]):
            rules.append({
                "attribute": "ProcVirtualization",
                "setting_name": "Hardware Virtualization (VT-x / SVM)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Hardware-assisted CPU virtualization (Intel VT-x / AMD SVM) is Enabled. Required for ESXi hypervisor operation.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Hardware Virtualization Considerations (p. 18)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcVirtualization",
                "setting_name": "Hardware Virtualization (VT-x / SVM)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "blocker",
                "status": "drifted",
                "rationale": f"Hardware virtualization is Disabled ({val}). ESXi cannot run virtual machines without hardware virtualization. Hard blocker for VCF 9.1.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Hardware Virtualization Considerations (p. 18)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "ProcVirtualization",
            "setting_name": "Hardware Virtualization (VT-x / SVM)",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Hardware virtualization attribute not exposed in BIOS telemetry.",
            "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Hardware Virtualization Considerations (p. 18)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 2: Directed I/O (Intel VT-d / AMD IOMMU) ───────────────────────
    vtd_val = None
    for k in ("VtdSupport", "IntelVTforDirectedIOVTd", "IOMMU", "Iommu", "VT-d", "DirectedIO"):
        for attr_k, attr_v in attrs.items():
            if k.lower() in attr_k.lower():
                vtd_val = attr_v
                break
        if vtd_val is not None:
            break

    if vtd_val is not None and str(vtd_val).strip():
        val = str(vtd_val).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["enable", "enabled", "1", "true"]):
            rules.append({
                "attribute": "VtdSupport",
                "setting_name": "Directed I/O (Intel VT-d / AMD IOMMU)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Intel VT for Directed I/O (VT-d / AMD IOMMU) is Enabled. Required for PCI pass-through, vSAN Direct, and DPU/SmartNIC operations.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Hardware Virtualization Considerations (p. 18)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "VtdSupport",
                "setting_name": "Directed I/O (Intel VT-d / AMD IOMMU)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "blocker",
                "status": "drifted",
                "rationale": f"Directed I/O is Disabled ({val}). ESXi cannot isolate PCI memory domains or pass NVMe devices directly to vSAN ESA.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Hardware Virtualization Considerations (p. 18)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "VtdSupport",
            "setting_name": "Directed I/O (Intel VT-d / AMD IOMMU)",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Directed I/O attribute not exposed in BIOS telemetry.",
            "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Hardware Virtualization Considerations (p. 18)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 3: SR-IOV Global Enable ────────────────────────────────────────
    sriov_val = None
    for k in ("SriovGlobalEnable", "SRIOV", "SriovSupport", "Sriov"):
        for attr_k, attr_v in attrs.items():
            if k.lower() in attr_k.lower():
                sriov_val = attr_v
                break
        if sriov_val is not None:
            break

    if sriov_val is not None and str(sriov_val).strip():
        val = str(sriov_val).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["enable", "enabled", "1", "true"]):
            rules.append({
                "attribute": "SriovGlobalEnable",
                "setting_name": "SR-IOV Global Enable",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "SR-IOV Global Enable is Enabled. PCIe NICs support hardware-assisted Virtual Functions (VFs).",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Network Hardware Considerations (p. 19)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "SriovGlobalEnable",
                "setting_name": "SR-IOV Global Enable",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "info",
                "status": "drifted",
                "rationale": f"SR-IOV is Disabled ({val}). Informational: Enable if Virtual Functions or DPU passthrough are required.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Network Hardware Considerations (p. 19)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "SriovGlobalEnable",
            "setting_name": "SR-IOV Global Enable",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "SR-IOV attribute not exposed in BIOS telemetry.",
            "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Network Hardware Considerations (p. 19)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 4: Intel VMD (Volume Management Device) ────────────────────────
    vmd_val = None
    for k in ("VmdSupport", "EnableDisableIntelVMD", "VMDEnable", "VMD"):
        for attr_k, attr_v in attrs.items():
            if k.lower() in attr_k.lower():
                vmd_val = attr_v
                break
        if vmd_val is not None:
            break

    if vmd_val is not None and str(vmd_val).strip():
        val = str(vmd_val).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["disable", "disabled", "0", "false"]):
            rules.append({
                "attribute": "VmdSupport",
                "setting_name": "Intel VMD (Volume Management Device)",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Intel VMD is Disabled. NVMe SSDs are attached directly to PCIe root complexes for native vSAN ESA pass-through.",
                "citation": VMWARE_ESA_GUIDE_TITLE,
                "citation_url": VMWARE_ESA_GUIDE_URL,
            })
        else:
            sev = "blocker" if is_esa_candidate else "warning"
            rules.append({
                "attribute": "VmdSupport",
                "setting_name": "Intel VMD (Volume Management Device)",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": sev,
                "status": "drifted",
                "rationale": (
                    f"Intel VMD is Enabled ({val}). Intercepts direct PCIe root ports behind Intel VMD driver, "
                    "preventing native vSAN ESA pass-through. Must be Disabled in BIOS for vSAN ESA."
                ),
                "citation": VMWARE_ESA_GUIDE_TITLE,
                "citation_url": VMWARE_ESA_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "VmdSupport",
            "setting_name": "Intel VMD (Volume Management Device)",
            "current_value": "Not Exposed",
            "expected_value": "Disabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Intel VMD attribute not exposed in BIOS telemetry.",
            "citation": VMWARE_ESA_GUIDE_TITLE,
            "citation_url": VMWARE_ESA_GUIDE_URL,
        })

    # ── Rule 5: Hyper-Threading / SMT ───────────────────────────────────────
    ht_val = None
    for k in ("LogicalProc", "HyperThreading", "IntelHyperThread", "SMT", "Smt"):
        for attr_k, attr_v in attrs.items():
            if k.lower() in attr_k.lower():
                ht_val = attr_v
                break
        if ht_val is not None:
            break

    if ht_val is not None and str(ht_val).strip():
        val = str(ht_val).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["enable", "enabled", "1", "true"]):
            rules.append({
                "attribute": "LogicalProc",
                "setting_name": "Hyper-Threading (Logical Processors)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Hyper-Threading / SMT is Enabled. Maximizes vCPU scheduling capacity and throughput for ESXi NUMA scheduler.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, CPU Virtualization (p. 17)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "LogicalProc",
                "setting_name": "Hyper-Threading (Logical Processors)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Hyper-Threading is Disabled ({val}). Server provides only physical core capacity without SMT execution threads.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, CPU Virtualization (p. 17)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "LogicalProc",
            "setting_name": "Hyper-Threading (Logical Processors)",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Hyper-Threading attribute not exposed in BIOS telemetry.",
            "citation": f"{VMWARE_PERF_GUIDE_TITLE}, CPU Virtualization (p. 17)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 6: CPU Turbo Mode ──────────────────────────────────────────────
    turbo_val = None
    for k in ("ProcTurboMode", "TurboMode", "IntelTurboBoostTech", "Turbo"):
        for attr_k, attr_v in attrs.items():
            if k.lower() in attr_k.lower():
                turbo_val = attr_v
                break
        if turbo_val is not None:
            break

    if turbo_val is not None and str(turbo_val).strip():
        val = str(turbo_val).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["enable", "enabled", "1", "true"]):
            rules.append({
                "attribute": "ProcTurboMode",
                "setting_name": "CPU Turbo Mode",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "CPU Turbo Mode is Enabled. Allows processors to opportunistically boost clock rates above nominal TDP baseline.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, CPU Performance (p. 17)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcTurboMode",
                "setting_name": "CPU Turbo Mode",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"CPU Turbo Mode is Disabled ({val}). Processors cannot scale frequencies dynamically under compute peaks.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, CPU Performance (p. 17)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "ProcTurboMode",
            "setting_name": "CPU Turbo Mode",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "CPU Turbo Mode attribute not exposed in BIOS telemetry.",
            "citation": f"{VMWARE_PERF_GUIDE_TITLE}, CPU Performance (p. 17)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 7: CPU C-States ────────────────────────────────────────────────
    cstate_val = None
    for k in ("ProcCStates", "CStates", "CoreCState", "C-State", "CState"):
        for attr_k, attr_v in attrs.items():
            if k.lower() in attr_k.lower():
                cstate_val = attr_v
                break
        if cstate_val is not None:
            break

    if cstate_val is not None and str(cstate_val).strip():
        val = str(cstate_val).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["disable", "disabled", "nocstates", "nocstate", "0", "false"]):
            rules.append({
                "attribute": "ProcCStates",
                "setting_name": "Processor Core C-States",
                "current_value": val,
                "expected_value": "Disabled (MaxPerf) / Autonomous (OS DBPM)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    "Processor Core C-States are Disabled. Eliminates core sleep wake-up transitions for deterministic "
                    "low-jitter hypervisor and storage I/O performance."
                ),
                "citation": f"{VMWARE_LATENCY_KB_TITLE}",
                "citation_url": VMWARE_LATENCY_KB_URL,
            })
        elif any(ok in val_lower for ok in ["autonomous", "legacy", "os", "enable", "enabled", "auto"]):
            rules.append({
                "attribute": "ProcCStates",
                "setting_name": "Processor Core C-States",
                "current_value": val,
                "expected_value": "Disabled (MaxPerf) / Autonomous (OS DBPM)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"Processor Core C-States are set to {val}, allowing ESXi Host Power Management (Balanced governor) "
                    "to manage processor idle and frequency states dynamically."
                ),
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcCStates",
                "setting_name": "Processor Core C-States",
                "current_value": val,
                "expected_value": "Disabled (MaxPerf) / Autonomous (OS DBPM)",
                "severity": "info",
                "status": "drifted",
                "rationale": f"Processor Core C-States is set to {val}.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "ProcCStates",
            "setting_name": "Processor Core C-States",
            "current_value": "Not Exposed",
            "expected_value": "Disabled / Autonomous",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Processor Core C-States attribute not exposed in BIOS telemetry.",
            "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Power Management BIOS Settings (p. 21)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 8: Sub-NUMA Clustering (SNC) / AMD NPS ─────────────────────────
    snc_val = None
    for k in ("SubNumaCluster", "SNC", "NumaNodesPerSocket", "NumaNodes"):
        for attr_k, attr_v in attrs.items():
            if k.lower() in attr_k.lower():
                snc_val = attr_v
                break
        if snc_val is not None:
            break

    if snc_val is not None and str(snc_val).strip():
        val = str(snc_val).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["disable", "disabled", "auto", "nps1", "1"]):
            rules.append({
                "attribute": "SubNumaCluster",
                "setting_name": "Sub-NUMA Clustering / AMD NPS",
                "current_value": val,
                "expected_value": "Disabled / NPS1 (General) / SNC2/NPS4 (Workload-Specific)",
                "severity": None,
                "status": "compliant",
                "rationale": f"NUMA domain partitioning is set to {val}. Exposes 1 NUMA node per socket, optimal for general-purpose virtualization and mixed VM sizes.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, NUMA Considerations (p. 23)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "SubNumaCluster",
                "setting_name": "Sub-NUMA Clustering / AMD NPS",
                "current_value": val,
                "expected_value": "Disabled / NPS1 (General) / SNC2/NPS4 (Workload-Specific)",
                "severity": None,
                "status": "compliant",
                "rationale": f"NUMA domain partitioning is set to {val}. Splits each socket into sub-NUMA domains; ensure VMs are sized to fit within cluster boundaries.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, NUMA Considerations (p. 23)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "SubNumaCluster",
            "setting_name": "Sub-NUMA Clustering / AMD NPS",
            "current_value": "Not Exposed",
            "expected_value": "Disabled / NPS1",
            "severity": None,
            "status": "not_applicable",
            "rationale": "NUMA clustering attribute not exposed in BIOS telemetry.",
            "citation": f"{VMWARE_PERF_GUIDE_TITLE}, NUMA Considerations (p. 23)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 9: Boot Mode ───────────────────────────────────────────────────
    boot_val = None
    for k in ("BootMode", "SystemBootMode", "BootOption"):
        for attr_k, attr_v in attrs.items():
            if k.lower() in attr_k.lower():
                boot_val = attr_v
                break
        if boot_val is not None:
            break

    if boot_val is not None and str(boot_val).strip() and str(boot_val).strip().lower() not in ("not exposed", ""):
        val = str(boot_val).strip()
        val_lower = val.lower()
        if "uefi" in val_lower:
            rules.append({
                "attribute": "BootMode",
                "setting_name": "System Boot Mode",
                "current_value": val,
                "expected_value": "UEFI",
                "severity": None,
                "status": "compliant",
                "rationale": "System Boot Mode is configured for UEFI. Required for modern ESXi, Secure Boot, and VCF 9.1.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Boot Options (p. 16)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "BootMode",
                "setting_name": "System Boot Mode",
                "current_value": val,
                "expected_value": "UEFI",
                "severity": "blocker",
                "status": "drifted",
                "rationale": f"System Boot Mode is set to Legacy BIOS ({val}). Legacy boot is deprecated and unsupported for VCF 9.1. Must switch to UEFI.",
                "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Boot Options (p. 16)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "BootMode",
            "setting_name": "System Boot Mode",
            "current_value": "Not Exposed",
            "expected_value": "UEFI",
            "severity": None,
            "status": "not_applicable",
            "rationale": "System Boot Mode attribute not exposed in BIOS telemetry.",
            "citation": f"{VMWARE_PERF_GUIDE_TITLE}, Boot Options (p. 16)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Aggregate Compliance & Scoring ──────────────────────────────────────
    applicable_rules = [r for r in rules if r.get("status") != "not_applicable"]
    total_rules = len(applicable_rules)
    drifts = [r for r in applicable_rules if r.get("status") == "drifted"]
    drift_count = len(drifts)
    passed_count = total_rules - drift_count

    blocker_count = sum(1 for d in drifts if d.get("severity") == "blocker")
    warning_count = sum(1 for d in drifts if d.get("severity") == "warning")
    info_count = sum(1 for d in drifts if d.get("severity") == "info")

    compliance_pct = round((passed_count / total_rules) * 100.0, 1) if total_rules > 0 else 100.0

    if blocker_count > 0:
        status = "blocker"
        badge = (
            f"<span class='badge danger'>🔴 BIOS Drift: {blocker_count} Blocker"
            f"{'s' if blocker_count > 1 else ''} ({compliance_pct}% Compliant)</span>"
        )
    elif warning_count > 0:
        status = "warning"
        badge = (
            f"<span class='badge warning'>🟡 BIOS Drift: {warning_count} Warning"
            f"{'s' if warning_count > 1 else ''} ({compliance_pct}% Compliant)</span>"
        )
    elif info_count > 0:
        status = "info"
        badge = (
            f"<span class='badge info'>ℹ️ BIOS Optimization: {info_count} Note"
            f"{'s' if info_count > 1 else ''} ({compliance_pct}% Compliant)</span>"
        )
    else:
        status = "pass"
        badge = "<span class='badge success'>🟢 BIOS Golden Baseline: 100% Compliant</span>"

    return {
        "compliance_pct": compliance_pct,
        "total_rules": total_rules,
        "passed_count": passed_count,
        "drift_count": drift_count,
        "blocker_count": blocker_count,
        "warning_count": warning_count,
        "info_count": info_count,
        "status": status,
        "badge": badge,
        "drifts": drifts,
        "rules": rules,
        "guide_title": VMWARE_PERF_GUIDE_TITLE,
        "guide_url": VMWARE_PERF_GUIDE_URL,
        "vmware_guide_title": VMWARE_PERF_GUIDE_TITLE,
        "vmware_guide_url": VMWARE_PERF_GUIDE_URL,
        "oem_guide_title": VMWARE_PERF_GUIDE_TITLE,
        "oem_guide_url": VMWARE_PERF_GUIDE_URL,
    }
