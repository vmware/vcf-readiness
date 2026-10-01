"""
VCF Readiness Tool — Lenovo ThinkSystem BIOS Golden Baseline Drift Engine.

Evaluates Lenovo ThinkSystem BIOS configuration against Broadcom VCF 9.1 and
vSAN Express Storage Architecture (ESA) recommended golden performance baselines,
incorporating official guidance from VMware vSphere 9.0 Performance Best Practices.

Clean-room implementation using Python 3.9+ standard library only.
Strictly non-destructive and read-only.
"""
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vcf_assess")

VMWARE_PERF_GUIDE_TITLE = "VMware vSphere 9.0 Performance Best Practices"
VMWARE_PERF_GUIDE_URL = "https://www.vmware.com/docs/vsphere-esxi-vcenter-server-90-performance-best-practices"


def get_lenovo_tuning_guide(
    model: Optional[str] = None,
    bios_version: Optional[str] = None,
    cpu_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Resolve generation-specific Lenovo ThinkSystem BIOS performance tuning guide and reference URL."""
    model_str = str(model or "").lower()
    cpu_str = ""
    if isinstance(cpu_info, dict):
        cpu_str = f"{cpu_info.get('model', '')} {cpu_info.get('architecture', '')}".lower()
    is_amd = "amd" in model_str or "epyc" in cpu_str or "zen" in cpu_str

    if is_amd:
        if "v4" in model_str or "turin" in cpu_str or "9005" in cpu_str:
            return {
                "title": "Lenovo Press LP2210: Tuning UEFI Settings on AMD EPYC 9005 Processors",
                "url": "https://lenovopress.lenovo.com/lp2210",
            }
        if "v3" in model_str or "genoa" in cpu_str or "bergamo" in cpu_str or "9004" in cpu_str:
            return {
                "title": "Lenovo Press LP1977: Tuning UEFI Settings on AMD EPYC 9004 Processors",
                "url": "https://lenovopress.lenovo.com/lp1977",
            }
        return {
            "title": "Lenovo Press LP1267: Tuning UEFI Settings on AMD EPYC 7002/7003 Processors",
            "url": "https://lenovopress.lenovo.com/lp1267",
        }

    # Intel ThinkSystem
    if "v4" in model_str or "xeon 6" in cpu_str or "granite rapids" in cpu_str or "sierra forest" in cpu_str:
        return {
            "title": "Lenovo ThinkSystem V4 Xeon 6 UEFI Setting Guide",
            "url": "https://pubs.lenovo.com/uefi_xeon_6th/uefi_setting_guide.pdf",
        }
    if "v3" in model_str or "sapphire rapids" in cpu_str or "emerald rapids" in cpu_str:
        return {
            "title": "Lenovo Press LP1836: Tuning UEFI Settings for 4th and 5th Gen Intel Xeon Scalable",
            "url": "https://lenovopress.lenovo.com/lp1836",
        }
    if any(k in model_str for k in ("v2", "v1")) or any(k in cpu_str for k in ("ice lake", "cascade lake", "skylake")):
        return {
            "title": "Lenovo Press LP1477: Tuning UEFI Settings for 1st, 2nd, and 3rd Gen Intel Xeon Scalable",
            "url": "https://lenovopress.lenovo.com/lp1477",
        }

    return {
        "title": "Lenovo Solution HT115952: Tuning VMware for Increased Performance",
        "url": "https://support.lenovo.com/us/en/solutions/ht115952",
    }


def evaluate_lenovo_bios_baseline(
    bios_attrs: Optional[Dict[str, Any]],
    cpu_info: Optional[Dict[str, Any]] = None,
    is_esa_candidate: bool = False,
    model: Optional[str] = None,
    bios_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate Lenovo ThinkSystem BIOS configuration attributes against VCF 9.1 Golden Baseline.

    Evaluates canonical attributes:
      1. Virtualization (VT-x): Expected Enable/Enabled (Critical Blocker if disabled)
      2. Directed I/O (VT-d): Expected Enable/Enabled (Critical Blocker if disabled)
      3. SR-IOV: Expected Enable/Enabled (Info if disabled)
      4. Intel VMD: Expected Disable/Disabled for native NVMe pass-through (Blocker if ESA candidate)
      5. Operating Mode: Expected Custom or Maximum_Performance (Warning if power-saving)
      6. C-States: Expected Autonomous, Legacy, or Disabled
      7. Turbo Mode: Expected Enable/Enabled (Warning if disabled)
      8. Hyper-Threading: Expected Enable/Enabled (Warning if disabled)
      9. Sub-NUMA Clustering (SNC): Expected Disable/Auto for general virtualization
     10. Hardware Prefetchers: Expected Enable/Enabled
     11. Boot Mode: Expected UEFIMode (Critical Blocker if legacy BIOS)
     12. MONITOR/MWAIT: Expected Enable per HT115952
     13. Latency Optimized Mode (V3+/V4): Expected Enable / Disable
     14. C1 Enhanced Mode: Expected Disable per HT115952
     15. Energy Efficient Turbo: Expected Disable per HT115952

    Args:
        bios_attrs: Dictionary of BIOS attributes (raw or normalized).
        cpu_info: CPU summary information dictionary.
        is_esa_candidate: Boolean indicating whether server is targeted for vSAN ESA.
        model: Optional server model string (e.g. 'ThinkSystem SR650 V3').
        bios_version: Optional BIOS firmware build string.

    Returns:
        Dictionary with compliance percentage, total drift count, severity counts,
        badge, and detailed per-attribute drift breakdown with VMware best practice citations.
    """
    from ..collector.oem.lenovo import normalize_lenovo_bios_attributes

    raw_attrs = bios_attrs if isinstance(bios_attrs, dict) else {}
    norm_attrs = normalize_lenovo_bios_attributes(raw_attrs)
    attrs = dict(raw_attrs)
    attrs.update(norm_attrs)

    oem_guide = get_lenovo_tuning_guide(model=model, bios_version=bios_version, cpu_info=cpu_info)
    rules: List[Dict[str, Any]] = []

    # ── Rule 1: Intel Virtualization Technology (VT-x) ──────────────────────
    vtx_val = attrs.get("Processors_IntelVirtualizationTechnology") or attrs.get("ProcVirtualization")
    if vtx_val is not None and str(vtx_val).strip():
        val = str(vtx_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "Processors_IntelVirtualizationTechnology",
                "setting_name": "Intel Virtualization Technology (VT-x)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Hardware-assisted CPU virtualization (Intel VT-x) is enabled. Required for ESXi 64-bit guest VMs.",
                "citation": "vSphere 9.0 Performance Best Practices, Hardware Virtualization Considerations (p. 18)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "Processors_IntelVirtualizationTechnology",
                "setting_name": "Intel Virtualization Technology (VT-x)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "blocker",
                "status": "drifted",
                "rationale": f"Intel VT-x is Disabled ({val}). ESXi cannot run virtual machines without hardware virtualization support. Hard blocker for VCF deployment.",
                "citation": "vSphere 9.0 Performance Best Practices, Hardware Virtualization Considerations (p. 18)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "Processors_IntelVirtualizationTechnology",
            "setting_name": "Intel Virtualization Technology (VT-x)",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Intel VT-x attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, Hardware Virtualization Considerations (p. 18)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 2: Intel VT-d (Directed I/O) ───────────────────────────────────
    vtd_val = attrs.get("DevicesandIOPorts_IntelVTforDirectedIOVTd") or attrs.get("IntelVTforDirectedIOVTd")
    if vtd_val is not None and str(vtd_val).strip():
        val = str(vtd_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "DevicesandIOPorts_IntelVTforDirectedIOVTd",
                "setting_name": "Intel VT-d (Directed I/O / IOMMU)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Intel VT-d (IOMMU) is enabled. Required for PCI pass-through, vSAN Direct, and DPU/SmartNIC operations.",
                "citation": "vSphere 9.0 Performance Best Practices, Hardware Virtualization Considerations (p. 18)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "DevicesandIOPorts_IntelVTforDirectedIOVTd",
                "setting_name": "Intel VT-d (Directed I/O / IOMMU)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "blocker",
                "status": "drifted",
                "rationale": f"Intel VT-d is Disabled ({val}). ESXi cannot isolate PCI memory domains or pass NVMe devices directly to vSAN ESA.",
                "citation": "vSphere 9.0 Performance Best Practices, Hardware Virtualization Considerations (p. 18)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "DevicesandIOPorts_IntelVTforDirectedIOVTd",
            "setting_name": "Intel VT-d (Directed I/O / IOMMU)",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Intel VT-d attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, Hardware Virtualization Considerations (p. 18)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 3: SR-IOV ──────────────────────────────────────────────────────
    sriov_val = attrs.get("DevicesandIOPorts_SRIOV") or attrs.get("SRIOV")
    if sriov_val is not None and str(sriov_val).strip():
        val = str(sriov_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "DevicesandIOPorts_SRIOV",
                "setting_name": "SR-IOV Global Enable",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "SR-IOV Global Enable is Enabled. PCIe NICs support hardware-assisted Virtual Functions (VFs).",
                "citation": "vSphere 9.0 Performance Best Practices, Network Hardware Considerations (p. 19)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "DevicesandIOPorts_SRIOV",
                "setting_name": "SR-IOV Global Enable",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "info",
                "status": "drifted",
                "rationale": f"SR-IOV is Disabled ({val}). Informational: Enable if Virtual Functions or direct network pass-through are required.",
                "citation": "vSphere 9.0 Performance Best Practices, Network Hardware Considerations (p. 19)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "DevicesandIOPorts_SRIOV",
            "setting_name": "SR-IOV Global Enable",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "SR-IOV attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, Network Hardware Considerations (p. 19)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 4: Intel VMD (Volume Management Device) ────────────────────────
    vmd_val = attrs.get("DevicesandIOPorts_EnableDisableIntelVMD") or attrs.get("EnableDisableIntelVMD")
    if vmd_val is not None and str(vmd_val).strip():
        val = str(vmd_val).strip()
        val_lower = val.lower()
        if "disable" in val_lower:
            rules.append({
                "attribute": "DevicesandIOPorts_EnableDisableIntelVMD",
                "setting_name": "Intel VMD (Volume Management Device)",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Intel VMD is Disabled. NVMe SSDs are attached directly to PCIe root complexes for native vSAN ESA pass-through.",
                "citation": "VMware vSAN Express Storage Architecture (ESA) Hardware Guidance",
                "citation_url": "https://core.vmware.com/resource/vmware-vsan-esa-hardware-guidance",
            })
        else:
            sev = "blocker" if is_esa_candidate else "warning"
            rules.append({
                "attribute": "DevicesandIOPorts_EnableDisableIntelVMD",
                "setting_name": "Intel VMD (Volume Management Device)",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": sev,
                "status": "drifted",
                "rationale": (
                    f"Intel VMD is Enabled ({val}). Intercepts direct PCIe root ports behind Intel VMD driver, "
                    "preventing native vSAN ESA pass-through. Must be Disabled in BIOS for vSAN ESA."
                ),
                "citation": "VMware vSAN Express Storage Architecture (ESA) Hardware Guidance",
                "citation_url": "https://core.vmware.com/resource/vmware-vsan-esa-hardware-guidance",
            })
    else:
        rules.append({
            "attribute": "DevicesandIOPorts_EnableDisableIntelVMD",
            "setting_name": "Intel VMD (Volume Management Device)",
            "current_value": "Not Exposed",
            "expected_value": "Disabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Intel VMD attribute not exposed in BIOS telemetry.",
            "citation": "VMware vSAN Express Storage Architecture (ESA) Hardware Guidance",
            "citation_url": "https://core.vmware.com/resource/vmware-vsan-esa-hardware-guidance",
        })

    # ── Rule 5: Operating Mode / Workload Profile ───────────────────────────
    v4_profile = attrs.get("SystemSettings_WorkloadProfile") or attrs.get("WorkloadProfile")
    op_mode = attrs.get("OperatingModes_ChooseOperatingMode") or attrs.get("ChooseOperatingMode")

    if v4_profile is not None and str(v4_profile).strip():
        val = str(v4_profile).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["virtualization_maxperformance", "maxperformance", "custom"]):
            rules.append({
                "attribute": "SystemSettings_WorkloadProfile",
                "setting_name": "Workload Profile (ThinkSystem V4)",
                "current_value": val,
                "expected_value": "Virtualization_MaxPerformance / Custom",
                "severity": None,
                "status": "compliant",
                "rationale": f"Workload Profile is set to {val}, tuned for peak deterministic hypervisor throughput.",
                "citation": "ThinkSystem V4 Xeon 6 UEFI Setting Guide & HT115952",
                "citation_url": "https://pubs.lenovo.com/uefi_xeon_6th/uefi_setting_guide.pdf",
            })
        elif "balanced" in val_lower or "favorperformance" in val_lower:
            rules.append({
                "attribute": "SystemSettings_WorkloadProfile",
                "setting_name": "Workload Profile (ThinkSystem V4)",
                "current_value": val,
                "expected_value": "Virtualization_MaxPerformance / Custom",
                "severity": "info",
                "status": "drifted",
                "rationale": f"Workload Profile is set to {val}. Balanced mode; for lowest latency, configure Virtualization_MaxPerformance.",
                "citation": "ThinkSystem V4 Xeon 6 UEFI Setting Guide & HT115952",
                "citation_url": "https://pubs.lenovo.com/uefi_xeon_6th/uefi_setting_guide.pdf",
            })
        else:
            rules.append({
                "attribute": "SystemSettings_WorkloadProfile",
                "setting_name": "Workload Profile (ThinkSystem V4)",
                "current_value": val,
                "expected_value": "Virtualization_MaxPerformance / Custom",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Workload Profile is set to {val}. Low-power profiles throttle processor frequencies under virtualized loads.",
                "citation": "ThinkSystem V4 Xeon 6 UEFI Setting Guide & HT115952",
                "citation_url": "https://pubs.lenovo.com/uefi_xeon_6th/uefi_setting_guide.pdf",
            })
    elif op_mode is not None and str(op_mode).strip():
        val = str(op_mode).strip()
        val_lower = val.lower()
        if "custom" in val_lower or "maximum_performance" in val_lower or "maximum performance" in val_lower:
            rules.append({
                "attribute": "OperatingModes_ChooseOperatingMode",
                "setting_name": "Operating Mode",
                "current_value": val,
                "expected_value": "Custom / Maximum Performance",
                "severity": None,
                "status": "compliant",
                "rationale": f"Operating Mode is set to {val}, allowing ESXi OS DBPM power governor or maximum deterministic clock frequency.",
                "citation": "Lenovo Solution HT115952: Tuning VMware for Increased Performance",
                "citation_url": "https://support.lenovo.com/us/en/solutions/ht115952",
            })
        elif "favorperformance" in val_lower:
            rules.append({
                "attribute": "OperatingModes_ChooseOperatingMode",
                "setting_name": "Operating Mode",
                "current_value": val,
                "expected_value": "Custom / Maximum Performance",
                "severity": "info",
                "status": "drifted",
                "rationale": f"Operating Mode is set to {val}. Factory default balanced mode; for lowest latency, switch to Custom (with HT115952 settings) or Maximum Performance.",
                "citation": "Lenovo Solution HT115952: Tuning VMware for Increased Performance",
                "citation_url": "https://support.lenovo.com/us/en/solutions/ht115952",
            })
        else:
            rules.append({
                "attribute": "OperatingModes_ChooseOperatingMode",
                "setting_name": "Operating Mode",
                "current_value": val,
                "expected_value": "Custom / Maximum Performance",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Operating Mode is set to {val}. Low-power or non-optimal profile throttles CPU/memory performance under VCF virtualized loads.",
                "citation": "Lenovo Solution HT115952: Tuning VMware for Increased Performance",
                "citation_url": "https://support.lenovo.com/us/en/solutions/ht115952",
            })
    else:
        rules.append({
            "attribute": "OperatingModes_ChooseOperatingMode",
            "setting_name": "Operating Mode",
            "current_value": "Not Exposed",
            "expected_value": "Custom / Maximum Performance",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Operating Mode attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 6: CPU C-States ────────────────────────────────────────────────
    cstates = attrs.get("Processors_CStates") or attrs.get("CStates")
    if cstates is not None and str(cstates).strip():
        val = str(cstates).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["autonomous", "legacy", "disable"]):
            rules.append({
                "attribute": "Processors_CStates",
                "setting_name": "CPU C-States",
                "current_value": val,
                "expected_value": "Autonomous / Legacy / Disabled",
                "severity": None,
                "status": "compliant",
                "rationale": f"CPU C-States is set to {val}, allowing ESXi power governance and preventing deep C-state sleep jitter.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "Processors_CStates",
                "setting_name": "CPU C-States",
                "current_value": val,
                "expected_value": "Autonomous / Legacy / Disabled",
                "severity": "info",
                "status": "drifted",
                "rationale": f"CPU C-States is set to {val}. May cause slight latency spikes during deep wake transitions.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "Processors_CStates",
            "setting_name": "CPU C-States",
            "current_value": "Not Exposed",
            "expected_value": "Autonomous / Legacy / Disabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "CPU C-States attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 7: CPU Turbo Mode ──────────────────────────────────────────────
    turbo = attrs.get("Processors_TurboMode") or attrs.get("TurboMode")
    if turbo is not None and str(turbo).strip():
        val = str(turbo).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "Processors_TurboMode",
                "setting_name": "CPU Turbo Mode",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "CPU Turbo Mode is Enabled. Allows processors to opportunistically boost clock rates above nominal TDP baseline.",
                "citation": "vSphere 9.0 Performance Best Practices, CPU Performance (p. 17)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "Processors_TurboMode",
                "setting_name": "CPU Turbo Mode",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"CPU Turbo Mode is Disabled ({val}). Processors cannot scale frequencies dynamically under compute peaks.",
                "citation": "vSphere 9.0 Performance Best Practices, CPU Performance (p. 17)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "Processors_TurboMode",
            "setting_name": "CPU Turbo Mode",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "CPU Turbo Mode attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, CPU Performance (p. 17)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 8: Hyper-Threading / SMT ───────────────────────────────────────
    ht_val = attrs.get("Processors_HyperThreading") or attrs.get("HyperThreading")
    if ht_val is not None and str(ht_val).strip():
        val = str(ht_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "Processors_HyperThreading",
                "setting_name": "Hyper-Threading (Logical Processors)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Hyper-Threading is Enabled. Maximizes vCPU scheduling capacity and throughput for ESXi NUMA scheduler.",
                "citation": "vSphere 9.0 Performance Best Practices, CPU Virtualization (p. 17)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "Processors_HyperThreading",
                "setting_name": "Hyper-Threading (Logical Processors)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Hyper-Threading is Disabled ({val}). Server provides only physical core capacity without SMT execution threads.",
                "citation": "vSphere 9.0 Performance Best Practices, CPU Virtualization (p. 17)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "Processors_HyperThreading",
            "setting_name": "Hyper-Threading (Logical Processors)",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Hyper-Threading attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, CPU Virtualization (p. 17)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 9: Sub-NUMA Clustering (SNC) ───────────────────────────────────
    snc_val = attrs.get("Processors_SNC") or attrs.get("SNC")
    if snc_val is not None and str(snc_val).strip():
        val = str(snc_val).strip()
        val_lower = val.lower()
        if "disable" in val_lower or "auto" in val_lower:
            rules.append({
                "attribute": "Processors_SNC",
                "setting_name": "Sub-NUMA Clustering (SNC)",
                "current_value": val,
                "expected_value": "Disabled / Auto",
                "severity": None,
                "status": "compliant",
                "rationale": f"Sub-NUMA Clustering is set to {val}, exposing 1 NUMA node per physical socket for predictable VM memory placement.",
                "citation": "vSphere 9.0 Performance Best Practices, Memory Virtualization Considerations (p. 22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "Processors_SNC",
                "setting_name": "Sub-NUMA Clustering (SNC)",
                "current_value": val,
                "expected_value": "Disabled / Auto",
                "severity": "info",
                "status": "drifted",
                "rationale": f"Sub-NUMA Clustering is set to {val}. Splits each socket into multiple NUMA domains. Ensure workloads are sized to fit SNC domain bounds.",
                "citation": "vSphere 9.0 Performance Best Practices, Memory Virtualization Considerations (p. 22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "Processors_SNC",
            "setting_name": "Sub-NUMA Clustering (SNC)",
            "current_value": "Not Exposed",
            "expected_value": "Disabled / Auto",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Sub-NUMA Clustering attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, Memory Virtualization Considerations (p. 22)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 10: Hardware & Cache Prefetchers ───────────────────────────────
    hw_pref = attrs.get("Processors_HardwarePrefetcher") or attrs.get("HardwarePrefetcher")
    if hw_pref is not None and str(hw_pref).strip():
        val = str(hw_pref).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "Processors_HardwarePrefetcher",
                "setting_name": "Hardware Prefetcher",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Hardware Prefetcher is Enabled. Streams contiguous cache lines into L2/L3 caches in advance of instructions.",
                "citation": "vSphere 9.0 Performance Best Practices, Memory Performance (p. 22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "Processors_HardwarePrefetcher",
                "setting_name": "Hardware Prefetcher",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Hardware Prefetcher is Disabled ({val}). Causes significant memory latency degradation for server workloads.",
                "citation": "vSphere 9.0 Performance Best Practices, Memory Performance (p. 22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "Processors_HardwarePrefetcher",
            "setting_name": "Hardware Prefetcher",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Hardware Prefetcher attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, Memory Performance (p. 22)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 11: Boot Mode ──────────────────────────────────────────────────
    boot_mode = attrs.get("BootModes_SystemBootMode") or attrs.get("BootMode")
    if boot_mode is not None and str(boot_mode).strip():
        val = str(boot_mode).strip()
        val_lower = val.lower()
        if "uefi" in val_lower:
            rules.append({
                "attribute": "BootModes_SystemBootMode",
                "setting_name": "System Boot Mode",
                "current_value": val,
                "expected_value": "UEFIMode",
                "severity": None,
                "status": "compliant",
                "rationale": "System Boot Mode is configured for UEFI. Required for modern ESXi, Secure Boot, and VCF 9.1.",
                "citation": "vSphere 9.0 Performance Best Practices, Boot Options (p. 16)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "BootModes_SystemBootMode",
                "setting_name": "System Boot Mode",
                "current_value": val,
                "expected_value": "UEFIMode",
                "severity": "blocker",
                "status": "drifted",
                "rationale": f"System Boot Mode is set to Legacy BIOS ({val}). Legacy boot is deprecated and unsupported for VCF 9.1. Must switch to UEFI.",
                "citation": "vSphere 9.0 Performance Best Practices, Boot Options (p. 16)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })

    # ── Rule 12: MONITOR/MWAIT (HT115952 Resolution) ────────────────────────
    mwait_val = attrs.get("Processors_MONITORMWAIT") or attrs.get("MONITORMWAIT")
    if mwait_val is not None and str(mwait_val).strip():
        val = str(mwait_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "Processors_MONITORMWAIT",
                "setting_name": "MONITOR/MWAIT Instructions",
                "current_value": val,
                "expected_value": "Enable",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    "MONITOR/MWAIT is Enabled. Official VMware advisory HT115952 recommends Enable to allow the ESXi hypervisor "
                    "to efficiently execute monitor/mwait opcodes for idle state thread scheduling. "
                    "(Note: Generic LP1836 Maximum Performance preset disables MONITOR/MWAIT, but VMware-specific advisory HT115952 takes precedence)."
                ),
                "citation": "Lenovo Solution HT115952: Tuning VMware for Increased Performance",
                "citation_url": "https://support.lenovo.com/us/en/solutions/ht115952",
            })
        else:
            rules.append({
                "attribute": "Processors_MONITORMWAIT",
                "setting_name": "MONITOR/MWAIT Instructions",
                "current_value": val,
                "expected_value": "Enable",
                "severity": "warning",
                "status": "drifted",
                "rationale": (
                    f"MONITOR/MWAIT is Disabled ({val}). Although generic UEFI performance profiles disable this opcode, "
                    "VMware official advisory HT115952 specifies that MONITOR/MWAIT must be Enabled for ESXi to coordinate core idle states."
                ),
                "citation": "Lenovo Solution HT115952: Tuning VMware for Increased Performance",
                "citation_url": "https://support.lenovo.com/us/en/solutions/ht115952",
            })

    # ── Rule 13: Latency Optimized Mode (ThinkSystem V3+/V4) ────────────────
    lom_val = attrs.get("Processors_LatencyOptimizedMode") or attrs.get("LatencyOptimizedMode")
    if lom_val is not None and str(lom_val).strip():
        val = str(lom_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "Processors_LatencyOptimizedMode",
                "setting_name": "Latency Optimized Mode",
                "current_value": val,
                "expected_value": "Enable (Low-Latency) / Disable (Throughput)",
                "severity": None,
                "status": "compliant",
                "rationale": "Latency Optimized Mode is Enabled. Optimizes interconnect and memory controller queues for low-latency virtualization.",
                "citation": "ThinkSystem V4 Xeon 6 UEFI Setting Guide & HT115952",
                "citation_url": "https://pubs.lenovo.com/uefi_xeon_6th/uefi_setting_guide.pdf",
            })
        elif "disable" in val_lower:
            rules.append({
                "attribute": "Processors_LatencyOptimizedMode",
                "setting_name": "Latency Optimized Mode",
                "current_value": val,
                "expected_value": "Enable (Low-Latency) / Disable (Throughput)",
                "severity": None,
                "status": "compliant",
                "rationale": "Latency Optimized Mode is Disabled. Maximizes all-core aggregate memory bandwidth across compute threads.",
                "citation": "ThinkSystem V4 Xeon 6 UEFI Setting Guide & HT115952",
                "citation_url": "https://pubs.lenovo.com/uefi_xeon_6th/uefi_setting_guide.pdf",
            })
        else:
            rules.append({
                "attribute": "Processors_LatencyOptimizedMode",
                "setting_name": "Latency Optimized Mode",
                "current_value": val,
                "expected_value": "Enable (Low-Latency) / Disable (Throughput)",
                "severity": "info",
                "status": "drifted",
                "rationale": f"Latency Optimized Mode is set to {val}.",
                "citation": "ThinkSystem V4 Xeon 6 UEFI Setting Guide & HT115952",
                "citation_url": "https://pubs.lenovo.com/uefi_xeon_6th/uefi_setting_guide.pdf",
            })

    # ── Rule 14: C1 Enhanced Mode (C1E) ─────────────────────────────────────
    c1e_val = attrs.get("Processors_C1_EnhancedMode") or attrs.get("C1EnhancedMode") or attrs.get("C1E")
    if c1e_val is not None and str(c1e_val).strip():
        val = str(c1e_val).strip()
        val_lower = val.lower()
        if "disable" in val_lower:
            rules.append({
                "attribute": "Processors_C1_EnhancedMode",
                "setting_name": "C1 Enhanced Mode (C1E)",
                "current_value": val,
                "expected_value": "Disabled (MaxPerf) / Enabled (OS DBPM)",
                "severity": None,
                "status": "compliant",
                "rationale": "C1 Enhanced Mode (C1E) is Disabled. Recommended by Lenovo HT115952 and VMware KB 1018206 for lowest latency and jitter.",
                "citation": "Lenovo Solution HT115952: Tuning VMware for Increased Performance",
                "citation_url": "https://support.lenovo.com/us/en/solutions/ht115952",
            })
        else:
            rules.append({
                "attribute": "Processors_C1_EnhancedMode",
                "setting_name": "C1 Enhanced Mode (C1E)",
                "current_value": val,
                "expected_value": "Disabled (MaxPerf) / Enabled (OS DBPM)",
                "severity": None,
                "status": "compliant",
                "rationale": f"C1 Enhanced Mode (C1E) is set to {val}. Standard configuration for OS DBPM / ESXi Balanced power governor.",
                "citation": "Lenovo Solution HT115952: Tuning VMware for Increased Performance",
                "citation_url": "https://support.lenovo.com/us/en/solutions/ht115952",
            })

    # ── Rule 15: Energy Efficient Turbo ─────────────────────────────────────
    eet_val = attrs.get("Processors_EnergyEfficientTurbo") or attrs.get("EnergyEfficientTurbo")
    if eet_val is not None and str(eet_val).strip():
        val = str(eet_val).strip()
        val_lower = val.lower()
        if "disable" in val_lower:
            rules.append({
                "attribute": "Processors_EnergyEfficientTurbo",
                "setting_name": "Energy Efficient Turbo",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Energy Efficient Turbo is Disabled. Prevents opportunistic downclocking during transient thermal/power thresholds per HT115952.",
                "citation": "Lenovo Solution HT115952: Tuning VMware for Increased Performance",
                "citation_url": "https://support.lenovo.com/us/en/solutions/ht115952",
            })
        else:
            rules.append({
                "attribute": "Processors_EnergyEfficientTurbo",
                "setting_name": "Energy Efficient Turbo",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": "info",
                "status": "drifted",
                "rationale": f"Energy Efficient Turbo is set to {val}. Can introduce core frequency variations under heavy virtualized compute bursts. Recommended: Disabled.",
                "citation": "Lenovo Solution HT115952: Tuning VMware for Increased Performance",
                "citation_url": "https://support.lenovo.com/us/en/solutions/ht115952",
            })

    # ── Rule 16: AMD NPS / NUMA Nodes Per Socket (if AMD) ───────────────────
    amd_nps = attrs.get("NumaNodesPerSocket") or attrs.get("Processors_NUMANodesPerSocket")
    if amd_nps is not None and str(amd_nps).strip():
        val = str(amd_nps).strip()
        val_lower = val.lower()
        if any(x in val_lower for x in ("nps1", "1", "one")):
            rules.append({
                "attribute": "NumaNodesPerSocket",
                "setting_name": "AMD NUMA Nodes Per Socket (NPS)",
                "current_value": val,
                "expected_value": "NPS1 (General) / NPS4 (HPC)",
                "severity": None,
                "status": "compliant",
                "rationale": "AMD NUMA Nodes Per Socket is set to NPS1. Exposes 1 NUMA node per socket, recommended for general-purpose virtualization.",
                "citation": "Lenovo Press LP1977: Tuning UEFI Settings on AMD EPYC 9004 Processors",
                "citation_url": "https://lenovopress.lenovo.com/lp1977",
            })
        elif any(x in val_lower for x in ("nps4", "4", "four")):
            rules.append({
                "attribute": "NumaNodesPerSocket",
                "setting_name": "AMD NUMA Nodes Per Socket (NPS)",
                "current_value": val,
                "expected_value": "NPS1 (General) / NPS4 (HPC)",
                "severity": None,
                "status": "compliant",
                "rationale": "AMD NUMA Nodes Per Socket is set to NPS4. Maximizes local memory bandwidth for cache/NUMA-aligned VMs.",
                "citation": "Lenovo Press LP1977: Tuning UEFI Settings on AMD EPYC 9004 Processors",
                "citation_url": "https://lenovopress.lenovo.com/lp1977",
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
        "oem_guide_title": oem_guide["title"],
        "oem_guide_url": oem_guide["url"],
        "vmware_guide_title": VMWARE_PERF_GUIDE_TITLE,
        "vmware_guide_url": VMWARE_PERF_GUIDE_URL,
    }
