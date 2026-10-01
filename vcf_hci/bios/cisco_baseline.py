"""
VCF Readiness Tool — Cisco UCS BIOS Golden Baseline Drift Engine.

Evaluates Cisco UCS (C-Series rack, B-Series blade, X-Series modular) BIOS configuration
against Broadcom VCF 9.1 and vSAN Express Storage Architecture (ESA) recommended golden
performance baselines, incorporating official guidance from Cisco UCS Performance Tuning
Guides across server generations (M4, M5, M6, M7, M8) and VMware vSphere 9.0 Performance
Best Practices.

Clean-room implementation using Python 3.9+ standard library only.
Strictly non-destructive and read-only.
"""
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vcf_assess")

VMWARE_PERF_GUIDE_TITLE = "VMware vSphere 9.0 Performance Best Practices"
VMWARE_PERF_GUIDE_URL = "https://www.vmware.com/docs/vsphere-esxi-vcenter-server-90-performance-best-practices"

# Generation-specific Cisco UCS Performance Tuning Whitepapers
CISCO_TUNING_GUIDES = {
    "M4-Intel": {
        "title": "Cisco UCS M4 Performance Tuning Guide",
        "url": "https://www.cisco.com/c/dam/global/zh_cn/partners/liangjian/files/ucs/whitepaper/cisco_unified_computing_system_bios_settings.pdf",
        "generation": "M4",
        "platform": "Cisco UCS M4 (Intel Xeon E5 v3/v4)",
    },
    "M5-Intel": {
        "title": "Performance Tuning Guide for Cisco UCS M5 Servers",
        "url": "https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/ucs-b-series-blade-servers/white-paper-c11-744678.html",
        "generation": "M5",
        "platform": "Cisco UCS M5 (Intel Xeon Scalable 1st/2nd Gen)",
    },
    "M5-AMD": {
        "title": "Performance Tuning for Cisco UCS C125 M5 with AMD EPYC",
        "url": "https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/ucs-c-series-rack-servers/performance-tuning-guide.pdf",
        "generation": "M5",
        "platform": "Cisco UCS C125 M5 (AMD EPYC 7001/7002)",
    },
    "M6-Intel": {
        "title": "Performance Tuning Guide for Cisco UCS M6 Servers",
        "url": "https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/ucs-b-series-blade-servers/performance-tuning-guide-ucs-m6-servers.html#BIOSsettingsforCiscoUCSM6servers",
        "generation": "M6",
        "platform": "Cisco UCS M6 (Intel Xeon Scalable 3rd Gen Ice Lake)",
    },
    "M6-AMD": {
        "title": "Performance Tuning for Cisco UCS C225 M6 and C245 M6 with AMD EPYC",
        "url": "https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/ucs-c-series-rack-servers/performance-tuning-wp.html",
        "generation": "M6",
        "platform": "Cisco UCS M6 (AMD EPYC 7003 Milan)",
    },
    "M7-Intel": {
        "title": "Performance Tuning Best Practices Guide for Cisco UCS M7 Platforms",
        "url": "https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/ucs-b-series-blade-servers/ucs-m7-platforms-wp.html",
        "generation": "M7",
        "platform": "Cisco UCS M7 (Intel Xeon Scalable 4th/5th Gen Sapphire/Emerald Rapids)",
    },
    "M8-Intel": {
        "title": "BIOS Performance and Workload Tuning Guide for Cisco UCS M8 Platforms",
        "url": "https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/ucs-c-series-rack-servers/bios-tuning-guide-ucs-m8-intel-xeon-wp.html",
        "generation": "M8",
        "platform": "Cisco UCS M8 (Intel Xeon 6)",
    },
    "M8-AMD": {
        "title": "Performance Tuning for Cisco UCS M8 Platforms with AMD EPYC",
        "url": "https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/ucs-c-series-rack-servers/ucs-c245-m8-rack-ser-4th-gen-amd-epyc-pro-wp.html",
        "generation": "M8",
        "platform": "Cisco UCS M8 (AMD EPYC 9004/9005 Genoa/Turin)",
    },
}


def _is_amd_cpu(cpu_info: Optional[Dict[str, Any]]) -> bool:
    """Check if processor architecture is AMD EPYC."""
    if not isinstance(cpu_info, dict):
        return False
    arch = str(cpu_info.get("architecture") or "").lower()
    model = str(cpu_info.get("model") or "").lower()
    return "amd" in model or "zen" in arch or "epyc" in model


def get_cisco_tuning_guide(
    model: Optional[str] = None,
    bios_version: Optional[str] = None,
    cpu_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Identify the generation-specific Cisco UCS Performance Tuning Guide.

    Determines server generation (M4-M8) and CPU vendor (Intel vs AMD) from
    model string (e.g. UCSC-C240-M6S, UCSB-B200-M5, UCSC-C245-M8), BIOS version,
    or CPU telemetry.

    Returns:
        Dict with keys: 'title', 'url', 'generation', 'platform'.
    """
    m_str = str(model or "").upper()
    bv_str = str(bios_version or "").upper()
    is_amd = _is_amd_cpu(cpu_info)

    # Specific AMD model prefixes in Cisco UCS
    if any(k in m_str for k in ("C125", "C225", "C245")):
        # Check if CPU or model indicates AMD
        if is_amd or "AMD" in m_str:
            is_amd = True

    # Generation pattern match
    gen = "M6"  # sensible baseline default
    if "M8" in m_str or "M8" in bv_str:
        gen = "M8"
    elif "M7" in m_str or "M7" in bv_str:
        gen = "M7"
    elif "M6" in m_str or "M6" in bv_str:
        gen = "M6"
    elif "M5" in m_str or "M5" in bv_str:
        gen = "M5"
    elif "M4" in m_str or "M4" in bv_str:
        gen = "M4"
    else:
        # Infer from CPU model if model string lacked generation
        cpu_model = str((cpu_info or {}).get("model") or "").lower()
        if "xeon 6" in cpu_model or "granite" in cpu_model:
            gen = "M8"
        elif any(k in cpu_model for k in ("sapphire", "emerald", "84", "85", "64", "65", "54", "55")):
            gen = "M7"
        elif any(k in cpu_model for k in ("ice lake", "83", "63", "53", "43", "milan", "7003")):
            gen = "M6"
        elif any(k in cpu_model for k in ("cascade", "skylake", "82", "81", "62", "61", "rome", "7002")):
            gen = "M5"
        elif any(k in cpu_model for k in ("v3", "v4", "e5-26")):
            gen = "M4"

    key = f"{gen}-AMD" if is_amd else f"{gen}-Intel"
    return CISCO_TUNING_GUIDES.get(key, CISCO_TUNING_GUIDES["M6-Intel"])


def evaluate_cisco_bios_baseline(
    bios_attrs: Optional[Dict[str, Any]],
    cpu_info: Optional[Dict[str, Any]] = None,
    is_esa_candidate: bool = False,
    model: Optional[str] = None,
    bios_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate Cisco UCS BIOS configuration attributes against VCF 9.1 Golden Baseline.

    Evaluates 14 canonical performance, reliability, and security rules:
      1. Intel VT / AMD-V: Expected Enabled (Critical Blocker if disabled)
      2. Intel VT-d / AMD IOMMU: Expected Enabled (Critical Blocker if disabled)
      3. Hyper-Threading / SMT: Expected Enabled (Warning if disabled)
      4. Turbo Boost: Expected Enabled (Warning if disabled)
      5. Enhanced Intel SpeedStep (EIST): Expected Enabled (Compliant)
      6. Intel VMD: Expected Disabled for native NVMe pass-through (Critical Blocker for ESA)
      7. Memory RAS: Expected ADDDC Sparing (Platform Default & Virtualization Recommended)
      8. NUMA Optimization: Expected Enabled (Warning if disabled)
      9. Sub-NUMA Clustering (SNC): Expected Disabled for general virtualization
     10. CPU Performance Profile: Expected Enterprise or Custom
     11. Workload Configuration: Expected IO Sensitive (Platform Default) or Balanced
     12. Energy Performance Tuning: Expected OS (Platform Default, permits ESXi Host Power Policy)
     13. Hardware & Cache Prefetchers: Expected Enabled (Platform Default)
     14. Boot Mode: Expected UEFI (Critical Blocker if legacy BIOS)

    Args:
        bios_attrs: Dictionary of BIOS attributes (raw or normalized).
        cpu_info: CPU summary information dictionary.
        is_esa_candidate: Boolean indicating whether server is targeted for vSAN ESA.
        model: Server hardware model string (e.g. UCSC-C240-M6S).
        bios_version: Server BIOS firmware version string.

    Returns:
        Dictionary with compliance percentage, total drift count, severity counts,
        badge, per-attribute drift breakdown, and generation-specific whitepaper link.
    """
    from ..collector.oem.cisco import normalize_cisco_bios_attributes

    raw_attrs = bios_attrs if isinstance(bios_attrs, dict) else {}
    norm_attrs = normalize_cisco_bios_attributes(raw_attrs)
    attrs = dict(raw_attrs)
    attrs.update(norm_attrs)

    guide = get_cisco_tuning_guide(model, bios_version, cpu_info)
    guide_title = guide["title"]
    guide_url = guide["url"]

    rules: List[Dict[str, Any]] = []

    # ── Rule 1: Hardware Virtualization (Intel VT / AMD SVM) ────────────────
    vt_val = attrs.get("IntelVT") or attrs.get("ProcVirtualization") or attrs.get("SVM Mode") or attrs.get("SvmMode")
    if vt_val is not None and str(vt_val).strip():
        val = str(vt_val).strip()
        if val.lower() in ("enabled", "true", "1", "enable"):
            rules.append({
                "attribute": "ProcVirtualization",
                "setting_name": "Hardware Virtualization (Intel VT / AMD-V)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Hardware-assisted CPU virtualization is Enabled. Required for VMware ESXi 64-bit hypervisor execution.",
                "citation": f"{guide_title}, Processor Configuration",
                "citation_url": guide_url,
            })
        else:
            rules.append({
                "attribute": "ProcVirtualization",
                "setting_name": "Hardware Virtualization (Intel VT / AMD-V)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "blocker",
                "status": "drifted",
                "rationale": f"Hardware virtualization is Disabled ({val}). ESXi cannot run 64-bit virtual machines. Critical Blocker: Enable Intel VT / AMD-V in BIOS.",
                "citation": f"{guide_title}, Processor Configuration",
                "citation_url": guide_url,
            })
    else:
        rules.append({
            "attribute": "ProcVirtualization",
            "setting_name": "Hardware Virtualization (Intel VT / AMD-V)",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Hardware virtualization attribute not exposed in BIOS telemetry.",
            "citation": f"{guide_title}, Processor Configuration",
            "citation_url": guide_url,
        })

    # ── Rule 2: Directed I/O (Intel VT-d / AMD IOMMU) ───────────────────────
    vtd_val = attrs.get("IntelVTD") or attrs.get("VtdSupport") or attrs.get("IOMMU") or attrs.get("Iommu")
    if vtd_val is not None and str(vtd_val).strip():
        val = str(vtd_val).strip()
        if val.lower() in ("enabled", "true", "1", "enable"):
            rules.append({
                "attribute": "VtdSupport",
                "setting_name": "Directed I/O (Intel VT-d / AMD IOMMU)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Intel VT for Directed I/O (VT-d / AMD IOMMU) is Enabled. Required for DMA isolation, memory protection, and PCIe passthrough.",
                "citation": f"{guide_title}, Processor Configuration",
                "citation_url": guide_url,
            })
        else:
            rules.append({
                "attribute": "VtdSupport",
                "setting_name": "Directed I/O (Intel VT-d / AMD IOMMU)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "blocker",
                "status": "drifted",
                "rationale": f"Directed I/O is Disabled ({val}). ESXi requires VT-d / IOMMU for device memory isolation and direct DMA. Critical Blocker: Enable in BIOS.",
                "citation": f"{guide_title}, Processor Configuration",
                "citation_url": guide_url,
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
            "citation": f"{guide_title}, Processor Configuration",
            "citation_url": guide_url,
        })

    # ── Rule 3: Hyper-Threading / Logical Processor ─────────────────────────
    ht_val = attrs.get("IntelHyperThread") or attrs.get("LogicalProc") or attrs.get("SMT Mode") or attrs.get("SmtMode")
    if ht_val is not None and str(ht_val).strip():
        val = str(ht_val).strip()
        if val.lower() in ("enabled", "true", "1", "enable"):
            rules.append({
                "attribute": "LogicalProc",
                "setting_name": "Hyper-Threading / SMT",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Logical Processor / Hyper-Threading is Enabled. Maximizes vCPU scheduling capacity and compute throughput.",
                "citation": f"{guide_title}, Processor Configuration",
                "citation_url": guide_url,
            })
        else:
            rules.append({
                "attribute": "LogicalProc",
                "setting_name": "Hyper-Threading / SMT",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Hyper-Threading is Disabled ({val}). Available logical cores are halved, reducing VM consolidation density. Recommended: Enabled.",
                "citation": f"{guide_title}, Processor Configuration",
                "citation_url": guide_url,
            })
    else:
        rules.append({
            "attribute": "LogicalProc",
            "setting_name": "Hyper-Threading / SMT",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Hyper-Threading attribute not exposed in BIOS telemetry.",
            "citation": f"{guide_title}, Processor Configuration",
            "citation_url": guide_url,
        })

    # ── Rule 4: Turbo Boost / Core Performance Boost ────────────────────────
    turbo_val = attrs.get("IntelTurboBoostTech") or attrs.get("ProcTurboMode") or attrs.get("Core Performance Boost")
    if turbo_val is not None and str(turbo_val).strip():
        val = str(turbo_val).strip()
        if val.lower() in ("enabled", "true", "1", "enable"):
            rules.append({
                "attribute": "ProcTurboMode",
                "setting_name": "Processor Turbo Boost",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Processor Turbo Boost is Enabled. Allows processors to opportunistically exceed base operating frequencies under workload demand.",
                "citation": f"{guide_title}, Processor Configuration",
                "citation_url": guide_url,
            })
        else:
            rules.append({
                "attribute": "ProcTurboMode",
                "setting_name": "Processor Turbo Boost",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Turbo Boost is Disabled ({val}). Processors are locked to base clock frequencies, degrading peak compute throughput. Recommended: Enabled.",
                "citation": f"{guide_title}, Processor Configuration",
                "citation_url": guide_url,
            })
    else:
        rules.append({
            "attribute": "ProcTurboMode",
            "setting_name": "Processor Turbo Boost",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Processor Turbo Boost attribute not exposed in BIOS telemetry.",
            "citation": f"{guide_title}, Processor Configuration",
            "citation_url": guide_url,
        })

    # ── Rule 5: Enhanced Intel SpeedStep (EIST) ─────────────────────────────
    eist_val = attrs.get("EnhancedIntelSpeedStep") or attrs.get("SpeedStep")
    if eist_val is not None and str(eist_val).strip():
        val = str(eist_val).strip()
        if val.lower() in ("enabled", "true", "1", "enable"):
            rules.append({
                "attribute": "SpeedStep",
                "setting_name": "Enhanced Intel SpeedStep (EIST)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Enhanced Intel SpeedStep is Enabled. Permits ESXi host power policies to regulate dynamic P-states.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management (p. 22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "SpeedStep",
                "setting_name": "Enhanced Intel SpeedStep (EIST)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "info",
                "status": "drifted",
                "rationale": f"Enhanced Intel SpeedStep is Disabled ({val}). Processor operates at static frequency without dynamic P-state scaling.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management (p. 22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "SpeedStep",
            "setting_name": "Enhanced Intel SpeedStep (EIST)",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "SpeedStep attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, Power Management (p. 22)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 6: Intel VMD (Volume Management Device) ────────────────────────
    vmd_val = attrs.get("VMDEnable") or attrs.get("VmdSupport")
    if vmd_val is not None and str(vmd_val).strip():
        val = str(vmd_val).strip()
        if val.lower() in ("disabled", "false", "0", "disable"):
            rules.append({
                "attribute": "VmdSupport",
                "setting_name": "Intel Volume Management Device (VMD)",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Intel VMD is Disabled in BIOS (Platform Default). Native PCIe pass-through mode active for vSAN ESA NVMe SSDs.",
                "citation": "VMware Cloud Foundation 9.1 Architecture Guide — vSAN ESA Storage Requirements",
                "citation_url": "https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html",
            })
        else:
            sev = "blocker" if is_esa_candidate else "warning"
            rules.append({
                "attribute": "VmdSupport",
                "setting_name": "Intel Volume Management Device (VMD)",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": sev,
                "status": "drifted",
                "rationale": (
                    f"Intel VMD is Enabled ({val}). For vSAN ESA, Intel VMD must be Disabled in BIOS to permit native NVMe driver "
                    f"direct attachment. {'Critical Blocker for vSAN ESA.' if is_esa_candidate else 'Recommended Disabled for native NVMe performance.'}"
                ),
                "citation": "VMware Cloud Foundation 9.1 Architecture Guide — vSAN ESA Storage Requirements",
                "citation_url": "https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html",
            })
    else:
        rules.append({
            "attribute": "VmdSupport",
            "setting_name": "Intel Volume Management Device (VMD)",
            "current_value": "Not Exposed",
            "expected_value": "Disabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Intel VMD attribute not exposed in BIOS telemetry.",
            "citation": "VMware Cloud Foundation 9.1 Architecture Guide — vSAN ESA Storage Requirements",
            "citation_url": "https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html",
        })

    # ── Rule 7: Memory RAS (SelectMemoryRAS) ────────────────────────────────
    ras_val = attrs.get("SelectMemoryRAS") or attrs.get("MemOpMode")
    if ras_val is not None and str(ras_val).strip():
        val = str(ras_val).strip()
        v_low = val.lower()
        if "adddc" in v_low:
            rules.append({
                "attribute": "MemOpMode",
                "setting_name": "Memory RAS Configuration",
                "current_value": val,
                "expected_value": "ADDDC Sparing / Maximum Performance",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    "ADDDC Sparing is active (Cisco Platform Default & Virtualization Recommended). Adaptive Double Device Data "
                    "Correction provides enterprise DRAM rank fault tolerance with minimal latency overhead."
                ),
                "citation": f"{guide_title}, Memory RAS Configuration",
                "citation_url": guide_url,
            })
        elif "max" in v_low or "perf" in v_low:
            rules.append({
                "attribute": "MemOpMode",
                "setting_name": "Memory RAS Configuration",
                "current_value": val,
                "expected_value": "ADDDC Sparing / Maximum Performance",
                "severity": None,
                "status": "compliant",
                "rationale": "Maximum Performance mode active. Standard ECC operation without sparing overhead; full memory bandwidth available.",
                "citation": f"{guide_title}, Memory RAS Configuration",
                "citation_url": guide_url,
            })
        elif "mirror" in v_low:
            rules.append({
                "attribute": "MemOpMode",
                "setting_name": "Memory RAS Configuration",
                "current_value": val,
                "expected_value": "ADDDC Sparing / Maximum Performance",
                "severity": "warning",
                "status": "drifted",
                "rationale": (
                    f"Memory Mirroring is active ({val}). 50% of installed memory capacity is consumed as mirror redundancy. "
                    "Re-validate vSAN node usable RAM sizing."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Memory Configuration",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "MemOpMode",
                "setting_name": "Memory RAS Configuration",
                "current_value": val,
                "expected_value": "ADDDC Sparing / Maximum Performance",
                "severity": "info",
                "status": "compliant",
                "rationale": f"Memory RAS operating mode is {val}.",
                "citation": f"{guide_title}, Memory RAS Configuration",
                "citation_url": guide_url,
            })
    else:
        rules.append({
            "attribute": "MemOpMode",
            "setting_name": "Memory RAS Configuration",
            "current_value": "Not Exposed",
            "expected_value": "ADDDC Sparing",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Memory RAS attribute not exposed in BIOS telemetry.",
            "citation": f"{guide_title}, Memory RAS Configuration",
            "citation_url": guide_url,
        })

    # ── Rule 8: NUMA Optimization (NUMAOptimize) ────────────────────────────
    numa_val = attrs.get("NUMAOptimize")
    if numa_val is not None and str(numa_val).strip():
        val = str(numa_val).strip()
        if val.lower() in ("enabled", "true", "1", "enable"):
            rules.append({
                "attribute": "NUMAOptimize",
                "setting_name": "NUMA Optimization",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "NUMA Optimization is Enabled (Platform Default). Hardware NUMA topology is exposed directly to the ESXi hypervisor.",
                "citation": "vSphere 9.0 Performance Best Practices, NUMA Considerations (p. 23)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "NUMAOptimize",
                "setting_name": "NUMA Optimization",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"NUMA Optimization is Disabled ({val}). Memory is interleaved across sockets, hiding NUMA topology from ESXi. Recommended: Enabled.",
                "citation": "vSphere 9.0 Performance Best Practices, NUMA Considerations (p. 23)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "NUMAOptimize",
            "setting_name": "NUMA Optimization",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "NUMA Optimization attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, NUMA Considerations (p. 23)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 9: Sub-NUMA Clustering (SNC) / AMD NPS ─────────────────────────
    snc_val = attrs.get("SNC") or attrs.get("SubNumaCluster") or attrs.get("NumaNodesPerSocket")
    if snc_val is not None and str(snc_val).strip():
        val = str(snc_val).strip()
        v_low = val.lower()
        if v_low in ("disabled", "auto", "off", "1", "nps1"):
            rules.append({
                "attribute": "SubNumaCluster",
                "setting_name": "Sub-NUMA Clustering (SNC)",
                "current_value": val,
                "expected_value": "Disabled / SNC2",
                "severity": None,
                "status": "compliant",
                "rationale": "Sub-NUMA Clustering is Disabled (Platform Default). Sockets exposed as single NUMA domains, optimal for general-purpose virtualization.",
                "citation": f"{guide_title}, Memory Configuration",
                "citation_url": guide_url,
            })
        else:
            rules.append({
                "attribute": "SubNumaCluster",
                "setting_name": "Sub-NUMA Clustering (SNC)",
                "current_value": val,
                "expected_value": "Disabled / SNC2",
                "severity": None,
                "status": "compliant",
                "rationale": f"Sub-NUMA Clustering is set to {val}. Sockets partitioned into sub-NUMA domains; ensure VMs are sized to fit within cluster boundaries.",
                "citation": f"{guide_title}, Memory Configuration",
                "citation_url": guide_url,
            })
    else:
        rules.append({
            "attribute": "SubNumaCluster",
            "setting_name": "Sub-NUMA Clustering (SNC)",
            "current_value": "Not Exposed",
            "expected_value": "Disabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Sub-NUMA Clustering attribute not exposed in BIOS telemetry.",
            "citation": f"{guide_title}, Memory Configuration",
            "citation_url": guide_url,
        })

    # ── Rule 10: CPU Performance Profile ────────────────────────────────────
    cpu_perf = attrs.get("CPUPerformance") or attrs.get("SysProfile")
    if cpu_perf is not None and str(cpu_perf).strip():
        val = str(cpu_perf).strip()
        v_low = val.lower()
        if any(k in v_low for k in ("enterprise", "throughput", "hpc", "custom", "performance")):
            rules.append({
                "attribute": "SysProfile",
                "setting_name": "CPU Performance Profile",
                "current_value": val,
                "expected_value": "Enterprise / Custom",
                "severity": None,
                "status": "compliant",
                "rationale": f"CPU Performance is set to {val} (Cisco Platform Default). Prefetchers and acceleration knobs tuned for enterprise virtualization.",
                "citation": f"{guide_title}, BIOS Profile Settings",
                "citation_url": guide_url,
            })
        elif "power" in v_low or "energy" in v_low:
            rules.append({
                "attribute": "SysProfile",
                "setting_name": "CPU Performance Profile",
                "current_value": val,
                "expected_value": "Enterprise / Custom",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"CPU Performance profile is tuned for power savings ({val}). May degrade vSAN latency and VM performance. Recommended: Enterprise.",
                "citation": f"{guide_title}, BIOS Profile Settings",
                "citation_url": guide_url,
            })
        else:
            rules.append({
                "attribute": "SysProfile",
                "setting_name": "CPU Performance Profile",
                "current_value": val,
                "expected_value": "Enterprise / Custom",
                "severity": None,
                "status": "compliant",
                "rationale": f"CPU Performance profile is {val}.",
                "citation": f"{guide_title}, BIOS Profile Settings",
                "citation_url": guide_url,
            })
    else:
        rules.append({
            "attribute": "SysProfile",
            "setting_name": "CPU Performance Profile",
            "current_value": "Not Exposed",
            "expected_value": "Enterprise",
            "severity": None,
            "status": "not_applicable",
            "rationale": "CPU Performance profile attribute not exposed in BIOS telemetry.",
            "citation": f"{guide_title}, BIOS Profile Settings",
            "citation_url": guide_url,
        })

    # ── Rule 11: Workload Configuration ─────────────────────────────────────
    workld = attrs.get("WorkLdConfig")
    if workld is not None and str(workld).strip():
        val = str(workld).strip()
        v_low = val.lower()
        if "io" in v_low or "sensitive" in v_low or "balanced" in v_low:
            rules.append({
                "attribute": "WorkLdConfig",
                "setting_name": "Workload Configuration",
                "current_value": val,
                "expected_value": "IO Sensitive / Balanced",
                "severity": None,
                "status": "compliant",
                "rationale": f"Workload Configuration is set to {val} (Cisco Platform Default). Maximizes I/O and memory throughput across interconnect links.",
                "citation": f"{guide_title}, Workload Configuration",
                "citation_url": guide_url,
            })
        else:
            rules.append({
                "attribute": "WorkLdConfig",
                "setting_name": "Workload Configuration",
                "current_value": val,
                "expected_value": "IO Sensitive",
                "severity": "info",
                "status": "compliant",
                "rationale": f"Workload Configuration is set to {val}.",
                "citation": f"{guide_title}, Workload Configuration",
                "citation_url": guide_url,
            })
    else:
        rules.append({
            "attribute": "WorkLdConfig",
            "setting_name": "Workload Configuration",
            "current_value": "Not Exposed",
            "expected_value": "IO Sensitive",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Workload Configuration attribute not exposed in BIOS telemetry.",
            "citation": f"{guide_title}, Workload Configuration",
            "citation_url": guide_url,
        })

    # ── Rule 12: Energy Performance Tuning (PwrPerfTuning) ───────────────────
    pwr_tune = attrs.get("PwrPerfTuning")
    if pwr_tune is not None and str(pwr_tune).strip():
        val = str(pwr_tune).strip()
        v_low = val.lower()
        if "os" in v_low:
            rules.append({
                "attribute": "PwrPerfTuning",
                "setting_name": "Energy Performance Tuning",
                "current_value": val,
                "expected_value": "OS / BIOS",
                "severity": None,
                "status": "compliant",
                "rationale": "Energy Performance Tuning is set to OS (Cisco Platform Default). Operating system (ESXi) Host Power Policy governs CPU energy bias.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management (p. 22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "PwrPerfTuning",
                "setting_name": "Energy Performance Tuning",
                "current_value": val,
                "expected_value": "OS / BIOS",
                "severity": None,
                "status": "compliant",
                "rationale": f"Energy Performance Tuning is set to {val}.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management (p. 22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "PwrPerfTuning",
            "setting_name": "Energy Performance Tuning",
            "current_value": "Not Exposed",
            "expected_value": "OS",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Energy Performance Tuning attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, Power Management (p. 22)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 13: Hardware & Cache Prefetchers ───────────────────────────────
    hw_pref = attrs.get("HardwarePrefetch") or attrs.get("AdjacentCacheLinePrefetch")
    if hw_pref is not None and str(hw_pref).strip():
        val = str(hw_pref).strip()
        if val.lower() in ("enabled", "true", "1", "enable"):
            rules.append({
                "attribute": "HardwarePrefetch",
                "setting_name": "Hardware & Cache Prefetchers",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Hardware & Cache Line Prefetchers are Enabled (Platform Default). Data prefetching active across caches for sequential memory streaming.",
                "citation": f"{guide_title}, Processor Configuration",
                "citation_url": guide_url,
            })
        else:
            rules.append({
                "attribute": "HardwarePrefetch",
                "setting_name": "Hardware & Cache Prefetchers",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Hardware Prefetcher is Disabled ({val}). Degrades memory streaming throughput for virtual machine workloads. Recommended: Enabled.",
                "citation": f"{guide_title}, Processor Configuration",
                "citation_url": guide_url,
            })
    else:
        rules.append({
            "attribute": "HardwarePrefetch",
            "setting_name": "Hardware & Cache Prefetchers",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Hardware Prefetcher attribute not exposed in BIOS telemetry.",
            "citation": f"{guide_title}, Processor Configuration",
            "citation_url": guide_url,
        })

    # ── Rule 14: Boot Mode ──────────────────────────────────────────────────
    bm_val = attrs.get("BootMode")
    if bm_val is not None and str(bm_val).strip() and str(bm_val).strip().lower() not in ("not exposed", ""):
        val = str(bm_val).strip()
        if "uefi" in val.lower():
            rules.append({
                "attribute": "BootMode",
                "setting_name": "System Boot Mode",
                "current_value": val,
                "expected_value": "UEFI",
                "severity": None,
                "status": "compliant",
                "rationale": f"Boot Mode is {val}. Broadcom VCF 9.1 mandates Pure UEFI boot mode across all workload and management domains.",
                "citation": "VMware Cloud Foundation 9.1 Architecture and Deployment Guide",
                "citation_url": "https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html",
            })
        elif any(k in val.lower() for k in ("unknown", "none", "n/a")):
            rules.append({
                "attribute": "BootMode",
                "setting_name": "System Boot Mode",
                "current_value": val,
                "expected_value": "UEFI",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Boot Mode is {val} in BIOS telemetry. Broadcom VCF 9.1 mandates Pure UEFI boot mode across all hosts.",
                "citation": "VMware Cloud Foundation 9.1 Architecture and Deployment Guide",
                "citation_url": "https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html",
            })
        else:
            rules.append({
                "attribute": "BootMode",
                "setting_name": "System Boot Mode",
                "current_value": val,
                "expected_value": "UEFI",
                "severity": "blocker",
                "status": "drifted",
                "rationale": f"Boot Mode is Legacy CSM ({val}). Broadcom VCF 9.1 mandates Pure UEFI boot mode. Critical Blocker: Switch to UEFI.",
                "citation": "VMware Cloud Foundation 9.1 Architecture and Deployment Guide",
                "citation_url": "https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html",
            })
    else:
        rules.append({
            "attribute": "BootMode",
            "setting_name": "System Boot Mode",
            "current_value": "Not Exposed",
            "expected_value": "UEFI",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Boot Mode attribute not exposed in BIOS telemetry.",
            "citation": "VMware Cloud Foundation 9.1 Architecture and Deployment Guide",
            "citation_url": "https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html",
        })

    # ── Rule 15: Processor Core C-States & C1E ──────────────────────────────
    cstate_val = attrs.get("CoreCState") or attrs.get("ProcCStates") or attrs.get("C1E") or attrs.get("C6State")
    if cstate_val is not None and str(cstate_val).strip() and str(cstate_val).strip().lower() not in ("not exposed", ""):
        val = str(cstate_val).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["disabled", "off", "0", "no"]):
            rules.append({
                "attribute": "CoreCState",
                "setting_name": "Processor Core C-States",
                "current_value": val,
                "expected_value": "Disabled (MaxPerf) / Enabled (Dynamic Turbo)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    "Core C-States are Disabled. Cisco UCS M5 tuning guide and VMware KB 1018206 recommend disabling C-states "
                    "for latency-sensitive workloads to eliminate core sleep wake-up transitions. "
                    "When BIOS is set to high performance, Cisco recommends setting ESXi Host Power Policy to High Performance."
                ),
                "citation": f"{guide_title}, Processor Power Management",
                "citation_url": guide_url,
            })
        else:
            rules.append({
                "attribute": "CoreCState",
                "setting_name": "Processor Core C-States",
                "current_value": val,
                "expected_value": "Disabled (MaxPerf) / Enabled (Dynamic Turbo)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"Core C-States are Enabled ({val}). In Cisco UCS M6/M7/M8 virtualization guidance, C-states are enabled "
                    "to allow idle cores to enter low-power sleep and yield higher Turbo Boost frequencies for active cores. "
                    "(Note: In M5, Cisco recommended disabling C-states; for lowest deterministic latency per KB 1018206, disable C-states)."
                ),
                "citation": f"{guide_title}, Processor Power Management",
                "citation_url": guide_url,
            })
    else:
        rules.append({
            "attribute": "CoreCState",
            "setting_name": "Processor Core C-States",
            "current_value": "Not Exposed",
            "expected_value": "Disabled / Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Processor Core C-States attribute not exposed in BIOS telemetry.",
            "citation": f"{guide_title}, Processor Power Management",
            "citation_url": guide_url,
        })

    # ── Rule 16: Latency Optimized Mode (Cisco UCS M8 Intel) ────────────────
    lom_val = attrs.get("LatencyOptimizedMode") or attrs.get("LatencyOptMode")
    if lom_val is not None and str(lom_val).strip() and str(lom_val).strip().lower() not in ("not exposed", ""):
        val = str(lom_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "LatencyOptimizedMode",
                "setting_name": "Latency Optimized Mode (M8 Intel)",
                "current_value": val,
                "expected_value": "Enabled (Low-Latency) / Disabled (Throughput)",
                "severity": None,
                "status": "compliant",
                "rationale": "Latency Optimized Mode is Enabled. Optimizes interconnect fabric latency for deterministic virtualization.",
                "citation": f"{guide_title}, BIOS Settings for Cisco UCS M8 Intel",
                "citation_url": guide_url,
            })
        elif "disable" in val_lower:
            rules.append({
                "attribute": "LatencyOptimizedMode",
                "setting_name": "Latency Optimized Mode (M8 Intel)",
                "current_value": val,
                "expected_value": "Enabled (Low-Latency) / Disabled (Throughput)",
                "severity": None,
                "status": "compliant",
                "rationale": "Latency Optimized Mode is Disabled. Maximizes all-core aggregate memory bandwidth for general virtualization.",
                "citation": f"{guide_title}, BIOS Settings for Cisco UCS M8 Intel",
                "citation_url": guide_url,
            })
        else:
            rules.append({
                "attribute": "LatencyOptimizedMode",
                "setting_name": "Latency Optimized Mode (M8 Intel)",
                "current_value": val,
                "expected_value": "Enabled (Low-Latency) / Disabled (Throughput)",
                "severity": "info",
                "status": "drifted",
                "rationale": f"Latency Optimized Mode is set to {val}.",
                "citation": f"{guide_title}, BIOS Settings for Cisco UCS M8 Intel",
                "citation_url": guide_url,
            })
    else:
        rules.append({
            "attribute": "LatencyOptimizedMode",
            "setting_name": "Latency Optimized Mode (M8 Intel)",
            "current_value": "Not Exposed",
            "expected_value": "Enabled / Disabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Latency Optimized Mode attribute not exposed on this server generation.",
            "citation": f"{guide_title}, BIOS Settings for Cisco UCS M8 Intel",
            "citation_url": guide_url,
        })

    # ── Rule 17: Optimized Power Mode (Cisco UCS M8 Intel) ──────────────────
    opm_val = attrs.get("OptimizedPowerMode")
    if opm_val is not None and str(opm_val).strip() and str(opm_val).strip().lower() not in ("not exposed", ""):
        val = str(opm_val).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["disabled", "off", "0", "disable"]):
            rules.append({
                "attribute": "OptimizedPowerMode",
                "setting_name": "Optimized Power Mode (M8 Intel)",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Optimized Power Mode is Disabled. Ensures maximum deterministic performance without uncore frequency throttling.",
                "citation": f"{guide_title}, BIOS Settings for Cisco UCS M8 Intel",
                "citation_url": guide_url,
            })
        else:
            rules.append({
                "attribute": "OptimizedPowerMode",
                "setting_name": "Optimized Power Mode (M8 Intel)",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Optimized Power Mode is Enabled ({val}). Cisco recommends Disabled for enterprise virtualization workloads.",
                "citation": f"{guide_title}, BIOS Settings for Cisco UCS M8 Intel",
                "citation_url": guide_url,
            })
    else:
        rules.append({
            "attribute": "OptimizedPowerMode",
            "setting_name": "Optimized Power Mode (M8 Intel)",
            "current_value": "Not Exposed",
            "expected_value": "Disabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Optimized Power Mode attribute not exposed on this server generation.",
            "citation": f"{guide_title}, BIOS Settings for Cisco UCS M8 Intel",
            "citation_url": guide_url,
        })

    # ── Rule 18: AMD Fabric & Determinism Tuning (AMD EPYC) ─────────────────
    if _is_amd_cpu(cpu_info) or "AMD" in str(model or "").upper():
        amd_det = attrs.get("DeterminismSlider") or attrs.get("Determinism")
        if amd_det is not None and str(amd_det).strip():
            val = str(amd_det).strip()
            if "power" in val.lower():
                rules.append({
                    "attribute": "DeterminismSlider",
                    "setting_name": "AMD Processor Determinism Slider",
                    "current_value": val,
                    "expected_value": "Power Determinism",
                    "severity": None,
                    "status": "compliant",
                    "rationale": "AMD Determinism Slider is set to Power Determinism. Cisco recommends Power determinism for consistent cross-core frequencies.",
                    "citation": f"{guide_title}, AMD Processor Configuration",
                    "citation_url": guide_url,
                })
            else:
                rules.append({
                    "attribute": "DeterminismSlider",
                    "setting_name": "AMD Processor Determinism Slider",
                    "current_value": val,
                    "expected_value": "Power Determinism",
                    "severity": "info",
                    "status": "drifted",
                    "rationale": f"AMD Determinism Slider is set to {val}. Cisco recommends Power determinism for deterministic performance across sockets.",
                    "citation": f"{guide_title}, AMD Processor Configuration",
                    "citation_url": guide_url,
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
            f"<span class='badge danger'>🔴 Cisco BIOS Drift: {blocker_count} Blocker"
            f"{'s' if blocker_count > 1 else ''} ({compliance_pct}% Compliant)</span>"
        )
    elif warning_count > 0:
        status = "warning"
        badge = (
            f"<span class='badge warning'>🟡 Cisco BIOS Drift: {warning_count} Warning"
            f"{'s' if warning_count > 1 else ''} ({compliance_pct}% Compliant)</span>"
        )
    elif info_count > 0:
        status = "info"
        badge = (
            f"<span class='badge info'>ℹ️ Cisco BIOS Optimization: {info_count} Note"
            f"{'s' if info_count > 1 else ''} ({compliance_pct}% Compliant)</span>"
        )
    else:
        status = "pass"
        badge = "<span class='badge success'>🟢 Cisco BIOS Golden Baseline: 100% Compliant</span>"

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
        "tuning_guide": guide,
        "guide_title": guide["title"],
        "guide_url": guide["url"],
        "oem_guide_title": guide["title"],
        "oem_guide_url": guide["url"],
        "vmware_guide_title": VMWARE_PERF_GUIDE_TITLE,
        "vmware_guide_url": VMWARE_PERF_GUIDE_URL,
    }
