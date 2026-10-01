"""
VCF Readiness Tool — Dell PowerEdge BIOS Golden Baseline Drift Engine.

Evaluates Dell PowerEdge BIOS configuration against Broadcom VCF 9.1 and
vSAN Express Storage Architecture (ESA) recommended golden performance baselines,
incorporating official guidance from VMware vSphere 9.0 Performance Best Practices.

Clean-room implementation using Python 3.9+ standard library only.
Strictly non-destructive and read-only.
"""
import logging
from typing import Any, Dict, List, Optional

from ..logging_utils import parse_version_tuple

logger = logging.getLogger("vcf_assess")

VMWARE_PERF_GUIDE_TITLE = "VMware vSphere 9.0 Performance Best Practices"
VMWARE_PERF_GUIDE_URL = "https://www.vmware.com/docs/vsphere-esxi-vcenter-server-90-performance-best-practices"


def get_dell_tuning_guide(
    model: Optional[str] = None,
    bios_version: Optional[str] = None,
    cpu_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Resolve generation-specific Dell BIOS performance tuning guide and reference URL."""
    model_str = str(model or "").lower()
    cpu_str = ""
    if isinstance(cpu_info, dict):
        cpu_str = f"{cpu_info.get('model', '')} {cpu_info.get('architecture', '')}".lower()
    is_amd = _is_amd_cpu(cpu_info or {}) or "amd" in model_str or "epyc" in cpu_str

    # 17G: R770, R670, R7715, R6715, R7725, R6725, XE7740, XE7745, etc.
    if (
        any(k in model_str for k in ("r770", "r670", "r7715", "r6715", "r7725", "r6725", "xe7740", "xe7745", "17g"))
        or any(k in cpu_str for k in ("granite rapids", "xeon 6", "turin", "9005"))
    ):
        if is_amd:
            return {
                "title": "Dell PowerEdge 17G Technical Guide & EPYC 9005 BIOS Settings (manual22236369)",
                "url": "https://dl.dell.com/content/manual22236369-dell-poweredge-r770-technical-guide.pdf",
            }
        return {
            "title": "Dell PowerEdge 17G Technical Guide & Xeon 6 BIOS Settings (manual22236369)",
            "url": "https://dl.dell.com/content/manual22236369-dell-poweredge-r770-technical-guide.pdf",
        }

    # 16G: R760, R660, R7625, R6625, R7615, R6615, R860, R960, HS5610, HS5620, C6620, etc.
    if (
        any(k in model_str for k in ("r760", "r660", "r7625", "r6625", "r7615", "r6615", "r860", "r960", "hs5610", "hs5620", "c6620", "16g"))
        or any(k in cpu_str for k in ("sapphire rapids", "emerald rapids", "genoa", "bergamo", "9004"))
    ):
        if is_amd:
            return {
                "title": "Dell PowerEdge 16G AMD Technical Guide & EPYC 9004 BIOS Settings (manual67448375)",
                "url": "https://dl.dell.com/content/manual67448375-dell-poweredge-r7625-technical-guide.pdf",
            }
        return {
            "title": "Dell PowerEdge 16G Technical Guide & Intel Xeon Scalable BIOS Settings (manual9251811)",
            "url": "https://dl.dell.com/content/manual9251811-dell-poweredge-r760-technical-guide.pdf",
        }

    # 15G: R750, R650, R7525, R6525, R7515, R6515, C6520, C6525, etc.
    if (
        any(k in model_str for k in ("r750", "r650", "r7525", "r6525", "r7515", "r6515", "c6520", "c6525", "15g"))
        or any(k in cpu_str for k in ("ice lake", "milan", "7003"))
    ):
        return {
            "title": "Dell PowerEdge 15G Technical Guide & Ice Lake BIOS Settings (manual19169649)",
            "url": "https://dl.dell.com/content/manual19169649-dell-emc-poweredge-r750-technical-guide.pdf",
        }

    # 14G: R740, R640, R7425, R6415, R7415, R840, R940, C6420, etc.
    if (
        any(k in model_str for k in ("r740", "r640", "r7425", "r6415", "r7415", "r840", "r940", "c6420", "14g"))
        or any(k in cpu_str for k in ("skylake", "cascade lake", "rome", "naples", "7002", "7001"))
    ):
        return {
            "title": "Dell PowerEdge 14G Reference Guide & BIOS Performance Settings (manual18780968)",
            "url": "https://dl.dell.com/topicspdf/poweredge-r740_owners-manual_en-us.pdf",
        }

    return {
        "title": "Dell PowerEdge BIOS Tuning Guide for VMware vSphere (KB 000060377)",
        "url": "https://www.dell.com/support/kbdoc/en-us/000060377",
    }


def _is_multi_socket_or_intel(cpu_info: Dict[str, Any]) -> bool:
    """Check if processor topology is multi-socket Intel Xeon."""
    if not isinstance(cpu_info, dict):
        return True  # conservative default: evaluate SNC
    count = cpu_info.get("count")
    try:
        if count is not None and int(count) <= 1:
            return False
    except (ValueError, TypeError):
        pass
    arch = str(cpu_info.get("architecture") or "").lower()
    model = str(cpu_info.get("model") or "").lower()
    return not ("amd" in model or "zen" in arch or "epyc" in model)


def _is_amd_cpu(cpu_info: Dict[str, Any]) -> bool:
    """Check if processor architecture is AMD EPYC."""
    if not isinstance(cpu_info, dict):
        return False
    arch = str(cpu_info.get("architecture") or "").lower()
    model = str(cpu_info.get("model") or "").lower()
    return "amd" in model or "zen" in arch or "epyc" in model


def evaluate_dell_bios_baseline(
    bios_attrs: Optional[Dict[str, Any]],
    cpu_info: Optional[Dict[str, Any]] = None,
    is_esa_candidate: bool = False,
    model: Optional[str] = None,
    bios_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate Dell BIOS configuration attributes against VCF 9.1 Golden Baseline.

    Evaluates canonical attributes:
      1. SysProfile: Expected PerfOptimized or Custom (OS DBPM)
      2. SubNumaCluster: Expected Disabled (general-purpose) or Enabled (workload-specific)
         or AMD NumaNodesPerSocket: Expected NPS-1 (general) or NPS-4 (HPC/pinned)
      3. VmdSupport: Expected Disabled for native NVMe pass-through (Blocker if ESA candidate)
      4. PcieAspm: Expected Disabled / L0sL1Off
      5. ProcVirtualization: Expected Enabled (Critical Blocker if disabled)
      6. LogicalProc: Expected Enabled (Hyper-Threading / SMT)
      7. BootMode: Expected Uefi (Critical Blocker if legacy BIOS)
      8. ProcCStates: Expected Enabled (vSphere power/turbo) or Disabled (deterministic low-jitter)
      9. ProcTurboMode: Expected Enabled
     10. SriovGlobalEnable: Expected Enabled
     11. LatencyOptimizedMode (17G Intel): Expected Enabled (low-latency) / Disabled (throughput)
     12. PciMultiSegment (17G AMD Turin): Expected Two Segments (for dense PCIe / ESXi 8.0 U3e+)

    Args:
        bios_attrs: Dictionary of BIOS attributes (raw or normalized).
        cpu_info: CPU summary information dictionary (architecture, model, socket count).
        is_esa_candidate: Boolean indicating whether server is targeted for vSAN ESA.
        model: Optional server hardware model string (e.g. 'PowerEdge R770').
        bios_version: Optional BIOS firmware release string.

    Returns:
        Dictionary with compliance percentage, total drift count, severity counts,
        badge, and detailed per-attribute drift breakdown with VMware best practice citations.
    """
    from ..collector.oem.dell import normalize_dell_bios_attributes

    raw_attrs = bios_attrs if isinstance(bios_attrs, dict) else {}
    norm_attrs = normalize_dell_bios_attributes(raw_attrs)
    # Merge so normalized canonical keys take precedence, but caller-provided keys remain
    attrs = dict(raw_attrs)
    attrs.update(norm_attrs)

    cpu_info = cpu_info if isinstance(cpu_info, dict) else {}
    model_str = str(model or "").lower()
    cpu_str = f"{cpu_info.get('model', '')} {cpu_info.get('architecture', '')}".lower()
    oem_guide = get_dell_tuning_guide(model=model, bios_version=bios_version, cpu_info=cpu_info)
    rules: List[Dict[str, Any]] = []

    sys_profile_raw = str(attrs.get("SysProfile") or "").strip().lower()
    sys_profile_is_perf = "perfoptimized" in sys_profile_raw or "densecfgoptimized" in sys_profile_raw

    # ── Rule 1: SysProfile (System Profile) ─────────────────────────────────
    sys_profile = attrs.get("SysProfile")
    if sys_profile is not None and str(sys_profile).strip():
        val = str(sys_profile).strip()
        val_lower = val.lower()
        if "perfoptimized" in val_lower or "densecfgoptimized" in val_lower:
            rules.append({
                "attribute": "SysProfile",
                "setting_name": "System Performance Profile",
                "current_value": val,
                "expected_value": "PerfOptimized / Custom (OS DBPM)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    "System Profile is set to Performance Optimized. CPU and memory sub-timings and power regulators are tuned for peak static throughput. "
                    "Configures PCIe ASPM (Disabled), CPU Power Management (MaxPerf), C-States (Disabled), and C1E (Disabled) by proxy."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        elif "workstationperf" in val_lower:
            rules.append({
                "attribute": "SysProfile",
                "setting_name": "System Performance Profile",
                "current_value": val,
                "expected_value": "PerfOptimized / Custom (OS DBPM)",
                "severity": None,
                "status": "compliant",
                "rationale": "System Profile is set to Workstation Performance.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        elif "custom" in val_lower:
            rules.append({
                "attribute": "SysProfile",
                "setting_name": "System Performance Profile",
                "current_value": val,
                "expected_value": "PerfOptimized / Custom (OS DBPM)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"System Profile is set to Custom ({val}). Allows OS-controlled power management (OS DBPM) "
                    "as recommended by VMware Best Practices so ESXi Host Power Management can govern CPU frequencies and C-states."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        elif "perfperwattoptimizeddapc" in val_lower or "dapc" in val_lower:
            rules.append({
                "attribute": "SysProfile",
                "setting_name": "System Performance Profile",
                "current_value": val,
                "expected_value": "PerfOptimized / Custom (OS DBPM)",
                "severity": "info",
                "status": "drifted",
                "rationale": (
                    f"System Profile is set to Dell Active Power Controller (DAPC) ({val}). Subsystem dynamic throttling "
                    "can introduce slight tail latency variations under intense vSAN ESA storage I/O bursts. "
                    "For peak deterministic throughput, VMware recommends configuring OS Controlled Mode or Performance Optimized "
                    "(which tunes power and ASPM by proxy)."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "SysProfile",
                "setting_name": "System Performance Profile",
                "current_value": val,
                "expected_value": "PerfOptimized / Custom (OS DBPM)",
                "severity": "warning",
                "status": "drifted",
                "rationale": (
                    f"System Profile is set to Power/Energy Efficient mode ({val}). Subsystem power capping and dynamic "
                    "P-state throttling introduce CPU and memory latency spikes under vSAN ESA I/O bursts. "
                    "Recommended: Performance Optimized or Custom (OS DBPM)."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "SysProfile",
            "setting_name": "System Performance Profile",
            "current_value": "Not Exposed",
            "expected_value": "PerfOptimized / Custom (OS DBPM)",
            "severity": "warning",
            "status": "drifted",
            "rationale": (
                "System Profile attribute not detected in BIOS telemetry. Verify BIOS is configured for Performance Optimized or Custom (OS DBPM). "
                "Tip: Setting SysProfile to Performance Optimized automatically configures PCIe ASPM, CPU Power, and C-States by proxy."
            ),
            "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 2: SubNumaCluster / AMD NUMA ──────────────────────────────────
    if _is_amd_cpu(cpu_info):
        amd_nps = attrs.get("NumaNodesPerSocket")
        if amd_nps is not None and str(amd_nps).strip():
            val = str(amd_nps).strip()
            val_lower = val.lower()
            if any(x in val_lower for x in ("4", "nps4", "2", "nps2")):
                rules.append({
                    "attribute": "NumaNodesPerSocket",
                    "setting_name": "AMD NUMA Nodes Per Socket (NPS)",
                    "current_value": val,
                    "expected_value": "NPS-1 (General) / NPS-4 (HPC/Pinned)",
                    "severity": None,
                    "status": "compliant",
                    "rationale": (
                        f"AMD NUMA Nodes Per Socket is set to {val}. Slices each socket into multiple NUMA nodes for increased aggregate "
                        "memory bandwidth. Recommended for highly NUMA-optimized, bandwidth-intensive, or pinned workloads (e.g. HPC, in-memory databases)."
                    ),
                    "citation": "vSphere 9.0 Performance Best Practices, AMD EPYC Processor NUMA Settings (p. 28)",
                    "citation_url": VMWARE_PERF_GUIDE_URL,
                })
            elif any(x in val_lower for x in ("1", "nps1")):
                rules.append({
                    "attribute": "NumaNodesPerSocket",
                    "setting_name": "AMD NUMA Nodes Per Socket (NPS)",
                    "current_value": val,
                    "expected_value": "NPS-1 (General) / NPS-4 (HPC/Pinned)",
                    "severity": None,
                    "status": "compliant",
                    "rationale": (
                        f"AMD NUMA Nodes Per Socket is set to NPS-1 ({val}). VMware vSphere 7.0 U2+ and vSphere 8/9 recommend NPS-1 "
                        "(with CCX-as-NUMA deactivated) as the default setting for optimal performance across general-purpose virtualized workloads."
                    ),
                    "citation": "vSphere 9.0 Performance Best Practices, AMD EPYC Processor NUMA Settings (p. 28)",
                    "citation_url": VMWARE_PERF_GUIDE_URL,
                })
            else:
                rules.append({
                    "attribute": "NumaNodesPerSocket",
                    "setting_name": "AMD NUMA Nodes Per Socket (NPS)",
                    "current_value": val,
                    "expected_value": "NPS-1 (General) / NPS-4 (HPC/Pinned)",
                    "severity": None,
                    "status": "compliant",
                    "rationale": f"AMD NUMA Nodes Per Socket is set to {val}.",
                    "citation": "vSphere 9.0 Performance Best Practices, AMD EPYC Processor NUMA Settings (p. 28)",
                    "citation_url": VMWARE_PERF_GUIDE_URL,
                })
        else:
            rules.append({
                "attribute": "NumaNodesPerSocket",
                "setting_name": "AMD NUMA Nodes Per Socket (NPS)",
                "current_value": "Not Exposed",
                "expected_value": "NPS-1 (General) / NPS-4 (HPC/Pinned)",
                "severity": None,
                "status": "not_applicable",
                "rationale": "AMD NUMA configuration attribute not exposed on this platform.",
                "citation": "vSphere 9.0 Performance Best Practices, AMD EPYC Processor NUMA Settings (p. 28)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    elif _is_multi_socket_or_intel(cpu_info):
        snc = attrs.get("SubNumaCluster")
        if snc is not None and str(snc).strip():
            val = str(snc).strip()
            val_lower = val.lower()
            if val_lower in ("disabled", "off", "0", "false"):
                rules.append({
                    "attribute": "SubNumaCluster",
                    "setting_name": "Sub-NUMA Clustering (SNC)",
                    "current_value": val,
                    "expected_value": "Disabled (General) / Enabled (Workload-Specific)",
                    "severity": None,
                    "status": "compliant",
                    "rationale": (
                        f"Sub-NUMA Clustering (SNC) is Disabled ({val}) — recommended default for general-purpose virtualization and mixed VM sizes. "
                        "Preserves wide NUMA node boundaries (1 NUMA node per socket), preventing intra-socket cross-cluster memory latency "
                        "and vNUMA fragmentation across dynamic VM sizes."
                    ),
                    "citation": "vSphere 9.0 Performance Best Practices, Snoop Mode Selection (p. 28)",
                    "citation_url": VMWARE_PERF_GUIDE_URL,
                })
            elif val_lower in ("enabled", "twocluster", "fourcluster", "2cluster", "4cluster", "snc-2", "snc-4"):
                rules.append({
                    "attribute": "SubNumaCluster",
                    "setting_name": "Sub-NUMA Clustering (SNC)",
                    "current_value": val,
                    "expected_value": "Disabled (General) / Enabled (Workload-Specific)",
                    "severity": None,
                    "status": "compliant",
                    "rationale": (
                        f"Sub-NUMA Clustering (SNC) is Enabled ({val}). Partitions each socket into sub-NUMA nodes (e.g. SNC-2/SNC-4) "
                        "to maximize L3 cache locality and local memory bandwidth. Recommended specifically for NUMA-aligned workloads "
                        "sized within sub-NUMA boundaries (e.g., SAP HANA, Epic Systems Caché/IRIS, HPC). "
                        "Note: VMs larger than a half-socket will cross sub-NUMA nodes and may incur remote latency penalties."
                    ),
                    "citation": "vSphere 9.0 Performance Best Practices, Snoop Mode Selection (p. 28)",
                    "citation_url": VMWARE_PERF_GUIDE_URL,
                })
            else:
                rules.append({
                    "attribute": "SubNumaCluster",
                    "setting_name": "Sub-NUMA Clustering (SNC)",
                    "current_value": val,
                    "expected_value": "Disabled (General) / Enabled (Workload-Specific)",
                    "severity": "warning",
                    "status": "drifted",
                    "rationale": f"Sub-NUMA Clustering setting '{val}' is unrecognized. Expected Disabled (general virtualization) or Enabled (specialized NUMA workloads).",
                    "citation": "vSphere 9.0 Performance Best Practices, Snoop Mode Selection (p. 28)",
                    "citation_url": VMWARE_PERF_GUIDE_URL,
                })
        else:
            rules.append({
                "attribute": "SubNumaCluster",
                "setting_name": "Sub-NUMA Clustering (SNC)",
                "current_value": "Not Exposed",
                "expected_value": "Disabled (General) / Enabled (Workload-Specific)",
                "severity": None,
                "status": "not_applicable",
                "rationale": "Sub-NUMA Clustering attribute not exposed on single-socket or pre-Scalable Xeon hardware.",
                "citation": "vSphere 9.0 Performance Best Practices, Snoop Mode Selection (p. 28)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "SubNumaCluster",
            "setting_name": "Sub-NUMA Clustering (SNC)",
            "current_value": "N/A (Single Socket)",
            "expected_value": "N/A",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Single-socket processor topology; Sub-NUMA Clustering is not applicable.",
            "citation": "vSphere 9.0 Performance Best Practices, Snoop Mode Selection (p. 28)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 3: VmdSupport (Intel VMD) ──────────────────────────────────────
    vmd = attrs.get("VmdSupport", "Disabled")
    val = str(vmd).strip()
    is_vmd_on = val.lower() in ("enabled", "true", "auto", "1")
    if is_vmd_on:
        sev = "blocker" if is_esa_candidate else "warning"
        rules.append({
            "attribute": "VmdSupport",
            "setting_name": "Intel Volume Management Device (VMD)",
            "current_value": val,
            "expected_value": "Disabled",
            "severity": sev,
            "status": "drifted",
            "rationale": (
                f"Intel Volume Management Device (VMD) is Enabled ({val}). VMD intercepts NVMe PCIe endpoints behind a proprietary "
                "RAID/management controller, preventing native direct-attach ESXi NVMe driver attachment required for vSAN ESA. "
                "Recommended: Disabled."
            ),
            "citation": "vSphere 9.0 Performance Best Practices, NVMe Storage (p. 17)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })
    else:
        rules.append({
            "attribute": "VmdSupport",
            "setting_name": "Intel Volume Management Device (VMD)",
            "current_value": val,
            "expected_value": "Disabled",
            "severity": None,
            "status": "compliant",
            "rationale": "Intel VMD is Disabled. NVMe SSDs operate in native PCIe pass-through mode for direct ESXi kernel and vSAN ESA attachment.",
            "citation": "vSphere 9.0 Performance Best Practices, NVMe Storage (p. 17)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 4: PcieAspm (PCIe Active State Power Management) ─────────────────
    aspm = attrs.get("PcieAspm")
    if aspm is not None and str(aspm).strip():
        val = str(aspm).strip()
        val_lower = val.lower()
        if val_lower in ("enabled", "l1", "l0s", "l0sl1", "true", "1", "per port", "l1 only"):
            rules.append({
                "attribute": "PcieAspm",
                "setting_name": "PCIe Active State Power Management (ASPM)",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": (
                    f"PCIe ASPM is Enabled ({val}). In storage-dense nodes loaded with NVMe SSDs or high-speed 25GbE/100GbE NICs, "
                    "PCIe ASPM dynamically drops PCIe bus links into low-power states (L0s/L1) during brief I/O lulls. The exit wake latency can trigger "
                    "ESXi vsandevicemonitord abort timeouts (>2,000,000 µs), risking NVMe controller resets or packet drops under bursty vSAN storage syncs. "
                    "Recommended: Disabled (L0sL1Off), or apply Performance Optimized profile."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Network Hardware Considerations (p. 19)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "PcieAspm",
                "setting_name": "PCIe Active State Power Management (ASPM)",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": None,
                "status": "compliant",
                "rationale": "PCIe ASPM is Disabled. High-speed PCIe links operate at full performance without link sleep wake latency.",
                "citation": "vSphere 9.0 Performance Best Practices, Network Hardware Considerations (p. 19)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "PcieAspm",
            "setting_name": "PCIe Active State Power Management (ASPM)",
            "current_value": "Not Exposed",
            "expected_value": "Disabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "PCIe ASPM attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, Network Hardware Considerations (p. 19)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 5: ProcVirtualization (VT-x / AMD-V) ───────────────────────────
    virt = attrs.get("ProcVirtualization")
    if virt is not None and str(virt).strip():
        val = str(virt).strip()
        if val.lower() in ("enabled", "true", "1"):
            rules.append({
                "attribute": "ProcVirtualization",
                "setting_name": "Hardware Virtualization (VT-x / AMD-V)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "CPU hardware-assisted virtualization (VT-x / AMD-V) is Enabled. ESXi hypervisor can schedule 64-bit guest workloads.",
                "citation": "vSphere 9.0 Performance Best Practices, Hardware-Assisted Virtualization (p. 12, 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcVirtualization",
                "setting_name": "Hardware Virtualization (VT-x / AMD-V)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "blocker",
                "status": "drifted",
                "rationale": (
                    f"CPU Virtualization Technology is Disabled ({val}). ESXi hypervisor cannot run hardware-accelerated virtual machines. "
                    "CRITICAL BLOCKER: Enable Intel VT-x / AMD-V in BIOS before commissioning host."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Hardware-Assisted Virtualization (p. 12, 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "ProcVirtualization",
            "setting_name": "Hardware Virtualization (VT-x / AMD-V)",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": "warning",
            "status": "drifted",
            "rationale": "CPU Virtualization Technology setting not verified in BIOS attributes. Confirm VT-x / AMD-V is enabled.",
            "citation": "vSphere 9.0 Performance Best Practices, Hardware-Assisted Virtualization (p. 12, 21)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 6: LogicalProc (Hyper-Threading / SMT) ─────────────────────────
    ht = attrs.get("LogicalProc")
    if ht is not None and str(ht).strip():
        val = str(ht).strip()
        if val.lower() in ("enabled", "true", "1"):
            rules.append({
                "attribute": "LogicalProc",
                "setting_name": "Logical Processor (Hyper-Threading / SMT)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Logical Processor (Hyper-Threading / SMT) is Enabled. All hardware execution threads are available to ESXi schedulers.",
                "citation": "vSphere 9.0 Performance Best Practices, General BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "LogicalProc",
                "setting_name": "Logical Processor (Hyper-Threading / SMT)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": (
                    f"Logical Processor (Hyper-Threading / SMT) is Disabled ({val}). ESXi thread capacity is halved, severely reducing "
                    "vSAN storage worker thread scalability and VM density. Recommended: Enabled."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, General BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "LogicalProc",
            "setting_name": "Logical Processor (Hyper-Threading / SMT)",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Logical Processor attribute not exposed on this CPU architecture.",
            "citation": "vSphere 9.0 Performance Best Practices, General BIOS Settings (p. 21)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 7: BootMode (UEFI vs Legacy BIOS) ──────────────────────────────
    boot = attrs.get("BootMode")
    if boot is not None and str(boot).strip():
        val = str(boot).strip()
        if "uefi" in val.lower():
            rules.append({
                "attribute": "BootMode",
                "setting_name": "System Boot Mode",
                "current_value": val,
                "expected_value": "Uefi",
                "severity": None,
                "status": "compliant",
                "rationale": "System Boot Mode is UEFI. Fully compliant with VCF 9.1, UEFI Secure Boot, TPM 2.0 attestation, and NVMe boot devices.",
                "citation": "vSphere 9.0 Performance Best Practices, Validate Your Hardware (p. 11)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "BootMode",
                "setting_name": "System Boot Mode",
                "current_value": val,
                "expected_value": "Uefi",
                "severity": "blocker",
                "status": "drifted",
                "rationale": (
                    f"System Boot Mode is set to Legacy BIOS ({val}). VMware Cloud Foundation 9.1 and vSphere 9.1 strictly require UEFI boot mode. "
                    "Legacy BIOS prevents Secure Boot, NVMe boot, and host attestation. CRITICAL BLOCKER: Switch Boot Mode to UEFI."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Validate Your Hardware (p. 11)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "BootMode",
            "setting_name": "System Boot Mode",
            "current_value": "Unknown",
            "expected_value": "Uefi",
            "severity": "warning",
            "status": "drifted",
            "rationale": "System Boot Mode not verified in BIOS attributes. Ensure UEFI boot mode is active.",
            "citation": "vSphere 9.0 Performance Best Practices, Validate Your Hardware (p. 11)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 8: ProcCStates (Processor C-States) ────────────────────────────
    cstates = attrs.get("ProcCStates")
    if cstates is not None and str(cstates).strip():
        val = str(cstates).strip()
        val_lower = val.lower()
        if val_lower in ("enabled", "true", "1", "c1e", "all c-states", "cstates"):
            rules.append({
                "attribute": "ProcCStates",
                "setting_name": "Processor C-States",
                "current_value": val,
                "expected_value": "Enabled (vSphere Power/Turbo) / Disabled (Deterministic Jitter)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"Processor C-States are Enabled ({val}). VMware recommends activating all C-states in BIOS "
                    "to allow ESXi Host Power Management full flexibility and maximize Turbo Boost frequency headroom "
                    "on active cores when idle cores enter deep sleep states."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21–22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        elif val_lower in ("disabled", "off", "0", "false"):
            rules.append({
                "attribute": "ProcCStates",
                "setting_name": "Processor C-States",
                "current_value": val,
                "expected_value": "Enabled (vSphere Power/Turbo) / Disabled (Deterministic Jitter)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"Processor C-States are Disabled ({val}). Eliminates CPU sleep state wake latencies, providing "
                    "deterministic low-jitter execution for latency-sensitive financial or high-throughput storage workloads."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcCStates",
                "setting_name": "Processor C-States",
                "current_value": val,
                "expected_value": "Enabled (vSphere Power/Turbo) / Disabled (Deterministic Jitter)",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Processor C-States setting '{val}' is unrecognized.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21–22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "ProcCStates",
            "setting_name": "Processor C-States",
            "current_value": "Not Exposed",
            "expected_value": "Enabled (vSphere Power/Turbo) / Disabled (Deterministic Jitter)",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Processor C-States attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21–22)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 9: ProcTurboMode (Processor Turbo Mode) ────────────────────────
    turbo = attrs.get("ProcTurboMode")
    if turbo is not None and str(turbo).strip():
        val = str(turbo).strip()
        if val.lower() in ("enabled", "true", "1"):
            rules.append({
                "attribute": "ProcTurboMode",
                "setting_name": "Processor Turbo Mode",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "CPU Turbo Mode is Enabled. Processors dynamically boost to maximum all-core and single-core frequencies under load.",
                "citation": "vSphere 9.0 Performance Best Practices, General BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcTurboMode",
                "setting_name": "Processor Turbo Mode",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": (
                    f"CPU Turbo Mode is Disabled ({val}). Processors are locked to base clock frequencies, degrading peak throughput "
                    "for vSAN compression and encryption. Recommended: Enabled."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, General BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        rules.append({
            "attribute": "ProcTurboMode",
            "setting_name": "Processor Turbo Mode",
            "current_value": "Not Exposed",
            "expected_value": "Enabled",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Processor Turbo Mode attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, General BIOS Settings (p. 21)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 10: SriovGlobalEnable (SR-IOV Global Enable) ───────────────────
    sriov = attrs.get("SriovGlobalEnable")
    if sriov is not None and str(sriov).strip():
        val = str(sriov).strip()
        if val.lower() in ("enabled", "true", "1"):
            rules.append({
                "attribute": "SriovGlobalEnable",
                "setting_name": "SR-IOV Global Enable",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "SR-IOV Global Enable is Enabled in BIOS. PCIe NICs support hardware-assisted Virtual Functions (VFs).",
                "citation": "vSphere 9.0 Performance Best Practices, Network Hardware Considerations (p. 19)",
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
                "rationale": (
                    f"SR-IOV Global Enable is Disabled ({val}). PCIe adapters cannot allocate Virtual Functions for direct-path I/O "
                    "or DPU/SmartNIC offloads. Informational: Enable if Virtual Functions or DPU passthrough are required."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Network Hardware Considerations (p. 19)",
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
            "rationale": "SR-IOV Global Enable attribute not exposed in BIOS telemetry.",
            "citation": "vSphere 9.0 Performance Best Practices, Network Hardware Considerations (p. 19)",
            "citation_url": VMWARE_PERF_GUIDE_URL,
        })

    # ── Rule 11: Latency Optimized Mode (17G Intel Xeon 6 / Granite Rapids) ──
    lom_val = attrs.get("LatencyOptimizedMode") or attrs.get("LatencyOptMode")
    if lom_val is not None and str(lom_val).strip():
        val = str(lom_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "LatencyOptimizedMode",
                "setting_name": "Latency Optimized Mode (LOM)",
                "current_value": val,
                "expected_value": "Enabled (Low-Latency) / Disabled (Throughput)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    "Latency Optimized Mode is Enabled. Optimizes mesh interconnect fabric and core latency for "
                    "deterministic low-jitter virtualization and vSAN ESA I/O."
                ),
                "citation": "Dell PowerEdge: Latency Optimized Mode (LOM) on 17G Intel Processors (KB 000334057)",
                "citation_url": "https://www.dell.com/support/kbdoc/en-us/000334057",
            })
        elif "disable" in val_lower:
            rules.append({
                "attribute": "LatencyOptimizedMode",
                "setting_name": "Latency Optimized Mode (LOM)",
                "current_value": val,
                "expected_value": "Enabled (Low-Latency) / Disabled (Throughput)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    "Latency Optimized Mode is Disabled. Maximizes all-core aggregate throughput for general-purpose "
                    "compute workloads. For ultra-low latency vSAN ESA or latency-sensitive VMs, consider enabling LOM."
                ),
                "citation": "Dell PowerEdge: Latency Optimized Mode (LOM) on 17G Intel Processors (KB 000334057)",
                "citation_url": "https://www.dell.com/support/kbdoc/en-us/000334057",
            })
        else:
            rules.append({
                "attribute": "LatencyOptimizedMode",
                "setting_name": "Latency Optimized Mode (LOM)",
                "current_value": val,
                "expected_value": "Enabled (Low-Latency) / Disabled (Throughput)",
                "severity": "info",
                "status": "drifted",
                "rationale": f"Latency Optimized Mode is set to {val}.",
                "citation": "Dell PowerEdge: Latency Optimized Mode (LOM) on 17G Intel Processors (KB 000334057)",
                "citation_url": "https://www.dell.com/support/kbdoc/en-us/000334057",
            })

    # ── Rule 12: PCI Multi-Segment (17G AMD Turin EPYC 9005) ────────────────
    pci_seg = attrs.get("PciMultiSegment")
    if pci_seg is not None and str(pci_seg).strip():
        val = str(pci_seg).strip()
        val_lower = val.lower()
        if any(ok in val_lower for ok in ["two", "2", "multi", "enable"]):
            rules.append({
                "attribute": "PciMultiSegment",
                "setting_name": "PCI Multi-Segment Allocation",
                "current_value": val,
                "expected_value": "Two Segments",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    "PCI Multi-Segment is set to Two Segments. Accommodates expanded PCIe bus allocations across dual-socket "
                    "AMD EPYC 9005 topologies with high NVMe density on ESXi 8.0 U3e+ / 9.x."
                ),
                "citation": "Dell PowerEdge: AMD Turin PCI Multi-Segment Configuration for VMware ESXi (KB 000267817)",
                "citation_url": "https://www.dell.com/support/kbdoc/en-us/000267817",
            })
        else:
            rules.append({
                "attribute": "PciMultiSegment",
                "setting_name": "PCI Multi-Segment Allocation",
                "current_value": val,
                "expected_value": "Two Segments",
                "severity": "warning",
                "status": "drifted",
                "rationale": (
                    f"PCI Multi-Segment is set to {val}. For dense NVMe storage configurations on ESXi 8.0 U3e+ or 9.x, "
                    "Dell and VMware recommend Two Segments to prevent PCIe bus address exhaustion."
                ),
                "citation": "Dell PowerEdge: AMD Turin PCI Multi-Segment Configuration for VMware ESXi (KB 000267817)",
                "citation_url": "https://www.dell.com/support/kbdoc/en-us/000267817",
            })

    # ── Rule 13: ProcPwrPerf (CPU Power Management Mode) ────────────────────
    pwr_perf = attrs.get("ProcPwrPerf")
    if pwr_perf is not None and str(pwr_perf).strip():
        val = str(pwr_perf).strip()
        val_lower = val.lower()
        if any(x in val_lower for x in ("maxperf", "maximumperformance", "max performance", "performance")):
            rules.append({
                "attribute": "ProcPwrPerf",
                "setting_name": "CPU Power Management",
                "current_value": val,
                "expected_value": "MaxPerf / OsDbpm",
                "severity": None,
                "status": "compliant",
                "rationale": "CPU Power Management is set to Maximum Performance (MaxPerf). Cores run at maximum clock frequencies without dynamic down-clocking.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        elif any(x in val_lower for x in ("osdbpm", "osdbpmmode", "os controlled", "oscontrol")):
            rules.append({
                "attribute": "ProcPwrPerf",
                "setting_name": "CPU Power Management",
                "current_value": val,
                "expected_value": "MaxPerf / OsDbpm",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"CPU Power Management is set to OS DBPM ({val}). Allows ESXi Host Power Management to govern CPU dynamic voltage and frequency scaling (DVFS), "
                    "aligning with VMware general virtualization recommendations."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        elif "dapc" in val_lower or "perfperwatt" in val_lower:
            rules.append({
                "attribute": "ProcPwrPerf",
                "setting_name": "CPU Power Management",
                "current_value": val,
                "expected_value": "MaxPerf / OsDbpm",
                "severity": "info",
                "status": "drifted",
                "rationale": (
                    f"CPU Power Management is set to DAPC ({val}). Dynamic autonomous power throttling can introduce latency jitter under vSAN burst loads. "
                    "Recommended: MaxPerf or OsDbpm."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcPwrPerf",
                "setting_name": "CPU Power Management",
                "current_value": val,
                "expected_value": "MaxPerf / OsDbpm",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"CPU Power Management is set to energy saving mode ({val}). Recommended: MaxPerf or OsDbpm.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        if sys_profile_is_perf:
            rules.append({
                "attribute": "ProcPwrPerf",
                "setting_name": "CPU Power Management",
                "current_value": "MaxPerf (Proxy: SysProfile)",
                "expected_value": "MaxPerf / OsDbpm",
                "severity": None,
                "status": "compliant",
                "rationale": "CPU Power Management is locked to Maximum Performance (MaxPerf) by proxy via SysProfile = PerfOptimized.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcPwrPerf",
                "setting_name": "CPU Power Management",
                "current_value": "Not Exposed",
                "expected_value": "MaxPerf / OsDbpm",
                "severity": None,
                "status": "not_applicable",
                "rationale": "CPU Power Management attribute not exposed in BIOS telemetry.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })

    # ── Rule 14: ProcC1E (Enhanced C1 State) ─────────────────────────────────
    c1e = attrs.get("ProcC1E")
    if c1e is not None and str(c1e).strip():
        val = str(c1e).strip()
        val_lower = val.lower()
        if val_lower in ("disabled", "off", "0", "false"):
            rules.append({
                "attribute": "ProcC1E",
                "setting_name": "Processor C1E (Enhanced Halt)",
                "current_value": val,
                "expected_value": "Disabled (Deterministic Jitter) / Enabled (OS DBPM)",
                "severity": None,
                "status": "compliant",
                "rationale": "Processor C1E is Disabled. Stops the CPU from dropping voltage and frequency during halt, eliminating microsecond wake-up delays for bursty storage I/O.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21–22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        elif val_lower in ("enabled", "on", "1", "true"):
            rules.append({
                "attribute": "ProcC1E",
                "setting_name": "Processor C1E (Enhanced Halt)",
                "current_value": val,
                "expected_value": "Disabled (Deterministic Jitter) / Enabled (OS DBPM)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"Processor C1E is Enabled ({val}). Operating under OS DBPM allows ESXi to govern idle core power savings and maximize Turbo Boost frequency headroom. "
                    "For ultra-low latency vSAN ESA or deterministic jitter requirements, Dell recommends setting C1E to Disabled."
                ),
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21–22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcC1E",
                "setting_name": "Processor C1E (Enhanced Halt)",
                "current_value": val,
                "expected_value": "Disabled (Deterministic Jitter) / Enabled (OS DBPM)",
                "severity": "info",
                "status": "drifted",
                "rationale": f"Processor C1E is set to {val}.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21–22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
    else:
        if sys_profile_is_perf:
            rules.append({
                "attribute": "ProcC1E",
                "setting_name": "Processor C1E (Enhanced Halt)",
                "current_value": "Disabled (Proxy: SysProfile)",
                "expected_value": "Disabled (Deterministic Jitter) / Enabled (OS DBPM)",
                "severity": None,
                "status": "compliant",
                "rationale": "Processor C1E is disabled by proxy via SysProfile = PerfOptimized, eliminating microsecond wake exit latency.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21–22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcC1E",
                "setting_name": "Processor C1E (Enhanced Halt)",
                "current_value": "Not Exposed",
                "expected_value": "Disabled (Deterministic Jitter) / Enabled (OS DBPM)",
                "severity": None,
                "status": "not_applicable",
                "rationale": "Processor C1E attribute not exposed in BIOS telemetry.",
                "citation": "vSphere 9.0 Performance Best Practices, Power Management BIOS Settings (p. 21–22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })

    # ── Rules 15–18: AMD Platform & Infinity Fabric Controls ─────────────────
    is_amd_platform = _is_amd_cpu(cpu_info) or any(k in model_str for k in ("r7715", "r6715", "r7725", "r6725", "r7625", "r6625", "r7615", "r6615", "r7525", "r6525", "r7515", "r6515"))
    if is_amd_platform:
        # Rule 15: ApbDis (AMD Power Brake Disable)
        apbdis = attrs.get("ApbDis")
        if apbdis is not None and str(apbdis).strip():
            val = str(apbdis).strip()
            val_lower = val.lower()
            if any(ok in val_lower for ok in ("enabled", "1", "p0", "highest", "true")):
                rules.append({
                    "attribute": "ApbDis",
                    "setting_name": "AMD Power Brake Disable (APBDIS)",
                    "current_value": val,
                    "expected_value": "Enabled (Data Fabric P0 Lock) / Disabled (Dynamic Scaling)",
                    "severity": None,
                    "status": "compliant",
                    "rationale": (
                        f"AMD Power Brake Disable (APBDIS) is Enabled ({val}). Locks AMD Data Fabric interconnect frequency (FCLK) at maximum P0 state, "
                        "preventing AGESA from down-clocking the fabric during transient I/O lulls and eliminating DMA latency jitter for NVMe storage pools."
                    ),
                    "citation": "AMD EPYC Performance Tuning Guide for VMware vSphere, Fabric Frequency (APBDIS)",
                    "citation_url": oem_guide["url"],
                })
            else:
                rules.append({
                    "attribute": "ApbDis",
                    "setting_name": "AMD Power Brake Disable (APBDIS)",
                    "current_value": val,
                    "expected_value": "Enabled (Data Fabric P0 Lock) / Disabled (Dynamic Scaling)",
                    "severity": None,
                    "status": "compliant",
                    "rationale": (
                        f"AMD Power Brake Disable (APBDIS) is set to {val}. Data Fabric dynamically scales frequency (FCLK) based on utilization. "
                        "For high-throughput NVMe storage pools or vSAN ESA with heavy burst syncs, setting APBDIS to Enabled locks Data Fabric to P0 to eliminate transient latency."
                    ),
                    "citation": "AMD EPYC Performance Tuning Guide for VMware vSphere, Fabric Frequency (APBDIS)",
                    "citation_url": oem_guide["url"],
                })
        else:
            rules.append({
                "attribute": "ApbDis",
                "setting_name": "AMD Power Brake Disable (APBDIS)",
                "current_value": "Not Exposed",
                "expected_value": "Enabled (Data Fabric P0 Lock) / Disabled (Dynamic Scaling)",
                "severity": None,
                "status": "not_applicable",
                "rationale": "AMD Power Brake Disable attribute not exposed in BIOS telemetry.",
                "citation": "AMD EPYC Performance Tuning Guide for VMware vSphere, Fabric Frequency (APBDIS)",
                "citation_url": oem_guide["url"],
            })

        # Rule 16: DfCState (Data Fabric C-States)
        df_cstate = attrs.get("DfCState")
        if df_cstate is not None and str(df_cstate).strip():
            val = str(df_cstate).strip()
            val_lower = val.lower()
            if val_lower in ("disabled", "off", "0", "false"):
                rules.append({
                    "attribute": "DfCState",
                    "setting_name": "AMD Data Fabric C-States",
                    "current_value": val,
                    "expected_value": "Disabled",
                    "severity": None,
                    "status": "compliant",
                    "rationale": "AMD Data Fabric C-States are Disabled. Interconnect links remain in C0 full-power state, eliminating link wake latency for vSAN NVMe transfers.",
                    "citation": "Dell PowerEdge BIOS Performance and Workload Tuning Guide, AMD Infinity Fabric",
                    "citation_url": oem_guide["url"],
                })
            else:
                rules.append({
                    "attribute": "DfCState",
                    "setting_name": "AMD Data Fabric C-States",
                    "current_value": val,
                    "expected_value": "Disabled",
                    "severity": "info",
                    "status": "drifted",
                    "rationale": (
                        f"AMD Data Fabric C-States are Enabled ({val}). Fabric links can enter low-power idle states. Under bursty vSAN storage syncs, "
                        "fabric wake delays can contribute to tail latency. Recommended for low latency: Disabled."
                    ),
                    "citation": "Dell PowerEdge BIOS Performance and Workload Tuning Guide, AMD Infinity Fabric",
                    "citation_url": oem_guide["url"],
                })
        else:
            rules.append({
                "attribute": "DfCState",
                "setting_name": "AMD Data Fabric C-States",
                "current_value": "Not Exposed",
                "expected_value": "Disabled",
                "severity": None,
                "status": "not_applicable",
                "rationale": "AMD Data Fabric C-States attribute not exposed in BIOS telemetry.",
                "citation": "Dell PowerEdge BIOS Performance and Workload Tuning Guide, AMD Infinity Fabric",
                "citation_url": oem_guide["url"],
            })

        # Rule 17: DeterminismSlider (AMD Determinism Slider)
        det = attrs.get("DeterminismSlider") or attrs.get("DeterminismControl")
        if det is not None and str(det).strip():
            val = str(det).strip()
            val_lower = val.lower()
            if any(ok in val_lower for ok in ("perf", "performance")):
                rules.append({
                    "attribute": "DeterminismSlider",
                    "setting_name": "AMD Determinism Slider",
                    "current_value": val,
                    "expected_value": "Performance Determinism / Power Determinism",
                    "severity": None,
                    "status": "compliant",
                    "rationale": (
                        f"AMD Determinism Slider is set to Performance Determinism ({val}). Sockets and CCD cores enforce tight, consistent latency curves "
                        "rather than dynamically shifting based on socket thermal headroom. Optimal for low tail latency in vSAN ESA."
                    ),
                    "citation": "vSphere 9.0 Performance Best Practices, AMD EPYC Processor Performance (p. 28)",
                    "citation_url": VMWARE_PERF_GUIDE_URL,
                })
            elif any(ok in val_lower for ok in ("power", "auto")):
                rules.append({
                    "attribute": "DeterminismSlider",
                    "setting_name": "AMD Determinism Slider",
                    "current_value": val,
                    "expected_value": "Performance Determinism / Power Determinism",
                    "severity": None,
                    "status": "compliant",
                    "rationale": (
                        f"AMD Determinism Slider is set to Power Determinism ({val}). Dynamically maximizes core clock speeds within the socket power envelope. "
                        "Suitable for general virtualization; consider Performance Determinism for ultra-low latency."
                    ),
                    "citation": "vSphere 9.0 Performance Best Practices, AMD EPYC Processor Performance (p. 28)",
                    "citation_url": VMWARE_PERF_GUIDE_URL,
                })
            else:
                rules.append({
                    "attribute": "DeterminismSlider",
                    "setting_name": "AMD Determinism Slider",
                    "current_value": val,
                    "expected_value": "Performance Determinism / Power Determinism",
                    "severity": None,
                    "status": "compliant",
                    "rationale": f"AMD Determinism Slider is set to {val}.",
                    "citation": "vSphere 9.0 Performance Best Practices, AMD EPYC Processor Performance (p. 28)",
                    "citation_url": VMWARE_PERF_GUIDE_URL,
                })
        else:
            rules.append({
                "attribute": "DeterminismSlider",
                "setting_name": "AMD Determinism Slider",
                "current_value": "Not Exposed",
                "expected_value": "Performance Determinism / Power Determinism",
                "severity": None,
                "status": "not_applicable",
                "rationale": "AMD Determinism Slider attribute not exposed in BIOS telemetry.",
                "citation": "vSphere 9.0 Performance Best Practices, AMD EPYC Processor Performance (p. 28)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })

        # Rule 18: AmdCmnXgmiPstateControl (xGMI Power Management / P-State)
        is_single_socket_amd = any(m in model_str for m in ("r7715", "r6715", "r7615", "r6615", "r7515", "r6515", "r7415", "r6415"))
        if not is_single_socket_amd and isinstance(cpu_info, dict):
            try:
                cnt = cpu_info.get("count")
                if cnt is not None and int(cnt) <= 1:
                    is_single_socket_amd = True
            except (ValueError, TypeError):
                pass

        if is_single_socket_amd:
            rules.append({
                "attribute": "AmdCmnXgmiPstateControl",
                "setting_name": "AMD xGMI Inter-Socket Fabric Power",
                "current_value": "N/A (Single Socket)",
                "expected_value": "N/A",
                "severity": None,
                "status": "not_applicable",
                "rationale": "Single-socket AMD server platform (e.g. PowerEdge R7715). Multi-socket xGMI interconnect links are not physically present; all communication occurs across local on-die Data Fabric.",
                "citation": "Dell PowerEdge Technical Guide & AMD BIOS Settings",
                "citation_url": oem_guide["url"],
            })
        else:
            xgmi = attrs.get("AmdCmnXgmiPstateControl")
            if xgmi is not None and str(xgmi).strip():
                val = str(xgmi).strip()
                rules.append({
                    "attribute": "AmdCmnXgmiPstateControl",
                    "setting_name": "AMD xGMI Inter-Socket Fabric Power",
                    "current_value": val,
                    "expected_value": "Auto / Maximum Performance",
                    "severity": None,
                    "status": "compliant",
                    "rationale": f"AMD xGMI Inter-Socket Fabric Power is set to {val}. Maintains high inter-socket bandwidth and low latency across dual-socket AMD topologies.",
                    "citation": "Dell PowerEdge Technical Guide & AMD BIOS Settings",
                    "citation_url": oem_guide["url"],
                })
            else:
                rules.append({
                    "attribute": "AmdCmnXgmiPstateControl",
                    "setting_name": "AMD xGMI Inter-Socket Fabric Power",
                    "current_value": "Not Exposed",
                    "expected_value": "Auto / Maximum Performance",
                    "severity": None,
                    "status": "not_applicable",
                    "rationale": "AMD xGMI Inter-Socket Fabric Power attribute not exposed in BIOS telemetry.",
                    "citation": "Dell PowerEdge Technical Guide & AMD BIOS Settings",
                    "citation_url": oem_guide["url"],
                })

    # ── Rule 19: 17G AMD BIOS Version & vSAN Ready Node Catalog Alignment ───
    is_17g_amd = (
        any(m in model_str for m in ("r7715", "r6715", "r7725", "r6725"))
        or (_is_amd_cpu(cpu_info) and any(k in f"{model_str} {cpu_str}" for k in ("turin", "9005", "17g")))
    )
    if is_17g_amd and bios_version and str(bios_version).strip() and str(bios_version).strip().lower() not in ("unknown", "n/a", "none"):
        bv_str = str(bios_version).strip()
        bv_tuple = parse_version_tuple(bv_str)
        catalog_target = "1.6.4"
        catalog_tuple = parse_version_tuple(catalog_target)
        if bv_tuple > catalog_tuple:
            rules.append({
                "attribute": "BiosVersionCatalogAlignment",
                "setting_name": "vSAN Ready Node Catalog Alignment (17G AMD)",
                "current_value": f"v{bv_str}",
                "expected_value": f"v{catalog_target} (Dell vSAN Catalog Target)",
                "severity": "warning" if is_esa_candidate else "info",
                "status": "drifted",
                "rationale": (
                    f"Installed BIOS v{bv_str} exceeds the Dell vSAN Ready Node Firmware Catalog baseline (v{catalog_target}). "
                    "Dell publishes standalone cumulative bare-metal fixes (such as v1.7.7) to general support pages before vSAN qualification. "
                    "Running newer uncertified BIOS on 17G AMD Ready Nodes triggers vSphere Health / vLCM Non-Compliance warnings, "
                    "PCIe ACS / driver timing variations, and known 17G AMD AGESA warm-reboot memory initialization hangs ('Please wait while the system is initializing...'). "
                    "For production vSAN ESA clusters, Dell recommends remaining on or reverting to catalog version v1.6.4 until Dell issues an updated vSAN BOM catalog."
                ),
                "citation": "PowerEdge: Firmware Catalog for Dell's vSAN Ready Nodes (KB 000189033)",
                "citation_url": "https://www.dell.com/support/kbdoc/en-us/000189033",
            })
        elif bv_tuple == catalog_tuple:
            rules.append({
                "attribute": "BiosVersionCatalogAlignment",
                "setting_name": "vSAN Ready Node Catalog Alignment (17G AMD)",
                "current_value": f"v{bv_str}",
                "expected_value": f"v{catalog_target} (Dell vSAN Catalog Target)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"BIOS v{bv_str} strictly matches the certified Dell vSAN Ready Node Firmware Catalog baseline (v{catalog_target}). "
                    "Fully validated for ESXi 8.0/9.0 drivers, vLCM remediation, and vSAN ESA storage stack."
                ),
                "citation": "PowerEdge: Firmware Catalog for Dell's vSAN Ready Nodes (KB 000189033)",
                "citation_url": "https://www.dell.com/support/kbdoc/en-us/000189033",
            })
        else:
            rules.append({
                "attribute": "BiosVersionCatalogAlignment",
                "setting_name": "vSAN Ready Node Catalog Alignment (17G AMD)",
                "current_value": f"v{bv_str}",
                "expected_value": f"v{catalog_target} (Dell vSAN Catalog Target)",
                "severity": "warning",
                "status": "drifted",
                "rationale": (
                    f"Installed BIOS v{bv_str} is older than the certified Dell vSAN Ready Node Firmware Catalog baseline (v{catalog_target}). "
                    "Updating to v1.6.4 is recommended to apply critical AMD AGESA microcode and platform stability fixes."
                ),
                "citation": "PowerEdge: Firmware Catalog for Dell's vSAN Ready Nodes (KB 000189033)",
                "citation_url": "https://www.dell.com/support/kbdoc/en-us/000189033",
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
        "guide_url": VMWARE_PERF_GUIDE_URL,
        "guide_title": VMWARE_PERF_GUIDE_TITLE,
        "oem_guide_title": oem_guide["title"],
        "oem_guide_url": oem_guide["url"],
        "vmware_guide_title": VMWARE_PERF_GUIDE_TITLE,
        "vmware_guide_url": VMWARE_PERF_GUIDE_URL,
    }
