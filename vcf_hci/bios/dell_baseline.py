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

from ..compat.firmware_currency import classify_currency, match_baseline
from ..constants import BIOS_BASELINES
from .dell_rules import (
    _is_amd_cpu as _is_amd_cpu,
)
from .dell_rules import (
    _is_multi_socket_or_intel as _is_multi_socket_or_intel,
)
from .dell_rules import (
    evaluate_amd_apbdis,
    evaluate_amd_determinism,
    evaluate_amd_fabric_cstates,
    evaluate_amd_xgmi,
    evaluate_boot_mode,
    evaluate_c1e,
    evaluate_catalog_alignment,
    evaluate_cstates,
    evaluate_latency_mode,
    evaluate_numa_policy,
    evaluate_pci_multisegment,
    evaluate_pcie_aspm,
    evaluate_power_management,
    evaluate_smt,
    evaluate_sriov,
    evaluate_system_profile,
    evaluate_turbo,
    evaluate_virtualization,
    evaluate_vmd,
    summarize_dell_rules,
)

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

    rules.extend(evaluate_system_profile(attrs, VMWARE_PERF_GUIDE_URL))
    rules.extend(evaluate_numa_policy(attrs, cpu_info, VMWARE_PERF_GUIDE_URL))
    rules.extend(evaluate_vmd(attrs, is_esa_candidate, VMWARE_PERF_GUIDE_URL))
    rules.extend(evaluate_pcie_aspm(attrs, VMWARE_PERF_GUIDE_URL))
    rules.extend(evaluate_virtualization(attrs, VMWARE_PERF_GUIDE_URL))
    rules.extend(evaluate_smt(attrs, VMWARE_PERF_GUIDE_URL))
    rules.extend(evaluate_boot_mode(attrs, VMWARE_PERF_GUIDE_URL))
    rules.extend(evaluate_cstates(attrs, VMWARE_PERF_GUIDE_URL))
    rules.extend(evaluate_turbo(attrs, VMWARE_PERF_GUIDE_URL))
    rules.extend(evaluate_sriov(attrs, VMWARE_PERF_GUIDE_URL))
    rules.extend(evaluate_latency_mode(attrs))
    rules.extend(evaluate_pci_multisegment(attrs))
    rules.extend(evaluate_power_management(attrs, sys_profile_is_perf, VMWARE_PERF_GUIDE_URL))
    rules.extend(evaluate_c1e(attrs, sys_profile_is_perf, VMWARE_PERF_GUIDE_URL))
    # ── Rules 15–18: AMD Platform & Infinity Fabric Controls ─────────────────
    is_amd_platform = _is_amd_cpu(cpu_info) or any(k in model_str for k in ("r7715", "r6715", "r7725", "r6725", "r7625", "r6625", "r7615", "r6615", "r7525", "r6525", "r7515", "r6515"))
    rules.extend(evaluate_amd_apbdis(attrs, is_amd_platform, oem_guide))
    rules.extend(evaluate_amd_fabric_cstates(attrs, is_amd_platform, oem_guide))
    rules.extend(evaluate_amd_determinism(attrs, VMWARE_PERF_GUIDE_URL, is_amd_platform))
    rules.extend(evaluate_amd_xgmi(attrs, cpu_info, is_amd_platform, model_str, oem_guide))
    # ── Rule 19: 17G AMD BIOS currency against the local OEM catalog ────────
    # A build newer than the snapshot is healthy. Age is called out only when
    # the installed BIOS is older than the catalog latest.
    is_17g_amd = (
        any(m in model_str for m in ("r7715", "r6715", "r7725", "r6725"))
        or (_is_amd_cpu(cpu_info) and any(k in f"{model_str} {cpu_str}" for k in ("turin", "9005", "17g")))
    )
    if is_17g_amd and bios_version and str(bios_version).strip() and str(bios_version).strip().lower() not in ("unknown", "n/a", "none"):
        bv_str = str(bios_version).strip()
        _bios_key, bios_row = match_baseline(BIOS_BASELINES, model_str)
        if bios_row:
            currency = classify_currency(bv_str, bios_row)
            rules.extend(evaluate_catalog_alignment(bv_str, bios_row, currency))

    return summarize_dell_rules(rules, oem_guide, VMWARE_PERF_GUIDE_TITLE, VMWARE_PERF_GUIDE_URL)
