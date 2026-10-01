"""
VCF Readiness Tool — HPE ProLiant & Synergy BIOS Golden Baseline Drift Engine.

Evaluates HPE ProLiant (Gen10, Gen10 Plus, Gen11, Gen12) and HPE Synergy BIOS / RBSU
configuration against Broadcom VCF 9.1 and vSAN Express Storage Architecture (ESA)
recommended golden performance baselines.

Incorporates official guidance from:
  • HPE ESXi deployment guide (a00061651enw)
  • HPE UEFI Workload-based Performance and Tuning Guide (881335-002)
  • HPE UEFI System Utilities for Gen11 / Gen12 / Synergy (sd00003788en_us)
  • HPE SAP HANA and vSAN on DL380 Gen11 (a50016126enw — SNC guidance)
  • VMware vSphere 9.1 Performance Best Practices
  • Broadcom KB 1018206 / 366987 (Host power management & MaxPerf profiles)
  • Broadcom KB 432801 (AMD EPYC NUMA & NPS guidance)

Clean-room implementation using Python 3.9+ standard library only.
Strictly non-destructive and read-only.
"""
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vcf_assess")

VMWARE_PERF_GUIDE_TITLE = "VMware vSphere 9.1 Performance Best Practices"
VMWARE_PERF_GUIDE_URL = "https://www.vmware.com/docs/vsphere-esxi-vcenter-server-9-1-performance-best-practices"

KB_1018206_TITLE = "Broadcom KB 1018206 — Host Power Management & BIOS Performance Profiles"
KB_1018206_URL = "https://knowledge.broadcom.com/external/article?legacyId=1018206"

KB_432801_TITLE = "Broadcom KB 432801 — AMD EPYC BIOS and NUMA Configuration"
KB_432801_URL = "https://knowledge.broadcom.com/external/article/432801/guidance-for-amd-epyc-bios-and-numa-conf.html"

HPE_ESXI_DEPLOY_TITLE = "Deploying and updating VMware ESXi on HPE servers (a00061651enw)"
HPE_ESXI_DEPLOY_URL = "https://www.hpe.com/psnow/downloadDoc/Deploying%20and%20updating%20VMware%20ESXi%20on%20HPE%20servers-a00061651enw.pdf?id=a00061651enw"

HPE_WORKLOAD_UG_TITLE = "HPE UEFI Workload-based Performance and Tuning Guide (881335-002)"
HPE_WORKLOAD_UG_URL = "https://www.hpe.com/support/Workload-UG-en"

HPE_GEN11_RBSU_TITLE = "UEFI System Utilities for HPE ProLiant Gen11, Gen12, and Synergy (sd00003788en_us)"
HPE_GEN11_RBSU_URL = "https://support.hpe.com/hpesc/public/docDisplay?docId=sd00003788en_us"

HPE_VSAN_SNC_TITLE = "HPE DL380 Gen11 vSAN SNC Architecture Note (a50016126enw)"
HPE_VSAN_SNC_URL = "https://www.hpe.com/services/hpe/pdf/a50016126enw"

# Generation-specific HPE ProLiant / Synergy Tuning Whitepapers
HPE_TUNING_GUIDES = {
    "Gen10-Intel": {
        "title": "Deploying and updating VMware ESXi on HPE ProLiant Gen10 Servers (a00061651enw)",
        "url": HPE_ESXI_DEPLOY_URL,
        "generation": "Gen10",
        "platform": "HPE ProLiant Gen10 (Intel Xeon Scalable 1st/2nd Gen Skylake/Cascade Lake)",
    },
    "Gen10-AMD": {
        "title": "HPE ProLiant Gen10 / Gen10 Plus AMD EPYC Performance Tuning & ESXi Configuration",
        "url": HPE_ESXI_DEPLOY_URL,
        "generation": "Gen10",
        "platform": "HPE ProLiant Gen10 (AMD EPYC 7001/7002 Naples/Rome)",
    },
    "Gen10Plus-Intel": {
        "title": "Deploying and updating VMware ESXi on HPE ProLiant Gen10 Plus Servers (a00061651enw)",
        "url": HPE_ESXI_DEPLOY_URL,
        "generation": "Gen10 Plus",
        "platform": "HPE ProLiant Gen10 Plus (Intel Xeon Scalable 3rd Gen Ice Lake)",
    },
    "Gen10Plus-AMD": {
        "title": "HPE ProLiant Gen10 Plus AMD EPYC 7003 Performance Tuning & ESXi Configuration",
        "url": HPE_ESXI_DEPLOY_URL,
        "generation": "Gen10 Plus",
        "platform": "HPE ProLiant Gen10 Plus (AMD EPYC 7003 Milan)",
    },
    "Gen11-Intel": {
        "title": "UEFI System Utilities and ESXi Performance Tuning for HPE ProLiant Gen11 Servers",
        "url": HPE_GEN11_RBSU_URL,
        "generation": "Gen11",
        "platform": "HPE ProLiant Gen11 / Synergy 480 Gen11 (Intel Xeon 4th/5th Gen Sapphire/Emerald Rapids)",
    },
    "Gen11-AMD": {
        "title": "UEFI System Utilities and Workload Tuning for HPE ProLiant Gen11 AMD EPYC 9004 Servers",
        "url": HPE_GEN11_RBSU_URL,
        "generation": "Gen11",
        "platform": "HPE ProLiant Gen11 (AMD EPYC 9004 Genoa/Bergamo)",
    },
    "Gen12-Intel": {
        "title": "UEFI System Utilities & Performance Tuning for HPE ProLiant Gen12 (Intel Xeon 6)",
        "url": HPE_GEN11_RBSU_URL,
        "generation": "Gen12",
        "platform": "HPE ProLiant Gen12 (Intel Xeon 6 Granite Rapids)",
    },
    "Gen12-AMD": {
        "title": "UEFI System Utilities & Performance Tuning for HPE ProLiant Gen12 (AMD EPYC 9005 Turin)",
        "url": HPE_GEN11_RBSU_URL,
        "generation": "Gen12",
        "platform": "HPE ProLiant Gen12 (AMD EPYC 9005 Turin)",
    },
    "Synergy": {
        "title": "UEFI System Utilities & ESXi Tuning for HPE Synergy Compute Modules",
        "url": HPE_GEN11_RBSU_URL,
        "generation": "Synergy",
        "platform": "HPE Synergy 480 / 660 Compute Modules",
    },
}


def _is_amd_cpu(cpu_info: Optional[Dict[str, Any]]) -> bool:
    """Check if processor architecture is AMD EPYC."""
    if not isinstance(cpu_info, dict):
        return False
    arch = str(cpu_info.get("architecture") or "").lower()
    model = str(cpu_info.get("model") or "").lower()
    return "amd" in model or "zen" in arch or "epyc" in model


def get_hpe_tuning_guide(
    model: Optional[str] = None,
    bios_version: Optional[str] = None,
    cpu_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Identify the generation-specific HPE ProLiant / Synergy Performance Tuning Guide.

    Determines server generation (Gen10, Gen10 Plus, Gen11, Gen12, Synergy) and CPU vendor
    from model string (e.g. ProLiant DL380 Gen10, DL380 Gen10 Plus, DL360 Gen11, DL385 Gen10 Plus,
    Synergy 480 Gen10), BIOS family (e.g. U30, U32, U46, P89), or CPU telemetry.

    Returns:
        Dict with keys: 'title', 'url', 'generation', 'platform'.
    """
    m_str = str(model or "").upper()
    bv_str = str(bios_version or "").upper()
    is_amd = _is_amd_cpu(cpu_info)

    # Detect AMD SKUs by model number (DL325, DL345, DL365, DL385)
    if any(k in m_str for k in ("325", "345", "365", "385", "XL645", "XL675")):
        is_amd = True

    # Synergy detection
    if "SYNERGY" in m_str:
        if "GEN11" in m_str:
            return HPE_TUNING_GUIDES["Gen11-Intel"] if not is_amd else HPE_TUNING_GUIDES["Gen11-AMD"]
        return HPE_TUNING_GUIDES["Synergy"]

    # Generation pattern match
    if "GEN12" in m_str:
        gen = "Gen12"
    elif "GEN11" in m_str:
        gen = "Gen11"
    elif "GEN10 PLUS" in m_str or "GEN10+" in m_str or "U46" in bv_str or "A42" in bv_str:
        gen = "Gen10Plus"
    elif "GEN10" in m_str or "U30" in bv_str or "U32" in bv_str or "A40" in bv_str:
        gen = "Gen10"
    else:
        # Infer from CPU model
        cpu_model = str((cpu_info or {}).get("model") or "").lower()
        if "xeon 6" in cpu_model or "granite" in cpu_model or "9005" in cpu_model or "turin" in cpu_model:
            gen = "Gen12"
        elif any(k in cpu_model for k in ("sapphire", "emerald", "84", "85", "64", "65", "54", "55", "9004", "genoa")):
            gen = "Gen11"
        elif any(k in cpu_model for k in ("ice lake", "83", "63", "53", "43", "milan", "7003")):
            gen = "Gen10Plus"
        elif any(k in cpu_model for k in ("cascade", "skylake", "82", "81", "62", "61", "rome", "naples", "7001", "7002")):
            gen = "Gen10"
        else:
            gen = "Gen10"

    key = f"{gen}-AMD" if is_amd else f"{gen}-Intel"
    return HPE_TUNING_GUIDES.get(key, HPE_TUNING_GUIDES["Gen10-Intel"])


def evaluate_hpe_bios_baseline(
    bios_attrs: Optional[Dict[str, Any]],
    cpu_info: Optional[Dict[str, Any]] = None,
    is_esa_candidate: bool = False,
    model: Optional[str] = None,
    bios_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate HPE ProLiant / Synergy BIOS attributes against VCF 9.1 Golden Baseline.

    Evaluates canonical attributes:
      1. WorkloadProfile: Expected Virtualization-MaxPerformance (or Custom / Virtualization-PowerEfficient)
      2. PowerRegulator: Expected StaticHighPerf or OsControl
      3. MinProcIdlePower: Minimum Core C-State (NoCStates for MaxPerf, C6 for VSI-HPM)
      4. CollaborativePowerControl: Expected Disabled (for Static High-Perf)
      5. EnergyEfficientTurbo: Expected Disabled (forced by Virt-MaxPerf)
      6. SubNumaClustering: Expected Disabled or Auto (Disabled required for vSAN per a50016126enw)
      7. ProcVirtualization (VT-x / AMD-V): Expected Enabled (Blocker if disabled)
      8. VtdSupport (VT-d / AMD IOMMU): Expected Enabled (Blocker if disabled)
      9. LogicalProc (HyperThreading / SMT): Expected Enabled (Warning if disabled)
     10. ProcTurboMode (Turbo Boost / CPB): Expected Enabled (Warning if disabled)
     11. SriovGlobalEnable: Expected Enabled (forced by Virt-MaxPerf)
     12. NumaGroupSizeOpt / NodeInterleave: Expected Flat / NodeInterleave Disabled
     13. AMD NUMA NPS & Determinism (if AMD CPU): NPS1 general, Determinism Power
     14. BootMode: Expected Uefi (Blocker if legacy BIOS)

    Args:
        bios_attrs: Dictionary of BIOS attributes (raw or normalized).
        cpu_info: CPU summary information dictionary.
        is_esa_candidate: Boolean indicating whether server is targeted for vSAN ESA.
        model: Server model name string.
        bios_version: BIOS firmware version string.

    Returns:
        Dictionary with compliance percentage, total drift count, severity counts,
        badge, and detailed per-attribute drift breakdown with VMware best practice citations.
    """
    from ..collector.oem.hpe import normalize_hpe_bios_attributes

    raw_attrs = bios_attrs if isinstance(bios_attrs, dict) else {}
    norm_attrs = normalize_hpe_bios_attributes(raw_attrs)
    attrs = dict(raw_attrs)
    attrs.update(norm_attrs)

    cpu_info = cpu_info if isinstance(cpu_info, dict) else {}
    is_amd = _is_amd_cpu(cpu_info)
    guide = get_hpe_tuning_guide(model=model, bios_version=bios_version, cpu_info=cpu_info)
    rules: List[Dict[str, Any]] = []

    # ── Rule 1: Workload Profile (OEM Easy-Button Profile) ──────────────────
    profile_val = attrs.get("WorkloadProfile") or attrs.get("SysProfile")
    if profile_val is not None and str(profile_val).strip():
        val = str(profile_val).strip()
        val_lower = val.lower().replace("-", "").replace("_", "").replace(" ", "")
        if "virtualizationmaxperformance" in val_lower or "virtmaxperf" in val_lower:
            rules.append({
                "attribute": "WorkloadProfile",
                "setting_name": "Workload Profile (System Profile)",
                "current_value": val,
                "expected_value": "Virtualization-MaxPerformance / Custom",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"Workload Profile is set to Virtualization-MaxPerformance ({val}). Sets static high-performance "
                    "power regulator, enables VT-x/VT-d/SR-IOV, disables energy-efficient turbo, and configures "
                    "subsystem timings for peak enterprise virtualization throughput."
                ),
                "citation": "HPE Deploying and updating VMware ESXi on HPE servers (a00061651enw)",
                "citation_url": HPE_ESXI_DEPLOY_URL,
            })
        elif "custom" in val_lower:
            rules.append({
                "attribute": "WorkloadProfile",
                "setting_name": "Workload Profile (System Profile)",
                "current_value": val,
                "expected_value": "Virtualization-MaxPerformance / Custom",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"Workload Profile is set to Custom ({val}). Allows selective tuning of power regulators, "
                    "sub-NUMA clustering, and C-states. Recommended when fine-tuning for OS-controlled power (VSI-HPM) "
                    "or disabling SNC for vSAN clusters."
                ),
                "citation": "HPE UEFI Workload-based Performance and Tuning Guide (881335-002)",
                "citation_url": HPE_WORKLOAD_UG_URL,
            })
        elif "virtualizationpowerefficient" in val_lower:
            rules.append({
                "attribute": "WorkloadProfile",
                "setting_name": "Workload Profile (System Profile)",
                "current_value": val,
                "expected_value": "Virtualization-MaxPerformance / Custom",
                "severity": "info",
                "status": "drifted",
                "rationale": (
                    f"Workload Profile is set to Virtualization-PowerEfficient ({val}). Leaves power management "
                    "under OS control with C-states enabled. Valid for general virtualization with ESXi Host Power Policy "
                    "= Balanced (VSI-HPM path), but differs from the maximum performance profile."
                ),
                "citation": "VMware vSphere 9.1 Performance Best Practices, Host Power Management (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        elif any(k in val_lower for k in ("generalpowerefficientcompute", "powerefficient", "balanced", "efficiency")):
            rules.append({
                "attribute": "WorkloadProfile",
                "setting_name": "Workload Profile (System Profile)",
                "current_value": val,
                "expected_value": "Virtualization-MaxPerformance / Custom",
                "severity": "warning",
                "status": "drifted",
                "rationale": (
                    f"Workload Profile is set to factory default or energy-saving profile ({val}). Dynamic frequency "
                    "throttling and power-capping introduce CPU and memory latency spikes during vSAN ESA burst I/O. "
                    "Recommended: Set Workload Profile to Virtualization-MaxPerformance."
                ),
                "citation": "HPE Deploying and updating VMware ESXi on HPE servers (a00061651enw)",
                "citation_url": HPE_ESXI_DEPLOY_URL,
            })
        else:
            rules.append({
                "attribute": "WorkloadProfile",
                "setting_name": "Workload Profile (System Profile)",
                "current_value": val,
                "expected_value": "Virtualization-MaxPerformance / Custom",
                "severity": "info",
                "status": "compliant",
                "rationale": f"Workload Profile is configured to {val}.",
                "citation": "HPE UEFI Workload-based Performance and Tuning Guide (881335-002)",
                "citation_url": HPE_WORKLOAD_UG_URL,
            })
    else:
        rules.append({
            "attribute": "WorkloadProfile",
            "setting_name": "Workload Profile (System Profile)",
            "current_value": "Not Exposed",
            "expected_value": "Virtualization-MaxPerformance / Custom",
            "severity": "warning",
            "status": "drifted",
            "rationale": "Workload Profile attribute not detected in BIOS telemetry. Verify BIOS is configured for Virtualization-MaxPerformance or Custom.",
            "citation": "HPE Deploying and updating VMware ESXi on HPE servers (a00061651enw)",
            "citation_url": HPE_ESXI_DEPLOY_URL,
        })

    # ── Rule 2: Power Regulator ─────────────────────────────────────────────
    reg_val = attrs.get("PowerRegulator")
    if reg_val is not None and str(reg_val).strip():
        val = str(reg_val).strip()
        val_lower = val.lower().replace("-", "").replace(" ", "")
        if any(k in val_lower for k in ("statichighperf", "statichighperformance", "highperformance")):
            rules.append({
                "attribute": "PowerRegulator",
                "setting_name": "Power Regulator Mode",
                "current_value": val,
                "expected_value": "StaticHighPerf / OsControl",
                "severity": None,
                "status": "compliant",
                "rationale": "Power Regulator is set to Static High-Performance Mode. CPU operates at maximum frequency without dynamic frequency modulation.",
                "citation": "HPE Deploying and updating VMware ESXi on HPE servers (a00061651enw, Step 1)",
                "citation_url": HPE_ESXI_DEPLOY_URL,
            })
        elif any(k in val_lower for k in ("oscontrol", "oscontrolmode", "os")):
            rules.append({
                "attribute": "PowerRegulator",
                "setting_name": "Power Regulator Mode",
                "current_value": val,
                "expected_value": "StaticHighPerf / OsControl",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"Power Regulator is set to OS Control Mode ({val}). Hypervisor governs processor performance "
                    "states via ESXi Host Power Management (Balanced policy) as recommended in vSphere Performance Best Practices."
                ),
                "citation": "VMware vSphere 9.1 Performance Best Practices, Host Power Management (p. 21)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        elif "dynamicpowersavings" in val_lower:
            rules.append({
                "attribute": "PowerRegulator",
                "setting_name": "Power Regulator Mode",
                "current_value": val,
                "expected_value": "StaticHighPerf / OsControl",
                "severity": "info",
                "status": "drifted",
                "rationale": (
                    f"Power Regulator is set to Dynamic Power Savings Mode ({val}). BIOS autonomously scales CPU frequency. "
                    "May introduce minor latency jitter during vSAN ESA storage bursts. VMware recommends Static High-Performance or OS Control Mode."
                ),
                "citation": "Broadcom KB 1018206 — Host Power Management & BIOS Performance Profiles",
                "citation_url": KB_1018206_URL,
            })
        else:
            rules.append({
                "attribute": "PowerRegulator",
                "setting_name": "Power Regulator Mode",
                "current_value": val,
                "expected_value": "StaticHighPerf / OsControl",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Power Regulator is set to {val}. May throttle processor frequency under load.",
                "citation": "HPE Deploying and updating VMware ESXi on HPE servers (a00061651enw)",
                "citation_url": HPE_ESXI_DEPLOY_URL,
            })
    else:
        rules.append({
            "attribute": "PowerRegulator",
            "setting_name": "Power Regulator Mode",
            "current_value": "Not Exposed",
            "expected_value": "StaticHighPerf / OsControl",
            "severity": None,
            "status": "not_applicable",
            "rationale": "Power Regulator attribute not exposed in BIOS telemetry.",
            "citation": "HPE Deploying and updating VMware ESXi on HPE servers (a00061651enw)",
            "citation_url": HPE_ESXI_DEPLOY_URL,
        })

    # ── Rule 3: Minimum Processor Idle Power Core C-State (MinProcIdlePower) ─
    cstate_val = attrs.get("MinProcIdlePower") or attrs.get("ProcCStates")
    if cstate_val is not None and str(cstate_val).strip():
        val = str(cstate_val).strip()
        val_lower = val.lower().replace("-", "").replace(" ", "")
        if "nocstates" in val_lower or "nocstate" in val_lower or "disabled" in val_lower:
            rules.append({
                "attribute": "MinProcIdlePower",
                "setting_name": "Processor Core Idle C-States",
                "current_value": val,
                "expected_value": "No C-states / C6 (OS Controlled)",
                "severity": None,
                "status": "compliant",
                "rationale": "Processor Core C-States are Disabled (No C-states). Prevents core sleep states, eliminating wake-up latency for deterministic low jitter.",
                "citation": "HPE Deploying and updating VMware ESXi on HPE servers (a00061651enw, Step 1)",
                "citation_url": HPE_ESXI_DEPLOY_URL,
            })
        elif "c6" in val_lower or "c1" in val_lower or "enabled" in val_lower or "auto" in val_lower:
            rules.append({
                "attribute": "MinProcIdlePower",
                "setting_name": "Processor Core Idle C-States",
                "current_value": val,
                "expected_value": "No C-states / C6 (OS Controlled)",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"Processor Core C-States is set to {val}. Normal for OS Control Mode / ESXi Balanced Power Policy. "
                    "For latency-sensitive or strict low-jitter workloads, KB 1018206 recommends setting to No C-states."
                ),
                "citation": "VMware vSphere 9.1 Performance Best Practices, C-States (p. 22)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "MinProcIdlePower",
                "setting_name": "Processor Core Idle C-States",
                "current_value": val,
                "expected_value": "No C-states / C6 (OS Controlled)",
                "severity": "info",
                "status": "compliant",
                "rationale": f"Processor Core C-States set to {val}.",
                "citation": "HPE Deploying and updating VMware ESXi on HPE servers (a00061651enw)",
                "citation_url": HPE_ESXI_DEPLOY_URL,
            })

    # ── Rule 4: Collaborative Power Control ─────────────────────────────────
    cpc_val = attrs.get("CollaborativePowerControl")
    if cpc_val is not None and str(cpc_val).strip():
        val = str(cpc_val).strip()
        val_lower = val.lower()
        if "disable" in val_lower:
            rules.append({
                "attribute": "CollaborativePowerControl",
                "setting_name": "Collaborative Power Control",
                "current_value": val,
                "expected_value": "Disabled (Static High-Perf) / Enabled (OS Control)",
                "severity": None,
                "status": "compliant",
                "rationale": "Collaborative Power Control is Disabled. Ensures Static High-Performance mode is strictly maintained without autonomous CPU power regulation.",
                "citation": "HPE Deploying and updating VMware ESXi on HPE servers (a00061651enw)",
                "citation_url": HPE_ESXI_DEPLOY_URL,
            })
        else:
            rules.append({
                "attribute": "CollaborativePowerControl",
                "setting_name": "Collaborative Power Control",
                "current_value": val,
                "expected_value": "Disabled (Static High-Perf) / Enabled (OS Control)",
                "severity": None,
                "status": "compliant",
                "rationale": f"Collaborative Power Control is {val}. Active under OS-controlled power management.",
                "citation": "HPE UEFI Workload-based Performance and Tuning Guide (881335-002)",
                "citation_url": HPE_WORKLOAD_UG_URL,
            })

    # ── Rule 5: Energy-Efficient Turbo (EET) ────────────────────────────────
    eet_val = attrs.get("EnergyEfficientTurbo")
    if eet_val is not None and str(eet_val).strip():
        val = str(eet_val).strip()
        val_lower = val.lower()
        if "disable" in val_lower:
            rules.append({
                "attribute": "EnergyEfficientTurbo",
                "setting_name": "Energy-Efficient Turbo",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Energy-Efficient Turbo is Disabled (forced by Virtualization-MaxPerformance). Turbo frequencies are not opportunistically throttled by energy-efficiency algorithms.",
                "citation": "HPE UEFI Workload-based Performance and Tuning Guide (881335-002)",
                "citation_url": HPE_WORKLOAD_UG_URL,
            })
        else:
            rules.append({
                "attribute": "EnergyEfficientTurbo",
                "setting_name": "Energy-Efficient Turbo",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": "info",
                "status": "drifted",
                "rationale": (
                    f"Energy-Efficient Turbo is Enabled ({val}). Part of the Virtualization-Power Efficient profile. "
                    "For maximum consistent CPU throughput, VMware KB 1018206 and HPE Virtualization-MaxPerformance recommend Disabled."
                ),
                "citation": "Broadcom KB 1018206 — Host Power Management & BIOS Performance Profiles",
                "citation_url": KB_1018206_URL,
            })

    # ── Rule 6: Hardware Virtualization (Intel VT-x / AMD-V) ─────────────────
    vtx_val = attrs.get("ProcVirtualization")
    if vtx_val is not None and str(vtx_val).strip():
        val = str(vtx_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "ProcVirtualization",
                "setting_name": "Hardware-Assisted CPU Virtualization (VT-x / AMD-V)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Hardware-assisted CPU virtualization is Enabled. Required for ESXi 64-bit guest virtual machine execution.",
                "citation": "VMware vSphere 9.1 Performance Best Practices, Hardware Virtualization Considerations (p. 18)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcVirtualization",
                "setting_name": "Hardware-Assisted CPU Virtualization (VT-x / AMD-V)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "blocker",
                "status": "drifted",
                "rationale": f"Hardware virtualization is Disabled ({val}). ESXi cannot run virtual machines. Hard blocker for VCF deployment.",
                "citation": "VMware vSphere 9.1 Performance Best Practices, Hardware Virtualization Considerations (p. 18)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })

    # ── Rule 7: Intel VT-d / AMD IOMMU ──────────────────────────────────────
    vtd_val = attrs.get("IntelProcVtd") or attrs.get("VtdSupport")
    if vtd_val is not None and str(vtd_val).strip():
        val = str(vtd_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "IntelProcVtd",
                "setting_name": "Intel VT-d / AMD IOMMU (Directed I/O)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Directed I/O virtualization (VT-d / AMD IOMMU) is Enabled. Required for PCI pass-through, vSAN Direct, and DPU/SmartNIC operations.",
                "citation": "VMware vSphere 9.1 Performance Best Practices, Hardware Virtualization Considerations (p. 18)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "IntelProcVtd",
                "setting_name": "Intel VT-d / AMD IOMMU (Directed I/O)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "blocker",
                "status": "drifted",
                "rationale": f"VT-d / IOMMU is Disabled ({val}). ESXi cannot isolate memory domains or pass NVMe devices directly to vSAN ESA.",
                "citation": "VMware vSphere 9.1 Performance Best Practices, Hardware Virtualization Considerations (p. 18)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })

    # ── Rule 8: Logical Processor (Hyper-Threading / SMT) ───────────────────
    ht_val = attrs.get("LogicalProc") or attrs.get("ProcHyperthreading")
    if ht_val is not None and str(ht_val).strip():
        val = str(ht_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "ProcHyperthreading",
                "setting_name": "Logical Processor (Hyper-Threading / SMT)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Logical Processor (Hyper-Threading / SMT) is Enabled. Exposes maximum logical execution contexts to ESXi CPU scheduler.",
                "citation": "VMware vSphere 9.1 Performance Best Practices, Hyper-Threading Considerations (p. 19)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcHyperthreading",
                "setting_name": "Logical Processor (Hyper-Threading / SMT)",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Hyper-Threading is Disabled ({val}). Halves logical core count and reduces aggregate host throughput by 20–30%.",
                "citation": "VMware vSphere 9.1 Performance Best Practices, Hyper-Threading Considerations (p. 19)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })

    # ── Rule 9: Processor Turbo Boost / CPB ─────────────────────────────────
    turbo_val = attrs.get("ProcTurboMode") or attrs.get("ProcTurbo")
    if turbo_val is not None and str(turbo_val).strip():
        val = str(turbo_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "ProcTurbo",
                "setting_name": "Processor Turbo Boost / Core Performance Boost",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Processor Turbo Boost is Enabled. Allows opportunistic execution frequency scaling above nominal TDP baseline.",
                "citation": "VMware vSphere 9.1 Performance Best Practices, Turbo Boost (p. 23)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "ProcTurbo",
                "setting_name": "Processor Turbo Boost / Core Performance Boost",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Turbo Boost is Disabled ({val}). Clamps CPU cores strictly to base frequency, sacrificing burst performance.",
                "citation": "VMware vSphere 9.1 Performance Best Practices, Turbo Boost (p. 23)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })

    # ── Rule 10: SR-IOV Global Enable ───────────────────────────────────────
    sriov_val = attrs.get("SriovGlobalEnable") or attrs.get("Sriov")
    if sriov_val is not None and str(sriov_val).strip():
        val = str(sriov_val).strip()
        val_lower = val.lower()
        if "enable" in val_lower:
            rules.append({
                "attribute": "Sriov",
                "setting_name": "SR-IOV Global Enable",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": None,
                "status": "compliant",
                "rationale": "SR-IOV is Enabled (forced by Virtualization-MaxPerformance). Allows PCIe NICs to expose hardware Virtual Functions (VFs).",
                "citation": "HPE UEFI Workload-based Performance and Tuning Guide (881335-002)",
                "citation_url": HPE_WORKLOAD_UG_URL,
            })
        else:
            rules.append({
                "attribute": "Sriov",
                "setting_name": "SR-IOV Global Enable",
                "current_value": val,
                "expected_value": "Enabled",
                "severity": "info",
                "status": "drifted",
                "rationale": f"SR-IOV is Disabled ({val}). Informational: Enable if Virtual Functions or direct network pass-through are required.",
                "citation": "HPE UEFI Workload-based Performance and Tuning Guide (881335-002)",
                "citation_url": HPE_WORKLOAD_UG_URL,
            })

    # ── Rule 11: NUMA Group Size Optimization / Node Interleave ─────────────
    numa_opt = attrs.get("NumaGroupSizeOpt")
    node_interleave = attrs.get("NodeInterleave")
    if numa_opt is not None and str(numa_opt).strip():
        val = str(numa_opt).strip()
        val_lower = val.lower()
        if "flat" in val_lower:
            rules.append({
                "attribute": "NumaGroupSizeOpt",
                "setting_name": "NUMA Group Size Optimization",
                "current_value": val,
                "expected_value": "Flat",
                "severity": None,
                "status": "compliant",
                "rationale": "NUMA Group Size Optimization is set to Flat. Keeps NUMA topology fully visible to the ESXi CPU scheduler.",
                "citation": "HPE UEFI Workload-based Performance and Tuning Guide (881335-002)",
                "citation_url": HPE_WORKLOAD_UG_URL,
            })
        elif "clustered" in val_lower:
            rules.append({
                "attribute": "NumaGroupSizeOpt",
                "setting_name": "NUMA Group Size Optimization",
                "current_value": val,
                "expected_value": "Flat",
                "severity": "info",
                "status": "drifted",
                "rationale": f"NUMA Group Size Optimization is set to Clustered ({val}). Virtualization-Max Performance profile recommends Flat.",
                "citation": "HPE UEFI Workload-based Performance and Tuning Guide (881335-002)",
                "citation_url": HPE_WORKLOAD_UG_URL,
            })
    elif node_interleave is not None and str(node_interleave).strip():
        val = str(node_interleave).strip()
        val_lower = val.lower()
        if "disable" in val_lower:
            rules.append({
                "attribute": "NodeInterleaving",
                "setting_name": "Node Interleaving (NUMA)",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": None,
                "status": "compliant",
                "rationale": "Node Interleaving is Disabled. Preserves NUMA topology across sockets for NUMA-aware ESXi scheduling.",
                "citation": "VMware vSphere 9.1 Performance Best Practices, NUMA Considerations (p. 25)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })
        else:
            rules.append({
                "attribute": "NodeInterleaving",
                "setting_name": "Node Interleaving (NUMA)",
                "current_value": val,
                "expected_value": "Disabled",
                "severity": "warning",
                "status": "drifted",
                "rationale": f"Node Interleaving is Enabled ({val}). Interleaves memory across sockets into a single uniform memory architecture, destroying NUMA locality.",
                "citation": "VMware vSphere 9.1 Performance Best Practices, NUMA Considerations (p. 25)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })

    # ── Rule 12: Sub-NUMA Clustering (SNC) — With vSAN Conditionality ────────
    snc_val = attrs.get("SubNumaClustering") or attrs.get("SubNumaCluster")
    if snc_val is not None and str(snc_val).strip():
        val = str(snc_val).strip()
        val_lower = val.lower()
        if is_esa_candidate and ("enable" in val_lower or "snc2" in val_lower or "snc4" in val_lower):
            # vSAN conflict: HPE technical documentation specifies SNC is NOT supported by vSAN
            rules.append({
                "attribute": "SubNumaClustering",
                "setting_name": "Sub-NUMA Clustering (SNC)",
                "current_value": val,
                "expected_value": "Disabled (vSAN requirement)",
                "severity": "warning",
                "status": "drifted",
                "rationale": (
                    f"Sub-NUMA Clustering is Enabled ({val}) on a server targeted for vSAN ESA. "
                    "HPE document a50016126enw states: 'Sub-NUMA Clustering is not supported by vSAN.' "
                    "Recommended procedure: Apply Workload Profile = Virtualization-MaxPerformance, "
                    "then switch profile to Custom, and set Sub-NUMA Clustering = Disabled."
                ),
                "citation": "HPE Solutions for SAP HANA and VMware vSAN on DL380 Gen11 (a50016126enw)",
                "citation_url": HPE_VSAN_SNC_URL,
            })
        elif "disable" in val_lower or "auto" in val_lower:
            rules.append({
                "attribute": "SubNumaClustering",
                "setting_name": "Sub-NUMA Clustering (SNC)",
                "current_value": val,
                "expected_value": "Disabled / Auto",
                "severity": None,
                "status": "compliant",
                "rationale": (
                    f"Sub-NUMA Clustering is {val}. Avoids partitioning physical sockets into multiple smaller "
                    "NUMA domains, preserving standard 1-node-per-socket memory locality for vSAN ESA and general VMs."
                ),
                "citation": "HPE Solutions for SAP HANA and VMware vSAN on DL380 Gen11 (a50016126enw)",
                "citation_url": HPE_VSAN_SNC_URL,
            })
        else:
            rules.append({
                "attribute": "SubNumaClustering",
                "setting_name": "Sub-NUMA Clustering (SNC)",
                "current_value": val,
                "expected_value": "Disabled / Auto (General Virt & vSAN)",
                "severity": "info",
                "status": "compliant",
                "rationale": f"Sub-NUMA Clustering is set to {val}.",
                "citation": "HPE UEFI Workload-based Performance and Tuning Guide (881335-002)",
                "citation_url": HPE_WORKLOAD_UG_URL,
            })

    # ── Rule 13: AMD EPYC NUMA & Determinism (AMD-specific) ─────────────────
    if is_amd:
        amd_nps = attrs.get("NumaNodesPerSocket")
        if amd_nps is not None and str(amd_nps).strip():
            val = str(amd_nps).strip()
            val_lower = val.lower()
            if any(k in val_lower for k in ("1", "nps1")):
                rules.append({
                    "attribute": "NumaNodesPerSocket",
                    "setting_name": "AMD NUMA Nodes Per Socket (NPS)",
                    "current_value": val,
                    "expected_value": "NPS1 (General Virt & vSAN) / NPS4 (Small-VM VDI)",
                    "severity": None,
                    "status": "compliant",
                    "rationale": (
                        f"AMD NUMA Nodes Per Socket is set to {val}. Single NUMA domain per socket presents all memory channels "
                        "uniformly. Broadcom KB 432801 recommends NPS1 as the optimal baseline for modern ESXi (>= 7.0 U2)."
                    ),
                    "citation": "Broadcom KB 432801 — AMD EPYC BIOS and NUMA Configuration",
                    "citation_url": KB_432801_URL,
                })
            elif any(k in val_lower for k in ("4", "nps4")):
                rules.append({
                    "attribute": "NumaNodesPerSocket",
                    "setting_name": "AMD NUMA Nodes Per Socket (NPS)",
                    "current_value": val,
                    "expected_value": "NPS1 (General Virt & vSAN) / NPS4 (Small-VM VDI)",
                    "severity": None,
                    "status": "compliant",
                    "rationale": (
                        f"AMD NUMA Nodes Per Socket is set to {val}. Slices socket into 4 quadrant NUMA nodes. "
                        "Effective for high-density small-vCPU workloads (VDI) where VMs fit within a single quadrant."
                    ),
                    "citation": "Broadcom KB 432801 — AMD EPYC BIOS and NUMA Configuration",
                    "citation_url": KB_432801_URL,
                })
            else:
                rules.append({
                    "attribute": "NumaNodesPerSocket",
                    "setting_name": "AMD NUMA Nodes Per Socket (NPS)",
                    "current_value": val,
                    "expected_value": "NPS1",
                    "severity": "info",
                    "status": "compliant",
                    "rationale": f"AMD NUMA Nodes Per Socket is set to {val}.",
                    "citation": "Broadcom KB 432801 — AMD EPYC BIOS and NUMA Configuration",
                    "citation_url": KB_432801_URL,
                })

        det_val = attrs.get("DeterminismSlider")
        if det_val is not None and str(det_val).strip():
            val = str(det_val).strip()
            val_lower = val.lower()
            if "power" in val_lower or "auto" in val_lower:
                rules.append({
                    "attribute": "DeterminismSlider",
                    "setting_name": "AMD Performance Determinism",
                    "current_value": val,
                    "expected_value": "Power / Auto",
                    "severity": None,
                    "status": "compliant",
                    "rationale": "AMD Determinism Slider is set to Power / Auto. Allows all processor cores to boost dynamically to maximum clock frequency.",
                    "citation": "HPE UEFI Workload-based Performance and Tuning Guide (881335-002)",
                    "citation_url": HPE_WORKLOAD_UG_URL,
                })
            else:
                rules.append({
                    "attribute": "DeterminismSlider",
                    "setting_name": "AMD Performance Determinism",
                    "current_value": val,
                    "expected_value": "Power / Auto",
                    "severity": "info",
                    "status": "drifted",
                    "rationale": f"AMD Determinism Slider is set to {val}. For virtualization workloads, Power determinism is recommended.",
                    "citation": "HPE UEFI Workload-based Performance and Tuning Guide (881335-002)",
                    "citation_url": HPE_WORKLOAD_UG_URL,
                })

    # ── Rule 14: Boot Mode ──────────────────────────────────────────────────
    boot_val = attrs.get("BootMode")
    if boot_val is not None and str(boot_val).strip():
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
                "rationale": "System Boot Mode is configured for UEFI. Mandatory for VCF 9.1, modern NVMe pass-through, and TPM 2.0 measurement.",
                "citation": "VMware vSphere 9.1 Performance Best Practices, System BIOS and Platform Firmware (p. 17)",
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
                "rationale": f"System Boot Mode is Legacy BIOS ({val}). VCF 9.1 strictly deprecates Legacy BIOS. Hard blocker for commissioning.",
                "citation": "VMware vSphere 9.1 Performance Best Practices, System BIOS and Platform Firmware (p. 17)",
                "citation_url": VMWARE_PERF_GUIDE_URL,
            })

    # ── Calculate Summary Metrics ───────────────────────────────────────────
    total_rules = len(rules)
    passed_count = sum(1 for r in rules if r.get("status") == "compliant")
    drift_count = sum(1 for r in rules if r.get("status") == "drifted")
    blocker_count = sum(1 for r in rules if r.get("status") == "drifted" and r.get("severity") == "blocker")
    warning_count = sum(1 for r in rules if r.get("status") == "drifted" and r.get("severity") == "warning")
    info_count = sum(1 for r in rules if r.get("status") == "drifted" and r.get("severity") == "info")

    applicable_count = total_rules - sum(1 for r in rules if r.get("status") == "not_applicable")
    compliance_pct = round((passed_count / applicable_count * 100), 1) if applicable_count > 0 else 100.0

    if blocker_count > 0:
        badge = f"<span class='badge danger'>🔴 Blocker ({blocker_count} Blocker, {warning_count} Warning)</span>"
        status = "fail"
    elif warning_count > 0:
        badge = f"<span class='badge warning'>🟡 Drift Detected ({warning_count} Warning, {drift_count} Drift)</span>"
        status = "warning"
    elif info_count > 0:
        badge = f"<span class='badge info'>ℹ️ Minor Drift ({info_count} Info)</span>"
        status = "info"
    else:
        badge = "<span class='badge success'>🟢 Golden Baseline Compliant (100%)</span>"
        status = "pass"

    drifts = [r for r in rules if r.get("status") == "drifted"]

    return {
        "compliance_pct": compliance_pct,
        "total_rules": total_rules,
        "passed_count": passed_count,
        "drift_count": drift_count,
        "blocker_count": blocker_count,
        "warning_count": warning_count,
        "info_count": info_count,
        "badge": badge,
        "status": status,
        "tuning_guide": guide,
        "guide_title": VMWARE_PERF_GUIDE_TITLE,
        "guide_url": VMWARE_PERF_GUIDE_URL,
        "oem_guide_title": guide.get("title", HPE_ESXI_DEPLOY_TITLE),
        "oem_guide_url": guide.get("url", HPE_ESXI_DEPLOY_URL),
        "vmware_guide_title": VMWARE_PERF_GUIDE_TITLE,
        "vmware_guide_url": VMWARE_PERF_GUIDE_URL,
        "drifts": drifts,
        "rules": rules,
    }
