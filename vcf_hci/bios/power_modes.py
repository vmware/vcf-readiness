"""
VCF Readiness Tool — BIOS attribute detector: CPU power and performance modes.
Parses BIOS Settings from the Redfish /Systems/{id}/Bios endpoint.
"""
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("vcf_assess")


# ---------------------------------------------------------------------------
# CPU Performance / power-mode detection rules
# Format: (key_pat, feature_label, value_map, allowed_vendors, allowed_archs)
# ---------------------------------------------------------------------------
_CPU_POWER_RULES: List[Tuple[str, str, Dict[str, Tuple[str, str, str]], Optional[Tuple[str, ...]], Optional[Tuple[str, ...]]]] = [
    # Dell iDRAC: SysProfile is the primary "system performance profile" knob
    ("sysprofile", "System Performance Profile (Dell)", {
        "perfoptimized":        ("success", "Performance Optimized",   "CPU/memory sub-timings and power limits set for max throughput. Recommended for vSAN."),
        "densecfgoptimized":    ("success", "Dense Config Optimized",  "High-density compute profile; performance-oriented."),
        "workstationperf":      ("info",    "Workstation Performance",  "Workstation profile — confirm CPU is not throttled."),
        "perfperwattoptimized": ("warning", "Power Efficient Mode",     "CPU can throttle under power budget; may cause VM latency spikes. Change to Performance Optimized for vSAN."),
        "oscontrolledmode":     ("warning", "OS Controlled",            "vSphere Power Management governs CPU P-states — set vSphere Host Power Policy to High Performance."),
        "custom":               ("info",    "Custom Profile",           "Individual BIOS settings override profile defaults — verify C-States, Turbo, and SpeedStep manually."),
    }, ("dell",), None),

    # HPE iLO 5/6: WorkloadProfile
    ("workloadprofile", "Workload Profile (HPE)", {
        "maximumperformance":           ("success", "Maximum Performance",           "All sub-systems at peak performance. Recommended for vSAN."),
        "virtualizationmaxperformance": ("success", "Virtualization Max Performance","Optimised for virtualised workloads at maximum performance."),
        "virtualization":               ("success", "Virtualization Profile",        "Standard virtualisation profile."),
        "generalpowerefficientcompute": ("warning", "Power Efficient Compute",       "Active power capping may cause CPU P-state throttling under vSAN IO load."),
        "transactionalapplicationperf": ("info",    "Transactional App Performance", "Tuned for transactional workloads."),
        "custom":                       ("info",    "Custom Profile",                "Review individual power and C-State settings."),
    }, ("hpe", "hp"), None),

    # HPE iLO 5/6: PowerRegulator (complements WorkloadProfile)
    ("powerregulator", "HPE Power Regulator", {
        "statichighperf":      ("success", "Static High Performance", "CPU locked to max P-state. Recommended for vSAN."),
        "maxperformance":      ("success", "Max Performance",         "CPU at maximum performance state."),
        "dynamicpowersavings": ("warning", "Dynamic Power Savings",   "CPU frequency scales with utilisation — IO-latency spikes possible under vSAN burst."),
        "staticlowpower":      ("warning", "Static Low Power",        "CPU fixed at a reduced P-state — not recommended for vSAN."),
        "oscontrol":           ("warning", "OS Controlled",           "vSphere Power Management governs CPU P-states — set Host Power Policy to High Performance in vCenter."),
    }, ("hpe", "hp"), None),

    # Cisco UCS / IMC: CPUPerformance and Workload Configuration
    ("cpuperformance", "CPU Performance Profile (Cisco)", {
        "enterprise":       ("success", "Enterprise (Platform Default)", "Prefetchers and hardware acceleration enabled for enterprise virtualization."),
        "high throughput":  ("success", "High Throughput",               "Prefetchers and data-reuse enabled for high throughput streaming."),
        "high-throughput":  ("success", "High Throughput",               "Prefetchers and data-reuse enabled for high throughput streaming."),
        "hpc":              ("success", "HPC Profile",                  "Maximum compute performance and all prefetchers active."),
        "custom":           ("info",    "Custom Profile",               "Individual BIOS settings govern performance and prefetchers."),
        "platform default": ("info",    "Platform Default",             "Platform default performance tuning."),
    }, ("cisco",), None),

    ("workldconfig", "Workload Configuration (Cisco)", {
        "io sensitive":   ("success", "I/O Sensitive (Platform Default)", "Cisco platform default. Maximizes I/O and memory throughput across interconnect links."),
        "i/o sensitive":  ("success", "I/O Sensitive (Platform Default)", "Cisco platform default. Maximizes I/O and memory throughput across interconnect links."),
        "balanced":       ("info",    "Balanced Workload",                "Balanced configuration between compute performance and energy efficiency."),
    }, ("cisco",), None),

    ("pwrperftuning", "Power Performance Tuning (Cisco)", {
        "os":   ("success", "OS Controlled (Platform Default)", "Cisco platform default. ESXi Host Power Policy governs CPU energy and performance bias."),
        "bios": ("info",    "BIOS Controlled",                  "Energy-performance bias tuned statically by server BIOS."),
        "peci": ("info",    "PECI Controlled",                  "Platform Environment Control Interface governs energy bias."),
    }, ("cisco",), None),

    ("cpuengperfbias", "Energy Performance Bias (Cisco)", {
        "balanced performance": ("success", "Balanced Performance (Platform Default)", "Cisco platform default for enterprise virtualization."),
        "performance":          ("success", "Performance Mode",                        "Peak CPU frequency and performance biased."),
        "balanced power":       ("warning", "Balanced Power",                           "Biased towards power saving; may increase VM execution latency."),
        "power":                ("warning", "Power Saving Mode",                        "Maximum power savings active; CPU latency increased under load."),
    }, ("cisco",), None),

    ("bootperformancemode", "Boot Performance Mode (Cisco)", {
        "max performance":         ("success", "Max Performance", "Processors initialize in maximum performance state during POST and boot."),
        "set by intel speedstep":  ("info",    "Set by SpeedStep", "Initial operating frequency governed by SpeedStep configuration."),
    }, ("cisco",), None),

    ("processorc6report", "Processor C6 Report (Cisco)", {
        "disabled": ("success", "C6 State Disabled (Platform Default)", "Cisco platform default. Eliminates C6 sleep wake-up latency for vSAN storage operations."),
        "enabled":  ("warning", "C6 State Enabled",                     "CPU enters deep C6 sleep during idle, which can introduce microsecond wake latency under bursty vSAN I/O."),
        "auto":     ("info",    "C6 State Auto",                        "Processor determines C6 availability automatically."),
    }, ("cisco",), None),

    ("processorc1e", "Processor C1E (Cisco)", {
        "disabled": ("success", "C1E Disabled (Platform Default)", "Cisco platform default. Processor stays at full operating voltage during C1 halt."),
        "enabled":  ("info",    "C1E Enabled",                     "Processor lowers frequency and voltage during halt state."),
    }, ("cisco",), None),

    ("packagecstatelimit", "Package C-State Limit (Cisco)", {
        "c0 c1 state":   ("success", "C0/C1 Limit (Platform Default)", "Cisco platform default. Limits package idle to C0/C1 state for low-latency responsiveness."),
        "c0/c1 state":   ("success", "C0/C1 Limit (Platform Default)", "Cisco platform default. Limits package idle to C0/C1 state for low-latency responsiveness."),
        "no limit":      ("warning", "No Limit (Deep C-States)",       "Package can enter deepest idle states."),
    }, ("cisco",), None),

    ("snc", "Sub-NUMA Clustering (SNC)", {
        "disabled": ("success", "SNC Disabled", "Sockets exposed as single NUMA domains — recommended baseline for general virtualization and vSAN."),
        "snc2":     ("info",    "SNC-2 (2 Clusters / Socket)", "Socket partitioned into 2 NUMA nodes. Optimizes cache locality for NUMA-aligned workloads."),
        "snc4":     ("info",    "SNC-4 (4 Clusters / Socket)", "Socket partitioned into 4 NUMA nodes. Optimizes cache locality for high-core-count multi-socket servers."),
        "enabled":  ("info",    "SNC Enabled", "Sub-NUMA clustering active."),
    }, None, None),

    ("subnuma", "Sub-NUMA Clustering (SNC)", {
        "disabled": ("success", "SNC Disabled", "Sockets exposed as single NUMA domains — recommended baseline for general virtualization and vSAN."),
        "snc2":     ("info",    "SNC-2 (2 Clusters / Socket)", "Socket partitioned into 2 NUMA nodes. Optimizes cache locality for NUMA-aligned workloads."),
        "snc4":     ("info",    "SNC-4 (4 Clusters / Socket)", "Socket partitioned into 4 NUMA nodes. Optimizes cache locality for high-core-count multi-socket servers."),
        "enabled":  ("info",    "SNC Enabled", "Sub-NUMA clustering active."),
    }, None, None),

    ("upiprefetch", "UPI Prefetcher (Intel)", {
        "enabled":  ("success", "UPI Prefetch Enabled", "Cross-socket Ultra Path Interconnect (UPI) prefetch active. Improves cross-socket memory throughput on multi-socket systems."),
        "disabled": ("info",    "UPI Prefetch Disabled", "Cross-socket UPI prefetch inactive."),
    }, None, ("intel",)),

    ("cpuinterconnectbuslinkpower", "UPI Link Power Management", {
        "disabled": ("success", "Link Power Mgmt Disabled", "UPI cross-socket links stay at full readiness with zero wake latency. Recommended for multi-socket vSAN."),
        "enabled":  ("info",    "Link Power Mgmt Enabled", "Cross-socket interconnect enters power savings during idle."),
    }, None, ("intel",)),

    ("numaoptimize", "NUMA Optimization (Cisco)", {
        "enabled":  ("success", "NUMA Optimized On (Platform Default)", "Cisco platform default. Exposes native hardware NUMA topology to the hypervisor."),
        "disabled": ("warning", "NUMA Interleaving Disabled",          "NUMA memory is interleaved across sockets, hiding NUMA topology from ESXi."),
    }, ("cisco",), None),

    # AMD EPYC Performance & Determinism (AMD architecture only)
    ("amdcpuavx512", "AMD Zen 5 AVX-512 Vector Execution", {
        "auto":     ("success", "AVX-512 Auto (Full 512-bit)", "AMD Zen 5 full-width 512-bit vector pipelines enabled. Optimal for vSphere AI/ML, encryption, and hashing."),
        "enabled":  ("success", "AVX-512 Enabled",             "AMD Zen 5 full-width 512-bit vector pipelines active."),
        "disabled": ("warning", "AVX-512 Disabled",            "Vector processing restricted to legacy instruction widths. AI/ML and cryptographic performance reduced."),
    }, None, ("amd",)),

    ("numanodespersocket", "AMD NUMA Nodes per Socket (NPS)", {
        "4":    ("success", "NPS4 (4 NUMA Nodes / Socket)", "Optimal memory latency and CCX alignment. Recommended for vSAN ESA and database performance."),
        "nps4": ("success", "NPS4 (4 NUMA Nodes / Socket)", "Optimal memory latency and CCX alignment. Recommended for vSAN ESA and database performance."),
        "2":    ("info",    "NPS2 (2 NUMA Nodes / Socket)", "Balanced NUMA interleaving."),
        "nps2": ("info",    "NPS2 (2 NUMA Nodes / Socket)", "Balanced NUMA interleaving."),
        "1":    ("info",    "NPS1 (1 NUMA Node / Socket)",  "Single NUMA domain per socket. Optimal for very wide VMs spanning full socket memory; consider NPS4 for latency-sensitive workloads."),
        "nps1": ("info",    "NPS1 (1 NUMA Node / Socket)",  "Single NUMA domain per socket. Optimal for very wide VMs spanning full socket memory; consider NPS4 for latency-sensitive workloads."),
    }, None, ("amd",)),

    ("amdmaxxgmispeed", "AMD Infinity Fabric (xGMI) Speed", {
        "32gb":   ("success", "xGMI 32 GT/s", "Peak 32 GT/s interconnect link speed active."),
        "32gt/s": ("success", "xGMI 32 GT/s", "Peak 32 GT/s interconnect link speed active."),
        "28gb":   ("info",    "xGMI 28 GT/s", "Interconnect running at 28 GT/s."),
    }, None, ("amd",)),

    ("controlledturbo", "Controlled CPU Turbo", {
        "enabled":  ("success", "Controlled Turbo Active",   "Enforces deterministic CPU core clock frequencies across sockets under load."),
        "disabled": ("info",    "Controlled Turbo Inactive", "Standard dynamic CPU turbo scaling."),
    }, None, None),

    ("cpufeatureerms", "Enhanced REP MOVSB/STOSB (ERMS)", {
        "enabled":  ("success", "ERMS Active",   "Fast hardware memory copy primitives enabled for hypervisor kernel operations."),
        "disabled": ("info",    "ERMS Disabled", "Standard memory copy operations."),
    }, None, None),

    ("determinismslider", "AMD Performance Determinism", {
        "performancedeterminism": ("success", "Performance Determinism", "CPUs enforce deterministic, low-jitter frequencies across all cores. Recommended for vSAN ESA tail latency."),
        "powerdeterminism":       ("info",    "Power Determinism",       "CPUs dynamically balance performance within socket power envelope (default). Consider Performance Determinism for ultra-low latency vSAN."),
        "manual":                 ("info",    "Manual Determinism",      "Determinism slider configured manually."),
    }, None, ("amd",)),

    ("ccxasnumadomain", "AMD CCX as NUMA Domain", {
        "disabled": ("success", "CCX as NUMA Domain Disabled", "NUMA domains mapped per socket or per die (NPS1). Recommended standard for general vSphere VM placement."),
        "enabled":  ("info",    "CCX as NUMA Domain Enabled",  "Each Core Complex (CCX) exposed as an independent NUMA node. Optimizes L3 cache locality for NUMA-aware workloads."),
    }, None, ("amd",)),

    ("dfcstate", "AMD Data Fabric C-States", {
        "disabled": ("success", "Data Fabric C-States Disabled", "AMD Data Fabric interconnect links stay in high-speed C0. Eliminates interconnect wake-up latency for vSAN ESA."),
        "enabled":  ("info",    "Data Fabric C-States Enabled",  "AMD Data Fabric interconnect scales down power during idle."),
    }, None, ("amd",)),

    ("dfpstatefreqoptimizer", "AMD Data Fabric P-State Optimizer", {
        "enabled":  ("success", "DF P-State Optimizer Enabled",  "Optimizes interconnect fabric frequency dynamically for memory throughput."),
        "disabled": ("info",    "DF P-State Optimizer Disabled", "Static Data Fabric P-state."),
    }, None, ("amd",)),

    # Architecture-agnostic: Processor x2APIC Mode (>255 cores / logical processors)
    ("procx2apic", "Processor x2APIC Mode", {
        "enabled":  ("success", "x2APIC Mode Enabled",  "Extended interrupt controller active. Required for systems with >255 logical processors."),
        "disabled": ("warning", "x2APIC Mode Disabled", "Standard APIC limits interrupt delivery to 255 processors. Must be enabled on high-core-count servers."),
    }, None, None),

    # Architecture-agnostic: PCIe ASPM (Active State Power Management)
    ("pcieaspm", "PCIe ASPM", {
        "disabled": ("success", "PCIe ASPM Disabled", "PCIe link power savings disabled — keeps high-speed NVMe and 100GbE links at full readiness with zero wake latency. Recommended for vSAN ESA."),
        "enabled":  ("warning", "PCIe ASPM Enabled",  "PCIe links enter low-power state during brief idle periods. May add microsecond wake latency to NVMe IO."),
    }, None, None),

    # Generic / multi-OEM: SpeedStep / EIST (Intel architecture only)
    ("enhancedintelspeedstep", "Enhanced Intel SpeedStep (EIST)", {
        "enabled":  ("warning", "SpeedStep Enabled",  "CPU frequency scales with load. Disable for consistent low-latency vSAN performance, or ensure vSphere Host Power Policy is High Performance."),
        "disabled": ("success", "SpeedStep Disabled", "CPU at fixed max frequency — consistent performance."),
    }, None, ("intel",)),

    ("speedstep", "Intel SpeedStep", {
        "enabled":  ("warning", "SpeedStep Enabled",  "CPU frequency scales with load."),
        "disabled": ("success", "SpeedStep Disabled", ""),
    }, None, ("intel",)),

    # Turbo Boost (Intel architecture only)
    ("procturbomode", "Intel Turbo Boost", {
        "enabled":  ("success", "Turbo Boost Enabled",  "CPU can burst above base clock when thermal headroom allows."),
        "disabled": ("warning", "Turbo Boost Disabled", "CPU limited to base clock — peak single-thread and vSAN front-end throughput reduced."),
    }, None, ("intel",)),

    ("turboboost", "Intel Turbo Boost", {
        "enabled":  ("success", "Turbo Boost Enabled",  ""),
        "disabled": ("warning", "Turbo Boost Disabled", ""),
    }, None, ("intel",)),

    # C-States (Dell: ProcCStates; HPE: MinProcIdlePkgState; generic: CStates)
    ("proccstates", "CPU C-States", {
        "enabled":        ("warning", "C-States Enabled",         "CPU can enter deep idle states. Acceptable for most workloads but adds wake-up latency for bursty vSAN IO."),
        "disabled":       ("success", "C-States Disabled",        "CPU stays in C0 (fully active). Recommended for latency-sensitive vSAN clusters."),
        "autonomousmode": ("warning", "Autonomous C-States",      "CPU autonomously enters/exits idle — similar to Enabled; monitor for latency outliers."),
    }, None, None),

    ("minprocidlepkgstate", "CPU Minimum Idle State (HPE)", {
        "nodcstates": ("success", "No Deep C-States", "CPU stays in C0/C1 — low-latency profile."),
        "c6":         ("warning", "C6 Idle State",    "CPU may drop to C6 under idle — adds wake latency."),
        "nocstates":  ("success", "No C-States",      ""),
    }, ("hpe", "hp"), None),

    # Hyper-Threading
    ("logicalproc", "Hyper-Threading (Dell)", {
        "enabled":  ("success", "Hyper-Threading On",  "Required for full vCPU density."),
        "disabled": ("warning", "Hyper-Threading Off", "Logical CPU count halved — reduces VM density and may impact vSAN CPU scheduling."),
    }, ("dell",), None),

    ("hyperthreading", "Hyper-Threading", {
        "enabled":  ("success", "Hyper-Threading On",  ""),
        "disabled": ("warning", "Hyper-Threading Off", ""),
    }, None, None),
]


def _detect_cpu_power_mode(
    attrs: dict,
    vendor: Optional[str] = None,
    architecture: Optional[str] = None,
) -> list:
    """Scan Redfish BIOS Attributes for CPU performance / power-mode settings.

    Returns a list of result dicts sorted danger → warning → info → success.
    Applies strict vendor and CPU architecture gating so platform-specific knobs
    do not misfire across OEMs or processor families.
    """
    results = []
    seen_keys: set = set()

    # Normalize vendor and architecture
    v_norm = (vendor or "").lower().strip()
    a_norm = (architecture or "").lower().strip()

    # Heuristic inference if not passed
    if not v_norm:
        if any(k in attrs for k in ("SysProfile", "CorrEccSmi", "PPROnUCE", "ProcCStates", "Slot2Bif", "BiosNvmeDriver")):
            v_norm = "dell"
        elif any(k in attrs for k in ("PowerRegulator", "MinProcIdlePkgState", "CollabPowerControl", "AmpMode")):
            v_norm = "hpe"
        elif any(k in attrs for k in ("MemoryOperatingMode", "LenovoCustom")):
            v_norm = "lenovo"
        elif any(k in attrs for k in ("SelectMemoryRAS", "SelectMemoryRasConfiguration", "CiscoCustom", "CPUPerformance", "CiscoAdaptiveMemTraining", "WorkLdConfig")):
            v_norm = "cisco"

    if not a_norm:
        if any(k in attrs for k in ("CcxAsNumaDomain", "DeterminismSlider", "DfCState", "CpuMinSevAsid", "Sme", "TransparentSme")):
            a_norm = "amd"
        elif any(k in attrs for k in ("ProcVmd", "VmdPort", "SgxFactoryReset", "EnhancedIntelSpeedStep", "SpeedStep")):
            a_norm = "intel"

    for raw_key, raw_val in attrs.items():
        key_lower = raw_key.lower()
        if key_lower in seen_keys:
            continue
        val_str = str(raw_val).lower().strip()
        if not val_str or val_str in ("n/a", "none", ""):
            continue

        # Dell 17G WorkloadProfile check: if on Dell and value is "NotConfigured", skip (SysProfile governs)
        if "dell" in v_norm and key_lower == "workloadprofile" and val_str == "notconfigured":
            continue

        for rule in _CPU_POWER_RULES:
            key_pat = rule[0]
            feature_label = rule[1]
            value_map = rule[2]
            allowed_vendors = rule[3] if len(rule) > 3 else None
            allowed_archs = rule[4] if len(rule) > 4 else None

            # Vendor gating
            if allowed_vendors is not None and v_norm:
                if not any(v and v in v_norm for v in allowed_vendors):
                    continue

            # Architecture gating
            if allowed_archs is not None and a_norm:
                if not any(a and a in a_norm for a in allowed_archs):
                    continue

            if key_pat in key_lower:
                seen_keys.add(key_lower)
                badge = label = note = None
                for val_pat, (b, l, n) in value_map.items():
                    if val_pat in val_str:
                        badge, label, note = b, l, n
                        break
                if badge is None:
                    badge, label, note = "info", str(raw_val), ""
                results.append({
                    "feature": feature_label,
                    "label":   label,
                    "badge":   badge,
                    "note":    note,
                    "raw_key": raw_key,
                    "raw_val": str(raw_val),
                })
                break

    _sev = {"danger": 0, "warning": 1, "info": 2, "success": 3}
    results.sort(key=lambda r: _sev.get(r["badge"], 4))
    return results
