"""
VCF Readiness Tool — BIOS attribute detector: RAS / memory interleaving modes.
Parses BIOS Settings from the Redfish /Systems/{id}/Bios endpoint.
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("vcf_assess")


# ---------------------------------------------------------------------------
# OEM & Architecture Memory RAS Documentation Links
# ---------------------------------------------------------------------------
_OEM_RAS_DOCS: Dict[str, Tuple[str, str]] = {
    "hpe": (
        "HPE Advanced Memory Protection Tech Brief ↗",
        "https://www.hpe.com/psnow/doc/a00018421en_us",
    ),
    "dell": (
        "Dell Memory RAS Tech Guide ↗",
        "https://www.dell.com/support/kbdoc/en-us/000116150/dell-poweredge-memory-ras-features",
    ),
    "lenovo": (
        "Lenovo Memory RAS Guide ↗",
        "https://lenovopress.lenovo.com/lp1023-lenovo-thinksystem-memory-ras-features",
    ),
    "cisco": (
        "Cisco UCS Memory Tech Note ↗",
        "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c-series_hardware/C220M5/install/b_C220M5_HIG/b_C220M5_HIG_chapter_0100.html",
    ),
    "intel": (
        "Intel Memory RAS Tech Article ↗",
        "https://www.intel.com/content/www/us/en/developer/articles/technical/intel-xeon-scalable-processor-family-memory-ras.html",
    ),
    "amd": (
        "AMD EPYC Memory Tech Overview ↗",
        "https://www.amd.com/en/products/processors/server/epyc.html",
    ),
    "vsphere_reliable_mem": (
        "vSphere Reliable Memory Overview ↗",
        "https://thenicholson.com/vmware-vsphere-reliable-memory-a-few-thoughts/",
    ),
}

# Primary BIOS attribute key substrings across vendors
_PRIMARY_OPMODE_PATTERNS = {
    "advancedmemprotection",
    "advancedmemoryprotection",
    "ampmode",
    "ampmodeactive",
    "ampmodestatus",
    "memopmode",
    "memoryoperatingmode",
    "memoryrasconfig",
    "selectmemoryras",
    "selectmemoryrasconfiguration",
    "memrasmode",
    "rasmode",
}

_MIRROR_SUB_KEYS = {"memmirrormode", "memorymirrormode", "memorymirror"}


# ---------------------------------------------------------------------------
# Memory RAS / protection mode rules
# ---------------------------------------------------------------------------
# Each rule: (key_substring_lower, display_name, {val_substring_lower: (badge, label, vcf_note, optional_doc_key)})
# Rules are matched in order; first key hit wins — put more-specific patterns before generic ones.
_MEM_RAS_RULES = [
    # HPE Advanced Memory Protection (Gen9 / Gen10 / Gen11 / Synergy / Apollo)
    ("advancedmemprotection", "Advanced Memory Protection", {
        "advancedecc":      ("success", "Advanced ECC",               "Enhanced multi-bit ECC protection active — 100% memory capacity available.", "hpe"),
        "advecc":           ("success", "Advanced ECC",               "Enhanced multi-bit ECC protection active — 100% memory capacity available.", "hpe"),
        "fastfaulttolerant":("info",    "Fast Fault Tolerant (ADDDC)","HPE Fast Fault Tolerant mode active — monitors memory health and dynamically spares failing DRAM regions under correctable error conditions.", "hpe"),
        "onlinespare":      ("info",    "Online Spare",               "HPE Online Spare active — reserves spare memory ranks for failover protection.", "hpe"),
        "partialmirroring": ("info",    "Partial Memory Mirroring",   "Address-range mirroring active (vSphere Reliable Memory). Mirrors hypervisor kernel memory while leaving remaining capacity for VMs.", "vsphere_reliable_mem"),
        "partial":          ("info",    "Partial Memory Mirroring",   "Address-range mirroring active (vSphere Reliable Memory). Mirrors hypervisor kernel memory while leaving remaining capacity for VMs.", "vsphere_reliable_mem"),
        "fullmirroring":    ("danger",  "Full Memory Mirroring ⚠️",   "50% of installed RAM consumed as mirror — effective usable memory is halved. Re-validate vSAN node sizing.", "hpe"),
        "intrasocketmirroring": ("danger", "Intrasocket Mirroring ⚠️", "50% of installed RAM consumed as mirror within socket pairs — effective usable memory is halved.", "hpe"),
        "intersocketmirroring": ("danger", "Intersocket Mirroring ⚠️", "50% of installed RAM consumed as mirror across sockets — effective usable memory is halved.", "hpe"),
        "mirrored":         ("danger",  "Memory Mirroring ⚠️",        "50% of installed RAM consumed as mirror — effective usable memory is halved.", "hpe"),
        "mirror":           ("danger",  "Memory Mirroring ⚠️",        "50% of installed RAM consumed as mirror — effective usable memory is halved.", "hpe"),
        "lockstep":         ("info",    "Lockstep Mode",              "Lockstep channel pair operation active.", "hpe"),
    }),
    ("advancedmemoryprotection", "Advanced Memory Protection", {
        "advancedecc":      ("success", "Advanced ECC",               "Enhanced multi-bit ECC protection active — 100% memory capacity available.", "hpe"),
        "fastfaulttolerant":("info",    "Fast Fault Tolerant (ADDDC)","HPE Fast Fault Tolerant mode active — monitors memory health and dynamically spares failing DRAM regions.", "hpe"),
        "onlinespare":      ("info",    "Online Spare",               "HPE Online Spare active — reserves spare memory ranks for failover protection.", "hpe"),
        "partialmirroring": ("info",    "Partial Memory Mirroring",   "Address-range mirroring active (vSphere Reliable Memory).", "vsphere_reliable_mem"),
        "partial":          ("info",    "Partial Memory Mirroring",   "Address-range mirroring active (vSphere Reliable Memory).", "vsphere_reliable_mem"),
        "mirror":           ("danger",  "Memory Mirroring ⚠️",        "50% of installed RAM consumed as mirror — effective usable memory is halved.", "hpe"),
    }),
    ("ampmode", "Advanced Memory Protection", {
        "advancedecc":      ("success", "Advanced ECC",               "Enhanced multi-bit ECC protection active — 100% memory capacity available.", "hpe"),
        "fastfaulttolerant":("info",    "Fast Fault Tolerant (ADDDC)","HPE Fast Fault Tolerant mode active — monitors memory health and dynamically spares failing DRAM regions.", "hpe"),
        "onlinespare":      ("info",    "Online Spare",               "HPE Online Spare active — reserves spare memory ranks for failover protection.", "hpe"),
        "partialmirroring": ("info",    "Partial Memory Mirroring",   "Address-range mirroring active (vSphere Reliable Memory).", "vsphere_reliable_mem"),
        "partial":          ("info",    "Partial Memory Mirroring",   "Address-range mirroring active (vSphere Reliable Memory).", "vsphere_reliable_mem"),
        "mirror":           ("danger",  "Memory Mirroring ⚠️",        "50% of installed RAM consumed as mirror — effective usable memory is halved.", "hpe"),
    }),

    # Dell PowerEdge / Intel / Supermicro MemOpMode
    ("memopmode", "Memory Operating Mode", {
        "optimizermode":   ("success", "ECC Optimizer",       "Standard ECC — no capacity or bandwidth overhead. Recommended for vSAN.", "dell"),
        "advancedeccmode": ("success", "Advanced ECC",        "Enhanced multi-bit ECC correction; no capacity overhead.", "dell"),
        "advancedecc":     ("success", "Advanced ECC",        "Enhanced multi-bit ECC correction; no capacity overhead.", "dell"),
        "partial":          ("info",    "Partial Memory Mirroring", "Address-range mirroring active (vSphere Reliable Memory). Mirrors hypervisor kernel memory while leaving remaining capacity for VMs.", "vsphere_reliable_mem"),
        "mirror":          ("danger",  "Memory Mirroring ⚠️", "50% of installed RAM consumed as mirror — effective capacity halved. Re-validate vSAN node sizing.", "dell"),
        "adddc":           ("info",    "ADDDC Sparing",       "Adaptive DDDC sparing active. Dynamically spares failing DRAM regions under correctable error conditions.", "intel"),
        "faulttolerant":   ("info",    "Fault Tolerant (ADDDC)", "Fault tolerant ADDDC sparing active.", "intel"),
        "sparing":         ("info",    "Rank Sparing",        "One rank per channel reserved for failover sparing.", "dell"),
        "spare":           ("info",    "Rank Sparing",        "One rank per channel reserved for failover sparing.", "dell"),
        "lockstep":        ("info",    "Lockstep Mode",       "Lockstep channel pair operation active.", "dell"),
    }),
    ("memoryoperatingmode", "Memory Operating Mode", {
        "independent":     ("success", "Independent / Standard ECC", "Standard ECC — no capacity or bandwidth overhead.", "lenovo"),
        "optimizermode":   ("success", "ECC Optimizer",              "Standard ECC — no capacity or bandwidth overhead.", "lenovo"),
        "advancedecc":     ("success", "Advanced ECC",               "Enhanced multi-bit ECC correction; no capacity overhead.", "lenovo"),
        "mirroring":       ("danger",  "Memory Mirroring ⚠️",        "50% of installed RAM consumed as mirror — effective capacity halved.", "lenovo"),
        "mirror":          ("danger",  "Memory Mirroring ⚠️",        "50% of installed RAM consumed as mirror — effective capacity halved.", "lenovo"),
        "ranksparing":     ("info",    "Rank Sparing",               "One rank per channel reserved for failover sparing.", "lenovo"),
        "sparing":         ("info",    "Rank Sparing",               "One rank per channel reserved for failover sparing.", "lenovo"),
        "lockstep":        ("info",    "Lockstep Mode",              "Lockstep channel pair operation active.", "lenovo"),
    }),

    # Cisco UCS / IMC Memory RAS
    ("memoryrasconfig", "Memory RAS Configuration", {
        "maximum-performance": ("success", "Maximum Performance", "Standard ECC — maximum memory bandwidth and full capacity available.", "cisco"),
        "maxperf":             ("success", "Maximum Performance", "Standard ECC — maximum memory bandwidth and full capacity available.", "cisco"),
        "mirroring":           ("danger",  "Memory Mirroring ⚠️",  "50% of installed RAM consumed as mirror — effective capacity halved.", "cisco"),
        "sparing":             ("info",    "Memory Sparing",      "Spare memory ranks reserved for failover.", "cisco"),
        "lockstep":            ("info",    "Lockstep Mode",       "Lockstep channel pair operation active.", "cisco"),
    }),
    ("selectmemoryras", "Memory RAS Configuration", {
        "adddc sparing":             ("success", "ADDDC Sparing (Platform Default)", "Adaptive Double Device Data Correction (ADDDC) Sparing is the Cisco platform default and VMware recommended RAS mode for enterprise virtualization, providing dynamic DRAM fault tolerance with minimal latency overhead.", "cisco"),
        "adddc":                     ("success", "ADDDC Sparing (Platform Default)", "Adaptive Double Device Data Correction (ADDDC) Sparing is the Cisco platform default and VMware recommended RAS mode for enterprise virtualization, providing dynamic DRAM fault tolerance with minimal latency overhead.", "cisco"),
        "maximum-performance":       ("success", "Maximum Performance",              "Standard ECC — maximum memory bandwidth and full capacity available.", "cisco"),
        "maximum performance":       ("success", "Maximum Performance",              "Standard ECC — maximum memory bandwidth and full capacity available.", "cisco"),
        "maxperf":                   ("success", "Maximum Performance",              "Standard ECC — maximum memory bandwidth and full capacity available.", "cisco"),
        "mirror mode 1lm":           ("danger",  "Memory Mirroring ⚠️",              "50% of installed RAM consumed as mirror — effective capacity halved.", "cisco"),
        "mirroring":                 ("danger",  "Memory Mirroring ⚠️",              "50% of installed RAM consumed as mirror — effective capacity halved.", "cisco"),
        "partial mirror mode 1lm":   ("info",    "Partial Memory Mirroring",         "Address-range mirroring active (vSphere Reliable Memory). Mirrors hypervisor kernel memory while leaving remaining capacity for VMs.", "vsphere_reliable_mem"),
        "partial mirror":            ("info",    "Partial Memory Mirroring",         "Address-range mirroring active (vSphere Reliable Memory). Mirrors hypervisor kernel memory while leaving remaining capacity for VMs.", "vsphere_reliable_mem"),
        "sparing":                   ("info",    "Memory Sparing",                   "Spare memory ranks reserved for failover.", "cisco"),
        "lockstep":                  ("info",    "Lockstep Mode",                    "Lockstep channel pair operation active.", "cisco"),
    }),
    ("partialcachelinesparing", "Partial Cache Line Sparing (Cisco)", {
        "enabled":  ("success", "Partial Cache Line Sparing On (Platform Default)", "Hardware spares failing cache lines dynamically without retiring entire memory ranks."),
        "disabled": ("info",    "Partial Cache Line Sparing Off", ""),
    }),
    ("selectpprtype", "Post Package Repair / PPR (Cisco)", {
        "hard ppr": ("success", "Hard PPR (Platform Default)", "Cisco platform default. Hardware fuses out failing DRAM rows across server reboots."),
        "soft ppr": ("info",    "Soft PPR",                    "Software runtime row repair active."),
    }),

    # Secondary / sub-setting keys
    ("memorymirrormode", "Memory Mirror Mode", {
        "full":     ("danger",  "Full Memory Mirror ⚠️", "50% of RAM consumed — re-validate vSAN capacity."),
        "partial":  ("info",    "Partial Memory Mirroring", "Address-range mirroring active (vSphere Reliable Memory).", "vsphere_reliable_mem"),
        "enabled":  ("danger",  "Memory Mirror ⚠️",      "50% of RAM reserved as mirror — re-validate vSAN capacity."),
        "disabled": ("success", "Mirroring Disabled",    "No capacity overhead."),
    }),
    ("memmirrormode", "Memory Mirror Mode", {
        "full":     ("danger",  "Full Memory Mirror ⚠️", "50% of RAM consumed."),
        "partial":  ("info",    "Partial Memory Mirroring", "Address-range mirroring active (vSphere Reliable Memory).", "vsphere_reliable_mem"),
        "enabled":  ("danger",  "Memory Mirror ⚠️",      "50% of RAM reserved."),
        "disabled": ("success", "Mirroring Disabled",    ""),
    }),
    ("memorymirror", "Memory Mirroring", {
        "enabled":  ("danger",  "Memory Mirror ⚠️",    "50% of RAM reserved — re-validate vSAN capacity."),
        "disabled": ("success", "Mirroring Disabled",  ""),
    }),

    # Sparing sub-settings
    ("memsparing", "Memory Sparing", {
        "enabled":  ("info",    "Memory Sparing Active",  "DIMMs reserved for failover sparing on memory errors."),
        "disabled": ("success", "Memory Sparing Off", ""),
    }),
    ("ranksparing", "Rank Sparing", {
        "enabled":  ("info",    "Rank Sparing Active",  "Reserves DIMM ranks for failover sparing."),
        "disabled": ("success", "Rank Sparing Off", ""),
    }),
    ("banksparing", "Bank Sparing", {
        "enabled":  ("info",    "Bank Sparing Active",  "Reserves DIMM banks for failover sparing."),
        "disabled": ("success", "Bank Sparing Off", ""),
    }),
    ("adddcsparing", "ADDDC Sparing", {
        "enabled":  ("info",    "ADDDC Sparing Active", "Adaptive Double Device Data Correction active."),
        "disabled": ("success", "ADDDC Sparing Off", ""),
    }),
    ("adddc", "ADDDC", {
        "enabled":  ("info",    "ADDDC Active",         "Adaptive DDDC active; monitors DRAM health."),
        "disabled": ("success", "ADDDC Off", ""),
    }),

    # Maintenance & reliability sub-settings
    ("mempatrolscrub", "Patrol Scrub", {
        "enabled":  ("success", "Patrol Scrub On",  "Background ECC scrubbing active — recommended."),
        "disabled": ("warning", "Patrol Scrub Off", "Correctable bit errors can accumulate silently; re-enable in BIOS."),
    }),
    ("patrolscrub", "Patrol Scrub", {
        "enabled":  ("success", "Patrol Scrub On",  ""),
        "disabled": ("warning", "Patrol Scrub Off", ""),
    }),
    ("memrefreshrate", "Memory Refresh Rate", {
        "1x": ("info",    "Refresh 1× (normal)",           "Standard DRAM refresh — no performance impact."),
        "2x": ("warning", "Refresh 2× (reliability mode)", "2× refresh rate reduces memory bandwidth ~10–15%. Typically deployed in high-temp environments or after correctable-error events."),
    }),

    # NUMA & Topology
    ("nodeinterleave", "NUMA Memory Interleaving (Node Interleave)", {
        "enabled":  ("warning", "Node Interleaving ON — NUMA Flattened",
                     "Node Interleaving converts the system to UMA, disabling ESXi NUMA-aware "
                     "scheduling and memory placement. Per vSphere 9.1 Best Practices: "
                     "disable Node Interleaving to leave NUMA active for optimal VM performance."),
        "disabled": ("success", "Node Interleaving OFF — NUMA Active",
                     "NUMA topology preserved. ESXi NUMA scheduler places VMs and memory locally — "
                     "recommended for vSphere 9.1 / VCF."),
    }),
    ("nodeinterleaving", "NUMA Memory Interleaving (Node Interleaving)", {
        "enabled":  ("warning", "Node Interleaving ON — NUMA Flattened",
                     "Node Interleaving converts the system to UMA, disabling ESXi NUMA-aware "
                     "scheduling. Disable in BIOS to restore NUMA-aware memory placement."),
        "disabled": ("success", "Node Interleaving OFF — NUMA Active",
                     "NUMA topology preserved. Recommended for vSphere 9.1 / VCF."),
    }),
    ("umabasedclustering", "UMA-Based Clustering (Hemisphere / Quadrant)", {
        "hemisphere": ("info", "Hemisphere Mode (2 Clusters)", "UMA-based clustering configured in Hemisphere mode (2 clusters per socket) — balances memory interleaving and latency."),
        "quadrant":   ("info", "Quadrant Mode (4 Clusters)",   "UMA-based clustering configured in Quadrant mode (4 clusters per socket) — optimizes cache locality for 4-socket topologies."),
        "disabled":   ("info", "Clustering Disabled",          "Standard monolithic socket clustering."),
        "all2all":    ("info", "All-to-All Mode",              "All-to-All uniform memory routing across sockets."),
    }),
    ("acpislit", "ACPI System Locality Information (SLIT)", {
        "enabled":  ("success", "ACPI SLIT Enabled", "System Locality Distance Information Table exposed to ESXi. Enables optimal cross-socket NUMA distance cost calculation."),
        "disabled": ("warning", "ACPI SLIT Disabled", "ACPI SLIT disabled — ESXi cannot determine cross-socket NUMA distance matrices."),
    }),
    ("acpirootbridgepxm", "ACPI Root Bridge Proximity (PXM)", {
        "enabled":  ("success", "Root Bridge PXM Enabled", "Exposes PCIe root bridge proximity domains for NUMA-aware PCIe device affinity."),
        "disabled": ("info",    "Root Bridge PXM Disabled", "PCIe root bridge proximity domains not exposed."),
    }),
    ("numagroupsizeopt", "NUMA Group Size Optimization", {
        "flat":      ("success", "NUMA Group: Flat", "Flat NUMA group topology preserves uniform local memory access for vSphere VMs."),
        "clustered": ("info",    "NUMA Group: Clustered", "Clustered NUMA group size optimization active."),
    }),
    ("numameminterleave", "NUMA Memory Interleaving (Node Interleaving)", {
        "enabled":  ("warning", "Node Interleaving ON — NUMA Flattened",
                     "Node Interleaving converts the system to UMA, disabling ESX NUMA-aware "
                     "scheduling and memory placement. Per vSphere 9.0 Best Practices §BIOS Settings: "
                     "disable Node Interleaving to leave NUMA active for optimal VM performance."),
        "disabled": ("success", "Node Interleaving OFF — NUMA Active",
                     "NUMA topology preserved. ESX NUMA scheduler places VMs and memory locally — "
                     "recommended for vSphere 9.0 / VCF."),
    }),
    ("numainterleaving", "NUMA Memory Interleaving (Node Interleaving)", {
        "enabled":  ("warning", "Node Interleaving ON — NUMA Flattened",
                     "Node Interleaving converts the system to UMA, disabling ESX NUMA-aware "
                     "scheduling. Disable in BIOS to restore NUMA-aware memory placement."),
        "disabled": ("success", "Node Interleaving OFF — NUMA Active", ""),
    }),

    # Architecture RAS Modes
    ("memrasmode", "Memory RAS Mode (AMD)", {
        "none":    ("success", "No RAS Overhead",     "Standard ECC only — no capacity or bandwidth penalty.", "amd"),
        "mirror":  ("danger",  "AMD Mirror Mode ⚠️",  "50% of RAM consumed as mirror — re-validate vSAN node sizing.", "amd"),
        "sparing": ("info",    "AMD Memory Sparing",  "Spare memory banks reserved for failover.", "amd"),
    }),
    ("rasmode", "Memory RAS Mode", {
        "none":    ("success", "No RAS Overhead",   ""),
        "mirror":  ("danger",  "Mirror Mode ⚠️",    "50% of RAM consumed as mirror."),
        "sparing": ("info",    "Memory Sparing",    ""),
    }),

    # Sub-NUMA Clustering
    ("subnumacluster", "Sub-NUMA Cluster / SNC (Intel)", {
        "disabled": ("success", "SNC Disabled",  "Single NUMA domain per socket — recommended for general vSAN ESA workloads.", "intel"),
        "snc2":     ("info",    "SNC-2 Enabled", "Intel SNC-2: 2 NUMA nodes per socket.", "intel"),
        "snc4":     ("info",    "SNC-4 Enabled", "Intel SNC-4: 4 NUMA nodes per socket.", "intel"),
        "enabled":  ("info",    "SNC Enabled",   "Sub-NUMA Cluster active. Consult server vendor guidance.", "intel"),
    }),
    ("intelsubnumaclusters", "Sub-NUMA Cluster / SNC (Intel)", {
        "disabled": ("success", "SNC Disabled",  "Single NUMA domain per socket — recommended for vSAN.", "intel"),
        "enabled":  ("info",    "SNC Enabled",   "SNC active — exposes sub-socket NUMA domains.", "intel"),
    }),
    ("clusterondie", "Cluster-On-Die (Intel COD)", {
        "disabled": ("success", "COD Disabled", "Single NUMA domain per socket.", "intel"),
        "enabled":  ("info",    "COD Enabled",  "Intel COD: partitions LLC and memory controller into 2 sub-socket NUMA domains.", "intel"),
    }),
    ("numanodespers", "NPS Mode (AMD EPYC)", {
        "nps0":  ("warning", "NPS-0 (UMA)",  "All EPYC sockets appear as a single NUMA node. Not recommended.", "amd"),
        "nps1":  ("success", "NPS-1",        "One NUMA node per socket — default and recommended for ESX / vSAN.", "amd"),
        "nps2":  ("info",    "NPS-2",        "2 NUMA nodes per EPYC socket.", "amd"),
        "nps4":  ("info",    "NPS-4",        "4 NUMA nodes per EPYC socket.", "amd"),
    }),
    ("amdnumanodespersocket", "NPS Mode (AMD EPYC)", {
        "nps0":  ("warning", "NPS-0 (UMA)",  "NUMA flattened — set to NPS-1 for vSphere.", "amd"),
        "nps1":  ("success", "NPS-1",        "Recommended — one NUMA node per socket.", "amd"),
        "nps2":  ("info",    "NPS-2",        "2 sub-socket NUMA nodes.", "amd"),
        "nps4":  ("info",    "NPS-4",        "4 sub-socket NUMA nodes.", "amd"),
    }),
    ("npsmode", "NPS Mode (AMD EPYC)", {
        "nps0":  ("warning", "NPS-0 (UMA)",  "NUMA flattened — set to NPS-1 for optimal ESX performance.", "amd"),
        "nps1":  ("success", "NPS-1",        "Recommended — one NUMA node per socket.", "amd"),
        "nps2":  ("info",    "NPS-2",        "2 sub-socket NUMA nodes.", "amd"),
        "nps4":  ("info",    "NPS-4",        "4 sub-socket NUMA nodes.", "amd"),
    }, None, ("amd",)),

    # Maintenance, Training, Frequency & Architecture Memory Security
    ("ppronuce", "Post Package Repair on UCE (PPR)", {
        "enabled":  ("success", "PPR on UCE Enabled", "DDR5 hardware DRAM row remapping active on uncorrectable ECC errors at boot. Automatically remaps faulty DRAM rows, preventing spurious server outages.", "dell"),
        "disabled": ("info",    "PPR on UCE Disabled", "DRAM hardware row remapping disabled."),
    }, None, None),
    ("correccsmi", "Correctable ECC SMI Logging", {
        "enabled":  ("success", "Correctable ECC SMI Logging Enabled", "System Management Interrupt triggers on correctable ECC errors, logging telemetry to BMC SEL for predictive failure analysis.", "dell"),
        "disabled": ("warning", "Correctable ECC SMI Disabled", "Correctable memory errors are not reported to BMC via SMI. Predictive memory failure alerts disabled."),
    }, None, None),
    ("memfrequency", "Memory Operating Frequency", {
        "maxperf":     ("success", "Max Performance Memory Frequency", "DRAM bus locked to maximum rated frequency for peak memory bandwidth."),
        "powersaving": ("warning", "Power Saving Memory Frequency", "Memory operates at reduced clock rate to save power. Reduces memory bandwidth."),
    }, None, None),
    ("memorytraining", "Memory Boot Training", {
        "memorytrainingfast": ("info", "Fast Memory Training", "Fast memory boot training active — optimizes server reboot duration."),
        "fast":               ("info", "Fast Memory Training", "Fast memory boot training active — optimizes server reboot duration."),
        "memorytrainingfull": ("info", "Full Memory Training", "Full memory calibration at boot."),
        "full":               ("info", "Full Memory Training", "Full memory calibration at boot."),
    }, None, None),
    ("currentcxlmemoryinterleavemode", "CXL Memory Interleave Mode", {
        "homogeneous":   ("info", "CXL Interleave Homogeneous", "CXL Type 3 attached memory pooled homogeneously across nodes."),
        "heterogeneous": ("info", "CXL Interleave Heterogeneous", "CXL Type 3 attached memory configured in tiered/heterogeneous mode."),
    }, None, None),
    ("cxlmemorymode", "CXL Memory Mode", {
        "homogeneous":   ("info", "CXL Homogeneous Memory", "Standard CXL 2.0 memory tiering topology."),
        "heterogeneous": ("info", "CXL Heterogeneous Memory", "Interleaved heterogeneous CXL memory tiering."),
    }, None, None),
    ("transparentsme", "AMD Transparent SME", {
        "enabled":  ("info", "Transparent SME Enabled", "Hardware DRAM contents encrypted transparently by AMD Secure Processor.", "amd"),
        "disabled": ("info", "Transparent SME Disabled", "Standard unencrypted DRAM operation (maximum memory performance).", "amd"),
    }, None, ("amd",)),
    ("sme", "AMD Secure Memory Encryption", {
        "enabled":  ("info", "SME Enabled", "AMD Secure Memory Encryption active.", "amd"),
        "disabled": ("info", "SME Disabled", "Standard unencrypted DRAM operation.", "amd"),
    }, None, ("amd",)),
]


def _detect_memory_ras_modes(
    attrs: dict,
    vendor: Optional[str] = None,
    architecture: Optional[str] = None,
) -> list:
    """Scan Redfish BIOS Attributes for memory RAS/protection mode settings.

    Returns a list of result dicts (feature, label, badge, note, raw_key, raw_val,
    optional doc_url & doc_label), sorted danger → warning → info → success.

    Applies vendor and CPU architecture gating so platform-specific knobs do not
    misfire across OEMs or processor families.

    HPE & Multi-Vendor post-processing:
    Primary operating mode attributes (AdvancedMemProtection, MemOpMode, MemoryOperatingMode,
    MemoryRasConfig) specify the active protection model.  When a primary operating mode is
    detected and confirms a non-mirroring mode (Advanced ECC, Fast Fault Tolerant / ADDDC,
    Online Spare, ECC Optimizer), secondary sub-setting keys (such as HPE's persistent
    MemMirrorMode=Full BIOS default) are suppressed to avoid false capacity alarms.
    """
    results: List[Dict[str, Any]] = []
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
        elif any(k in attrs for k in ("SelectMemoryRAS", "SelectMemoryRasConfiguration", "CiscoCustom", "CiscoAdaptiveMemTraining", "CPUPerformance")):
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

        for rule in _MEM_RAS_RULES:
            key_pat = rule[0]
            feature_label = rule[1]
            value_map = rule[2]
            allowed_vendors = rule[3] if len(rule) > 3 else None
            allowed_archs = rule[4] if len(rule) > 4 else None

            # Vendor gating
            if allowed_vendors is not None and v_norm:
                if not any(v in v_norm for v in allowed_vendors):
                    continue

            # Architecture gating
            if allowed_archs is not None and a_norm:
                if not any(a in a_norm for a in allowed_archs):
                    continue

            if key_pat in key_lower:
                seen_keys.add(key_lower)
                badge = label = note = doc_key = None
                for val_pat, val_tuple in value_map.items():
                    if val_pat in val_str:
                        if len(val_tuple) == 4:
                            badge, label, note, doc_key = val_tuple
                        else:
                            badge, label, note = val_tuple[:3]
                        break

                if badge is None:
                    badge, label, note = "info", str(raw_val), ""

                doc_label = doc_url = None
                if doc_key and doc_key in _OEM_RAS_DOCS:
                    doc_label, doc_url = _OEM_RAS_DOCS[doc_key]

                res_dict: Dict[str, Any] = {
                    "feature": feature_label,
                    "label":   label,
                    "badge":   badge,
                    "note":    note,
                    "raw_key": raw_key,
                    "raw_val": str(raw_val),
                }
                if doc_url and doc_label:
                    res_dict["doc_url"] = doc_url
                    res_dict["doc_label"] = doc_label

                results.append(res_dict)
                break

    # ── HPE & Multi-Vendor MemMirrorMode post-processing ───────────────────
    _opmode_results = [
        r for r in results
        if any(pk in r["raw_key"].lower() for pk in _PRIMARY_OPMODE_PATTERNS)
    ]
    _opmode_present = len(_opmode_results) > 0
    _opmode_is_non_mirror = _opmode_present and all(
        r["badge"] != "danger" and "mirror" not in r["label"].lower()
        for r in _opmode_results
    )

    filtered: List[Dict[str, Any]] = []
    for r in results:
        is_mirror_sub = any(mk in r["raw_key"].lower() for mk in _MIRROR_SUB_KEYS)
        if is_mirror_sub:
            if _opmode_is_non_mirror:
                # Primary mode confirmed non-mirroring — skip this sub-setting entry entirely
                continue
            elif not _opmode_present and r["badge"] == "danger":
                # Primary mode key absent (e.g. BMC firmware gap) — treat as info note
                doc_lbl, doc_u = _OEM_RAS_DOCS.get("hpe", (None, None))
                entry = {
                    **r,
                    "badge": "info",
                    "note": (
                        "MemMirrorMode=Full sub-setting detected. On HPE Gen10 this key is "
                        "stored regardless of the active memory mode. Verify AdvancedMemProtection / "
                        "MemOpMode in BIOS before treating this as an active capacity reduction."
                    ),
                }
                if doc_u and doc_lbl:
                    entry["doc_url"] = doc_u
                    entry["doc_label"] = doc_lbl
                filtered.append(entry)
                continue

        filtered.append(r)

    _sev = {"danger": 0, "warning": 1, "info": 2, "success": 3}
    filtered.sort(key=lambda r: _sev.get(r["badge"], 4))
    return filtered
