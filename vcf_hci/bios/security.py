"""
VCF Readiness Tool — BIOS attribute detector: side-channel security settings.
Parses BIOS Settings from the Redfish /Systems/{id}/Bios endpoint.
"""
import logging
import re

logger = logging.getLogger("vcf_assess")


# ---------------------------------------------------------------------------
# Side-channel security mitigation BIOS rules
# ---------------------------------------------------------------------------
# Each rule: (key_substring_lower, display_name, {val_substring_lower: (badge, label, vcf_note)})
# Covers Spectre V2/V4, MDS, L1TF, SMM locking, VT-d, and Intel TXT.
# Matched in order; first key hit wins — put more-specific patterns first.
_SIDE_CHANNEL_RULES = [
    # IBRS — Spectre V2 (CVE-2017-5715) hardware mitigation
    ("procibrs", "Intel IBRS (Spectre V2 — CVE-2017-5715)", {
        "enabled":  ("success", "IBRS Enabled",  "Indirect Branch Restricted Speculation active — Spectre V2 mitigated at hardware level."),
        "disabled": ("warning", "IBRS Disabled", "Spectre V2 branch-injection vector not mitigated in BIOS. Enable IBRS or confirm OS retpoline is active."),
    }),
    ("ibrs", "Intel IBRS (Spectre V2)", {
        "enabled":  ("success", "IBRS Enabled",  "Hardware IBRS active."),
        "disabled": ("warning", "IBRS Disabled", "Spectre V2 hardware mitigation inactive."),
    }),
    # STIBP — Cross-HT Spectre V2 isolation
    ("procstibp", "STIBP (Cross-HT Spectre V2)", {
        "enabled":   ("success", "STIBP Enabled",   "Cross-hyperthread branch prediction sharing blocked — cross-HT Spectre V2 mitigated."),
        "alwayson":  ("success", "STIBP Always On", "STIBP continuously asserted on all logical cores."),
        "disabled":  ("warning", "STIBP Disabled",  "Cross-HT Spectre V2 mitigation inactive. Enable when Hyper-Threading is on in multi-tenant environments."),
    }),
    ("stibp", "STIBP (Cross-HT Spectre V2)", {
        "enabled":  ("success", "STIBP Enabled",  ""),
        "disabled": ("warning", "STIBP Disabled", ""),
    }),
    # SSBD — Spectre V4 (CVE-2018-3639)
    ("procssbd", "SSBD (Spectre V4 — CVE-2018-3639)", {
        "enabled":  ("success", "SSBD Enabled",  "Speculative Store Bypass disabled — CVE-2018-3639 mitigated."),
        "disabled": ("info",    "SSBD Disabled", "Spectre V4 SSB not mitigated at BIOS level — ensure OS prctl / KVM SSBD is enabled for tenant isolation."),
    }),
    ("ssbd", "SSBD (Spectre V4)", {
        "enabled":  ("success", "SSBD Enabled",  ""),
        "disabled": ("info",    "SSBD Disabled", ""),
    }),
    # MDS / MD_CLEAR (CVE-2019-11135 — RIDL / Fallout / TAA)
    ("procmdclear", "MDS / MD_CLEAR (CVE-2019-11135)", {
        "enabled":  ("success", "MDS Clear Enabled",  "Microarchitectural Data Sampling buffers flushed on context switch — MDS mitigated."),
        "disabled": ("warning", "MDS Clear Disabled", "MDS not mitigated at BIOS level. Update BIOS and CPU microcode to a post-May-2019 bundle."),
    }),
    ("mdclear", "MDS / MD_CLEAR (CVE-2019-11135)", {
        "enabled":  ("success", "MDS Clear Enabled",  ""),
        "disabled": ("warning", "MDS Clear Disabled", ""),
    }),
    # L1TF / Foreshadow (CVE-2018-3646 — L1 data cache flush on VM-exit)
    ("l1nextflush", "L1TF / Foreshadow (CVE-2018-3646)", {
        "enabled":  ("success", "L1TF Flush Enabled",  "L1 cache flushed on VM-exit — Foreshadow-VMM cross-VM vector mitigated."),
        "disabled": ("warning", "L1TF Flush Disabled", "L1TF cross-VM vector not mitigated in BIOS. Enable or ensure ESXi Side-Channel Aware Scheduler is active."),
    }),
    ("l1tfmitigation", "L1TF Mitigation", {
        "enabled":  ("success", "L1TF Mitigation On",  ""),
        "disabled": ("warning", "L1TF Mitigation Off", ""),
    }),
    # SMM Base Lock — blocks SMM-based BIOS rootkit persistence
    ("smmbaselock", "SMM Base Lock", {
        "enabled":  ("success", "SMM Base Locked",   "SMBASE register locked at POST — protects against SMM BIOS-level tampering."),
        "disabled": ("warning", "SMM Base Unlocked", "SMM Base Lock not set. Enable in BIOS for VCF security baseline."),
    }),
    ("smmbsasupport", "SMM Base Lock", {
        "enabled":  ("success", "SMM BSA Lock On",  ""),
        "disabled": ("warning", "SMM BSA Lock Off", ""),
    }),
    # SMM Security Mitigation (Dell iDRAC attribute name)
    ("smmsecuritymitigation", "SMM Security Mitigation", {
        "enabled":  ("success", "SMM Security On",  "SMM code-access and SMRAM-lock mitigation active."),
        "disabled": ("warning", "SMM Security Off", "SMM memory not locked — enable for VCF 9.1 security baseline."),
    }),
    # Intel TXT — measured-boot / TPM-anchored trust chain
    ("inteltxt", "Intel Trusted Execution Technology (TXT)", {
        "enabled":  ("success", "Intel TXT Enabled",  "Measured launch active — BIOS → hypervisor chain is TPM-anchored."),
        "disabled": ("info",    "Intel TXT Disabled", "Not required for VCF 9.1 but recommended for attestation workloads."),
    }),
    # VT-d IOMMU — required for PCIe passthrough; also provides DMA isolation
    ("vtdsupport", "Intel VT-d (IOMMU)", {
        "enabled":  ("success", "VT-d Enabled",  "IOMMU active — PCIe passthrough and DMA isolation available."),
        "disabled": ("warning", "VT-d Disabled", "IOMMU not active — VMDirectPath / PCIe passthrough unavailable; DMA security isolation reduced."),
    }),
    ("vtd", "Intel VT-d (IOMMU)", {
        "enabled":  ("success", "VT-d Enabled",  ""),
        "disabled": ("warning", "VT-d Disabled", ""),
    }),
    # AMD SEV-SNP Confidential Computing
    ("cpuminsevasid", "AMD SEV-SNP (Confidential VMs)", {
        "1":        ("success", "SEV-SNP Enabled (ASID Reserved)", "Hardware ASID reservation active for AMD SEV / SEV-ES / SEV-SNP VMware Confidential VMs."),
        "0":        ("info",    "SEV-SNP Inactive (0 ASIDs)",      "No ASIDs reserved for AMD SEV."),
        "disabled": ("info",    "SEV-SNP Disabled",                "No ASIDs reserved for AMD SEV."),
    }),
    # BIOS Security Freeze Lock
    ("securityfreezelock", "BIOS Security Freeze Lock", {
        "enabled":  ("success", "Security Freeze Lock Enabled",  "BIOS locks security configuration at POST to prevent runtime malware modification."),
        "disabled": ("warning", "Security Freeze Lock Disabled", "BIOS security configuration is not locked at POST."),
    }),
    # Modern NVMe-oF Boot Support
    ("nvmeofendis", "NVMe-oF TCP Boot Support", {
        "enabled":  ("success", "NVMe-oF Boot Enabled",  "Native UEFI NVMe-over-Fabrics over TCP boot support active."),
        "disabled": ("info",    "NVMe-oF Boot Disabled", "Standard local / SAN boot mode."),
    }),
]


def _detect_side_channel_settings(attrs: dict) -> list:
    """Scan Redfish BIOS Attributes for side-channel mitigation settings.

    Returns a list of result dicts (same schema as _detect_cpu_power_mode output).
    Also extracts ProcXMicrocode / Proc0Microcode … Proc3Microcode as info entries.
    """
    results = []
    seen_keys: set = set()

    for raw_key, raw_val in attrs.items():
        key_lower = raw_key.lower()
        if key_lower in seen_keys:
            continue
        val_str = str(raw_val).lower().strip()
        if not val_str or val_str in ("n/a", "none", ""):
            continue

        # Structured rule matching
        matched = False
        for key_pat, feature_label, value_map in _SIDE_CHANNEL_RULES:
            if key_pat in key_lower:
                seen_keys.add(key_lower)
                matched = True
                mapped = value_map.get(val_str)
                if mapped:
                    badge, label, note = mapped
                else:
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

        # Microcode revision entries: Proc0Microcode … Proc3Microcode / ProcMicrocode
        if not matched and re.match(r"proc\d*microcode", key_lower):
            seen_keys.add(key_lower)
            cpu_idx = re.search(r"\d+", key_lower)
            cpu_label = f"CPU {cpu_idx.group()} Microcode Revision" if cpu_idx else "CPU Microcode Revision"
            hex_val = hex(int(str(raw_val), 0)) if str(raw_val).isdigit() else str(raw_val)
            results.append({
                "feature": cpu_label,
                "label":   hex_val,
                "badge":   "info",
                "note":    "Loaded microcode revision. Cross-reference with Intel/AMD microcode release notes.",
                "raw_key": raw_key,
                "raw_val": str(raw_val),
            })

    _sev = {"danger": 0, "warning": 1, "info": 2, "success": 3}
    results.sort(key=lambda r: _sev.get(r["badge"], 4))
    return results



