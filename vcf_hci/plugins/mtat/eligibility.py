"""Versioned DRAM-only policies. CSV output follows only the selected policy."""

from __future__ import annotations

MTAT_32_REASONS = (
    ("pci_passthrough", "Passthrough"),
    ("vgpu", "vGPU"),
    ("sriov", "SR-IOV"),
    ("rdma", "RDMA"),
    ("pinned_memory", "Pinned memory"),
    ("latency_high", "Latency Sensitivity High"),
    ("fault_tolerance", "Fault Tolerance"),
    ("tiering_disabled", "Tiering disabled"),
)
CURRENT_REASONS = MTAT_32_REASONS + (
    ("nested_virtualization", "Nested virtualization"),
    ("confidential", "Confidential"),
    ("large_pages_policy", "Large pages"),
    ("monster_vm", "Monster VM"),
    ("page_1gb", "1GB pages"),
    ("vqat", "vQAT"),
)
IGNORED_FLAGS = {"full_reservation"}
POLICIES = {
    "mtat-3.2": MTAT_32_REASONS,
    "vsphere-current-2026-11-10": CURRENT_REASONS,
}


def reasons_for(flags: tuple[str, ...], policy: str) -> tuple[str, ...]:
    if policy not in POLICIES:
        raise ValueError("unknown eligibility policy")
    known = {key for key, _label in CURRENT_REASONS}
    unknown = [flag for flag in flags if flag not in known and flag not in IGNORED_FLAGS]
    if unknown:
        raise ValueError("unknown eligibility flag: %s" % ", ".join(unknown))
    allowed = {key for key, _label in POLICIES[policy]}
    return tuple(label for key, label in POLICIES[policy] if key in flags and key in allowed)


def dram_only_cell(flags: tuple[str, ...], policy: str, assessed: bool) -> str:
    labels = reasons_for(flags, policy)
    if not assessed:
        return "Unknown"
    if not labels:
        return "No"
    return "Yes (%s)" % ", ".join(labels)
