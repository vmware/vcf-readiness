"""
VCF Readiness Tool — VCF 9.1 compatibility rules engine package (Layer B).
"""
from .bios_boot import _cve_tier_from_date, evaluate_bios_version, evaluate_boot_mode
from .chassis import _is_oem_chassis_certified
from .cpu import evaluate_cpu, get_cpu_deep_profile
from .dell_eems import (
    DellEemsInfo,
    build_dell_eems_guide_url,
    decode_dell_message_id,
)
from .engine import VCF9CompatibilityEngine
from .firmware import (
    KNOWN_DEFECTIVE_DRIVE_FIRMWARE,
    _compare_fw_versions,
    _parse_fw_version_tuple,
    check_defective_drive_firmware,
    evaluate_bmc_fw_version,
    evaluate_drive_fw,
    evaluate_driver_firmware_recommendation,
)
from .memory import MemoryInterleavingEngine, evaluate_memory_topology
from .npar import evaluate_npar
from .pci import (
    _EVAL_PCI_CACHE_MAX,
    _EVAL_PCI_COMPAT_CACHE,
    evaluate_pci_compatibility,
    evaluate_pcie_lane_budget,
    evaluate_pcie_link_health,
)
from .vsan import evaluate_vsan

__all__ = [
    "_EVAL_PCI_CACHE_MAX",
    "_EVAL_PCI_COMPAT_CACHE",
    "DellEemsInfo",
    "MemoryInterleavingEngine",
    "VCF9CompatibilityEngine",
    "_compare_fw_versions",
    "_cve_tier_from_date",
    "_is_oem_chassis_certified",
    "_parse_fw_version_tuple",
    "build_dell_eems_guide_url",
    "check_defective_drive_firmware",
    "decode_dell_message_id",
    "KNOWN_DEFECTIVE_DRIVE_FIRMWARE",
    "evaluate_bios_version",
    "evaluate_bmc_fw_version",
    "evaluate_boot_mode",
    "evaluate_cpu",
    "evaluate_drive_fw",
    "evaluate_driver_firmware_recommendation",
    "evaluate_memory_topology",
    "evaluate_npar",
    "evaluate_pci_compatibility",
    "evaluate_pcie_lane_budget",
    "evaluate_pcie_link_health",
    "evaluate_vsan",
    "get_cpu_deep_profile",
]
