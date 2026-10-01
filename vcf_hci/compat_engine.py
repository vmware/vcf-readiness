"""
VCF Readiness Tool — VCF 9.1 compatibility rules engine (Layer B).

Facade module for backward compatibility. Implementation has been split into
domain-specific modules under the ``vcf_hci.compat`` package:
  - ``vcf_hci.compat.npar``: NIC Partitioning (NPAR) evaluation
  - ``vcf_hci.compat.bios_boot``: UEFI/Legacy boot mode and BIOS baseline / Spectre analysis
  - ``vcf_hci.compat.firmware``: BMC and drive firmware & HCL recommendation comparisons
  - ``vcf_hci.compat.chassis``: Modular chassis and OEM certification checks
  - ``vcf_hci.compat.pci``: PCI device compatibility and PCIe root-complex lane budgeting
  - ``vcf_hci.compat.cpu``: CPU generation categorization and NUMA/chiplet profiling
  - ``vcf_hci.compat.vsan``: vSAN ESA and OSA hardware readiness rules
  - ``vcf_hci.compat.memory``: Memory channel interleaving & topology evaluation
  - ``vcf_hci.compat.engine``: VCF9CompatibilityEngine orchestrator class
"""
from vcf_hci.compat.bios_boot import _cve_tier_from_date, evaluate_bios_version, evaluate_boot_mode
from vcf_hci.compat.chassis import _is_oem_chassis_certified
from vcf_hci.compat.cpu import evaluate_cpu, get_cpu_deep_profile
from vcf_hci.compat.dell_eems import (
    DellEemsInfo,
    build_dell_eems_guide_url,
    decode_dell_message_id,
)
from vcf_hci.compat.engine import VCF9CompatibilityEngine
from vcf_hci.compat.firmware import (
    KNOWN_DEFECTIVE_DRIVE_FIRMWARE,
    _compare_fw_versions,
    _parse_fw_version_tuple,
    check_defective_drive_firmware,
    evaluate_bmc_fw_version,
    evaluate_drive_fw,
    evaluate_driver_firmware_recommendation,
)
from vcf_hci.compat.memory import MemoryInterleavingEngine, evaluate_memory_topology
from vcf_hci.compat.npar import evaluate_npar
from vcf_hci.compat.pci import (
    _EVAL_PCI_CACHE_MAX,
    _EVAL_PCI_COMPAT_CACHE,
    evaluate_pci_compatibility,
    evaluate_pcie_lane_budget,
    evaluate_pcie_link_health,
)
from vcf_hci.compat.vsan import evaluate_vsan

__all__ = [
    "_EVAL_PCI_CACHE_MAX",
    "_EVAL_PCI_COMPAT_CACHE",
    "MemoryInterleavingEngine",
    "VCF9CompatibilityEngine",
    "_compare_fw_versions",
    "_cve_tier_from_date",
    "_is_oem_chassis_certified",
    "_parse_fw_version_tuple",
    "check_defective_drive_firmware",
    "decode_dell_message_id",
    "DellEemsInfo",
    "build_dell_eems_guide_url",
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
