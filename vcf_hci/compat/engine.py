"""
VCF 9.1 Compatibility Engine aggregating domain-specific evaluations (Layer B).
"""

from .cpu import evaluate_cpu, get_cpu_deep_profile
from .firmware import evaluate_driver_firmware_recommendation
from .memory import evaluate_memory_topology
from .npar import evaluate_npar
from .pci import evaluate_pci_compatibility, evaluate_pcie_lane_budget, evaluate_pcie_link_health
from .vsan import evaluate_vsan


class VCF9CompatibilityEngine:
    """Unified VCF 9.1 Compatibility Engine aggregating domain rules."""

    evaluate_npar = staticmethod(evaluate_npar)
    evaluate_pci_compatibility = staticmethod(evaluate_pci_compatibility)
    evaluate_driver_firmware_recommendation = staticmethod(evaluate_driver_firmware_recommendation)
    evaluate_cpu = staticmethod(evaluate_cpu)
    get_cpu_deep_profile = staticmethod(get_cpu_deep_profile)
    evaluate_vsan = staticmethod(evaluate_vsan)
    evaluate_pcie_lane_budget = staticmethod(evaluate_pcie_lane_budget)
    evaluate_pcie_link_health = staticmethod(evaluate_pcie_link_health)
    evaluate_memory_topology = staticmethod(evaluate_memory_topology)
