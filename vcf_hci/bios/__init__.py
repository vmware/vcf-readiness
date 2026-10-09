"""
VCF Readiness Tool — BIOS attribute detectors package.

Re-exports all detector functions for convenient single-import access.
"""
from .apply_recommended import apply_recommended, build_apply_plan
from .cisco_baseline import evaluate_cisco_bios_baseline, get_cisco_tuning_guide
from .dell_baseline import evaluate_dell_bios_baseline, get_dell_tuning_guide
from .generic_baseline import evaluate_generic_bios_baseline
from .hpe_baseline import evaluate_hpe_bios_baseline, get_hpe_tuning_guide
from .lenovo_baseline import evaluate_lenovo_bios_baseline, get_lenovo_tuning_guide
from .power_modes import _detect_cpu_power_mode
from .ras_modes import _detect_memory_ras_modes
from .recommend import build_recommend_report, report_from_collector
from .security import _detect_side_channel_settings

__all__ = [
    "apply_recommended",
    "build_apply_plan",
    "build_recommend_report",
    "evaluate_cisco_bios_baseline",
    "get_cisco_tuning_guide",
    "evaluate_dell_bios_baseline",
    "get_dell_tuning_guide",
    "evaluate_generic_bios_baseline",
    "evaluate_hpe_bios_baseline",
    "get_hpe_tuning_guide",
    "evaluate_lenovo_bios_baseline",
    "get_lenovo_tuning_guide",
    "report_from_collector",
    "_detect_cpu_power_mode",
    "_detect_memory_ras_modes",
    "_detect_side_channel_settings",
]
