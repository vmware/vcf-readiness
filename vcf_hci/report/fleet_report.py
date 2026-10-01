"""
VCF Readiness Tool — fleet summary HTML report generator (Layer D).
Backward-compatibility re-export facade.
"""
from vcf_hci.report.fleet.combined import (
    _generate_combined_html,
    generate_combined_html,
    generate_combined_tabbed_html,
)
from vcf_hci.report.fleet.summary import generate_summary_html
from vcf_hci.report.fleet.switch_matrix import build_fleet_switch_matrix_html
from vcf_hci.report.fleet.tiles import build_fleet_tiles_html
from vcf_hci.report.fleet.vendor import normalize_oem_vendor

__all__ = [
    "_generate_combined_html",
    "build_fleet_switch_matrix_html",
    "build_fleet_tiles_html",
    "generate_combined_html",
    "generate_combined_tabbed_html",
    "generate_summary_html",
    "normalize_oem_vendor",
]
