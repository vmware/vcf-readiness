"""
VCF Readiness Tool — Report generation package (Layer D).

Exports the HTML, CSV, and Excel report generators:
  generate_host_html_report()    — standalone per-host HTML file
  generate_summary_html()        — fleet-level summary HTML file
  build_fleet_tiles_html()       — inner tile HTML for the fleet summary
  export_all_csvs()              — standardized CSV exports (Schema v2.0)
  export_to_excel()              — multi-tab Excel workbook generator (.xlsx)
"""

from .csv_export import (
    export_all_csvs,
    generate_drives_csv,
    generate_failed_hosts_csv,
    generate_fleet_summary_csv,
    generate_gpus_csv,
    generate_nics_csv,
)
from .excel_export import (
    _build_excel_sheets,
    _strip_html,
    _vcf_color,
    _write_xlsx,
    export_to_excel,
)
from .fleet_report import (
    _generate_combined_html,
    build_fleet_tiles_html,
    generate_combined_html,
    generate_combined_tabbed_html,
    generate_summary_html,
    normalize_oem_vendor,
)
from .host_report import generate_host_html_report
from .readme import (
    generate_scan_readme,
    write_scan_readme,
)
from .schema_registry import FLEET_SUMMARY_FIELDS, SCHEMA_VERSION

__all__ = [
    "FLEET_SUMMARY_FIELDS",
    "SCHEMA_VERSION",
    "_build_excel_sheets",
    "_generate_combined_html",
    "_strip_html",
    "_vcf_color",
    "_write_xlsx",
    "build_fleet_tiles_html",
    "export_all_csvs",
    "export_to_excel",
    "generate_combined_html",
    "generate_combined_tabbed_html",
    "generate_drives_csv",
    "generate_failed_hosts_csv",
    "generate_fleet_summary_csv",
    "generate_gpus_csv",
    "generate_host_html_report",
    "generate_nics_csv",
    "generate_scan_readme",
    "generate_summary_html",
    "normalize_oem_vendor",
    "write_scan_readme",
]
