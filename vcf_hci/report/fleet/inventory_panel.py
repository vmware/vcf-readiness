"""
Detailed Inventory HTML panel — dense SE decision matrix for combined fleet reports.

Transparent facade re-exporting inventory components from vcf_hci.report.fleet.inventory.
"""
from __future__ import annotations

from vcf_hci.report.fleet.inventory import (
    _DASH,
    _SUBSYSTEM_SUBTABS,
    _build_bios_table,
    _build_bmc_hardening_cell,
    _build_drives_table,
    _build_health_table,
    _build_inventory_reference_modal_html,
    _build_nics_table,
    _build_security_table,
    _cpu_dot,
    _default_pii,
    _dot_bool,
    _drive_fw_cell,
    _drive_model_link,
    _esa_profile_chip,
    _esa_tier_chip,
    _format_cpu_model,
    _nic_fw_cell,
    _nic_name_link,
    _storage_qualification_chip,
    _vmd_cell,
    build_detailed_inventory_html,
)

__all__ = [
    "build_detailed_inventory_html",
    "_build_bios_table",
    "_build_drives_table",
    "_build_health_table",
    "_build_nics_table",
    "_build_security_table",
    "_build_bmc_hardening_cell",
    "_build_inventory_reference_modal_html",
    "_cpu_dot",
    "_format_cpu_model",
    "_storage_qualification_chip",
    "_esa_profile_chip",
    "_esa_tier_chip",
    "_dot_bool",
    "_vmd_cell",
    "_drive_fw_cell",
    "_drive_model_link",
    "_nic_fw_cell",
    "_nic_name_link",
    "_default_pii",
    "_DASH",
    "_SUBSYSTEM_SUBTABS",
]
