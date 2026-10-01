"""
Detailed Inventory HTML panel submodules.
"""
from __future__ import annotations

from vcf_hci.report.fleet.inventory.builder import (
    build_detailed_inventory_html,
)
from vcf_hci.report.fleet.inventory.chips import (
    _DASH,
    _SUBSYSTEM_SUBTABS,
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
)
from vcf_hci.report.fleet.inventory.reference_modal import (
    _build_inventory_reference_modal_html,
)
from vcf_hci.report.fleet.inventory.subtables import (
    _build_bios_table,
    _build_bmc_hardening_cell,
    _build_drives_table,
    _build_health_table,
    _build_nics_table,
    _build_security_table,
)

__all__ = [
    "build_detailed_inventory_html",
    "_DASH",
    "_SUBSYSTEM_SUBTABS",
    "_default_pii",
    "_format_cpu_model",
    "_cpu_dot",
    "_storage_qualification_chip",
    "_esa_profile_chip",
    "_esa_tier_chip",
    "_dot_bool",
    "_vmd_cell",
    "_drive_fw_cell",
    "_drive_model_link",
    "_nic_fw_cell",
    "_nic_name_link",
    "_build_bios_table",
    "_build_bmc_hardening_cell",
    "_build_drives_table",
    "_build_health_table",
    "_build_nics_table",
    "_build_security_table",
    "_build_inventory_reference_modal_html",
]
