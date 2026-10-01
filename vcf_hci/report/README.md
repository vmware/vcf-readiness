# Report Generation Subpackage (`vcf_hci.report`)

> Layer D HTML report generation engine, section renderers, Excel exporter, and Clarity CSS styling tokens.

---

## Architecture & Rendering Pipeline

Report generation is modular. `host_report.py` orchestrates evaluation results from `compat_engine.py` and section builders from `vcf_hci/report/sections/` to produce a standalone HTML report with **zero external CSS/JS dependencies**.

```
Host Summary JSON / Collector Payload
                  │
                  ▼
      VCF9CompatibilityEngine (compat_engine.py)
                  │
                  ▼
         host_report.py (Renderer Orchestrator)
    ┌─────────────┼─────────────┬─────────────┐
    │             │             │             │
overview.py    cpu.py      storage.py   health.py ... (Sections)
    │             │             │             │
    └─────────────┴─────────────┴─────────────┘
                  │
                  ▼
     Standalone HTML File (vsphere_vsan_report_<IP>.html)
```

---

## Files & Modules Index

- **`host_report.py`**: `generate_host_report()` creating standalone HTML reports per server.
- **`fleet_report.py`**: Backward-compatibility re-export facade for `generate_summary_html()`, `build_fleet_tiles_html()`, etc.
- **`inventory_tables.py`**: `build_host_decision_rows()`, `summarize_esa_disks()`, `summarize_nics()`, and `build_inventory_sheets()` producing dense SE decision records and granular component rows (`Decision`, `vCPU`, `vMemory`, `vStorage`, `vNetwork`, `vGPU`, `vFirmware`, `vHBA`).
- **`fleet/`**: Subpackage containing modular domain generators for multi-host fleet reporting:
  - **`summary.py`**: `generate_summary_html()` creating the executive overview HTML dashboard (`fleet_summary.html`).
  - **`tiles.py`**: `build_fleet_tiles_html()` rendering the 13-tile fleet health dashboard.
  - **`switch_matrix.py`**: `build_fleet_switch_matrix_html()` rendering ToR switch fabric and topology matrix.
  - **`inventory_panel.py`**: `build_detailed_inventory_html()` rendering the Detailed Inventory & SE Decision Matrix tab panel with live client-side facet filtering and drive/NIC subpanes.
  - **`combined.py`**: `_generate_combined_html()` rendering multi-host tabbed fleet reports (`fleet_combined.html`) with Detailed Inventory at Tab 1.
  - **`vendor.py`**: `normalize_oem_vendor()` OEM vendor string normalization helper.
  - **`escape.py`**: `_xe()` XML/HTML-escape helper.
- **`excel_export.py`**: `export_to_excel()`, `build_inventory_xlsx_bytes()`, and `build_obfuscated_inventory_zip()` exporting host inventory and compatibility assessments into comprehensive 10-tab Excel workbooks (`Summary`, `Decision`, `vCPU`, `vMemory`, `vStorage`, `vNetwork`, `vGPU`, `vFirmware`, `vHBA`, `Security`, and optional `Failed_Hosts`) and private obfuscation key ZIP bundles.
- **`csv_export.py`**: `export_all_csvs()`, `generate_fleet_summary_csv()`, `generate_drives_csv()`, `generate_nics_csv()`, `generate_gpus_csv()`, and `generate_failed_hosts_csv()` producing standardized tabular CSV exports.
- **`schema_registry.py`**: Extensible Schema Registry (Schema v2.0) defining 40+ typed hardware fields across 11 architectural domains (`ExportField`, `FLEET_SUMMARY_FIELDS`). Provides stable column definitions, text sanitization (`strip_html`), and deterministic verdict color mapping (`color_for_verdict`) used by both Excel and CSV export engines.
- **`sel_links.py`**: Multi-Vendor SEL / IML Guide Links & Event Resolvers (`VENDOR_SEL_GUIDES`, `get_sel_link`, `format_sel_badge`). Maps raw hardware alarms, event IDs, and hex codes directly to official vendor error documentation across Dell PowerEdge (EEMS 12G–17G), HPE ProLiant (IML Gen10–12), Cisco UCS (IMC Faults Guide), Lenovo ThinkSystem (XCC Events Guide), and Supermicro BMC (IPMI Spec).
- **`components.py`**: Reusable HTML component builders (badges, status cards, data tables, collapsible `<details>` sections, gauge bars).
- **`styles.py`**: CSS styling rules using VMware Clarity Design System design tokens and CSS variables (`--success:#16a34a`, `--warning:#ca8a04`, `--danger:#dc2626`, `--primary:#2563eb`).
- **`helpers.py`**: Utility functions for formatting storage sizes, temperatures, badge colors, and links.
- **`sections/`**: Individual report section modules:
  - **`overview.py`**: Executive summary cards (CPU tier, vSAN ESA readiness, TPM status, BIOS baseline).
  - **`cpu.py`**: CPU specifications, socket layout, core counts, and Broadcom HCL links.
  - **`memory.py`**: Memory DIMM layout, capacity, channel interleaving, and NUMA topology.
  - **`storage.py`**: Disk controllers, drive endurance/wear %, vSAN ESA drive compatibility, and SMART metrics.
  - **`network.py`**: Network interface adapters, port speed, ESA NIC qualification, and FC HBAs with WWPNs.
  - **`pcie_gpu.py`**: NVIDIA/AMD/Intel GPU accelerators and PCIe expansion topology.
  - **`bios_security.py`**: BIOS version evaluation, TPM 2.0 state, Intel VMD settings, and Secure Boot.
  - **`firmware_os.py`**: BMC firmware versions, ESXi build targets, and management IP information.
  - **`health.py`**: System Event Log (SEL/IML) alarms, thermal sensor accordion matrix, and PSU redundancy.

---

## Design System Constraints

1. **Inline CSS & Self-Contained HTML:**
   - Reports must open and render cleanly off-grid (no internet required).
   - No external `<link rel="stylesheet">` or `<script src="...">` tags permitted.
2. **Dark Mode Support:**
   - Styles use CSS variables to support light and dark theme switching seamlessly.
3. **Component Deep-Linking:**
   - Every hardware component (CPU, drive, NIC, GPU) must embed a clickable Broadcom Compatibility Guide deep-link generated via `bcg_links.py`.
4. **Obfuscation UI State Awareness:**
   - Standard reports include dynamic DOM elements (`<span class="pii" data-real="..." data-mask="...">`) and an interactive **"Obfuscate report"** checkbox (`#maskPII`).
   - Server-side pre-obfuscated reports (`obfuscated=True` / `OBFUSCATED_*.html`) emit plain text for anonymized values and render a static **🔒 Obfuscated Report** badge instead of interactive checkbox controls to prevent double-hashing.

---

## Light Background Contrast & Dark Mode Guidelines

1. **NEVER Use Hardcoded Light Backgrounds Without Theme Variables:**
   - Do NOT hardcode inline styles like `background:#fef3c7`, `background:#fffbe0`, or `background:#fee2e2` without theme CSS variables or alert CSS classes.
   - In dark mode (`data-theme="dark"` or OS dark preference), default body text color is light (`#f1f5f9` / `#e2e8f0`). Hardcoded light backgrounds result in unreadable white text on a yellow/light background.
2. **ALWAYS Pair Background Colors with Theme Text Color Variables:**
   - Use standard CSS alert classes (`class="alert alert-warning"`, `class="alert alert-danger"`, `class="alert alert-success"`, `class="alert alert-info"`) or callout CSS variables (`var(--callout-warn-bg)`, `var(--callout-warn-h)`, `var(--callout-warn-ul)`, `var(--tint-danger-bg)`, `var(--tint-danger-text)`).
   - Ensure explicit foreground text colors are paired with background colors across both light and dark mode tokens.
3. **Contrast Review Requirement:**
   - Every new alert box, callout, banner, or status element in generated HTML reports must be reviewed and tested in both light (`data-theme="light"`) and dark (`data-theme="dark"`) modes to guarantee WCAG AA contrast compliance.
