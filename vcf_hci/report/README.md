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

- **`host_report.py`**: `generate_host_html_report()` creating standalone HTML reports per server.
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
- **`styles.py`**: Explicit host/fleet CSS composition; combined reports select source constants independently of host HTML and ordering.
- **`presentation.py`**: Shared Clarity-inspired tokens, semantic light/dark pairs, tab/dialog/resize behavior, evidence navigation and print support. Static Python constants keep distribution packaging and offline behavior consistent.
- **`readiness.py`**: Shared existing OEM/model qualification for host and fleet presentation; vendor approval is not a denial.
- **`overview.py`**: Presentation-only Server Readiness, storage and security groups from existing decision-row verdicts and shared chassis qualification. Both fleet formats use identical counts and host-index evidence links; overlapping dimensions are never summed.
- **`disclosures.py`**: Native supporting-evidence shells and expand/collapse controls. Rendered content is trusted HTML; labels and attributes are escaped separately.
- **`fleet/inventory/view.py`**: Density and keyed column visibility, validated layout-only preferences and reset. Host identity is required; exports retain all fields.
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
2. **Shared presentation ownership:**
   - Keep shared typography, spacing, controls, semantic colors and browser primitives in `presentation.py`; retain domain rendering in section builders.
   - Inventory headers and cells use matching stable `data-column-key` attributes, including optional FC columns. Keep layout state independent from filter/pager/export data.
   - Use escaped `data-*` action arguments and delegated listeners. Do not introduce inline handlers with quoted arguments.
3. **Dark Mode Support:**
   - Styles use CSS variables to support light and dark theme switching seamlessly.
4. **Component Deep-Linking:**
   - Every hardware component (CPU, drive, NIC, GPU) must embed a clickable Broadcom Compatibility Guide deep-link generated via `bcg_links.py`.
5. **Obfuscation UI State Awareness:**
   - Standard reports include dynamic DOM elements (`<span class="pii" data-real="..." data-mask="...">`) and an interactive **"Obfuscate report"** checkbox (`#maskPII`).
   - Downloaded public copies substitute a complete obfuscated workbook for the original workbook, remove the private key bundle/control and disable fallback to private export APIs. Sidecar copies use only the obfuscated workbook sibling.
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


## Retained component evidence

The host Health tab includes expandable service parts, sensors, PCIe CPU locality,
firmware provenance, power sizing and per-metric availability. Assembly records
merge with component inventory by serial or part plus location; sensor detail
merges by name and kind. CPU locality uses explicit affinity links and stays
unknown when none are exposed. PSU capacity after losing the largest supply is
an arithmetic sizing estimate; verify redundancy mode and feed wiring separately.
Memory bus utilization measures bandwidth, not occupied RAM.

CSV exports include `00_component_evidence.csv`, `00_telemetry_completeness.csv`
and `00_firmware_spread.csv` (with `00_OBFUSCATED_` prefixes for sanitized copies).
Completeness reports the full fleet and the population assessed for each current
or peak metric. Eligibility and license restrictions are never inferred from an
absent value. Firmware spread compares matching component names within one OEM
and server model; age is measured against a known capture date and carries no
health verdict. The drives CSV preserves zero counters and separates unavailable
spare percentages from their retained raw evidence.

Offline regeneration preserves capture dates separately from report-generation
time. An unknown capture date remains unknown. Mixed directories contain original
identities even when obfuscated copies are also present; use the separately
filtered obfuscated ZIP for external sharing after reviewing its contents.
FC inventory uses the shared `vcf_hci/fc_inventory.py` reconciliation helpers before reporting. Node-WWN aliases are merged only with matching adapter/port evidence; card counts use physical identity rather than model names. Unknown card counts remain explicit. Inventory rollups preserve the legacy `count` field as a port count and also expose `port_count` and `adapter_count`.
