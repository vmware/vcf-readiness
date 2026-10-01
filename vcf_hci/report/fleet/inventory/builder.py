"""
Detailed Inventory HTML panel builder for combined fleet reports.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
from typing import Any, List, Optional

from vcf_hci.hcl import load_vsan_hcl_json
from vcf_hci.obfuscation import (
    _obf_ip,
    _obf_label,
    _obf_mac,
    _pii_span,
)
from vcf_hci.report.fleet.escape import _xe
from vcf_hci.report.fleet.inventory.chips import (
    _DASH,
    _cpu_dot,
    _dot_bool,
    _esa_profile_chip,
    _storage_qualification_chip,
    _vmd_cell,
)
from vcf_hci.report.fleet.inventory.reference_modal import (
    _build_inventory_reference_modal_html,
)
from vcf_hci.report.fleet.inventory.subtables import (
    _build_bios_table,
    _build_drives_table,
    _build_health_table,
    _build_nics_table,
    _build_security_table,
)
from vcf_hci.report.inventory_tables import (
    build_compact_fleet_inventory,
    clean_model_code,
)

logger = logging.getLogger("vcf_assess")


def build_detailed_inventory_html(
    rows: List[dict],
    all_results: Optional[List[dict]] = None,
    obfuscated: bool = False,
    json_hcl: Optional[dict] = None,
    host_tab_offset: int = 3,
    page_salt: Optional[str] = None,
    embed_mode: str = "inline",
    sibling_xlsx: Optional[str] = None,
) -> str:
    """Render the Detailed Inventory tab panel (matrix + Drives/NICs/BIOS/Health/Security panes)."""
    all_results = all_results or []
    salt = page_salt or os.urandom(16).hex()

    if obfuscated and all_results:
        from vcf_hci.obfuscation import obfuscate_host_data
        _needs_obf = any(
            not r.get("obfuscated") and not re.match(r"^Host-\d+$", str((r.get("system") or {}).get("hostname", "")))
            for r in all_results
        )
        if _needs_obf:
            all_results = [
                obfuscate_host_data(r, f"Host-{i+1}", salt) if (not r.get("obfuscated") and not re.match(r"^Host-\d+$", str((r.get("system") or {}).get("hostname", "")))) else r
                for i, r in enumerate(all_results)
            ]
            from vcf_hci.report.inventory_tables import build_host_decision_rows
            rows = build_host_decision_rows(all_results)

    if obfuscated and rows:
        for idx, r in enumerate(rows):
            h = str(r.get("hostname") or "")
            if not re.match(r"^Host-\d+$", h):
                r["hostname"] = f"Host-{int(r.get('host_idx', idx)) + 1}"
            ip = str(r.get("ip") or "")
            if not ip.startswith("192.0.2."):
                r["ip"] = f"192.0.2.{(int(r.get('host_idx', idx)) % 250) + 1}"

    def _pii(val: Any, kind: str = "host") -> str:
        s = str(val or "")
        if not s:
            return ""
        if obfuscated:
            if kind == "mac" and not s.lower().startswith("02:"):
                return _xe(_obf_mac(salt, s))
            if kind == "ip" and not s.startswith("192.0.2."):
                return _xe(_obf_ip(salt, s))
            if kind == "host" and not re.match(r"^Host-\d+$", s):
                return _xe(_obf_label(salt, "HOST", s))
            return _xe(s)
        return _pii_span(salt, s, kind)

    if json_hcl is None:
        try:
            json_hcl = load_vsan_hcl_json()
        except Exception:
            json_hcl = {}

    excel_b64 = ""
    obf_zip_b64 = ""
    # Sidecar skips Excel/zip Base64 embed; link sibling .xlsx instead. inline may still embed Excel.
    if embed_mode != "sidecar" and all_results:
        try:
            from vcf_hci.report.excel_export import (
                build_inventory_xlsx_bytes,
                build_obfuscated_inventory_zip,
            )
            if not obfuscated:
                xlsx_bytes = build_inventory_xlsx_bytes(all_results, obfuscated=False)
                excel_b64 = base64.b64encode(xlsx_bytes).decode("ascii")
                zip_bytes = build_obfuscated_inventory_zip(all_results)
                obf_zip_b64 = base64.b64encode(zip_bytes).decode("ascii")
            else:
                xlsx_bytes = build_inventory_xlsx_bytes(all_results, obfuscated=True)
                excel_b64 = base64.b64encode(xlsx_bytes).decode("ascii")
                obf_zip_b64 = excel_b64
        except Exception as exc:
            logger.debug("Failed building embedded Excel base64: %s", exc)

    sibling_xlsx_val = sibling_xlsx or ""
    sibling_obf_xlsx_val = ""
    if sibling_xlsx_val:
        if sibling_xlsx_val.startswith("00_OBFUSCATED_"):
            sibling_obf_xlsx_val = sibling_xlsx_val
        else:
            sibling_obf_xlsx_val = f"00_OBFUSCATED_{sibling_xlsx_val}"

    inv_dl_filename = "inventory_obfuscated.xlsx" if obfuscated else "inventory.xlsx"
    if obfuscated:
        export_buttons = (
            '<button type="button" class="inv-btn" onclick="dlInvExcel(false)">Export Excel (Obfuscated)</button>'
        )
    else:
        export_buttons = (
            '<button type="button" class="inv-btn" onclick="dlInvExcel(false)">Export Excel</button>\n'
            '    <button type="button" class="inv-btn" onclick="dlInvExcel(true)">Export Obfuscated + Key</button>'
        )

    # Build compact FLEET_INV JSON island
    compact_inv = build_compact_fleet_inventory(all_results, rows=rows, obfuscated=obfuscated, page_salt=salt)
    compact_inv_json = json.dumps(compact_inv, separators=(',', ':')).replace("</", "<\\/")
    fleet_inv_island = f'<script id="fleet-inv-data" type="application/json">\n{compact_inv_json}\n</script>'

    oems = sorted({r.get("facet_oem") or "Unknown" for r in rows})
    oem_opts = "".join(f"<option value='{_xe(o)}'>{_xe(o)}</option>" for o in oems)

    # Detect whether any host in the fleet has FC HBAs
    has_fc_hbas = any(bool(r.get("fc_hba", {}).get("count")) for r in rows) or any(
        bool(d.get("fc_hbas")) for d in all_results
    )

    # For large fleets (> 500 hosts), cap rendered static DOM rows at 500 to keep HTML under 8 MB budget
    # The full fleet dataset remains intact in the JSON island and for Excel/Obfuscated exports
    render_limit = 500
    render_rows = rows[:render_limit] if len(rows) > render_limit else rows
    render_results = all_results[:render_limit] if len(all_results) > render_limit else all_results

    matrix_rows = []
    for r in render_rows:
        idx = int(r.get("host_idx") or 0)
        host_tab = idx + host_tab_offset
        hostname = r.get("hostname") or r.get("ip") or f"Host {idx+1}"
        ip = r.get("ip") or ""
        if obfuscated:
            if not re.match(r"^Host-\d+$", str(hostname)):
                hostname = f"Host-{idx+1}"
            if not str(ip).startswith("192.0.2."):
                ip = f"192.0.2.{(idx % 250) + 1}"
        vendor_raw = str(r.get("vendor") or "")
        model_raw = str(r.get("model") or "")
        clean_m = r.get("clean_model") or clean_model_code(vendor_raw, model_raw) or model_raw or _DASH
        full_model = f"{vendor_raw} {model_raw}".strip()

        nic = r.get("nic") or {}
        esa = r.get("esa") or {}
        fc = r.get("fc_hba") or {}
        nic_html = nic.get("html_display") or _xe(nic.get("display") or _DASH)
        nic_tip = _xe(nic.get("tooltip") or "")
        ram = r.get("ram_gb") or _DASH
        dimms = r.get("dimm_count") or 0
        interleaving = r.get("interleaving_str") or ""
        dimm_info = f"{dimms} DIMM" + (f" \u00b7 {interleaving}" if interleaving else "")
        gpu = r.get("gpu_count") or 0
        gpu_td = str(gpu) if gpu else _DASH

        fc_cell = ""
        if has_fc_hbas:
            fc_cell = (
                f"<td style='text-align:center' title='{_xe(fc.get('models') or '')}'>"
                f"{_xe(fc.get('display') or _DASH)}</td>"
            )

        ctrl_esa = "1" if r.get("ctrl_esa") else "0"
        ctrl_osa = "1" if r.get("ctrl_osa") else "0"
        ctrl_unsup = "1" if r.get("ctrl_unsup") else "0"

        esa_profile_data = r.get("esa_profile") or {}
        esa_tier_code = esa_profile_data.get("tier_code") or r.get("esa_tier") or ""

        sec_badge = r.get("sec_badge") or "<span class='inv-muted'>—</span>"
        sec_tip = r.get("sec_tooltip") or ""
        sec_posture = r.get("sec_posture") or "not_assessed"
        sec_jump = (
            f"<a href='#' class='btn-link tab-jump' data-tab='{host_tab}' data-subtab='tab-security' style='color:inherit;text-decoration:none;display:inline-block'>{sec_badge}</a>"
            if r.get("sec_badge") else sec_badge
        )

        os_label = str(r.get("os_label") or "").strip()
        eol = str(r.get("os_eol_label") or r.get("esxi_eol") or "").strip()
        if os_label:
            if "EOL" in eol:
                os_td = (
                    f"<span class='inv-bad' title='{_xe(eol)}'>{_xe(os_label)}</span>"
                    f"<div style='font-size:9px;color:var(--text-muted,#64748b)'>{_xe(eol)}</div>"
                )
            else:
                os_td = f"<span>{_xe(os_label)}</span>"
        else:
            os_td = "<span class='inv-muted' title='Host OS not reported via BMC agent'>—</span>"

        matrix_rows.append(
            f"<tr class='inv-row' data-oem='{_xe(r.get('facet_oem') or '')}' "
            f"data-cpu='{_xe(r.get('facet_cpu') or '')}' "
            f"data-esa='{_xe(r.get('facet_esa') or '')}' "
            f"data-esa-tier='{_xe(esa_tier_code)}' "
            f"data-ctrl-esa='{ctrl_esa}' data-ctrl-osa='{ctrl_osa}' data-ctrl-unsup='{ctrl_unsup}' "
            f"data-nic='{_xe(r.get('facet_nic') or '')}' "
            f"data-link='{_xe(r.get('facet_link') or '')}' "
            f"data-sec-posture='{_xe(sec_posture)}' "
            f"data-host-idx='{idx}'>"
            f"<td class='inv-sticky'><a href='#' class='btn-link tab-jump' data-tab='{host_tab}' data-subtab='tab-overview' style='color:inherit;text-decoration:none;display:block'>"
            f"<strong>{_pii(hostname, 'host')}</strong>"
            f"<br><small style='color:var(--text-muted,#64748b)'>{_pii(ip, 'ip')}</small></a></td>"
            f"<td title='{_xe(full_model)}'><strong>{_xe(clean_m)}</strong></td>"
            f"<td><a href='#' class='btn-link tab-jump' data-tab='{host_tab}' data-subtab='tab-cpu' style='color:inherit;text-decoration:none;display:inline-block'>{_cpu_dot(r.get('cpu_tier') or '', r.get('cpu_model') or '', r.get('cpu_verdict') or '')}</a></td>"
            f"<td>{os_td}</td>"
            f"<td>{_xe(esa.get('display') or _DASH)}<br>{_storage_qualification_chip(r)}</td>"
            f"<td>{_esa_profile_chip(esa_profile_data)}</td>"
            f"<td title='{nic_tip}'>{nic_html}</td>"
            f"{fc_cell}"
            f"<td>{_xe(ram)} GB"
            f"<div style='font-size:9px;color:var(--text-muted,#64748b)'>{dimm_info}</div></td>"
            f"<td style='text-align:center'>{_dot_bool(r.get('tpm_ok'), 'TPM OK', 'TPM issue')}</td>"
            f"<td style='text-align:center' title='{_xe(sec_tip)}'>{sec_jump}</td>"
            f"<td style='text-align:center'>{_vmd_cell(r.get('vmd_on'))}</td>"
            f"<td style='text-align:center'>{_xe(gpu_td)}</td>"
            f"</tr>"
        )
    colspan = 13 if has_fc_hbas else 12
    tbody = "\n".join(matrix_rows) if matrix_rows else (
        f"<tr><td colspan='{colspan}' style='color:#94a3b8'>No hosts</td></tr>"
    )
    n_hosts = len(rows)
    inv_shown_count = len(render_rows)
    inv_banner = (
        f"<div style='margin:0.4rem 0;font-size:11px;padding:6px 10px;"
        f"background:rgba(245,158,11,0.15);border:1px solid #f59e0b;border-radius:4px;color:#f59e0b'>"
        f"⚠️ <strong>Large Fleet Mode ({n_hosts:,} hosts):</strong> Detailed Inventory tables display first {inv_shown_count} hosts. "
        f"All {n_hosts:,} hosts are available in Excel export and in the interactive Web UI.</div>"
    ) if len(rows) > render_limit else ""
    drives_html = _build_drives_table(render_results, json_hcl=json_hcl, host_tab_offset=host_tab_offset, _pii=_pii, obfuscated=obfuscated)
    nics_html = _build_nics_table(render_results, json_hcl=json_hcl, host_tab_offset=host_tab_offset, _pii=_pii, obfuscated=obfuscated)
    bios_html = _build_bios_table(render_results, host_tab_offset=host_tab_offset, _pii=_pii, obfuscated=obfuscated)
    health_html = _build_health_table(render_results, host_tab_offset=host_tab_offset, _pii=_pii, obfuscated=obfuscated)
    security_html = _build_security_table(render_results, host_tab_offset=host_tab_offset, _pii=_pii, obfuscated=obfuscated)
    ref_modal_html = _build_inventory_reference_modal_html()

    fc_th = '<th title="Fibre Channel Host Bus Adapters detected in system">FC HBA</th>' if has_fc_hbas else ""

    return f"""
<style>
.inv-wrap{{padding:0.6rem 0.85rem 1rem;font-family:ui-sans-serif,system-ui,Segoe UI,sans-serif;color:var(--text,#e2e8f0)}}
.inv-toolbar{{display:flex;flex-wrap:wrap;gap:0.45rem 0.75rem;align-items:center;margin-bottom:0.45rem}}
.inv-toolbar strong{{font-size:0.95rem;margin-right:0.4rem}}
.inv-filters{{display:flex;flex-wrap:wrap;gap:0.35rem 0.65rem;align-items:center;font-size:11px}}
.inv-filters select,.inv-filters input{{font-size:11px;padding:3px 6px;border:1px solid var(--border,#334155);border-radius:4px;background:var(--card,#0f172a);color:var(--text,#e2e8f0)}}
.inv-btn{{font-size:11px;padding:3px 8px;border:1px solid var(--border,#334155);border-radius:4px;background:var(--card,#1e293b);color:var(--text,#e2e8f0);cursor:pointer;text-decoration:none;transition:background .15s;display:inline-flex;align-items:center}}
.inv-btn:hover{{background:var(--border,#334155)}}
.inv-seg{{display:inline-flex;gap:0;margin:0.35rem 0 0.5rem}}
.inv-seg button{{font-size:11px;padding:3px 10px;border:1px solid var(--border,#334155);background:var(--bg,#0f172a);color:var(--text-muted,#94a3b8);cursor:pointer;transition:all .12s}}
.inv-seg button.active{{background:var(--card,#1e293b);color:var(--text,#f1f5f9);border-color:var(--primary,#3b82f6);font-weight:600}}
.inv-seg button:first-child{{border-radius:4px 0 0 4px}}
.inv-seg button:last-child{{border-radius:0 4px 4px 0}}
.inv-pane{{display:none}}.inv-pane.active{{display:block}}
.inv-scroll{{overflow:auto;max-height:calc(100vh - 120px);border:1px solid var(--border,#1e293b);border-radius:4px}}
.inv-table{{border-collapse:collapse;font-size:11px;white-space:nowrap;width:max-content;min-width:100%;line-height:1.25}}
.inv-table th,.inv-table td{{padding:4px 8px;border:1px solid var(--border,#334155);vertical-align:top;position:relative}}
.inv-table thead th{{position:sticky;top:0;background:var(--th-bg,#1e293b);color:var(--text,#e2e8f0);z-index:2;font-weight:600;text-align:left}}
.inv-table td.inv-sticky,.inv-table th.inv-sticky{{position:sticky;left:0;background:var(--bg,#0f172a);z-index:1}}
.inv-table thead th.inv-sticky{{z-index:3;background:var(--th-bg,#1e293b)}}
.inv-table tbody tr:nth-child(even){{background:var(--bg-alt,rgba(0,0,0,0.15))}}
.inv-table tbody tr:nth-child(odd){{background:var(--card,transparent)}}
.inv-good{{color:#15803d;font-weight:600}}
.inv-bad{{color:#dc2626;font-weight:600}}
.inv-warn{{color:#b45309;font-weight:600}}
.inv-muted{{color:var(--text-muted,#64748b)}}
.inv-code{{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:10.5px}}
[data-theme='dark'] .inv-good{{color:#4ade80}}
[data-theme='dark'] .inv-bad{{color:#f87171}}
[data-theme='dark'] .inv-warn{{color:#fbbf24}}
[data-theme='light'] .inv-wrap{{color:#1e293b}}
[data-theme='light'] .inv-good{{color:#15803d}}
[data-theme='light'] .inv-bad{{color:#dc2626}}
[data-theme='light'] .inv-warn{{color:#b45309}}
[data-theme='light'] .inv-table thead th{{background:#f1f5f9;color:#1e293b;border-color:#cbd5e1}}
[data-theme='light'] .inv-table th,[data-theme='light'] .inv-table td{{border-color:#cbd5e1}}
[data-theme='light'] .inv-table td.inv-sticky{{background:#ffffff}}
[data-theme='light'] .inv-table thead th.inv-sticky{{background:#f1f5f9}}
[data-theme='light'] .inv-table tbody tr:nth-child(even){{background:#f8fafc}}
[data-theme='light'] .inv-table tbody tr:nth-child(odd){{background:#ffffff}}
[data-theme='light'] .inv-filters select,[data-theme='light'] .inv-filters input{{background:#ffffff;color:#1e293b;border-color:#cbd5e1}}
[data-theme='light'] .inv-btn{{background:#ffffff;color:#1e293b;border-color:#cbd5e1}}
[data-theme='light'] .inv-btn:hover{{background:#f1f5f9}}
[data-theme='light'] .inv-seg button{{background:#f8fafc;color:#64748b;border-color:#cbd5e1}}
[data-theme='light'] .inv-seg button.active{{background:#ffffff;color:#0f172a;border-color:#2563eb}}
.inv-count{{font-size:11px;color:var(--text-muted,#94a3b8);margin-left:auto}}
.inv-row-perc7xx{{background:rgba(220,38,38,0.22) !important;color:#fca5a5}}
.inv-row-perc7xx:hover{{background:rgba(220,38,38,0.35) !important}}
[data-theme='light'] .inv-row-perc7xx{{background:#fee2e2 !important;color:#991b1b}}
[data-theme='light'] .inv-row-perc7xx:hover{{background:#fecaca !important}}
.col-resizer{{position:absolute;top:0;right:0;width:5px;cursor:col-resize;user-select:none;height:100%;z-index:10}}
.col-resizer:hover,.col-resizer.resizing{{background:var(--primary,#3b82f6);opacity:0.8}}

/* Column Reference Modal */
.inv-modal-backdrop{{display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.65);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);z-index:9999;align-items:center;justify-content:center;padding:1.5rem;box-sizing:border-box}}
.inv-modal-backdrop.open{{display:flex}}
.inv-modal-card{{background:var(--card,#0f172a);color:var(--text,#e2e8f0);border:1px solid var(--border,#334155);border-radius:8px;box-shadow:0 20px 25px -5px rgba(0,0,0,0.5),0 10px 10px -5px rgba(0,0,0,0.2);width:100%;max-width:960px;max-height:85vh;display:flex;flex-direction:column;overflow:hidden;animation:invModalFadeIn 0.15s ease-out}}
@keyframes invModalFadeIn{{from{{opacity:0;transform:scale(0.97)}}to{{opacity:1;transform:scale(1)}}}}
[data-theme='light'] .inv-modal-card{{background:#ffffff;color:#0f172a;border-color:#cbd5e1;box-shadow:0 20px 25px -5px rgba(0,0,0,0.1),0 10px 10px -5px rgba(0,0,0,0.04)}}
.inv-modal-header{{display:flex;align-items:center;justify-content:space-between;padding:0.85rem 1.25rem;border-bottom:1px solid var(--border,#334155);background:var(--bg-alt,rgba(0,0,0,0.2))}}
[data-theme='light'] .inv-modal-header{{border-color:#e2e8f0;background:#f8fafc}}
.inv-modal-header h3{{margin:0;font-size:1.05rem;font-weight:700;display:flex;align-items:center;gap:0.5rem}}
.inv-modal-close{{background:none;border:none;font-size:1.25rem;line-height:1;cursor:pointer;color:var(--text-muted,#94a3b8);padding:0.25rem 0.5rem;border-radius:4px;transition:color .12s,background .12s}}
.inv-modal-close:hover{{color:var(--text,#f1f5f9);background:rgba(255,255,255,0.1)}}
[data-theme='light'] .inv-modal-close:hover{{color:#0f172a;background:#e2e8f0}}
.inv-modal-body{{padding:1.25rem;overflow-y:auto;font-size:0.85rem;line-height:1.5}}
.inv-modal-body h4{{margin:1.25rem 0 0.5rem;font-size:0.95rem;color:var(--primary,#3b82f6);border-bottom:1px solid var(--border,#334155);padding-bottom:0.3rem}}
[data-theme='light'] .inv-modal-body h4{{color:#2563eb;border-color:#e2e8f0}}
.inv-modal-body h4:first-child{{margin-top:0}}
.inv-ref-table{{width:100%;border-collapse:collapse;margin:0.5rem 0 1rem;font-size:0.8rem}}
.inv-ref-table th,.inv-ref-table td{{padding:6px 10px;border:1px solid var(--border,#334155);text-align:left;vertical-align:top}}
[data-theme='light'] .inv-ref-table th,[data-theme='light'] .inv-ref-table td{{border-color:#cbd5e1}}
.inv-ref-table thead th{{background:var(--bg-alt,rgba(0,0,0,0.25));font-weight:600}}
[data-theme='light'] .inv-ref-table thead th{{background:#f1f5f9;color:#0f172a}}
.inv-modal-footer{{padding:0.75rem 1.25rem;border-top:1px solid var(--border,#334155);display:flex;justify-content:flex-end;background:var(--bg-alt,rgba(0,0,0,0.1))}}
[data-theme='light'] .inv-modal-footer{{border-color:#e2e8f0;background:#f8fafc}}
</style>
<div class="inv-wrap" id="invRoot">
  <div class="inv-toolbar">
    <strong>Detailed Inventory</strong>
    {export_buttons}
    <button type="button" class="inv-btn" onclick="openInvRefModal()" title="Open Detailed Inventory Column Reference Guide">📖 Column Reference</button>
    <div class="inv-page-controls" style="display:inline-flex;align-items:center;gap:6px;font-size:11px;margin-left:auto">
      <label style="display:inline-flex;align-items:center;gap:4px">Page size:
        <select id="invPageSize" style="font-size:11px;padding:2px 6px;border:1px solid var(--border,#334155);border-radius:4px;background:var(--card,#0f172a);color:var(--text,#e2e8f0)">
          <option value="25">25</option>
          <option value="50" selected>50</option>
          <option value="100">100</option>
          <option value="all">All</option>
        </select>
      </label>
      <button type="button" class="inv-btn" id="invPrevBtn">‹ Prev</button>
      <span id="invPageInfo" style="min-width:65px;text-align:center">Page 1 of 1</span>
      <button type="button" class="inv-btn" id="invNextBtn">Next ›</button>
      <span id="invPageWarn" style="display:none;color:#f59e0b;font-weight:600">⚠️ Capped at 500 rows</span>
      <span class="inv-count"><span id="invShown">{inv_shown_count}</span> shown / {n_hosts}</span>
    </div>
  </div>
  {inv_banner}
  <div class="inv-filters">
    <label>OEM <select id="invOem"><option value="">All</option>{oem_opts}</select></label>
    <label>CPU <select id="invCpu">
      <option value="">All</option>
      <option value="green">Supported</option>
      <option value="yellow">Deprecated</option>
      <option value="red">Unsupported</option>
    </select></label>
    <label>ESA Profile <select id="invEsa">
      <option value="">All</option>
      <option value="ESA-L">ESA-L (Large)</option>
      <option value="ESA-M">ESA-M (Medium)</option>
      <option value="ESA-S">ESA-S (Small)</option>
      <option value="ESA-XS">ESA-XS (Edge)</option>
      <option value="Needs 25G">Needs 25G NIC</option>
      <option value="Ready">ESA Ready (Any)</option>
      <option value="Blocked">Blocked</option>
      <option value="Insufficient">Insufficient</option>
    </select></label>
    <label>Controller <select id="invCtrl">
      <option value="">All Controllers</option>
      <option value="esa">ESA Direct (NVMe)</option>
      <option value="osa">OSA Compatible (HBA)</option>
      <option value="unsupported">Unsupported / RAID</option>
    </select></label>
    <label>NIC <select id="invNic">
      <option value="">All</option>
      <option value="25">&ge;25 GbE</option>
      <option value="lt25">&lt;25 GbE</option>
    </select></label>
    <label>Link <select id="invLink">
      <option value="">All Links</option>
      <option value="up">All Links Up</option>
      <option value="down">Has Down Links</option>
    </select></label>
    <label>Security <select id="invSec">
      <option value="">All Security</option>
      <option value="action_req">Action Required</option>
      <option value="baseline_met">Baseline Met</option>
      <option value="partial">Partially Assessed</option>
    </select></label>
    <input type="search" id="invFilter" placeholder="Filter…" style="min-width:140px"/>
  </div>
  <div class="inv-seg">
    <button type="button" class="active" data-inv-view="hosts" onclick="showInvView('hosts')">Hosts</button>
    <button type="button" data-inv-view="drives" onclick="showInvView('drives')">Drives</button>
    <button type="button" data-inv-view="nics" onclick="showInvView('nics')">NICs</button>
    <button type="button" data-inv-view="bios" onclick="showInvView('bios')">BIOS Settings</button>
    <button type="button" data-inv-view="health" onclick="showInvView('health')">Health Alarms</button>
    <button type="button" data-inv-view="security" onclick="showInvView('security')">Security</button>
  </div>
  <div id="inv-pane-hosts" class="inv-pane active">
    <div class="inv-scroll">
      <table class="inv-table" id="invHostTable">
        <thead><tr>
          <th class="inv-sticky" title="Host system hostname and BMC IP address (Click to view full host assessment report)">Host</th>
          <th title="Server hardware manufacturer and chassis model">Model</th>
          <th title="Processor model and VCF 9.1 CPU architecture compatibility tier">CPU</th>
          <th title="Installed operating system or hypervisor release and lifecycle support status">Host OS</th>
          <th title="Direct-attached NVMe storage capacity and hardware pass-through qualification">ESA disks</th>
          <th title="vSAN ESA ReadyNode profile qualification (ESA-L Large, ESA-M Medium, ESA-S Small) based on NVMe storage, RAM, CPU cores, and 25 GbE+ networking">ESA Tier</th>
          <th title="Network interface adapters and 25 GbE+ baseline compliance (Down ports highlighted in Red)">NICs</th>
          {fc_th}
          <th title="Total system RAM capacity, DIMM slot population count, and memory channel interleaving">RAM</th>
          <th title="Trusted Platform Module 2.0 presence and activation status">TPM</th>
          <th title="Out-of-band management security posture baseline compliance (Click host for detailed audit)">BMC Sec</th>
          <th title="Intel Volume Management Device status (must be Disabled for native NVMe passthrough)">VMD</th>
          <th title="PCIe GPU accelerators detected in system">GPU</th>
        </tr></thead>
        <tbody>
{tbody}
        </tbody>
      </table>
    </div>
  </div>
  <div id="inv-pane-drives" class="inv-pane">{drives_html}</div>
  <div id="inv-pane-nics" class="inv-pane">{nics_html}</div>
  <div id="inv-pane-bios" class="inv-pane">{bios_html}</div>
  <div id="inv-pane-health" class="inv-pane">{health_html}</div>
  <div id="inv-pane-security" class="inv-pane">{security_html}</div>
  {ref_modal_html}
  {fleet_inv_island}
</div>
<script>
(function(){{
  function openInvRefModal(){{
    var m = document.getElementById('invRefModal');
    if (m) {{
      m.classList.add('open');
      document.body.style.overflow = 'hidden';
    }}
  }}
  window.openInvRefModal = openInvRefModal;

  function closeInvRefModal(){{
    var m = document.getElementById('invRefModal');
    if (m) {{
      m.classList.remove('open');
      document.body.style.overflow = '';
    }}
  }}
  window.closeInvRefModal = closeInvRefModal;

  document.addEventListener('keydown', function(e){{
    if (e.key === 'Escape' || e.keyCode === 27) {{
      closeInvRefModal();
    }}
  }});

  var _fleetScript = document.getElementById('fleet-inv-data');
  if (_fleetScript) {{
    try {{
      window.FLEET_INV = JSON.parse(_fleetScript.textContent);
    }} catch(e) {{}}
  }}

  if (!window.initFleetTablePager) {{
    window.initFleetTablePager = function(opts) {{
      var table = typeof opts.table === 'string' ? document.querySelector(opts.table) : opts.table;
      if (!table) return null;
      var rowSelector = opts.rowSelector || 'tbody tr';
      var pageSizeEl = typeof opts.pageSizeSelect === 'string' ? document.querySelector(opts.pageSizeSelect) : opts.pageSizeSelect;
      var prevBtn = typeof opts.prevBtn === 'string' ? document.querySelector(opts.prevBtn) : opts.prevBtn;
      var nextBtn = typeof opts.nextBtn === 'string' ? document.querySelector(opts.nextBtn) : opts.nextBtn;
      var pageInfoEl = typeof opts.pageInfo === 'string' ? document.querySelector(opts.pageInfo) : opts.pageInfo;
      var countEl = typeof opts.countEl === 'string' ? document.querySelector(opts.countEl) : opts.countEl;
      var warnEl = typeof opts.warnEl === 'string' ? document.querySelector(opts.warnEl) : opts.warnEl;

      var state = {{
        currentPage: 1,
        pageSize: 50,
        isCapped: false,
        totalMatching: 0,
        matchingRows: []
      }};

      function update() {{
        var allRows = Array.from(table.querySelectorAll(rowSelector));
        var matching = [];
        allRows.forEach(function(row) {{
          var match = true;
          if (typeof opts.filterFn === 'function') {{
            match = opts.filterFn(row);
          }}
          if (match) matching.push(row);
        }});
        state.matchingRows = matching;
        state.totalMatching = matching.length;

        var rawPageSize = pageSizeEl ? pageSizeEl.value : '50';
        var effPageSize = 50;
        state.isCapped = false;
        if (rawPageSize === 'all') {{
          if (matching.length > 500) {{
            effPageSize = 500;
            state.isCapped = true;
          }} else {{
            effPageSize = Math.max(1, matching.length);
          }}
        }} else {{
          effPageSize = parseInt(rawPageSize, 10) || 50;
        }}
        state.pageSize = effPageSize;

        var totalPages = Math.max(1, Math.ceil(matching.length / effPageSize));
        if (state.currentPage > totalPages) state.currentPage = totalPages;
        if (state.currentPage < 1) state.currentPage = 1;

        var start = (state.currentPage - 1) * effPageSize;
        var end = start + effPageSize;

        for (var i = 0; i < allRows.length; i++) {{
          allRows[i].style.display = 'none';
        }}
        for (var j = start; j < Math.min(end, matching.length); j++) {{
          matching[j].style.display = '';
        }}

        if (warnEl) {{
          warnEl.style.display = state.isCapped ? 'inline' : 'none';
        }}
        if (prevBtn) prevBtn.disabled = (state.currentPage <= 1);
        if (nextBtn) nextBtn.disabled = (state.currentPage >= totalPages);
        if (pageInfoEl) {{
          pageInfoEl.textContent = 'Page ' + state.currentPage + ' of ' + totalPages;
        }}
        if (countEl) {{
          countEl.textContent = String(matching.length);
        }}
        if (typeof opts.onUpdate === 'function') {{
          opts.onUpdate(state, matching);
        }}
      }}

      if (opts.bindControls !== false) {{
        if (pageSizeEl) {{
          pageSizeEl.addEventListener('change', function() {{
            state.currentPage = 1;
            update();
          }});
        }}
        if (prevBtn) {{
          prevBtn.addEventListener('click', function() {{
            if (state.currentPage > 1) {{
              state.currentPage--;
              update();
            }}
          }});
        }}
        if (nextBtn) {{
          nextBtn.addEventListener('click', function() {{
            state.currentPage++;
            update();
          }});
        }}
      }}

      return {{
        update: update,
        getState: function() {{ return state; }},
        setPage: function(p) {{ state.currentPage = p; update(); }},
        nextPage: function() {{ state.currentPage++; update(); }},
        prevPage: function() {{ if (state.currentPage > 1) {{ state.currentPage--; update(); }} }}
      }};
    }};
  }}

  var currentInvView = 'hosts';
  var matchingHostIndicesMap = {{}};
  var hostFilterActive = false;

  function evaluateHostMatches() {{
    var oem = (document.getElementById('invOem') || {{}}).value || '';
    var cpu = (document.getElementById('invCpu') || {{}}).value || '';
    var esa = (document.getElementById('invEsa') || {{}}).value || '';
    var ctrl = (document.getElementById('invCtrl') || {{}}).value || '';
    var nic = (document.getElementById('invNic') || {{}}).value || '';
    var link = (document.getElementById('invLink') || {{}}).value || '';
    var sec = (document.getElementById('invSec') || {{}}).value || '';
    var text = ((document.getElementById('invFilter') || {{}}).value || '').toLowerCase();

    hostFilterActive = !!(oem || cpu || esa || ctrl || nic || link || sec || text);
    var matching = {{}};
    document.querySelectorAll('#invHostTable tbody tr.inv-row').forEach(function(tr){{
      var ok = true;
      if (oem && tr.getAttribute('data-oem') !== oem) ok = false;
      if (cpu && tr.getAttribute('data-cpu') !== cpu) ok = false;
      if (sec && tr.getAttribute('data-sec-posture') !== sec) ok = false;
      if (esa) {{
        var dEsa = tr.getAttribute('data-esa') || '';
        var dProfile = tr.getAttribute('data-esa-tier') || '';
        if (esa === 'Ready') {{
          if (dProfile !== 'ESA-L' && dProfile !== 'ESA-M' && dProfile !== 'ESA-S' && dProfile !== 'ESA-XS' && dEsa !== 'Ready') ok = false;
        }} else if (esa === 'Blocked') {{
          if (dProfile !== 'Blocked' && dEsa !== 'Blocked') ok = false;
        }} else if (esa === 'Insufficient') {{
          if (dProfile !== 'Insufficient' && dEsa !== 'Insufficient') ok = false;
        }} else if (esa !== dProfile && esa !== dEsa) {{
          ok = false;
        }}
      }}
      if (ctrl === 'esa' && tr.getAttribute('data-ctrl-esa') !== '1') ok = false;
      if (ctrl === 'osa' && tr.getAttribute('data-ctrl-osa') !== '1') ok = false;
      if (ctrl === 'unsupported' && tr.getAttribute('data-ctrl-unsup') !== '1') ok = false;
      if (nic && tr.getAttribute('data-nic') !== nic) ok = false;
      if (link === 'down' && tr.getAttribute('data-link') !== 'down') ok = false;
      if (link === 'up' && tr.getAttribute('data-link') !== 'up') ok = false;
      if (text && (tr.innerText || '').toLowerCase().indexOf(text) < 0) ok = false;

      if (ok) {{
        var idx = tr.getAttribute('data-host-idx') || '';
        if (idx !== '') matching[idx] = true;
      }}
    }});
    matchingHostIndicesMap = matching;
    return matching;
  }}

  function visibleHostIndices(){{
    return evaluateHostMatches();
  }}
  window.visibleHostIndices = visibleHostIndices;

  function matchDetailRow(tr) {{
    var hidx = tr.getAttribute('data-host-idx') || '';
    if (hostFilterActive && !matchingHostIndicesMap[hidx]) return false;
    var ctrl = (document.getElementById('invCtrl') || {{}}).value || '';
    if (ctrl) {{
      var dCtrl = tr.getAttribute('data-ctrl-type') || '';
      if (dCtrl && dCtrl !== ctrl) return false;
    }}
    var link = (document.getElementById('invLink') || {{}}).value || '';
    if (link) {{
      var dLink = tr.getAttribute('data-link-status') || '';
      if (dLink && dLink !== link) return false;
    }}
    var sec = (document.getElementById('invSec') || {{}}).value || '';
    if (sec) {{
      var dSec = tr.getAttribute('data-sec-posture') || '';
      if (dSec && dSec !== sec) return false;
    }}
    return true;
  }}

  var invPagers = {{
    hosts: window.initFleetTablePager({{
      table: '#invHostTable',
      rowSelector: 'tbody tr.inv-row',
      pageSizeSelect: '#invPageSize',
      prevBtn: '#invPrevBtn',
      nextBtn: '#invNextBtn',
      pageInfo: '#invPageInfo',
      countEl: '#invShown',
      warnEl: '#invPageWarn',
      bindControls: false,
      filterFn: function(tr) {{
        return !!matchingHostIndicesMap[tr.getAttribute('data-host-idx')];
      }}
    }}),
    drives: window.initFleetTablePager({{
      table: '#invDrivesTable',
      rowSelector: 'tbody tr.inv-detail-row',
      pageSizeSelect: '#invPageSize',
      prevBtn: '#invPrevBtn',
      nextBtn: '#invNextBtn',
      pageInfo: '#invPageInfo',
      countEl: '#invShown',
      warnEl: '#invPageWarn',
      bindControls: false,
      filterFn: matchDetailRow
    }}),
    nics: window.initFleetTablePager({{
      table: '#invNicsTable',
      rowSelector: 'tbody tr.inv-detail-row',
      pageSizeSelect: '#invPageSize',
      prevBtn: '#invPrevBtn',
      nextBtn: '#invNextBtn',
      pageInfo: '#invPageInfo',
      countEl: '#invShown',
      warnEl: '#invPageWarn',
      bindControls: false,
      filterFn: matchDetailRow
    }}),
    bios: window.initFleetTablePager({{
      table: '#invBiosTable',
      rowSelector: 'tbody tr.inv-detail-row',
      pageSizeSelect: '#invPageSize',
      prevBtn: '#invPrevBtn',
      nextBtn: '#invNextBtn',
      pageInfo: '#invPageInfo',
      countEl: '#invShown',
      warnEl: '#invPageWarn',
      bindControls: false,
      filterFn: matchDetailRow
    }}),
    health: window.initFleetTablePager({{
      table: '#invHealthTable',
      rowSelector: 'tbody tr.inv-detail-row',
      pageSizeSelect: '#invPageSize',
      prevBtn: '#invPrevBtn',
      nextBtn: '#invNextBtn',
      pageInfo: '#invPageInfo',
      countEl: '#invShown',
      warnEl: '#invPageWarn',
      bindControls: false,
      filterFn: matchDetailRow
    }}),
    security: window.initFleetTablePager({{
      table: '#invSecurityTable',
      rowSelector: 'tbody tr.inv-detail-row',
      pageSizeSelect: '#invPageSize',
      prevBtn: '#invPrevBtn',
      nextBtn: '#invNextBtn',
      pageInfo: '#invPageInfo',
      countEl: '#invShown',
      warnEl: '#invPageWarn',
      bindControls: false,
      filterFn: matchDetailRow
    }})
  }};

  function getActiveInvPager() {{
    return invPagers[currentInvView] || invPagers.hosts;
  }}

  var invPrevBtnEl = document.getElementById('invPrevBtn');
  if (invPrevBtnEl) {{
    invPrevBtnEl.addEventListener('click', function() {{
      var p = getActiveInvPager();
      if (p) p.prevPage();
    }});
  }}
  var invNextBtnEl = document.getElementById('invNextBtn');
  if (invNextBtnEl) {{
    invNextBtnEl.addEventListener('click', function() {{
      var p = getActiveInvPager();
      if (p) p.nextPage();
    }});
  }}
  var invPageSizeEl = document.getElementById('invPageSize');
  if (invPageSizeEl) {{
    invPageSizeEl.addEventListener('change', function() {{
      var p = getActiveInvPager();
      if (p) p.setPage(1);
    }});
  }}

  function applyInvFilters(){{
    evaluateHostMatches();
    var p = getActiveInvPager();
    if (p) {{
      p.update();
    }}
  }}
  window.applyInvFilters = applyInvFilters;

  function showInvView(name){{
    currentInvView = name;
    document.querySelectorAll('#invRoot .inv-pane').forEach(function(p){{
      p.classList.toggle('active', p.id === 'inv-pane-' + name);
    }});
    document.querySelectorAll('#invRoot .inv-seg button').forEach(function(b){{
      b.classList.toggle('active', b.getAttribute('data-inv-view') === name);
    }});
    var p = getActiveInvPager();
    if (p) p.setPage(1);
  }}
  window.showInvView = showInvView;
  window.showInvTab = showInvView;

  ['invOem','invCpu','invEsa','invCtrl','invNic','invLink','invSec'].forEach(function(id){{
    var el = document.getElementById(id);
    if (el) el.addEventListener('change', applyInvFilters);
  }});
  var filt = document.getElementById('invFilter');
  if (filt) filt.addEventListener('input', applyInvFilters);

  function setupTableResizers(rootEl){{
    (rootEl || document).querySelectorAll('table.inv-table, table.sortable-table').forEach(function(table){{
      var ths = table.querySelectorAll('thead th');
      ths.forEach(function(th){{
        if (th.querySelector('.col-resizer')) return;
        var resizer = document.createElement('span');
        resizer.className = 'col-resizer';
        th.appendChild(resizer);

        var startX, startW;
        function onMouseDown(e){{
          e.stopPropagation();
          e.preventDefault();
          startX = e.pageX;
          startW = th.offsetWidth;
          resizer.classList.add('resizing');
          document.addEventListener('mousemove', onMouseMove);
          document.addEventListener('mouseup', onMouseUp);
        }}
        function onMouseMove(e){{
          var diff = e.pageX - startX;
          var newW = Math.max(30, startW + diff);
          th.style.width = newW + 'px';
          th.style.minWidth = newW + 'px';
        }}
        function onMouseUp(){{
          resizer.classList.remove('resizing');
          document.removeEventListener('mousemove', onMouseMove);
          document.removeEventListener('mouseup', onMouseUp);
        }}
        resizer.addEventListener('mousedown', onMouseDown);
      }});
    }});
  }}
  window.setupTableResizers = setupTableResizers;
  if (document.readyState === 'loading') {{
    document.addEventListener('DOMContentLoaded', function(){{ setupTableResizers(document.getElementById('invRoot')); }});
  }} else {{
    setupTableResizers(document.getElementById('invRoot'));
  }}

  var _EMBEDDED_EXCEL_B64 = "{excel_b64}";
  var _EMBEDDED_OBF_ZIP_B64 = "{obf_zip_b64}";
  var _SIBLING_XLSX = "{sibling_xlsx_val}";
  var _SIBLING_OBF_XLSX = "{sibling_obf_xlsx_val}";

  window.dlInvExcel = function(obf){{
    var b64 = obf ? _EMBEDDED_OBF_ZIP_B64 : _EMBEDDED_EXCEL_B64;
    var filename = obf ? 'inventory_obfuscated.zip' : '{inv_dl_filename}';
    var mime = obf ? 'application/zip' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

    if (b64 && b64.length > 0) {{
      try {{
        var byteChars = atob(b64);
        var byteNumbers = new Array(byteChars.length);
        for (var i = 0; i < byteChars.length; i++) {{
          byteNumbers[i] = byteChars.charCodeAt(i);
        }}
        var byteArray = new Uint8Array(byteNumbers);
        var blob = new Blob([byteArray], {{type: mime}});
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
        URL.revokeObjectURL(a.href);
        return;
      }} catch (e) {{
        console.error('Embedded export decode failed:', e);
      }}
    }}

    var sib = obf ? (_SIBLING_OBF_XLSX || _SIBLING_XLSX) : _SIBLING_XLSX;
    if (sib) {{
      var a = document.createElement('a');
      a.href = sib;
      a.download = sib.split('/').pop() || filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      return;
    }}

    if (location.protocol === 'file:') {{
      alert('Export payload is not available in offline file mode without sibling .xlsx.');
      return;
    }}
    var url = obf ? '/api/export-inventory-excel-obfuscated' : '/api/export-excel';
    fetch(url, {{method:'POST', credentials:'same-origin'}})
      .then(function(r){{
        if (!r.ok) throw new Error('export failed');
        var cd = r.headers.get('Content-Disposition') || '';
        var m = /filename="?([^"]+)"?/.exec(cd);
        var name = m ? m[1] : (obf ? 'inventory.zip' : 'inventory.xlsx');
        return r.blob().then(function(b){{ return {{b:b, name:name}}; }});
      }})
      .then(function(o){{
        var a = document.createElement('a');
        a.href = URL.createObjectURL(o.b);
        a.download = o.name;
        a.click();
        URL.revokeObjectURL(a.href);
      }})
      .catch(function(){{
        alert('Export failed. Open this report via the VCF Readiness web UI (not file://).');
      }});
  }};
}})();
</script>
"""
