"""Combined multi-host tabbed HTML report generator."""
import hashlib
import html
import logging
import os
import re
import time
from typing import Optional

from vcf_hci.constants import COMBINED_HTML_DEFAULT_MAX_HOSTS, TOOL_VERSION
from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.report.fleet.escape import _xe
from vcf_hci.report.fleet.inventory_panel import build_detailed_inventory_html
from vcf_hci.report.fleet.switch_matrix import build_fleet_switch_matrix_html
from vcf_hci.report.fleet.tiles import build_fleet_tiles_html
from vcf_hci.report.fleet.vendor import normalize_oem_vendor
from vcf_hci.report.helpers import _h
from vcf_hci.report.inventory_tables import build_host_decision_rows, clean_model_code
from vcf_hci.report.styles import HOST_REPORT_CSS
from vcf_hci.security.scoring import score_host_security

logger = logging.getLogger(__name__)

try:
    from vcf_hci.web.docs_data import DOCS_DATA
except ImportError:
    DOCS_DATA = {}


def _generate_combined_html(
    all_results: list,
    report_paths: list,
    outdir: str,
    obfuscated: bool = False,
    output_filename: Optional[str] = None,
    embed_mode: Optional[str] = None,
) -> str:
    """Generate a single combined tabbed HTML report containing all host reports."""
    if not all_results:
        return ""

    _page_salt = os.urandom(16).hex()

    if obfuscated and all_results:
        from vcf_hci.obfuscation import obfuscate_host_data
        _needs_obf = any(
            not r.get("obfuscated") and not re.match(r"^Host-\d+$", str((r.get("system") or {}).get("hostname", "")))
            for r in all_results
        )
        if _needs_obf:
            all_results = [
                obfuscate_host_data(r, f"Host-{i+1}", _page_salt) if (not r.get("obfuscated") and not re.match(r"^Host-\d+$", str((r.get("system") or {}).get("hostname", "")))) else r
                for i, r in enumerate(all_results)
            ]

    n_hosts = len(all_results)
    mode = embed_mode or ("inline" if n_hosts <= COMBINED_HTML_DEFAULT_MAX_HOSTS else "sidecar")
    _style_re = re.compile(r"<style[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)

    host_html_list: list = []
    css_block = HOST_REPORT_CSS
    if mode == "inline":
        for i, path in enumerate(report_paths):
            try:
                report_html = ""
                is_p_obf = bool(path and ("obfuscated" in os.path.basename(path).lower()))
                if obfuscated and not is_p_obf and i < len(all_results):
                    import tempfile

                    from vcf_hci.report.host_report import generate_host_html_report
                    with tempfile.NamedTemporaryFile("w+", suffix=".html", delete=False) as tf:
                        tf_path = tf.name
                    try:
                        generate_host_html_report(all_results[i], tf_path, obfuscated=True)
                        with open(tf_path, encoding="utf-8") as tf_in:
                            report_html = tf_in.read()
                    finally:
                        try:
                            os.unlink(tf_path)
                        except OSError:
                            pass
                else:
                    with open(path, encoding="utf-8") as fh:
                        report_html = fh.read()
                m = _style_re.search(report_html)
                if m:
                    css_block = m.group(1)
                host_html_list.append(report_html)
            except Exception as exc:
                host_html_list.append(f"<!DOCTYPE html><html><body><p style='color:red'>Error: {_h(exc)}</p></body></html>")
    else:
        if report_paths:
            try:
                with open(report_paths[0], encoding="utf-8") as fh:
                    first_html = fh.read(65536)
                m = _style_re.search(first_html)
                if m:
                    css_block = m.group(1)
            except Exception:
                pass

    def _pii(value: str, kind: str = "host") -> str:
        if not value:
            return ""
        if obfuscated:
            return _h(value)
        mask = f"{kind[0].upper()}-{hashlib.sha256((_page_salt + value).encode()).hexdigest()[:8].upper()}"
        safe_val = _h(value)
        return f'<span class="pii" data-real="{safe_val}" data-mask="{mask}">{safe_val}</span>'

    tiles_html = build_fleet_tiles_html(all_results, report_prefix="", page_salt=_page_salt)
    switch_matrix_block = build_fleet_switch_matrix_html(all_results, report_prefix="", page_salt=_page_salt, obfuscated=obfuscated)

    sum_rows = ""
    _oem_set = set()
    slow_bmc_hosts = []

    for data in all_results:
        _vr = str((data.get("system") or {}).get("vendor", "")).strip()
        if _vr:
            _oem_set.add(normalize_oem_vendor(_vr))

    # At assemble scale (N > 500), cap initial summary table DOM rows at 500 to keep HTML under 8 MB budget
    max_summary_rows = 500 if n_hosts > 500 else n_hosts
    for idx, data in enumerate(all_results[:max_summary_rows]):
        si = data.get("system", {})
        ci = si.get("cpu_summary", {})
        all_drv = [d for ctrl in data.get("storage_subsystem", []) for d in ctrl.get("drives", [])]
        esa_n = sum(1 for d in all_drv if d.get("category") == "vSAN ESA/OSA NVMe")
        osa_n = sum(1 for d in all_drv if d.get("category") in ("vSAN OSA Only", "vSAN OSA SAS/SATA"))
        verdict = ci.get("verdict", "")
        if "Unsupported" in verdict:
            cpu_cls = "danger"
            cpu_td = "🔴 Unsupported"
            _cpu_sort = "4"
            _row_unsupported = "1"
        elif "Override Required" in verdict or "9.1 Only" in verdict:
            cpu_cls = "warning"
            cpu_td = "🟡 Override Required"
            _cpu_sort = "3"
            _row_unsupported = "0"
        elif "Deprecated" in verdict:
            cpu_cls = "warning"
            cpu_td = "🟡 Deprecated"
            _cpu_sort = "2"
            _row_unsupported = "0"
        else:
            cpu_cls = "success"
            cpu_td = "🟢 Supported"
            _cpu_sort = "1"
            _row_unsupported = "0"

        esa_cls = "success" if esa_n >= 2 else ("warning" if (osa_n >= 2 or esa_n + osa_n >= 2) else "danger")
        if esa_n >= 2:
            esa_td = f"🟢 ESA ({esa_n} NVMe)"
        elif osa_n >= 2 or (esa_n + osa_n >= 2):
            if esa_n > 0 and osa_n > 0:
                esa_td = f"🟡 OSA ({esa_n} ESA + {osa_n} OSA)"
            elif esa_n > 0:
                esa_td = f"🟡 OSA ({esa_n} NVMe)"
            else:
                esa_td = f"🟡 OSA ({osa_n} drives)"
        else:
            esa_td = "🔴 None"
        _esa_sort = str(esa_n)
        psu = data.get("psu_status", {})
        psu_cls = "success" if psu.get("redundant") else "warning"
        psu_td = "🟢 Redundant" if psu.get("redundant") else "🟡 Single"
        _psu_sort = "1" if psu.get("redundant") else "2"
        fc_n = len(data.get("fc_hbas", []))
        gpu_n = len(data.get("gpu_accelerators", []))
        tpm = si.get("tpm_status_badge", "<span class='badge warning'>⚠️ Unknown</span>")
        _tpm_sort = "1" if "success" in tpm else ("3" if "danger" in tpm else "2")
        hostname = si.get("hostname") or si.get("ip", "Unknown")
        raw_ip = si.get("ip", "")
        if obfuscated:
            if not re.match(r"^Host-\d+$", str(hostname)):
                hostname = f"Host-{idx+1}"
            if not str(raw_ip).startswith("192.0.2."):
                raw_ip = f"192.0.2.{(idx % 250) + 1}"

        _vendor_raw = si.get("vendor", "") or ""
        _model_str = f"{_vendor_raw} {si.get('model','')}".strip()
        _vendor_norm = normalize_oem_vendor(_vendor_raw)
        _oem_set.add(_vendor_norm)

        scan_dur = float(data.get("scan_duration_sec", 0) or 0)
        is_throttled = bool(data.get("adaptive_throttled"))
        is_skipped = bool(data.get("skipped"))
        bmc_fw = data.get("bmc_firmware", {})
        fw_ver = str(bmc_fw.get("bmc_fw_version", "")).strip()
        bmc_model = str(bmc_fw.get("bmc_model", "BMC")).strip()
        fw_eval = bmc_fw.get("bmc_fw_eval", {})
        latest_ver = fw_eval.get("latest_version", "")
        update_rec = fw_eval.get("update_recommended") or ("Update Available" in bmc_fw.get("badge", "") or "Outdated" in bmc_fw.get("badge", ""))

        slow_bmc_badge = ""
        if scan_dur >= 60.0 or is_throttled or is_skipped:
            m_str = f"{int(scan_dur // 60)}m {int(scan_dur % 60)}s" if scan_dur >= 60 else f"{int(scan_dur)}s"
            upg_note = f" (Recommend {bmc_model} Upgrade to v{latest_ver})" if (update_rec and latest_ver and latest_ver != "N/A") else " (Recommend BMC Reset / Upgrade)"
            slow_bmc_badge = (
                f"<br><span class='badge warning' style='font-size:.73rem;margin-top:2px;display:inline-block;' "
                f"title='Redfish scan took {m_str}. API response latency or socket timeouts occurred.'>"
                f"⚠️ Slow BMC API{_xe(upg_note)}</span>"
            )
            slow_bmc_hosts.append((hostname, raw_ip or "Unknown", m_str, _model_str, bmc_model, fw_ver, latest_ver, update_rec))

        _model_raw = str(si.get("model", "") or "")
        _clean_model = clean_model_code(_vendor_raw, _model_raw) or _model_raw or "\u2014"

        _sec_score = score_host_security(data)
        if _sec_score.get("is_fleet_manager"):
            sec_td = "<span class='badge' style='background:var(--card);color:var(--text-muted);border:1px solid var(--border)'>Excluded (Fleet Mgr)</span>"
            _sec_sort = "4"
        elif _sec_score.get("assessed"):
            _p_cnt = _sec_score.get("pass_count", 0)
            _f_cnt = _sec_score.get("fail_count", 0)
            _u_cnt = _sec_score.get("unknown_count", 0)
            _posture = _sec_score.get("posture", "")
            _comp_pct = _sec_score.get("compliance_pct", 0.0)
            _tip = f"{_f_cnt} Failed, {_p_cnt} Passed, {_u_cnt} Unknown ({_comp_pct}% compliance). Click to view BMC security audit."
            if _posture == "Baseline Met":
                sec_badge = f"<span class='badge success'>🟢 Met ({_p_cnt}P)</span>"
                _sec_sort = "1"
            elif _posture == "Action Required":
                sec_badge = f"<span class='badge danger'>🔴 Action Req ({_f_cnt}F &middot; {_p_cnt}P)</span>"
                _sec_sort = "3"
            else:
                sec_badge = f"<span class='badge warning'>🟡 Partial ({_u_cnt}U &middot; {_p_cnt}P)</span>"
                _sec_sort = "2"
            sec_td = (
                f"<a href='#' class='btn-link tab-jump' data-tab='{idx + 3}' data-subtab='tab-security' "
                f"title='{_xe(_tip)}' style='text-decoration:none;display:inline-block'>{sec_badge}</a>"
            )
        else:
            sec_td = "<span style='color:#94a3b8'>—</span>"
            _sec_sort = "5"

        _sort_hostname = _xe(hostname) if obfuscated else f"Host-{idx+1}"
        _cpu_model_raw = str(ci.get("model", "") or "")
        _cpu_tip = f"{_cpu_model_raw} — Click to view host CPU details" if _cpu_model_raw else "Click to view host CPU details"
        cpu_cell_html = (
            f"<a href='#' class='btn-link tab-jump' data-tab='{idx + 3}' data-subtab='tab-cpu' "
            f"title='{_xe(_cpu_tip)}' style='text-decoration:none;display:inline-block'>"
            f"<span class='badge {cpu_cls}'>{cpu_td}</span></a>"
        )
        tpm_cell_html = (
            f"<a href='#' class='btn-link tab-jump' data-tab='{idx + 3}' data-subtab='tab-security' "
            f"title='Click to view host Security &amp; TPM details' style='text-decoration:none;display:inline-block'>{tpm}</a>"
        )
        esa_cell_html = (
            f"<a href='#' class='btn-link tab-jump' data-tab='{idx + 3}' data-subtab='tab-storage' "
            f"title='Click to view host Storage &amp; vSAN details' style='text-decoration:none;display:inline-block'>"
            f"<span class='badge {esa_cls}'>{esa_td}</span></a>"
        )
        sum_rows += (
            f"<tr data-vendor='{_xe(_vendor_norm)}' data-unsupported='{_row_unsupported}'>"
            f"<td data-sort='{_sort_hostname}'><a href='#' class='btn-link tab-jump' data-tab='{idx + 3}'>"
            f"<strong>{_pii(hostname)}</strong></a>"
            f"<br><small style='color:#64748b'>{_pii(raw_ip, 'ip')}</small></td>"
            f"<td data-sort='{_xe(_model_str)}' title='{_xe(_model_str)}'>{_xe(_clean_model)}{slow_bmc_badge}</td>"
            f"<td data-sort='{_cpu_sort}'>{cpu_cell_html}</td>"
            f"<td data-sort='{_tpm_sort}'>{tpm_cell_html}</td>"
            f"<td data-sort='{_sec_sort}'>{sec_td}</td>"
            f"<td data-sort='{_esa_sort}'>{esa_cell_html}</td>"
            f"<td data-sort='{_psu_sort}'><span class='badge {psu_cls}'>{psu_td}</span></td>"
            f"<td data-sort='{fc_n}'>{'🔵 ' + str(fc_n) + ' HBA' if fc_n else '—'}</td>"
            f"<td data-sort='{gpu_n}'>{'🟣 ' + str(gpu_n) + ' GPU' if gpu_n else '—'}</td>"
            f"</tr>"
        )

    _oem_options_html = "".join(
        f"<option value='{_xe(v)}'>{_xe(v)}</option>"
        for v in sorted(_oem_set)
    )

    slow_bmc_alert_html = ""
    if slow_bmc_hosts:
        items_html = "".join(
            f"<li><strong>{_pii(h[0])}</strong> ({_pii(h[1], 'ip')}) — <em>{_xe(h[3])}</em>: "
            f"Scan duration <strong>{h[2]}</strong>"
            f"{f' ({_xe(h[4])} v{_xe(h[5])} installed)' if (len(h) > 5 and h[5] and h[5] != 'N/A') else ''}"
            f"{f' — 💡 <strong>Action Recommended: Upgrade {_xe(h[4])} to v{_xe(h[6])} and perform a BMC reset (<code>racadm racreset</code>)</strong>' if (len(h) > 7 and h[7] and h[6] and h[6] != 'N/A') else ' — 💡 <strong>Action Recommended: Reset BMC or upgrade firmware to recommended baseline</strong>'}"
            f"</li>"
            for h in slow_bmc_hosts
        )
        slow_bmc_alert_html = (
            f"<details class='alert alert-warning' style='margin:1.25rem 0;cursor:pointer'>"
            f"<summary style='font-size:.92rem;font-weight:700;cursor:pointer;outline:none'>"
            f"⚠️ Degraded Redfish BMC Service / Slow Response Times Detected ({len(slow_bmc_hosts)} Host(s))"
            f"</summary>"
            f"<div style='margin-top:.6rem;cursor:default'>"
            f"<p style='margin:.4rem 0 0;font-size:.86rem'>The following host BMC(s) experienced socket timeouts, response latency, or worker throttling during Redfish collection:</p>"
            f"<div style='max-height:240px;overflow-y:auto;margin-top:.4rem;padding-right:.5rem;border:1px solid var(--border,#e2e8f0);border-radius:4px;padding:.5rem .75rem;background:rgba(0,0,0,0.02)'>"
            f"<ul style='margin:0;padding-left:1.25rem;font-size:.85rem'>{items_html}</ul>"
            f"</div>"
            f"<p style='margin:.5rem 0 0;font-size:.83rem;font-weight:600'>💡 Action Recommended: Verify BMC network latency, reset frozen BMC web services, and upgrade iDRAC / BMC firmware to recommended baseline releases prior to VCF deployment.</p>"
            f"</div>"
            f"</details>"
        )

    summary_title = f"VCF / vSphere 9.1 Readiness — Fleet Health Dashboard{' (Obfuscated)' if obfuscated else ''}"
    if obfuscated:
        header_controls = (
            '<div style="text-align:right;margin-bottom:1rem">'
            '<span class="badge cyber-recovery" style="font-size:.82rem;padding:.3rem .75rem;border:1px solid #7c3aed">'
            '🔒 Obfuscated Fleet Report</span>'
            '&nbsp;&nbsp;<button id="themeToggle" title="Toggle dark/light mode">🌙 Dark</button>'
            '</div>'
        )
    else:
        header_controls = (
            '<p style="text-align:right;margin-bottom:1rem">'
            '<label style="font-size:.82rem;cursor:pointer;user-select:none">'
            '<input type="checkbox" id="maskPII"> Obfuscate report'
            '</label>'
            '<a id="dlObf" href="#" class="btn-link" style="display:none;margin-left:.5rem;font-size:.82rem;color:var(--primary,#60a5fa);text-decoration:none;border:1px solid var(--primary,#60a5fa);border-radius:4px;padding:.15rem .5rem" title="Download obfuscated HTML copy">&#11015; Save obfuscated copy</a>'
            '<a id="dlObfCombined" href="#" style="margin-left:.75rem;font-size:.82rem;color:var(--ms-3dpc-color,#a78bfa);text-decoration:none;border:1px solid var(--ms-3dpc-color,#a78bfa);border-radius:4px;padding:.15rem .5rem;white-space:nowrap" title="Download a copy of this combined report with all host identifiers replaced by hash tokens">&#11015; Save obfuscated combined report</a>'
            '&nbsp;&nbsp;<button id="themeToggle" title="Toggle dark/light mode">🌙 Dark</button>'
            '</p>'
        )

    summary_tab = f"""<div class="container" style="padding-top:2rem">
{header_controls}
<h1>{summary_title}</h1>
<p style="color:#64748b">{n_hosts} host(s) assessed — click a host tab for full detail.</p>
<h2 style="font-size:.9rem;font-weight:700;color:var(--text-muted,#94a3b8);margin:2rem 0 .75rem;text-transform:uppercase">Fleet Health Tiles</h2>
{tiles_html}
{slow_bmc_alert_html}
<h2 style="font-size:.9rem;font-weight:700;color:var(--text-muted,#94a3b8);margin:2rem 0 .75rem;text-transform:uppercase">Per-Host Assessment Table</h2>
<div id="table-controls" style="display:flex;gap:1.25rem;align-items:center;margin:.5rem 0 .75rem;flex-wrap:wrap;background:var(--card, #f8fafc);border:1px solid var(--border, #e2e8f0);border-radius:6px;padding:.6rem 1rem;font-size:.87rem">
  <label style="display:flex;align-items:center;gap:.45rem;font-weight:600;color:var(--text-muted, #64748b)">
    OEM Filter:
    <select id="oem-filter" style="margin-left:.25rem;padding:.28rem .65rem;border:1px solid var(--border, #cbd5e1);border-radius:5px;font-size:.85rem;background:var(--card, #ffffff);color:var(--text, #0f172a)">
      <option value="all">All OEMs</option>
      {_oem_options_html}
    </select>
  </label>
  <label style="display:flex;align-items:center;gap:.4rem;cursor:pointer;color:var(--text-muted, #64748b)">
    <input type="checkbox" id="hide-unsupported" style="cursor:pointer">
    Hide unsupportable hosts <small style="color:var(--text-muted, #64748b)">(pre-Skylake)</small>
  </label>
  <div class="summary-pagination" style="display:inline-flex;align-items:center;gap:0.45rem;font-size:0.85rem;margin-left:auto">
    <label style="display:inline-flex;align-items:center;gap:0.35rem;color:var(--text-muted,#64748b)">
      Show:
      <select id="sumPageSize" style="padding:2px 6px;border-radius:4px;border:1px solid var(--border,#cbd5e1);background:var(--card,#ffffff);color:var(--text,#0f172a);font-size:0.85rem">
        <option value="25">25</option>
        <option value="50" selected>50</option>
        <option value="100">100</option>
        <option value="all">All</option>
      </select>
    </label>
    <button type="button" id="sumPrevBtn" class="inv-btn" style="padding:2px 8px;font-size:0.85rem">‹ Prev</button>
    <span id="sumPageInfo" style="color:var(--text-muted,#64748b);min-width:65px;text-align:center">Page 1 of 1</span>
    <button type="button" id="sumNextBtn" class="inv-btn" style="padding:2px 8px;font-size:0.85rem">Next ›</button>
    <span id="sumPageWarn" style="display:none;color:#f59e0b;font-weight:600">⚠️ Capped at 500 rows</span>
  </div>
</div>
{f"<div class='alert alert-warning' style='margin:0.75rem 0'>⚠️ <strong>Large Fleet Mode:</strong> Showing first 500 hosts of {n_hosts:,} in standalone HTML summary table. Use the searchable Host Picker above to open any host report directly, or use the Web UI (<code>python -m vcf_hci.web</code>) for full pagination across all {n_hosts:,} hosts.</div>" if n_hosts > 500 else ""}
<table class="sortable-table"><thead><tr>
<th title="Click to sort">Host / IP<span class="sort-ind">⇅</span></th>
<th title="Click to sort">Model<span class="sort-ind">⇅</span></th>
<th title="Click to sort">CPU Support<span class="sort-ind">⇅</span></th>
<th title="Click to sort">TPM 2.0<span class="sort-ind">⇅</span></th>
<th title="Click to sort">BMC Security<span class="sort-ind">⇅</span></th>
<th title="Click to sort">vSAN Tier<span class="sort-ind">⇅</span></th>
<th title="Click to sort">PSU<span class="sort-ind">⇅</span></th>
<th title="Click to sort">FC HBAs<span class="sort-ind">⇅</span></th>
<th title="Click to sort">GPUs<span class="sort-ind">⇅</span></th>
</tr></thead><tbody>{sum_rows}</tbody></table>
{switch_matrix_block}
</div>"""

    sibling_xlsx = None
    if mode == "sidecar" and outdir and os.path.isdir(outdir):
        xlsx_candidates = [
            f for f in os.listdir(outdir)
            if f.lower().endswith(".xlsx")
        ]
        for f in xlsx_candidates:
            is_f_obf = "obfuscated" in f.lower() or f.startswith("00_OBFUSCATED")
            if bool(obfuscated) == is_f_obf:
                sibling_xlsx = f
                break
        if not sibling_xlsx and xlsx_candidates:
            sibling_xlsx = xlsx_candidates[0]

    inv_rows = build_host_decision_rows(all_results)
    inventory_tab = build_detailed_inventory_html(
        inv_rows,
        all_results,
        obfuscated=obfuscated,
        page_salt=_page_salt,
        embed_mode=mode,
        sibling_xlsx=sibling_xlsx,
    )

    docs_data = DOCS_DATA
    if not docs_data:
        try:
            from vcf_hci.web.docs_data import DOCS_DATA as _DD
            docs_data = _DD
        except Exception:
            docs_data = {}
    readme_data = (
        docs_data.get("user_guide_reference", {})
        or docs_data.get("readme", {})
    ) if isinstance(docs_data, dict) else {}
    readme_html_content = readme_data.get("html", "")
    if not readme_html_content:
        # Fallback reading README.md directly if available
        try:
            readme_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "README.md"))
            if os.path.exists(readme_path):
                with open(readme_path, encoding="utf-8") as rfh:
                    raw_md = rfh.read()
                # Basic conversion so raw formatting characters are rendered cleanly
                md_lines = []
                for line in raw_md.splitlines():
                    if line.startswith("# "):
                        md_lines.append(f"<h1>{_h(line[2:])}</h1>")
                    elif line.startswith("## "):
                        md_lines.append(f"<h2>{_h(line[3:])}</h2>")
                    elif line.startswith("### "):
                        md_lines.append(f"<h3>{_h(line[4:])}</h3>")
                    elif line.startswith("> "):
                        md_lines.append(f"<blockquote>{_h(line[2:])}</blockquote>")
                    elif line.startswith("- "):
                        md_lines.append(f"<li>{_h(line[2:])}</li>")
                    elif not line.strip():
                        md_lines.append("<br>")
                    else:
                        md_lines.append(f"<p>{_h(line)}</p>")
                readme_html_content = "\n".join(md_lines)
        except Exception:
            readme_html_content = "<p>User Guide & Documentation not available in offline bundle.</p>"

    if readme_html_content:
        # Strip dummy anchor wrappers like <a href="#"><img></a> and root-relative /docs/ links for offline file:// compatibility
        readme_html_content = re.sub(r'<a\s+href=["\']#["\']>(.*?)</a>', r'\1', readme_html_content)
        readme_html_content = re.sub(r'<a\s+href=["\']/(?:docs|api)[^"\']*["\'][^>]*>(.*?)</a>', r'\1', readme_html_content)

    readme_tab = (
        '<div class="container" style="padding-top:2rem">\n'
        '<div class="card" style="max-width:1200px;margin:0 auto;padding:2rem">\n'
        '  <div style="display:flex;align-items:center;justify-content:space-between;border-bottom:2px solid var(--border,#334155);padding-bottom:1rem;margin-bottom:1.5rem">\n'
        f'    <h1 style="margin:0;font-size:1.6rem">📖 VCF Readiness — User Guide &amp; Reference</h1>\n'
        f'    <span class="badge info" style="font-size:0.85rem">v{TOOL_VERSION} Standalone</span>\n'
        '  </div>\n'
        '  <div class="docs-embedded-content" style="line-height:1.65;font-size:0.92rem">\n'
        f'    {readme_html_content}\n'
        '  </div>\n'
        '</div>\n'
        '</div>'
    )

    picker_options = [f'<option value="">-- Jump to Host ({n_hosts}) --</option>']
    for i, d in enumerate(all_results):
        si = d.get("system", {}) if isinstance(d, dict) else {}
        ci = si.get("cpu_summary", {}) if isinstance(si, dict) else {}
        model = str(si.get("model", "") or "")
        verdict = str(ci.get("verdict", "") or "")
        tab_idx = i + 3
        if obfuscated:
            opt_lbl = f"Host-{i+1}"
            search_term = f"host-{i+1} {model} {verdict}".lower()
        else:
            h_name = str(si.get("hostname") or "")
            h_ip = str(si.get("ip") or "")
            if h_name and h_ip and h_name != h_ip:
                opt_lbl = f"{h_name} ({h_ip})"
            elif h_name:
                opt_lbl = h_name
            elif h_ip:
                opt_lbl = h_ip
            else:
                opt_lbl = f"Host {i+1}"
            search_term = f"{h_name} {h_ip} {model} {verdict}".lower()

        picker_options.append(
            f'<option value="{tab_idx}" data-search="{_xe(search_term)}">{_xe(opt_lbl)}</option>'
        )

    picker_html = (
        '<div class="host-picker-bar">'
        '<input type="text" id="host-picker-search" placeholder="🔍 Find host..." '
        'style="padding:.3rem .6rem;border-radius:4px;border:1px solid var(--border,#334155);background:var(--card,#1e293b);color:var(--text,#f8fafc);font-size:.82rem;width:150px;" '
        'title="Search by hostname, IP, model, or verdict" autocomplete="off">'
        '<select id="host-picker-select" style="padding:.3rem .6rem;border-radius:4px;border:1px solid var(--border,#334155);background:var(--card,#1e293b);color:var(--text,#f8fafc);font-size:.82rem;max-width:260px;" '
        'onchange="if(this.value) showTab(parseInt(this.value, 10))">\n'
        + "\n".join(picker_options) +
        '\n</select>'
        '</div>'
    )

    if mode == "inline":
        host_labels = [
            ((d.get("system") or {}).get("hostname") or (d.get("system") or {}).get("ip", f"Host {i+1}"))
            for i, d in enumerate(all_results)
        ]
        labels = ["Fleet Summary", "Detailed Inventory", "Help & Readme"] + host_labels

        def _tab_lbl(i, lbl):
            if i <= 2:
                if i == 2:
                    return f"📖 {html.escape(lbl)}"
                return html.escape(lbl)
            if obfuscated:
                return html.escape(lbl)
            return _pii(lbl)

        def _tab_btn_class(i):
            if i == 0:
                return "tab-btn tab-btn-summary active"
            elif i == 1:
                return "tab-btn tab-btn-inventory"
            elif i == 2:
                return "tab-btn tab-btn-help"
            return "tab-btn tab-btn-host"

        tab_btns = "\n".join(
            f'<button class="{_tab_btn_class(i)}" onclick="showTab({i})">'
            f'{_tab_lbl(i, lbl)}</button>'
            for i, lbl in enumerate(labels)
        ) + "\n" + picker_html
    else:
        fixed_btns = [
            '<button class="tab-btn tab-btn-summary active" onclick="showTab(0)">Fleet Summary</button>',
            '<button class="tab-btn tab-btn-inventory" onclick="showTab(1)">Detailed Inventory</button>',
            '<button class="tab-btn tab-btn-help" onclick="showTab(2)">📖 Help &amp; Readme</button>',
            '<button id="active-host-btn" class="tab-btn tab-btn-host" style="display:none;" onclick="var s = document.getElementById(\'host-picker-select\'); if (s && s.value) showTab(parseInt(s.value, 10));"></button>',
        ]
        tab_btns = "\n".join(fixed_btns) + "\n" + picker_html

    def _resolve_rel_report(i, d_sys):
        rp = None
        if isinstance(report_paths, (list, tuple)):
            if 0 <= i < len(report_paths):
                rp = report_paths[i]
        elif isinstance(report_paths, dict):
            target_key = d_sys.get("ip") or d_sys.get("hostname") or f"Host-{i+1}"
            rp = report_paths.get(target_key) or report_paths.get(i)

        if obfuscated:
            if rp and "obfuscated" in os.path.basename(rp).lower():
                if os.path.isabs(rp):
                    return os.path.relpath(rp, outdir).replace("\\", "/")
                return rp.replace("\\", "/")
            return f"reports/OBFUSCATED_Host-{i+1}.html"
        if rp:
            if os.path.isabs(rp):
                return os.path.relpath(rp, outdir).replace("\\", "/")
            if os.path.exists(os.path.join(outdir, rp)):
                return rp.replace("\\", "/")
            return os.path.relpath(os.path.abspath(rp), os.path.abspath(outdir)).replace("\\", "/")
        host_ip_str = d_sys.get("ip") or f"host_{i+1}"
        return f"reports/{sanitize_filename(f'vsphere_vsan_report_{host_ip_str}.html')}"

    panels = (
        '<div id="tab-0" class="tab-content active">__SUMMARY_TAB__</div>\n'
        '<div id="tab-1" class="tab-content">__INVENTORY_TAB__</div>\n'
        '<div id="tab-2" class="tab-content">__README_TAB__</div>\n'
    )
    if mode == "inline":
        for i, host_html in enumerate(host_html_list):
            safe_srcdoc = _h(host_html)
            d_host = all_results[i] if i < len(all_results) else {}
            d_sys = d_host.get("system", {}) if isinstance(d_host, dict) else {}
            d_ip = "" if obfuscated else str(d_sys.get("ip") or "")
            d_name = "" if obfuscated else str(d_sys.get("hostname") or d_sys.get("dns_name") or "")
            rel_p = _resolve_rel_report(i, d_sys)
            panels += (
                f'<div id="tab-{i+3}" class="tab-content" data-host-ip="{_xe(d_ip)}" data-hostname="{_xe(d_name)}" '
                f'data-src="{_xe(rel_p)}">'
                f'<iframe data-srcdoc="{safe_srcdoc}" style="width:100%;height:calc(100vh - 100px);border:none;" '
                f'title="Host Report {i+1}"></iframe></div>\n'
            )
    else:
        for i in range(n_hosts):
            d_host = all_results[i] if i < len(all_results) else {}
            d_sys = d_host.get("system", {}) if isinstance(d_host, dict) else {}
            d_ip = "" if obfuscated else str(d_sys.get("ip") or "")
            d_name = "" if obfuscated else str(d_sys.get("hostname") or d_sys.get("dns_name") or "")
            rel_p = _resolve_rel_report(i, d_sys)
            panels += (
                f'<div id="tab-{i+3}" class="tab-content" data-host-ip="{_xe(d_ip)}" data-hostname="{_xe(d_name)}" '
                f'data-src="{_xe(rel_p)}"></div>\n'
            )

    timestamp = time.strftime("%Y-%m-%d %H:%M")
    page_title = f"VCF Readiness{' (Obfuscated)' if obfuscated else ''} — {n_hosts} Host(s)"
    combined_template = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <title>{page_title}</title>
  <style>
{css_block}
    html,body{{margin:0;padding:0}}
    .tab-bar{{display:flex;background:#0f172a;padding:0 1rem;gap:4px;position:sticky;top:0;z-index:100;
              box-shadow:0 2px 8px rgba(0,0,0,.4);overflow-x:auto;align-items:center}}
    [data-theme='light'] .tab-bar{{background:#f1f5f9;box-shadow:0 2px 8px rgba(0,0,0,.1);border-bottom:1px solid #cbd5e1}}

    .host-picker-bar{{display:flex;align-items:center;margin-left:auto;gap:8px;padding:4px 0}}
    [data-theme='light'] #host-picker-search, [data-theme='light'] #host-picker-select{{
      background:#ffffff;color:#0f172a;border-color:#cbd5e1;
    }}

    .tab-btn{{padding:.75rem 1.15rem;cursor:pointer;color:#94a3b8;background:none;border:none;
              border-bottom:3px solid transparent;font-size:.84rem;font-weight:600;white-space:nowrap;
              border-radius:4px 4px 0 0;
              transition:color .12s,border-color .12s,background .12s}}
    [data-theme='light'] .tab-btn{{color:#64748b}}
    .tab-btn:hover{{color:#e2e8f0;background:#1e293b}}
    [data-theme='light'] .tab-btn:hover{{color:#0f172a;background:#e2e8f0}}
    .tab-btn.active{{color:#f1f5f9;border-bottom-color:#3b82f6;background:#1e293b}}
    [data-theme='light'] .tab-btn.active{{color:#0f172a;border-bottom-color:#2563eb;background:#ffffff}}

    /* Fleet Summary Tab (Royal Blue / Indigo Accent) */
    .tab-btn.tab-btn-summary{{color:#93c5fd;background:rgba(37,99,235,0.14);border-bottom:3px solid rgba(59,130,246,0.5)}}
    .tab-btn.tab-btn-summary:hover{{color:#bfdbfe;background:rgba(37,99,235,0.25);border-bottom-color:#60a5fa}}
    .tab-btn.tab-btn-summary.active{{color:#ffffff;background:rgba(37,99,235,0.38);border-bottom-color:#3b82f6;font-weight:700}}

    [data-theme='light'] .tab-btn.tab-btn-summary{{color:#1e40af;background:#dbeafe;border-bottom:3px solid #93c5fd}}
    [data-theme='light'] .tab-btn.tab-btn-summary:hover{{color:#1d4ed8;background:#bfdbfe;border-bottom-color:#3b82f6}}
    [data-theme='light'] .tab-btn.tab-btn-summary.active{{color:#1e3a8a;background:#ffffff;border-bottom-color:#1d4ed8;font-weight:700}}

    /* Detailed Inventory Tab (Emerald / Teal Accent) */
    .tab-btn.tab-btn-inventory{{color:#6ee7b7;background:rgba(5,150,105,0.14);border-bottom:3px solid rgba(16,185,129,0.5)}}
    .tab-btn.tab-btn-inventory:hover{{color:#a7f3d0;background:rgba(5,150,105,0.25);border-bottom-color:#34d399}}
    .tab-btn.tab-btn-inventory.active{{color:#ffffff;background:rgba(5,150,105,0.38);border-bottom-color:#10b981;font-weight:700}}

    [data-theme='light'] .tab-btn.tab-btn-inventory{{color:#065f46;background:#d1fae5;border-bottom:3px solid #6ee7b7}}
    [data-theme='light'] .tab-btn.tab-btn-inventory:hover{{color:#047857;background:#a7f3d0;border-bottom-color:#10b981}}
    [data-theme='light'] .tab-btn.tab-btn-inventory.active{{color:#064e3b;background:#ffffff;border-bottom-color:#059669;font-weight:700}}

    /* Help & Readme Tab (Amber / Gold Accent) */
    .tab-btn.tab-btn-help{{color:#fde047;background:rgba(217,119,6,0.14);border-bottom:3px solid rgba(245,158,11,0.5)}}
    .tab-btn.tab-btn-help:hover{{color:#fef08a;background:rgba(217,119,6,0.25);border-bottom-color:#fbbf24}}
    .tab-btn.tab-btn-help.active{{color:#ffffff;background:rgba(217,119,6,0.38);border-bottom-color:#f59e0b;font-weight:700}}

    [data-theme='light'] .tab-btn.tab-btn-help{{color:#92400e;background:#fef3c7;border-bottom:3px solid #fde047}}
    [data-theme='light'] .tab-btn.tab-btn-help:hover{{color:#78350f;background:#fde68a;border-bottom-color:#f59e0b}}
    [data-theme='light'] .tab-btn.tab-btn-help.active{{color:#451a03;background:#ffffff;border-bottom-color:#d97706;font-weight:700}}

    .docs-embedded-content h1{{font-size:1.6rem;border-bottom:2px solid var(--border,#334155);padding-bottom:.4rem;margin-top:0}}
    .docs-embedded-content h2{{font-size:1.3rem;border-bottom:1px solid var(--border,#334155);padding-bottom:.3rem;margin-top:1.5rem}}
    .docs-embedded-content h3{{font-size:1.05rem;margin-top:1.2rem}}
    .docs-embedded-content h4{{font-size:0.95rem;margin-top:1rem}}
    .docs-embedded-content a{{color:var(--primary,#60a5fa);text-decoration:none;font-weight:500}}
    .docs-embedded-content a:visited{{color:var(--primary,#60a5fa)}}
    .docs-embedded-content a:hover{{text-decoration:underline;color:#93c5fd}}
    .docs-embedded-content a code{{color:inherit;text-decoration:inherit}}
    .docs-embedded-content pre{{background:var(--code-bg,#0f172a);padding:1rem;border-radius:6px;overflow-x:auto}}
    .docs-embedded-content code{{background:var(--code-bg,#0f172a);padding:.2rem .4rem;border-radius:4px;font-family:monospace}}
    .docs-embedded-content pre code{{padding:0;background:none}}
    .docs-embedded-content table{{width:100%;border-collapse:collapse;margin:1rem 0}}
    .docs-embedded-content th, .docs-embedded-content td{{border:1px solid var(--border,#334155);padding:.5rem .75rem;text-align:left}}
    .docs-embedded-content th{{background:var(--th-bg,#1e293b)}}
    .docs-embedded-content blockquote{{border-left:4px solid var(--primary,#60a5fa);margin:1rem 0;padding:.5rem 1rem;background:var(--card,#1e293b)}}
    .docs-embedded-content ul, .docs-embedded-content ol{{padding-left:1.5rem;margin:.5rem 0 1rem}}
    .docs-embedded-content li{{margin-bottom:.25rem}}
    .docs-embedded-content hr{{border:none;border-top:1px solid var(--border,#334155);margin:1.5rem 0}}

    [data-theme='light'] .docs-embedded-content a{{color:#2563eb}}
    [data-theme='light'] .docs-embedded-content a:visited{{color:#2563eb}}
    [data-theme='light'] .docs-embedded-content a:hover{{color:#1d4ed8}}
    [data-theme='light'] .docs-embedded-content pre{{background:#f8fafc;border:1px solid #e2e8f0}}
    [data-theme='light'] .docs-embedded-content code{{background:#f1f5f9;color:#0f172a}}
    [data-theme='light'] .docs-embedded-content th{{background:#f8fafc}}
    [data-theme='light'] .docs-embedded-content th, [data-theme='light'] .docs-embedded-content td{{border-color:#e2e8f0}}
    [data-theme='light'] .docs-embedded-content h1, [data-theme='light'] .docs-embedded-content h2{{border-bottom-color:#e2e8f0}}
    [data-theme='light'] .docs-embedded-content blockquote{{background:#f8fafc;border-left-color:#2563eb}}
    [data-theme='light'] .docs-embedded-content hr{{border-top-color:#e2e8f0}}
    .docs-embedded-content h1, .docs-embedded-content h2, .docs-embedded-content h3, .docs-embedded-content h4{{scroll-margin-top:4.5rem}}

    .tab-content{{display:none}}.tab-content.active{{display:block}}
    body{{padding:0}}.container{{padding-top:1.5rem}}
    .sort-ind{{margin-left:.3rem;opacity:.35;font-size:.7rem;vertical-align:middle}}
    th.sorted .sort-ind{{opacity:1}}
    th{{cursor:pointer;user-select:none;position:relative}}
    .col-resizer{{position:absolute;top:0;right:0;width:5px;cursor:col-resize;user-select:none;height:100%;z-index:10}}
    .col-resizer:hover,.col-resizer.resizing{{background:var(--primary,#3b82f6);opacity:0.8}}

    /* Segmented Slider Toggle */
    .view-mode-toggle{{display:inline-flex;background:var(--code-bg,#0f172a);border:1px solid var(--border,#334155);border-radius:8px;padding:3px;gap:2px;user-select:none}}
    .view-mode-btn{{padding:.38rem .85rem;font-size:.82rem;font-weight:600;border:1px solid transparent;border-radius:6px;background:transparent;color:var(--text-muted,#94a3b8);cursor:pointer;display:inline-flex;align-items:center;gap:.4rem;transition:all .15s ease}}
    .view-mode-btn:hover{{color:var(--text,#f8fafc);background:rgba(255,255,255,0.05)}}
    .view-mode-btn.active{{background:var(--primary,#3b82f6);color:#ffffff;border-color:rgba(255,255,255,0.15);box-shadow:0 1px 3px rgba(0,0,0,0.25)}}
    [data-theme='light'] .view-mode-toggle{{background:#e2e8f0;border-color:#cbd5e1}}
    [data-theme='light'] .view-mode-btn{{color:#64748b}}
    [data-theme='light'] .view-mode-btn:hover{{color:#0f172a;background:rgba(0,0,0,0.04)}}
    [data-theme='light'] .view-mode-btn.active{{background:#2563eb;color:#ffffff}}

    /* Outlined Sub-Report Button */
    .btn-subreport-outline{{padding:.42rem .95rem;font-size:.82rem;font-weight:700;border:2px solid var(--primary,#3b82f6);background:rgba(59,130,246,0.12);color:var(--primary,#60a5fa);border-radius:6px;cursor:pointer;display:inline-flex;align-items:center;gap:.4rem;transition:all .15s ease}}
    .btn-subreport-outline:hover{{background:rgba(59,130,246,0.28);color:#ffffff;box-shadow:0 0 8px rgba(59,130,246,0.35)}}
    [data-theme='light'] .btn-subreport-outline{{border-color:#2563eb;background:#eff6ff;color:#1d4ed8}}
    [data-theme='light'] .btn-subreport-outline:hover{{background:#dbeafe;color:#1e40af}}

    /* Interactive Spec Cards in Simplified View */
    .host-spec-card-clickable{{cursor:pointer;position:relative;transition:transform .12s ease,border-color .15s ease,box-shadow .15s ease}}
    .host-spec-card-clickable:hover{{transform:translateY(-2px);border-color:var(--primary,#3b82f6);box-shadow:0 4px 12px rgba(59,130,246,0.2)}}
    .host-spec-card-clickable .jump-arrow{{position:absolute;top:0.6rem;right:0.75rem;font-size:0.85rem;opacity:0.4;transition:opacity .15s ease,transform .15s ease}}
    .host-spec-card-clickable:hover .jump-arrow{{opacity:1;transform:translate(2px,-2px);color:var(--primary,#60a5fa)}}
  </style>
</head>
<body>
<div class="tab-bar">{tab_btns}</div>
<script>
var _lruFrames = [];
var _subreportsState = 'unknown';
var _fallbackTimer = null;

window.addEventListener('message', function(ev) {{
  if (ev.data && ev.data.type === 'vcf-subreport-ready') {{
    _subreportsState = 'available';
    if (_fallbackTimer) {{
      clearTimeout(_fallbackTimer);
      _fallbackTimer = null;
    }}
  }}
}});

function _esc(s) {{
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}}

function syncIframeTheme(targetIframe) {{
  try {{
    var th = document.documentElement.getAttribute('data-theme') || 'dark';
    var ifr = targetIframe || document.querySelector('.tab-content.active iframe');
    if (ifr && ifr.contentDocument && ifr.contentDocument.documentElement) {{
      ifr.contentDocument.documentElement.setAttribute('data-theme', th);
      var ibtn = ifr.contentDocument.getElementById('themeToggle');
      if (ibtn) ibtn.textContent = th === 'dark' ? '🌙 Dark' : '☀️ Light';
    }}
  }} catch(e) {{}}
}}

function sendSubTabActivation(iframe, subTab, attempt) {{
  if (!iframe || !subTab) return;
  attempt = attempt || 0;
  var done = false;
  try {{
    if (iframe.contentWindow) {{
      iframe.contentWindow.postMessage({{ type: 'vcf_activate_tab', tab: subTab }}, '*');
    }}
    var iwin = iframe.contentWindow;
    var idoc = iframe.contentDocument || (iwin && iwin.document);
    if (iwin && typeof iwin.activateTab === 'function') {{
      done = iwin.activateTab(subTab, true);
    }} else if (idoc) {{
      var btn = idoc.querySelector('.tab-nav [data-tab="' + subTab + '"]') || idoc.querySelector('[data-tab="' + subTab + '"]');
      if (btn) {{
        btn.click();
        var inav = idoc.querySelector('.tab-nav');
        if (inav) {{
          setTimeout(function(){{
            try {{ inav.scrollIntoView({{ behavior: 'smooth', block: 'start' }}); }} catch(ex) {{ inav.scrollIntoView(true); }}
          }}, 40);
        }}
        done = true;
      }}
    }}
  }} catch(e) {{}}
  if (!done && attempt < 25) {{
    setTimeout(function(){{ sendSubTabActivation(iframe, subTab, attempt + 1); }}, 40);
  }}
}}

function attachIframeSync(iframe, n, subTab) {{
  syncIframeTheme(iframe);
  iframe.addEventListener('load', function(){{
    syncIframeTheme();
    syncIframeTheme(iframe);
    try {{
      if (iframe.contentDocument && iframe.contentDocument.title && !iframe.contentDocument.title.includes('404')) {{
        _subreportsState = 'available';
        if (_fallbackTimer) {{
          clearTimeout(_fallbackTimer);
          _fallbackTimer = null;
        }}
      }}
    }} catch(e) {{}}
    if (subTab) {{
      sendSubTabActivation(iframe, subTab);
    }}
  }});
}}

var _preferredViewMode = 'advanced';

function setHostViewMode(n, mode, subTab) {{
  var card = document.getElementById('card-tab-' + n);
  var wrap = document.getElementById('iframe-wrap-tab-' + n);
  var pane = document.getElementById('tab-' + n);
  if (!card || !wrap || !pane) return;

  if (!subTab) {{
    _preferredViewMode = mode;
  }}

  var btnSimple = document.getElementById('btn-mode-simple-' + n);
  var btnAdv = document.getElementById('btn-mode-advanced-' + n);
  var btnSimpleIfr = document.getElementById('btn-mode-simple-ifr-' + n);
  var btnAdvIfr = document.getElementById('btn-mode-advanced-ifr-' + n);

  if (mode === 'simplified') {{
    wrap.style.display = 'none';
    card.style.display = 'block';
    if (btnSimple) btnSimple.classList.add('active');
    if (btnAdv) btnAdv.classList.remove('active');
    if (btnSimpleIfr) btnSimpleIfr.classList.add('active');
    if (btnAdvIfr) btnAdvIfr.classList.remove('active');

    if (subTab) {{
      var targetSecId = null;
      if (subTab === 'tab-storage') targetSecId = 'host-drives-sec-' + n;
      else if (subTab === 'tab-network') targetSecId = 'host-nics-sec-' + n;
      else if (subTab === 'tab-health') targetSecId = 'host-health-sec-' + n;
      else if (subTab === 'tab-cpu' || subTab === 'tab-security') targetSecId = 'host-specs-grid-' + n;
      if (targetSecId) {{
        var el = document.getElementById(targetSecId);
        if (el) {{
          setTimeout(function(){{
            try {{ el.scrollIntoView({{ behavior: 'smooth', block: 'start' }}); }}
            catch(ex) {{ el.scrollIntoView(true); }}
          }}, 50);
        }}
      }}
    }}
  }} else {{
    card.style.display = 'none';
    wrap.style.display = 'block';
    if (btnSimple) btnSimple.classList.remove('active');
    if (btnAdv) btnAdv.classList.add('active');
    if (btnSimpleIfr) btnSimpleIfr.classList.remove('active');
    if (btnAdvIfr) btnAdvIfr.classList.add('active');

    var mount = document.getElementById('iframe-mount-' + n);
    var iframe = mount ? mount.querySelector('iframe') : null;
    if (!iframe && pane.hasAttribute('data-src')) {{
      iframe = document.createElement('iframe');
      iframe.style.width = '100%';
      iframe.style.height = 'calc(100vh - 100px)';
      iframe.style.border = 'none';
      iframe.title = 'Host Report ' + (n - 2);
      iframe.src = pane.getAttribute('data-src');
      var srcLbl = document.getElementById('iframe-src-label-' + n);
      if (srcLbl) srcLbl.textContent = pane.getAttribute('data-src');
      mount.appendChild(iframe);
      attachIframeSync(iframe, n, subTab);

      _lruFrames = _lruFrames.filter(function(x){{ return x !== n; }});
      _lruFrames.push(n);
      while (_lruFrames.length > 3) {{
        var oldN = _lruFrames.shift();
        var oldMount = document.getElementById('iframe-mount-' + oldN);
        if (oldMount) {{ oldMount.innerHTML = ''; }}
        var oldCard = document.getElementById('card-tab-' + oldN);
        var oldWrap = document.getElementById('iframe-wrap-tab-' + oldN);
        if (oldCard && oldWrap) {{
          oldWrap.style.display = 'none';
          oldCard.style.display = 'block';
          var oldSimple = document.getElementById('btn-mode-simple-' + oldN);
          var oldAdv = document.getElementById('btn-mode-advanced-' + oldN);
          if (oldSimple) oldSimple.classList.add('active');
          if (oldAdv) oldAdv.classList.remove('active');
        }}
      }}
    }} else if (iframe) {{
      if (!iframe.srcdoc && iframe.hasAttribute('data-srcdoc')) {{
        iframe.srcdoc = iframe.getAttribute('data-srcdoc');
        iframe.removeAttribute('data-srcdoc');
        attachIframeSync(iframe, n, subTab);
      }}
      if (subTab) {{
        sendSubTabActivation(iframe, subTab);
      }}
    }}
  }}
}}

function toggleHostSubreport(n, subTab) {{
  var wrap = document.getElementById('iframe-wrap-tab-' + n);
  var isShowingIframe = (wrap && wrap.style.display !== 'none');
  setHostViewMode(n, isShowingIframe ? 'simplified' : 'advanced', subTab);
}}

function handleSpecCardClick(n, targetSubTab, fallbackSecId) {{
  if (_subreportsState === 'unavailable') {{
    var sec = document.getElementById(fallbackSecId);
    if (sec) {{
      setTimeout(function(){{
        try {{ sec.scrollIntoView({{ behavior: 'smooth', block: 'start' }}); }}
        catch(ex) {{ sec.scrollIntoView(true); }}
      }}, 50);
    }}
  }} else {{
    setHostViewMode(n, 'advanced', targetSubTab);
  }}
}}

function renderEmbeddedHostCard(n, pane) {{
  if (document.getElementById('card-tab-' + n)) return true;

  var hostIdx = n - 3;
  var invScript = document.getElementById('fleet-inv-data');
  if (!invScript) return false;
  var invData;
  try {{
    invData = JSON.parse(invScript.textContent);
  }} catch(e) {{
    return false;
  }}
  if (!invData || !invData.hosts || !invData.hosts[hostIdx]) return false;

  var h = invData.hosts[hostIdx];
  var hostDrives = (invData.drives || []).filter(function(d){{ return d.host_idx === hostIdx; }});
  var hostNics = (invData.nics || []).filter(function(ni){{ return ni.host_idx === hostIdx; }});
  var hostHealth = (invData.health || []).filter(function(hl){{ return hl.host_idx === hostIdx; }});

  var container = document.createElement('div');
  container.className = 'host-embedded-card';
  container.id = 'card-tab-' + n;
  container.style.padding = '0 1rem 2rem';

  var targetSrc = pane.getAttribute('data-src') || (pane.querySelector('iframe') ? (pane.querySelector('iframe').getAttribute('src') || '') : '') || ('reports/OBFUSCATED_Host-' + (hostIdx + 1) + '.html');

  // Header & Controls
  var headerHtml = '<div style="display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--border,#334155);padding:1rem 0;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem">' +
    '<div>' +
      '<div style="display:flex;align-items:center;gap:.6rem;flex-wrap:wrap">' +
        '<h1 style="margin:0;font-size:1.6rem;color:var(--h-color,#f8fafc)">🖥️ <span>' + _esc(h.hostname || ('Host ' + (hostIdx + 1))) + '</span></h1>' +
        '<span class="badge info" style="font-size:.85rem">' + _esc((h.vendor ? h.vendor + ' ' : '') + (h.model || '')) + '</span>' +
        (h.ip ? '<span class="badge" style="font-size:.85rem;background:var(--code-bg,#263548);border:1px solid var(--border,#334155)">' + _esc(h.ip) + '</span>' : '') +
      '</div>' +
      '<div style="color:var(--text-muted,#94a3b8);font-size:.85rem;margin-top:.4rem">' +
        'Sub-report target: <code>' + _esc(targetSrc) + '</code>' +
      '</div>' +
    '</div>' +
    '<div style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap">' +
      '<div class="view-mode-toggle" id="view-mode-toggle-' + n + '">' +
        '<button type="button" class="view-mode-btn active" id="btn-mode-simple-' + n + '" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="simplified">' +
          '📄 Simplified Host View' +
        '</button>' +
        '<button type="button" class="view-mode-btn" id="btn-mode-advanced-' + n + '" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="advanced">' +
          '🔬 Advanced Report View' +
        '</button>' +
      '</div>' +
    '</div>' +
  '</div>';

  // Offline Notice Banner
  var bannerHtml = '<div class="alert alert-info" id="host-banner-' + n + '" style="margin-bottom:1.5rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem">' +
    '<div>ℹ️ <strong>Simplified Host View:</strong> Consolidated Host Specifications from fleet scan data.</div>' +
    '<button type="button" class="btn-subreport-outline" id="btn-toggle-subreport-' + n + '" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="advanced">' +
      '🔬 Switch to Advanced Report View' +
    '</button>' +
  '</div>';

  // Overview Cards Grid
  var secBadge = h.sec_badge || (h.tpm_ok ? '<span class="badge success">TPM 2.0 OK</span>' : '<span class="badge danger">TPM Action Req</span>');
  var gridHtml = '<div class="grid" id="host-specs-grid-' + n + '" style="margin-bottom:1.5rem">' +
    '<div class="card host-spec-card-clickable" data-action="spec-card-click" data-host-idx="' + n + '" data-subtab="tab-cpu" data-target-sec="host-specs-grid-' + n + '" title="Click to view CPU details in Advanced Report">' +
      '<span class="jump-arrow">↗</span>' +
      '<div style="font-size:.78rem;font-weight:700;color:var(--text-muted,#94a3b8);text-transform:uppercase;letter-spacing:.03em">CPU Compatibility</div>' +
      '<div style="font-size:1.15rem;font-weight:700;margin:.35rem 0 .2rem;color:var(--h-color,#f8fafc)">' + (h.cpu_verdict ? h.cpu_verdict : 'N/A') + '</div>' +
      '<div style="font-size:.85rem;color:var(--text-muted,#94a3b8)">' + _esc(h.cpu_model || 'Unknown CPU') + '</div>' +
    '</div>' +
    '<div class="card host-spec-card-clickable" data-action="spec-card-click" data-host-idx="' + n + '" data-subtab="tab-memory" data-target-sec="host-specs-grid-' + n + '" title="Click to view Memory details in Advanced Report">' +
      '<span class="jump-arrow">↗</span>' +
      '<div style="font-size:.78rem;font-weight:700;color:var(--text-muted,#94a3b8);text-transform:uppercase;letter-spacing:.03em">Memory &amp; Population</div>' +
      '<div style="font-size:1.15rem;font-weight:700;margin:.35rem 0 .2rem;color:var(--h-color,#f8fafc)">' + (h.ram_gb || 0) + ' GB <span style="font-size:.85rem;font-weight:500;color:var(--text-muted,#94a3b8)">(' + (h.dimm_count || 0) + ' DIMMs)</span></div>' +
      '<div style="font-size:.85rem;color:var(--text-muted,#94a3b8)">Interleaving: <strong>' + _esc(h.interleaving_str || 'N/A') + '</strong></div>' +
    '</div>' +
    '<div class="card host-spec-card-clickable" data-action="spec-card-click" data-host-idx="' + n + '" data-subtab="tab-storage" data-target-sec="host-drives-sec-' + n + '" title="Click to view Storage &amp; vSAN details in Advanced Report">' +
      '<span class="jump-arrow">↗</span>' +
      '<div style="font-size:.78rem;font-weight:700;color:var(--text-muted,#94a3b8);text-transform:uppercase;letter-spacing:.03em">vSAN ESA / OSA Readiness</div>' +
      '<div style="font-size:1.15rem;font-weight:700;margin:.35rem 0 .2rem;color:var(--h-color,#f8fafc)">' + _esc(h.esa_tier || 'N/A') + '</div>' +
      '<div style="font-size:.85rem;color:var(--text-muted,#94a3b8)">' + _esc(h.esa_profile || '') + (h.esa_display ? ' · ' + _esc(h.esa_display) : '') + '</div>' +
    '</div>' +
    '<div class="card host-spec-card-clickable" data-action="spec-card-click" data-host-idx="' + n + '" data-subtab="tab-network" data-target-sec="host-nics-sec-' + n + '" title="Click to view Network details in Advanced Report">' +
      '<span class="jump-arrow">↗</span>' +
      '<div style="font-size:.78rem;font-weight:700;color:var(--text-muted,#94a3b8);text-transform:uppercase;letter-spacing:.03em">Network Connectivity</div>' +
      '<div style="font-size:1.15rem;font-weight:700;margin:.35rem 0 .2rem;color:var(--h-color,#f8fafc)">' + (h.nic_max_gbps || 0) + ' Gbps Max</div>' +
      '<div style="font-size:.85rem;color:var(--text-muted,#94a3b8)">' + _esc(h.nic_display || 'No NICs recorded') + '</div>' +
    '</div>' +
    '<div class="card host-spec-card-clickable" data-action="spec-card-click" data-host-idx="' + n + '" data-subtab="tab-security" data-target-sec="host-health-sec-' + n + '" title="Click to view Security &amp; TPM details in Advanced Report">' +
      '<span class="jump-arrow">↗</span>' +
      '<div style="font-size:.78rem;font-weight:700;color:var(--text-muted,#94a3b8);text-transform:uppercase;letter-spacing:.03em">Security Baseline &amp; TPM</div>' +
      '<div style="margin:.35rem 0 .2rem">' + secBadge + '</div>' +
      '<div style="font-size:.85rem;color:var(--text-muted,#94a3b8)">TPM 2.0: ' + (h.tpm_ok ? '🟢 Enabled' : '🔴 Missing/Disabled') + ' · VMD: ' + (h.vmd_on ? '⚠️ Enabled' : '🟢 Disabled') + '</div>' +
    '</div>' +
  '</div>';

  // Storage Drives Section
  var drivesHtml = '<h2 id="host-drives-sec-' + n + '" style="margin:1.8rem 0 .75rem;font-size:1.15rem;color:var(--h-color,#f8fafc)">💾 Storage Subsystem (' + hostDrives.length + ' Drives)</h2>';
  if (hostDrives.length > 0) {{
    drivesHtml += '<div style="overflow-x:auto;margin-bottom:1.5rem"><table><thead><tr>' +
      '<th>Drive / Controller</th><th>Model</th><th>Type</th><th>Protocol</th><th>Capacity</th><th>Firmware</th><th>Endurance</th><th>vSAN Category</th><th>Status</th>' +
    '</tr></thead><tbody>';
    hostDrives.forEach(function(d){{
      var capStr = d.capacity_gb ? (d.capacity_gb >= 1000 ? (d.capacity_gb / 1000).toFixed(1) + ' TB' : Number(d.capacity_gb).toFixed(0) + ' GB') : 'N/A';
      var endStr = (d.endurance_pct !== null && d.endurance_pct !== undefined) ? d.endurance_pct + '%' : 'N/A';
      var statusBadge = (d.drive_health === 'OK' || d.drive_health === 'Good') ? '<span class="badge success">OK</span>' : '<span class="badge warning">' + _esc(d.drive_health || 'Unknown') + '</span>';
      drivesHtml += '<tr>' +
        '<td><strong>' + _esc(d.ctrl_name || 'Direct / Unknown') + '</strong></td>' +
        '<td>' + _esc(d.model || 'Unknown Model') + '</td>' +
        '<td>' + _esc(d.media_type || 'N/A') + '</td>' +
        '<td>' + _esc(d.protocol || 'N/A') + '</td>' +
        '<td>' + capStr + '</td>' +
        '<td><code>' + _esc(d.firmware || 'N/A') + '</code></td>' +
        '<td>' + endStr + '</td>' +
        '<td>' + _esc(d.category || 'N/A') + '</td>' +
        '<td>' + statusBadge + '</td>' +
      '</tr>';
    }});
    drivesHtml += '</tbody></table></div>';
  }} else {{
    drivesHtml += '<p style="color:var(--text-muted,#94a3b8);margin-bottom:1.5rem">No storage drives recorded for this host.</p>';
  }}

  // Network Interfaces Section
  var nicsHtml = '<h2 id="host-nics-sec-' + n + '" style="margin:1.8rem 0 .75rem;font-size:1.15rem;color:var(--h-color,#f8fafc)">🌐 Network Interfaces (' + hostNics.length + ' Ports)</h2>';
  if (hostNics.length > 0) {{
    nicsHtml += '<div style="overflow-x:auto;margin-bottom:1.5rem"><table><thead><tr>' +
      '<th>Adapter</th><th>Port ID</th><th>Speed</th><th>Link Status</th><th>MAC Address</th><th>Firmware</th><th>ESA ≥25G</th>' +
    '</tr></thead><tbody>';
    hostNics.forEach(function(ni){{
      var speedStr = ni.speed_gbps ? ni.speed_gbps + ' Gbps' : 'N/A';
      var linkBadge = (ni.link_status === 'Up' || ni.link_status === 'LinkUp') ? '<span class="badge success">Up</span>' : '<span class="badge" style="background:var(--code-bg);color:var(--text-muted)">' + _esc(ni.link_status || 'Down') + '</span>';
      var esaBadge = ni.meets_25g ? '<span class="badge success">🟢 Yes</span>' : '<span class="badge warning">🟡 &lt;25G</span>';
      nicsHtml += '<tr>' +
        '<td><strong>' + _esc(ni.adapter || 'Integrated NIC') + '</strong></td>' +
        '<td>' + _esc(ni.port_id || 'Port') + '</td>' +
        '<td>' + speedStr + '</td>' +
        '<td>' + linkBadge + '</td>' +
        '<td><code>' + _esc(ni.mac_address || '02:00:00:00:00:00') + '</code></td>' +
        '<td><code>' + _esc(ni.firmware || 'N/A') + '</code></td>' +
        '<td>' + esaBadge + '</td>' +
      '</tr>';
    }});
    nicsHtml += '</tbody></table></div>';
  }} else {{
    nicsHtml += '<p style="color:var(--text-muted,#94a3b8);margin-bottom:1.5rem">No network interfaces recorded for this host.</p>';
  }}

  // Health Alarms Section
  var healthHtml = '<h2 id="host-health-sec-' + n + '" style="margin:1.8rem 0 .75rem;font-size:1.15rem;color:var(--h-color,#f8fafc)">⚠️ Health Alarms &amp; Event Logs (' + hostHealth.length + ' Items)</h2>';
  if (hostHealth.length > 0) {{
    healthHtml += '<div style="overflow-x:auto;margin-bottom:1.5rem"><table><thead><tr>' +
      '<th>Severity</th><th>Subsystem</th><th>Message</th><th>Target</th><th>Timestamp</th>' +
    '</tr></thead><tbody>';
    hostHealth.forEach(function(hl){{
      var sev = String(hl.severity || 'Warning');
      var sevBadge = '<span class="badge ' + (sev === 'Critical' ? 'danger' : (sev === 'Warning' ? 'warning' : 'info')) + '">' + _esc(sev) + '</span>';
      healthHtml += '<tr>' +
        '<td>' + sevBadge + '</td>' +
        '<td><strong>' + _esc(hl.subsystem || 'System') + '</strong></td>' +
        '<td>' + _esc(hl.message || '') + '</td>' +
        '<td><code>' + _esc(hl.target || 'System') + '</code></td>' +
        '<td style="font-size:.82rem;color:var(--text-muted,#94a3b8);white-space:nowrap">' + _esc(hl.timestamp || 'N/A') + '</td>' +
      '</tr>';
    }});
    healthHtml += '</tbody></table></div>';
  }} else {{
    healthHtml += '<div class="alert alert-success" style="margin-top:1rem">🟢 No active health alarms or critical SEL events recorded for this host.</div>';
  }}

  container.innerHTML = headerHtml + bannerHtml + gridHtml + drivesHtml + nicsHtml + healthHtml;

  var iframeWrapper = document.createElement('div');
  iframeWrapper.className = 'host-iframe-wrapper';
  iframeWrapper.id = 'iframe-wrap-tab-' + n;
  iframeWrapper.style.display = 'none';
  iframeWrapper.innerHTML = '<div style="background:var(--th-bg,#1e293b);padding:.5rem 1rem;border-bottom:1px solid var(--border,#334155);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.75rem">' +
    '<div style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap">' +
      '      <div class="view-mode-toggle" id="view-mode-toggle-iframe-' + n + '">' +
        '<button type="button" class="view-mode-btn" id="btn-mode-simple-ifr-' + n + '" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="simplified">' +
          '📄 Simplified Host View' +
        '</button>' +
        '<button type="button" class="view-mode-btn active" id="btn-mode-advanced-ifr-' + n + '" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="advanced">' +
          '🔬 Advanced Report View' +
        '</button>' +
      '</div>' +
      '<span style="font-size:.82rem;color:var(--text-muted,#94a3b8)">Sub-report: <code id="iframe-src-label-' + n + '">' + _esc(targetSrc) + '</code></span>' +
    '</div>' +
    '<div style="display:flex;align-items:center;gap:.5rem">' +
      '<button type="button" class="inv-btn" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="simplified" style="padding:.3rem .75rem;font-size:.8rem" title="Return to Consolidated Host Specifications">' +
        '⬅ Return to Consolidated Host Specifications' +
      '</button>' +
      '<button type="button" class="inv-btn" data-action="open-tab-src" data-src="' + _esc(targetSrc) + '" style="padding:.3rem .75rem;font-size:.8rem" title="Open full sub-report in separate browser tab">' +
        '↗ Open in New Tab' +
      '</button>' +
    '</div>' +
  '</div>' +
  '<div id="iframe-mount-' + n + '"></div>';

  var existingIframe = pane.querySelector('iframe');
  if (existingIframe) {{
    existingIframe.style.height = 'calc(100vh - 100px)';
    var mount = iframeWrapper.querySelector('#iframe-mount-' + n);
    if (mount) {{
      mount.appendChild(existingIframe);
    }}
  }}

  pane.appendChild(container);
  pane.appendChild(iframeWrapper);
  return true;
}}

function showTab(n, subTab){{
  document.querySelectorAll('.tab-content').forEach(function(el){{
    el.classList.toggle('active', el.id === 'tab-' + n);
  }});
  var activeBtn = null;
  document.querySelectorAll('.tab-btn').forEach(function(el, i){{
    var isActive = (i === n);
    el.classList.toggle('active', isActive);
    if (isActive) activeBtn = el;
  }});

  var hostSelect = document.getElementById('host-picker-select');
  var activeHostBtn = document.getElementById('active-host-btn');
  if (hostSelect) {{
    if (n >= 3) {{
      hostSelect.value = String(n);
      if (activeHostBtn) {{
        var selOpt = hostSelect.options[hostSelect.selectedIndex];
        activeHostBtn.textContent = '🖥️ ' + (selOpt ? selOpt.textContent : ('Host ' + (n - 2)));
        activeHostBtn.style.display = 'inline-block';
        activeHostBtn.classList.add('active');
        activeBtn = activeHostBtn;
      }}
    }} else {{
      hostSelect.value = '';
      if (activeHostBtn) {{
        activeHostBtn.classList.remove('active');
        activeHostBtn.style.display = 'none';
      }}
    }}
  }}

  if (activeBtn && typeof activeBtn.scrollIntoView === 'function') {{
    try {{
      activeBtn.scrollIntoView({{ behavior: 'smooth', block: 'nearest', inline: 'nearest' }});
    }} catch(e) {{}}
  }}
  window.scrollTo(0, 0);

  try {{
    if (history.replaceState) {{
      var h = '#tab-' + n + (subTab ? ':' + subTab : '');
      history.replaceState(null, '', h);
    }}
  }} catch(e) {{}}

  if (n >= 3) {{
    var pane = document.getElementById('tab-' + n);
    if (pane) {{
      var hasCard = renderEmbeddedHostCard(n, pane);
      if (hasCard) {{
        var isInline = !!(pane.querySelector('iframe[srcdoc], iframe[data-srcdoc]'));
        var targetMode = subTab ? 'advanced' : (_subreportsState === 'unavailable' ? 'simplified' : _preferredViewMode);
        setHostViewMode(n, targetMode, subTab);
        if (!isInline && _subreportsState === 'unknown' && targetMode === 'advanced') {{
          if (_fallbackTimer) clearTimeout(_fallbackTimer);
          _fallbackTimer = setTimeout(function() {{
            _fallbackTimer = null;
            if (_subreportsState === 'unknown') {{
              _subreportsState = 'unavailable';
              setHostViewMode(n, 'simplified', subTab);
              var banner = document.getElementById('host-banner-' + n);
              if (banner) {{
                banner.className = 'alert alert-warning';
                banner.innerHTML = '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem;width:100%">' +
                  '<div>⚠️ <strong>Sub-report file not found:</strong> Could not load <code>' + _esc(pane.getAttribute('data-src')) + '</code>. Showing Simplified Host View (Consolidated Host Specifications).</div>' +
                  '<button type="button" class="btn-subreport-outline" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="advanced">Retry Loading 🔬</button>' +
                '</div>';
              }}
            }}
          }}, 1200);
        }}
      }} else {{
        // Fallback for environments without fleet-inv-data
        var iframe = pane.querySelector('iframe');
        if (iframe) {{
          if (!iframe.srcdoc && iframe.hasAttribute('data-srcdoc')) {{
            iframe.srcdoc = iframe.getAttribute('data-srcdoc');
            iframe.removeAttribute('data-srcdoc');
            attachIframeSync(iframe, n, subTab);
          }}
          sendSubTabActivation(iframe, subTab);
          iframe.addEventListener('load', function(){{ sendSubTabActivation(iframe, subTab); }}, {{once: true}});
        }} else if (pane.hasAttribute('data-src')) {{
          iframe = document.createElement('iframe');
          iframe.style.width = '100%';
          iframe.style.height = 'calc(100vh - 50px)';
          iframe.style.border = 'none';
          iframe.title = 'Host Report ' + (n - 2);
          iframe.src = pane.getAttribute('data-src');
          pane.appendChild(iframe);
          attachIframeSync(iframe, n, subTab);
        }}
      }}
    }}
  }}
}}
window.showTab = showTab;

(function initHostPicker(){{
  var hostSearch = document.getElementById('host-picker-search');
  var hostSelect = document.getElementById('host-picker-select');
  if (!hostSearch || !hostSelect) return;
  var allOptions = Array.from(hostSelect.options).slice(1);
  hostSearch.addEventListener('input', function() {{
    var q = hostSearch.value.trim().toLowerCase();
    allOptions.forEach(function(opt) {{
      var s = (opt.getAttribute('data-search') || opt.textContent).toLowerCase();
      opt.style.display = (q === '' || s.indexOf(q) !== -1) ? '' : 'none';
    }});
  }});
  hostSearch.addEventListener('keydown', function(e) {{
    if (e.key === 'Enter') {{
      e.preventDefault();
      var q = hostSearch.value.trim().toLowerCase();
      var firstMatch = allOptions.find(function(opt) {{
        var s = (opt.getAttribute('data-search') || opt.textContent).toLowerCase();
        return (q === '' || s.indexOf(q) !== -1);
      }});
      if (firstMatch) {{
        hostSelect.value = firstMatch.value;
        showTab(parseInt(firstMatch.value, 10));
      }}
    }}
  }});
}})();

function handleHashChange(){{
  var rawHash = (location.hash || '').replace(/^#/, '').trim();
  if (!rawHash) return;

  var match = rawHash.match(/^tab-(\\d+)(?:[:/_-](tab-[a-z0-9_-]+|[a-z0-9_-]+))?$/i);
  if (match) {{
    var tabNum = parseInt(match[1], 10);
    var sub = match[2] || '';
    if (sub && !sub.startsWith('tab-') && !sub.startsWith('inv-')) sub = 'tab-' + sub;
    showTab(tabNum, sub);
    return;
  }}

  var ipMatch = rawHash.match(/^([0-9a-z.-]+)(?:[:/_-](tab-[a-z0-9_-]+|[a-z0-9_-]+))?$/i);
  if (ipMatch) {{
    var hostId = ipMatch[1];
    var subId = ipMatch[2] || '';
    if (subId && !subId.startsWith('tab-') && !subId.startsWith('inv-')) subId = 'tab-' + subId;
    var foundPane = document.querySelector('.tab-content[data-host-ip="' + hostId + '"]') ||
                    document.querySelector('.tab-content[data-hostname="' + hostId + '"]');
    if (foundPane && foundPane.id) {{
      var n = parseInt(foundPane.id.replace('tab-', ''), 10);
      if (!isNaN(n)) {{
        showTab(n, subId);
        return;
      }}
    }}
  }}

  var subName = rawHash.toLowerCase();
  if (subName === 'tab-security' || subName === 'security') {{
    var activePane = document.querySelector('.tab-content.active');
    if (activePane && activePane.id && parseInt(activePane.id.replace('tab-', ''), 10) >= 3) {{
      var hostN = parseInt(activePane.id.replace('tab-', ''), 10);
      showTab(hostN, 'tab-security');
    }} else {{
      showTab(1);
      var fn = window.showInvView || window.showInvTab;
      if (fn) fn('security');
    }}
    return;
  }}
  if (subName === 'tab-cpu' || subName === 'cpu') {{
    var activePane = document.querySelector('.tab-content.active');
    if (activePane && activePane.id && parseInt(activePane.id.replace('tab-', ''), 10) >= 3) {{
      var hostN = parseInt(activePane.id.replace('tab-', ''), 10);
      showTab(hostN, 'tab-cpu');
    }} else {{
      showTab(1);
      var fn = window.showInvView || window.showInvTab;
      if (fn) fn('hosts');
    }}
    return;
  }}

  if (subName.startsWith('inv-') || ['hosts','drives','nics','bios','health'].indexOf(subName) !== -1) {{
    showTab(1);
    var vName = subName.replace('inv-', '');
    var fn = window.showInvView || window.showInvTab;
    if (fn) fn(vName);
    return;
  }}
}}

window.addEventListener('hashchange', handleHashChange);
if (document.readyState === 'loading') {{
  document.addEventListener('DOMContentLoaded', handleHashChange);
}} else {{
  handleHashChange();
}}

document.addEventListener('click', function(e) {{
  if (!e.target || !e.target.closest) return;

  var target = e.target.closest('.tab-jump');
  if (target) {{
    var t = parseInt(target.getAttribute('data-tab') || target.dataset.tab, 10);
    var sub = target.getAttribute('data-subtab') || target.dataset.subtab || '';
    if (!isNaN(t)) {{
      e.preventDefault();
      showTab(t, sub);
    }}
    return;
  }}

  var actionEl = e.target.closest('[data-action]');
  if (actionEl) {{
    var action = actionEl.getAttribute('data-action');
    if (action === 'set-view-mode') {{
      e.preventDefault();
      var hostIdx = parseInt(actionEl.getAttribute('data-host-idx'), 10);
      var mode = actionEl.getAttribute('data-mode');
      if (!isNaN(hostIdx) && mode) {{
        setHostViewMode(hostIdx, mode);
      }}
    }} else if (action === 'spec-card-click') {{
      e.preventDefault();
      var hostIdx = parseInt(actionEl.getAttribute('data-host-idx'), 10);
      var subTab = actionEl.getAttribute('data-subtab') || '';
      var targetSec = actionEl.getAttribute('data-target-sec') || '';
      if (!isNaN(hostIdx)) {{
        handleSpecCardClick(hostIdx, subTab, targetSec);
      }}
    }} else if (action === 'open-tab-src') {{
      e.preventDefault();
      var src = actionEl.getAttribute('data-src');
      if (src) {{
        window.open(src, '_blank');
      }}
    }}
  }}
}});
</script>
{panels}
<script>
var table = document.querySelector('.sortable-table');
if (table) {{
  var summaryPager = window.initFleetTablePager ? window.initFleetTablePager({{
    table: table,
    rowSelector: 'tbody tr',
    pageSizeSelect: '#sumPageSize',
    prevBtn: '#sumPrevBtn',
    nextBtn: '#sumNextBtn',
    pageInfo: '#sumPageInfo',
    warnEl: '#sumPageWarn',
    filterFn: function(row) {{
      var oem = (document.getElementById('oem-filter') || {{}}).value || 'all';
      var hideUnsup = (document.getElementById('hide-unsupported') || {{}}).checked || false;
      var vendor = row.getAttribute('data-vendor') || '';
      var unsup  = row.getAttribute('data-unsupported') === '1';
      if (oem !== 'all' && vendor !== oem) return false;
      if (hideUnsup && unsup) return false;
      return true;
    }}
  }}) : null;

  var headers = table.querySelectorAll('thead th');
  var sortState = {{}};

  headers.forEach(function(th, colIdx) {{
    th.addEventListener('click', function() {{
      var tbody = table.querySelector('tbody');
      var rows = Array.from(tbody.querySelectorAll('tr'));
      var dir = (sortState[colIdx] === 'asc') ? -1 : 1;
      sortState = {{}};
      sortState[colIdx] = (dir === 1) ? 'asc' : 'desc';

      headers.forEach(function(h, i) {{
        h.classList.remove('sorted');
        var ind = h.querySelector('.sort-ind');
        if (ind) ind.textContent = (i === colIdx) ? (dir === 1 ? '\\u25b2' : '\\u25bc') : '\\u21c5';
      }});
      th.classList.add('sorted');

      rows.sort(function(a, b) {{
        var aCell = a.querySelectorAll('td')[colIdx];
        var bCell = b.querySelectorAll('td')[colIdx];
        if (!aCell || !bCell) return 0;
        var aVal = (aCell.hasAttribute('data-sort') ? aCell.getAttribute('data-sort') : aCell.textContent).trim();
        var bVal = (bCell.hasAttribute('data-sort') ? bCell.getAttribute('data-sort') : bCell.textContent).trim();
        var aNum = parseFloat(aVal), bNum = parseFloat(bVal);
        if (!isNaN(aNum) && !isNaN(bNum)) return dir * (aNum - bNum);
        return dir * aVal.toLowerCase().localeCompare(bVal.toLowerCase());
      }});
      rows.forEach(function(row) {{ tbody.appendChild(row); }});
      if (summaryPager) {{
        summaryPager.update();
      }} else {{
        applyTableFilters();
      }}
    }});
  }});

  function applyTableFilters() {{
    if (summaryPager) {{
      summaryPager.setPage(1);
    }} else {{
      var oem = (document.getElementById('oem-filter') || {{}}).value || 'all';
      var hideUnsup = (document.getElementById('hide-unsupported') || {{}}).checked || false;
      var tbody = table.querySelector('tbody');
      if (!tbody) return;
      Array.from(tbody.querySelectorAll('tr')).forEach(function(row) {{
        var vendor = row.getAttribute('data-vendor') || '';
        var unsup  = row.getAttribute('data-unsupported') === '1';
        var show = true;
        if (oem !== 'all' && vendor !== oem) show = false;
        if (hideUnsup && unsup) show = false;
        row.style.display = show ? '' : 'none';
      }});
    }}
  }}

  var oemSel = document.getElementById('oem-filter');
  var hideChk = document.getElementById('hide-unsupported');
  if (oemSel) oemSel.addEventListener('change', applyTableFilters);
  if (hideChk) hideChk.addEventListener('change', applyTableFilters);
}}

(function initCombinedResizers(){{
  document.querySelectorAll('table.sortable-table, table.inv-table').forEach(function(table){{
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
}})();

(function(){{
  var cb = document.getElementById('maskPII');
  var dlBtn = document.getElementById('dlObf');
  var dlCombBtn = document.getElementById('dlObfCombined');

  if (cb) {{
    cb.addEventListener('change', function() {{
      var isMasked = cb.checked;
      document.querySelectorAll('.pii').forEach(function(el) {{
        el.textContent = isMasked ? el.dataset.mask : el.dataset.real;
      }});
      var thMac = document.getElementById('thNicMac');
      if (thMac) {{
        thMac.innerHTML = isMasked ? 'MAC <em>(obfuscated)</em>' : 'MAC';
      }}
      if (dlBtn) dlBtn.style.display = isMasked ? 'inline-block' : 'none';
      document.querySelectorAll('iframe').forEach(function(iframe) {{
        try {{
          if (iframe.contentDocument) {{
            var icb = iframe.contentDocument.getElementById('maskPII');
            if (icb) {{
              icb.checked = isMasked;
              icb.dispatchEvent(new Event('change'));
            }} else {{
              iframe.contentDocument.querySelectorAll('.pii').forEach(function(el) {{
                el.textContent = isMasked ? el.dataset.mask : el.dataset.real;
              }});
            }}
          }}
        }} catch(e){{}}
      }});
    }});
  }}

  function downloadObfuscatedCombined(e) {{
    if (e) e.preventDefault();
    var clone = document.documentElement.cloneNode(true);
    clone.querySelectorAll('.pii').forEach(function(el) {{
      var mask = el.dataset.mask || el.textContent;
      el.textContent = mask;
      el.removeAttribute('data-real');
      el.setAttribute('data-mask', mask);
    }});
    clone.querySelectorAll('[data-host-ip]').forEach(function(el) {{
      el.removeAttribute('data-host-ip');
    }});
    clone.querySelectorAll('[data-hostname]').forEach(function(el) {{
      el.removeAttribute('data-hostname');
    }});

    var thMacClone = clone.querySelector('#thNicMac');
    if (thMacClone) {{
      thMacClone.innerHTML = 'MAC <em>(obfuscated)</em>';
    }}

    // Reset and sanitize sidecar host panes
    clone.querySelectorAll('.tab-content[data-src]').forEach(function(pane, idx) {{
      pane.setAttribute('data-src', 'reports/OBFUSCATED_Host-' + (idx + 1) + '.html');
      var ifrWrap = pane.querySelector('.host-iframe-wrapper');
      if (ifrWrap) {{
        var mount = ifrWrap.querySelector('[id^="iframe-mount-"]');
        if (mount) mount.innerHTML = '';
        ifrWrap.style.display = 'none';
        var srcLbl = ifrWrap.querySelector('[id^="iframe-src-label-"]');
        if (srcLbl) srcLbl.textContent = 'reports/OBFUSCATED_Host-' + (idx + 1) + '.html';
      }}
      var card = pane.querySelector('.host-embedded-card');
      if (card) {{
        card.style.display = 'block';
      }}
      pane.querySelectorAll('iframe').forEach(function(ifr) {{
        if (!ifr.hasAttribute('data-srcdoc') && !ifr.hasAttribute('srcdoc')) {{
          if (ifr.parentNode) ifr.parentNode.removeChild(ifr);
        }}
      }});
    }});

    clone.querySelectorAll('iframe').forEach(function(iframe) {{
      var srcdoc = iframe.getAttribute('srcdoc') || iframe.getAttribute('data-srcdoc');
      if (srcdoc) {{
        var cleanSrcdoc = srcdoc.replace(/<span\\s+class=["']pii["'][^>]*data-mask=["']([^"']+)["'][^>]*>([\\s\\S]*?)<\\/span>/gi, function(match, mask) {{
          return '<span class="pii" data-mask="' + mask + '">' + mask + '</span>';
        }});
        cleanSrcdoc = cleanSrcdoc.replace(/\\s+data-real=["'][^"']*["']/gi, '');
        cleanSrcdoc = cleanSrcdoc.replace(/<title>.*?<\\/title>/gi, '<title>VCF Readiness<\\/title>');
        cleanSrcdoc = cleanSrcdoc.replace(/(^|[^0-9])(?:10\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{{1,3}}\\.\\d{{1,3}}|192\\.168\\.\\d{{1,3}}\\.\\d{{1,3}})(?=[^0-9]|$)/g, '$1192.0.2.1');
        if (iframe.hasAttribute('data-srcdoc')) {{
          iframe.setAttribute('data-srcdoc', cleanSrcdoc);
        }} else {{
          iframe.setAttribute('srcdoc', cleanSrcdoc);
        }}
      }}
    }});
    var invScript = clone.querySelector('#fleet-inv-data');
    if (invScript) {{
      try {{
        var invData = JSON.parse(invScript.textContent);
        if (invData.hosts) {{
          invData.hosts.forEach(function(h, idx) {{
            h.hostname = 'Host-' + (idx + 1);
            h.ip = '192.0.2.' + ((idx % 250) + 1);
          }});
        }}
        if (invData.drives) {{
          invData.drives.forEach(function(d) {{
            var hidx = (d.host_idx !== undefined ? d.host_idx : 0);
            if (d.hostname) d.hostname = 'Host-' + (hidx + 1);
            if (d.ip) d.ip = '192.0.2.' + ((hidx % 250) + 1);
            if (d.serial) d.serial = 'MASKED';
          }});
        }}
        if (invData.nics) {{
          invData.nics.forEach(function(n) {{
            var hidx = (n.host_idx !== undefined ? n.host_idx : 0);
            if (n.hostname) n.hostname = 'Host-' + (hidx + 1);
            if (n.ip) n.ip = '192.0.2.' + ((hidx % 250) + 1);
            if (n.mac_address) n.mac_address = '02:00:00:00:00:00';
          }});
        }}
        if (invData.health) {{
          invData.health.forEach(function(hl) {{
            var hidx = (hl.host_idx !== undefined ? hl.host_idx : 0);
            if (hl.hostname) hl.hostname = 'Host-' + (hidx + 1);
            if (hl.ip) hl.ip = '192.0.2.' + ((hidx % 250) + 1);
            if (hl.message) {{
              hl.message = hl.message.replace(/(^|[^0-9])(?:10\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{{1,3}}\\.\\d{{1,3}}|192\\.168\\.\\d{{1,3}}\\.\\d{{1,3}})(?=[^0-9]|$)/g, '$1192.0.2.1');
            }}
          }});
        }}
        invData.meta = invData.meta || {{}};
        invData.meta.obfuscated = true;
        invScript.textContent = JSON.stringify(invData);
      }} catch(e) {{
        invScript.textContent = '{{}}';
      }}
    }}
    var pickerOpts = clone.querySelectorAll('#host-picker-select option');
    pickerOpts.forEach(function(opt, idx) {{
      if (idx > 0) {{
        opt.textContent = 'Host-' + idx;
        opt.removeAttribute('data-search');
      }}
    }});
    var activeBtn = clone.querySelector('#active-host-btn');
    if (activeBtn) {{
      activeBtn.textContent = '';
      activeBtn.style.display = 'none';
      activeBtn.classList.remove('active');
    }}

    // Reset active tab to tab-0 in clone
    clone.querySelectorAll('.tab-content').forEach(function(el) {{
      el.classList.toggle('active', el.id === 'tab-0');
    }});
    clone.querySelectorAll('.tab-btn').forEach(function(el, i) {{
      el.classList.toggle('active', i === 0);
    }});

    var titleEl = clone.querySelector('title');
    if (titleEl && titleEl.textContent.indexOf('Obfuscated') === -1) {{
      titleEl.textContent = titleEl.textContent.replace('VCF Readiness', 'VCF Readiness (Obfuscated)');
    }}

    var cbClone = clone.querySelector('#maskPII');
    if (cbClone) cbClone.checked = true;
    var rawHtml = '<!DOCTYPE html>' + clone.outerHTML;
    // Strip raw embedded un-obfuscated Excel sheet payload from exported HTML
    rawHtml = rawHtml.replace(/var _EMBEDDED_EXCEL_B64 = "[^"]*";/g, 'var _EMBEDDED_EXCEL_B64 = "";');
    // Scrub any stray private IPs that might appear in free-text outer HTML
    rawHtml = rawHtml.replace(/(^|[^0-9])(?:10\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{{1,3}}\\.\\d{{1,3}}|192\\.168\\.\\d{{1,3}}\\.\\d{{1,3}})(?=[^0-9]|$)/g, '$1192.0.2.1');
    var blob = new Blob([rawHtml], {{type: 'text/html'}});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.download = '00_OBFUSCATED_fleet_combined.html';
    a.href = url;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }}

  if (dlBtn) dlBtn.addEventListener('click', downloadObfuscatedCombined);
  if (dlCombBtn) dlCombBtn.addEventListener('click', downloadObfuscatedCombined);

  // Theme synchronization and localStorage persistence
  var storedTheme;
  try {{ storedTheme = localStorage.getItem('vcf-report-theme'); }} catch(e) {{}}
  var initialTheme = storedTheme || document.documentElement.getAttribute('data-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', initialTheme);

  var tt = document.getElementById('themeToggle');
  if (tt) {{
    tt.textContent = initialTheme === 'dark' ? '🌙 Dark' : '☀️ Light';
    tt.addEventListener('click', function() {{
      var cur = document.documentElement.getAttribute('data-theme') || 'dark';
      var next = cur === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try {{ localStorage.setItem('vcf-report-theme', next); }} catch(e) {{}}
      tt.textContent = next === 'dark' ? '🌙 Dark' : '☀️ Light';
      document.querySelectorAll('iframe').forEach(function(iframe) {{
        try {{
          if (iframe.contentDocument && iframe.contentDocument.documentElement) {{
            iframe.contentDocument.documentElement.setAttribute('data-theme', next);
            var ibtn = iframe.contentDocument.getElementById('themeToggle');
            if (ibtn) ibtn.textContent = next === 'dark' ? '🌙 Dark' : '☀️ Light';
          }}
        }} catch(e){{}}
      }});
    }});
  }}

  // Propagate active theme to every iframe on load and immediately
  document.querySelectorAll('iframe').forEach(function(iframe) {{
    function applyToIframe() {{
      try {{
        var th = document.documentElement.getAttribute('data-theme') || 'dark';
        if (iframe.contentDocument && iframe.contentDocument.documentElement) {{
          iframe.contentDocument.documentElement.setAttribute('data-theme', th);
          var ibtn = iframe.contentDocument.getElementById('themeToggle');
          if (ibtn) ibtn.textContent = th === 'dark' ? '🌙 Dark' : '☀️ Light';
        }}
      }} catch(e) {{}}
    }}
    applyToIframe();
    iframe.addEventListener('load', applyToIframe);
  }});
}})();
</script>
<!-- VCF Readiness v{TOOL_VERSION} · {timestamp} -->
</body></html>"""
    combined_html = combined_template.replace("__SUMMARY_TAB__", summary_tab).replace("__INVENTORY_TAB__", inventory_tab).replace("__README_TAB__", readme_tab)

    out_filename = output_filename or ("00_OBFUSCATED_fleet_combined.html" if obfuscated else "00_fleet_combined.html")
    compat_out_path = os.path.join(outdir, out_filename)
    try:
        safe = combined_html.encode("utf-8", errors="surrogatepass").decode("utf-8", errors="replace")
        with open(compat_out_path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(safe)
        return compat_out_path
    except Exception as exc:
        logger.error(f"Error writing combined report: {exc}")
        return ""


generate_combined_html = _generate_combined_html
generate_combined_tabbed_html = _generate_combined_html
