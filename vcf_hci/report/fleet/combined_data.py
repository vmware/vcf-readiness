"""Combined report fact preparation and escaped summary/navigation views."""
import hashlib
import html
import re
from functools import partial

from vcf_hci.bios.x2apic import refresh_x2apic_guidance
from vcf_hci.branding import MARK_SVG
from vcf_hci.collector.oem.dell_storage import normalize_dell_backplanes
from vcf_hci.report.fleet.escape import _xe
from vcf_hci.report.fleet.fc_matrix import build_fleet_fc_matrix_html
from vcf_hci.report.fleet.switch_matrix import build_fleet_switch_matrix_html
from vcf_hci.report.fleet.tiles import build_fleet_tiles_html
from vcf_hci.report.fleet.vendor import normalize_oem_vendor
from vcf_hci.report.formatting import fleet_tpm_badge
from vcf_hci.report.helpers import _h
from vcf_hci.report.inventory_tables import clean_model_code, summarize_fc_hbas
from vcf_hci.report.readiness import cpu_verdict_unassessed
from vcf_hci.security.scoring import score_host_security
from vcf_hci.storage_pcie import storage_pcie_view
from vcf_hci.ui_clarity import icon_html


def prepare_combined_results(all_results: list) -> list:
    """Preserve saved-summary copy/provenance and lightweight repair ordering."""
    all_results = [storage_pcie_view(host) for host in all_results]
    for host in all_results:
        refresh_x2apic_guidance(host)
        normalize_dell_backplanes(host)
    return all_results


def obfuscate_combined_results(all_results: list, obfuscated: bool, _page_salt: str) -> list:
    """Retain per-report salt and the existing already-obfuscated host guard."""
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

    return all_results


def identity_text(value: str, kind: str = "host", *, page_salt: str, obfuscated: bool) -> str:
    if not value:
        return ""
    if obfuscated:
        return _h(value)
    mask = f"{kind[0].upper()}-{hashlib.sha256((page_salt + value).encode()).hexdigest()[:8].upper()}"
    safe_val = _h(value)
    return f'<span class="pii" data-real="{safe_val}" data-mask="{mask}">{safe_val}</span>'


def build_combined_summary_rows(all_results: list, obfuscated: bool, page_salt: str) -> tuple:
    """Build capped per-host facts, OEM options and slow-BMC observations."""
    n_hosts = len(all_results)
    _pii = partial(identity_text, page_salt=page_salt, obfuscated=obfuscated)
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
        if cpu_verdict_unassessed(verdict):
            cpu_cls = "info"
            cpu_td = "Not assessed"
            _cpu_sort = "5"
            _row_unsupported = "0"
        elif "Unsupported" in verdict:
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
        fc_summary = summarize_fc_hbas(data)
        fc_n = fc_summary["count"]
        gpu_n = len(data.get("gpu_accelerators", []))
        tpm = fleet_tpm_badge(si)
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
                sec_badge = f"<span class='badge danger'>🔴 Action Suggested ({_f_cnt}F &middot; {_p_cnt}P)</span>"
                _sec_sort = "3"
            else:
                sec_badge = f"<span class='badge warning'>🟡 Partial ({_u_cnt}U &middot; {_p_cnt}P)</span>"
                _sec_sort = "2"
            sec_td = (
                f"<a href='#' class='btn-link tab-jump' data-tab='{idx + 3}' data-subtab='tab-security' "
                f"title='{_xe(_tip)}' style='text-decoration:none;display:inline-block'>{sec_badge}</a>"
            )
        else:
            sec_td = "<span style='color:var(--text-muted)'>—</span>"
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
            f"<tr data-host-idx='{idx}' data-vendor='{_xe(_vendor_norm)}' data-unsupported='{_row_unsupported}'>"
            f"<td data-sort='{_sort_hostname}'><a href='#' class='btn-link tab-jump' data-tab='{idx + 3}'>"
            f"<strong>{_pii(hostname)}</strong></a>"
            f"<br><small style='color:var(--text-muted)'>{_pii(raw_ip, 'ip')}</small></td>"
            f"<td data-sort='{_xe(_model_str)}' title='{_xe(_model_str)}'>{_xe(_clean_model)}{slow_bmc_badge}</td>"
            f"<td data-sort='{_cpu_sort}'>{cpu_cell_html}</td>"
            f"<td data-sort='{_tpm_sort}'>{tpm_cell_html}</td>"
            f"<td data-sort='{_sec_sort}'>{sec_td}</td>"
            f"<td data-sort='{_esa_sort}'>{esa_cell_html}</td>"
            f"<td data-sort='{_psu_sort}'><span class='badge {psu_cls}'>{psu_td}</span></td>"
            f"<td data-sort='{fc_n}'>{_h(fc_summary['display']) if fc_n else '—'}</td>"
            f"<td data-sort='{gpu_n}'>{'🟣 ' + str(gpu_n) + ' GPU' if gpu_n else '—'}</td>"
            f"</tr>"
        )

    _oem_options_html = "".join(
        f"<option value='{_xe(v)}'>{_xe(v)}</option>"
        for v in sorted(_oem_set)
    )

    return sum_rows, _oem_options_html, slow_bmc_hosts


def build_slow_bmc_alert(slow_bmc_hosts: list, obfuscated: bool, page_salt: str) -> str:
    """Render the existing BMC observation disclosure without changing its policy."""
    _pii = partial(identity_text, page_salt=page_salt, obfuscated=obfuscated)
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

    return slow_bmc_alert_html


def build_combined_summary(all_results: list, obfuscated: bool, page_salt: str) -> str:
    """Compose existing tiles/matrices and the per-host assessment view."""
    n_hosts = len(all_results)
    _page_salt = page_salt
    tiles_html = build_fleet_tiles_html(all_results, report_prefix="", page_salt=_page_salt)
    switch_matrix_block = build_fleet_switch_matrix_html(all_results, report_prefix="", page_salt=_page_salt, obfuscated=obfuscated)
    fc_matrix_block = build_fleet_fc_matrix_html(all_results, report_prefix="", page_salt=_page_salt, obfuscated=obfuscated)

    sum_rows, _oem_options_html, slow_bmc_hosts = build_combined_summary_rows(all_results, obfuscated, page_salt)
    slow_bmc_alert_html = build_slow_bmc_alert(slow_bmc_hosts, obfuscated, page_salt)
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

    has_topology = bool(switch_matrix_block and switch_matrix_block.strip())
    has_fc = bool(fc_matrix_block and fc_matrix_block.strip())
    has_sub_panes = has_topology or has_fc

    fleet_detail_buttons = ['<button type="button" class="active" data-action="fleet-detail-view" data-fleet-view="hosts">Hosts</button>']
    if has_topology:
        fleet_detail_buttons.append('<button type="button" data-action="fleet-detail-view" data-fleet-view="topology">Network Topology</button>')
    if has_fc:
        fleet_detail_buttons.append('<button type="button" data-action="fleet-detail-view" data-fleet-view="fc">Fibre Channel</button>')

    fleet_detail_seg = (
        f'<div class="fleet-detail-seg" role="tablist" aria-label="Fleet detail view">{"".join(fleet_detail_buttons)}</div>'
    ) if has_sub_panes else ""
    hosts_pane_open = ' class="fleet-detail-pane active" id="fleet-detail-hosts"' if has_sub_panes else ' id="fleet-detail-hosts"'
    topology_pane = (
        f'<div class="fleet-detail-pane" id="fleet-detail-topology">{switch_matrix_block}</div>'
        if has_topology
        else switch_matrix_block
    )
    fc_pane = (
        f'<div class="fleet-detail-pane" id="fleet-detail-fc">{fc_matrix_block}</div>'
        if has_fc
        else ""
    )
    summary_tab = f"""<div class="container" style="padding-top:2rem">
{header_controls}
<h1 style="display:flex;align-items:center">{MARK_SVG}{summary_title}</h1>
<p class="report-fleet-subtitle">{n_hosts} host(s) assessed — use Find host or Jump to Host for full detail.</p>
{tiles_html}
{slow_bmc_alert_html}
{fleet_detail_seg}
<div{hosts_pane_open}>
<h2 id="fleet-per-host-table" style="font-size:.9rem;font-weight:700;color:var(--text-muted,#94a3b8);margin:2rem 0 .75rem;text-transform:uppercase">Per-Host Assessment Table</h2>
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
<div class="report-scroll-region" role="region" aria-label="Per-host assessments" tabindex="0">
<table class="sortable-table"><thead><tr>
<th title="Click to sort">Host / IP<span class="sort-ind">⇅</span></th>
<th title="Click to sort">Model<span class="sort-ind">⇅</span></th>
<th title="Click to sort">CPU Support<span class="sort-ind">⇅</span></th>
<th title="Click to sort">TPM 2.0<span class="sort-ind">⇅</span></th>
<th title="Click to sort">BMC Security<span class="sort-ind">⇅</span></th>
<th title="Click to sort">vSAN Tier<span class="sort-ind">⇅</span></th>
<th title="Click to sort">PSU<span class="sort-ind">⇅</span></th>
<th title="Click to sort">FC cards / ports<span class="sort-ind">⇅</span></th>
<th title="Click to sort">GPUs<span class="sort-ind">⇅</span></th>
</tr></thead><tbody>{sum_rows}</tbody></table>
</div>
</div>
{topology_pane}
{fc_pane}
</div>"""

    return summary_tab


def build_host_picker(all_results: list, obfuscated: bool) -> str:
    """Keep escaped host search and fixed tab offsets."""
    n_hosts = len(all_results)
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
        '<label class="host-search">' + icon_html('search') +
        '<input type="search" id="host-picker-search" aria-label="Find host" placeholder="Find host..." '
        'style="padding:.3rem .6rem .3rem 2rem;border-radius:4px;border:1px solid var(--border,#334155);background:var(--card,#1e293b);color:var(--text,#f8fafc);font-size:.82rem;width:100%;" '
        'title="Search by hostname, IP, model, or verdict" autocomplete="off"></label>'
        '<select id="host-picker-select" aria-label="Select host" style="padding:.3rem .6rem;border-radius:4px;border:1px solid var(--border,#334155);background:var(--card,#1e293b);color:var(--text,#f8fafc);font-size:.82rem;max-width:260px;" '
        'onchange="if(this.value) showTab(parseInt(this.value, 10))">\n'
        + "\n".join(picker_options) +
        '\n</select>'
        '</div>'
    )

    return picker_html


def build_host_navigation(all_results: list, mode: str, obfuscated: bool, page_salt: str) -> str:
    """Build fixed tabs and lazy host navigation using existing IDs/actions."""
    _pii = partial(identity_text, page_salt=page_salt, obfuscated=obfuscated)
    picker_html = build_host_picker(all_results, obfuscated)
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
            f'<button class="{_tab_btn_class(i)}" data-action="report-tab" data-tab-target="tab-{i}">'
            f'{_tab_lbl(i, lbl)}</button>'
            for i, lbl in enumerate(labels)
        )
    else:
        fixed_btns = [
            '<button class="tab-btn tab-btn-summary active" data-action="report-tab" data-tab-target="tab-0">Fleet Summary</button>',
            '<button class="tab-btn tab-btn-inventory" data-action="report-tab" data-tab-target="tab-1">Detailed Inventory</button>',
            '<button class="tab-btn tab-btn-help" data-action="report-tab" data-tab-target="tab-2">📖 Help &amp; Readme</button>',
            '<button id="active-host-btn" class="tab-btn tab-btn-host" style="display:none;" onclick="var s = document.getElementById(\'host-picker-select\'); if (s && s.value) showTab(parseInt(s.value, 10));"></button>',
        ]
        tab_btns = "\n".join(fixed_btns)

    tab_btns = '<div class="report-tabs">' + tab_btns + '</div>' + picker_html

    return tab_btns
