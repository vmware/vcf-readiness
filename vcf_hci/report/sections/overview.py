"""
VCF Readiness Tool — header, banners & alert rollup report section builders (Layer D).
"""
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.constants import MTAT_GITHUB_URL, VCF_OPS_DEMO_URL
from vcf_hci.obfuscation import _pii_span
from vcf_hci.report.helpers import _h, host_has_redfish_latency


def render_protocol_diagnostics_badges(
    data: Optional[Dict[str, Any]],
    data_src: str = "redfish",
) -> Tuple[str, str, str]:
    """Return (expand_badge, pipelining_badge, pacing_badge) HTML strings."""
    if data_src.startswith("wsman"):
        return "", "", ""
    scan_data = data or {}
    diag = scan_data.get("diagnostics") if isinstance(scan_data.get("diagnostics"), dict) else {}

    # 1. Expansion status badge
    expand_supp = bool(diag.get("expand_supported", False))
    if expand_supp:
        syn = diag.get("expand_syntax") or "*"
        lvl = diag.get("expand_max_levels") or 1
        try:
            lvl_int = int(lvl)
        except (ValueError, TypeError):
            lvl_int = 1
        lvl_str = f" (Levels: {lvl_int})" if lvl_int > 1 else ""
        expand_badge = f'<span class="badge success" style="font-size:.74rem" title="Redfish OData Collection Expansion active">🟢 OData $expand={_h(str(syn))}{lvl_str}</span>'
    else:
        expand_badge = '<span class="badge" style="font-size:.74rem;background:var(--code-bg,#f1f5f9);color:var(--text-muted,#64748b)" title="Standard iterative Redfish crawling (expansion unsupported or disabled)">⚪ Iterative Crawl</span>'

    # 2. Pipelining badge
    pipe_supp = bool(diag.get("multiple_http_requests", False))
    if pipe_supp:
        pipelining_badge = '<span class="badge success" style="font-size:.74rem" title="BMC MultipleHTTPRequests connection pipelining active">🟢 MultipleHTTPRequests Active</span>'
    else:
        pipelining_badge = '<span class="badge" style="font-size:.74rem;background:var(--code-bg,#f1f5f9);color:var(--text-muted,#64748b)" title="Standard single-request HTTP transaction keep-alive">⚪ Standard Keep-Alive</span>'

    # 3. Pacing badge
    pacing_val = diag.get("request_pacing_s")
    if pacing_val is not None:
        try:
            pacing_f = float(pacing_val)
        except (ValueError, TypeError):
            pacing_f = 0.05
    else:
        pacing_f = 0.05

    if pacing_f == 0.0:
        pacing_badge = '<span class="badge success" style="font-size:.74rem" title="Zero artificial inter-request pacing delay">0.0ms (Pipelined)</span>'
    else:
        pacing_ms = int(round(pacing_f * 1000))
        pacing_badge = f'<span class="badge" style="font-size:.74rem;background:var(--code-bg,#f1f5f9);color:var(--text-muted,#64748b)" title="Inter-request pacing interval">{pacing_ms}ms (Conservative)</span>'

    return expand_badge, pipelining_badge, pacing_badge


def render_header_and_banners(
    sys_info: Dict[str, Any],
    host_os: Dict[str, Any],
    page_salt: str,
    quick_mode: bool,
    data_src: str,
    wsman_proto_label: str,
    bcg_server_url: str,
    bcg_cpu_url: str,
    obfuscated: bool = False,
    collector_class: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """Render PII labels, obfuscation banner, header HTML, banners and callout box."""
    host_display_label = sys_info.get("dns_name") or sys_info.get("hostname") or sys_info.get("ip") or "Unknown"
    _ip = sys_info.get("ip", "")
    _serial_val = str(sys_info.get("serial_number") or "").strip()
    _vendor_upper = str(sys_info.get("vendor") or "").upper()
    _sn_label = "Chassis Serial" if ("DELL" in _vendor_upper and sys_info.get("chassis_label")) else ("Service Tag" if "DELL" in _vendor_upper else "S/N")

    _sku_val        = str(sys_info.get("sku") or "").strip()
    _has_sku        = bool(_sku_val and _sku_val.upper() != _serial_val.upper())

    if obfuscated:
        _pii_host_label = _h(host_display_label)
        _pii_ip_label   = _h(_ip) if _ip else ""
        _pii_serial     = _h(_serial_val)
        _pii_sku        = _h(_sku_val) if _has_sku else ""
    else:
        _pii_host_label = _pii_span(page_salt, host_display_label, "host")
        _pii_ip_label   = _pii_span(page_salt, _ip, "ip") if _ip else ""
        _pii_serial     = _pii_span(page_salt, _serial_val, "SN")
        _pii_sku        = _pii_span(page_salt, _sku_val, "SKU") if _has_sku else ""

    _obf_banner = (
        '<div class="alert alert-danger" style="border-width:2px;border-style:solid;text-align:center;margin-bottom:1.5rem;padding:1rem 1.5rem">'
        '<strong style="color:var(--danger,#dc2626);font-size:1.05rem">&#128274; OBFUSCATED REPORT</strong>'
        '<p style="margin:.3rem 0 0;font-size:.82rem;color:var(--tint-danger-text,#991b1b)">'
        'Host identifiers have been replaced with hash tokens. '
        'Identical tokens&nbsp;=&nbsp;identical real values. '
        'Hardware specs and VCF verdicts are unmodified.</p></div>'
    ) if obfuscated else ""

    _obf_controls = (
        '<span class="badge cyber-recovery" style="font-size:.8rem;padding:.25rem .6rem;border:1px solid #7c3aed">🔒 Obfuscated Report</span>'
    ) if obfuscated else (
        '<label style="display:inline-flex;align-items:center;gap:.4rem;cursor:pointer;font-size:.8rem;color:var(--text-muted)" title="Cosmetic in-browser view mask. For external sharing, use generated OBFUSCATED_*.html reports.">'
        '<input type="checkbox" id="maskPII" style="cursor:pointer">'
        'Obfuscate view (client-side)'
        '</label>'
        '<a id="dlObf" href="#" style="display:none;font-size:.8rem;color:var(--primary);text-decoration:none;border:1px solid var(--primary);border-radius:4px;padding:.15rem .5rem" title="Download obfuscated HTML copy">&#11015; Save obfuscated copy</a>'
    )

    scan_data = data or {}
    has_latency = host_has_redfish_latency(scan_data)

    bmc_fw = scan_data.get("bmc_firmware", {})
    fw_ver = str(bmc_fw.get("bmc_fw_version", "")).strip()
    bmc_model = str(bmc_fw.get("bmc_model", "")).strip() or "BMC"
    fw_eval = bmc_fw.get("bmc_fw_eval", {})
    latest_ver = fw_eval.get("latest_version", "")

    is_partial = bool(scan_data.get("partial_scan"))
    remediation = scan_data.get("remediation") or {}

    _warning_banner = ""
    if remediation.get("status") == "fully_remediated":
        _res_sec = remediation.get("resolved_sections") or []
        _res_str = f" Recovered sections: <code>{', '.join(_h(str(s)) for s in _res_sec)}</code>." if _res_sec else ""
        _warning_banner = (
            '<div class="alert alert-success" style="margin-bottom:1.5rem; padding:1rem 1.25rem; border-left:4px solid var(--success,#16a34a); border-radius:6px">'
            '<strong style="color:var(--success,#16a34a); font-size:1.02rem">🔄 REMEDIATED VIA TARGETED RESCAN:</strong> '
            f'<p style="margin:.3rem 0 0; line-height:1.5">'
            f'All previously missing or timed-out sections were successfully recovered via targeted differential rescan.{_res_str} '
            'Hardware inventory and compatibility checks are fully populated.</p>'
            '</div>'
        )
    elif is_partial and remediation.get("status") == "partially_remediated":
        _res_sec = remediation.get("resolved_sections") or []
        _rem_sec = remediation.get("remaining_sections") or scan_data.get("partial_sections") or []
        _res_str = f" Recovered sections: <code>{', '.join(_h(str(s)) for s in _res_sec)}</code>." if _res_sec else ""
        _rem_str = f" Remaining incomplete section(s): <code>{', '.join(_h(str(s)) for s in _rem_sec)}</code>." if _rem_sec else ""
        _warning_banner = (
            '<div class="alert alert-warning" style="margin-bottom:1.5rem; padding:1rem 1.25rem; border-left:4px solid var(--warning,#ca8a04); border-radius:6px">'
            '<strong style="color:var(--warning,#ca8a04); font-size:1.02rem">⚠️ INCOMPLETE / PARTIAL SCAN REPORT (Partially Remediated):</strong> '
            f'<p style="margin:.3rem 0 0; line-height:1.5">'
            f'Targeted rescan executed.{_res_str}{_rem_str} '
            'Data shown below reflects partial hardware capture.</p>'
            '<div style="margin-top:0.4rem; font-size:0.88rem"><b>💡 Recommended Action:</b> Perform a soft reset of the BMC controller (e.g. <code>racadm racreset</code> for Dell or <code>iloreset</code> for HPE) or upgrade BMC firmware to resolve remaining timeouts, then re-scan this host.</div>'
            '</div>'
        )
    elif is_partial and has_latency:
        _stg = _h(str(scan_data.get("partial_stage") or "Collection"))
        _sections = scan_data.get("partial_sections") or []
        _sec_str = f" Incomplete or timed-out sections: <code>{', '.join(_h(str(s)) for s in _sections)}</code>." if _sections else ""
        latest_str = f" (latest baseline: <b>v{_h(latest_ver)}</b>)" if (latest_ver and latest_ver != "N/A") else ""
        ver_str = f" (<b>v{_h(fw_ver)}</b> installed)" if (fw_ver and fw_ver != "N/A") else ""
        rec_action = (
            f"Upgrade <b>{_h(bmc_model)}</b> firmware to <b>v{_h(latest_ver)}</b> and perform a BMC reset (e.g. <code>racadm racreset</code> for Dell or <code>iloreset</code> for HPE)"
            if (latest_ver and latest_ver != "N/A")
            else f"Upgrade <b>{_h(bmc_model)}</b> firmware to the latest vendor release and perform a BMC reset (e.g. <code>racadm racreset</code> for Dell or <code>iloreset</code> for HPE)"
        )
        _warning_banner = (
            '<div class="alert alert-warning" style="margin-bottom:1.5rem; padding:1rem 1.25rem; border-left:4px solid var(--warning,#ca8a04); border-radius:6px">'
            f'<strong style="color:var(--warning,#ca8a04); font-size:1.02rem">⚠️ INCOMPLETE / PARTIAL SCAN REPORT — Redfish API Latency &amp; Timeouts Detected:</strong> '
            f'<p style="margin:.3rem 0 0; line-height:1.5">'
            f'Redfish collection timed out during stage: <code>{_stg}</code>.{_sec_str} '
            f'This host experienced Redfish API response latency or socket timeouts during collection{ver_str}{latest_str}. '
            'Data shown below reflects a partial Redfish API capture and may be missing some hardware inventory or telemetry metrics.</p>'
            f'<div style="margin-top:0.4rem; font-size:0.88rem"><b>💡 Recommended Action:</b> {rec_action} to resolve API thread locking, socket exhaustion, and Redfish responsiveness issues, then re-scan this host.</div>'
            '</div>'
        )
    elif is_partial:
        _stg = _h(str(scan_data.get("partial_stage") or "Collection"))
        _sections = scan_data.get("partial_sections") or []
        _sec_str = f" Incomplete or timed-out sections: <code>{', '.join(_h(str(s)) for s in _sections)}</code>." if _sections else ""
        _warning_banner = (
            '<div class="alert alert-warning" style="margin-bottom:1.5rem; padding:1rem 1.25rem; border-left:4px solid var(--warning,#ca8a04); border-radius:6px">'
            f'<strong style="color:var(--warning,#ca8a04); font-size:1.02rem">⚠️ INCOMPLETE / PARTIAL SCAN REPORT:</strong> '
            f'<p style="margin:.3rem 0 0; line-height:1.5">'
            f'Redfish collection timed out during stage: <code>{_stg}</code>.{_sec_str} '
            'Data shown below reflects a partial Redfish API capture and may be missing some hardware inventory or telemetry metrics.</p>'
            '<div style="margin-top:0.4rem; font-size:0.88rem"><b>💡 Recommended Action:</b> Perform a soft reset of the BMC controller (e.g. <code>racadm racreset</code> for Dell or <code>iloreset</code> for HPE) or upgrade BMC firmware, then re-scan this host.</div>'
            '</div>'
        )
    elif has_latency:
        latest_str = f" (latest baseline: <b>v{_h(latest_ver)}</b>)" if (latest_ver and latest_ver != "N/A") else ""
        ver_str = f" (<b>v{_h(fw_ver)}</b> installed)" if (fw_ver and fw_ver != "N/A") else ""
        rec_action = (
            f"Upgrade <b>{_h(bmc_model)}</b> firmware to <b>v{_h(latest_ver)}</b> and perform a BMC reset (e.g. <code>racadm racreset</code> for Dell or <code>iloreset</code> for HPE)"
            if (latest_ver and latest_ver != "N/A")
            else f"Upgrade <b>{_h(bmc_model)}</b> firmware to the latest vendor release and perform a BMC reset (e.g. <code>racadm racreset</code> for Dell or <code>iloreset</code> for HPE)"
        )
        _warning_banner = (
            '<div class="alert alert-warning" style="margin-bottom:1.5rem; padding:1rem 1.25rem; border-left:4px solid var(--warning,#ca8a04); border-radius:6px">'
            f'<strong style="color:var(--warning,#ca8a04); font-size:1.02rem">⚠️ Redfish API Latency / Timeouts Detected — {_h(bmc_model)} Upgrade Recommended</strong>'
            f'<p style="margin:.3rem 0 0; line-height:1.5">'
            f'This host experienced Redfish API response latency or socket timeouts during collection'
            f'{ver_str}{latest_str}.<br>'
            f'<b>💡 Action Recommended:</b> {rec_action} to resolve API thread locking, socket exhaustion, and Redfish responsiveness issues.</p>'
            '</div>'
        )

    _os_name    = _h(host_os.get("os_name", ""))
    _os_upd_lbl = _h(host_os.get("esxi_update_label", ""))
    _os_eol_b   = host_os.get("eol_badge", "")
    _os_kb_url  = host_os.get("kb_url", "")

    _os_header_disp = ((_os_upd_lbl or _os_name) + ' &nbsp;' + _os_eol_b + ((' &nbsp;<a href="' + _os_kb_url + '" target="_blank" class="btn-link" style="font-size:.78rem">🔗 KB ↗</a>') if _os_kb_url else '')) if _os_name else '<span style="color:var(--text-muted)">Not Reported</span>'

    _chassis_lbl = sys_info.get("chassis_label", "")
    _enc = sys_info.get("enclosure_info") or (data.get("system") or {}).get("enclosure_info") or {}
    _blade_banner = ""
    if _enc.get("is_enclosure_contained"):
        _enc_name = _enc.get("enclosure_name") or "Blade Enclosure Infrastructure"
        _enc_sn = _enc.get("enclosure_serial", "")
        _tray = _enc.get("tray_id", "")
        _node_w = _enc.get("node_power_watts")
        _enc_w = _enc.get("chassis_power_watts")
        _pwr_parts = []
        if _node_w is not None:
            _pwr_parts.append(f"Node: <b>{_node_w}W</b>")
        if _enc_w is not None:
            _pwr_parts.append(f"Chassis: <b>{_enc_w}W</b>")
        _pwr_str = f" &nbsp;|&nbsp; ⚡ Power ({' / '.join(_pwr_parts)})" if _pwr_parts else ""
        _tray_str = f" &nbsp;|&nbsp; Tray / Slot: <code>{_h(str(_tray))}</code>" if _tray else ""
        _sn_str = f" &nbsp;|&nbsp; Enclosure S/N: <code>{_h(_enc_sn)}</code>" if _enc_sn else ""
        _blade_banner = (
            f'<div class="callout-box" style="margin-bottom:1rem;border-left:4px solid var(--accent,#38bdf8);background:rgba(56,189,248,0.06);padding:.6rem 1rem;border-radius:6px">'
            f'<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem">'
            f'<div>'
            f'<strong>🏢 Blade Compute Node:</strong> Enclosure <strong>{_h(_enc_name)}</strong>'
            f'{_sn_str}{_tray_str}{_pwr_str}'
            f'</div>'
            f'</div>'
            f'</div>'
        )
    _chassis_span = f' &nbsp;<span style="font-size:.82rem;color:#64748b">· {_h(str(_chassis_lbl))}</span>' if _chassis_lbl else ""

    _proto_badges_html = ""
    if not data_src.startswith("wsman"):
        _exp_b, _pipe_b, _pacing_b = render_protocol_diagnostics_badges(data, data_src)
        _proto_badges_html = (
            f'<div style="margin-top:.35rem;display:flex;gap:.35rem;justify-content:flex-end;flex-wrap:wrap;align-items:center">'
            f'{_exp_b} {_pipe_b} {_pacing_b}'
            f'</div>'
        )

    header_html = (
        f'{_obf_banner}'
        f'{_warning_banner}'
        f'<div class="header">'
        f'<div>'
        f'<h1 style="margin:0 0 .25rem">VCF / vSphere 9.1 Readiness Assessment</h1>'
        f'<span style="color:var(--text-muted)">Host: <strong>{_pii_host_label}</strong>'
        f'{(" &nbsp;|&nbsp; Target IP: <strong>" + _pii_ip_label + "</strong>") if (_ip and _ip not in host_display_label) else ""}'
        f' &nbsp;|&nbsp; Model: <strong>{_h(str(sys_info.get("vendor", "")))} {_h(str(sys_info.get("model", "")))}</strong>'
        f'{_chassis_span}'
        f' &nbsp;|&nbsp; {_sn_label}: <code>{_pii_serial}</code>'
        f'{(" &nbsp;|&nbsp; SKU: <code>" + _pii_sku + "</code>") if _has_sku else ""}</span>'
        f'<div style="margin-top:.35rem;display:flex;align-items:center;gap:.75rem;flex-wrap:wrap">'
        f'{_obf_controls}'
        f'<button id="themeToggle" title="Toggle dark/light mode">🌙 Dark</button>'
        f'</div>'
        f'</div>'
        f'<div style="text-align:right">'
        f'<div>BIOS: <code>v{_h(str(sys_info.get("bios_version", "")))} ({_h(str(sys_info.get("bios_release_date", "")))})</code>'
        f' &nbsp;|&nbsp; <span class="badge {"info" if data_src.startswith("wsman") else "success"}" style="font-size:.78rem">{"🔌 " + wsman_proto_label if data_src.startswith("wsman") else "🔵 Redfish"}</span>'
        f'</div>'
        f'<div style="margin-top:.3rem;font-size:.85rem">'
        f'💻 OS: {_os_header_disp}'
        f'</div>'
        f'{_proto_badges_html}'
        f'<div style="margin-top:.5rem">'
        f'<a href="{bcg_server_url}" target="_blank" class="btn-link" style="font-size:.85rem">🔗 BCG Server Search ↗</a>&nbsp;&nbsp;'
        f'<a href="{bcg_cpu_url}" target="_blank" class="btn-link" style="font-size:.85rem">🧠 BCG CPU Search ↗</a>'
        f'{("&nbsp;&nbsp;" + f"""<a href="redfish_explorer_{_ip}.html" target="_blank" class="btn-link" style="font-size:.85rem;color:var(--accent,#38bdf8);font-weight:600;border:1px solid rgba(56,189,248,0.3);padding:2px 8px;border-radius:4px" title="Inspect raw Redfish API payloads for this server">🧭 Redfish Explorer ↗</a>""") if _ip else ""}'
        f'</div>'
        f'</div>'
        f'</div>'
    )

    quick_banner = (
        '<div style="background:var(--callout-info-bg,#eff6ff);border:1px solid var(--callout-info-border,#bfdbfe);'
        'border-left:4px solid var(--primary,#2563eb);padding:.6rem 1rem;border-radius:6px;margin-bottom:1rem;font-size:.85rem;'
        'color:var(--callout-info-h,#1e40af);display:flex;align-items:center;justify-content:space-between">'
        '<span>⚡ <b>Quick Scan Mode:</b> Scanned System, CPU, Memory, BIOS, and vSAN ESA drives in &lt;10 seconds. Storage controllers, NIC inventory, thermal sensors, and firmware inventory were skipped — run without <code>--quick</code> for a full report.</span>'
        '</div>'
    ) if quick_mode else ""

    wsman_banner = (
        f'<div style="background:var(--callout-info-bg,#eff6ff);border:1px solid var(--callout-info-border,#bfdbfe);'
        f'border-left:4px solid var(--primary,#2563eb);padding:.6rem 1rem;border-radius:6px;margin-bottom:1rem;font-size:.85rem;'
        f'color:var(--callout-info-h,#1e40af);display:flex;align-items:center;justify-content:space-between">'
        f'<span>🔌 <b>Legacy Management Protocol ({_h(wsman_proto_label)}):</b> Redfish was unavailable or disabled. Hardware inventory collected via {_h(wsman_proto_label)} (DMTF WS-Management standard).</span>'
        f'</div>'
    ) if data_src.startswith("wsman") else ""

    appliance_banner = (
        '<div style="background:var(--callout-warn-bg,#fefce8);border:1px solid var(--callout-warn-border,#fef08a);'
        'border-left:4px solid var(--warning,#ca8a04);padding:.6rem 1rem;border-radius:6px;margin-bottom:1rem;font-size:.85rem;'
        'color:var(--callout-warn-h,#854d0e);display:flex;align-items:center;justify-content:space-between">'
        '<span>📦 <b>Storage Appliance / HCI Node:</b> System identified as a specialized storage appliance. Redfish /Storage endpoint is managed by appliance firmware.</span>'
        '</div>'
    ) if sys_info.get("is_storage_appliance") else ""

    generic_banner = (
        '<div style="background:var(--callout-info-bg,#eff6ff);border:1px solid var(--callout-info-border,#bfdbfe);'
        'border-left:4px solid var(--primary,#2563eb);padding:.6rem 1rem;border-radius:6px;margin-bottom:1rem;font-size:.85rem;'
        'color:var(--callout-info-h,#1e40af);display:flex;align-items:center;justify-content:space-between">'
        '<span>No OEM adapter matched this BMC. Inventory is DMTF Redfish only. Capture a sanitized dump with <code>tools/redfishMockupCreate.py</code> and see <code>docs/adding-oem-support.md</code>.</span>'
        '</div>'
    ) if collector_class == "GenericCollector" else ""

    callout_box = (
        f'<div class="callout-box">'
        f'<h3 style="margin:0 0 .5rem;color:var(--primary)">💡 Memory Tiering &amp; Sizing Resources</h3>'
        f'<p style="margin:0;font-size:.9rem;line-height:1.6">'
        f'For memory tiering workload sizing use <strong>VCF Operations 9.1</strong> or the open-source <a href="{MTAT_GITHUB_URL}" target="_blank" class="btn-link">Memory Tiering Assessment Tool (MTAT) ↗</a>.'
        f' For a VCF Ops 9 demo, see this <a href="{VCF_OPS_DEMO_URL}" target="_blank" class="btn-link">Video ↗</a>.'
        f'</p>'
        f'</div>'
    )

    _multi_sock = (data or {}).get("multi_socket_telemetry") or (sys_info.get("cpu_summary") or {}).get("multi_socket_telemetry") or {}
    _cpu_cnt = int((sys_info.get("cpu_summary") or {}).get("count") or 1)
    _quad_banner = ""
    if _cpu_cnt >= 4 or _multi_sock.get("is_quad_socket"):
        _snc_disp = _multi_sock.get("snc_mode") or _multi_sock.get("sub_numa_clustering")
        _uma_disp = _multi_sock.get("uma_clustering")
        _clust_parts = []
        if _snc_disp:
            _clust_parts.append(f"SNC: <b>{_h(_snc_disp)}</b>")
        if _uma_disp:
            _clust_parts.append(f"Clustering: <b>{_h(_uma_disp)}</b>")
        if _multi_sock.get("upi_prefetch"):
            _clust_parts.append(f"UPI Prefetch: <b>{_h(_multi_sock['upi_prefetch'])}</b>")
        _clust_str = f" &nbsp;|&nbsp; 🔀 {' &middot; '.join(_clust_parts)}" if _clust_parts else ""
        _quad_banner = (
            f'<div class="callout-box" style="margin-bottom:1rem;border-left:4px solid #8b5cf6;background:rgba(139,92,246,0.06);padding:.6rem 1rem;border-radius:6px">'
            f'<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem">'
            f'<div>'
            f'<strong>⚡ Quad-Socket (4S) Multi-Processor Topology:</strong> 4 CPU Sockets Populated'
            f'{_clust_str}'
            f'</div>'
            f'</div>'
            f'</div>'
        )

    banners_html = f"{_blade_banner}{_quad_banner}{quick_banner}{wsman_banner}{appliance_banner}{generic_banner}{callout_box}"
    return header_html, banners_html


def render_alert_rollup(
    sel: List[Dict[str, Any]],
    storage: List[Dict[str, Any]],
    thermal: Dict[str, Any],
    mem_info: Dict[str, Any],
    mem_topo: Dict[str, Any],
    nics: List[Dict[str, Any]],
    tpm_badge_raw: str,
    sb_badge: str,
    spectre_badge_html: str,
    psu: Dict[str, Any],
    gpus: List[Dict[str, Any]],
    data: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str, Dict[str, str]]:
    """Scan collected section data and return (rollup_bar_html, rollup_detail_html, tab_dots)."""
    _rollup_items: List[Tuple[str, str, str, str]] = []

    # SEL & EEMS Hardware Blockers
    _vcf_blockers = (data.get("vcf_blockers") or []) if data else []
    if not _vcf_blockers:
        _vcf_blockers = [a for a in sel if a.get("is_vcf_blocker") or (isinstance(a.get("eems"), dict) and a["eems"].get("is_vcf_blocker"))]
    _sel_crit = sum(1 for a in sel if "danger" in a.get("badge", ""))
    _sel_warn = sum(1 for a in sel if "warning" in a.get("badge", ""))
    if _vcf_blockers:
        _b_count = len(_vcf_blockers)
        _b_codes = ", ".join(dict.fromkeys(b.get("code") or b.get("eems_code") or "FAULT" for b in _vcf_blockers))
        _first_b = _vcf_blockers[0]
        _b_impact = _first_b.get("vcf_impact") or "Hardware Fault Blocker"
        _rollup_items.append((
            "danger",
            f"🔴 {_b_count} VCF Hardware Blocker{'s' if _b_count > 1 else ''} ({_b_codes})",
            "tab-overview",
            f"Critical hardware fault {_b_codes} ({_b_impact}) — component replacement or remediation required before VCF commissioning.",
        ))
    elif _sel_crit:
        _rollup_items.append(("danger", f"🔴 {_sel_crit} critical SEL event{'s' if _sel_crit>1 else ''}", "tab-overview",
                               f"{_sel_crit} critical alarm(s) in the System Event Log — review immediately."))
    elif _sel_warn:
        _rollup_items.append(("warning", f"⚠️ {_sel_warn} SEL warning{'s' if _sel_warn>1 else ''}", "tab-overview",
                               f"{_sel_warn} warning alarm(s) in the System Event Log."))
    else:
        _rollup_items.append(("success", "✅ SEL: No Alarms", "tab-overview", "No critical or warning events in the System Event Log."))

    # Storage
    _stor_degraded = sum(
        1 for ctrl in storage for d in ctrl.get("drives", [])
        if str(d.get("health", "")).lower() in ("critical", "warning", "failed")
    )
    _stor_low_endurance = sum(
        1 for ctrl in storage for d in ctrl.get("drives", [])
        if isinstance(d.get("endurance_remaining_pct"), (int, float)) and d["endurance_remaining_pct"] < 20
    )
    if _stor_degraded:
        _rollup_items.append(("danger", f"🔴 {_stor_degraded} degraded drive{'s' if _stor_degraded>1 else ''}", "tab-storage",
                               f"{_stor_degraded} drive(s) reporting Critical/Warning health — replace immediately."))
    elif _stor_low_endurance:
        _rollup_items.append(("warning", f"⚠️ {_stor_low_endurance} drive(s) low endurance (<20%)", "tab-storage",
                               f"{_stor_low_endurance} drive(s) with endurance remaining below 20% — plan replacement."))
    elif storage:
        _rollup_items.append(("success", "✅ Storage: Healthy", "tab-storage", "All drives report OK health."))
    else:
        _sys_s = (data or {}).get("system", {})
        _enc_s = _sys_s.get("enclosure_info") or {}
        _is_bld = _sys_s.get("is_blade") or _enc_s.get("is_enclosure_contained") or "e910" in str(_sys_s.get("model", "")).lower()
        if _is_bld or (data and not data.get("partial_scan") and "storage_subsystem" not in data.get("partial_sections", [])):
            _rollup_items.append(("info", "ℹ️ Storage: Diskless Node", "tab-storage", "No local drives installed (SAN / PXE booted compute node)."))

    # Thermal
    _therm_crit = sum(1 for s in thermal.get("sensors", []) if "🔴" in s.get("status_flag", ""))
    _therm_warn = sum(1 for s in thermal.get("sensors", []) if "🟡" in s.get("status_flag", ""))
    if _therm_crit:
        _rollup_items.append(("danger", f"🔴 {_therm_crit} thermal critical sensor{'s' if _therm_crit>1 else ''}", "tab-health",
                               f"{_therm_crit} sensor(s) above critical threshold — check cooling immediately."))
    elif _therm_warn:
        _rollup_items.append(("warning", f"⚠️ {_therm_warn} thermal warning sensor{'s' if _therm_warn>1 else ''}", "tab-health",
                               f"{_therm_warn} sensor(s) above warning threshold."))
    elif thermal.get("sensors"):
        _rollup_items.append(("success", "✅ Thermal: In Spec", "tab-health", "All thermal sensors within normal operating range."))

    # Memory
    _mem_failed = sum(
        1 for dimm in mem_info.get("dimms", [])
        if str(dimm.get("health", "")).lower() in ("critical", "failed")
    )
    _mem_score = mem_topo.get("interleaving_score_pct", 100)
    if _mem_failed:
        _rollup_items.append(("danger", f"🔴 {_mem_failed} DIMM fault{'s' if _mem_failed>1 else ''}", "tab-memory",
                               f"{_mem_failed} DIMM(s) reporting Critical health — check memory slots."))
    elif _mem_score < 60:
        _rollup_items.append(("warning", f"⚠️ Memory interleaving {_mem_score}%", "tab-memory",
                               f"Channel interleaving efficiency is low ({_mem_score}%) — review DIMM population."))
    elif mem_info.get("dimms"):
        _rollup_items.append(("success", "✅ Memory: Healthy", "tab-memory", "No DIMM faults detected; channel interleaving optimal."))

    # Networking
    _nic_linkdown = sum(
        1 for n in nics for p in n.get("ports", [])
        if str(p.get("link_status", "")).lower() in ("down", "linkdown", "no link")
    )
    if _nic_linkdown:
        _rollup_items.append(("warning", f"⚠️ {_nic_linkdown} NIC port{'s' if _nic_linkdown>1 else ''} link-down", "tab-network",
                               f"{_nic_linkdown} NIC port(s) showing Link Down — verify cable/switch connectivity."))
    elif nics:
        _rollup_items.append(("success", "✅ Networking: Linked", "tab-network", "All discovered NIC ports are link-up."))

    _opt_warnings = (data.get("optical_warnings") or []) if data else []
    if _opt_warnings:
        _opt_cnt = len(_opt_warnings)
        _rollup_items.append((
            "warning",
            f"⚠️ {_opt_cnt} Optical Signal Warning{'s' if _opt_cnt > 1 else ''}",
            "tab-network",
            "Marginal or degraded optical signal detected on transceiver(s) — check fiber links.",
        ))

    # Multi-Socket / NUMA Topology & BIOS checks
    _mst = (data or {}).get("multi_socket_telemetry") or (data or {}).get("bios_checks", {}).get("multi_socket_telemetry") or {}
    if _mst.get("node_interleave_warning"):
        _rollup_items.append((
            "warning",
            "⚠️ BIOS: Node Interleaving ON",
            "tab-bios",
            "Node Interleaving flattens NUMA into UMA, disabling ESXi NUMA-aware scheduling. Set Node Interleaving to Disabled in BIOS.",
        ))
    if _mst.get("proc_x2apic_warning"):
        _rollup_items.append((
            "warning",
            "⚠️ BIOS: x2APIC Disabled",
            "tab-bios",
            "x2APIC Mode is Disabled on a multi-socket / high-core server. Must be Enabled in BIOS for vSphere 9.1 interrupt scaling.",
        ))
    if _mst.get("is_quad_socket"):
        _snc_desc = _mst.get("snc_mode") or "Standard"
        _rollup_items.append((
            "info",
            f"ℹ️ Topology: 4-Socket NUMA ({_snc_desc})",
            "tab-cpu",
            f"Quad-socket server topology with {_mst.get('socket_count', 4)} populated CPU sockets.",
        ))

    # Security
    _sec_audit = (data.get("bmc_security_audit") or {}) if data else {}
    _sec_audit_fails = _sec_audit.get("summary", {}).get("fail", 0)
    _sec_audit_unknowns = _sec_audit.get("summary", {}).get("unknown", 0)
    _sec_audit_passes = _sec_audit.get("summary", {}).get("pass", 0)

    _sec_rollup_badges = [tpm_badge_raw, sb_badge, (spectre_badge_html or "")]
    if _sec_audit_fails > 0 or any("danger" in b for b in _sec_rollup_badges):
        _fail_txt = f" ({_sec_audit_fails} failed control{'s' if _sec_audit_fails != 1 else ''})" if _sec_audit_fails else ""
        _detail_txt = (
            f"{_sec_audit_fails} BMC security audit failure{'s' if _sec_audit_fails != 1 else ''} ({_sec_audit_passes} passed) — see Security tab for details."
            if _sec_audit_fails else "One or more security checks failed — see Security tab for details."
        )
        _rollup_items.append(("danger", f"🔴 Security: Action Required{_fail_txt}", "tab-security", _detail_txt))
    elif any("warning" in b for b in _sec_rollup_badges):
        _rollup_items.append(("warning", "⚠️ Security: Review Required", "tab-security",
                               "One or more security checks need attention — see Security tab."))
    elif _sec_audit_unknowns > 0:
        _rollup_items.append(("info", f"ℹ️ Security: Partially Assessed ({_sec_audit_passes} passed, {_sec_audit_unknowns} unknown)", "tab-security",
                               f"Hardware security audit: {_sec_audit_passes} passed, {_sec_audit_unknowns} unknown controls — see Security tab for details."))
    else:
        _rollup_items.append(("success", "✅ Security: Baseline Met", "tab-security",
                               "TPM, Secure Boot, and hardware security baseline checks passed."))

    # PSU
    if psu.get("psus"):
        if not psu.get("redundant"):
            _rollup_items.append(("warning", "⚠️ PSU: Non-Redundant", "tab-health",
                                   "Single or non-redundant power supply detected — consider adding a second PSU."))
        else:
            _rollup_items.append(("success", "✅ PSU: Redundant", "tab-health", "Redundant power supplies detected."))

    # Drive SMART
    _pop_drives_smart = [d for ctrl in storage for d in ctrl.get("drives", []) if d.get("populated", True)]
    _smart_crit = sum(1 for d in _pop_drives_smart if (
        d.get("failure_predicted")
        or d.get("is_failing")
        or ((d.get("pcie_errors") or {}).get("fatal_errors") or 0) > 0
        or (isinstance(d.get("endurance_remaining_pct"), (int, float)) and d.get("endurance_remaining_pct") < 20)
    ))
    def _smart_warn_check(d: dict) -> bool:
        _d_is_boot = bool(d.get("is_boot") or d.get("usage_role") == "Boot Drive" or "boot" in str(d.get("category", "")).lower() or any(k in str(d.get("model", "")).upper() for k in ["BOSS", "NS204I"]))
        _p_errs = d.get("pcie_errors") or {}
        _has_signal_warn = bool(
            (_p_errs.get("l0_to_recovery_count") or 0) > 0
            or (_p_errs.get("replay_rollover_count") or 0) > 0
            or (_p_errs.get("replay_count") or 0) > 50
        )
        return bool(
            (isinstance(d.get("endurance_remaining_pct"), (int, float)) and 20 <= d.get("endurance_remaining_pct") < 50)
            or (isinstance(d.get("unsafe_shutdowns"), (int, float)) and d.get("unsafe_shutdowns") > 0)
            or (isinstance(d.get("media_errors"), (int, float)) and d.get("media_errors") > 0)
            or (isinstance(d.get("temperature_c"), (int, float)) and d.get("temperature_c") >= 60)
            or d.get("thermal_throttled")
            or (d.get("single_lane_alert") and not _d_is_boot)
            or (d.get("pcie_downshifted") and not _d_is_boot)
            or _has_signal_warn
            or bool(d.get("error_description"))
        )
    _smart_warn = sum(1 for d in _pop_drives_smart if _smart_warn_check(d))
    if _smart_crit:
        _rollup_items.append(("danger", f"🔴 {_smart_crit} drive SMART critical alert(s)", "tab-health",
                               f"{_smart_crit} drive(s) with imminent failure or low endurance (<20%)."))
    elif _smart_warn:
        _rollup_items.append(("warning", f"⚠️ {_smart_warn} drive SMART warning(s)", "tab-health",
                               f"{_smart_warn} drive(s) with SMART warnings (unsafe shutdowns, media errors, or throttling)."))

    # PCIe Link & Signal Integrity Rollup
    _pcie_warns = (data.get("pcie_link_warnings") or []) if data else []
    if _pcie_warns:
        _has_crit_pcie = any("Fatal" in w or "Critical" in w for w in _pcie_warns)
        if _has_crit_pcie:
            _rollup_items.append((
                "danger",
                f"🔴 {len(_pcie_warns)} PCIe Signal / Link Fatal Alert(s)",
                "tab-pcie",
                _pcie_warns[0]
            ))
        else:
            _rollup_items.append((
                "warning",
                f"⚠️ {len(_pcie_warns)} PCIe Signal / Link Degradation Alert(s)",
                "tab-pcie",
                _pcie_warns[0]
            ))

    # BMC API Latency / Firmware Recommendation
    if data and host_has_redfish_latency(data):
        _bmc_fw = data.get("bmc_firmware", {})
        _bmc_model = str(_bmc_fw.get("bmc_model", "BMC")).strip()
        _fw_ver = str(_bmc_fw.get("bmc_fw_version", "")).strip()
        _fw_eval = _bmc_fw.get("bmc_fw_eval", {})
        _latest_ver = _fw_eval.get("latest_version", "")
        _upg_lbl = f"Recommend {_bmc_model} Upgrade" if _bmc_model else "Recommend BMC Upgrade"
        _target_v = f" to v{_latest_ver}" if (_latest_ver and _latest_ver != "N/A") else ""
        _rollup_items.append((
            "warning",
            f"⚠️ {_upg_lbl}",
            "tab-firmware",
            f"Redfish API timeouts occurred on {_bmc_model} v{_fw_ver} — upgrade firmware{_target_v} to resolve latency."
        ))

    # BMC Active Sessions Warning
    _session_warn = (data.get("bmc_session_warning") or (data.get("collector_metadata") or {}).get("bmc_session_warning")) if data else None
    if _session_warn:
        _rollup_items.append((
            "warning",
            "⚠️ BMC: High Session Load",
            "tab-health",
            str(_session_warn),
        ))

    # LC Job Queue
    _job_q = (data.get("job_queue") or {}) if data else {}
    _failed_jobs = int(_job_q.get("failed_jobs") or 0)
    _stale_jobs = int(_job_q.get("stale_jobs") or 0)
    _pending_reboot_jobs = int(_job_q.get("pending_reboot_jobs") or 0)
    if _failed_jobs > 0 or _stale_jobs > 0:
        _rollup_items.append((
            "warning",
            f"⚠️ {_failed_jobs + _stale_jobs} Stuck/Failed LC Job{'s' if (_failed_jobs + _stale_jobs) > 1 else ''}",
            "tab-health",
            f"Stale/Failed LC Jobs Detected ({_failed_jobs} failed, {_stale_jobs} stale). May block VCF host staging or reboot. "
            f"Log into iDRAC Web UI or run RACADM `jobqueue delete` to clear stalled tasks prior to VCF commissioning.",
        ))
    elif _pending_reboot_jobs > 0:
        _rollup_items.append((
            "info",
            f"ℹ️ {_pending_reboot_jobs} LC Job{'s' if _pending_reboot_jobs > 1 else ''} Pending Reboot",
            "tab-health",
            f"{_pending_reboot_jobs} lifecycle job(s) waiting for server reboot to apply.",
        ))
    elif _job_q.get("total_jobs", 0) > 0:
        _rollup_items.append(("success", "✅ Job Queue: Clean", "tab-health", "No failed or stale jobs in Lifecycle Controller queue."))

    # Tab dots
    _tab_ids = ["tab-overview", "tab-cpu", "tab-bios", "tab-memory", "tab-storage", "tab-pcie", "tab-network", "tab-health", "tab-security", "tab-firmware"]
    if gpus:
        _tab_ids.insert(_tab_ids.index("tab-pcie") + 1, "tab-gpu")
    _sev_rank = {"danger": 3, "warning": 2, "success": 1, "info": 0}
    _tab_dots: Dict[str, str] = dict.fromkeys(_tab_ids, "info")
    for _sev, _lbl, _tid, _det in _rollup_items:
        if _sev_rank.get(_sev, 0) > _sev_rank.get(_tab_dots.get(_tid, "info"), 0):
            _tab_dots[_tid] = _sev

    if _vcf_blockers:
        for b in _vcf_blockers:
            dom = str(b.get("domain") or "").lower()
            if "mem" in dom and "tab-memory" in _tab_dots:
                _tab_dots["tab-memory"] = "danger"
            elif ("stor" in dom or "raid" in dom or "disk" in dom) and "tab-storage" in _tab_dots:
                _tab_dots["tab-storage"] = "danger"
            elif "cpu" in dom and "tab-cpu" in _tab_dots:
                _tab_dots["tab-cpu"] = "danger"
            elif "sec" in dom and "tab-security" in _tab_dots:
                _tab_dots["tab-security"] = "danger"
            elif "net" in dom and "tab-network" in _tab_dots:
                _tab_dots["tab-network"] = "danger"

    # Rollup bar HTML
    _all_green = all(s == "success" for s, _, _, _ in _rollup_items)
    if _all_green:
        _rollup_bar_html = (
            "<div class='alert-rollup'>"
            "<span class='badge success' style='font-size:.85rem'>✅ All systems nominal</span>"
            "</div>"
        )
    else:
        _bar_badges = []
        for _sev, _lbl, _tid, _ in _rollup_items:
            if _sev != "success":
                _cls = _sev if _sev in ("danger", "warning") else "info"
                _bar_badges.append(f"<span class='badge {_cls}' style='font-size:.82rem'>{_lbl}</span>")
        _rollup_bar_html = (
            "<div class='alert-rollup'>"
            "<span style='font-size:.78rem;font-weight:700;color:var(--text-muted);"
            "text-transform:uppercase;letter-spacing:.05em;margin-right:.25rem'>Alerts</span>"
            + " ".join(_bar_badges)
            + "</div>"
        )

    # Rollup detail HTML
    _detail_rows = []
    for _sev, _lbl, _tid, _det in _rollup_items:
        _row_cls = {
            "danger":  "background:var(--tint-danger-bg,#fef2f2);border-left:3px solid var(--danger)",
            "warning": "background:var(--tint-warning-bg,#fefce8);border-left:3px solid var(--warning)",
            "success": "background:var(--tint-success-bg,#f0fdf4);border-left:3px solid var(--success)",
        }.get(_sev, "background:var(--tint-info-bg,#f8fafc);border-left:3px solid var(--text-muted)")
        _tab_label = {
            "tab-overview": "Overview", "tab-cpu": "CPU", "tab-bios": "BIOS",
            "tab-memory": "Memory", "tab-storage": "Storage", "tab-pcie": "PCIe",
            "tab-gpu": "GPU", "tab-network": "Networking", "tab-health": "Health",
            "tab-security": "Security", "tab-firmware": "Firmware Inventory",
        }.get(_tid, _tid)
        _detail_rows.append(
            f"<div style='{_row_cls};padding:.5rem .75rem;border-radius:4px;margin-bottom:.35rem;"
            f"display:flex;justify-content:space-between;align-items:center;gap:.5rem'>"
            f"<span style='font-size:.88rem'>{_lbl} &mdash; <span style='color:var(--text-muted)'>{_det}</span></span>"
            f"<a href='#{_tid}' data-jump-tab='{_tid}' class='btn-link tab-jump-link' "
            f"style='font-size:.8rem;white-space:nowrap'>{_tab_label} tab ↗</a>"
            f"</div>"
        )
    _rollup_detail_html = (
        "<div style='margin-bottom:1.5rem'>"
        "<h3 style='margin:0 0 .75rem;color:var(--h-color,#0f172a)'>System Assessment Summary</h3>"
        + "".join(_detail_rows)
        + "</div>"
    )

    return _rollup_bar_html, _rollup_detail_html, _tab_dots
