"""
VCF Readiness Tool — header, banners & alert rollup report section builders (Layer D).
"""
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.bios.x2apic import LEGACY_X2APIC_WARNING, x2apic_recommendation
from vcf_hci.branding import MARK_SVG
from vcf_hci.obfuscation import _pii_span
from vcf_hci.report.helpers import _h, host_has_redfish_latency
from vcf_hci.report.inventory_tables import _is_boot_ctrl
from vcf_hci.ui_clarity import icon_html


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
    """Render compact host identity, metadata and assessment notices."""
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

    _obf_controls = (
        '<details class="report-obfuscation"><summary>' + icon_html("lock") + ' Obfuscated Report</summary>'
        '<p>Host identifiers have been replaced with hash tokens. Identical tokens represent '
        'identical values. Hardware specifications and readiness verdicts are unchanged.</p></details>'
    ) if obfuscated else (
        '<label class="report-view-mask" title="Cosmetic in-browser mask. Use generated obfuscated reports for sharing.">'
        '<input type="checkbox" id="maskPII"> Obfuscate view</label>'
        '<a id="dlObf" href="#" style="display:none" class="btn-link" title="Download obfuscated HTML copy">Save obfuscated copy</a>'
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

    _os_present = bool(_os_name.strip() and _os_name.strip().lower() not in
                       ("unknown", "n/a", "not reported", "notreported", "none"))
    _os_header_disp = (
        '<span class="report-host-os">' + icon_html("computer") + ' OS: ' + (_os_upd_lbl or _os_name)
        + ' ' + _os_eol_b
        + (('<a href="' + _h(_os_kb_url) + '" target="_blank" rel="noopener noreferrer" class="btn-link">KB ↗</a>') if _os_kb_url else '')
        + '</span>'
    ) if _os_present else ''

    _chassis_lbl = sys_info.get("chassis_label", "")
    _enc = sys_info.get("enclosure_info") or (scan_data.get("system") or {}).get("enclosure_info") or {}
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
    _chassis_span = f' &nbsp;<span style="font-size:.82rem;color:var(--text-muted)">· {_h(str(_chassis_lbl))}</span>' if _chassis_lbl else ""

    _detail_rows = [
        (_sn_label, f'<code>{_pii_serial}</code>'),
        ("SKU", f'<code>{_pii_sku}</code>' if _has_sku else ''),
        ("BIOS", _h(str(sys_info.get("bios_version") or ''))),
        ("Power", _h(str(sys_info.get("power_state") or ''))),
        ("Health", _h(str(sys_info.get("health") or ''))),
        ("Health rollup", _h(str(sys_info.get("health_rollup") or ''))),
        ("Boot", _h(str((sys_info.get("boot_progress") or {}).get("last_state") or ''))),
        ("Collection protocol", _h(wsman_proto_label if data_src.startswith("wsman") else "Redfish")),
    ]
    _watchdog = sys_info.get("watchdog") or {}
    if isinstance(_watchdog, dict) and isinstance(_watchdog.get("function_enabled"), bool):
        _detail_rows.append(("Watchdog", "Enabled" if _watchdog["function_enabled"] else "Disabled"))
    _detail_html = ''.join(f'<dt>{_h(label)}</dt><dd>{value}</dd>' for label, value in _detail_rows if value)
    header_html = (
        f'{_warning_banner}'
        f'<header class="header report-host-header">'
        f'<div class="report-host-title"><h1>{MARK_SVG}VCF / vSphere 9.1 Readiness Assessment</h1>'
        f'{_obf_controls}<button id="themeToggle" title="Toggle dark/light mode">Dark</button></div>'
        f'<div class="report-host-identity"><strong>{_pii_host_label}</strong>'
        f' · {_h(str(sys_info.get("vendor", "")))} {_h(str(sys_info.get("model", "")))}{_chassis_span}'
        f'{(" · Target IP: " + _pii_ip_label) if (_ip and _ip not in host_display_label) else ""}'
        f'{(" · " + sys_info.get("liquid_cooling_badge")) if sys_info.get("liquid_cooling_badge") else ""}</div>'
        f'<div class="report-host-actions">'
        f'<details class="report-host-details"><summary>Host details</summary><dl>{_detail_html}</dl></details>'
        f'{_os_header_disp}'
        f'<a href="{bcg_server_url}" target="_blank" rel="noopener noreferrer" class="btn-link">{icon_html("host")} BCG Server Search ↗</a>'
        f'<a href="{bcg_cpu_url}" target="_blank" rel="noopener noreferrer" class="btn-link">{icon_html("cpu")} BCG CPU Search ↗</a>'
        f'</div></header>'
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
    ) if sys_info.get("hci_appliance") or sys_info.get("is_storage_appliance") else ""

    # Nutanix-on-Supermicro HCI posture card (dual identity, boot RAID, FixedBootOrder, security, FW depth)
    hci_posture_card = ""
    _vendor_u = str(sys_info.get("vendor") or "").upper()
    _model_u = str(sys_info.get("model") or "").upper()
    _is_nutanix_hci = bool(sys_info.get("hci_appliance")) or "NUTANIX" in _vendor_u or _model_u.startswith("NX-")
    if _is_nutanix_hci:
        _ch = sys_info.get("chassis_hardware") if isinstance(sys_info.get("chassis_hardware"), dict) else {}
        _fbo = sys_info.get("fixed_boot_order") if isinstance(sys_info.get("fixed_boot_order"), dict) else {}
        _sb = (data or {}).get("secure_boot") if isinstance((data or {}).get("secure_boot"), dict) else {}
        _fw_inv = (data or {}).get("firmware_inventory") or []
        _storage = (data or {}).get("storage_subsystem") or []
        _boot_ctrls = [c for c in _storage if isinstance(c, dict) and _is_boot_ctrl(c)]
        _cap_ctrls = [c for c in _storage if isinstance(c, dict) and not _is_boot_ctrl(c)]
        _boot_bits = []
        for c in _boot_ctrls[:2]:
            vols = c.get("volumes") or []
            v0 = vols[0] if vols else {}
            _boot_bits.append(
                f"{_h(c.get('ctrl_model') or c.get('name') or 'Boot ctrl')}"
                f" · {_h(v0.get('raid_type') or v0.get('volume_type') or 'RAID')}"
                f" {_h(v0.get('vd_name') or v0.get('name') or '')}".rstrip()
            )
        _cap_bits = []
        for c in _cap_ctrls[:2]:
            n_drv = len(c.get("drives") or [])
            _cap_bits.append(f"{_h(c.get('name') or 'NVMeSSD')} ({n_drv} drives)")
        _esxi_hint = ""
        for b in (sys_info.get("boot_order_details") or []):
            if isinstance(b, dict) and "esxi" in str(b.get("name") or "").lower():
                _esxi_hint = str(b.get("name") or "")
                break
        if not _esxi_hint:
            uhd = _fbo.get("uefi_hard_disk")
            if isinstance(uhd, list) and uhd:
                _esxi_hint = str(uhd[0])
            elif isinstance(uhd, str) and uhd:
                _esxi_hint = uhd
        _golden = ""
        _backup = ""
        for fi in _fw_inv if isinstance(_fw_inv, list) else []:
            if not isinstance(fi, dict):
                continue
            _fid = str(fi.get("Id") or fi.get("Name") or "")
            if "Golden_BIOS" in _fid or _fid == "Golden_BIOS":
                _golden = str(fi.get("Version") or "")[:80]
            if "Backup_BIOS" in _fid or _fid == "Backup_BIOS":
                _backup = str(fi.get("Version") or "")[:80]
        _sb_mode = str(_sb.get("SecureBootMode") or _sb.get("mode") or "").strip()
        _sb_en = _sb.get("SecureBootEnable")
        if _sb_en is None:
            _sb_en = _sb.get("enabled")
        _tpm_note = str(sys_info.get("tpm_posture_note") or "").strip()
        _identity_line = (
            f"<b>Appliance</b> {_h(sys_info.get('vendor'))} {_h(sys_info.get('model'))}"
            f" &nbsp;·&nbsp; <b>Chassis</b> {_h(_ch.get('manufacturer') or 'Supermicro')} "
            f"{_h(_ch.get('part_number') or _ch.get('model') or '')}"
        )
        if _ch.get("board_id"):
            _identity_line += f" &nbsp;·&nbsp; BoardID {_h(_ch.get('board_id'))}"
        _rows = [
            ("Identity", _identity_line),
            ("Boot storage", " · ".join(_boot_bits) or "Marvell HA-RAID boot path not enumerated"),
            ("Capacity NVMe", " · ".join(_cap_bits) or "NVMeSSD topology not enumerated"),
            ("Boot order", _h(_esxi_hint) or _h(_fbo.get("boot_mode_selected") or sys_info.get("boot_mode") or "—")),
            (
                "Security",
                (
                    f"SecureBoot={'Enabled' if _sb_en else ('Disabled' if _sb_en is False else 'Unknown')}"
                    + (f" ({_h(_sb_mode)})" if _sb_mode else "")
                    + (f" · {_h(_tpm_note)}" if _tpm_note else f" · TPM {_h(sys_info.get('tpm_state') or 'NotReported')}")
                ),
            ),
        ]
        if _golden or _backup:
            _rows.append(("FW depth", f"Golden BIOS: {_h(_golden) or '—'} · Backup BIOS: {_h(_backup) or '—'}"))
        _row_html = "".join(
            f"<tr><td style='color:var(--text-muted);padding:.2rem .6rem .2rem 0;white-space:nowrap'>{_h(k)}</td>"
            f"<td style='padding:.2rem 0'>{v}</td></tr>"
            for k, v in _rows
        )
        hci_posture_card = (
            '<details class="report-posture-card" style="background:var(--surface,#fff);border:1px solid var(--border,#e2e8f0);'
            'border-left:4px solid #ea580c;padding:.75rem 1rem;border-radius:6px;margin-bottom:1rem;font-size:.85rem">'
            '<summary class="report-posture-heading">Nutanix Appliance · Supermicro Chassis Posture</summary>'
            f'<table style="border-collapse:collapse;width:100%">{_row_html}</table>'
            '</details>'
        )

    generic_banner = (
        '<div style="background:var(--callout-info-bg,#eff6ff);border:1px solid var(--callout-info-border,#bfdbfe);'
        'border-left:4px solid var(--primary,#2563eb);padding:.6rem 1rem;border-radius:6px;margin-bottom:1rem;font-size:.85rem;'
        'color:var(--callout-info-h,#1e40af);display:flex;align-items:center;justify-content:space-between">'
        '<span>No OEM adapter matched this BMC. Inventory is DMTF Redfish only. Capture a sanitized dump with <code>tools/redfishMockupCreate.py</code> and see <code>docs/adding-oem-support.md</code>.</span>'
        '</div>'
    ) if collector_class == "GenericCollector" else ""

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

    _findings = []
    for _f in scan_data.get("hardware_findings") or []:
        if isinstance(_f, dict):
            _findings.append(f"<li><code>{_h(str(_f.get('tag') or ''))}</code> {_h(str(_f.get('detail') or ''))}</li>")
    _warnings = list(scan_data.get("readiness_findings") or []) + list(scan_data.get("readiness_warnings") or [])
    for _rw in dict.fromkeys(str(w) for w in _warnings):
        if _rw == LEGACY_X2APIC_WARNING:
            _rw = x2apic_recommendation(sys_info.get("cpu_summary") or {})
        _findings.append(f"<li>{_h(_rw)}</li>")
    findings_banner = (
        '<details class="report-findings alert alert-warning"><summary>'
        + icon_html("warning-standard") + f' Hardware findings · {len(_findings)} '
        + ('item' if len(_findings) == 1 else 'items')
        + ' — review recommended</summary><ul>' + ''.join(_findings) + '</ul></details>'
        if _findings else ""
    )
    banners_html = (
        f"{_blade_banner}{_quad_banner}{quick_banner}{wsman_banner}"
        f"{appliance_banner}{hci_posture_card}{generic_banner}{findings_banner}"
    )
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

    # Storage. Collectors persist drive status as drive_health; health/status remain fallbacks.
    def _drive_health_token(drive: Dict[str, Any]) -> str:
        return str(drive.get("drive_health") or drive.get("health") or drive.get("status") or "").lower()

    _stor_degraded = sum(
        1 for ctrl in storage for d in ctrl.get("drives", [])
        if _drive_health_token(d) in ("critical", "warning", "failed", "degraded")
    )
    _stor_low_endurance = sum(
        1 for ctrl in storage for d in ctrl.get("drives", [])
        if isinstance(d.get("endurance_remaining_pct"), (int, float))
        and 0 <= d["endurance_remaining_pct"] < 20
        and d["endurance_remaining_pct"] != 255
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

    # Memory. The collector stores DIMMs on dimm_list; dimms is the legacy alias.
    _dimm_rows = mem_info.get("dimm_list") or mem_info.get("dimms") or []
    _mem_failed = sum(
        1 for dimm in _dimm_rows
        if str(dimm.get("health", "")).lower() in ("critical", "failed")
    )
    _mem_score = mem_topo.get("interleaving_score_pct", 100)
    if _mem_failed:
        _rollup_items.append(("danger", f"🔴 {_mem_failed} DIMM fault{'s' if _mem_failed>1 else ''}", "tab-memory",
                               f"{_mem_failed} DIMM(s) reporting Critical health — check memory slots."))
    elif _mem_score < 60:
        _rollup_items.append(("warning", f"⚠️ Memory interleaving {_mem_score}%", "tab-memory",
                               f"Channel interleaving efficiency is low ({_mem_score}%) — review DIMM population."))
    elif _dimm_rows:
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

    # Fibre Channel HBAs
    _fc_hbas_list = (data.get("fc_hbas") or []) if data else []
    if _fc_hbas_list:
        _fc_down = [h for h in _fc_hbas_list if str(h.get("link_status", "")).lower() in ("down", "nolink")]
        _fc_downgraded = [h for h in _fc_hbas_list if h.get("downgraded")]
        _fc_up = [h for h in _fc_hbas_list if str(h.get("link_status", "")).lower() == "up"]
        if _fc_downgraded:
            _rollup_items.append((
                "warning",
                f"⚠️ {len(_fc_downgraded)} FC HBA port{'s' if len(_fc_downgraded)>1 else ''} PCIe downgraded",
                "tab-hba",
                "One or more Fibre Channel HBAs running below maximum PCIe link width or generation.",
            ))
        elif _fc_down and not _fc_up:
            _rollup_items.append((
                "warning",
                f"⚠️ {len(_fc_down)} FC HBA port{'s' if len(_fc_down)>1 else ''} link-down",
                "tab-hba",
                "All detected Fibre Channel ports are link-down or disconnected from SAN fabric.",
            ))
        elif _fc_up:
            _speeds = sorted({f"{h['speed_gbps']} Gbps" for h in _fc_up if h.get("speed_gbps") and h.get("speed_gbps") != "N/A"})
            _spd_str = f" ({', '.join(_speeds)})" if _speeds else ""
            _rollup_items.append((
                "success",
                f"✅ FC HBA: {len(_fc_up)} Port{'s' if len(_fc_up)>1 else ''} Linked{_spd_str}",
                "tab-hba",
                "Fibre Channel SAN connectivity established.",
            ))
        else:
            _rollup_items.append((
                "info",
                f"ℹ️ FC HBA: {len(_fc_hbas_list)} Port{'s' if len(_fc_hbas_list)>1 else ''} Discovered",
                "tab-hba",
                "Fibre Channel host bus adapters detected.",
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
            x2apic_recommendation(((data or {}).get("system") or {}).get("cpu_summary") or {}),
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
        _rollup_items.append(("danger", f"🔴 Security: Action Suggested{_fail_txt}", "tab-security", _detail_txt))
    elif any("warning" in b for b in _sec_rollup_badges):
        _rollup_items.append(("warning", "⚠️ Security: Review Recommended", "tab-security",
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
        or (isinstance(d.get("endurance_remaining_pct"), (int, float)) and 0 <= d.get("endurance_remaining_pct") < 20 and d.get("endurance_remaining_pct") != 255)
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
            (isinstance(d.get("endurance_remaining_pct"), (int, float)) and 20 <= d.get("endurance_remaining_pct") < 50 and d.get("endurance_remaining_pct") != 255)
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
    _tab_ids = ["tab-overview", "tab-cpu", "tab-bios", "tab-memory", "tab-storage", "tab-pcie", "tab-network", "tab-health", "tab-security", "tab-hba", "tab-firmware"]
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
            "tab-security": "Security", "tab-hba": "HBA", "tab-firmware": "Firmware Inventory",
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
