"""
VCF Readiness Tool — thermal, power supply, NVMe SMART & SEL report section builders (Layer D).
"""
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.report.helpers import _h


def render_psu_card_and_health_section(psu: Dict[str, Any]) -> Tuple[str, str]:
    """Render PSU summary card HTML and PSU detail section for Health tab."""
    psu = psu or {}
    _pm = psu.get("power_metrics") or {}
    _psu_watt_parts = []
    if psu.get("consumed_watts") is not None:
        _psu_watt_parts.append(f"Draw: <b>{psu['consumed_watts']} W</b>")
    if psu.get("total_capacity_watts"):
        _psu_watt_parts.append(f"Installed: <b>{psu['total_capacity_watts']} W</b>")
    if _pm.get("avg_w"):
        _psu_watt_parts.append(f"Avg: {_pm['avg_w']} W")
    if _pm.get("max_w"):
        _psu_watt_parts.append(f"Peak: {_pm['max_w']} W")
    _psu_watt_detail = " · ".join(_psu_watt_parts)

    _pcap_bdg = psu.get("power_cap_badge", "")
    _kwh_val = psu.get("consumed_energy_kwh")
    _kwh_line = f"<br><small style='color:var(--text-muted)'>⚡ Cumulative Energy: <b>{_kwh_val} kWh</b></small>" if _kwh_val is not None else ""
    _pcap_html = f"<div style='margin-top:.35rem'>{_pcap_bdg}</div>" if _pcap_bdg else ""

    psu_badge = psu.get("badge", "<span class='badge info'>ℹ️ N/A</span>")
    psu_summary = psu.get("summary", "")

    psu_card_html = (
        f"<div class='card'>"
        f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
        f"<h3 style='margin:0'>Power Supply</h3>"
        f"<a href='#tab-health' data-jump-tab='tab-health' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to Health section'>Details &rarr;</a>"
        f"</div>"
        f"<div>{psu_badge}</div>{_pcap_html}"
        f"<p style='font-size:.85rem;color:var(--text-muted);margin-top:.5rem'>{psu_summary}"
        f"{('<br>' + _psu_watt_detail) if _psu_watt_detail else ''}{_kwh_line}</p>"
        f"<div style='margin-top:.5rem;border-top:1px solid var(--border);padding-top:.4rem'>"
        f"<a href='#tab-health' data-jump-tab='tab-health' class='btn-link tab-jump-link' style='font-size:.78rem'>"
        f"Full details in Health tab &#8599;</a></div>"
        f"</div>"
    )

    _psu_health_section = ""
    if psu.get("psus"):
        _ph_rows = ""
        for _pu in psu["psus"]:
            _ph_h   = _pu.get("health", "Unknown")
            _ph_cls = "success" if _ph_h in ("OK", "Ok") else ("danger" if _ph_h == "Critical" else "warning")
            _ph_w   = _pu.get("wattage", "—")
            _ph_w_str = f"{_ph_w} W" if isinstance(_ph_w, (int, float)) else _h(str(_ph_w))
            _ph_rows += (
                f"<tr><td><strong>{_h(str(_pu.get('name', 'PSU')))}</strong></td>"
                f"<td>{_h(str(_pu.get('model', 'Unknown')))}</td>"
                f"<td>{_ph_w_str}</td>"
                f"<td><span class='badge {_ph_cls}'>{_h(_ph_h)}</span></td></tr>"
            )
        _psu_health_section = (
            f"<h2>Power Supply Detail</h2>"
            f"<table><thead><tr><th>PSU</th><th>Model / Part</th>"
            f"<th>Capacity</th><th>Health</th></tr></thead>"
            f"<tbody>{_ph_rows}</tbody></table>"
        )

    return psu_card_html, _psu_health_section


def render_thermal_health_section(thermal: Dict[str, Any]) -> Tuple[str, str]:
    """Render Thermal sensor matrix accordion and return (thermal_section_html, key_sensor_str)."""
    thermal = thermal or {}
    ks = thermal.get("key_sensor") or {}
    key_sensor_str = f"Key Sensor — <strong>{_h(str(ks.get('name', '')))}</strong>: <strong>{_h(str(ks.get('reading', '')))}</strong> (Warn: {_h(str(ks.get('threshold_warn', '')))}, Crit: {_h(str(ks.get('threshold_crit', '')))})" if ks else "All Sensors In Spec"
    thermal_rows = "".join(
        f"<tr><td><strong>{_h(str(s.get('name', '')))}</strong></td>"
        f"<td><b>{_h(str(s.get('reading', '')))}</b></td>"
        f"<td>{_h(str(s.get('threshold_warn', '')))}</td>"
        f"<td>{_h(str(s.get('threshold_crit', '')))}</td>"
        f"<td>{s.get('status_flag', '')}</td></tr>"
        for s in thermal.get("sensors", [])
    ) or "<tr><td colspan='5' style='color:var(--text-muted)'>No thermal sensors reported or scan run in Quick mode.</td></tr>"

    _default_thermal_badge = '<span class="badge info">ℹ️ N/A</span>'
    thermal_section_html = (
        f"<h2>Thermal &amp; Environmental Health</h2>"
        f"<details class='accordion'>"
        f"    <summary>"
        f"        <div>🌡️ Thermal: {thermal.get('overall_status_badge', _default_thermal_badge)} &nbsp;"
        f"        <span style='font-size:.85rem;color:var(--text-muted)'>{key_sensor_str}</span></div>"
        f"        <span style='font-size:.85rem;color:var(--primary)'>Expand Sensor Matrix ▾</span>"
        f"    </summary>"
        f"    <div class='accordion-body'><table><thead><tr><th>Sensor</th><th>Reading (°C)</th><th>Warn (°C)</th><th>Critical (°C)</th><th>Status</th></tr></thead><tbody>{thermal_rows}</tbody></table></div>"
        f"</details>"
    )
    return thermal_section_html, key_sensor_str


def render_nvme_smart_health_section(all_drives: List[Dict[str, Any]]) -> str:
    """Render NVMe SMART & Drive Health section for Health tab."""
    _pop_drives = [d for d in (all_drives or []) if d.get("populated", True)]
    if not _pop_drives:
        return ""

    def _is_critical(d: Dict[str, Any]) -> bool:
        end = d.get("endurance_remaining_pct")
        c_warn = d.get("critical_warnings")
        asp = d.get("available_spare_pct")
        thresh = d.get("available_spare_threshold")
        spare_below = False
        if isinstance(asp, (int, float)) and isinstance(thresh, (int, float)):
            spare_below = asp <= thresh
        return bool(
            d.get("failure_predicted")
            or (isinstance(end, (int, float)) and end < 20)
            or (isinstance(c_warn, (int, float)) and c_warn > 0)
            or spare_below
        )

    def _is_warning(d: Dict[str, Any]) -> bool:
        end = d.get("endurance_remaining_pct")
        un_shut = d.get("unsafe_shutdowns")
        m_err = d.get("media_errors")
        temp = d.get("temperature_c")
        poh = d.get("power_on_hours") or (d.get("oem_metrics") or {}).get("power_on_hours")
        _d_is_boot = bool(d.get("is_boot") or d.get("usage_role") == "Boot Drive" or "boot" in str(d.get("category", "")).lower() or any(k in str(d.get("model", "")).upper() for k in ["BOSS", "NS204I"]))
        return bool(
            (isinstance(end, (int, float)) and 20 <= end < 50)
            or (isinstance(un_shut, (int, float)) and un_shut > 0)
            or (isinstance(m_err, (int, float)) and m_err > 0)
            or (isinstance(temp, (int, float)) and temp >= 60)
            or (isinstance(poh, (int, float)) and poh >= 30000)
            or (isinstance(un_shut, (int, float)) and un_shut >= 50)
            or d.get("thermal_throttled")
            or (d.get("single_lane_alert") and not _d_is_boot)
            or (d.get("pcie_downshifted") and not _d_is_boot)
            or bool(d.get("error_description"))
        )

    _sh_critical_count = sum(1 for d in _pop_drives if _is_critical(d))
    _sh_warning_count  = sum(1 for d in _pop_drives if _is_warning(d))

    if _sh_critical_count > 0:
        _sh_rollup_badge = f"<span class='badge danger'>🔴 {_sh_critical_count} Drive(s) Critical / Imminent Failure</span>"
    elif _sh_warning_count > 0:
        _sh_rollup_badge = f"<span class='badge warning'>⚠️ {_sh_warning_count} Drive(s) with SMART Warnings</span>"
    else:
        _sh_rollup_badge = f"<span class='badge success'>🟢 All {len(_pop_drives)} Drive(s) Healthy</span>"

    _smart_rows = ""
    for _d in _pop_drives:
        _slot_lbl = f"Slot {_d.get('bay_slot', '?')}" if _d.get("bay_slot") is not None else "Bay"
        _m_str    = _h(str(_d.get("model", "Drive")))
        _sn_str   = _h(str(_d.get("serial_number", "N/A")))
        _pn_str   = _h(str(_d.get("product_id") or (_d.get("oem_metrics") or {}).get("part_number") or ""))

        _drive_col = f"<strong>{_slot_lbl}</strong>: {_m_str}<br><small style='color:var(--text-muted)'>SN: {_sn_str}</small>"
        if _pn_str and _pn_str not in ("N/A", "UNKNOWN") and _pn_str != _m_str:
            _drive_col += f"<br><small style='color:var(--text-muted)'>PN/PPID: {_pn_str}</small>"
        _err_desc = _h(str(_d.get("error_description") or ""))
        if _err_desc:
            _drive_col += f"<br><span class='badge warning' style='font-size:.7rem;' title='Hardware Error Description'>⚠️ {_err_desc}</span>"

        _poh_chk = _d.get("power_on_hours") or (_d.get("oem_metrics") or {}).get("power_on_hours")
        _us_chk = _d.get("unsafe_shutdowns")
        if (isinstance(_poh_chk, (int, float)) and _poh_chk >= 30000) or (isinstance(_us_chk, (int, float)) and _us_chk >= 50):
            _aging_reasons = []
            if isinstance(_poh_chk, (int, float)) and _poh_chk >= 30000:
                _aging_reasons.append(f"{int(_poh_chk):,}h POH")
            if isinstance(_us_chk, (int, float)) and _us_chk >= 50:
                _aging_reasons.append(f"{int(_us_chk)} shutdowns")
            _drive_col += f"<br><span class='badge warning' style='font-size:.7rem;' title='Aging / Wear Alert'>🟡 Aging / Wear Alert ({', '.join(_aging_reasons)})</span>"

        _proto = _h(str(_d.get("protocol", "NVMe")))
        _role  = _h(str(_d.get("usage_role", "Data Drive")))
        _ff    = _h(str(_d.get("form_factor_label") or "").strip())
        _sec   = _h(str(_d.get("security_status", "N/A")))

        _proto_col = f"<strong>{_proto}</strong>"
        if _ff:
            _proto_col += f" <span class='badge info' style='font-size:.7rem;'>{_ff}</span>"
        _proto_col += f"<br><small style='color:var(--text-muted)'>{_role}</small>"
        if _sec and _sec != "N/A":
            _sec_cls = "success" if _sec.lower() in ("unencrypted", "none", "unlocked", "ok") else "info"
            _proto_col += f"<br><span class='badge {_sec_cls}' style='font-size:.7rem;margin-top:2px;'>🔒 {_sec}</span>"
        _crypto_ok = _d.get("crypto_erase_capable")
        _erase_cap = _h(str(_d.get("erase_capability") or ""))
        if _crypto_ok or (_erase_cap and _erase_cap not in ("N/A", "None", "")):
            _proto_col += "<br><span class='badge info' style='font-size:.7rem;margin-top:2px;' title='Cryptographic Erase / Sanitize Capable'>🔒 Crypto Erase Capable</span>"

        _dh     = str(_d.get("drive_health", "OK")).strip()
        _c_warn = _d.get("critical_warnings")
        _fail_p = _d.get("failure_predicted", False) or (_d.get("oem_metrics") or {}).get("predictive_failure", False)
        if _fail_p or _dh in ("Critical", "Failure") or (isinstance(_c_warn, (int, float)) and _c_warn > 0):
            if isinstance(_c_warn, (int, float)) and _c_warn > 0:
                _h_badge = f"<span class='badge danger' title='NVMe Critical Warnings: {_c_warn}'>🔴 Critical Alert ({_c_warn})</span>"
            else:
                _h_badge = "<span class='badge danger'>🔴 Critical Failure</span>"
        elif _dh in ("Warning", "Degraded"):
            _h_badge = "<span class='badge warning'>⚠️ Warning</span>"
        else:
            _h_badge = "<span class='badge success'>🟢 OK</span>"

        _is_healthy = not _fail_p and _dh not in ("Critical", "Failure", "Warning", "Degraded") and not (isinstance(_c_warn, (int, float)) and _c_warn > 0)

        _end = _d.get("endurance_remaining_pct")
        if isinstance(_end, (int, float)):
            if _end < 20:
                _end_str = f"<span class='badge danger'>{_end}% (Critical)</span>"
            elif _end < 50:
                _end_str = f"<span class='badge warning'>{_end}% (Watch)</span>"
            else:
                _end_str = f"<span class='badge success'>{_end}%</span>"
        elif _d.get("is_magnetic"):
            _end_str = "<span style='color:var(--text-muted)'>N/A (HDD)</span>"
        elif _is_healthy:
            _end_str = "<span class='badge success'>OK</span>"
        else:
            _end_str = f"<span style='color:var(--text-muted)'>{_h(str(_end or 'N/A'))}</span>"

        _temp = _d.get("temperature_c")
        _throt = _d.get("thermal_throttled")
        _temp_parts = []
        if isinstance(_temp, (int, float)):
            if _temp >= 60:
                _temp_parts.append(f"<strong style='color:#dc2626'>{_temp}°C</strong>")
            elif _temp >= 50:
                _temp_parts.append(f"<strong style='color:#ca8a04'>{_temp}°C</strong>")
            else:
                _temp_parts.append(f"<span style='color:#16a34a'>{_temp}°C</span>")
        elif _is_healthy:
            _temp_parts.append("<span style='color:#16a34a'>OK</span>")
        else:
            _temp_parts.append("<span style='color:var(--text-muted)'>N/A</span>")

        if _throt:
            _temp_parts.append("<br><span class='badge warning'>🔥 Throttled</span>")
        _temp_html = "".join(_temp_parts)

        _us = _d.get("unsafe_shutdowns")
        if isinstance(_us, (int, float)) and _us > 0:
            _us_str = f"<strong style='color:#ca8a04'>⚠️ {_us}</strong>"
        elif isinstance(_us, (int, float)):
            _us_str = f"<span style='color:#16a34a'>{_us}</span>"
        elif _is_healthy:
            _us_str = "<span style='color:#16a34a'>0</span>"
        else:
            _us_str = "<span style='color:var(--text-muted)'>N/A</span>"

        _me = _d.get("media_errors") or (_d.get("oem_metrics") or {}).get("drive_error_count")
        if isinstance(_me, (int, float)) and _me > 0:
            _me_str = f"<strong style='color:#dc2626'>⚠️ {_me}</strong>"
        elif isinstance(_me, (int, float)):
            _me_str = f"<span style='color:#16a34a'>{_me}</span>"
        elif _is_healthy:
            _me_str = "<span style='color:#16a34a'>0</span>"
        else:
            _me_str = "<span style='color:var(--text-muted)'>N/A</span>"

        _spare  = _d.get("available_spare_pct")
        _thresh = _d.get("available_spare_threshold")
        _waf    = _d.get("write_amplification")
        _bad_n  = _d.get("bad_nand_blocks")
        _e_log  = _d.get("error_log_entries")
        _extra_parts = []
        if isinstance(_spare, (int, float)):
            _th_str = f" <small style='color:var(--text-muted)'>(Min {_thresh}%)</small>" if isinstance(_thresh, (int, float)) else ""
            if _spare < 10 or (isinstance(_thresh, (int, float)) and _spare <= _thresh):
                _extra_parts.append(f"Spare: <strong style='color:#dc2626'>{_spare}%</strong>{_th_str}")
            else:
                _extra_parts.append(f"Spare: <strong>{_spare}%</strong>{_th_str}")
        elif _is_healthy and not _d.get("is_magnetic"):
            _extra_parts.append("Spare: <strong style='color:#16a34a'>OK</strong>")

        if isinstance(_c_warn, (int, float)) and _c_warn > 0:
            _extra_parts.append(f"<span class='badge danger' style='font-size:.7rem;'>🔴 NVMe Alert ({_c_warn})</span>")

        if isinstance(_waf, (int, float)):
            _extra_parts.append(f"WAF: <strong>{_waf}</strong>")

        if isinstance(_bad_n, (int, float)):
            if _bad_n > 0:
                _extra_parts.append(f"Bad Blocks: <strong style='color:#ca8a04'>{_bad_n}</strong>")
            else:
                _extra_parts.append("Bad Blocks: <span style='color:#16a34a'>0</span>")
        elif _is_healthy and not _d.get("is_magnetic"):
            _extra_parts.append("Bad Blocks: <span style='color:#16a34a'>0</span>")

        if isinstance(_e_log, (int, float)) and _e_log > 0:
            _extra_parts.append(f"<span style='color:#ca8a04'>Log Errors: {_e_log}</span>")

        _reserve_html = "<br>".join(_extra_parts) if _extra_parts else "<span style='color:var(--text-muted)'>N/A</span>"

        _gen   = _d.get("pcie_gen") or ""
        _lanes = _d.get("pcie_lanes_in_use")
        _neg_w = _d.get("pcie_negotiated_width") or (f"x{_lanes}" if _lanes else "")
        _cap_w = _d.get("pcie_capable_width") or (f"x{_d.get('pcie_max_lanes')}" if _d.get('pcie_max_lanes') else "")
        _d_is_boot = bool(_d.get("is_boot") or _d.get("usage_role") == "Boot Drive" or "boot" in str(_d.get("category", "")).lower() or any(k in str(_d.get("model", "")).upper() for k in ["BOSS", "NS204I"]))
        _downshifted = _d.get("pcie_downshifted") and not _d_is_boot
        _pcie_errs = _d.get("pcie_bus_errors")
        _neg_speed = _d.get("negotiated_speed_gbs")
        _pcie_parts = []

        if _downshifted:
            _pcie_parts.append(f"<strong style='color:#dc2626'>⚠️ Downshifted ({_neg_w} of {_cap_w})</strong>")
        elif _gen or _neg_w:
            _pcie_parts.append(f"{_gen} {_neg_w}".strip())
            if _d.get("single_lane_alert") and not _d_is_boot:
                _pcie_parts.append("<br><strong style='color:#dc2626'>(x1 Warning)</strong>")
        elif _neg_speed:
            _pcie_parts.append(f"Speed: {_neg_speed} Gbps")
        elif _is_healthy:
            _pcie_parts.append("<span style='color:#16a34a'>OK</span>")

        _p_errors = _d.get("pcie_errors")
        if isinstance(_p_errors, dict):
            _fat = _p_errors.get("fatal_errors") or 0
            _non_fat = _p_errors.get("non_fatal_errors") or 0
            _l0 = _p_errors.get("l0_to_recovery_count") or 0
            _rep = _p_errors.get("replay_count") or 0
            _rol = _p_errors.get("replay_rollover_count") or 0
            _corr = _p_errors.get("correctable_errors") or 0

            _err_items = []
            if _fat > 0:
                _err_items.append(f"<strong style='color:#dc2626'>Fatal: {_fat}</strong>")
            if _l0 > 0:
                _err_items.append(f"<strong style='color:#ca8a04'>Retrains: {_l0}</strong>")
            if _rol > 0:
                _err_items.append(f"<strong style='color:#ca8a04'>Rollovers: {_rol}</strong>")
            if _rep > 0:
                _err_items.append(f"Replays: {_rep}")
            if _non_fat > 0:
                _err_items.append(f"NonFatal: {_non_fat}")
            if _corr > 0:
                _err_items.append(f"Corr: {_corr}")

            if _err_items:
                _pcie_parts.append("<br><span style='font-size:0.8em'>" + " | ".join(_err_items) + "</span>")
            else:
                _pcie_parts.append("<br><span style='color:#16a34a;font-size:0.8em'>Errors: 0</span>")
        elif isinstance(_pcie_errs, (int, float)):
            if _pcie_errs > 0:
                _pcie_parts.append(f"<br>Errors: <strong style='color:#ca8a04'>{_pcie_errs}</strong>")
            else:
                _pcie_parts.append("<br>Errors: <span style='color:#16a34a'>0</span>")

        _pcie_html = "".join(_pcie_parts) if _pcie_parts else "<span style='color:var(--text-muted)'>N/A</span>"

        _poh    = _d.get("power_on_hours") or (_d.get("oem_metrics") or {}).get("power_on_hours")
        _tbw    = _d.get("tbw_written")
        _tbr    = _d.get("tbr_read")
        _cycles = _d.get("power_cycles")
        _duty   = _d.get("controller_duty_cycle_pct")
        _life_parts = []
        if isinstance(_poh, (int, float)):
            _cyc_str = f" <small style='color:var(--text-muted)'>({int(_cycles):,} cyc)</small>" if isinstance(_cycles, (int, float)) else ""
            _life_parts.append(f"POH: {int(_poh):,} hrs{_cyc_str}")

        if isinstance(_tbw, (int, float)) or isinstance(_tbr, (int, float)):
            _io_strs = []
            if isinstance(_tbw, (int, float)):
                _io_strs.append(f"W: {round(_tbw, 1)} TB")
            if isinstance(_tbr, (int, float)):
                _io_strs.append(f"R: {round(_tbr, 1)} TB")
            _life_parts.append(" | ".join(_io_strs))

            if isinstance(_tbw, (int, float)) and isinstance(_tbr, (int, float)) and (_tbw + _tbr) > 0:
                _tot_io = _tbw + _tbr
                _r_pct = round((_tbr / _tot_io) * 100)
                _w_pct = 100 - _r_pct
                _life_parts.append(f"<small style='color:var(--text-muted)'>Ratio: {_r_pct}% R / {_w_pct}% W</small>")

        if isinstance(_duty, (int, float)):
            _life_parts.append(f"<small style='color:var(--text-muted)'>Duty: {_duty}% busy</small>")

        _life_html = "<br>".join(_life_parts) if _life_parts else "<span style='color:var(--text-muted)'>N/A</span>"

        _smart_rows += (
            f"<tr>"
            f"<td>{_drive_col}</td>"
            f"<td>{_proto_col}</td>"
            f"<td>{_h_badge}</td>"
            f"<td>{_end_str}</td>"
            f"<td>{_temp_html}</td>"
            f"<td>{_us_str}</td>"
            f"<td>{_me_str}</td>"
            f"<td><small>{_reserve_html}</small></td>"
            f"<td><small>{_pcie_html}</small></td>"
            f"<td><small>{_life_html}</small></td>"
            f"</tr>"
        )

    return (
        f"<h2>💾 NVMe SMART &amp; Drive Health Summary</h2>"
        f"<details class='accordion' open>"
        f"  <summary>"
        f"    <div>💾 Drive SMART Telemetry: {_sh_rollup_badge} &nbsp;"
        f"    <span style='font-size:.85rem;color:var(--text-muted)'>{len(_pop_drives)} drive(s) scanned</span></div>"
        f"    <span style='font-size:.85rem;color:var(--primary)'>Toggle Details ▾</span>"
        f"  </summary>"
        f"  <div class='accordion-body'>"
        f"    <table><thead><tr>"
        f"      <th>Drive / Model</th><th>Protocol &amp; Role</th><th>Health</th><th>Endurance</th>"
        f"      <th>Temp / Throttling</th><th>Unsafe Shutdowns</th><th>Media Errors</th>"
        f"      <th>Spare / WAF / Bad Blocks</th><th>PCIe Bus &amp; Width</th><th>Workload / POH</th>"
        f"    </tr></thead>"
        f"    <tbody>{_smart_rows}</tbody></table>"
        f"  </div>"
        f"</details>"
    )


def render_sel_section(sel: List[Dict[str, Any]], vendor: Optional[str] = None) -> str:
    """Render System Event Log (SEL / IML) rows."""
    from vcf_hci.report.components import _sel_row
    return "".join(_sel_row(a, vendor=vendor) for a in (sel or [])) or "<tr><td colspan='4' style='color:var(--text-muted)'>No critical or warning event log entries reported in the last 12 months.</td></tr>"


def render_bmc_diagnostics_section(data: Optional[Dict[str, Any]]) -> str:
    """Render BMC Diagnostics, Active Session Capacity, and Redfish Protocol Capabilities section."""
    if not data:
        return ""
    meta = data.get("collector_metadata") or {}
    session_warning = data.get("bmc_session_warning") or meta.get("bmc_session_warning")
    session_count = data.get("active_sessions_count") if data.get("active_sessions_count") is not None else meta.get("active_sessions_count")
    diag = data.get("diagnostics") if isinstance(data.get("diagnostics"), dict) else {}

    if not session_warning and session_count is None and not diag:
        return ""

    parts = ["<h2>BMC Diagnostics &amp; Active Session Health</h2>"]

    if session_warning:
        parts.append(
            f"<div class='alert alert-warning' style='margin-bottom:1.25rem;padding:1rem 1.25rem;border-left:4px solid var(--warning,#ca8a04);border-radius:6px'>"
            f"<strong>⚠️ BMC Active Session Capacity Warning:</strong> {_h(str(session_warning))}"
            f"<p style='margin:0.4rem 0 0;font-size:0.85rem;color:var(--text-muted)'>"
            f"High concurrent active sessions on the BMC management processor can exhaust HTTP session pools (standard limit is 16 sessions). "
            f"Recommend reviewing automated tooling or resetting BMC sessions (e.g. via <code>racadm racreset</code> or <code>iloreset</code>) to prevent management lockouts and collection failures.</p>"
            f"</div>"
        )
    elif session_count is not None:
        parts.append(
            f"<div style='margin-bottom:1.25rem;padding:0.75rem 1rem;background:var(--code-bg,#f8fafc);border:1px solid var(--border);border-radius:6px;font-size:0.85rem'>"
            f"<span class='badge success' style='font-size:.74rem'>🟢 Session Pool Normal</span> &nbsp; "
            f"Active BMC Sessions: <strong>{session_count}</strong> / 16 ceiling. Session hygiene verified."
            f"</div>"
        )

    if diag:
        from vcf_hci.report.sections.overview import render_protocol_diagnostics_badges
        exp_badge, pipe_badge, pacing_badge = render_protocol_diagnostics_badges(data)

        expand_supp = bool(diag.get("expand_supported", False))
        if expand_supp:
            syn = diag.get("expand_syntax") or "*"
            lvl = diag.get("expand_max_levels") or 1
            exp_desc = f"Supported ($expand={syn}, levels={lvl})"
        else:
            exp_desc = "Disabled / Unsupported (iterative member traversal)"

        pipe_supp = bool(diag.get("multiple_http_requests", False))
        pipe_desc = "Supported (concurrent pipelined HTTP requests enabled)" if pipe_supp else "Standard (single request per TLS connection)"

        pacing_val = diag.get("request_pacing_s")
        if pacing_val is not None:
            try:
                p_f = float(pacing_val)
            except (ValueError, TypeError):
                p_f = 0.05
        else:
            p_f = 0.05
        pacing_desc = "0.0ms delay (pipelined zero-pacing)" if p_f == 0.0 else f"{int(round(p_f * 1000))}ms conservative inter-request pacing"

        req_cnt = diag.get("request_count", "N/A")
        scan_dur = diag.get("total_scan_duration_s") or data.get("scan_duration_sec", "N/A")
        avg_lat = diag.get("avg_get_latency_ms", "N/A")
        unsupp = diag.get("unsupported_expand_endpoints") or []
        unsupp_str = ", ".join(f"<code>{_h(str(u))}</code>" for u in unsupp) if unsupp else "None (all collections expanded)"

        parts.append(
            f"<div class='card' style='margin-bottom:1.25rem;padding:1rem 1.25rem'>"
            f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem;flex-wrap:wrap;gap:.5rem'>"
            f"<h3 style='margin:0;font-size:1rem'>Redfish Protocol Capabilities &amp; Optimization Telemetry</h3>"
            f"<div style='display:flex;gap:.4rem;flex-wrap:wrap;align-items:center'>"
            f"{exp_badge} {pipe_badge} {pacing_badge}"
            f"</div>"
            f"</div>"
            f"<table style='width:100%;font-size:.85rem;border-collapse:collapse'>"
            f"<thead><tr><th style='text-align:left;padding:6px 10px'>Protocol Feature</th><th style='text-align:left;padding:6px 10px'>Status / Value</th><th style='text-align:left;padding:6px 10px'>Telemetry Details</th></tr></thead>"
            f"<tbody>"
            f"<tr><td style='padding:6px 10px'><strong>OData Collection Expansion</strong></td><td style='padding:6px 10px'>{exp_badge}</td><td style='padding:6px 10px'>{_h(exp_desc)}</td></tr>"
            f"<tr><td style='padding:6px 10px'><strong>HTTP Connection Pipelining</strong></td><td style='padding:6px 10px'>{pipe_badge}</td><td style='padding:6px 10px'>{_h(pipe_desc)}</td></tr>"
            f"<tr><td style='padding:6px 10px'><strong>Inter-Request Pacing Delay</strong></td><td style='padding:6px 10px'>{pacing_badge}</td><td style='padding:6px 10px'>{_h(pacing_desc)}</td></tr>"
            f"<tr><td style='padding:6px 10px'><strong>HTTP Requests &amp; Latency</strong></td><td style='padding:6px 10px'><code>{req_cnt}</code> requests</td><td style='padding:6px 10px'>Avg BMC GET latency: <code>{avg_lat} ms</code> &middot; Scan duration: <code>{scan_dur} s</code></td></tr>"
            f"<tr><td style='padding:6px 10px'><strong>Expansion Fallback Endpoints</strong></td><td style='padding:6px 10px' colspan='2'>{unsupp_str}</td></tr>"
            f"</tbody>"
            f"</table>"
            f"</div>"
        )

    return "".join(parts)


def render_job_queue_card_and_health_section(data: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """Render Lifecycle Controller Job Queue summary card for overview grid and detail section for Health tab."""
    if not data:
        return "", ""
    job_q = data.get("job_queue")
    if not isinstance(job_q, dict) or not job_q:
        return "", ""

    total_jobs = int(job_q.get("total_jobs") or 0)
    failed_jobs = int(job_q.get("failed_jobs") or 0)
    stale_jobs = int(job_q.get("stale_jobs") or 0)
    pending_reboot_jobs = int(job_q.get("pending_reboot_jobs") or 0)
    jobs = job_q.get("jobs") or []

    # Status badge & color
    if failed_jobs > 0 or stale_jobs > 0:
        badge_cls = "warning"
        badge_icon = "⚠️"
        badge_lbl = f"{failed_jobs} Failed, {stale_jobs} Stale"
        card_summary = f"Stale/Failed LC Jobs Detected ({failed_jobs} failed, {stale_jobs} stale). May block VCF host staging or reboot."
        remediation_hint = "Log into iDRAC Web UI or run RACADM <code>jobqueue delete</code> to clear stalled tasks prior to VCF commissioning."
    elif pending_reboot_jobs > 0:
        badge_cls = "info"
        badge_icon = "⏳"
        badge_lbl = f"{pending_reboot_jobs} Pending Reboot"
        card_summary = f"Configuration jobs staged ({pending_reboot_jobs} job{'s' if pending_reboot_jobs > 1 else ''}) and awaiting server reboot."
        remediation_hint = "Reboot server to complete pending lifecycle configuration tasks."
    else:
        badge_cls = "success"
        badge_icon = "✅"
        badge_lbl = "Queue Clean"
        card_summary = f"No stalled or failed lifecycle tasks ({total_jobs} total historical jobs)."
        remediation_hint = "Lifecycle Controller job queue is clear."

    badge_html = f"<span class='badge {badge_cls}'>{badge_icon} {badge_lbl}</span>"

    # Overview Card HTML
    card_html = (
        f"<div class='card'>"
        f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
        f"<h3 style='margin:0'>LC Job Queue</h3>"
        f"<a href='#tab-health' data-jump-tab='tab-health' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to Health section'>Details &rarr;</a>"
        f"</div>"
        f"<div>{badge_html}</div>"
        f"<p style='font-size:.85rem;color:var(--text-muted);margin-top:.5rem'>{_h(card_summary)}</p>"
        f"<div style='margin-top:.5rem;border-top:1px solid var(--border);padding-top:.4rem'>"
        f"<a href='#tab-health' data-jump-tab='tab-health' class='btn-link tab-jump-link' style='font-size:.78rem'>"
        f"Full details in Health tab &#8599;</a></div>"
        f"</div>"
    )

    # Health Detail Section HTML
    troubled_jobs = [j for j in jobs if j.get("is_failed") or j.get("is_stale") or j.get("is_pending_reboot")]
    other_jobs = [j for j in jobs if not (j.get("is_failed") or j.get("is_stale") or j.get("is_pending_reboot"))]
    ordered_jobs = troubled_jobs + other_jobs

    job_rows = ""
    for j in ordered_jobs:
        j_id = _h(str(j.get("id") or "—"))
        j_name = _h(str(j.get("name") or "Job"))
        j_state = str(j.get("state") or "Unknown")
        j_pct = f"{j['percent_complete']}%" if j.get("percent_complete") is not None else "—"
        j_start = _h(str(j.get("start_time") or "—"))
        j_dur = f"{j['duration_seconds']}s" if j.get("duration_seconds") is not None else "—"
        if j.get("duration_seconds") and j["duration_seconds"] > 3600:
            hrs = round(j["duration_seconds"] / 3600.0, 1)
            j_dur = f"{hrs}h"

        j_msg = _h(str(j.get("message") or "—"))

        if j.get("is_failed"):
            st_cls = "danger"
            st_icon = "🔴"
        elif j.get("is_stale"):
            st_cls = "warning"
            st_icon = "⚠️"
        elif j.get("is_pending_reboot"):
            st_cls = "info"
            st_icon = "⏳"
        elif "completed" in j_state.lower():
            st_cls = "success"
            st_icon = "✓"
        else:
            st_cls = "info"
            st_icon = "ℹ️"

        st_badge = f"<span class='badge {st_cls}'>{st_icon} {_h(j_state)}</span>"

        job_rows += (
            f"<tr>"
            f"<td><strong>{j_id}</strong></td>"
            f"<td>{j_name}</td>"
            f"<td>{st_badge}</td>"
            f"<td>{j_pct}</td>"
            f"<td>{j_start}</td>"
            f"<td>{j_dur}</td>"
            f"<td style='max-width:320px;word-break:break-word'>{j_msg}</td>"
            f"</tr>"
        )

    if not job_rows:
        job_rows = "<tr><td colspan='7' style='color:var(--text-muted)'>No active or historical jobs in queue.</td></tr>"

    remediation_banner = ""
    if failed_jobs > 0 or stale_jobs > 0:
        remediation_banner = (
            f"<div class='alert alert-warning' style='margin-bottom:1rem;padding:0.75rem 1rem;border-left:4px solid var(--warning,#ca8a04);border-radius:6px;font-size:0.85rem'>"
            f"<strong>⚠️ Action Recommended:</strong> {_h(card_summary)}<br>"
            f"<strong>Remediation:</strong> {remediation_hint}"
            f"</div>"
        )

    is_open = "open" if (failed_jobs > 0 or stale_jobs > 0) else ""

    health_section_html = (
        f"<div style='margin-top:1.5rem'>"
        f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem'>"
        f"<h2 style='margin:0'>Lifecycle Controller (LC) Job Queue Pre-Flight Audit</h2>"
        f"<div>{badge_html}</div>"
        f"</div>"
        f"{remediation_banner}"
        f"<details class='accordion' {is_open}>"
        f"<summary>"
        f"<div>📋 Itemized Job Queue ({len(jobs)} jobs inspected, {failed_jobs} failed, {stale_jobs} stale)</div>"
        f"<span style='font-size:.85rem;color:var(--primary)'>Toggle Details &#9662;</span>"
        f"</summary>"
        f"<div class='accordion-body' style='padding:1rem'>"
        f"<table>"
        f"<thead><tr><th>Job ID</th><th>Name / Task</th><th>State</th><th>Progress</th><th>Start Time</th><th>Duration</th><th>Status Message</th></tr></thead>"
        f"<tbody>{job_rows}</tbody>"
        f"</table>"
        f"</div>"
        f"</details>"
        f"</div>"
    )

    return card_html, health_section_html
