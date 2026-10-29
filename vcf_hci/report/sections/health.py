"""
VCF Readiness Tool — thermal, power supply, NVMe SMART & SEL report section builders (Layer D).
"""
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.report.helpers import _h
from vcf_hci.storage_pcie import drive_link_description, drive_pcie_view
from vcf_hci.ui_clarity import icon_html


def render_psu_card_and_health_section(psu: Dict[str, Any]) -> Tuple[str, str]:
    """Render PSU summary card HTML and PSU detail section for Health tab."""
    psu = psu or {}
    _pm = psu.get("power_metrics") or {}
    _psu_watt_parts = []
    if psu.get("consumed_watts") is not None:
        _psu_watt_parts.append(f"Draw: <b>{_h(str(psu['consumed_watts']))} W</b>")
    if psu.get("total_capacity_watts"):
        _psu_watt_parts.append(f"Installed: <b>{_h(str(psu['total_capacity_watts']))} W</b>")
    if _pm.get("avg_w") is not None:
        _psu_watt_parts.append(f"Avg: {_h(str(_pm['avg_w']))} W")
    if _pm.get("max_w") is not None:
        _psu_watt_parts.append(f"Peak: {_h(str(_pm['max_w']))} W")
    _psu_watt_detail = " · ".join(_psu_watt_parts)

    _pcap_bdg = psu.get("power_cap_badge", "")
    _kwh_val = psu.get("consumed_energy_kwh")
    _kwh_line = f"<br><small style='color:var(--text-muted)'>⚡ Cumulative Energy: <b>{_h(str(_kwh_val))} kWh</b></small>" if _kwh_val is not None else ""
    _pcap_html = f"<div>{_pcap_bdg}</div>" if _pcap_bdg else ""

    psu_badge = psu.get("badge", "<span class='badge info'>ℹ️ N/A</span>")

    # Keep the engine verdict, but remove its repeated inventory count on this card.
    _card_badge = re.sub(r"\s*\(\d+× PSUs, \d+ healthy\)", "", psu_badge)
    _metrics = []
    for _label, _value in (("Draw", psu.get("consumed_watts")),
                           ("Installed", psu.get("total_capacity_watts"))):
        if _value is not None and (_label == "Draw" or _value):
            _metrics.append(f"<div><dt>{_label}</dt><dd>{_h(str(_value))} W</dd></div>")
    _units = []
    for _idx, _unit in enumerate(psu.get("psus") or [], 1):
        _health = str(_unit.get("health") or "Unknown")
        _state = _health.casefold()
        _tone, _shape = ("success", "success-standard") if _state == "ok" else (
            ("danger", "error-standard") if _state == "critical" else ("warning", "warning-standard")
        )
        _name = re.sub(r"\s+Status$", "", str(_unit.get("name") or f"PSU {_idx}"))
        _watts = _unit.get("wattage")
        _capacity = f"{_h(str(_watts))} W · " if isinstance(_watts, (int, float)) else ""
        _units.append(
            f"<li><span class='psu-unit-icon psu-unit-{_tone}'>{icon_html(_shape)}</span>"
            f"<span class='psu-unit-name'>{_h(_name)}</span>"
            f"<span class='psu-unit-reading'>{_capacity}{_h(_health)}</span></li>"
        )
    _unit_list = "<ul class='psu-unit-list'>" + "".join(_units) + "</ul>" if _units else (
        "<p class='psu-card-note'>Per-supply data unavailable.</p>"
    )
    _cap_line = ""
    _limit = psu.get("power_limit_watts")
    if isinstance(_limit, (int, float)) and _limit > 0:
        _enforced = psu.get("power_limit_enforced")
        _cap_state = "enforced" if _enforced is True else (
            "enforcement disabled" if _enforced is False else "enforcement unknown"
        )
        _cap_tone = " psu-cap-enforced" if _enforced is True else ""
        _cap_line = f"<p class='psu-card-note{_cap_tone}'>Cap: {_h(str(_limit))} W · {_cap_state}</p>"
    elif _pcap_bdg:
        _cap_line = f"<div class='psu-card-note'>{_pcap_bdg}</div>"
    psu_card_html = (
        "<div class='card psu-summary-card'>"
        "<div class='report-card-header'><h3>Power Supply</h3>"
        "<a href='#tab-health' data-jump-tab='tab-health' class='btn-link tab-jump-link'"
        " title='Power supply inventory and telemetry in Health'>Details &rarr;</a></div>"
        f"<div class='psu-verdict'>{_card_badge}</div>"
        + ("<dl class='psu-card-metrics'>" + "".join(_metrics) + "</dl>" if _metrics else "")
        + _unit_list + _cap_line + "</div>"
    )

    _psu_health_section = ""
    if psu.get("psus") or _psu_watt_detail or _pcap_html or _kwh_line:
        _ph_rows = ""
        for _pu in psu.get("psus") or []:
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
        _ph_rows = _ph_rows or "<tr><td colspan='4'>Per-supply data unavailable.</td></tr>"
        _psu_health_section = (
            f"<h2>Power Supply Detail</h2>"
            f"{_pcap_html}"
            f"<p class='psu-detail-metrics'>{_psu_watt_detail}{_kwh_line}</p>"
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
        f"<h2>{icon_html('thermometer')} Thermal &amp; Environmental Health</h2>"
        f"<details class='accordion' data-report-evidence='supporting'>"
        f"    <summary>"
        f"        <div>🌡️ Thermal: {thermal.get('overall_status_badge', _default_thermal_badge)} &nbsp;"
        f"        <span style='font-size:.85rem;color:var(--text-muted)'>{key_sensor_str}</span></div>"
        f"        <span style='font-size:.85rem;color:var(--primary)'>Expand Sensor Matrix ▾</span>"
        f"    </summary>"
        f"    <div class='accordion-body' id='thermal-sensor-evidence'><table><thead><tr><th>Sensor</th><th>Reading (°C)</th><th>Warn (°C)</th><th>Critical (°C)</th><th>Status</th></tr></thead><tbody>{thermal_rows}</tbody></table></div>"
        f"</details>"
    )
    return thermal_section_html, key_sensor_str


def render_nvme_smart_health_section(all_drives: List[Dict[str, Any]]) -> str:
    """Render NVMe SMART & Drive Health section for Health tab."""
    _pop_drives = [drive_pcie_view(d) for d in (all_drives or []) if d.get("populated", True)]
    if not _pop_drives:
        return ""

    def _is_critical(d: Dict[str, Any]) -> bool:
        end = d.get("endurance_remaining_pct")
        if end in (255, "255", "255%"):
            end = None
        c_warn = d.get("critical_warnings")
        asp = d.get("available_spare_pct")
        thresh = d.get("available_spare_threshold")
        spare_below = False
        if isinstance(asp, (int, float)) and isinstance(thresh, (int, float)):
            spare_below = asp <= thresh
        return bool(
            d.get("failure_predicted")
            or (isinstance(end, (int, float)) and 0 <= end < 20 and end != 255)
            or (isinstance(c_warn, (int, float)) and c_warn > 0)
            or spare_below
        )

    def _is_warning(d: Dict[str, Any]) -> bool:
        end = d.get("endurance_remaining_pct")
        if end in (255, "255", "255%"):
            end = None
        un_shut = d.get("unsafe_shutdowns")
        m_err = d.get("media_errors")
        temp = d.get("temperature_c")
        poh = d.get("power_on_hours") or (d.get("oem_metrics") or {}).get("power_on_hours")
        _d_is_boot = bool(d.get("is_boot") or d.get("usage_role") == "Boot Drive" or "boot" in str(d.get("category", "")).lower() or any(k in str(d.get("model", "")).upper() for k in ["BOSS", "NS204I"]))
        return bool(
            (isinstance(end, (int, float)) and 20 <= end < 50 and end != 255)
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

        _d_is_boot = bool(_d.get("is_boot") or _d.get("usage_role") == "Boot Drive" or "boot" in str(_d.get("category", "")).lower() or any(k in str(_d.get("model", "")).upper() for k in ["BOSS", "NS204I"]))
        _end = _d.get("endurance_remaining_pct")
        if _end in (255, "255", "255%"):
            _end = None
        if isinstance(_end, (int, float)) and 0 <= _end <= 100 and _end != 255:
            if _end < 20:
                _end_str = f"<span class='badge danger'>{_end}% (Critical)</span>"
            elif _end < 50:
                _end_str = f"<span class='badge warning'>{_end}% (Watch)</span>"
            else:
                _end_str = f"<span class='badge success'>{_end}%</span>"
        elif _d.get("is_magnetic"):
            _end_str = "<span style='color:var(--text-muted)'>N/A (HDD)</span>"
        elif _is_healthy:
            _ctrl_nm = str(_d.get("controller_name") or _d.get("controller_id") or "").upper()
            _is_raid_ctrl = bool(
                _d.get("behind_trimode")
                or _d.get("behind_software_raid")
                or any(k in _ctrl_nm for k in ["RAID", "MRVL", "MARVELL", "PERC", "SMART ARRAY", "HBA"])
            )
            if _is_raid_ctrl or _d_is_boot:
                _end_str = "<span class='badge success' title='Hardware reports SMART Status: OK (Endurance % virtualized by RAID controller)'>OK (SMART Pass)</span>"
            else:
                _end_str = "<span class='badge success' title='Hardware reports SMART Status: OK'>OK (SMART Pass)</span>"
        else:
            _end_str = f"<span style='color:var(--text-muted)'>{_h(str(_end or 'N/A'))}</span>"

        _temp = _d.get("temperature_c")
        _throt = _d.get("thermal_throttled")
        _temp_parts = []
        if isinstance(_temp, (int, float)):
            if _temp >= 60:
                _temp_parts.append(f"<strong style='color:#dc2626'>{_temp}°C</strong>")
            elif _temp >= 50:
                _temp_parts.append(f"<strong style='color:var(--warning)'>{_temp}°C</strong>")
            else:
                _temp_parts.append(f"<span style='color:var(--success)'>{_temp}°C</span>")
        elif _is_healthy:
            _temp_parts.append("<span style='color:var(--success)'>OK</span>")
        else:
            _temp_parts.append("<span style='color:var(--text-muted)'>N/A</span>")

        if _throt:
            _temp_parts.append("<br><span class='badge warning'>🔥 Throttled</span>")
        _temp_html = "".join(_temp_parts)

        _us = _d.get("unsafe_shutdowns")
        if isinstance(_us, (int, float)) and _us > 0:
            _us_str = f"<strong style='color:var(--warning)'>⚠️ {_us}</strong>"
        elif isinstance(_us, (int, float)):
            _us_str = f"<span style='color:var(--success)'>{_us}</span>"
        elif _is_healthy:
            _us_str = "<span style='color:var(--success)'>0</span>"
        else:
            _us_str = "<span style='color:var(--text-muted)'>N/A</span>"

        _me = next((v for v in (_d.get("media_errors"), (_d.get("oem_metrics") or {}).get("media_errors"), (_d.get("oem_metrics") or {}).get("drive_error_count")) if v is not None), None)
        if isinstance(_me, (int, float)) and _me > 0:
            _me_str = f"<strong style='color:#dc2626'>⚠️ {_me}</strong>"
        elif isinstance(_me, (int, float)):
            _me_str = f"<span style='color:var(--success)'>{_me}</span>"
        else:
            _me_str = "<span style='color:var(--text-muted)'>N/A</span>"

        _spare  = _d.get("available_spare_pct")
        _thresh = _d.get("available_spare_threshold")
        _waf    = _d.get("write_amplification")
        _bad_n  = _d.get("bad_nand_blocks")
        _e_log  = _d.get("error_log_entries")
        _extra_parts = []
        if isinstance(_spare, (int, float)) and 0 <= _spare <= 100:
            _th_str = f" <small style='color:var(--text-muted)'>(Min {_thresh}%)</small>" if isinstance(_thresh, (int, float)) else ""
            if _spare < 10 or (isinstance(_thresh, (int, float)) and _spare <= _thresh):
                _extra_parts.append(f"Spare: <strong style='color:#dc2626'>{_spare}%</strong>{_th_str}")
            else:
                _extra_parts.append(f"Spare: <strong>{_spare}%</strong>{_th_str}")
        else:
            _extra_parts.append("Spare: unavailable")

        if isinstance(_c_warn, (int, float)) and _c_warn > 0:
            _extra_parts.append(f"<span class='badge danger' style='font-size:.7rem;'>🔴 NVMe Alert ({_c_warn})</span>")

        if isinstance(_waf, (int, float)):
            _extra_parts.append(f"WAF: <strong>{_waf}</strong>")

        if isinstance(_bad_n, (int, float)):
            if _bad_n > 0:
                _extra_parts.append(f"Bad Blocks: <strong style='color:var(--warning)'>{_bad_n}</strong>")
            else:
                _extra_parts.append("Bad Blocks: <span style='color:var(--success)'>0</span>")
        elif _is_healthy and not _d.get("is_magnetic"):
            _extra_parts.append("Bad Blocks: <span style='color:var(--success)'>0</span>")

        if isinstance(_e_log, (int, float)) and _e_log > 0:
            _extra_parts.append(f"<span style='color:var(--warning)'>Log Errors: {_e_log}</span>")

        _reserve_html = "<br>".join(_extra_parts) if _extra_parts else "<span style='color:var(--text-muted)'>N/A</span>"

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
        elif "NVME" in str(_d.get("protocol") or "").upper() or "PCIE" in str(_d.get("protocol") or "").upper():
            _pcie_parts.append(_h(drive_link_description(_d)))
            if _d.get("single_lane_alert") and not _d_is_boot:
                _pcie_parts.append("<br><strong style='color:var(--danger)'>(x1 Warning)</strong>")
        elif _neg_speed:
            _pcie_parts.append(f"Speed: {_neg_speed} Gbps")
        elif _is_healthy:
            _pcie_parts.append("<span style='color:var(--success)'>OK</span>")

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
                _err_items.append(f"<strong style='color:var(--warning)'>Retrains: {_l0}</strong>")
            if _rol > 0:
                _err_items.append(f"<strong style='color:var(--warning)'>Rollovers: {_rol}</strong>")
            if _rep > 0:
                _err_items.append(f"Replays: {_rep}")
            if _non_fat > 0:
                _err_items.append(f"NonFatal: {_non_fat}")
            if _corr > 0:
                _err_items.append(f"Corr: {_corr}")

            if _err_items:
                _pcie_parts.append("<br><span style='font-size:0.8em'>" + " | ".join(_err_items) + "</span>")
            else:
                _pcie_parts.append("<br><span style='color:var(--success);font-size:0.8em'>Errors: 0</span>")
        elif isinstance(_pcie_errs, (int, float)):
            if _pcie_errs > 0:
                _pcie_parts.append(f"<br>Errors: <strong style='color:var(--warning)'>{_pcie_errs}</strong>")
            else:
                _pcie_parts.append("<br>Errors: <span style='color:var(--success)'>0</span>")

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
        f"<h2>{icon_html('hard-disk')} NVMe SMART &amp; Drive Health Summary</h2>"
        f"<details class='accordion' data-report-evidence='supporting' {'open' if (_sh_critical_count or _sh_warning_count) else ''}>"
        f"  <summary>"
        f"    <div>{icon_html('hard-disk')} Drive SMART Telemetry: {_sh_rollup_badge} &nbsp;"
        f"    <span style='font-size:.85rem;color:var(--text-muted)'>{len(_pop_drives)} drive(s) scanned</span></div>"
        f"    <span style='font-size:.85rem;color:var(--primary)'>Toggle Details ▾</span>"
        f"  </summary>"
        f"  <div class='accordion-body' id='drive-smart-evidence'>"
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
            f"<details class='accordion' data-report-evidence='supporting' style='margin-bottom:1.25rem'>"
            f"<summary>"
            f"<div>📶 Redfish Protocol Capabilities &amp; Optimization Telemetry &nbsp;"
            f"{exp_badge} {pipe_badge} {pacing_badge}</div>"
            f"<span style='font-size:.85rem;color:var(--primary)'>Expand Protocol Details ▾</span>"
            f"</summary>"
            f"<div class='accordion-body' style='padding:1rem 1.25rem'>"
            f"<table style='width:100%;font-size:.85rem;border-collapse:collapse'>"
            f"<thead><tr><th style='text-align:left;padding:6px 10px'>Protocol Feature</th><th style='text-align:left;padding:6px 10px'>Status / Value</th><th style='text-align:left;padding:6px 10px'>Telemetry Details</th></tr></thead>"
            f"<tbody>"
            f"<tr><td style='padding:6px 10px'><strong>OData Collection Expansion</strong></td><td style='padding:6px 10px'>{exp_badge}</td><td style='padding:6px 10px'>{_h(exp_desc)}</td></tr>"
            f"<tr><td style='padding:6px 10px'><strong>HTTP Connection Pipelining</strong></td><td style='padding:6px 10px'>{pipe_badge}</td><td style='padding:6px 10px'>{_h(pipe_desc)}</td></tr>"
            f"<tr><td style='padding:6px 10px'><strong>Inter-Request Pacing Delay</strong></td><td style='padding:6px 10px'>{pacing_badge}</td><td style='padding:6px 10px'>{_h(pacing_desc)}</td></tr>"
            f"<tr><td style='padding:6px 10px'><strong>HTTP Requests &amp; Latency</strong></td><td style='padding:6px 10px'><code>{req_cnt}</code> requests</td><td style='padding:6px 10px'>Avg BMC GET latency: <code>{avg_lat} ms</code> &middot; Scan duration: <code>{scan_dur} s</code></td></tr>"
            f"<tr><td style='padding:6px 10px'><strong>Silicon generation</strong></td><td colspan='2' style='padding:6px 10px'><code>{_h(str(diag.get('silicon_generation') or 'n/a'))}</code></td></tr>"
            f"<tr><td style='padding:6px 10px'><strong>Phase timing</strong></td><td colspan='2' style='padding:6px 10px'>phase1 <code>{_h(str(diag.get('phase1_duration_s') or ''))}</code>s &middot; phase2 <code>{_h(str(diag.get('phase2_duration_s') or ''))}</code>s</td></tr>"
            f"<tr><td style='padding:6px 10px'><strong>TLS reuse</strong></td><td colspan='2' style='padding:6px 10px'><code>{_h(str(diag.get('tls_reuse_ratio') or ''))}</code> &middot; handshake <code>{_h(str(diag.get('tls_handshake_avg_ms') or ''))}</code> ms</td></tr>"
            f"<tr><td style='padding:6px 10px'><strong>Expansion Fallback Endpoints</strong></td><td style='padding:6px 10px' colspan='2'>{unsupp_str}</td></tr>"
            f"</tbody>"
            f"</table>"
            f"</div>"
            f"</details>"
        )

    return "".join(parts)


def render_job_queue_card_and_health_section(data: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """Keep job history quiet while exposing failures and stalled work at a glance."""
    if not data or not isinstance(data.get("job_queue"), dict) or not data["job_queue"]:
        return "", ""
    job_q = data["job_queue"]
    jobs = [j for j in job_q.get("jobs") or [] if isinstance(j, dict)]

    def failed(job):
        return bool(job.get("is_failed")) or str(job.get("state") or "").lower() in ("failed", "exception", "killed")

    def completed(job):
        return str(job.get("state") or "").lower() in ("completed", "rebootcompleted") and not (
            failed(job) or job.get("is_stale") or job.get("is_pending_reboot")
        )

    def timestamp(value):
        try:
            parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
            return (parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed).timestamp()
        except (ValueError, TypeError, OverflowError, OSError):
            return None

    def started(job):
        # Attempt order uses start time, not completion time of a long-running job.
        return timestamp(job.get("start_time"))

    ordered = sorted(jobs, key=lambda j: (started(j) is not None, started(j) or 0), reverse=True)
    dated = [j for j in ordered if started(j) is not None]
    latest = dated[:5]
    recent_failed = sum(1 for j in latest if failed(j))
    failed_jobs = max(int(job_q.get("failed_jobs") or 0), sum(failed(j) for j in jobs))
    stale_jobs = max(int(job_q.get("stale_jobs") or 0), sum(bool(j.get("is_stale")) for j in jobs))
    pending_reboot_jobs = max(int(job_q.get("pending_reboot_jobs") or 0), sum(bool(j.get("is_pending_reboot")) for j in jobs))
    total_jobs = max(int(job_q.get("total_jobs") or 0), len(jobs))
    successful = [j for j in ordered if completed(j)]
    attention = [j for j in ordered if not completed(j)]
    recent_note = f"{recent_failed} of the {len(latest)} latest dated attempts failed." if recent_failed else ""

    if failed_jobs or stale_jobs:
        badge_cls = "danger" if recent_failed else "warning"
        badge_shape = "error-standard" if recent_failed else "warning-standard"
        badge_lbl = f"{failed_jobs} Failed, {stale_jobs} Stale"
        card_summary = f"{failed_jobs} failed · {stale_jobs} potentially stuck · {pending_reboot_jobs} awaiting reboot."
    elif pending_reboot_jobs:
        badge_cls, badge_shape = "info", "clock"
        badge_lbl = f"{pending_reboot_jobs} Pending Reboot"
        card_summary = "Configuration tasks are waiting for a server reboot."
    elif attention:
        badge_cls, badge_shape = "info", "info-standard"
        badge_lbl = "Jobs to Review"
        card_summary = f"{len(attention)} active or unclassified jobs; no failures or stale jobs reported."
    else:
        badge_cls, badge_shape = "success", "check"
        badge_lbl = "Queue Clean"
        card_summary = f"No failed or stuck jobs reported; {total_jobs} historical jobs."
    badge_html = f"<span class='badge {badge_cls}'>{icon_html(badge_shape)} {_h(badge_lbl)}</span>"
    card_html = (
        "<div class='card job-queue-card'><div class='report-card-header'><h3>LC Job Queue</h3>"
        "<a href='#tab-health' data-jump-tab='tab-health' class='btn-link tab-jump-link'>Details &rarr;</a></div>"
        f"{badge_html}<p class='job-queue-summary'>{_h(card_summary)}</p>"
        + (f"<p class='job-queue-recent'>{icon_html('error-standard')} {_h(recent_note)}</p>" if recent_note else "")
        + "</div>"
    )

    def table(items, label):
        rows = []
        for job in items:
            state = str(job.get("state") or "Unknown")
            if failed(job):
                tone, shape = "danger", "error-standard"
            elif job.get("is_stale"):
                tone, shape = "warning", "warning-standard"
            elif completed(job):
                tone, shape = "success", "check"
            else:
                tone, shape = "info", "clock" if job.get("is_pending_reboot") else "info-standard"
            duration = job.get("duration_seconds")
            terminal = completed(job) or failed(job) or state.lower() in ("cancelled", "canceled")
            # Missing end timestamps must not make completed jobs look years long.
            if terminal and timestamp(job.get("end_time")) is None:
                duration = None
            duration_text = "—"
            if isinstance(duration, (int, float)):
                duration_text = f"{round(duration / 3600, 1)}h" if duration > 3600 else f"{duration:g}s"
            pct = str(job["percent_complete"]) + "%" if job.get("percent_complete") is not None else "—"
            rows.append(
                f"<tr><td><strong>{_h(str(job.get('id') or '—'))}</strong></td>"
                f"<td>{_h(str(job.get('name') or 'Job'))}</td>"
                f"<td><span class='badge {tone}'>{icon_html(shape)} {_h(state)}</span></td>"
                f"<td>{_h(pct)}</td><td>{_h(str(job.get('start_time') or '—'))}</td>"
                f"<td>{_h(duration_text)}</td><td>{_h(str(job.get('message') or '—'))}</td></tr>"
            )
        return (
            f"<div class='job-queue-table' role='region' aria-label='{_h(label)}' tabindex='0'>"
            "<table><thead><tr><th>Job ID</th><th>Name / Task</th><th>State</th><th>Progress</th>"
            "<th>Start Time</th><th>Duration</th><th>Status Message</th></tr></thead>"
            "<tbody>" + "".join(rows) + "</tbody></table></div>"
        )

    banner = ""
    if recent_failed or failed_jobs or stale_jobs:
        alert_tone = "danger" if recent_failed else "warning"
        alert_title = "Latest recorded attempts include failures" if recent_failed else "Job queue needs review"
        alert_note = recent_note or card_summary
        banner = (
            f"<div class='alert alert-{alert_tone} job-queue-alert'>"
            f"<strong>{icon_html('error-standard' if recent_failed else 'warning-standard')} {_h(alert_title)}</strong>"
            f"<p>{_h(alert_note)} Review job messages before staging or rebooting this host.</p></div>"
        )
    details = table(attention, "Jobs needing review") if attention else "<p>No jobs need review in the captured details.</p>"
    if successful:
        details += (
            f"<details class='job-success-history' data-report-evidence='supporting'><summary>Successful history ({len(successful)} jobs)</summary>"
            + table(successful, "Successful job history") + "</details>"
        )
    if not jobs:
        details = "<p>No itemized job records were captured.</p>"
    coverage_note = f"{len(jobs)} itemized records captured; {total_jobs} total reported by the controller."
    if len(dated) < len(jobs):
        coverage_note += f" {len(jobs) - len(dated)} records have no valid start time and cannot be ordered as recent."
    remediation = ""
    if failed_jobs or stale_jobs:
        remediation = (
            "<p>Review the affected jobs and dependencies in iDRAC. For confirmed obsolete or stalled tasks, "
            "RACADM <code>jobqueue delete</code> is available; verify the job IDs and impact before clearing them.</p>"
        )
    health_html = (
        "<section class='job-queue-section'><h2>Lifecycle Controller (LC) Job Queue Pre-Flight Audit</h2>"
        f"<div>{badge_html}</div>{banner}"
        "<p class='job-queue-summary'>Potentially stuck means an unfinished job exceeded 24 hours at capture. "
        "Completed jobs are history, not stuck work. Latest attempts are ordered by recorded start time; this is saved scan evidence.</p>"
        "<details class='accordion job-queue-details' data-report-evidence='supporting'>"
        f"<summary><span>{icon_html('clipboard')} Itemized Job Queue</span>"
        f"<span>{failed_jobs} failed · {stale_jobs} stale · {len(successful)} successful</span></summary>"
        f"<div class='accordion-body'><p class='job-queue-summary'>{_h(coverage_note)}</p>{details}{remediation}</div>"
        "</details></section>"
    )
    return card_html, health_html
