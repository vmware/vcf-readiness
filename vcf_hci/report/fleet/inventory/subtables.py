"""
Subtable generators for Detailed Inventory panel (Drives, NICs, BIOS, Health, Security).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.constants import BMC_FW_BASELINES
from vcf_hci.report.fleet.escape import _xe
from vcf_hci.report.fleet.inventory.chips import (
    _DASH,
    _SUBSYSTEM_SUBTABS,
    _default_pii,
    _drive_fw_cell,
    _drive_model_link,
    _nic_fw_cell,
    _nic_name_link,
)
from vcf_hci.report.inventory_tables import (
    ESA_CATEGORY,
    _all_drives,
    _extract_nic_rated_speed,
    _host_ip,
    _link_is_up,
    clean_model_code,
    select_cpu_power_entry,
    select_memory_ras_entry,
)
from vcf_hci.report.sel_links import (
    normalize_vendor,
    resolve_cisco_event_info,
    resolve_dell_event_info,
    resolve_hpe_event_info,
    resolve_sel_event_url,
)
from vcf_hci.security.scoring import score_host_security

__all__ = [
    "_build_drives_table",
    "_build_nics_table",
    "_build_bios_table",
    "_build_health_table",
    "_build_bmc_hardening_cell",
    "_build_security_table",
]

_PERC_7XX_PATTERN = re.compile(r"\bPERC\s*H?7\d\d\w*\b", re.IGNORECASE)


def _build_drives_table(
    all_results: List[dict],
    json_hcl: Optional[dict] = None,
    host_tab_offset: int = 3,
    _pii: Optional[Any] = None,
    obfuscated: bool = False,
) -> str:
    if _pii is None:
        _pii = _default_pii
    rows = []
    for idx, data in enumerate(all_results or []):
        host_tab = idx + host_tab_offset
        si = data.get("system") or {}
        ip = _host_ip(data) or f"Host {idx+1}"
        hostname = str(si.get("hostname") or ip)
        if obfuscated or data.get("obfuscated"):
            if not re.match(r"^Host-\d+$", hostname):
                hostname = f"Host-{idx+1}"
            if not str(ip).startswith("192.0.2."):
                ip = f"192.0.2.{(idx % 250) + 1}"
        for ctrl in data.get("storage_subsystem") or []:
            ctrl_name = str(ctrl.get("name") or ctrl.get("ctrl_model") or ctrl.get("id") or "")
            ctrl_id = str(ctrl.get("id") or "")
            ctrl_model = str(ctrl.get("ctrl_model") or "")
            is_perc7xx = bool(
                _PERC_7XX_PATTERN.search(ctrl_name)
                or _PERC_7XX_PATTERN.search(ctrl_id)
                or _PERC_7XX_PATTERN.search(ctrl_model)
            )

            for d in ctrl.get("drives") or []:
                if (d.get("category") or "") == "Empty":
                    continue
                ep = d.get("endurance_remaining_pct", "")
                life = ep if ep != "" else "N/A"
                cat = str(d.get("category") or "")
                proto = str(d.get("protocol") or "")
                behind_tm = bool(d.get("behind_trimode"))
                behind_sw = bool(d.get("behind_software_raid"))
                is_sw_ctrl = bool(ctrl.get("is_software_raid"))

                # Determine controller type for drive row filtering
                if not is_sw_ctrl and not behind_sw and (is_perc7xx or "Tri-Mode" in cat or behind_tm or (cat == "Unsupported NVMe RAID")):
                    ctrl_type = "unsupported"
                elif cat == ESA_CATEGORY or proto.upper() in ("NVME", "PCIE"):
                    ctrl_type = "esa"
                elif "OSA" in cat or "HBA" in ctrl_name.upper():
                    ctrl_type = "osa"
                else:
                    ctrl_type = "unsupported"

                row_classes = ["inv-detail-row"]
                row_title = ""
                if is_perc7xx:
                    row_classes.append("inv-row-perc7xx")
                    row_title = f" title='Drive behind Dell PERC 7xx controller ({_xe(ctrl_name)}) {_DASH} Ineligible for native vSAN ESA'"
                elif behind_sw or is_sw_ctrl:
                    row_title = f" title='Drive behind Software RAID controller ({_xe(ctrl_name)}) {_DASH} Bypass in BIOS (AHCI/Non-RAID) for direct vSAN ESA pass-through'"

                dh = str(d.get("drive_health") or "OK")
                c_warn = d.get("critical_warnings")
                if isinstance(c_warn, (int, float)) and c_warn > 0:
                    health_cell = f"<span class='badge danger' title='NVMe Critical Warnings: {c_warn}'>🔴 Alert ({c_warn})</span>"
                elif dh in ("Critical", "Failure"):
                    health_cell = f"<span class='badge danger'>🔴 {dh}</span>"
                elif dh in ("Warning", "Degraded"):
                    health_cell = f"<span class='badge warning'>⚠️ {dh}</span>"
                else:
                    health_cell = f"<span class='badge success'>🟢 {dh}</span>"

                tbw = d.get("tbw_written")
                tbr = d.get("tbr_read")
                duty = d.get("controller_duty_cycle_pct")
                poh = d.get("power_on_hours")
                life_title_parts = []
                if isinstance(poh, (int, float)):
                    life_title_parts.append(f"POH: {int(poh):,}h")
                if isinstance(tbw, (int, float)):
                    life_title_parts.append(f"Writes: {round(tbw, 1)} TB")
                if isinstance(tbr, (int, float)):
                    life_title_parts.append(f"Reads: {round(tbr, 1)} TB")
                if isinstance(duty, (int, float)):
                    life_title_parts.append(f"Duty: {duty}%")
                life_title = f" title='{_xe(' | '.join(life_title_parts))}'" if life_title_parts else ""

                rows.append(
                    f"<tr class='{' '.join(row_classes)}' data-host-idx='{idx}' data-ctrl-type='{ctrl_type}'{row_title}>"
                    f"<td><a href='#' class='btn-link tab-jump' data-tab='{host_tab}' data-subtab='tab-storage' style='color:inherit;text-decoration:none;display:block'>"
                    f"<strong>{_pii(hostname, 'host')}</strong><br><small style='color:var(--text-muted,#64748b)'>{_pii(ip, 'ip')}</small></a></td>"
                    f"<td>{_xe(ctrl_name)}</td>"
                    f"<td>{_drive_model_link(d, json_hcl)}</td>"
                    f"<td>{_xe(d.get('media_type') or '')}</td>"
                    f"<td>{_xe(d.get('capacity_gb') or '')}</td>"
                    f"<td>{_xe(d.get('protocol') or '')}</td>"
                    f"<td>{_xe(cat)}</td>"
                    f"<td>{health_cell}</td>"
                    f"<td{life_title}>{_xe(life)}</td>"
                    f"<td>{_drive_fw_cell(d, json_hcl)}</td>"
                    f"</tr>"
                )
    body = "\n".join(rows) if rows else "<tr><td colspan='10' style='color:#94a3b8'>No drives</td></tr>"
    return f"""<div class="inv-scroll">
<table class="inv-table" id="invDrivesTable">
<thead><tr>
<th title="Host server hostname and BMC IP address">Host</th>
<th title="Storage controller model (PERC, Smart Array, HBA, or Direct NVMe)">Controller</th>
<th title="Drive manufacturer part number and model with Broadcom Compatibility Guide deep link">Model</th>
<th title="Storage media technology (NVMe SSD, SAS SSD, SATA SSD, HDD)">Media</th>
<th title="Raw drive storage capacity in gigabytes">Cap GB</th>
<th title="Storage transport bus protocol (NVMe, SAS, SATA)">Protocol</th>
<th title="Storage role classification (vSAN ESA NVMe, vSAN OSA, Tri-Mode, RAID)">Category</th>
<th title="Drive hardware diagnostic health and SMART telemetry status">Health</th>
<th title="Remaining flash silicon endurance percentage">Life%</th>
<th title="Installed drive firmware version with certified baseline comparison">Firmware</th>
</tr></thead><tbody>{body}</tbody></table></div>"""


def _build_nics_table(
    all_results: List[dict],
    json_hcl: Optional[dict] = None,
    host_tab_offset: int = 3,
    _pii: Optional[Any] = None,
    obfuscated: bool = False,
) -> str:
    if _pii is None:
        _pii = _default_pii
    rows = []
    for idx, data in enumerate(all_results or []):
        host_tab = idx + host_tab_offset
        si = data.get("system") or {}
        ip = _host_ip(data) or f"Host {idx+1}"
        hostname = str(si.get("hostname") or ip)
        if obfuscated or data.get("obfuscated"):
            if not re.match(r"^Host-\d+$", hostname):
                hostname = f"Host-{idx+1}"
            if not str(ip).startswith("192.0.2."):
                ip = f"192.0.2.{(idx % 250) + 1}"
        for n in data.get("network_adapters") or []:
            for p in n.get("ports") or []:
                is_up = _link_is_up(p.get("link_status"))
                spd = p.get("current_speed_gbps") or 0
                try:
                    spdf = float(spd)
                except (TypeError, ValueError):
                    spdf = 0.0
                if spdf <= 0:
                    spdf = _extract_nic_rated_speed(n, p)
                spd_str = f"{spdf:g} Gbps" if spdf > 0 else _DASH
                link_raw = str(p.get("link_status") or ("Up" if is_up else "Down"))
                link_cls = "inv-good" if is_up else "inv-bad"
                link_val = "up" if is_up else "down"

                rx_p = p.get("rx_power_dbm")
                tx_p = p.get("tx_power_dbm")
                tx_temp = p.get("transceiver_temperature_c") if p.get("transceiver_temperature_c") is not None else p.get("temperature_c")
                tx_id = p.get("transceiver_identifier") or ""
                tx_if = p.get("transceiver_interface") or ""
                tx_tip_items = []
                if tx_id or tx_if:
                    tx_tip_items.append(f"Optics: {tx_id} {tx_if}".strip())
                if rx_p is not None:
                    tx_tip_items.append(f"RX: {rx_p:+.1f} dBm" if isinstance(rx_p, (int, float)) else f"RX: {rx_p} dBm")
                if tx_p is not None:
                    tx_tip_items.append(f"TX: {tx_p:+.1f} dBm" if isinstance(tx_p, (int, float)) else f"TX: {tx_p} dBm")
                if tx_temp is not None:
                    tx_tip_items.append(f"Temp: {tx_temp:.1f}°C" if isinstance(tx_temp, (int, float)) else f"Temp: {tx_temp}°C")

                port_label = _xe(str(p.get("port_id") or ""))
                port_cell = f"<span title='{_xe(' · '.join(tx_tip_items))}'>{port_label}</span>" if tx_tip_items else port_label

                opt_warn = p.get("optical_warning")
                opt_health = p.get("optical_signal_health")
                if opt_health == "critical" or (opt_warn and "critical" in str(opt_warn).lower()):
                    warn_tip = _xe(str(opt_warn)) if opt_warn else "Critical optical signal degradation"
                    link_cell = f"<span class='{link_cls}'>{_xe(link_raw)}</span> <span class='inv-bad' style='font-size:.72rem' title='{warn_tip}'>⚠️ Opt Crit</span>"
                elif opt_health == "marginal" or (opt_warn and "marginal" in str(opt_warn).lower()):
                    warn_tip = _xe(str(opt_warn)) if opt_warn else "Marginal optical signal level"
                    link_cell = f"<span class='{link_cls}'>{_xe(link_raw)}</span> <span class='inv-warn' style='font-size:.72rem' title='{warn_tip}'>⚠️ Opt Warn</span>"
                else:
                    link_cell = f"<span class='{link_cls}'>{_xe(link_raw)}</span>"

                rows.append(
                    f"<tr class='inv-detail-row' data-host-idx='{idx}' data-link-status='{link_val}'>"
                    f"<td><a href='#' class='btn-link tab-jump' data-tab='{host_tab}' data-subtab='tab-network' style='color:inherit;text-decoration:none;display:block'>"
                    f"<strong>{_pii(hostname, 'host')}</strong><br><small style='color:var(--text-muted,#64748b)'>{_pii(ip, 'ip')}</small></a></td>"
                    f"<td>{_nic_name_link(n, json_hcl)}</td>"
                    f"<td>{port_cell}</td>"
                    f"<td>{_xe(spd_str)}</td>"
                    f"<td>{link_cell}</td>"
                    f"<td>{_pii(p.get('mac_address') or '', 'mac')}</td>"
                    f"<td>{_nic_fw_cell(n, json_hcl)}</td>"
                    f"</tr>"
                )
    body = "\n".join(rows) if rows else "<tr><td colspan='7' style='color:#94a3b8'>No NICs</td></tr>"
    mac_th = (
        '<th id="thNicMac" title="Physical hardware MAC address of the network port (Obfuscated hash with synthetic 02: prefix)">MAC <em>(obfuscated)</em></th>'
        if obfuscated
        else '<th id="thNicMac" title="Physical hardware MAC address of the network port">MAC</th>'
    )
    return f"""<div class="inv-scroll">
<table class="inv-table" id="invNicsTable">
<thead><tr>
<th title="Host server hostname and BMC IP address">Host</th>
<th title="Network controller adapter model with Broadcom Compatibility Guide deep link">Adapter</th>
<th title="Physical network interface port identifier">Port</th>
<th title="Current negotiated link speed or rated hardware bandwidth">Speed</th>
<th title="Physical network link connection state (Up / Down)">Link</th>
{mac_th}
<th title="Installed NIC controller firmware version and compatibility status">Firmware</th>
</tr></thead><tbody>{body}</tbody></table></div>"""


def _build_bios_table(
    all_results: List[dict],
    host_tab_offset: int = 3,
    _pii: Optional[Any] = None,
    obfuscated: bool = False,
) -> str:
    """Build unified BIOS performance settings and configuration table across the fleet."""
    if _pii is None:
        _pii = _default_pii
    rows = []
    for idx, data in enumerate(all_results or []):
        host_tab = idx + host_tab_offset
        si = data.get("system") or {}
        ip = _host_ip(data) or f"Host {idx+1}"
        hostname = str(si.get("hostname") or ip)
        if obfuscated or data.get("obfuscated"):
            if not re.match(r"^Host-\d+$", hostname):
                hostname = f"Host-{idx+1}"
            if not str(ip).startswith("192.0.2."):
                ip = f"192.0.2.{(idx % 250) + 1}"
        vendor_raw = str(si.get("vendor") or "")
        model_raw = str(si.get("model") or "")
        clean_m = clean_model_code(vendor_raw, model_raw) or model_raw or _DASH

        bios_checks = data.get("bios_checks") or {}
        bios_eval = si.get("bios_eval") or {}
        bios_ver = str(si.get("bios_version") or _DASH)
        bios_date = str(si.get("bios_release_date") or "")

        # CPU Power Profile (Plain text: Performance in green, others in amber/red)
        cpu_power = bios_checks.get("cpu_power") or []
        chosen_pwr = select_cpu_power_entry(cpu_power)
        if chosen_pwr:
            pwr_label = str(chosen_pwr.get("label") or "Performance")
            pwr_badge = str(chosen_pwr.get("badge") or "success")
            low_label = pwr_label.lower()
            if pwr_badge == "danger":
                pwr_cell = f"<span class='inv-bad'>✗ {_xe(pwr_label)}</span>"
            elif pwr_badge == "warning":
                pwr_cell = f"<span class='inv-warn'>▲ {_xe(pwr_label)}</span>"
            elif pwr_badge == "info" and ("notavailable" in low_label or "n/a" in low_label or not pwr_label.strip()):
                pwr_cell = f"<span class='inv-muted'>{_DASH}</span>"
            elif any(k in low_label for k in ("perf", "maximum", "os control")) or pwr_badge == "success":
                pwr_cell = f"<span class='inv-good'>✓ {_xe(pwr_label)}</span>"
            else:
                pwr_cell = f"<span class='inv-warn'>▲ {_xe(pwr_label)}</span>"
        else:
            pwr_cell = f"<span class='inv-muted'>{_DASH}</span>"

        # Memory RAS (Plain text)
        mem_ras = bios_checks.get("memory_ras") or []
        chosen_ras = select_memory_ras_entry(mem_ras)
        if chosen_ras:
            ras_label = str(chosen_ras.get("label") or "Optimized")
            ras_cell = f"<span>{_xe(ras_label)}</span>"
        else:
            ras_cell = "<span class='inv-muted'>Standard</span>"

        # Intel VMD (Plain text: Disabled / Pass-thru in green, Enabled in red)
        vmd_on = bool(bios_checks.get("vmd_enabled_flag"))
        if vmd_on:
            vmd_cell = "<span class='inv-bad'>✗ Enabled (VMD)</span>"
        else:
            vmd_cell = "<span class='inv-good'>✓ Disabled (Pass-thru)</span>"

        # Boot Mode (Plain text: UEFI in green, Legacy BIOS in red)
        boot_mode = str(si.get("boot_mode") or si.get("raw_boot_mode") or "UEFI")
        if "uefi" in boot_mode.lower():
            boot_cell = "<span class='inv-good'>✓ UEFI</span>"
        elif "legacy" in boot_mode.lower() or "bios" in boot_mode.lower() or "csm" in boot_mode.lower():
            boot_cell = "<span class='inv-bad'>✗ Legacy BIOS</span>"
        else:
            boot_cell = f"<span class='inv-muted'>{_xe(boot_mode)}</span>"

        # Spectre / CVE Coverage Tier (Plain text: Tier 4 green, <4 red)
        cve_tier_int = bios_eval.get("cve_tier")
        cve_label = bios_eval.get("cve_tier_label")
        if cve_tier_int is not None and cve_tier_int >= 0:
            if cve_tier_int >= 4:
                tier_cell = f"<span class='inv-good'>✓ Tier {cve_tier_int}: {_xe(cve_label or '')}</span>"
            else:
                tier_cell = f"<span class='inv-bad'>✗ Tier {cve_tier_int}: {_xe(cve_label or '')}</span>"
        else:
            tier_cell = f"<span class='inv-muted'>{_DASH}</span>"

        rows.append(
            f"<tr class='inv-detail-row' data-host-idx='{idx}'>"
            f"<td><a href='#' class='btn-link tab-jump' data-tab='{host_tab}' data-subtab='tab-bios' style='color:inherit;text-decoration:none;display:block'>"
            f"<strong>{_pii(hostname, 'host')}</strong><br><small style='color:var(--text-muted,#64748b)'>{_pii(ip, 'ip')}</small></a></td>"
            f"<td><strong>{_xe(clean_m)}</strong></td>"
            f"<td><code class='inv-code'>{_xe(bios_ver)}</code></td>"
            f"<td>{_xe(bios_date or _DASH)}</td>"
            f"<td>{pwr_cell}</td>"
            f"<td>{ras_cell}</td>"
            f"<td>{vmd_cell}</td>"
            f"<td>{boot_cell}</td>"
            f"<td>{tier_cell}</td>"
            f"</tr>"
        )
    body = "\n".join(rows) if rows else "<tr><td colspan='9' style='color:#94a3b8'>No hosts</td></tr>"
    return f"""<div class="inv-scroll">
<table class="inv-table" id="invBiosTable">
<thead><tr>
<th title="Host server hostname and BMC IP address">Host</th>
<th title="Server hardware manufacturer and chassis model">Model</th>
<th title="Installed system BIOS/UEFI firmware release version">BIOS Version</th>
<th title="OEM release date of the installed system BIOS">Release Date</th>
<th title="Processor power management policy (Performance profile required for VCF/ESXi)">CPU Power Profile</th>
<th title="Reliability, Availability, and Serviceability memory mode (Advanced ECC, Mirroring, etc.)">Memory RAS</th>
<th title="Intel Volume Management Device status (must be Disabled for native vSAN ESA NVMe passthrough)">Intel VMD</th>
<th title="Firmware boot architecture (UEFI required for VCF 9.1; Legacy BIOS unsupported)">Boot Mode</th>
<th title="Processor microcode security baseline tier covering Spectre, Meltdown, L1TF, MDS, and SRBDS">Spectre / CVE Tier</th>
</tr></thead><tbody>{body}</tbody></table></div>"""


def _build_health_table(
    all_results: List[dict],
    host_tab_offset: int = 3,
    _pii: Optional[Any] = None,
    obfuscated: bool = False,
) -> str:
    """Build unified health and alarm roll-up table across the fleet."""
    if _pii is None:
        _pii = _default_pii
    rows = []
    for idx, data in enumerate(all_results or []):
        host_tab = idx + host_tab_offset
        si = data.get("system") or {}
        ip = _host_ip(data) or f"Host {idx+1}"
        hostname = str(si.get("hostname") or ip)
        if obfuscated or data.get("obfuscated"):
            if not re.match(r"^Host-\d+$", hostname):
                hostname = f"Host-{idx+1}"
            if not str(ip).startswith("192.0.2."):
                ip = f"192.0.2.{(idx % 250) + 1}"

        host_alarms: List[Dict[str, Any]] = []

        # 1. SEL Alarms
        sel = data.get("sel_alarms") or data.get("system_event_log") or data.get("sel") or []
        vendor_str = str(si.get("vendor") or "")
        norm_v = normalize_vendor(vendor_str)
        for item in sel:
            sev_raw = str(item.get("severity") or item.get("badge") or "Warning").upper()
            sev = "Critical" if "CRIT" in sev_raw or "DANGER" in sev_raw else ("Warning" if "WARN" in sev_raw else "Info")
            msg = str(item.get("message") or item.get("msg") or item.get("description") or "Event entry")
            ts = str(item.get("timestamp") or item.get("created") or item.get("time") or _DASH)
            msg_id = str(item.get("message_id") or item.get("id") or item.get("code") or _DASH)

            clean_mid = msg_id if msg_id != _DASH else None
            if norm_v == "dell":
                info = resolve_dell_event_info(clean_mid, msg)
                target_label = f"Event {info['display']}" if info.get("display") else ("Event " + msg_id if clean_mid else "SEL Entry")
                event_url = info.get("url")
            elif norm_v == "hpe":
                info = resolve_hpe_event_info(clean_mid, msg)
                target_label = f"Event {info['display']}" if info.get("display") else ("Event " + msg_id if clean_mid else "SEL Entry")
                event_url = info.get("url")
            elif norm_v == "cisco":
                info = resolve_cisco_event_info(clean_mid, msg)
                target_label = f"Event {info['display']}" if info.get("display") else ("Event " + msg_id if clean_mid else "SEL Entry")
                event_url = info.get("url")
            else:
                target_label = f"Event {msg_id}" if clean_mid else "SEL Entry"
                event_url = resolve_sel_event_url(vendor_str, clean_mid, msg)

            alarm_dict = {
                "severity": sev,
                "subsystem": "SEL Event Log",
                "message": msg,
                "target": target_label,
                "timestamp": ts,
                "subtab": "tab-overview",
            }
            if event_url:
                alarm_dict["url"] = event_url
            host_alarms.append(alarm_dict)

        # 2. Drive SMART & Telemetry alerts
        for _ctrl, d in _all_drives(data):
            if (d.get("category") or "") == "Empty":
                continue
            bay = d.get("bay_slot") or d.get("bay_position") or d.get("id") or "Bay"
            d_model = str(d.get("model") or d.get("name") or "Drive")
            target_str = f"Slot {bay} ({d_model})"

            if d.get("failure_predicted") or (d.get("oem_metrics") or {}).get("predictive_failure"):
                host_alarms.append({
                    "severity": "Critical",
                    "subsystem": "Drive SMART",
                    "message": "Predictive Failure / S.M.A.R.T. Trip reported on drive",
                    "target": target_str,
                    "timestamp": "Active Alarm",
                })

            dh = str(d.get("drive_health") or "").strip()
            if dh in ("Critical", "Failure"):
                host_alarms.append({
                    "severity": "Critical",
                    "subsystem": "Drive Health",
                    "message": f"Drive reported hardware status: {dh}",
                    "target": target_str,
                    "timestamp": "Active State",
                })
            elif dh in ("Warning", "Degraded"):
                host_alarms.append({
                    "severity": "Warning",
                    "subsystem": "Drive Health",
                    "message": f"Drive reported degraded health: {dh}",
                    "target": target_str,
                    "timestamp": "Active State",
                })

            end = d.get("endurance_remaining_pct")
            if isinstance(end, (int, float)):
                if end < 20:
                    host_alarms.append({
                        "severity": "Critical",
                        "subsystem": "Drive Wear",
                        "message": f"Endurance critical: {end}% remaining life",
                        "target": target_str,
                        "timestamp": f"Life: {end}%",
                    })
                elif end < 50:
                    host_alarms.append({
                        "severity": "Warning",
                        "subsystem": "Drive Wear",
                        "message": f"Endurance low: {end}% remaining life",
                        "target": target_str,
                        "timestamp": f"Life: {end}%",
                    })

            temp = d.get("temperature_c")
            if isinstance(temp, (int, float)):
                if temp >= 70:
                    host_alarms.append({
                        "severity": "Critical",
                        "subsystem": "Drive Thermal",
                        "message": f"Critical drive temperature: {int(temp)}°C",
                        "target": target_str,
                        "timestamp": f"{int(temp)}°C",
                    })
                elif temp >= 60:
                    host_alarms.append({
                        "severity": "Warning",
                        "subsystem": "Drive Thermal",
                        "message": f"Elevated drive temperature: {int(temp)}°C",
                        "target": target_str,
                        "timestamp": f"{int(temp)}°C",
                    })

            if d.get("thermal_throttled"):
                host_alarms.append({
                    "severity": "Warning",
                    "subsystem": "Drive Thermal",
                    "message": "Drive thermal throttling active",
                    "target": target_str,
                    "timestamp": "Active",
                })

            _d_is_boot = bool(d.get("is_boot") or d.get("usage_role") == "Boot Drive" or "boot" in str(d.get("category", "")).lower() or any(k in str(d.get("model", "")).upper() for k in ["BOSS", "NS204I"]))
            if d.get("pcie_downshifted") and not _d_is_boot:
                cap_w = d.get("pcie_capable_width") or ""
                neg_w = d.get("pcie_negotiated_width") or ""
                host_alarms.append({
                    "severity": "Warning",
                    "subsystem": "Drive PCIe",
                    "message": f"PCIe bus width downshifted ({neg_w} of {cap_w})",
                    "target": target_str,
                    "timestamp": "Link Degraded",
                })

            me = d.get("media_errors") or (d.get("oem_metrics") or {}).get("drive_error_count")
            if isinstance(me, (int, float)) and me > 0:
                host_alarms.append({
                    "severity": "Warning",
                    "subsystem": "Drive Media",
                    "message": f"Media / read error count: {int(me)}",
                    "target": target_str,
                    "timestamp": f"{int(me)} errors",
                })

        # 3. PSU Alerts
        psu = data.get("psu_status") or {}
        if psu:
            if psu.get("redundant") is False:
                host_alarms.append({
                    "severity": "Warning",
                    "subsystem": "Power Supply",
                    "message": "Power supply non-redundant (single active feed / loss of redundancy)",
                    "target": "Chassis PSU",
                    "timestamp": "Active State",
                })
            for pu in psu.get("psus") or []:
                pu_h = str(pu.get("health") or "").strip()
                if pu_h in ("Critical", "Failure", "Degraded", "Warning"):
                    sev = "Critical" if pu_h in ("Critical", "Failure") else "Warning"
                    pu_name = str(pu.get("name") or "PSU")
                    host_alarms.append({
                        "severity": sev,
                        "subsystem": "Power Supply",
                        "message": f"Power supply unit health: {pu_h}",
                        "target": pu_name,
                        "timestamp": "Active State",
                    })

        # 4. Thermal Telemetry Alerts
        thermal = data.get("thermal_telemetry") or {}
        for s in thermal.get("sensors") or []:
            reading = s.get("reading")
            crit = s.get("threshold_crit")
            warn = s.get("threshold_warn")
            s_name = str(s.get("name") or "Thermal Sensor")
            if isinstance(reading, (int, float)):
                if isinstance(crit, (int, float)) and reading >= crit:
                    host_alarms.append({
                        "severity": "Critical",
                        "subsystem": "Thermal",
                        "message": f"Sensor threshold breach: {reading}°C >= {crit}°C crit",
                        "target": s_name,
                        "timestamp": f"{reading}°C",
                    })
                elif isinstance(warn, (int, float)) and reading >= warn:
                    host_alarms.append({
                        "severity": "Warning",
                        "subsystem": "Thermal",
                        "message": f"Sensor elevated temperature: {reading}°C >= {warn}°C warn",
                        "target": s_name,
                        "timestamp": f"{reading}°C",
                    })

        # 5. Memory Health & ECC
        mem = data.get("memory_subsystem") or {}
        for fd in mem.get("failed_dimms") or []:
            f_slot = str(fd.get("slot") or "DIMM")
            f_h = str(fd.get("health") or fd.get("state") or "Degraded")
            host_alarms.append({
                "severity": "Critical" if "Critical" in f_h else "Warning",
                "subsystem": "Memory",
                "message": f"DIMM degraded or unseated: {f_h}",
                "target": f_slot,
                "timestamp": "Active State",
            })
        for dimm in mem.get("dimm_list") or []:
            uecc = dimm.get("uncorrectable_ecc")
            if isinstance(uecc, (int, float)) and uecc > 0:
                d_slot = str(dimm.get("slot") or "DIMM")
                host_alarms.append({
                    "severity": "Critical",
                    "subsystem": "Memory",
                    "message": f"Uncorrectable multi-bit ECC error count: {int(uecc)}",
                    "target": d_slot,
                    "timestamp": f"{int(uecc)} UECC",
                })

        # 6. Partial scan status
        if data.get("partial_scan"):
            p_reason = str(data.get("partial_reason") or "Collection incomplete")
            host_alarms.append({
                "severity": "Warning",
                "subsystem": "Scan Status",
                "message": f"Partial Assessment: {p_reason}",
                "target": "Redfish Scan",
                "timestamp": "Incomplete",
            })

        # Sort host alarms: Critical first, then Warning, then Info
        sev_rank = {"Critical": 1, "Warning": 2, "Info": 3}
        host_alarms.sort(key=lambda a: sev_rank.get(a["severity"], 9))

        host_cell = (
            f"<a href='#' class='btn-link tab-jump' data-tab='{host_tab}' data-subtab='tab-health' style='color:inherit;text-decoration:none;display:block'>"
            f"<strong>{_pii(hostname, 'host')}</strong><br><small style='color:var(--text-muted,#64748b)'>{_pii(ip, 'ip')}</small></a>"
        )

        if not host_alarms:
            rows.append(
                f"<tr class='inv-detail-row' data-host-idx='{idx}'>"
                f"<td>{host_cell}</td>"
                f"<td><span class='inv-good'>✓ Healthy</span></td>"
                f"<td>System Health</td>"
                f"<td>All hardware subsystems reporting healthy &amp; in specification</td>"
                f"<td>Host Overall</td>"
                f"<td class='inv-good'>Normal</td>"
                f"</tr>"
            )
        else:
            for alarm in host_alarms:
                s_cls = "inv-bad" if alarm["severity"] == "Critical" else ("inv-warn" if alarm["severity"] == "Warning" else "inv-muted")
                s_icon = "✗ " if alarm["severity"] == "Critical" else ("▲ " if alarm["severity"] == "Warning" else "ℹ ")
                subtab = alarm.get("subtab") or _SUBSYSTEM_SUBTABS.get(alarm.get("subsystem"), "tab-health")
                jump_title = f"Jump to {alarm['subsystem']} details"

                msg_cell = (
                    f"<a href='#' class='btn-link tab-jump' data-tab='{host_tab}' data-subtab='{subtab}' "
                    f"style='color:inherit;text-decoration:none;display:inline-flex;align-items:center;gap:.35rem' "
                    f"title='{_xe(jump_title)}'>"
                    f"<span>{_xe(alarm['message'])}</span> "
                    f"<span style='font-size:.72rem;color:var(--primary,#2563eb);opacity:.85;flex-shrink:0'>&rarr;</span></a>"
                )

                if alarm.get("url"):
                    target_cell = (
                        f"<a href='{_xe(alarm['url'])}' target='_blank' rel='noopener noreferrer' style='text-decoration:none;color:inherit' "
                        f"title='View documentation for {_xe(alarm['target'])}'>"
                        f"<code class='inv-code' style='text-decoration:underline;color:var(--primary,#2563eb)'>{_xe(alarm['target'])}</code> "
                        f"<span style='font-size:.72rem'>↗</span></a>"
                    )
                else:
                    target_cell = (
                        f"<a href='#' class='btn-link tab-jump' data-tab='{host_tab}' data-subtab='{subtab}' style='color:inherit;text-decoration:none' "
                        f"title='{_xe(jump_title)}'>"
                        f"<code class='inv-code'>{_xe(alarm['target'])}</code> "
                        f"<span style='font-size:.72rem;color:var(--primary,#2563eb);opacity:.75'>&rarr;</span></a>"
                    )

                rows.append(
                    f"<tr class='inv-detail-row' data-host-idx='{idx}'>"
                    f"<td>{host_cell}</td>"
                    f"<td><span class='{s_cls}'>{s_icon}{_xe(alarm['severity'])}</span></td>"
                    f"<td><strong>{_xe(alarm['subsystem'])}</strong></td>"
                    f"<td>{msg_cell}</td>"
                    f"<td>{target_cell}</td>"
                    f"<td>{_xe(alarm['timestamp'])}</td>"
                    f"</tr>"
                )

    body = "\n".join(rows) if rows else "<tr><td colspan='6' style='color:#94a3b8'>No health data</td></tr>"
    return f"""<div class="inv-scroll">
<table class="inv-table" id="invHealthTable">
<thead><tr>
<th title="Host server hostname and BMC IP address">Host</th>
<th title="Alarm urgency level (Critical, Warning, or Info)">Severity</th>
<th title="Hardware subsystem reporting the fault (SEL, Storage, Power, Thermal, Memory)">Subsystem</th>
<th title="Detailed fault description, event message, or sensor breach telemetry">Health Alarm / Telemetry</th>
<th title="Specific physical component identifier or drive bay slot">Component / Target</th>
<th title="Event timestamp or active condition status">Timestamp / Status</th>
</tr></thead><tbody>{body}</tbody></table></div>"""


def _build_bmc_hardening_cell(data: dict) -> Tuple[str, str]:
    """Build rich high-priority BMC security hardening HTML badges and posture slug.

    Evaluates both normalized BMC security audit findings (bmc_security_audit)
    and legacy BMC security config checks (bmc_security_config).
    Returns (html_cell, sec_slug) where sec_slug is in ('action_req', 'baseline_met', 'partial', 'excluded', 'not_assessed').
    """
    sec_score = score_host_security(data)
    if sec_score.get("is_fleet_manager"):
        return "<span class='inv-muted' title='Central fleet orchestrator excluded from host BMC security scoring'>Excluded (Fleet Mgr)</span>", "excluded"

    audit = data.get("bmc_security_audit") or {}
    findings = audit.get("findings") or []
    findings_by_id = {f.get("control_id"): f for f in findings if isinstance(f, dict) and f.get("control_id")}
    fails = {cid: f for cid, f in findings_by_id.items() if f.get("status") == "fail"}

    bmc_sec = data.get("bmc_security_config") or data.get("bmc_sec_cfg") or {}
    checks = bmc_sec.get("checks") or []
    checks_by_feature = {c.get("feature"): c for c in checks if isinstance(c, dict) and c.get("feature")}

    crit_issues_legacy = [str(c.get("feature") or "") + ": " + str(c.get("label") or "") for c in checks if c.get("badge") == "danger"]
    warn_issues_legacy = [str(c.get("feature") or "") + ": " + str(c.get("label") or "") for c in checks if c.get("badge") == "warning"]
    all_issues_legacy = crit_issues_legacy + warn_issues_legacy

    tags: List[str] = []

    # 1. Posture Badge (when audit is assessed)
    if sec_score.get("assessed"):
        p_cnt = int(sec_score.get("pass_count") or 0)
        f_cnt = int(sec_score.get("fail_count") or 0)
        u_cnt = int(sec_score.get("unknown_count") or 0)
        comp = sec_score.get("compliance_pct", 0.0)

        if f_cnt > 0:
            sec_slug = "action_req"
            tip = f"BMC Security Audit: {f_cnt} failed, {p_cnt} passed, {u_cnt} unknown ({comp}% compliance)"
            tags.append(f"<span class='inv-bad' title='{_xe(tip)}'>✗ Action Req ({f_cnt}F)</span>")
        elif u_cnt > 0:
            sec_slug = "partial"
            tip = f"BMC Security Audit: {p_cnt} passed, {u_cnt} unknown controls ({comp}% compliance)"
            tags.append(f"<span class='inv-warn' title='{_xe(tip)}'>▲ Partial ({u_cnt}U)</span>")
        else:
            sec_slug = "baseline_met"
            tip = f"BMC Security Audit: all {p_cnt} evaluated controls passed"
            tags.append(f"<span class='inv-good' title='{_xe(tip)}'>✓ Baseline Met</span>")
    else:
        # Fallback slug based on bmc_sec
        if bmc_sec.get("overall_badge") == "danger" or crit_issues_legacy or bmc_sec.get("default_pwd_changed") is False:
            sec_slug = "action_req"
        elif bmc_sec.get("overall_badge") == "warning" or warn_issues_legacy or bmc_sec.get("ipmi_lan_enabled") is True:
            sec_slug = "partial"
        elif bmc_sec.get("overall_badge") == "success" or (bmc_sec.get("default_pwd_changed") is True and bmc_sec.get("ipmi_lan_enabled") is False):
            sec_slug = "baseline_met"
        else:
            sec_slug = "not_assessed"

    # 2. Extract Specific Concern Badges
    issue_tags: List[Tuple[str, str, str]] = []

    # Critical Issues (Red ✗)
    has_telnet = "C23" in fails or checks_by_feature.get("BMC Telnet", {}).get("badge") == "danger"
    if has_telnet:
        issue_tags.append(("crit", "Telnet", "<span class='inv-bad' title='Telnet is enabled (unencrypted cleartext management shell) — disable immediately'>✗ Telnet</span>"))

    has_default_pwd = "C41" in fails or bmc_sec.get("default_pwd_changed") is False
    if has_default_pwd:
        issue_tags.append(("crit", "Default Pwd", "<span class='inv-bad' title='Default factory root password unchanged — rotate root password'>✗ Default Pwd</span>"))

    tls_ver = str(bmc_sec.get("tls_version") or "")
    has_legacy_tls = "C02" in fails or any(v in tls_ver for v in ("1.0", "1.1"))
    if has_legacy_tls:
        issue_tags.append(("crit", "TLS < 1.2", f"<span class='inv-bad' title='Legacy TLS protocol active ({_xe(tls_ver)}) — enforce TLS 1.2+'>✗ TLS &lt; 1.2</span>"))

    # High-Priority Warnings (Amber ▲)
    has_http = "C01" in fails or checks_by_feature.get("BMC HTTP (Plaintext)", {}).get("badge") in ("danger", "warning")
    if has_http:
        issue_tags.append(("warn", "HTTP", "<span class='inv-warn' title='Plaintext HTTP web interface enabled without HTTPS redirection'>▲ HTTP</span>"))

    has_ipmi_lan = "C21" in fails or bmc_sec.get("ipmi_lan_enabled") is True or checks_by_feature.get("IPMI over LAN", {}).get("badge") in ("danger", "warning")
    if has_ipmi_lan:
        issue_tags.append(("warn", "IPMI LAN", "<span class='inv-warn' title='IPMI over LAN is enabled (known RMCP+ cipher 0 vulnerabilities)'>▲ IPMI LAN On</span>"))

    has_no_lockout = "C16" in fails or "C43" in fails or checks_by_feature.get("Account Lockout", {}).get("badge") in ("danger", "warning")
    if has_no_lockout:
        issue_tags.append(("warn", "No Lockout", "<span class='inv-warn' title='Account lockout disabled — vulnerable to brute-force authentication'>▲ No Lockout</span>"))

    has_passthrough = "C15" in fails
    if has_passthrough:
        issue_tags.append(("warn", "Host Pass-Through", "<span class='inv-warn' title='OS-to-BMC pass-through or USB NIC enabled (hypervisor escape / internal boundary risk)'>▲ Host Pass-Through</span>"))

    has_weak_ciphers = "C03" in fails or "C04" in fails
    if has_weak_ciphers:
        issue_tags.append(("warn", "Weak Ciphers", "<span class='inv-warn' title='Weak TLS ciphers or &lt;256-bit encryption permitted (C03/C04)'>▲ Weak Ciphers</span>"))

    has_no_syslog = "C07" in fails or checks_by_feature.get("BMC Remote Syslog", {}).get("badge") in ("danger", "warning")
    if has_no_syslog:
        issue_tags.append(("warn", "No Syslog", "<span class='inv-warn' title='Remote syslog over TLS not configured or disabled'>▲ No Syslog</span>"))

    has_vnc = "C36" in fails
    if has_vnc:
        issue_tags.append(("warn", "VNC", "<span class='inv-warn' title='VNC server enabled without encryption'>▲ VNC</span>"))

    has_usb_mgmt = "C14" in fails
    if has_usb_mgmt:
        issue_tags.append(("warn", "USB Mgmt", "<span class='inv-warn' title='Physical USB port management / USB SCP provisioning active'>▲ USB Mgmt</span>"))

    has_weak_pwd = "C40" in fails or checks_by_feature.get("Min Password Length", {}).get("badge") in ("danger", "warning")
    if has_weak_pwd:
        issue_tags.append(("warn", "Weak Pwd", "<span class='inv-warn' title='Minimum password length &lt; 8 characters'>▲ Weak Pwd</span>"))

    # Discrete baseline tokens if no audit findings assessed (e.g. legacy test fixtures or older scan formats)
    if not sec_score.get("assessed"):
        legacy_hard_tags: List[str] = []
        if tls_ver:
            legacy_hard_tags.append(f"<code class='inv-code'>{_xe(tls_ver)}</code>")
        if bmc_sec.get("default_pwd_changed") is False:
            legacy_hard_tags.append("<span class='inv-bad' title='Default password not changed'>✗ Default Pwd</span>")
        elif bmc_sec.get("default_pwd_changed") is True:
            legacy_hard_tags.append("<span class='inv-good' title='Default password changed'>✓ Pwd Changed</span>")
        if bmc_sec.get("ipmi_lan_enabled") is True:
            legacy_hard_tags.append("<span class='inv-warn' title='IPMI over LAN is enabled'>▲ IPMI LAN On</span>")
        elif bmc_sec.get("ipmi_lan_enabled") is False:
            legacy_hard_tags.append("<span class='inv-good' title='IPMI over LAN is disabled'>✓ IPMI Disabled</span>")

        if legacy_hard_tags:
            return " ".join(legacy_hard_tags), sec_slug
        elif all_issues_legacy:
            summary = "; ".join(all_issues_legacy)
            if crit_issues_legacy:
                return f"<span class='inv-bad' title='{_xe(summary)}'>✗ Action Req</span>", sec_slug
            else:
                return f"<span class='inv-warn' title='{_xe(summary)}'>▲ Review Req</span>", sec_slug
        elif checks:
            return "<span class='inv-good' title='All assessed BMC hardening checks meet baseline'>✓ Baseline Met</span>", sec_slug
        else:
            return "<span class='inv-muted'>Standard</span>", sec_slug

    # 3. Assemble badges for assessed hosts
    if issue_tags:
        max_inline = 3 if tags else 4
        inline_issues = issue_tags[:max_inline]
        overflow = issue_tags[max_inline:]
        for _kind, _lbl, html_str in inline_issues:
            tags.append(html_str)
        if overflow:
            more_names = ", ".join(lbl for _k, lbl, _h in overflow)
            tags.append(f"<span class='inv-warn' title='Additional security concerns: {_xe(more_names)}'>+{len(overflow)} more</span>")
    else:
        if tls_ver and not has_legacy_tls:
            tags.append(f"<code class='inv-code'>{_xe(tls_ver)}</code>")
        if bmc_sec.get("default_pwd_changed") is True:
            tags.append("<span class='inv-good' title='Default password changed'>✓ Pwd Changed</span>")
        if bmc_sec.get("ipmi_lan_enabled") is False:
            tags.append("<span class='inv-good' title='IPMI over LAN is disabled'>✓ IPMI Disabled</span>")
        if len(tags) == 1 and sec_slug == "baseline_met":
            tags.append("<span class='inv-good' title='High-priority controls hardened'>✓ Hardened</span>")

    return " ".join(tags), sec_slug


def _build_security_table(
    all_results: List[dict],
    host_tab_offset: int = 3,
    _pii: Optional[Any] = None,
    obfuscated: bool = False,
) -> str:
    """Build unified security posture and hardening configuration table across the fleet."""
    if _pii is None:
        _pii = _default_pii
    rows = []
    for idx, data in enumerate(all_results or []):
        host_tab = idx + host_tab_offset
        si = data.get("system") or {}
        ip = _host_ip(data) or f"Host {idx+1}"
        hostname = str(si.get("hostname") or ip)
        if obfuscated or data.get("obfuscated"):
            if not re.match(r"^Host-\d+$", hostname):
                hostname = f"Host-{idx+1}"
            if not str(ip).startswith("192.0.2."):
                ip = f"192.0.2.{(idx % 250) + 1}"
        vendor_raw = str(si.get("vendor") or "")
        model_raw = str(si.get("model") or "")
        clean_m = clean_model_code(vendor_raw, model_raw) or model_raw or _DASH

        # TPM 2.0 (green Check or Red X)
        tpm_raw = str(si.get("tpm_status_badge") or "")
        if "success" in tpm_raw or "2.0" in tpm_raw.lower() or "enabled" in tpm_raw.lower():
            if "danger" in tpm_raw or "disabled" in tpm_raw.lower() or "absent" in tpm_raw.lower() or "1.2" in tpm_raw:
                tpm_cell = "<span class='inv-bad' title='TPM Disabled, Absent, or Incompatible'>✗</span>"
            else:
                tpm_cell = "<span class='inv-good' title='TPM 2.0 Enabled'>✓</span>"
        elif "danger" in tpm_raw or "disabled" in tpm_raw.lower() or "absent" in tpm_raw.lower():
            tpm_cell = "<span class='inv-bad' title='TPM Disabled or Absent'>✗</span>"
        elif tpm_raw and "warning" in tpm_raw:
            tpm_cell = "<span class='inv-warn' title='TPM Unknown or Incompatible'>?</span>"
        else:
            tpm_cell = "<span class='inv-muted' title='TPM Not Detected'>?</span>"

        # Secure Boot (green Check if enabled, red Ex if disabled without 'disabled' text)
        sb = data.get("secure_boot") or {}
        sb_enabled = sb.get("enabled")
        if sb_enabled is True:
            sb_cell = "<span class='inv-good' title='Secure Boot Enabled'>✓</span>"
        elif sb_enabled is False:
            sb_cell = "<span class='inv-bad' title='Secure Boot Disabled'>✗</span>"
        else:
            sb_cell = "<span class='inv-muted' title='Secure Boot Not Exposed'>—</span>"

        # BMC Model & Firmware (word-wrapped after model)
        bm = data.get("bmc_firmware") or {}
        bmc_model = str(bm.get("bmc_model") or "BMC")
        bmc_fw = str(bm.get("bmc_fw_version") or _DASH)
        bmc_cell = f"<strong>{_xe(bmc_model)}</strong><br><code class='inv-code'>{_xe(bmc_fw)}</code>"

        # Check BMC firmware baseline
        bmc_model_up = bmc_model.upper()
        bmc_base = next((BMC_FW_BASELINES[k] for k in BMC_FW_BASELINES if k in bmc_model_up), None)
        if bmc_base and bmc_fw != _DASH:
            latest = str(bmc_base.get("latest") or "")
            min_rec = str(bmc_base.get("min_recommended") or "")
            if bmc_fw >= latest or (min_rec and bmc_fw >= min_rec):
                bmc_cell += f" <span class='inv-good' title='Meets certified baseline ({latest})'>✓</span>"
            else:
                bmc_cell += f" <span class='inv-bad' title='Upgrade recommended (latest: {latest})'>▲</span>"

        # CVE Coverage Tier (Green check if current Tier 4, Red X if < Tier 4)
        bios_eval = si.get("bios_eval") or {}
        cve_tier_int = bios_eval.get("cve_tier")
        cve_label = bios_eval.get("cve_tier_label")
        if cve_tier_int is not None and cve_tier_int >= 0:
            if cve_tier_int >= 4:
                cve_cell = f"<span class='inv-good' title='Current CVE baseline: {_xe(cve_label or '')}'>✓ Tier {cve_tier_int}</span>"
            else:
                cve_cell = f"<span class='inv-bad' title='Outdated CVE baseline: {_xe(cve_label or '')}'>✗ Tier {cve_tier_int}</span>"
        else:
            cve_cell = f"<span class='inv-muted'>{_DASH}</span>"

        # Hyperthreading / HT (Plain text: Enabled or Disabled)
        ci = si.get("cpu_summary") or {}
        ht_on = ci.get("ht_enabled")
        if ht_on is True:
            ht_cell = "<span>Enabled</span>"
        elif ht_on is False:
            ht_cell = "<span>Disabled</span>"
        else:
            ht_cell = f"<span class='inv-muted'>{_DASH}</span>"

        # NTP / Time Drift
        bmc_net_proto = data.get("bmc_net_proto") or {}
        ntp_active = bmc_net_proto.get("ntp_enabled")
        ntp_servers = bmc_net_proto.get("ntp_servers") or []
        time_drift_detected = bmc_net_proto.get("time_drift_detected")
        drift_sec = bmc_net_proto.get("time_drift_seconds")

        if time_drift_detected and drift_sec is not None:
            abs_d = abs(drift_sec)
            mins = abs_d // 60
            secs = abs_d % 60
            full_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
            disp_str = f"{mins}m" if mins > 0 else f"{secs}s"
            ntp_cell = f"<span class='inv-bad' title='Time drift detected: {full_str} clock skew'>✗ Drift ({disp_str})</span>"
        elif ntp_active and ntp_servers:
            srv_str = "Configured" if obfuscated else ", ".join(ntp_servers[:2])
            ntp_cell = f"<span class='inv-good' title='NTP Active: {srv_str}'>✓ In Sync</span>"
        elif ntp_active:
            ntp_cell = "<span class='inv-warn' title='NTP enabled on BMC but no NTP servers configured'>▲ No Servers</span>"
        elif ntp_active is False:
            ntp_cell = "<span class='inv-bad' title='NTP disabled on BMC'>✗ Disabled</span>"
        else:
            ntp_cell = f"<span class='inv-muted'>{_DASH}</span>"

        # DNS Configuration
        dns_active = bmc_net_proto.get("dns_enabled")
        dns_servers = bmc_net_proto.get("dns_servers") or []
        dns_configured = bmc_net_proto.get("dns_configured")
        dns_name = si.get("dns_name")

        if dns_servers or dns_configured:
            srv_label = "Configured" if obfuscated else (", ".join(dns_servers[:2]) if dns_servers else "Configured")
            dns_cell = f"<span class='inv-good' title='DNS Servers: {_xe(srv_label)}'>✓ Configured</span>"
        elif dns_name:
            dns_lbl = "Configured" if obfuscated else _xe(dns_name)
            dns_cell = f"<span class='inv-good' title='FCrDNS Name: {dns_lbl}'>✓ Configured</span>"
        elif dns_active:
            dns_cell = "<span class='inv-warn' title='DNS protocol enabled on BMC but no servers configured'>▲ No Servers</span>"
        else:
            dns_cell = "<span class='inv-bad' title='DNS not configured on BMC'>✗ Not Configured</span>"

        # BMC Hardening
        bmc_hard_cell, sec_slug = _build_bmc_hardening_cell(data)

        # BMC License
        lic = data.get("bmc_license") or {}
        name = str(lic.get("license_name") or "").strip()
        low = name.lower()
        if not name:
            lic_cell = f"<span class='inv-muted'>{_DASH}</span>"
        elif any(k in low for k in ("expir", "required", "blocked", "missing")):
            lic_cell = f"<span class='inv-bad' title='{_xe(name)}'>✗ {_xe(name)}</span>"
        elif any(k in low for k in ("advanced", "enterprise", "datacenter", "perpetual")):
            lic_cell = f"<span class='inv-good'>{_xe(name)}</span>"
        else:
            lic_cell = f"<span>{_xe(name)}</span>"

        rows.append(
            f"<tr class='inv-detail-row' data-host-idx='{idx}' data-sec-posture='{sec_slug}'>"
            f"<td><a href='#' class='btn-link tab-jump' data-tab='{host_tab}' data-subtab='tab-security' style='color:inherit;text-decoration:none;display:block'>"
            f"<strong>{_pii(hostname, 'host')}</strong><br><small style='color:var(--text-muted,#64748b)'>{_pii(ip, 'ip')}</small></a></td>"
            f"<td><strong>{_xe(clean_m)}</strong></td>"
            f"<td>{tpm_cell}</td>"
            f"<td>{sb_cell}</td>"
            f"<td>{bmc_cell}</td>"
            f"<td>{lic_cell}</td>"
            f"<td>{cve_cell}</td>"
            f"<td>{ht_cell}</td>"
            f"<td>{ntp_cell}</td>"
            f"<td>{dns_cell}</td>"
            f"<td>{bmc_hard_cell}</td>"
            f"</tr>"
        )
    body = "\n".join(rows) if rows else "<tr><td colspan='11' style='color:#94a3b8'>No hosts</td></tr>"
    return f"""<div class="inv-scroll">
<table class="inv-table" id="invSecurityTable">
<thead><tr>
<th title="Host server hostname and BMC IP address">Host</th>
<th title="Server hardware manufacturer and chassis model">Model</th>
<th title="Trusted Platform Module 2.0 presence and activation (Required for VCF 9.1 security baseline)">TPM 2.0</th>
<th title="UEFI Secure Boot verification status (Recommended for VCF hardening baseline)">Secure<br>Boot</th>
<th title="Out-of-band management controller model and firmware version baseline">BMC Model<br>&amp; FW</th>
<th title="Out-of-band management controller license tier and activation status">BMC<br>License</th>
<th title="BIOS processor microcode mitigation tier (Tier 4 is the current certified baseline)">CVE Coverage<br>Tier</th>
<th title="Intel Hyper-Threading / AMD SMT processor logical core status (Enabled or Disabled)">HT</th>
<th title="BMC Network Time Protocol synchronization status and clock skew detection (5m threshold)">NTP /<br>Time Drift</th>
<th title="BMC Domain Name System server configuration for hostname resolution">DNS</th>
<th title="Out-of-band security posture: high-priority hardening controls, protocol security, credential policy, and attack surface mitigations">BMC<br>Hardening</th>
</tr></thead><tbody>{body}</tbody></table></div>"""
