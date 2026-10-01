"""
VCF Readiness Tool — per-host standalone HTML report generator (Layer D).

generate_host_html_report() produces a zero-dependency, self-contained HTML
file that an SE can email or double-click on any machine.
"""
import logging
import os
from typing import Optional

logger = logging.getLogger("vcf_assess")

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.compat_engine import VCF9CompatibilityEngine
from vcf_hci.hcl import load_optional_vsan_csv, load_vsan_hcl_json
from vcf_hci.report.helpers import _h, html_escape
from vcf_hci.report.sections.bios_security import (
    render_bios_perf_card_and_accordion,
    render_boot_order_card,
    render_security_card_and_accordion,
)
from vcf_hci.report.sections.cpu import render_cpu_combined_card, render_cpu_deep_section
from vcf_hci.report.sections.firmware_os import (
    render_bundle_card,
    render_driver_fw_alignment_card,
    render_firmware_inventory_section,
    render_os_card,
    render_warranty_card,
)
from vcf_hci.report.sections.health import (
    render_bmc_diagnostics_section,
    render_job_queue_card_and_health_section,
    render_nvme_smart_health_section,
    render_psu_card_and_health_section,
    render_sel_section,
    render_thermal_health_section,
)
from vcf_hci.report.sections.memory import render_memory_combined_card, render_memory_interleaving_section
from vcf_hci.report.sections.network import render_network_section
from vcf_hci.report.sections.overview import render_alert_rollup, render_header_and_banners
from vcf_hci.report.sections.pcie_gpu import (
    render_gpu_cards_and_section,
    render_pcie_slot_section,
)
from vcf_hci.report.sections.storage import (
    enrich_drives_hcl,
    render_storage_subsystem_section,
    render_vsan_esa_ready_node_cards,
)
from vcf_hci.report.sel_links import render_vendor_guide_button
from vcf_hci.report.styles import HOST_REPORT_CSS, THEME_TOGGLE_JS


def generate_host_html_report(
    data: dict,
    output_filepath: str,
    json_hcl: Optional[dict] = None,
    csv_path: Optional[str] = None,
    quick_mode: bool = False,
    hcl_bundle_metadata: Optional[dict] = None,
    obfuscated: bool = False,
):
    """Generate standalone HTML report for a single host."""
    _page_salt = os.urandom(16).hex()

    sys_info = data.get("system", {})
    _ip = str(sys_info.get("ip") or "").strip()
    cpu_info = sys_info.get("cpu_summary", {})
    bios_info = data.get("bios_checks", {})
    bios_eval = sys_info.get("bios_eval", {})
    mem_info = data.get("memory_subsystem", {})
    mem_tel = data.get("memory_telemetry", {})
    cpu_tel = data.get("cpu_telemetry", {})
    io_tel  = data.get("io_telemetry", {})
    thermal = data.get("thermal_telemetry", {})
    nics = data.get("network_adapters", [])
    storage = data.get("storage_subsystem", [])
    sel = data.get("sel_alarms") or data.get("sel") or data.get("system_event_log") or []
    gpus = data.get("gpu_accelerators", [])
    fc_hbas = data.get("fc_hbas", [])
    lldp_neighbors = data.get("lldp_neighbors", [])
    psu = data.get("psu_status", {})
    bmc_lic = data.get("bmc_license", {})
    pcie_switches = data.get("pcie_switches", [])
    pcie_slots = data.get("pcie_slots", [])
    pcie_lane_budget = data.get("pcie_lane_budget", {})
    secure_boot = data.get("secure_boot", {})
    bmc_firmware = data.get("bmc_firmware", {})
    bmc_sec_cfg = data.get("bmc_security_config", {})
    host_os = data.get("host_os", {})
    warranty_info = data.get("warranty", {})
    csv_db = load_optional_vsan_csv(csv_path)
    if json_hcl is None:
        json_hcl = load_vsan_hcl_json()
    _data_src = sys_info.get("data_source", "")
    _wsman_proto_label = sys_info.get("wsman_proto_label", "WS-Man")

    mem_topo = data.get("memory_topology")
    if not mem_topo:
        mem_topo = VCF9CompatibilityEngine.evaluate_memory_topology(mem_info, cpu_info)

    all_drives = enrich_drives_hcl(storage, json_hcl=json_hcl, csv_db=csv_db)
    esa_nvme_count = sum(1 for d in all_drives if d.get("category") == "vSAN ESA/OSA NVMe")
    osa_count = sum(1 for d in all_drives if d.get("category") == "vSAN OSA SAS/SATA")

    if cpu_info.get("model"):
        cpu_verdict, fresh_arch, _, _, _ = VCF9CompatibilityEngine.evaluate_cpu(
            cpu_info.get("model", ""), sys_info.get("vendor", ""), sys_info.get("model", "")
        )
        if not cpu_info.get("architecture") or cpu_info.get("architecture") == "Unknown":
            cpu_info["architecture"] = fresh_arch
    else:
        cpu_verdict = cpu_info.get("verdict") or "Unsupported"
    cpu_arch = cpu_info.get("architecture", "")
    vmd_enabled = bios_info.get("vmd_enabled_flag", False)
    is_skylake_deprecated = "Skylake" in cpu_arch and "Cascade" not in cpu_arch

    _vendor_str = sys_info.get("vendor", "")
    _model_str = sys_info.get("model", "")
    bcg_server_url = BCGLinkGenerator.server(_vendor_str, _model_str, cpu_info)
    bcg_cpu_url = BCGLinkGenerator.cpu(cpu_info.get("model", ""), cpu_info.get("processor_id", ""))

    header_html, banners_html = render_header_and_banners(
        sys_info, host_os, _page_salt, quick_mode, _data_src, _wsman_proto_label, bcg_server_url, bcg_cpu_url, obfuscated, data.get("collector_class"), data=data
    )

    _cpu_combined_card_html = render_cpu_combined_card(cpu_info, sys_info, cpu_verdict)
    _cpu_deep_section_html = render_cpu_deep_section(cpu_info, sys_info, bios_info, cpu_verdict)

    _mem_section_html = render_memory_interleaving_section(mem_topo, bios_info=bios_info)
    _memory_combined_card_html = render_memory_combined_card(mem_topo, sys_info, bios_info)

    _rn_card_html, _vsan_esa_card_html = render_vsan_esa_ready_node_cards(
        sys_info, cpu_info, nics, all_drives, esa_nvme_count, vmd_enabled, is_skylake_deprecated, data=data
    )
    storage_section_html, (_stor_badge_cls, _stor_badge_lbl) = render_storage_subsystem_section(
        storage, sys_info, _page_salt, pcie_switches, pcie_lane_budget, json_hcl=json_hcl, quick_mode=quick_mode, bmc_lic=bmc_lic, data=data
    )

    _tor_switch_map_html, network_section_html, _fc_hba_card_html = render_network_section(
        nics, lldp_neighbors, fc_hbas, _page_salt, quick_mode=quick_mode, bmc_lic=bmc_lic, data_src=_data_src, wsman_proto_label=_wsman_proto_label, data=data, json_hcl=json_hcl
    )

    psu_card_html, _psu_health_section = render_psu_card_and_health_section(psu)
    thermal_section_html, key_sensor_str = render_thermal_health_section(thermal)
    _smart_health_section = render_nvme_smart_health_section(all_drives)
    _bmc_health_section = render_bmc_diagnostics_section(data)
    _jobq_card_html, _jobq_health_section = render_job_queue_card_and_health_section(data)
    sel_rows = render_sel_section(sel, vendor=_vendor_str)
    _sel_guide_btn = render_vendor_guide_button(_vendor_str)

    _bios_perf_card_html, _ras_detail_section = render_bios_perf_card_and_accordion(bios_info, sys_info, bios_eval)
    _boot_order_section = render_boot_order_card(sys_info)

    # Vendor BIOS Tuning Guide link button for BIOS tab header
    _tuning_guide_btn = ""
    _vendor_l = str(sys_info.get("vendor") or "").lower()
    _model_l = str(sys_info.get("model") or "").lower()
    if "cisco" in _vendor_l or "cisco" in _model_l or "ucs" in _model_l:
        from vcf_hci.bios.cisco_baseline import get_cisco_tuning_guide
        c_drift = bios_info.get("cisco_baseline_drift") or bios_info.get("bios_baseline_drift") or {}
        guide = c_drift.get("tuning_guide") or get_cisco_tuning_guide(sys_info.get("model"), sys_info.get("bios_version"), sys_info.get("cpu_summary"))
        g_url = guide.get("url")
        g_title = guide.get("title", "Cisco UCS Tuning Guide")
        g_gen = guide.get("generation", "M6")
        if g_url:
            _tuning_guide_btn = f'<a href="{g_url}" target="_blank" rel="noopener noreferrer" class="btn-link" style="font-size:.8rem;color:var(--primary);border:1px solid rgba(14,165,233,0.3);padding:2px 8px;border-radius:4px" title="{_h(g_title)}">📖 Cisco UCS {g_gen} Tuning Guide ↗</a>'
    elif "dell" in _vendor_l or "poweredge" in _model_l:
        from vcf_hci.bios.dell_baseline import get_dell_tuning_guide
        d_guide = get_dell_tuning_guide(sys_info.get("model"), sys_info.get("bios_version"), sys_info.get("cpu_summary"))
        g_url = d_guide.get("url")
        g_title = d_guide.get("title", "Dell PowerEdge Tuning Guide")
        if g_url:
            _tuning_guide_btn = f'<a href="{g_url}" target="_blank" rel="noopener noreferrer" class="btn-link" style="font-size:.8rem;color:var(--primary);border:1px solid rgba(14,165,233,0.3);padding:2px 8px;border-radius:4px" title="{_h(g_title)}">📖 Dell BIOS Tuning Guide ↗</a>'
    elif "hpe" in _vendor_l or "proliant" in _model_l or "synergy" in _model_l:
        from vcf_hci.bios.hpe_baseline import get_hpe_tuning_guide
        h_guide = get_hpe_tuning_guide(sys_info.get("model"), sys_info.get("bios_version"), sys_info.get("cpu_summary"))
        g_url = h_guide.get("url")
        g_title = h_guide.get("title", "HPE ProLiant Tuning Guide")
        g_gen = h_guide.get("generation", "Gen10/Gen11")
        if g_url:
            _tuning_guide_btn = f'<a href="{g_url}" target="_blank" rel="noopener noreferrer" class="btn-link" style="font-size:.8rem;color:var(--primary);border:1px solid rgba(14,165,233,0.3);padding:2px 8px;border-radius:4px" title="{_h(g_title)}">📖 HPE {g_gen} Tuning Guide ↗</a>'
    elif "lenovo" in _vendor_l or "thinksystem" in _model_l:
        from vcf_hci.bios.lenovo_baseline import get_lenovo_tuning_guide
        l_guide = get_lenovo_tuning_guide(sys_info.get("model"), sys_info.get("bios_version"), sys_info.get("cpu_summary"))
        g_url = l_guide.get("url")
        g_title = l_guide.get("title", "Lenovo ThinkSystem Tuning Guide")
        if g_url:
            _tuning_guide_btn = f'<a href="{g_url}" target="_blank" rel="noopener noreferrer" class="btn-link" style="font-size:.8rem;color:var(--primary);border:1px solid rgba(14,165,233,0.3);padding:2px 8px;border-radius:4px" title="{_h(g_title)}">📖 Lenovo BIOS Tuning Guide ↗</a>'
    else:
        _tuning_guide_btn = '<a href="https://www.vmware.com/docs/vsphere-esxi-vcenter-server-90-performance-best-practices" target="_blank" rel="noopener noreferrer" class="btn-link" style="font-size:.8rem;color:var(--primary);border:1px solid rgba(14,165,233,0.3);padding:2px 8px;border-radius:4px" title="VMware vSphere 9.0 Performance Best Practices">📖 VMware Performance Guide ↗</a>'
    _security_card_html, _security_accordion, _tpm_badge_raw, _sb_badge, _spectre_badge_html = render_security_card_and_accordion(
        sys_info, bios_info, bios_eval, cpu_info, secure_boot, bmc_firmware, bmc_sec_cfg, data, _page_salt
    )

    _rollup_bar_html, _rollup_detail_html, _tab_dots = render_alert_rollup(
        sel, storage, thermal, mem_info, mem_topo, nics, _tpm_badge_raw, _sb_badge, _spectre_badge_html, psu, gpus, data=data
    )

    pcie_slot_section = render_pcie_slot_section(pcie_slots, _page_salt, json_hcl=json_hcl)
    _gpu_cards_html, gpu_section = render_gpu_cards_and_section(gpus, _page_salt, json_hcl=json_hcl)

    _warranty_card_html = render_warranty_card(warranty_info)
    _bundle_card_html = render_bundle_card(hcl_bundle_metadata)
    _os_card_html = render_os_card(host_os)
    real_nics = [n for n in nics if not n.get("unsupported_license")]
    _driver_fw_alignment_card_html = render_driver_fw_alignment_card(real_nics, storage, json_hcl=json_hcl)
    _firmware_inv_section = render_firmware_inventory_section(data, sys_info, json_hcl=json_hcl)

    _wsman_extra_cards = ""
    if _data_src.startswith("wsman"):
        _sb_badge_extra = sys_info.get("secure_boot_badge", "<span class='badge info'>ℹ️ Unknown</span>")
        _wsman_extra_cards += (
            f"<div class='card'><h3>Secure Boot (UEFI)</h3>"
            f"<div>{_sb_badge_extra}</div>"
            f"<p style='font-size:.85rem;color:var(--text-muted);margin-top:.5rem'>"
            f"Required for vSphere 9.1 secure boot baseline.</p></div>"
        )
        if _data_src == "wsman_amt" and sys_info.get("amt_mode_badge"):
            _wsman_extra_cards += (
                f"<div class='card'><h3>AMT Provisioning</h3>"
                f"<div>{sys_info['amt_mode_badge']}</div>"
                f"<p style='font-size:.85rem;color:var(--text-muted);margin-top:.5rem'>"
                f"CCM = limited inventory; ACM = full inventory access.</p></div>"
            )
        if sys_info.get("ddr_gen") and sys_info["ddr_gen"] != "Unknown":
            _spd = f" @ {sys_info.get('ddr_speed_mhz', 0)} MHz" if sys_info.get('ddr_speed_mhz') else ""
            _wsman_extra_cards += (
                f"<div class='card'><h3>Memory Generation</h3>"
                f"<div><span class='badge info'>ℹ️ {sys_info['ddr_gen']}{_spd}</span></div>"
                f"<p style='font-size:.85rem;color:var(--text-muted);margin-top:.5rem'>"
                f"Detected via CIM_PhysicalMemory.MemoryType</p></div>"
            )

    cpu_curr = f"{cpu_tel.get('current_utilization_pct')}%" if isinstance(cpu_tel.get("current_utilization_pct"), (int, float)) else "N/A"
    cpu_peak = f"{cpu_tel.get('historical_peak_pct')}%" if isinstance(cpu_tel.get("historical_peak_pct"), (int, float)) else "N/A"
    mem_curr = f"{mem_tel.get('current_utilization_pct')}%" if isinstance(mem_tel.get("current_utilization_pct"), (int, float)) else "N/A"
    mem_peak = f"{mem_tel.get('historical_peak_pct')}%" if isinstance(mem_tel.get("historical_peak_pct"), (int, float)) else "N/A"
    io_curr  = f"{io_tel.get('io_current_pct')}%" if isinstance(io_tel.get("io_current_pct"), (int, float)) else "N/A"
    io_peak  = f"{io_tel.get('io_peak_pct')}%" if isinstance(io_tel.get("io_peak_pct"), (int, float)) else "N/A"
    has_telemetry = cpu_curr != "N/A" or mem_curr != "N/A" or io_curr != "N/A"

    _io_tooltip = (
        "PCIe root complex bandwidth utilization. "
        "Hardware counters at each PCIe root port are summed to measure all PCIe bus traffic — "
        "NVMe drives, NICs, and GPUs. This is NOT OS-level disk or network I/O. "
        "The BMC samples at 5-second intervals; the value shown is the 1-minute rolling average at scan time."
    )

    if data.get("ilo_advanced_license_required") or data.get("dcms_license_required"):
        tel_cards = (
            "<div class='card'><h3>Telemetry Metrics</h3>"
            "<div><span class='badge warning'>🔒 License Upgrade Required</span></div>"
            "<p style='font-size:.82rem;color:var(--text-muted);margin-top:.5rem'>"
            "HPE iLO Advanced or Supermicro DCMS License required to collect live CPU/Memory telemetry.</p></div>"
        )
        tel_section = (
            "<h2>Live Telemetry Metrics (1-Min Rolling Average)</h2>"
            "<p style='color:#7f1d1d;padding:.5rem 0'>"
            "🔒 Telemetry collection requires a license upgrade on this BMC. "
            "HPE iLO Advanced or Supermicro DCMS license needed.</p>"
        )
    elif has_telemetry:
        tel_cards = (
            f"<div class='card'><h3>Telemetry Metrics</h3>"
            f"<div><span class='badge success'>🟢 Live Counters</span></div>"
            f"<p style='font-size:.85rem;color:var(--text-muted);margin-top:.5rem'>"
            f"CPU: <b>{cpu_curr}</b> (Peak <b>{cpu_peak}</b>) &nbsp;|&nbsp; "
            f"RAM: <b>{mem_curr}</b> (Peak <b>{mem_peak}</b>)<br>"
            f"<span title='{_io_tooltip}'>PCIe I/O ℹ️: <b>{io_curr}</b> (Peak <b>{io_peak}</b>)</span></p></div>"
        )
        tel_section = (
            f"<h2>Live Telemetry Metrics (1-Min Rolling Average)</h2>"
            f"<table><thead><tr><th>Metric</th><th>Current Utilization</th><th>1-Min Historical Peak</th><th>Source Endpoint</th></tr></thead>"
            f"<tbody>"
            f"<tr><td><b>CPU Utilization</b></td><td>{cpu_curr}</td><td>{cpu_peak}</td><td>Redfish TelemetryService / SystemUsage</td></tr>"
            f"<tr><td><b>Memory Utilization</b></td><td>{mem_curr}</td><td>{mem_peak}</td><td>Redfish TelemetryService / SystemUsage</td></tr>"
            f"<tr><td><b title='{_io_tooltip}'>PCIe Root Complex I/O ℹ️</b></td><td>{io_curr}</td><td>{io_peak}</td><td>Redfish TelemetryService / SystemUsage</td></tr>"
            f"</tbody></table>"
        )
    else:
        tel_cards = ""
        tel_section = (
            "<h2>Live Telemetry Metrics (1-Min Rolling Average)</h2>"
            "<p style='color:var(--text-muted);padding:.5rem 0'>Telemetry endpoints not populated on this BMC platform.</p>"
        )

    _exp_nav_btn = (
        f'<a href="redfish_explorer_{_ip}.html" target="_blank" '
        f'style="margin-left:auto;text-decoration:none;padding:5px 12px;font-size:0.8rem;font-weight:600;color:var(--accent,#38bdf8);'
        f'background:rgba(56,189,248,0.1);border:1px solid rgba(56,189,248,0.3);border-radius:6px;display:inline-flex;align-items:center;gap:4px;" '
        f'title="Inspect raw Redfish API payloads for this server">🧭 Redfish Explorer ↗</a>'
    ) if _ip else ""

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>VCF Readiness — {_h(str(sys_info.get('dns_name') or sys_info.get('hostname', '')))}</title>
    <style>{HOST_REPORT_CSS}</style>
</head>
<body>
<div class="container">
    {header_html}
    {banners_html}

    <div class="grid">
        {_cpu_combined_card_html}
        {_bios_perf_card_html}
        {_security_card_html}
        {_wsman_extra_cards}
        {_memory_combined_card_html}
        {_driver_fw_alignment_card_html}
        {_bundle_card_html}
        {_warranty_card_html}
        {_vsan_esa_card_html}
        {_rn_card_html}
        {_os_card_html}
        {psu_card_html}
        {tel_cards}
        {_fc_hba_card_html}
        {_jobq_card_html}
    </div>

    {_rollup_bar_html}

    <div class="tab-nav">
        <button class="tab-btn" data-tab="tab-overview"><span class="tab-dot dot-{_tab_dots['tab-overview']}"></span>Overview</button>
        <button class="tab-btn" data-tab="tab-cpu"><span class="tab-dot dot-{_tab_dots['tab-cpu']}"></span>CPU</button>
        <button class="tab-btn" data-tab="tab-bios"><span class="tab-dot dot-{_tab_dots['tab-bios']}"></span>BIOS</button>
        <button class="tab-btn" data-tab="tab-memory"><span class="tab-dot dot-{_tab_dots['tab-memory']}"></span>Memory</button>
        <button class="tab-btn" data-tab="tab-storage"><span class="tab-dot dot-{_tab_dots['tab-storage']}"></span>Storage</button>
        <button class="tab-btn" data-tab="tab-pcie"><span class="tab-dot dot-{_tab_dots['tab-pcie']}"></span>PCIe</button>
        {'<button class="tab-btn" data-tab="tab-gpu"><span class="tab-dot dot-info"></span>GPU</button>' if gpus else ''}
        <button class="tab-btn" data-tab="tab-network"><span class="tab-dot dot-{_tab_dots['tab-network']}"></span>Networking</button>
        <button class="tab-btn" data-tab="tab-health"><span class="tab-dot dot-{_tab_dots['tab-health']}"></span>Health</button>
        <button class="tab-btn" data-tab="tab-security"><span class="tab-dot dot-{_tab_dots['tab-security']}"></span>Security</button>
        <button class="tab-btn" data-tab="tab-firmware"><span class="tab-dot dot-{_tab_dots['tab-firmware']}"></span>Firmware Inventory</button>
        {_exp_nav_btn}
    </div>

    <div id="tab-overview" class="tab-pane">
        {_rollup_detail_html}
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;flex-wrap:wrap;gap:0.5rem">
            <h2 style="margin:0">Recent System Event Log (SEL / IML)</h2>
            <div style="display:flex;gap:8px;align-items:center;">
                {_sel_guide_btn}
                {f'<a href="redfish_explorer_{_ip}.html?fixture=sel" target="_blank" class="btn-link" style="font-size:.8rem;color:var(--accent,#38bdf8);border:1px solid rgba(56,189,248,0.3);padding:2px 8px;border-radius:4px" title="Inspect SEL/IML in Redfish Explorer">🧭 Inspect SEL in Redfish ↗</a>' if _ip else ''}
            </div>
        </div>
        <table><thead><tr><th>Severity</th><th>Message ID</th><th>Alarm Details</th><th>Timestamp</th></tr></thead><tbody>{sel_rows}</tbody></table>
    </div>

    <div id="tab-cpu" class="tab-pane">
        {f'<div style="display:flex;justify-content:flex-end;margin-bottom:0.75rem;"><a href="redfish_explorer_{_ip}.html?fixture=cpu" target="_blank" class="btn-link" style="font-size:.8rem;color:var(--accent,#38bdf8);border:1px solid rgba(56,189,248,0.3);padding:2px 8px;border-radius:4px" title="Inspect Processors in Redfish Explorer">🧭 Inspect CPU in Redfish ↗</a></div>' if _ip else ''}
        {_cpu_deep_section_html}
    </div>

    <div id="tab-bios" class="tab-pane">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;flex-wrap:wrap;gap:0.5rem">
            <h2 style="margin:0">BIOS &amp; Performance Settings</h2>
            <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">
                {_tuning_guide_btn}
                {f'<a href="redfish_explorer_{_ip}.html?fixture=bios" target="_blank" class="btn-link" style="font-size:.8rem;color:var(--accent,#38bdf8);border:1px solid rgba(56,189,248,0.3);padding:2px 8px;border-radius:4px" title="Inspect BIOS & Boot in Redfish Explorer">🧭 Inspect BIOS in Redfish ↗</a>' if _ip else ''}
            </div>
        </div>
        {_boot_order_section}
        {_ras_detail_section}
    </div>

    <div id="tab-memory" class="tab-pane">
        {f'<div style="display:flex;justify-content:flex-end;margin-bottom:0.75rem;"><a href="redfish_explorer_{_ip}.html?fixture=memory" target="_blank" class="btn-link" style="font-size:.8rem;color:var(--accent,#38bdf8);border:1px solid rgba(56,189,248,0.3);padding:2px 8px;border-radius:4px" title="Inspect Memory in Redfish Explorer">🧭 Inspect Memory in Redfish ↗</a></div>' if _ip else ''}
        {_mem_section_html}
        {tel_section}
    </div>

    <div id="tab-storage" class="tab-pane">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;flex-wrap:wrap;gap:0.5rem">
            <h2 style="margin:0">Storage Subsystem</h2>
            {f'<a href="redfish_explorer_{_ip}.html?fixture=storage" target="_blank" class="btn-link" style="font-size:.8rem;color:var(--accent,#38bdf8);border:1px solid rgba(56,189,248,0.3);padding:2px 8px;border-radius:4px" title="Inspect Storage in Redfish Explorer">🧭 Inspect Storage in Redfish ↗</a>' if _ip else ''}
        </div>
        <details class="accordion" open>
            <summary>
                <div>&#128230; Drive &amp; Storage Inventory &nbsp;<span class="badge {_stor_badge_cls}">{_stor_badge_lbl}</span></div>
                <span style="font-size:.85rem;color:var(--primary)">Collapse Details &#9652;</span>
            </summary>
            <div class="accordion-body" style="padding:1.25rem">
                {storage_section_html}
            </div>
        </details>
    </div>

    <div id="tab-pcie" class="tab-pane">
        {pcie_slot_section}
    </div>

    {'<div id="tab-gpu" class="tab-pane">' + gpu_section + '</div>' if gpus else ''}

    <div id="tab-network" class="tab-pane">
        {f'<div style="display:flex;justify-content:flex-end;margin-bottom:0.75rem;"><a href="redfish_explorer_{_ip}.html?fixture=network" target="_blank" class="btn-link" style="font-size:.8rem;color:var(--accent,#38bdf8);border:1px solid rgba(56,189,248,0.3);padding:2px 8px;border-radius:4px" title="Inspect Network Adapters in Redfish Explorer">🧭 Inspect NICs in Redfish ↗</a></div>' if _ip else ''}
        {_tor_switch_map_html}
        {network_section_html}
    </div>

    <div id="tab-health" class="tab-pane">
        {f'<div style="display:flex;justify-content:flex-end;margin-bottom:0.75rem;"><a href="redfish_explorer_{_ip}.html?fixture=power" target="_blank" class="btn-link" style="font-size:.8rem;color:var(--accent,#38bdf8);border:1px solid rgba(56,189,248,0.3);padding:2px 8px;border-radius:4px" title="Inspect Power & Thermals in Redfish Explorer">🧭 Inspect Power &amp; Thermal in Redfish ↗</a></div>' if _ip else ''}
        {_bmc_health_section}
        {_jobq_health_section}
        {thermal_section_html}
        {_psu_health_section}
        {_smart_health_section}
    </div>

    <div id="tab-security" class="tab-pane">
        {_security_accordion}
    </div>

    <div id="tab-firmware" class="tab-pane">
        {_firmware_inv_section}
    </div>
</div>
<script>
(function(){{
  var cb = document.getElementById('maskPII');
  var dlBtn = document.getElementById('dlObf');
  if (!cb) return;
  cb.addEventListener('change', function() {{
    document.querySelectorAll('.pii').forEach(function(el) {{
      el.textContent = cb.checked ? el.dataset.mask : el.dataset.real;
    }});
    if (dlBtn) dlBtn.style.display = cb.checked ? 'inline-block' : 'none';
  }});
  if (dlBtn) {{
    dlBtn.addEventListener('click', function(e) {{
      e.preventDefault();
      var clone = document.documentElement.cloneNode(true);
      clone.querySelectorAll('.pii').forEach(function(el) {{
        var mask = el.dataset.mask || el.textContent;
        el.textContent = mask;
        el.removeAttribute('data-real');
        el.setAttribute('data-mask', mask);
      }});
      clone.querySelectorAll('[data-tabs-ready]').forEach(function(el) {{
        el.removeAttribute('data-tabs-ready');
      }});
      var cbClone = clone.querySelector('#maskPII');
      if (cbClone) cbClone.checked = true;
      var dlClone = clone.querySelector('#dlObf');
      if (dlClone) dlClone.style.display = 'inline-block';
      var blob = new Blob(['<!DOCTYPE html>' + clone.outerHTML], {{type: 'text/html'}});
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      var base = (window.location.pathname.split('/').pop() || 'report.html').replace(/^OBFUSCATED_/i, '');
      a.download = 'OBFUSCATED_' + base;
      a.href = url;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }});
  }}
}})();
(function(){{
  document.querySelectorAll('.tab-nav:not([data-tabs-ready])').forEach(function(nav){{
    nav.setAttribute('data-tabs-ready','1');
    var scope = nav.parentElement;
    var btns  = nav.querySelectorAll('[data-tab]');
    function scrollToNav(smooth){{
      setTimeout(function(){{
        try {{
          nav.scrollIntoView({{ behavior: smooth ? 'smooth' : 'auto', block: 'start' }});
        }} catch(e) {{
          nav.scrollIntoView(true);
        }}
      }}, 30);
    }}
    function activate(id, doScroll){{
      var targetBtn = nav.querySelector('[data-tab="'+id+'"]');
      var targetPane = scope.querySelector('#'+id);
      if(!targetBtn || !targetPane) return false;
      btns.forEach(function(b){{ b.classList.toggle('active', b.dataset.tab===id); }});
      scope.querySelectorAll('.tab-pane').forEach(function(p){{ p.classList.toggle('active', p.id===id); }});
      if(history.replaceState) history.replaceState(null,'','#'+id);
      if(doScroll) scrollToNav(true);
      return true;
    }}
    window.activateTab = function(id, doScroll){{
      return activate(id, doScroll !== false);
    }};
    function activateByHash(h, doScroll){{
      if(!h) return false;
      if(activate(h, doScroll)) return true;
      var target = document.getElementById(h);
      if(target){{
        var pane = target.closest ? target.closest('.tab-pane') : null;
        if(pane && nav.querySelector('[data-tab="'+pane.id+'"]')){{
          activate(pane.id, false);
          if(doScroll){{
            setTimeout(function(){{
              try {{ target.scrollIntoView({{ behavior: 'smooth', block: 'start' }}); }}
              catch(e) {{ target.scrollIntoView(true); }}
            }}, 40);
          }}
          return true;
        }}
      }}
      return false;
    }}
    btns.forEach(function(b){{
      b.addEventListener('click',function(){{ activate(b.dataset.tab, true); }});
    }});
    scope.querySelectorAll('.tab-jump-link[data-jump-tab]').forEach(function(a){{
      a.addEventListener('click',function(e){{
        e.preventDefault();
        activate(this.dataset.jumpTab, true);
      }});
    }});
    document.addEventListener('click', function(e){{
      var a = e.target && e.target.closest ? e.target.closest('a[href*="#"]') : null;
      if(a){{
        var href = a.getAttribute('href') || '';
        var hashIdx = href.indexOf('#');
        if(hashIdx !== -1 && !href.startsWith('javascript:')){{
          var hashId = href.substring(hashIdx + 1).split(/[?#&]/)[0];
          if(hashId && activateByHash(hashId, true)){{
            e.preventDefault();
          }}
        }}
      }}
    }});
    window.addEventListener('hashchange', function(){{
      var h = (location.hash||'').replace('#','');
      if(h) activateByHash(h, true);
    }});
    var hash=(location.hash||'').replace('#','');
    var first=btns[0]?btns[0].dataset.tab:'';
    if(hash && activateByHash(hash, true)){{
      if(document.readyState !== 'complete'){{
        window.addEventListener('load', function(){{
          scrollToNav(false);
        }}, {{ once: true }});
      }}
    }} else {{
      activate(first, false);
    }}
  }});
  if (window.parent && window.parent !== window) {{
    try {{
      window.parent.postMessage({{ type: 'vcf-subreport-ready', host: document.title, url: window.location.href }}, '*');
    }} catch(e) {{}}
  }}
  window.addEventListener('message', function(ev) {{
    if (ev.data && ev.data.type === 'vcf_activate_tab' && ev.data.tab && window.activateTab) {{
      window.activateTab(ev.data.tab, true);
    }}
  }});
}})();
</script>
{THEME_TOGGLE_JS}
</body>
</html>"""

    html_safe = html_escape(html) if False else html.encode("utf-8", errors="surrogatepass").decode("utf-8", errors="replace")
    with open(output_filepath, "w", encoding="utf-8", errors="replace") as f:
        f.write(html_safe)
