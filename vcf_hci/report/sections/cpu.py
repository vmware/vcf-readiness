"""
VCF Readiness Tool — CPU architecture & compatibility report section builders (Layer D).
"""
import re
from typing import Any, Dict

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.compat_engine import VCF9CompatibilityEngine, _is_oem_chassis_certified
from vcf_hci.constants import BROADCOM_KB_428874_URL
from vcf_hci.report.helpers import _h

_KNOWN_VSPHERE_OEMS = {
    "DELL", "HPE", "HEWLETT", "LENOVO", "CISCO", "FUJITSU", "HUAWEI", "NEC", "SUPERMICRO",
    "QUANTA", "QCT", "GIGABYTE", "INTEL",
}


def render_cpu_combined_card(
    cpu_info: Dict[str, Any],
    sys_info: Dict[str, Any],
    cpu_verdict: str,
) -> str:
    """Render merged CPU summary card (verdict badge + condensed spec table)."""
    _vendor_str = str(sys_info.get("vendor") or "")
    _model_str = str(sys_info.get("model") or "")
    _vendor_upper = _vendor_str.upper()
    _oem_known = any(k in _vendor_upper for k in _KNOWN_VSPHERE_OEMS)
    _bcg_server_url = BCGLinkGenerator.server(_vendor_str, _model_str, cpu_info)
    _bcg_cpu_url = BCGLinkGenerator.cpu(cpu_info.get("model", ""), cpu_info.get("processor_id", ""))

    _is_dell_14g = "DELL" in _vendor_upper and bool(re.search(r"R[23456789]40|T[1346]40|C6420|MX[78]40C|XC[679]40", _model_str, re.I))
    _requires_vendor_confirm = _is_dell_14g or "Verify with OEM" in cpu_verdict or "Confirm with vendor" in cpu_verdict

    _is_certified_chassis = _is_oem_chassis_certified(_vendor_str, _model_str) or (_oem_known and bool(_model_str))
    if _is_certified_chassis:
        if _requires_vendor_confirm:
            _server_badge = '<span class="badge warning">🟡 Confirm with Vendor</span>'
        else:
            _server_badge = '<span class="badge success">🟢 Certified Server Chassis</span>'
    elif _vendor_str or _model_str:
        _server_badge = '<span class="badge warning">🟡 Unverified Server Chassis</span>'
    else:
        _server_badge = ''

    if "VCF 9.x Supported" in cpu_verdict:
        vsphere_9_badge = '<span class="badge success">🟢 VCF 9.x Supported</span>'
        if _requires_vendor_confirm:
            cpu_subtext = (
                f'Intel Cascade Lake-SP 2nd Gen — Supported for VCF 9.x / vSphere 9.x. '
                f'Broadcom Compatibility Guide lists this OEM chassis as <b>Confirm with vendor</b> — verify qualification details on '
                f'<a href="{_bcg_server_url}" target="_blank" class="btn-link">BCG ↗</a>.'
            )
        else:
            cpu_subtext = (
                f'Intel Cascade Lake-SP 2nd Gen — Fully certified on {_h(_vendor_str)} {_h(_model_str)} '
                f'for VCF 9.x / vSphere 9.x. '
                f'Verify details on <a href="{_bcg_server_url}" target="_blank" class="btn-link">BCG ↗</a>.'
            )
    elif ("Override Required" in cpu_verdict) or ("Deprecated Mode" in cpu_verdict and "9.1 Only" in cpu_verdict):
        vsphere_9_badge = '<span class="badge warning">🟡 Supported (Override Required)</span>'
        cpu_subtext = (
            f'Intel Skylake-SP — Supported for VCF 9.x per Broadcom KB 428874. '
            f'Installation or upgrade requires CPU support override. '
            f'Confirm server on <a href="{_bcg_server_url}" target="_blank" class="btn-link">BCG ↗</a> &nbsp;·&nbsp; '
            f'<a href="{BROADCOM_KB_428874_URL}" target="_blank" class="btn-link">KB 428874 ↗</a>'
        )
    elif "Deprecated Mode" in cpu_verdict:
        vsphere_9_badge = '<span class="badge success">🟢 VCF 9.x Supported</span>' if _requires_vendor_confirm else '<span class="badge warning">🟡 Deprecated Mode</span>'
        cpu_subtext = (
            f'CPU platform in deprecated mode for vSphere 9.x. Confirm OEM support and qualification on '
            f'<a href="{_bcg_server_url}" target="_blank" class="btn-link">BCG ↗</a> &nbsp;·&nbsp; '
            f'<a href="{BROADCOM_KB_428874_URL}" target="_blank" class="btn-link">KB 428874 ↗</a>'
        )
    elif "Unsupported" in cpu_verdict or "Not VCF-Eligible" in cpu_verdict:
        vsphere_9_badge = '<span class="badge danger">🔴 Not VCF-Eligible</span>'
        if "Not VCF-Eligible" in cpu_verdict:
            _cpu_arch_label = cpu_info.get("arch_label", "Consumer CPU")
            cpu_subtext = (
                f"{_cpu_arch_label}. "
                f"VCF 9.x requires Intel Xeon Scalable (Skylake-SP or newer) or AMD EPYC. "
                f"This system may still be useful as a homelab ESXi host."
            )
        else:
            cpu_subtext = (
                f"Legacy processor not supported in vSphere 9.x. "
                f"Refer to <a href='{BROADCOM_KB_428874_URL}' target='_blank' class='btn-link'>KB 428874 ↗</a>."
            )
    elif "Unverified" in cpu_verdict or "Unknown" in cpu_verdict:
        vsphere_9_badge = '<span class="badge warning">🟡 Unverified CPU</span>'
        _model_clean = re.sub(r'\(R\)|\(TM\)|@\s*[\d.]+\s*GHz?', '', cpu_info.get('model', 'Unknown CPU'), flags=re.I).strip()
        cpu_subtext = (
            f"Unverified CPU model ({_h(_model_clean)}). "
            f'Verify hardware compatibility on <a href="{_bcg_server_url}" target="_blank" class="btn-link">BCG ↗</a>.'
        )
    else:
        vsphere_9_badge = '<span class="badge success">🟢 Fully Compatible</span>'
        _model_clean = re.sub(r'\(R\)|\(TM\)|@\s*[\d.]+\s*GHz?', '', cpu_info.get('model', ''), flags=re.I).strip()
        cpu_subtext = (
            f"<a href='{BCGLinkGenerator.cpu(cpu_info.get('model', ''), cpu_info.get('processor_id', ''))}' "
            f"target='_blank' class='btn-link'>{_h(_model_clean)} — BCG ↗</a>"
        )

    _cpu_prof = VCF9CompatibilityEngine.get_cpu_deep_profile(
        cpu_info.get("model", ""),
        cpu_info.get("architecture", ""),
        cpu_info.get("max_pcie_lanes_per_socket", 64),
        cpu_info.get("cores_per_socket", 0),
    )

    _model_disp = re.sub(r'\(R\)|\(TM\)|@\s*[\d.]+\s*GHz?', '', cpu_info.get('model', 'Unknown'), flags=re.I).strip()
    _cpu_spec_rows = []
    if _vendor_str or _model_str:
        _server_disp = f"{_h(_vendor_str)} {_h(_model_str)}".strip()
        _cpu_spec_rows.append(("Server Chassis", f"<a href='{_bcg_server_url}' target='_blank' class='btn-link'>{_server_disp} ↗</a>"))
    if cpu_info.get("count", 1) > 1:
        _cpu_spec_rows.append(("Sockets", str(cpu_info.get("count", 1))))
    if cpu_info.get("cores_per_socket"):
        _cpu_spec_rows.append(("Cores / socket", str(cpu_info["cores_per_socket"])))
    if cpu_info.get("threads_per_socket"):
        _cpu_spec_rows.append(("Threads / socket", str(cpu_info["threads_per_socket"])))
    if cpu_info.get("base_freq_ghz"):
        _freq_line = f"{cpu_info['base_freq_ghz']} GHz"
        if cpu_info.get("max_freq_ghz") and cpu_info["max_freq_ghz"] != cpu_info["base_freq_ghz"]:
            _freq_line += f" base · {cpu_info['max_freq_ghz']} GHz turbo"
        _cpu_spec_rows.append(("Frequency", _freq_line))
    if cpu_info.get("architecture"):
        _arch_short = re.sub(
            r'\s+\d(?:st|nd|rd|th)\s+Gen(?:\s+Xeon\s+Scalable)?|\s+Series|\s+\([^)]+\)',
            '', cpu_info["architecture"]
        ).strip()
        _arch_short = re.sub(r'^(?:Intel|AMD)\s+', '', _arch_short, flags=re.I).strip()
        _cpu_spec_rows.append(("Architecture", _h(_arch_short)))

    _nt_card = _cpu_prof.get("numa_topology", {})
    if _nt_card.get("numa_nodes_default"):
        _nnd_c = _nt_card["numa_nodes_default"]
        if _cpu_prof.get("is_amd"):
            _nns_c = f"NPS-{_nnd_c}" if _nnd_c > 1 else str(_nnd_c)
        elif _nnd_c > 1:
            _nns_c = f"SNC-{_nnd_c} active"
        else:
            _nns_c = str(_nnd_c)
        _cpu_spec_rows.append(("NUMA nodes / socket", _nns_c))

    _cpu_spec_tbl = "".join(
        f"<tr><td style='color:var(--text-muted);padding:.15rem .3rem .15rem 0;white-space:nowrap'>{k}</td>"
        f"<td style='font-weight:600;padding:.15rem 0'>{v}</td></tr>"
        for k, v in _cpu_spec_rows
    )

    _cpu_tab_link = (
        "<a href='#tab-cpu' data-jump-tab='tab-cpu' class='btn-link tab-jump-link' style='font-size:.78rem'>"
        "Full details in CPU tab &#8599;</a>"
    )
    _badges_html = f"<div style='margin-bottom:.4rem;display:flex;gap:.4rem;flex-wrap:wrap'>{vsphere_9_badge}{(' ' + _server_badge) if _server_badge else ''}</div>"

    return (
        f"<div class='card'>"
        f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
        f"<h3 style='margin:0'>CPU and Server &mdash; vSphere 9.1</h3>"
        f"<a href='#tab-cpu' data-jump-tab='tab-cpu' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to CPU section'>Details &rarr;</a>"
        f"</div>"
        f"{_badges_html}"
        f"<div style='font-size:.83rem;font-weight:700;margin-bottom:.3rem'>"
        f"<a href='{_bcg_cpu_url}' target='_blank' class='btn-link' style='color:var(--primary)'>{_h(_model_disp)} ↗</a>"
        f"</div>"
        f"<table style='font-size:.8rem;width:100%;border-collapse:collapse'><tbody>{_cpu_spec_tbl}</tbody></table>"
        f"<p style='font-size:.8rem;color:var(--text-muted);margin-top:.4rem'>{cpu_subtext}</p>"
        f"<div style='margin-top:.5rem;border-top:1px solid var(--border);padding-top:.4rem'>{_cpu_tab_link}</div>"
        f"</div>"
    )


def render_cpu_deep_section(
    cpu_info: Dict[str, Any],
    sys_info: Dict[str, Any],
    bios_info: Dict[str, Any],
    cpu_verdict: str,
) -> str:
    """Render full CPU Architecture tab section."""
    _vendor_str = str(sys_info.get("vendor") or "")
    _model_str = str(sys_info.get("model") or "")
    _vendor_upper = _vendor_str.upper()
    _oem_known = any(k in _vendor_upper for k in _KNOWN_VSPHERE_OEMS)
    _bcg_server_url = BCGLinkGenerator.server(_vendor_str, _model_str, cpu_info)
    _bcg_cpu_url = BCGLinkGenerator.cpu(cpu_info.get("model", ""), cpu_info.get("processor_id", ""))

    _is_dell_14g = "DELL" in _vendor_upper and bool(re.search(r"R[23456789]40|T[1346]40|C6420|MX[78]40C|XC[679]40", _model_str, re.I))
    _requires_vendor_confirm = _is_dell_14g or "Verify with OEM" in cpu_verdict or "Confirm with vendor" in cpu_verdict

    if "VCF 9.x Supported" in cpu_verdict:
        vsphere_9_badge = '<span class="badge success">🟢 VCF 9.x Supported</span>'
    elif ("Override Required" in cpu_verdict) or ("Deprecated Mode" in cpu_verdict and "9.1 Only" in cpu_verdict):
        vsphere_9_badge = '<span class="badge warning">🟡 Supported (Override Required)</span>'
    elif "Deprecated Mode" in cpu_verdict:
        vsphere_9_badge = '<span class="badge success">🟢 VCF 9.x Supported</span>' if _requires_vendor_confirm else '<span class="badge warning">🟡 Deprecated Mode</span>'
    elif "Unsupported" in cpu_verdict or "Not VCF-Eligible" in cpu_verdict:
        vsphere_9_badge = '<span class="badge danger">🔴 Not VCF-Eligible</span>'
    elif "Unverified" in cpu_verdict or "Unknown" in cpu_verdict:
        vsphere_9_badge = '<span class="badge warning">🟡 Unverified CPU</span>'
    else:
        vsphere_9_badge = '<span class="badge success">🟢 Fully Compatible</span>'

    _cpu_prof = VCF9CompatibilityEngine.get_cpu_deep_profile(
        cpu_info.get("model", ""),
        cpu_info.get("architecture", ""),
        cpu_info.get("max_pcie_lanes_per_socket", 64),
        cpu_info.get("cores_per_socket", 0),
    )

    _deep_model_disp = re.sub(r'\(R\)|\(TM\)|@\s*[\d.]+\s*GHz?', '', cpu_info.get('model', 'Unknown'), flags=re.I).strip()

    _pcie_gen_badge = (
        f"<span class='badge success'>{_cpu_prof['pcie_gen']} · "
        f"{cpu_info.get('max_pcie_lanes_per_socket', '?')} lanes/socket</span>"
    )

    _evc_bl = _cpu_prof.get("evc_baseline", "")
    _evc_badge_deep = (
        f"<span class='badge info' style='font-size:.78rem'>📐 EVC: {_h(_evc_bl)}</span>"
        if _evc_bl and _evc_bl != "Unknown" else ""
    )

    _dd_spec_parts = []
    if cpu_info.get("count", 1) > 1:
        _dd_spec_parts.append(f"{cpu_info['count']}\u00d7 sockets")
    if cpu_info.get("cores_per_socket"):
        _dd_spec_parts.append(f"{cpu_info['cores_per_socket']} cores/socket")
    if cpu_info.get("base_freq_ghz"):
        _f = f"{cpu_info['base_freq_ghz']} GHz"
        if cpu_info.get("max_freq_ghz") and cpu_info["max_freq_ghz"] != cpu_info["base_freq_ghz"]:
            _f += f" \u2191{cpu_info['max_freq_ghz']} GHz turbo"
        _dd_spec_parts.append(_f)
    _chan = cpu_info.get("channels_per_socket")
    _ddr  = "DDR5" if cpu_info.get("max_ram_speed_mhz", 0) >= 4000 else "DDR4"
    if _chan:
        _dd_spec_parts.append(f"{_chan}-ch {_ddr}")
    _dd_spec_line = " \u00b7 ".join(_dd_spec_parts)

    _cache_rows = ""
    _raw_cache = cpu_info.get("cache_list", [])
    if _raw_cache:
        for _ci in _raw_cache:
            _lvl  = _h(str(_ci.get("level", "")).strip()) or "—"
            _smib = _ci.get("size_mib", 0)
            if isinstance(_smib, (int, float)) and _smib > 0:
                _smib_str = f"{_smib * 1024:.0f} KB" if _smib < 1 else f"{_smib} MiB"
            else:
                _smib_str = "—"
            _assoc = _h(str(_ci.get("associativity", "")).strip())
            _cache_rows += (
                f"<tr><td style='padding:.2rem .4rem;white-space:nowrap'>{_lvl}</td>"
                f"<td style='padding:.2rem .4rem;font-weight:600'>{_smib_str}</td>"
                f"<td style='padding:.2rem .4rem;color:var(--text-muted);font-size:.8rem'>{_assoc}</td></tr>"
            )
        _cache_source_note = "<span style='font-size:.72rem;color:var(--text-muted);font-style:italic'>Source: Redfish Processors API</span>"
    else:
        _fb_l3 = _cpu_prof.get("typical_l3_mb", "")
        if _fb_l3:
            _cache_rows = (
                f"<tr><td style='padding:.2rem .4rem'>L3 Cache</td>"
                f"<td style='padding:.2rem .4rem;font-weight:600'>{_h(_fb_l3)}</td>"
                f"<td style='padding:.2rem .4rem;color:var(--text-muted);font-size:.8rem'></td></tr>"
            )
            _cache_source_note = "<span style='font-size:.72rem;color:var(--text-muted);font-style:italic'>L3 estimate from CPU family — Redfish Cache endpoint not populated on this BMC</span>"
        else:
            _cache_rows = (
                "<tr><td colspan='3' style='padding:.3rem .4rem;color:var(--text-muted);font-style:italic;font-size:.82rem'>"
                "Not available — Redfish Processors/Cache not populated on this BMC</td></tr>"
            )
            _cache_source_note = ""

    _cache_table = (
        f"<table style='font-size:.82rem;width:100%;border-collapse:collapse;'>"
        f"<thead><tr>"
        f"<th style='text-align:left;padding:.2rem .4rem;border-bottom:1px solid var(--border);font-size:.78rem;color:var(--text-muted)'>Level</th>"
        f"<th style='text-align:left;padding:.2rem .4rem;border-bottom:1px solid var(--border);font-size:.78rem;color:var(--text-muted)'>Size</th>"
        f"<th style='text-align:left;padding:.2rem .4rem;border-bottom:1px solid var(--border);font-size:.78rem;color:var(--text-muted)'>Associativity</th>"
        f"</tr></thead><tbody>{_cache_rows}</tbody></table>"
        f"<div style='margin-top:.25rem'>{_cache_source_note}</div>"
    )

    _dd_spec_rows = []
    if cpu_info.get("architecture"):
        _dd_spec_rows.append(("Architecture", _h(cpu_info["architecture"])))
    if cpu_info.get("count", 1) > 1:
        _dd_spec_rows.append(("Sockets", str(cpu_info["count"])))
    if cpu_info.get("cores_per_socket"):
        _dd_spec_rows.append(("Cores / socket", str(cpu_info["cores_per_socket"])))
    if cpu_info.get("threads_per_socket"):
        _dd_spec_rows.append(("Threads / socket", str(cpu_info["threads_per_socket"])))
    if cpu_info.get("ht_enabled") is not None:
        _dd_spec_rows.append(("Hyper-Threading", "✅ Enabled" if cpu_info["ht_enabled"] else "❌ Disabled"))
    if cpu_info.get("base_freq_ghz"):
        _fline = f"{cpu_info['base_freq_ghz']} GHz base"
        if cpu_info.get("max_freq_ghz") and cpu_info["max_freq_ghz"] != cpu_info["base_freq_ghz"]:
            _fline += f" · {cpu_info['max_freq_ghz']} GHz turbo"
        _dd_spec_rows.append(("Frequency", _fline))
    if cpu_info.get("channels_per_socket"):
        _dd_spec_rows.append(("Memory Channels", f"{cpu_info['channels_per_socket']} / socket ({_ddr})"))
    if cpu_info.get("max_ram_speed_mhz"):
        _dd_spec_rows.append(("Max RAM Speed", f"{cpu_info['max_ram_speed_mhz']} MHz"))
    if cpu_info.get("max_pcie_lanes_per_socket"):
        _dd_spec_rows.append(("PCIe Lanes", f"{cpu_info['max_pcie_lanes_per_socket']} / socket ({_cpu_prof['pcie_gen']})"))
    if cpu_info.get("socket_label"):
        _dd_spec_rows.append(("Socket ID", _h(str(cpu_info["socket_label"]))))
    if cpu_info.get("stepping"):
        _dd_spec_rows.append(("Stepping", _h(str(cpu_info["stepping"]))))
    if cpu_info.get("processor_id"):
        _dd_spec_rows.append(("Processor ID", f"<span style='font-family:monospace;font-size:.78rem'>{_h(str(cpu_info['processor_id']))}</span>"))

    _nt_acc = _cpu_prof.get("numa_topology", {})
    if _nt_acc.get("numa_nodes_default"):
        _nnd_a = _nt_acc["numa_nodes_default"]
        _nnm_a = _nt_acc.get("numa_nodes_max", _nnd_a)
        if _cpu_prof.get("is_amd"):
            _nns_a = f"{_nnd_a} (NPS-{_nnd_a} default &middot; NPS-{_nnm_a} optional via BIOS)"
        elif _nnm_a > 1:
            _nns_a = f"{_nnd_a} (SNC disabled default &middot; up to SNC-{_nnm_a} via BIOS)"
        else:
            _nns_a = str(_nnd_a)
        _dd_spec_rows.append(("NUMA nodes / socket", _nns_a))

    _mst = cpu_info.get("multi_socket_telemetry") or (bios_info or {}).get("multi_socket_telemetry") or {}
    if _mst:
        if _mst.get("snc_mode"):
            _dd_spec_rows.append(("Sub-NUMA Clustering (SNC)", _h(_mst["snc_mode"])))
        if _mst.get("uma_clustering"):
            _dd_spec_rows.append(("UMA Clustering Status", _h(_mst["uma_clustering"])))
        if _mst.get("node_interleave"):
            _ni_val = _mst["node_interleave"]
            _ni_warn = _mst.get("node_interleave_warning")
            _ni_badge = f"<span class='badge warning'>⚠️ {_h(_ni_val)} (NUMA Flattened)</span>" if _ni_warn else f"<span class='badge success'>🟢 {_h(_ni_val)} (NUMA Active)</span>"
            _dd_spec_rows.append(("Node Interleaving", _ni_badge))
        if _mst.get("proc_x2apic"):
            _x2_val = _mst["proc_x2apic"]
            _x2_warn = _mst.get("proc_x2apic_warning")
            _x2_badge = f"<span class='badge warning'>⚠️ {_h(_x2_val)}</span>" if _x2_warn else f"<span class='badge success'>🟢 {_h(_x2_val)}</span>"
            _dd_spec_rows.append(("Processor x2APIC", _x2_badge))
        if _mst.get("upi_prefetch"):
            _dd_spec_rows.append(("UPI Prefetch", _h(_mst["upi_prefetch"])))
        if _mst.get("upi_link_power"):
            _dd_spec_rows.append(("UPI Link Power Mgmt", _h(_mst["upi_link_power"])))
        if _mst.get("acpi_slit"):
            _dd_spec_rows.append(("ACPI SLIT (NUMA Distance)", _h(_mst["acpi_slit"])))
        if _mst.get("acpi_root_bridge_pxm"):
            _dd_spec_rows.append(("Root Bridge PXM (PCIe NUMA)", _h(_mst["acpi_root_bridge_pxm"])))
        if _mst.get("numa_group_size_opt"):
            _dd_spec_rows.append(("NUMA Group Size Opt", _h(_mst["numa_group_size_opt"])))

    _dd_spec_tbl = "".join(
        f"<tr><td style='color:var(--text-muted);padding:.18rem .35rem .18rem 0;white-space:nowrap;font-size:.82rem'>{k}</td>"
        f"<td style='font-weight:600;padding:.18rem 0;font-size:.82rem'>{v}</td></tr>"
        for k, v in _dd_spec_rows
    )
    _dd_full_spec_table = f"<table style='width:100%;border-collapse:collapse'><tbody>{_dd_spec_tbl}</tbody></table>"

    # CPU topology diagram
    _topo_diagram_html = ""
    _topo = _cpu_prof.get("numa_topology", {})
    if _topo and _topo.get("chiplets_count"):
        _tp_chiplets  = _topo["chiplets_count"]
        _tp_def_nodes = _topo.get("numa_nodes_default", 1)
        _tp_max_nodes = _topo.get("numa_nodes_max", _tp_def_nodes)
        _tp_has_io    = _topo.get("has_io_die", False)
        _tp_io_count  = _topo.get("io_dies_count", 1 if _tp_has_io else 0)
        _tp_die_lbl   = _topo.get("die_label", "Die")
        _tp_cpc       = _topo.get("cores_per_chiplet", 8)
        _tp_c_list    = _topo.get("cores_per_tile", [_tp_cpc] * _tp_chiplets)
        _tp_die_cfg   = _topo.get("die_config_name", "")
        _tp_pkg_sock  = _topo.get("package_socket", "")
        _tp_num_socks = cpu_info.get("count", 1) or 1
        _tp_cps       = cpu_info.get("cores_per_socket")
        _tp_is_mono   = (_tp_chiplets == 1 and not _tp_has_io and not _tp_die_cfg)

        _tp_active_nodes = _tp_def_nodes
        _bios_perf = bios_info.get("performance_settings", []) if bios_info else []
        for _bset in _bios_perf:
            _bkey = str(_bset.get("key", "")).lower()
            _bval = str(_bset.get("value", "")).lower()
            if "snc" in _bkey or "subnuma" in _bkey:
                if "snc4" in _bval or _bval == "4":
                    _tp_active_nodes = 4
                elif "snc2" in _bval or _bval in ("2", "enabled"):
                    _tp_active_nodes = 2
                elif _bval in ("disabled", "0"):
                    _tp_active_nodes = 1
                break
            elif "nps" in _bkey or "numanodes" in _bkey:
                if "nps4" in _bval or _bval == "4":
                    _tp_active_nodes = 4
                elif "nps2" in _bval or _bval == "2":
                    _tp_active_nodes = 2
                elif _bval in ("disabled", "0", "1"):
                    _tp_active_nodes = 1
                break

        _tp_cpn = max(1, (_tp_chiplets + _tp_active_nodes - 1) // _tp_active_nodes)
        _TP_DISP_MAX = 16
        _TP_COLS = 4

        def _tp_dots(n_cores: int) -> str:
            shown = min(n_cores, _TP_DISP_MAX)
            rows  = (shown + _TP_COLS - 1) // _TP_COLS
            pad   = rows * _TP_COLS - shown
            dots  = (
                f"<div style='display:grid;grid-template-columns:repeat({_TP_COLS},6px);gap:1px'>"
                + "".join("<div style='width:6px;height:6px;background:var(--primary, #3b82f6);border-radius:1px'></div>" for _ in range(shown))
                + "".join("<div style='width:6px;height:6px'></div>" for _ in range(pad))
                + "</div>"
            )
            label = f"<div style='font-size:.55rem;color:var(--text-muted, #64748b);text-align:center;line-height:1.2;font-weight:600;margin-top:2px'>{n_cores} cores</div>"
            return dots + label

        def _tp_chiplet_box(idx: int) -> str:
            n_cores_tile = _tp_c_list[idx] if idx < len(_tp_c_list) else _tp_cpc
            return (
                f"<div style='border:1px solid var(--numa-chip-border, #93c5fd);border-radius:4px;padding:4px;"
                f"background:var(--numa-chip-bg, #eff6ff);text-align:center;min-width:48px'>"
                f"<div style='font-size:.5rem;color:var(--numa-chip-title, #1e40af);font-weight:700;"
                f"margin-bottom:2px;white-space:nowrap'>{_tp_die_lbl}&nbsp;{idx}</div>"
                f"{_tp_dots(n_cores_tile)}"
                f"</div>"
            )

        def _tp_numa_box(numa_idx: int, chiplet_indices: list) -> str:
            chips_html = "".join(_tp_chiplet_box(ci) for ci in chiplet_indices)
            return (
                f"<div style='border:1.5px dashed var(--numa-box-border, #8b5cf6);border-radius:5px;"
                f"padding:5px;margin-bottom:4px;background:var(--numa-box-bg, rgba(139,92,246,.04))'>"
                f"<div style='font-size:.6rem;color:var(--numa-box-title, #7c3aed);font-weight:700;"
                f"margin-bottom:3px'>NUMA&nbsp;{numa_idx}</div>"
                f"<div style='display:flex;flex-wrap:wrap;gap:3px;align-items:stretch'>{chips_html}</div>"
                f"</div>"
            )

        def _tp_io_die(lbl: str = "") -> str:
            lbl_str = f"I/O {lbl}".strip() if lbl else "I/O"
            return (
                f"<div style='border:1px solid var(--nps-warn-border, var(--warning, #fbbf24));border-radius:4px;padding:4px 5px;"
                f"background:var(--nps-warn-bg, #fffbeb);display:flex;align-items:center;justify-content:center;"
                f"min-height:56px;writing-mode:vertical-rl;text-orientation:mixed'>"
                f"<div style='font-size:.58rem;color:var(--nps-warn-color, #b45309);font-weight:700;"
                f"letter-spacing:.05em'>{lbl_str}</div>"
                f"</div>"
            ) if _tp_has_io else ""

        def _tp_socket(sock_idx: int) -> str:
            numa_base = sock_idx * _tp_active_nodes
            if _tp_is_mono:
                n_cores_mono = _tp_c_list[0] if _tp_c_list else (_tp_cps or _tp_cpc)
                nodes_html = (
                    f"<div style='border:1.5px dashed var(--numa-box-border, #8b5cf6);border-radius:5px;"
                    f"padding:5px;background:var(--numa-box-bg, rgba(139,92,246,.04))'>"
                    f"<div style='font-size:.6rem;color:var(--numa-box-title, #7c3aed);font-weight:700;"
                    f"margin-bottom:3px'>NUMA&nbsp;{numa_base}</div>"
                    f"<div style='border:1px solid var(--numa-chip-border, #93c5fd);border-radius:4px;"
                    f"padding:6px;background:var(--numa-chip-bg, #eff6ff);text-align:center'>"
                    f"<div style='font-size:.5rem;color:var(--numa-chip-title, #1e40af);font-weight:700;"
                    f"margin-bottom:3px'>Monolithic Die</div>"
                    f"{_tp_dots(n_cores_mono)}</div></div>"
                )
            else:
                nodes_html = ""
                for _n in range(_tp_active_nodes):
                    _c_start = _n * _tp_cpn
                    _c_end   = _c_start + _tp_cpn
                    _cidxs   = list(range(_c_start, min(_c_end, _tp_chiplets)))
                    if _cidxs:
                        nodes_html += _tp_numa_box(numa_base + _n, _cidxs)

            if _tp_io_count == 2:
                socket_inner = f"{_tp_io_die('0')}<div style='flex:1'>{nodes_html}</div>{_tp_io_die('1')}"
            elif _tp_io_count == 1:
                socket_inner = f"<div style='flex:1'>{nodes_html}</div>{_tp_io_die()}"
            else:
                socket_inner = f"<div style='flex:1'>{nodes_html}</div>"

            return (
                f"<div style='border:2px solid var(--numa-sock-border, #6366f1);border-radius:8px;padding:8px;"
                f"background:var(--numa-sock-bg, #faf5ff);display:inline-flex;flex-direction:column;"
                f"min-width:130px;vertical-align:top'>"
                f"<div style='font-size:.72rem;font-weight:700;color:var(--numa-sock-title, #4f46e5);"
                f"margin-bottom:5px'>Socket&nbsp;{sock_idx}</div>"
                f"<div style='display:flex;gap:4px;align-items:center'>"
                f"{socket_inner}"
                f"</div></div>"
            )

        _tp_sockets_html = "".join(_tp_socket(i) for i in range(_tp_num_socks))

        _tp_io_legend = (
            f"<span><span style='display:inline-block;width:9px;height:9px;"
            f"background:var(--warning, #fbbf24);border-radius:1px;vertical-align:middle;"
            f"margin-right:2px'></span>I/O Die{'s' if _tp_io_count > 1 else ''} ({_tp_io_count})</span>"
        ) if _tp_has_io else ""
        _tp_legend = (
            f"<div style='display:flex;flex-wrap:wrap;gap:10px;font-size:.67rem;"
            f"color:var(--text-muted, #64748b);margin-bottom:7px;align-items:center'>"
            f"<span><span style='display:inline-block;width:9px;height:9px;"
            f"background:var(--primary, #3b82f6);border-radius:1px;vertical-align:middle;"
            f"margin-right:2px'></span>Core</span>"
            f"{_tp_io_legend}"
            f"<span style='display:inline-flex;align-items:center;gap:3px'>"
            f"<span style='display:inline-block;width:18px;height:0;"
            f"border-top:1.5px dashed var(--numa-box-border, #8b5cf6)'></span>NUMA boundary</span>"
            f"</div>"
        )

        _tp_actual_note = ""
        if _tp_cps and not _tp_die_cfg:
            _tp_max_cores = sum(_tp_c_list)
            if _tp_cps != _tp_max_cores:
                _tp_actual_note = (
                    f"<div style='font-size:.65rem;color:var(--text-muted, #94a3b8);font-style:italic;"
                    f"margin-top:6px'>Diagram shows {_tp_die_lbl} topology for this "
                    f"CPU family ({sum(_tp_c_list)}\u00a0cores across {_tp_chiplets}"
                    f"\u00a0{_tp_die_lbl}s). "
                    f"Actual installed: {_tp_cps}\u00a0cores/socket.</div>"
                )

        _tp_badge = ""
        if _tp_die_cfg:
            _tp_badge = (
                f"<span class='badge info' style='font-size:.65rem;font-weight:600'>"
                f"{_tp_die_cfg} &middot; {_tp_chiplets} Compute Tile{'s' if _tp_chiplets > 1 else ''} &middot; "
                f"{_tp_io_count} I/O Die{'s' if _tp_io_count > 1 else ''}"
                f"{f' &middot; {_tp_pkg_sock}' if _tp_pkg_sock else ''}"
                f"</span>"
            )

        if _tp_active_nodes > 1:
            _tp_nps_label = (
                f"<span style='font-size:.65rem;color:var(--numa-box-title, #7c3aed);font-weight:600'>"
                f"{_tp_active_nodes}\u00a0NUMA nodes/socket "
                f"({'SNC-%d active' % _tp_active_nodes if _cpu_prof.get('is_intel') else 'NPS-%d active' % _tp_active_nodes})"
                f"</span>"
            )
        else:
            _tp_nps_label = (
                f"<span style='font-size:.65rem;color:var(--numa-box-title, #7c3aed);font-weight:600'>"
                f"1\u00a0NUMA node/socket "
                f"({'SNC disabled default' if _cpu_prof.get('is_intel') and _tp_max_nodes > 1 else 'NPS-1 default' if _cpu_prof.get('is_amd') else 'Default'})"
                f"</span>"
            )

        _topo_diagram_html = (
            f"<div style='background:var(--code-bg, #f1f5f9);border:1px solid var(--border, #e2e8f0);border-radius:8px;"
            f"padding:10px 12px;overflow-x:auto;margin-bottom:.75rem'>"
            f"<div style='display:flex;justify-content:space-between;align-items:center;"
            f"flex-wrap:wrap;gap:6px;margin-bottom:6px'>"
            f"<div style='display:flex;align-items:center;gap:8px;flex-wrap:wrap'>"
            f"<div style='font-size:.73rem;font-weight:700;color:var(--text, #374151)'>CPU Topology</div>"
            f"{_tp_badge}"
            f"</div>"
            f"{_tp_nps_label}"
            f"</div>"
            f"{_tp_legend}"
            f"<div style='display:flex;flex-wrap:wrap;gap:10px'>{_tp_sockets_html}</div>"
            f"{_tp_actual_note}"
            f"</div>"
        )

    _numa_cfg  = _cpu_prof.get("numa_config", "")
    _chiplet_d = _cpu_prof.get("chiplet_desc", "")
    if _numa_cfg or _chiplet_d:
        _numa_block = (
            f'<div style="background:var(--callout-blue-bg,#f0f9ff);border:1px solid var(--callout-blue-border,#bae6fd);border-left:4px solid var(--primary,#0ea5e9);'
            f'padding:.6rem .8rem;border-radius:6px;font-size:.82rem;">'
            f'<div style="font-weight:700;color:var(--callout-blue-title,#0369a1);margin-bottom:.2rem">{_h(_numa_cfg)}</div>'
            f'<div style="color:var(--callout-blue-body,#0c4a6e);line-height:1.5">{_h(_chiplet_d)}</div>'
            f'</div>'
        )
    else:
        _numa_block = (
            '<div style="font-size:.82rem;color:var(--text-muted);font-style:italic">'
            'NUMA/chiplet data not available for this CPU family.</div>'
        )

    # AMD EPYC & High-Core NUMA Optimization Card
    _amd_numa_card = ""
    _is_epyc = bool(_cpu_prof.get("is_amd")) or "EPYC" in str(cpu_info.get("model", "")).upper()
    _cpu_pwr_modes = bios_info.get("cpu_power", []) if bios_info else []
    _nps_check = next((c for c in _cpu_pwr_modes if "numanodes" in str(c.get("raw_key", "")).lower()), None)
    _xgmi_check = next((c for c in _cpu_pwr_modes if "xgmi" in str(c.get("raw_key", "")).lower()), None)
    _avx_check = next((c for c in _cpu_pwr_modes if "avx512" in str(c.get("raw_key", "")).lower()), None)

    if _is_epyc or _nps_check or _xgmi_check:
        _nps_val = str((_nps_check or {}).get("raw_val") or "").upper()
        if "NPS4" in _nps_val or _nps_val == "4":
            _nps_badge = "<span class='badge success' style='font-size:.76rem'>🟢 NPS4 (Optimal Latency)</span>"
            _nps_advice = "NPS4 partitions each socket into 4 CCX-aligned NUMA domains. Recommended for vSAN ESA, SQL/HANA, and latency-sensitive workloads."
        elif "NPS1" in _nps_val or _nps_val == "1":
            _nps_badge = "<span class='badge info' style='font-size:.76rem'>ℹ️ NPS1 (Single NUMA Node — Optimal for Wide VMs)</span>"
            _nps_advice = "NPS1 presents each socket as a single unified NUMA domain. Optimal for wide VMs spanning the whole socket, but may increase cross-CCX memory latency under high I/O."
        elif "NPS2" in _nps_val or _nps_val == "2":
            _nps_badge = "<span class='badge info' style='font-size:.76rem'>ℹ️ NPS2 (2 NUMA Nodes / Socket)</span>"
            _nps_advice = "NPS2 partitions each socket into 2 quadrant NUMA domains, balancing inter-core latency with local memory pools."
        else:
            _nps_badge = "<span class='badge info' style='font-size:.76rem'>ℹ️ NPS Configurable</span>"
            _nps_advice = "AMD EPYC processors support configurable NUMA nodes per socket (NPS1, NPS2, NPS4) to align memory controllers with CCX clusters."

        _xgmi_badge = ""
        if _xgmi_check:
            _xgmi_lbl = _xgmi_check.get("label", "32 GT/s")
            _xgmi_badge = f"<span class='badge success' style='font-size:.74rem'>🚀 Infinity Fabric: {_h(_xgmi_lbl)}</span> "

        _avx_badge = ""
        if _avx_check:
            _avx_lbl = _avx_check.get("label", "AVX-512")
            _avx_badge = f"<span class='badge success' style='font-size:.74rem'>⚡ {_h(_avx_lbl)}</span> "

        _amd_numa_card = (
            f'<div style="margin-top:.6rem;background:var(--callout-ok-bg,#f0fdf4);border:1px solid var(--callout-ok-border,#bbf7d0);'
            f'border-left:4px solid var(--success,#16a34a);padding:.6rem .8rem;border-radius:6px;font-size:.82rem;">'
            f'<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.4rem;margin-bottom:.3rem">'
            f'<div style="font-weight:700;color:var(--callout-ok-h,#166534)">⚡ AMD EPYC &amp; High-Core NUMA Optimization</div>'
            f'<div>{_xgmi_badge}{_avx_badge}{_nps_badge}</div>'
            f'</div>'
            f'<div style="color:var(--callout-ok-ul,#15803d);line-height:1.4">{_nps_advice}</div>'
            f'</div>'
        )

    _nps_note = ""
    _bios_perf = bios_info.get("performance_settings", []) if bios_info else []
    for _bset in _bios_perf:
        _bkey = _bset.get("key", "").lower()
        _bval = _bset.get("value", "").lower()
        if "nps" in _bkey or "numanodes" in _bkey:
            if not _amd_numa_card and _bval not in ("nps1", "1", "disabled", ""):
                _nps_note = (
                    f'<div style="margin-top:.4rem;font-size:.78rem;color:var(--nps-warn-color,#92400e);background:var(--nps-warn-bg,#fef3c7);'
                    f'border:1px solid var(--nps-warn-border,#fde68a);border-radius:4px;padding:.25rem .5rem;">'
                    f'⚠️ BIOS NPS setting detected: <b>{_h(_bset.get("display_value", _bval))}</b> — '
                    f'NPS-1 recommended for vSphere per VMware Best Practices §AMD EPYC NUMA.</div>'
                )
            break
        if "subnuma" in _bkey or "snc" in _bkey:
            if _bval not in ("disabled", "0", ""):
                _nps_note = (
                    f'<div style="margin-top:.4rem;font-size:.78rem;color:var(--nps-info-color,#1e40af);background:var(--nps-info-bg,#dbeafe);'
                    f'border:1px solid var(--nps-info-border,#bfdbfe);border-radius:4px;padding:.25rem .5rem;">'
                    f'ℹ️ BIOS SNC setting detected: <b>{_h(_bset.get("display_value", _bval))}</b> — '
                    f'disabled recommended for general vSAN ESA workloads.</div>'
                )
            break

    if _evc_bl and _evc_bl != "Unknown":
        _evc_block = (
            f'<span class="badge info" style="font-size:.82rem;margin-bottom:.4rem;display:inline-block">📐 {_h(_evc_bl)}</span>'
            f'<p style="font-size:.8rem;color:var(--text-muted);margin:.2rem 0 0 0;line-height:1.4">'
            f'Set this as the cluster EVC mode in vCenter when building a homogeneous cluster with this CPU generation. '
            f'Mixed-generation clusters require the lowest common baseline.</p>'
        )
    else:
        _evc_block = '<p style="font-size:.82rem;color:var(--text-muted);font-style:italic">EVC baseline not determined for this CPU family.</p>'

    _ext_links = [
        (f'<a href="{_bcg_cpu_url}" target="_blank" class="btn-link" '
         f'style="display:inline-block;padding:.35rem .7rem;background:var(--lbtn-blue-bg,#eff6ff);border:1px solid var(--lbtn-blue-border,#bfdbfe);'
         f'border-radius:6px;font-size:.82rem;font-weight:600;color:var(--lbtn-blue-text,#1d4ed8);text-decoration:none">'
         f'BCG CPU Compatibility ↗</a>'),
        (f'<a href="{_bcg_server_url}" target="_blank" class="btn-link" '
         f'style="display:inline-block;padding:.35rem .7rem;background:var(--lbtn-green-bg,#f0fdf4);border:1px solid var(--lbtn-green-border,#bbf7d0);'
         f'border-radius:6px;font-size:.82rem;font-weight:600;color:var(--lbtn-green-text,#15803d);text-decoration:none">'
         f'BCG Server HCL ↗</a>'),
    ]
    if _cpu_prof.get("is_intel"):
        _ark_url = BCGLinkGenerator.intel_ark(cpu_info.get("model", ""))
        _ext_links.append(
            f'<a href="{_ark_url}" target="_blank" class="btn-link" '
            f'style="display:inline-block;padding:.35rem .7rem;background:var(--lbtn-orange-bg,#fff7ed);border:1px solid var(--lbtn-orange-border,#fed7aa);'
            f'border-radius:6px;font-size:.82rem;font-weight:600;color:var(--lbtn-orange-text,#c2410c);text-decoration:none">'
            f'Intel ARK ↗</a>'
        )
    elif _cpu_prof.get("is_amd"):
        _amd_url = BCGLinkGenerator.amd_product(cpu_info.get("model", ""))
        _ext_links.append(
            f'<a href="{_amd_url}" target="_blank" class="btn-link" '
            f'style="display:inline-block;padding:.35rem .7rem;background:var(--lbtn-purple-bg,#faf5ff);border:1px solid var(--lbtn-purple-border,#e9d5ff);'
            f'border-radius:6px;font-size:.82rem;font-weight:600;color:var(--lbtn-purple-text,#7e22ce);text-decoration:none">'
            f'AMD Products ↗</a>'
        )
    _ext_links_html = f'<div style="display:flex;flex-wrap:wrap;gap:.5rem">{"".join(_ext_links)}</div>'

    return (
        f'<h2>CPU Architecture</h2>'
        f'<div class="card" style="margin-bottom:1.5rem;">'
        f'<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;">'
        f'<div>'
        f'<h3 style="margin:0 0 .4rem 0;color:var(--primary)">{_h(_deep_model_disp)}</h3>'
        f'<div style="display:flex;flex-wrap:wrap;gap:.35rem;align-items:center;">'
        f'{vsphere_9_badge}'
        f'{_cpu_prof["tier_badge_html"]}'
        f'{_evc_badge_deep}'
        f'{_pcie_gen_badge}'
        f'</div>'
        f'</div>'
        f'<div style="font-size:.82rem;color:var(--text-muted);text-align:right;white-space:nowrap">'
        f'{_h(_dd_spec_line)}'
        f'</div>'
        f'</div>'
        f'<details class="accordion" open style="margin-top:1.2rem;margin-bottom:0;">'
        f'<summary>'
        f'<div>🔬 NUMA, Cache &amp; External Resources</div>'
        f'<span style="font-size:.85rem;color:var(--primary)">Collapse Architecture Details &#9652;</span>'
        f'</summary>'
        f'<div class="accordion-body">'
        f'<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:1.4rem;">'
        f'<div>'
        f'<h4 style="margin:0 0 .4rem 0;font-size:.88rem;color:var(--primary)">Cache Hierarchy</h4>'
        f'{_cache_table}'
        f'<h4 style="margin:.9rem 0 .4rem 0;font-size:.88rem;color:var(--primary)">Processor Specifications</h4>'
        f'{_dd_full_spec_table}'
        f'</div>'
        f'<div>'
        f'<h4 style="margin:0 0 .4rem 0;font-size:.88rem;color:var(--primary)">NUMA &amp; Chiplet Architecture</h4>'
        f'{_topo_diagram_html}'
        f'{_numa_block}'
        f'{_amd_numa_card}'
        f'{_nps_note}'
        f'<h4 style="margin:.9rem 0 .4rem 0;font-size:.88rem;color:var(--primary)">VMware EVC Baseline</h4>'
        f'{_evc_block}'
        f'<h4 style="margin:.9rem 0 .4rem 0;font-size:.88rem;color:var(--primary)">External Resources</h4>'
        f'{_ext_links_html}'
        f'</div>'
        f'</div>'
        f'</div>'
        f'</details>'
        f'</div>'
    )
