"""
VCF Readiness Tool — networking, LLDP & FC HBA report section builders (Layer D).
"""
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.compat_engine import evaluate_npar
from vcf_hci.hcl import lookup_unique_hcl_device
from vcf_hci.obfuscation import _pii_span
from vcf_hci.report.components import (
    _nic_has_active_port,
    _render_nic_row,
    build_tor_switch_card,
    match_nic_info_for_lldp,
)
from vcf_hci.report.helpers import _h, html_escape


def render_fc_hba_card(fc_hbas: List[Dict[str, Any]]) -> str:
    """Render FC HBA summary badge cards (E+ / M+ / Cisco VIC / CNA)."""
    _emulex_hbas = [h for h in (fc_hbas or []) if h.get("vendor_class") == "emulex" and not h.get("is_cna")]
    _marvell_hbas = [h for h in (fc_hbas or []) if h.get("vendor_class") == "marvell" and not h.get("is_cna")]
    _vic_hbas = [h for h in (fc_hbas or []) if h.get("cna_family") == "cisco_vic"]
    _other_cna_hbas = [
        h for h in (fc_hbas or [])
        if h.get("is_cna") and h.get("cna_family") != "cisco_vic"
    ]
    _other_fc_hbas = [
        h for h in (fc_hbas or [])
        if not h.get("is_cna") and h.get("vendor_class") not in ("emulex", "marvell")
    ]
    _fc_hba_card_html = ""
    if _emulex_hbas:
        _e_badge = (
            "<span style='background:#CC092F;color:#fff;display:inline-block;"
            "padding:.25rem .65rem;border-radius:4px;font-weight:700;"
            "font-size:.82rem;letter-spacing:.02em'>E+ FC HBA</span>"
        )
        _e_names = ", ".join(sorted({h.get("adapter_name", "Emulex HBA") for h in _emulex_hbas}))
        _e_port_s = "port" if len(_emulex_hbas) == 1 else "ports"
        _fc_hba_card_html += (
            f"<div class='card'>"
            f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
            f"<h3 style='margin:0'>Broadcom Emulex FC HBA</h3>"
            f"<a href='#tab-network' data-jump-tab='tab-network' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to Networking section'>Details &rarr;</a>"
            f"</div>"
            f"<div>{_e_badge}</div>"
            f"<p style='font-size:.85rem;color:var(--text-muted);margin-top:.5rem'>"
            f"{len(_emulex_hbas)} Prism / Prism+ {_e_port_s} detected.<br>"
            f"<span style='font-size:.8rem'>{_h(_e_names)}</span></p>"
            f"<div style='margin-top:.5rem;border-top:1px solid var(--border);padding-top:.4rem'>"
            f"<a href='#tab-network' data-jump-tab='tab-network' class='btn-link tab-jump-link' style='font-size:.78rem'>"
            f"Full details in Networking tab &#8599;</a></div>"
            f"</div>"
        )
    if _marvell_hbas:
        _m_badge = (
            "<span style='background:#0072CE;color:#fff;display:inline-block;"
            "padding:.25rem .65rem;border-radius:4px;font-weight:700;"
            "font-size:.82rem;letter-spacing:.02em'>M+ FC HBA</span>"
        )
        _m_names = ", ".join(sorted({h.get("adapter_name", "Marvell HBA") for h in _marvell_hbas}))
        _m_port_s = "port" if len(_marvell_hbas) == 1 else "ports"
        _fc_hba_card_html += (
            f"<div class='card'>"
            f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
            f"<h3 style='margin:0'>Marvell QLogic FC HBA</h3>"
            f"<a href='#tab-network' data-jump-tab='tab-network' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to Networking section'>Details &rarr;</a>"
            f"</div>"
            f"<div>{_m_badge}</div>"
            f"<p style='font-size:.85rem;color:var(--text-muted);margin-top:.5rem'>"
            f"{len(_marvell_hbas)} QLE-series {_m_port_s} detected.<br>"
            f"<span style='font-size:.8rem'>{_h(_m_names)}</span></p>"
            f"<div style='margin-top:.5rem;border-top:1px solid var(--border);padding-top:.4rem'>"
            f"<a href='#tab-network' data-jump-tab='tab-network' class='btn-link tab-jump-link' style='font-size:.78rem'>"
            f"Full details in Networking tab &#8599;</a></div>"
            f"</div>"
        )
    if _vic_hbas:
        _v_badge = (
            "<span style='background:#0284c7;color:#fff;display:inline-block;"
            "padding:.25rem .65rem;border-radius:4px;font-weight:700;"
            "font-size:.82rem;letter-spacing:.02em'>Cisco VIC vHBA</span>"
        )
        _v_names = ", ".join(sorted({h.get("adapter_name", "Cisco VIC") for h in _vic_hbas}))
        _v_port_s = "port" if len(_vic_hbas) == 1 else "ports"
        _v_speeds = sorted({f"{h['speed_gbps']} Gbps" for h in _vic_hbas if h.get("speed_gbps") and h.get("speed_gbps") != "N/A"})
        _v_speed_str = f" @ {', '.join(_v_speeds)}" if _v_speeds else ""
        _fc_hba_card_html += (
            f"<div class='card'>"
            f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
            f"<h3 style='margin:0'>Cisco VIC FC (vHBA)</h3>"
            f"<a href='#tab-network' data-jump-tab='tab-network' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to Networking section'>Details &rarr;</a>"
            f"</div>"
            f"<div>{_v_badge}</div>"
            f"<p style='font-size:.85rem;color:var(--text-muted);margin-top:.5rem'>"
            f"{len(_vic_hbas)} virtual FC {_v_port_s}{_v_speed_str} (fnic) detected.<br>"
            f"<span style='font-size:.8rem'>{_h(_v_names)}</span></p>"
            f"<div style='margin-top:.5rem;border-top:1px solid var(--border);padding-top:.4rem'>"
            f"<a href='#tab-network' data-jump-tab='tab-network' class='btn-link tab-jump-link' style='font-size:.78rem'>"
            f"Full details in Networking tab &#8599;</a></div>"
            f"</div>"
        )
    if _other_cna_hbas:
        _c_badge = (
            "<span style='background:#4f46e5;color:#fff;display:inline-block;"
            "padding:.25rem .65rem;border-radius:4px;font-weight:700;"
            "font-size:.82rem;letter-spacing:.02em'>CNA vHBA</span>"
        )
        _c_names = ", ".join(sorted({h.get("adapter_name", "CNA Adapter") for h in _other_cna_hbas}))
        _c_port_s = "port" if len(_other_cna_hbas) == 1 else "ports"
        _c_drvs = ", ".join(sorted({h.get("cna_fc_driver") for h in _other_cna_hbas if h.get("cna_fc_driver")}))
        _c_drv_str = f" ({_c_drvs})" if _c_drvs else ""
        _c_speeds = sorted({f"{h['speed_gbps']} Gbps" for h in _other_cna_hbas if h.get("speed_gbps") and h.get("speed_gbps") != "N/A"})
        _c_speed_str = f" @ {', '.join(_c_speeds)}" if _c_speeds else ""
        _fc_hba_card_html += (
            f"<div class='card'>"
            f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
            f"<h3 style='margin:0'>Converged Network Adapter (vHBA)</h3>"
            f"<a href='#tab-network' data-jump-tab='tab-network' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to Networking section'>Details &rarr;</a>"
            f"</div>"
            f"<div>{_c_badge}</div>"
            f"<p style='font-size:.85rem;color:var(--text-muted);margin-top:.5rem'>"
            f"{len(_other_cna_hbas)} CNA vHBA {_c_port_s}{_c_speed_str}{_c_drv_str} detected.<br>"
            f"<span style='font-size:.8rem'>{_h(_c_names)}</span></p>"
            f"<div style='margin-top:.5rem;border-top:1px solid var(--border);padding-top:.4rem'>"
            f"<a href='#tab-network' data-jump-tab='tab-network' class='btn-link tab-jump-link' style='font-size:.78rem'>"
            f"Full details in Networking tab &#8599;</a></div>"
            f"</div>"
        )
    if _other_fc_hbas:
        _o_badge = (
            "<span style='background:#475569;color:#fff;display:inline-block;"
            "padding:.25rem .65rem;border-radius:4px;font-weight:700;"
            "font-size:.82rem;letter-spacing:.02em'>FC HBA</span>"
        )
        _o_names = ", ".join(sorted({h.get("adapter_name", "Fibre Channel HBA") for h in _other_fc_hbas}))
        _o_port_s = "port" if len(_other_fc_hbas) == 1 else "ports"
        _o_speeds = sorted({f"{h['speed_gbps']} Gbps" for h in _other_fc_hbas if h.get("speed_gbps") and h.get("speed_gbps") != "N/A"})
        _o_speed_str = f" @ {', '.join(_o_speeds)}" if _o_speeds else ""
        _fc_hba_card_html += (
            f"<div class='card'>"
            f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
            f"<h3 style='margin:0'>Fibre Channel HBA</h3>"
            f"<a href='#tab-network' data-jump-tab='tab-network' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to Networking section'>Details &rarr;</a>"
            f"</div>"
            f"<div>{_o_badge}</div>"
            f"<p style='font-size:.85rem;color:var(--text-muted);margin-top:.5rem'>"
            f"{len(_other_fc_hbas)} FC {_o_port_s}{_o_speed_str} detected.<br>"
            f"<span style='font-size:.8rem'>{_h(_o_names)}</span></p>"
            f"<div style='margin-top:.5rem;border-top:1px solid var(--border);padding-top:.4rem'>"
            f"<a href='#tab-network' data-jump-tab='tab-network' class='btn-link tab-jump-link' style='font-size:.78rem'>"
            f"Full details in Networking tab &#8599;</a></div>"
            f"</div>"
        )
    return _fc_hba_card_html


def render_network_section(
    nics: List[Dict[str, Any]],
    lldp_neighbors: List[Dict[str, Any]],
    fc_hbas: List[Dict[str, Any]],
    page_salt: str,
    quick_mode: bool = False,
    bmc_lic: Optional[Dict[str, Any]] = None,
    data_src: str = "",
    wsman_proto_label: str = "WS-Man",
    data: Optional[Dict[str, Any]] = None,
    json_hcl: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str, str]:
    """Render Networking tab section, return (tor_switch_map_html, network_section_html, fc_hba_card_html)."""
    bmc_lic = bmc_lic or {}
    data = data or {}
    fc_hba_card_html = render_fc_hba_card(fc_hbas)

    real_nics = [n for n in (nics or []) if not n.get("unsupported_license")]
    nic_blocked_rows = "".join(
        f"<tr><td colspan='5' style='color:#7f1d1d'>⚠️ {_h(n.get('name', 'NIC'))}: {_h(n.get('note', 'Collection blocked'))}</td></tr>"
        for n in (nics or []) if n.get("unsupported_license")
    )
    active_nics = [n for n in real_nics if _nic_has_active_port(n)]
    linkdown_nics = [n for n in real_nics if not _nic_has_active_port(n)]

    nic_rows = nic_blocked_rows + "".join(_render_nic_row(n, hcl_data=json_hcl, page_salt=page_salt) for n in active_nics)
    linkdown_rows = "".join(_render_nic_row(n, hcl_data=json_hcl, page_salt=page_salt) for n in linkdown_nics)
    if linkdown_rows:
        linkdown_rows = (
            f"<div style='margin-top:1.5rem'>"
            f"<h3 style='color:var(--text-muted);font-size:1rem'>Inactive / Disconnected Adapters ({len(linkdown_nics)})</h3>"
            f"<table><thead><tr><th>Adapter &amp; Part #</th><th>Manufacturer</th><th>Firmware</th><th>Port Status / Speed</th><th>BCG Links</th></tr></thead>"
            f"<tbody>{linkdown_rows}</tbody></table></div>"
        )

    hba_rows = ""
    for hba in (fc_hbas or []):
        hba_fw = hba.get("firmware_version", "N/A")
        hba_fw_cell = (
            f"<code style='font-size:.82rem'>{_h(str(hba_fw))}</code>"
            if hba_fw and hba_fw != "N/A"
            else "<span style='color:var(--text-muted)'>N/A</span>"
        )
        hba_vid = hba.get("vendor_id", "")
        hba_did = hba.get("device_id", "")
        hba_svid = hba.get("subsystem_vendor_id", "")
        hba_ssid = hba.get("subsystem_id", "")
        hba_quad = hba.get("pci_quad") or (f"{hba_vid}:{hba_did}:{hba_svid}:{hba_ssid}" if (hba_vid and hba_did and hba_svid and hba_ssid) else f"{hba_vid}:{hba_did}" if (hba_vid and hba_did) else "")

        _unique_hba = lookup_unique_hcl_device(
            vid=hba_vid, did=hba_did, svid=hba_svid, ssid=hba_ssid, json_hcl=json_hcl, model_name=hba.get("adapter_name", "")
        ) if json_hcl else None
        _hba_pid = _unique_hba.get("product_id", "") if _unique_hba else ""
        _hba_prog = _unique_hba.get("hcl_program", "") if _unique_hba else "io"

        if _hba_pid:
            bcg_hba = BCGLinkGenerator.device_detail(_hba_pid, _hba_prog)
        elif hba_vid and hba_did:
            bcg_hba = BCGLinkGenerator.pci_exact(hba_vid, hba_did, hba_svid, hba_ssid, program="io")
        else:
            bcg_hba = BCGLinkGenerator.fc_hba(hba.get("adapter_name", ""))

        hba_pci_badge = f"<br><code style='font-size:.76rem;background:var(--pci-bg);color:var(--pci-color);padding:1px 4px;border-radius:3px;'>PCI: {_h(hba_quad)}</code>" if hba_quad else ""
        cur_hba_gen = hba.get("current_pcie_type")
        cur_hba_width = hba.get("current_pcie_width")
        if cur_hba_gen or cur_hba_width:
            link_str = f"{cur_hba_gen or ''} x{cur_hba_width}" if cur_hba_width else f"{cur_hba_gen}"
            hba_pci_badge += f"<br><small style='color:var(--text-muted);font-size:.74rem;'>PCIe Link: <code>{_h(link_str.strip())}</code></small>"
        if hba.get("downgraded") and hba.get("downgrade_badge"):
            hba_pci_badge += f"<br>{hba['downgrade_badge']}"
        if hba.get("is_cna"):
            fam_l = hba.get("cna_family_label") or "Unified Fabric"
            hba_pci_badge += f"<br><span class='badge info' style='font-size:.72rem;background:#4f46e5;color:#fff;'>🟣 CNA vHBA ({_h(fam_l)})</span>"

        _wwnn_raw  = hba.get("wwnn", "")
        _wwpn_raw  = hba.get("wwpn", "N/A")
        wwnn_cell = (
            f"<code style='font-size:.8rem'>{_pii_span(page_salt, _wwnn_raw, 'wwn')}</code>"
            if _wwnn_raw else
            "<span style='color:var(--text-muted)'>—</span>"
        )

        _vc = hba.get("vendor_class", "")
        if _vc == "emulex":
            _vendor_badge = (
                " <span style='background:#CC092F;color:#fff;font-size:.68rem;"
                "font-weight:700;padding:.1rem .35rem;border-radius:3px;"
                "vertical-align:middle'>E+</span>"
            )
        elif _vc == "marvell":
            _vendor_badge = (
                " <span style='background:#0072CE;color:#fff;font-size:.68rem;"
                "font-weight:700;padding:.1rem .35rem;border-radius:3px;"
                "vertical-align:middle'>M+</span>"
            )
        else:
            _vendor_badge = ""

        _ls = hba.get("link_status", "Unknown")
        if _ls == "Up":
            _link_cell = "<span class='badge success' style='font-size:.75rem'>🟢 Up</span>"
        elif _ls in ("Down", "NoLink"):
            _link_cell = f"<span class='badge danger' style='font-size:.75rem'>🔴 {_h(_ls)}</span>"
        elif _ls == "Unknown":
            _link_cell = "<span style='color:var(--text-muted);font-size:.82rem'>—</span>"
        else:
            _link_cell = f"<span class='badge info' style='font-size:.75rem'>{_h(_ls)}</span>"

        _sw_wwpn = hba.get("remote_switch_wwpn", "")
        _sw_vend = hba.get("remote_switch_vendor", "")
        _sw_vend_html = f"<br><small style='color:var(--text-muted);font-size:.72rem;'>{_h(_sw_vend)}</small>" if _sw_vend else ""
        _sw_cell = (
            f"<code style='font-size:.78rem'>"
            f"{_pii_span(page_salt, _sw_wwpn, 'wwn')}</code>{_sw_vend_html}"
            if _sw_wwpn else
            "<span style='color:var(--text-muted)'>—</span>"
        )

        boot_html = ""
        for bt in (hba.get("boot_targets") or []):
            prio_label = "Primary" if bt["priority"] == 0 else f"Alt {bt['priority']}"
            _tgt_wwpn_pii = _pii_span(page_salt, bt['target_wwpn'], 'wwn')
            arr_v = bt.get("target_array_vendor")
            arr_fam = bt.get("target_array_family", "")
            fam_str = f" ({_h(arr_fam)})" if arr_fam else ""
            arr_badge = (
                f"<br><span class='badge info' style='font-size:.7rem;margin-top:2px;'>💾 {_h(arr_v)}{fam_str}</span>"
                if arr_v and arr_v != "Unknown Array" else ""
            )
            boot_html += (
                f"<div style='margin-top:.3rem'>"
                f"<span class='badge success' style='font-size:.72rem'>"
                f"SAN Boot · {prio_label}</span>{arr_badge}"
                f"<br><code style='font-size:.8rem'>{_tgt_wwpn_pii}</code>"
                f"&nbsp; LUN <strong>{bt['lun']}</strong></div>"
            )
        if not boot_html:
            boot_html = "<span style='color:var(--text-muted)'>—</span>"
        hba_rows += (
            f"<tr>"
            f"<td><strong>{_h(hba['adapter_name'])}</strong>{hba_pci_badge}</td>"
            f"<td>{_h(hba.get('manufacturer', 'Unknown'))}{_vendor_badge}</td>"
            f"<td>{hba_fw_cell}</td>"
            f"<td>{wwnn_cell}</td>"
            f"<td><code>{_pii_span(page_salt, _wwpn_raw, 'wwn')}</code></td>"
            f"<td>{hba['speed_gbps']} Gbps</td>"
            f"<td>{_link_cell}</td>"
            f"<td>{_sw_cell}</td>"
            f"<td>{boot_html}</td>"
            f"<td><a href='{bcg_hba}' target='_blank' class='btn-link'>BCG 9.1 ↗</a></td>"
            f"</tr>"
        )
    hba_section = (
        f"<h2>Fibre Channel HBAs (SAN Connectivity)</h2>"
        f"<table><thead><tr>"
        f"<th>Adapter</th><th>Manufacturer</th><th>Firmware</th>"
        f"<th>WWNN</th><th>WWPN</th><th>Speed</th>"
        f"<th>Link</th><th>Switch Port</th>"
        f"<th>SAN Boot Target</th><th>BCG 9.1 Check</th>"
        f"</tr></thead><tbody>{hba_rows}</tbody></table>"
        f"<p style='color:var(--text-muted);font-size:.82rem;margin:.6rem 0 1.25rem'>"
        f"ℹ️ <strong>Out-of-Band (OOB) Redfish Discovery Boundary:</strong> Surfaces HBA BIOS-configured SAN Boot Targets, Target WWPNs, Boot LUN IDs, and fabric switch WWPNs. "
        f"Full in-band SAN storage volume discovery (all non-boot SAN LUN volumes, volume capacity in TB, VMFS/RDM datastores, and ALUA multipath topologies) operates inside the host ESXi kernel storage stack and is reported when in-band agents (Dell iSM / HPE AMS) or ESXi vCenter integrations are present.</p>"
    ) if fc_hbas else ""

    lldp_rows = ""
    for n in (lldp_neighbors or []):
        src_badge = (
            "<span class='badge info' style='font-size:.72rem'>MGMT</span>"
            if n.get("source") == "mgmt" else
            "<span class='badge success' style='font-size:.72rem'>NIC</span>"
        )
        proto = n.get("protocol") or "LLDP"
        proto_badge = f"<span class='badge info' style='font-size:.7rem;margin-left:.2rem'>{_h(proto)}</span>" if proto != "LLDP" else ""
        _lldp_mac     = _pii_span(page_salt, n.get('local_mac'), "mac")       if n.get('local_mac')   else "—"
        _lldp_sw_name = _pii_span(page_salt, n.get('switch_name'), "switch") if n.get('switch_name') else "—"
        _lldp_sw_port = _pii_span(page_salt, n.get('switch_port'), "port")   if n.get('switch_port') else "—"
        _lldp_chassis = _pii_span(page_salt, n.get('chassis_id'), "mac")      if n.get('chassis_id')  else "—"
        _lldp_mgmt_ip = _pii_span(page_salt, n.get('mgmt_ipv4'), "ip")       if n.get('mgmt_ipv4')   else "—"

        nic_match = match_nic_info_for_lldp(n.get("local_iface", ""), n.get("local_mac", ""), nics, n.get("source", "nic"))
        nic_detail_html = f"<br><span style='font-size:.74rem;font-weight:600;color:var(--text);'>{_h(nic_match['label'])}</span>" if nic_match.get("label") else ""

        lldp_rows += (
            f"<tr>"
            f"<td>{src_badge}{proto_badge}&nbsp;"
            f"<code style='font-size:.82rem'>{_h(n.get('local_iface', ''))}</code>"
            f"{nic_detail_html}"
            f"<br><small style='color:var(--text-muted)'>{_lldp_mac}</small></td>"
            f"<td><strong>{_lldp_sw_name}</strong></td>"
            f"<td><code>{_lldp_sw_port}</code></td>"
            f"<td><code style='font-size:.8rem'>{_lldp_chassis}</code></td>"
            f"<td>{_lldp_mgmt_ip}</td>"
            f"<td style='max-width:260px;font-size:.8rem;color:var(--text-muted)'>"
            f"{_h(n.get('system_desc') or '—')}</td>"
            f"</tr>"
        )
    tor_switch_map_html = build_tor_switch_card(lldp_neighbors, nics)

    lldp_section = (
        f"<h2>LLDP / CDP Switch Neighbors</h2>"
        f"<p style='color:var(--text-muted);font-size:.88rem;margin:-.5rem 0 .75rem'>"
        f"Reported by the BMC management port and host NICs via LLDP and Cisco CDP. Coverage varies by "
        f"vendor and firmware — Dell iDRAC 9+, HPE iLO 5/6, Cisco IMC, and Lenovo XCC expose "
        f"management port and host NIC switch neighbors when enabled.</p>"
        f"<table><thead><tr>"
        f"<th>Local Interface &amp; Adapter</th><th>Neighbor Switch</th><th>Switch Port</th>"
        f"<th>Chassis ID</th><th>Mgmt IPv4</th><th>Description</th>"
        f"</tr></thead><tbody>{lldp_rows}</tbody></table>"
    ) if lldp_neighbors else ""

    if nic_rows:
        nic_table_body = nic_rows
    elif quick_mode:
        nic_table_body = "<tr><td colspan='5' style='color:var(--text-muted)'>Network collection skipped in Quick mode — re-run in Full mode.</td></tr>"
    elif data.get("partial_scan") or "network_adapters" in data.get("partial_sections", []):
        nic_table_body = "<tr><td colspan='5' style='color:var(--warning,#ca8a04)'>⚠️ Network adapter collection timed out or was incomplete due to BMC responsiveness. Perform a BMC reset (<code>racadm racreset</code> or <code>iloreset</code>) and re-scan.</td></tr>"
    elif any(kw in bmc_lic.get('license_name','').lower() for kw in ['required','blocked','missing']):
        nic_table_body = "<tr><td colspan='5' style='color:#7f1d1d'>⚠️ Network collection was blocked by a license restriction — see BMC License row for details.</td></tr>"
    elif data_src.startswith('wsman'):
        nic_table_body = f"<tr><td colspan='5' style='color:var(--text-muted)'>ℹ️ No NICs discovered via {wsman_proto_label}. CIM_NetworkPort returned no entries.</td></tr>"
    else:
        nic_table_body = "<tr><td colspan='5'>No NICs discovered via Redfish API.</td></tr>"

    npar_eval = evaluate_npar(nics)
    npar_banner_html = ""
    if npar_eval.get("npar_detected"):
        npar_banner_html = (
            f"<div class='alert-warning' style='background:rgba(202,138,4,0.12);border-left:4px solid var(--warning,#ca8a04);padding:.75rem 1rem;border-radius:4px;margin-bottom:1rem;'>"
            f"<strong>⚠️ NIC Partitioning (NPAR) Advisory for VCF 9.1:</strong> {html_escape(npar_eval['advisory'])}<br>"
            f"<small style='font-weight:600;margin-top:.25rem;display:inline-block;'>Recommendation: {html_escape(npar_eval['recommendation'])}</small>"
            f"</div>"
        )
    elif npar_eval.get("vic_virtual_detected") and npar_eval.get("vic_info"):
        vic_info = npar_eval["vic_info"]
        if isinstance(vic_info, dict):
            vic_desc = vic_info.get("description", "")
            vic_rec = vic_info.get("recommendation", "")
        else:
            vic_desc = str(vic_info)
            vic_rec = (
                "Cisco VIC virtual interfaces are fully supported for VCF 9.1 / vSphere 9.x. "
                "Ensure ESXi inbox drivers ('nenic' for Ethernet, 'fnic' for Fibre Channel) and "
                "appropriate QoS / CoS policies are configured in Cisco Intersight or UCS Manager."
            )
        rec_html = f"<br><small style='color:var(--text-muted);font-weight:600;margin-top:.25rem;display:inline-block;'>Recommendation: {html_escape(vic_rec)}</small>" if vic_rec else ""
        npar_banner_html = (
            f"<div class='alert-info' style='background:rgba(2,132,199,0.08);border-left:4px solid #0284c7;padding:.75rem 1rem;border-radius:4px;margin-bottom:1rem;'>"
            f"<strong>🔵 Cisco VIC Hardware Virtualization:</strong> {html_escape(vic_desc)}"
            f"{rec_html}"
            f"</div>"
        )

    # ── Out-of-Band BMC Dedicated Management Interface ────────────────────────
    sys_info = data.get("system") or {}
    vendor = sys_info.get("vendor") or ""
    bmc_type = (
        "Dell iDRAC" if "dell" in vendor.lower() else
        "HPE iLO" if ("hpe" in vendor.lower() or "hewlett" in vendor.lower()) else
        "Cisco IMC" if "cisco" in vendor.lower() else
        "Lenovo XCC" if "lenovo" in vendor.lower() else
        "Supermicro BMC" if "supermicro" in vendor.lower() else
        "BMC Management Controller"
    )
    bmc_fw = sys_info.get("bmc_fw_version") or ""
    mgmt_ip = sys_info.get("ip") or data.get("host") or ""
    mgmt_lldp = next((n for n in (lldp_neighbors or []) if n.get("source") == "mgmt"), None)
    mgmt_mac = (mgmt_lldp.get("local_mac") if mgmt_lldp else None) or sys_info.get("bmc_mac") or ""
    mgmt_iface_name = (mgmt_lldp.get("local_iface") if mgmt_lldp else None) or (
        "iDRAC.Embedded.1" if "dell" in vendor.lower() else
        "iLO Dedicated Port" if "hpe" in vendor.lower() else
        "CIMC Dedicated Mgmt" if "cisco" in vendor.lower() else
        "Dedicated BMC Port"
    )

    mgmt_switch_html = "<span style='color:var(--text-muted)'>— (LLDP not reported)</span>"
    if mgmt_lldp and (mgmt_lldp.get("switch_name") or mgmt_lldp.get("switch_port")):
        _sw_n = _pii_span(page_salt, mgmt_lldp.get('switch_name'), 'switch') if mgmt_lldp.get('switch_name') else ""
        _sw_p = _pii_span(page_salt, mgmt_lldp.get('switch_port'), 'port') if mgmt_lldp.get('switch_port') else ""
        if _sw_n and _sw_p:
            mgmt_switch_html = f"<strong>{_sw_n}</strong> (port <code>{_sw_p}</code>)"
        elif _sw_n:
            mgmt_switch_html = f"<strong>{_sw_n}</strong>"
        elif _sw_p:
            mgmt_switch_html = f"Port <code>{_sw_p}</code>"

    _mgmt_ip_pii = _pii_span(page_salt, mgmt_ip, 'ip') if mgmt_ip else "<span style='color:var(--text-muted)'>N/A</span>"
    _mgmt_mac_pii = f"<code>{_pii_span(page_salt, mgmt_mac, 'mac')}</code>" if mgmt_mac else "<span style='color:var(--text-muted)'>—</span>"
    _fw_str = f"<br><small style='color:var(--text-muted)'>{_h(bmc_type)} FW {_h(bmc_fw)}</small>" if bmc_fw else ""

    bmc_mgmt_card_html = (
        f"<div style='margin-top:1.5rem;padding:0.85rem 1.1rem;background:var(--code-bg,#f8fafc);border:1px solid var(--border);border-radius:6px;'>"
        f"  <div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem;margin-bottom:.5rem'>"
        f"    <div style='font-weight:600;font-size:.9rem;display:flex;align-items:center;gap:.4rem'>"
        f"      <span>🛠️</span> <strong>Dedicated BMC Management Interface ({_h(bmc_type)})</strong>"
        f"    </div>"
        f"    <div>"
        f"      <span class='badge info' style='font-size:.74rem'>Out-of-Band Management · 1 GbE Dedicated</span>"
        f"    </div>"
        f"  </div>"
        f"  <table style='margin:0;font-size:.82rem'>"
        f"    <thead>"
        f"      <tr>"
        f"        <th>Interface &amp; Controller</th>"
        f"        <th>Management IPv4</th>"
        f"        <th>MAC Address</th>"
        f"        <th>Link Status &amp; Speed</th>"
        f"        <th>Connected Switch / Port</th>"
        f"      </tr>"
        f"    </thead>"
        f"    <tbody>"
        f"      <tr>"
        f"        <td><strong>{_h(mgmt_iface_name)}</strong>{_fw_str}</td>"
        f"        <td>{_mgmt_ip_pii}</td>"
        f"        <td>{_mgmt_mac_pii}</td>"
        f"        <td><span class='badge success' style='font-size:.72rem'>🟢 Link Up (1 GbE)</span></td>"
        f"        <td>{mgmt_switch_html}</td>"
        f"      </tr>"
        f"    </tbody>"
        f"  </table>"
        f"</div>"
    ) if (mgmt_ip or mgmt_lldp) else ""

    optical_banner_html = ""
    optical_warnings = (data.get("optical_warnings") or []) if data else []
    if optical_warnings:
        warn_items = "".join(f"<li>{html_escape(str(w))}</li>" for w in optical_warnings)
        optical_banner_html = (
            f"<div class='alert-warning' style='background:rgba(202,138,4,0.12);border-left:4px solid var(--warning,#ca8a04);padding:.75rem 1rem;border-radius:4px;margin-bottom:1rem;'>"
            f"<strong>⚠️ Optical Transceiver Signal Health Warning:</strong>"
            f"<ul style='margin:.25rem 0 0 1.2rem;padding:0;'>{warn_items}</ul>"
            f"<small style='font-size:.78rem;color:var(--text-muted);display:inline-block;margin-top:.35rem;'>Optical power levels below -10.0 dBm (marginal) or -13.0 dBm (critical) on Short Range (850nm) optics can cause intermittent frame drops, CRC errors, or link flapping. Inspect cable bend radii and clean optical fiber endfaces with a one-click cleaner.</small>"
            f"</div>"
        )

    network_section_html = (
        f"<h2>Network Interfaces (NICs)</h2>"
        f"{npar_banner_html}"
        f"{optical_banner_html}"
        f"<table><thead><tr><th>Adapter &amp; Part #</th><th>Manufacturer</th><th>Firmware</th><th>Port Status / Speed</th><th>BCG Links</th></tr></thead><tbody>{nic_table_body}</tbody></table>"
        f"{linkdown_rows}"
        f"{bmc_mgmt_card_html}"
        f"{lldp_section}"
        f"{hba_section}"
    )

    return tor_switch_map_html, network_section_html, fc_hba_card_html
