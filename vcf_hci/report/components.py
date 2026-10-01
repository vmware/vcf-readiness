"""
VCF Readiness Tool — reusable HTML component builders.

These functions produce HTML fragments used by generate_host_html_report().
All functions here are standalone (no closure over outer-scope data) so they
can be independently imported, tested, and reused.

Design tokens (CSS custom properties):
  --success:#16a34a  --warning:#ca8a04  --danger:#dc2626  --primary:#2563eb
  badge classes: success, warning, danger, info, cyber-recovery
"""
import html
import re
import urllib.parse
from typing import Optional

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.compat_engine import check_defective_drive_firmware, evaluate_drive_fw, evaluate_pci_compatibility
from vcf_hci.constants import KB_TRIMODE
from vcf_hci.hcl import evaluate_drive_hcl_tier, lookup_unique_hcl_device
from vcf_hci.obfuscation import _pii_span
from vcf_hci.report.helpers import _h, badge  # noqa: F401
from vcf_hci.report.switch_topology import classify_switch


def _rn_dim_row(icon, label, actual, needed, ok):
    cls  = "success" if ok else "warning"
    mark = "✅" if ok else "⚠️"
    return (
        f"<div style='display:flex;justify-content:space-between;align-items:center;"
        f"padding:.18rem 0;border-bottom:1px solid var(--border);font-size:.8rem'>"
        f"<span>{icon} {label}</span>"
        f"<span class='badge {cls}' style='font-size:.73rem;padding:.1rem .4rem'>"
        f"{mark} {actual}</span></div>"
    )


def _build_bios_rows(modes):
    parts = []
    for r in modes:
        bdg = r["badge"]
        parts.append(
            f"<tr>"
            f"<td>{_h(r['feature'])}</td>"
            f"<td><span class='badge {bdg}'>{_h(r['label'])}</span></td>"
            f"<td style='font-size:.85rem;color:var(--text-muted)'>{_h(r['note'])}</td>"
            f"<td><code style='font-size:.8rem'>{_h(r['raw_key'])}={_h(r['raw_val'])}</code></td>"
            f"</tr>"
        )
    return "".join(parts)

def _sel_row(a, vendor=None):
    from vcf_hci.report.sel_links import (
        normalize_vendor,
        render_sel_message_id_cell,
        resolve_cisco_event_info,
        resolve_dell_event_info,
        resolve_hpe_event_info,
        resolve_sel_event_url,
    )
    msg_id = a.get("message_id")
    msg = a.get("message")
    msg_id_html = render_sel_message_id_cell(vendor, msg_id, msg)

    norm = normalize_vendor(vendor)
    if norm == "dell":
        info = resolve_dell_event_info(msg_id, msg)
        event_url = info.get("url")
        link_title = f"Dell EEMS Reference: {info.get('title')}"
    elif norm == "hpe":
        info = resolve_hpe_event_info(msg_id, msg)
        event_url = info.get("url")
        link_title = info.get("title") or "HPE IML Reference"
    elif norm == "cisco":
        info = resolve_cisco_event_info(msg_id, msg)
        event_url = info.get("url")
        link_title = info.get("title") or "Cisco IMC Faults Reference"
    else:
        event_url = resolve_sel_event_url(vendor, msg_id, msg)
        link_title = "Lookup vendor reference for this alert"

    if event_url:
        msg_html = (
            f"<a href='{html.escape(event_url)}' target='_blank' rel='noopener noreferrer' "
            f"style='color:inherit;text-decoration:none' title='{html.escape(link_title)}'>"
            f"<strong>{_h(str(msg))}</strong> <span style='font-size:.72rem;color:var(--primary)'>↗</span></a>"
        )
    else:
        msg_html = f"<strong>{_h(str(msg))}</strong>"
    return (
        f"<tr><td>{a['badge']}</td><td>{msg_id_html}</td>"
        f"<td>{msg_html}</td><td><small>{_h(str(a['timestamp']))}</small></td></tr>"
    )

def _nic_has_active_port(nic):
    return any(
        str(p.get("link_status", "")).capitalize() == "Up" and p.get("current_speed_gbps", 0)
        for p in nic.get("ports", [])
    )

def _render_nic_row(nic, hcl_data=None, page_salt=""):
    port_badges = []
    nic_name = str(nic.get("name") or "")
    nic_id = str(nic.get("id") or "")
    is_nic_fc = (
        "fibre channel" in nic_name.lower()
        or bool(re.search(r"\bFC\.", nic_id))
        or bool(re.search(r"\bFC\s+(?:Adapter|HBA)\b", nic_name, re.I))
    )
    for p in nic.get("ports", []):
        spd = p.get("current_speed_gbps") or 0
        link_st = str(p.get("link_status", "Down")).capitalize()
        pid = p.get("port_id", 1)
        is_port_fc = (
            is_nic_fc
            or str(pid).startswith("FC.")
            or ".FC." in str(pid)
            or "fibre channel" in str(p.get("transceiver_interface") or "").lower()
        )
        if link_st != "Up" or spd == 0:
            badge_html = f"<span class='badge danger'>🔴 Port {pid}: Link Down</span>"
        elif is_port_fc:
            badge_html = f"<span class='badge success'>🟢 Port {pid}: {spd} Gbps FC</span>"
        elif spd >= 25:
            badge_html = f"<span class='badge success'>🟢 Port {pid}: {spd} Gbps — ESA Qualified</span>"
        else:
            badge_html = f"<span class='badge warning'>🟡 Port {pid}: {spd} Gbps — OSA Only</span>"

        tx_id = p.get("transceiver_identifier") or ""
        tx_if = p.get("transceiver_interface") or ""
        tx_vendor = p.get("transceiver_vendor") or ""
        tx_pn = p.get("transceiver_part_number") or ""
        tx_parts = []
        if tx_id or tx_if:
            tx_parts.append(f"{tx_id} {tx_if}".strip())
        if tx_vendor:
            tx_parts.append(tx_vendor)
        if tx_pn:
            tx_parts.append(f"PN: {tx_pn}")
        if tx_parts:
            badge_html += f"<br><small style='color:var(--text-muted);font-size:.73rem;display:inline-block;padding-left:1.1rem;'>🔌 {_h(' | '.join(tx_parts))}</small>"

        rx_p = p.get("rx_power_dbm")
        tx_p = p.get("tx_power_dbm")
        tx_temp = p.get("transceiver_temperature_c") if p.get("transceiver_temperature_c") is not None else p.get("temperature_c")
        ddm_parts = []
        if rx_p is not None:
            ddm_parts.append(f"RX: {rx_p:+.1f} dBm" if isinstance(rx_p, (int, float)) else f"RX: {rx_p} dBm")
        if tx_p is not None:
            ddm_parts.append(f"TX: {tx_p:+.1f} dBm" if isinstance(tx_p, (int, float)) else f"TX: {tx_p} dBm")
        if tx_temp is not None:
            ddm_parts.append(f"Temp: {tx_temp:.1f}°C" if isinstance(tx_temp, (int, float)) else f"Temp: {tx_temp}°C")
        if ddm_parts:
            ddm_tip_items = list(ddm_parts)
            bias_ma = p.get("laser_bias_current_ma")
            volt_v = p.get("voltage_v")
            if bias_ma is not None:
                ddm_tip_items.append(f"Bias: {bias_ma:.1f} mA" if isinstance(bias_ma, (int, float)) else f"Bias: {bias_ma} mA")
            if volt_v is not None:
                ddm_tip_items.append(f"Voltage: {volt_v:.2f} V" if isinstance(volt_v, (int, float)) else f"Voltage: {volt_v} V")
            ddm_tip = f"Digital Diagnostics Monitoring (DDM): {', '.join(ddm_tip_items)}"
            badge_html += f"<br><small style='color:var(--text-muted);font-size:.73rem;display:inline-block;padding-left:1.1rem;' title='{_h(ddm_tip)}'>📊 DDM: {_h(' · '.join(ddm_parts))}</small>"

        opt_warn = p.get("optical_warning")
        opt_health = p.get("optical_signal_health")
        if opt_health == "critical" or (opt_warn and "critical" in str(opt_warn).lower()):
            rx_str = f" ({rx_p:+.1f} dBm)" if isinstance(rx_p, (int, float)) else ""
            warn_tip = _h(str(opt_warn)) if opt_warn else "Critical optical signal degradation"
            badge_html += f"<br><span class='badge danger' style='font-size:.72rem' title='{warn_tip}'><span class='badge-label'>⚠️ Critical Optical Signal{rx_str}</span></span>"
        elif opt_health == "marginal" or (opt_warn and "marginal" in str(opt_warn).lower()):
            rx_str = f" ({rx_p:+.1f} dBm)" if isinstance(rx_p, (int, float)) else ""
            warn_tip = _h(str(opt_warn)) if opt_warn else "Marginal optical signal level"
            badge_html += f"<br><span class='badge warning' style='font-size:.72rem' title='{warn_tip}'><span class='badge-label'>⚠️ Marginal Optical Signal{rx_str}</span></span>"

        port_badges.append(badge_html)
    fw = nic.get("firmware_version", "N/A")
    fw_cell = (
        f"<code style='font-size:.82rem'>{_h(str(fw))}</code>"
        if fw and fw != "N/A"
        else "<span style='color:var(--text-muted)'>N/A</span>"
    )
    bcg_nic, bcg_vsan_nic = BCGLinkGenerator.io_nic_exact(
        nic.get("name", ""), fw,
        nic.get("vendor_id", ""), nic.get("device_id", ""),
        nic.get("subsystem_vendor_id", ""), nic.get("subsystem_id", "")
    )

    vid = nic.get("vendor_id", "")
    did = nic.get("device_id", "")
    svid = nic.get("subsystem_vendor_id", "")
    ssid = nic.get("subsystem_id", "")
    pci_quad = nic.get("pci_quad") or (f"{vid}:{did}:{svid}:{ssid}" if (vid and did and svid and ssid) else f"{vid}:{did}" if (vid and did) else "")

    pci_badge = ""
    if pci_quad:
        pci_badge = f"<br><code style='font-size:.76rem;background:var(--pci-bg);color:var(--pci-color);padding:1px 4px;border-radius:3px;'>PCI: {_h(pci_quad)}</code>"

    cur_gen = nic.get("current_pcie_type")
    cur_width = nic.get("current_pcie_width")
    if cur_gen or cur_width:
        link_str = f"{cur_gen or ''} x{cur_width}" if cur_width else f"{cur_gen}"
        pci_badge += f"<br><small style='color:var(--text-muted);font-size:.74rem;'>PCIe Link: <code>{_h(link_str.strip())}</code></small>"

    if nic.get("downgraded") and nic.get("downgrade_badge"):
        pci_badge += f"<br>{nic['downgrade_badge']}"

    if nic.get("is_cna"):
        fam = nic.get("cna_family_label") or "CNA"
        pci_badge += f"<br><span class='badge info' style='font-size:.74rem;background:#4f46e5;color:#fff;'>🟣 CNA: {_h(fam)} (vNIC + vHBA)</span>"

    if nic.get("is_vic_virtual") or nic.get("cna_family") == "cisco_vic" or nic.get("vic_virtual_interfaces"):
        v_count = len(nic.get("vic_virtual_interfaces") or [])
        pci_badge += f"<br><span class='badge info' style='font-size:.74rem;background:#0284c7;color:#fff;'>🔵 Cisco VIC Virtual Interfaces ({v_count} vNIC/vHBA)</span>"
    elif nic.get("is_npar"):
        n_count = len(nic.get("npar_partitions") or [])
        pci_badge += f"<br><span class='badge warning' style='font-size:.74rem;'>🟡 NPAR Partitioned ({n_count} virtual functions)</span>"

    pci_verdict_html = ""
    if vid and did:
        pci_eval = evaluate_pci_compatibility(vid, did, svid, ssid, nic.get("name", ""), fw, hcl_data=hcl_data)
        pci_verdict_html = f"<br>{pci_eval['badge']}"
        if pci_eval.get("rdma_badge"):
            pci_verdict_html += f"<br>{pci_eval['rdma_badge']}"
        if pci_eval.get("recommended_driver"):
            pci_verdict_html += f"<br><small style='color:var(--text-muted);font-size:.75rem;'>🚗 Driver (9.1): <code>{_h(pci_eval['recommended_driver'])}</code></small>"
        if pci_eval.get("recommended_firmware") and pci_eval.get("fw_badge"):
            pci_verdict_html += f"<br>{pci_eval['fw_badge']}"
        if pci_eval.get("action_required"):
            pci_verdict_html += f"<br><small style='color:var(--warning-text, #ca8a04);font-size:.75rem;'>⚠️ {pci_eval['action_required']}</small>"
        if pci_eval.get("vcglink"):
            bcg_vsan_nic = pci_eval["vcglink"]
        elif pci_eval.get("product_id"):
            _nic_pid = str(pci_eval["product_id"]).strip()
            bcg_vsan_nic = BCGLinkGenerator.device_detail(_nic_pid, "rdmanic")

        if pci_eval.get("io_vcglink"):
            bcg_nic = pci_eval["io_vcglink"]
        elif pci_eval.get("io_product_id"):
            _io_pid = str(pci_eval["io_product_id"]).strip()
            bcg_nic = BCGLinkGenerator.device_detail(_io_pid, "io")
    elif hcl_data:
        _unique = lookup_unique_hcl_device(json_hcl=hcl_data, model_name=nic.get("name", ""))
        if _unique:
            if _unique.get("vcglink"):
                bcg_vsan_nic = _unique["vcglink"]
            elif _unique.get("product_id"):
                _nic_pid = str(_unique["product_id"]).strip()
                bcg_vsan_nic = BCGLinkGenerator.device_detail(_nic_pid, "rdmanic")

            if _unique.get("io_vcglink"):
                bcg_nic = _unique["io_vcglink"]
            elif _unique.get("io_product_id"):
                _io_pid = str(_unique["io_product_id"]).strip()
                bcg_nic = BCGLinkGenerator.device_detail(_io_pid, "io")

    ports_html = "<br>".join(port_badges) if port_badges else "<span style='color:var(--text-muted)'>No port data</span>"
    if (nic.get("is_vic_virtual") or nic.get("cna_family") == "cisco_vic" or nic.get("vic_virtual_interfaces")) and nic.get("vic_virtual_interfaces"):
        v_list = nic["vic_virtual_interfaces"]
        vic_lines = []
        for v in v_list:
            v_id = str(v.get("partition_id") or v.get("name") or "vNIC")
            cdn = f" ({v.get('cdn')})" if v.get("cdn") else ""
            spd = f"{v.get('speed_gbps', 0)} Gbps" if v.get('speed_gbps') else ""
            proto = str(v.get("protocol") or v.get("interface_type") or "").lower()
            is_fc = "fc" in proto or "fibre" in proto or "vhba" in v_id.lower() or v_id.lower().startswith("fc") or bool(v.get("wwpn"))

            parts = []
            if spd:
                parts.append(_h(spd))
            if is_fc:
                parts.append("FCoE Fabric")
                if v.get("wwpn"):
                    _raw_wwpn = str(v["wwpn"])
                    _wwpn_html = _pii_span(page_salt, _raw_wwpn, "wwn") if page_salt else _h(_raw_wwpn)
                    parts.append(f"WWPN {_wwpn_html}")
                if v.get("wwnn"):
                    _raw_wwnn = str(v["wwnn"])
                    _wwnn_html = _pii_span(page_salt, _raw_wwnn, "wwn") if page_salt else _h(_raw_wwnn)
                    parts.append(f"WWNN {_wwnn_html}")
                if v.get("cos") is not None:
                    parts.append(f"CoS {_h(str(v['cos']))}")
            else:
                if v.get("mac_address"):
                    _raw_vmac = str(v["mac_address"])
                    _vmac_html = _pii_span(page_salt, _raw_vmac, "mac") if page_salt else _h(_raw_vmac)
                    parts.append(f"MAC {_vmac_html}")
                if v.get("mtu"):
                    parts.append(f"MTU {_h(str(v['mtu']))}")
                if v.get("vlan_mode") == "Access" and v.get("vlan_id"):
                    parts.append(f"VLAN {_h(str(v['vlan_id']))}")
                elif v.get("vlan_mode") == "Trunk":
                    parts.append("VLAN Trunk")
                elif v.get("vlan_id"):
                    parts.append(f"VLAN {_h(str(v['vlan_id']))}")
                if v.get("geneve_offload"):
                    parts.append("NSX Geneve Offload")
                if v.get("vxlan_offload") and not v.get("geneve_offload"):
                    parts.append("VXLAN Offload")
                if v.get("tso_enabled") or v.get("lro_enabled"):
                    parts.append("TSO/LRO")
                if v.get("rss_enabled"):
                    parts.append("RSS")
                if v.get("rocev2"):
                    parts.append("RoCEv2")

            cap_str = " · ".join(parts)
            line = f"<code>{_h(v_id)}{_h(cdn)}</code>: {cap_str}" if cap_str else f"<code>{_h(v_id)}{_h(cdn)}</code>"
            vic_lines.append(line)

        ports_html += (
            "<div style='margin-top:.4rem;padding:.35rem .55rem;background:var(--code-bg,#f8fafc);border-left:3px solid #0284c7;border-radius:3px;font-size:.73rem;line-height:1.45;'>"
            "<strong style='color:#0284c7;display:block;margin-bottom:.2rem;'>Virtual Interfaces:</strong>"
            + "<br>".join(vic_lines)
            + "</div>"
        )
    elif nic.get("is_npar") and nic.get("npar_partitions"):
        p_list = nic["npar_partitions"]
        p_strs = []
        for p in p_list:
            pid = _h(str(p.get("partition_id", "P")))
            spd = f"{p.get('speed_gbps', 0)}G"
            mac_str = ""
            if p.get("mac_address"):
                _p_mac = str(p["mac_address"])
                _m_html = _pii_span(page_salt, _p_mac, "mac") if page_salt else _h(_p_mac)
                mac_str = f" ({_m_html})"
            p_strs.append(f"{pid}: {spd}{mac_str}")
        ports_html += f"<br><small style='color:var(--text-muted);font-size:.74rem'>Partitions: {', '.join(p_strs)}</small>"

    cna_links = ""
    if nic.get("is_cna"):
        if nic.get("cna_eth_bcg_url"):
            drv = nic.get("cna_eth_driver", "NIC")
            cna_links += f"<br><a href='{nic['cna_eth_bcg_url']}' target='_blank' class='btn-link' style='font-size:.78rem'>BCG Eth ({_h(drv)}) ↗</a>"
        if nic.get("cna_fc_bcg_url"):
            drv = nic.get("cna_fc_driver", "HBA")
            cna_links += f"<br><a href='{nic['cna_fc_bcg_url']}' target='_blank' class='btn-link' style='font-size:.78rem'>BCG FC ({_h(drv)}) ↗</a>"

    return (
        f"<tr><td><strong>{_h(nic.get('name', 'Unknown'))}</strong>{pci_badge}{pci_verdict_html}<br>"
        f"<small style='color:var(--text-muted)'>PN: {_h(nic.get('part_number', 'N/A'))}</small></td>"
        f"<td>{_h(nic.get('manufacturer', 'Unknown'))}</td>"
        f"<td>{fw_cell}</td>"
        f"<td>{ports_html}</td>"
        f"<td><a href='{bcg_nic}' target='_blank' class='btn-link'>BCG IO ↗</a>"
        f"<br><a href='{bcg_vsan_nic}' target='_blank' class='btn-link'"
        f" style='font-size:.78rem;opacity:.8' title='vSAN RDMA HCL — match indicates RDMA/RoCE qualification'>vSAN RDMA ↗</a>"
        f"{cna_links}</td></tr>"
    )

def _is_nvme_d(d):
    p = str(d.get("protocol", "")).upper()
    return "NVME" in p or "PCIE" in p or d.get("is_edsff", False)

def _is_sas_sata_d(d):
    p = str(d.get("protocol", "")).upper()
    return "SAS" in p or "SATA" in p

def _chassis_svg(
    nvme_list,
    sas_list=None,
    empty_list=None,
    position_label="",
    chassis_title="",
    total_slots_override=None,
):
    """Render an inline SVG chassis diagram from drive bay data.

    Supports both 3-list positional call style (nvme_list, sas_list, empty_list)
    or single list call style where nvme_list is a list of all drive dicts on the host/chassis.

    Draws a unified physical backplane diagram with accurate grid positioning,
    color-coding by drive type/protocol, and interactive hover tooltips.
    """
    if sas_list is None and empty_list is None and isinstance(nvme_list, list):
        all_bays = [dict(d) for d in nvme_list]
    else:
        all_bays = (
            [dict(d) for d in (nvme_list or [])]
            + [dict(d) for d in (sas_list or [])]
            + [dict(d) for d in (empty_list or [])]
        )

    if not all_bays:
        return ""

    # ── Slot completion: ensure all physical slots 0..N-1 exist ──
    known_slots: list = [
        int(d["bay_slot"]) for d in all_bays if isinstance(d, dict) and isinstance(d.get("bay_slot"), int)
    ]
    max_known_slot = max(known_slots) if known_slots else -1

    target_total = (
        total_slots_override
        if total_slots_override and total_slots_override > 0
        else max(max_known_slot + 1, len(all_bays))
    )
    if target_total in (9, 10):
        target_total = 10
    elif target_total in (23, 24):
        target_total = 24
    elif target_total in (15, 16):
        target_total = 16
    elif target_total in (7, 8):
        target_total = 8
    elif target_total in (3, 4):
        target_total = 4

    pos_label = position_label or "Front"

    known_slots = [
        int(d["bay_slot"]) for d in all_bays if isinstance(d, dict) and isinstance(d.get("bay_slot"), int)
    ]
    max_known_slot = max(known_slots) if known_slots else -1

    target_total = (
        total_slots_override
        if total_slots_override and total_slots_override > 0
        else max(max_known_slot + 1, len(all_bays))
    )
    if target_total in (9, 10):
        target_total = 10
    elif target_total in (23, 24):
        target_total = 24
    elif target_total in (15, 16):
        target_total = 16
    elif target_total in (7, 8):
        target_total = 8
    elif target_total in (3, 4):
        target_total = 4

    target_total = max(target_total, len(all_bays))

    # Place drives in bounded slot_map 0..target_total-1
    slots = [None] * target_total
    unassigned = []

    for d in all_bays:
        s = d.get("bay_slot")
        if isinstance(s, int) and 0 <= s < target_total and slots[s] is None:
            slots[s] = dict(d)
        else:
            unassigned.append(dict(d))

    for d in unassigned:
        placed = False
        for idx in range(target_total):
            if slots[idx] is None:
                d_copy = dict(d)
                d_copy["bay_slot"] = idx
                slots[idx] = d_copy
                placed = True
                break
        if not placed:
            d_copy = dict(d)
            d_copy["bay_slot"] = len(slots)
            slots.append(d_copy)

    for idx in range(len(slots)):
        if slots[idx] is None:
            slots[idx] = {
                "populated": False,
                "bay_slot": idx,
                "bay_position": pos_label,
                "name": f"Empty Slot {idx}",
                "model": "",
                "product_id": "",
                "protocol": "",
                "capacity_gb": 0,
            }

    sorted_bays: list = [d for d in slots if isinstance(d, dict)]

    n = len(sorted_bays)

    # ── Form-factor & grid dimensions ──
    edsff_count = sum(1 for d in sorted_bays if d.get("is_edsff"))
    lff_count   = sum(1 for d in sorted_bays if d.get("form_factor_label") == '3.5"')

    if edsff_count >= max(1, n // 2):
        bw, bh = 18, 70
        ff_tag = "EDSFF"
    elif lff_count >= max(1, n // 2):
        bw, bh = 48, 64
        ff_tag = '3.5" LFF'
    else:
        bw, bh = 38, 54
        ff_tag = '2.5" SFF'

    # ── Physical Grid Layout ──
    # 10 SFF bays (e.g. Dell R640 321-BCQQ / DL360 10 SFF): 2 rows x 5 cols
    # Vertical pairing: Slot 0 top left, Slot 1 bottom left, Slot 2 top 2nd col ...
    is_10_sff_grid = (n == 10)
    if is_10_sff_grid:
        cols = 5
        rows = 2
    elif n <= 4:
        cols = n
        rows = 1
    elif n <= 8:
        cols = 8 if n == 8 else min(n, 8)
        rows = 1
    elif n <= 12 and lff_count > 0:
        cols = 4
        rows = 3
    elif n <= 16:
        cols = 8
        rows = 2
    elif n <= 24:
        cols = 12
        rows = 2
    else:
        cols = min(n, 12)
        rows = max(1, (n + cols - 1) // cols)

    gap = 4
    pad_top, pad_bot = 30, 14
    grid_w = cols * (bw + gap) - gap
    min_panel_w = 380
    svg_w = max(grid_w + 28, min_panel_w)
    pad_x = (svg_w - grid_w) // 2
    svg_h = pad_top + rows * (bh + gap) - gap + pad_bot

    bay_svgs = []
    _empty_seq = target_total

    for i, d in enumerate(sorted_bays):
        bs = d.get("bay_slot")
        if bs is None:
            _empty_seq += 1
            bs = _empty_seq

        lbl = str(bs)

        # Calculate grid cell cx, cy
        if is_10_sff_grid and isinstance(bs, int) and 0 <= bs < 10:
            grid_col = bs // 2   # 0..4
            grid_row = bs % 2    # 0 for top row (0,2,4,6,8), 1 for bottom row (1,3,5,7,9)
        elif isinstance(bs, int) and bs >= 0 and cols > 0:
            if rows > 1 and n in (16, 24) and bs < cols * rows:
                grid_col = bs // rows
                grid_row = bs % rows
            else:
                grid_col = bs % cols
                grid_row = bs // cols
        else:
            grid_col = i % cols
            grid_row = i // cols

        cx = pad_x + grid_col * (bw + gap)
        cy = pad_top + grid_row * (bh + gap)

        pop  = d.get("populated", True)
        is_nv = _is_nvme_d(d)
        is_edsff = d.get("is_edsff", False)
        proto_up = str(d.get("protocol", "")).upper()
        media_up = str(d.get("media_type", "")).upper()
        is_hdd = "HDD" in media_up or "HARD" in media_up or "MAGNETIC" in media_up

        if not pop or not d.get("model"):
            fill = "var(--chassis-empty-fill, #1e293b)"
            stroke = "var(--chassis-empty-stroke, #334155)"
            tc = "var(--chassis-empty-text, #64748b)"
            face = "var(--chassis-empty-face, #243b55)"
            led_c = "#475569"
            tag_str = "EMPTY"
        elif is_edsff:
            fill, stroke, tc, face, led_c = "#c2410c", "#f97316", "#fed7aa", "#ea580c", "#fb923c"
            tag_str = "EDSFF"
        elif is_nv:
            fill, stroke, tc, face, led_c = "#166534", "#16a34a", "#86efac", "#15803d", "#4ade80"
            tag_str = "NVMe"
        elif is_hdd:
            fill, stroke, tc, face, led_c = "#075985", "#0ea5e9", "#bae6fd", "#0369a1", "#38bdf8"
            tag_str = "HDD"
        else:
            fill, stroke, tc, face, led_c = "#3730a3", "#6366f1", "#c7d2fe", "#4338ca", "#a78bfa"
            tag_str = "SATA" if "SATA" in proto_up else "SAS" if "SAS" in proto_up else "SSD"

        if pop and d.get("model"):
            model = d.get("model", "")
            pn    = d.get("product_id", "") or "N/A"
            cap   = d.get("capacity_gb", 0)
            proto = d.get("protocol", "")
            ctrl  = d.get("attached_ctrl_name", "") or d.get("controller_id", "Storage Subsystem")
            hlth  = d.get("drive_health", "OK") or "OK"
            end   = d.get("endurance_remaining_pct", "N/A")
            end_s = f"{end}%" if isinstance(end, (int, float)) else str(end)
            gen   = d.get("pcie_gen", "")
            lanes = d.get("pcie_lanes_in_use") or d.get("pcie_max_lanes")
            lane_s= f" {gen}x{lanes}" if (gen or lanes) else ""

            tip = _h(f"Slot {lbl}: {model} ({cap}GB {proto}{lane_s}) · PN: {pn} · Ctrl: {ctrl} · Health: {hlth} · Endurance: {end_s}".strip())
            vsan_badge = "vSAN Certified" if is_nv and cap >= 1600 else "vSAN OSA / Compatible" if pop else "N/A"
        else:
            model = "Empty Slot"
            pn    = "N/A"
            cap   = 0
            proto = "N/A"
            ctrl  = "N/A"
            hlth  = "N/A"
            end_s = "N/A"
            tip   = f"Slot {lbl}: Empty Slot / Blank Filler"
            vsan_badge = "Unpopulated"

        pos_desc = ""
        if is_10_sff_grid and isinstance(bs, int) and 0 <= bs < 10:
            col_name = ["Left", "Col 2", "Col 3", "Col 4", "Right"][bs // 2]
            row_name = "Top" if bs % 2 == 0 else "Bottom"
            pos_desc = f"{row_name} {col_name}"
        else:
            pos_desc = pos_label or "Front"

        face_h = 7
        led_r  = max(2, bw // 10)
        led_cx = cx + bw - led_r - 3
        led_cy = cy + face_h // 2 + 2

        bay_svgs.append(
            f'<g class="chassis-bay-slot" '
            f'data-slot="{_h(lbl)}" '
            f'data-pos="{_h(pos_desc)}" '
            f'data-model="{_h(model)}" '
            f'data-pn="{_h(pn)}" '
            f'data-cap="{cap}" '
            f'data-proto="{_h(proto or tag_str)}" '
            f'data-ctrl="{_h(ctrl)}" '
            f'data-health="{_h(hlth)}" '
            f'data-endurance="{_h(end_s)}" '
            f'data-vsan="{_h(vsan_badge)}" '
            f'onmouseover="if(typeof showChassisBayInfo===\'function\')showChassisBayInfo(this)" '
            f'onclick="if(typeof showChassisBayInfo===\'function\')showChassisBayInfo(this)" '
            f'style="cursor:pointer">'
            f'<title>{tip}</title>'
            f'<rect x="{cx}" y="{cy}" width="{bw}" height="{bh}" rx="2" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
            f'<rect x="{cx+1}" y="{cy+1}" width="{bw-2}" height="{face_h}" rx="1" fill="{face}"/>'
            f'<circle cx="{led_cx}" cy="{led_cy}" r="{led_r}" fill="{led_c}"/>'
            f'<text x="{cx+bw//2}" y="{cy+bh-14}" text-anchor="middle" '
            f'fill="{tc}" font-size="7" font-family="monospace" font-weight="bold">{tag_str}</text>'
            f'<text x="{cx+bw//2}" y="{cy+bh-4}" text-anchor="middle" '
            f'fill="{tc}" font-size="8.5" font-family="monospace" font-weight="bold">{lbl}</text>'
            f'</g>'
        )

    title_str = chassis_title or (f"{str(pos_label or '').upper()} CHASSIS PANEL" if pos_label else "CHASSIS FRONT PANEL")
    header_pad = 12
    plbl_svg = (
        f'<text x="{header_pad}" y="18" fill="var(--text-muted, #94a3b8)" font-size="9.5" '
        f'font-family="monospace" font-weight="bold">{_h(str(title_str or "").upper())}</text>'
    )
    ff_svg = (
        f'<text x="{svg_w - header_pad}" y="18" text-anchor="end" fill="var(--text-muted, #64748b)" '
        f'font-size="9" font-family="monospace">{ff_tag}</text>'
    )

    return (
        f'<div class="chassis-diagram-container" style="margin-bottom:1rem">'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{svg_w}" height="{svg_h}" '
        f'viewBox="0 0 {svg_w} {svg_h}" '
        f'style="max-width:100%;display:block;background:var(--chassis-bg, #0f172a);'
        f'border:1px solid var(--chassis-border, #334155);'
        f'border-radius:6px;padding:2px">'
        f'{plbl_svg}{ff_svg}'
        + "".join(bay_svgs) +
        '</svg>'
        '<div id="chassis-bay-detail-panel" style="background:var(--sec-muted-bg, #1e293b);'
        'border:1px solid var(--chassis-border, #334155);border-radius:6px;'
        'padding:.65rem .85rem;margin-top:.4rem;font-size:.84rem;'
        'min-height:42px;display:flex;align-items:center;">'
        '<div id="chassis-bay-detail-content" style="color:var(--text-muted, #94a3b8)">'
        '💡 <strong>Hover or click any drive slot above</strong> to inspect exact drive model, part number, capacity, attached controller, health, and vSAN status.'
        '</div></div></div>'
    )

def _pcie_info_html(drive: dict) -> str:
    """Render a small PCIe gen / lane-width / PCI ID sub-line for the Type/Bus cell."""
    lanes = drive.get("pcie_lanes_in_use")
    gen   = drive.get("pcie_gen") or ""
    proto = str(drive.get("protocol") or "")
    pci_quad = drive.get("pci_quad") or (f"{drive.get('vendor_id')}:{drive.get('device_id')}" if drive.get("vendor_id") and drive.get("device_id") else "")
    if "NVME" not in proto.upper() and "PCIE" not in proto.upper() and not pci_quad:
        return ""
    gen_str = gen.replace("Gen", "PCIe Gen") if gen else ""
    lane_html = ""
    if lanes == 1:
        lane_html = f"<span style='color:var(--danger);font-weight:700'>x{lanes} ⚠️</span>"
    elif lanes == 2:
        lane_html = f"<span style='color:var(--warning)'>x{lanes}</span>"
    elif lanes is not None:
        lane_html = f"x{lanes}"
    pci_html = f"<code style='font-size:.73rem;background:var(--pci-bg);color:var(--pci-color);padding:1px 4px;border-radius:3px;'>PCI: {_h(pci_quad)}</code>" if pci_quad else ""
    parts = [p for p in [gen_str, lane_html, pci_html] if p]
    return f"<br><small>{'&nbsp;'.join(parts)}</small>" if parts else ""

def _trimode_banner_html(ctrl: dict) -> str:
    if not ctrl.get("is_trimode"):
        return ""
    protos   = " / ".join(ctrl.get("device_protocols") or []) or "N/A"
    fw       = ctrl.get("ctrl_firmware") or "N/A"
    gen      = ctrl.get("pcie_gen") or ""
    lanes    = ctrl.get("pcie_lanes_in_use") or ctrl.get("pcie_max_lanes")
    pcie_str = " ".join(p for p in [gen, f"x{lanes}" if lanes else ""] if p) or "N/A"
    return (
        "<div class='alert alert-danger' style='margin-bottom:.75rem'>"
        "🔴 <strong>Tri-Mode RAID Controller</strong> — NVMe drives attached to this "
        "controller are <strong>NOT supported for vSAN</strong>. "
        "NVMe must be directly CPU-attached or behind a native NVMe HBA. "
        f"<a href='{KB_TRIMODE}' target='_blank' style='color:var(--tint-danger-text,#991b1b);font-weight:600'>"
        "KB314305 ↗</a>"
        f"<br><small style='color:var(--tint-danger-text,#991b1b);opacity:.85'>"
        f"Supported Protocols: <strong>{_h(protos)}</strong>&emsp;"
        f"PCIe: <strong>{_h(pcie_str)}</strong>&emsp;"
        f"Firmware: <code style='font-size:.8rem'>{_h(fw)}</code>"
        f"</small></div>"
    )

def _software_raid_banner_html(ctrl: dict) -> str:
    if not ctrl.get("is_software_raid"):
        return ""
    ctrl_name = str(ctrl.get("name") or ctrl.get("ctrl_model") or "Software RAID Controller").strip()
    ctrl_name_up = ctrl_name.upper()

    if any(k in ctrl_name_up for k in ["PERC S", "S100", "S110", "S120", "S130", "S140", "S150", "S160"]):
        bypass_steps = (
            "<strong>Dell PowerEdge BIOS Bypass Steps:</strong>"
            "<ol style='margin:4px 0 0 1.2rem;padding:0'>"
            "<li>Reboot into System Setup (F2) &rarr; <em>Device Settings</em> &rarr; <em>Dell PERC S-series Configuration Utility</em> &rarr; Delete any existing Virtual Disks.</li>"
            "<li>Go to <em>System BIOS Settings</em> &rarr; <em>SATA Settings</em> &rarr; Change <strong>Embedded SATA</strong> from <code>RAID Mode</code> to <code>AHCI Mode</code> (or <code>Off</code>).</li>"
            "<li>Go to <em>System BIOS Settings</em> &rarr; <em>NVMe Settings</em> (or <em>Integrated Devices</em>) &rarr; Set NVMe mode to <code>Non-RAID / Pass-Through</code>.</li>"
            "<li>Ensure <strong>Intel VMD</strong> is <code>Disabled</code> for native ESXi NVMe pass-through driver binding.</li>"
            "</ol>"
        )
    elif any(k in ctrl_name_up for k in ["DYNAMIC SMART ARRAY", "SR100I", "B110I", "B120I", "B140I", "B320I"]):
        bypass_steps = (
            "<strong>HPE ProLiant BIOS Bypass Steps:</strong>"
            "<ol style='margin:4px 0 0 1.2rem;padding:0'>"
            "<li>Reboot into UEFI System Utilities (F9) &rarr; <em>System Configuration</em> &rarr; <em>BIOS/Platform Configuration (RBSU)</em>.</li>"
            "<li>Go to <em>Storage Options</em> &rarr; <em>SATA Controller Options</em> &rarr; Set <strong>Embedded SATA Configuration</strong> to <code>Enable SATA AHCI Support</code> (disables Dynamic Smart Array software RAID).</li>"
            "<li>Ensure direct NVMe PCIe slots are enabled for native OS pass-through.</li>"
            "</ol>"
        )
    else:
        bypass_steps = (
            "<strong>BIOS Bypass Recommendation:</strong> "
            "Enter System BIOS Setup and configure Embedded Storage / SATA controller from <code>RAID Mode</code> to <code>AHCI Mode</code> "
            "or <code>Disabled</code>, delete software RAID virtual disks, and verify NVMe drive pass-through is active."
        )

    return (
        "<div class='alert alert-warning' style='margin-bottom:.75rem'>"
        f"⚠️ <strong>Host Software RAID Controller Detected: {_h(ctrl_name)}</strong> — "
        "VMware ESXi does not support host software RAID. NVMe and SATA drives connected through this controller "
        "must be switched to native AHCI / PCIe pass-through in BIOS before ESXi installation.<br>"
        f"<div style='margin-top:6px;font-size:.84rem;'>{bypass_steps}</div>"
        "<small style='display:block;margin-top:6px;opacity:.9'>"
        "💡 <em>Once bypassed in BIOS, direct-attached NVMe drives will be claimed directly by ESXi's native <code>nvme-pcie</code> driver for vSAN ESA.</em>"
        "</small></div>"
    )

def _render_ctrl_drives(ctrl, json_hcl=None, csv_db=None):
    rows = ""
    for drive in ctrl.get("drives", []):
        if not drive.get("populated", True):   # skip empty bay placeholders
            continue
        end_val = drive.get("endurance_remaining_pct", "N/A")
        end_badge = (
            f"<b>{end_val}%</b>"
            if isinstance(end_val, (int, float))
            else f"<span>{end_val}</span>"
        )
        eval_hcl = evaluate_drive_hcl_tier(drive, json_hcl=json_hcl, csv_db=csv_db)
        _proto_up = str(drive.get("protocol") or "").upper()
        _is_nvme_drive = "NVME" in _proto_up or "PCIE" in _proto_up or drive.get("is_edsff") or drive.get("is_nvme")

        vsan_badge = eval_hcl["status_badge"]
        hcl_str = eval_hcl["hcl_str"]

        _unique_item = lookup_unique_hcl_device(
            vid=drive.get("vendor_id", ""),
            did=drive.get("device_id", ""),
            svid=drive.get("subsystem_vendor_id", ""),
            ssid=drive.get("subsystem_id", ""),
            json_hcl=json_hcl,
            model_name=drive.get("model", ""),
        )
        _pid = _unique_item.get("product_id", "") if _unique_item else ""
        _prog = _unique_item.get("hcl_program", "") if _unique_item else ""
        if not _prog:
            _prog = "hdd" if "HDD" in str(drive.get("media_type", "")).upper() else "ssd"

        bcg_ssd = BCGLinkGenerator.prefer_device_or_search(
            _pid, _prog,
            BCGLinkGenerator.storage_exact,
            drive.get("model", ""), drive.get("product_id", ""),
            drive.get("vendor_id", ""), drive.get("device_id", ""),
            drive.get("subsystem_vendor_id", ""), drive.get("subsystem_id", ""),
            media_type=drive.get("media_type", "")
        )
        pcie_html = _pcie_info_html(drive)
        _drive_model = str(drive.get("model", "") or "")
        _drive_fw = str(drive.get("firmware", "N/A") or "N/A")
        _has_defect = bool(check_defective_drive_firmware(_drive_model, _drive_fw))
        _fw_cell = (
            evaluate_drive_fw(
                _drive_model,
                _drive_fw,
                hcl_data=json_hcl,
                vid=drive.get("vendor_id", ""),
                did=drive.get("device_id", ""),
                svid=drive.get("subsystem_vendor_id", ""),
                ssid=drive.get("subsystem_id", ""),
            )
            if (_is_nvme_drive or _has_defect)
            else f"<code>{_drive_fw}</code>"
        )

        # Bay cell: slot number + Front/Rear/Internal position
        _bay_s   = drive.get("bay_slot")
        _bay_pos = str(drive.get("bay_position") or "")
        _pos_style = (
            "color:#dc2626" if _bay_pos == "Rear"
            else "color:var(--text-muted)"
        )
        _bay_cell = (
            f"<b style='font-size:.95rem'>{_bay_s}</b>"
            f"<br><small style='{_pos_style}'>{_h(_bay_pos)}</small>"
            if _bay_s is not None
            else "<span style='color:var(--text-muted)'>—</span>"
        )

        # Connector sub-line in Type/Bus: show U.2 / U.3 / M.2 / EDSFF
        _conn = str(drive.get("nvme_connector") or "")
        _conn_tag = ""
        if _conn:
            _conn_color = (
                "var(--primary)" if _conn in ("U.2", "U.3", "U.3 slot")
                else "var(--text-muted)" if _conn == "M.2"
                else "#f97316"   # orange for EDSFF variants
            )
            _conn_tag = (
                f"<br><small style='color:{_conn_color};font-weight:600'>"
                f"{_h(_conn)}</small>"
            )
        elif drive.get("form_factor_label"):
            _conn_tag = (
                f"<br><small style='color:var(--text-muted)'>"
                f"{_h(drive['form_factor_label'])}</small>"
            )

        _dhealth = str(drive.get("drive_health") or "").strip()
        _health_cell = (
            "<span class='badge success'>OK</span>" if _dhealth.upper() == "OK"
            else f"<span class='badge warning'>{_h(_dhealth)}</span>" if _dhealth
            else "<span style='color:var(--text-muted)'>—</span>"
        )

        temp_c = drive.get("temperature_c")
        poh = drive.get("power_on_hours")
        pred_fail = drive.get("failure_predicted")
        tbw = drive.get("tbw_written") if drive.get("tbw_written") is not None else drive.get("tbw")
        unsafe_sd = drive.get("unsafe_shutdowns")

        smart_tags = []
        if pred_fail:
            smart_tags.append("<span class='badge danger' style='font-size:.7rem;'>🔴 PREDICTED FAILURE</span>")
        if temp_c is not None and isinstance(temp_c, (int, float)):
            t_cls = "danger" if temp_c >= 70 else ("warning" if temp_c >= 65 else "info")
            smart_tags.append(f"<span class='badge {t_cls}' style='font-size:.7rem;'>🌡️ {int(temp_c)}°C</span>")
        if poh is not None and isinstance(poh, (int, float)):
            smart_tags.append(f"<span class='badge info' style='font-size:.7rem;'>⏱️ {int(poh):,}h</span>")
        if tbw is not None and isinstance(tbw, (int, float)):
            smart_tags.append(f"<span class='badge info' style='font-size:.7rem;'>💾 {float(tbw):.1f} TBW</span>")
        if unsafe_sd is not None and isinstance(unsafe_sd, (int, float)) and unsafe_sd > 0:
            sd_cls = "warning" if unsafe_sd >= 50 else "info"
            smart_tags.append(f"<span class='badge {sd_cls}' style='font-size:.7rem;' title='Unsafe Shutdown Count'>⚡ {int(unsafe_sd)} shutdowns</span>")
        if (isinstance(poh, (int, float)) and poh >= 30000) or (isinstance(unsafe_sd, (int, float)) and unsafe_sd >= 50):
            smart_tags.append("<span class='badge warning' style='font-size:.7rem;' title='High Power-On Hours (>30,000h) or Unsafe Shutdowns (>=50)'>🟡 Aging / Wear Alert</span>")

        smart_html = f"<br>{' '.join(smart_tags)}" if smart_tags else ""

        rows += (
            f"<tr>"
            f"<td style='text-align:center;white-space:nowrap'>{_bay_cell}</td>"
            f"<td><strong>{_h(drive.get('model','Unknown'))}</strong>"
            f"<br><small style='color:var(--text-muted)'>PN: {_h(drive.get('product_id','N/A'))}</small>{hcl_str}{smart_html}</td>"
            f"<td>{_h(drive.get('media_type','?'))} / {_h(drive.get('protocol','?'))}{_conn_tag}{pcie_html}</td>"
            f"<td><b>{drive.get('capacity_gb',0)} GB</b></td>"
            f"<td>{_fw_cell}</td>"
            f"<td>{end_badge}</td><td>{_health_cell}</td><td>{vsan_badge}</td>"
            f"<td><a href='{bcg_ssd}' target='_blank' class='btn-link'>BCG ↗</a></td></tr>"
        )
    return rows or '<tr><td colspan="9">No drives found.</td></tr>'

def _ctrl_meta_html(ctrl: dict, hcl_data: Optional[dict] = None) -> str:
    """Small subtitle line for a storage controller card showing firmware, protocols, PCI quad, recommended driver, and BCG links."""
    parts = []
    fw = ctrl.get("ctrl_firmware") or ""
    if fw and fw != "N/A":
        parts.append(f"FW: <code style='font-size:.8rem'>{_h(str(fw))}</code>")
    protos = ctrl.get("device_protocols") or []
    if protos:
        parts.append("Protocols: " + " / ".join(_h(p) for p in protos))
    gen   = ctrl.get("pcie_gen") or ""
    lanes = ctrl.get("pcie_lanes_in_use") or ctrl.get("pcie_max_lanes")
    pcie_tokens = " ".join(p for p in [_h(gen), f"x{lanes}" if lanes else ""] if p)
    if pcie_tokens:
        parts.append(f"PCIe: {pcie_tokens}")

    cvid = ctrl.get("vendor_id", "")
    cdid = ctrl.get("device_id", "")
    csvid = ctrl.get("subsystem_vendor_id", "")
    cssid = ctrl.get("subsystem_id", "")
    ctrl_name = ctrl.get("name", "") or ctrl.get("ctrl_model", "") or "Storage Controller"

    pci_eval = None
    if cvid and cdid:
        pci_eval = evaluate_pci_compatibility(cvid, cdid, csvid, cssid, ctrl_name, fw, hcl_data=hcl_data)

    cpci_quad = ctrl.get("pci_quad") or (f"{cvid}:{cdid}:{csvid}:{cssid}" if (cvid and cdid and csvid and cssid) else f"{cvid}:{cdid}" if (cvid and cdid) else "")
    if cpci_quad:
        parts.append(f"<code style='font-size:.76rem;background:var(--pci-bg);color:var(--pci-color);padding:1px 4px;border-radius:3px;'>PCI: {_h(cpci_quad)}</code>")

    if pci_eval:
        if pci_eval.get("badge"):
            parts.append(pci_eval["badge"])
        if pci_eval.get("recommended_driver"):
            parts.append(f"Driver (9.1): <code>{_h(pci_eval['recommended_driver'])}</code>")
        if pci_eval.get("fw_badge"):
            parts.append(pci_eval["fw_badge"])

    if ctrl.get("bbu_badge"):
        parts.append(ctrl["bbu_badge"])

    vols = ctrl.get("volumes") or []
    if vols:
        vol_strs = []
        for v in vols:
            boot_icon = " 🚀 [Boot]" if v.get("bootable") else ""
            vol_strs.append(f"<b>{_h(v.get('name'))}</b> ({_h(v.get('volume_type'))}, {v.get('capacity_gb')} GB, {_h(v.get('health'))}{boot_icon})")
        parts.append(f"Virtual Disks: {', '.join(vol_strs)}")

    _ctrl_item = lookup_unique_hcl_device(
        vid=cvid, did=cdid, svid=csvid, ssid=cssid, json_hcl=hcl_data, model_name=ctrl_name
    )
    _ctrl_pid = _ctrl_item.get("product_id", "") if _ctrl_item else ""
    _ctrl_prog = _ctrl_item.get("hcl_program", "") if _ctrl_item else "vsanio"

    if _ctrl_pid:
        bcg_vsan_url = BCGLinkGenerator.device_detail(_ctrl_pid, _ctrl_prog)
        bcg_io_url   = BCGLinkGenerator.device_detail(_ctrl_pid, "io")
    elif cvid and cdid:
        bcg_vsan_url = BCGLinkGenerator.pci_exact(cvid, cdid, csvid, cssid, program="vsanio")
        bcg_io_url   = BCGLinkGenerator.pci_exact(cvid, cdid, csvid, cssid, program="io")
    elif ctrl_name and str(ctrl_name).upper() not in ("N/A", "UNKNOWN", "STORAGE CONTROLLER"):
        bcg_vsan_url = f"https://compatibilityguide.broadcom.com/search?program=vsanio&persona=live&keyword={urllib.parse.quote(ctrl_name)}"
        bcg_io_url   = BCGLinkGenerator.io_device_fw(ctrl_name, fw)
    else:
        bcg_vsan_url = ""
        bcg_io_url   = ""

    if bcg_vsan_url:
        parts.append(f"<a href='{bcg_vsan_url}' target='_blank' class='btn-link' style='font-size:.8rem'>vSAN HBA BCG ↗</a>")
    if bcg_io_url:
        parts.append(f"<a href='{bcg_io_url}' target='_blank' class='btn-link' style='font-size:.78rem;opacity:.8'>I/O BCG ↗</a>")

    if not parts:
        return ""
    return (
        "<p style='font-size:.82rem;color:var(--text-muted);margin:-.4rem 0 .6rem'>"
        + "&emsp;".join(parts)
        + "</p>"
    )


def build_dimm_slot_diagram(memory_subsystem: dict, cpu_summary: Optional[dict] = None) -> str:
    """Render a visual Motherboard Physical DIMM Slot & Channel Topology grid.

    Renders DIMM slots grouped by CPU Socket and Channel with color coding:
      • Populated OK: Green pill with capacity/speed
      • Failed/Degraded: Red pill with warning
      • Unpopulated: Slate dashed outline pill
    """
    dimm_list = memory_subsystem.get("dimm_list") or []
    if not dimm_list:
        return ""

    cpu_summary = cpu_summary or {}
    cpu_count = cpu_summary.get("count", 1)

    # Group DIMMs by socket (1..N) and channel (A, B, C...)
    sockets = {}
    for d in dimm_list:
        s_id = d.get("socket")
        if not s_id or s_id == "Unknown":
            loc = str(d.get("slot_locator") or d.get("id") or "").upper()
            m_s = re.search(r"(?:PROC|CPU|SOCKET|P)[._\s-]*([1-4])", loc)
            s_id = int(m_s.group(1)) if m_s else 1

        c_id = d.get("channel") or "A"
        sockets.setdefault(s_id, {}).setdefault(c_id, []).append(d)

    if not sockets:
        return ""

    html_parts = [
        "<div class='card' style='margin:1rem 0;border:1px solid var(--border);border-radius:6px;background:var(--card)'>",
        "  <div class='card-block' style='padding:.85rem 1.1rem'>",
        "    <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:.75rem'>",
        "      <h4 class='card-title' style='margin:0;font-size:.95rem;display:flex;align-items:center;gap:.4rem'>",
        "        <span>🧠</span> Physical Motherboard DIMM Slot & Channel Map",
        "      </h4>",
        "      <span style='font-size:.78rem;color:var(--text-muted)'>Legend: "
        "<span style='color:var(--success, #16a34a);font-weight:600'>● Populated (OK)</span> &nbsp; "
        "<span style='color:var(--danger, #dc2626);font-weight:600'>● Degraded/Error</span> &nbsp; "
        "<span style='color:var(--text-muted, #94a3b8);font-weight:500'>○ Empty Slot</span></span>",
        "    </div>",
        "    <div style='display:grid;grid-template-columns:repeat(auto-fit, minmax(320px, 1fr));gap:1rem'>"
    ]

    for sock_num in sorted(sockets.keys()):
        chans = sockets[sock_num]
        total_dimms = sum(len(dimms) for dimms in chans.values())
        sock_ram_gb = sum(
            int(d.get("capacity_gb") or 0)
            for dimms in chans.values()
            for d in dimms
            if d.get("populated", True)
        )

        html_parts.append(
            f"      <div style='background:var(--ms-sock-bg, var(--code-bg, #f8fafc));border:1px solid var(--border);border-radius:6px;padding:.75rem'>"
            f"        <div style='font-weight:600;font-size:.85rem;margin-bottom:.5rem;display:flex;justify-content:space-between;color:var(--text)'>"
            f"          <span>CPU Socket {sock_num}</span>"
            f"          <span style='font-size:.78rem;color:var(--text-muted)'>{total_dimms} DIMMs ({sock_ram_gb} GB)</span>"
            f"        </div>"
            f"        <div style='display:grid;grid-template-columns:repeat(auto-fill, minmax(140px, 1fr));gap:.4rem'>"
        )

        for ch_num in sorted(chans.keys()):
            dimm_items = chans[ch_num]
            for d in dimm_items:
                loc = _h(d.get("slot_locator") or d.get("id") or f"Ch {ch_num}")
                cap = d.get("capacity_gb", 0)
                mtype = _h(d.get("memory_type") or "DRAM")
                speed = d.get("speed_mhz") or ""
                health = str(d.get("health") or "OK").upper()
                is_pop = d.get("populated", True) and cap > 0

                if not is_pop:
                    style = "background:var(--ms-empty-bg, transparent);border:1px dashed var(--ms-empty-border, var(--border));color:var(--text-muted);opacity:.8"
                    status_dot = "<span style='color:var(--text-muted)'>○</span>"
                    badge_text = f"{loc}: Empty"
                elif health in ("OK", "GOOD"):
                    style = "background:var(--ms-slot1-bg, rgba(22,163,74,0.15));border:1px solid var(--ms-slot1-border, #16a34a);color:var(--text)"
                    status_dot = "<span style='color:var(--success, #16a34a)'>●</span>"
                    speed_str = f" @ {speed}MHz" if speed else ""
                    badge_text = f"{loc}: <strong>{cap}GB</strong> {mtype}{speed_str}"
                else:
                    style = "background:var(--ms-crit-bg, rgba(220,38,38,0.15));border:1px solid var(--ms-crit-border, #dc2626);color:var(--ms-crit-color, var(--danger))"
                    status_dot = "<span style='color:var(--danger, #dc2626)'>⚠️</span>"
                    badge_text = f"{loc}: <strong>{cap}GB</strong> ({health})"

                html_parts.append(
                    f"          <div style='padding:.35rem .5rem;border-radius:4px;font-size:.76rem;{style};display:flex;align-items:center;gap:.35rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap' "
                    f"title='Locator: {loc}\nCapacity: {cap} GB\nHealth: {health}\nChannel: {ch_num}\nSocket: {sock_num}'>"
                    f"{status_dot} <span>{badge_text}</span>"
                    f"          </div>"
                )

        html_parts.append("        </div>")  # end channel grid
        html_parts.append("      </div>")      # end socket card

    html_parts.append("    </div>")  # end main sockets grid
    html_parts.append("  </div>")    # end card-block
    html_parts.append("</div>")      # end card
    return "\n".join(html_parts)


def render_switch_chassis_svg(width: int = 120, height: int = 56) -> str:
    """Render a Modular Chassis Switch SVG (e.g. Cisco Nexus 7000/7700, Arista 7500/7800)."""
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 120 56" fill="none" xmlns="http://www.w3.org/2000/svg" style="display:inline-block;vertical-align:middle">'
        f'<rect x="2" y="2" width="116" height="52" rx="3" fill="var(--card, #1e293b)" stroke="var(--border, #475569)" stroke-width="1.5"/>'
        f'<!-- Left Rack Ear -->'
        f'<rect x="2" y="6" width="6" height="44" rx="1" fill="var(--border, #64748b)"/>'
        f'<circle cx="5" cy="12" r="1.5" fill="var(--card, #0f172a)"/>'
        f'<circle cx="5" cy="44" r="1.5" fill="var(--card, #0f172a)"/>'
        f'<!-- Right Rack Ear -->'
        f'<rect x="112" y="6" width="6" height="44" rx="1" fill="var(--border, #64748b)"/>'
        f'<circle cx="115" cy="12" r="1.5" fill="var(--card, #0f172a)"/>'
        f'<circle cx="115" cy="44" r="1.5" fill="var(--card, #0f172a)"/>'
        f'<!-- Supervisors / Slot 1 & 2 -->'
        f'<rect x="12" y="6" width="96" height="8" rx="1" fill="var(--code-bg, #334155)" stroke="var(--border, #475569)" stroke-width="0.75"/>'
        f'<circle cx="16" cy="10" r="1.5" fill="#22c55e"/><circle cx="21" cy="10" r="1.5" fill="#3b82f6"/>'
        f'<rect x="28" y="8" width="12" height="4" rx="0.5" fill="var(--border, #64748b)"/>'
        f'<rect x="44" y="8" width="12" height="4" rx="0.5" fill="var(--border, #64748b)"/>'
        f'<!-- Line Card Slot 1 -->'
        f'<rect x="12" y="16" width="96" height="8" rx="1" fill="var(--code-bg, #334155)" stroke="var(--border, #475569)" stroke-width="0.75"/>'
        f'<circle cx="16" cy="20" r="1.2" fill="#22c55e"/>'
        f'<rect x="22" y="18" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="29" y="18" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="36" y="18" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="43" y="18" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/>'
        f'<rect x="52" y="18" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="59" y="18" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="66" y="18" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="73" y="18" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/>'
        f'<!-- Line Card Slot 2 -->'
        f'<rect x="12" y="26" width="96" height="8" rx="1" fill="var(--code-bg, #334155)" stroke="var(--border, #475569)" stroke-width="0.75"/>'
        f'<circle cx="16" cy="30" r="1.2" fill="#22c55e"/>'
        f'<rect x="22" y="28" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="29" y="28" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="36" y="28" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="43" y="28" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/>'
        f'<rect x="52" y="28" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="59" y="28" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="66" y="28" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="73" y="28" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/>'
        f'<!-- Line Card Slot 3 -->'
        f'<rect x="12" y="36" width="96" height="8" rx="1" fill="var(--code-bg, #334155)" stroke="var(--border, #475569)" stroke-width="0.75"/>'
        f'<circle cx="16" cy="40" r="1.2" fill="#22c55e"/>'
        f'<rect x="22" y="38" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="29" y="38" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="36" y="38" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="43" y="38" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/>'
        f'<rect x="52" y="38" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="59" y="38" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="66" y="38" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="73" y="38" width="5" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/>'
        f'<!-- Dual Power Supplies -->'
        f'<rect x="12" y="46" width="46" height="6" rx="1" fill="var(--card, #1e293b)" stroke="var(--border, #475569)" stroke-width="0.5"/>'
        f'<circle cx="16" cy="49" r="1" fill="#22c55e"/><rect x="20" y="48" width="34" height="2" fill="var(--border, #475569)"/>'
        f'<rect x="62" y="46" width="46" height="6" rx="1" fill="var(--card, #1e293b)" stroke="var(--border, #475569)" stroke-width="0.5"/>'
        f'<circle cx="66" cy="49" r="1" fill="#22c55e"/><rect x="70" y="48" width="34" height="2" fill="var(--border, #475569)"/>'
        f'</svg>'
    )


def render_switch_leaf_svg(width: int = 120, height: int = 26) -> str:
    """Render a 1RU Fixed Leaf Switch SVG (e.g. Cisco Nexus 9300, Arista 7050/7280R, Dell S-Series)."""
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 120 26" fill="none" xmlns="http://www.w3.org/2000/svg" style="display:inline-block;vertical-align:middle">'
        f'<rect x="2" y="2" width="116" height="22" rx="2" fill="var(--card, #1e293b)" stroke="var(--border, #475569)" stroke-width="1.2"/>'
        f'<!-- Left Rack Ear -->'
        f'<rect x="2" y="4" width="5" height="18" rx="1" fill="var(--border, #64748b)"/>'
        f'<circle cx="4.5" cy="8" r="1.2" fill="var(--card, #0f172a)"/>'
        f'<circle cx="4.5" cy="18" r="1.2" fill="var(--card, #0f172a)"/>'
        f'<!-- Right Rack Ear -->'
        f'<rect x="113" y="4" width="5" height="18" rx="1" fill="var(--border, #64748b)"/>'
        f'<circle cx="115.5" cy="8" r="1.2" fill="var(--card, #0f172a)"/>'
        f'<circle cx="115.5" cy="18" r="1.2" fill="var(--card, #0f172a)"/>'
        f'<!-- Status LEDs -->'
        f'<circle cx="12" cy="9" r="1.5" fill="#22c55e"/>'
        f'<circle cx="12" cy="17" r="1.5" fill="#3b82f6"/>'
        f'<!-- 10G/25G SFP/Port Block 1 -->'
        f'<rect x="18" y="6" width="38" height="14" rx="1" fill="var(--code-bg, #334155)" stroke="var(--border, #475569)" stroke-width="0.5"/>'
        f'<rect x="20" y="8" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="25" y="8" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="30" y="8" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="35" y="8" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="40" y="8" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="45" y="8" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/>'
        f'<rect x="20" y="14" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="25" y="14" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="30" y="14" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="35" y="14" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="40" y="14" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="45" y="14" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/>'
        f'<circle cx="51" cy="9" r="1" fill="#22c55e"/><circle cx="51" cy="17" r="1" fill="#22c55e"/>'
        f'<!-- Port Block 2 -->'
        f'<rect x="58" y="6" width="38" height="14" rx="1" fill="var(--code-bg, #334155)" stroke="var(--border, #475569)" stroke-width="0.5"/>'
        f'<rect x="60" y="8" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="65" y="8" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="70" y="8" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="75" y="8" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="80" y="8" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="85" y="8" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/>'
        f'<rect x="60" y="14" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="65" y="14" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="70" y="14" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="75" y="14" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="80" y="14" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/><rect x="85" y="14" width="4" height="4" rx="0.5" fill="var(--primary, #3b82f6)"/>'
        f'<circle cx="91" cy="9" r="1" fill="#22c55e"/><circle cx="91" cy="17" r="1" fill="#22c55e"/>'
        f'<!-- 40G/100G QSFP Uplinks -->'
        f'<rect x="98" y="7" width="6" height="12" rx="0.75" fill="var(--border, #475569)" stroke="var(--primary, #3b82f6)" stroke-width="0.75"/>'
        f'<rect x="105" y="7" width="6" height="12" rx="0.75" fill="var(--border, #475569)" stroke="var(--primary, #3b82f6)" stroke-width="0.75"/>'
        f'</svg>'
    )


def match_nic_info_for_lldp(local_iface: str, local_mac: str = "", network_adapters: Optional[list] = None, source: str = "nic") -> dict:
    """Resolve human-friendly NIC model name and link speed for an LLDP connection."""
    src_str = str(source or "nic").lower()
    lif_raw = str(local_iface or "").strip()
    lif_upper = lif_raw.upper()

    if src_str == "mgmt" or any(k in lif_upper for k in ("IDRAC", "ILO", "CIMC", "XCC", "MGMT", "BMC")):
        return {
            "name": "Dedicated BMC Management Port",
            "speed": "1 GbE",
            "label": "Dedicated BMC Mgmt · 1 GbE",
            "is_mgmt": True,
        }

    clean_mac = re.sub(r"[^0-9a-fA-F]", "", str(local_mac or "")).upper()

    # 1. Match by MAC address
    if clean_mac and network_adapters:
        for nic in network_adapters:
            nic_name = str(nic.get("name") or "NIC").strip()
            for p in (nic.get("ports") or []):
                p_mac = re.sub(r"[^0-9a-fA-F]", "", str(p.get("mac_address") or "")).upper()
                if p_mac and p_mac == clean_mac:
                    spd = p.get("current_speed_gbps") or nic.get("speed_gbps") or 0
                    spd_str = f"{spd} GbE" if spd else ""
                    lbl = f"{nic_name} · {spd_str}".strip(" ·")
                    return {"name": nic_name, "speed": spd_str, "label": lbl, "is_mgmt": False}
            for part in (nic.get("vic_virtual_interfaces") or nic.get("npar_partitions") or []):
                part_mac = re.sub(r"[^0-9a-fA-F]", "", str(part.get("mac_address") or "")).upper()
                if part_mac and part_mac == clean_mac:
                    spd = part.get("speed_gbps") or nic.get("speed_gbps") or 0
                    spd_str = f"{spd} GbE" if spd else ""
                    lbl = f"{nic_name} · {spd_str}".strip(" ·")
                    return {"name": nic_name, "speed": spd_str, "label": lbl, "is_mgmt": False}

    # 2. Match by Interface ID prefix / regex
    if lif_upper and network_adapters:
        for nic in network_adapters:
            nic_id = str(nic.get("id") or "").upper().strip()
            nic_name = str(nic.get("name") or "NIC").strip()
            if not nic_id:
                continue

            if lif_upper == nic_id or lif_upper.startswith(nic_id + "-") or lif_upper.startswith(nic_id + "_") or lif_upper.startswith(nic_id + "."):
                port_spd = 0
                for p in (nic.get("ports") or []):
                    pid = str(p.get("port_id") or "").upper().strip()
                    if pid and (lif_upper == pid or lif_upper.startswith(pid + "-") or lif_upper.startswith(pid + "_")):
                        port_spd = p.get("current_speed_gbps") or 0
                        break
                if not port_spd and nic.get("ports"):
                    port_spd = nic["ports"][0].get("current_speed_gbps") or 0

                spd_str = f"{port_spd} GbE" if port_spd else ""
                lbl = f"{nic_name} · {spd_str}".strip(" ·")
                return {"name": nic_name, "speed": spd_str, "label": lbl, "is_mgmt": False}

    return {"name": "", "speed": "", "label": "", "is_mgmt": False}


def build_tor_switch_card(lldp_neighbors: list, network_adapters: Optional[list] = None) -> str:
    """Render a Top-of-Rack (ToR) Switch Topology & LLDP Network Map card."""
    lldp_list = [n for n in (lldp_neighbors or []) if isinstance(n, dict) and (n.get("switch_name") or n.get("chassis_id") or n.get("switch_port"))]
    if not lldp_list:
        return ""

    # Group connections by switch name/chassis ID
    switches = {}
    for n in lldp_list:
        sw_name = n.get("switch_name") or n.get("chassis_id") or "Unknown Switch"
        switches.setdefault(sw_name, []).append(n)

    distinct_switches = [s for s in switches if s != "Unknown Switch"]
    is_dual_homed = len(distinct_switches) >= 2

    redundancy_badge = (
        "<span class='badge success' style='font-size:.78rem;padding:.2rem .5rem'>🟢 ToR Redundancy: Dual-Homed</span>"
        if is_dual_homed else
        "<span class='badge warning' style='font-size:.78rem;padding:.2rem .5rem'>🟡 ToR Redundancy: Single Switch</span>"
    )

    html = [
        "<div class='card' style='margin:1.25rem 0;border:1px solid var(--border);border-radius:6px;background:var(--card)'>",
        "  <div class='card-block' style='padding:.85rem 1.1rem'>",
        "    <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:.75rem;flex-wrap:wrap;gap:.5rem'>",
        "      <h4 class='card-title' style='margin:0;font-size:.95rem;display:flex;align-items:center;gap:.4rem'>",
        "        <span>🔀</span> Top-of-Rack (ToR) Switch Connectivity & LLDP Map",
        "      </h4>",
        f"      <div>{redundancy_badge}</div>",
        "    </div>",
        "    <div style='display:grid;grid-template-columns:repeat(auto-fit, minmax(340px, 1fr));gap:1rem'>"
    ]

    for sw_name, ports in switches.items():
        sample = ports[0]
        ch_id = _h(sample.get("chassis_id") or "N/A")
        mgmt_ip = _h(sample.get("mgmt_ipv4") or "N/A")
        sys_desc = _h(sample.get("system_desc") or "")
        port_names = [p.get("switch_port") for p in ports if p.get("switch_port")]

        info = classify_switch(
            switch_name=sw_name,
            chassis_id=sample.get("chassis_id", ""),
            system_desc=sample.get("system_desc", ""),
            port_names=port_names,
        )

        svg_graphic = render_switch_chassis_svg(110, 48) if info["is_chassis"] else render_switch_leaf_svg(110, 24)

        html.append(
            f"      <div style='background:var(--code-bg);border:1px solid var(--border);border-radius:6px;padding:.85rem'>"
            f"        <div style='display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:.4rem;gap:.5rem'>"
            f"          <div>"
            f"            <div style='font-weight:600;font-size:.88rem;color:var(--primary);margin-bottom:.2rem'>🌐 {_h(sw_name)}</div>"
            f"            <div style='font-size:.76rem;color:var(--text-muted)'>"
            f"              <span>Vendor: <b>{_h(info['vendor'])}</b></span> | <span>ASIC: <code>{_h(info['asic_family'])}</code></span>"
            f"            </div>"
            f"          </div>"
            f"          <div style='text-align:right;flex-shrink:0'>{svg_graphic}</div>"
            f"        </div>"
        )

        if info["badges_html"]:
            html.append(f"        <div style='margin-bottom:.5rem;display:flex;gap:.3rem;flex-wrap:wrap'>{info['badges_html']}</div>")

        if info["is_fex"]:
            html.append(
                "        <div class='alert alert-warning' style='font-size:.74rem;padding:.35rem .6rem;margin-bottom:.5rem;border-radius:4px'>"
                "          <b>⚠️ Potential Cisco FEX Detected:</b> FEX units (Nexus 2000) have shared uplink oversubscription without local switching. Dedicated 10/25/100 GbE ToR switching is recommended for VCF 9.1."
                "        </div>"
            )

        html.append(
            f"        <div style='font-size:.76rem;color:var(--text-muted);margin-bottom:.6rem'>"
            f"          <span>Chassis ID: <code>{ch_id}</code></span> | <span>Mgmt IP: <code>{mgmt_ip}</code></span>"
            f"        </div>"
        )
        if sys_desc:
            html.append(f"        <div style='font-size:.74rem;color:var(--text-muted);margin-bottom:.6rem;font-style:italic'>{sys_desc}</div>")

        html.append("        <table style='width:100%;font-size:.78rem;margin:0;border-collapse:collapse'>")
        html.append("          <thead><tr style='border-bottom:1px solid var(--border);text-align:left'>")
        html.append("            <th style='padding:.2rem .4rem'>Local Interface &amp; Adapter</th>")
        html.append("            <th style='padding:.2rem .4rem'>Local MAC</th>")
        html.append("            <th style='padding:.2rem .4rem'>Switch Port</th>")
        html.append("            <th style='padding:.2rem .4rem'>Type</th>")
        html.append("          </tr></thead><tbody>")

        for p in ports:
            lif = _h(p.get("local_iface") or "Port")
            mac = _h(p.get("local_mac") or "N/A")
            swp = _h(p.get("switch_port") or "N/A")
            src = _h(p.get("source") or "nic").upper()
            proto = _h(p.get("protocol") or "LLDP")
            proto_tag = f" &middot; {proto}" if proto != "LLDP" else ""

            nic_match = match_nic_info_for_lldp(p.get("local_iface", ""), p.get("local_mac", ""), network_adapters, p.get("source", "nic"))
            nic_detail_html = f"<div style='font-size:.71rem;color:var(--text-muted);font-weight:400'>{_h(nic_match['label'])}</div>" if nic_match.get("label") else ""

            html.append("          <tr style='border-bottom:1px solid var(--border)'>")
            html.append(f"            <td style='padding:.25rem .4rem'><div style='font-weight:600'>{lif}</div>{nic_detail_html}</td>")
            html.append(f"            <td style='padding:.25rem .4rem'><code>{mac}</code></td>")
            html.append(f"            <td style='padding:.25rem .4rem;color:var(--primary);font-weight:600'>{swp}</td>")
            html.append(f"            <td style='padding:.25rem .4rem'><span class='badge info' style='font-size:.7rem'>{src}{proto_tag}</span></td>")
            html.append("          </tr>")

        html.append("          </tbody></table>")
        html.append("      </div>")  # end switch card

    html.append("    </div>")  # end grid
    html.append("  </div>")    # end card-block
    html.append("</div>")      # end main card
    return "\n".join(html)



