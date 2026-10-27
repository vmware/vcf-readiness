"""
VCF Readiness Tool — Fibre Channel HBA detailed report section builder (Layer D).
"""
from typing import Any, Dict, List, Optional

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.collector.fc_plus import classify_fc_plus
from vcf_hci.constants import normalize_component_manufacturer
from vcf_hci.fc_inventory import fc_adapter_count, normalize_fc_ports
from vcf_hci.hcl import lookup_unique_hcl_device
from vcf_hci.obfuscation import _pii_span
from vcf_hci.report.helpers import _h


def _fc_plus_badge(hba: Dict[str, Any], json_hcl: Optional[Dict[str, Any]] = None) -> str:
    """Return E+ or M+ badge classification for an FC HBA."""
    if not isinstance(hba, dict) or hba.get("is_cna"):
        return ""
    hcl_model = ""
    if json_hcl:
        unique = lookup_unique_hcl_device(
            vid=hba.get("vendor_id", ""),
            did=hba.get("device_id", ""),
            svid=hba.get("subsystem_vendor_id", ""),
            ssid=hba.get("subsystem_id", ""),
            json_hcl=json_hcl,
            model_name=hba.get("adapter_name", "") or hba.get("model", ""),
        )
        if isinstance(unique, dict):
            hcl_model = str(unique.get("model") or "")
    return classify_fc_plus(hba, hcl_model)


def fc_generation_label(speed_gbps: Any) -> str:
    """Map speed in Gbps to industry standard Fibre Channel generation label."""
    try:
        spd = float(speed_gbps)
    except (ValueError, TypeError):
        return "Standard FC"

    if spd >= 128:
        return "Gen 8 (128 Gbps)"
    elif spd >= 64:
        return "Gen 7 (64 Gbps)"
    elif spd >= 32:
        return "Gen 6 (32 Gbps)"
    elif spd >= 16:
        return "Gen 5 (16 Gbps)"
    elif spd >= 8:
        return "Gen 4 (8 Gbps)"
    elif spd >= 4:
        return "Gen 3 (4 Gbps)"
    elif spd > 0:
        return f"{spd:.0f} Gbps"
    return "Standard FC"


def render_hba_tab(
    fc_hbas: List[Dict[str, Any]],
    json_hcl: Optional[Dict[str, Any]] = None,
    page_salt: str = "",
    data: Optional[Dict[str, Any]] = None,
) -> str:
    """Render the comprehensive Host Detailed HBA tab."""
    data = data or {}
    hbas = normalize_fc_ports(fc_hbas)

    if not hbas:
        return (
            "<div style='margin-bottom:1.5rem'>"
            "<div class='card' style='padding:1.5rem;background:var(--card-subtle,#f8fafc);border:1px solid var(--border,#e2e8f0);border-radius:8px'>"
            "<div style='display:flex;align-items:flex-start;gap:1.25rem'>"
            "<div style='font-size:2.2rem;line-height:1'>ℹ️</div>"
            "<div>"
            "<h3 style='margin:0 0 .4rem;font-size:1.15rem;color:var(--text,#1e293b)'>No Fibre Channel (FC) Host Bus Adapters Detected</h3>"
            "<p style='margin:0 0 .5rem;color:var(--text-muted,#64748b);font-size:.9rem;line-height:1.5'>"
            "This host is configured for direct-attached NVMe/SAS drives and Ethernet storage "
            "(vSAN ESA, NVMe-oF/TCP, iSCSI, or NFS). No physical Fibre Channel HBAs or converged network adapter (CNA) vHBAs were reported by the BMC out-of-band inventory."
            "</p>"
            "<p style='margin:0;color:var(--text-muted,#64748b);font-size:.82rem'>"
            "If an FC HBA is physically installed in a PCIe slot, verify that the adapter option ROM is enabled in system BIOS and that the card is recognized in the PCIe Device inventory."
            "</p>"
            "</div>"
            "</div>"
            "</div>"
            "</div>"
        )

    # ── Calculate KPI aggregates ──────────────────────────────────────────────
    total_ports = len(hbas)
    unique_adapters = fc_adapter_count(hbas)
    adapter_s = "adapter" if unique_adapters == 1 else "adapters"
    adapter_label = f"{unique_adapters} physical {adapter_s}" if unique_adapters is not None else "Physical adapter count not reported"
    adapter_footer = f" across {unique_adapters} physical {adapter_s}" if unique_adapters is not None else " (physical adapter count not reported)"
    port_s = "Port" if total_ports == 1 else "Ports"

    # Speeds & Generation
    numeric_speeds = []
    for h in hbas:
        try:
            s_val = float(h.get("speed_gbps", 0))
            if s_val > 0:
                numeric_speeds.append(s_val)
        except (ValueError, TypeError):
            pass

    max_spd = max(numeric_speeds) if numeric_speeds else None
    if max_spd:
        gen_str = fc_generation_label(max_spd)
    else:
        gen_str = "Enterprise SAN"

    # E+ / M+ badges
    e_plus_count = sum(1 for h in hbas if _fc_plus_badge(h, json_hcl) == "E+")
    m_plus_count = sum(1 for h in hbas if _fc_plus_badge(h, json_hcl) == "M+")
    cna_count = sum(1 for h in hbas if h.get("is_cna") or h.get("cna_family") == "cisco_vic")

    badge_pills = []
    if e_plus_count:
        badge_pills.append(
            "<span style='background:#CC092F;color:#fff;padding:.15rem .45rem;border-radius:3px;font-size:.72rem;font-weight:700'>Broadcom E+</span>"
        )
    if m_plus_count:
        badge_pills.append(
            "<span style='background:#0072CE;color:#fff;padding:.15rem .45rem;border-radius:3px;font-size:.72rem;font-weight:700'>Marvell M+</span>"
        )
    if cna_count:
        badge_pills.append(
            "<span style='background:#4f46e5;color:#fff;padding:.15rem .45rem;border-radius:3px;font-size:.72rem;font-weight:700'>CNA vHBA</span>"
        )
    badges_html = f"<div style='display:flex;gap:.35rem;flex-wrap:wrap;margin-top:.35rem'>{''.join(badge_pills)}</div>" if badge_pills else ""

    # Link Status
    ports_up = sum(1 for h in hbas if str(h.get("link_status", "")).lower() == "up")
    ports_down = sum(1 for h in hbas if str(h.get("link_status", "")).lower() in ("down", "nolink"))
    ports_unknown = total_ports - (ports_up + ports_down)

    if ports_up == total_ports:
        link_kpi_badge = "<span class='badge success'>🟢 All Ports Linked</span>"
        link_kpi_sub = f"{ports_up} of {total_ports} ports active"
    elif ports_up > 0:
        link_kpi_badge = f"<span class='badge warning'>⚠️ {ports_up}/{total_ports} Linked</span>"
        link_kpi_sub = f"{ports_down} port(s) disconnected"
    else:
        link_kpi_badge = "<span class='badge danger'>🔴 Disconnected</span>"
        link_kpi_sub = f"{ports_down} port(s) link-down" if ports_down else "Link status unknown"

    # SAN Boot & Connected Storage Arrays
    all_targets = []
    array_vendors = set()
    for h in hbas:
        for bt in (h.get("boot_targets") or []):
            if isinstance(bt, dict):
                t_wwpn = str(bt.get("target_wwpn") or "").strip()
                if t_wwpn and t_wwpn.replace(":", "").replace("0", ""):
                    all_targets.append(bt)
                    v = bt.get("target_array_vendor")
                    if v and v != "Unknown Array":
                        fam = bt.get("target_array_family")
                        array_vendors.add(f"{v} ({fam})" if fam else v)

    if array_vendors:
        array_kpi_val = ", ".join(sorted(array_vendors))
        array_kpi_badge = f"<span class='badge success' style='font-size:.72rem'>💾 {len(all_targets)} Boot Target(s)</span>"
    elif all_targets:
        array_kpi_val = f"{len(all_targets)} Target(s) Configured"
        array_kpi_badge = "<span class='badge success' style='font-size:.72rem'>SAN Boot Target</span>"
    else:
        array_kpi_val = "Local Boot / In-Band VMFS"
        array_kpi_badge = "<span class='badge info' style='font-size:.72rem'>Local Boot (In-Band SAN)</span>"

    # Remote switch info
    switch_vendors = {h.get("remote_switch_vendor") for h in hbas if h.get("remote_switch_vendor")}
    switch_str = f" &middot; Switch: {', '.join(sorted(switch_vendors))}" if switch_vendors else ""

    kpi_strip_html = f"""
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:1rem;margin-bottom:1.5rem">
        <div class="card" style="padding:1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px">
            <div style="font-size:.74rem;font-weight:700;color:var(--text-muted,#64748b);text-transform:uppercase;letter-spacing:.03em">HBA Hardware</div>
            <div style="font-size:1.35rem;font-weight:700;margin:.3rem 0 .15rem;color:var(--text,#0f172a)">{total_ports} {port_s}</div>
            <div style="font-size:.82rem;color:var(--text-muted,#64748b)">{adapter_label}</div>
            {badges_html}
        </div>
        <div class="card" style="padding:1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px">
            <div style="font-size:.74rem;font-weight:700;color:var(--text-muted,#64748b);text-transform:uppercase;letter-spacing:.03em">Fibre Channel Tier</div>
            <div style="font-size:1.35rem;font-weight:700;margin:.3rem 0 .15rem;color:var(--text,#0f172a)">{_h(gen_str)}</div>
            <div style="font-size:.82rem;color:var(--text-muted,#64748b)">Max speed: {f'{max_spd} Gbps' if max_spd else 'N/A'}{switch_str}</div>
        </div>
        <div class="card" style="padding:1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px">
            <div style="font-size:.74rem;font-weight:700;color:var(--text-muted,#64748b);text-transform:uppercase;letter-spacing:.03em">SAN Fabric Link</div>
            <div style="margin:.3rem 0 .2rem">{link_kpi_badge}</div>
            <div style="font-size:.82rem;color:var(--text-muted,#64748b)">{link_kpi_sub}</div>
        </div>
        <div class="card" style="padding:1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px">
            <div style="font-size:.74rem;font-weight:700;color:var(--text-muted,#64748b);text-transform:uppercase;letter-spacing:.03em">Storage Array / SAN Boot</div>
            <div style="font-size:1rem;font-weight:700;margin:.3rem 0 .15rem;color:var(--text,#0f172a);white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="{_h(array_kpi_val)}">{_h(array_kpi_val)}</div>
            <div style="font-size:.82rem;color:var(--text-muted,#64748b)">{array_kpi_badge}</div>
        </div>
    </div>
    """

    # ── Table Rows ────────────────────────────────────────────────────────────
    hba_rows = ""
    for hba in hbas:
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
        hba_quad = hba.get("pci_quad") or (
            f"{hba_vid}:{hba_did}:{hba_svid}:{hba_ssid}"
            if (hba_vid and hba_did and hba_svid and hba_ssid)
            else f"{hba_vid}:{hba_did}"
            if (hba_vid and hba_did)
            else ""
        )

        _unique_hba = (
            lookup_unique_hcl_device(
                vid=hba_vid,
                did=hba_did,
                svid=hba_svid,
                ssid=hba_ssid,
                json_hcl=json_hcl,
                model_name=hba.get("adapter_name", ""),
            )
            if json_hcl
            else None
        )
        _hba_pid = _unique_hba.get("product_id", "") if _unique_hba else ""
        _hba_prog = _unique_hba.get("hcl_program", "") if _unique_hba else "io"

        if _hba_pid:
            bcg_hba = BCGLinkGenerator.device_detail(_hba_pid, _hba_prog)
        elif hba_vid and hba_did:
            bcg_hba = BCGLinkGenerator.pci_exact(hba_vid, hba_did, hba_svid, hba_ssid, program="io")
        else:
            bcg_hba = BCGLinkGenerator.fc_hba(hba.get("adapter_name", ""), manufacturer=hba.get("manufacturer", ""))

        hba_pci_badge = (
            f"<br><code style='font-size:.76rem;background:var(--pci-bg);color:var(--pci-color);padding:1px 4px;border-radius:3px;'>PCI: {_h(hba_quad)}</code>"
            if hba_quad
            else ""
        )
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

        _wwnn_raw = hba.get("wwnn", "")
        _wwpn_raw = hba.get("wwpn", "N/A")
        wwnn_cell = (
            f"<code style='font-size:.8rem'>{_pii_span(page_salt, _wwnn_raw, 'wwn')}</code>"
            if _wwnn_raw
            else "<span style='color:var(--text-muted)'>—</span>"
        )
        wwpn_cell = (
            f"<code style='font-size:.8rem'>{_pii_span(page_salt, _wwpn_raw, 'wwn')}</code>"
            if _wwpn_raw and _wwpn_raw != "N/A"
            else "<span style='color:var(--text-muted)'>N/A</span>"
        )

        _plus = _fc_plus_badge(hba, json_hcl)
        if _plus == "E+":
            _vendor_badge = (
                " <span style='background:#CC092F;color:#fff;font-size:.68rem;"
                "font-weight:700;padding:.1rem .35rem;border-radius:3px;"
                "vertical-align:middle'>E+</span>"
            )
        elif _plus == "M+":
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
            if _sw_wwpn
            else "<span style='color:var(--text-muted)'>—</span>"
        )

        boot_html = ""
        valid_bts = [
            bt for bt in (hba.get("boot_targets") or [])
            if isinstance(bt, dict) and str(bt.get("target_wwpn") or "").replace(":", "").replace("0", "")
        ]
        for bt in valid_bts:
            prio_label = "Primary" if bt.get("priority", 0) == 0 else f"Alt {bt.get('priority')}"
            _tgt_wwpn_pii = _pii_span(page_salt, bt.get("target_wwpn", ""), "wwn")
            arr_v = bt.get("target_array_vendor")
            arr_fam = bt.get("target_array_family", "")
            fam_str = f" ({_h(arr_fam)})" if arr_fam else ""
            arr_badge = (
                f"<br><span class='badge info' style='font-size:.7rem;margin-top:2px;'>💾 {_h(arr_v)}{fam_str}</span>"
                if arr_v and arr_v != "Unknown Array"
                else ""
            )
            boot_html += (
                f"<div style='margin-top:.3rem'>"
                f"<span class='badge success' style='font-size:.72rem'>"
                f"SAN Boot · {prio_label}</span>{arr_badge}"
                f"<br><code style='font-size:.8rem'>{_tgt_wwpn_pii}</code>"
                f"&nbsp; LUN <strong>{_h(str(bt.get('lun', '0')))}</strong></div>"
            )
        if not boot_html:
            boot_html = "<span style='color:var(--text-muted);font-size:.82rem'>Local Boot (In-Band SAN)</span>"

        _hba_mfr = normalize_component_manufacturer(hba.get("manufacturer", "Unknown"))
        port_id_disp = hba.get("port_id") or "Port"
        speed_disp = f"{hba['speed_gbps']} Gbps" if hba.get("speed_gbps") and hba.get("speed_gbps") != "N/A" else "N/A"

        hba_rows += (
            f"<tr>"
            f"<td><strong>{_h(hba.get('adapter_name', 'FC HBA'))}</strong>{hba_pci_badge}</td>"
            f"<td>{_h(_hba_mfr)}{_vendor_badge}</td>"
            f"<td>{hba_fw_cell}</td>"
            f"<td><code>{_h(str(port_id_disp))}</code></td>"
            f"<td>{wwnn_cell}</td>"
            f"<td>{wwpn_cell}</td>"
            f"<td>{speed_disp}</td>"
            f"<td>{_link_cell}</td>"
            f"<td>{_sw_cell}</td>"
            f"<td>{boot_html}</td>"
            f"<td><a href='{bcg_hba}' target='_blank' class='btn-link'>BCG 9.1 ↗</a></td>"
            f"</tr>"
        )

    table_html = (
        f"<div style='overflow-x:auto'>"
        f"<table><thead><tr>"
        f"<th>Adapter &amp; Part #</th><th>Manufacturer</th><th>Firmware</th>"
        f"<th>Port ID</th><th>WWNN</th><th>WWPN</th><th>Speed</th>"
        f"<th>Link</th><th>Switch Port</th>"
        f"<th>SAN Boot Target</th><th>BCG 9.1 Check</th>"
        f"</tr></thead><tbody>{hba_rows}</tbody></table>"
        f"</div>"
    )

    oob_boundary_note = (
        "<div class='alert' style='background:var(--card-subtle,#f8fafc);border:1px solid var(--border,#e2e8f0);padding:.85rem 1.1rem;border-radius:6px;margin-top:1.25rem'>"
        "<div style='font-size:.82rem;color:var(--text-muted,#64748b);line-height:1.5'>"
        "ℹ️ <strong>Out-of-Band (OOB) Redfish Discovery Boundary:</strong> Surfaces HBA BIOS-configured SAN Boot Targets, Target WWPNs, Boot LUN IDs, and fabric switch WWPNs. "
        "Full in-band SAN storage volume discovery (all non-boot SAN LUN volumes, volume capacity in TB, VMFS/RDM datastores, and ALUA multipath topologies) operates inside the host ESXi kernel storage stack and is reported when in-band agents (Dell iSM / HPE AMS) or ESXi vCenter integrations are present."
        "</div>"
        "</div>"
    )

    return (
        f"<div style='margin-bottom:1.5rem'>"
        f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:.75rem;flex-wrap:wrap;gap:.5rem'>"
        f"<h2 style='margin:0'>Fibre Channel Host Bus Adapters (SAN Connectivity)</h2>"
        f"<span style='font-size:.82rem;color:var(--text-muted,#64748b)'>{total_ports} port(s) detected{adapter_footer}</span>"
        f"</div>"
        f"{kpi_strip_html}"
        f"{table_html}"
        f"{oob_boundary_note}"
        f"</div>"
    )
