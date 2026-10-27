"""Fleet Fibre Channel (FC) fabric & storage matrix section renderer (Layer D)."""
from collections import defaultdict
from typing import Tuple

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.fc_inventory import normalize_fc_ports
from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.obfuscation import _pii_span
from vcf_hci.report.disclosures import evidence_controls_html, supporting_evidence_html
from vcf_hci.report.helpers import _h
from vcf_hci.report.sections.hba import _fc_plus_badge, fc_generation_label


def _classify_fc_generation_bucket(hba: dict) -> Tuple[str, str, str]:
    """Return (bucket_id, bucket_title, badge_color)."""
    spd_raw = hba.get("speed_gbps")
    try:
        spd = float(spd_raw)
    except (ValueError, TypeError):
        spd = 0.0

    name = str(hba.get("adapter_name") or hba.get("model") or "").upper()
    is_cna = bool(hba.get("is_cna") or hba.get("cna_family") == "cisco_vic" or "VIC" in name or "CNA" in name)

    if is_cna:
        return "cna", "CNA / vHBA Unified Fabric", "#4f46e5"
    if spd >= 64 or "64G" in name or "SN1700" in name or "LPE36" in name or "LPE38" in name:
        return "gen7", "Gen 7 (64 Gbps) — Ultra-Performance", "#CC092F"
    if spd >= 32 or "32G" in name or "2772" in name or "LPE32" in name or "LPE35" in name or "SN1610" in name:
        return "gen6", "Gen 6 (32 Gbps) — Enterprise Standard", "#0072CE"
    if spd >= 16 or "16G" in name or "LPE31" in name or "2692" in name:
        return "gen5", "Gen 5 (16 Gbps) — Legacy SAN", "#475569"
    if spd >= 8 or "8G" in name:
        return "gen4", "Gen 4 (8 Gbps) — Legacy SAN", "#64748b"
    return "other", "Standard Fibre Channel", "#334155"


def build_fleet_fc_matrix_html(
    all_results: list,
    report_prefix: str = "vsphere_vsan_report_",
    page_salt: str = "",
    obfuscated: bool = False,
) -> str:
    """Render the Fleet Fibre Channel Fabric & Storage Matrix section."""
    fc_hosts_data = []
    host_to_tab = {}

    for idx, res in enumerate(all_results):
        if not isinstance(res, dict):
            continue
        sys_data = res.get("system") or {}
        tab_idx = idx + 3 if not report_prefix else idx + 1
        h_name = str(sys_data.get("hostname") or res.get("host") or f"Host-{idx+1}").strip()
        h_ip = str(sys_data.get("ip") or sys_data.get("bmc_ip") or res.get("host") or "").strip()
        h_bmc = str(sys_data.get("bmc_ip") or "").strip()
        h_dns = str(sys_data.get("dns_name") or "").strip()
        for k in (h_name, h_ip, h_bmc, h_dns):
            if k:
                host_to_tab[k] = tab_idx
                host_to_tab[k.lower()] = tab_idx

        hbas = normalize_fc_ports(res.get("fc_hbas"))
        if hbas:
            fc_hosts_data.append({
                "idx": idx,
                "tab_idx": tab_idx,
                "hostname": h_name,
                "ip": h_ip,
                "vendor": sys_data.get("vendor") or "Generic",
                "model": sys_data.get("model") or "Server",
                "hbas": hbas,
            })

    if not fc_hosts_data:
        return (
            "<div id='switch-fabric-fc' style='padding:1.5rem 0'>"
            "<div class='card' style='padding:1.5rem;background:var(--card-subtle,#f8fafc);border:1px solid var(--border,#e2e8f0);border-radius:8px'>"
            "<div style='display:flex;align-items:flex-start;gap:1.25rem'>"
            "<div style='font-size:2.2rem;line-height:1'>ℹ️</div>"
            "<div>"
            "<h3 style='margin:0 0 .4rem;font-size:1.15rem;color:var(--text,#1e293b)'>No Fibre Channel HBAs Discovered in Fleet</h3>"
            "<p style='margin:0;color:var(--text-muted,#64748b);font-size:.9rem;line-height:1.5'>"
            "None of the assessed hosts reported physical Fibre Channel (FC) HBAs or converged network adapters (CNA) with active FC personas. "
            "The assessed servers are configured strictly for direct-attached drives (vSAN ESA / OSA) and Ethernet storage (NVMe-oF/TCP, iSCSI, or NFS)."
            "</p>"
            "</div>"
            "</div>"
            "</div>"
            "</div>"
        )

    # ── Helpers for host links & PII ──────────────────────────────────────────
    def _fc_label(val: str, prefix: str = "wwn") -> str:
        if not val or val.upper() in ("N/A", "NONE", "—", ""):
            return "—"
        if not page_salt or obfuscated:
            return _h(val)
        return _pii_span(page_salt, val, prefix)

    def _host_link(host_name: str, host_ip: str) -> str:
        _fname = sanitize_filename(host_ip or host_name)
        _disp_name = _fc_label(host_name, "host")
        _disp_ip = _fc_label(host_ip, "ip") if host_ip else ""
        _ip_part = f"<br><small style='color:var(--text-muted,#64748b)'>{_disp_ip}</small>" if _disp_ip else ""
        if not report_prefix:
            tab_idx = host_to_tab.get(host_name) or host_to_tab.get(host_name.lower()) or host_to_tab.get(host_ip) or host_to_tab.get(host_ip.lower())
            if tab_idx is not None:
                return f"<a href='#' class='btn-link tab-jump' data-tab='{tab_idx}' data-subtab='tab-hba' style='color:var(--primary,#2563eb);text-decoration:none;font-weight:600'>{_disp_name}</a>{_ip_part}"
            return f"<a href='#' class='btn-link tab-jump' data-tab='3' data-subtab='tab-hba' style='color:var(--primary,#2563eb);text-decoration:none;font-weight:600'>{_disp_name}</a>{_ip_part}"
        _url = f"{report_prefix}{_fname}.html#tab-hba"
        return f"<a href='{_h(_url)}' class='btn-link' style='color:var(--primary,#2563eb);text-decoration:none;font-weight:600'>{_disp_name}</a>{_ip_part}"

    # ── Aggregate Fleet KPIs ──────────────────────────────────────────────────
    n_fc_hosts = len(fc_hosts_data)
    total_hosts = len(all_results)
    pct_fc = (n_fc_hosts / total_hosts * 100) if total_hosts else 0

    total_fc_ports = sum(len(d["hbas"]) for d in fc_hosts_data)
    linked_ports = 0
    down_ports = 0
    all_speeds = []
    e_plus_count = 0
    m_plus_count = 0
    cna_count = 0

    generation_hosts = defaultdict(list)
    generation_ports = defaultdict(int)

    # Fabric / Array Grouping collectors
    fabric_target_groups = defaultdict(list)
    fabric_switch_groups = defaultdict(list)
    local_inband_hosts = []
    san_boot_hosts = set()

    for hdata in fc_hosts_data:
        h_name = hdata["hostname"]
        h_ip = hdata["ip"]
        has_san_target = False

        for hba in hdata["hbas"]:
            ls = str(hba.get("link_status") or "").lower()
            if ls == "up":
                linked_ports += 1
            elif ls in ("down", "nolink"):
                down_ports += 1

            spd = hba.get("speed_gbps")
            try:
                s_f = float(spd)
                if s_f > 0:
                    all_speeds.append(s_f)
            except (ValueError, TypeError):
                pass

            badge = _fc_plus_badge(hba)
            if badge == "E+":
                e_plus_count += 1
            elif badge == "M+":
                m_plus_count += 1
            if hba.get("is_cna") or hba.get("cna_family") == "cisco_vic":
                cna_count += 1

            b_id, b_title, b_color = _classify_fc_generation_bucket(hba)
            if hdata not in generation_hosts[b_id]:
                generation_hosts[b_id].append(hdata)
            generation_ports[b_id] += 1

            # Boot Targets & Array vendors
            for bt in (hba.get("boot_targets") or []):
                t_wwpn = str(bt.get("target_wwpn") or "").strip()
                if t_wwpn and t_wwpn.replace(":", "").replace("0", ""):
                    has_san_target = True
                    san_boot_hosts.add(h_name)
                    arr_v = bt.get("target_array_vendor") or "Unknown Array"
                    arr_f = bt.get("target_array_family") or ""
                    lun = bt.get("lun") or "0"
                    t_key = (t_wwpn, lun, arr_v, arr_f)
                    fabric_target_groups[t_key].append({
                        "hostname": h_name,
                        "ip": h_ip,
                        "hba": hba,
                        "boot_target": bt,
                    })

            # Remote switch WWPN
            sw_wwpn = str(hba.get("remote_switch_wwpn") or "").strip()
            if sw_wwpn and sw_wwpn.replace(":", "").replace("0", ""):
                sw_v = hba.get("remote_switch_vendor") or "SAN Switch"
                fabric_switch_groups[(sw_wwpn, sw_v)].append({
                    "hostname": h_name,
                    "ip": h_ip,
                    "hba": hba,
                })

        if not has_san_target:
            local_inband_hosts.append(hdata)

    max_spd = max(all_speeds) if all_speeds else None
    max_gen_str = fc_generation_label(max_spd) if max_spd else "Enterprise SAN"

    # SAN Boot Deployment Stats
    san_boot_count = len(san_boot_hosts)
    san_boot_pct = (san_boot_count / n_fc_hosts * 100) if n_fc_hosts else 0
    if san_boot_count > 0:
        san_boot_badge = "<span class='badge success' style='font-size:.72rem'>🟢 SAN Boot Active</span>"
        san_boot_sub = f"{san_boot_pct:.1f}% SAN Booted ({san_boot_count}/{n_fc_hosts} nodes)"
    else:
        san_boot_badge = "<span class='badge info' style='font-size:.72rem'>Local Boot (In-Band SAN)</span>"
        san_boot_sub = f"0% SAN Boot &middot; {n_fc_hosts} Local Boot / In-Band SAN"

    # KPI Badges
    badge_chips = []
    if e_plus_count:
        badge_chips.append(f"<span style='background:#CC092F;color:#fff;padding:.15rem .45rem;border-radius:3px;font-size:.72rem;font-weight:700'>Broadcom E+ ({e_plus_count})</span>")
    if m_plus_count:
        badge_chips.append(f"<span style='background:#0072CE;color:#fff;padding:.15rem .45rem;border-radius:3px;font-size:.72rem;font-weight:700'>Marvell M+ ({m_plus_count})</span>")
    if cna_count:
        badge_chips.append(f"<span style='background:#4f46e5;color:#fff;padding:.15rem .45rem;border-radius:3px;font-size:.72rem;font-weight:700'>CNA vHBA ({cna_count})</span>")
    badges_html = f"<div style='display:flex;gap:.35rem;flex-wrap:wrap;margin-top:.4rem'>{''.join(badge_chips)}</div>" if badge_chips else ""

    kpi_strip_html = f"""
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:1rem;margin:1rem 0 1.5rem">
        <div class="card" style="padding:1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px">
            <div style="font-size:.74rem;font-weight:700;color:var(--text-muted,#64748b);text-transform:uppercase;letter-spacing:.03em">FC Adoption</div>
            <div style="font-size:1.35rem;font-weight:700;margin:.3rem 0 .15rem;color:var(--text,#0f172a)">{n_fc_hosts} Hosts</div>
            <div style="font-size:.82rem;color:var(--text-muted,#64748b)">{pct_fc:.1f}% of fleet ({n_fc_hosts}/{total_hosts} nodes)</div>
            {badges_html}
        </div>
        <div class="card" style="padding:1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px">
            <div style="font-size:.74rem;font-weight:700;color:var(--text-muted,#64748b);text-transform:uppercase;letter-spacing:.03em">Speed Spectrum</div>
            <div style="font-size:1.35rem;font-weight:700;margin:.3rem 0 .15rem;color:var(--text,#0f172a)">{_h(max_gen_str)}</div>
            <div style="font-size:.82rem;color:var(--text-muted,#64748b)">Peak speed: {f'{max_spd} Gbps' if max_spd else 'N/A'}</div>
        </div>
        <div class="card" style="padding:1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px">
            <div style="font-size:.74rem;font-weight:700;color:var(--text-muted,#64748b);text-transform:uppercase;letter-spacing:.03em">Port Inventory &amp; Link</div>
            <div style="font-size:1.35rem;font-weight:700;margin:.3rem 0 .15rem;color:var(--text,#0f172a)">{total_fc_ports} Ports</div>
            <div style="font-size:.82rem;color:var(--text-muted,#64748b)"><span style="color:var(--success,#16a34a)">🟢 {linked_ports} Linked</span> &middot; <span style="color:var(--danger,#dc2626)">🔴 {down_ports} Down</span></div>
        </div>
        <div class="card" style="padding:1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px">
            <div style="font-size:.74rem;font-weight:700;color:var(--text-muted,#64748b);text-transform:uppercase;letter-spacing:.03em">SAN Boot Deployment</div>
            <div style="font-size:1.35rem;font-weight:700;margin:.3rem 0 .15rem;color:var(--text,#0f172a)">{san_boot_count} Hosts Booting from SAN</div>
            <div style="font-size:.82rem;color:var(--text-muted,#64748b)">{san_boot_sub}</div>
            <div style="margin-top:.4rem">{san_boot_badge}</div>
        </div>
        <div class="card" style="padding:1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px">
            <div style="font-size:.74rem;font-weight:700;color:var(--text-muted,#64748b);text-transform:uppercase;letter-spacing:.03em">Storage Fabric Groups</div>
            <div style="font-size:1.35rem;font-weight:700;margin:.3rem 0 .15rem;color:var(--text,#0f172a)">{len(fabric_target_groups) or (1 if local_inband_hosts else 0)} Array Group(s)</div>
            <div style="font-size:.82rem;color:var(--text-muted,#64748b)">{len(fabric_switch_groups)} Fabric Switch Port(s) mapped</div>
        </div>
    </div>
    """

    # ── Generation & Speed Spectrum Cards ─────────────────────────────────────
    gen_definitions = [
        ("gen7", "Gen 7 (64 Gbps)", "#CC092F", "Optimal for high-throughput NVMe/FC, vSphere 9.1 VMFS, and lowest latency external SAN integration."),
        ("gen6", "Gen 6 (32 Gbps)", "#0072CE", "Mainstream enterprise 32G Fibre Channel SAN infrastructure with full VCF 9.1 support."),
        ("gen5", "Gen 5 (16 Gbps)", "#475569", "Standard enterprise 16G Fibre Channel SAN fabric (Broadcom / Marvell / QLogic)."),
        ("cna", "CNA / vHBA Unified", "#4f46e5", "Converged Ethernet/FC hardware virtualization (Cisco VIC fnic / Marvell FastLinQ qfle3f)."),
    ]

    gen_cards_html = []
    for b_id, b_title, b_color, b_desc in gen_definitions:
        hosts_in_b = generation_hosts.get(b_id, [])
        ports_in_b = generation_ports.get(b_id, 0)
        pct_b = (len(hosts_in_b) / n_fc_hosts * 100) if n_fc_hosts else 0

        host_chips = []
        for h in hosts_in_b[:8]:
            host_chips.append(_host_link(h["hostname"], h["ip"]))
        more_cnt = len(hosts_in_b) - 8
        if more_cnt > 0:
            host_chips.append(f"<span style='color:var(--text-muted,#64748b);font-size:.8rem'>+{more_cnt} more</span>")

        chip_list_html = (
            "<div style='display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin-top:.6rem'>"
            + " ".join(host_chips)
            + "</div>"
        ) if host_chips else "<div style='color:var(--text-muted,#64748b);font-size:.82rem;margin-top:.4rem'>None in fleet</div>"

        gen_cards_html.append(
            f"<div class='card' style='padding:1.1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px;border-top:3px solid {b_color}'>"
            f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:.35rem'>"
            f"<strong style='font-size:.95rem;color:var(--text,#0f172a)'>{_h(b_title)}</strong>"
            f"<span style='font-size:.82rem;font-weight:700;color:{b_color}'>{len(hosts_in_b)} Hosts &middot; {ports_in_b} Ports</span>"
            f"</div>"
            f"<p style='font-size:.82rem;color:var(--text-muted,#64748b);margin:0 0 .5rem;line-height:1.4'>{_h(b_desc)}</p>"
            f"<div style='background:var(--border,#e2e8f0);height:4px;border-radius:2px;overflow:hidden;margin:.5rem 0'>"
            f"<div style='background:{b_color};width:{pct_b:.1f}%;height:100%'></div>"
            f"</div>"
            f"{chip_list_html}"
            f"</div>"
        )

    spectrum_section = (
        f"<div style='margin-bottom:1.5rem'>"
        f"<h3 style='margin:0 0 .75rem;font-size:1.05rem;color:var(--text,#0f172a)'>Fibre Channel Generation &amp; Speed Distribution</h3>"
        f"<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem'>"
        f"{''.join(gen_cards_html)}"
        f"</div>"
        f"</div>"
    )

    # ── Storage Array & Fabric Groups ─────────────────────────────────────────
    fabric_cards_html = []

    # 1. Connected SAN Target Groups
    for (t_wwpn, lun, arr_v, arr_f), members in sorted(fabric_target_groups.items(), key=lambda x: len(x[1]), reverse=True):
        distinct_hosts = {}
        for m in members:
            distinct_hosts[m["hostname"]] = m["ip"]

        fam_txt = f" ({arr_f})" if arr_f else ""
        title_txt = f"Storage Array: {arr_v}{fam_txt}" if arr_v != "Unknown Array" else f"Storage Array Target: {_fc_label(t_wwpn, 'wwn')}"

        host_links = []
        for h_name, h_ip in list(distinct_hosts.items())[:12]:
            host_links.append(_host_link(h_name, h_ip))
        if len(distinct_hosts) > 12:
            host_links.append(f"<span style='color:var(--text-muted,#64748b);font-size:.8rem'>+{len(distinct_hosts)-12} more</span>")

        fabric_cards_html.append(
            f"<div class='card' style='padding:1.1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px'>"
            f"<div style='display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:.5rem;margin-bottom:.5rem'>"
            f"<div>"
            f"<span class='badge info' style='font-size:.72rem'>💾 Storage Array Fabric</span>"
            f"<h4 style='margin:.3rem 0 .15rem;font-size:1rem;color:var(--text,#0f172a)'>{_h(title_txt)}</h4>"
            f"<div style='font-size:.82rem;color:var(--text-muted,#64748b)'>"
            f"Target WWPN: <code>{_fc_label(t_wwpn, 'wwn')}</code> &middot; Boot LUN ID: <strong>{_h(lun)}</strong>"
            f"</div>"
            f"</div>"
            f"<span class='badge success' style='font-size:.78rem'>{len(distinct_hosts)} Connected Host(s)</span>"
            f"</div>"
            f"<div style='margin-top:.75rem;padding-top:.5rem;border-top:1px solid var(--border,#e2e8f0)'>"
            f"<div style='font-size:.76rem;font-weight:700;color:var(--text-muted,#64748b);text-transform:uppercase;letter-spacing:.04em;margin-bottom:.35rem'>Member Hosts</div>"
            f"<div style='display:flex;gap:.5rem;flex-wrap:wrap;align-items:center'>"
            f"{' '.join(host_links)}"
            f"</div>"
            f"</div>"
            f"</div>"
        )

    # 2. Fabric Switch Groups
    for (sw_wwpn, sw_v), members in sorted(fabric_switch_groups.items(), key=lambda x: len(x[1]), reverse=True):
        distinct_hosts = {m["hostname"]: m["ip"] for m in members}
        host_links = [_host_link(hn, hip) for hn, hip in list(distinct_hosts.items())[:10]]
        fabric_cards_html.append(
            f"<div class='card' style='padding:1.1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px'>"
            f"<div style='display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:.5rem;margin-bottom:.5rem'>"
            f"<div>"
            f"<span class='badge' style='background:#0f766e;color:#fff;font-size:.72rem'>🔀 SAN Fabric Switch</span>"
            f"<h4 style='margin:.3rem 0 .15rem;font-size:1rem;color:var(--text,#0f172a)'>{_h(sw_v)}</h4>"
            f"<div style='font-size:.82rem;color:var(--text-muted,#64748b)'>Switch Port WWPN: <code>{_fc_label(sw_wwpn, 'wwn')}</code></div>"
            f"</div>"
            f"<span class='badge info' style='font-size:.78rem'>{len(distinct_hosts)} Host(s) Attached</span>"
            f"</div>"
            f"<div style='margin-top:.75rem;padding-top:.5rem;border-top:1px solid var(--border,#e2e8f0)'>"
            f"<div style='font-size:.76rem;font-weight:700;color:var(--text-muted,#64748b);text-transform:uppercase;letter-spacing:.04em;margin-bottom:.35rem'>Attached Hosts</div>"
            f"<div style='display:flex;gap:.5rem;flex-wrap:wrap;align-items:center'>"
            f"{' '.join(host_links)}"
            f"</div>"
            f"</div>"
            f"</div>"
        )

    # 3. Direct / In-Band SAN (No BIOS SAN boot target)
    if local_inband_hosts:
        distinct_hosts = {h["hostname"]: h["ip"] for h in local_inband_hosts}
        host_links = [_host_link(hn, hip) for hn, hip in list(distinct_hosts.items())[:12]]
        if len(distinct_hosts) > 12:
            host_links.append(f"<span style='color:var(--text-muted,#64748b);font-size:.8rem'>+{len(distinct_hosts)-12} more</span>")

        fabric_cards_html.append(
            f"<div class='card' style='padding:1.1rem;background:var(--card,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:6px'>"
            f"<div style='display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:.5rem;margin-bottom:.5rem'>"
            f"<div>"
            f"<span class='badge' style='background:#475569;color:#fff;font-size:.72rem'>🌐 In-Band SAN Datastores</span>"
            f"<h4 style='margin:.3rem 0 .15rem;font-size:1rem;color:var(--text,#0f172a)'>Direct SAN Fabric / In-Band VMFS LUNs</h4>"
            f"<div style='font-size:.82rem;color:var(--text-muted,#64748b)'>Physical FC HBAs present for in-band ESXi datastores without BIOS SAN boot targets.</div>"
            f"</div>"
            f"<span class='badge' style='background:var(--card-subtle,#f8fafc);color:var(--text-muted,#64748b);font-size:.78rem'>{len(distinct_hosts)} Host(s)</span>"
            f"</div>"
            f"<div style='margin-top:.75rem;padding-top:.5rem;border-top:1px solid var(--border,#e2e8f0)'>"
            f"<div style='font-size:.76rem;font-weight:700;color:var(--text-muted,#64748b);text-transform:uppercase;letter-spacing:.04em;margin-bottom:.35rem'>Member Hosts</div>"
            f"<div style='display:flex;gap:.5rem;flex-wrap:wrap;align-items:center'>"
            f"{' '.join(host_links)}"
            f"</div>"
            f"</div>"
            f"</div>"
        )

    fabric_section = (
        f"<div style='margin-bottom:1.5rem'>"
        f"<h3 style='margin:0 0 .75rem;font-size:1.05rem;color:var(--text,#0f172a)'>Storage Array Targets &amp; Fabric Groups</h3>"
        f"<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:1rem'>"
        f"{''.join(fabric_cards_html)}"
        f"</div>"
        f"</div>"
    )

    # ── Searchable Fleet FC Host Roster Table ─────────────────────────────────
    roster_rows = []
    for hdata in fc_hosts_data:
        h_name = hdata["hostname"]
        h_ip = hdata["ip"]
        vendor_model = f"{hdata['vendor']} {hdata['model']}"

        for hba in hdata["hbas"]:
            name = hba.get("adapter_name") or hba.get("model") or "FC HBA"
            fw = hba.get("firmware_version") or "N/A"
            port_id = hba.get("port_id") or "Port"
            spd = hba.get("speed_gbps")
            spd_disp = f"{spd} Gbps" if spd and spd != "N/A" else "N/A"
            gen_label = fc_generation_label(spd)

            ls = str(hba.get("link_status") or "Unknown")
            if ls.lower() == "up":
                link_badge = "<span class='badge success' style='font-size:.72rem'>🟢 Up</span>"
            elif ls.lower() in ("down", "nolink"):
                link_badge = f"<span class='badge danger' style='font-size:.72rem'>🔴 {_h(ls)}</span>"
            else:
                link_badge = f"<span class='badge info' style='font-size:.72rem'>{_h(ls)}</span>"

            badge = _fc_plus_badge(hba)
            badge_html = ""
            if badge == "E+":
                badge_html = " <span style='background:#CC092F;color:#fff;font-size:.68rem;font-weight:700;padding:.1rem .35rem;border-radius:3px'>E+</span>"
            elif badge == "M+":
                badge_html = " <span style='background:#0072CE;color:#fff;font-size:.68rem;font-weight:700;padding:.1rem .35rem;border-radius:3px'>M+</span>"
            elif hba.get("is_cna") or hba.get("cna_family") == "cisco_vic":
                badge_html = " <span style='background:#4f46e5;color:#fff;font-size:.68rem;font-weight:700;padding:.1rem .35rem;border-radius:3px'>CNA</span>"

            wwpn_cell = f"<code>{_fc_label(hba.get('wwpn'), 'wwn')}</code>"
            wwnn_raw = hba.get("wwnn")
            wwnn_cell = f"<br><small style='color:var(--text-muted,#64748b)'>WWNN: <code>{_fc_label(wwnn_raw, 'wwn')}</code></small>" if wwnn_raw else ""

            # SAN Target / Array info
            valid_bts = [
                bt for bt in (hba.get("boot_targets") or [])
                if str(bt.get("target_wwpn") or "").replace(":", "").replace("0", "")
            ]
            if valid_bts:
                bt_items = []
                for bt in valid_bts:
                    arr_v = bt.get("target_array_vendor")
                    arr_f = bt.get("target_array_family") or ""
                    tgt_w = bt.get("target_wwpn") or ""
                    lun = bt.get("lun") or "0"
                    arr_str = f"💾 {_h(arr_v)}" if arr_v and arr_v != "Unknown Array" else "Target"
                    if arr_f:
                        arr_str += f" ({_h(arr_f)})"
                    bt_items.append(
                        f"<div><span class='badge info' style='font-size:.68rem'>{arr_str} &middot; LUN {lun}</span>"
                        f"<br><small><code>{_fc_label(tgt_w, 'wwn')}</code></small></div>"
                    )
                target_cell = "".join(bt_items)
            else:
                target_cell = "<span style='color:var(--text-muted,#64748b);font-size:.82rem'>Local Boot (In-Band SAN)</span>"

            # Switch info
            sw_w = hba.get("remote_switch_wwpn")
            sw_v = hba.get("remote_switch_vendor")
            if sw_w:
                sw_cell = f"<code>{_fc_label(sw_w, 'wwn')}</code>" + (f"<br><small>{_h(sw_v)}</small>" if sw_v else "")
            else:
                sw_cell = "<span style='color:var(--text-muted,#64748b)'>—</span>"

            bcg_url = BCGLinkGenerator.fc_hba(name, manufacturer=hba.get("manufacturer", ""))

            roster_rows.append(
                f"<tr class='fc-roster-row'>"
                f"<td>{_host_link(h_name, h_ip)}</td>"
                f"<td style='font-size:.82rem'>{_h(vendor_model)}</td>"
                f"<td><strong>{_h(name)}</strong>{badge_html}<br><small style='color:var(--text-muted,#64748b)'>FW: <code>{_h(fw)}</code></small></td>"
                f"<td><code>{_h(str(port_id))}</code></td>"
                f"<td><strong>{spd_disp}</strong><br><small style='color:var(--text-muted,#64748b)'>{_h(gen_label)}</small></td>"
                f"<td>{link_badge}</td>"
                f"<td>{wwpn_cell}{wwnn_cell}</td>"
                f"<td>{sw_cell}</td>"
                f"<td>{target_cell}</td>"
                f"<td><a href='{bcg_url}' target='_blank' class='btn-link' style='font-size:.8rem'>BCG ↗</a></td>"
                f"</tr>"
            )

    roster_table_html = (
        f"<div style='margin-bottom:1.5rem'>"
        f"<div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.75rem;margin-bottom:.75rem'>"
        f"<h3 style='margin:0;font-size:1.05rem;color:var(--text,#0f172a)'>Fleet Fibre Channel Host Roster ({n_fc_hosts} Hosts &middot; {total_fc_ports} Ports)</h3>"
        f"<input type='text' id='fcHostSearch' aria-label='Filter Fibre Channel hosts, adapters and targets' placeholder='🔍 Filter hosts, adapters, WWPNs, arrays...' style='padding:.35rem .75rem;border:1px solid var(--border,#cbd5e1);border-radius:5px;font-size:.85rem;min-width:280px;background:var(--card,#ffffff);color:var(--text,#0f172a)'>"
        f"</div>"
        f"<div style='overflow-x:auto'>"
        f"<table><thead><tr>"
        f"<th>Host</th><th>Server Model</th><th>FC HBA &amp; Firmware</th><th>Port</th>"
        f"<th>Speed &amp; Gen</th><th>Link</th><th>Initiator WWPN / WWNN</th><th>Switch Port</th>"
        f"<th>Storage Array Target</th><th>BCG Check</th>"
        f"</tr></thead><tbody>{''.join(roster_rows)}</tbody></table>"
        f"</div>"
        f"</div>"
    )

    filter_js = (
        "<script>\n"
        "(function(){\n"
        "  var inp = document.getElementById('fcHostSearch');\n"
        "  if (!inp) return;\n"
        "  inp.addEventListener('input', function(){\n"
        "    var q = (inp.value || '').toLowerCase().trim();\n"
        "    var rows = document.querySelectorAll('.fc-roster-row');\n"
        "    rows.forEach(function(row){\n"
        "      var txt = (row.textContent || '').toLowerCase();\n"
        "      row.style.display = (!q || txt.indexOf(q) !== -1) ? '' : 'none';\n"
        "    });\n"
        "  });\n"
        "})();\n"
        "</script>\n"
    )

    return (
        f"<div id='switch-fabric-fc' style='padding-top:.5rem'>"
        f"<div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem;margin-bottom:.5rem'>"
        f"<div>"
        f"<h2 style='margin:0;display:flex;align-items:center;gap:.5rem'>"
        f"<span>⚡</span> Fleet Fibre Channel (FC) Fabric &amp; Storage Matrix"
        f"</h2>"
        f"<div style='font-size:.82rem;color:var(--text-muted,#64748b);margin-top:.25rem'>"
        f"Enterprise SAN connectivity, HBA speed spectrum, storage array targets, and SAN fabric groupings across all scanned hosts."
        f"</div>"
        f"</div>"
        f"<span class='badge success' style='font-size:.82rem;padding:.3rem .7rem'>{n_fc_hosts} FC Node(s) Detected</span>"
        f"</div>"
        f"{kpi_strip_html}"
        f"{spectrum_section}"
        f"{evidence_controls_html() if fabric_section else ''}"
        f"{supporting_evidence_html('SAN fabric evidence', fabric_section, n_fc_hosts, 'fc-fabric-evidence') if fabric_section else ''}"
        f"{roster_table_html}"
        f"{filter_js}"
        f"</div>"
    )
