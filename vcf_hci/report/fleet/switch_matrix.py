"""Fleet switch fabric & topology matrix section renderer."""
from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.obfuscation import _pii_span
from vcf_hci.report.components import render_switch_chassis_svg, render_switch_leaf_svg
from vcf_hci.report.helpers import _h
from vcf_hci.report.switch_topology import build_fleet_switch_topology


def build_fleet_switch_matrix_html(
    all_results: list,
    report_prefix: str = "vsphere_vsan_report_",
    page_salt: str = "",
    obfuscated: bool = False,
) -> str:
    """Render the Fleet Switch Fabric & Topology Matrix section."""
    topo = build_fleet_switch_topology(all_results)
    stats = topo.get("stats", {})
    if stats.get("total_switches", 0) == 0:
        return ""

    switches = topo.get("switches", {})
    leaf_pairs = topo.get("leaf_pairs", [])
    single_switches = topo.get("single_switches", [])
    single_homed_hosts = topo.get("single_homed_hosts", [])
    fex_hosts = topo.get("fex_attached_hosts", [])
    miscabled_hosts = topo.get("miscabled_hosts", [])

    host_to_tab = {}
    for idx, res in enumerate(all_results):
        if not isinstance(res, dict):
            continue
        sys_data = res.get("system") or {}
        tab_idx = idx + 3 if not report_prefix else idx + 1
        h_name = str(sys_data.get("hostname") or "").strip()
        h_ip = str(sys_data.get("ip") or "").strip()
        h_bmc = str(sys_data.get("bmc_ip") or "").strip()
        h_dns = str(sys_data.get("dns_name") or "").strip()
        for k in (h_name, h_ip, h_bmc, h_dns):
            if k:
                host_to_tab[k] = tab_idx
                host_to_tab[k.lower()] = tab_idx

    def _sw_label(val: str, prefix: str = "SW") -> str:
        if not val or val == "Unknown Hostname":
            return "Unknown"
        if not page_salt or obfuscated:
            return _h(val)
        return _pii_span(page_salt, val, prefix)

    def _render_sw_meta(sw: dict) -> str:
        parts = [f"Chassis ID: <code>{_sw_label(sw.get('chassis_id') or 'N/A', 'mac')}</code>"]
        if sw.get('mgmt_ipv4'):
            parts.append(f"Mgmt IP: <code>{_sw_label(sw['mgmt_ipv4'], 'ip')}</code>")
        if sw.get('mgmt_ipv6'):
            parts.append(f"IPv6: <code>{_sw_label(sw['mgmt_ipv6'], 'ip')}</code>")
        if sw.get('management_vlan_id') is not None:
            parts.append(f"VLAN: <code>{sw['management_vlan_id']}</code>")
        return " | ".join(parts)

    def _host_link(host_name: str, host_ip: str) -> str:
        _fname = sanitize_filename(host_ip or host_name)
        _disp_name = _sw_label(host_name, "host")
        _disp_ip = _sw_label(host_ip, "ip") if host_ip else ""
        _ip_part = f"<br><small style='color:var(--text-muted,#64748b)'>{_disp_ip}</small>" if _disp_ip else ""
        if not report_prefix:
            tab_idx = host_to_tab.get(host_name) or host_to_tab.get(host_name.lower()) or host_to_tab.get(host_ip) or host_to_tab.get(host_ip.lower())
            if tab_idx is not None:
                return f"<a href='#' class='btn-link tab-jump' data-tab='{tab_idx}' style='color:var(--primary,#2563eb);text-decoration:none;font-weight:600'>{_disp_name}</a>{_ip_part}"
            return f"<a href='#' class='btn-link tab-jump' data-tab='3' style='color:var(--primary,#2563eb);text-decoration:none;font-weight:600'>{_disp_name}</a>{_ip_part}"
        _url = f"{report_prefix}{_fname}.html"
        return f"<a href='{_h(_url)}' class='btn-link' style='color:var(--primary,#2563eb);text-decoration:none;font-weight:600'>{_disp_name}</a>{_ip_part}"

    # Build Leaf Pair Cards HTML
    pairs_html = []
    for pair in leaf_pairs:
        sw_a = pair["switch_a"]
        sw_b = pair["switch_b"]
        common_hosts = pair["dual_homed_hosts"]
        single_a = pair["single_homed_a_hosts"]
        single_b = pair["single_homed_b_hosts"]

        svg_a = render_switch_chassis_svg(100, 44) if sw_a.get("is_chassis") else render_switch_leaf_svg(100, 22)
        svg_b = render_switch_chassis_svg(100, 44) if sw_b.get("is_chassis") else render_switch_leaf_svg(100, 22)

        # Host connection rows for this pair
        host_rows = []
        for h in common_hosts:
            conns_a = [c for c in sw_a["connections"] if c["hostname"] == h]
            conns_b = [c for c in sw_b["connections"] if c["hostname"] == h]
            ports_a = ", ".join(c.get("switch_port") or "Port" for c in conns_a) or "—"
            ports_b = ", ".join(c.get("switch_port") or "Port" for c in conns_b) or "—"
            ifaces_a = ", ".join(c.get("local_iface") or "NIC" for c in conns_a) or "—"
            ifaces_b = ", ".join(c.get("local_iface") or "NIC" for c in conns_b) or "—"
            h_ip = conns_a[0].get("host_ip") if conns_a else (conns_b[0].get("host_ip") if conns_b else "")
            host_rows.append(
                f"<tr style='border-bottom:1px solid var(--border)'>"
                f"<td style='padding:0.35rem 0.6rem'>{_host_link(h, h_ip)}</td>"
                f"<td style='padding:0.35rem 0.6rem'><span class='badge success' style='font-size:0.72rem'>🟢 Dual-Homed</span></td>"
                f"<td style='padding:0.35rem 0.6rem'><code>{_h(ifaces_a)}</code> &rarr; <b style='color:var(--primary)'>{_sw_label(ports_a, 'port')}</b></td>"
                f"<td style='padding:0.35rem 0.6rem'><code>{_h(ifaces_b)}</code> &rarr; <b style='color:var(--primary)'>{_sw_label(ports_b, 'port')}</b></td>"
                f"</tr>"
            )

        for h in single_a:
            conns_a = [c for c in sw_a["connections"] if c["hostname"] == h]
            ports_a = ", ".join(c.get("switch_port") or "Port" for c in conns_a) or "—"
            ifaces_a = ", ".join(c.get("local_iface") or "NIC" for c in conns_a) or "—"
            h_ip = conns_a[0].get("host_ip") if conns_a else ""
            host_rows.append(
                f"<tr style='border-bottom:1px solid var(--border);background:rgba(202,138,4,0.04)'>"
                f"<td style='padding:0.35rem 0.6rem'>{_host_link(h, h_ip)}</td>"
                f"<td style='padding:0.35rem 0.6rem'><span class='badge warning' style='font-size:0.72rem'>🟡 Single-Homed (A only)</span></td>"
                f"<td style='padding:0.35rem 0.6rem'><code>{_h(ifaces_a)}</code> &rarr; <b style='color:var(--primary)'>{_sw_label(ports_a, 'port')}</b></td>"
                f"<td style='padding:0.35rem 0.6rem;color:var(--text-muted)'>— (No link)</td>"
                f"</tr>"
            )

        for h in single_b:
            conns_b = [c for c in sw_b["connections"] if c["hostname"] == h]
            ports_b = ", ".join(c.get("switch_port") or "Port" for c in conns_b) or "—"
            ifaces_b = ", ".join(c.get("local_iface") or "NIC" for c in conns_b) or "—"
            h_ip = conns_b[0].get("host_ip") if conns_b else ""
            host_rows.append(
                f"<tr style='border-bottom:1px solid var(--border);background:rgba(202,138,4,0.04)'>"
                f"<td style='padding:0.35rem 0.6rem'>{_host_link(h, h_ip)}</td>"
                f"<td style='padding:0.35rem 0.6rem'><span class='badge warning' style='font-size:0.72rem'>🟡 Single-Homed (B only)</span></td>"
                f"<td style='padding:0.35rem 0.6rem;color:var(--text-muted)'>— (No link)</td>"
                f"<td style='padding:0.35rem 0.6rem'><code>{_h(ifaces_b)}</code> &rarr; <b style='color:var(--primary)'>{_sw_label(ports_b, 'port')}</b></td>"
                f"</tr>"
            )

        fex_warning_a = f"<div class='alert alert-warning' style='font-size:0.75rem;padding:0.3rem 0.5rem;margin-top:0.4rem'>⚠️ <b>Cisco FEX Detected:</b> {_h(sw_a.get('fex_reason'))}</div>" if sw_a.get("is_fex") else ""
        fex_warning_b = f"<div class='alert alert-warning' style='font-size:0.75rem;padding:0.3rem 0.5rem;margin-top:0.4rem'>⚠️ <b>Cisco FEX Detected:</b> {_h(sw_b.get('fex_reason'))}</div>" if sw_b.get("is_fex") else ""

        pairs_html.append(f"""
        <div class="card" style="margin-bottom:1.25rem;border:1px solid var(--border);border-radius:8px;background:var(--card);padding:1rem">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;flex-wrap:wrap;gap:0.5rem">
            <div>
              <span class="badge info" style="font-size:0.8rem;padding:0.25rem 0.6rem">🔗 Inferred ToR Leaf Switch Pair</span>
              <strong style="font-size:0.95rem;margin-left:0.5rem;color:var(--text)">{_sw_label(sw_a['switch_name'])} + {_sw_label(sw_b['switch_name'])}</strong>
            </div>
            <div>
              <span class="badge success" style="font-size:0.78rem;padding:0.2rem 0.55rem">🟢 {len(common_hosts)} Dual-Homed Server{"" if len(common_hosts) == 1 else "s"}</span>
              {f"<span class='badge warning' style='font-size:0.78rem;padding:0.2rem 0.55rem;margin-left:0.3rem'>🟡 {len(single_a) + len(single_b)} Single-Homed</span>" if (single_a or single_b) else ""}
            </div>
          </div>

          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(320px, 1fr));gap:0.85rem;margin-bottom:0.85rem">
            <!-- Switch A -->
            <div style="background:var(--code-bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:0.5rem">
                <div>
                  <div style="font-weight:700;font-size:0.9rem;color:var(--primary)">🌐 {_sw_label(sw_a['switch_name'])}</div>
                  <div style="font-size:0.76rem;color:var(--text-muted);margin-top:0.2rem">
                    <span>Vendor: <b>{_h(sw_a['vendor'])}</b></span> | <span>ASIC: <code>{_h(sw_a['asic_family'])}</code></span>
                  </div>
                </div>
                <div style="flex-shrink:0">{svg_a}</div>
              </div>
              <div style="margin:0.4rem 0 0.2rem;display:flex;gap:0.3rem;flex-wrap:wrap">{sw_a.get('badges_html', '')}</div>
              {fex_warning_a}
              <div style="font-size:0.76rem;color:var(--text-muted);margin-top:0.4rem">
                {_render_sw_meta(sw_a)}
              </div>
            </div>

            <!-- Switch B -->
            <div style="background:var(--code-bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:0.5rem">
                <div>
                  <div style="font-weight:700;font-size:0.9rem;color:var(--primary)">🌐 {_sw_label(sw_b['switch_name'])}</div>
                  <div style="font-size:0.76rem;color:var(--text-muted);margin-top:0.2rem">
                    <span>Vendor: <b>{_h(sw_b['vendor'])}</b></span> | <span>ASIC: <code>{_h(sw_b['asic_family'])}</code></span>
                  </div>
                </div>
                <div style="flex-shrink:0">{svg_b}</div>
              </div>
              <div style="margin:0.4rem 0 0.2rem;display:flex;gap:0.3rem;flex-wrap:wrap">{sw_b.get('badges_html', '')}</div>
              {fex_warning_b}
              <div style="font-size:0.76rem;color:var(--text-muted);margin-top:0.4rem">
                {_render_sw_meta(sw_b)}
              </div>
            </div>
          </div>

          <!-- Connected Hosts Accordion -->
          <details style="margin-top:0.5rem">
            <summary style="cursor:pointer;font-size:0.83rem;font-weight:600;color:var(--primary);padding:0.3rem 0">
              🔍 View Connected Hosts &amp; Port Mapping ({len(pair['all_hosts'])} servers)
            </summary>
            <div style="overflow-x:auto;margin-top:0.5rem">
              <table style="width:100%;font-size:0.78rem;border-collapse:collapse;margin:0">
                <thead><tr style="border-bottom:1px solid var(--border);text-align:left;background:var(--code-bg)">
                  <th style="padding:0.35rem 0.6rem">Host / IP</th>
                  <th style="padding:0.35rem 0.6rem">Fabric Redundancy</th>
                  <th style="padding:0.35rem 0.6rem">Link &rarr; {_sw_label(sw_a['switch_name'])} Port</th>
                  <th style="padding:0.35rem 0.6rem">Link &rarr; {_sw_label(sw_b['switch_name'])} Port</th>
                </tr></thead>
                <tbody>{''.join(host_rows)}</tbody>
              </table>
            </div>
          </details>
        </div>
        """)

    # Build Standalone / Unpaired Switches HTML
    standalone_html = []
    for sw_k in single_switches:
        sw = switches[sw_k]
        svg_icon = render_switch_chassis_svg(100, 44) if sw.get("is_chassis") else render_switch_leaf_svg(100, 22)
        h_rows = []
        for c in sw["connections"]:
            h_rows.append(
                f"<tr style='border-bottom:1px solid var(--border)'>"
                f"<td style='padding:0.35rem 0.6rem'>{_host_link(c['hostname'], c['host_ip'])}</td>"
                f"<td style='padding:0.35rem 0.6rem'><code>{_h(c.get('local_iface') or 'NIC')}</code></td>"
                f"<td style='padding:0.35rem 0.6rem'><b style='color:var(--primary)'>{_sw_label(c.get('switch_port') or 'Port', 'port')}</b></td>"
                f"<td style='padding:0.35rem 0.6rem'><span class='badge info' style='font-size:0.7rem'>{_h(c.get('source','nic')).upper()}</span></td>"
                f"</tr>"
            )
        fex_warn = f"<div class='alert alert-warning' style='font-size:0.75rem;padding:0.3rem 0.5rem;margin-top:0.4rem'>⚠️ <b>Cisco FEX Detected:</b> {_h(sw.get('fex_reason'))}</div>" if sw.get("is_fex") else ""
        standalone_html.append(f"""
        <div style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:0.85rem;margin-bottom:0.75rem">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:0.5rem">
            <div>
              <div style="font-weight:700;font-size:0.9rem;color:var(--primary)">🌐 {_sw_label(sw['switch_name'])}</div>
              <div style="font-size:0.76rem;color:var(--text-muted);margin-top:0.2rem">
                <span>Role: <b>{_h(sw.get('role', 'Leaf'))}</b></span> | <span>Vendor: <b>{_h(sw['vendor'])}</b></span> | <span>ASIC: <code>{_h(sw['asic_family'])}</code></span>
              </div>
            </div>
            <div style="flex-shrink:0">{svg_icon}</div>
          </div>
          <div style="margin:0.4rem 0 0.2rem;display:flex;gap:0.3rem;flex-wrap:wrap">{sw.get('badges_html', '')}</div>
          {fex_warn}
          <div style="font-size:0.76rem;color:var(--text-muted);margin:0.3rem 0 0.5rem">
            {_render_sw_meta(sw)} | Connected: <b>{len(sw['connected_hosts'])} host(s)</b>
          </div>
          <details>
            <summary style="cursor:pointer;font-size:0.78rem;font-weight:600;color:var(--primary)">View Connected Hosts ({len(sw['connected_hosts'])})</summary>
            <div style="overflow-x:auto;margin-top:0.4rem">
              <table style="width:100%;font-size:0.76rem;border-collapse:collapse;margin:0">
                <thead><tr style="border-bottom:1px solid var(--border);text-align:left;background:var(--code-bg)">
                  <th style="padding:0.25rem 0.5rem">Host / IP</th><th style="padding:0.25rem 0.5rem">Local NIC</th><th style="padding:0.25rem 0.5rem">Switch Port</th><th style="padding:0.25rem 0.5rem">Type</th>
                </tr></thead>
                <tbody>{''.join(h_rows)}</tbody>
              </table>
            </div>
          </details>
        </div>
        """)

    # Build Dedicated Management Switches HTML
    mgmt_keys = [k for k, s in switches.items() if s.get("role_tag") == "mgmt"]
    mgmt_html = []
    for sw_k in mgmt_keys:
        sw = switches[sw_k]
        mgmt_html.append(f"""
        <div style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:0.75rem;margin-bottom:0.6rem">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <strong style="font-size:0.86rem;color:var(--text)">🌐 {_sw_label(sw['switch_name'])}</strong>
              <span style="font-size:0.75rem;color:var(--text-muted);margin-left:0.4rem">(Chassis: <code>{_sw_label(sw.get('chassis_id') or 'N/A', 'mac')}</code>)</span>
            </div>
            <span class="badge info" style="font-size:0.72rem">{len(sw['connected_hosts'])} BMCs</span>
          </div>
        </div>
        """)

    # Cabling Audit Warning Box
    cabling_alerts = []
    if single_homed_hosts:
        cabling_alerts.append(
            f"<li><b>Single-Homed Hosts ({len(single_homed_hosts)}):</b> "
            f"{', '.join(_sw_label(h, 'host') for h in single_homed_hosts[:10])}"
            f"{f' ... (+{len(single_homed_hosts)-10} more)' if len(single_homed_hosts) > 10 else ''} "
            f"— lack high-speed ToR switch pair redundancy.</li>"
        )
    if miscabled_hosts:
        cabling_alerts.append(
            f"<li><b>Potential Mis-Cabled Hosts ({len(miscabled_hosts)}):</b> "
            f"{', '.join(_sw_label(h, 'host') for h in miscabled_hosts[:10])} "
            f"— multiple redundant NICs connected to the same physical switch.</li>"
        )
    if fex_hosts:
        cabling_alerts.append(
            f"<li><b>Potential Cisco FEX Attached Hosts ({len(fex_hosts)}):</b> "
            f"{', '.join(_sw_label(h, 'host') for h in fex_hosts[:10])} "
            f"— connected to oversubscribed remote line card without local switching.</li>"
        )

    audit_box_html = ""
    if cabling_alerts:
        audit_box_html = f"""
        <div class="alert alert-warning" style="margin-top:1rem;margin-bottom:1rem;padding:0.85rem 1.15rem;border-radius:6px">
          <strong style="color:var(--warning,#ca8a04);font-size:0.92rem">⚠️ Fabric Redundancy &amp; Cabling Audit Alerts:</strong>
          <ul style="margin:0.4rem 0 0 1.2rem;padding:0;font-size:0.82rem;line-height:1.5">
            {''.join(cabling_alerts)}
          </ul>
        </div>
        """

    pairs_section = f'<h3 style="font-size:0.95rem;color:var(--text-muted);margin:1.25rem 0 0.5rem">Detected ToR Leaf Switch Pairs ({len(leaf_pairs)})</h3>' + ''.join(pairs_html) if pairs_html else ''
    standalone_section = f'<h3 style="font-size:0.95rem;color:var(--text-muted);margin:1.25rem 0 0.5rem">Standalone High-Speed Switches ({len(single_switches)})</h3>' + ''.join(standalone_html) if standalone_html else ''
    mgmt_section = f'<h3 style="font-size:0.95rem;color:var(--text-muted);margin:1.25rem 0 0.5rem">Dedicated Management / OOB Switches ({len(mgmt_keys)})</h3><div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:0.6rem">' + ''.join(mgmt_html) + '</div>' if mgmt_html else ''

    return f"""
    <div id="switch-fabric-topology" style="margin-top:2rem;margin-bottom:2rem">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;flex-wrap:wrap;gap:0.5rem">
        <h2 style="margin:0;display:flex;align-items:center;gap:0.5rem">
          <span>🔀</span> Fleet Top-of-Rack (ToR) Switch Fabric &amp; Topology Matrix
        </h2>
        <div style="font-size:0.8rem;color:var(--text-muted)">
          Discovered: <b>{stats.get('total_switches',0)} Switches</b> ({stats.get('tor_switches_count',0)} ToR / {stats.get('mgmt_switches_count',0)} Mgmt) &middot; <b>{stats.get('leaf_pairs_count',0)} Leaf Pairs</b>
        </div>
      </div>

      {audit_box_html}

      {pairs_section}

      {standalone_section}

      {mgmt_section}
    </div>
    """
