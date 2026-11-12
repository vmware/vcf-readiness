"""Experimental vSphere inventory context for single-host HTML reports."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from vcf_hci.report.helpers import _h


def _flag(value: Any) -> str:
    return "<span class='badge success'>On</span>" if value else "<span class='badge info'>Off</span>"


def _table(headers: List[str], rows: List[List[str]], empty: str) -> str:
    if not rows:
        return f"<p style='color:var(--text-muted);font-size:.85rem'>{_h(empty)}</p>"
    head = "".join(f"<th>{_h(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_vsphere_context_card(ctx: Optional[Mapping[str, Any]]) -> str:
    """Summary-grid card; empty when the host has no vCenter match."""
    if not ctx:
        return ""
    issues = list(ctx.get("discrepancies") or ())
    badge = (
        f"<span class='badge warning'>⚠️ {len(issues)} discrepanc{'y' if len(issues) == 1 else 'ies'}</span>"
        if issues else "<span class='badge success'>🟢 Matched to vCenter</span>"
    )
    modes = []
    if ctx.get("in_maintenance_mode"):
        modes.append("<span class='badge warning'>Maintenance mode</span>")
    if ctx.get("in_quarantine_mode"):
        modes.append("<span class='badge warning'>Quarantine mode</span>")
    return (
        "<div class='card' id='vsphereContextCard'>"
        "<h3>🧩 vSphere Context <span class='badge info'>Experimental</span></h3>"
        f"<div>{badge} {' '.join(modes)}</div>"
        "<p style='font-size:.88rem;margin-top:.5rem'>"
        f"<strong>{_h(ctx.get('esxi_host', ''))}</strong>"
        f"<br><small style='color:var(--text-muted)'>vCenter: {_h(ctx.get('vcenter_server', ''))}"
        f" &nbsp;·&nbsp; {_h(ctx.get('datacenter', ''))} / {_h(ctx.get('cluster', ''))}</small>"
        f"<br><small style='color:var(--text-muted)'>ESXi: {_h(ctx.get('esxi_version', ''))}</small>"
        f"<br><small style='color:var(--text-muted)'>VMs: <strong>{_h(ctx.get('vm_count_active', 0))}</strong> on"
        f" / {_h(ctx.get('vm_count_total', 0))} total &nbsp;·&nbsp; vCPUs: {_h(ctx.get('vcpus_allocated', 0))}"
        f" ({_h(ctx.get('vcpus_per_core', ''))} per core)</small>"
        f"<br><small style='color:var(--text-muted)'>Memory tiering: <strong>{_h(ctx.get('memory_tiering', 'Unknown'))}</strong>"
        f" &nbsp;·&nbsp; EVC: {_h(ctx.get('evc_mode', ''))}</small>"
        "</p>"
        f"<p style='font-size:.78rem;color:var(--text-muted);margin-top:.4rem'>Matched by {_h(ctx.get('match_method', ''))}</p>"
        "</div>"
    )


def render_vsphere_context_section(ctx: Optional[Mapping[str, Any]]) -> str:
    """Overview-tab section: cluster features, discrepancies, workloads, and vCenter health findings."""
    if not ctx:
        return ""
    features = (
        f"vSAN {_flag(ctx.get('vsan_enabled'))} &nbsp; HA {_flag(ctx.get('ha_enabled'))}"
        f" &nbsp; DRS {_flag(ctx.get('drs_enabled'))}"
    )
    issues = "".join(f"<li>{_h(d)}</li>" for d in ctx.get("discrepancies") or ())
    vms = [
        [_h(v.get("name", "")), _h(v.get("powerstate", "")), _h(v.get("cpus", "")),
         _h(v.get("memory_mib", "")), _h(v.get("os", ""))]
        for v in ctx.get("vms_summary") or ()
    ]
    findings = [
        [_h(f.get("type", "")), _h(f.get("name", "")), _h(f.get("message", ""))]
        for f in ctx.get("vhealth_findings") or ()
    ]
    return (
        "<details class='accordion' id='vsphereContextSection' open>"
        "<summary><div>🧩 vSphere Context (experimental)</div>"
        "<span style='font-size:.85rem;color:var(--primary)'>Collapse Details &#9652;</span></summary>"
        "<div class='accordion-body' style='padding:1.25rem'>"
        f"<p style='font-size:.88rem'>Cluster features: {features}</p>"
        + (f"<h4>Discrepancies</h4><ul>{issues}</ul>" if issues else "")
        + "<h4>Workloads (first 50)</h4>"
        + _table(["VM", "Power", "vCPUs", "Memory MiB", "Guest OS"], vms, "No VMs registered on this host.")
        + "<h4>vCenter health findings</h4>"
        + _table(["Type", "Object", "Message"], findings, "No vCenter health findings for this host.")
        + "</div></details>"
    )


def _bmc_ports(data: Mapping[str, Any]) -> Dict[str, Dict[str, str]]:
    ports: Dict[str, Dict[str, str]] = {}
    for nic in data.get("network_adapters") or ():
        if not isinstance(nic, dict):
            continue
        adapter = str(nic.get("name") or nic.get("model") or nic.get("id") or "NIC")
        for port in nic.get("ports") or ():
            if isinstance(port, dict):
                mac = str(port.get("mac_address") or port.get("mac") or "").strip().lower()
                if mac:
                    ports[mac] = {
                        "adapter": adapter,
                        "port": str(port.get("port_id") or port.get("name") or ""),
                        "speed": str(port.get("speed_gbps") or port.get("link_speed_gbps") or ""),
                    }
    return ports


def render_vsphere_network_section(ctx: Optional[Mapping[str, Any]], data: Mapping[str, Any]) -> str:
    """Network-tab correlation of ESXi vmnics to Redfish NIC ports by MAC, plus VMkernel adapters."""
    if not ctx:
        return ""
    bmc = _bmc_ports(data)
    rows = []
    for mac, vnic in sorted((ctx.get("vnic_by_mac") or {}).items(), key=lambda kv: str(kv[1].get("vmnic", ""))):
        port = bmc.get(str(mac).lower())
        lldp = " ".join(x for x in (str(vnic.get("lldp_sysname") or ""), str(vnic.get("lldp_port") or "")) if x)
        cdp = " ".join(x for x in (str(vnic.get("cdp_switch") or ""), str(vnic.get("cdp_port") or "")) if x)
        rows.append([
            _h(vnic.get("vmnic", "")), _h(mac), _h(vnic.get("speed_mbps", "")), _h(vnic.get("switch", "")),
            _h(lldp or cdp or "—"),
            _h(f"{port['adapter']} {port['port']}".strip()) if port else "<span class='badge warning'>No Redfish port</span>",
            _h(port["speed"]) if port else "—",
        ])
    vmks = [[_h(v.get("device", "")), _h(v.get("ip", "")), _h(v.get("portgroup", ""))] for v in ctx.get("vmk_ips") or ()]
    return (
        "<details class='accordion' id='vsphereNetworkSection' open>"
        "<summary><div>🧩 vSphere Uplinks ↔ Redfish NIC Ports (experimental)</div>"
        "<span style='font-size:.85rem;color:var(--primary)'>Collapse Details &#9652;</span></summary>"
        "<div class='accordion-body' style='padding:1.25rem'>"
        + _table(["vmnic", "MAC", "ESXi Speed (Mb)", "Switch", "LLDP / CDP neighbor", "Redfish Port", "Redfish Gb/s"],
                 rows, "vCenter reported no physical NICs for this host.")
        + "<h4>VMkernel adapters</h4>"
        + _table(["Device", "IP Address", "Port Group"], vmks, "No VMkernel adapters reported.")
        + "</div></details>"
    )
