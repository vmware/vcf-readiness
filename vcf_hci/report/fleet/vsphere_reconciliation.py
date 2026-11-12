"""Experimental fleet-dashboard panel reconciling Redfish hosts with a vSphere inventory snapshot."""

from __future__ import annotations

from typing import Any, Optional

from vcf_hci.report.helpers import _h

_STATUS_BADGE = {"Matched": "success", "BMC Only": "warning", "vCenter Only": "info"}


def _chip(label: str, value: Any, tone: str) -> str:
    return (
        f"<div class='card' style='padding:.6rem .9rem;min-width:9rem'>"
        f"<div style='font-size:.75rem;color:var(--text-muted)'>{_h(label)}</div>"
        f"<div style='font-size:1.3rem;font-weight:700'><span class='badge {tone}'>{_h(value)}</span></div></div>"
    )


def render_fleet_reconciliation_html(report: Optional[Any]) -> str:
    """Render KPI chips, the per-host match table, and cluster rollups; empty without a report."""
    if report is None:
        return ""
    chips = "".join((
        _chip("Matched hosts", report.matched_count, "success"),
        _chip("BMC only", report.bmc_only_count, "warning" if report.bmc_only_count else "success"),
        _chip("vCenter only", report.vcenter_only_count, "info"),
        _chip("Hosts with discrepancies", report.discrepancy_host_count, "warning" if report.discrepancy_host_count else "success"),
        _chip("VMs (powered on / total)", f"{report.powered_on_vms} / {report.total_vms}", "info"),
    ))
    rows = "".join(
        "<tr>"
        f"<td><span class='badge {_STATUS_BADGE.get(r.match_status, 'info')}'>{_h(r.match_status)}</span></td>"
        f"<td>{_h(r.bmc_hostname)}<br><small>{_h(r.bmc_ip)}</small></td>"
        f"<td>{_h(r.esxi_host)}</td><td>{_h(r.cluster)}</td><td>{_h(r.match_method)}</td>"
        f"<td>{_h(r.esxi_version)}</td><td>{_h(r.memory_tiering)}</td><td>{_h(r.vm_counts)}</td>"
        f"<td>{'<br>'.join(_h(d) for d in r.discrepancies) or '—'}</td>"
        "</tr>"
        for r in report.records
    )
    rollups = "".join(
        "<tr>"
        f"<td>{_h(c.get('cluster', ''))}</td><td>{_h(c.get('datacenter', ''))}</td>"
        f"<td>{_h(c.get('vcenter_hosts', 0))}</td><td>{_h(c.get('matched_bmc_hosts', 0))}</td>"
        f"<td>{_h(c.get('unscanned_bmc_hosts', 0))}</td><td>{_h(c.get('discrepancy_hosts', 0))}</td>"
        f"<td>{_h(c.get('vhealth_findings', 0))}</td><td>{_h(c.get('features', ''))}</td>"
        "</tr>"
        for c in report.cluster_rollups
    )
    rollup_table = (
        "<h3 style='font-size:.85rem;margin-top:1rem'>Cluster rollup</h3>"
        "<table><thead><tr><th>Cluster</th><th>Datacenter</th><th>vCenter hosts</th><th>Matched</th>"
        "<th>Not scanned</th><th>With discrepancies</th><th>Health findings</th><th>Features</th></tr></thead>"
        f"<tbody>{rollups}</tbody></table>"
    ) if rollups else ""
    return (
        "<details class='accordion' id='fleetVsphereReconciliation' open>"
        "<summary><div>🧩 vSphere Reconciliation <span class='badge info'>Experimental</span>"
        f" &nbsp;<small style='color:var(--text-muted)'>vCenter {_h(report.vcenter_server)} · snapshot {_h(report.generated_utc)}</small></div>"
        "<span style='font-size:.85rem;color:var(--primary)'>Collapse Details &#9652;</span></summary>"
        "<div class='accordion-body' style='padding:1.25rem'>"
        f"<div style='display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1rem'>{chips}</div>"
        "<table><thead><tr><th>Status</th><th>BMC host</th><th>ESXi host</th><th>Cluster</th><th>Matched by</th>"
        "<th>ESXi version</th><th>Memory tiering</th><th>VMs</th><th>Discrepancies</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        f"{rollup_table}"
        "</div></details>"
    )
