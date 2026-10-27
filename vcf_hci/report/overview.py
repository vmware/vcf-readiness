"""Presentation-only fleet overview, using the existing inventory verdicts."""

from typing import Optional

from vcf_hci.report.helpers import _h
from vcf_hci.report.inventory_tables import build_host_decision_rows
from vcf_hci.report.readiness import chassis_qualification

COMPONENT_CERTIFICATION_BLOG = 'https://blogs.vmware.com/cloud-foundation/2026/02/25/vcf-9-0-server-certification-preserving-your-hardware-investment-and-giving-the-best-roi/'
COMPONENT_CERTIFICATION_NOTE = (
    'Server chassis not found. CPU and components can be supported through '
    'component-level certification. Verify the installed components and '
    'firmware/driver combinations in the Broadcom Compatibility Guide.'
)


def fleet_overview_groups(all_results: list) -> list:
    """Keep host indices per dimension; never add overlapping dimensions together."""
    rows = build_host_decision_rows(all_results)
    server = {'Server supported': [], 'components certified': [], 'Review / Override Required': [], 'Unsupported for VCF 9.x': [], 'Not assessed': []}
    esa = {'Ready': [], 'Storage met / upgrade needed': [], 'Blocked / insufficient': [], 'Unknown': []}
    security = {'Baseline met': [], 'Action suggested': [], 'Partially assessed': [], 'Not assessed': []}
    for row in rows:
        idx = row['host_idx']
        verdict = str(row.get('cpu_verdict') or '').strip()
        if not verdict or any(word in verdict.lower() for word in ('unknown', 'not assessed', 'unverified')):
            label = 'Not assessed'
        elif row.get('cpu_tier') == 'red':
            label = 'Unsupported for VCF 9.x'
        elif row.get('cpu_tier') == 'yellow':
            label = 'Review / Override Required'
        elif row.get('cpu_tier') == 'green':
            chassis = chassis_qualification(all_results[idx].get('system') or {}, verdict)
            label = 'Server supported' if chassis['qualified'] else 'components certified'
        else:
            label = 'Not assessed'
        server[label].append(idx)
        esa_label = {'Ready': 'Ready', 'StorageMet': 'Storage met / upgrade needed', 'Blocked': 'Blocked / insufficient', 'Insufficient': 'Blocked / insufficient'}.get(row.get('esa_tier'), 'Unknown')
        esa[esa_label].append(idx)
        posture = row.get('sec_posture')
        if posture != 'excluded':
            security[{'baseline_met': 'Baseline met', 'action_req': 'Action suggested', 'partial': 'Partially assessed'}.get(posture, 'Not assessed')].append(idx)
    return [
        {'title': 'Server Readiness', 'total': len(rows), 'counts': server, 'success': 'Server supported', 'statuses': {'components certified': 'info'}, 'note': 'Check vendor qualifications for continued hardware support.'},
        {'title': 'vSAN storage readiness', 'total': len(rows), 'counts': esa, 'success': 'Ready'},
        {'title': 'BMC security', 'total': sum(map(len, security.values())), 'counts': security, 'success': 'Baseline met'},
    ]


def build_fleet_overview_html(all_results: list, groups: Optional[list] = None) -> str:
    """Render consistent counts and index-based evidence links for both fleet pages."""
    cards = []
    for group in (groups if groups is not None else fleet_overview_groups(all_results)):
        items = []
        for label, indices in group['counts'].items():
            status = 'success' if label == group['success'] else ('unknown' if label in ('Unknown', 'Not assessed') else 'warning')
            if label in ('Unsupported', 'Unsupported for VCF 9.x', 'Blocked / insufficient', 'Action suggested'):
                status = 'danger'
            status = group.get('statuses', {}).get(label, status)
            content = f'<span class="report-status report-status-{status}">{_h(label)}</span> <strong>{len(indices)}</strong>'
            if indices:
                values = ','.join(map(str, indices))
                content = f'<a href="#fleet-per-host-table" data-action="overview-evidence" data-host-indices="{values}" data-evidence-label="{_h(group["title"] + ": " + label)}">{content}</a>'
            else:
                content = f'<span class="report-metric-empty">{content}</span>'
            if group['title'] == 'Server Readiness' and label == 'components certified':
                # The label opens policy guidance; the count still opens evidence.
                count = f'<strong>{len(indices)}</strong>'
                if indices:
                    count = (
                        f'<a class="report-component-count" href="#fleet-per-host-table" data-action="overview-evidence" '
                        f'data-host-indices="{values}" data-evidence-label="Server Readiness: components certified" '
                        f'aria-label="Inspect {len(indices)} hosts: components certified">{count}</a>'
                    )
                items.append(
                    '<li class="report-component-row"><span class="report-component-label">'
                    f'<a class="report-component-link" href="{_h(COMPONENT_CERTIFICATION_BLOG)}" '
                    'target="_blank" rel="noopener noreferrer" '
                    'aria-label="components certified — server certification guidance (opens in a new tab)">components certified</a>'
                    '<span class="report-info" data-info-tooltip>'
                    '<button type="button" class="report-info-trigger" '
                    'aria-label="About component certification" aria-describedby="report-components-tooltip">i</button>'
                    f'<span class="report-info-tooltip" role="tooltip" id="report-components-tooltip">{_h(COMPONENT_CERTIFICATION_NOTE)}</span>'
                    f'</span></span> {count}</li>'
                )
                continue
            items.append(f'<li>{content}</li>')
        note = f'<p class="report-qualification-note">{_h(group["note"])}</p>' if group.get('note') else ''
        cards.append(f'<section class="report-overview-card"><h3>{_h(group["title"])}</h3><p>{group["total"]} host(s) in this assessment</p><ul>{"".join(items)}</ul>{note}</section>')
    return (
        '<section class="report-overview" aria-labelledby="report-overview-title">'
        '<h2 id="report-overview-title">Readiness overview</h2>'
        '<p>Inspect exceptions and missing evidence first. Dimensions overlap; counts are not additive. '
        'Security excludes fleet management appliances.</p>'
        f'<div class="report-overview-grid">{"".join(cards)}</div></section>'
        '<div class="report-filter-context" hidden role="status"><span></span> '
        '<button type="button" data-action="clear-overview">Clear assessment filter</button></div>'
    )
