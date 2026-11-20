"""Offline MTAT evidence panel shared by standalone and fleet reports."""
import csv
import html
from io import StringIO
from typing import Sequence

from vcf_hci.plugins.mtat.constants import WARNING
from vcf_hci.plugins.mtat.csv_export import render_hosts, render_vms
from vcf_hci.plugins.mtat.models import Assessment
from vcf_hci.plugins.mtat.reporting import render_matrix_csv, summarize_assessment


def _table(text: str) -> str:
    rows = list(csv.reader(StringIO(text)))
    if not rows:
        return '<p>No rows collected.</p>'
    header = ''.join('<th>' + html.escape(cell) + '</th>' for cell in rows[0])
    body = ''.join('<tr>' + ''.join('<td>' + html.escape(cell) + '</td>' for cell in row) + '</tr>' for row in rows[1:])
    return '<div style="overflow:auto"><table><thead><tr>' + header + '</tr></thead><tbody>' + body + '</tbody></table></div>'


def render_mtat_panel(assessments: Sequence[Assessment]) -> str:
    parts = ['<section aria-label="MTAT assessment"><h2>MTAT assessment</h2>',
             '<p>Collected workload evidence. Real-time snapshots describe current usage; history uses retained samples. Missing evidence remains unknown.</p>']
    parts.append('<p>' + html.escape(WARNING) + '</p>')
    for assessment in assessments:
        summary = summarize_assessment(assessment)
        parts.append('<h3>' + html.escape(assessment.range_name) + '</h3>')
        parts.append('<p>Source: ' + html.escape(assessment.source_kind + ' / ' + assessment.source_label) +
                     ' · Policy: ' + html.escape(assessment.policy) +
                     ' · Validation: ' + html.escape(assessment.validation_lane) + '</p>')
        for warning in assessment.warnings:
            parts.append('<p>' + html.escape(warning) + '</p>')
        parts.append('<h4>Workload graphs</h4><p>Range aggregates, not a sample timeline. Percentages use the same evidence and calculations as the assessment page.</p>')
        for item in summary['checklist']:
            value = float(item['value_pct'])
            parts.append('<div class="mtat-chart"><strong>' + html.escape(item['metric']) +
                         '</strong> · ' + html.escape(item['value_label']) +
                         '<div class="mtat-track" role="img" aria-label="' +
                         html.escape(item['metric'] + ': ' + item['value_label'], quote=True) +
                         '"><div class="mtat-bar" style="width:%.2f%%"></div></div><p>' % max(0, min(100, value)) +
                         html.escape(item['status'] + ' · Target ' + item['target'] + ' ' + item['note']) + '</p></div>')
        parts.append('<h4>Sizing and savings</h4><p>Projections for all three tiering ratios; review evidence gaps before using them for deployment.</p>')
        parts.append('<div class="mtat-sizing-grid">')
        for ratio in summary['sizing']['ratios'].values():
            fields = [('Recommended NVMe (GB)', 'recommended_nvme_gb'),
                      ('Effective capacity (GB)', 'effective_tiered_capacity_gb'),
                      ('Reclaimable DRAM (GB)', 'reclaimable_dram_gb'),
                      ('DRAM savings (%)', 'dram_savings_pct'),
                      ('Minimum DRAM (GB)', 'min_dram_required_gb')]
            parts.append('<div class="mtat-sizing-card"><h5>' + html.escape(ratio['ratio_label']) + '</h5><dl>' +
                         ''.join('<dt>' + label + '</dt><dd>' + html.escape(str(ratio[key])) + '</dd>'
                                 for label, key in fields) + '</dl><p><strong>' +
                         ('Viable projection' if ratio['viable'] else 'Review required') + '</strong></p><p>' +
                         html.escape(ratio['guidance']) + '</p></div>')
        parts.append('</div>')
        for title, renderer in [('Qualification matrix', lambda item: render_matrix_csv((item,))), ('Hosts', render_hosts), ('Virtual machines', render_vms)]:
            parts.append('<h4>' + title + '</h4>' + _table(renderer(assessment)))
        if assessment.failed_vms:
            parts.append('<h4>Failed VM collection</h4><ul>' + ''.join('<li>' + html.escape(name) + '</li>' for name in assessment.failed_vms) + '</ul>')
    return ''.join(parts) + '</section>'


def standalone_report(panel: str, title: str = 'MTAT assessment') -> str:
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><title>' + html.escape(title) +
            '</title><style>.mtat-sizing-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1rem}.mtat-sizing-card{border:1px solid #c5d0d8;border-radius:6px;padding:1rem;break-inside:avoid}.mtat-sizing-card h5{font-size:1rem;margin:0 0 1rem}.mtat-sizing-card dl{display:grid;grid-template-columns:1fr auto;gap:.5rem}.mtat-sizing-card dd{margin:0}.mtat-chart{margin:1rem 0;break-inside:avoid}.mtat-track{height:1rem;background:#e9eef2;max-width:50rem}.mtat-bar{height:100%;background:#0079b8;print-color-adjust:exact}dt{font-weight:600}dd{margin-bottom:.4rem}body{font:15px system-ui;margin:2rem;color:#20323d;line-height:1.45}h2{color:#00567a}h3{border-bottom:2px solid #0079b8;padding-bottom:.5rem}h4{margin-top:1.8rem}@media(max-width:600px){body{margin:1rem}.mtat-sizing-grid{grid-template-columns:1fr}}table{border-collapse:collapse}th,td{padding:.5rem;border:1px solid #999;text-align:left}th{background:#e9eef2;color:#182832}</style><body>' + panel + '</body></html>')


def render_upstream_panel(calculation: dict) -> str:
    """Render upstream decisions verbatim; the host does not repeat MTAT math."""
    parts = ['<section aria-label="Upstream MTAT assessment"><h2>MTAT upstream assessment</h2>',
             '<p>Source: installed MTAT integration plugin. Requested ranges, evidence gaps and sizing assumptions remain in the standalone export.</p>']
    for cluster in calculation.get('clusters', []):
        parts.append('<h3>' + html.escape(str(cluster.get('cluster', 'Cluster'))) + ' — ' + html.escape(str(cluster.get('range_name', ''))) + '</h3>')
        parts.append('<p>Candidate: ' + html.escape(str(cluster.get('candidate', 'Unknown'))) + '</p>')
        sizing = cluster.get('sizing') or {}
        parts.append('<p>Sizing: ' + html.escape(str(sizing.get('status', 'Unknown'))) + '</p>')
        for key in ('blocked_reasons', 'assumptions'):
            values = sizing.get(key) or []
            if values:
                parts.append('<ul>' + ''.join('<li>' + html.escape(str(value)) + '</li>' for value in values) + '</ul>')
        summary = cluster.get('summary') or {}
        parts.append('<dl>' + ''.join('<dt>' + html.escape(str(k)) + '</dt><dd>' + html.escape(str(v)) + '</dd>'
                                     for k, v in summary.items() if not isinstance(v, (dict, list))) + '</dl>')
    return ''.join(parts) + '</section>'
