"""Offline MTAT evidence panel shared by standalone and fleet reports."""
import csv
import html
from io import StringIO
from typing import Sequence

from vcf_hci.plugins.mtat.csv_export import render_hosts, render_vms
from vcf_hci.plugins.mtat.models import Assessment
from vcf_hci.plugins.mtat.reporting import render_matrix_csv


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
    for assessment in assessments:
        parts.append('<h3>' + html.escape(assessment.range_name) + '</h3>')
        for title, renderer in [('Qualification matrix', lambda item: render_matrix_csv((item,))), ('Hosts', render_hosts), ('Virtual machines', render_vms)]:
            parts.append('<h4>' + title + '</h4>' + _table(renderer(assessment)))
    return ''.join(parts) + '</section>'


def standalone_report(panel: str, title: str = 'MTAT assessment') -> str:
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><title>' + html.escape(title) +
            '</title><style>body{font:15px system-ui;margin:2rem}table{border-collapse:collapse}th,td{padding:.5rem;border:1px solid #999;text-align:left}th{background:#e9eef2;color:#182832}</style><body>' + panel + '</body></html>')


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
