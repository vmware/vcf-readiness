"""Combine native hardware and imported VDT evidence in a consultant review brief.

This module renders evidence supplied by callers. It performs no collection,
asset correlation, certification, or implicit health-to-readiness conversion.
"""

import html
import time
from collections import Counter
from typing import Optional

from vcf_hci.report.executive import build_executive_summary

_STATUSES = ('PASS', 'FAIL', 'WARN', 'INFO', 'SKIP', 'UNKNOWN')
_PRODUCTS = {'vcenter': 'vCenter', 'vks': 'VKS', 'sddc_manager': 'SDDC Manager'}


def _text(value: object) -> str:
    return str(value) if value is not None else ''


def _coverage(native: dict, runs: list, has_storage: bool, has_network: bool) -> list:
    hardware = bool(native['assessed_hosts'])
    diagnostics = any(run['findings'] for run in runs)
    return [
        {'area': 'Hardware and compatibility', 'status': 'Partial' if hardware else 'Not assessed',
         'evidence': 'Native Redfish inventory, CPU, BMC security, and compatibility observations.' if hardware else 'No native host evidence supplied.',
         'required': 'Confirm target release, current compatibility data, full host coverage, and firmware support.'},
        {'area': 'Management platform health', 'status': 'Partial' if diagnostics else 'Not assessed',
         'evidence': 'Imported VDT diagnostic snapshots; targets and products are operator declared; collection timestamps come from VDT with unknown timezone.' if diagnostics else 'No VDT findings supplied.',
         'required': 'Full VDT from each in-scope vCenter; identify missing vCenters and review skipped or unknown checks. SDDC Manager and VKS evidence applies only where supplied.'},
        {'area': 'Lifecycle and upgrade path', 'status': 'Partial' if hardware or diagnostics else 'Not assessed',
         'evidence': 'Available hardware and diagnostic observations support review; no end-to-end upgrade path was validated.',
         'required': 'Validate product versions, interoperability, upgrade sequencing, and release-specific prerequisites.'},
        {'area': 'Storage architecture', 'status': 'Partial' if has_storage else 'Not assessed',
         'evidence': 'Native storage observations are present; completeness and ESA qualification require review.' if has_storage else 'No native storage evidence supplied.',
         'required': 'HST, RVTools ALL, capacity/performance baselines, supported vSAN design, and external storage dependencies.'},
        {'area': 'Networking', 'status': 'Partial' if has_network else 'Not assessed',
         'evidence': 'Native NIC inventory is present; link evidence and design coverage require review.' if has_network else 'No native NIC evidence supplied.',
         'required': 'Physical and virtual design, VLANs, MTU, uplinks, routing, and target architecture review.'},
        {'area': 'Operations and resilience', 'status': 'Partial' if diagnostics else 'Not assessed',
         'evidence': 'VDT health observations where present; operational practices have not been validated.',
         'required': 'Customer interviews; backup/restore evidence, monitoring, processes, skills, and change windows.'},
        {'area': 'Workloads and dependencies', 'status': 'Not assessed',
         'evidence': 'The hybrid import does not include workload discovery or dependency analysis.',
         'required': 'RVTools ALL, HST, application dependencies, resource demand, and migration constraints.'},
        {'area': 'Business requirements', 'status': 'Not assessed',
         'evidence': 'No interviews, acceptance criteria, business objectives, or approved scope supplied.',
         'required': 'Agree outcomes, scope, constraints, availability requirements, budget, owners, and sign-off criteria.'},
        {'area': 'NSX / Aria / DR / integrations', 'status': 'Not assessed',
         'evidence': 'No dedicated assessment of these domains is performed by this fusion.',
         'required': 'Product-specific discovery, architecture and interoperability review, and recovery validation.'},
        {'area': 'RVTools ALL and HST deliverables', 'status': 'Not assessed',
         'evidence': 'These exports have not been ingested by this prototype.',
         'required': 'Collect and review both PSO-requested inputs separately; attach references to the consultant deliverable.'},
    ]


def build_hybrid_summary(results: list, failed_hosts: Optional[list] = None,
                         vdt_runs: Optional[list] = None) -> dict:
    """Build a partial assessment while preserving source and denominator boundaries.

    VDT counts describe checks in imported snapshots, not unique appliances.
    Targets and products are operator declarations. Collection time is VDT-origin
    metadata with unknown timezone, not independent freshness verification.
    Unknown states and empty imports never become passing observations.
    """
    native = build_executive_summary(results, failed_hosts)
    runs = []
    counts = Counter(dict.fromkeys(_STATUSES, 0))
    groups = {}
    for index, source in enumerate(vdt_runs or [], 1):
        if not isinstance(source, dict):
            continue
        run: dict = {key: _text(source.get(key)) for key in (
            'product', 'target', 'collected_at', 'filename', 'sha256', 'imported_at')}
        run['version'] = _text(source.get('version') or source.get('vdt_version'))
        run['collection_scope'] = source.get('collection_scope') if isinstance(source.get('collection_scope'), dict) else {}
        run['id'] = f'VDT-{index}'
        run['findings'] = []
        raw_findings = source.get('findings')
        for raw in raw_findings if isinstance(raw_findings, list) else []:
            if not isinstance(raw, dict):
                continue
            status = _text(raw.get('status')).upper()
            status = status if status in _STATUSES else 'UNKNOWN'
            finding = {'status': status, 'category': _text(raw.get('category')) or 'Uncategorized',
                       'title': _text(raw.get('title')) or 'Unnamed check',
                       'details': _text(raw.get('details'))}
            run['findings'].append(finding)
            counts[status] += 1
            if status in ('FAIL', 'WARN', 'SKIP', 'UNKNOWN'):
                key = (status, run['product'], finding['category'], finding['title'])
                group = groups.setdefault(key, {
                    'status': status, 'product': run['product'], 'category': finding['category'],
                    'title': finding['title'], 'occurrences': 0, 'sources': [],
                })
                group['occurrences'] += 1
                if run['id'] not in group['sources']:
                    group['sources'].append(run['id'])
        runs.append(run)
    order = {'FAIL': 0, 'WARN': 1, 'UNKNOWN': 2, 'SKIP': 3}
    priorities = sorted(groups.values(), key=lambda row: (
        order[row['status']], -row['occurrences'], row['product'], row['title']))
    has_hardware = bool(native['assessed_hosts'])
    has_diagnostics = any(run['findings'] for run in runs)
    has_storage = any(isinstance(host, dict) and bool(host.get('storage_subsystem')) for host in results)
    has_network = any(isinstance(host, dict) and bool(host.get('network_adapters')) for host in results)
    impacts = []
    if any(row['priority'] == 'P1' for row in native['priorities']):
        impacts.append('Native priority findings require review before committing hardware to the target design; replacement, configuration remediation, or evidence recovery may affect scope and schedule.')
    if counts['FAIL']:
        impacts.append(f"{counts['FAIL']} failed VDT check observation(s) require technical triage before an upgrade decision. A FAIL may indicate timeout or collection failure rather than a confirmed defect. A failed diagnostic check is not automatically a migration blocker.")
    if counts['WARN']:
        impacts.append(f"{counts['WARN']} VDT warning observation(s) may add remediation or validation work; confirm relevance and business impact with the platform owner.")
    if not impacts:
        impacts.append('No urgent business impact was established by the supplied evidence. Missing evidence and the absence of failures do not establish readiness.')
    impacts.append('The assessment remains partial until scope, missing discovery inputs, dependencies, and customer requirements are reviewed. Hardware readiness and management health use different populations and are not combined into a score.')
    return {
        'generated_at': time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime()),
        'assessment_status': 'Partial assessment' if has_hardware or has_diagnostics else 'Not assessed',
        'native': native, 'vdt_runs': runs, 'vdt_counts': dict(counts),
        'vdt_priorities': priorities, 'coverage': _coverage(native, runs, has_storage, has_network),
        'business_impact': impacts,
        'next_steps': [
            'Confirm the target release, customer objectives, in-scope environments, and accountable owners.',
            'Obtain RVTools ALL, HST, full VDT from every in-scope vCenter, and customer interviews; review other domains separately.',
            'Validate source targets and collection times, identify missing or stale snapshots, and map appliances to physical hosts using verified inventory.',
            'Review findings, distinguish Blocking / Conditional / Advisory impact, agree remediation owners and dates, then recollect evidence after changes.',
        ],
    }


def hybrid_html(summary: dict) -> str:
    """Render a standalone, printable brief with full imported diagnostic appendix."""
    def esc(value: object) -> str:
        return html.escape(_text(value), quote=True)

    native = summary['native']
    runs = summary['vdt_runs']
    counts = summary['vdt_counts']
    metrics = []
    for name, label in (('cpu', 'CPU support'), ('storage', 'vSAN ESA readiness'), ('security', 'BMC security')):
        rows = ''.join(f'<tr><td>{esc(status)}</td><td>{count}</td></tr>'
                       for status, count in native['metrics'][name].items())
        metrics.append(f'<section class="card"><h3>{label}</h3><table><tbody>{rows}</tbody></table></section>')
    vdts = ''.join(f'<span class="stat"><strong>{count}</strong> {status}</span>' for status, count in counts.items())
    impact = ''.join(f'<li>{esc(line)}</li>' for line in summary['business_impact'])
    next_steps = ''.join(f'<li>{esc(line)}</li>' for line in summary['next_steps'])
    coverage = ''.join(
        f'<tr><th scope="row">{esc(row["area"])}</th><td>{esc(row["status"])}</td>'
        f'<td>{esc(row["evidence"])}</td><td>{esc(row["required"])}</td></tr>'
        for row in summary['coverage'])
    native_actions = []
    remediation = []
    for item in native['priorities']:
        reference = f'Native action {item["rank"]} — {item["affected_hosts"]} host(s): ' + ', '.join(item['examples'])
        native_actions.append(
            f'<tr><td>{esc(item["priority"])}</td><td>{esc(item["title"])}</td>'
            f'<td>{item["affected_hosts"]} host(s): {esc(", ".join(item["examples"]))}</td>'
            f'<td>{esc(item["action"])}</td></tr>')
        remediation.append((reference, item['title'], item['action']))
    vdt_actions = []
    for item in summary['vdt_priorities']:
        product = _PRODUCTS.get(item['product'], item['product'] or 'Unspecified product')
        action = ('Review the failed check and supporting VDT details with the platform owner; validate applicability, remediate through the approved process, and rerun VDT.'
                  if item['status'] == 'FAIL' else
                  'Review the warning, confirm its relevance to the target design, agree remediation, and rerun the affected checks.'
                  if item['status'] == 'WARN' else
                  'Recover missing diagnostic coverage; determine why this check was skipped or unclassified and recollect evidence.')
        sources = ', '.join(item['sources'])
        vdt_actions.append(
            f'<tr><td>{esc(item["status"])}</td><td>{esc(product)} / {esc(item["category"])}<br>{esc(item["title"])}</td>'
            f'<td>{item["occurrences"]} check observation(s)<br>{esc(sources)}</td><td>{esc(action)}</td></tr>')
        remediation.append((sources, item['title'], action))
    remediation_rows = []
    for reference, finding, recommendation in remediation:
        remediation_rows.append(
            '<tr>'
            f'<td>{esc(reference)}</td><td><strong>Finding:</strong> {esc(finding)}'
            '<br><strong>Discussion / implication:</strong> <span contenteditable="true" role="textbox" aria-label="Discussion and business implication">Consultant review required</span></td>'
            '<td><span contenteditable="true" role="textbox" aria-label="Business impact classification">Pending consultant classification</span></td>'
            '<td contenteditable="true" role="textbox" aria-label="Risk severity">Pending consultant assessment</td>'
            f'<td><strong>Recommendation:</strong> {esc(recommendation)}<br><strong>Remediation / acceptance:</strong> '
            '<span contenteditable="true" role="textbox" aria-label="Remediation and acceptance criteria">Agree plan and validate new evidence</span></td>'
            '<td contenteditable="true" role="textbox" aria-label="Remediation owner">Unassigned</td>'
            '<td contenteditable="true" role="textbox" aria-label="Target date">To agree</td></tr>')
    appendices = []
    for run in runs:
        product = _PRODUCTS.get(run['product'], run['product'] or 'Unspecified product')
        rows = ''.join(
            f'<tr><td>{esc(finding["status"])}</td><td>{esc(finding["category"])}</td>'
            f'<td>{esc(finding["title"])}</td><td class="details">{esc(finding["details"])}</td></tr>'
            for finding in run['findings'])
        rows = rows or '<tr><td colspan="4">No diagnostic findings supplied; not assessed.</td></tr>'
        scope = run.get('collection_scope') or {}
        scope_rows = ''.join(f'<li>{esc(note)}</li>' for note in scope.get('scope_notes', []))
        excluded = ', '.join(_text(value) for value in scope.get('checks_excluded', []))
        omitted = ', '.join(_text(value) for value in scope.get('checks_not_executed', []))
        scope_html = ('<div class="notice"><strong>Collection scope reported by the collector</strong>'
                      f'<p>Adapter: {esc(scope.get("adapter", ""))}</p><ul>{scope_rows}</ul>'
                      f'<p>Excluded checks: {esc(excluded) or "Not listed"}</p>'
                      f'<p>Selected checks not executed: {esc(omitted) or "None recorded"}</p></div>') if scope else ''
        appendices.append(
            f'<section class="source"><h3>{esc(run["id"])} — {esc(product)}</h3><dl>'
            f'<dt>Declared target</dt><dd>{esc(run["target"]) or "Not supplied"}</dd>'
            f'<dt>VDT collection time (timezone unknown)</dt><dd>{esc(run["collected_at"]) or "Not recorded — freshness unknown"}</dd>'
            f'<dt>VDT version</dt><dd>{esc(run["version"]) or "Not recorded"}</dd>'
            f'<dt>Import time</dt><dd>{esc(run["imported_at"]) or "Not supplied"}</dd>'
            f'<dt>Source file</dt><dd>{esc(run["filename"]) or "Not supplied"}</dd>'
            f'<dt>Source SHA-256</dt><dd class="hash">{esc(run["sha256"]) or "Not supplied"}</dd></dl>{scope_html}'
            '<table><thead><tr><th>Status</th><th>Category</th><th>Check</th><th>Details</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></section>')
    native_table = ''.join(native_actions) or '<tr><td colspan="4">No native priority actions in supplied evidence. Review collection coverage before drawing conclusions.</td></tr>'
    vdt_table = ''.join(vdt_actions) or '<tr><td colspan="4">No actionable VDT observations in supplied evidence. Missing checks and missing appliances remain not assessed.</td></tr>'
    remediation_table = ''.join(remediation_rows) or '<tr><td colspan="7">Collect and review evidence before assigning remediation.</td></tr>'
    appendix = ''.join(appendices) or '<p>No VDT snapshots imported. Management diagnostic health is not assessed.</p>'
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>VCF Hybrid Assessment — Executive Review</title><style>
body{{font:14px/1.5 'Segoe UI',Arial,sans-serif;color:#243746;background:#eef2f5;margin:0}}main{{max-width:1200px;background:#fff;margin:auto;padding:32px}}h1{{font-size:28px}}h2{{margin-top:28px;font-size:21px}}h3{{font-size:16px}}.muted{{color:#526777}}.notice{{border-left:4px solid #0072a3;background:#eef6fa;padding:12px 16px}}.cards{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}}.card{{border:1px solid #c5cdd4;padding:12px}}.stat{{display:inline-block;padding:8px 14px;margin:3px;border:1px solid #c5cdd4}}table{{border-collapse:collapse;width:100%;margin:12px 0;table-layout:fixed}}th,td{{border:1px solid #c5cdd4;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}}thead{{background:#edf2f5}}dl{{display:grid;grid-template-columns:190px 1fr}}dt{{font-weight:600}}dd{{margin:0 0 8px;overflow-wrap:anywhere}}.details{{white-space:pre-wrap}}.hash{{font:12px monospace}}[contenteditable]{{background:#fff9d8;min-width:3em;outline:1px dashed #8195a3}}button{{padding:8px 14px;margin:12px 8px 0 0;background:#0072a3;color:#fff;border:0;cursor:pointer}}.source{{margin:24px 0}}@media(max-width:700px){{main{{padding:16px}}.cards{{grid-template-columns:1fr}}dl{{grid-template-columns:1fr}}table{{font-size:12px}}}}@page{{size:A4 landscape;margin:15mm}}@media print{{body,main{{background:white;margin:0;padding:0;max-width:none}}button,.editing-help{{display:none}}.executive{{break-after:page;font-size:12px;line-height:1.4}}.executive h1{{font-size:25px;margin:8px 0}}.executive h2{{font-size:17px;margin-top:12px}}.executive p{{margin:8px 0}}h2,h3{{break-after:avoid}}tr{{break-inside:avoid}}[contenteditable]{{background:transparent;outline:0}}.source{{break-before:page}}thead{{display:table-header-group}}}}
</style></head><body><main>
<section class="executive"><p class="muted">VCF readiness assessment · Hardware and management diagnostics</p>
<h1>Hybrid executive review</h1><p><strong>{esc(summary['assessment_status'])}</strong> · Generated {esc(summary['generated_at'])}</p>
<div class="notice">This is a partial assessment assembled from separate evidence sources. It does not establish certification, an approved upgrade path, or completion of the PSO engagement. No host-to-appliance association has been inferred.</div>
<h2>Scope and current state</h2><p><strong>{native['assessed_hosts']}</strong> native host result(s), <strong>{native['failed_targets']}</strong> failed target(s), <strong>{native['partial_hosts']}</strong> partial host scan(s); <strong>{len(runs)}</strong> imported VDT snapshot(s), <strong>{sum(counts.values())}</strong> diagnostic check observation(s). Repeated snapshots can include the same appliance or check; these are not unique-asset counts.</p>
<h2>Business implications</h2><ul>{impact}</ul><h2>Decision and next steps</h2><ol>{next_steps}</ol>
<p class="muted">Consultant decision: <span contenteditable="true" role="textbox" aria-label="Consultant executive decision">Pending evidence review, customer requirements, and agreed acceptance criteria.</span></p>
<button type="button" id="printHybrid">Print / Save as PDF</button><button type="button" id="saveHybrid">Save annotated HTML</button>
<p class="editing-help muted">Yellow fields are editable in this document. Save annotated HTML to retain changes, or print to PDF. Edits do not update scanner evidence. Business impact and risk severity require consultant classification; diagnostic status and native priority are separate evidence.</p></section>
<h2>Hardware readiness — native scanner</h2><p class="muted">Counts describe native host results. Dimensions overlap and must not be summed into a score. BMC fleet managers are excluded from security readiness.</p><div class="cards">{''.join(metrics)}</div>
<table><thead><tr><th>Priority</th><th>Finding</th><th>Affected native hosts</th><th>Recommendation</th></tr></thead><tbody>{native_table}</tbody></table>
<h2>Management diagnostic health — VDT</h2><p class="muted">Counts describe imported checks. PASS means only that the reported diagnostic check passed. SKIP and UNKNOWN are coverage gaps. Imported checks are not hardware compatibility verdicts. A FAIL may reflect a timeout or collection failure rather than a confirmed defect. Authentication- or service-excluded checks can be absent from the VDT JSON entirely; absence cannot be counted as PASS or SKIP.</p><div>{vdts}</div>
<table><thead><tr><th>Status</th><th>Finding</th><th>Observations / sources</th><th>Recommendation</th></tr></thead><tbody>{vdt_table}</tbody></table>
<h2>Assessment coverage and required evidence</h2><p>Use this matrix to complete the consultant assessment. “Partial” describes available evidence, not a passing control. RVTools ALL, HST, customer interviews, and dedicated domain reviews remain required.</p>
<table><thead><tr><th>Domain / input</th><th>Coverage</th><th>Available evidence</th><th>Required follow-up</th></tr></thead><tbody>{coverage}</tbody></table>
<h2>Gap and remediation register</h2><p class="muted">Review each discussion, finding, recommendation, and remediation. Confirm Blocking / Conditional / Advisory impact, accountable owner, and target date with the customer. Native priorities show the executive engine's top action groups; detailed host reports remain the full native record. Every imported VDT finding appears in the appendix.</p>
<table><thead><tr><th>Affected sources / hosts</th><th>Discussion / finding</th><th>Business impact</th><th>Risk severity</th><th>Recommendation / remediation</th><th>Owner</th><th>Target date</th></tr></thead><tbody>{remediation_table}</tbody></table>
<h2>Evidence appendix — imported VDT snapshots</h2><p class="muted">Targets and products are declared by the importing operator. Collection timestamps and VDT version come from the export; legacy collection timestamps have no timezone, so timezone and freshness require validation. Import time is not collection time. Compare snapshots with native scan dates before relying on their combined relevance. SHA-256 identifies the source bytes; it does not authenticate the producer. Preserve original exports and detailed native host reports with this assessment.</p>{appendix}
</main><script>
document.getElementById('printHybrid').addEventListener('click', function(){{window.print();}});
document.getElementById('saveHybrid').addEventListener('click', function(){{
  var content = '<!doctype html>\\n' + document.documentElement.outerHTML;
  var url = URL.createObjectURL(new Blob([content], {{type:'text/html;charset=utf-8'}}));
  var link = document.createElement('a');link.href = url;link.download = 'hybrid_assessment_annotated.html';link.click();
  setTimeout(function(){{URL.revokeObjectURL(url);}}, 1000);
}});
</script></body></html>'''
