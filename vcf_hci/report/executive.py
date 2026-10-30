"""Evidence-based executive brief and a dependency-free, paginated PDF export."""
import html
import os
import re
import time
from collections import Counter
from typing import Optional

from vcf_hci.report.formatting import without_emojis
from vcf_hci.report.inventory_tables import build_host_decision_rows
from vcf_hci.security.metadata import CONTROL_CATALOG
from vcf_hci.security.scoring import is_fleet_manager_asset


def _plain(value: object, limit: int = 240) -> str:
    return ' '.join(without_emojis(html.unescape(re.sub(r'<[^>]*>', '', str(value or '')))).split())[:limit]


def build_executive_summary(results: list, failed_hosts: Optional[list] = None, obfuscated: bool = False) -> dict:
    """Rank distinct actions by urgency, then affected hosts, then stable title.

    Counts are per dimension and must never be summed into a certification score.
    """
    hosts = [host for host in results if isinstance(host, dict)]
    rows = build_host_decision_rows(hosts)
    metrics = {
        'cpu': Counter(dict.fromkeys(['Supported', 'Review required', 'Unsupported', 'Not assessed'], 0)),
        'storage': Counter(dict.fromkeys(['Ready', 'Upgrade or review', 'Blocked', 'Insufficient', 'Not assessed'], 0)),
        'security': Counter(dict.fromkeys(['Baseline met', 'Action suggested', 'Partially assessed', 'Not assessed', 'Excluded fleet manager'], 0)),
    }
    actions = {}
    seen = {str(row.get('ip') or row.get('hostname') or host.get('host') or '') for host, row in zip(hosts, rows) if not host.get('partial_scan') and not host.get('timed_out')}
    failures = {}
    for index, failed in enumerate(failed_hosts or []):
        if not isinstance(failed, dict):
            continue
        key = str(failed.get('ip') or failed.get('host') or failed.get('hostname') or f'failure-{index}')
        if key not in seen:
            failures[key] = failed

    def add(key, priority, title, action, host_key, label):
        item = actions.setdefault(key, {'priority': priority, 'title': title, 'action': action, 'hosts': {}})
        item['hosts'][host_key] = label
        item['priority'] = min(item['priority'], priority)

    for index, (host, row) in enumerate(zip(hosts, rows)):
        label = f'Host-{index + 1}' if obfuscated else _plain(row.get('ip') or row.get('hostname') or f'Host-{index + 1}', 100)
        key = str(index)
        cpu = row.get('cpu_tier')
        verdict = _plain(row.get('cpu_verdict')).lower()
        cpu_known = bool(verdict) and not any(word in verdict for word in ('unknown', 'not assessed', 'unverified'))
        cpu_status = {'green': 'Supported', 'yellow': 'Review required', 'red': 'Unsupported'}.get(cpu, 'Not assessed') if cpu_known else 'Not assessed'
        metrics['cpu'][cpu_status] += 1
        if cpu_status == 'Unsupported':
            add('cpu-blocked', 1, 'Resolve unsupported CPU platforms', 'Replace or exclude these platforms from the VCF 9.x candidate pool; confirm the target release requirements.', key, label)
        elif cpu_status == 'Review required':
            add('cpu-review', 2, 'Review CPU exceptions and overrides', 'Confirm the documented installation or upgrade override and vendor support conditions before migration.', key, label)
        elif cpu_status == 'Not assessed':
            add('cpu-evidence', 2, 'Complete CPU support evidence', 'Run a complete scan and verify the CPU model against the target release compatibility requirements.', key, label)

        storage_known = bool(host.get('storage_subsystem')) and bool(host.get('network_adapters'))
        storage_status = {'Ready': 'Ready', 'StorageMet': 'Upgrade or review', 'Blocked': 'Blocked', 'Insufficient': 'Insufficient'}.get(row.get('esa_tier'), 'Not assessed') if storage_known else 'Not assessed'
        metrics['storage'][storage_status] += 1
        if storage_status in ('Blocked', 'Insufficient'):
            add('esa-blocked', 1, 'Address vSAN ESA storage and network blockers', 'Review direct-attached NVMe counts, controller mode, VMD, and NIC capacity in the host reports; choose a supported configuration or an alternative design.', key, label)
        elif storage_status == 'Upgrade or review':
            add('esa-review', 2, 'Confirm vSAN design and required upgrades', 'Review storage qualification and network requirements for the intended ESA size profile; an OSA-compatible host is not automatically ESA-ready.', key, label)
        elif storage_status == 'Not assessed':
            add('storage-evidence', 2, 'Complete storage and network evidence', 'Collect the storage and network inventories before accepting an ESA readiness verdict.', key, label)

        excluded = is_fleet_manager_asset(host)
        posture = {'baseline_met': 'Baseline met', 'action_req': 'Action suggested', 'partial': 'Partially assessed'}.get(row.get('sec_posture'), 'Not assessed')
        if excluded:
            metrics['security']['Excluded fleet manager'] += 1
        else:
            metrics['security'][posture] += 1
            findings = (host.get('bmc_security_audit') or {}).get('findings') or []
            failed = [finding for finding in findings if isinstance(finding, dict) and finding.get('status') == 'fail']
            for finding in failed:
                control = _plain(finding.get('control_id') or finding.get('id') or 'unclassified', 64)
                if control not in CONTROL_CATALOG:
                    control = 'unclassified'
                severity = str(finding.get('severity') or '').lower()
                priority = 1 if severity in ('critical', 'high') else 3 if severity == 'low' else 2
                title = _plain(CONTROL_CATALOG.get(control, {}).get('title') or 'BMC hardening control')
                add('security-' + control, priority, f'Review BMC hardening control {control}: {title}', 'Review control applicability, risk, and supporting evidence in the BMC Security section of each affected host report; plan appropriate hardening and rescan. A failed hardening control alone does not establish a VCF upgrade blocker.', key, label)
            if posture == 'Action suggested' and not failed:
                add('security-review', 1, 'Investigate BMC security failures', 'Review the BMC security audit and confirm applicable hardening actions. Detailed control evidence was not available in this summary; a VCF upgrade blocker has not been established.', key, label)
            if posture in ('Partially assessed', 'Not assessed'):
                add('security-evidence', 2, 'Complete BMC security assessment coverage', 'Collect the missing audit controls and verify unknown results. Missing evidence is not a passing security baseline.', key, label)
        drives = [drive for controller in host.get('storage_subsystem') or [] for drive in controller.get('drives') or [] if isinstance(drive, dict) and drive.get('populated', True)]
        drive_fault = any(
            drive.get('failure_predicted')
            or str(drive.get('drive_health') or '').lower() in ('critical', 'warning', 'failed', 'error')
            or (isinstance(drive.get('endurance_remaining_pct'), (int, float)) and 0 <= drive['endurance_remaining_pct'] < 20)
            for drive in drives
        )
        psu_fault = any(str(psu.get('health') or '').lower() in ('critical', 'warning', 'failed', 'error') for psu in (host.get('psu_status') or {}).get('psus') or [] if isinstance(psu, dict))
        if drive_fault or psu_fault or (host.get('memory_subsystem') or {}).get('failed_dimms') or (host.get('thermal_telemetry') or {}).get('fan_faults'):
            add('hardware-health', 1, 'Investigate recorded hardware health faults', 'Review failed DIMMs, PSU/fan alarms, drive health, predictive failure, and low-endurance evidence. Resolve active faults before deployment and rescan.', key, label)
        bios = (host.get('system') or {}).get('bios_eval') or {}
        if 'danger' in str(bios.get('badge') or '') or bios.get('spectre_status') == 'exposed':
            add('bios', 2, 'Review BIOS baseline and mitigation gaps', 'Validate the recorded OEM BIOS baseline and platform mitigation guidance, then plan a supported update and rescan.', key, label)
        if row.get('tpm_ok') is False:
            add('tpm', 1, 'Validate TPM 2.0 configuration', 'Review the recorded TPM version and enabled/activated state against the target platform requirements.', key, label)
        if row.get('vmd_on'):
            add('vmd', 1, 'Review Intel VMD before ESA deployment', 'Validate the storage controller and native NVMe path; confirm the required VMD configuration for the intended deployment.', key, label)
        if row.get('os_eol_is_eol'):
            add('os-lifecycle', 2, 'Plan ESXi lifecycle remediation', 'Confirm the recorded ESXi release support lifecycle and plan the supported upgrade path.', key, label)
        if host.get('partial_scan'):
            add('partial', 2, 'Recover incomplete host scans', 'Rescan missing sections and resolve collection failures before accepting the readiness assessment.', key, label)

    for index, key in enumerate(sorted(failures)):
        label = f'Uncollected-host-{index + 1}' if obfuscated else _plain(key, 100)
        add('failed-scan', 1, 'Restore visibility for failed scan targets', 'Check reachability, credentials, TLS, and scan timeouts, then rerun collection. These targets are outside the assessed-host readiness counts.', 'failed-' + key, label)

    ranked = sorted(actions.values(), key=lambda item: (item['priority'], -len(item['hosts']), item['title']))
    top = []
    for rank, item in enumerate(ranked[:10], 1):
        labels = sorted(item['hosts'].values())
        top.append({'rank': rank, 'priority': f'P{item["priority"]}', 'title': item['title'], 'action': item['action'], 'affected_hosts': len(labels), 'examples': labels[:3]})
    return {'generated_at': time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime()), 'assessed_hosts': len(hosts), 'failed_targets': len(failures), 'partial_hosts': sum(bool(host.get('partial_scan')) for host in hosts), 'metrics': {name: dict(counts) for name, counts in metrics.items()}, 'priorities': top, 'total_action_groups': len(ranked), 'obfuscated': obfuscated}


def executive_html(summary: dict) -> str:
    def esc(value):
        return html.escape(str(value), quote=True)
    cards = []
    for key, title in [('cpu', 'CPU support'), ('storage', 'vSAN ESA readiness'), ('security', 'BMC security')]:
        rows = ''.join(f'<li><span>{esc(label)}</span><strong>{count}</strong></li>' for label, count in summary['metrics'][key].items()) or '<li>Not assessed</li>'
        cards.append(f'<section class="metric"><h2>{title}</h2><ul>{rows}</ul></section>')
    items = ''.join(f'<li><div class="priority-title"><span class="priority">{item["priority"]}</span><h3>{esc(item["title"])}</h3><strong>{item["affected_hosts"]} host(s)</strong></div><p>{esc(item["action"])}</p><p class="muted">Examples: {esc(", ".join(item["examples"]))}</p></li>' for item in summary['priorities'])
    if not items:
        items = '<li>No priority actions were identified in the available evidence. This does not establish certification or replace the detailed assessment.</li>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VCF Readiness Executive Summary</title><style>
body{{font:14px/1.5 'Segoe UI',Arial,sans-serif;color:#243746;margin:0;background:#f4f6f8}}main{{max-width:1000px;margin:auto;padding:32px;background:white}}h1{{font-size:28px;margin:8px 0}}h2{{font-size:18px}}h3{{font-size:15px;margin:0}}.eyebrow,.muted{{color:#526777}}.metrics{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin:24px 0}}.metric{{border:1px solid #c5cdd4;padding:16px}}.metric ul{{padding:0;list-style:none}}.metric li{{display:flex;justify-content:space-between;gap:12px;border-top:1px solid #edf1f4;padding:6px 0}}.context{{border-left:3px solid #0072a3;padding:12px 16px;background:#f4f6f8}}ol{{padding-left:24px}}ol>li{{padding:12px 0;border-bottom:1px solid #c5cdd4;break-inside:avoid}}.priority-title{{display:flex;gap:12px;align-items:baseline;flex-wrap:wrap}}.priority{{font-weight:600;border:1px solid #6c8290;padding:2px 6px}}p{{margin:8px 0}}button{{padding:8px 16px;background:#0072a3;color:white;border:0;cursor:pointer}}@media(max-width:650px){{main{{padding:16px}}.metrics{{grid-template-columns:1fr}}}}@page{{size:A4;margin:16mm}}@media print{{body,main{{background:white;margin:0;padding:0;max-width:none}}button{{display:none}}.metrics{{grid-template-columns:repeat(3,minmax(0,1fr))}}h2,h3{{break-after:avoid}}}}
</style></head><body><main><p class="eyebrow">VCF / vSphere readiness assessment</p><h1>Executive environment summary{' — Obfuscated' if summary['obfuscated'] else ''}</h1><p class="muted">Generated {esc(summary['generated_at'])}</p><p><strong>{summary['assessed_hosts']}</strong> assessed hosts · <strong>{summary['failed_targets']}</strong> failed targets · <strong>{summary['partial_hosts']}</strong> partial scans</p><div class="context">Assessment evidence, not a certification decision. Readiness dimensions overlap and must not be added into a single score. Missing data remains not assessed. BMC fleet managers are excluded from security readiness.</div><div class="metrics">{''.join(cards)}</div><h2>Priority actions — top {len(summary['priorities'])} of {summary['total_action_groups']} identified groups</h2><p class="muted">P1: blockers or urgent review. P2: remediation or evidence completion. P3: lower-severity hardening. Ordered by priority, then affected-host count. A host can appear in several actions.</p><ol>{items}</ol><p class="muted">Scope: evidence collected by this scan. Review host reports and current Broadcom compatibility requirements before deployment. Examples are limited to three hosts per action.</p><button type="button" id="printExecutive">Print / Save as PDF</button></main><script>document.getElementById('printExecutive').addEventListener('click',function(){{window.print();}});</script></body></html>'''


def executive_pdf(summary: dict) -> bytes:
    """Write a valid PDF with Base-14 fonts, wrapping, and automatic page breaks.

    Unsupported glyphs are shown as escaped Unicode rather than silently lost.
    Full Unicode is retained in the companion HTML/print view.
    """
    pages = [[]]
    y = 790

    def pdf_text(value):
        text = str(value).encode('cp1252', 'backslashreplace').decode('cp1252')
        return text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)').replace('\r', ' ').replace('\n', ' ')

    def line(text='', size=10, bold=False, gap=15):
        nonlocal y
        if y < 55:
            pages.append([])
            y = 790
        font = 'F2' if bold else 'F1'
        pages[-1].append(f'BT /{font} {size} Tf 0.14 0.21 0.27 rg 1 0 0 1 44 {y} Tm ({pdf_text(text)}) Tj ET')
        y -= gap

    def wrapped(text, size=10, bold=False):
        # Base-14 Helvetica advance widths, padded for the bold face. The
        # conservative fallback also keeps unusual WinAnsi glyphs in bounds.
        widths = {' ': 278, 'i': 222, 'l': 222, 'I': 278, 'j': 222, 'f': 278, 't': 278,
                  'm': 833, 'w': 722, 'M': 833, 'W': 944, '.': 278, ',': 278, ':': 278,
                  ';': 278, '!': 278, 'r': 333, 's': 500, 'z': 500, 'x': 500, 'v': 500}
        value = str(text).encode('cp1252', 'backslashreplace').decode('cp1252')
        lines, current, advance = [], '', 0.0
        for char in value:
            width = widths.get(char, 700 if char.isupper() else 600) * size / 1000 * (1.08 if bold else 1)
            if advance + width > 500 and current:
                split = current.rfind(' ')
                if split > len(current) // 2:
                    lines.append(current[:split])
                    current = current[split + 1:]
                    advance = sum(widths.get(c, 700 if c.isupper() else 600) * size / 1000 * (1.08 if bold else 1) for c in current)
                else:
                    lines.append(current)
                    current, advance = '', 0.0
            current += char
            advance += width
        if current or not lines:
            lines.append(current)
        return lines

    def paragraph(text, bold=False, size=10):
        for value in wrapped(text, size, bold):
            line(value, size=size, bold=bold)

    line('VCF READINESS | EXECUTIVE SUMMARY', 19, True, 28)
    paragraph('Obfuscated environment brief' if summary['obfuscated'] else 'Environment readiness at a glance', True, 13)
    line(summary['generated_at'], gap=22)
    paragraph(f"Assessed hosts: {summary['assessed_hosts']} | Failed targets: {summary['failed_targets']} | Partial scans: {summary['partial_hosts']}", True)
    paragraph('Assessment evidence, not certification. Dimensions overlap; do not add counts into a single score. Missing evidence is not a pass.')
    line(gap=5)
    for key, title in [('cpu', 'CPU support'), ('storage', 'vSAN ESA readiness'), ('security', 'BMC security')]:
        paragraph(title, True, 12)
        paragraph('; '.join(f'{label}: {count}' for label, count in summary['metrics'][key].items()) or 'Not assessed')
        line(gap=5)
    paragraph(f"Priority actions: top {len(summary['priorities'])} of {summary['total_action_groups']} groups", True, 13)
    paragraph('P1: blockers/urgent review. P2: remediation/evidence. P3: lower-severity hardening. Ranked by priority, then affected hosts. Hosts can appear in multiple actions.')
    line(gap=5)
    for item in summary['priorities']:
        height = 15 * (len(wrapped(f"{item['rank']}. [{item['priority']}] {item['title']} ({item['affected_hosts']} hosts)", bold=True)) + len(wrapped(item['action'])) + len(wrapped('Examples: ' + ', '.join(item['examples'])))) + 20
        if y - height < 55:
            pages.append([])
            y = 790
        paragraph(f"{item['rank']}. [{item['priority']}] {item['title']} ({item['affected_hosts']} hosts)", True)
        paragraph(item['action'])
        paragraph('Examples: ' + ', '.join(item['examples']))
        line(gap=5)
    if not summary['priorities']:
        paragraph('No priority actions identified in the available evidence. Review detailed reports; absence of findings does not establish certification.')
    paragraph('Scope: collected scan evidence. Review detailed host reports and current Broadcom compatibility requirements before deployment. Examples show at most three hosts per action.')
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>', b'', b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>', b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>']
    kids = []
    for index, commands in enumerate(pages, 1):
        commands.append(f'BT /F1 9 Tf 0.32 0.40 0.47 rg 1 0 0 1 44 28 Tm (VCF Readiness | Page {index} of {len(pages)}) Tj ET')
        stream = '\n'.join(commands).encode('cp1252')
        page_id = len(objects) + 1
        kids.append(f'{page_id} 0 R')
        objects.append(f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {page_id + 1} 0 R >>'.encode('ascii'))
        objects.append(f'<< /Length {len(stream)} >>\nstream\n'.encode('ascii') + stream + b'\nendstream')
    objects[1] = f'<< /Type /Pages /Count {len(pages)} /Kids [{" ".join(kids)}] >>'.encode('ascii')
    output = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f'{index} 0 obj\n'.encode('ascii') + obj + b'\nendobj\n')
    xref = len(output)
    output.extend(f'xref\n0 {len(objects) + 1}\n0000000000 65535 f \n'.encode('ascii'))
    for offset in offsets[1:]:
        output.extend(f'{offset:010d} 00000 n \n'.encode('ascii'))
    output.extend(f'trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode('ascii'))
    return bytes(output)


def write_executive_reports(results: list, directory: str, failed_hosts: Optional[list] = None, obfuscated: bool = False) -> tuple:
    summary = build_executive_summary(results, failed_hosts, obfuscated)
    stem = '00_OBFUSCATED_executive_summary' if obfuscated else '00_executive_summary'
    html_path, pdf_path = os.path.join(directory, stem + '.html'), os.path.join(directory, stem + '.pdf')
    with open(html_path, 'w', encoding='utf-8') as stream:
        stream.write(executive_html(summary))
    with open(pdf_path, 'wb') as stream:
        stream.write(executive_pdf(summary))
    return html_path, pdf_path
