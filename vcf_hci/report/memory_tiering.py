"""Presentation of Memory Tiering evidence without changing vSAN verdicts."""
from html import escape
from typing import Optional

from vcf_hci.hcl.memory_tiering import (
    memory_tiering_matches,
    namespace_candidate_source,
    namespace_preview_enabled,
)
from vcf_hci.hcl.memory_tiering_data import active_catalog
from vcf_hci.ui_clarity import icon_html


def host_memory_tiering_drives(host: dict, json_hcl: Optional[dict] = None) -> dict:
    """Count physical drive availability once, including RI only when enabled."""
    from vcf_hci.hcl import evaluate_drive_hcl_tier

    listed = read_intensive = 0
    for ctrl in host.get('storage_subsystem') or []:
        for drive in ctrl.get('drives') or []:
            protocol = str(drive.get('protocol') or '').upper()
            category = str(drive.get('category') or '')
            if (not drive.get('populated', True) or drive.get('is_boot') or category == 'Boot Device'
                    or category.startswith('Unsupported NVMe') or ctrl.get('is_vmd')
                    or any(drive.get(key) for key in ('behind_vmd', 'behind_trimode', 'behind_software_raid'))
                    or (protocol and 'NVME' not in protocol and 'PCIE' not in protocol)):
                continue
            if memory_tiering_matches(drive, json_hcl):
                listed += 1
            elif namespace_preview_enabled():
                evaluation = evaluate_drive_hcl_tier(drive, json_hcl=json_hcl)
                if namespace_candidate_source(drive, evaluation, json_hcl):
                    read_intensive += 1
    return {'listed': listed, 'read_intensive': read_intensive, 'total': listed + read_intensive}


def memory_tiering_count_badge(counts: dict) -> str:
    title = escape(f'{counts["listed"]} BCG-listed; {counts["read_intensive"]} TLC RI 1 DWPD. '
                   'Drive availability only; verify firmware, release, namespace sizing and dedicated use.', quote=True)
    return f'<span class="badge {"info" if counts["total"] else "neutral"}" title="{title}">{counts["total"]}</span>'


def drive_memory_tiering_badges(drive: dict, evaluation: dict, json_hcl: Optional[dict] = None, stacked: bool = False) -> str:
    parts = []
    label = icon_html('memory') + ' Memory Tiering' if stacked else 'Mem Tier'
    for name, partner, product_id, releases in memory_tiering_matches(drive, json_hcl):
        title = escape(f'BCG listing: {name}; {partner}; {", ".join(releases)}. '
                       f'Snapshot {active_catalog(json_hcl)["fetched_at"]}. Verify firmware, release and deployment requirements.', quote=True)
        parts.append(f'<a class="badge {"success" if stacked else "info"}" target="_blank" rel="noopener" title="{title}" '
                     f'href="https://compatibilityguide.broadcom.com/detail?program=memorytier&amp;productId={escape(product_id, quote=True)}&amp;persona=live">{label}</a>')
    source = namespace_candidate_source(drive, evaluation, json_hcl) if namespace_preview_enabled() else None
    if source:
        title = escape('Namespace sizing required; verify deployment requirements. TLC / 1 DWPD evidence: ' + source, quote=True)
        parts.append(f'<a class="badge info" title="{title}" href="#nvme-namespace-preview">{label} — TLC RI 1 DWPD</a>')
    if stacked:
        return ''.join('<div class="drive-memory-tiering" style="margin-top:.3rem">' + part + '</div>' for part in parts)
    return '<br>' + ' '.join(parts) if parts else ''


def host_memory_tiering_status(host: dict, json_hcl: Optional[dict] = None, compact: bool = False) -> str:
    """Show drive availability under Memory using the fleet's shared predicate."""
    counts = host_memory_tiering_drives(host, json_hcl)
    if not counts['total']:
        return ''
    title = escape(f'{counts["listed"]} BCG-listed; {counts["read_intensive"]} TLC RI 1 DWPD. '
                   'Drive availability; verify firmware, namespace sizing and dedicated use.', quote=True)
    if compact:
        return (f'<a class="badge success host-memory-tiering-badge tab-jump-link" title="{title}" '
                'href="#tab-memory" data-jump-tab="tab-memory">'
                + icon_html('check', 'Drive available') + ' NVMe Tiering</a>')
    return (f'<div class="host-memory-tiering-status" data-memory-tiering-count="{counts["total"]}" '
            f'title="{title}" style="margin:.75rem 0;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap">'
            '<span style="color:var(--success);display:inline-flex;align-items:center;gap:.35rem">'
            + icon_html('check', 'Drive available') + '<strong>NVMe Tiering drive</strong></span>'
            f'<span>{counts["total"]} identified</span> '
            '<a class="btn-link tab-jump-link" href="#tab-storage" data-jump-tab="tab-storage">View drives</a></div>')


def namespace_help_html() -> str:
    if not namespace_preview_enabled():
        return ''
    from vcf_hci.web.docs_data import DOCS_DATA

    return ('<details id="nvme-namespace-preview"><summary>NVMe namespace sizing — Help</summary>'
            + DOCS_DATA['nvme_namespace']['html'] + '</details>')
