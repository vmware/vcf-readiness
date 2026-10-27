"""Small native disclosure helpers for supporting report evidence."""

from vcf_hci.report.helpers import _h


def evidence_controls_html() -> str:
    """Offer an explicit way to expose evidence for reading, Find and printing."""
    return (
        '<div class="report-evidence-controls" aria-label="Supporting evidence controls">'
        '<button type="button" data-action="expand-evidence">Expand evidence</button>'
        '<button type="button" data-action="collapse-evidence">Collapse supporting evidence</button>'
        '</div>'
    )


def supporting_evidence_html(title: str, body_html: str, count: int, element_id: str) -> str:
    """Wrap already-rendered trusted HTML; escape labels and attributes separately."""
    return (
        f'<details class="report-evidence" data-report-evidence="supporting">'
        f'<summary>{_h(title)} · {int(count)} item(s)</summary>'
        f'<div class="report-evidence-body" id="{_h(element_id)}">{body_html}</div></details>'
    )
