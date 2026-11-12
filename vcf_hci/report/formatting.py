"""Shared report layout/icon rendering and text-only executive sanitization."""
import re
from html import escape

from vcf_hci.report.layout import apply_report_layout
from vcf_hci.ui_clarity import CLARITY_LICENSE_NOTICE, icon_html, replace_ui_icons

_EMOJI = re.compile('[\U0001f000-\U0001faff\u2600-\u26ff\u2700-\u27bf\ufe0e\ufe0f\u200d\u20e3]')
_STATUS = str.maketrans({'✅': '✓', '❌': '✗', '⚠': '!', '🟢': '●', '🟡': '●', '🔴': '●'})


def compact_storage_tier_labels(value: str) -> str:
    """Short display names for OSA roles; retain canonical HCL source values."""
    return value.replace('vSAN All Flash Caching Tier', 'OSA Flash Cache').replace(
        'vSAN All Flash Capacity Tier', 'OSA Capacity Tier'
    )


def without_emojis(value: str) -> str:
    """Remove pictographs while retaining text, math, and monochrome status signs."""
    return _EMOJI.sub(lambda match: match[0] if match[0] in ('✓', '✗', '✔', '✕') else '', str(value).translate(_STATUS))


def format_report_html(source: str) -> str:
    """Apply shared containment and icons without altering collected or user text."""
    source = replace_ui_icons(apply_report_layout(source))
    if "data-clarity-icon=" in source and CLARITY_LICENSE_NOTICE not in source:
        source = source.replace("</head>", "<!--\n" + CLARITY_LICENSE_NOTICE + "\n-->\n</head>", 1)
    return source


def fleet_tpm_badge(system: dict) -> str:
    """Compact fleet status; preserve unknown and legacy TPM evidence."""
    interface = str(system.get("tpm_interface") or "").strip()
    state = str(system.get("tpm_state") or "").strip()
    raw = str(system.get("tpm_status_badge") or "<span class='badge warning'>Unknown</span>")
    text = re.sub(r'<[^>]+>', '', raw).lower()
    if interface == 'TPM 1.2' or re.search(r'\btpm\s*1\.2\b', text):
        return "<span class='badge danger'>TPM 1.2</span>"
    if state.lower() == 'disabled' or 'disabled' in text:
        return "<span class='badge warning'>Disabled</span>"
    if (re.sub(r'[\s_-]', '', state.lower()) in ('absent', 'missing', 'notpresent')
            or re.search(r'\b(?:missing|absent|not\s+present|no\s+tpm)\b', text)):
        return "<span class='badge danger'>Missing</span>"
    if ((interface == 'TPM 2.0' and state.lower() == 'enabled')
            or ('2.0' in text and 'success' in raw and not any(w in text for w in ('unknown', 'absent', 'not detected')))):
        return ('<span class="fleet-tpm-present success" role="img" aria-label="TPM present" title="TPM present" '
                'style="display:inline-flex;color:var(--success);vertical-align:middle">'
                + icon_html('success-standard') + '</span>')
    return re.sub(r"\s+FW\s+[^\s<)]+", "", raw)


def fleet_host_os_cell(host: dict) -> tuple:
    """Return escaped OS display and sort value for either fleet host list."""
    os_info = host.get('host_os') or {}
    label = str(os_info.get('esxi_update_label') or os_info.get('os_name') or os_info.get('os_description') or '')
    version = str(os_info.get('os_version') or os_info.get('os_build') or '')
    content = escape(label) if label else '—'
    if version and version not in label:
        content += '<br><small>' + escape(version) + '</small>'
    return content, label or 'zzz'
