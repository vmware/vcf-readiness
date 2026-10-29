"""Shared report layout/icon rendering and text-only executive sanitization."""
import re
from html import escape

from vcf_hci.report.layout import apply_report_layout
from vcf_hci.ui_clarity import CLARITY_LICENSE_NOTICE, replace_ui_icons

_EMOJI = re.compile('[\U0001f000-\U0001faff\u2600-\u26ff\u2700-\u27bf\ufe0e\ufe0f\u200d\u20e3]')
_STATUS = str.maketrans({'✅': '✓', '❌': '✗', '⚠': '!', '🟢': '●', '🟡': '●', '🔴': '●'})


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
    """Keep firmware inventory out of the fleet's TPM status label."""
    interface = str(system.get("tpm_interface") or "").strip()
    state = str(system.get("tpm_state") or "").strip()
    if interface == "TPM 2.0" and state == "Disabled":
        return f"<span class='badge warning'>{escape(interface)} — Disabled</span>"
    raw = str(system.get("tpm_status_badge") or "<span class='badge warning'>Unknown</span>")
    return re.sub(r"\s+FW\s+[^\s<)]+", "", raw)
