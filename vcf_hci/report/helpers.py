"""
VCF Readiness Tool — shared HTML escaping and badge rendering helpers.
"""
import html as _html_mod


def html_escape(s) -> str:
    """HTML-escape a BMC-sourced string/object; returns '' for None to avoid AttributeError."""
    if s is None:
        return ""
    return _html_mod.escape(str(s), quote=True).replace("'", "&#39;")


# Canonical shorthand alias matching codebase conventions
_h = html_escape


def badge(label_or_cls: str, label_or_cls2: str = "info", style: str = "") -> str:
    """Render a standard HTML badge span with HTML-escaped label. Supports badge(cls, label) or badge(label, cls)."""
    # If first param is standard badge class, treat as (cls, label)
    if label_or_cls in ("success", "warning", "danger", "info"):
        cls, label = label_or_cls, label_or_cls2
    else:
        label, cls = label_or_cls, label_or_cls2
    style_attr = f' style="{style}"' if style else ""
    return f"<span class='badge {cls}'{style_attr}>{html_escape(label)}</span>"


def raw_badge(label_html: str, cls: str = "info", style: str = "") -> str:
    """Render an HTML badge span where label_html is already formatted HTML."""
    style_attr = f' style="{style}"' if style else ""
    return f'<span class="badge {cls}"{style_attr}>{label_html}</span>'


def host_has_redfish_latency(scan_data) -> bool:
    """True when BMC HTTP timeouts/throttle/high GET latency were recorded.

    Scan duration alone is NOT a signal: a healthy full Dell scan is often 80-140s.
    """
    if not isinstance(scan_data, dict):
        return False
    if scan_data.get("adaptive_throttled") or scan_data.get("skipped"):
        return True
    diag = scan_data.get("diagnostics") if isinstance(scan_data.get("diagnostics"), dict) else {}

    def _as_int(v):
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            return 0

    def _as_float(v):
        try:
            return float(v or 0.0)
        except (TypeError, ValueError):
            return 0.0

    if _as_int(diag.get("timeout_count")) > 0:
        return True
    if _as_int(diag.get("throttle_engaged_count")) > 0:
        return True
    return _as_float(diag.get("avg_get_latency_ms")) >= 1000.0

