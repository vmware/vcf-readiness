"""
VCF Readiness Tool — Branding Assets and Constants.

Project-owned VCF-R brand assets aligned with Clarity Design System.
Provides vector SVGs and data URIs for web chrome, standalone reports, and favicons.
"""

# Favicon SVG (32x32)
FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" role="img" aria-label="VCF-R">'
    '<rect width="32" height="32" rx="6" ry="6" fill="#0072A3"/>'
    '<path d="M8 16.5 L13 21.5 L24 9" fill="none" stroke="#FFFFFF" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>'
    '</svg>'
)

# Inline favicon data URI for <link rel="icon">
FAVICON_DATA_URI = (
    "data:image/svg+xml;base64,"
    "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiIgcm9sZT0iaW1nIiBhcmlhLWxhYmVsPSJWQ0YtUiI+"
    "PHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iNiIgcnk9IjYiIGZpbGw9IiMwMDcyQTMiLz4"
    "8cGF0aCBkPSJNOCAxNi41IEwxMyAyMS41IEwyNCA5IiBmaWxsPSJub25lIiBzdHJva2U9IiNGRkZGRkYiIHN0cm9rZS13aWR0aD0iMy4yIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4"
    "8L3N2Zz4="
)

# Compact dark-chrome navigation lockup (viewBox 0 0 106 32, badge + VCF-R text)
NAV_LOCKUP_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 106 32" height="28" role="img" aria-label="VCF-R" style="vertical-align:middle;flex-shrink:0">'
    '<rect x="0" y="2" width="28" height="28" rx="6" ry="6" fill="#0072A3"/>'
    '<path d="M8 16 L13 21 L22 10" fill="none" stroke="#FFFFFF" stroke-width="2.75" stroke-linecap="round" stroke-linejoin="round"/>'
    '<text x="36" y="23" font-family="system-ui, -apple-system, \'Segoe UI\', Roboto, Helvetica, Arial, sans-serif" font-size="18" font-weight="700" letter-spacing="0.03em" fill="#E2EAF0">VCF-R</text>'
    '</svg>'
)

# Full nav SVG (as stored in branding kit, viewBox 0 0 220 32)
NAV_FULL_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 220 32" role="img" aria-label="VCF-R">'
    '<title>VCF-R nav lockup</title>'
    '<desc>Compact lockup for the dark web UI nav bar (48px tall chrome).</desc>'
    '<rect x="0" y="2" width="28" height="28" rx="6" ry="6" fill="#0072A3"/>'
    '<path d="M8 16 L13 21 L22 10" fill="none" stroke="#FFFFFF" stroke-width="2.75" stroke-linecap="round" stroke-linejoin="round"/>'
    '<text x="36" y="23" font-family="system-ui, -apple-system, \'Segoe UI\', Roboto, Helvetica, Arial, sans-serif" font-size="18" font-weight="700" letter-spacing="0.03em" fill="#E2EAF0">VCF-R</text>'
    '</svg>'
)

# Self-colored brand icon mark (64x64) for HTML report headers
MARK_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="26" height="26" style="vertical-align:middle;margin-right:.5rem;display:inline-block;flex-shrink:0" role="img" aria-label="VCF-R">'
    '<rect width="64" height="64" rx="12" ry="12" fill="#0072A3"/>'
    '<path d="M18 33 L28 43 L48 19" fill="none" stroke="#FFFFFF" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>'
    '</svg>'
)


def render_nav_brand(subtitle: str = "Readiness Assessment") -> str:
    """Render the standard .nav-brand HTML component with the VCF-R badge and subtitle."""
    return (
        f'<span class="nav-brand" style="display:inline-flex;align-items:center;gap:.65rem">'
        f'{NAV_LOCKUP_SVG}'
        f'<span style="font-size:.82rem;font-weight:400;color:#94a3b8;letter-spacing:.02em;border-left:1px solid rgba(255,255,255,.2);padding-left:.65rem">{subtitle}</span>'
        f'</span>'
    )
