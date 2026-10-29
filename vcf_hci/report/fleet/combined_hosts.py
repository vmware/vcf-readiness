"""Combined report file acquisition, local Help fallback and lazy host panels."""
import html
import os
import re
from functools import partial
from typing import Any, Optional

from vcf_hci.constants import TOOL_VERSION
from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.report.clarity import build_help_layout
from vcf_hci.report.fleet.escape import _xe
from vcf_hci.report.formatting import format_report_html
from vcf_hci.report.helpers import _h


def load_inline_host_reports(all_results: list, report_paths: Any, outdir: str, obfuscated: bool) -> list:
    """Load inline documents, retaining private temporary-public-report cleanup."""
    host_html_list = []
    path_index = index_report_paths(report_paths)
    for i, host in enumerate(all_results):
        try:
            system = host.get("system", {}) if isinstance(host, dict) else {}
            path = resolve_host_report_path(i, system, report_paths, obfuscated, path_index)
            report_html = ""
            is_p_obf = bool(path and ("obfuscated" in os.path.basename(path).lower()))
            if obfuscated and not is_p_obf and i < len(all_results):
                import tempfile

                from vcf_hci.report.host_report import generate_host_html_report
                with tempfile.NamedTemporaryFile("w+", suffix=".html", delete=False) as tf:
                    tf_path = tf.name
                try:
                    generate_host_html_report(all_results[i], tf_path, obfuscated=True)
                    with open(tf_path, encoding="utf-8") as tf_in:
                        report_html = tf_in.read()
                finally:
                    try:
                        os.unlink(tf_path)
                    except OSError:
                        pass
            else:
                if not path:
                    raise FileNotFoundError("Host report file is not available.")
                if not os.path.isabs(path) and os.path.exists(os.path.join(outdir, path)):
                    path = os.path.join(outdir, path)
                with open(path, encoding="utf-8") as fh:
                    report_html = fh.read()
            host_html_list.append(report_html)
        except Exception as exc:
            host_html_list.append(f"<!DOCTYPE html><html><body><p style='color:red'>Error: {_h(exc)}</p></body></html>")

    return host_html_list


def select_sibling_workbook(mode: str, outdir: str, obfuscated: bool) -> Optional[str]:
    """Select the existing sibling-workbook download target."""
    sibling_xlsx = None
    if mode == "sidecar" and outdir and os.path.isdir(outdir):
        xlsx_candidates = [
            f for f in os.listdir(outdir)
            if f.lower().endswith(".xlsx")
        ]
        for f in xlsx_candidates:
            is_f_obf = "obfuscated" in f.lower() or f.startswith("00_OBFUSCATED")
            if bool(obfuscated) == is_f_obf:
                sibling_xlsx = f
                break
        if not sibling_xlsx and xlsx_candidates:
            sibling_xlsx = xlsx_candidates[0]

    return sibling_xlsx


def build_combined_help(docs_data: Any) -> str:
    """Prepare local bundled/fallback Help and remove remote decorative images."""
    if not docs_data:
        try:
            from vcf_hci.web.docs_data import DOCS_DATA as _DD
            docs_data = _DD
        except Exception:
            docs_data = {}
    readme_data = (
        docs_data.get("user_guide_reference", {})
        or docs_data.get("readme", {})
    ) if isinstance(docs_data, dict) else {}
    readme_html_content = readme_data.get("html", "")
    if not readme_html_content:
        # Fallback reading README.md directly if available
        try:
            readme_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "README.md"))
            if os.path.exists(readme_path):
                with open(readme_path, encoding="utf-8") as rfh:
                    raw_md = rfh.read()
                # Basic conversion so raw formatting characters are rendered cleanly
                md_lines = []
                for line in raw_md.splitlines():
                    if line.startswith("# "):
                        md_lines.append(f"<h1>{_h(line[2:])}</h1>")
                    elif line.startswith("## "):
                        md_lines.append(f"<h2>{_h(line[3:])}</h2>")
                    elif line.startswith("### "):
                        md_lines.append(f"<h3>{_h(line[4:])}</h3>")
                    elif line.startswith("> "):
                        md_lines.append(f"<blockquote>{_h(line[2:])}</blockquote>")
                    elif line.startswith("- "):
                        md_lines.append(f"<li>{_h(line[2:])}</li>")
                    elif not line.strip():
                        md_lines.append("<br>")
                    else:
                        md_lines.append(f"<p>{_h(line)}</p>")
                readme_html_content = "\n".join(md_lines)
        except Exception:
            readme_html_content = "<p>User Guide & Documentation not available in offline bundle.</p>"

    if readme_html_content:
        # Decorative remote badges must not make an offline report fetch images.
        def _offline_image_label(match):
            label = re.search(r'\balt=["\']([^"\']*)["\']', match.group(0), re.IGNORECASE)
            return _h(html.unescape(label.group(1))) if label else ''

        readme_html_content = re.sub(
            r'<img\b[^>]*\bsrc=["\']https?://[^"\']*["\'][^>]*>',
            _offline_image_label, readme_html_content, flags=re.IGNORECASE,
        )
        # Strip dummy anchor wrappers like <a href="#"><img></a> and root-relative /docs/ links for offline file:// compatibility
        readme_html_content = re.sub(r'<a\s+href=["\']#["\']>(.*?)</a>', r'\1', readme_html_content)
        readme_html_content = re.sub(r'<a\s+href=["\']/(?:docs|api)[^"\']*["\'][^>]*>(.*?)</a>', r'\1', readme_html_content)

    return build_help_layout(readme_html_content, TOOL_VERSION)


def index_report_paths(report_paths: Any) -> tuple:
    """Index explicit IP/obfuscated-host identities before positional fallback."""
    # Pre-build lookup dictionaries for defensive report path resolution
    _rp_by_ip = {}
    _rp_by_host_idx = {}
    if isinstance(report_paths, (list, tuple)):
        for p in report_paths:
            if not p:
                continue
            bn = os.path.basename(p)
            m_ip = re.search(r"vsphere_vsan_report_(\d+\.\d+\.\d+\.\d+)", bn)
            if m_ip:
                _rp_by_ip[m_ip.group(1)] = p
            m_obf = re.search(r"OBFUSCATED_Host-(\d+)", bn, re.I)
            if m_obf:
                _rp_by_host_idx[int(m_obf.group(1))] = p

    return _rp_by_ip, _rp_by_host_idx


def resolve_host_report_path(i: int, d_sys: dict, report_paths: Any, obfuscated: bool, path_index: tuple) -> Optional[str]:
    """Resolve host identity once for inline content and sidecar references."""
    _rp_by_ip, _rp_by_host_idx = path_index
    rp = None
    target_ip = str(d_sys.get("ip") or "").strip()
    if obfuscated:
        rp = _rp_by_host_idx.get(i + 1)
    elif target_ip and target_ip in _rp_by_ip:
        rp = _rp_by_ip[target_ip]

    if not rp:
        if isinstance(report_paths, (list, tuple)):
            if 0 <= i < len(report_paths):
                candidate = report_paths[i]
                identified_paths = _rp_by_host_idx if obfuscated else _rp_by_ip
                # With a known target, a recognized file belongs to another host
                # when lookup failed. Keep legacy positional use without identity.
                if (not obfuscated and not target_ip) or candidate not in identified_paths.values():
                    rp = candidate
        elif isinstance(report_paths, dict):
            target_key = d_sys.get("ip") or d_sys.get("hostname") or f"Host-{i+1}"
            rp = report_paths.get(target_key) or report_paths.get(i)

    return rp


def relative_report_path(i: int, d_sys: dict, report_paths: Any, outdir: str, obfuscated: bool, path_index: tuple) -> str:
    """Retain identity-first sidecar resolution and sanitized relative fallbacks."""
    rp = resolve_host_report_path(i, d_sys, report_paths, obfuscated, path_index)
    if obfuscated:
        if rp and "obfuscated" in os.path.basename(rp).lower():
            if os.path.isabs(rp):
                return os.path.relpath(rp, outdir).replace("\\", "/")
            return rp.replace("\\", "/")
        return f"reports/OBFUSCATED_Host-{i+1}.html"
    if rp:
        if os.path.isabs(rp):
            return os.path.relpath(rp, outdir).replace("\\", "/")
        if os.path.exists(os.path.join(outdir, rp)):
            return rp.replace("\\", "/")
        return os.path.relpath(os.path.abspath(rp), os.path.abspath(outdir)).replace("\\", "/")
    host_ip_str = d_sys.get("ip") or f"host_{i+1}"
    return f"reports/{sanitize_filename(f'vsphere_vsan_report_{host_ip_str}.html')}"


def build_host_panels(all_results: list, report_paths: Any, outdir: str, mode: str, obfuscated: bool, host_html_list: list) -> str:
    """Compose lazy host panes; keep host attributes and delivery contracts."""
    n_hosts = len(all_results)
    _resolve_rel_report = partial(relative_report_path, report_paths=report_paths, outdir=outdir, obfuscated=obfuscated, path_index=index_report_paths(report_paths))
    panels = (
        '<div id="tab-0" class="tab-content active">__SUMMARY_TAB__</div>\n'
        '<div id="tab-1" class="tab-content">__INVENTORY_TAB__</div>\n'
        '<div id="tab-2" class="tab-content">__README_TAB__</div>\n'
    )
    if mode == "inline":
        for i, host_html in enumerate(host_html_list):
            host_html = format_report_html(host_html)
            safe_srcdoc = _h(host_html)
            d_host = all_results[i] if i < len(all_results) else {}
            d_sys = d_host.get("system", {}) if isinstance(d_host, dict) else {}
            d_ip = "" if obfuscated else str(d_sys.get("ip") or "")
            d_name = "" if obfuscated else str(d_sys.get("hostname") or d_sys.get("dns_name") or "")
            rel_p = _resolve_rel_report(i, d_sys)
            panels += (
                f'<div id="tab-{i+3}" class="tab-content" data-host-ip="{_xe(d_ip)}" data-hostname="{_xe(d_name)}" '
                f'data-src="{_xe(rel_p)}">'
                f'<iframe data-srcdoc="{safe_srcdoc}" style="width:100%;height:calc(100vh - 100px);border:none;" '
                f'title="Host Report {i+1}"></iframe></div>\n'
            )
    else:
        for i in range(n_hosts):
            d_host = all_results[i] if i < len(all_results) else {}
            d_sys = d_host.get("system", {}) if isinstance(d_host, dict) else {}
            d_ip = "" if obfuscated else str(d_sys.get("ip") or "")
            d_name = "" if obfuscated else str(d_sys.get("hostname") or d_sys.get("dns_name") or "")
            rel_p = _resolve_rel_report(i, d_sys)
            panels += (
                f'<div id="tab-{i+3}" class="tab-content" data-host-ip="{_xe(d_ip)}" data-hostname="{_xe(d_name)}" '
                f'data-src="{_xe(rel_p)}"></div>\n'
            )

    return panels
