"""Combined multi-host report facade; assets, facts and file delivery have explicit owners."""
import logging
import os
import time
from typing import Optional

from vcf_hci.constants import COMBINED_HTML_DEFAULT_MAX_HOSTS
from vcf_hci.report.fleet.combined_assets import render_combined_document
from vcf_hci.report.fleet.combined_data import (
    build_combined_summary,
    build_host_navigation,
    obfuscate_combined_results,
    prepare_combined_results,
)
from vcf_hci.report.fleet.combined_hosts import (
    build_combined_help,
    build_host_panels,
    load_inline_host_reports,
    select_sibling_workbook,
)
from vcf_hci.report.fleet.inventory_panel import build_detailed_inventory_html
from vcf_hci.report.formatting import format_report_html
from vcf_hci.report.inventory_tables import build_host_decision_rows

logger = logging.getLogger(__name__)

try:
    from vcf_hci.web.docs_data import DOCS_DATA
except ImportError:
    DOCS_DATA = {}


def _generate_combined_html(
    all_results: list,
    report_paths: list,
    outdir: str,
    obfuscated: bool = False,
    output_filename: Optional[str] = None,
    embed_mode: Optional[str] = None,
    json_hcl: Optional[dict] = None,
) -> str:
    """Generate a single combined tabbed HTML report containing all host reports."""
    all_results = prepare_combined_results(all_results)
    if not all_results:
        return ""

    if json_hcl is None:
        try:
            from vcf_hci.hcl.loader import load_vsan_hcl_json
            json_hcl = load_vsan_hcl_json(max_age_days=30)
        except Exception:
            json_hcl = None

    _page_salt = os.urandom(16).hex()

    all_results = obfuscate_combined_results(all_results, obfuscated, _page_salt)
    n_hosts = len(all_results)
    mode = embed_mode or ("inline" if n_hosts <= COMBINED_HTML_DEFAULT_MAX_HOSTS else "sidecar")
    host_html_list = load_inline_host_reports(all_results, report_paths, outdir, obfuscated) if mode == "inline" else []
    summary_tab = build_combined_summary(all_results, obfuscated, _page_salt)
    sibling_xlsx = select_sibling_workbook(mode, outdir, obfuscated)
    inv_rows = build_host_decision_rows(all_results)
    inventory_tab = build_detailed_inventory_html(
        inv_rows,
        all_results,
        obfuscated=obfuscated,
        json_hcl=json_hcl,
        page_salt=_page_salt,
        embed_mode=mode,
        sibling_xlsx=sibling_xlsx,
    )

    readme_tab = build_combined_help(DOCS_DATA)
    tab_btns = build_host_navigation(all_results, mode, obfuscated, _page_salt)
    panels = build_host_panels(all_results, report_paths, outdir, mode, obfuscated, host_html_list)
    timestamp = time.strftime("%Y-%m-%d %H:%M")
    page_title = f"VCF Readiness{' (Obfuscated)' if obfuscated else ''} — {n_hosts} Host(s)"
    combined_template = render_combined_document(page_title, tab_btns, panels, timestamp)
    combined_html = combined_template.replace("__SUMMARY_TAB__", summary_tab).replace("__INVENTORY_TAB__", inventory_tab).replace("__README_TAB__", readme_tab)

    out_filename = output_filename or ("00_OBFUSCATED_fleet_combined.html" if obfuscated else "00_fleet_combined.html")
    compat_out_path = os.path.join(outdir, out_filename)
    try:
        safe = combined_html.encode("utf-8", errors="surrogatepass").decode("utf-8", errors="replace")
        with open(compat_out_path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(format_report_html(safe))
        return compat_out_path
    except Exception as exc:
        logger.error(f"Error writing combined report: {exc}")
        return ""


generate_combined_html = _generate_combined_html
generate_combined_tabbed_html = _generate_combined_html
