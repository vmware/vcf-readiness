"""
VCF Readiness Tool — Export Web API Mixin (vcf_hci.web.export_api)

Defines ExportApiMixin for Excel, CSV, and summary JSON artifact export.
"""

import json
import logging
import os
import time
import urllib.parse
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from http.server import SimpleHTTPRequestHandler
    class _ApiMixinBase(SimpleHTTPRequestHandler):
        def _send_json(self, obj: Any, status: int = 200, extra_headers: Optional[dict] = None) -> None: ...
        def _send_html(self, html: str, status: int = 200, extra_headers: Optional[dict] = None) -> None: ...
        def _read_json_body(self) -> dict: ...
        def _send_error_json(self, msg: str, code: int = 400) -> None: ...
        def _require_auth(self) -> bool: ...
        def _get_request_session_token(self) -> Optional[str]: ...
        def _cors_headers(self) -> None: ...
        def _is_remote_server(self) -> bool: ...
else:
    _ApiMixinBase = object

from vcf_hci import (
    normalize_output_dir,
    obfuscate_host_data,
    sanitize_filename,
)
from vcf_hci.report.csv_export import generate_fleet_summary_csv
from vcf_hci.report.excel_export import (
    _build_excel_sheets,
    _write_xlsx,
    build_obfuscated_inventory_zip,
)
from vcf_hci.summary_io import write_fleet_summary
from vcf_hci.web.scan_worker import (
    _get_dispatch,
    _state,
    _state_lock,
)

logger = logging.getLogger("vcf_assess")


class ExportApiMixin(_ApiMixinBase):
    """Excel, CSV, and JSON export endpoints mixed into AppHandler."""

    # ── Excel export ──────────────────────────────────────────────────────────

    def _api_export_excel(self) -> None:
        with _state_lock:
            results = list(_state.get("results", []))
            failed_hosts = list(_state.get("failed_hosts", []))
            outdir = _state.get("outdir", "")
        if not results and outdir:
            try:
                from vcf_hci.summary_io import load_summary
                results = load_summary(outdir) or []
            except Exception:
                pass
        if not results and not failed_hosts:
            self._send_json({"error": "No scan results available"}, 400)
            return
        try:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            is_obf = qs.get("obfuscated", ["0"])[0].lower() in ("1", "true", "yes")

            if is_obf and results:
                obf_salt = _state.get("obf_salt") or os.urandom(16).hex()
                obf_host_fn = _get_dispatch("obfuscate_host_data", obfuscate_host_data)
                export_results = [obf_host_fn(r, f"Host-{i+1}", obf_salt) for i, r in enumerate(results)]
                fname = f"00_OBFUSCATED_vcf_readiness_{time.strftime('%Y%m%d_%H%M%S')}.xlsx"
            else:
                export_results = results
                fname = f"vcf_readiness_{time.strftime('%Y%m%d_%H%M%S')}.xlsx"

            build_sheets_fn = _get_dispatch("_build_excel_sheets", _build_excel_sheets)
            write_xlsx_fn = _get_dispatch("_write_xlsx", _write_xlsx)
            sheets = build_sheets_fn(export_results, failed_hosts=failed_hosts, obfuscated=is_obf)
            xlsx = write_xlsx_fn(sheets)
            self.send_response(200)
            self.send_header("Content-Type",
                             "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(xlsx)))
            self.end_headers()
            self.wfile.write(xlsx)
        except Exception:
            logger.exception("Excel export failed")
            self._send_json({"error": "Excel export failed; see server log for details"}, 500)

    # ── Obfuscated Inventory ZIP export ───────────────────────────────────────

    def _api_export_inventory_excel_obfuscated(self) -> None:
        with _state_lock:
            results = list(_state.get("results", []))
            failed_hosts = list(_state.get("failed_hosts", []))
            outdir = _state.get("outdir", "")
        if not results and outdir:
            try:
                from vcf_hci.summary_io import load_summary
                results = load_summary(outdir) or []
            except Exception:
                pass
        if not results and not failed_hosts:
            self._send_json({"error": "No scan results available"}, 400)
            return
        try:
            blob = build_obfuscated_inventory_zip(results, failed_hosts=failed_hosts)
            fname = f"vcf_inventory_obfuscated_{time.strftime('%Y%m%d_%H%M%S')}.zip"
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)
        except Exception:
            logger.exception("Obfuscated inventory export failed")
            self._send_json({"error": "Obfuscated inventory export failed; see server log for details"}, 500)

    # ── Obfuscated Package ZIP export ─────────────────────────────────────────

    def _api_export_obfuscated_zip(self) -> None:
        with _state_lock:
            results = list(_state.get("results", []))
            failed_hosts = list(_state.get("failed_hosts", []))
            outdir = _state.get("outdir", "")
        if not results and outdir:
            try:
                from vcf_hci.summary_io import load_summary
                results = load_summary(outdir) or []
            except Exception:
                pass
        if not results and not failed_hosts and not (outdir and os.path.isdir(outdir)):
            self._send_json({"error": "No scan results available"}, 400)
            return

        try:
            from vcf_hci.logging_utils import create_obfuscated_scan_zip_archive
            if outdir and os.path.isdir(outdir):
                target_outdir = outdir
            else:
                import tempfile
                target_outdir = tempfile.mkdtemp(prefix="vcf_obf_export_")

            create_obf_zip_fn = _get_dispatch("create_obfuscated_scan_zip_archive", create_obfuscated_scan_zip_archive)
            zip_path = create_obf_zip_fn(
                scan_dir=target_outdir,
                failed_hosts=failed_hosts,
                results=results,
            )
            with open(zip_path, "rb") as f:
                blob = f.read()

            fname = os.path.basename(zip_path)
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)
        except Exception:
            logger.exception("Obfuscated package zip export failed")
            self._send_json({"error": "Obfuscated package zip export failed; see server log for details"}, 500)

    # ── CSV export ────────────────────────────────────────────────────────────

    def _api_export_csv(self) -> None:
        with _state_lock:
            results = list(_state.get("results", []))
            failed_hosts = list(_state.get("failed_hosts", []))
            outdir = _state.get("outdir", "")
        if not results and outdir:
            try:
                from vcf_hci.summary_io import load_summary
                results = load_summary(outdir) or []
            except Exception:
                pass
        if not results and not failed_hosts:
            self._send_json({"error": "No scan results available"}, 400)
            return
        try:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            is_obf = qs.get("obfuscated", ["0"])[0].lower() in ("1", "true", "yes")

            if is_obf and results:
                obf_salt = _state.get("obf_salt") or os.urandom(16).hex()
                obf_host_fn = _get_dispatch("obfuscate_host_data", obfuscate_host_data)
                export_results = [obf_host_fn(r, f"Host-{i+1}", obf_salt) for i, r in enumerate(results)]
                fname = f"00_OBFUSCATED_fleet_summary_{time.strftime('%Y%m%d_%H%M%S')}.csv"
            else:
                export_results = results
                fname = f"fleet_summary_{time.strftime('%Y%m%d_%H%M%S')}.csv"

            gen_csv_fn = _get_dispatch("generate_fleet_summary_csv", generate_fleet_summary_csv)
            csv_str = gen_csv_fn(export_results)
            csv_bytes = csv_str.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(csv_bytes)))
            self.end_headers()
            self.wfile.write(csv_bytes)
        except Exception:
            logger.exception("CSV export failed")
            self._send_json({"error": "CSV export failed; see server log for details"}, 500)

    # ── Summary JSON export ───────────────────────────────────────────────────

    def _api_export_summary_json(self) -> None:
        with _state_lock:
            results = list(_state.get("results", []))
            outdir = _state.get("outdir", "")
        if not results and outdir:
            try:
                from vcf_hci.summary_io import load_summary
                results = load_summary(outdir) or []
            except Exception:
                pass
        if not results:
            self._send_json({"error": "No scan results available"}, 400)
            return
        try:
            if len(results) == 1:
                sys_d = results[0].get("system") or {}
                host_ip = sys_d.get("bmc_ip") or sys_d.get("hostname") or "host"
                fname = f"vcf_summary_{sanitize_filename(host_ip)}.json"
                json_bytes = json.dumps(results[0], indent=2, default=str).encode("utf-8")
                ctype = "application/json; charset=utf-8"
            else:
                outdir = normalize_output_dir(outdir)
                target_dir = os.path.join(outdir, "data") if os.path.isdir(os.path.join(outdir, "data")) else outdir
                write_fleet_fn = _get_dispatch("write_fleet_summary", write_fleet_summary)
                meta = write_fleet_fn(results, target_dir, prefix="fleet_summary")
                manifest_path = meta["manifest_path"]
                with open(manifest_path, "rb") as mf:
                    json_bytes = mf.read()
                fname = os.path.basename(manifest_path)
                ctype = "application/json; charset=utf-8"

            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(json_bytes)))
            self.end_headers()
            self.wfile.write(json_bytes)
        except Exception:
            logger.exception("Summary JSON export failed")
            self._send_json({"error": "Summary JSON export failed; see server log for details"}, 500)
