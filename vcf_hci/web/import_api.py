"""
VCF Readiness Tool — Import Web API Mixin (vcf_hci.web.import_api)

Defines ImportApiMixin for HCL bundle import/refresh and summary import rendering.
"""

import base64
import gc
import json
import logging
import os
import re
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

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
    _generate_combined_html,
    create_hcl_bundle,
    create_scan_output_dir,
    create_scan_zip_archive,
    ensure_auto_hcl_bundle,
    generate_host_html_report,
    generate_summary_html,
    get_hcl_dir,
    import_hcl_bundle,
    load_optional_vsan_csv,
    load_vsan_hcl_json,
    normalize_output_dir,
    obfuscate_host_data,
    sanitize_filename,
    update_latest_scan_aliases,
)
from vcf_hci.compat_engine import VCF9CompatibilityEngine
from vcf_hci.summary_io import load_summary, write_fleet_summary
from vcf_hci.web.desktop import _is_safe_desktop_folder
from vcf_hci.web.scan_worker import (
    _broadcast,
    _get_active_hcl_metadata,
    _get_dispatch,
    _handle_host_done,
    _handle_host_start,
    _state,
    _state_lock,
    set_custom_hcl_bundle,
)

logger = logging.getLogger("vcf_assess")

_COLLECTOR_OK = True


class ImportApiMixin(_ApiMixinBase):
    """HCL and summary import endpoints mixed into AppHandler."""

    def _api_import_hcl(self) -> None:
        if not _COLLECTOR_OK:
            self._send_json({"error": "Collector package not available"}, 503)
            return

        body = self._read_json_body()
        bundle_path = body.get("bundle_path", "").strip()
        filename = body.get("filename", "").strip()
        content_b64 = body.get("content_b64", "").strip()

        # Enforce uploaded payload save into get_hcl_dir()
        if content_b64:
            try:
                # Cap base64 string length before decode (~50 MB raw data max)
                if len(content_b64) > 70 * 1024 * 1024:
                    self._send_json({"error": "Uploaded HCL bundle exceeds size limit (max 50 MB)"}, 400)
                    return
                hcl_dir = get_hcl_dir()
                os.makedirs(hcl_dir, exist_ok=True)
                save_name = sanitize_filename(filename or "custom_vcf_hcl_bundle.zip")
                if not save_name.endswith(".zip"):
                    save_name += ".zip"
                bundle_path = os.path.join(hcl_dir, save_name)
                raw_bytes = base64.b64decode(content_b64)
                if len(raw_bytes) > 50 * 1024 * 1024:
                    self._send_json({"error": "Uploaded HCL bundle exceeds size limit (max 50 MB)"}, 400)
                    return
                with open(bundle_path, "wb") as f:
                    f.write(raw_bytes)
            except Exception as exc:
                self._send_json({"error": f"Failed to save uploaded HCL bundle: {exc}"}, 400)
                return
        elif bundle_path:
            if self._is_remote_server():
                self._send_json({"error": "HCL bundle import by local path is disabled in remote mode."}, 403)
                return
            resolved = os.path.realpath(os.path.expanduser(bundle_path))
            if not resolved.lower().endswith(".zip") or not os.path.isfile(resolved):
                self._send_json({"error": "bundle_path must point to an existing .zip file"}, 400)
                return
            if not _is_safe_desktop_folder(os.path.dirname(resolved)):
                self._send_json({"error": "bundle_path is outside allowed directories"}, 400)
                return
            bundle_path = resolved
        else:
            self._send_json({"error": "bundle_path or content_b64 is required"}, 400)
            return

        set_hcl_fn = _get_dispatch("set_custom_hcl_bundle", set_custom_hcl_bundle)
        try:
            metadata = set_hcl_fn(bundle_path)
            self._send_json({"ok": True, "metadata": metadata})
        except Exception as exc:
            self._send_json({"error": str(exc)}, 400)

    def _api_refresh_hcl(self) -> None:
        if not _COLLECTOR_OK:
            self._send_json({"error": "Collector package not available"}, 503)
            return
        try:
            load_hcl_fn = _get_dispatch("load_vsan_hcl_json", load_vsan_hcl_json)
            create_hcl_fn = _get_dispatch("create_hcl_bundle", create_hcl_bundle)
            json_hcl = load_hcl_fn(refresh_live=True)
            if not json_hcl or not (json_hcl.get("models") or json_hcl.get("quads")):
                self._send_json({"error": "Failed to download or parse live Broadcom HCL dataset"}, 502)
                return
            try:
                create_hcl_fn()
            except Exception as be:
                logger.debug("Auto-bundle rebuild after refresh error: %s", be)
            status = _get_dispatch("_get_active_hcl_metadata", _get_active_hcl_metadata)()
            self._send_json({"ok": True, "status": status})
        except Exception as exc:
            logger.error("Error refreshing live HCL: %s", exc, exc_info=True)
            self._send_json({"error": "Failed to refresh live HCL; see server log for details"}, 500)

    def _process_imported_results(self, results: List[Dict[str, Any]], base_outdir: str, source_label: str = "summary") -> None:
        scan_id = "import_" + os.urandom(4).hex()
        outdir = create_scan_output_dir(base_dir=base_outdir, host_count=len(results), save_json=True)
        data_dir = os.path.join(outdir, "data")
        os.makedirs(data_dir, exist_ok=True)

        with _state_lock:
            _state.update({
                "scan_id": scan_id,
                "running": True,
                "done": False,
                "error": None,
                "total": len(results),
                "completed": 0,
                "n_ok": 0,
                "is_retry": False,
                "is_rescan": False,
                "is_import": True,
                "active_hosts": {},
                "completed_hosts": set(),
                "skipped_ips": set(),
                "results": [],
                "report_paths": [],
                "failed_hosts": [],
                "partial_hosts": [],
                "outdir": outdir,
                "log_lines": [f"[📁] Offline Import — Rendering reports for {len(results)} host(s)..."],
            })

        broadcast_fn = _get_dispatch("_broadcast", _broadcast)
        broadcast_fn("status", {
            "running": True,
            "done": False,
            "completed": 0,
            "total": len(results),
            "is_import": True,
            "is_rescan": False,
            "is_retry": False,
            "scan_id": scan_id,
        })
        broadcast_fn("log", {
            "scan_id": scan_id,
            "msg": f"[📁] Offline Import — Rendering reports for {len(results)} host(s)...",
        })

        json_hcl = None
        csv_db = None
        hcl_bundle_metadata = None
        with _state_lock:
            custom_path = _state.get("custom_hcl_bundle_path")
            custom_meta = _state.get("custom_hcl_bundle_metadata")

        if custom_path and os.path.exists(custom_path):
            try:
                json_hcl, csv_db, hcl_bundle_metadata = import_hcl_bundle(custom_path)
            except Exception as _exc:
                logger.debug("Failed loading custom HCL bundle: %s", _exc)
        else:
            auto_bundle_path = ensure_auto_hcl_bundle(max_age_days=30) if _COLLECTOR_OK else None
            if auto_bundle_path:
                try:
                    json_hcl, csv_db, hcl_bundle_metadata = import_hcl_bundle(auto_bundle_path)
                except Exception as _exc:
                    logger.debug("Failed loading auto HCL bundle: %s", _exc)

        if not json_hcl and _COLLECTOR_OK:
            try:
                json_hcl = load_vsan_hcl_json(max_age_days=30)
                csv_db = load_optional_vsan_csv()
            except Exception as _exc:
                logger.debug("Failed loading default vSAN HCL: %s", _exc)

        # Re-evaluate CPU verdict and compute readiness
        vcf_sup = vcf_dep = vcf_unsup = 0
        for r in results:
            si = r.get("system") or {}
            ci = si.get("cpu_summary") or {}
            if ci.get("model") and _COLLECTOR_OK:
                try:
                    v_fresh, arch_fresh, _, _, _ = VCF9CompatibilityEngine.evaluate_cpu(
                        ci.get("model", ""), si.get("vendor", ""), si.get("model", "")
                    )
                    ci["verdict"] = v_fresh
                    if not ci.get("architecture") or ci.get("architecture") == "Unknown":
                        ci["architecture"] = arch_fresh
                except Exception:
                    pass
            v = ci.get("verdict", "")
            if "Unsupported" in v:
                vcf_unsup += 1
            elif "Deprecated" in v:
                vcf_dep += 1
            else:
                vcf_sup += 1

        vcf_readiness = {
            "supported": vcf_sup,
            "deprecated": vcf_dep,
            "unsupported": vcf_unsup,
        }

        reports_dir = os.path.join(outdir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        _obf_salt = os.urandom(16).hex()

        completed_lock = threading.Lock()
        completed_count = 0

        gen_host_fn = _get_dispatch("generate_host_html_report", generate_host_html_report)
        obf_host_fn = _get_dispatch("obfuscate_host_data", obfuscate_host_data)

        def _process_one_host(idx_host: Tuple[int, Dict[str, Any]]) -> Dict[str, Any]:
            nonlocal completed_count
            idx, host_data = idx_host
            sys_data = host_data.get("system") or {}
            ip_or_host = (
                sys_data.get("bmc_ip")
                or sys_data.get("hostname")
                or host_data.get("host")
                or f"imported_host_{idx}"
            )
            _get_dispatch("_handle_host_start", _handle_host_start)(scan_id, {
                "ip": ip_or_host,
                "hostname": sys_data.get("hostname") or ip_or_host,
                "stage": "Rendering HTML Report...",
                "is_import": True,
                "start_time": time.time(),
            })
            try:
                filename = sanitize_filename(f"vcf_readiness_{ip_or_host}.html")
                filepath = os.path.join(reports_dir, filename)
                gen_host_fn(
                    host_data,
                    filepath,
                    json_hcl=json_hcl,
                    hcl_bundle_metadata=hcl_bundle_metadata,
                )

                _alias = f"Host-{idx}"
                _obf_filepath = os.path.join(reports_dir, f"OBFUSCATED_{_alias}.html")
                _obf_data = obf_host_fn(host_data, _alias, _obf_salt)
                gen_host_fn(
                    _obf_data,
                    _obf_filepath,
                    json_hcl=json_hcl,
                    hcl_bundle_metadata=hcl_bundle_metadata,
                    obfuscated=True,
                )

                # Save individual host JSON in data/
                _host_json_fname = f"vcf_summary_{sanitize_filename(ip_or_host)}.json"
                _host_json_path = os.path.join(data_dir, _host_json_fname)
                try:
                    with open(_host_json_path, "w", encoding="utf-8") as _jf:
                        json.dump(host_data, _jf, separators=(",", ":"), default=str)
                except Exception:
                    pass

                ci = sys_data.get("cpu_summary") or {}
                row = {
                    "ip": sys_data.get("bmc_ip") or host_data.get("host") or ip_or_host,
                    "hostname": sys_data.get("hostname") or ip_or_host,
                    "vendor": sys_data.get("vendor", ""),
                    "model": sys_data.get("model", ""),
                    "verdict": ci.get("verdict", "Fully Supported"),
                    "report": filename,
                    "obf_report": f"OBFUSCATED_{_alias}.html",
                    "partial_scan": bool(host_data.get("partial_scan")),
                    "partial_reason": host_data.get("partial_reason", ""),
                    "remediation": host_data.get("remediation"),
                }

                _get_dispatch("_handle_host_done", _handle_host_done)(scan_id, {
                    "ip": ip_or_host,
                    "hostname": sys_data.get("hostname") or ip_or_host,
                    "vendor": sys_data.get("vendor", ""),
                    "model": sys_data.get("model", ""),
                    "verdict": ci.get("verdict", "Fully Supported"),
                    "report": filename,
                    "obf_report": f"OBFUSCATED_{_alias}.html",
                    "partial_scan": bool(host_data.get("partial_scan")),
                    "partial_reason": host_data.get("partial_reason", ""),
                    "remediation": host_data.get("remediation"),
                    "msg": f"  [✓] {ip_or_host}  →  reports/{filename}",
                })

                with completed_lock:
                    completed_count += 1
                    curr_done = completed_count
                    with _state_lock:
                        _state["completed"] = curr_done
                        _state["n_ok"] = curr_done

                _get_dispatch("_broadcast", _broadcast)("progress", {
                    "scan_id": scan_id,
                    "completed": curr_done,
                    "total": len(results),
                    "is_import": True,
                    "phase": "import",
                    "msg": f"Importing: {curr_done}/{len(results)} hosts",
                })

                return {
                    "idx": idx,
                    "filepath": filepath,
                    "obf_filepath": _obf_filepath,
                    "row": row,
                }
            except Exception as exc:
                logger.warning("Failed to generate report for imported host %d: %s", idx, exc)
                _get_dispatch("_handle_host_done", _handle_host_done)(scan_id, {
                    "ip": ip_or_host,
                    "error": True,
                    "msg": f"  [✗] {ip_or_host} — report generation error: {exc}",
                })
                with completed_lock:
                    completed_count += 1
                    curr_done = completed_count
                    with _state_lock:
                        _state["completed"] = curr_done
                _get_dispatch("_broadcast", _broadcast)("progress", {
                    "scan_id": scan_id,
                    "completed": curr_done,
                    "total": len(results),
                    "is_import": True,
                    "phase": "import",
                    "msg": f"Importing: {curr_done}/{len(results)} hosts",
                })
                return {
                    "idx": idx,
                    "filepath": None,
                    "obf_filepath": None,
                    "row": None,
                }

        indexed_items = list(enumerate(results, 1))
        max_workers = min(32, max(4, (os.cpu_count() or 4) * 2))
        if len(indexed_items) <= 1:
            processed_records = [_process_one_host(item) for item in indexed_items]
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                processed_records = list(executor.map(_process_one_host, indexed_items))

        report_paths = []
        obf_report_paths = []
        hosts_rows = []
        for rec in processed_records:
            if rec.get("filepath"):
                report_paths.append(rec["filepath"])
            if rec.get("obf_filepath"):
                obf_report_paths.append(rec["obf_filepath"])
            if rec.get("row"):
                hosts_rows.append(rec["row"])

        # Save fleet summary JSONs to data/
        try:
            write_fleet_fn = _get_dispatch("write_fleet_summary", write_fleet_summary)
            write_fleet_fn(results, data_dir, prefix="fleet_summary")
            obf_results = [obf_host_fn(r, f"Host-{i+1}", _obf_salt) for i, r in enumerate(results)]
            write_fleet_fn(obf_results, data_dir, prefix="OBFUSCATED_fleet_summary")
        except Exception as exc:
            logger.warning("Failed writing imported fleet summary JSON: %s", exc)

        _get_dispatch("_broadcast", _broadcast)("log", {
            "scan_id": scan_id,
            "msg": "[✓] Generating fleet summary dashboard & archives...",
        })

        fleet_path = ""
        summary_path = ""
        _obf_sum = ""
        _obf_fleet = ""
        gen_sum_fn = _get_dispatch("generate_summary_html", generate_summary_html)
        gen_comb_fn = _get_dispatch("_generate_combined_html", _generate_combined_html)

        if len(results) >= 1:
            try:
                summary_out = os.path.join(outdir, "00_fleet_summary.html")
                gen_sum_fn(results, summary_out, hcl_bundle_metadata=hcl_bundle_metadata)
                summary_path = summary_out
            except Exception as exc:
                logger.warning("Failed to generate fleet summary report: %s", exc)

            try:
                if len(results) >= 1:
                    fleet_path = gen_comb_fn(results, report_paths, outdir)
            except Exception as exc:
                logger.warning("Failed to generate combined tabbed report: %s", exc)

            if len(results) > 1:
                try:
                    _obf_sum = os.path.join(outdir, "00_OBFUSCATED_fleet_summary.html")
                    obf_results = [obf_host_fn(r, f"Host-{i+1}", _obf_salt) for i, r in enumerate(results)]
                    gen_sum_fn(obf_results, _obf_sum, hcl_bundle_metadata=hcl_bundle_metadata, obfuscated=True)
                except Exception as exc:
                    logger.warning("Failed to generate obfuscated fleet summary: %s", exc)
            else:
                _obf_sum = ""

            try:
                if len(results) >= 1:
                    obf_results = [obf_host_fn(r, f"Host-{i+1}", _obf_salt) for i, r in enumerate(results)]
                    _obf_fleet = gen_comb_fn(obf_results, obf_report_paths, outdir, obfuscated=True)
            except Exception as exc:
                logger.warning("Failed to generate obfuscated combined report: %s", exc)

        try:
            from vcf_hci.fleet_library import write_scan_manifest
            write_scan_manifest(
                outdir=outdir,
                host_count=len(results),
                scan_profile="imported",
                obfuscated=False,
            )
        except Exception as _m_exc:
            logger.debug("Failed writing imported scan manifest: %s", _m_exc)

        try:
            from vcf_hci.report import write_scan_readme
            write_scan_readme(
                outdir=outdir,
                host_count=len(results),
                scan_profile="imported",
                obfuscated=False,
            )
        except Exception as _r_exc:
            logger.debug("Failed writing imported scan readme: %s", _r_exc)

        zip_path = ""
        try:
            zip_path = create_scan_zip_archive(outdir)
        except Exception:
            pass

        try:
            update_latest_scan_aliases(scan_dir=outdir, base_dir=base_outdir)
        except Exception:
            pass

        obf_sum_file = "00_OBFUSCATED_fleet_summary.html" if os.path.isfile(os.path.join(outdir, "00_OBFUSCATED_fleet_summary.html")) else ""
        obf_fleet_file = "00_OBFUSCATED_fleet_combined.html" if os.path.isfile(os.path.join(outdir, "00_OBFUSCATED_fleet_combined.html")) else ""

        scan_summary_str = f"Imported {len(results)} host(s) offline (0 network probes)"

        done_payload = {
            "ok": True,
            "scan_id": scan_id,
            "count": len(results),
            "n_ok": len(results),
            "n_total": len(results),
            "hosts": hosts_rows,
            "reports": report_paths,
            "fleet": os.path.basename(fleet_path) if fleet_path else "",
            "summary": os.path.basename(summary_path) if summary_path else "",
            "obf_summary": obf_sum_file,
            "obf_fleet": obf_fleet_file,
            "outdir": outdir,
            "zip_path": zip_path,
            "scan_summary": scan_summary_str,
            "vcf_readiness": vcf_readiness,
            "is_import": True,
        }

        from vcf_hci.web.fleet_api import _build_compact_host_row
        compact_rows = [_build_compact_host_row(i, h, reports_dir) for i, h in enumerate(results, 1)]
        stored_results = results if len(results) <= 500 else []

        with _state_lock:
            _state.update({
                "scan_id": scan_id,
                "running": False,
                "done": True,
                "error": None,
                "total": len(results),
                "completed": len(results),
                "n_ok": len(results),
                "results": stored_results,
                "fleet_index": compact_rows,
                "report_paths": report_paths,
                "fleet_path": fleet_path,
                "summary_path": summary_path,
                "outdir": outdir,
                "zip_path": zip_path,
                "scan_summary": scan_summary_str,
                "vcf_readiness": vcf_readiness,
                "failed_hosts": [],
                "partial_hosts": [],
                "is_import": False,
                "log_lines": [f"[✓] {scan_summary_str}"],
            })

        gc.collect()

        _get_dispatch("_broadcast", _broadcast)("done", done_payload)

        self._send_json(done_payload)

    def _api_import_summary(self) -> None:
        if not _COLLECTOR_OK:
            self._send_json({"error": "Collector package not available"}, 503)
            return

        body = self._read_json_body()
        raw_data = body.get("data")
        if not raw_data:
            self._send_json({"error": "No JSON payload provided in 'data' field"}, 400)
            return

        results = []
        if isinstance(raw_data, list):
            results = raw_data
        elif isinstance(raw_data, dict):
            if "results" in raw_data and isinstance(raw_data["results"], list):
                results = raw_data["results"]
            elif "hosts" in raw_data and isinstance(raw_data["hosts"], list):
                results = raw_data["hosts"]
            else:
                results = [raw_data]

        if not results:
            self._send_json({"error": "No valid host results found in summary JSON"}, 400)
            return

        raw_outdir = body.get("output_dir", "").strip()
        base_outdir = normalize_output_dir(raw_outdir)
        ImportApiMixin._process_imported_results(self, results, base_outdir, source_label="summary")

    def _api_import_summary_file(self) -> None:
        if not _COLLECTOR_OK:
            self._send_json({"error": "Collector package not available"}, 503)
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            content_length = 0

        max_allowed = 512 * 1024 * 1024  # 512 MB cap for scan packages / zip archives
        if content_length > max_allowed:
            self._send_json({"error": f"Uploaded file exceeds limit of {max_allowed} bytes (512 MB)"}, 413)
            return

        raw_outdir = self.headers.get("X-Output-Dir", "").strip()
        base_outdir = normalize_output_dir(raw_outdir)

        cd_header = self.headers.get("Content-Disposition", "")
        m = re.search(r'filename=["\']?([^"\'\s;]+)', cd_header)
        orig_fname = m.group(1) if m else "imported_summary.json"
        suffix = ".json"
        if orig_fname.endswith(".gz"):
            suffix = ".json.gz"
        elif orig_fname.endswith(".zip"):
            suffix = ".zip"

        with tempfile.NamedTemporaryFile("wb", suffix=suffix, delete=False) as tf:
            temp_path = tf.name
            remaining = content_length if content_length > 0 else max_allowed
            chunk_size = 64 * 1024
            bytes_read = 0
            while remaining > 0:
                read_size = min(chunk_size, remaining)
                chunk = self.rfile.read(read_size)
                if not chunk:
                    break
                tf.write(chunk)
                bytes_read += len(chunk)
                if content_length > 0:
                    remaining -= len(chunk)
                else:
                    if bytes_read >= max_allowed:
                        break

        try:
            load_sum_fn = _get_dispatch("load_summary", load_summary)
            results = load_sum_fn(temp_path)
        except Exception as exc:
            self._send_json({"error": f"Failed parsing summary file: {exc}"}, 400)
            return
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

        if not results:
            self._send_json({"error": "No valid host results found in uploaded summary file"}, 400)
            return

        ImportApiMixin._process_imported_results(self, results, base_outdir, source_label="file")
