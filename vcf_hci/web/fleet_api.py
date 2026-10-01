"""
VCF Readiness Tool — Fleet Library Web API Mixin (vcf_hci.web.fleet_api)

Defines FleetApiMixin for multi-scan library discovery, server-side assembly,
paginated index querying, and zip archive drop ingest.
"""

import base64
import gc
import logging
import os
import re
import secrets
import shutil
import time
import urllib.parse
import zipfile
from typing import TYPE_CHECKING, Any, Dict, List, Optional

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
    create_obfuscated_scan_zip_archive,
    create_scan_zip_archive,
    generate_host_html_report,
    generate_summary_html,
    get_default_output_dir,
    normalize_output_dir,
    obfuscate_host_data,
    sanitize_filename,
    update_latest_scan_aliases,
)
from vcf_hci.fleet_library import (
    assemble_fleet,
    discover_scans,
    write_scan_manifest,
)
from vcf_hci.report.csv_export import export_all_csvs
from vcf_hci.report.excel_export import (
    _build_excel_sheets,
    _write_xlsx,
)
from vcf_hci.report.readme import write_scan_readme
from vcf_hci.summary_io import write_fleet_summary
from vcf_hci.web.desktop import _is_safe_desktop_folder
from vcf_hci.web.scan_worker import (
    _broadcast,
    _get_dispatch,
    _state,
    _state_lock,
)

logger = logging.getLogger("vcf_assess")


def _build_compact_host_row(idx: int, host: Dict[str, Any], reports_dir: str = "") -> Dict[str, Any]:
    """Extract a compact decision row from a full host dictionary for index and pagination."""
    sys_data = host.get("system") or {}
    if not isinstance(sys_data, dict):
        sys_data = {}
    cpu_summary = sys_data.get("cpu_summary") or {}
    if not isinstance(cpu_summary, dict):
        cpu_summary = {}

    ip = str(sys_data.get("bmc_ip") or sys_data.get("ip") or host.get("host") or "").strip()
    hostname = str(sys_data.get("hostname") or "").strip()
    vendor = str(sys_data.get("vendor") or "").strip()
    model = str(sys_data.get("model") or "").strip()
    verdict = str(cpu_summary.get("verdict") or "Fully Supported").strip()
    site_val = str(host.get("site") or "").strip()
    source_scan = str(host.get("source_scan") or "").strip()
    scanned_at = str(host.get("scanned_at") or "").strip()

    is_obf = bool(host.get("obfuscated")) or hostname.startswith("Host-") or ip.startswith("Host-")
    if is_obf:
        alias = hostname if hostname.startswith("Host-") else (ip if ip.startswith("Host-") else f"Host-{idx}")
        rep_name = f"OBFUSCATED_{alias}.html"
    else:
        rep_name = f"vcf_readiness_{sanitize_filename(ip)}.html" if ip else f"host_{idx}.html"
    has_rep = False
    if reports_dir and os.path.isdir(reports_dir):
        has_rep = os.path.isfile(os.path.join(reports_dir, rep_name))

    return {
        "idx": idx,
        "ip": ip,
        "hostname": hostname,
        "vendor": vendor,
        "model": model,
        "verdict": verdict,
        "site": site_val,
        "source_scan": source_scan,
        "scanned_at": scanned_at,
        "report": rep_name if has_rep else "",
        "has_report": has_rep,
        "partial_scan": bool(host.get("partial_scan")),
    }


def _resolve_library_dir(raw_path: str = "") -> str:
    """Resolve library directory, prioritizing ~/Documents/Redfish-Library over legacy Desktop/VCF-Scans."""
    clean = str(raw_path or "").strip()
    if clean:
        return os.path.abspath(os.path.expanduser(clean))
    for candidate in (
        os.path.expanduser("~/Documents/Redfish-Library/scans"),
        os.path.expanduser("~/Documents/Redfish-Library"),
        os.path.expanduser("~/Desktop/VCF-Scans"),
    ):
        if os.path.isdir(candidate):
            return os.path.abspath(candidate)
    return os.path.abspath(os.path.expanduser(get_default_output_dir()))


def _scan_ref_path(ref: Any) -> str:
    """Path string from a discover dict or a raw path."""
    if isinstance(ref, dict):
        return str(ref.get("path") or "")
    return str(ref or "")


def _path_is_under(base_dir: str, candidate: str) -> bool:
    """True when candidate resolves to base_dir or a child of it."""
    if not base_dir or not candidate or not isinstance(candidate, str):
        return False
    try:
        abs_base = os.path.realpath(os.path.abspath(base_dir))
        abs_target = os.path.realpath(os.path.abspath(os.path.expanduser(candidate)))
    except (OSError, ValueError):
        return False
    return abs_target == abs_base or abs_target.startswith(abs_base + os.sep)


class FleetApiMixin(_ApiMixinBase):
    """Fleet Library discovery, assembly, paginated index, and ingest endpoints."""

    # ── /api/fleet/discover (GET & POST) ──────────────────────────────────────

    def _api_fleet_discover(self) -> None:
        raw_path = ""
        cmd = getattr(self, "command", "GET")
        if cmd == "GET":
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            raw_path = qs.get("path", [""])[0] or qs.get("library_dir", [""])[0]
        else:
            body = self._read_json_body()
            if isinstance(body, dict):
                raw_path = str(body.get("library_dir") or body.get("path") or "")

        lib_dir = _resolve_library_dir(raw_path)

        if self._is_remote_server() and not _is_safe_desktop_folder(lib_dir):
            self._send_json({"error": "library_dir is outside allowed directories"}, 403)
            return

        discover_fn = _get_dispatch("discover_scans", discover_scans)
        try:
            scans = discover_fn(lib_dir)
        except Exception as exc:
            logger.warning("Error discovering scans in %s: %s", lib_dir, exc)
            self._send_json({"error": f"Failed discovering scans: {exc}"}, 500)
            return

        self._send_json({
            "ok": True,
            "library_dir": lib_dir,
            "scans": scans,
            "count": len(scans),
        })

    # ── /api/fleet/assemble (POST) ───────────────────────────────────────────

    def _api_fleet_assemble(self) -> None:
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._send_json({"error": "Invalid JSON body"}, 400)
            return

        raw_lib = str(body.get("library_dir") or "").strip()
        lib_dir = _resolve_library_dir(raw_lib)

        if self._is_remote_server() and not _is_safe_desktop_folder(lib_dir):
            self._send_json({"error": "library_dir is outside allowed directories"}, 403)
            return

        requested_scans = body.get("scans") or body.get("scan_paths") or []
        site_override = str(body.get("site") or "").strip()
        output_dir_param = str(body.get("output_dir") or "").strip()
        obfuscate = bool(body.get("obfuscate"))

        discover_fn = _get_dispatch("discover_scans", discover_scans)
        discovered = discover_fn(lib_dir)

        scan_refs: List[Any] = []
        if requested_scans and isinstance(requested_scans, list):
            # Map requested scan identifiers or paths to discovered scans
            disc_by_id = {s.get("scan_id"): s for s in discovered}
            disc_by_path = {os.path.abspath(s.get("path", "")): s for s in discovered}
            for req in requested_scans:
                req_str = str(req).strip()
                if not req_str:
                    continue
                req_abs = os.path.abspath(os.path.expanduser(req_str))
                if req_abs in disc_by_path:
                    chosen = disc_by_path[req_abs]
                elif req_str in disc_by_id:
                    chosen = disc_by_id[req_str]
                elif os.path.exists(req_abs):
                    chosen = req_abs
                else:
                    continue
                if not _path_is_under(lib_dir, _scan_ref_path(chosen)):
                    self._send_json({"error": "scan path is outside the library directory"}, 400)
                    return
                scan_refs.append(chosen)
        else:
            scan_refs = [s for s in discovered if _path_is_under(lib_dir, _scan_ref_path(s))]

        if not scan_refs:
            self._send_json({"error": "No scan folders or archives found to assemble"}, 400)
            return

        assemble_fn = _get_dispatch("assemble_fleet", assemble_fleet)
        policy = {"site": site_override} if site_override else None
        try:
            assemble_res = assemble_fn(scan_refs, policy=policy)
        except Exception as exc:
            logger.error("Error during fleet assembly: %s", exc, exc_info=True)
            self._send_json({"error": f"Fleet assembly failed: {exc}"}, 500)
            return

        results = assemble_res.get("results") or []
        if not results:
            self._send_json({"error": "No valid host results found across selected scans"}, 400)
            return

        # Prepare unique assemble output directory
        base_outdir = normalize_output_dir(output_dir_param or get_default_output_dir())
        outdir = os.path.join(base_outdir, f"assembled_{time.strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(outdir, exist_ok=True)
        data_dir = os.path.join(outdir, "data")
        reports_dir = os.path.join(outdir, "reports")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(reports_dir, exist_ok=True)

        # Map source scan paths for lazy report copying
        scans_meta = assemble_res.get("scans") or []
        scan_path_map: Dict[str, str] = {}
        for sm in scans_meta:
            sid = sm.get("scan_id")
            sp = sm.get("path")
            if sid and sp:
                scan_path_map[sid] = sp

        report_paths: List[str] = []
        obf_salt = os.urandom(16).hex() if obfuscate else ""
        obf_results: List[Dict[str, Any]] = []
        obf_report_paths: List[str] = []

        if obfuscate:
            obf_host_fn = _get_dispatch("obfuscate_host_data", obfuscate_host_data)
            obf_results = [obf_host_fn(r, f"Host-{i+1}", obf_salt) for i, r in enumerate(results)]

            from concurrent.futures import ThreadPoolExecutor
            gen_host_fn = _get_dispatch("generate_host_html_report", generate_host_html_report)

            def _render_obf_h(pair):
                i_idx, h_data = pair
                rep_name = f"OBFUSCATED_Host-{i_idx}.html"
                rep_path = os.path.join(reports_dir, rep_name)
                try:
                    gen_host_fn(h_data, rep_path, obfuscated=True)
                    return rep_path
                except Exception as h_exc:
                    logger.debug("Could not generate obfuscated host report %s: %s", rep_path, h_exc)
                    return ""

            max_workers = min(32, max(4, (os.cpu_count() or 4) * 2))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                obf_report_paths = list(executor.map(_render_obf_h, enumerate(obf_results, 1)))
            obf_report_paths = [p for p in obf_report_paths if p and os.path.isfile(p)]
        else:
            for idx, host in enumerate(results, 1):
                sys_info = host.get("system") or {}
                ip = str(sys_info.get("bmc_ip") or sys_info.get("ip") or host.get("host") or "").strip()
                source_scan = str(host.get("source_scan") or "")
                src_path = scan_path_map.get(source_scan)

                dest_report = ""
                if ip and src_path:
                    cand_names = [
                        f"vcf_readiness_{sanitize_filename(ip)}.html",
                        f"vsphere_vsan_report_{sanitize_filename(ip)}.html",
                    ]
                    if os.path.isdir(src_path):
                        for cname in cand_names:
                            for sub in ("reports", ""):
                                cand_file = os.path.join(src_path, sub, cname) if sub else os.path.join(src_path, cname)
                                if os.path.isfile(cand_file):
                                    dest_report = os.path.join(reports_dir, f"vcf_readiness_{sanitize_filename(ip)}.html")
                                    try:
                                        if not os.path.exists(dest_report):
                                            shutil.copy2(cand_file, dest_report)
                                    except Exception as c_exc:
                                        logger.debug("Could not copy host report from %s: %s", cand_file, c_exc)
                                    break
                            if dest_report:
                                break
                    elif zipfile.is_zipfile(src_path):
                        try:
                            with zipfile.ZipFile(src_path, "r") as zf:
                                znames = set(zf.namelist())
                                for cname in cand_names:
                                    for zprefix in ("reports/", ""):
                                        ztarget = f"{zprefix}{cname}"
                                        if ztarget in znames:
                                            dest_report = os.path.join(reports_dir, f"vcf_readiness_{sanitize_filename(ip)}.html")
                                            if not os.path.exists(dest_report):
                                                with open(dest_report, "wb") as df:
                                                    df.write(zf.read(ztarget))
                                            break
                                    if dest_report:
                                        break
                        except Exception as z_exc:
                            logger.debug("Could not extract host report from %s: %s", src_path, z_exc)

                report_paths.append(dest_report)

        effective_results = obf_results if obfuscate else results
        effective_report_paths = obf_report_paths if obfuscate else report_paths

        # 1. Summary JSON & Manifest
        try:
            write_fleet_fn = _get_dispatch("write_fleet_summary", write_fleet_summary)
            if obfuscate:
                write_fleet_fn(obf_results, data_dir, prefix="OBFUSCATED_fleet_summary")
            else:
                write_fleet_fn(results, data_dir, prefix="fleet_summary")

            write_manifest_fn = _get_dispatch("write_scan_manifest", write_scan_manifest)
            write_manifest_fn(
                outdir=outdir,
                host_count=len(effective_results),
                site=site_override,
                scan_profile="assembled",
                obfuscated=obfuscate,
            )
        except Exception as s_exc:
            logger.warning("Could not write assembled fleet summary JSON or manifest: %s", s_exc)

        # 2. Excel workbook
        excel_fname = ""
        try:
            build_sheets_fn = _get_dispatch("_build_excel_sheets", _build_excel_sheets)
            write_xlsx_fn = _get_dispatch("_write_xlsx", _write_xlsx)
            sheets = build_sheets_fn(effective_results, failed_hosts=[], obfuscated=obfuscate)
            xlsx_bytes = write_xlsx_fn(sheets)
            ts = time.strftime("%Y%m%d_%H%M%S")
            fname_prefix = "00_OBFUSCATED_vcf_readiness_" if obfuscate else "vcf_readiness_"
            excel_fname = sanitize_filename(f"{fname_prefix}{ts}.xlsx")
            with open(os.path.join(outdir, excel_fname), "wb") as f:
                f.write(xlsx_bytes)
        except Exception as x_exc:
            logger.warning("Failed writing assembled Excel workbook: %s", x_exc)

        # 3. CSV set
        try:
            export_csvs_fn = _get_dispatch("export_all_csvs", export_all_csvs)
            export_csvs_fn(effective_results, outdir, obfuscated=obfuscate)
        except Exception as c_exc:
            logger.warning("Failed writing assembled CSV files: %s", c_exc)

        # 4. Fleet Summary HTML
        summary_path = ""
        try:
            gen_sum_fn = _get_dispatch("generate_summary_html", generate_summary_html)
            summary_fname = "00_OBFUSCATED_fleet_summary.html" if obfuscate else "00_fleet_summary.html"
            summary_path = os.path.join(outdir, summary_fname)
            gen_sum_fn(effective_results, summary_path, obfuscated=obfuscate)
        except Exception as sum_exc:
            logger.warning("Failed generating assembled summary HTML: %s", sum_exc)

        # 5. Combined Fleet Hub
        fleet_path = ""
        try:
            gen_comb_fn = _get_dispatch("_generate_combined_html", _generate_combined_html)
            fleet_path = gen_comb_fn(effective_results, effective_report_paths, outdir, obfuscated=obfuscate)
        except Exception as comb_exc:
            logger.warning("Failed generating assembled Fleet Hub HTML: %s", comb_exc)

        # 5.5. Readme index guide
        try:
            write_readme_fn = _get_dispatch("write_scan_readme", write_scan_readme)
            write_readme_fn(
                outdir=outdir,
                host_count=len(effective_results),
                site=site_override,
                scan_profile="assembled",
                obfuscated=obfuscate,
            )
        except Exception as r_exc:
            logger.warning("Failed writing assembled Readme.txt: %s", r_exc)

        # 6. Zip archive
        zip_path = ""
        try:
            if obfuscate:
                create_obf_zip_fn = _get_dispatch("create_obfuscated_scan_zip_archive", create_obfuscated_scan_zip_archive)
                zip_path = create_obf_zip_fn(outdir, results=effective_results)
            else:
                create_zip_fn = _get_dispatch("create_scan_zip_archive", create_scan_zip_archive)
                zip_path = create_zip_fn(outdir)
        except Exception as z_exc:
            logger.warning("Failed creating scan zip archive for assembled fleet: %s", z_exc)

        # 7. Symlink aliases
        try:
            update_aliases_fn = _get_dispatch("update_latest_scan_aliases", update_latest_scan_aliases)
            update_aliases_fn(scan_dir=outdir, base_dir=base_outdir)
        except Exception:
            pass

        # 8. Build compact index rows
        compact_rows = [_build_compact_host_row(i, h, reports_dir) for i, h in enumerate(results, 1)]

        # Compute readiness counts
        vcf_sup = vcf_dep = vcf_unsup = 0
        for row in compact_rows:
            v = row.get("verdict", "")
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

        scan_id = "assemble_" + secrets.token_hex(4)
        scan_summary_str = (
            f"Assembled {len(results)} unique host(s) across {assemble_res['total_scans']} scan(s) "
            f"({assemble_res['duplicates_count']} duplicate(s) merged)"
        )

        # For large fleets (> 500 hosts), trim _state["results"] so compact index
        # (_state["fleet_index"]) is the process working set, keeping RAM minimal.
        stored_results = effective_results if len(effective_results) <= 500 else []

        with _state_lock:
            _state.update({
                "scan_id": scan_id,
                "running": False,
                "done": True,
                "error": None,
                "total": len(effective_results),
                "completed": len(effective_results),
                "n_ok": len(effective_results),
                "results": stored_results,
                "fleet_index": compact_rows,
                "report_paths": effective_report_paths,
                "fleet_path": fleet_path,
                "summary_path": summary_path,
                "outdir": outdir,
                "zip_path": zip_path,
                "scan_summary": scan_summary_str,
                "vcf_readiness": vcf_readiness,
                "failed_hosts": [],
                "partial_hosts": [],
                "is_import": False,
                "is_assemble": True,
                "log_lines": [f"[✓] {scan_summary_str}"],
            })

        broadcast_fn = _get_dispatch("_broadcast", _broadcast)
        broadcast_fn("done", {
            "ok": True,
            "scan_id": scan_id,
            "count": len(effective_results),
            "n_ok": len(effective_results),
            "n_total": len(effective_results),
            "fleet": os.path.basename(fleet_path) if fleet_path else "",
            "summary": os.path.basename(summary_path) if summary_path else "",
            "outdir": outdir,
            "zip_path": zip_path,
            "scan_summary": scan_summary_str,
            "vcf_readiness": vcf_readiness,
            "is_assemble": True,
        })

        gc.collect()

        self._send_json({
            "ok": True,
            "scan_id": scan_id,
            "total_hosts": len(effective_results),
            "total_unique": assemble_res["total_hosts_unique"],
            "total_scans": assemble_res["total_scans"],
            "duplicates_count": assemble_res["duplicates_count"],
            "outdir": outdir,
            "fleet_path": fleet_path,
            "summary_path": summary_path,
            "zip_path": zip_path,
            "excel_file": excel_fname,
            "scan_summary": scan_summary_str,
            "vcf_readiness": vcf_readiness,
        })

    # ── /api/fleet/prerender (POST) ──────────────────────────────────────────

    def _api_fleet_prerender(self) -> None:
        """Pre-generate all single-host HTML reports across the fleet for fully offline portable bundles."""
        with _state_lock:
            outdir = _state.get("outdir", "")
            results = list(_state.get("results") or [])

        if not outdir or not os.path.isdir(outdir):
            self._send_json({"error": "No assembled or scanned fleet directory found"}, 400)
            return

        if not results:
            try:
                from vcf_hci.summary_io import load_summary
                results = load_summary(outdir) or []
            except Exception as exc:
                logger.error("Could not load summary for pre-rendering: %s", exc)
                self._send_json({"error": f"Failed reading summary: {exc}"}, 500)
                return

        if not results:
            self._send_json({"error": "No hosts found to pre-render"}, 400)
            return

        reports_dir = os.path.join(outdir, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        from vcf_hci.report import generate_host_html_report

        obf_salt = _state.get("obf_salt") or os.urandom(16).hex()
        rendered_count = 0
        report_paths: List[str] = []

        for idx, host in enumerate(results, 1):
            sys_info = host.get("system") or {}
            ip = str(sys_info.get("bmc_ip") or sys_info.get("ip") or host.get("host") or "").strip()
            rep_name = f"vcf_readiness_{sanitize_filename(ip)}.html" if ip else f"host_{idx}.html"
            dest_report = os.path.join(reports_dir, rep_name)

            if not os.path.exists(dest_report):
                try:
                    generate_host_html_report(host, dest_report, obfuscated=False)
                    rendered_count += 1
                except Exception as exc:
                    logger.warning("Failed pre-rendering host report %s: %s", rep_name, exc)

            report_paths.append(dest_report)

            # Pre-render obfuscated host report if obfuscated summary exists
            obf_sum_exists = os.path.isfile(os.path.join(outdir, "00_OBFUSCATED_fleet_summary.html")) or os.path.isfile(os.path.join(outdir, "data", "OBFUSCATED_fleet_summary.json"))
            if obf_sum_exists:
                obf_file = f"OBFUSCATED_Host-{idx}.html"
                dest_obf = os.path.join(reports_dir, obf_file)
                if not os.path.exists(dest_obf):
                    try:
                        obf_host = obfuscate_host_data(host, f"Host-{idx}", obf_salt)
                        generate_host_html_report(obf_host, dest_obf, obfuscated=True)
                    except Exception:
                        pass

        # Update compact index with updated has_report flags
        new_compact_rows = [_build_compact_host_row(i, h, reports_dir) for i, h in enumerate(results, 1)]

        try:
            write_readme_fn = _get_dispatch("write_scan_readme", write_scan_readme)
            write_readme_fn(outdir=outdir, host_count=len(results))
        except Exception:
            pass

        zip_path = _state.get("zip_path") or ""
        try:
            create_zip_fn = _get_dispatch("create_scan_zip_archive", create_scan_zip_archive)
            zip_path = create_zip_fn(outdir)
        except Exception as z_exc:
            logger.debug("Failed updating scan zip archive: %s", z_exc)

        with _state_lock:
            _state.update({
                "fleet_index": new_compact_rows,
                "report_paths": report_paths,
                "zip_path": zip_path,
            })

        gc.collect()

        self._send_json({
            "ok": True,
            "total": len(results),
            "rendered": rendered_count,
            "reports_dir": reports_dir,
            "zip_path": zip_path,
        })

    # ── /api/fleet/index (GET) ────────────────────────────────────────────────

    def _api_fleet_index(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        try:
            offset = max(0, int(qs.get("offset", ["0"])[0]))
        except (ValueError, TypeError):
            offset = 0

        try:
            limit = min(500, max(1, int(qs.get("limit", ["50"])[0])))
        except (ValueError, TypeError):
            limit = 50

        facet_param = qs.get("facet", [""])[0].strip()
        search_param = qs.get("search", [""])[0].strip().lower()
        site_filter = qs.get("site", [""])[0].strip()
        vendor_filter = qs.get("vendor", [""])[0].strip()
        verdict_filter = qs.get("verdict", [""])[0].strip()

        if ":" in facet_param:
            f_parts = facet_param.split(":", 1)
            f_key = f_parts[0].strip().lower()
            f_val = f_parts[1].strip()
            if f_key == "site":
                site_filter = f_val
            elif f_key == "vendor":
                vendor_filter = f_val
            elif f_key == "verdict":
                verdict_filter = f_val
        elif facet_param and not search_param:
            search_param = facet_param.lower()

        with _state_lock:
            stored_index = _state.get("fleet_index")
            if stored_index is not None and isinstance(stored_index, list):
                all_items = list(stored_index)
            else:
                raw_results = _state.get("results") or []
                rep_dir = os.path.join(_state.get("outdir", ""), "reports")
                all_items = [_build_compact_host_row(i, h, rep_dir) for i, h in enumerate(raw_results, 1)]

        # Collect facet counts across all un-filtered items
        sites_map: Dict[str, int] = {}
        vendors_map: Dict[str, int] = {}
        verdicts_map: Dict[str, int] = {}

        for it in all_items:
            s_name = it.get("site") or "Unassigned"
            v_name = it.get("vendor") or "Unknown"
            vd_name = it.get("verdict") or "Unknown"
            sites_map[s_name] = sites_map.get(s_name, 0) + 1
            vendors_map[v_name] = vendors_map.get(v_name, 0) + 1
            verdicts_map[vd_name] = verdicts_map.get(vd_name, 0) + 1

        # Apply filters
        filtered: List[Dict[str, Any]] = []
        for it in all_items:
            if site_filter:
                it_site = it.get("site") or "Unassigned"
                if it_site.lower() != site_filter.lower():
                    continue
            if vendor_filter:
                it_vend = it.get("vendor") or "Unknown"
                if it_vend.lower() != vendor_filter.lower():
                    continue
            if verdict_filter:
                it_verd = it.get("verdict") or ""
                if verdict_filter.lower() not in it_verd.lower():
                    continue
            if search_param:
                search_haystack = " ".join([
                    str(it.get("ip") or ""),
                    str(it.get("hostname") or ""),
                    str(it.get("vendor") or ""),
                    str(it.get("model") or ""),
                    str(it.get("site") or ""),
                    str(it.get("source_scan") or ""),
                    str(it.get("verdict") or ""),
                ]).lower()
                if search_param not in search_haystack:
                    continue
            filtered.append(it)

        paged_items = filtered[offset : offset + limit]

        self._send_json({
            "ok": True,
            "total": len(all_items),
            "filtered_total": len(filtered),
            "offset": offset,
            "limit": limit,
            "items": paged_items,
            "facets": {
                "sites": sites_map,
                "vendors": vendors_map,
                "verdicts": verdicts_map,
            },
        })

    # ── /api/fleet/ingest (POST) & /api/v1/fleet/ingest (alias) ───────────────

    def _api_fleet_ingest(self) -> None:
        """Drop-folder ingest wrapper: saves zip into library, then assembles fleet."""
        content_type = self.headers.get("Content-Type", "").lower() if hasattr(self, "headers") and self.headers else ""
        raw_lib = self.headers.get("X-Library-Dir", "").strip() if hasattr(self, "headers") and self.headers else ""

        zip_bytes: bytes = b""
        filename = ""
        should_assemble = True

        if "application/json" in content_type:
            body = self._read_json_body()
            if not isinstance(body, dict):
                self._send_json({"error": "Invalid JSON body"}, 400)
                return
            b64_str = body.get("content_b64") or body.get("data_b64") or ""
            filename = str(body.get("filename") or "").strip()
            raw_lib = raw_lib or str(body.get("library_dir") or "").strip()
            if "assemble" in body:
                should_assemble = bool(body.get("assemble"))

            if b64_str:
                try:
                    zip_bytes = base64.b64decode(b64_str)
                except Exception as exc:
                    self._send_json({"error": f"Failed decoding base64 payload: {exc}"}, 400)
                    return
            elif body.get("zip_path"):
                src_zip = os.path.realpath(os.path.abspath(os.path.expanduser(str(body.get("zip_path")))))
                if not os.path.isfile(src_zip):
                    self._send_json({"error": "zip_path must point to an existing file"}, 400)
                    return
                if self._is_remote_server():
                    self._send_json({"error": "zip ingest by local path is disabled in remote mode."}, 403)
                    return
                if not _is_safe_desktop_folder(os.path.dirname(src_zip)):
                    self._send_json({"error": "zip_path is outside allowed directories"}, 400)
                    return
                try:
                    with open(src_zip, "rb") as f:
                        zip_bytes = f.read()
                    if not filename:
                        filename = os.path.basename(src_zip)
                except Exception as exc:
                    self._send_json({"error": f"Could not read source zip_path: {exc}"}, 400)
                    return
        else:
            try:
                content_len = int(self.headers.get("Content-Length", 0))
            except (ValueError, TypeError):
                content_len = 0

            max_allowed = 512 * 1024 * 1024
            if content_len > max_allowed:
                self._send_json({"error": f"Uploaded zip exceeds {max_allowed} bytes"}, 413)
                return

            cd_header = self.headers.get("Content-Disposition", "")
            m = re.search(r'filename=["\']?([^"\'\s;]+)', cd_header)
            if m:
                filename = m.group(1)

            if content_len > 0:
                zip_bytes = self.rfile.read(content_len)

        if not zip_bytes:
            self._send_json({"error": "No zip file content received"}, 400)
            return

        lib_dir = _resolve_library_dir(raw_lib)

        if self._is_remote_server() and not _is_safe_desktop_folder(lib_dir):
            self._send_json({"error": "library_dir is outside allowed directories"}, 403)
            return

        os.makedirs(lib_dir, exist_ok=True)
        if not filename:
            filename = f"scan_drop_{time.strftime('%Y%m%d_%H%M%S')}.zip"
        safe_fname = sanitize_filename(filename)
        if not safe_fname.lower().endswith(".zip"):
            safe_fname += ".zip"

        dest_zip_path = os.path.join(lib_dir, safe_fname)
        try:
            with open(dest_zip_path, "wb") as f:
                f.write(zip_bytes)
        except Exception as exc:
            self._send_json({"error": f"Failed writing zip to library: {exc}"}, 500)
            return

        if not should_assemble:
            self._send_json({"ok": True, "saved_path": dest_zip_path, "assembled": False})
            return

        # Execute assembly over library
        assemble_fn = _get_dispatch("assemble_fleet", assemble_fleet)
        try:
            assemble_res = assemble_fn(lib_dir)
        except Exception as exc:
            self._send_json({
                "ok": True,
                "saved_path": dest_zip_path,
                "assembled": False,
                "assemble_error": str(exc),
            })
            return

        self._send_json({
            "ok": True,
            "saved_path": dest_zip_path,
            "assembled": True,
            "total_hosts": assemble_res.get("total_hosts_unique", 0),
            "total_scans": assemble_res.get("total_scans", 0),
        })
