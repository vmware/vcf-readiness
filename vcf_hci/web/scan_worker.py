"""
VCF Readiness Tool — Background Scan Worker & SSE Engine (vcf_hci.web.scan_worker)

Handles background multi-threaded scanning, SSE event broadcasting,
multi-pass auto-retry logic, and fleet artifact regeneration.
"""

import json
import logging
import os
import queue
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vcf_assess")

# ── Collector imports ────────────────────────────────────────────────────────
from vcf_hci import (
    _generate_combined_html,
    create_obfuscated_scan_zip_archive,
    create_scan_zip_archive,
    ensure_auto_hcl_bundle,
    generate_summary_html,
    get_hcl_cache_status,
    import_hcl_bundle,
    obfuscate_host_data,
    sanitize_filename,
    scan_hosts,
    update_latest_scan_aliases,
)
from vcf_hci.constants import COMBINED_HTML_MAX_HOSTS
from vcf_hci.report import _build_excel_sheets, _write_xlsx, export_all_csvs, generate_host_html_report
from vcf_hci.summary_io import write_fleet_summary

_COLLECTOR_OK = True


# =============================================================================
# Global scan state  (shared across handler instances)
# =============================================================================
_state_lock = threading.Lock()
_state: Dict[str, Any] = {
    "scan_id": None,
    "running": False,
    "done": False,
    "error": None,
    "total": 0,
    "completed": 0,
    "is_retry": False,
    "is_rescan": False,
    "is_import": False,
    "had_auto_retry": False,
    "execution": "local",
    "jump_host_id": None,
    "n_ok": 0,
    "active_hosts": {},
    "completed_hosts": set(),
    "skipped_ips": set(),
    "results": [],
    "failed_hosts": [],
    "partial_hosts": [],
    "report_paths": [],
    "fleet_path": "",
    "summary_path": "",
    "outdir": "",
    "log_lines": [],
    "custom_hcl_bundle_path": None,
    "hcl_bundle_metadata": None,
    "disconnected_jump_scan": None,
    "active_remote_scans": [],
}
_sse_clients: List[queue.Queue] = []  # list of queue.Queue, one per connected SSE client
_shutdown_event = threading.Event()
_cancel_event = threading.Event()


def _get_dispatch(name: str, default_fn: Any) -> Any:
    srv = sys.modules.get("vcf_hci.web.server")
    if srv is not None and hasattr(srv, name):
        return getattr(srv, name)
    return default_fn


def set_custom_hcl_bundle(bundle_path: str) -> dict:
    """Load and register a custom dark-site HCL bundle zip for web server scans."""
    if not os.path.exists(bundle_path):
        raise FileNotFoundError(f"HCL bundle file not found: {bundle_path}")
    json_hcl, csv_db, metadata = import_hcl_bundle(bundle_path)
    if not metadata and not json_hcl and not csv_db:
        raise ValueError("Failed to import or parse HCL bundle")
    with _state_lock:
        _state["custom_hcl_bundle_path"] = bundle_path
        _state["hcl_bundle_metadata"] = metadata
    return metadata


def _get_active_hcl_metadata() -> dict:
    """Return active dark-site or auto-bundle HCL metadata."""
    with _state_lock:
        custom_path = _state.get("custom_hcl_bundle_path")
        custom_meta = _state.get("hcl_bundle_metadata")

    if custom_path and custom_meta:
        meta = dict(custom_meta)
        meta["is_custom_bundle"] = True
        meta["source_type"] = "custom_bundle"
        return meta

    status = {}
    if _COLLECTOR_OK:
        try:
            status = get_hcl_cache_status()
        except Exception as se:
            logger.debug("Error getting HCL cache status: %s", se)
        auto_path = ensure_auto_hcl_bundle(max_age_days=30)
        if auto_path:
            _, _, meta = import_hcl_bundle(auto_path)
            if meta:
                meta_copy = dict(meta)
                meta_copy.update(status)
                meta_copy["is_custom_bundle"] = False
                return meta_copy
        status["is_custom_bundle"] = False
        return status

    return {"is_custom_bundle": False, "source_type": "missing"}


def _broadcast(event_type: str, data: dict) -> None:
    """Send an SSE message to all connected clients and append to log."""
    msg = f"event: {event_type}\ndata: {json.dumps(data, default=str)}\n\n"
    with _state_lock:
        msg_str = data.get("msg", "")
        if msg_str:
            _state["log_lines"].append(msg_str)
            if len(_state["log_lines"]) > 500:
                _state["log_lines"] = _state["log_lines"][-500:]
        for q in list(_sse_clients):
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass


# =============================================================================
# Scan worker callbacks
# =============================================================================
def _handle_host_start(scan_id: str, info: dict) -> None:
    info["scan_id"] = scan_id
    ip = info.get("ip")
    start_time = info.get("start_time", time.time())
    if ip:
        with _state_lock:
            if ip in _state.get("completed_hosts", set()):
                return
            is_r = bool(_state.get("is_retry") or _state.get("is_rescan") or info.get("is_rescan"))
            is_imp = bool(_state.get("is_import") or info.get("is_import"))
            default_stage = "Rendering HTML Report..." if is_imp else ("Connecting & Starting Rescan..." if is_r else "Connecting & Starting Scan...")
            stage = info.get("stage") or default_stage
            _state["active_hosts"][ip] = {
                "start_time": start_time,
                "stage": stage,
                "is_rescan": is_r,
                "is_import": is_imp,
            }
    _get_dispatch("_broadcast", _broadcast)("host_start", info)


def _handle_host_stage(scan_id: str, info: dict) -> None:
    info["scan_id"] = scan_id
    ip = info.get("ip")
    stage = info.get("stage", "")
    if ip:
        with _state_lock:
            if ip in _state.get("completed_hosts", set()):
                return
            is_r = bool(_state.get("is_retry") or _state.get("is_rescan") or info.get("is_rescan"))
            if ip in _state["active_hosts"] and isinstance(_state["active_hosts"][ip], dict):
                _state["active_hosts"][ip]["stage"] = stage
                _state["active_hosts"][ip]["req_count"] = info.get("req_count", 0)
                _state["active_hosts"][ip]["throttled"] = info.get("throttled", False)
                if is_r:
                    _state["active_hosts"][ip]["is_rescan"] = True
            else:
                return
    _get_dispatch("_broadcast", _broadcast)("host_stage", info)


def _handle_host_done(scan_id: str, info: dict) -> None:
    info["scan_id"] = scan_id
    ip = info.get("ip")
    with _state_lock:
        is_remote = (_state.get("execution") == "remote") or bool(_state.get("active_remote_scans"))
        if is_remote:
            info["is_remote"] = True
        if ip:
            _state.setdefault("completed_hosts", set()).add(ip)
            _state["active_hosts"].pop(ip, None)
    _get_dispatch("_broadcast", _broadcast)("host_done", info)


def _regenerate_fleet_artifacts(
    results: list,
    failed_hosts: list,
    outdir: str,
    combined: bool = True,
    obfuscate: bool = False,
    debug: bool = False,
    save_json: bool = False,
    custom_hcl_metadata: Optional[dict] = None,
    log_callback=None,
    export_sheets: bool = True,
    excel: bool = True,
    site: Optional[str] = None,
    collector_id: Optional[str] = None,
    scan_profile: Optional[str] = None,
) -> tuple:
    """Regenerate consolidated fleet summary, combined HTML report, and zip archive across merged results.

    Returns:
        (fleet_path, summary_path, zip_path, report_paths)
    """
    def _log(msg: str):
        if log_callback:
            try:
                log_callback("log", msg)
            except Exception:
                pass
        else:
            logger.info(msg)

    n = len(results)
    reports_dir = os.path.join(outdir, "reports")
    data_dir = os.path.join(outdir, "data")
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)

    fleet_path = ""
    summary_path = ""
    zip_path = ""
    _obf_fleet_path = ""
    _obf_sum = ""
    obf_results = None

    report_paths = []
    for r in results:
        ip = ((r.get("system") or {}).get("ip") or r.get("host") or "").strip()
        if ip:
            rp = os.path.join(reports_dir, f"vsphere_vsan_report_{sanitize_filename(ip)}.html")
            if os.path.isfile(rp):
                report_paths.append(rp)

    if n >= 1 or len(failed_hosts) >= 1:
        if combined and n >= 1:
            if n > COMBINED_HTML_MAX_HOSTS:
                _log(f"[!] Note: Combined report host count ({n}) exceeds soft limit of {COMBINED_HTML_MAX_HOSTS}.")
            try:
                fleet_path = _generate_combined_html(results, report_paths, outdir)
                if fleet_path:
                    _log(f"[✓] Combined report  →  {os.path.basename(fleet_path)}")
            except Exception as exc:
                _log(f"[!] Combined report failed: {exc}")

        try:
            summary_path = os.path.join(outdir, "00_fleet_summary.html")
            generate_summary_html(results, summary_path, hcl_bundle_metadata=custom_hcl_metadata, failed_hosts=failed_hosts)
            _log("[✓] Fleet summary    →  00_fleet_summary.html")
        except Exception as exc:
            _log(f"[!] Fleet summary failed: {exc}")

        obf_results = None
        if obfuscate and n >= 1:
            _obf_salt = os.urandom(16).hex()
            obf_results = [obfuscate_host_data(r, f"Host-{i+1}", _obf_salt) for i, r in enumerate(results)]
            if n > 1:
                try:
                    _obf_sum = os.path.join(outdir, "00_OBFUSCATED_fleet_summary.html")
                    generate_summary_html(
                        obf_results,
                        _obf_sum,
                        hcl_bundle_metadata=custom_hcl_metadata,
                        obfuscated=True,
                    )
                    _log("[🔒] Obfuscated fleet summary  →  00_OBFUSCATED_fleet_summary.html")
                except Exception as exc:
                    _log(f"[!] Obfuscated fleet summary failed: {exc}")

            def _render_obf_host(item):
                i, obf_h = item
                obf_path = os.path.join(reports_dir, f"OBFUSCATED_Host-{i+1}.html")
                if os.path.isfile(obf_path) and os.path.getsize(obf_path) > 0:
                    return obf_path
                try:
                    generate_host_html_report(
                        obf_h,
                        obf_path,
                        hcl_bundle_metadata=custom_hcl_metadata,
                        obfuscated=True,
                    )
                    return obf_path
                except Exception as exc:
                    logger.warning("Failed generating obfuscated host report %s: %s", obf_path, exc)
                    return None

            max_workers = min(32, max(4, (os.cpu_count() or 4) * 2))
            if n <= 1:
                obf_report_paths = [_render_obf_host((0, obf_results[0]))]
            else:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    obf_report_paths = list(executor.map(_render_obf_host, enumerate(obf_results)))
            obf_report_paths = [p for p in obf_report_paths if p and os.path.isfile(p)]

            if combined and n >= 1:
                try:
                    _obf_fleet_path = _generate_combined_html(
                        obf_results,
                        obf_report_paths,
                        outdir,
                        obfuscated=True,
                    )
                    if _obf_fleet_path:
                        _log(f"[🔒] Obfuscated combined report →  {os.path.basename(_obf_fleet_path)}")
                except Exception as exc:
                    _log(f"[!] Obfuscated combined report failed: {exc}")

        if (debug or save_json) and n >= 1:
            _indent = 2 if debug else None
            _separators = None if debug else (",", ":")
            try:
                write_fleet_summary(results, data_dir, prefix="fleet_summary", indent=_indent, separators=_separators)
                _log("[✓] Fleet summary JSON →  data/fleet_summary.json")
            except Exception as exc:
                _log(f"[!] Fleet summary JSON failed: {exc}")

            if obfuscate and obf_results:
                try:
                    write_fleet_summary(obf_results, data_dir, prefix="OBFUSCATED_fleet_summary", indent=_indent, separators=_separators)
                    _log("[🔒] Obfuscated fleet summary JSON →  data/OBFUSCATED_fleet_summary.json")
                except Exception as exc:
                    _log(f"[!] Obfuscated fleet summary JSON failed: {exc}")

        if (excel or export_sheets) and n >= 1:
            try:
                sheets = _build_excel_sheets(results, failed_hosts=failed_hosts)
                xlsx_bytes = _write_xlsx(sheets)
                excel_fname = sanitize_filename(f"vcf_readiness_{time.strftime('%Y%m%d_%H%M%S')}.xlsx")
                excel_path = os.path.join(outdir, excel_fname)
                with open(excel_path, "wb") as f:
                    f.write(xlsx_bytes)
                _log(f"[✓] Excel report     →  {excel_fname}")
            except Exception as exc:
                _log(f"[!] Excel report failed: {exc}")

            try:
                export_all_csvs(results, outdir, obfuscated=False, failed_hosts=failed_hosts)
                _log("[✓] CSV exports      →  00_fleet_summary.csv, 00_drives_inventory.csv, 00_nics_inventory.csv")
            except Exception as exc:
                _log(f"[!] CSV exports failed: {exc}")

            if obfuscate and obf_results:
                try:
                    from vcf_hci.obfuscation import obfuscate_failed_hosts
                    obf_failed_hosts = obfuscate_failed_hosts(failed_hosts, salt=_obf_salt, start_idx=len(obf_results) + 1)
                    obf_sheets = _build_excel_sheets(obf_results, failed_hosts=obf_failed_hosts, obfuscated=True)
                    obf_xlsx_bytes = _write_xlsx(obf_sheets)
                    obf_excel_fname = sanitize_filename(f"00_OBFUSCATED_vcf_readiness_{time.strftime('%Y%m%d_%H%M%S')}.xlsx")
                    obf_excel_path = os.path.join(outdir, obf_excel_fname)
                    with open(obf_excel_path, "wb") as f:
                        f.write(obf_xlsx_bytes)
                    _log(f"[🔒] Obfuscated Excel report →  {obf_excel_fname}")
                except Exception as exc:
                    _log(f"[!] Obfuscated Excel report failed: {exc}")

                try:
                    export_all_csvs(obf_results, outdir, obfuscated=True, failed_hosts=obf_failed_hosts)
                    _log("[🔒] Obfuscated CSV exports  →  00_OBFUSCATED_fleet_summary.csv, ...")
                except Exception as exc:
                    _log(f"[!] Obfuscated CSV exports failed: {exc}")

        try:
            from vcf_hci.fleet_library import write_scan_manifest
            write_scan_manifest(
                outdir=outdir,
                host_count=n,
                site=site,
                collector_id=collector_id,
                scan_profile=scan_profile,
                obfuscated=obfuscate,
            )
            _log("[✓] Scan manifest    →  MANIFEST.json")
        except Exception as _m_exc:
            logger.debug("Failed writing scan manifest: %s", _m_exc)

        try:
            from vcf_hci.report import write_scan_readme
            write_scan_readme(
                outdir=outdir,
                host_count=n,
                site=site,
                collector_id=collector_id,
                scan_profile=scan_profile,
                obfuscated=obfuscate,
                failed_count=len(failed_hosts) if failed_hosts else 0,
            )
            _log("[✓] Scan index guide →  Readme.txt")
        except Exception as _r_exc:
            logger.debug("Failed writing scan readme: %s", _r_exc)

        try:
            zip_path = create_scan_zip_archive(outdir)
            _log(f"[📦] Compressed archive →  {os.path.basename(zip_path)}")
        except Exception as exc:
            _log(f"[!] Zip compression failed: {exc}")

        if obfuscate:
            try:
                obf_zip = create_obfuscated_scan_zip_archive(
                    outdir,
                    failed_hosts=failed_hosts,
                    results=obf_results if n >= 1 else None,
                )
                _log(f"[📦] Obfuscated archive (sanitized) →  {os.path.basename(obf_zip)}")
            except Exception as exc:
                _log(f"[!] Obfuscated zip compression failed: {exc}")

        try:
            update_latest_scan_aliases(scan_dir=outdir)
        except Exception as exc:
            logger.debug("Failed updating latest scan aliases: %s", exc)

    return fleet_path, summary_path, zip_path, report_paths


def _run_scan_worker(scan_id: str, ips: list, creds: dict, outdir: str,
                     threads: int, quick: bool, combined: bool,
                     obfuscate: bool, debug: bool,
                     dell_creds: Optional[dict],
                     save_json: bool = False,
                     include_raw: bool = False,
                     lean: bool = False,
                     host_timeout: int = 300,
                     allow_partial: bool = False,
                     is_retry: bool = False,
                     append_outdir: Optional[str] = None,
                     auto_retry: bool = True,
                     prior_results: Optional[list] = None,
                     prior_failed_hosts: Optional[list] = None,
                     force_threads: bool = False,
                     verify_ssl: bool = False,
                     ca_bundle: Optional[str] = None,
                     dns_lookup: bool = False,
                     pinned_thumbprints: Optional[dict] = None,
                     enable_dash: bool = False,
                     profile: Optional[str] = None,
                     two_pass: bool = False,
                     auto_throttle: bool = True,
                     export_sheets: bool = True,
                     crawl_endpoints: bool = False,
                     site: Optional[str] = None,
                     collector_id: Optional[str] = None,
                     execution: str = "local",
                     jump_host_id: Optional[str] = None) -> None:
    def _log_cb(event: str, msg: str):
        if msg.startswith("[→] Scan folder: "):
            eff_dir = msg.split("[→] Scan folder: ", 1)[-1].strip()
            with _state_lock:
                _state["outdir"] = eff_dir
        logger.info(msg)
        _get_dispatch("_broadcast", _broadcast)(event, {"scan_id": scan_id, "msg": msg})

    def _host_start_cb(info: dict):
        _get_dispatch("_handle_host_start", _handle_host_start)(scan_id, info)

    def _host_stage_cb(info: dict):
        _get_dispatch("_handle_host_stage", _handle_host_stage)(scan_id, info)

    def _host_done_cb(info: dict):
        _get_dispatch("_handle_host_done", _handle_host_done)(scan_id, info)

    def _progress_cb(completed: int, total: int):
        with _state_lock:
            safe_completed = min(completed, total) if total > 0 else completed
            _state["completed"] = safe_completed
            _state["total"] = total
            is_r = bool(_state.get("is_retry") or _state.get("is_rescan"))
        _get_dispatch("_broadcast", _broadcast)("progress", {
            "scan_id": scan_id,
            "completed": safe_completed,
            "total": total,
            "is_retry": is_r,
            "is_rescan": is_r,
            "phase": "rescan" if is_r else "scan",
            "msg": f"{'Rescanning' if is_r else 'Progress'}: {safe_completed}/{total}",
        })

    with _state_lock:
        _state["execution"] = execution or "local"
        if jump_host_id:
            _state["jump_host_id"] = jump_host_id

    try:
        if (execution or "local") == "remote":
            from vcf_hci.web.remote_scan import execute_remote_scan
            execute_remote_scan(
                scan_id=scan_id,
                ips=list(ips),
                creds=creds,
                outdir=outdir,
                threads=threads,
                profile=profile,
                jump_host_id=jump_host_id or "auto",
                host_timeout=host_timeout,
                debug=debug,
                log_callback=_log_cb,
                host_start_callback=_host_start_cb,
                host_stage_callback=_host_stage_cb,
                host_done_callback=_host_done_cb,
                progress_callback=_progress_cb,
                cancel_event=_cancel_event,
            )
            return
        with _state_lock:
            _state["is_retry"] = is_retry
            _state["is_rescan"] = is_retry
            _state["had_auto_retry"] = False
            custom_hcl_path = _state.get("custom_hcl_bundle_path")
            custom_hcl_metadata = _state.get("hcl_bundle_metadata")
            skipped_ips = _state["skipped_ips"]

        target_outdir = append_outdir if (is_retry and append_outdir) else outdir
        create_subfolder = not (is_retry and bool(append_outdir))

        if isinstance(creds, dict):
            blank_pwd_hosts = [
                ip for ip, val in creds.items()
                if isinstance(val, (tuple, list)) and len(val) >= 2 and not (val[1] or "").strip()
            ]
            if blank_pwd_hosts:
                sample_str = ", ".join(blank_pwd_hosts[:3])
                _log_cb(
                    "log",
                    f"  [!] WARNING: No password provided for {len(blank_pwd_hosts)} target(s) "
                    f"(e.g. {sample_str}) — authentication will likely fail with 401 Unauthorized.",
                )

        scan_fn = _get_dispatch("scan_hosts", scan_hosts)
        scan_res = scan_fn(
            target_ips=ips,
            creds=creds,
            outdir=target_outdir,
            threads=threads,
            quick=quick,
            lean=lean,
            profile=profile,
            obfuscate=obfuscate,
            debug=debug,
            save_json=save_json,
            include_raw=include_raw,
            combined=combined,
            dell_creds=dell_creds,
            hcl_bundle_path=custom_hcl_path,
            create_subfolder=create_subfolder,
            create_zip=False,
            cancel_event=_cancel_event,
            log_callback=_log_cb,
            host_start_callback=_host_start_cb,
            host_stage_callback=_host_stage_cb,
            host_done_callback=_host_done_cb,
            progress_callback=_progress_cb,
            skip_host_set=skipped_ips,
            host_timeout=host_timeout,
            allow_partial=allow_partial,
            prior_results=prior_results if is_retry else None,
            force_threads=force_threads,
            verify_ssl=verify_ssl,
            ca_bundle=ca_bundle,
            dns_lookup=dns_lookup,
            pinned_thumbprints=pinned_thumbprints,
            enable_dash=enable_dash,
            two_pass=two_pass,
            auto_throttle=auto_throttle,
            export_sheets=export_sheets,
            crawl_endpoints=crawl_endpoints,
            generate_fleet_artifacts=False,
        )

        pass1_results = scan_res.get("results", [])
        pass1_failed = scan_res.get("failed_hosts", [])
        cancelled = scan_res.get("cancelled", False)
        effective_outdir = scan_res.get("outdir", target_outdir)
        scan_summary = scan_res.get("scan_summary", "")

        if cancelled or _cancel_event.is_set():
            with _state_lock:
                _state["running"] = False
                _state["done"] = True
                _state["error"] = "Cancelled by user"
                _state["completed"] = len(ips)
                _state["total"] = len(ips)
                _state["n_ok"] = len(pass1_results)
                _state["is_retry"] = is_retry
                _state["is_rescan"] = is_retry
                _state["had_auto_retry"] = False
                _state["active_hosts"] = {}
                _state["outdir"] = effective_outdir
                _state["scan_summary"] = scan_summary
                _state["vcf_readiness"] = {"supported": 0, "deprecated": 0, "unsupported": 0}
                _state["failed_hosts"] = pass1_failed
                _state["partial_hosts"] = []
            _get_dispatch("_broadcast", _broadcast)("done", {
                "scan_id": scan_id,
                "n_ok": len(pass1_results),
                "n_total": len(ips),
                "is_retry": is_retry,
                "is_rescan": is_retry,
                "had_auto_retry": False,
                "fleet_report": "",
                "summary_report": "",
                "scan_summary": scan_summary,
                "vcf_readiness": {"supported": 0, "deprecated": 0, "unsupported": 0},
                "outdir": effective_outdir,
                "zip_path": "",
                "failed_hosts": pass1_failed,
                "partial_hosts": [],
            })
            return

        had_auto_retry = False
        current_results_map = {}
        for r in pass1_results:
            r_ip = ((r.get("system") or {}).get("ip") or r.get("host") or "").strip()
            if r_ip:
                current_results_map[r_ip] = r

        current_failed_map = {(f.get("ip") if isinstance(f, dict) else str(f)): f for f in pass1_failed}

        MAX_AUTO_RETRY_PASSES = 3

        # Multi-pass Auto-Retry (up to 3 passes) for partial scans and slow BMC timeouts
        if auto_retry and not is_retry and not _cancel_event.is_set():
            retry_pass = 1
            while retry_pass <= (MAX_AUTO_RETRY_PASSES - 1) and not _cancel_event.is_set():
                auto_retry_ips = []
                seen_ar_ips = set()

                # Prioritize hosts that have partial scan data needing targeted differential rescan
                for r in current_results_map.values():
                    if r.get("partial_scan"):
                        r_ip = ((r.get("system") or {}).get("ip") or r.get("host") or "").strip()
                        if r_ip and r_ip not in seen_ar_ips:
                            seen_ar_ips.add(r_ip)
                            auto_retry_ips.append(r_ip)

                # Include failed hosts: on pass 1 retry timeouts and unreachable hosts; on subsequent passes only retry timeouts/responded hosts
                for f_ip, f in list(current_failed_map.items()):
                    if not f_ip or f_ip in current_results_map:
                        continue
                    rcode = (f.get("reason_code") if isinstance(f, dict) else "") or ""
                    if retry_pass == 1 or "timeout" in rcode or rcode in ("timeout_after_auth", "timeout_before_auth", "partial_scan"):
                        if f_ip not in seen_ar_ips:
                            seen_ar_ips.add(f_ip)
                            auto_retry_ips.append(f_ip)

                if not auto_retry_ips:
                    break

                had_auto_retry = True
                pass_label = f"Auto-Retry Pass {retry_pass} of {MAX_AUTO_RETRY_PASSES - 1}"
                retry_threads = 2 if len(auto_retry_ips) <= 4 else 4
                retry_timeout = max(600, host_timeout)
                _log_cb("log", f"\n[🔄] {pass_label}: Re-scanning {len(auto_retry_ips)} failed/incomplete host(s) with gentle profile ({retry_threads} threads, {retry_timeout}s timeout)...")

                with _state_lock:
                    _state["is_retry"] = True
                    _state["is_rescan"] = True
                    _state["had_auto_retry"] = True
                    _state["total"] = len(auto_retry_ips)
                    _state["completed"] = 0
                    for _ar_ip in auto_retry_ips:
                        _state.get("completed_hosts", set()).discard(_ar_ip)
                        _state.get("active_hosts", {}).pop(_ar_ip, None)

                _get_dispatch("_broadcast", _broadcast)("progress", {
                    "scan_id": scan_id,
                    "completed": 0,
                    "total": len(auto_retry_ips),
                    "is_retry": True,
                    "is_rescan": True,
                    "phase": "rescan",
                    "msg": f"{pass_label}: 0/{len(auto_retry_ips)}",
                })

                prev_partial_count = sum(1 for r in current_results_map.values() if r.get("partial_scan"))
                prev_remediated_count = sum(1 for r in current_results_map.values() if (r.get("remediation") or {}).get("status") == "fully_remediated")

                pass_res = scan_fn(
                    target_ips=auto_retry_ips,
                    creds=creds,
                    outdir=effective_outdir,
                    threads=retry_threads,
                    quick=quick,
                    lean=lean,
                    profile=profile,
                    obfuscate=obfuscate,
                    debug=debug,
                    save_json=save_json,
                    include_raw=include_raw,
                    combined=combined,
                    dell_creds=dell_creds,
                    hcl_bundle_path=custom_hcl_path,
                    create_subfolder=False,
                    create_zip=False,
                    cancel_event=_cancel_event,
                    log_callback=_log_cb,
                    host_start_callback=_host_start_cb,
                    host_stage_callback=_host_stage_cb,
                    host_done_callback=_host_done_cb,
                    progress_callback=_progress_cb,
                    skip_host_set=skipped_ips,
                    host_timeout=retry_timeout,
                    allow_partial=True,
                    prior_results=list(current_results_map.values()),
                    force_threads=force_threads,
                    verify_ssl=verify_ssl,
                    ca_bundle=ca_bundle,
                    dns_lookup=dns_lookup,
                    pinned_thumbprints=pinned_thumbprints,
                    enable_dash=enable_dash,
                    append_log=True,
                    generate_fleet_artifacts=False,
                )

                pass_results = pass_res.get("results", [])
                pass_failed = pass_res.get("failed_hosts", [])

                for r in pass_results:
                    r_ip = ((r.get("system") or {}).get("ip") or r.get("host") or "").strip()
                    if r_ip:
                        current_results_map[r_ip] = r
                        if not r.get("partial_scan"):
                            current_failed_map.pop(r_ip, None)

                for f in pass_failed:
                    f_ip = (f.get("ip") if isinstance(f, dict) else str(f))
                    if f_ip and f_ip not in current_results_map:
                        current_failed_map[f_ip] = f

                new_partial_count = sum(1 for r in current_results_map.values() if r.get("partial_scan"))
                new_remediated_count = sum(1 for r in current_results_map.values() if (r.get("remediation") or {}).get("status") == "fully_remediated")
                recovered_count = (prev_partial_count - new_partial_count) + (new_remediated_count - prev_remediated_count)

                if new_partial_count == 0:
                    _log_cb("log", f"[✓] {pass_label} complete — all responsive hosts are fully remediated!")
                    break
                elif recovered_count <= 0 and retry_pass > 1:
                    _log_cb("log", f"[ℹ️] {pass_label} complete — no additional sections recovered; concluding retries.")
                    break
                else:
                    _log_cb("log", f"[✓] {pass_label} complete ({new_remediated_count} fully remediated, {new_partial_count} partial remaining)")

                retry_pass += 1

            final_results = list(current_results_map.values())
            final_failed = list(current_failed_map.values())
        elif is_retry:
            prior_res = prior_results or []
            prior_fail = prior_failed_hosts or []

            merged_results_map = {}
            for r in prior_res:
                r_ip = ((r.get("system") or {}).get("ip") or r.get("host") or "").strip()
                if r_ip:
                    merged_results_map[r_ip] = r

            for r in pass1_results:
                r_ip = ((r.get("system") or {}).get("ip") or r.get("host") or "").strip()
                if r_ip:
                    merged_results_map[r_ip] = r

            final_results = list(merged_results_map.values())

            merged_failed_map = { (f.get("ip") if isinstance(f, dict) else str(f)): f for f in prior_fail }
            for f in pass1_failed:
                f_ip = (f.get("ip") if isinstance(f, dict) else str(f))
                if f_ip:
                    merged_failed_map[f_ip] = f

            for r in pass1_results:
                r_ip = ((r.get("system") or {}).get("ip") or r.get("host") or "").strip()
                if r_ip and not r.get("partial_scan"):
                    merged_failed_map.pop(r_ip, None)

            final_failed = list(merged_failed_map.values())
        else:
            final_results = pass1_results
            final_failed = pass1_failed

        # Regenerate consolidated reports across entire merged results
        regen_fn = _get_dispatch("_regenerate_fleet_artifacts", _regenerate_fleet_artifacts)
        fleet_path, summary_path, zip_path, report_paths = regen_fn(
            results=final_results,
            failed_hosts=final_failed,
            outdir=effective_outdir,
            combined=combined,
            obfuscate=obfuscate,
            debug=debug,
            save_json=save_json,
            custom_hcl_metadata=custom_hcl_metadata,
            log_callback=_log_cb,
            export_sheets=export_sheets,
            site=site,
            collector_id=collector_id,
            scan_profile=profile,
        )

        partial_hosts = []
        for r in final_results:
            if r.get("partial_scan"):
                ph_ip = ((r.get("system") or {}).get("ip") or r.get("host") or "").strip()
                ph_sec = r.get("partial_sections") or []
                ph_reason = r.get("partial_reason") or ""
                partial_hosts.append({
                    "ip": ph_ip,
                    "sections": ph_sec,
                    "reason": ph_reason,
                })

        vcf_sup = vcf_dep = vcf_unsup = vcf_inc = 0
        for r in final_results:
            v = ((r.get("system") or {}).get("cpu_summary") or {}).get("verdict", "") or ""
            partial = bool(r.get("partial_scan"))
            if "Unsupported" in v:
                vcf_unsup += 1
            elif partial or not v or v == "Unknown" or "Unverified" in v:
                vcf_inc += 1
            elif "Deprecated" in v:
                vcf_dep += 1
            else:
                vcf_sup += 1
        vcf_readiness = {
            "supported": vcf_sup,
            "deprecated": vcf_dep,
            "unsupported": vcf_unsup,
            "incomplete": vcf_inc,
        }
        n = len(final_results)
        tot_hosts = n + len(final_failed)
        n_remediated = sum(1 for r in final_results if (r.get("remediation") or {}).get("status") == "fully_remediated")
        _log_cb("log", f"\n[✓] Finished scan — Assessment complete ({n}/{tot_hosts} hosts succeeded)")
        if scan_summary:
            _log_cb("log", f"[⏱️] {scan_summary}")
        _log_cb("log", f"[📊] VCF Readiness: {vcf_sup} Supported, {vcf_dep} Deprecated, {vcf_unsup} Unsupported, {vcf_inc} Incomplete")
        if n_remediated > 0:
            _log_cb("log", f"[🔄] Remediated via Rescan: {n_remediated} host(s)")
        if final_failed:
            _log_cb("log", f"[⚠️] Failed/Incomplete hosts: {len(final_failed)}")
        _log_cb("log", f"[📁] Output folder: {effective_outdir}")
        if zip_path:
            _log_cb("log", f"[📦] Compressed archive: {zip_path}")

        with _state_lock:
            _state["running"]      = False
            _state["done"]         = True
            _state["completed"]    = tot_hosts
            _state["total"]        = tot_hosts
            _state["n_ok"]         = n
            _state["is_retry"]     = is_retry
            _state["is_rescan"]    = is_retry or had_auto_retry
            _state["had_auto_retry"] = had_auto_retry
            _state["active_hosts"] = {}
            _state["fleet_path"]   = fleet_path
            _state["summary_path"] = summary_path
            _state["results"]      = final_results
            _state["report_paths"] = report_paths
            _state["outdir"]       = effective_outdir
            _state["zip_path"]     = zip_path
            _state["scan_summary"] = scan_summary
            _state["vcf_readiness"] = vcf_readiness
            _state["failed_hosts"] = final_failed
            _state["partial_hosts"] = partial_hosts
            _state["n_remediated"] = n_remediated

        obf_sum = os.path.join(effective_outdir, "00_OBFUSCATED_fleet_summary.html")
        obf_fleet = os.path.join(effective_outdir, "00_OBFUSCATED_fleet_combined.html")
        _get_dispatch("_broadcast", _broadcast)("done", {
            "scan_id": scan_id,
            "n_ok": n,
            "n_total": tot_hosts,
            "is_retry": is_retry,
            "is_rescan": is_retry or had_auto_retry,
            "had_auto_retry": had_auto_retry,
            "n_remediated": n_remediated,
            "fleet_report": os.path.basename(fleet_path) if fleet_path else "",
            "summary_report": os.path.basename(summary_path) if summary_path else "",
            "obf_summary_report": "00_OBFUSCATED_fleet_summary.html" if os.path.isfile(obf_sum) else "",
            "obf_fleet_report": "00_OBFUSCATED_fleet_combined.html" if os.path.isfile(obf_fleet) else "",
            "scan_summary": scan_summary,
            "vcf_readiness": vcf_readiness,
            "outdir": effective_outdir,
            "zip_path": zip_path,
            "failed_hosts": final_failed,
            "partial_hosts": partial_hosts,
            "msg": f"[✓] Done — {n}/{tot_hosts} hosts",
        })

    except Exception as exc:
        logger.exception("Scan worker error")
        with _state_lock:
            _state["running"] = False
            _state["done"]    = True
            _state["active_hosts"] = {}
            _state["error"]   = str(exc)
        _get_dispatch("_broadcast", _broadcast)("error", {"scan_id": scan_id, "msg": f"[✗] Fatal: {exc}"})
