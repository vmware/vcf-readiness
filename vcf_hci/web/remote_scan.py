"""Bridge a web scan onto the jump-host orchestrator.

Does not import scan_worker at module import time (scan_worker imports this
module from inside the worker thread).
"""

import csv
import logging
import os
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("vcf_assess")

__all__ = ["execute_remote_scan", "load_fleet_summary", "resume_remote_scan_job"]


def load_fleet_summary(directory: str) -> List[dict]:
    from vcf_hci.summary_io import load_summary

    if not directory or not os.path.isdir(directory):
        return []

    # If this is a fanout parent with from-* dirs, aggregate from each run
    try:
        subdirs = [
            os.path.join(directory, entry)
            for entry in sorted(os.listdir(directory))
            if os.path.isdir(os.path.join(directory, entry)) and not entry.startswith(".")
        ]

        from_dirs = [d for d in subdirs if os.path.basename(d).startswith("from-")]
        if from_dirs:
            all_results: List[dict] = []
            seen_ips = set()
            for fdir in from_dirs:
                sub_items = load_fleet_summary(fdir)
                for item in sub_items:
                    ip = ((item.get("system") or {}).get("ip") or item.get("host") or "")
                    if ip and ip in seen_ips:
                        continue
                    if ip:
                        seen_ips.add(ip)
                    all_results.append(item)
            if all_results:
                return all_results

        # Try loading summary directly via centralized load_summary (supports v2 manifests with gzip/parts, json.gz, etc.)
        loaded = load_summary(directory)
        if loaded:
            return loaded

        # Otherwise sort scan dirs newest first
        subdirs.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
        for sub in subdirs:
            sub_items = load_fleet_summary(sub)
            if sub_items:
                return sub_items
    except OSError:
        pass

    return []


def _find(directory: str, name: str) -> str:
    path = os.path.join(directory, name)
    if os.path.isfile(path):
        return path
    try:
        subdirs = [
            os.path.join(directory, e)
            for e in os.listdir(directory)
            if os.path.isdir(os.path.join(directory, e)) and not e.startswith(".")
        ]
        subdirs.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
        for sub in subdirs:
            cand = os.path.join(sub, name)
            if os.path.isfile(cand):
                return cand
            for sub_entry in os.listdir(sub):
                sub_cand = os.path.join(sub, sub_entry, name)
                if os.path.isfile(sub_cand):
                    return sub_cand
    except OSError:
        pass
    return ""


def _relay(event: Dict[str, Any], log_callback, host_start_callback, host_stage_callback,
           host_done_callback, progress_callback) -> None:
    try:
        kind = event.get("event")
        if kind == "log" and log_callback is not None:
            try:
                log_callback(str(event.get("channel") or "log"), str(event.get("msg") or ""))
            except Exception as cb_exc:
                logger.debug("Error in log_callback relay: %s", cb_exc)
        elif kind == "host_start" and host_start_callback is not None:
            try:
                host_start_callback(event)
            except Exception as cb_exc:
                logger.debug("Error in host_start_callback relay: %s", cb_exc)
        elif kind == "host_stage" and host_stage_callback is not None:
            try:
                host_stage_callback(event)
            except Exception as cb_exc:
                logger.debug("Error in host_stage_callback relay: %s", cb_exc)
        elif kind == "host_done" and host_done_callback is not None:
            try:
                host_done_callback(event)
            except Exception as cb_exc:
                logger.debug("Error in host_done_callback relay: %s", cb_exc)
        elif kind == "remote_sandbox":
            from vcf_hci.web import scan_worker
            with scan_worker._state_lock:
                scans = scan_worker._state.setdefault("active_remote_scans", [])
                scans.append({
                    "jump_host_id": event.get("jump_host"),
                    "host": event.get("host"),
                    "remote_dir": event.get("remote_dir"),
                    "run_id": event.get("run_id"),
                })
        elif kind == "progress" and progress_callback is not None:
            try:
                progress_callback(int(event.get("completed") or 0), int(event.get("total") or 0))
            except Exception as cb_exc:
                logger.debug("Error in progress_callback relay: %s", cb_exc)
    except Exception as exc:
        logger.debug("Error in _relay: %s", exc)


def _load_failed_hosts(directory: str) -> List[dict]:
    path = _find(directory, "00_failed_hosts.csv")
    if path and os.path.isfile(path) and os.path.getsize(path) > 0:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                reader = csv.DictReader(fh)
                failures = []
                for row in reader:
                    failures.append({
                        "ip": row.get("BMC IP") or row.get("ip") or "",
                        "hostname": row.get("Hostname") or row.get("hostname") or "Unknown",
                        "reason_label": row.get("Failure Reason") or row.get("reason_label") or "Failed",
                        "stage": row.get("Stage") or row.get("stage") or "",
                        "detail": row.get("Details") or row.get("detail") or "",
                        "error": True,
                    })
                return failures
        except Exception:
            pass
    return []


def _process_scan_results(effective: str) -> Tuple[List[dict], Dict[str, int], List[dict], List[dict], str]:
    summary = load_fleet_summary(effective)
    vcf_sup = vcf_dep = vcf_unsup = 0
    partial_hosts = []
    for r in summary:
        v = ((r.get("system") or {}).get("cpu_summary") or {}).get("verdict", "")
        if "Unsupported" in v:
            vcf_unsup += 1
        elif "Deprecated" in v:
            vcf_dep += 1
        else:
            vcf_sup += 1
        if r.get("partial_scan"):
            ph_ip = ((r.get("system") or {}).get("ip") or r.get("host") or "").strip()
            ph_sec = r.get("partial_sections") or []
            ph_reason = r.get("partial_reason") or ""
            partial_hosts.append({
                "ip": ph_ip,
                "sections": ph_sec,
                "reason": ph_reason,
            })
    vcf_readiness = {
        "supported": vcf_sup,
        "deprecated": vcf_dep,
        "unsupported": vcf_unsup,
    }
    failed_hosts = _load_failed_hosts(effective)
    zip_path = ""
    try:
        candidates = [
            os.path.join(effective, e)
            for e in os.listdir(effective)
            if e.endswith(".zip") and os.path.isfile(os.path.join(effective, e))
        ]
        if candidates:
            candidates.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
            zip_path = candidates[0]
    except OSError:
        pass
    return summary, vcf_readiness, failed_hosts, partial_hosts, zip_path


def _finish(
    scan_id: str,
    outdir: str,
    n_ok: int,
    n_total: int,
    error: Optional[str],
    vcf_readiness: Optional[Dict[str, int]] = None,
    results: Optional[List[dict]] = None,
    failed_hosts: Optional[List[dict]] = None,
    partial_hosts: Optional[List[dict]] = None,
    zip_path: str = "",
) -> None:
    from vcf_hci.web import scan_worker
    fleet_path = _find(outdir, "00_fleet_combined.html")
    summary_path = _find(outdir, "00_fleet_summary.html")
    obf_sum = _find(outdir, "00_OBFUSCATED_fleet_summary.html")
    obf_fleet = _find(outdir, "00_OBFUSCATED_fleet_combined.html")
    reports_dir = os.path.join(outdir, "reports")
    report_paths: List[str] = []
    if os.path.isdir(reports_dir):
        report_paths = [
            os.path.join(reports_dir, f)
            for f in sorted(os.listdir(reports_dir))
            if f.endswith(".html") and os.path.isfile(os.path.join(reports_dir, f))
        ]
    with scan_worker._state_lock:
        scan_worker._state["running"] = False
        scan_worker._state["done"] = True
        scan_worker._state["active_hosts"] = {}
        scan_worker._state["active_remote_scans"] = []
        scan_worker._state["outdir"] = outdir
        scan_worker._state["error"] = error
        scan_worker._state["n_ok"] = n_ok
        scan_worker._state["completed"] = n_total
        scan_worker._state["total"] = n_total
        scan_worker._state["fleet_path"] = fleet_path
        scan_worker._state["summary_path"] = summary_path
        scan_worker._state["obf_fleet_path"] = obf_fleet
        scan_worker._state["obf_summary_path"] = obf_sum
        scan_worker._state["zip_path"] = zip_path
        scan_worker._state["report_paths"] = report_paths
        if results is not None:
            scan_worker._state["results"] = results
        if vcf_readiness is not None:
            scan_worker._state["vcf_readiness"] = vcf_readiness
        if failed_hosts is not None:
            scan_worker._state["failed_hosts"] = failed_hosts
        if partial_hosts is not None:
            scan_worker._state["partial_hosts"] = partial_hosts

    if error:
        scan_worker._broadcast("error", {"scan_id": scan_id, "msg": "[✗] %s" % error})
        return

    readiness = vcf_readiness or {"supported": 0, "deprecated": 0, "unsupported": 0}
    scan_worker._broadcast("done", {
        "scan_id": scan_id,
        "n_ok": n_ok,
        "n_total": n_total,
        "fleet_report": os.path.basename(fleet_path) if fleet_path else "",
        "summary_report": os.path.basename(summary_path) if summary_path else "",
        "obf_summary_report": os.path.basename(obf_sum) if obf_sum else "",
        "obf_fleet_report": os.path.basename(obf_fleet) if obf_fleet else "",
        "outdir": outdir,
        "zip_path": zip_path,
        "vcf_readiness": readiness,
        "failed_hosts": failed_hosts or [],
        "partial_hosts": partial_hosts or [],
        "results": results or [],
        "msg": "[ok] Remote scan finished — %s/%s hosts" % (n_ok, n_total),
    })


def execute_remote_scan(
    scan_id: str,
    ips: List[str],
    creds: Any,
    outdir: str,
    threads: int = 8,
    profile: Optional[str] = None,
    jump_host_id: str = "auto",
    host_timeout: int = 300,
    debug: bool = False,
    log_callback: Optional[Callable] = None,
    host_start_callback: Optional[Callable] = None,
    host_stage_callback: Optional[Callable] = None,
    host_done_callback: Optional[Callable] = None,
    progress_callback: Optional[Callable] = None,
    cancel_event: Optional[Any] = None,
) -> Dict[str, Any]:
    """Build a zipapp, fan out over jump hosts, and mark the web scan finished."""
    from vcf_hci.remote.orchestrator import run_fanout
    from vcf_hci.web import vault_session
    from vcf_hci.zipapp_builder import build_collector_pyz

    vault = vault_session.get()
    if vault is None:
        _finish(scan_id, outdir, 0, len(ips), "Vault is locked. Unlock it before a remote scan.")
        raise RuntimeError("Vault is locked")
    jumps = vault.jump_host_map()
    if not jumps:
        message = "No jump hosts are stored in the vault."
        _finish(scan_id, outdir, 0, len(ips), message)
        raise RuntimeError(message)

    pyz_path = ""
    scan_start_time = time.time()
    try:
        handle = tempfile.NamedTemporaryFile(prefix="vcfr_worker_", suffix=".pyz", delete=False)
        pyz_path = handle.name
        handle.close()
        build_collector_pyz(pyz_path)
        with open(pyz_path, "rb") as fh:
            pyz_bytes = fh.read()

        def _progress(event: Dict[str, Any]) -> None:
            _relay(
                event, log_callback, host_start_callback, host_stage_callback,
                host_done_callback, progress_callback,
            )

        def _on_sandbox(info: Dict[str, Any]) -> None:
            from vcf_hci.web import scan_worker
            with scan_worker._state_lock:
                scans = scan_worker._state.setdefault("active_remote_scans", [])
                scans.append({
                    "jump_host_id": info.get("jump_host"),
                    "host": info.get("host"),
                    "remote_dir": info.get("remote_dir"),
                    "run_id": info.get("run_id"),
                })

        result = run_fanout(
            jump_hosts=jumps,
            targets=list(ips),
            creds=creds,
            local_outdir=outdir,
            pyz_bytes=pyz_bytes,
            selected_id=jump_host_id or "auto",
            threads=threads,
            profile=profile or "readiness-full",
            host_timeout=host_timeout,
            debug=debug,
            on_progress=_progress,
            cancel_event=cancel_event,
            on_sandbox=_on_sandbox,
        )
    except Exception as exc:
        logger.exception("Remote scan failed")
        from vcf_hci.remote.executor import JumpHostConnectionLostError
        is_conn_lost = False
        conn_host = ""
        if isinstance(exc, JumpHostConnectionLostError):
            is_conn_lost = True
            conn_host = getattr(exc, "host", "") or ""
        elif "connection to jump host" in str(exc).lower() or "broken pipe" in str(exc).lower() or "network is unreachable" in str(exc).lower():
            is_conn_lost = True

        if not conn_host:
            if jump_host_id and jump_host_id != "auto" and jumps.get(jump_host_id):
                conn_host = str(jumps[jump_host_id].get("host") or jump_host_id)
            else:
                conn_host = "remote"

        if is_conn_lost:
            from vcf_hci.web import scan_worker
            rem_dir = getattr(exc, "remote_dir", None)
            r_id = getattr(exc, "run_id", None)
            disconn_info = {
                "scan_id": scan_id,
                "jump_host_id": jump_host_id,
                "host": conn_host,
                "remote_dir": rem_dir,
                "run_id": r_id,
                "outdir": outdir,
                "ips": list(ips),
                "profile": profile,
                "threads": threads,
            }
            with scan_worker._state_lock:
                scan_worker._state["disconnected_jump_scan"] = disconn_info
            scan_worker._broadcast("jump_disconnected", disconn_info)
            if log_callback is not None:
                log_callback("log", f"[✗] Connection to jump host '{conn_host}' was lost (VPN or network link dropped).")
                log_callback("log", f"[ℹ] Check your VPN connection to '{conn_host}'. Once reconnected, click 'Reconnect & Pull Results' to retrieve your scan.")
            error_msg = f"Connection to jump host '{conn_host}' was lost (VPN or network link dropped)."
        else:
            if log_callback is not None:
                log_callback("log", f"[✗] Remote scan failed: {exc}")
            error_msg = str(exc)
        _finish(scan_id, outdir, 0, len(ips), error_msg)
        raise
    finally:
        if pyz_path:
            try:
                os.remove(pyz_path)
            except OSError:
                pass

    runs = result.get("runs") or []
    effective = outdir
    if len(runs) == 1:
        effective = runs[0].get("local_outdir") or outdir

    # If effective is a container directory containing child Scan_* folder(s),
    # resolve effective to the newest scan folder so outdir, fleet_path, and
    # summary_path match local scan behavior
    try:
        scan_folders = [
            os.path.join(effective, e)
            for e in os.listdir(effective)
            if e.startswith("Scan_") and os.path.isdir(os.path.join(effective, e))
            and (os.path.getmtime(os.path.join(effective, e)) >= scan_start_time - 120.0)
        ]
        if scan_folders:
            scan_folders.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
            effective = scan_folders[0]
    except OSError:
        pass

    summary, vcf_readiness, failed_hosts, partial_hosts, zip_path = _process_scan_results(effective)
    n_ok = len(summary) if summary else 0
    if log_callback is not None:
        log_callback("log", f"\n[✓] Finished scan — Assessment complete ({n_ok}/{len(ips)} hosts succeeded)")
        log_callback(
            "log",
            f"[📊] VCF Readiness: {vcf_readiness['supported']} Supported, "
            f"{vcf_readiness['deprecated']} Deprecated, {vcf_readiness['unsupported']} Unsupported",
        )
        if failed_hosts:
            log_callback("log", f"[⚠️] Failed/Incomplete hosts: {len(failed_hosts)}")
        log_callback("log", f"[📁] Output folder: {effective}")
        if zip_path:
            log_callback("log", f"[📦] Compressed archive: {zip_path}")
    _finish(
        scan_id,
        effective,
        n_ok,
        len(ips),
        None,
        vcf_readiness=vcf_readiness,
        results=summary,
        failed_hosts=failed_hosts,
        partial_hosts=partial_hosts,
        zip_path=zip_path,
    )
    result["local_outdir"] = effective
    result["n_ok"] = n_ok

    try:
        from vcf_hci.logging_utils import update_latest_scan_aliases
        if os.path.basename(effective).startswith("Scan_"):
            update_latest_scan_aliases(scan_dir=effective)
    except Exception as exc:
        logger.debug("Failed updating latest scan aliases after remote scan: %s", exc)

    return result


def resume_remote_scan_job(
    info: Dict[str, Any],
    log_callback: Optional[Callable] = None,
    host_start_callback: Optional[Callable] = None,
    host_stage_callback: Optional[Callable] = None,
    host_done_callback: Optional[Callable] = None,
    progress_callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """Resume a disconnected remote scan from stored state."""
    from vcf_hci.remote.executor import JumpHostConnectionLostError, resume_remote_scan
    from vcf_hci.web import scan_worker, vault_session

    scan_id = str(info.get("scan_id") or "")
    jump_host_id = str(info.get("jump_host_id") or "")
    remote_dir = str(info.get("remote_dir") or "")
    outdir = str(info.get("outdir") or "").strip()
    if not outdir:
        from vcf_hci.logging_utils import get_default_output_dir
        outdir = get_default_output_dir()
    ips = list(info.get("ips") or [])
    conn_host = str(info.get("host") or "")

    with scan_worker._state_lock:
        scan_worker._state["running"] = True
        scan_worker._state["done"] = False
        scan_worker._state["error"] = None
        scan_worker._state["execution"] = "remote"
        if jump_host_id:
            scan_worker._state["jump_host_id"] = jump_host_id

    vault = vault_session.get()
    if vault is None:
        err = "Vault is locked. Unlock it in the Credential Vault panel first."
        if log_callback is not None:
            log_callback("log", f"[✗] {err}")
        _finish(scan_id, outdir, 0, len(ips), err)
        raise RuntimeError(err)

    jump_profile = vault.get_jump_host(jump_host_id) if jump_host_id and jump_host_id != "auto" else None
    if not jump_profile:
        jumps = vault.jump_host_map()
        if jump_host_id in jumps:
            jump_profile = jumps[jump_host_id]
        elif jumps:
            jump_profile = next((p for p in jumps.values() if p.get("is_default")), next(iter(jumps.values()), None))

    if not jump_profile:
        err = f"Jump host profile '{jump_host_id}' not found in vault."
        if log_callback is not None:
            log_callback("log", f"[✗] {err}")
        _finish(scan_id, outdir, 0, len(ips), err)
        raise RuntimeError(err)

    if not remote_dir:
        err = "No remote sandbox directory recorded for this scan."
        if log_callback is not None:
            log_callback("log", f"[✗] {err}")
        _finish(scan_id, outdir, 0, len(ips), err)
        raise RuntimeError(err)

    if log_callback is not None:
        log_callback("log", f"[🔄] Attempting to reconnect to jump host '{conn_host or jump_profile.get('host')}'...")

    def _progress(event: Dict[str, Any]) -> None:
        _relay(
            event, log_callback, host_start_callback, host_stage_callback,
            host_done_callback, progress_callback,
        )

    resume_start_time = time.time()
    try:
        res = resume_remote_scan(
            jump=jump_profile,
            remote_dir=remote_dir,
            local_outdir=outdir,
            run_id=info.get("run_id"),
            on_progress=_progress,
        )
        with scan_worker._state_lock:
            scan_worker._state["disconnected_jump_scan"] = None

        effective = outdir
        try:
            scan_folders = [
                os.path.join(effective, e)
                for e in os.listdir(effective)
                if e.startswith("Scan_") and os.path.isdir(os.path.join(effective, e))
                and (os.path.getmtime(os.path.join(effective, e)) >= resume_start_time - 120.0)
            ]
            if scan_folders:
                scan_folders.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
                effective = scan_folders[0]
        except OSError:
            pass

        summary, vcf_readiness, failed_hosts, partial_hosts, zip_path = _process_scan_results(effective)
        n_ok = len(summary) if summary else 0
        if log_callback is not None:
            log_callback("log", f"[✓] Reconnected successfully. Retrieved assessment results for {n_ok}/{len(ips)} hosts.")
            log_callback(
                "log",
                f"[📊] VCF Readiness: {vcf_readiness['supported']} Supported, "
                f"{vcf_readiness['deprecated']} Deprecated, {vcf_readiness['unsupported']} Unsupported",
            )
            if failed_hosts:
                log_callback("log", f"[⚠️] Failed/Incomplete hosts: {len(failed_hosts)}")
            log_callback("log", f"[📁] Output folder: {effective}")
            if zip_path:
                log_callback("log", f"[📦] Compressed archive: {zip_path}")
        _finish(
            scan_id,
            effective,
            n_ok,
            len(ips),
            None,
            vcf_readiness=vcf_readiness,
            results=summary,
            failed_hosts=failed_hosts,
            partial_hosts=partial_hosts,
            zip_path=zip_path,
        )
        try:
            from vcf_hci.logging_utils import update_latest_scan_aliases
            if os.path.basename(effective).startswith("Scan_"):
                update_latest_scan_aliases(scan_dir=effective)
        except Exception:
            pass
        return res
    except Exception as exc:
        logger.exception("Reconnect to remote jump host failed")
        is_conn_lost = isinstance(exc, JumpHostConnectionLostError) or "connection to jump host" in str(exc).lower() or "broken pipe" in str(exc).lower()
        if is_conn_lost:
            msg = f"[✗] Could not reconnect to jump host '{conn_host or jump_profile.get('host')}' (VPN still down or host unreachable). Please restore VPN and try again."
        else:
            msg = f"[✗] Reconnect failed: {exc}"
        if log_callback is not None:
            log_callback("log", msg)
        _finish(scan_id, outdir, 0, len(ips), str(exc))
        raise
