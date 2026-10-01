"""
VCF Readiness Tool — Scan Web API Mixin (vcf_hci.web.scan_api)

Defines ScanApiMixin for scan triggering, cancellation, skipping, and SSE streaming.
"""

import json
import logging
import os
import queue
import threading
import time
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
        def _vault_guard(self) -> bool: ...
else:
    _ApiMixinBase = object

from vcf_hci import (
    normalize_output_dir,
    parse_ip_targets,
)
from vcf_hci.summary_io import load_summary
from vcf_hci.web import vault_session
from vcf_hci.web.scan_worker import (
    _broadcast,
    _cancel_event,
    _get_dispatch,
    _run_scan_worker,
    _shutdown_event,
    _sse_clients,
    _state,
    _state_lock,
)

logger = logging.getLogger("vcf_assess")

_COLLECTOR_OK = True


class ScanApiMixin(_ApiMixinBase):
    """Scan and SSE streaming endpoints mixed into AppHandler."""

    # ── SSE endpoint ──────────────────────────────────────────────────────────

    def _sse_scan_events(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        # Replay recent log lines and capture current active hosts under lock
        with _state_lock:
            replay = [line for line in _state.get("log_lines", []) if line]
            running = _state.get("running", False)
            done = _state.get("done", False)
            completed = _state.get("completed", 0)
            total = _state.get("total", 0)
            active_copy = {}
            for _ip, _info in _state.get("active_hosts", {}).items():
                if isinstance(_info, dict):
                    active_copy[_ip] = dict(_info)
                else:
                    active_copy[_ip] = {"start_time": _info, "stage": "Scanning..."}

        for line in replay[-40:]:
            try:
                self.wfile.write(
                    f"event: log\ndata: {json.dumps({'msg': line})}\n\n".encode())
            except Exception:
                return

        # Send current status immediately
        try:
            is_rescan_flag = bool(_state.get("is_retry", False) or _state.get("is_rescan", False))
            is_import_flag = bool(_state.get("is_import", False))
            is_remote_flag = bool((_state.get("execution") == "remote") or _state.get("active_remote_scans"))
            disconn = _state.get("disconnected_jump_scan")
            self.wfile.write(
                f"event: status\ndata: {json.dumps({'running': running, 'done': done, 'completed': completed, 'total': total, 'execution': _state.get('execution', 'local'), 'is_remote': is_remote_flag, 'is_retry': _state.get('is_retry', False), 'is_rescan': is_rescan_flag, 'is_import': is_import_flag, 'had_auto_retry': _state.get('had_auto_retry', False), 'active_hosts': active_copy, 'disconnected_jump_scan': disconn})}\n\n".encode()
            )
            self.wfile.flush()
        except Exception:
            return

        q: queue.Queue = queue.Queue(maxsize=256)
        with _state_lock:
            _sse_clients.append(q)

        try:
            while not _shutdown_event.is_set():
                try:
                    msg = q.get(timeout=15)
                    self.wfile.write(msg.encode())
                    self.wfile.flush()
                except queue.Empty:
                    # Keepalive comment
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except Exception:
            pass
        finally:
            with _state_lock:
                try:
                    _sse_clients.remove(q)
                except ValueError:
                    pass

    # ── /api/scan ─────────────────────────────────────────────────────────────

    def _api_scan(self) -> None:
        if not _COLLECTOR_OK:
            self._send_json({"error": "Collector not available"}, 503)
            return

        body = self._read_json_body()
        raw_targets = body.get("targets", "").strip()
        if not raw_targets:
            self._send_json({"error": "targets required"}, 400)
            return

        restrict_private = bool(body.get("restrict_private_targets", False))
        try:
            ips = parse_ip_targets(raw_targets, restrict_private=restrict_private)
        except Exception as exc:
            self._send_json({"error": str(exc)}, 400)
            return

        if not ips:
            self._send_json({"error": "No valid IPs in range"}, 400)
            return

        try:
            threads = int(body.get("threads", 12))
        except (ValueError, TypeError):
            threads = 12
        threads = min(32, max(1, threads))

        raw_outdir = body.get("output_dir", "").strip()
        outdir = normalize_output_dir(raw_outdir)

        try:
            os.makedirs(outdir, exist_ok=True)
        except Exception as exc:
            self._send_json({"error": f"Cannot create output directory '{outdir}': {exc}"}, 400)
            return

        creds_list = body.get("creds", [])
        shared_user = body.get("username", "root") or "root"
        shared_pass = body.get("password", "")
        creds: dict = {}
        use_vault = bool(body.get("use_vault", False))   # OPT-IN; default False keeps legacy behaviour
        if use_vault:
            if self._is_remote_server():
                self._send_json({"error": "The credential vault is disabled when --allow-remote is enabled."}, 403)
                return
            vault = vault_session.get()
            if vault is None:
                self._send_json({"error": "Vault is locked. Unlock it in the Credential Vault panel first.", "locked": True}, 423)
                return
            creds = vault.resolve_for_targets(ips)
            if shared_pass:
                creds.setdefault("default", (shared_user, shared_pass))
            missing = [ip for ip in ips if ip not in creds and "default" not in creds]
            if missing:
                logger.info("Vault scan: %d target(s) without credentials will be skipped", len(missing))
        elif creds_list:
            for row in creds_list:
                ip = row.get("ip")
                if not ip:
                    continue
                cur_user, cur_pass = creds.get(ip, (shared_user, shared_pass))
                u = row.get("user", cur_user) if "user" in row else cur_user
                p = row.get("pass", cur_pass) if "pass" in row else cur_pass
                creds[ip] = (u, p)
            for ip in ips:
                if ip not in creds:
                    creds[ip] = (shared_user, shared_pass)
        else:
            creds = dict.fromkeys(ips, (shared_user, shared_pass))

        if not use_vault:
            blank_pwd_hosts = [ip for ip, (_, pw) in creds.items() if not (pw or "").strip()]
            if blank_pwd_hosts:
                logger.warning(
                    "Scan started with NO password for %d target(s) (e.g. %s) — BMC requests will likely fail with 401 Unauthorized.",
                    len(blank_pwd_hosts),
                    ", ".join(blank_pwd_hosts[:5]),
                )

        execution = str(body.get("execution") or "local").strip().lower()
        jump_host_id = str(body.get("jump_host") or "auto").strip() or "auto"
        if execution not in ("local", "remote"):
            self._send_json({"error": "execution must be local or remote"}, 400)
            return
        if execution == "remote" and self._is_remote_server():
            self._send_json({"error": "Remote jump execution is disabled when --allow-remote is enabled."}, 403)
            return
        if execution == "remote":
            vault = vault_session.get()
            if vault is None:
                self._send_json(
                    {"error": "Vault is locked. Unlock it in the Credential Vault panel first to use remote jump hosts.", "locked": True},
                    423,
                )
                return
            jumps = vault.jump_host_map()
            if not jumps:
                self._send_json(
                    {"error": "No jump hosts configured in vault. Add a jump host in the Credential Vault panel first."},
                    400,
                )
                return
            if jump_host_id != "auto" and jump_host_id not in jumps:
                self._send_json(
                    {"error": f"Selected jump host '{jump_host_id}' not found in vault."},
                    400,
                )
                return

        scan_id = os.urandom(6).hex()
        _cancel_event.clear()

        is_retry = bool(body.get("is_retry", False))
        append_outdir = (body.get("append_outdir", "") or "").strip() or None
        auto_retry = bool(body.get("auto_retry", True))
        verify_ssl = bool(body.get("verify_ssl", False))
        ca_bundle = body.get("ca_bundle", None) or None
        dns_lookup = bool(body.get("dns_lookup", False))
        pinned_thumbprints = body.get("pinned_thumbprints", {}) or {}
        enable_dash = bool(body.get("enable_dash", False))

        with _state_lock:
            if _state["running"]:
                self._send_json({"error": "Scan already running"}, 409)
                return

            prior_results = list(_state.get("results", [])) if is_retry else []
            prior_failed_hosts = list(_state.get("failed_hosts", [])) if is_retry else []

            if is_retry and not prior_results and append_outdir:
                try:
                    loaded = load_summary(os.path.join(append_outdir, "data", "fleet_summary.json"))
                    if loaded and isinstance(loaded, list):
                        prior_results = loaded
                except Exception:
                    pass

            effective_initial_outdir = append_outdir if (is_retry and append_outdir) else outdir
            _state.update({
                "scan_id": scan_id, "running": True, "done": False, "error": None,
                "total": len(ips), "completed": 0,
                "execution": execution,
                "jump_host_id": jump_host_id if execution == "remote" else None,
                "is_retry": is_retry,
                "is_rescan": is_retry,
                "had_auto_retry": False,
                "active_hosts": {},
                "completed_hosts": set(),
                "skipped_ips": set(),
                "results": prior_results, "failed_hosts": prior_failed_hosts, "partial_hosts": [], "report_paths": [],
                "fleet_path": "", "summary_path": "", "outdir": effective_initial_outdir, "log_lines": [],
                "disconnected_jump_scan": None,
            })

        scan_prof = body.get("profile") or body.get("scan_profile")
        if not scan_prof:
            if body.get("quick"):
                scan_prof = "inventory-lite"
            elif body.get("lean"):
                scan_prof = "readiness-lean"
            else:
                scan_prof = "readiness-full"

        worker_fn = _get_dispatch("_run_scan_worker", _run_scan_worker)
        threading.Thread(
            target=worker_fn,
            args=(scan_id, ips, creds, outdir,
                  threads,
                  bool(body.get("quick", False)),
                  bool(body.get("combined", True)),
                  bool(body.get("obfuscate", False)),
                  bool(body.get("debug", False)),
                  body.get("dell_creds"),
                  bool(body.get("save_json", False)),
                  bool(body.get("include_raw", False)),
                  bool(body.get("lean", False)),
                  min(2700, max(60, int(body.get("host_timeout", 300)))),
                  bool(body.get("allow_partial", False)),
                  is_retry,
                  append_outdir,
                  auto_retry,
                  prior_results,
                  prior_failed_hosts,
                  bool(body.get("force_threads", False)),
                  verify_ssl,
                  ca_bundle,
                  dns_lookup,
                  pinned_thumbprints,
                  enable_dash,
                  scan_prof,
                  False,
                  True,
                  bool(body.get("export_sheets", body.get("excel", True))),
                  bool(body.get("crawl_endpoints", False)),
                  None,
                  None,
                  execution,
                  jump_host_id),
            daemon=True,
        ).start()

        self._send_json({"ok": True, "scan_id": scan_id, "total": len(ips)})

    def _api_cancel(self) -> None:
        _cancel_event.set()
        with _state_lock:
            _state["running"] = False
            _state["done"] = True
            _state["error"] = "Cancelled by user"
            _state["disconnected_jump_scan"] = None
            scan_id = _state.get("scan_id")
            n_ok = len(_state.get("results", []))
            n_total = _state.get("total", 0)
            remote_scans = list(_state.get("active_remote_scans") or [])
            _state["active_remote_scans"] = []

        if remote_scans:
            vault = vault_session.get()
            if vault:
                from vcf_hci.remote.executor import kill_remote_scan
                def _terminate_remote_scans():
                    for rs in remote_scans:
                        jid = rs.get("jump_host_id")
                        rdir = rs.get("remote_dir")
                        j_prof = vault.get_jump_host(jid) if jid else None
                        if not j_prof:
                            j_map = vault.jump_host_map()
                            j_prof = j_map.get(jid)
                        if j_prof and rdir:
                            try:
                                kill_remote_scan(j_prof, remote_dir=rdir, timeout=10)
                            except Exception as k_err:
                                logger.warning("Failed terminating remote scan on %s: %s", jid, k_err)
                threading.Thread(target=_terminate_remote_scans, daemon=True).start()

        broadcast_fn = _get_dispatch("_broadcast", _broadcast)
        broadcast_fn("log", {"scan_id": scan_id, "msg": "  [!] Scan cancelled by user."})
        broadcast_fn("done", {
            "scan_id": scan_id,
            "n_ok": n_ok,
            "n_total": n_total,
            "fleet_report": "",
            "summary_report": "",
        })
        self._send_json({"ok": True})

    def _api_scan_preflight(self) -> None:
        body = self._read_json_body()
        execution = body.get("execution", "local")
        if execution != "remote":
            self._send_json({"ok": True, "has_active_scan": False, "active_scans": []})
            return
        if not self._vault_guard():
            return

        vault = vault_session.get()
        if vault is None:
            self._send_json({
                "ok": False,
                "error": "Credential Vault is locked. Unlock it in the Credential Vault panel before starting a remote assessment.",
                "locked": True,
            }, 423)
            return

        jumps = vault.jump_host_map()
        if not jumps:
            self._send_json({
                "ok": False,
                "error": "No jump hosts are configured in the Credential Vault.",
                "category": "jump_hosts_missing",
            }, 400)
            return

        selected_id = str(body.get("jump_host") or "auto").strip()
        raw_targets = body.get("targets") or body.get("ips") or []
        if isinstance(raw_targets, str):
            from vcf_hci.logging_utils import parse_ip_targets
            ips = parse_ip_targets(raw_targets)
        elif isinstance(raw_targets, list):
            ips = [str(x).strip() for x in raw_targets if str(x).strip()]
        else:
            ips = []

        from vcf_hci.remote.executor import inspect_jump_scans
        from vcf_hci.remote.orchestrator import route_targets

        target_jumps: Dict[str, Dict[str, Any]] = {}
        if selected_id and selected_id != "auto":
            profile = vault.get_jump_host(selected_id)
            if not profile:
                self._send_json({"ok": False, "error": f"Jump host '{selected_id}' not found in vault."}, 404)
                return
            target_jumps[selected_id] = profile
        elif ips:
            try:
                routes, unrouted = route_targets(ips, jumps, selected_id="auto")
                for jid in routes:
                    if jid in jumps:
                        target_jumps[jid] = jumps[jid]
            except Exception:
                target_jumps = dict(jumps)
        else:
            target_jumps = dict(jumps)

        active_scans: List[Dict[str, Any]] = []
        for jid, profile in target_jumps.items():
            try:
                scans = inspect_jump_scans(profile, timeout=10)
                for s in scans:
                    item = dict(s)
                    item["jump_host_id"] = jid
                    item["host"] = str(profile.get("host") or jid)
                    sb = item.get("sandbox") or item.get("sandbox_path") or ""
                    if sb:
                        item["sandbox"] = sb
                        item["sandbox_path"] = sb
                    active_scans.append(item)
            except Exception as exc:
                logger.debug("Failed probing active scans on %s: %s", jid, exc)

        self._send_json({
            "ok": True,
            "has_active_scan": len(active_scans) > 0,
            "active_scans": active_scans,
        })

    def _api_scan_kill_active(self) -> None:
        if not self._vault_guard():
            return
        body = self._read_json_body()
        jump_id = str(body.get("jump_host_id") or "").strip()
        remote_dir = str(body.get("remote_dir") or body.get("sandbox") or body.get("sandbox_path") or "all").strip()

        vault = vault_session.get()
        if vault is None:
            self._send_json({"ok": False, "error": "Vault is locked.", "locked": True}, 423)
            return

        profile = vault.get_jump_host(jump_id) if jump_id else None
        if not profile and jump_id:
            jumps = vault.jump_host_map()
            profile = jumps.get(jump_id)

        from vcf_hci.remote.executor import kill_remote_scan
        if profile:
            res = kill_remote_scan(profile, remote_dir=remote_dir, timeout=15)
            self._send_json(res)
        else:
            all_res = []
            for jid, prof in vault.jump_host_map().items():
                r = kill_remote_scan(prof, remote_dir="all", timeout=15)
                all_res.append({"jump_host_id": jid, "result": r})
            self._send_json({"ok": True, "results": all_res})

    def _api_scan_reconnect(self) -> None:
        if not self._vault_guard():
            return
        body = self._read_json_body()
        with _state_lock:
            info = dict(_state.get("disconnected_jump_scan") or {})
            remote_dir = str(
                body.get("remote_dir")
                or body.get("sandbox")
                or body.get("sandbox_path")
                or info.get("remote_dir")
                or ""
            ).strip()
            jump_host_id = str(body.get("jump_host_id") or info.get("jump_host_id") or "").strip()

            if jump_host_id and remote_dir:
                from vcf_hci.logging_utils import get_default_output_dir
                outdir = str(
                    body.get("outdir")
                    or _state.get("outdir")
                    or info.get("outdir")
                    or get_default_output_dir()
                ).strip()
                info.update({
                    "scan_id": body.get("scan_id") or info.get("scan_id") or ("resumed-" + str(int(time.time()))),
                    "jump_host_id": jump_host_id,
                    "remote_dir": remote_dir,
                    "host": body.get("host") or info.get("host") or "",
                    "run_id": body.get("run_id") or info.get("run_id") or "",
                    "outdir": outdir,
                })
            elif remote_dir and not info.get("remote_dir"):
                info["remote_dir"] = remote_dir

            if not info:
                self._send_json({"error": "No disconnected jump-host scan to resume"}, 400)
                return
            if _state.get("running"):
                self._send_json({"error": "Scan already running"}, 409)
                return

        vault = vault_session.get()
        if vault is None:
            self._send_json({"error": "Vault is locked. Unlock it in the Credential Vault panel first.", "locked": True}, 423)
            return

        if not info.get("outdir"):
            from vcf_hci.logging_utils import get_default_output_dir
            info["outdir"] = str(_state.get("outdir") or get_default_output_dir()).strip()

        if not info.get("remote_dir"):
            self._send_json({"error": "No remote directory found to resume"}, 400)
            return
        try:
            from vcf_hci.remote.guardrails import assert_sandbox_path
            info["remote_dir"] = assert_sandbox_path(str(info.get("remote_dir") or ""))
        except Exception:
            self._send_json({"error": "Invalid remote sandbox path"}, 400)
            return

        def _reconnect_target():
            from vcf_hci.web.remote_scan import resume_remote_scan_job
            from vcf_hci.web.scan_worker import (
                _broadcast,
                _handle_host_done,
                _handle_host_stage,
                _handle_host_start,
            )

            def _log_cb(event: str, msg: str):
                logger.info(msg)
                _get_dispatch("_broadcast", _broadcast)(event, {"scan_id": info.get("scan_id"), "msg": msg})

            def _host_start_cb(h_info: dict):
                _get_dispatch("_handle_host_start", _handle_host_start)(info.get("scan_id"), h_info)

            def _host_stage_cb(h_info: dict):
                _get_dispatch("_handle_host_stage", _handle_host_stage)(info.get("scan_id"), h_info)

            def _host_done_cb(h_info: dict):
                _get_dispatch("_handle_host_done", _handle_host_done)(info.get("scan_id"), h_info)

            def _progress_cb(completed: int, total: int):
                with _state_lock:
                    _state["completed"] = completed
                    _state["total"] = total
                _get_dispatch("_broadcast", _broadcast)("progress", {
                    "scan_id": info.get("scan_id"),
                    "completed": completed,
                    "total": total,
                    "is_rescan": False,
                    "msg": f"Progress: {completed}/{total}",
                })

            try:
                resume_remote_scan_job(
                    info=info,
                    log_callback=_log_cb,
                    host_start_callback=_host_start_cb,
                    host_stage_callback=_host_stage_cb,
                    host_done_callback=_host_done_cb,
                    progress_callback=_progress_cb,
                )
            except Exception:
                logger.exception("Reconnect background worker failed")

        threading.Thread(target=_reconnect_target, daemon=True).start()
        self._send_json({"ok": True, "msg": "Reconnecting to jump host...", "scan_id": info.get("scan_id")})

    def _api_skip_host(self) -> None:
        body = self._read_json_body()
        ip = body.get("ip", "").strip()
        if not ip:
            self._send_json({"error": "ip parameter required"}, 400)
            return
        with _state_lock:
            _state["skipped_ips"].add(ip)
            _state["active_hosts"].pop(ip, None)
        _get_dispatch("_broadcast", _broadcast)("host_skipped", {"scan_id": _state.get("scan_id"), "ip": ip, "msg": f"Skipping host {ip}..."})
        logger.info("User requested skip for host %s", ip)
        self._send_json({"ok": True, "ip": ip})
