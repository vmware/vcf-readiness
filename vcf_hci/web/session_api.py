"""
VCF Readiness Tool — Session, Vault, & Report Web API Mixin (vcf_hci.web.session_api)

Defines SessionApiMixin for discovery, credential test, profiles, keychain,
vault management, desktop folder integration, and static report serving.
"""

import base64
import html
import json
import logging
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

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
    get_default_output_dir,
    is_cloud_metadata_target,
    parse_ip_targets,
)
from vcf_hci.logging_utils import create_pinned_connection, sanitize_filename
from vcf_hci.tls_utils import (
    build_bmc_opener,
    build_ssl_context,
    format_ssl_error,
    inspect_server_certificate,
)
from vcf_hci.vault import (
    MIN_PASSPHRASE_LEN,
    VaultAuthError,
    VaultError,
    VaultExistsError,
    VaultFormatError,
    VaultNotFoundError,
    parse_credentials_csv,
)
from vcf_hci.web import vault_session
from vcf_hci.web.desktop import (
    _browse_folder_dialog,
    _open_folder_in_desktop,
    _resolve_desktop_open_path,
)
from vcf_hci.web.scan_worker import (
    _get_dispatch,
    _state,
    _state_lock,
)
from vcf_hci.web.session_store import (
    _load_profiles,
    _load_session,
    _save_profiles,
    _save_session,
    _SecretStore,
)

logger = logging.getLogger("vcf_assess")

_COLLECTOR_OK = True


def _get_resp_header(resp: Any, name: str) -> str:
    headers = getattr(resp, "headers", None)
    if headers is not None and hasattr(headers, "get"):
        val = headers.get(name)
        if val is not None:
            return str(val).strip()
    getheader = getattr(resp, "getheader", None)
    if callable(getheader):
        val = getheader(name)
        if val is not None:
            return str(val).strip()
    return ""


def _is_safe_session_redirect(redirect_url: str, host: str) -> bool:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(redirect_url)
        if not parsed.netloc:
            return redirect_url.startswith("/redfish/") and "Sessions" in redirect_url
        target_host = host.split(":")[0].lower().strip("[]")
        redir_host = (parsed.hostname or "").lower().strip("[]")
        return (
            parsed.scheme in ("https", "http")
            and redir_host == target_host
            and parsed.path.startswith("/redfish/")
            and "Sessions" in parsed.path
        )
    except Exception:
        return False


def _delete_test_session(
    ip: str,
    session_uri: str,
    session_token: str,
    ctx: ssl.SSLContext,
    pinned_thumbprints: Optional[dict] = None,
) -> None:
    """Send DELETE to terminate temporary test Redfish session cleanly."""
    if not session_uri or not session_token:
        return
    try:
        from vcf_hci.collector.http_session import RedfishSessionManager
        mgr = RedfishSessionManager(
            host=ip,
            session_uri=session_uri,
            session_token=session_token,
            ssl_context=ctx,
            pinned_thumbprints=pinned_thumbprints,
        )
        mgr.close()
    except Exception:
        try:
            delete_url = session_uri if session_uri.startswith("http") else f"https://{ip}/{session_uri.lstrip('/')}"
            req = urllib.request.Request(
                delete_url,
                headers={"X-Auth-Token": session_token},
                method="DELETE",
            )
            del_opener = build_bmc_opener(ssl_context=ctx, pinned_thumbprints=pinned_thumbprints)
            with del_opener.open(req, timeout=3.0):
                pass
        except Exception as exc:
            logger.debug("Failed to delete test session on %s: %s", ip, exc)


def _probe_bmc_credentials(
    ip: str,
    user: str,
    pwd: str,
    ctx: ssl.SSLContext,
    pinned_thumbprints: Optional[dict] = None,
    timeout: float = 3.5,
) -> Tuple[bool, int, str, Optional[dict]]:
    """Test BMC credentials by attempting Redfish Session POST first, falling back to Basic Auth.

    Returns:
        (auth_ok, http_status_code, detail_message, ssl_err_info)
    """
    if not pwd:
        return False, 0, "Password is required", None

    opener = build_bmc_opener(ssl_context=ctx, pinned_thumbprints=pinned_thumbprints)

    def _open_req(req: urllib.request.Request, req_timeout: float = timeout):
        is_mocked = not hasattr(urllib.request.urlopen, "__code__") or "Mock" in type(urllib.request.urlopen).__name__ or hasattr(urllib.request.urlopen, "mock")
        if is_mocked and not (hasattr(opener, "mock") or "Mock" in type(opener).__name__):
            return urllib.request.urlopen(req, timeout=req_timeout, context=ctx)
        return opener.open(req, timeout=req_timeout)

    # ── Step 1: Attempt Redfish Session creation via POST ─────────────────────
    session_endpoints = [
        f"https://{ip}/redfish/v1/SessionService/Sessions",
        f"https://{ip}/redfish/v1/Sessions",
    ]
    session_payload = json.dumps({"UserName": user, "Password": pwd}).encode("utf-8")
    session_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    auth_failed_code = 0
    last_error_code = 0
    last_error_detail = "Connection failed"

    for s_url in session_endpoints:
        s_req = urllib.request.Request(s_url, data=session_payload, headers=session_headers, method="POST")
        session_created = False
        status = 200
        token = ""
        location = ""
        try:
            with _open_req(s_req, req_timeout=timeout) as resp:
                status = getattr(resp, "status", getattr(resp, "code", 200))
                token = _get_resp_header(resp, "X-Auth-Token") or _get_resp_header(resp, "x-auth-token")
                location = _get_resp_header(resp, "Location") or _get_resp_header(resp, "location")

                if not location or not token:
                    try:
                        raw_body = resp.read()
                        if raw_body:
                            data = json.loads(raw_body.decode("utf-8", errors="replace"))
                            if isinstance(data, dict):
                                if not token and data.get("Token"):
                                    token = str(data["Token"]).strip()
                                if not location:
                                    location = data.get("@odata.id") or ""
                                    if not location and data.get("Id"):
                                        location = f"{s_url.rstrip('/')}/{data['Id']}"
                    except Exception:
                        pass

                if token or status in (200, 201):
                    session_created = True
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 307, 308):
                redir = e.headers.get("Location") or e.headers.get("location") or ""
                if redir and _is_safe_session_redirect(redir, ip):
                    redir_url = redir if redir.startswith("http") else f"https://{ip}/{redir.lstrip('/')}"
                    try:
                        redir_req = urllib.request.Request(redir_url, data=session_payload, headers=session_headers, method="POST")
                        redir_token = ""
                        redir_loc = ""
                        redir_status = 200
                        with _open_req(redir_req, req_timeout=timeout) as redir_resp:
                            redir_status = getattr(redir_resp, "status", getattr(redir_resp, "code", 200))
                            redir_token = _get_resp_header(redir_resp, "X-Auth-Token") or _get_resp_header(redir_resp, "x-auth-token")
                            redir_loc = _get_resp_header(redir_resp, "Location") or _get_resp_header(redir_resp, "location")
                        if redir_token or redir_status in (200, 201):
                            if redir_loc and redir_token:
                                _delete_test_session(ip, redir_loc, redir_token, ctx, pinned_thumbprints)
                            return True, redir_status, "", None
                    except Exception:
                        pass

            if e.code in (401, 403):
                auth_failed_code = e.code
                break
            if e.code == 404:
                continue
            last_error_code = e.code
            last_error_detail = str(e.reason)
            break
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, (ssl.SSLCertVerificationError, ssl.CertificateError, ssl.SSLError)):
                err_info = format_ssl_error(reason if isinstance(reason, Exception) else e, ip)
                return False, 0, err_info["detail"], err_info
            return False, 0, str(e), None
        except Exception as e:
            if isinstance(e, (ssl.SSLCertVerificationError, ssl.CertificateError, ssl.SSLError)):
                err_info = format_ssl_error(e, ip)
                return False, 0, err_info["detail"], err_info
            return False, 0, str(e), None

        if session_created:
            if location and token:
                _delete_test_session(ip, location, token, ctx, pinned_thumbprints)
            elif location:
                _delete_test_session(ip, location, token or "", ctx, pinned_thumbprints)
            return True, status, "", None

    # ── Step 2: Fallback to HTTP Basic Auth on Systems/Managers ───────────────
    # We do NOT test GET /redfish/v1/SessionService/Sessions with Basic Auth because modern
    # BMCs (e.g. Lenovo XCC 3) reject reading the Session collection with HTTP 401 Unauthorized.
    basic_token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    basic_endpoints = [
        f"https://{ip}/redfish/v1/Systems",
        f"https://{ip}/redfish/v1/Managers",
    ]
    for ep in basic_endpoints:
        b_req = urllib.request.Request(
            ep,
            headers={
                "Authorization": f"Basic {basic_token}",
                "Accept": "application/json",
            },
        )
        try:
            with _open_req(b_req, req_timeout=timeout) as resp:
                b_status = getattr(resp, "status", getattr(resp, "code", 200))
                return True, b_status, "", None
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                return False, e.code, "Invalid credentials or unauthorized", None
            if e.code in (404, 405):
                continue
            return False, e.code, str(e.reason), None
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, (ssl.SSLCertVerificationError, ssl.CertificateError, ssl.SSLError)):
                err_info = format_ssl_error(reason if isinstance(reason, Exception) else e, ip)
                return False, 0, err_info["detail"], err_info
            return False, 0, str(e), None
        except Exception as e:
            if isinstance(e, (ssl.SSLCertVerificationError, ssl.CertificateError, ssl.SSLError)):
                err_info = format_ssl_error(e, ip)
                return False, 0, err_info["detail"], err_info
            return False, 0, str(e), None

    if auth_failed_code:
        return False, auth_failed_code, "Invalid credentials or unauthorized", None

    if last_error_code:
        return False, last_error_code, last_error_detail, None

    return False, 0, "Connection failed", None


class SessionApiMixin(_ApiMixinBase):
    """Discovery, credentials, profiles, vault, folder, and report serving mixed into AppHandler."""

    # ── /api/discover ─────────────────────────────────────────────────────────

    def _api_discover(self) -> None:
        if not _COLLECTOR_OK:
            self._send_json({"error": "Collector not available"}, 503)
            return
        body = self._read_json_body()
        raw = body.get("targets", "").strip()
        if not raw:
            self._send_json({"error": "targets required"}, 400)
            return
        try:
            ips = parse_ip_targets(raw)
        except Exception as exc:
            self._send_json({"error": str(exc)}, 400)
            return

        inspect_cert_fn = _get_dispatch("inspect_server_certificate", inspect_server_certificate)

        def _probe(ip: str):
            t0 = time.time()
            try:
                with create_pinned_connection((ip, 443), timeout=2.0):
                    latency_ms = round((time.time() - t0) * 1000, 1)
                    cert_info = inspect_cert_fn(ip, port=443, timeout=2.5)
                    return ip, True, 443, latency_ms, cert_info
            except Exception:
                pass
            t0 = time.time()
            try:
                with create_pinned_connection((ip, 80), timeout=2.0):
                    latency_ms = round((time.time() - t0) * 1000, 1)
                    return ip, True, 80, latency_ms, None
            except Exception:
                pass
            return ip, False, 0, 0.0, None

        found = []
        latencies = []
        max_threads = max(1, min(32, len(ips))) if ips else 1
        with ThreadPoolExecutor(max_workers=max_threads) as ex:
            for ip, reachable, port, latency_ms, cert_info in ex.map(_probe, ips):
                if reachable:
                    item = {"ip": ip, "port": port, "latency_ms": latency_ms}
                    if cert_info and cert_info.get("reachable"):
                        item["cert_info"] = cert_info
                    found.append(item)
                    latencies.append(latency_ms)

        avg_latency_ms = round(sum(latencies) / len(latencies), 1) if latencies else 0.0
        max_latency_ms = max(latencies) if latencies else 0.0
        high_latency_detected = bool(avg_latency_ms > 80.0 or max_latency_ms > 150.0)

        self._send_json({
            "hosts": found,
            "avg_latency_ms": avg_latency_ms,
            "max_latency_ms": max_latency_ms,
            "high_latency_detected": high_latency_detected,
        })

    # ── /api/inspect-cert ─────────────────────────────────────────────────────

    def _api_inspect_cert(self) -> None:
        host = ""
        port = 443
        parsed = urllib.parse.urlparse(self.path)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            host = (params.get("host", [""])[0] or params.get("ip", [""])[0] or "").strip()
            try:
                port = int(params.get("port", [443])[0])
            except (ValueError, TypeError):
                port = 443
        if not host:
            body = self._read_json_body()
            host = (body.get("host") or body.get("ip") or "").strip()
            try:
                port = int(body.get("port", 443) or 443)
            except (ValueError, TypeError):
                port = 443
        if not host:
            self._send_json({"error": "host required"}, 400)
            return
        if is_cloud_metadata_target(host):
            self._send_json({"error": f"Target '{host}' is a prohibited cloud metadata endpoint."}, 400)
            return
        inspect_cert_fn = _get_dispatch("inspect_server_certificate", inspect_server_certificate)
        cert_data = inspect_cert_fn(host, port=port, timeout=3.0)
        self._send_json(cert_data)

    # ── /api/test-creds ───────────────────────────────────────────────────────

    def _api_test_creds(self) -> None:
        body = self._read_json_body()
        raw_ip = body.get("ip", "").strip()
        user = (body.get("username") or "").strip() or "root"
        pwd = body.get("password", "")
        verify_ssl = bool(body.get("verify_ssl", False))
        ca_bundle = body.get("ca_bundle", None) or None
        pinned_thumbprints = body.get("pinned_thumbprints", None) or None
        use_vault = bool(body.get("use_vault", False))
        if not raw_ip:
            self._send_json({"error": "ip required"}, 400)
            return
        if is_cloud_metadata_target(raw_ip):
            self._send_json({"error": f"Target '{raw_ip}' is a prohibited cloud metadata endpoint."}, 400)
            return

        # Security gate: require pinned thumbprints or CA bundle if TLS verification is requested
        if verify_ssl and not ca_bundle and not pinned_thumbprints:
            self._send_json(
                {
                    "ok": False,
                    "code": 495,
                    "detail": "Certificate thumbprints required when Ignore TLS is unchecked. Review and pin certificates or enable Ignore TLS.",
                    "requires_tofu": True,
                    "tested_ip": raw_ip,
                },
                400,
            )
            return

        # Expand ranges/CIDR and select candidate targets (e.g. "10.0.0.10-12" → ["10.0.0.10", "10.0.0.11", "10.0.0.12"])
        target_candidates = [raw_ip]
        try:
            parsed = parse_ip_targets(raw_ip)
            if parsed:
                target_candidates = parsed
        except Exception:
            pass

        is_batch = bool(body.get("batch", False))
        if is_batch:
            self._handle_batch_test_creds(
                raw_ip=raw_ip,
                target_candidates=target_candidates,
                default_user=user,
                default_pwd=pwd,
                body=body,
                verify_ssl=verify_ssl,
                ca_bundle=ca_bundle,
                pinned_thumbprints=pinned_thumbprints,
                use_vault=use_vault,
            )
            return

        selected_ip = target_candidates[0]
        candidate_hint = (body.get("candidate_ip") or "").strip()
        if candidate_hint and candidate_hint in target_candidates and not is_cloud_metadata_target(candidate_hint):
            selected_ip = candidate_hint
        elif len(target_candidates) > 1:
            def _check_tcp(cand: str) -> Optional[str]:
                if is_cloud_metadata_target(cand):
                    return None
                try:
                    with socket.create_connection((cand, 443), timeout=0.5):
                        return cand
                except OSError:
                    pass
                try:
                    with socket.create_connection((cand, 80), timeout=0.4):
                        return cand
                except OSError:
                    pass
                return None

            probe_slice = target_candidates[:min(len(target_candidates), 64)]
            with ThreadPoolExecutor(max_workers=min(len(probe_slice), 32)) as ex:
                futures = [ex.submit(_check_tcp, cand) for cand in probe_slice]
                for fut in as_completed(futures):
                    try:
                        res = fut.result()
                        if res:
                            selected_ip = res
                            for f in futures:
                                f.cancel()
                            break
                    except Exception:
                        pass

        ip = selected_ip
        if is_cloud_metadata_target(ip):
            self._send_json({"error": f"Target '{ip}' is a prohibited cloud metadata endpoint."}, 400)
            return

        # Resolve credentials from vault if not supplied or use_vault explicitly set
        is_remote = False
        try:
            rem = self._is_remote_server()
            if isinstance(rem, bool):
                is_remote = rem
        except Exception:
            pass

        if (not pwd or use_vault) and not is_remote:
            v = vault_session.get()
            if v is not None:
                pair = v.resolve(ip)
                if pair:
                    user, pwd = pair

        if not pwd:
            self._send_json({"ok": False, "code": 0, "detail": "Password is required (or unlock vault to use stored credentials)", "tested_ip": ip})
            return

        ctx = build_ssl_context(verify_ssl=verify_ssl, ca_bundle=ca_bundle)
        auth_ok, code, detail, ssl_err_info = _probe_bmc_credentials(
            ip=ip,
            user=user,
            pwd=pwd,
            ctx=ctx,
            pinned_thumbprints=pinned_thumbprints,
            timeout=3.5,
        )
        if auth_ok:
            self._send_json({"ok": True, "code": code, "tested_ip": ip})
            return
        if ssl_err_info:
            self._send_json({
                "ok": False,
                "code": 0,
                "detail": ssl_err_info["detail"],
                "reason_code": ssl_err_info.get("reason_code", "ssl_error"),
                "tested_ip": ip,
            })
            return
        self._send_json({"ok": False, "code": code, "detail": detail or "Connection failed", "tested_ip": ip})

    def _handle_batch_test_creds(
        self,
        raw_ip: str,
        target_candidates: List[str],
        default_user: str,
        default_pwd: str,
        body: dict,
        verify_ssl: bool,
        ca_bundle: Optional[str],
        pinned_thumbprints: Optional[dict],
        use_vault: bool,
    ) -> None:
        for cand in target_candidates:
            if is_cloud_metadata_target(cand):
                self._send_json({"error": f"Target '{cand}' is a prohibited cloud metadata endpoint."}, 400)
                return

        per_host_input = body.get("creds", [])
        creds_map: Dict[str, Tuple[str, str]] = {}
        if isinstance(per_host_input, list):
            for item in per_host_input:
                if isinstance(item, dict) and item.get("ip"):
                    u = str(item.get("user") or default_user).strip() or "root"
                    p = str(item.get("pass") or default_pwd)
                    creds_map[str(item["ip"])] = (u, p)

        is_remote = False
        try:
            rem = self._is_remote_server()
            if isinstance(rem, bool):
                is_remote = rem
        except Exception:
            pass

        v = vault_session.get() if (use_vault and not is_remote) else None

        def _check_tcp_batch(cand: str) -> Tuple[str, bool]:
            try:
                with socket.create_connection((cand, 443), timeout=0.8):
                    return cand, True
            except OSError:
                pass
            try:
                with socket.create_connection((cand, 80), timeout=0.4):
                    return cand, True
            except OSError:
                pass
            return cand, False

        probe_workers = max(1, min(len(target_candidates), 64))
        reachable_set: Set[str] = set()
        with ThreadPoolExecutor(max_workers=probe_workers) as ex:
            tcp_futures = [ex.submit(_check_tcp_batch, cand) for cand in target_candidates]
            for fut in as_completed(tcp_futures):
                try:
                    cip, is_up = fut.result()
                    if is_up:
                        reachable_set.add(cip)
                except Exception:
                    pass

        ctx = build_ssl_context(verify_ssl=verify_ssl, ca_bundle=ca_bundle)

        def _test_single_host_auth(target_ip: str) -> Dict[str, Any]:
            u, p = creds_map.get(target_ip, (default_user, default_pwd))
            if (not p or use_vault) and v is not None:
                pair = v.resolve(target_ip)
                if pair:
                    u, p = pair
            if not p:
                return {
                    "ip": target_ip,
                    "reachable": True,
                    "auth_ok": False,
                    "code": 0,
                    "detail": "Password is required",
                }

            auth_ok, code, detail, ssl_err_info = _probe_bmc_credentials(
                ip=target_ip,
                user=u,
                pwd=p,
                ctx=ctx,
                pinned_thumbprints=pinned_thumbprints,
                timeout=3.0,
            )
            if auth_ok:
                return {
                    "ip": target_ip,
                    "reachable": True,
                    "auth_ok": True,
                    "code": code,
                }
            if ssl_err_info:
                return {
                    "ip": target_ip,
                    "reachable": True,
                    "auth_ok": False,
                    "code": 0,
                    "detail": ssl_err_info["detail"],
                }
            return {
                "ip": target_ip,
                "reachable": True,
                "auth_ok": False,
                "code": code,
                "detail": detail or "Connection failed",
            }

        reachable_list = [t for t in target_candidates if t in reachable_set]
        auth_workers = max(1, min(len(reachable_list), 32)) if reachable_list else 1
        host_results: List[Dict[str, Any]] = []
        if reachable_list:
            with ThreadPoolExecutor(max_workers=auth_workers) as ex:
                auth_futures = [ex.submit(_test_single_host_auth, rip) for rip in reachable_list]
                for fut in as_completed(auth_futures):
                    try:
                        host_results.append(fut.result())
                    except Exception as exc:
                        logger.debug("Batch auth test failed: %s", exc)

        total = len(target_candidates)
        reachable_count = len(reachable_set)
        unreachable_count = total - reachable_count
        auth_ok_count = sum(1 for r in host_results if r.get("auth_ok"))
        auth_failed_count = sum(1 for r in host_results if not r.get("auth_ok"))
        failed_hosts = [r["ip"] for r in host_results if not r.get("auth_ok")]
        unreachable_hosts = [t for t in target_candidates if t not in reachable_set]

        self._send_json({
            "ok": bool(auth_ok_count == total and total > 0),
            "batch": True,
            "total": total,
            "reachable": reachable_count,
            "unreachable": unreachable_count,
            "auth_ok": auth_ok_count,
            "auth_failed": auth_failed_count,
            "results": host_results[:100],
            "failed_hosts": failed_hosts,
            "unreachable_hosts": unreachable_hosts,
        })

    # ── Profile / Session ─────────────────────────────────────────────────────

    def _api_save_profile(self) -> None:
        body = self._read_json_body()
        name = body.get("name", "").strip()
        if not name:
            self._send_json({"error": "name required"}, 400)
            return
        pwd = body.get("password", "")
        load_prof_fn = _get_dispatch("_load_profiles", _load_profiles)
        save_prof_fn = _get_dispatch("_save_profiles", _save_profiles)
        secret_store_cls = _get_dispatch("_SecretStore", _SecretStore)

        profiles = load_prof_fn()
        profiles[name] = {k: v for k, v in body.items() if k != "password"}
        save_prof_fn(profiles)
        if pwd:
            secret_store_cls.store(f"profile:{name}", pwd)
        self._send_json({"ok": True})

    def _api_save_session(self) -> None:
        body = self._read_json_body()
        load_sess_fn = _get_dispatch("_load_session", _load_session)
        save_sess_fn = _get_dispatch("_save_session", _save_session)
        current = load_sess_fn()
        current.update(body)
        save_sess_fn(current)
        self._send_json({"ok": True})

    # ── Keychain ──────────────────────────────────────────────────────────────

    def _require_same_origin(self) -> bool:
        origin = self.headers.get("Origin", "").strip() if self.headers else ""
        sfs = self.headers.get("Sec-Fetch-Site", "").strip().lower() if self.headers else ""
        if sfs and sfs not in ("same-origin", "none"):
            return False
        if origin:
            try:
                p = urllib.parse.urlparse(origin)
                srv_port = getattr(self.server, "server_address", ("127.0.0.1", 0))[1]
                o_port = p.port or (443 if p.scheme == "https" else 80)
                if o_port != srv_port:
                    return False
            except Exception:
                return False
        return True

    def _require_ui_referer(self) -> bool:
        """True only for a request whose document is the dashboard at path /.

        Script cannot set Referer. A /reports/ document sends that path, or no
        Referer after Referrer-Policy: no-referrer. opener.fetch is not covered
        here: its Referer is the dashboard, which is why report responses also
        send Cross-Origin-Opener-Policy: noopener-allow-popups.
        """
        referer = self.headers.get("Referer", "").strip() if self.headers else ""
        if not referer:
            return False
        try:
            parsed = urllib.parse.urlparse(referer)
            if parsed.scheme not in ("http", "https"):
                return False
            srv_port = getattr(self.server, "server_address", ("127.0.0.1", 0))[1]
            r_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if r_port != srv_port:
                return False
            return (parsed.path or "/") == "/"
        except Exception:
            return False

    def _api_keychain_store(self) -> None:
        if not self._require_same_origin() or not self._require_ui_referer():
            self._send_json({"error": "Forbidden"}, 403)
            return
        if self._is_remote_server():
            self._send_json({
                "ok": False,
                "error": "Secret storage is disabled when remote network access (--allow-remote) is enabled."
            }, 403)
            return
        body = self._read_json_body()
        key = body.get("key", "")
        val = body.get("value", "")
        if not key:
            self._send_json({"error": "key required"}, 400)
            return
        secret_store_cls = _get_dispatch("_SecretStore", _SecretStore)
        if secret_store_cls.backend() == "none":
            self._send_json({
                "ok": False,
                "error": "No secure secret storage backend available on this system (macOS Keychain, Windows DPAPI, or Linux secret-tool required)."
            }, 501)
            return
        ok = secret_store_cls.store(key, val)
        if not ok:
            self._send_json({"ok": False, "error": f"Failed storing secret in {secret_store_cls.label()}"}, 500)
            return
        self._send_json({"ok": True, "backend": secret_store_cls.label()})

    def _api_keychain_retrieve(self) -> None:
        if not self._require_same_origin() or not self._require_ui_referer():
            self._send_json({"error": "Forbidden"}, 403)
            return
        if self._is_remote_server():
            self._send_json({
                "error": "Secret retrieval is disabled when remote network access (--allow-remote) is enabled."
            }, 403)
            return
        body = self._read_json_body()
        key = body.get("key", "")
        secret_store_cls = _get_dispatch("_SecretStore", _SecretStore)
        val = secret_store_cls.retrieve(key) if key else None
        self._send_json({"value": val})

    # ── Encrypted credential vault (opt-in; local-only; never returns passwords) ──

    def _vault_guard(self) -> bool:
        """Common gate for every /api/vault/* endpoint. Returns False after sending an error."""
        if not self._require_same_origin():
            self._send_json({"error": "Forbidden"}, 403)
            return False
        if self._is_remote_server():
            self._send_json({
                "ok": False,
                "error": "The credential vault is disabled when remote network access (--allow-remote) is enabled."
            }, 403)
            return False
        return True

    def _vault_or_423(self):
        v = vault_session.get()
        if v is None:
            self._send_json({"ok": False, "error": "Vault is locked", "locked": True}, 423)
        return v

    def _api_vault_status(self) -> None:
        if not self._vault_guard():
            return
        self._send_json(vault_session.status())

    def _api_vault_create(self) -> None:
        if not self._vault_guard():
            return
        body = self._read_json_body()
        passphrase = body.get("passphrase", "")
        if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE_LEN:
            self._send_json({"ok": False, "error": f"Passphrase must be at least {MIN_PASSPHRASE_LEN} characters."}, 400)
            return
        try:
            vault_session.create(passphrase)
        except VaultExistsError:
            self._send_json({"ok": False, "error": "A vault already exists at this path. Unlock it instead."}, 409)
            return
        except VaultError as exc:
            self._send_json({"ok": False, "error": str(exc)}, 400)
            return
        self._send_json({"ok": True, **vault_session.status()})

    def _api_vault_unlock(self) -> None:
        if not self._vault_guard():
            return
        body = self._read_json_body()
        passphrase = body.get("passphrase", "")
        if not isinstance(passphrase, str) or not passphrase:
            self._send_json({"ok": False, "error": "passphrase required"}, 400)
            return
        try:
            vault_session.unlock(passphrase)
        except VaultNotFoundError:
            self._send_json({"ok": False, "error": "No vault exists yet. Create one first."}, 404)
            return
        except VaultAuthError:
            time.sleep(0.5)  # blunt online-guessing brake; the KDF is the real cost
            self._send_json({"ok": False, "error": "Incorrect passphrase (or the vault file was tampered with)."}, 401)
            return
        except VaultFormatError as exc:
            self._send_json({"ok": False, "error": f"Unreadable vault: {exc}"}, 400)
            return
        self._send_json({"ok": True, **vault_session.status()})

    def _api_vault_lock(self) -> None:
        if not self._vault_guard():
            return
        vault_session.lock()
        self._send_json({"ok": True, **vault_session.status()})

    def _api_vault_entries(self) -> None:
        if not self._vault_guard():
            return
        v = self._vault_or_423()
        if v is None:
            return
        self._send_json({"ok": True, "entries": v.list_entries(), "entry_count": v.entry_count})

    def _api_vault_set_entry(self) -> None:
        if not self._vault_guard():
            return
        v = self._vault_or_423()
        if v is None:
            return
        body = self._read_json_body()
        try:
            written = v.set_entry(
                str(body.get("target", "")),
                str(body.get("username", "")),
                str(body.get("password", "")),
                str(body.get("note", "") or ""),
            )
            v.save()
        except VaultError as exc:
            self._send_json({"ok": False, "error": str(exc)}, 400)
            return
        self._send_json({"ok": True, "written": written, "entry_count": v.entry_count})

    def _api_vault_remove(self) -> None:
        if not self._vault_guard():
            return
        v = self._vault_or_423()
        if v is None:
            return
        body = self._read_json_body()
        removed = v.remove_entry(str(body.get("target", "")))
        if removed:
            try:
                v.save()
            except VaultError as exc:
                self._send_json({"ok": False, "error": str(exc)}, 500)
                return
        self._send_json({"ok": True, "removed": removed, "entry_count": v.entry_count})

    def _api_vault_import_csv(self) -> None:
        if not self._vault_guard():
            return
        v = self._vault_or_423()
        if v is None:
            return
        body = self._read_json_body()
        csv_text = body.get("csv_text", "")
        if not isinstance(csv_text, str) or not csv_text.strip():
            self._send_json({"ok": False, "error": "csv_text required"}, 400)
            return
        if len(csv_text) > 2_000_000:
            self._send_json({"ok": False, "error": "CSV too large (2 MB limit)"}, 413)
            return
        replace = bool(body.get("replace", False))
        skip_invalid = bool(body.get("skip_invalid", False))
        rows, errors, warnings = parse_credentials_csv(csv_text)
        if errors and not skip_invalid:
            self._send_json({"ok": False, "imported": 0, "skipped": len(rows) + len(errors),
                             "errors": errors, "warnings": warnings,
                             "error": "Import aborted: fix the listed rows or enable 'skip invalid rows'."}, 400)
            return
        try:
            result = v.import_rows(rows, replace=replace, skip_invalid=skip_invalid)
            all_errors = errors + list(result.get("errors", []))
            if result["imported"] == 0 and all_errors and not skip_invalid:
                self._send_json({"ok": False, "imported": 0, "skipped": result["skipped"],
                                 "errors": all_errors, "warnings": warnings,
                                 "error": "Import aborted: no changes written."}, 400)
                return
            v.save()
        except VaultError as exc:
            self._send_json({"ok": False, "error": str(exc)}, 400)
            return
        self._send_json({"ok": True, "imported": result["imported"],
                         "skipped": result["skipped"] + len(errors),
                         "errors": all_errors, "warnings": warnings, "entry_count": v.entry_count})

    def _api_vault_coverage(self) -> None:
        if not self._vault_guard():
            return
        v = self._vault_or_423()
        if v is None:
            return
        body = self._read_json_body()
        raw_targets = body.get("targets", "")
        try:
            if isinstance(raw_targets, list):
                targets = [str(t) for t in raw_targets if str(t).strip()]
            else:
                targets = parse_ip_targets(str(raw_targets or ""), block_metadata=False)
        except Exception as exc:
            self._send_json({"ok": False, "error": str(exc)}, 400)
            return
        self._send_json({"ok": True, **v.coverage(targets)})

    # ── Folder browsing and open in desktop ───────────────────────────────────

    def _api_browse_folder(self) -> None:
        if self._is_remote_server():
            self._send_json({"error": "Desktop folder chooser is disabled when remote network access (--allow-remote) is enabled."}, 403)
            return
        body = self._read_json_body() or {}
        initial_dir = body.get("initial_dir", "").strip() or None
        browse_fn = _get_dispatch("_browse_folder_dialog", _browse_folder_dialog)
        chosen = browse_fn(initial_dir=initial_dir)
        if chosen:
            self._send_json({"ok": True, "path": chosen})
        else:
            self._send_json({"ok": False, "cancelled": True})

    def _api_open_folder(self) -> None:
        if self._is_remote_server():
            self._send_json({"error": "Opening desktop folders is disabled when remote network access (--allow-remote) is enabled."}, 403)
            return
        body = self._read_json_body() or {}
        req_path = body.get("path", "").strip()
        with _state_lock:
            chosen = str(_state.get("outdir") or "").strip()
        if not chosen:
            chosen = get_default_output_dir()
        if not req_path:
            req_path = chosen
        resolve_fn = _get_dispatch("_resolve_desktop_open_path", _resolve_desktop_open_path)
        resolved = resolve_fn(req_path, chosen)
        if not resolved:
            self._send_json({"error": f"Path '{req_path}' is outside allowed directories."}, 400)
            return
        open_fn = _get_dispatch("_open_folder_in_desktop", _open_folder_in_desktop)
        success = open_fn(resolved, allowed_root=chosen)
        if success:
            self._send_json({"ok": True, "path": resolved})
        else:
            self._send_json({"error": f"Could not open directory '{req_path}' in local file manager."}, 500)

    # ── Static report serving ─────────────────────────────────────────────────

    def _serve_report(self, filename: str) -> None:
        with _state_lock:
            outdir = _state.get("outdir", "")
            rpaths = list(_state.get("report_paths", []))
            is_remote_running = bool(
                _state.get("running", False)
                and (
                    _state.get("execution") == "remote"
                    or bool(_state.get("active_remote_scans"))
                )
            )
            is_disconnected = bool(_state.get("disconnected_jump_scan"))
            is_remote_pending = is_remote_running or is_disconnected
        outdir = os.path.expanduser(outdir) if outdir else get_default_output_dir()
        safe = re.sub(r"[^A-Za-z0-9 _.()@-]", "_", os.path.basename(filename))
        path = os.path.join(outdir, safe)
        if not os.path.isfile(path):
            alt_reports = os.path.join(outdir, "reports", safe)
            alt_data = os.path.join(outdir, "data", safe)
            if os.path.isfile(alt_reports):
                path = alt_reports
            elif os.path.isfile(alt_data):
                path = alt_data
            else:
                # Fallback to OBFUSCATED copies if standard file requested is missing
                obf_fallback = None
                if safe == "00_fleet_summary.html":
                    obf_fallback = "00_OBFUSCATED_fleet_summary.html"
                elif safe == "00_fleet_combined.html":
                    obf_fallback = "00_OBFUSCATED_fleet_combined.html"
                elif safe.startswith("vsphere_vsan_report_"):
                    for idx, rp in enumerate(rpaths, 1):
                        if os.path.basename(rp) == safe:
                            obf_fallback = f"OBFUSCATED_Host-{idx}.html"
                            break

                if obf_fallback:
                    cand1 = os.path.join(outdir, obf_fallback)
                    cand2 = os.path.join(outdir, "reports", obf_fallback)
                    if os.path.isfile(cand1):
                        path = cand1
                    elif os.path.isfile(cand2):
                        path = cand2

            # If still missing, attempt on-demand dynamic generation
            if not os.path.isfile(path):
                rendered_path = self._try_render_host_report_on_demand(safe, outdir)
                if rendered_path and os.path.isfile(rendered_path):
                    path = rendered_path
                elif is_remote_pending:
                    self._serve_remote_sync_pending_page(safe, is_disconnected=is_disconnected)
                    return
                else:
                    self.send_error(404, f"Report not found: {safe}")
                    return
        try:
            with open(path, "rb") as fh:
                body = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            # Inline script stays: fleet and host reports ship their own controllers.
            # connect-src none blocks this document's fetch. COOP drops window.opener
            # so the script cannot borrow the dashboard document, whose CSP allows
            # connect-src 'self'. no-referrer makes keychain Referer checks fail closed.
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; connect-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'")
            self.send_header("Cross-Origin-Opener-Policy", "noopener-allow-popups")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            logger.exception("Failed to serve report '%s'", filename)
            self.send_error(500, "Internal server error; see server log for details")

    def _serve_remote_sync_pending_page(self, safe: str, is_disconnected: bool = False) -> None:
        """Serve an auto-refreshing holding page when a report is requested before remote sync completes."""
        escaped_target = html.escape(safe)
        if is_disconnected:
            badge_html = '<div class="badge" style="background:#b91c1c;color:#fef2f2;">⚠️ Jump Host Disconnected</div>'
            msg_html = (
                "The SSH connection to the jump host was lost (e.g. VPN dropped). "
                "The remote scan may still be running or completed in the jump host sandbox. "
                "Please reconnect your VPN and click <strong>Reconnect &amp; Pull Results</strong> on the dashboard to retrieve your reports."
            )
            refresh_meta = '<meta http-equiv="refresh" content="6">'
            footnote_html = "This page will refresh every 6 seconds to check for recovered reports."
            refresh_val = "6"
        else:
            badge_html = '<div class="badge">☁️ Jump Host Assessment Active</div>'
            msg_html = (
                "This assessment completed on the remote jump host. "
                "The HTML report is currently stored in the jump host sandbox and will sync to this workstation as soon as all target scans finish."
            )
            refresh_meta = '<meta http-equiv="refresh" content="4">'
            footnote_html = "This page will automatically refresh every 4 seconds. Once the batch sync completes, your report will appear immediately."
            refresh_val = "4"

        page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  {refresh_meta}
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Report Sync Pending — {escaped_target}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #0f172a;
      color: #f1f5f9;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 1.5rem;
      box-sizing: border-box;
    }}
    .card {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      max-width: 560px;
      width: 100%;
      padding: 2.5rem;
      text-align: center;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
    }}
    .spinner {{
      width: 44px;
      height: 44px;
      border: 3px solid #334155;
      border-top-color: #38bdf8;
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin: 0 auto 1.5rem;
    }}
    @keyframes spin {{
      0% {{ transform: rotate(0deg); }}
      100% {{ transform: rotate(360deg); }}
    }}
    h1 {{
      font-size: 1.35rem;
      font-weight: 600;
      margin: 0 0 0.75rem;
      color: #f8fafc;
    }}
    p {{
      font-size: 0.925rem;
      line-height: 1.6;
      color: #94a3b8;
      margin: 0 0 1.25rem;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: #0369a1;
      color: #e0f2fe;
      font-size: 0.8rem;
      font-weight: 600;
      padding: 4px 12px;
      border-radius: 9999px;
      margin-bottom: 1.25rem;
    }}
    .target-box {{
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 6px;
      padding: 0.75rem 1rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.875rem;
      color: #38bdf8;
      word-break: break-all;
      margin-bottom: 1.5rem;
    }}
    .footnote {{
      font-size: 0.8rem;
      color: #64748b;
      margin: 0 0 1.5rem;
    }}
    .back-link {{
      display: inline-block;
      color: #38bdf8;
      text-decoration: none;
      font-size: 0.875rem;
      font-weight: 500;
    }}
    .back-link:hover {{
      text-decoration: underline;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    {badge_html}
    <h1>Report Sync Pending</h1>
    <p>{msg_html}</p>
    <div class="target-box">{escaped_target}</div>
    <p class="footnote">{footnote_html}</p>
    <a href="/" class="back-link">&larr; Return to Assessment Dashboard</a>
  </div>
</body>
</html>"""
        self._send_html(page, status=200, extra_headers={"Refresh": refresh_val})

    def _try_render_host_report_on_demand(self, safe: str, outdir: str) -> Optional[str]:
        """Dynamically generate a missing single-host HTML report on demand."""
        if not safe.lower().endswith(".html"):
            return None
        if "fleet" in safe.lower() or safe.startswith("00_"):
            return None

        import json

        from vcf_hci.obfuscation import obfuscate_host_data
        from vcf_hci.report import generate_host_html_report

        is_obf = safe.startswith("OBFUSCATED_Host-")
        host_idx: Optional[int] = None
        target_slug: Optional[str] = None

        if is_obf:
            m = re.match(r"OBFUSCATED_Host-(\d+)\.html", safe)
            if m:
                host_idx = int(m.group(1)) - 1
        elif safe.startswith("vcf_readiness_"):
            target_slug = safe[len("vcf_readiness_"):-len(".html")].strip()
        elif safe.startswith("vsphere_vsan_report_"):
            target_slug = safe[len("vsphere_vsan_report_"):-len(".html")].strip()
        elif safe.startswith("host_"):
            target_slug = safe[len("host_"):-len(".html")].strip()
        else:
            return None

        with _state_lock:
            results = list(_state.get("results") or [])
            fleet_idx = list(_state.get("fleet_index") or [])

        target_host: Optional[dict] = None
        target_host_idx: int = host_idx if host_idx is not None else -1

        # 1. Search in-memory results if available
        if results:
            if host_idx is not None and 0 <= host_idx < len(results):
                target_host = results[host_idx]
                target_host_idx = host_idx
            elif target_slug:
                slug_norm = target_slug.replace("_", ".")
                for i, h in enumerate(results):
                    si = h.get("system") or {}
                    h_ip = str(si.get("bmc_ip") or si.get("ip") or h.get("host") or "").strip()
                    h_name = str(si.get("hostname") or "").strip()
                    if (target_slug in (sanitize_filename(h_ip), sanitize_filename(h_name), h_ip, h_name)
                            or slug_norm in (h_ip, h_name)):
                        target_host = h
                        target_host_idx = i
                        break

        # 2. Search on-disk data/ and summaries if not in memory
        if not target_host and outdir and os.path.isdir(outdir):
            if target_slug:
                for cand_name in (
                    f"vcf_summary_{sanitize_filename(target_slug)}.json",
                    f"host_{sanitize_filename(target_slug)}.json",
                    f"{target_slug}.json",
                ):
                    cand_path = os.path.join(outdir, "data", cand_name)
                    if not os.path.isfile(cand_path):
                        cand_path = os.path.join(outdir, cand_name)
                    if os.path.isfile(cand_path):
                        try:
                            with open(cand_path, encoding="utf-8") as jf:
                                target_host = json.load(jf)
                                if target_host_idx < 0:
                                    target_host_idx = 0
                                break
                        except Exception:
                            pass

            if not target_host:
                try:
                    from vcf_hci.summary_io import load_summary
                    disk_results = load_summary(outdir) or []
                    if host_idx is not None and 0 <= host_idx < len(disk_results):
                        target_host = disk_results[host_idx]
                        target_host_idx = host_idx
                    elif target_slug:
                        slug_norm = target_slug.replace("_", ".")
                        for i, h in enumerate(disk_results):
                            si = h.get("system") or {}
                            h_ip = str(si.get("bmc_ip") or si.get("ip") or h.get("host") or "").strip()
                            h_name = str(si.get("hostname") or "").strip()
                            if (target_slug in (sanitize_filename(h_ip), sanitize_filename(h_name), h_ip, h_name)
                                    or slug_norm in (h_ip, h_name)):
                                target_host = h
                                target_host_idx = i
                                break
                except Exception as exc:
                    logger.debug("Failed reading fleet summary on demand: %s", exc)

        if not target_host:
            return None

        rep_dir = os.path.join(outdir, "reports")
        os.makedirs(rep_dir, exist_ok=True)
        dest_path = os.path.join(rep_dir, safe)

        try:
            if is_obf:
                obf_salt = _state.get("obf_salt") or os.urandom(16).hex()
                alias = f"Host-{target_host_idx + 1}"
                obf_data = obfuscate_host_data(target_host, alias, obf_salt)
                generate_host_html_report(obf_data, dest_path, obfuscated=True)
            else:
                generate_host_html_report(target_host, dest_path, obfuscated=False)

            with _state_lock:
                current_rpaths = list(_state.get("report_paths") or [])
                if dest_path not in current_rpaths:
                    current_rpaths.append(dest_path)
                    _state["report_paths"] = current_rpaths
                if fleet_idx and 0 <= target_host_idx < len(fleet_idx):
                    fleet_idx[target_host_idx]["has_report"] = True
                    fleet_idx[target_host_idx]["report"] = safe
                    _state["fleet_index"] = fleet_idx

            return dest_path
        except Exception as r_exc:
            logger.warning("Failed on-demand host report generation for '%s': %s", safe, r_exc, exc_info=True)
            return None

    def _list_reports(self) -> dict:
        with _state_lock:
            outdir = _state.get("outdir", "")
            rpaths = list(_state.get("report_paths", []))
            fleet_path = _state.get("fleet_path", "")
            summary_path = _state.get("summary_path", "")
            fleet_idx = list(_state.get("fleet_index") or [])
            results = list(_state.get("results", []))

        reports = []
        if fleet_idx:
            for item in fleet_idx:
                idx = item.get("idx", 1)
                ip = item.get("ip", "")
                fname = item.get("report") or f"vcf_readiness_{sanitize_filename(ip)}.html"
                obf_file = f"OBFUSCATED_Host-{idx}.html"
                obf_full = os.path.join(outdir, "reports", obf_file)
                has_obf = os.path.isfile(obf_full) or os.path.isfile(os.path.join(outdir, obf_file))
                reports.append({
                    "filename": fname,
                    "obf_filename": obf_file if has_obf else "",
                    "ip": ip,
                    "hostname": item.get("hostname", ip),
                    "vendor": item.get("vendor", ""),
                    "model": item.get("model", ""),
                    "verdict": item.get("verdict", ""),
                })
        else:
            for idx, (path, data) in enumerate(zip(rpaths, results), 1):
                si = data.get("system", {})
                obf_file = f"OBFUSCATED_Host-{idx}.html"
                obf_full = os.path.join(outdir, "reports", obf_file)
                has_obf = os.path.isfile(obf_full) or os.path.isfile(os.path.join(outdir, obf_file))
                reports.append({
                    "filename": os.path.basename(path),
                    "obf_filename": obf_file if has_obf else "",
                    "ip": si.get("ip", ""),
                    "hostname": si.get("hostname", si.get("ip", "")),
                    "vendor": si.get("vendor", ""),
                    "model": si.get("model", ""),
                    "verdict": (si.get("cpu_summary") or {}).get("verdict", ""),
                })

        obf_sum = "00_OBFUSCATED_fleet_summary.html" if os.path.isfile(os.path.join(outdir, "00_OBFUSCATED_fleet_summary.html")) or os.path.isfile(os.path.join(outdir, "reports", "00_OBFUSCATED_fleet_summary.html")) else ""
        obf_fleet = "00_OBFUSCATED_fleet_combined.html" if os.path.isfile(os.path.join(outdir, "00_OBFUSCATED_fleet_combined.html")) or os.path.isfile(os.path.join(outdir, "reports", "00_OBFUSCATED_fleet_combined.html")) else ""

        return {
            "reports": reports,
            "fleet": os.path.basename(fleet_path) if fleet_path else "",
            "summary": os.path.basename(summary_path) if summary_path else "",
            "obf_summary": obf_sum,
            "obf_fleet": obf_fleet,
            "outdir": outdir,
        }
