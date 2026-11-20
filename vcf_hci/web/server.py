"""
VCF Readiness Tool — Browser UI HTTP Server (vcf_hci.web.server)

A stdlib-only ThreadingHTTPServer bound to 127.0.0.1 by default.
A non-loopback bind, or --allow-remote, listens with TLS 1.2+ only.
  • Serves the Clarity-styled single-page app
  • Exposes a JSON / SSE API for running scans in background threads
  • Persists profiles and session state to ~/.vcf-readiness-*.json
  • Serves generated HTML reports as static files
  • Handles Excel export and combined tabbed report generation

No external dependencies — stdlib only:
    http.server, socketserver, threading, queue, gzip, base64, json, ssl, subprocess
"""

import argparse
import base64
import gzip
import hashlib
import json
import logging
import os
import re
import secrets
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Optional, Set

logger = logging.getLogger("vcf_assess")

# ── Collector imports ────────────────────────────────────────────────────────
from vcf_hci.constants import TOOL_VERSION
from vcf_hci.fleet_library import assemble_fleet, discover_scans, write_scan_manifest  # noqa: F401
from vcf_hci.logging_utils import get_default_output_dir, is_root_user
from vcf_hci.plugins.mtat_runtime import RuntimeManager
from vcf_hci.plugins.vdt import default_plugin_root, discover_vdt
from vcf_hci.report.csv_export import generate_fleet_summary_csv  # noqa: F401
from vcf_hci.report.excel_export import (  # noqa: F401
    _build_excel_sheets,
    _write_xlsx,
)
from vcf_hci.report.fleet.combined import _generate_combined_html  # noqa: F401
from vcf_hci.scan import scan_hosts  # noqa: F401
from vcf_hci.web import vault_session
from vcf_hci.web.api_mixin import ApiMixin
from vcf_hci.web.desktop import (  # noqa: F401
    _browse_folder_dialog,
    _is_safe_desktop_folder,
    _open_folder_in_desktop,
)
from vcf_hci.web.group_api import GroupApiMixin
from vcf_hci.web.hcl_export_api import HclExportApiMixin
from vcf_hci.web.mtat_api import MtatApiMixin
from vcf_hci.web.plugin_api import PluginApiMixin
from vcf_hci.web.remote_vdt_api import RemoteVdtApiMixin, cancel_remote_jobs
from vcf_hci.web.scan_worker import (  # noqa: F401
    _broadcast,
    _cancel_event,
    _get_active_hcl_metadata,
    _handle_host_done,
    _handle_host_stage,
    _handle_host_start,
    _regenerate_fleet_artifacts,
    _run_scan_worker,
    _shutdown_event,
    _sse_clients,
    _state,
    _state_lock,
    set_custom_hcl_bundle,
)
from vcf_hci.web.session_store import (  # noqa: F401
    PROFILE_FILE,
    SESSION_FILE,
    _load_profiles,
    _load_session,
    _sanitize_session_dict,
    _save_profiles,
    _save_session,
    _SecretStore,
)
from vcf_hci.web.update_check import ReleaseUpdateChecker
from vcf_hci.web.vdt_setup_api import VdtSetupApiMixin
from vcf_hci.web.vinv_api import UPLOAD_BODY_LIMIT as _VINV_UPLOAD_BODY_LIMIT
from vcf_hci.web.vinv_api import VinvApiMixin, VinvLibrary

_COLLECTOR_OK = True

# ── Clarity CSS asset ─────────────────────────────────────────────────────────
try:
    from vcf_hci.web.assets import CLARITY_CSS_GZ_B64
    _CLARITY_CSS: bytes = gzip.decompress(base64.b64decode(CLARITY_CSS_GZ_B64))
except Exception:
    _CLARITY_CSS = b""

# ── Server security state ────────────────────────────────────────────────────
# One-time browser bootstrap secret. It is not a session and not an API credential.
_LAUNCH_TOKEN = secrets.token_hex(16)
_LAUNCH_SESSION: Optional[str] = None
_LAUNCH_REDEEMED_AT: float = 0.0
_LAUNCH_CLOSED = False
# A lost redirect can retry the same URL briefly. After this, or after the
# browser presents the session cookie, the launch token is dead.
_LAUNCH_GRACE_SEC = 5.0
_session_lock = threading.Lock()
_VALID_SESSIONS: Set[str] = set()
_SERVER_BIND_TOKEN: str = _LAUNCH_TOKEN
_OEM_MODE = False
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_WILDCARD_HOSTS = frozenset({"0.0.0.0", "::", ""})
_TOKEN_QUERY_RE = re.compile(r"(token=)[^&\s\"']+")


def listener_requires_tls(bind_host: str, allow_remote: bool) -> bool:
    """True when the UI can be reached by something other than a loopback client.

    ``--allow-remote`` widens Host and Origin checks even if the bind address
    is loopback, so that flag requires TLS too.
    """
    host = (bind_host or "").strip().lower()
    if allow_remote:
        return True
    return host not in _LOOPBACK_HOSTS


def _normalise_host(host: str) -> str:
    """Return a lower-case hostname/IP without a port, brackets, or one trailing dot."""
    raw = str(host or "").strip()
    if not raw:
        return ""
    if raw.startswith("["):
        try:
            name = urllib.parse.urlparse("//" + raw).hostname or ""
        except ValueError:
            return ""
    elif raw.count(":") == 1:
        name = raw.split(":", 1)[0]
    else:
        name = raw
    name = name.lower()
    return name[:-1] if name.endswith(".") else name


def _certificate_san_names(cert_path: str) -> set:
    """Read DNS and IP subjectAltName values from the listener certificate."""
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is None:
        raise ValueError("This Python build cannot inspect the listener certificate names")
    try:
        decoded = decoder(cert_path)
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise ValueError("Could not read subjectAltName values from the listener certificate") from exc
    names = set()
    for kind, value in decoded.get("subjectAltName", ()):
        if kind in ("DNS", "IP Address"):
            name = _normalise_host(value)
            if name:
                names.add(name)
    return names


def _remote_gate_gap(bind_host: str, allow_remote: bool) -> bool:
    host = (bind_host or "").strip().lower()
    return (
        listener_requires_tls(bind_host, allow_remote)
        and not allow_remote
        and host not in (_LOOPBACK_HOSTS | _WILDCARD_HOSTS)
    )


def _indented_warning(message: str) -> str:
    return "  " + message.replace("\n", "\n  ")


def _remote_gate_gap_warning(bind_host: str) -> str:
    return (
        "[!] WARNING: This listener is reachable over HTTPS, but remote-mode gates remain local.\n"
        f"    Bind {bind_host} is not loopback, and --allow-remote was not set.\n"
        "    The credential vault, OS keychain, desktop folder chooser, saved plug-in credentials,\n"
        "    and MTAT package install / upstream bridge remain available as on a local listener.\n"
        "    Bind 127.0.0.1 to remove this exposure. --allow-remote applies the remote gates;\n"
        "    it is not the recommended headless setup. Prefer the SSH local forward in docs/INSTALL.md:\n"
        "      ssh -L 7182:127.0.0.1:7182 user@server\n"
        "      python3 vcfr_web.py --no-browser"
    )


def _allow_remote_warning(allowed_names: set) -> str:
    names_text = ", ".join(sorted(allowed_names))
    return (
        "[!] WARNING: --allow-remote is an opt-in and is not the recommended headless setup.\n"
        "    Prefer a loopback bind and the SSH local forward in docs/INSTALL.md.\n"
        f"    Accepted Host names: {names_text}"
    )


def tls_material_error(
    bind_host: str,
    allow_remote: bool,
    tls_cert: Optional[str],
    tls_key: Optional[str],
) -> Optional[str]:
    """Return a startup error when an exposed listener would be plain HTTP."""
    if not listener_requires_tls(bind_host, allow_remote):
        return None
    if not tls_cert or not tls_key:
        return (
            "SECURITY BLOCK: a network-exposed Web UI (--allow-remote, or a --bind "
            "other than 127.0.0.1 / ::1 / localhost) must be HTTPS.\n"
            "      Pass --tls-cert and --tls-key (PEM). Plain HTTP would expose the\n"
            "      one-time launch URL and the session cookie to the network.\n"
            "      Example: python -m vcf_hci.web --bind 0.0.0.0 --allow-remote "
            "--tls-cert ui.crt --tls-key ui.key"
        )
    if not os.path.isfile(tls_cert):
        return f"SECURITY BLOCK: TLS certificate not found: {tls_cert}"
    if not os.path.isfile(tls_key):
        return f"SECURITY BLOCK: TLS private key not found: {tls_key}"
    return None


def cert_fingerprint_sha256(cert_path: str) -> str:
    """SHA-256 fingerprint of the first PEM certificate, colon-separated."""
    with open(cert_path, encoding="ascii", errors="ignore") as fh:
        text = fh.read()
    start = text.find("-----BEGIN CERTIFICATE-----")
    end = text.find("-----END CERTIFICATE-----")
    if start < 0 or end < 0:
        raise ValueError(f"No PEM certificate in {cert_path}")
    end += len("-----END CERTIFICATE-----")
    der = ssl.PEM_cert_to_DER_cert(text[start:end])
    digest = hashlib.sha256(der).hexdigest()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _launch_token_acceptable(query_tok: str) -> bool:
    """True when GET / may still redeem this launch token. Does not mint a session."""
    if not query_tok or not secrets.compare_digest(query_tok, _LAUNCH_TOKEN):
        return False
    with _session_lock:
        if _LAUNCH_CLOSED:
            return False
        if _LAUNCH_SESSION is None:
            return True
        return (time.monotonic() - _LAUNCH_REDEEMED_AT) <= _LAUNCH_GRACE_SEC


def _redeem_launch_token(query_tok: str) -> Optional[str]:
    """Exchange the one-time launch token for a session id.

    A retry inside the grace window returns the same session so a lost redirect
    can complete. The launch token is never itself placed in ``_VALID_SESSIONS``.
    """
    global _LAUNCH_SESSION, _LAUNCH_REDEEMED_AT, _LAUNCH_CLOSED
    if not query_tok or not secrets.compare_digest(query_tok, _LAUNCH_TOKEN):
        return None
    with _session_lock:
        now = time.monotonic()
        if _LAUNCH_CLOSED:
            return None
        if _LAUNCH_SESSION is not None:
            if (now - _LAUNCH_REDEEMED_AT) > _LAUNCH_GRACE_SEC:
                _LAUNCH_CLOSED = True
                return None
            return _LAUNCH_SESSION
        session = secrets.token_hex(24)
        _VALID_SESSIONS.add(session)
        _LAUNCH_SESSION = session
        _LAUNCH_REDEEMED_AT = now
        return session


def _session_is_known(token: str) -> bool:
    """True if ``token`` is a live session.

    Presenting the session that was minted from the launch token retires the
    launch token immediately, including during the grace window.
    """
    global _LAUNCH_CLOSED
    if not token:
        return False
    with _session_lock:
        matched = False
        for tok in _VALID_SESSIONS:
            if secrets.compare_digest(token, tok):
                matched = True
                break
        if not matched:
            return False
        if _LAUNCH_SESSION is not None and secrets.compare_digest(token, _LAUNCH_SESSION):
            _LAUNCH_CLOSED = True
        return True


# =============================================================================
# HTTP Server & Request Handler
# =============================================================================
class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    vdt_plugin: dict
    vdt_lock: Any
    vdt_sessions: dict
    vdt_plugin_root: str
    vdt_remote_jobs: dict

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        bind_and_activate=True,
        bind_host="127.0.0.1",
        allow_remote=False,
        allow_hosts=None,
    ):
        self.bind_host = bind_host
        self.allow_remote = allow_remote
        self.allow_hosts = {_normalise_host(value) for value in (allow_hosts or set()) if _normalise_host(value)}
        self.cert_san_names = set()
        self.tls_enabled = False
        self.update_checker = ReleaseUpdateChecker(TOOL_VERSION)
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def server_close(self):
        if hasattr(self, 'mtat_runtime'):
            self.mtat_runtime.close()
        cancel_remote_jobs(self, wait=25)
        super().server_close()

    def handle_error(self, request, client_address):
        exc_type, exc_val, _ = sys.exc_info()
        if exc_type in (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            logger.debug("Client disconnected (%s): %s", client_address, exc_val)
            return
        super().handle_error(request, client_address)


class AppHandler(GroupApiMixin, HclExportApiMixin, VdtSetupApiMixin, RemoteVdtApiMixin, MtatApiMixin, VinvApiMixin, PluginApiMixin, ApiMixin, BaseHTTPRequestHandler):
    server_version = f"VCFReadiness/{TOOL_VERSION}"

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass

    def log_message(self, format: str, *args: Any) -> None:  # suppress default access log → use our logger
        try:
            msg = "HTTP " + (format % args)
        except Exception:
            msg = f"HTTP {format} {args}"
        msg = _TOKEN_QUERY_RE.sub(r"\1REDACTED", msg)
        logger.debug(msg)

    def send_header(self, keyword: str, value: str) -> None:
        clean_key = str(keyword).replace("\r", "").replace("\n", "")
        clean_val = str(value).replace("\r", "").replace("\n", "")
        low = clean_key.lower()
        if low == "referrer-policy":
            self._sent_referrer = True
        elif low == "cache-control":
            self._sent_cache = True
        elif low == "x-content-type-options":
            self._sent_nosniff = True
        super().send_header(clean_key, clean_val)

    def end_headers(self) -> None:
        # Cover send_error and other paths that never set these. Do not override
        # an explicit Cache-Control (the CSS asset is intentionally cacheable).
        if not getattr(self, "_sent_referrer", False):
            self._sent_referrer = True
            super().send_header("Referrer-Policy", "no-referrer")
        if not getattr(self, "_sent_cache", False):
            self._sent_cache = True
            super().send_header("Cache-Control", "no-store")
        if not getattr(self, "_sent_nosniff", False):
            self._sent_nosniff = True
            super().send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    # ── Response / Request helpers ───────────────────────────────────────────

    def _send_json(self, obj: dict, status: int = 200, extra_headers: Optional[dict] = None) -> None:
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for k, v in extra_headers.items():
                clean_k = str(k).replace("\r", "").replace("\n", "")
                clean_v = str(v).replace("\r", "").replace("\n", "")
                self.send_header(clean_k, clean_v)
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str, status: int = 200, extra_headers: Optional[dict] = None) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data:; connect-src 'self';")
        if extra_headers:
            for k, v in extra_headers.items():
                clean_k = str(k).replace("\r", "").replace("\n", "")
                clean_v = str(v).replace("\r", "").replace("\n", "")
                self.send_header(clean_k, clean_v)
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    MAX_BODY_SIZE = 32 * 1024 * 1024  # 32 MB cap for JSON bodies (e.g. summary import)

    def _read_json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            return {}
        body_limit = self.MAX_BODY_SIZE
        if getattr(self, "path", "").split("?", 1)[0] in ("/api/plugins/mtat/jobs", "/api/plugins/mtat/preflight"):
            body_limit = 4 * ((32 * 1024 * 1024 + 2) // 3) + 65536
        elif getattr(self, "path", "").split("?", 1)[0] in ("/api/plugins/mtat/upstream/import.upload", "/api/plugins/mtat/upstream/import.chunk"):
            body_limit = 4 * ((16 * 1024 * 1024 + 2) // 3) + 65536
        elif getattr(self, "path", "").split("?", 1)[0] == "/api/plugins/vinv/import":
            body_limit = _VINV_UPLOAD_BODY_LIMIT
        if length <= 0 or length > body_limit:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return {}

    def _get_request_session_token(self) -> Optional[str]:
        cookie_hdr = self.headers.get("Cookie", "") if hasattr(self, "headers") and self.headers else ""
        if cookie_hdr:
            for part in cookie_hdr.split(";"):
                part = part.strip()
                if part.startswith("vcf_session="):
                    return part.split("=", 1)[1].strip()
        return None

    def _query_token(self) -> str:
        parsed = urllib.parse.urlparse(getattr(self, "path", "") or "")
        if not parsed.query:
            return ""
        return urllib.parse.parse_qs(parsed.query).get("token", [""])[0]

    def _session_cookie_header(self, token: str) -> str:
        parts = [f"vcf_session={token}", "Path=/", "HttpOnly", "SameSite=Strict"]
        if getattr(self.server, "tls_enabled", False):
            parts.append("Secure")
        return "; ".join(parts)

    def _current_session(self) -> Optional[str]:
        """Return the presented session id, never the launch token."""
        hdr_token = self.headers.get("X-Server-Token", "").strip() if getattr(self, "headers", None) else ""
        if hdr_token and _session_is_known(hdr_token):
            return hdr_token
        cookie_tok = self._get_request_session_token()
        if cookie_tok and _session_is_known(cookie_tok):
            return cookie_tok
        return None

    def _is_authenticated(self) -> bool:
        return self._current_session() is not None

    def _send_auth_error(self, status: int, message: str) -> None:
        body = (message + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _redirect_strip_token(self, cookie_hdr: str) -> None:
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", cookie_hdr)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _request_host_name(self) -> str:
        """Hostname from the Host header, without port or brackets."""
        raw = self.headers.get("Host", "").strip() if hasattr(self, "headers") and self.headers else ""
        if not raw:
            return ""
        return _normalise_host(raw)

    def _host_matches_request(self, hostname: str) -> bool:
        """True when hostname is this request's Host, or an explicit allow_hosts entry."""
        h = _normalise_host(hostname)
        if not h:
            return False
        req = self._request_host_name()
        if req and h == req:
            return True
        allow_hosts = getattr(self.server, "allow_hosts", set()) or set()
        return h in {_normalise_host(ah) for ah in allow_hosts}

    def _is_allowed_origin(self, origin: str) -> bool:
        if not origin:
            return False
        try:
            parsed = urllib.parse.urlparse(origin)
            if parsed.scheme not in ("http", "https"):
                return False
            h = _normalise_host(parsed.hostname or "")
            if not h:
                return False
            srv_port = getattr(self.server, "server_address", ("127.0.0.1", 0))[1]
            o_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if o_port != srv_port:
                return False
            allow_remote = getattr(self.server, "allow_remote", False)
            if allow_remote:
                # Credentialed CORS must not trust every host that shares this port.
                # SameSite=Strict is a separate cookie attribute, not this check.
                return self._host_matches_request(h)
            bind_host = getattr(self.server, "bind_host", "127.0.0.1")
            actual_host = getattr(self.server, "server_address", ("127.0.0.1", 0))[0]
            allowed = {"127.0.0.1", "localhost"}
            if bind_host and bind_host not in ("0.0.0.0", "::", ""):
                allowed.add(_normalise_host(bind_host))
            if actual_host and actual_host not in ("0.0.0.0", "::", ""):
                allowed.add(_normalise_host(actual_host))
            allow_hosts = getattr(self.server, "allow_hosts", set())
            if allow_hosts:
                allowed.update(_normalise_host(ah) for ah in allow_hosts)
            return h in allowed
        except Exception:
            return False

    def _is_remote_server(self) -> bool:
        bind_host = getattr(self.server, "bind_host", "127.0.0.1")
        allow_remote = getattr(self.server, "allow_remote", False)
        return bool(allow_remote or bind_host in ("0.0.0.0", "::", ""))

    def _cors_headers(self) -> None:
        origin = self.headers.get("Origin", "").strip() if hasattr(self, "headers") and self.headers else ""
        origin = origin.replace("\r", "").replace("\n", "")
        if self._is_allowed_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Server-Token, X-Output-Dir, Content-Disposition, Cookie")
        self.send_header("Vary", "Origin")

    def _validate_request(self) -> bool:
        bind_host = getattr(self.server, "bind_host", "127.0.0.1")
        actual_host = getattr(self.server, "server_address", ("127.0.0.1", 0))[0]
        allow_remote = getattr(self.server, "allow_remote", False)
        allow_hosts = getattr(self.server, "allow_hosts", set())

        def _is_allowed_host(host_str: str) -> bool:
            if not host_str:
                return not listener_requires_tls(bind_host, allow_remote)
            h = _normalise_host(host_str)
            allowed = set()
            if listener_requires_tls(bind_host, allow_remote):
                allowed.update(
                    _normalise_host(value)
                    for value in (bind_host, actual_host)
                    if value and value not in _WILDCARD_HOSTS
                )
                allowed.update(_normalise_host(value) for value in allow_hosts)
                allowed.update(getattr(self.server, "cert_san_names", set()) or set())
                return bool(h) and h in allowed

            allowed.update(_LOOPBACK_HOSTS)
            if bind_host and bind_host not in _WILDCARD_HOSTS:
                allowed.add(_normalise_host(bind_host))
            if actual_host and actual_host not in _WILDCARD_HOSTS:
                allowed.add(_normalise_host(actual_host))
            if allow_hosts:
                allowed.update(_normalise_host(value) for value in allow_hosts)
            return h in allowed

        host = self._request_host_name()
        if not _is_allowed_host(host):
            self.send_error(403, "Forbidden: invalid Host header")
            return False

        origin = self.headers.get("Origin", "").strip() if hasattr(self, "headers") and self.headers else ""
        if origin:
            try:
                if allow_remote:
                    # allow-remote CORS: reflect only the addressed host
                    if not self._is_allowed_origin(origin):
                        self.send_error(403, "Forbidden: invalid Origin header")
                        return False
                else:
                    parsed_origin = urllib.parse.urlparse(origin)
                    if parsed_origin.hostname and not _is_allowed_host(parsed_origin.hostname):
                        self.send_error(403, "Forbidden: invalid Origin header")
                        return False
            except Exception:
                self.send_error(403, "Forbidden: invalid Origin header")
                return False

        referer = self.headers.get("Referer", "").strip() if hasattr(self, "headers") and self.headers else ""
        if referer:
            try:
                if allow_remote:
                    parsed_ref = urllib.parse.urlparse(referer)
                    if parsed_ref.hostname and not self._is_allowed_origin(referer):
                        self.send_error(403, "Forbidden: invalid Referer header")
                        return False
                else:
                    parsed_ref = urllib.parse.urlparse(referer)
                    if parsed_ref.hostname and not _is_allowed_host(parsed_ref.hostname):
                        self.send_error(403, "Forbidden: invalid Referer header")
                        return False
            except Exception:
                self.send_error(403, "Forbidden: invalid Referer header")
                return False

        raw_path = getattr(self, "path", "")
        if not isinstance(raw_path, str):
            raw_path = "/"
        parsed_path = urllib.parse.urlparse(raw_path).path
        cmd = getattr(self, "command", "")

        is_public_get = (
            cmd == "GET" and (
                (parsed_path == "/api/version" and not self._is_remote_server())
                or parsed_path.startswith("/docs")
                or parsed_path.startswith("/assets/")
                or parsed_path in ("/favicon.ico", "/favicon.svg")
            )
        )
        if cmd == "OPTIONS" or is_public_get:
            return True

        if cmd == "GET" and parsed_path == "/":
            if self._is_authenticated():
                return True
            if _launch_token_acceptable(self._query_token()):
                return True
            self._send_auth_error(
                401,
                "Unauthorized: open the one-time launch URL printed at startup. "
                "That URL stops working once the browser session starts."
            )
            return False

        if not self._is_authenticated():
            self.send_error(403, "Forbidden: invalid or missing authentication session cookie or token")
            return False

        return True

    def do_OPTIONS(self) -> None:
        if not self._validate_request():
            return
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    # ── GET dispatcher ────────────────────────────────────────────────────────

    def do_GET(self) -> None:
        if not self._validate_request():
            return
        from vcf_hci.web.app_html import build_app_html
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"

        if path == "/":
            query_tok = self._query_token()
            existing = self._current_session()
            if existing:
                sess_token = existing
            elif query_tok:
                sess_token = _redeem_launch_token(query_tok)
                if not sess_token:
                    self._send_auth_error(
                        401,
                        "Unauthorized: the launch URL has already been used. "
                        "Use the open browser session, or restart the server for a new URL."
                    )
                    return
            else:
                self._send_auth_error(
                    401,
                    "Unauthorized: open the one-time launch URL printed at startup."
                )
                return
            cookie_hdr = self._session_cookie_header(sess_token)
            if query_tok:
                self._redirect_strip_token(cookie_hdr)
                return
            self._send_html(
                build_app_html(TOOL_VERSION, _COLLECTOR_OK, oem_mode=_OEM_MODE, vdt_available=self.server.vdt_plugin["present"]),
                extra_headers={"Set-Cookie": cookie_hdr}
            )

        elif path == "/docs" or path.startswith("/docs/"):
            from vcf_hci.web.docs_html import build_docs_html
            raw_id = urllib.parse.unquote(path[6:]).strip("/") if path.startswith("/docs/") else ""
            doc_id = raw_id if re.match(r"^[a-zA-Z0-9_-]+$", raw_id) else "readme"
            self._send_html(build_docs_html(doc_id, TOOL_VERSION))

        elif path in ("/favicon.ico", "/favicon.svg"):
            from vcf_hci.branding import FAVICON_SVG
            fav_bytes = FAVICON_SVG.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", str(len(fav_bytes)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(fav_bytes)

        elif path == "/assets/clarity.css":
            self.send_response(200)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.send_header("Content-Length", str(len(_CLARITY_CSS)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(_CLARITY_CSS)

        elif path.startswith("/reports/"):
            self._serve_report(urllib.parse.unquote(path[9:]))

        elif path == "/api/scan/events":
            self._sse_scan_events()

        elif path == "/api/scan/status":
            with _state_lock:
                active_copy = {}
                for _ip, _info in _state.get("active_hosts", {}).items():
                    if isinstance(_info, dict):
                        active_copy[_ip] = dict(_info)
                    else:
                        active_copy[_ip] = {"start_time": _info, "stage": "Scanning..."}
                is_remote_scan = bool((_state.get("execution") == "remote") or _state.get("active_remote_scans"))
                results_summary = []
                for r in (_state.get("results") or []):
                    sys_info = r.get("system") or {}
                    results_summary.append({
                        "ip": sys_info.get("ip") or r.get("host") or "",
                        "hostname": sys_info.get("hostname") or sys_info.get("dns_name") or "",
                        "vendor": sys_info.get("vendor") or "",
                        "model": sys_info.get("model") or "",
                        "verdict": (sys_info.get("cpu_summary") or {}).get("verdict") or "",
                        "report": r.get("report") or r.get("filename") or "",
                        "obf_report": r.get("obf_report") or r.get("obf_filename") or "",
                        "partial_scan": bool(r.get("partial_scan")),
                        "partial_stage": r.get("partial_stage") or "",
                        "partial_reason": r.get("partial_reason") or "",
                        "remediation": r.get("remediation"),
                        "is_remote": bool(r.get("is_remote", is_remote_scan)),
                    })
                s = {
                    "scan_id": _state.get("scan_id"),
                    "running": _state.get("running", False),
                    "done": _state.get("done", False),
                    "finalizing": bool(_state.get("_fleet_worker_active") or _state.get("_fleet_operation")),
                    "error": _state.get("error"),
                    "total": _state.get("total", 0),
                    "completed": _state.get("completed", 0),
                    "n_ok": _state.get("n_ok", 0),
                    "execution": _state.get("execution", "local"),
                    "is_remote": is_remote_scan,
                    "is_retry": _state.get("is_retry", False),
                    "is_rescan": bool(_state.get("is_retry", False) or _state.get("is_rescan", False)),
                    "is_import": bool(_state.get("is_import", False)),
                    "had_auto_retry": _state.get("had_auto_retry", False),
                    "active_hosts": active_copy,
                    "fleet_path": _state.get("fleet_path", ""),
                    "summary_path": _state.get("summary_path", ""),
                    "outdir": _state.get("outdir", ""),
                    "zip_path": _state.get("zip_path", ""),
                    "scan_summary": _state.get("scan_summary", ""),
                    "vcf_readiness": _state.get("vcf_readiness", {"supported": 0, "deprecated": 0, "unsupported": 0}),
                    "failed_hosts": _state.get("failed_hosts", []),
                    "partial_hosts": _state.get("partial_hosts", []),
                    "results": results_summary,
                    "disconnected_jump_scan": _state.get("disconnected_jump_scan"),
                }
            self._send_json(s)

        elif path == "/api/reports":
            self._send_json(self._list_reports())

        elif path == "/api/profiles":
            self._send_json(_load_profiles())

        elif path == "/api/groups":
            self._api_groups_get()

        elif path == "/api/session":
            sess = _load_session()
            if _OEM_MODE:
                sess["oem_mode"] = True
            self._send_json(sess)

        elif path == "/api/keychain":
            if self._is_remote_server():
                self._send_json({
                    "available": False,
                    "label": "disabled (remote access enabled)",
                    "remote_disabled": True,
                })
            else:
                self._send_json({"available": _SecretStore.backend() != "none",
                                 "label": _SecretStore.label()})

        elif path == "/api/hcl/export":
            self._api_hcl_export()

        elif path in ("/api/hcl", "/api/hcl/status"):
            self._send_json(_get_active_hcl_metadata())

        elif path == "/api/vault/status":
            self._api_vault_status()

        elif path == "/api/vault/entries":
            self._api_vault_entries()
        elif path == "/api/vault/bmc-pins":
            self._api_vault_bmc_pins()

        elif path == "/api/vault/services":
            self._api_vault_services("list")
        elif path == "/api/vault/jump-hosts":
            self._api_jump_hosts_list()

        elif path == "/api/update":
            self._send_json(self.server.update_checker.snapshot())

        elif path == "/api/version":
            is_root, sudo_user = is_root_user()
            default_outdir = get_default_output_dir()
            self._send_json({
                "version": TOOL_VERSION,
                "collector_ok": _COLLECTOR_OK,
                "is_root": is_root,
                "sudo_user": sudo_user,
                "default_outdir": default_outdir,
            })

        elif path == "/api/plugins":
            self._api_plugins()

        elif path == "/api/plugins/vdt/remote/status":
            self._api_remote_vdt("status")

        elif path == "/api/plugins/vdt/runs":
            self._api_vdt("runs")

        elif path == "/api/plugins/vdt/hybrid":
            self._api_vdt("hybrid")

        elif path == "/api/export-executive":
            self._api_export_executive()

        elif path == "/api/export-summary-json":
            self._api_export_summary_json()

        elif path == "/api/export-excel":
            self._api_export_excel()

        elif path == "/api/export-inventory-excel-obfuscated":
            self._api_export_inventory_excel_obfuscated()

        elif path == "/api/export-obfuscated-zip":
            self._api_export_obfuscated_zip()

        elif path == "/api/export-csv":
            self._api_export_csv()

        elif path == "/api/inspect-cert":
            self._api_inspect_cert()

        elif path == "/api/security/summary":
            self._api_security_summary()

        elif path == "/api/security/findings":
            self._api_security_findings()

        elif path.startswith("/api/security/host/"):
            host_id = path[len("/api/security/host/"):]
            self._api_security_host(host_id)

        elif path == "/api/fleet/discover":
            self._api_fleet_discover()

        elif path == "/api/fleet/index":
            self._api_fleet_index()

        elif path == "/metrics":
            self._serve_prometheus_metrics(parsed.query)

        elif path == "/api/plugins/mtat":
            self._api_mtat_catalog()
        elif path.startswith("/api/plugins/mtat/jobs/"):
            self._api_mtat_job_get(path)
        elif path == "/api/plugins/vinv":
            self._api_vinv_catalog()
        elif path.startswith("/api/plugins/vinv/jobs/"):
            self._api_vinv_job_get(self.path)
        elif path == "/api/plugins/vinv/library" or path.startswith("/api/plugins/vinv/library/"):
            self._api_vinv_library_get(self.path)
        elif path == "/api/plugins/vinv/reconciled/fleet.html":
            self._api_vinv_reconciled_fleet()

        else:
            self.send_error(404)

    def _serve_prometheus_metrics(self, query: str) -> None:
        """Serve Prometheus metrics exposition format (version 0.0.4)."""
        from vcf_hci.telemetry_exporter import render_assessment_metrics, render_fleet_metrics
        params = urllib.parse.parse_qs(query or "")
        target = params.get("target", [None])[0]

        with _state_lock:
            results = list(_state.get("results") or [])

        if target:
            matched = [
                r for r in results
                if str((r.get("system") or {}).get("ip") or r.get("host") or r.get("ip") or "") == str(target)
            ]
            if matched:
                content = render_fleet_metrics(matched)
            else:
                content = render_assessment_metrics({"ip": target, "timed_out": True}, target_ip=target)
        else:
            content = render_fleet_metrics(results)

        body = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── POST dispatcher ───────────────────────────────────────────────────────

    def do_POST(self) -> None:
        if not self._validate_request():
            return
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path.rstrip("/")

        if path == "/api/plugins/vdt/install":
            self._api_vdt_install()
        elif path == "/api/plugins/mtat/install":
            self._api_mtat_install()
        elif path.startswith("/api/plugins/mtat/upstream/"):
            self._api_mtat_upstream(path.rsplit('/', 1)[-1])
        elif path == "/api/plugins/vdt/discover":
            self._api_vdt_discover()
        elif path in ("/api/plugins/vdt/remote/probe", "/api/plugins/vdt/remote/preflight", "/api/plugins/vdt/remote/run", "/api/plugins/vdt/remote/cancel"):
            self._api_remote_vdt(path.rsplit("/", 1)[-1])
        elif path in ("/api/plugins/vdt/import", "/api/plugins/vdt/remove", "/api/plugins/vdt/clear"):
            self._api_vdt(path.rsplit("/", 1)[-1])
        elif path == "/api/groups":
            self._api_groups_post()
        elif path == "/api/scan":
            self._api_scan()
        elif path == "/api/scan/preflight":
            self._api_scan_preflight()
        elif path == "/api/scan/kill_active":
            self._api_scan_kill_active()
        elif path == "/api/scan/reconnect":
            self._api_scan_reconnect()
        elif path in ("/api/scan/skip_host", "/api/scan/skip"):
            self._api_skip_host()
        elif path == "/api/cancel":
            self._api_cancel()
        elif path == "/api/discover":
            self._api_discover()
        elif path in ("/api/test-creds", "/api/test-creds-batch"):
            self._api_test_creds()
        elif path == "/api/inspect-cert":
            self._api_inspect_cert()
        elif path == "/api/profiles":
            self._api_save_profile()
        elif path == "/api/session":
            self._api_save_session()
        elif path == "/api/export-excel":
            self._api_export_excel()
        elif path == "/api/export-inventory-excel-obfuscated":
            self._api_export_inventory_excel_obfuscated()
        elif path == "/api/export-obfuscated-zip":
            self._api_export_obfuscated_zip()
        elif path == "/api/export-csv":
            self._api_export_csv()
        elif path == "/api/export-executive":
            self._api_export_executive()

        elif path == "/api/export-summary-json":
            self._api_export_summary_json()
        elif path == "/api/import-summary":
            self._api_import_summary()
        elif path == "/api/import-summary-file":
            self._api_import_summary_file()
        elif path == "/api/import-hcl":
            self._api_import_hcl()
        elif path in ("/api/hcl/refresh", "/api/refresh-hcl"):
            self._api_refresh_hcl()
        elif path == "/api/browse-folder":
            self._api_browse_folder()
        elif path == "/api/open-folder":
            self._api_open_folder()
        elif path == "/api/keychain/store":
            self._api_keychain_store()
        elif path == "/api/keychain/retrieve":
            self._api_keychain_retrieve()
        elif path == "/api/vault/create":
            self._api_vault_create()
        elif path == "/api/vault/unlock":
            self._api_vault_unlock()
        elif path == "/api/vault/lock":
            self._api_vault_lock()
        elif path == "/api/vault/entries":
            self._api_vault_set_entry()
        elif path == "/api/vault/bmc-pins":
            self._api_vault_bmc_pins(save=True)
        elif path == "/api/vault/services":
            self._api_vault_services("save")
        elif path == "/api/vault/services/remove":
            self._api_vault_services("remove")
        elif path == "/api/vault/services/trust":
            self._api_vault_services("trust")
        elif path == "/api/vault/remove":
            self._api_vault_remove()
        elif path == "/api/vault/import-csv":
            self._api_vault_import_csv()
        elif path == "/api/vault/coverage":
            self._api_vault_coverage()
        elif path == "/api/vault/jump-hosts":
            self._api_jump_hosts_save()
        elif path == "/api/vault/jump-hosts/subnets":
            self._api_jump_hosts_subnets()
        elif path == "/api/vault/jump-hosts/remove":
            self._api_jump_hosts_remove()
        elif path == "/api/vault/jump-hosts/test":
            self._api_jump_hosts_test()
        elif path == "/api/vault/jump-hosts/probe-key":
            self._api_jump_hosts_probe_key()
        elif path == "/api/fleet/discover":
            self._api_fleet_discover()
        elif path == "/api/fleet/assemble":
            self._api_fleet_assemble()
        elif path == "/api/fleet/prerender":
            self._api_fleet_prerender()
        elif path in ("/api/fleet/ingest", "/api/v1/fleet/ingest"):
            self._api_fleet_ingest()
        elif path == "/api/shutdown":
            cancel_remote_jobs(self.server)
            _cancel_event.set()
            vault_session.lock()
            self._send_json({"ok": True})
            threading.Thread(target=lambda: (time.sleep(0.3),
                                             _shutdown_event.set()), daemon=True).start()
        elif path == "/api/plugins/mtat/preflight":
            self._api_mtat_preflight()
        elif path == "/api/wizard/artifacts":
            from vcf_hci.web.wizard_artifacts import save_artifacts
            save_artifacts(self)
        elif path == "/api/plugins/mtat/jobs":
            self._api_mtat_jobs_post()
        elif path.startswith("/api/plugins/mtat/jobs/") and path.endswith("/cancel"):
            self._api_mtat_cancel(path)
        elif path == "/api/plugins/vinv/preflight":
            self._api_vinv_preflight()
        elif path == "/api/plugins/vcenter-check":
            from vcf_hci.web.vcenter_check_api import handle_vcenter_check
            handle_vcenter_check(self)
        elif path == "/api/plugins/esxi-usb/targets":
            from vcf_hci.web.esxi_usb_api import handle_esxi_targets
            handle_esxi_targets(self)
        elif path == "/api/plugins/esxi-usb/jobs":
            from vcf_hci.web.esxi_usb_api import handle_esxi_scan
            handle_esxi_scan(self)
        elif path == "/api/plugins/vinv/jobs":
            self._api_vinv_jobs_post()
        elif path.startswith("/api/plugins/vinv/jobs/") and path.endswith("/cancel"):
            self._api_vinv_cancel(path)
        elif path == "/api/plugins/vinv/import":
            self._api_vinv_import()
        elif path.startswith("/api/plugins/vinv/saved/"):
            self._api_vinv_saved_post(path)
        elif path == "/api/plugins/vinv/detach" or path.startswith("/api/plugins/vinv/library/"):
            self._api_vinv_library_post(path)

        else:
            self.send_error(404)

    # ── DELETE dispatcher ─────────────────────────────────────────────────────

    def do_DELETE(self) -> None:
        if not self._validate_request():
            return
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path
        if path.startswith("/api/profiles/"):
            name = urllib.parse.unquote(path[14:])
            profiles = _load_profiles()
            if name in profiles:
                del profiles[name]
                _save_profiles(profiles)
                _SecretStore.delete(f"profile:{name}")
            self._send_json({"ok": True})
        elif path == "/api/hcl":
            with _state_lock:
                _state["custom_hcl_bundle_path"] = None
                _state["hcl_bundle_metadata"] = None
            self._send_json({"ok": True})
        else:
            self.send_error(404)


# =============================================================================
# Public server factory & main
# =============================================================================
def make_server(
    port: int = 7182,
    host: str = "127.0.0.1",
    allow_remote: bool = False,
    allow_hosts: Optional[set] = None,
    tls_cert: Optional[str] = None,
    tls_key: Optional[str] = None,
    plugins_dir: Optional[str] = None,
    cert_san_names: Optional[set] = None,
) -> _ThreadingHTTPServer:
    """Create a ThreadingHTTPServer bound to the given host and port.

    When ``tls_cert`` and ``tls_key`` are set, the listening socket is wrapped
    with TLS 1.2+ and ``server.tls_enabled`` is True.
    """
    server = _ThreadingHTTPServer(
        (host, port),
        AppHandler,
        bind_host=host,
        allow_remote=allow_remote,
        allow_hosts=allow_hosts,
    )
    server.vdt_plugin = discover_vdt(plugins_dir)
    server.vdt_lock = threading.Lock()
    server.vdt_sessions = {}
    server.mtat_lock = threading.Lock()
    # Session-keyed for future multi-session hardening; beta still mints one session.
    server.mtat_job = {}
    server.vdt_plugin_root = os.path.abspath(plugins_dir) if plugins_dir is not None else str(default_plugin_root())
    server.mtat_runtime = RuntimeManager(Path(server.vdt_plugin_root))
    # Jobs carry session ownership; per-session busy checks are future hardening while beta still mints one session.
    server.vdt_remote_jobs = {}
    server.experimental_mtat = True
    server.experimental_vinv = True
    server.cert_san_names = set(cert_san_names or ())
    server.vinv_lock = threading.Lock()
    # Session-keyed for future multi-session hardening; beta still mints one session.
    server.vinv_job = {}
    server.vinv_library = VinvLibrary()
    if tls_cert and tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
        except Exception:
            server.server_close()
            raise
        server.tls_enabled = True
    return server


def _find_free_port(preferred: int = 7182, host: str = "127.0.0.1") -> int:
    """Return ``preferred`` if available on ``host``, else a random free port."""
    ports = [preferred] + list(range(preferred + 1, preferred + 68))
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                return port
        except OSError:
            continue
    # Fallback: let the OS pick
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, 0))
        return s.getsockname()[1]


def _configure_console_output() -> None:
    """Keep startup diagnostics usable with legacy Windows redirected streams."""
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")


def main() -> None:
    """Main entry point for the VCF Readiness Browser UI server."""
    _configure_console_output()
    parser = argparse.ArgumentParser(
        description="VCF Readiness Assessment Tool — Browser UI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--port", "-p", type=int, default=7182, help="Port to bind HTTP server to (default: 7182)"
    )
    parser.add_argument(
        "--bind", "-b", type=str, default="127.0.0.1",
        help=("IP interface to bind (default: 127.0.0.1). A non-loopback bind requires TLS; "
              "without --allow-remote, a warning explains that local-mode gates stay local."),
    )
    parser.add_argument(
        "--no-browser", action="store_true", help="Do not automatically open the default web browser"
    )
    parser.add_argument(
        "--import-hcl", type=str, default=None, help="Path to offline air-gapped dark-site HCL zip bundle"
    )
    parser.add_argument(
        "--allow-remote", action="store_true",
        help=("Opt in to remote access; not the recommended headless setup. Prefer a loopback bind "
              "and the SSH forward in docs/INSTALL.md. Requires --tls-cert and --tls-key."),
    )
    parser.add_argument(
        "--allow-host", action="append", default=[], metavar="HOST",
        help="Additional Host name accepted by an exposed HTTPS listener; repeat for each name.",
    )
    parser.add_argument(
        "--tls-cert", type=str, default=None, help="PEM certificate for the Web UI listener. Required with --allow-remote or a non-loopback --bind."
    )
    parser.add_argument(
        "--tls-key", type=str, default=None, help="PEM private key matching --tls-cert. Required with --allow-remote or a non-loopback --bind."
    )
    parser.add_argument(
        "--oem", action="store_true", help="Launch in OEM Import Mode: presets deep Redfish crawl, raw JSON capture, and 15m timeouts"
    )
    parser.add_argument(
        "--crawl", "--crawl-endpoints", action="store_true", dest="crawl", help="Launch with deep Redfish crawling enabled by default"
    )
    parser.add_argument("--plugins-dir", default=None, help="Optional plugin folder (default: Plugins beside the source or executable)")
    parser.add_argument(
        "--nvme-namespace-preview", action="store_true",
        help="Include TLC RI 1 DWPD ESA drive tags and NVMe namespace sizing Help (default: off)",
    )
    parser.add_argument(
        "--no-hcl-auto-refresh", action="store_true",
        help="Keep startup HCL data offline; disable the background public BCG refresh",
    )
    args = parser.parse_args()
    from vcf_hci.hcl.memory_tiering import PREVIEW_ENV
    if args.nvme_namespace_preview:
        os.environ[PREVIEW_ENV] = "1"
    else:
        os.environ.pop(PREVIEW_ENV, None)

    # Safety check: Prevent accidental wildcard network exposures unless --allow-remote is provided
    if args.bind in ("0.0.0.0", "::", "") and not args.allow_remote:
        print(
            f"\n  [✗] SECURITY BLOCK: Binding to wildcard interface '{args.bind}' exposes the web assessment UI to the entire local network.\n"
            "      To explicitly allow remote connections, pass the '--allow-remote' flag.\n"
            "      Example: python -m vcf_hci.web --bind 0.0.0.0 --allow-remote "
            "--tls-cert ui.crt --tls-key ui.key\n",
            file=sys.stderr,
        )
        sys.exit(1)

    tls_err = tls_material_error(args.bind, args.allow_remote, args.tls_cert, args.tls_key)
    if tls_err:
        print(f"\n  [✗] {tls_err}\n", file=sys.stderr)
        sys.exit(1)

    exposed = listener_requires_tls(args.bind, args.allow_remote)
    allow_hosts = {_normalise_host(value) for value in args.allow_host}
    if "" in allow_hosts:
        print("\n  [✗] SECURITY BLOCK: --allow-host requires a hostname or IP address.\n", file=sys.stderr)
        sys.exit(1)
    cert_san_names = set()
    if exposed and args.tls_cert:
        try:
            cert_san_names = _certificate_san_names(args.tls_cert)
        except (OSError, ssl.SSLError, ValueError) as exc:
            print(f"\n  [✗] SECURITY BLOCK: could not read listener certificate names: {exc}\n", file=sys.stderr)
            sys.exit(1)

    bind_name = _normalise_host(args.bind)
    specific_bind = bool(bind_name and bind_name not in _WILDCARD_HOSTS)
    if args.allow_remote and not specific_bind and not allow_hosts and not cert_san_names:
        print(
            "\n  [✗] SECURITY BLOCK: wildcard remote listeners need at least one certificate DNS/IP SAN "
            "or --allow-host name. Pass --allow-host once for each name browsers will use.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    gap_warning = None
    if _remote_gate_gap(args.bind, args.allow_remote):
        gap_warning = _remote_gate_gap_warning(args.bind)
        print("\n" + gap_warning + "\n", file=sys.stderr)

    allow_remote_warning = None

    global _OEM_MODE
    if getattr(args, "oem", False) or getattr(args, "crawl", False):
        _OEM_MODE = True

    # Configure basic logging early so server startup messages are visible
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s  %(message)s",
        stream=sys.stderr,
    )

    is_root, sudo_user = is_root_user()
    default_outdir = get_default_output_dir()

    fingerprint = None
    if args.tls_cert and args.tls_key:
        try:
            fingerprint = cert_fingerprint_sha256(args.tls_cert)
        except (OSError, ValueError, ssl.SSLError) as exc:
            print(f"\n  [✗] SECURITY BLOCK: could not read TLS certificate: {exc}\n", file=sys.stderr)
            sys.exit(1)
        if os.name == "posix":
            key_mode = os.stat(args.tls_key).st_mode
            if key_mode & 0o077:
                print(
                    "  [!] WARNING: TLS private key is readable by group or others. Restrict it to mode 600.",
                    file=sys.stderr,
                )

    port = _find_free_port(preferred=args.port, host=args.bind)
    display_host = "127.0.0.1" if args.bind in ("0.0.0.0", "::", "") else args.bind

    if args.import_hcl:
        if os.path.exists(args.import_hcl):
            set_custom_hcl_bundle(args.import_hcl)
            print(f"  [🔒] Pre-loaded Dark-Site HCL Bundle: {args.import_hcl}")
        else:
            print(f"  [✗] WARNING: Dark-Site HCL Bundle not found: {args.import_hcl}", file=sys.stderr)

    try:
        server = make_server(
            port,
            host=args.bind,
            allow_remote=args.allow_remote,
            allow_hosts=allow_hosts,
            tls_cert=args.tls_cert if exposed else None,
            tls_key=args.tls_key if exposed else None,
            plugins_dir=args.plugins_dir,
            cert_san_names=cert_san_names,
        )
    except (OSError, ssl.SSLError, ValueError) as exc:
        print(f"\n  [✗] SECURITY BLOCK: could not start the TLS listener: {exc}\n", file=sys.stderr)
        sys.exit(1)

    if args.allow_remote:
        allowed_names = set(allow_hosts) | set(cert_san_names)
        actual_name = _normalise_host(server.server_address[0])
        if actual_name and actual_name not in _WILDCARD_HOSTS:
            allowed_names.add(actual_name)
        if specific_bind:
            allowed_names.add(bind_name)
        allow_remote_warning = _allow_remote_warning(allowed_names)
        print("\n" + allow_remote_warning + "\n", file=sys.stderr)

    scheme = "https" if server.tls_enabled else "http"
    tokenized_url = f"{scheme}://{display_host}:{port}/?token={_LAUNCH_TOKEN}"

    # Serve in a daemon thread so Ctrl-C stops it immediately
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    server.update_checker.start()
    from vcf_hci.web.hcl_startup import start_hcl_refresh
    start_hcl_refresh(disabled=args.no_hcl_auto_refresh, imported_bundle=args.import_hcl)

    print("\n  VCF Readiness Assessment")
    print("  ─────────────────────────────────────────────────────")
    if gap_warning:
        print(_indented_warning(gap_warning))
        print("  ─────────────────────────────────────────────────────")
    if allow_remote_warning:
        print(_indented_warning(allow_remote_warning))
        print("  ─────────────────────────────────────────────────────")
    if server.tls_enabled:
        print("  [!] Remote Web UI is HTTPS (TLS 1.2+).")
        print("      The launch URL works once. After the browser loads, it stops working.")
        print(f"      Certificate SHA-256: {fingerprint}")
        print("      Confirm that fingerprint before entering BMC passwords.")
        print("      The browser was not opened here, so this URL is still unused.")
        print("  ─────────────────────────────────────────────────────")
    if is_root:
        user_desc = f"root (sudo user: {sudo_user})" if sudo_user else "root"
        print(f"  [!] WARNING: Running as {user_desc}.")
        print("      Root privileges are not required for Redfish BMC access.")
        print(f"      Default report folder set to: {default_outdir}")
        print("  ─────────────────────────────────────────────────────")
    print(f"  Web UI  →  {tokenized_url}")
    print("  The launch URL works once. After the browser loads, the session cookie takes over.")
    if args.bind != "127.0.0.1":
        print(f"  Bound   →  {args.bind}:{port}")
    print("  Press Ctrl-C or click Quit in the browser to exit.", flush=True)
    print()

    # Do not auto-open an exposed listener: that would consume the one-time URL
    # on the server host before the operator can use it.
    if not args.no_browser and not server.tls_enabled:
        time.sleep(0.25)
        webbrowser.open(tokenized_url)

    # Block on the shutdown event (set by /api/shutdown or SIGINT/SIGTERM)
    def _handle_signal(sig, frame):
        if _shutdown_event.is_set():
            print("\n[!] Force exit requested.")
            os._exit(1)
        _cancel_event.set()
        cancel_remote_jobs(server)
        print("\n[→] Shutting down…")
        _shutdown_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    _shutdown_event.wait()  # blocks until Quit button or Ctrl-C

    vault_session.lock()   # drop any unlocked credential vault from memory
    try:
        server.shutdown()
    finally:
        server.server_close()
    print("[✓] Server stopped.")
