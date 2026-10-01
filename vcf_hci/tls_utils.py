"""
VCF Readiness Tool — TLS & SSL Context Utilities (vcf_hci.tls_utils).

Provides helpers for configuring SSL contexts for BMC connections:
  - Insecure / Ignore Errors mode (default for unmanaged/self-signed BMCs)
  - Verified mode using system trust store
  - Verified mode using custom enterprise CA bundle file
  - Diagnostics for SSL handshake and certificate verification failures
"""

import hashlib
import http.client
import ipaddress
import logging
import os
import socket
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple, Union, cast

logger = logging.getLogger("vcf_assess")


def normalize_thumbprint(thumbprint: str) -> str:
    """Normalize a SHA-256 certificate thumbprint to a 64-character uppercase hex string."""
    if not thumbprint:
        return ""
    clean = str(thumbprint).strip().upper()
    if clean.startswith("SHA256:") or clean.startswith("SHA-256:"):
        clean = clean.split(":", 1)[1]
    clean = clean.replace(":", "").replace("-", "").replace(" ", "")
    return clean


def format_thumbprint(thumbprint: str) -> str:
    """Format a 64-character hex thumbprint into colon-separated XX:YY:... pairs."""
    norm = normalize_thumbprint(thumbprint)
    if not norm or len(norm) != 64:
        return thumbprint
    return ":".join(norm[i:i+2] for i in range(0, 64, 2))


def _port_from_suffix(rest: str) -> Optional[int]:
    if not rest.startswith(":"):
        return None
    port_s = rest[1:]
    if not port_s.isdigit():
        return None
    port = int(port_s)
    if port < 1 or port > 65535:
        return None
    return port


def parse_target_authority(
    host: str,
    default_scheme: str = "https",
) -> Tuple[str, str, Optional[int]]:
    """Return (scheme, hostname, port) for a BMC target.

    Accepts a hostname, IPv4, bare or bracketed IPv6, host:port, and an
    http(s) URL. Userinfo is ignored. IPv6 is not split on ':'.
    """
    scheme = default_scheme or "https"
    text = str(host or "").strip()
    if text.startswith("https://"):
        scheme = "https"
        text = text[len("https://"):]
    elif text.startswith("http://"):
        scheme = "http"
        text = text[len("http://"):]
    text = text.split("/", 1)[0]
    text = text.split("?", 1)[0]
    text = text.split("#", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    text = text.strip()
    if not text:
        return scheme, "", None

    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            name = text[1:end]
            return scheme, name, _port_from_suffix(text[end + 1:])

    try:
        ipaddress.ip_address(text)
        return scheme, text, None
    except ValueError:
        pass

    if text.count(":") == 1:
        name, port_s = text.rsplit(":", 1)
        port = _port_from_suffix(":" + port_s)
        if name and port is not None:
            return scheme, name, port

    return scheme, text, None


def _strip_host_brackets(host: str) -> str:
    text = str(host or "").strip()
    if text.startswith("[") and text.endswith("]"):
        return text[1:-1]
    return text


def hosts_equal(left: str, right: str) -> bool:
    """True when two host strings name the same IP or the same DNS name."""
    a = _strip_host_brackets(left)
    b = _strip_host_brackets(right)
    if not a or not b:
        return False
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return a.lower().rstrip(".") == b.lower().rstrip(".")


def thumbprint_for_host(host: str, pins: Optional[Dict[str, str]]) -> str:
    """Return the pinned SHA-256 thumbprint for this dial host, or ""."""
    if not pins:
        return ""
    _scheme, name, _port = parse_target_authority(host)
    candidates = []
    raw = str(host or "").strip().lower()
    if raw:
        candidates.append(raw)
    if name:
        low = name.lower()
        if low not in candidates:
            candidates.append(low)
        if ":" in low:
            bracketed = "[%s]" % low
            if bracketed not in candidates:
                candidates.append(bracketed)
    folded = {}
    for key, value in pins.items():
        if value:
            folded[str(key).strip().lower()] = value
    for cand in candidates:
        found = folded.get(cand)
        if found:
            return found
    return ""


def url_is_allowed_bmc_target(
    url: str,
    host: str,
    scheme: str = "https",
    port: Optional[int] = None,
) -> bool:
    """True when url is relative or stays on this BMC scheme, host, and port."""
    parsed = urllib.parse.urlsplit(str(url or ""))
    if parsed.scheme and not parsed.hostname:
        return False
    if not parsed.hostname:
        return True
    allowed_scheme = scheme or "https"
    _parsed_scheme, dial_host, embedded_port = parse_target_authority(
        host, default_scheme=allowed_scheme
    )
    if parsed.scheme not in ("https", allowed_scheme):
        return False
    if not hosts_equal(parsed.hostname, dial_host):
        return False
    allowed_port = port if port is not None else embedded_port
    if allowed_port is None:
        allowed_port = 443 if allowed_scheme == "https" else 80
    dest_scheme = parsed.scheme or allowed_scheme
    if parsed.port is not None:
        dest_port = parsed.port
    elif dest_scheme == "http":
        dest_port = 80
    else:
        dest_port = 443
    return dest_port == allowed_port


def _redirect_stays_on_request_host(original_url: str, new_url: str) -> bool:
    orig = urllib.parse.urlsplit(original_url)
    dest = urllib.parse.urlsplit(new_url)
    if not dest.scheme or dest.scheme not in ("https", orig.scheme or "https"):
        return False
    if not dest.hostname or not orig.hostname:
        return False
    if not hosts_equal(dest.hostname, orig.hostname):
        return False
    if dest.port is None:
        return True
    if orig.port is not None:
        return dest.port == orig.port
    default_port = 443 if (orig.scheme or "https") == "https" else 80
    return dest.port == default_port


def _extract_rdn_value(rdn_seq: Any, key_name: str) -> Optional[str]:
    """Extract attribute value from nested RDN tuple-of-tuples returned by ssl._test_decode_cert."""
    if not rdn_seq or not isinstance(rdn_seq, (list, tuple)):
        return None
    for rdn in rdn_seq:
        if isinstance(rdn, (list, tuple)):
            for item in rdn:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    k, v = item
                    if k == key_name:
                        return str(v)
    return None


def _decode_cert_der(der_bytes: bytes) -> Dict[str, Any]:
    """Decode DER certificate bytes into a dictionary of certificate fields using stdlib helpers."""
    if not der_bytes:
        return {}
    try:
        pem = ssl.DER_cert_to_PEM_cert(der_bytes)
        if hasattr(ssl, "_ssl") and hasattr(ssl._ssl, "_test_decode_cert"):
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".pem", delete=False) as tf:
                tf.write(pem)
                tf.flush()
                tf_path = tf.name
            try:
                res = ssl._ssl._test_decode_cert(tf_path)
                return res if isinstance(res, dict) else {}
            finally:
                try:
                    os.unlink(tf_path)
                except OSError:
                    pass
    except Exception as exc:
        logger.debug("Failed decoding cert via _test_decode_cert: %s", exc)
    return {}


def inspect_server_certificate(
    host: str,
    port: int = 443,
    timeout: float = 3.0,
    server_hostname: Optional[str] = None,
) -> Dict[str, Any]:
    """Connect to host:port via TLS, retrieve the server certificate, and extract trust metadata.

    Returns:
        dict containing host, port, reachable, sha256 (formatted), sha256_raw,
        subject_cn, issuer_cn, subject_org, issuer_org, not_before, not_after,
        is_self_signed, is_expired, subject_alt_names, serial_number, and error.
    """
    clean_host = str(host or "").strip()
    if clean_host.startswith("https://"):
        clean_host = clean_host[8:]
    elif clean_host.startswith("http://"):
        clean_host = clean_host[7:]
    if ":" in clean_host:
        parts = clean_host.split(":")
        clean_host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass

    res = {
        "host": clean_host,
        "port": port,
        "reachable": False,
        "tcp_rtt_ms": None,
        "tls_rtt_ms": None,
        "sha256": "",
        "sha256_raw": "",
        "subject_cn": "",
        "issuer_cn": "",
        "subject_org": "",
        "issuer_org": "",
        "not_before": "",
        "not_after": "",
        "is_self_signed": False,
        "is_expired": False,
        "subject_alt_names": [],
        "serial_number": "",
        "error": None,
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        t_sock0 = time.monotonic()
        with socket.create_connection((clean_host, port), timeout=timeout) as sock:
            t_sock1 = time.monotonic()
            res["tcp_rtt_ms"] = round((t_sock1 - t_sock0) * 1000.0, 2)
            t_tls0 = time.monotonic()
            with ctx.wrap_socket(sock, server_hostname=server_hostname or clean_host) as ssock:
                t_tls1 = time.monotonic()
                res["tls_rtt_ms"] = round((t_tls1 - t_tls0) * 1000.0, 2)
                der_bytes = ssock.getpeercert(binary_form=True)
                if not der_bytes:
                    res["error"] = "No peer certificate returned"
                    return res

                raw_sha = hashlib.sha256(der_bytes).hexdigest().upper()
                res["reachable"] = True
                res["sha256_raw"] = raw_sha
                res["sha256"] = format_thumbprint(raw_sha)

                decoded = _decode_cert_der(der_bytes)
                if decoded:
                    subject = decoded.get("subject", ())
                    issuer = decoded.get("issuer", ())
                    res["subject_cn"] = _extract_rdn_value(subject, "commonName") or ""
                    res["issuer_cn"] = _extract_rdn_value(issuer, "commonName") or ""
                    res["subject_org"] = _extract_rdn_value(subject, "organizationName") or ""
                    res["issuer_org"] = _extract_rdn_value(issuer, "organizationName") or ""
                    res["not_before"] = str(decoded.get("notBefore") or "")
                    res["not_after"] = str(decoded.get("notAfter") or "")
                    res["serial_number"] = str(decoded.get("serialNumber") or "")

                    san_list = []
                    for san_item in decoded.get("subjectAltName", ()):
                        if isinstance(san_item, (list, tuple)) and len(san_item) == 2:
                            san_list.append(f"{san_item[0]}:{san_item[1]}")
                    res["subject_alt_names"] = san_list

                    if res["not_after"]:
                        try:
                            expiry_ts = ssl.cert_time_to_seconds(res["not_after"])
                            res["is_expired"] = bool(expiry_ts < time.time())
                        except Exception:
                            pass

                    # Determine self-signed
                    if (subject and issuer and subject == issuer) or (res["subject_cn"] and res["issuer_cn"] and res["subject_cn"] == res["issuer_cn"]):
                        res["is_self_signed"] = True
                else:
                    # Fallback if decode failed
                    res["subject_cn"] = clean_host
                    res["is_self_signed"] = True
                return res
    except Exception as exc:
        res["error"] = str(exc)
        return res


def measure_connection_rtt(
    host: str,
    port: int = 443,
    timeout: float = 3.0,
    samples: int = 3,
    server_hostname: Optional[str] = None,
) -> Dict[str, Any]:
    """Measure TCP round-trip time (RTT) and TLS handshake latency using stdlib sockets.

    Args:
        host: Target BMC hostname or IP address.
        port: Target TCP port (default 443).
        timeout: Socket timeout in seconds per attempt.
        samples: Number of TCP connection probes (default 3).
        server_hostname: SNI hostname if different from host.

    Returns:
        dict with keys: host, port, reachable, tcp_rtt_min_ms, tcp_rtt_avg_ms,
        tcp_rtt_max_ms, tls_handshake_ms, packet_loss_pct, jitter_ms,
        high_latency_warning, error.
    """
    clean_host = str(host or "").strip()
    if clean_host.startswith("https://"):
        clean_host = clean_host[8:]
    elif clean_host.startswith("http://"):
        clean_host = clean_host[7:]
    if ":" in clean_host:
        parts = clean_host.split(":")
        clean_host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass

    res: Dict[str, Any] = {
        "host": clean_host,
        "port": port,
        "reachable": False,
        "tcp_rtt_min_ms": None,
        "tcp_rtt_avg_ms": None,
        "tcp_rtt_max_ms": None,
        "tls_handshake_ms": None,
        "packet_loss_pct": 100.0,
        "jitter_ms": None,
        "high_latency_warning": False,
        "error": None,
    }

    if not clean_host or samples <= 0:
        res["error"] = "Invalid host or sample count"
        return res

    latencies = []
    failed_attempts = 0

    for _ in range(samples):
        t0 = time.monotonic()
        try:
            with socket.create_connection((clean_host, port), timeout=timeout):
                t1 = time.monotonic()
                latencies.append((t1 - t0) * 1000.0)
        except Exception as exc:
            failed_attempts += 1
            if not res["error"]:
                res["error"] = str(exc)

    total_attempts = len(latencies) + failed_attempts
    if total_attempts > 0:
        res["packet_loss_pct"] = round((failed_attempts / float(total_attempts)) * 100.0, 1)

    if latencies:
        res["reachable"] = True
        min_rtt = min(latencies)
        max_rtt = max(latencies)
        avg_rtt = sum(latencies) / float(len(latencies))
        res["tcp_rtt_min_ms"] = round(min_rtt, 2)
        res["tcp_rtt_max_ms"] = round(max_rtt, 2)
        res["tcp_rtt_avg_ms"] = round(avg_rtt, 2)

        if len(latencies) > 1:
            variance = sum((x - avg_rtt) ** 2 for x in latencies) / float(len(latencies))
            res["jitter_ms"] = round(variance ** 0.5, 2)
        else:
            res["jitter_ms"] = 0.0

        if avg_rtt > 300.0 or res["packet_loss_pct"] > 0.0:
            res["high_latency_warning"] = True

        # Measure TLS handshake latency on one sample connection
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((clean_host, port), timeout=timeout) as sock:
                t_tls0 = time.monotonic()
                with ctx.wrap_socket(sock, server_hostname=server_hostname or clean_host):
                    t_tls1 = time.monotonic()
                    res["tls_handshake_ms"] = round((t_tls1 - t_tls0) * 1000.0, 2)
        except Exception:
            pass

    return res


def verify_peer_thumbprint(der_cert: bytes, expected_thumbprint: str) -> bool:
    """Verify that a DER certificate matches an expected SHA-256 thumbprint."""
    if not der_cert or not expected_thumbprint:
        return False
    actual = hashlib.sha256(der_cert).hexdigest().upper()
    expected = normalize_thumbprint(expected_thumbprint)
    return actual == expected


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that validates peer certificate SHA-256 against a pinned thumbprint map."""

    def __init__(
        self,
        *args: Any,
        pinned_thumbprints: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ):
        super().__init__(*args, **kwargs)
        self.pinned_thumbprints = pinned_thumbprints or {}

    def connect(self) -> None:
        super().connect()
        if not self.pinned_thumbprints:
            return

        expected = thumbprint_for_host(self.host, self.pinned_thumbprints)
        if not expected:
            return

        der = self.sock.getpeercert(binary_form=True)
        if not der:
            raise ssl.SSLCertVerificationError(
                f"No peer certificate returned for pinned host {self.host}"
            )

        actual_sha = hashlib.sha256(der).hexdigest().upper()
        norm_expected = normalize_thumbprint(expected)
        if actual_sha != norm_expected:
            formatted_actual = format_thumbprint(actual_sha)
            formatted_expected = format_thumbprint(norm_expected)
            raise ssl.SSLCertVerificationError(
                f"Pinned certificate thumbprint mismatch for {self.host}: expected {formatted_expected}, got {formatted_actual}"
            )


class PinnedThumbprintHTTPSHandler(urllib.request.HTTPSHandler):
    """urllib.request HTTPSHandler that injects PinnedHTTPSConnection."""

    def __init__(
        self,
        pinned_thumbprints: Optional[Dict[str, str]] = None,
        context: Optional[ssl.SSLContext] = None,
        check_hostname: Optional[bool] = None,
    ):
        super().__init__(context=context, check_hostname=check_hostname)
        self.pinned_thumbprints = pinned_thumbprints or {}
        self._context = context
        self._check_hostname = check_hostname

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(cast(Any, self._build_connection), req)

    def _build_connection(self, host: str, timeout: float = 300) -> PinnedHTTPSConnection:
        kwargs: Dict[str, Any] = {
            "pinned_thumbprints": self.pinned_thumbprints,
        }
        ctx = getattr(self, "_context", None)
        if ctx is not None:
            kwargs["context"] = ctx
        check_host = getattr(self, "_check_hostname", None)
        if check_host is not None:
            kwargs["check_hostname"] = check_host
        return PinnedHTTPSConnection(
            host,
            timeout=timeout,
            **kwargs,
        )


class SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only when it stays on the request host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        joined = urllib.parse.urljoin(req.full_url, newurl)
        if not _redirect_stays_on_request_host(req.full_url, joined):
            raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
        return urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl
        )


def build_bmc_opener(
    ssl_context: Optional[ssl.SSLContext] = None,
    pinned_thumbprints: Optional[Dict[str, str]] = None,
) -> urllib.request.OpenerDirector:
    """Open a BMC URL and follow redirects only back to that same host."""
    handlers = [SameHostRedirectHandler()]
    if pinned_thumbprints:
        handlers.append(
            PinnedThumbprintHTTPSHandler(
                pinned_thumbprints=pinned_thumbprints,
                context=ssl_context,
            )
        )
    elif ssl_context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    return urllib.request.build_opener(*handlers)


def build_pinned_opener(
    ssl_context: Optional[ssl.SSLContext] = None,
    pinned_thumbprints: Optional[Dict[str, str]] = None,
) -> urllib.request.OpenerDirector:
    """Build a urllib.request.OpenerDirector configured with SSLContext and optional pinned thumbprints."""
    handler = PinnedThumbprintHTTPSHandler(
        pinned_thumbprints=pinned_thumbprints,
        context=ssl_context,
    )
    return urllib.request.build_opener(SameHostRedirectHandler(), handler)


class StdlibHTTPConnectionPool:
    """Thread-safe persistent HTTP/HTTPS connection pool using Python stdlib http.client.

    Maintains up to `max_connections` reusable Keep-Alive connections per host/port target.
    Handles socket disconnections, TLS certificate pinning, custom SSLContext,
    and automatic reconnection on stale connections without external dependencies.
    """

    def __init__(
        self,
        host: str,
        port: int = 443,
        scheme: str = "https",
        ssl_context: Optional[ssl.SSLContext] = None,
        pinned_thumbprints: Optional[Dict[str, str]] = None,
        max_connections: int = 3,
        idle_timeout: float = 30.0,
        server_hostname: Optional[str] = None,
        connect_timeout: float = 5.0,
        read_timeout: float = 15.0,
    ):
        clean_host = str(host or "").strip()
        explicit_scheme = clean_host.startswith("https://") or clean_host.startswith("http://")
        parsed_scheme, parsed_host, parsed_port = parse_target_authority(
            clean_host, default_scheme=scheme
        )
        if parsed_host:
            clean_host = parsed_host
        if parsed_port is not None:
            port = parsed_port
        if explicit_scheme and parsed_scheme:
            scheme = parsed_scheme

        self.host = clean_host
        self.port = port
        self.scheme = scheme.lower()
        self.ssl_context = ssl_context or build_ssl_context(verify_ssl=False)
        self.pinned_thumbprints = pinned_thumbprints or {}
        self.max_connections = max(1, max_connections)
        self.idle_timeout = idle_timeout
        self.server_hostname = server_hostname
        self.connect_timeout = float(connect_timeout)
        self.read_timeout = float(read_timeout)

        # Pool synchronization
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._idle_conns: List[Tuple[Union[http.client.HTTPConnection, http.client.HTTPSConnection], float]] = []
        self._total_conns = 0
        self._closed = False

        # Metrics and timing diagnostics
        self.connections_created = 0
        self.connections_reused = 0
        self.requests_served = 0
        self.stale_evictions = 0
        self.total_tls_handshake_ms = 0.0
        self.total_request_time_ms = 0.0

    def _create_connection(
        self, timeout: float = 15.0
    ) -> Union[http.client.HTTPConnection, http.client.HTTPSConnection]:
        if self.scheme == "https":
            kwargs: Dict[str, Any] = {
                "context": self.ssl_context,
                "timeout": timeout,
            }
            if self.pinned_thumbprints:
                kwargs["pinned_thumbprints"] = self.pinned_thumbprints
                return PinnedHTTPSConnection(
                    self.host,
                    port=self.port,
                    **kwargs,
                )
            return http.client.HTTPSConnection(
                self.host,
                port=self.port,
                **kwargs,
            )
        return http.client.HTTPConnection(
            self.host,
            port=self.port,
            timeout=timeout,
        )

    @staticmethod
    def _is_conn_stale(conn: Union[http.client.HTTPConnection, http.client.HTTPSConnection]) -> bool:
        sock = getattr(conn, "sock", None)
        if sock is None:
            return True
        try:
            import select
            r, _, _ = select.select([sock], [], [], 0)
            if r:
                try:
                    peek = sock.recv(1, socket.MSG_PEEK)
                    if not peek:
                        return True
                except (BlockingIOError, InterruptedError):
                    pass
                except (ssl.SSLEOFError, ConnectionResetError, BrokenPipeError):
                    return True
                except Exception:
                    return True
        except Exception:
            return True
        return False

    def _acquire_conn(
        self, timeout: float = 15.0
    ) -> Tuple[Union[http.client.HTTPConnection, http.client.HTTPSConnection], bool]:
        deadline = time.time() + timeout
        with self._cv:
            while not self._closed:
                while self._idle_conns:
                    conn, last_used = self._idle_conns.pop()
                    if (time.time() - last_used) > self.idle_timeout or self._is_conn_stale(conn):
                        try:
                            conn.close()
                        except Exception:
                            pass
                        self._total_conns = max(0, self._total_conns - 1)
                        self.stale_evictions += 1
                        continue
                    with self._lock:
                        self.connections_reused += 1
                    return conn, True

                if self._total_conns < self.max_connections:
                    self._total_conns += 1
                    conn_to = min(timeout, self.connect_timeout) if timeout > 0 else self.connect_timeout
                    conn = self._create_connection(timeout=conn_to)
                    t0 = time.time()
                    try:
                        conn.connect()
                    except Exception:
                        self._total_conns = max(0, self._total_conns - 1)
                        raise
                    handshake_ms = (time.time() - t0) * 1000
                    with self._lock:
                        self.connections_created += 1
                        self.total_tls_handshake_ms += handshake_ms
                    return conn, False

                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                self._cv.wait(timeout=min(remaining, 0.5))

            if self._closed:
                raise RuntimeError("Connection pool is closed")

            conn_to = min(timeout, self.connect_timeout) if timeout > 0 else self.connect_timeout
            conn = self._create_connection(timeout=conn_to)
            conn.connect()
            with self._lock:
                self.connections_created += 1
            return conn, False

    def _release_conn(self, conn: Union[http.client.HTTPConnection, http.client.HTTPSConnection]) -> None:
        with self._cv:
            if self._closed or conn is None:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
                self._total_conns = max(0, self._total_conns - 1)
            else:
                self._idle_conns.append((conn, time.time()))
            self._cv.notify()

    def _discard_conn(self, conn: Union[http.client.HTTPConnection, http.client.HTTPSConnection]) -> None:
        with self._cv:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            self._total_conns = max(0, self._total_conns - 1)
            self._cv.notify()

    def request(
        self,
        method: str,
        url_or_path: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Union[bytes, str]] = None,
        timeout: float = 15.0,
    ) -> Tuple[int, Dict[str, str], bytes]:
        if self._closed:
            raise RuntimeError("Connection pool is closed")

        clean_path = url_or_path
        if clean_path.startswith("http://") or clean_path.startswith("https://"):
            parsed = urllib.parse.urlsplit(clean_path)
            clean_path = parsed.path or "/"
            if parsed.query:
                clean_path = f"{clean_path}?{parsed.query}"
        if not clean_path.startswith("/"):
            clean_path = f"/{clean_path}"

        req_headers: Dict[str, str] = {
            "Host": self.host if self.port in (80, 443) else f"{self.host}:{self.port}",
            "Accept": "application/json",
            "Connection": "keep-alive",
            "User-Agent": "VCF-HCI-Readiness-Tool/9.8.2",
        }
        if headers:
            req_headers.update(headers)

        req_body: Optional[bytes] = None
        if body is not None:
            if isinstance(body, str):
                req_body = body.encode("utf-8")
            else:
                req_body = body
            req_headers["Content-Length"] = str(len(req_body))

        max_redirects = 5
        curr_path = clean_path
        curr_method = method

        for _redirect_step in range(max_redirects + 1):
            max_retries = 2
            status = 0
            resp_headers: Dict[str, str] = {}
            raw_body = b""

            for attempt in range(max_retries):
                conn, is_reused = self._acquire_conn(timeout=timeout)
                t_req_start = time.time()
                try:
                    read_to = timeout if timeout > 0 else self.read_timeout
                    if getattr(conn, "sock", None) is not None:
                        conn.sock.settimeout(read_to)
                    conn.request(curr_method, curr_path, body=req_body, headers=req_headers)
                    resp = conn.getresponse()
                    status = resp.status
                    resp_headers = {k: v for k, v in resp.getheaders()}
                    raw_body = resp.read()
                    elapsed_ms = (time.time() - t_req_start) * 1000

                    with self._lock:
                        self.requests_served += 1
                        self.total_request_time_ms += elapsed_ms

                    conn_hdr = str(resp_headers.get("Connection") or resp_headers.get("connection") or "").lower()
                    if "close" in conn_hdr or status in (401, 403):
                        self._discard_conn(conn)
                    else:
                        self._release_conn(conn)
                    break
                except (
                    http.client.RemoteDisconnected,
                    http.client.CannotSendRequest,
                    http.client.CannotSendHeader,
                    http.client.BadStatusLine,
                    ConnectionResetError,
                    BrokenPipeError,
                ) as exc:
                    self._discard_conn(conn)
                    if is_reused and attempt == 0 and not self._closed:
                        logger.debug("Reused pooled connection was dropped by peer (%s); retrying with fresh connection...", exc)
                        continue
                    raise
                except Exception:
                    self._discard_conn(conn)
                    raise

            if status in (301, 302, 303, 307, 308) and _redirect_step < max_redirects:
                loc = resp_headers.get("Location") or resp_headers.get("location")
                if loc:
                    if loc.startswith("http://") or loc.startswith("https://"):
                        p_loc = urllib.parse.urlsplit(loc)
                        if p_loc.hostname and p_loc.hostname.lower() != self.host.lower():
                            return status, resp_headers, raw_body
                        curr_path = p_loc.path or "/"
                        if p_loc.query:
                            curr_path = f"{curr_path}?{p_loc.query}"
                    else:
                        curr_path = urllib.parse.urljoin(curr_path, loc)
                    if not curr_path.startswith("/"):
                        curr_path = f"/{curr_path}"
                    if status in (301, 302, 303):
                        curr_method = "GET"
                        req_body = None
                        req_headers.pop("Content-Length", None)
                    continue

            return status, resp_headers, raw_body

        raise RuntimeError("Request retry loop exhausted")

    def close(self) -> None:
        with self._cv:
            self._closed = True
            for conn, _ in self._idle_conns:
                try:
                    conn.close()
                except Exception:
                    pass
            self._idle_conns.clear()
            self._total_conns = 0
            self._cv.notify_all()

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            reqs = max(1, self.requests_served)
            created = max(1, self.connections_created)
            return {
                "connections_created": self.connections_created,
                "connections_reused": self.connections_reused,
                "requests_served": self.requests_served,
                "stale_evictions": self.stale_evictions,
                "total_tls_handshake_ms": round(self.total_tls_handshake_ms, 2),
                "avg_tls_handshake_ms": round(self.total_tls_handshake_ms / created, 2),
                "avg_request_time_ms": round(self.total_request_time_ms / reqs, 2),
                "tls_reuse_ratio": round(self.connections_reused / reqs, 2),
            }


_INSECURE_TLS_WARNED = False


def build_ssl_context(
    verify_ssl: bool = False,
    ca_bundle: Optional[str] = None,
    tls_min_version: Optional[str] = None,
    legacy_ciphers: bool = False,
) -> ssl.SSLContext:
    """Create an ssl.SSLContext configured according to user preferences.

    Args:
        verify_ssl: If True, enforce certificate validation and hostname checking.
                    If False (default), allow self-signed and unverified BMC certificates.
        ca_bundle: Optional filesystem path to a custom CA bundle (.pem / .crt).
        tls_min_version: Minimum TLS protocol version required (e.g. "1.0", "1.1", "1.2", "1.3").
        legacy_ciphers: If True, permit legacy TLS 1.0/1.1 protocols and older OpenSSL cipher suites.

    Returns:
        ssl.SSLContext object.
    """
    if not verify_ssl:
        global _INSECURE_TLS_WARNED
        if not _INSECURE_TLS_WARNED:
            _INSECURE_TLS_WARNED = True
            logger.warning(
                "BMC TLS certificate verification is DISABLED (default). "
                "Credentials are exposed to man-in-the-middle interception on untrusted networks. "
                "Enable verification with --verify-ssl / --ca-bundle, or pin certificates via thumbprints."
            )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif ca_bundle and os.path.isfile(ca_bundle):
        try:
            ctx = ssl.create_default_context(cafile=ca_bundle)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        except Exception as exc:
            logger.warning(
                "Failed loading custom CA bundle '%s': %s. Falling back to system trust store.",
                ca_bundle,
                exc,
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

    # Apply minimum TLS version and legacy cipher suite options
    if legacy_ciphers or (tls_min_version and tls_min_version.strip() in ("1.0", "1.1")):
        if hasattr(ssl, "TLSVersion"):
            try:
                if tls_min_version and tls_min_version.strip() == "1.0" and hasattr(ssl.TLSVersion, "TLSv1"):
                    ctx.minimum_version = ssl.TLSVersion.TLSv1
                elif hasattr(ssl.TLSVersion, "TLSv1_1"):
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            except Exception:
                pass
        # Lower security level and allow older ciphers in OpenSSL 3.0+
        for cipher_str in ("DEFAULT:@SECLEVEL=1", "HIGH:!DH:!aNULL", "ALL:@SECLEVEL=1", "DEFAULT"):
            try:
                ctx.set_ciphers(cipher_str)
                break
            except ssl.SSLError:
                continue
    elif tls_min_version:
        v_clean = tls_min_version.strip().lower()
        if hasattr(ssl, "TLSVersion"):
            try:
                if v_clean in ("1.2", "tlsv1_2") and hasattr(ssl.TLSVersion, "TLSv1_2"):
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                elif v_clean in ("1.3", "tlsv1_3") and hasattr(ssl.TLSVersion, "TLSv1_3"):
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            except Exception:
                pass

    return ctx


def format_ssl_error(exc: Exception, host: str, port: int = 443) -> dict:
    """Translate an SSL exception into structured diagnostic information for SE reports and UI."""
    exc_str = str(exc)
    exc_cls = exc.__class__.__name__

    if isinstance(exc, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in exc_str:
        exc_lower = exc_str.lower()
        if "pinned certificate" in exc_lower or "thumbprint mismatch" in exc_lower:
            reason_code = "ssl_pinned_thumbprint_mismatch"
            reason_label = "Pinned Certificate Thumbprint Mismatch"
            detail = (
                f"The SSL/TLS certificate presented by {host}:{port} does not match the pinned SHA-256 thumbprint ({exc_str}). "
                f"Review the certificate and update the pinned thumbprint."
            )
        elif "self signed certificate" in exc_lower or "self-signed" in exc_lower:
            reason_code = "ssl_self_signed"
            reason_label = "Self-Signed BMC Certificate"
            detail = (
                "BMC presents a self-signed certificate untrusted by the CA store. "
                "Supply a custom CA bundle with --ca-bundle or check 'Ignore BMC TLS certificate errors'."
            )
        elif "certificate has expired" in exc_lower:
            reason_code = "ssl_cert_expired"
            reason_label = "Expired BMC Certificate"
            detail = f"The SSL/TLS certificate presented by {host}:{port} is expired ({exc_str})."
        elif "hostname" in exc_lower or "match" in exc_lower:
            reason_code = "ssl_hostname_mismatch"
            reason_label = "TLS Hostname Mismatch"
            detail = (
                f"Certificate Subject/SAN does not match target host '{host}'. "
                f"Ensure reverse DNS matches the certificate SAN or disable certificate checking."
            )
        else:
            reason_code = "ssl_untrusted_ca"
            reason_label = "Untrusted BMC Certificate Authority"
            detail = (
                f"Certificate Authority is not in the system trust store ({exc_str}). "
                f"Provide enterprise root CA via --ca-bundle or enable 'Ignore BMC TLS certificate errors'."
            )
    elif isinstance(exc, ssl.CertificateError) or "hostname" in exc_str.lower():
        reason_code = "ssl_hostname_mismatch"
        reason_label = "TLS Hostname Mismatch"
        detail = f"Certificate does not match hostname '{host}': {exc_str}"
    else:
        reason_code = "ssl_handshake_failed"
        reason_label = "TLS Handshake Failed"
        detail = f"SSL/TLS handshake with {host}:{port} failed: {exc_str} ({exc_cls})"

    return {
        "reason_code": reason_code,
        "reason_label": reason_label,
        "detail": detail,
        "raw_error": exc_str,
    }
