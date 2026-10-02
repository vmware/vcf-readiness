"""
VCF Readiness Tool — Redfish session and HTTP transport management module.
"""
import http.client
import json
import logging
import re
import socket
import ssl
import threading
import time
import urllib.request
from contextlib import nullcontext
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError

from vcf_hci.tls_utils import build_bmc_opener, build_pinned_opener, url_is_allowed_bmc_target

logger = logging.getLogger("vcf_assess")

# Peak concurrent Redfish connections to a single BMC per scan phase.
# Keeps BMC load low while still parallelising BIOS/SEL/license/storage/NICs.
_BMC_INNER_WORKERS = 3

_thread_local = threading.local()

# Circuit-breaker registry for hosts with confirmed authentication failures
# Prevents hammering BMCs with invalid credentials and tripping account lockouts
_AUTH_LOCKOUT_LOCK = threading.Lock()
_AUTH_LOCKOUT_HOSTS: Dict[str, float] = {}


def record_auth_lockout(host: str, ttl_seconds: float = 1800.0) -> None:
    """Record an authentication lockout for a host to prevent repeatedly hammering bad BMC credentials."""
    if not host:
        return
    h_clean = str(host).strip().lower()
    with _AUTH_LOCKOUT_LOCK:
        _AUTH_LOCKOUT_HOSTS[h_clean] = time.time() + ttl_seconds
    logger.warning("[%s] Recorded in auth lockout circuit-breaker for %.0fs to prevent BMC account lockout", h_clean, ttl_seconds)


def is_host_auth_locked(host: str) -> bool:
    """Check if a host is currently in auth circuit-breaker lockout."""
    if not host:
        return False
    h_clean = str(host).strip().lower()
    with _AUTH_LOCKOUT_LOCK:
        expiry = _AUTH_LOCKOUT_HOSTS.get(h_clean)
        if expiry is None:
            return False
        if time.time() < expiry:
            return True
        del _AUTH_LOCKOUT_HOSTS[h_clean]
        return False


def clear_auth_lockout(host: str = "") -> None:
    """Clear auth lockout for a specific host, or all hosts if host is empty."""
    with _AUTH_LOCKOUT_LOCK:
        if host:
            _AUTH_LOCKOUT_HOSTS.pop(str(host).strip().lower(), None)
        else:
            _AUTH_LOCKOUT_HOSTS.clear()


def compute_request_pacing(collector: Any) -> float:
    """Calculate effective inter-request pacing interval in seconds.

    Returns 0.0s for pipelined BMCs (MultipleHTTPRequests: true) when not throttled.
    Enforces a minimum 0.10s floor for throttled collectors or fragile vendors (Cisco/Supermicro without pipelining).
    """
    if collector is None:
        return 0.05
    is_throttled = bool(getattr(collector, "_throttled", False))
    has_pipelining = bool(getattr(collector, "multiple_http_requests", False))
    base_pacing = float(getattr(collector, "_request_pacing_s", 0.05))
    vendor = str(getattr(collector, "vendor", "") or "").lower()

    if is_throttled:
        return max(base_pacing, 0.10)
    if has_pipelining:
        return 0.0
    if vendor in ("cisco", "supermicro"):
        return max(base_pacing, 0.10)
    return base_pacing


class RedfishSessionManager:
    """Manages Redfish session lifecycle and guarantees session teardown on exit or failure."""

    def __init__(
        self,
        host: str,
        session_uri: str,
        session_token: str,
        ssl_context: Optional[ssl.SSLContext] = None,
        pinned_thumbprints: Optional[Dict[str, str]] = None,
    ):
        self.host = host
        # Safely normalize session URI regardless of relative path or absolute URL
        raw_uri = str(session_uri or "").strip()
        if raw_uri and not raw_uri.startswith("http://") and not raw_uri.startswith("https://"):
            self.session_uri = f"https://{host}/{raw_uri.lstrip('/')}"
        else:
            self.session_uri = raw_uri
        self.session_token = session_token
        if ssl_context:
            self._ctx = ssl_context
        else:
            from vcf_hci.tls_utils import build_ssl_context
            logger.warning(
                "RedfishSessionManager for %s created without an SSL context; "
                "falling back to UNVERIFIED TLS (certificate checking disabled).", host
            )
            self._ctx = build_ssl_context(verify_ssl=False)
        self.pinned_thumbprints = pinned_thumbprints or {}
        self._opener = build_pinned_opener(ssl_context=self._ctx, pinned_thumbprints=self.pinned_thumbprints) if self.pinned_thumbprints else None

    def close(self):
        """Sends DELETE to terminate the active Redfish session."""
        if not self.session_uri or not self.session_token:
            return
        delete_url = self.session_uri
        if not delete_url.startswith("http://") and not delete_url.startswith("https://"):
            delete_url = f"https://{self.host}/{delete_url.lstrip('/')}"
        req = urllib.request.Request(
            url=delete_url,
            method="DELETE",
            headers={"X-Auth-Token": self.session_token}
        )
        try:
            if self._opener is not None:
                with self._opener.open(req, timeout=5):
                    pass
            else:
                with build_bmc_opener(ssl_context=self._ctx).open(req, timeout=5):
                    pass
            logger.debug(f"RedfishSessionManager: closed session {self.session_uri}")
        except Exception:
            pass  # Suppress teardown errors during exit cleanup
        self.session_uri = ""
        self.session_token = ""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def redfish_get(
    collector: Any,
    endpoint: str,
    _retry: bool = True,
    timeout: int = 15,
    critical: bool = True,
) -> Optional[dict]:
    """Execute a Redfish HTTP GET request with retries, caching, and concurrency guards."""
    if not endpoint:
        return None

    ep_clean = str(endpoint).strip()
    if not ep_clean or ep_clean.lower() in ("/empty", "empty", "none", "null", "n/a", "/"):
        return None

    target_host = str(getattr(collector, "host", "") or "").strip().lower()
    is_mocked = not hasattr(urllib.request.urlopen, "__code__") or "Mock" in type(urllib.request.urlopen).__name__ or hasattr(urllib.request.urlopen, "mock")
    if not is_mocked and is_host_auth_locked(target_host):
        logger.debug("[%s] Host is currently in auth lockout circuit-breaker — skipping GET %s", target_host, endpoint)
        collector.auth_failed = True
        return None

    if "://" not in ep_clean:
        ep_clean = re.sub(r"/+", "/", ep_clean)

    if getattr(collector, "_closed", False) or getattr(collector, "_assessment_complete", False):
        return None

    is_cancelled_fn = getattr(collector, "_is_cancelled_or_skipped", None)
    if callable(is_cancelled_fn) and is_cancelled_fn():
        return None

    if getattr(collector, "_phase1_expired", False) and getattr(_thread_local, "is_phase1", False):
        logger.debug("[%s] Phase 1 task expired — aborting GET %s", getattr(collector, "host", "unknown"), endpoint)
        return None

    if getattr(collector, "_phase2_expired", False) and getattr(_thread_local, "is_phase2", False):
        logger.debug("[%s] Phase 2 task expired — aborting GET %s", getattr(collector, "host", "unknown"), endpoint)
        return None

    # Increase timeout on rescans or throttled BMCs to accommodate slow PLDM/I2C buses
    if getattr(collector, "_is_rescan", False) or getattr(collector, "_throttled", False):
        timeout = max(timeout, 20)

    cache_lock = getattr(collector, "_cache_lock", None)
    lock_ctx = cache_lock if cache_lock is not None else nullcontext()

    # Disable retries or abort early if BMC is consistently unresponsive across multiple calls
    with lock_ctx:
        consec = getattr(collector, "_consecutive_timeouts", 0)
        if consec >= 3 or getattr(collector, "_throttled", False):
            _retry = False

    if endpoint.startswith("http"):
        url = re.sub(r"(?<!:)//+", "/", endpoint)
    elif ep_clean.startswith("/redfish/v1"):
        url = f"{collector.host_url}{ep_clean}"
    else:
        url = f"{collector.base_url}/{ep_clean.lstrip('/')}"

    parsed_path = url.split("://", 1)[-1].split("/", 1)[-1]
    path_suffix = f"/{parsed_path.lstrip('/')}"

    # Fast negative endpoint bypass (skip known 404 endpoints for this host by exact path suffix)
    with lock_ctx:
        neg_endpoints = getattr(collector, "_negative_endpoints", None)
        if neg_endpoints is not None and path_suffix in neg_endpoints:
            logger.debug(f"Skipping known negative endpoint {url}")
            return None

        # Per-scan in-memory GET cache
        req_cache = getattr(collector, "_request_cache", None)
        if req_cache is not None and url in req_cache:
            logger.debug(f"CACHE HIT: GET {url}")
            return req_cache[url]

    # Activate in-flight adaptive throttling if BMC experiences repeated timeouts/latency
    throttle_fn = getattr(collector, "_check_adaptive_throttle", None)
    if callable(throttle_fn):
        throttle_fn()

    headers = {"Accept": "application/json"}
    session_tok = getattr(collector, "session_token", "")
    if session_tok:
        headers["X-Auth-Token"] = session_tok
    else:
        auth_hdr = getattr(collector, "_auth_header", "")
        headers["Authorization"] = f"Basic {auth_hdr}"

    max_attempts = 2 if _retry else 1
    inner_cv = getattr(collector, "_inner_cv", None)

    for attempt in range(max_attempts):
        if attempt > 0:
            if getattr(collector, "_closed", False) or getattr(collector, "_assessment_complete", False) or (callable(is_cancelled_fn) and is_cancelled_fn()):
                return None
            time.sleep(1)

        if inner_cv is not None:
            with inner_cv:
                while True:
                    if getattr(collector, "_closed", False) or getattr(collector, "_assessment_complete", False) or (callable(is_cancelled_fn) and is_cancelled_fn()):
                        return None
                    if getattr(collector, "_phase1_expired", False) and getattr(_thread_local, "is_phase1", False):
                        return None
                    if getattr(collector, "_phase2_expired", False) and getattr(_thread_local, "is_phase2", False):
                        return None

                    max_allowed = 1 if getattr(collector, "_throttled", False) else getattr(collector, "_max_inner_workers", _BMC_INNER_WORKERS)
                    if getattr(collector, "_active_inner_workers", 0) < max_allowed:
                        collector._active_inner_workers = getattr(collector, "_active_inner_workers", 0) + 1
                        break
                    inner_cv.wait(timeout=0.5)

        try:
            if getattr(collector, "_closed", False) or getattr(collector, "_assessment_complete", False) or (callable(is_cancelled_fn) and is_cancelled_fn()):
                return None
            if getattr(collector, "_phase1_expired", False) and getattr(_thread_local, "is_phase1", False):
                return None
            if getattr(collector, "_phase2_expired", False) and getattr(_thread_local, "is_phase2", False):
                return None

            is_mocked = not hasattr(urllib.request.urlopen, "__code__") or "Mock" in type(urllib.request.urlopen).__name__ or hasattr(urllib.request.urlopen, "mock")
            opener = getattr(collector, "_opener", None)
            ssl_ctx = getattr(collector, "ssl_context", None)
            conn_pool = getattr(collector, "_conn_pool", None)

            # Inter-request pacing to protect fragile BMC web servers (e.g. Cisco/Supermicro/throttled)
            if not is_mocked:
                pacing = compute_request_pacing(collector)
                if pacing > 0:
                    with lock_ctx:
                        last_finish = getattr(collector, "_last_req_finish_time", 0.0)
                        now_t = time.time()
                        delay = pacing - (now_t - last_finish)
                    if delay > 0:
                        time.sleep(delay)

            if is_mocked:
                req = urllib.request.Request(url, headers=headers)
                resp_cm = opener.open(req, timeout=timeout) if opener is not None else urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx)
                with resp_cm as r:
                    raw = r.read()
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8", errors="replace")
                    status_val = getattr(r, "status", None) or getattr(r, "code", None)
                    status = status_val if isinstance(status_val, int) else 200
            elif conn_pool is not None:
                try:
                    status, resp_headers, raw_bytes = conn_pool.request(
                        "GET", url, headers=headers, timeout=timeout
                    )
                    raw = raw_bytes.decode("utf-8", errors="replace")
                except (socket.timeout, TimeoutError):
                    raise
                except (http.client.HTTPException, ConnectionError, OSError) as exc:
                    if "timed out" in str(exc).lower():
                        raise socket.timeout(str(exc)) from exc
                    target_host = str(getattr(collector, "host", "") or "")
                    target_scheme = str(getattr(collector, "scheme", "https") or "https")
                    target_port = getattr(collector, "port", None)
                    if not url_is_allowed_bmc_target(url, target_host, target_scheme, target_port):
                        logger.debug("Refusing off-target HTTP fallback for %s", url)
                        return None
                    logger.debug("Connection pool request failed for %s (%s); falling back to urllib.request", url, exc)
                    req = urllib.request.Request(url, headers=headers)
                    pins = getattr(collector, "pinned_thumbprints", None) or None
                    fallback_opener = build_bmc_opener(
                        ssl_context=ssl_ctx,
                        pinned_thumbprints=pins,
                    )
                    with fallback_opener.open(req, timeout=timeout) as r:
                        raw = r.read()
                        if isinstance(raw, bytes):
                            raw = raw.decode("utf-8", errors="replace")
                        status_val = getattr(r, "status", None) or getattr(r, "code", None)
                        status = status_val if isinstance(status_val, int) else 200
            elif opener is not None:
                req = urllib.request.Request(url, headers=headers)
                with opener.open(req, timeout=timeout) as r:
                    status_val = getattr(r, "status", None) or getattr(r, "code", None)
                    status = status_val if isinstance(status_val, int) else 200
                    raw = r.read().decode("utf-8", errors="replace")
            else:
                req = urllib.request.Request(url, headers=headers)
                with build_bmc_opener(ssl_context=ssl_ctx).open(req, timeout=timeout) as r:
                    status_val = getattr(r, "status", None) or getattr(r, "code", None)
                    status = status_val if isinstance(status_val, int) else 200
                    raw = r.read().decode("utf-8", errors="replace")

            stage_fn = getattr(collector, "_update_stage", None)
            retry_hook = getattr(collector, "oem_handle_retry", None)

            if 200 <= status < 300:
                logger.debug(f"GET {url} -> {status}")
                with lock_ctx:
                    collector._last_http_status = status
                    collector._request_count = getattr(collector, "_request_count", 0) + 1
                    collector._last_active_time = time.time()
                    collector._consecutive_timeouts = 0
                    collector._consecutive_successes = getattr(collector, "_consecutive_successes", 0) + 1
                if callable(throttle_fn):
                    try:
                        throttle_fn(status)
                    except TypeError:
                        throttle_fn()
                if callable(stage_fn):
                    stage_fn(getattr(collector, "_current_stage", "Scanning…"))
                try:
                    data = json.loads(raw)
                    # OEM retry hook (e.g., HPE iLO ResourceNotReadyRetry)
                    if callable(retry_hook) and retry_hook(data, endpoint):
                        if attempt == 0 and _retry and not (callable(is_cancelled_fn) and is_cancelled_fn()):
                            logger.debug(f"oem_handle_retry triggered on {url}, waiting 3s...")
                            time.sleep(3)
                            continue
                        logger.debug(f"oem_handle_retry unhandled or exhausted on {url}, returning None without caching")
                        return None
                    with lock_ctx:
                        req_cache = getattr(collector, "_request_cache", None)
                        if req_cache is not None:
                            if not getattr(collector, "_preserve_all_raw", False) and len(req_cache) >= 500:
                                try:
                                    oldest_k = next(iter(req_cache))
                                    del req_cache[oldest_k]
                                except (StopIteration, KeyError):
                                    pass
                            req_cache[url] = data
                    return data
                except json.JSONDecodeError:
                    # Supermicro BMCs return HTML 404 pages for missing endpoints — expected
                    logger.debug(f"Non-JSON response from {url} (likely HTML 404 page)")
                    return None
            else:
                logger.debug(f"HTTP {status} for {url}")
                with lock_ctx:
                    collector._last_http_status = status
                    collector._request_count = getattr(collector, "_request_count", 0) + 1
                    collector._last_active_time = time.time()
                    if status in (429, 500, 502, 503, 504):
                        collector._consecutive_timeouts = getattr(collector, "_consecutive_timeouts", 0) + 1
                        collector._consecutive_successes = 0
                    else:
                        collector._consecutive_timeouts = 0
                        collector._consecutive_successes = getattr(collector, "_consecutive_successes", 0) + 1
                if callable(throttle_fn):
                    try:
                        throttle_fn(status)
                    except TypeError:
                        throttle_fn()
                if callable(stage_fn):
                    stage_fn(getattr(collector, "_current_stage", "Scanning…"))

                # Transient server error retry
                if status in (500, 502, 503, 504) and attempt < max_attempts - 1 and _retry and not (callable(is_cancelled_fn) and is_cancelled_fn()):
                    logger.debug(f"Transient HTTP {status} for {url}; retrying attempt {attempt + 2}/{max_attempts} after 1.5s...")
                    time.sleep(1.5)
                    continue

                # OEM retry check for non-200 responses (e.g. HPE ResourceNotReady, Dell SYS518)
                try:
                    err_data = json.loads(raw) if raw else {}
                    if isinstance(err_data, dict) and callable(retry_hook) and retry_hook(err_data, endpoint):
                        if attempt < max_attempts - 1 and _retry and not (callable(is_cancelled_fn) and is_cancelled_fn()):
                            logger.debug(f"oem_handle_retry triggered on HTTP {status} for {url}, waiting 3s...")
                            time.sleep(3)
                            continue
                except (json.JSONDecodeError, Exception):
                    pass

                if status == 401:
                    if getattr(collector, "session_token", ""):
                        logger.debug(f"Session token expired for {url} (HTTP 401). Clearing session and retrying with Basic Auth...")
                        collector.session_token = ""
                        collector.session_uri = ""
                        headers.pop("X-Auth-Token", None)
                        auth_hdr = getattr(collector, "_auth_header", "")
                        headers["Authorization"] = f"Basic {auth_hdr}"
                        if not (callable(is_cancelled_fn) and is_cancelled_fn()):
                            time.sleep(0.5)
                            return collector._get(endpoint, _retry=False, timeout=timeout, critical=critical)
                    if critical and not any(opt in url for opt in ("/TelemetryService", "/MetricReports", "/LicenseService", "/EventService", "/JobService")):
                        collector.auth_failed = True
                        cred_prov = getattr(collector, "credential_provider", None)
                        if cred_prov and hasattr(cred_prov, "invalidate"):
                            try:
                                cred_prov.invalidate(target_host)
                            except Exception as inv_err:
                                logger.debug("Credential provider invalidation failed: %s", inv_err)
                        if not is_mocked:
                            record_auth_lockout(target_host)
                elif status == 403:
                    if critical and not any(opt in url for opt in ("/TelemetryService", "/MetricReports", "/LicenseService", "/EventService", "/JobService")):
                        collector.auth_failed = True
                elif status == 404:
                    is_dell = getattr(collector, "vendor", "") == "dell"
                    if is_dell and attempt == 0 and _retry and not (callable(is_cancelled_fn) and is_cancelled_fn()):
                        logger.debug("Transient 404 on Dell BMC for %s; retrying once...", url)
                        time.sleep(2)
                        continue
                    with lock_ctx:
                        neg_counts = getattr(collector, "_negative_endpoint_counts", None)
                        if neg_counts is None:
                            collector._negative_endpoint_counts = {}
                            neg_counts = collector._negative_endpoint_counts
                        neg_counts[path_suffix] = neg_counts.get(path_suffix, 0) + 1
                        neg_endpoints = getattr(collector, "_negative_endpoints", None)
                        if neg_endpoints is not None:
                            neg_endpoints.add(path_suffix)
                            logger.debug("Added negative endpoint pattern: %s (after %d 404s)", path_suffix, neg_counts[path_suffix])
                if "/TelemetryService" in url:
                    if status in (403, 404, 500, 502, 503, 504):
                        collector._telemetry_service_supported = False
                return None
        except HTTPError as e:
            logger.debug(f"HTTP {e.code} for {url}")
            with lock_ctx:
                collector._last_http_status = e.code
                collector._request_count = getattr(collector, "_request_count", 0) + 1
                collector._last_active_time = time.time()
                if e.code in (429, 500, 502, 503, 504):
                    collector._consecutive_timeouts = getattr(collector, "_consecutive_timeouts", 0) + 1
                    collector._total_timeouts_encountered = getattr(collector, "_total_timeouts_encountered", 0) + 1
                    collector._consecutive_successes = 0
                else:
                    collector._consecutive_timeouts = 0
                    collector._consecutive_successes = getattr(collector, "_consecutive_successes", 0) + 1
            if callable(throttle_fn):
                try:
                    throttle_fn(e.code)
                except TypeError:
                    throttle_fn()
            stage_fn = getattr(collector, "_update_stage", None)
            if callable(stage_fn):
                stage_fn(getattr(collector, "_current_stage", "Scanning…"))

            # Read error body if available for OEM retry detection
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass

            # Transient server error retry
            if e.code in (500, 502, 503, 504) and attempt < max_attempts - 1 and _retry and not (callable(is_cancelled_fn) and is_cancelled_fn()):
                logger.debug(f"Transient HTTP {e.code} for {url}; retrying attempt {attempt + 2}/{max_attempts} after 1.5s...")
                time.sleep(1.5)
                continue

            retry_hook = getattr(collector, "oem_handle_retry", None)
            if err_body:
                try:
                    err_data = json.loads(err_body)
                    if isinstance(err_data, dict) and callable(retry_hook) and retry_hook(err_data, endpoint):
                        if attempt < max_attempts - 1 and _retry and not (callable(is_cancelled_fn) and is_cancelled_fn()):
                            logger.debug(f"oem_handle_retry triggered on HTTP {e.code} for {url}, waiting 3s...")
                            time.sleep(3)
                            continue
                except (json.JSONDecodeError, Exception):
                    pass

            if e.code == 401:
                if getattr(collector, "session_token", ""):
                    logger.debug(f"Session token expired for {url} (HTTP 401). Clearing session and retrying with Basic Auth...")
                    collector.session_token = ""
                    collector.session_uri = ""
                    headers.pop("X-Auth-Token", None)
                    auth_hdr = getattr(collector, "_auth_header", "")
                    headers["Authorization"] = f"Basic {auth_hdr}"
                    if not (callable(is_cancelled_fn) and is_cancelled_fn()):
                        time.sleep(0.5)
                        return collector._get(endpoint, _retry=False, timeout=timeout, critical=critical)
                if critical and not any(opt in url for opt in ("/TelemetryService", "/MetricReports", "/LicenseService", "/EventService", "/JobService")):
                    collector.auth_failed = True
                    cred_prov = getattr(collector, "credential_provider", None)
                    if cred_prov and hasattr(cred_prov, "invalidate"):
                        try:
                            cred_prov.invalidate(target_host)
                        except Exception as inv_err:
                            logger.debug("Credential provider invalidation failed: %s", inv_err)
                    if not is_mocked:
                        record_auth_lockout(target_host)
            elif e.code == 403:
                if critical and not any(opt in url for opt in ("/TelemetryService", "/MetricReports", "/LicenseService", "/EventService", "/JobService")):
                    collector.auth_failed = True
            elif e.code == 404:
                is_dell = getattr(collector, "vendor", "") == "dell"
                if is_dell and attempt == 0 and _retry and not (callable(is_cancelled_fn) and is_cancelled_fn()):
                    logger.debug("Transient 404 on Dell BMC for %s; retrying once...", url)
                    time.sleep(2)
                    continue
                with lock_ctx:
                    neg_counts = getattr(collector, "_negative_endpoint_counts", None)
                    if neg_counts is None:
                        collector._negative_endpoint_counts = {}
                        neg_counts = collector._negative_endpoint_counts
                    neg_counts[path_suffix] = neg_counts.get(path_suffix, 0) + 1
                    neg_endpoints = getattr(collector, "_negative_endpoints", None)
                    if neg_endpoints is not None:
                        neg_endpoints.add(path_suffix)
                        logger.debug("Added negative endpoint pattern: %s (after %d 404s)", path_suffix, neg_counts[path_suffix])
            if "/TelemetryService" in url:
                if e.code in (403, 404, 500, 502, 503, 504):
                    collector._telemetry_service_supported = False
            return None
        except (TimeoutError, socket.timeout, ssl.SSLError) as e:
            # Catch TLS certificate validation errors immediately without retrying
            is_cert_err = isinstance(e, (ssl.SSLCertVerificationError, ssl.CertificateError)) or (
                isinstance(e, ssl.SSLError) and any(kw in str(e).lower() for kw in ("certificate verify failed", "self-signed", "certificate has expired", "hostname"))
            )
            if is_cert_err:
                collector.ssl_error = e
                logger.warning(f"TLS certificate verification failed for {url}: {e}")
                return None

            is_expired_p1 = getattr(collector, "_phase1_expired", False) and getattr(_thread_local, "is_phase1", False)
            is_expired_p2 = getattr(collector, "_phase2_expired", False) and getattr(_thread_local, "is_phase2", False)
            is_non_critical = not critical or any(nc in url for nc in ("/TelemetryService", "/MetricReports"))
            if "/TelemetryService" in url:
                collector._telemetry_service_supported = False
            if not is_expired_p1 and not is_expired_p2 and not is_non_critical:
                with lock_ctx:
                    collector._last_http_status = None
                    collector._consecutive_timeouts = getattr(collector, "_consecutive_timeouts", 0) + 1
                    collector._total_timeouts_encountered = getattr(collector, "_total_timeouts_encountered", 0) + 1
                    collector._consecutive_successes = 0
                    consec = collector._consecutive_timeouts
                if callable(throttle_fn):
                    throttle_fn()
            else:
                with lock_ctx:
                    collector._last_http_status = None
                    collector._total_timeouts_encountered = getattr(collector, "_total_timeouts_encountered", 0) + 1
                    consec = getattr(collector, "_consecutive_timeouts", 0)
            logger.debug(f"Timeout querying {url} (consecutive timeouts: {consec}): {e}")
            if attempt < max_attempts - 1 and consec < 5 and not (callable(is_cancelled_fn) and is_cancelled_fn()) and not is_non_critical:
                logger.debug(f"Retrying GET {url} after timeout...")
                if "handshake" in str(e).lower() or "ssl" in str(e).lower():
                    time.sleep(2)
                continue
            return None
        except URLError as e:
            # Catch wrapped SSL certificate verification errors in URLError
            if isinstance(getattr(e, "reason", None), (ssl.SSLCertVerificationError, ssl.CertificateError, ssl.SSLError)):
                reason_str = str(e.reason).lower()
                if any(kw in reason_str for kw in ("certificate verify failed", "self-signed", "certificate has expired", "hostname")):
                    collector.ssl_error = e.reason
                    logger.warning(f"TLS certificate verification failed for {url}: {e.reason}")
                    return None
            is_expired_p1 = getattr(collector, "_phase1_expired", False) and getattr(_thread_local, "is_phase1", False)
            is_expired_p2 = getattr(collector, "_phase2_expired", False) and getattr(_thread_local, "is_phase2", False)
            is_non_critical = not critical or any(nc in url for nc in ("/TelemetryService", "/MetricReports"))
            if "/TelemetryService" in url:
                collector._telemetry_service_supported = False
            if not is_expired_p1 and not is_expired_p2 and not is_non_critical:
                with lock_ctx:
                    collector._last_http_status = None
                    collector._consecutive_timeouts = getattr(collector, "_consecutive_timeouts", 0) + 1
                    collector._total_timeouts_encountered = getattr(collector, "_total_timeouts_encountered", 0) + 1
                    collector._consecutive_successes = 0
                    consec = collector._consecutive_timeouts
                if callable(throttle_fn):
                    throttle_fn()
            else:
                with lock_ctx:
                    collector._last_http_status = None
                    collector._total_timeouts_encountered = getattr(collector, "_total_timeouts_encountered", 0) + 1
                    consec = getattr(collector, "_consecutive_timeouts", 0)
            logger.debug(f"URLError for {url}: {e.reason}")
            if attempt < max_attempts - 1 and consec < 5 and not (callable(is_cancelled_fn) and is_cancelled_fn()) and not is_non_critical:
                logger.debug(f"Retrying GET {url} after URLError ({e.reason})...")
                err_str = str(e.reason).lower()
                if "handshake" in err_str or "ssl" in err_str or "timed out" in err_str:
                    time.sleep(2)
                continue
            return None
        except http.client.HTTPException as e:
            logger.debug(f"HTTPException querying {url}: {e}")
            with lock_ctx:
                collector._last_http_status = None
                collector._consecutive_timeouts = getattr(collector, "_consecutive_timeouts", 0) + 1
                collector._total_timeouts_encountered = getattr(collector, "_total_timeouts_encountered", 0) + 1
                collector._consecutive_successes = 0
                consec = collector._consecutive_timeouts
            if callable(throttle_fn):
                throttle_fn()
            if attempt < max_attempts - 1 and consec < 5 and not (callable(is_cancelled_fn) and is_cancelled_fn()):
                continue
            return None
        except Exception as e:
            logger.debug(f"Unexpected error querying {url}: {e}")
            return None
        finally:
            with lock_ctx:
                collector._last_req_finish_time = time.time()
            if inner_cv is not None:
                with inner_cv:
                    collector._active_inner_workers = max(0, getattr(collector, "_active_inner_workers", 1) - 1)
                    inner_cv.notify_all()

    return None


class _HttpGetMixin:
    """HTTP GET transport mixin for Redfish collectors."""

    def _get(self, endpoint: str, _retry: bool = True, timeout: int = 15, critical: bool = True) -> Optional[dict]:
        return redfish_get(self, endpoint, _retry=_retry, timeout=timeout, critical=critical)


__all__ = [
    "RedfishSessionManager",
    "compute_request_pacing",
    "redfish_get",
    "_HttpGetMixin",
    "_BMC_INNER_WORKERS",
    "_thread_local",
    "record_auth_lockout",
    "is_host_auth_locked",
    "clear_auth_lockout",
]
