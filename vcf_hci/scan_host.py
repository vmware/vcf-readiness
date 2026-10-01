"""
VCF Readiness Tool — Per-host scanning helper.

Provides _scan_one_host() and protocol dispatch logic for scanning individual
BMC targets via Redfish, WS-Man, or identifying unsupported interfaces.
"""

import logging
import time
from typing import Any, Optional, Tuple

logger = logging.getLogger("vcf_assess")

from vcf_hci.collector.oem import create_collector
from vcf_hci.enrichment import enrich_host_result
from vcf_hci.logging_utils import resolve_target_fqdn
from vcf_hci.protocol import detect_management_protocol
from vcf_hci.tls_utils import format_ssl_error
from vcf_hci.wsman import WsManCollector


def _timeout_reason_code(stage: Optional[str], collector: Optional[Any] = None) -> str:
    stg = stage or ""
    if collector is not None:
        if bool(getattr(collector, "session_token", None)):
            return "timeout_after_auth"
        if bool(getattr(collector, "sys_uris", None)):
            return "timeout_after_auth"
    post_auth = ("Collecting", "Phase", "Discovering", "Evaluating", "Deep Redfish", "Targeted Rescan")
    if any(tok in stg for tok in post_auth):
        return "timeout_after_auth"
    return "timeout_before_auth"


def get_credentials_for_ip(creds: Any, ip: str) -> Optional[Tuple[str, str]]:
    if isinstance(creds, dict):
        if ip in creds:
            val = creds[ip]
            if isinstance(val, (tuple, list)) and len(val) >= 2:
                return (str(val[0]), str(val[1]))
            return None
        for fallback_key in ("default", "*", "__default__"):
            if fallback_key in creds:
                val = creds[fallback_key]
                if isinstance(val, (tuple, list)) and len(val) >= 2:
                    return (str(val[0]), str(val[1]))
        return None
    elif isinstance(creds, (tuple, list)) and len(creds) >= 2:
        return (str(creds[0]), str(creds[1]))
    return None


def _scan_log(ctx: Any, msg: str, event: str = "log") -> None:
    log_fn = getattr(ctx, "log", None)
    if callable(log_fn):
        try:
            log_fn(msg, event=event)
        except Exception:
            pass
    else:
        logger.info(msg)


def _scan_one_host(
    ip: str, ctx: Any
) -> Tuple[Optional[Any], bool, bool, Optional[dict]]:
    cancel_event = getattr(ctx, "cancel_event", None)
    if cancel_event and cancel_event.is_set():
        return None, False, False, None

    skip_host_set = getattr(ctx, "skip_host_set", None)
    if skip_host_set is not None and ip in skip_host_set:
        _scan_log(ctx, f"  [⏭️] {ip} — skipped before scan start")
        return None, False, False, None

    _h_start = time.time()
    prior_results_map = getattr(ctx, "prior_results_map", {}) or {}
    prior_host_data = prior_results_map.get(ip)
    is_targeted_rescan = bool(
        prior_host_data
        and isinstance(prior_host_data, dict)
        and prior_host_data.get("partial_scan")
        and prior_host_data.get("partial_sections")
    )
    _last_stage = "Connecting for Targeted Rescan..." if is_targeted_rescan else "Connecting & Protocol Discovery"
    try:
        host_start_callback = getattr(ctx, "host_start_callback", None)
        if host_start_callback:
            try:
                host_start_callback({
                    "ip": ip,
                    "start_time": _h_start,
                    "is_rescan": is_targeted_rescan,
                    "stage": _last_stage,
                })
            except Exception:
                pass

        host_stage_callback = getattr(ctx, "host_stage_callback", None)

        def _stage_cb(host_ip: str, stage_data: Any) -> None:
            nonlocal _last_stage
            if isinstance(stage_data, dict):
                st = stage_data.get("stage")
                if st:
                    _last_stage = str(st)
            elif isinstance(stage_data, str) and stage_data:
                _last_stage = stage_data

            if host_stage_callback:
                try:
                    if isinstance(stage_data, dict):
                        host_stage_callback(stage_data)
                    else:
                        host_stage_callback({"ip": host_ip, "stage": str(stage_data)})
                except Exception:
                    pass

        server_hostname = None
        dns_lookup = getattr(ctx, "dns_lookup", False)
        verify_ssl = getattr(ctx, "verify_ssl", False)
        if dns_lookup or verify_ssl:
            resolved_fqdn = resolve_target_fqdn(ip)
            if resolved_fqdn:
                server_hostname = resolved_fqdn
                _scan_log(ctx, f"  [🌐] {ip} → {resolved_fqdn} (FCrDNS verified)")

        cred_pair = None
        if callable(getattr(ctx, "get_credentials", None)):
            cred_pair = ctx.get_credentials(ip)
        elif hasattr(ctx, "creds"):
            cred_pair = get_credentials_for_ip(ctx.creds, ip)

        if cred_pair is None:
            _scan_log(ctx, f"  [✗] {ip} — no credentials provided; skipping")
            logger.warning(f"{ip}: no credentials provided; skipping")
            fail_info = {
                "ip": ip,
                "hostname": server_hostname or "Unknown",
                "reason_code": "no_credentials",
                "reason_label": "No Credentials Provided",
                "stage": "Credential Resolution",
                "detail": f"No credentials provided for target {ip}",
                "error": "no credentials provided",
                "vendor_model": "",
            }
            return None, False, False, fail_info
        user, pwd = cred_pair

        detect_proto_fn = getattr(ctx, "detect_management_protocol", detect_management_protocol)
        diag = {}
        try:
            res = detect_proto_fn(
                ip,
                timeout=getattr(ctx, "discovery_timeout", 8.0),
                verify_ssl=verify_ssl,
                ca_bundle=getattr(ctx, "ca_bundle", None),
                enable_dash=getattr(ctx, "enable_dash", False),
                return_diagnostics=True,
            )
            if isinstance(res, tuple) and len(res) == 3:
                proto, port, diag = res
            else:
                proto, port = res[0], res[1]
        except TypeError:
            proto, port = detect_proto_fn(
                ip,
                verify_ssl=verify_ssl,
                ca_bundle=getattr(ctx, "ca_bundle", None),
                enable_dash=getattr(ctx, "enable_dash", False),
            )
        if proto == "redfish":
            scheme = "http" if port == 80 else "https"
            if scheme == "http":
                logger.warning(
                    f"{ip}: Redfish endpoint on port {port} uses plain HTTP — "
                    "credentials and inventory will be transmitted UNENCRYPTED."
                )
            collector_kwargs = {
                "host_timeout": getattr(ctx, "host_timeout", 300),
                "verify_ssl": verify_ssl,
                "ca_bundle": getattr(ctx, "ca_bundle", None),
                "server_hostname": server_hostname,
                "scheme": scheme,
                "port": port,
                "pinned_thumbprints": getattr(ctx, "pinned_thumbprints", None),
            }
            if getattr(ctx, "legacy_tls", False):
                collector_kwargs["legacy_ciphers"] = True
            if getattr(ctx, "tls_min_version", None):
                collector_kwargs["tls_min_version"] = ctx.tls_min_version

            create_collector_fn = getattr(ctx, "create_collector", create_collector)
            with create_collector_fn(
                ip,
                user,
                pwd,
                **collector_kwargs,
            ) as c:
                c.stage_callback = _stage_cb
                c.cancel_event = cancel_event
                c.host_timeout = getattr(ctx, "host_timeout", 300)
                if skip_host_set is not None:
                    c.skip_host_set = skip_host_set
                if is_targeted_rescan:
                    _p_sec = prior_host_data.get("partial_sections", [])
                    _friendly_sec = [s.replace('_', ' ').title() for s in _p_sec]
                    _scan_log(ctx, f"  [🔄] {ip} — rescanning {len(_p_sec)} missing section(s): {', '.join(_friendly_sec)}")
                    data = c.rescan_partial_sections(prior_host_data, _p_sec)
                else:
                    run_kwargs = {
                        "quick_mode": getattr(ctx, "quick", False),
                        "capture_raw": (getattr(ctx, "debug", False) or getattr(ctx, "include_raw", False)),
                        "lean_mode": getattr(ctx, "lean", False),
                        "allow_partial": getattr(ctx, "allow_partial", False),
                        "scan_profile": getattr(ctx, "profile", None),
                    }
                    if getattr(ctx, "crawl_endpoints", False):
                        run_kwargs["crawl_endpoints"] = True
                    data = c.run_assessment(**run_kwargs)
                auth_failed = getattr(c, "auth_failed", False)
                skipped = getattr(c, "skipped", False)
                ssl_err = getattr(c, "ssl_error", None)
                c_timeouts = getattr(c, "_consecutive_timeouts", 0)
                if not isinstance(c_timeouts, (int, float)):
                    c_timeouts = 0
                timed_out = (getattr(c, "timed_out", False) is True) or c_timeouts >= 4
                if timed_out:
                    timed_out_lock = getattr(ctx, "timed_out_lock", None)
                    timed_out_hosts = getattr(ctx, "timed_out_hosts", None)
                    if timed_out_lock and timed_out_hosts is not None:
                        with timed_out_lock:
                            if ip not in timed_out_hosts:
                                timed_out_hosts.append(ip)
                if skipped and not (data and data.get("partial_scan")):
                    _scan_log(ctx, f"  [⏭️] {ip} — skipped ({'timeout' if timed_out else 'user request'})")

                enrich_fn = getattr(ctx, "enrich_host_result", enrich_host_result)
                if data:
                    data = enrich_fn(data, json_hcl=getattr(ctx, "json_hcl", None), csv_db=getattr(ctx, "csv_db", None))

                fail_info = None
                if not data:
                    stg = getattr(c, "_current_stage", _last_stage)
                    if ssl_err:
                        err_info = format_ssl_error(ssl_err, ip, port)
                        fail_info = {
                            "ip": ip,
                            "hostname": server_hostname or "Unknown",
                            "reason_code": err_info["reason_code"],
                            "reason_label": err_info["reason_label"],
                            "stage": stg,
                            "detail": err_info["detail"],
                            "vendor_model": "",
                        }
                    elif auth_failed:
                        rcode = "auth_failed"
                        rlabel = "Authentication Failed (HTTP 401/403)"
                        rdetail = f"HTTP 401/403 Unauthorized for user '{user}'"
                        fail_info = {
                            "ip": ip,
                            "hostname": server_hostname or "Unknown",
                            "reason_code": rcode,
                            "reason_label": rlabel,
                            "stage": stg,
                            "detail": rdetail,
                            "vendor_model": "",
                        }
                    elif timed_out:
                        timeout_fn = getattr(ctx, "timeout_reason_code", _timeout_reason_code)
                        rcode = timeout_fn(stg, collector=c)
                        rlabel = "Timed Out During Collection"
                        elapsed_s = max(1, int(round(time.time() - _h_start)))
                        rdetail = f"Timed out after {elapsed_s}s during {stg}"
                        fail_info = {
                            "ip": ip,
                            "hostname": server_hostname or "Unknown",
                            "reason_code": rcode,
                            "reason_label": rlabel,
                            "stage": stg,
                            "detail": rdetail,
                            "vendor_model": "",
                        }
                    else:
                        rcode = "connection_failed"
                        rlabel = "Connection Refused / Unreachable"
                        rdetail = f"No Redfish service responding on target {ip}"
                        fail_info = {
                            "ip": ip,
                            "hostname": server_hostname or "Unknown",
                            "reason_code": rcode,
                            "reason_label": rlabel,
                            "stage": stg,
                            "detail": rdetail,
                            "vendor_model": "",
                        }
                return data, auth_failed, timed_out, fail_info
        elif proto in ("amt", "dash"):
            wsman_cls = getattr(ctx, "wsman_collector_cls", WsManCollector)
            with wsman_cls(
                ip,
                user,
                pwd,
                protocol=proto,
                port=port,
                host_timeout=getattr(ctx, "host_timeout", 300),
                verify_ssl=verify_ssl,
                ca_bundle=getattr(ctx, "ca_bundle", None),
            ) as c:
                c.stage_callback = _stage_cb
                c.cancel_event = cancel_event
                c.host_timeout = getattr(ctx, "host_timeout", 300)
                if skip_host_set is not None:
                    c.skip_host_set = skip_host_set
                if is_targeted_rescan:
                    data = c.rescan_partial_sections(prior_host_data)
                else:
                    data = c.run_assessment(allow_partial=getattr(ctx, "allow_partial", False))
                auth_failed = getattr(c, "auth_failed", False)
                skipped = getattr(c, "skipped", False)
                timed_out = (getattr(c, "timed_out", False) is True)
                if timed_out:
                    timed_out_lock = getattr(ctx, "timed_out_lock", None)
                    timed_out_hosts = getattr(ctx, "timed_out_hosts", None)
                    if timed_out_lock and timed_out_hosts is not None:
                        with timed_out_lock:
                            if ip not in timed_out_hosts:
                                timed_out_hosts.append(ip)
                if skipped and not (data and data.get("partial_scan")):
                    _scan_log(ctx, f"  [⏭️] {ip} — skipped ({'timeout' if timed_out else 'user request'})")

                enrich_fn = getattr(ctx, "enrich_host_result", enrich_host_result)
                if data:
                    data = enrich_fn(data, json_hcl=getattr(ctx, "json_hcl", None), csv_db=getattr(ctx, "csv_db", None))

                fail_info = None
                if not data:
                    stg = getattr(c, "_current_stage", _last_stage)
                    if auth_failed:
                        rcode = "auth_failed"
                        rlabel = "Authentication Failed (HTTP 401/403)"
                        rdetail = f"WS-Man HTTP 401/403 Unauthorized for user '{user}'"
                    elif timed_out:
                        rcode = "timeout_after_auth"
                        rlabel = "Timed Out During Collection"
                        elapsed_s = max(1, int(round(time.time() - _h_start)))
                        rdetail = f"WS-Man timed out after {elapsed_s}s during {stg}"
                    else:
                        rcode = "connection_failed"
                        rlabel = "Connection Refused / Unreachable"
                        rdetail = f"No WS-Man service responding on target {ip}"
                    fail_info = {
                        "ip": ip,
                        "hostname": "Unknown",
                        "reason_code": rcode,
                        "reason_label": rlabel,
                        "stage": stg,
                        "detail": rdetail,
                        "vendor_model": "",
                    }
                return data, auth_failed, timed_out, fail_info
        elif proto == "ipmi":
            _scan_log(
                ctx,
                f"  [!] {ip} — IPMI/RMCP detected on port 623. "
                "IPMI is not supported; upgrade firmware to Redfish or use an IPMI tool."
            )
            fail_info = {
                "ip": ip,
                "hostname": "Unknown",
                "reason_code": "unsupported_protocol",
                "reason_label": "IPMI/RMCP Only (Unsupported)",
                "stage": "Protocol Discovery",
                "detail": "IPMI/RMCP detected on port 623; upgrade BMC to Redfish",
                "vendor_model": "",
            }
            return None, False, False, fail_info
        else:
            is_443_open = diag.get("port_443_open")
            is_80_open = diag.get("port_80_open")
            if is_443_open is None and is_80_open is None:
                from vcf_hci.protocol import _tcp_reachable
                is_443_open = _tcp_reachable(ip, 443, 2.0)
                is_80_open = _tcp_reachable(ip, 80, 2.0) if not is_443_open else False

            if is_443_open or is_80_open or diag.get("probe_timeout"):
                open_p = 443 if is_443_open else 80
                probe_t = diag.get("probe_timeout_seconds") or getattr(ctx, "discovery_timeout", 8.0)
                _scan_log(ctx, f"  [✗] {ip} — Port {open_p} open, but Redfish probe timed out after {probe_t}s (slow/hung BMC HTTP service)")
                fail_info = {
                    "ip": ip,
                    "hostname": "Unknown",
                    "reason_code": "probe_timeout",
                    "reason_label": f"BMC Web Service Unresponsive (Port {open_p} Open)",
                    "stage": "Protocol Discovery",
                    "detail": f"Port {open_p} reachable on {ip}, but Redfish probe timed out after {probe_t}s (slow/hung BMC HTTP service)",
                    "vendor_model": "",
                }
            else:
                _scan_log(ctx, f"  [✗] {ip} — no Redfish, AMT, or DASH interface found on standard ports")
                fail_info = {
                    "ip": ip,
                    "hostname": "Unknown",
                    "reason_code": "connection_failed",
                    "reason_label": "Connection Refused / Unreachable",
                    "stage": "Protocol Discovery",
                    "detail": f"No Redfish, AMT, or DASH interface found on {ip}",
                    "vendor_model": "",
                }
            return None, False, False, fail_info
    finally:
        _h_dur = time.time() - _h_start
        dur_lock = getattr(ctx, "dur_lock", None)
        host_durations = getattr(ctx, "host_durations", None)
        if dur_lock and host_durations is not None:
            with dur_lock:
                host_durations[ip] = _h_dur
