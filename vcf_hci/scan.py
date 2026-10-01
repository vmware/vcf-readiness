"""
VCF Readiness Tool — Unified host scan engine.

scan_hosts() provides a single shared scanning loop used by both the CLI
and the Web server. It executes multi-threaded data collection, report
generation (host, fleet, obfuscated, combined, and JSON), Dell warranty enrichment,
cancellation support, and callback hooks for logging and progress.
"""

import copy
import logging
import os
import threading
import time
import types
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from typing import Any, Callable, Optional, Tuple, Union

logger = logging.getLogger("vcf_assess")

from vcf_hci.collector.oem import create_collector
from vcf_hci.constants import COMBINED_HTML_MAX_HOSTS
from vcf_hci.enrichment import enrich_host_result
from vcf_hci.fleet_discovery import (
    discover_and_prioritize_fleet,
    load_discovery_cache,
    save_discovery_cache,
)
from vcf_hci.hcl import (
    ensure_auto_hcl_bundle,
    import_hcl_bundle,
    load_optional_vsan_csv,
    load_vsan_hcl_json,
)
from vcf_hci.logging_utils import (
    configure_logging,
    create_obfuscated_scan_zip_archive,
    create_scan_output_dir,
    create_scan_zip_archive,
    normalize_output_dir,
    sanitize_filename,
    update_latest_scan_aliases,
)
from vcf_hci.obfuscation import obfuscate_host_data
from vcf_hci.protocol import detect_management_protocol, probe_fleet_network_latency
from vcf_hci.report import (
    _build_excel_sheets,
    _generate_combined_html,
    _write_xlsx,
    export_all_csvs,
    generate_host_html_report,
    generate_summary_html,
    write_scan_readme,
)
from vcf_hci.scan_complete import _handle_completed_host
from vcf_hci.scan_host import _scan_one_host, _timeout_reason_code, get_credentials_for_ip
from vcf_hci.summary_io import load_summary, write_fleet_summary
from vcf_hci.system_throttle import SystemThrottleMonitor
from vcf_hci.wsman import WsManCollector

_get_credentials_for_ip = get_credentials_for_ip

try:
    from vcf_hci.servicetag import DellTechDirectClient, summarise_warranty
except ImportError:
    DellTechDirectClient: Any = None  # type: ignore[assignment,misc]
    summarise_warranty: Any = None    # type: ignore[assignment]


def _format_dur_min(sec: float) -> str:
    m = sec / 60.0
    if m < 1.0:
        return f"{m:.1f} minutes ({round(sec)}s)"
    return f"{m:.1f} minutes"


def scan_hosts(
    target_ips: list,
    creds: Union[dict, tuple],
    outdir: str,
    threads: int = 8,
    quick: bool = False,
    lean: bool = False,
    profile: Optional[str] = None,
    obfuscate: bool = False,
    debug: bool = False,
    save_json: bool = False,
    include_raw: bool = False,
    combined: bool = False,
    dell_creds: Optional[dict] = None,
    csv_path: Optional[str] = None,
    hcl_bundle_path: Optional[str] = None,
    excel: bool = True,
    export_sheets: bool = True,
    create_subfolder: bool = True,
    create_zip: bool = True,
    cancel_event: Optional[threading.Event] = None,
    log_callback: Optional[Callable[[str, str], None]] = None,
    host_start_callback: Optional[Callable[[dict], None]] = None,
    host_stage_callback: Optional[Callable[[dict], None]] = None,
    host_done_callback: Optional[Callable[[dict], None]] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    skip_host_set: Optional[set] = None,
    host_timeout: int = 300,
    allow_partial: bool = False,
    prior_results: Optional[list] = None,
    force_threads: bool = False,
    verify_ssl: bool = False,
    ca_bundle: Optional[str] = None,
    dns_lookup: bool = False,
    pinned_thumbprints: Optional[dict] = None,
    enable_dash: bool = False,
    append_log: bool = False,
    two_pass: bool = False,
    auto_throttle: bool = True,
    crawl_endpoints: bool = False,
    legacy_tls: bool = False,
    tls_min_version: Optional[str] = None,
    discovery_cache: Optional[str] = None,
    discover_only: bool = False,
    prune_inactive: bool = False,
    generate_fleet_artifacts: bool = True,
    site: Optional[str] = None,
    collector_id: Optional[str] = None,
    allow_timeout_retry: bool = True,
) -> dict:
    """Execute multi-threaded scan across target_ips and generate reports.

    Args:
        target_ips: List of BMC IP addresses / hostnames to scan.
        creds: Dict mapping IP -> (username, password) OR tuple (username, password).
        outdir: Base output directory path (e.g. ~/Desktop/VCF-Scans).
        threads: Number of parallel worker threads.
        quick: If True, gather CPU, BIOS, and logs only (quick scan).
        lean: If True, skip telemetry, firmware inventory, and extra thermal GETs.
        profile: Scan profile: 'readiness-full', 'readiness-lean', or 'inventory-lite'.
        obfuscate: If True, write OBFUSCATED_* reports alongside normal reports.
        debug: If True, write verbose debug log file and raw JSON responses.
        save_json: If True, export per-host summary JSON files.
        combined: If True, force generation of combined tabbed HTML report even for 1 host.
        dell_creds: Optional dict with 'id' and 'secret' for Dell TechDirect warranty API.
        csv_path: Optional path to custom vSAN HCL CSV file.
        hcl_bundle_path: Optional path to dark-site HCL bundle zip.
        create_subfolder: If True, create a unique per-scan subfolder inside outdir.
        create_zip: If True, compress the scan directory into a .zip archive upon completion.
        cancel_event: Optional threading.Event to signal scan cancellation.
        log_callback: Optional callback(event_type, msg_string) for progress logging.
        host_done_callback: Optional callback(host_info_dict) called when a host finishes.
        progress_callback: Optional callback(completed_count, total_count) on host progress.

    Returns:
        dict with keys:
            'results': list of collected host data dicts
            'report_paths': list of generated individual host HTML report filepaths
            'fleet_path': path to combined tabbed HTML report if generated, else ''
            'summary_path': path to fleet summary HTML report if generated, else ''
            'outdir': effective per-scan output directory path
            'zip_path': path to created zip archive if generated, else ''
            'cancelled': bool indicating if scan was cancelled prematurely
    """
    if profile is None:
        if quick:
            profile = "inventory-lite"
            lean = True
        elif lean:
            profile = "readiness-lean"
            quick = False
        else:
            profile = "readiness-full"
            quick = False
            lean = False
    elif profile == "inventory-lite":
        quick = True
        lean = True
    elif profile == "readiness-lean":
        quick = False
        lean = True
    else:
        profile = "readiness-full"
        quick = False
        lean = False
    orig_outdir = outdir
    if create_subfolder:
        base_outdir = normalize_output_dir(outdir)
        outdir = create_scan_output_dir(
            base_dir=base_outdir,
            host_count=len(target_ips),
            quick=quick,
            obfuscate=obfuscate,
            lean=lean,
            save_json=save_json,
        )
    else:
        outdir = os.path.abspath(os.path.expanduser(str(outdir).strip())) if outdir else normalize_output_dir(outdir)
        os.makedirs(outdir, exist_ok=True)

    reports_dir = os.path.join(outdir, "reports")
    data_dir = os.path.join(outdir, "data")
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)

    def _log(msg: str, event: str = "log") -> None:
        if log_callback:
            try:
                log_callback(event, msg)
            except Exception:
                pass
        else:
            logger.info(msg)

    _debug_log = os.path.join(data_dir, "vcf_assess_debug.log") if debug else None
    if debug:
        _log_mode = "a" if (append_log or (not create_subfolder and _debug_log is not None and os.path.exists(_debug_log))) else "w"
        configure_logging(debug=True, log_file=_debug_log, mode=_log_mode)
        if _log_mode == "a":
            logger.info("=" * 60)
            logger.info("=== AUTO-RETRY / RESCAN PASS LOG CONTINUATION ===")
            logger.info("=" * 60)

    _obf_salt = os.urandom(16).hex() if obfuscate else ""

    _log(f"[→] Scan folder: {outdir}")
    _log(f"[→] Mode: {'Quick (CPU+BIOS+SEL)' if quick else 'Full'}")
    if obfuscate:
        _log("[🔒] Obfuscated copies will be written alongside normal reports")
    _log("[→] Loading vSAN HCL data…")

    json_hcl = None
    csv_db = None
    hcl_bundle_metadata = None

    if hcl_bundle_path and os.path.exists(hcl_bundle_path):
        try:
            json_hcl, csv_db, hcl_bundle_metadata = import_hcl_bundle(hcl_bundle_path)
            _log(f"[🔒] Dark-Site HCL Bundle Active: {hcl_bundle_metadata.get('bundle_filename')}")
        except Exception as _exc:
            logger.debug(f"Failed loading specified HCL bundle: {_exc}")

    if not json_hcl:
        auto_bundle_path = ensure_auto_hcl_bundle(max_age_days=30)
        if auto_bundle_path:
            try:
                json_hcl, csv_db, hcl_bundle_metadata = import_hcl_bundle(auto_bundle_path)
            except Exception as _exc:
                logger.debug(f"Failed loading auto HCL bundle: {_exc}")

    if not json_hcl:
        json_hcl = load_vsan_hcl_json(max_age_days=30)
        csv_db = load_optional_vsan_csv(csv_path)

    effective_threads = max(1, threads)
    if not force_threads and len(target_ips) >= 1 and effective_threads > 8:
        latency_info = probe_fleet_network_latency(target_ips)
        if latency_info.get("high_latency"):
            avg_rtt = latency_info.get("avg_rtt_ms", 0.0)
            max_rtt = latency_info.get("max_rtt_ms", 0.0)
            recommended_threads = min(effective_threads, 8)
            _log(
                f"[⚡] High network latency detected (avg RTT: {avg_rtt}ms, max: {max_rtt}ms over VPN/WAN). "
                f"Auto-adjusting concurrency from {effective_threads} to {recommended_threads} thread(s) to prevent BMC socket exhaustion."
            )
            effective_threads = recommended_threads

    discovery_probe_results: dict = {}
    if discovery_cache and os.path.exists(discovery_cache) and not discover_only:
        try:
            cached_targets, cached_probe_results, cache_meta = load_discovery_cache(discovery_cache, only_active=True)
            if cached_targets:
                _log(
                    f"[⚡] Discovery Cache Active: Loaded {len(cached_targets)} active target(s) from {discovery_cache} "
                    f"(cached at {cache_meta.get('timestamp', '')}). Skipping initial network sweep."
                )
                target_ips = cached_targets
                discovery_probe_results = cached_probe_results
        except Exception as _c_load_exc:
            _log(f"[!] Warning: Failed loading discovery cache '{discovery_cache}': {_c_load_exc}. Running live discovery.")

    if (two_pass or prior_results or discover_only or prune_inactive) and len(target_ips) > 1 and not discovery_probe_results:
        try:
            target_ips, discovery_probe_results = discover_and_prioritize_fleet(
                target_ips=target_ips,
                creds=creds,
                threads=min(effective_threads, 96),
                prior_results=prior_results,
                verify_ssl=verify_ssl,
                ca_bundle=ca_bundle,
                pinned_thumbprints=pinned_thumbprints,
                cancel_event=cancel_event,
                log_callback=log_callback,
                prune_inactive=(prune_inactive and not discover_only),
            )
        except Exception as _disc_exc:
            logger.debug(f"Two-pass discovery encountered error, proceeding with original order: {_disc_exc}")

    if len(target_ips) > 1 and not discovery_probe_results:
        try:
            from vcf_hci.fleet_discovery import (
                PRIORITY_MAP,
                classify_host_weight,
                extract_historical_hints,
            )
            hints_source = list(prior_results) if prior_results else []
            if not hints_source:
                candidate_paths = [
                    os.path.join(outdir, "fleet_summary.json"),
                    os.path.join(outdir, "data", "fleet_summary.json"),
                ]
                parent_dir = os.path.dirname(outdir) if os.path.basename(outdir).startswith("Scan_") else outdir
                candidate_paths.extend([
                    os.path.join(parent_dir, "fleet_summary.json"),
                    os.path.join(parent_dir, "data", "fleet_summary.json"),
                ])
                if orig_outdir:
                    clean_orig = os.path.abspath(os.path.expanduser(str(orig_outdir).strip()))
                    candidate_paths.extend([
                        os.path.join(clean_orig, "fleet_summary.json"),
                        os.path.join(clean_orig, "data", "fleet_summary.json"),
                    ])
                if os.path.isdir(parent_dir):
                    try:
                        for entry in sorted(os.listdir(parent_dir), reverse=True):
                            sub = os.path.join(parent_dir, entry)
                            if os.path.isdir(sub) and ("Scan_" in entry or "run-" in entry):
                                cand = os.path.join(sub, "data", "fleet_summary.json")
                                if os.path.isfile(cand):
                                    candidate_paths.append(cand)
                                    break
                    except OSError:
                        pass
                for cpath in candidate_paths:
                    if os.path.isfile(cpath) and os.path.getsize(cpath) > 0:
                        try:
                            loaded = load_summary(cpath)
                            if loaded:
                                hints_source = loaded
                                break
                        except Exception:
                            pass
            if hints_source:
                hints = extract_historical_hints(hints_source)
                def _get_target_prio(ip: str) -> Tuple[int, float]:
                    h_hint = hints.get(ip, {})
                    is_strag = h_hint.get("is_straggler", False)
                    hist_dur = float(h_hint.get("duration_sec", 0.0))
                    drive_cnt = int(h_hint.get("drive_count", 0))
                    weight, _, _ = classify_host_weight(
                        drive_cnt, is_straggler=is_strag, historical_duration=hist_dur
                    )
                    prio = PRIORITY_MAP.get(weight, 3)
                    return (prio, -hist_dur)
                target_ips = sorted(target_ips, key=_get_target_prio)
                _log(f"  [+] LJF Priority Ordering applied across {len(target_ips)} host(s) based on historical hints.")
        except Exception as _prio_err:
            logger.debug(f"LJF priority ordering skipped: {_prio_err}")

    if discovery_probe_results:
        default_cache_path = os.path.join(data_dir, "discovery_cache.json")
        try:
            save_discovery_cache(default_cache_path, target_ips, discovery_probe_results)
            if discovery_cache and os.path.abspath(discovery_cache) != os.path.abspath(default_cache_path):
                save_discovery_cache(discovery_cache, target_ips, discovery_probe_results)
        except Exception as _c_save_exc:
            logger.debug(f"Could not auto-save discovery cache: {_c_save_exc}")

    if discover_only:
        active_count = len([ip for ip in target_ips if discovery_probe_results.get(ip, {}).get("reachable", False)])
        inactive_count = len([ip for ip in discovery_probe_results if not discovery_probe_results[ip].get("reachable", False)])
        saved_cache_file = discovery_cache if (discovery_cache and os.path.exists(discovery_cache)) else os.path.join(data_dir, "discovery_cache.json")
        _log(f"[✓] Discover-Only Scan Complete: {active_count} active host(s) discovered, {inactive_count} unreachable.")
        _log(f"[💾] Discovery cache written to: {saved_cache_file}")

        return {
            "discover_only": True,
            "outdir": outdir,
            "active_targets": [ip for ip in target_ips if discovery_probe_results.get(ip, {}).get("reachable", False)],
            "inactive_targets": [ip for ip in discovery_probe_results if not discovery_probe_results[ip].get("reachable", False)],
            "discovery_cache_path": saved_cache_file,
            "probe_results": discovery_probe_results,
        }

    scan_start_wall_time = time.time()

    prior_results_map = {}
    if prior_results:
        for pr in prior_results:
            if isinstance(pr, dict):
                p_ip = ((pr.get("system") or {}).get("ip") or pr.get("host") or "").strip()
                if p_ip:
                    prior_results_map[p_ip] = pr

    dell_client = None
    if dell_creds and dell_creds.get("id") and dell_creds.get("secret") and DellTechDirectClient is not None:
        try:
            dell_client = DellTechDirectClient(str(dell_creds["id"]), str(dell_creds["secret"]))
        except Exception as _exc:
            logger.debug(f"Failed initializing DellTechDirectClient: {_exc}")

    ctx = types.SimpleNamespace()
    ctx.target_ips = target_ips
    ctx.creds = creds
    ctx.get_credentials = lambda ip: get_credentials_for_ip(creds, ip)
    ctx.outdir = outdir
    ctx.reports_dir = reports_dir
    ctx.data_dir = data_dir
    ctx.debug = debug
    ctx.debug_log = _debug_log
    ctx.obfuscate = obfuscate
    ctx.obf_salt = _obf_salt
    ctx.quick = quick
    ctx.lean = lean
    ctx.profile = profile
    ctx.include_raw = include_raw
    ctx.save_json = save_json
    ctx.crawl_endpoints = crawl_endpoints
    ctx.host_timeout = host_timeout
    ctx.allow_partial = allow_partial
    ctx.allow_timeout_retry = allow_timeout_retry
    ctx.verify_ssl = verify_ssl
    ctx.ca_bundle = ca_bundle
    ctx.dns_lookup = dns_lookup
    ctx.pinned_thumbprints = pinned_thumbprints
    ctx.enable_dash = enable_dash
    ctx.legacy_tls = legacy_tls
    ctx.tls_min_version = tls_min_version
    ctx.cancel_event = cancel_event
    ctx.skip_host_set = skip_host_set
    ctx.log = _log
    ctx.host_start_callback = host_start_callback
    ctx.host_stage_callback = host_stage_callback
    ctx.host_done_callback = host_done_callback
    ctx.progress_callback = progress_callback
    ctx.prior_results_map = prior_results_map
    ctx.json_hcl = json_hcl
    ctx.csv_db = csv_db
    ctx.hcl_bundle_metadata = hcl_bundle_metadata
    ctx.csv_path = csv_path
    ctx.dell_client = dell_client
    ctx.timeout_reason_code = _timeout_reason_code

    # Mutable state
    ctx.completed = 0
    ctx.was_cancelled = False
    ctx.results = []
    ctx.report_paths = []
    ctx.obf_report_paths = []
    ctx.warranty_cache = {}
    ctx.timed_out_hosts = []
    ctx.timed_out_lock = threading.Lock()
    ctx.failed_hosts = []
    ctx.failed_hosts_lock = threading.Lock()
    ctx.host_durations = {}
    ctx.dur_lock = threading.Lock()

    # Pass mockable references
    ctx.create_collector = create_collector
    ctx.detect_management_protocol = detect_management_protocol
    ctx.wsman_collector_cls = WsManCollector
    ctx.generate_host_html_report = generate_host_html_report
    ctx.enrich_host_result = enrich_host_result

    # Sliding window dynamic dispatch executor
    throttle_monitor = SystemThrottleMonitor(
        initial_threads=effective_threads,
        max_threads=max(effective_threads, 96),
        auto_throttle=auto_throttle,
    )
    pending_ips = list(target_ips)
    active_futures = {}

    with ThreadPoolExecutor(max_workers=max(effective_threads, 96)) as executor:
        while pending_ips or active_futures:
            if cancel_event and cancel_event.is_set():
                _log("  [!] Scan cancelled by user.")
                was_cancelled = True
                for f in active_futures:
                    f.cancel()
                break

            current_limit = throttle_monitor.check_and_adjust_concurrency() if auto_throttle else effective_threads

            while pending_ips and len(active_futures) < current_limit:
                next_ip = pending_ips.pop(0)
                fut = executor.submit(_scan_one_host, next_ip, ctx)
                active_futures[fut] = next_ip

            if not active_futures:
                break

            done, _ = wait(list(active_futures.keys()), timeout=0.5, return_when=FIRST_COMPLETED)
            for f in done:
                ip = active_futures.pop(f)
                _handle_completed_host(f, ip, ctx)

        if cancel_event and cancel_event.is_set():
            ctx.was_cancelled = True

    # Timeout retry pass (Plan 06 / lab_fleet_smoke port)
    if getattr(ctx, "allow_timeout_retry", True) and not ctx.was_cancelled and (ctx.timed_out_hosts or ctx.failed_hosts):
        def _item_matches_ip(item: Any, target_ip: str) -> bool:
            if not isinstance(item, dict):
                return False
            if item.get("host") == target_ip:
                return True
            sys_dict = item.get("system")
            if isinstance(sys_dict, dict):
                if sys_dict.get("ip") == target_ip or sys_dict.get("bmc_ip") == target_ip:
                    return True
                if target_ip in str(sys_dict.get("ip_addresses") or []):
                    return True
            return False

        timeout_failed_ips = [
            ip for ip in ctx.timed_out_hosts
            if not any(_item_matches_ip(r, ip) for r in ctx.results)
        ]
        with ctx.failed_hosts_lock:
            for f in ctx.failed_hosts:
                f_ip = f.get("ip")
                if f_ip and f_ip not in timeout_failed_ips:
                    rcode = str(f.get("reason_code") or "").lower()
                    rdetail = str(f.get("detail") or "").lower()
                    if "timeout" in rcode or "timeout" in rdetail:
                        if not any(_item_matches_ip(r, f_ip) for r in ctx.results):
                            timeout_failed_ips.append(f_ip)

        if timeout_failed_ips:
            retry_workers = min(4, max(2, len(timeout_failed_ips)))
            retry_timeout = max(600, int((ctx.host_timeout or 300) * 2))
            _log(
                f"  [🔄] Timeout retry pass: {len(timeout_failed_ips)} timeout host(s), "
                f"threads={retry_workers}, timeout={retry_timeout}s, allow_partial=True"
            )
            retry_ctx = copy.copy(ctx)
            retry_ctx.allow_timeout_retry = False
            retry_ctx.host_timeout = retry_timeout
            retry_ctx.allow_partial = True
            retry_ctx.progress_callback = None
            retry_ctx.results = []
            retry_ctx.report_paths = []
            retry_ctx.obf_report_paths = []
            retry_ctx.timed_out_hosts = []
            retry_ctx.timed_out_lock = threading.Lock()
            retry_ctx.failed_hosts = []
            retry_ctx.failed_hosts_lock = threading.Lock()
            retry_ctx.host_durations = {}
            retry_ctx.dur_lock = threading.Lock()

            with ThreadPoolExecutor(max_workers=retry_workers) as retry_executor:
                retry_futures = {
                    retry_executor.submit(_scan_one_host, rip, retry_ctx): rip
                    for rip in timeout_failed_ips
                }
                for rf in as_completed(retry_futures):
                    if cancel_event and cancel_event.is_set():
                        _log("  [!] Scan cancelled by user during timeout retry.")
                        ctx.was_cancelled = True
                        break
                    rip = retry_futures[rf]
                    res_before = len(retry_ctx.results)
                    _handle_completed_host(rf, rip, retry_ctx)
                    if len(retry_ctx.results) > res_before:
                        new_items = retry_ctx.results[res_before:]
                        ctx.results.extend(new_items)
                        with ctx.timed_out_lock:
                            if rip in ctx.timed_out_hosts:
                                ctx.timed_out_hosts.remove(rip)
                        with ctx.failed_hosts_lock:
                            ctx.failed_hosts = [f for f in ctx.failed_hosts if f.get("ip") != rip]
                        _log(f"  [🔄✓] {rip} — RECOVERED during timeout retry pass.")
                    else:
                        _log(f"  [✗] {rip} — still timed out after retry pass.")

            ctx.report_paths.extend(retry_ctx.report_paths)
            ctx.obf_report_paths.extend(retry_ctx.obf_report_paths)
            with ctx.dur_lock:
                ctx.host_durations.update(retry_ctx.host_durations)

    results = ctx.results
    report_paths = ctx.report_paths
    obf_report_paths = ctx.obf_report_paths
    timed_out_hosts = ctx.timed_out_hosts
    failed_hosts = ctx.failed_hosts
    _host_durations = ctx.host_durations
    was_cancelled = ctx.was_cancelled

    scan_total_sec = time.time() - scan_start_wall_time
    if _host_durations:
        avg_sec = sum(_host_durations.values()) / len(_host_durations)
        longest_ip, longest_sec = max(_host_durations.items(), key=lambda x: x[1])
        scan_summary_str = (
            f"Scan took {_format_dur_min(scan_total_sec)}, "
            f"average time for hosts {_format_dur_min(avg_sec)}, "
            f"longest scan host {longest_ip} with {_format_dur_min(longest_sec)}"
        )
    else:
        scan_summary_str = f"Scan took {_format_dur_min(scan_total_sec)}"

    fleet_reqs = 0
    fleet_timeouts = 0
    fleet_throttles = 0
    fleet_latencies = []
    fleet_reuse_ratios = []
    for item in results:
        if not isinstance(item, dict):
            continue
        diag = item.get("diagnostics")
        if isinstance(diag, dict):
            rc = diag.get("request_count", 0)
            if isinstance(rc, (int, float)):
                fleet_reqs += int(rc)
            tc = diag.get("timeout_count", 0)
            if isinstance(tc, (int, float)):
                fleet_timeouts += int(tc)
            tec = diag.get("throttle_engaged_count", 0)
            if isinstance(tec, (int, float)):
                fleet_throttles += int(tec)
            lat = diag.get("avg_get_latency_ms")
            if isinstance(lat, (int, float)) and lat > 0:
                fleet_latencies.append(float(lat))
            rr = diag.get("tls_reuse_ratio")
            if isinstance(rr, (int, float)):
                fleet_reuse_ratios.append(float(rr))

    avg_fleet_latency = round(sum(fleet_latencies) / len(fleet_latencies), 1) if fleet_latencies else 0.0
    avg_fleet_reuse = round(sum(fleet_reuse_ratios) / len(fleet_reuse_ratios) * 100, 1) if fleet_reuse_ratios else 0.0

    fleet_diagnostics = {
        "total_requests": fleet_reqs,
        "total_timeouts": fleet_timeouts,
        "total_throttles": fleet_throttles,
        "avg_get_latency_ms": avg_fleet_latency,
        "avg_tls_reuse_pct": avg_fleet_reuse,
    }

    if was_cancelled:
        _log(f"\n[⏱️] {scan_summary_str}")
        if fleet_reqs > 0:
            _log(f"[📊] Fleet HTTP diagnostics: {fleet_reqs} requests ({avg_fleet_latency}ms avg GET, {avg_fleet_reuse}% keep-alive reuse, {fleet_timeouts} timeouts)")
        return {
            "results": results,
            "report_paths": report_paths,
            "fleet_path": "",
            "obf_fleet_path": "",
            "summary_path": "",
            "outdir": outdir,
            "zip_path": "",
            "cancelled": True,
            "scan_summary": scan_summary_str,
            "fleet_diagnostics": fleet_diagnostics,
            "timed_out_hosts": timed_out_hosts,
            "failed_hosts": failed_hosts,
        }

    fleet_path = ""
    _obf_fleet_path = ""
    summary_path = ""
    n = len(results)

    if generate_fleet_artifacts and (n >= 1 or len(failed_hosts) >= 1):
        if combined and n >= 1:
            if n > COMBINED_HTML_MAX_HOSTS:
                _log(f"\n[!] Note: Combined report host count ({n}) exceeds soft limit of {COMBINED_HTML_MAX_HOSTS}.")
            try:
                fleet_path = _generate_combined_html(results, report_paths, outdir)
                if fleet_path:
                    _log(f"\n[✓] Combined report  →  {os.path.basename(fleet_path)}")
            except Exception as exc:
                _log(f"\n[!] Combined report failed: {exc}")

        try:
            summary_path = os.path.join(outdir, "00_fleet_summary.html")
            generate_summary_html(results, summary_path, hcl_bundle_metadata=hcl_bundle_metadata, failed_hosts=failed_hosts)
            _log("[✓] Fleet summary    →  00_fleet_summary.html")
        except Exception as exc:
            _log(f"[!] Fleet summary failed: {exc}")

        _obf_sum = ""
        obf_results = (
            [obfuscate_host_data(r, f"Host-{i+1}", _obf_salt) for i, r in enumerate(results)]
            if (obfuscate and n >= 1)
            else None
        )
        if obfuscate and n >= 1:
            if n > 1:
                try:
                    _obf_sum = os.path.join(outdir, "00_OBFUSCATED_fleet_summary.html")
                    generate_summary_html(
                        obf_results,
                        _obf_sum,
                        hcl_bundle_metadata=hcl_bundle_metadata,
                        obfuscated=True,
                        failed_hosts=failed_hosts,
                    )
                    _log("[🔒] Obfuscated fleet summary  →  00_OBFUSCATED_fleet_summary.html")
                except Exception as exc:
                    _log(f"[!] Obfuscated fleet summary failed: {exc}")

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
                    obf_sheets = _build_excel_sheets(obf_results, failed_hosts=obf_failed_hosts)
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

        # Ensure main report files have the newest mtime in outdir
        for _main_html in (summary_path, fleet_path, _obf_sum, _obf_fleet_path):
            if _main_html and os.path.exists(_main_html):
                try:
                    time.sleep(0.01)
                    os.utime(_main_html, None)
                except Exception:
                    pass

    if not was_cancelled and n >= 1:
        try:
            from vcf_hci.fleet_library import write_scan_manifest
            write_scan_manifest(
                outdir=outdir,
                host_count=n,
                site=site,
                collector_id=collector_id,
                scan_profile=profile,
                obfuscated=obfuscate,
            )
            _log("[✓] Scan manifest    →  MANIFEST.json")
        except Exception as _m_exc:
            logger.debug(f"Failed writing scan manifest: {_m_exc}")

        try:
            write_scan_readme(
                outdir=outdir,
                host_count=n,
                site=site,
                collector_id=collector_id,
                scan_profile=profile,
                obfuscated=obfuscate,
                failed_count=len(failed_hosts),
            )
            _log("[✓] Scan index guide →  Readme.txt")
        except Exception as _r_exc:
            logger.debug(f"Failed writing scan readme: {_r_exc}")

    zip_path = ""
    obf_zip_path = ""
    if create_zip and not was_cancelled and n >= 1:
        try:
            zip_path = create_scan_zip_archive(outdir)
            _log(f"[📦] Compressed archive →  {os.path.basename(zip_path)}")
        except Exception as exc:
            _log(f"[!] Zip compression failed: {exc}")

        if obfuscate:
            try:
                obf_zip_path = create_obfuscated_scan_zip_archive(
                    outdir,
                    failed_hosts=timed_out_hosts,
                    results=obf_results,
                )
                _log(f"[📦] Obfuscated archive (sanitized) →  {os.path.basename(obf_zip_path)}")
            except Exception as exc:
                _log(f"[!] Obfuscated zip compression failed: {exc}")

    n_timed_out = len(timed_out_hosts)
    if n_timed_out > 0:
        _log(f"[⚠️] Timed out hosts: {n_timed_out} host(s) were identified but timed out during collection (out-of-band management patch & reboot recommended).")
    else:
        _log("[✓] Timed out hosts: 0 hosts timed out.")

    partial_hosts = [r for r in results if r.get("partial_scan")]
    if partial_hosts:
        _log(f"[⚠️] Incomplete / Partial scans: {len(partial_hosts)} host(s) completed with partial data due to BMC timeouts.")
        for ph in partial_hosts:
            ph_ip = (ph.get("system") or {}).get("ip") or ph.get("host") or "Unknown"
            ph_sec = ph.get("partial_sections") or []
            _sec_msg = f" (missing: {', '.join(ph_sec)})" if ph_sec else ""
            _log(f"    - {ph_ip}{_sec_msg}")
        _log("    💡 Recommended Action: Soft reset BMC (racadm racreset / iloreset) or update BMC firmware and re-scan.")

    if not was_cancelled and n >= 1:
        try:
            update_latest_scan_aliases(scan_dir=outdir)
        except Exception as exc:
            logger.debug(f"Failed updating latest scan aliases: {exc}")

    _log(f"\n[⏱️] {scan_summary_str}")
    if fleet_reqs > 0:
        _log(f"[📊] Fleet HTTP diagnostics: {fleet_reqs} requests ({avg_fleet_latency}ms avg GET, {avg_fleet_reuse}% keep-alive reuse, {fleet_timeouts} timeouts)")

    return {
        "results": results,
        "report_paths": report_paths,
        "fleet_path": fleet_path,
        "obf_fleet_path": _obf_fleet_path,
        "summary_path": summary_path,
        "outdir": outdir,
        "zip_path": zip_path,
        "obf_zip_path": obf_zip_path,
        "cancelled": False,
        "scan_summary": scan_summary_str,
        "fleet_diagnostics": fleet_diagnostics,
        "timed_out_hosts": timed_out_hosts,
        "failed_hosts": failed_hosts,
    }
