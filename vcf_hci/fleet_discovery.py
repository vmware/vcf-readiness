"""
VCF Readiness Tool — Fleet Discovery, Pre-Qualification & LJF Priority Scheduling.

Provides lightweight two-pass host discovery, fast CPU pre-qualification,
storage topology counting (without drive leaf walking), historical duration caching
("Straggler Suspects"), and Longest-Job-First (LJF) queue prioritization.
"""

import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from vcf_hci.collector.oem import create_collector
from vcf_hci.compat.cpu import evaluate_cpu

logger = logging.getLogger("vcf_assess")

# Weight categories and corresponding scheduling priority (lower number = earlier dispatch)
WEIGHT_STRAGGLER_SUSPECT = "straggler_suspect"
WEIGHT_HEAVY = "heavy"
WEIGHT_MEDIUM = "medium"
WEIGHT_LIGHT = "light"
WEIGHT_INACTIVE = "inactive"

PRIORITY_MAP: Dict[str, int] = {
    WEIGHT_STRAGGLER_SUSPECT: 0,
    WEIGHT_HEAVY: 1,
    WEIGHT_MEDIUM: 2,
    WEIGHT_LIGHT: 3,
    WEIGHT_INACTIVE: 99,
}

# Thresholds for weight classification
DRIVE_COUNT_HEAVY_THRESHOLD = 16
DRIVE_COUNT_MEDIUM_THRESHOLD = 6
STRAGGLER_DURATION_THRESHOLD_SEC = 90.0


def extract_historical_hints(prior_results: Optional[List[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    """Extract past scan durations, drive counts, and straggler hints from prior results.

    Args:
        prior_results: List of host result dictionaries from a previous scan or digest.

    Returns:
        Dict mapping host IP to historical metrics dict:
        {
            "duration_sec": float,
            "drive_count": int,
            "is_straggler": bool,
            "cpu_verdict": str,
            "vendor": str,
            "model": str,
        }
    """
    hints: Dict[str, Dict[str, Any]] = {}
    if not prior_results:
        return hints

    for pr in prior_results:
        if not isinstance(pr, dict):
            continue
        sys_info = pr.get("system") or {}
        ip = str(sys_info.get("bmc_ip") or sys_info.get("ip") or pr.get("host") or "").strip()
        if not ip:
            continue

        dur = float(pr.get("scan_duration_sec") or pr.get("duration_sec") or 0.0)
        storage = pr.get("storage_subsystem") or []
        drive_count = 0
        if isinstance(storage, list):
            for ctrl in storage:
                if isinstance(ctrl, dict):
                    drive_count += len(ctrl.get("drives") or [])

        cpu_summary = sys_info.get("cpu_summary") or {}
        cpu_verdict = str(cpu_summary.get("verdict") or "")

        is_straggler = (
            dur >= STRAGGLER_DURATION_THRESHOLD_SEC
            or drive_count >= DRIVE_COUNT_HEAVY_THRESHOLD
            or bool(pr.get("adaptive_throttled"))
        )

        hints[ip] = {
            "duration_sec": dur,
            "drive_count": drive_count,
            "is_straggler": is_straggler,
            "cpu_verdict": cpu_verdict,
            "vendor": str(sys_info.get("vendor") or ""),
            "model": str(sys_info.get("model") or ""),
        }

    return hints


def classify_host_weight(
    drive_count_hint: int,
    is_straggler: bool = False,
    historical_duration: float = 0.0,
    is_active: bool = True,
) -> Tuple[str, int, float]:
    """Classify a host into a weight category, priority tier, and estimated duration.

    Args:
        drive_count_hint: Estimated number of attached drives from storage controller inquiry.
        is_straggler: Flag indicating known slow host from historical scan or telemetry.
        historical_duration: Prior measured scan runtime in seconds.
        is_active: Whether host responded successfully to initial probe.

    Returns:
        Tuple of (weight_category, priority_rank, estimated_duration_sec).
    """
    if not is_active:
        return WEIGHT_INACTIVE, PRIORITY_MAP[WEIGHT_INACTIVE], 0.0

    if is_straggler or historical_duration >= STRAGGLER_DURATION_THRESHOLD_SEC:
        est_dur = max(historical_duration, 180.0)
        return WEIGHT_STRAGGLER_SUSPECT, PRIORITY_MAP[WEIGHT_STRAGGLER_SUSPECT], est_dur

    if drive_count_hint >= DRIVE_COUNT_HEAVY_THRESHOLD:
        est_dur = max(historical_duration, 150.0)
        return WEIGHT_HEAVY, PRIORITY_MAP[WEIGHT_HEAVY], est_dur

    if drive_count_hint >= DRIVE_COUNT_MEDIUM_THRESHOLD:
        est_dur = max(historical_duration, 45.0)
        return WEIGHT_MEDIUM, PRIORITY_MAP[WEIGHT_MEDIUM], est_dur

    est_dur = max(historical_duration, 15.0)
    return WEIGHT_LIGHT, PRIORITY_MAP[WEIGHT_LIGHT], est_dur


def probe_host_prequalification(
    ip: str,
    username: str,
    password: str,
    timeout: float = 4.0,
    verify_ssl: bool = False,
    ca_bundle: Optional[str] = None,
    pinned_thumbprints: Optional[Dict[str, str]] = None,
    historical_hint: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Perform a rapid lightweight Redfish inquiry to determine CPU qualification and storage weight.

    Queries only /redfish/v1, /redfish/v1/Systems, and /redfish/v1/Systems/1/Storage to count
    drive hyperlinks without fetching individual drive leaves.

    Args:
        ip: Target BMC IP address or hostname.
        username: BMC login username.
        password: BMC login password.
        timeout: Socket timeout in seconds (default 4.0s).
        verify_ssl: SSL certificate verification flag.
        ca_bundle: Path to CA bundle file.
        pinned_thumbprints: Optional dict of pinned SSL certificate thumbprints.
        historical_hint: Optional dict of metrics from a prior scan.

    Returns:
        Prequalification summary dict.
    """
    t_start = time.time()
    res: Dict[str, Any] = {
        "ip": ip,
        "reachable": False,
        "auth_failed": False,
        "timed_out": False,
        "vendor": "",
        "model": "",
        "cpu_model": "",
        "cpu_verdict": "",
        "drive_count_hint": 0,
        "ctrl_count_hint": 0,
        "weight": WEIGHT_LIGHT,
        "priority": PRIORITY_MAP[WEIGHT_LIGHT],
        "estimated_duration_sec": 15.0,
        "probe_duration_sec": 0.0,
        "error": None,
    }

    # If historical hints exist, incorporate them as baseline defaults
    if historical_hint:
        res["vendor"] = historical_hint.get("vendor", "")
        res["model"] = historical_hint.get("model", "")
        res["cpu_verdict"] = historical_hint.get("cpu_verdict", "")
        res["drive_count_hint"] = historical_hint.get("drive_count", 0)
        if historical_hint.get("is_straggler"):
            res["weight"] = WEIGHT_STRAGGLER_SUSPECT
            res["priority"] = PRIORITY_MAP[WEIGHT_STRAGGLER_SUSPECT]
            res["estimated_duration_sec"] = max(historical_hint.get("duration_sec", 0.0), 180.0)

    try:
        collector = create_collector(
            host=ip,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            ca_bundle=ca_bundle,
            pinned_thumbprints=pinned_thumbprints,
        )
    except Exception as exc:
        res["error"] = f"Collector initialization failed: {exc}"
        res["weight"], res["priority"], res["estimated_duration_sec"] = classify_host_weight(
            drive_count_hint=res["drive_count_hint"],
            is_straggler=bool(historical_hint and historical_hint.get("is_straggler")),
            is_active=False,
        )
        res["probe_duration_sec"] = round(time.time() - t_start, 3)
        return res

    with collector:
        # Fast query root endpoint
        root_data = collector._get("", timeout=int(timeout), critical=False)
        if not root_data:
            if collector.auth_failed:
                res["auth_failed"] = True
                res["error"] = "Authentication failed (HTTP 401/403)"
            elif collector.timed_out:
                res["timed_out"] = True
                res["error"] = f"Connection timed out ({timeout}s)"
            else:
                res["error"] = "Redfish service unreachable"

            res["weight"], res["priority"], res["estimated_duration_sec"] = classify_host_weight(
                drive_count_hint=0,
                is_active=False,
            )
            res["probe_duration_sec"] = round(time.time() - t_start, 3)
            return res

        res["reachable"] = True

        # Fast query Systems collection or root
        sys_coll = root_data.get("Systems") or {}
        sys_uri = None
        if isinstance(sys_coll, dict) and sys_coll.get("@odata.id"):
            sys_coll_data = collector._get(sys_coll["@odata.id"], timeout=int(timeout), critical=False)
            if isinstance(sys_coll_data, dict):
                members = sys_coll_data.get("Members") or []
                if members and isinstance(members[0], dict):
                    sys_uri = members[0].get("@odata.id")

        if not sys_uri:
            sys_uri = "/redfish/v1/Systems/1"

        sys_data = collector._get(sys_uri, timeout=int(timeout), critical=False) or {}
        if sys_data and not sys_data.get("error"):
            res["vendor"] = str(sys_data.get("Manufacturer") or sys_data.get("Vendor") or "").strip()
            res["model"] = str(sys_data.get("Model") or "").strip()

            # Inspect Processors for CPU qualification
            proc_coll = sys_data.get("Processors") or {}
            proc_uri = proc_coll.get("@odata.id") if isinstance(proc_coll, dict) else f"{sys_uri}/Processors"
            if proc_uri:
                proc_data = collector._get(proc_uri, timeout=int(timeout), critical=False)
                if isinstance(proc_data, dict):
                    p_members = proc_data.get("Members") or []
                    if p_members and isinstance(p_members[0], dict) and p_members[0].get("@odata.id"):
                        p_detail = collector._get(p_members[0]["@odata.id"], timeout=int(timeout), critical=False)
                        if isinstance(p_detail, dict):
                            res["cpu_model"] = str(p_detail.get("Model") or p_detail.get("InstructionSet") or "").strip()

            if res["cpu_model"]:
                verdict_tuple = evaluate_cpu(res["cpu_model"], vendor=res["vendor"], model=res["model"])
                res["cpu_verdict"] = verdict_tuple[0] if verdict_tuple else ""

            # Inspect Storage collection to count drive URIs without leaf walks
            storage_coll = sys_data.get("Storage") or {}
            storage_uri = storage_coll.get("@odata.id") if isinstance(storage_coll, dict) else f"{sys_uri}/Storage"
            if storage_uri:
                storage_data = collector._get(storage_uri, timeout=int(timeout), critical=False)
                if isinstance(storage_data, dict):
                    ctrl_members = storage_data.get("Members") or []
                    res["ctrl_count_hint"] = len(ctrl_members)
                    total_drives = 0
                    for c_ref in ctrl_members:
                        c_uri = c_ref.get("@odata.id") if isinstance(c_ref, dict) else None
                        if c_uri:
                            c_data = collector._get(c_uri, timeout=int(timeout), critical=False)
                            if isinstance(c_data, dict):
                                drives_list = c_data.get("Drives") or []
                                if isinstance(drives_list, list):
                                    total_drives += len(drives_list)
                                elif isinstance(drives_list, dict) and drives_list.get("Members"):
                                    total_drives += len(drives_list.get("Members") or [])
                    res["drive_count_hint"] = total_drives

    # Finalize weight & priority
    is_straggler = bool(historical_hint and historical_hint.get("is_straggler"))
    hist_dur = float((historical_hint or {}).get("duration_sec", 0.0))

    res["weight"], res["priority"], res["estimated_duration_sec"] = classify_host_weight(
        drive_count_hint=res["drive_count_hint"],
        is_straggler=is_straggler,
        historical_duration=hist_dur,
        is_active=res["reachable"],
    )
    res["probe_duration_sec"] = round(time.time() - t_start, 3)
    return res


def discover_and_prioritize_fleet(
    target_ips: List[str],
    creds: Union[dict, tuple],
    threads: int = 16,
    prior_results: Optional[List[Dict[str, Any]]] = None,
    timeout: float = 4.0,
    verify_ssl: bool = False,
    ca_bundle: Optional[str] = None,
    pinned_thumbprints: Optional[Dict[str, str]] = None,
    cancel_event: Optional[threading.Event] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    log_callback: Optional[Callable[[str, str], None]] = None,
    prune_inactive: bool = False,
    cache_path: Optional[str] = None,
) -> Tuple[List[str], Dict[str, Dict[str, Any]]]:
    """Execute Pass 1 discovery across fleet and return targets sorted by LJF priority.

    Args:
        target_ips: List of target BMC IP addresses or hostnames.
        creds: Dict mapping IP -> (user, pwd) or global tuple (user, pwd).
        threads: Concurrency for discovery probes (up to 96).
        prior_results: Optional results from previous scan for warm-start hints.
        timeout: Socket timeout for discovery probes.
        verify_ssl: SSL certificate verification flag.
        ca_bundle: Path to CA bundle file.
        pinned_thumbprints: Optional dict of pinned SSL certificate thumbprints.
        cancel_event: Optional cancellation event.
        progress_callback: Optional callback(completed, total) for progress reporting.
        log_callback: Optional callback(event_type, msg) for logging.

    Returns:
        Tuple of (sorted_target_ips, prequalification_results_dict).
    """
    def _log(msg: str, evt: str = "discovery"):
        if log_callback:
            try:
                log_callback(evt, msg)
            except Exception:
                pass
        logger.info(msg)

    if not target_ips:
        return [], {}

    historical_map = extract_historical_hints(prior_results)
    if historical_map:
        _log(f"[⚡] Pass 1 Warm-Start: Loaded {len(historical_map)} historical host runtime profile(s).")

    def _get_creds(ip: str) -> Tuple[str, str]:
        if isinstance(creds, dict):
            if ip in creds and isinstance(creds[ip], (tuple, list)) and len(creds[ip]) >= 2:
                return str(creds[ip][0]), str(creds[ip][1])
            for fb in ("default", "*", "__default__"):
                if fb in creds and isinstance(creds[fb], (tuple, list)) and len(creds[fb]) >= 2:
                    return str(creds[fb][0]), str(creds[fb][1])
            return ("root", "calvin")
        elif isinstance(creds, (tuple, list)) and len(creds) >= 2:
            return str(creds[0]), str(creds[1])
        return ("root", "calvin")

    probe_results: Dict[str, Dict[str, Any]] = {}
    completed_count = 0
    total_targets = len(target_ips)
    effective_workers = min(max(1, threads), total_targets, 96)

    _log(f"[🔍] Pass 1 Fast Discovery: Probing {total_targets} host(s) across {effective_workers} worker(s)…")

    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        futures = {}
        for ip in target_ips:
            user, pwd = _get_creds(ip)
            hist = historical_map.get(ip)
            fut = executor.submit(
                probe_host_prequalification,
                ip=ip,
                username=user,
                password=pwd,
                timeout=timeout,
                verify_ssl=verify_ssl,
                ca_bundle=ca_bundle,
                pinned_thumbprints=pinned_thumbprints,
                historical_hint=hist,
            )
            futures[fut] = ip

        for fut in as_completed(futures):
            if cancel_event and cancel_event.is_set():
                _log("  [!] Discovery cancelled by user.")
                for f in futures:
                    f.cancel()
                break

            ip = futures[fut]
            completed_count += 1
            if progress_callback:
                try:
                    progress_callback(completed_count, total_targets)
                except Exception:
                    pass

            try:
                res = fut.result()
            except Exception as exc:
                logger.debug(f"Discovery exception for {ip}: {exc}")
                res = {
                    "ip": ip,
                    "reachable": False,
                    "auth_failed": False,
                    "timed_out": False,
                    "weight": WEIGHT_INACTIVE,
                    "priority": PRIORITY_MAP[WEIGHT_INACTIVE],
                    "estimated_duration_sec": 0.0,
                    "error": str(exc),
                }

            probe_results[ip] = res

    # Sort target IPs by (priority ASC, estimated_duration DESC, drive_count DESC, ip)
    def _sort_key(ip: str) -> Tuple[int, float, int, str]:
        r = probe_results.get(ip, {})
        pri = r.get("priority", 99)
        est = float(r.get("estimated_duration_sec", 0.0))
        drives = int(r.get("drive_count_hint", 0))
        # Lower priority number first, then highest estimated duration first (negated)
        return (pri, -est, -drives, ip)

    sorted_ips = sorted(target_ips, key=_sort_key)

    # Summarize discovered weights for logging
    counts: Dict[str, int] = {}
    for r in probe_results.values():
        w = str(r.get("weight", "unknown"))
        counts[w] = counts.get(w, 0) + 1

    summary_str = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
    _log(f"[✓] Pass 1 Complete: LJF queue prioritized ({summary_str}).")

    if prune_inactive:
        active_ips = [ip for ip in sorted_ips if probe_results.get(ip, {}).get("reachable", False)]
        inactive_ips = [ip for ip in sorted_ips if not probe_results.get(ip, {}).get("reachable", False)]
        if inactive_ips:
            _log(
                f"[⚡] Discovery Pruning: {len(inactive_ips)} unreachable host(s) pruned from full collection queue "
                f"({len(active_ips)} active host(s) queued)."
            )
            sorted_ips = active_ips

    if cache_path:
        try:
            save_discovery_cache(cache_path, sorted_ips, probe_results, total_targets=total_targets)
            _log(f"[💾] Discovery cache written to: {cache_path}")
        except Exception as _c_exc:
            logger.debug(f"Failed to auto-save discovery cache to {cache_path}: {_c_exc}")

    return sorted_ips, probe_results


def save_discovery_cache(
    filepath: str,
    sorted_ips: List[str],
    probe_results: Dict[str, Dict[str, Any]],
    total_targets: Optional[int] = None,
) -> str:
    """Save Pass 1 fleet discovery results to a reusable discovery cache JSON file.

    Decouples out-of-band network discovery from deep inventory collection, allowing
    rapid re-runs across large subnets (/16, /20, /24) without repeating the multi-threaded
    network sweep across dark/unreachable IP addresses.

    Args:
        filepath: Target output file path (e.g. data/discovery_cache.json).
        sorted_ips: Discovered target IPs sorted in preferred priority order.
        probe_results: Dict mapping host IP -> prequalification probe result dict.
        total_targets: Total number of targets evaluated in discovery sweep.

    Returns:
        Canonical absolute path to the written discovery cache file.
    """
    total = total_targets if total_targets is not None else len(probe_results)
    active_targets = [ip for ip in sorted_ips if probe_results.get(ip, {}).get("reachable", False)]
    for ip, r in probe_results.items():
        if isinstance(r, dict) and r.get("reachable", False) and ip not in active_targets:
            active_targets.append(ip)

    inactive_targets = [ip for ip, r in probe_results.items() if isinstance(r, dict) and not r.get("reachable", False)]

    cache_data = {
        "version": "1.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_targets": total,
        "active_count": len(active_targets),
        "inactive_count": len(inactive_targets),
        "active_targets": active_targets,
        "inactive_targets": inactive_targets,
        "probe_results": probe_results,
    }

    clean_path = os.path.abspath(os.path.expanduser(str(filepath).strip()))
    dir_path = os.path.dirname(clean_path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    with open(clean_path, "w", encoding="utf-8") as f:
        json.dump(cache_data, f, indent=2)

    logger.debug(f"Saved discovery cache to {clean_path} ({len(active_targets)} active, {len(inactive_targets)} inactive).")
    return clean_path


def load_discovery_cache(
    filepath: str,
    only_active: bool = True,
) -> Tuple[List[str], Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """Load cached Pass 1 fleet discovery results from a JSON file.

    Args:
        filepath: Path to the discovery cache JSON file.
        only_active: If True (default), return only reachable/responsive target IPs.

    Returns:
        Tuple of (target_ips, probe_results, metadata).
    """
    clean_path = os.path.abspath(os.path.expanduser(str(filepath).strip()))
    if not os.path.exists(clean_path):
        raise FileNotFoundError(f"Discovery cache file not found: {clean_path}")

    with open(clean_path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid discovery cache format in {clean_path} (root is not a dict).")

    active_targets = data.get("active_targets") or []
    inactive_targets = data.get("inactive_targets") or []
    probe_results = data.get("probe_results") or {}

    if only_active:
        selected_targets = [str(x).strip() for x in active_targets if str(x).strip()]
    else:
        selected_targets = [str(x).strip() for x in (list(active_targets) + list(inactive_targets)) if str(x).strip()]

    # Fallback to extracting from probe_results if active_targets list was empty
    if not selected_targets and probe_results:
        for ip, r in probe_results.items():
            if isinstance(r, dict):
                if (only_active and r.get("reachable")) or not only_active:
                    selected_targets.append(str(ip).strip())

    metadata = {
        "timestamp": data.get("timestamp", ""),
        "total_targets": data.get("total_targets", len(selected_targets)),
        "active_count": data.get("active_count", len(active_targets)),
        "inactive_count": data.get("inactive_count", len(inactive_targets)),
        "version": data.get("version", "1.0"),
    }

    return selected_targets, probe_results, metadata

