"""Partition scan targets across jump hosts and fan out one ephemeral run each."""

import ipaddress
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from vcf_hci.remote.executor import RemoteExecError, run_remote_scan

logger = logging.getLogger("vcf_assess")

__all__ = [
    "UnroutedTargets",
    "route_targets",
    "run_fanout",
]


class UnroutedTargets(RemoteExecError):
    """Some targets matched no jump-host subnet and no default jump host."""

    def __init__(self, targets: Sequence[str]) -> None:
        self.targets = list(targets)
        super().__init__("no jump host for: %s" % ", ".join(self.targets))


def _network(cidr: str) -> Optional[Any]:
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def _as_ip(target: str) -> Optional[Any]:
    try:
        return ipaddress.ip_address(target)
    except ValueError:
        return None


def route_targets(
    targets: Sequence[str],
    jump_hosts: Dict[str, Dict[str, Any]],
    selected_id: str = "auto",
) -> Tuple[Dict[str, List[str]], List[str]]:
    """Return ``({jump_id: [targets]}, unrouted)``.

    Longest matching prefix wins. Equal-length overlaps raise RemoteExecError.
    A profile with ``is_default`` receives hostnames and unmatched addresses.
    ``selected_id`` other than ``auto`` sends every target to that one host.
    """
    if selected_id and selected_id != "auto":
        if selected_id not in jump_hosts:
            raise RemoteExecError("unknown jump host %s" % selected_id)
        return {selected_id: list(targets)}, []

    default_ids = [jid for jid, profile in jump_hosts.items() if profile.get("is_default")]
    if len(default_ids) > 1:
        raise RemoteExecError("more than one default jump host is configured")
    default_id = default_ids[0] if default_ids else None

    routes: Dict[str, List[str]] = {}
    unrouted: List[str] = []
    for target in targets:
        ip = _as_ip(target)
        if ip is None:
            if default_id:
                routes.setdefault(default_id, []).append(target)
            else:
                unrouted.append(target)
            continue
        matches: List[Tuple[int, str]] = []
        for jid, profile in jump_hosts.items():
            for cidr in profile.get("subnets") or []:
                net = _network(str(cidr))
                if net is not None and ip in net:
                    matches.append((net.prefixlen, jid))
        if not matches:
            if default_id:
                routes.setdefault(default_id, []).append(target)
            else:
                unrouted.append(target)
            continue
        matches.sort(key=lambda item: item[0], reverse=True)
        best_len = matches[0][0]
        winners = {jid for length, jid in matches if length == best_len}
        if len(winners) > 1:
            raise RemoteExecError("target %s matches more than one jump host at /%s" % (target, best_len))
        routes.setdefault(matches[0][1], []).append(target)
    return routes, unrouted


def _filter_creds(creds: Any, targets: Sequence[str]) -> Dict[str, Tuple[str, str]]:
    if isinstance(creds, tuple):
        return {"default": (str(creds[0]), str(creds[1]))}
    if not isinstance(creds, dict):
        raise RemoteExecError("creds must be a dict or a (username, password) tuple")
    out: Dict[str, Tuple[str, str]] = {}
    for target in targets:
        if target in creds:
            pair = creds[target]
            out[target] = (str(pair[0]), str(pair[1]))
    if "default" in creds:
        pair = creds["default"]
        out["default"] = (str(pair[0]), str(pair[1]))
    return out


def run_fanout(
    jump_hosts: Dict[str, Dict[str, Any]],
    targets: Sequence[str],
    creds: Any,
    local_outdir: str,
    pyz_bytes: bytes,
    selected_id: str = "auto",
    threads: int = 8,
    profile: str = "readiness-full",
    force: bool = False,
    on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
    executor: Callable[..., Dict[str, Any]] = run_remote_scan,
    max_workers: int = 4,
    host_timeout: int = 300,
    debug: bool = False,
    cancel_event: Optional[Any] = None,
    on_sandbox: Optional[Callable[[Dict[str, Any]], None]] = None,
    sandbox_retain: int = 0,
) -> Dict[str, Any]:
    """Run one remote scan per jump host. Artifacts land under ``local_outdir``."""
    routes, unrouted = route_targets(targets, jump_hosts, selected_id=selected_id)
    if unrouted:
        raise UnroutedTargets(unrouted)
    if not routes:
        raise RemoteExecError("no targets to scan")

    def _one(jump_id: str, batch: List[str]) -> Dict[str, Any]:
        profile_row = jump_hosts[jump_id]
        dest = local_outdir if len(routes) == 1 else os.path.join(local_outdir, "from-%s" % jump_id)
        os.makedirs(dest, exist_ok=True)

        def _progress(event: Dict[str, Any]) -> None:
            if on_progress is None:
                return
            stamped = dict(event)
            stamped["jump_host"] = jump_id
            on_progress(stamped)

        def _sandbox(info: Dict[str, Any]) -> None:
            if on_sandbox is None:
                return
            stamped = dict(info)
            stamped["jump_host"] = jump_id
            on_sandbox(stamped)

        exec_kwargs: Dict[str, Any] = {
            "jump": profile_row,
            "pyz_bytes": pyz_bytes,
            "targets": batch,
            "creds": _filter_creds(creds, batch),
            "local_outdir": dest,
            "threads": threads,
            "profile": profile,
            "force": force,
            "on_progress": _progress,
        }
        if host_timeout is not None:
            exec_kwargs["host_timeout"] = host_timeout
        if debug:
            exec_kwargs["debug"] = debug
        if cancel_event is not None:
            exec_kwargs["cancel_event"] = cancel_event
        if on_sandbox is not None:
            exec_kwargs["on_sandbox"] = _sandbox
        if sandbox_retain:
            exec_kwargs["sandbox_retain"] = sandbox_retain
        try:
            result = executor(**exec_kwargs)
        except TypeError as te:
            if "unexpected keyword argument" in str(te):
                exec_kwargs.pop("host_timeout", None)
                exec_kwargs.pop("debug", None)
                exec_kwargs.pop("cancel_event", None)
                exec_kwargs.pop("on_sandbox", None)
                exec_kwargs.pop("sandbox_retain", None)
                result = executor(**exec_kwargs)
            else:
                logger.exception("Unexpected TypeError during remote execution on jump %s", jump_id)
                raise
        result["jump_id"] = jump_id
        result["targets"] = list(batch)
        return result

    results: List[Dict[str, Any]] = []
    errors: List[str] = []
    workers = max(1, min(int(max_workers), len(routes)))
    if workers == 1:
        for jump_id, batch in routes.items():
            try:
                results.append(_one(jump_id, batch))
            except Exception as exc:
                logger.exception("Remote scan failed on jump host %s: %s", jump_id, exc)
                errors.append("%s: %s" % (jump_id, exc))
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_one, jump_id, batch): jump_id for jump_id, batch in routes.items()}
            for future in as_completed(futures):
                jump_id = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    logger.exception("Remote scan failed on jump host %s: %s", jump_id, exc)
                    errors.append("%s: %s" % (jump_id, exc))
    if errors:
        raise RemoteExecError("remote scan failed: %s" % "; ".join(errors))
    return {
        "ok": True,
        "runs": results,
        "local_outdir": local_outdir,
        "jump_ids": [row["jump_id"] for row in results],
    }
