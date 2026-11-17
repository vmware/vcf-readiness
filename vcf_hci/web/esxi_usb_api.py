"""Wizard hook for ESXi SSH targets and scans.

Target discovery reuses the vSphere inventory adapter. The scan itself waits
for the USB BMC branch and returns 501 until that module imports.
"""

from __future__ import annotations

import logging
from typing import Any

from vcf_hci.plugins.esxi_usb import targets_from_property_rows
from vcf_hci.web.plugin_credentials import resolve_plugin_credentials
from vcf_hci.wizard.dedupe import filter_esxi_targets

logger = logging.getLogger("vcf_assess")
_NO_STORE = {"Cache-Control": "no-store"}


def handle_esxi_targets(handler: Any) -> None:
    if handler._vinv_guard() is None:
        return
    data = handler._read_json_body()
    if not isinstance(data, dict):
        handler._send_json({"error": "Expected a JSON object."}, 400, extra_headers=_NO_STORE)
        return
    data = dict(data)
    if not resolve_plugin_credentials(handler, data, "vcenter"):
        return
    request = handler._vinv_request(data)
    if request is None:
        return
    from vcf_hci.plugins.vinv.limits import MAX_HOSTS
    from vcf_hci.plugins.vinv.sources.diagnostics import VinvError
    from vcf_hci.web.vinv_api import failure_payload, open_adapter

    adapter = None
    try:
        adapter = open_adapter()
        adapter._open(request)
        vim = adapter._sdk.vim
        clusters = adapter._properties(vim.ClusterComputeResource, ("name",), adapter._content.rootFolder, MAX_HOSTS)
        container, _ = adapter._scope(request, clusters)
        rows = adapter._properties(
            vim.HostSystem,
            ("name", "config.network.vnic", "hardware.systemInfo", "config.ipmi", "config.virtualNicManagerInfo.netConfig"),
            container,
            MAX_HOSTS,
        )
        hosts = targets_from_property_rows(rows)
    except VinvError as exc:
        handler._send_json(failure_payload(exc, "esxi target discovery"), 400, extra_headers=_NO_STORE)
        return
    except PermissionError:
        handler._send_json(
            {"error": "Acknowledge the experimental collection before listing ESXi hosts.", "error_code": "acknowledgement_required"},
            400,
            extra_headers=_NO_STORE,
        )
        return
    except Exception as exc:
        logger.exception("ESXi target discovery failed")
        handler._send_json(failure_payload(exc, "esxi target discovery"), 500, extra_headers=_NO_STORE)
        return
    finally:
        request.password.clear()
        if adapter is not None:
            try:
                adapter.close()
            except Exception:
                logger.debug("ESXi target discovery cleanup failed", exc_info=True)
    from vcf_hci.web.scan_worker import _state, _state_lock
    with _state_lock:
        completed = list(_state.get("results") or [])
    keep, skipped = filter_esxi_targets(hosts, completed)
    handler._send_json({"ok": True, "hosts": keep, "skipped": skipped}, extra_headers=_NO_STORE)


def handle_esxi_scan(handler: Any) -> None:
    """Run one selected pinned host using the normal scan session/artifacts."""
    if handler._vinv_guard() is None:
        return
    if handler._is_remote_server():
        handler._send_json({"error": "ESXi collection requires the local loopback UI."}, 403)
        return
    data = handler._read_json_body()
    if not isinstance(data, dict):
        handler._send_json({"error": "Expected a JSON object."}, 400)
        return
    if not data.get("acknowledged"):
        handler._send_json({"error": "Acknowledge experimental ESXi collection before scanning."}, 400)
        return
    profile = data.get("profile", "inventory-lite")
    if profile not in ("inventory-lite", "readiness-full"):
        handler._send_json({"error": "Unsupported ESXi scan profile."}, 400)
        return
    from vcf_hci.remote.ssh_target import validate_target as _target
    try:
        target = _target({"host": data.get("host"), "username": data.get("username"),
                          "password": data.get("password"), "host_key": data.get("host_key_pin")})
        if not data.get("bmc_user") or not data.get("bmc_password"):
            raise ValueError("Separate BMC credentials are required.")
    except ValueError:
        handler._send_json({"error": "Select one host, its reviewed SSH public key, SSH credentials and separate BMC credentials."}, 400)
        return
    except Exception:
        handler._send_json({"error": "Invalid ESXi target or host key."}, 400)
        return
    import os
    import threading
    import uuid

    from vcf_hci.logging_utils import normalize_output_dir, sanitize_filename
    from vcf_hci.plugins.esxi_usb import scan_via_esxi
    from vcf_hci.web.scan_worker import _cancel_event, _regenerate_fleet_artifacts, _state, _state_lock

    scan_id = uuid.uuid4().hex
    outdir = os.path.join(normalize_output_dir(data.get("output_dir")), sanitize_filename("ESXi_" + scan_id))
    with _state_lock:
        if _state.get("running") or _state.get("_fleet_worker_active") or _state.get("_fleet_operation"):
            handler._send_json({"error": "A hardware scan is already running."}, 409)
            return
        # Existing captures are authoritative; never accept a caller-provided skip list.
        completed = list(_state.get("results") or [])
        _state.update(_fleet_worker_active=True, scan_id=scan_id, running=True, done=False, error=None, results=[],
                      failed_hosts=[], total=1, completed=0, execution="local", n_ok=0,
                      active_hosts={}, completed_hosts=set(), skipped_ips=set(), log_lines=[],
                      fleet_path="", summary_path="", zip_path="", outdir=outdir,
                      partial_hosts=[], report_paths=[], is_retry=False, is_import=False)
        _cancel_event.clear()

    def run():
        try:
            options = {"bmc_user": data["bmc_user"], "bmc_password": data["bmc_password"],
                       "certificate_pin": data.get("certificate_pin", ""),
                       "verify_ssl": bool(data.get("verify_ssl", False)),
                       "profile": profile, "cancelled": _cancel_event.is_set, "completed_bmc": completed}
            result = scan_via_esxi(target["host"], target["username"], target["password"], target["host_key"], options)
            from vcf_hci.wizard.dedupe import same_host
            prior = next((r for r in completed if same_host(r, result)), None)
            results = completed if prior or result.get("skip_reason") else completed + [result]
            if _cancel_event.is_set():
                raise RuntimeError("cancelled")
            os.makedirs(outdir, exist_ok=False)
            from vcf_hci.report import generate_host_html_report
            reports_dir = os.path.join(outdir, "reports")
            os.makedirs(reports_dir, exist_ok=True)
            for entry in results:
                identity = str((entry.get("system") or {}).get("ip") or target["host"])
                report = os.path.join(reports_dir, sanitize_filename("vsphere_vsan_report_" + identity + ".html"))
                generate_host_html_report(entry, report)
            fleet, summary, archive, reports = _regenerate_fleet_artifacts(results, [], outdir, save_json=True)
            with _state_lock:
                _state.update(results=results, completed=1, n_ok=len(results), fleet_path=fleet,
                              summary_path=summary, zip_path=archive, report_paths=reports)
        except Exception:
            logger.warning("ESXi collection failed; credentials and remote details withheld")
            with _state_lock:
                _state["results"] = completed
                _state["error"] = "ESXi collection failed or was cancelled. Check host trust, USB route and BMC credentials."
        finally:
            data.clear()
            target.clear()
            with _state_lock:
                _state.update(running=False, done=True)
                _state.pop("_fleet_worker_active", None)
    threading.Thread(target=run, daemon=True).start()
    handler._send_json({"ok": True, "scan_id": scan_id}, 202, extra_headers=_NO_STORE)
