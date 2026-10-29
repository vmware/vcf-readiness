"""Authenticated server-group metadata endpoints; mixed into the existing app handler."""

import os
import urllib.parse
from typing import List

from vcf_hci import parse_ip_targets
from vcf_hci.server_groups import _LOCK, GroupRegistry, hydrate_groups
from vcf_hci.summary_io import load_summary
from vcf_hci.web.fleet_api import _ApiMixinBase, _build_compact_host_row
from vcf_hci.web.job_guard import exclusive_fleet_change
from vcf_hci.web.scan_worker import _regenerate_fleet_artifacts, _state, _state_lock


def _targets(value: object) -> List[str]:
    if value is None or value == "":
        return []
    if not isinstance(value, str):
        raise ValueError("Targets must be an IP/hostname list or range")
    return parse_ip_targets(value)


class GroupApiMixin(_ApiMixinBase):
    """GET lists groups/parsed targets; POST performs explicit metadata mutations."""

    def _api_groups_get(self) -> None:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            targets = _targets(query.get("targets", [""])[0])
            with _LOCK:
                registry = GroupRegistry()
                target_hosts = []
                for target in targets:
                    host = {"host": target}
                    ident = registry.register(host)
                    target_hosts.append({"target": target, "host_id": ident, "server_groups": host["server_groups"]})
                groups = registry.groups()
            self._send_json({"ok": True, "groups": groups, "target_hosts": target_hosts})
        except (ValueError, OSError) as exc:
            self._send_json({"error": str(exc)}, 400)

    @exclusive_fleet_change
    def _api_groups_post(self) -> None:
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._send_json({"error": "JSON object required"}, 400)
            return
        with _state_lock:
            if _state.get("running"):
                self._send_json({"error": "Wait for the current scan/import to finish before changing groups"}, 409)
                return
            results = list(_state.get("results") or [])
            outdir = _state.get("outdir") or ""
            failed = list(_state.get("failed_hosts") or [])
        if not results and outdir and os.path.isdir(outdir):
            try:
                results = load_summary(outdir)
            except (OSError, ValueError):
                results = []
        try:
            action = body.get("action")
            if action not in ("create", "rename", "delete", "assign", "remove"):
                raise ValueError("Unknown group action")
            targets = _targets(body.get("targets"))
            ids = body.get("host_ids") or []
            if not isinstance(ids, list) or any(not isinstance(i, str) for i in ids):
                raise ValueError("host_ids must be an explicit list of stable host IDs")
            created = None
            with _LOCK:
                registry = GroupRegistry()
                for host in results:
                    if not host.get("obfuscated"):
                        registry.register(host)
                ids = list(ids)
                ids.extend(registry.register({"host": target}) for target in targets)
                if action == "create":
                    created = registry.create(body.get("name"))
                    if ids:
                        registry.assign(ids, [created["id"]])
                elif action == "rename":
                    registry.rename(str(body.get("group_id") or ""), body.get("name"))
                elif action == "delete":
                    registry.delete(str(body.get("group_id") or ""))
                else:
                    registry.assign(ids, registry.require_groups(body.get("group_ids")), remove=action == "remove")
                registry.save()
                groups = registry.groups()
            hydrate_groups(results)
        except (ValueError, OSError, TypeError) as exc:
            self._send_json({"error": str(exc)}, 400)
            return

        # Persist/export the current observation too. Historical source scans remain
        # portable observations; local removal tombstones reconcile them on reopen.
        artifact_error = ""
        if results and outdir and os.path.isdir(outdir):
            try:
                has_obfuscated = any(name.startswith("00_OBFUSCATED_") for name in os.listdir(outdir))
                fleet, summary, archive, report_paths = _regenerate_fleet_artifacts(
                    results, failed, outdir, combined=True, obfuscate=has_obfuscated,
                    save_json=True, export_sheets=True,
                )
                with _state_lock:
                    _state.update({"fleet_path": fleet, "summary_path": summary, "zip_path": archive, "report_paths": report_paths})
            except Exception as exc:
                artifact_error = "Groups were saved; report refresh failed: " + str(exc)
        with _state_lock:
            if results:
                _state["results"] = results if len(results) <= 500 else []
                _state["fleet_index"] = [_build_compact_host_row(i, h, os.path.join(outdir, "reports")) for i, h in enumerate(results, 1)]
        self._send_json({"ok": True, "groups": groups, "group": created, "affected_hosts": len(set(ids)), "warning": artifact_error})
