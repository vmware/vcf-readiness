"""
VCF Readiness Tool — Security Web API Mixin (vcf_hci.web.security_api)

Defines SecurityApiMixin for BMC security audit summary, findings, and per-host query.
"""

import urllib.parse
from typing import TYPE_CHECKING, Any, Optional

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

from vcf_hci.web.scan_worker import (
    _state,
    _state_lock,
)


class SecurityApiMixin(_ApiMixinBase):
    """BMC security audit API endpoints mixed into AppHandler."""

    def _api_security_summary(self) -> None:
        """Return fleet-wide BMC security audit summary, posture counts, and scores."""
        from vcf_hci.security.scoring import aggregate_fleet_security

        with _state_lock:
            results = list(_state.get("results", []))
            outdir = _state.get("outdir", "")

        if not results and outdir:
            try:
                from vcf_hci.summary_io import load_summary
                results = load_summary(outdir) or []
            except Exception:
                pass

        agg = aggregate_fleet_security(results)
        self._send_json(agg)

    def _api_security_findings(self) -> None:
        """Return all normalized security findings across evaluated hosts."""
        from vcf_hci.security.metadata import get_control_title
        from vcf_hci.security.scoring import is_fleet_manager_asset

        with _state_lock:
            results = list(_state.get("results", []))
            outdir = _state.get("outdir", "")

        if not results and outdir:
            try:
                from vcf_hci.summary_io import load_summary
                results = load_summary(outdir) or []
            except Exception:
                pass

        all_findings = []
        for host in results:
            if is_fleet_manager_asset(host):
                continue
            si = host.get("system") or {}
            ip = str(si.get("bmc_ip") or si.get("ip") or host.get("host") or "")
            hostname = str(si.get("hostname") or "")
            vendor = str(si.get("vendor") or "")

            audit = host.get("bmc_security_audit") or {}
            findings = audit.get("findings") or []
            for f in findings:
                cid = str(f.get("control_id") or "")
                finding_copy = dict(f)
                finding_copy["control_title"] = get_control_title(cid)
                finding_copy["host_ip"] = ip
                finding_copy["hostname"] = hostname
                finding_copy["vendor"] = vendor
                all_findings.append(finding_copy)

        self._send_json({"findings": all_findings, "total": len(all_findings)})

    def _api_security_host(self, host_id: str) -> None:
        """Return detailed security audit findings and scores for a specific host by IP or hostname."""
        from vcf_hci.security.scoring import score_host_security

        with _state_lock:
            results = list(_state.get("results", []))
            outdir = _state.get("outdir", "")

        if not results and outdir:
            try:
                from vcf_hci.summary_io import load_summary
                results = load_summary(outdir) or []
            except Exception:
                pass

        target_host = None
        decoded_id = urllib.parse.unquote(host_id).strip()

        for host in results:
            si = host.get("system") or {}
            ip = str(si.get("bmc_ip") or si.get("ip") or host.get("host") or "").strip()
            hostname = str(si.get("hostname") or "").strip()
            if decoded_id in (ip, hostname):
                target_host = host
                break

        if not target_host:
            self._send_json({"error": f"Host '{decoded_id}' not found in current scan results"}, 404)
            return

        score = score_host_security(target_host)
        audit = target_host.get("bmc_security_audit") or {}

        response_data = {
            "host_id": decoded_id,
            "score": score,
            "bmc_security_audit": audit,
        }
        self._send_json(response_data)
