"""Authenticated vCenter quick check. Does not install or run VDT."""

from __future__ import annotations

import logging
from typing import Any

from vcf_hci.plugins.vinv.models import VinvRequest
from vcf_hci.web.plugin_credentials import resolve_plugin_credentials

logger = logging.getLogger("vcf_assess")
_NO_STORE = {"Cache-Control": "no-store"}


def handle_vcenter_check(handler: Any) -> None:
    if handler._vinv_guard() is None:
        return
    data = handler._read_json_body()
    if not isinstance(data, dict):
        handler._send_json({"error": "Expected a JSON object."}, 400, extra_headers=_NO_STORE)
        return
    data = dict(data)
    data["acknowledged"] = True
    if not resolve_plugin_credentials(handler, data, "vcenter", required_role="administrator"):
        return
    request = handler._vinv_request(data)
    if request is None:
        return
    _run_preflight(handler, request)


def _run_preflight(handler: Any, request: VinvRequest) -> None:
    from vcf_hci.plugins.vinv.sources.diagnostics import VinvError
    from vcf_hci.web.vinv_api import failure_payload, open_adapter

    adapter = None
    try:
        adapter = open_adapter()
        report = adapter.preflight(request)
    except VinvError as exc:
        failure = failure_payload(exc, "quick check")
        handler._send_json(failure, 400, extra_headers=_NO_STORE)
        return
    except PermissionError:
        handler._send_json(
            {"error": "Acknowledge the experimental collection before running the quick check.", "error_code": "acknowledgement_required"},
            400,
            extra_headers=_NO_STORE,
        )
        return
    except Exception as exc:
        logger.exception("vCenter quick check failed")
        failure = failure_payload(exc, "quick check")
        handler._send_json(failure, 500, extra_headers=_NO_STORE)
        return
    finally:
        request.password.clear()
        if adapter is not None:
            try:
                adapter.close()
            except Exception:
                logger.debug("vCenter quick check session cleanup failed", exc_info=True)
    handler._send_json({
        "ok": True,
        "ready": report.ok,
        "server_version": report.server_version,
        "server_build": report.server_build,
        "server_uuid": report.server_uuid,
        "clusters": [{"id": item["id"], "name": item["name"]} for item in report.clusters],
        "host_count": report.host_count,
        "vm_count": report.vm_count,
        "messages": list(report.messages),
    }, extra_headers=_NO_STORE)
