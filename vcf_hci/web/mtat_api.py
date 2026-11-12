"""Session-owned MTAT routes. Adapters load only after the gate and acknowledgement."""

from __future__ import annotations

import base64
import json
import logging
import os
import tempfile
import threading
import uuid
import zipfile
from dataclasses import asdict, replace
from io import BytesIO
from typing import TYPE_CHECKING, Any, Optional, Sequence

from vcf_hci.constants import TOOL_VERSION
from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.plugins.mtat.constants import FEATURE_ID, WARNING
from vcf_hci.plugins.mtat.csv_export import render_hosts, render_hosts_history, render_vms, render_vms_history
from vcf_hci.plugins.mtat.diagnostics import MtatError
from vcf_hci.plugins.mtat.lifecycle import catalog_entry, disabled_body
from vcf_hci.plugins.mtat.limits import MAX_UPLOAD_BYTES
from vcf_hci.plugins.mtat.manifest import build_manifest
from vcf_hci.plugins.mtat.models import Assessment, Secret
from vcf_hci.plugins.mtat.reporting import (
    build_report_payload,
    render_matrix_csv,
    render_multi_hosts_history,
    render_multi_vms_history,
    sanitize_endpoint_label,
    select_primary_assessment,
)
from vcf_hci.plugins.mtat.sources.base import CollectionRequest
from vcf_hci.web.export_api import _ApiMixinBase
from vcf_hci.web.plugin_credentials import resolve_plugin_credentials

logger = logging.getLogger(__name__)

_NO_STORE = {"Cache-Control": "no-store"}
_JOB_PREFIX = "/api/plugins/mtat/jobs/"
_VALID_UNITS = {"auto", "B", "KB", "KiB", "MB", "MiB", "GB", "GiB", "TB", "TiB"}


class Cancelled(Exception):
    """Raised between adapter batches when the owning session cancels the job."""


class _Progress:
    def __init__(self, job: dict, range_index: int = 0, range_count: int = 1) -> None:
        self._job = job
        self._range_index = range_index
        self._range_count = max(1, range_count)

    def update(self, stage: str, completed: int, total: int, message: str) -> None:
        del message
        if self._job.get("cancel"):
            raise Cancelled()
        self._job["stage"] = "running"
        if self._range_count <= 1:
            self._job["completed"] = completed
            self._job["total"] = total
        else:
            per_range = max(1, total)
            self._job["completed"] = self._range_index * per_range + completed
            self._job["total"] = self._range_count * per_range
        self._job["message"] = stage or "running"


def failure_payload(exc: Exception, operation: str) -> dict:
    reference = uuid.uuid4().hex[:12]
    code = exc.code if isinstance(exc, MtatError) else "invalid_request" if isinstance(exc, ValueError) else "mtat_failure"
    stage = exc.stage if isinstance(exc, MtatError) else operation
    message = str(exc) if isinstance(exc, MtatError) else (
        "Check the source, endpoint, cluster, history window and workbook options." if isinstance(exc, ValueError)
        else "MTAT could not complete this request. Check the server diagnostics using the reference below.")
    logger.warning("MTAT %s failed: reference=%s code=%s stage=%s exception_type=%s",
                   operation, reference, code, stage, type(exc).__name__)
    return {"error": message, "error_code": code, "stage": stage, "reference": reference}


def open_adapter(kind: str):
    if kind == "vcenter":
        from vcf_hci.plugins.mtat.sources.vcenter import VcenterAdapter
        return VcenterAdapter(enabled=True)
    if kind == "operations-rest":
        from vcf_hci.plugins.mtat.sources.operations_rest import OperationsRestAdapter
        return OperationsRestAdapter(enabled=True)
    if kind == "operations-xlsx":
        from vcf_hci.plugins.mtat.sources.operations_xlsx import OperationsXlsxAdapter
        return OperationsXlsxAdapter(enabled=True)
    raise ValueError("unsupported source")


def job_id_from(path: str) -> str:
    if not path.startswith(_JOB_PREFIX):
        return ""
    token = path[len(_JOB_PREFIX):].split("/", 1)[0]
    if token and all(character in "0123456789abcdef" for character in token):
        return token
    return ""


def status_payload(job: dict) -> dict:
    payload: dict[str, Any] = {
        "id": job["id"],
        "lifecycle": "experimental",
        "enabled": True,
        "mtat_contract": "3.2",
        "warning": WARNING,
        "stage": job.get("stage"),
        "completed": job.get("completed", 0),
        "total": job.get("total", 0),
        "message": job.get("message") or job.get("stage"),
    }
    for key in ("error_code", "reference"):
        if key in job:
            payload[key] = job[key]
    if job.get("stage") == "done":
        payload["links"] = {
            "zip": "/api/plugins/mtat/jobs/%s/export.zip" % job["id"],
            "matrix": "/api/plugins/mtat/jobs/%s/matrix.csv" % job["id"],
            "hosts": "/api/plugins/mtat/jobs/%s/hosts.csv" % job["id"],
            "vms": "/api/plugins/mtat/jobs/%s/vms.csv" % job["id"],
            "hosts_history": "/api/plugins/mtat/jobs/%s/hosts_history.csv" % job["id"],
            "vms_history": "/api/plugins/mtat/jobs/%s/vms_history.csv" % job["id"],
        }
        assessments = tuple(job.get("assessments") or ())
        if not assessments and isinstance(job.get("assessment"), Assessment):
            assessments = (job["assessment"],)
        if assessments:
            payload["report"] = build_report_payload(
                assessments,
                endpoint_label=str(job.get("endpoint_label") or ""),
            )
    return payload


def export_zip(
    assessment: Assessment,
    product_version: str,
    assessments: Optional[Sequence[Assessment]] = None,
) -> bytes:
    all_assessments = tuple(assessments) if assessments else (assessment,)
    manifest = json.dumps(build_manifest(assessment, product_version), sort_keys=True, indent=2).encode("utf-8")
    hosts_history_csv = (
        render_hosts_history(assessment)
        if len(all_assessments) == 1
        else render_multi_hosts_history(all_assessments)
    )
    vms_history_csv = (
        render_vms_history(assessment)
        if len(all_assessments) == 1
        else render_multi_vms_history(all_assessments)
    )
    files = {
        "hosts.csv": render_hosts(assessment).encode("utf-8"),
        "vms.csv": render_vms(assessment).encode("utf-8"),
        "hosts_history.csv": hosts_history_csv.encode("utf-8"),
        "vms_history.csv": vms_history_csv.encode("utf-8"),
        "manifest.json": manifest,
    }
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class MtatApiMixin(_ApiMixinBase):
    if TYPE_CHECKING:
        server: Any
        def _current_session(self) -> Optional[str]: ...

    def _mtat_enabled(self) -> bool:
        return bool(getattr(self.server, "experimental_mtat", True))

    def _mtat_disabled(self) -> None:
        self._send_json(disabled_body(), 403, extra_headers=_NO_STORE)

    def _own_job(self, job_id: str) -> Optional[dict]:
        session = self._current_session() or ""
        job = getattr(self.server, "mtat_job", None)
        if not session or not job or job.get("id") != job_id or job.get("session") != session:
            self._send_json({"error": "Not found"}, 404, extra_headers=_NO_STORE)
            return None
        return job

    def _api_mtat_catalog(self) -> None:
        self._send_json(catalog_entry(self._mtat_enabled()), extra_headers=_NO_STORE)

    def _parse_window(self, window: Any, source_kind: str) -> tuple[str, int, int]:
        if not isinstance(window, dict) or "begin" not in window or "end" not in window:
            raise ValueError("invalid window")
        raw_begin, raw_end = window["begin"], window["end"]
        if (
            not isinstance(raw_begin, (int, str))
            or not isinstance(raw_end, (int, str))
            or isinstance(raw_begin, bool)
            or isinstance(raw_end, bool)
        ):
            raise ValueError("invalid window")
        try:
            begin, end = int(raw_begin), int(raw_end)
        except (TypeError, ValueError):
            raise ValueError("invalid window") from None
        if begin < 0 or end < begin:
            raise ValueError("invalid window")
        interval = ""
        if source_kind == "vcenter":
            interval = str(window.get("interval") or "").strip()
            if not interval:
                raise ValueError("invalid window")
        return interval, begin, end

    def _normalize_ranges(self, data: dict, request: CollectionRequest) -> list[dict[str, Any]]:
        raw_ranges = data.get("ranges")
        if raw_ranges is None:
            return [{"range_name": request.range_name, "window": data.get("window")}]
        if not isinstance(raw_ranges, list) or not raw_ranges:
            raise ValueError("invalid ranges")
        specs: list[dict[str, Any]] = []
        for entry in raw_ranges:
            if not isinstance(entry, dict):
                raise ValueError("invalid ranges")
            range_name = str(entry.get("range_name") or "").strip()
            window = entry.get("window")
            if not range_name:
                if request.source_kind == "operations-xlsx":
                    range_name = ""
                else:
                    raise ValueError("invalid range_name")
            elif range_name == "realtime" and window is not None and request.source_kind in {"vcenter", "operations-rest"}:
                range_name = "history"
            elif range_name == "realtime" and request.source_kind == "operations-xlsx":
                range_name = ""
            if window is not None:
                self._parse_window(window, request.source_kind)
            specs.append({"range_name": range_name, "window": window})
        return specs

    def _configure(self, adapter: Any, data: dict, request: CollectionRequest) -> None:
        if not isinstance(data.get("verify_tls", True), bool):
            raise ValueError("verify_tls must be boolean")
        windows_map: dict[str, Any] = {}
        window = data.get("window")
        if window is not None:
            interval, begin, end = self._parse_window(window, request.source_kind)
            if request.source_kind == "vcenter":
                windows_map[request.range_name] = (interval, begin, end)
            elif request.source_kind == "operations-rest":
                windows_map[request.range_name] = (begin, end)
        if data.get("ranges") is not None:
            for spec in self._normalize_ranges(data, request):
                spec_window = spec.get("window")
                if spec_window is not None:
                    interval, begin, end = self._parse_window(spec_window, request.source_kind)
                    if request.source_kind == "vcenter":
                        windows_map[spec["range_name"]] = (interval, begin, end)
                    elif request.source_kind == "operations-rest":
                        windows_map[spec["range_name"]] = (begin, end)
        if windows_map:
            adapter.windows = windows_map
        if request.source_kind == "operations-xlsx":
            unit = data.get("memory_unit", "auto")
            if not isinstance(unit, str) or unit not in _VALID_UNITS:
                raise ValueError("invalid memory unit")
            adapter.memory_unit = unit

    def _build_request(self, data: dict, endpoint: str, password_text: str) -> CollectionRequest:
        if not isinstance(data.get("verify_tls", True), bool):
            raise ValueError("verify_tls must be boolean")
        kind = str(data.get("source_kind") or "")
        raw_range = str(data.get("range_name") or "").strip()
        if not raw_range and isinstance(data.get("ranges"), list) and data["ranges"]:
            first_entry = data["ranges"][0]
            if isinstance(first_entry, dict):
                raw_range = str(first_entry.get("range_name") or "").strip()
        if not raw_range:
            raw_range = "" if kind == "operations-xlsx" else ("history" if data.get("window") is not None else "realtime")
        elif raw_range == "realtime" and data.get("window") is not None and kind in {"vcenter", "operations-rest"}:
            raw_range = "history"
        elif raw_range == "realtime" and kind == "operations-xlsx":
            raw_range = ""
        return CollectionRequest(
            source_kind=kind,
            endpoint=endpoint,
            username=str(data.get("username") or ""),
            password=Secret(password_text),
            cluster=str(data.get("cluster") or ""),
            range_name=raw_range,
            verify_tls=bool(data.get("verify_tls", True)),
            ca_file=data.get("ca_file") or None,
            auth_source=str(data.get("auth_source") or ""),
            policy=str(data.get("policy") or "mtat-3.2"),
            acknowledged=data.get("acknowledged") is True,
            certificate_pin=str(data.get("certificate_pin") or ""),
        )

    def _password_for(self, data: dict) -> Optional[str]:
        if "vault_credential_id" in data:
            kind = {"vcenter": "vcenter", "operations-rest": "operations"}.get(data.get("source_kind"), "")
            if not resolve_plugin_credentials(self, data, kind):
                return None
        if data.get("source_kind") == "operations-xlsx":
            return "workbook-import"
        password = data.get("password")
        if not isinstance(password, str) or not password:
            self._send_json({"error": "A password is required."}, 400, extra_headers=_NO_STORE)
            return None
        return password

    def _workbook_path(self, data: dict) -> Optional[str]:
        if data.get("source_kind") != "operations-xlsx":
            return ""
        raw = data.get("workbook_base64")
        if not isinstance(raw, str):
            self._send_json({"error": "Workbook payload is required."}, 400, extra_headers=_NO_STORE)
            return None
        if len(raw) > 4 * ((MAX_UPLOAD_BYTES + 2) // 3):
            self._send_json({"error": "Workbook exceeds the upload limit."}, 413, extra_headers=_NO_STORE)
            return None
        try:
            content = base64.b64decode(raw, validate=True)
        except (ValueError, TypeError):
            self._send_json({"error": "Workbook payload is invalid."}, 400, extra_headers=_NO_STORE)
            return None
        if len(content) > MAX_UPLOAD_BYTES:
            self._send_json({"error": "Workbook exceeds the upload limit."}, 413, extra_headers=_NO_STORE)
            return None
        handle = tempfile.NamedTemporaryFile(prefix="mtat-", suffix=".xlsx", delete=False)
        handle.write(content)
        handle.close()
        return handle.name

    def _cleanup(self, adapter: Any, temp_path: str) -> bool:
        ok = True
        if adapter is not None:
            try:
                adapter.close()
            except Exception:
                logger.warning("MTAT session cleanup failed")
                ok = False
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                logger.warning("MTAT workbook cleanup failed; retained path: %s", temp_path)
                ok = False
        return ok

    def _api_mtat_preflight(self) -> None:
        if not self._mtat_enabled():
            self._mtat_disabled()
            return
        data = self._read_json_body()
        if not isinstance(data, dict):
            self._send_json({"error": "Expected a JSON object."}, 400, extra_headers=_NO_STORE)
            return
        if data.get("acknowledged") is not True:
            self._send_json({"error_code": "acknowledgement_required", "error": WARNING}, 400, extra_headers=_NO_STORE)
            return
        password = self._password_for(data)
        if password is None:
            return
        temp_path = self._workbook_path(data)
        if temp_path is None:
            return
        endpoint = temp_path or str(data.get("endpoint") or "")
        adapter = None
        request = None
        try:
            request = self._build_request(data, endpoint, password)
            adapter = open_adapter(request.source_kind)
            self._configure(adapter, data, request)
            report = adapter.preflight(request)
        except Exception as exc:
            self._send_json(failure_payload(exc, "preflight"), 400, extra_headers=_NO_STORE)
            return
        finally:
            if request is not None:
                request.password._value = ""
            cleanup_ok = self._cleanup(adapter, temp_path)
        if not cleanup_ok:
            self._send_json({"error": "Preflight cleanup failed"}, 500, extra_headers=_NO_STORE)
            return
        self._send_json(
            {
                "ready": report.ready,
                "source_version": report.source_version,
                "tls_verified": report.tls_verified,
                "capabilities": report.capabilities,
                "messages": list(report.messages),
                "clusters": list(report.clusters),
                "historical_intervals": [asdict(interval) for interval in report.historical_intervals],
                "warning": WARNING,
                "lifecycle": "experimental",
            },
            extra_headers=_NO_STORE,
        )

    def _api_mtat_jobs_post(self) -> None:
        if not self._mtat_enabled():
            self._mtat_disabled()
            return
        session = self._current_session() or ""
        if not session:
            self._send_json({"error": "Unauthorized"}, 401, extra_headers=_NO_STORE)
            return
        data = self._read_json_body()
        if not isinstance(data, dict):
            self._send_json({"error": "Expected a JSON object."}, 400, extra_headers=_NO_STORE)
            return
        if data.get("acknowledged") is not True:
            self._send_json({"error_code": "acknowledgement_required", "error": WARNING}, 400, extra_headers=_NO_STORE)
            return
        password = self._password_for(data)
        if password is None:
            return
        temp_path = self._workbook_path(data)
        if temp_path is None:
            return
        endpoint = temp_path or str(data.get("endpoint") or "")
        request = None
        try:
            request = self._build_request(data, endpoint, password)
            self._configure(type("_Cfg", (), {})(), data, request)
        except ValueError:
            if request is not None:
                request.password._value = ""
            self._cleanup(None, temp_path)
            self._send_json({"error": "The request was rejected."}, 400, extra_headers=_NO_STORE)
            return
        endpoint_label = sanitize_endpoint_label(endpoint, request.source_kind)
        job = {
            "id": uuid.uuid4().hex,
            "session": session,
            "stage": "queued",
            "completed": 0,
            "total": 0,
            "message": "queued",
            "cancel": False,
            "assessment": None,
            "assessments": (),
            "endpoint_label": endpoint_label,
        }
        with self.server.mtat_lock:
            current = self.server.mtat_job
            if current and current.get("stage") in {"queued", "running", "hosts"}:
                request.password._value = ""
                self._cleanup(None, temp_path)
                self._send_json({"error_code": "mtat_job_busy", "error": "An MTAT job is already running."}, 409, extra_headers=_NO_STORE)
                return
            self.server.mtat_job = job
        options = {k: data[k] for k in ("window", "ranges", "memory_unit", "verify_tls") if k in data}
        try:
            threading.Thread(target=self._mtat_worker, args=(job, request, temp_path, options), daemon=True).start()
        except Exception:
            request.password._value = ""
            self._cleanup(None, temp_path)
            job["stage"] = "failed"
            job["message"] = "Worker startup failed"
            self._send_json({"error": "Worker startup failed"}, 500, extra_headers=_NO_STORE)
            return
        self._send_json({"id": job["id"]}, extra_headers=_NO_STORE)

    def _mtat_worker(self, job: dict, request: CollectionRequest, temp_path: str, options: Optional[dict] = None) -> None:
        adapter = None
        outcome = "failed"
        password_text = request.password.reveal()
        try:
            job["stage"] = "running"
            job["message"] = "running"
            if not job.get("endpoint_label"):
                job["endpoint_label"] = sanitize_endpoint_label(request.endpoint, request.source_kind)
            opts = dict(options or {})
            range_specs = self._normalize_ranges(opts, request)
            adapter = open_adapter(request.source_kind)
            adapter.cancelled = lambda: bool(job.get("cancel"))
            self._configure(adapter, opts, request)
            collected: list[Assessment] = []
            total_ranges = len(range_specs)
            for idx, spec in enumerate(range_specs):
                if job.get("cancel"):
                    raise Cancelled()
                spec_range = str(spec.get("range_name") or "")
                spec_window = spec.get("window")
                if total_ranges == 1 and spec_range == request.range_name:
                    range_req = request
                else:
                    range_req = replace(
                        request,
                        range_name=spec_range,
                        password=Secret(password_text or "workbook-import"),
                    )
                range_opts: dict[str, Any] = {
                    k: opts[k] for k in ("memory_unit", "verify_tls") if k in opts
                }
                if spec_window is not None:
                    range_opts["window"] = spec_window
                self._configure(adapter, range_opts, range_req)
                try:
                    if (
                        request.source_kind == "operations-rest"
                        and spec_window is None
                        and spec_range.strip().lower() in {"real-time", "real-time snapshot"}
                    ):
                        raw_assessment = adapter.collect(
                            replace(range_req, range_name="realtime"),
                            _Progress(job, idx, total_ranges),
                        )
                        assessment = replace(raw_assessment, range_name=spec_range)
                    else:
                        assessment = adapter.collect(range_req, _Progress(job, idx, total_ranges))
                finally:
                    range_req.password._value = ""
                collected.append(assessment)
            job["assessments"] = tuple(collected)
            job["assessment"] = select_primary_assessment(collected)
            job["stage"] = "running"
            outcome = "cancelled" if job.get("cancel") else "done"
            job["message"] = job["stage"]
        except Cancelled:
            outcome = "cancelled"
            job["message"] = "cancelled"
        except Exception as exc:
            outcome = "cancelled" if job.get("cancel") else "failed"
            details = failure_payload(exc, "collection")
            job["message"] = details["error"]
            job["error_code"] = details["error_code"]
            job["reference"] = details["reference"]
        finally:
            password_text = ""
            request.password._value = ""
            if adapter is not None:
                try:
                    adapter.close()
                except Exception:
                    outcome = "failed"
                    job["message"] = "Session cleanup failed"
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    outcome = "failed"
                    job["message"] = "Workbook cleanup failed"

        job["stage"] = outcome
        if outcome != "done":
            job["assessment"] = None
            job["assessments"] = ()
        if outcome == "done" or outcome == "cancelled":
            job["message"] = outcome

    def _api_mtat_job_get(self, path: str) -> None:
        if not self._mtat_enabled():
            self._mtat_disabled()
            return
        job_id = job_id_from(path)
        job = self._own_job(job_id)
        if job is None:
            return
        suffix = path[len(_JOB_PREFIX) + len(job_id):]
        if suffix in ("", "/"):
            self._send_json(status_payload(job), extra_headers=_NO_STORE)
            return
        if job.get("stage") != "done" or not isinstance(job.get("assessment"), Assessment):
            self._send_json({"error": "The result is not ready."}, 409, extra_headers=_NO_STORE)
            return
        assessment = job["assessment"]
        assessments = tuple(job.get("assessments") or (assessment,))
        endpoint_label = str(job.get("endpoint_label") or "")
        if suffix == "/export.zip":
            self._mtat_bytes(
                export_zip(assessment, TOOL_VERSION, assessments),
                "application/zip",
                "experimental-mtat-export.zip",
            )
            return
        names = {
            "/hosts.csv": ("experimental-hosts.csv", render_hosts(assessment), "text/csv; charset=utf-8"),
            "/vms.csv": ("experimental-vms.csv", render_vms(assessment), "text/csv; charset=utf-8"),
            "/hosts_history.csv": (
                "experimental-hosts-history.csv",
                render_multi_hosts_history(assessments),
                "text/csv; charset=utf-8",
            ),
            "/vms_history.csv": (
                "experimental-vms-history.csv",
                render_multi_vms_history(assessments),
                "text/csv; charset=utf-8",
            ),
            "/matrix.csv": (
                "experimental-mtat-matrix.csv",
                render_matrix_csv(assessments, endpoint_label=endpoint_label),
                "text/csv; charset=utf-8",
            ),
        }
        if suffix not in names:
            self._send_json({"error": "Not found"}, 404, extra_headers=_NO_STORE)
            return
        filename, content, content_type = names[suffix]
        self._mtat_bytes(content.encode("utf-8"), content_type, filename)

    def _api_mtat_cancel(self, path: str) -> None:
        if not self._mtat_enabled():
            self._mtat_disabled()
            return
        job = self._own_job(job_id_from(path))
        if job is None:
            return
        if job.get("stage") not in {"done", "failed", "cancelled"}:
            job["cancel"] = True
        self._send_json({"id": job["id"], "message": "cancelled"}, extra_headers=_NO_STORE)

    def _mtat_bytes(self, body: bytes, content_type: str, filename: str) -> None:
        filename = sanitize_filename(filename)
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Disposition", 'attachment; filename="%s"' % filename)
        self.send_header("X-Experimental-Feature", FEATURE_ID)
        self.end_headers()
        self.wfile.write(body)
