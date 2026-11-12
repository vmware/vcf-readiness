"""Session-owned vSphere inventory routes. The adapter loads only after the gate and acknowledgement."""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
import uuid
import zipfile
from collections import OrderedDict
from io import BytesIO
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from vcf_hci.constants import TOOL_VERSION
from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.plugins.vinv.constants import FEATURE_ID, LIFECYCLE, SCHEMA_VERSION, WARNING
from vcf_hci.plugins.vinv.lifecycle import catalog_entry, disabled_body
from vcf_hci.plugins.vinv.limits import MAX_RESULT_BYTES, MAX_UPLOAD_BYTES
from vcf_hci.plugins.vinv.models import Secret, VinvRequest, VinvSnapshot
from vcf_hci.web.export_api import _ApiMixinBase
from vcf_hci.web.plugin_credentials import resolve_plugin_credentials

logger = logging.getLogger("vcf_assess.vinv.api")

_NO_STORE = {"Cache-Control": "no-store"}
_PREFIX = "/api/plugins/vinv"
_JOB_PREFIX = _PREFIX + "/jobs/"
_LIB_PREFIX = _PREFIX + "/library/"
_ACTIVE = {"queued", "running"}
_XLSX_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
MAX_LIBRARY_PER_SESSION = 8
MAX_LIBRARY_TOTAL = 32
UPLOAD_BODY_LIMIT = 4 * ((MAX_UPLOAD_BYTES + 2) // 3) + 65536
_EXPECTED_CODES = {"authentication", "certificate_pin_invalid", "cluster_not_found", "endpoint_invalid", "cancelled"}


class Cancelled(Exception):
    """Raised between adapter batches when the owning session cancels the job."""


class _Progress:
    def __init__(self, job: dict) -> None:
        self._job = job

    def update(self, stage: str, completed: int, total: int, message: str) -> None:
        if self._job.get("cancel"):
            raise Cancelled()
        self._job["stage"] = "running"
        self._job["completed"] = completed
        self._job["total"] = total
        self._job["message"] = message or stage or "running"


def open_adapter() -> Any:
    from vcf_hci.plugins.vinv.sources.vcenter import VinvVcenterAdapter
    return VinvVcenterAdapter(enabled=True)


def failure_payload(exc: Exception, operation: str) -> Dict[str, str]:
    """Return a credential-safe failure body; logs carry the code, stage and type chain only."""
    from vcf_hci.plugins.vinv.sources.diagnostics import VinvError, exception_summary
    reference = uuid.uuid4().hex[:12]
    if isinstance(exc, VinvError):
        body = {"error": str(exc), "error_code": exc.code, "stage": exc.stage}
    else:
        body = {"error": "%s failed" % operation.capitalize(), "error_code": "vinv_%s_failed" % operation.replace(" ", "_"),
                "stage": operation}
    body["reference"] = reference
    level = logging.INFO if body["error_code"] in _EXPECTED_CODES else logging.WARNING
    logger.log(level, "vSphere inventory %s failed: reference=%s code=%s stage=%s chain=%s",
               operation, reference, body["error_code"], body["stage"], exception_summary(exc))
    return body


def _token_after(path: str, prefix: str) -> Tuple[str, str]:
    if not path.startswith(prefix):
        return "", ""
    token, _, rest = path[len(prefix):].partition("/")
    if token and len(token) <= 64 and all(c in "0123456789abcdef" for c in token):
        return token, ("/" + rest) if rest else ""
    return "", ""


def snapshot_summary(snapshot: VinvSnapshot) -> Dict[str, Any]:
    counts = {tab.name: len(tab.rows) for tab in snapshot.tabs}
    return {
        "vcenter_server": snapshot.vcenter_server,
        "vcenter_version": snapshot.vcenter_version,
        "vcenter_build": snapshot.vcenter_build,
        "generated_utc": snapshot.generated_utc,
        "scope_cluster": snapshot.scope_cluster,
        "tls_verified": snapshot.tls_verified,
        "include_file_info": snapshot.include_file_info,
        "hosts": counts.get("vHost", 0),
        "vms": counts.get("vInfo", 0),
        "clusters": counts.get("vCluster", 0),
        "datastores": counts.get("vDatastore", 0),
        "health_findings": counts.get("vHealth", 0),
        "tabs": counts,
        "warnings": list(snapshot.warnings),
    }


def build_manifest(snapshot: VinvSnapshot, obfuscated: bool) -> Dict[str, Any]:
    manifest = snapshot_summary(snapshot)
    manifest.update({
        "feature": FEATURE_ID,
        "lifecycle": LIFECYCLE,
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "obfuscated": obfuscated,
        "warning": WARNING,
    })
    return manifest


def export_zip(snapshot: VinvSnapshot, obfuscated: bool = False) -> bytes:
    from vcf_hci.plugins.vinv.xlsx_io import render_vinv_xlsx, snapshot_to_json
    files = {
        "vsphere_inventory.xlsx": render_vinv_xlsx(snapshot),
        "vinv_snapshot.json": snapshot_to_json(snapshot).encode("utf-8"),
        "manifest.json": json.dumps(build_manifest(snapshot, obfuscated), sort_keys=True, indent=2).encode("utf-8"),
    }
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def obfuscation_salt() -> str:
    from vcf_hci.web.scan_worker import _state, _state_lock
    with _state_lock:
        salt = _state.get("obf_salt")
    return str(salt) if salt else os.urandom(16).hex()


class VinvLibrary:
    """Bounded in-memory snapshot library. Entries are owned by one session; at most one is attached."""

    def __init__(self, per_session: int = MAX_LIBRARY_PER_SESSION, total: int = MAX_LIBRARY_TOTAL) -> None:
        self._lock = threading.Lock()
        self._items: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._attached: Optional[str] = None
        self._per_session = per_session
        self._total = total

    def _summary(self, entry_id: str, entry: Dict[str, Any]) -> Dict[str, Any]:
        out = snapshot_summary(entry["snapshot"])
        out.update({"id": entry_id, "label": entry["label"], "source": entry["source"],
                    "added_utc": entry["added_utc"], "attached": entry_id == self._attached})
        return out

    def add(self, session: str, snapshot: VinvSnapshot, source: str, label: str) -> Dict[str, Any]:
        entry_id = uuid.uuid4().hex
        with self._lock:
            owned = [k for k, v in self._items.items() if v["session"] == session]
            while len(owned) >= self._per_session or len(self._items) >= self._total:
                victims = [k for k in (owned if len(owned) >= self._per_session else list(self._items)) if k != self._attached]
                if not victims:
                    raise ValueError("Remove a library entry before adding another.")
                self._items.pop(victims[0])
                owned = [k for k in owned if k != victims[0]]
            entry = {"session": session, "snapshot": snapshot, "source": source, "label": label[:120],
                     "added_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())}
            self._items[entry_id] = entry
            return self._summary(entry_id, entry)

    def list(self, session: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [self._summary(k, v) for k, v in self._items.items() if v["session"] == session]

    def get(self, session: str, entry_id: str) -> Optional[VinvSnapshot]:
        with self._lock:
            entry = self._items.get(entry_id)
            return entry["snapshot"] if entry and entry["session"] == session else None

    def remove(self, session: str, entry_id: str) -> bool:
        with self._lock:
            entry = self._items.get(entry_id)
            if not entry or entry["session"] != session:
                return False
            self._items.pop(entry_id)
            if self._attached == entry_id:
                self._attached = None
            return True

    def attach(self, session: str, entry_id: str) -> bool:
        with self._lock:
            entry = self._items.get(entry_id)
            if not entry or entry["session"] != session:
                return False
            self._attached = entry_id
            return True

    def detach(self) -> None:
        with self._lock:
            self._attached = None

    def attached(self) -> Optional[VinvSnapshot]:
        with self._lock:
            entry = self._items.get(self._attached or "")
            return entry["snapshot"] if entry else None


def server_state(server: Any) -> Tuple[threading.Lock, VinvLibrary]:
    lock = getattr(server, "vinv_lock", None)
    library = getattr(server, "vinv_library", None)
    if lock is None or library is None:
        lock = lock or threading.Lock()
        library = library or VinvLibrary()
        server.vinv_lock = lock
        server.vinv_library = library
        if not hasattr(server, "vinv_job"):
            server.vinv_job = None
    return lock, library


def attached_snapshot(server: Any) -> Optional[VinvSnapshot]:
    """Snapshot attached to the active Redfish assessment, or None when disabled or unattached."""
    if getattr(server, "experimental_vinv", False) is not True:
        return None
    library = getattr(server, "vinv_library", None)
    if not isinstance(library, VinvLibrary):
        return None
    return library.attached()


class VinvApiMixin(_ApiMixinBase):
    if TYPE_CHECKING:
        server: Any
        def _current_session(self) -> Optional[str]: ...

    # ── Helpers ──────────────────────────────────────────────────────────

    def _vinv_enabled(self) -> bool:
        return bool(getattr(self.server, "experimental_vinv", True))

    def _vinv_guard(self) -> Optional[str]:
        """Return the session id, or send the 403/401 response and return None."""
        if not self._vinv_enabled():
            self._send_json(disabled_body(), 403, extra_headers=_NO_STORE)
            return None
        from vcf_hci.plugins.vinv.sources.diagnostics import configure_debug_logging
        configure_debug_logging()
        session = self._current_session() or ""
        if not session:
            self._send_json({"error": "Unauthorized"}, 401, extra_headers=_NO_STORE)
            return None
        return session

    def _vinv_body(self) -> Optional[dict]:
        data = self._read_json_body()
        if not isinstance(data, dict) or not data:
            self._send_json({"error": "Expected a JSON object."}, 400, extra_headers=_NO_STORE)
            return None
        if data.get("acknowledged") is not True:
            self._send_json({"error_code": "acknowledgement_required", "error": WARNING}, 400, extra_headers=_NO_STORE)
            return None
        return data

    def _vinv_request(self, data: dict) -> Optional[VinvRequest]:
        if not resolve_plugin_credentials(self, data, "vcenter"):
            return None
        password = data.get("password")
        if not isinstance(password, str) or not password:
            self._send_json({"error": "A password is required."}, 400, extra_headers=_NO_STORE)
            return None
        for flag in ("verify_tls", "include_network_hints", "include_file_info"):
            if flag in data and not isinstance(data[flag], bool):
                self._send_json({"error": f"{flag} must be boolean"}, 400, extra_headers=_NO_STORE)
                return None
        endpoint = str(data.get("endpoint") or "").strip()
        username = str(data.get("username") or "").strip()
        if not endpoint or not username:
            self._send_json({"error": "Endpoint and username are required."}, 400, extra_headers=_NO_STORE)
            return None
        from vcf_hci.plugins.mtat.tls import validated_pin
        from vcf_hci.plugins.vinv.sources.diagnostics import MESSAGES
        from vcf_hci.plugins.vinv.sources.vcenter import connection_target
        try:
            connection_target(endpoint)
        except ValueError:
            logger.debug("vinv request rejected: code=endpoint_invalid")
            self._send_json({"error": MESSAGES["endpoint_invalid"], "error_code": "endpoint_invalid", "stage": "input"},
                            400, extra_headers=_NO_STORE)
            return None
        pin = data.get("certificate_pin") or ""
        try:
            if not isinstance(pin, str):
                raise ValueError
            pin = validated_pin(pin) if pin else ""
        except ValueError:
            logger.debug("vinv request rejected: code=certificate_pin_invalid")
            self._send_json({"error": MESSAGES["certificate_pin_invalid"], "error_code": "certificate_pin_invalid", "stage": "input"},
                            400, extra_headers=_NO_STORE)
            return None
        return VinvRequest(
            endpoint=endpoint,
            username=username,
            password=Secret(password),
            cluster=str(data.get("cluster") or "").strip(),
            verify_tls=data.get("verify_tls", True),
            ca_file=None,
            include_network_hints=data.get("include_network_hints", True),
            include_file_info=data.get("include_file_info", False),
            acknowledged=True,
            certificate_pin=pin,
        )

    def _vinv_bytes(self, body: bytes, content_type: str, filename: str) -> None:
        filename = sanitize_filename(filename)
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Disposition", 'attachment; filename="%s"' % filename)
        self.send_header("X-Experimental-Feature", FEATURE_ID)
        self.end_headers()
        self.wfile.write(body)

    def _vinv_send_snapshot(self, snapshot: VinvSnapshot, suffix: str, obfuscated: bool) -> None:
        from vcf_hci.plugins.vinv.xlsx_io import render_vinv_xlsx
        if obfuscated:
            from vcf_hci.plugins.vinv.obfuscate import obfuscate_vinv_snapshot
            snapshot = obfuscate_vinv_snapshot(snapshot, obfuscation_salt())
        stem = "experimental-vsphere-inventory-%s" % time.strftime("%Y%m%d_%H%M%S")
        if obfuscated:
            stem = "00_OBFUSCATED_" + stem
        if suffix == "/export.xlsx":
            self._vinv_bytes(render_vinv_xlsx(snapshot), _XLSX_TYPE, stem + ".xlsx")
        elif suffix == "/export.zip":
            self._vinv_bytes(export_zip(snapshot, obfuscated), "application/zip", stem + ".zip")
        else:
            self._send_json({"error": "Not found"}, 404, extra_headers=_NO_STORE)

    def _vinv_obfuscated_query(self) -> bool:
        query = getattr(self, "path", "").partition("?")[2]
        return any(part in ("obfuscated=1", "obfuscated=true") for part in query.split("&"))

    # ── Catalog / preflight / jobs ───────────────────────────────────────

    def _api_vinv_catalog(self) -> None:
        body = catalog_entry(self._vinv_enabled())
        if self._vinv_enabled():
            session = self._current_session() or ""
            _, library = server_state(self.server)
            body["library"] = library.list(session) if session else []
        self._send_json(body, extra_headers=_NO_STORE)

    def _api_vinv_preflight(self) -> None:
        if self._vinv_guard() is None:
            return
        data = self._vinv_body()
        if data is None:
            return
        request = self._vinv_request(data)
        if request is None:
            return
        from vcf_hci.plugins.vinv.sources.diagnostics import VinvError
        adapter = None
        started = time.monotonic()
        logger.debug("vinv preflight requested: discovery=%s pinned=%s", not request.cluster, bool(request.certificate_pin))
        try:
            adapter = open_adapter()
            report = adapter.preflight(request)
        except VinvError as exc:
            self._send_json(failure_payload(exc, "preflight"), 400, extra_headers=_NO_STORE)
            return
        except (PermissionError, ValueError) as exc:
            self._send_json({"error": str(exc) or "Preflight rejected", "error_code": "preflight_rejected", "stage": "input"},
                            400, extra_headers=_NO_STORE)
            return
        except Exception as exc:
            self._send_json(failure_payload(exc, "preflight"), 400, extra_headers=_NO_STORE)
            return
        finally:
            request.password.clear()
            if adapter is not None:
                try:
                    adapter.close()
                except Exception as exc:
                    failure_payload(exc, "session cleanup")
        logger.debug("vinv preflight returned in %d ms: clusters=%d hosts=%d vms=%d",
                     int((time.monotonic() - started) * 1000), len(report.clusters), report.host_count, report.vm_count)
        self._send_json({
            "ready": report.ok,
            "server_version": report.server_version,
            "server_build": report.server_build,
            "tls_verified": report.verify_tls,
            "clusters": [{"id": c["id"], "name": c["name"]} for c in report.clusters],
            "host_count": report.host_count,
            "vm_count": report.vm_count,
            "datastore_count": report.datastore_count,
            "messages": list(report.messages),
            "warning": WARNING,
            "lifecycle": LIFECYCLE,
        }, extra_headers=_NO_STORE)

    def _api_vinv_jobs_post(self) -> None:
        session = self._vinv_guard()
        if session is None:
            return
        data = self._vinv_body()
        if data is None:
            return
        request = self._vinv_request(data)
        if request is None:
            return
        lock, _ = server_state(self.server)
        job = {"id": uuid.uuid4().hex, "session": session, "stage": "queued", "completed": 0, "total": 0,
               "message": "queued", "cancel": False, "entry_id": None, "summary": None}
        with lock:
            current = getattr(self.server, "vinv_job", None)
            if current and current.get("stage") in _ACTIVE:
                request.password.clear()
                self._send_json({"error_code": "vinv_job_busy", "error": "A vSphere inventory job is already running."},
                                409, extra_headers=_NO_STORE)
                return
            self.server.vinv_job = job
        label = str(data.get("label") or "").strip() or request.endpoint
        logger.debug("vinv job %s queued: scope=%s pinned=%s file_info=%s", job["id"][:8], "cluster" if request.cluster else "all",
                     bool(request.certificate_pin), request.include_file_info)
        try:
            threading.Thread(target=self._vinv_worker, args=(job, request, label), daemon=True).start()
        except Exception as exc:
            request.password.clear()
            failure = failure_payload(exc, "worker startup")
            job.update(stage="failed", message="Worker startup failed", error_code=failure["error_code"], reference=failure["reference"])
            self._send_json({"error": "Worker startup failed", "error_code": failure["error_code"], "reference": failure["reference"]},
                            500, extra_headers=_NO_STORE)
            return
        self._send_json({"id": job["id"]}, extra_headers=_NO_STORE)

    def _vinv_worker(self, job: dict, request: VinvRequest, label: str) -> None:
        adapter = None
        outcome = "failed"
        started = time.monotonic()
        try:
            job["stage"] = "running"
            job["message"] = "Connecting to vCenter"
            adapter = open_adapter()
            adapter.cancelled = lambda: bool(job.get("cancel"))
            snapshot = adapter.collect(request, _Progress(job))
            if job.get("cancel"):
                outcome = "cancelled"
            else:
                _, library = server_state(self.server)
                entry = library.add(job["session"], snapshot, "vcenter", label)
                job["entry_id"] = entry["id"]
                job["summary"] = entry
                outcome = "done"
        except Cancelled:
            outcome = "cancelled"
        except Exception as exc:
            outcome = "cancelled" if job.get("cancel") else "failed"
            if outcome == "failed":
                failure = failure_payload(exc, "collection")
                job["error"], job["error_code"], job["reference"] = failure["error"], failure["error_code"], failure["reference"]
        finally:
            request.password.clear()
            if adapter is not None:
                try:
                    adapter.close()
                except Exception as exc:
                    failure = failure_payload(exc, "session cleanup")
                    if outcome != "done":
                        outcome = "failed"
                        job["message"] = "Session cleanup failed"
                        job["error_code"], job["reference"] = failure["error_code"], failure["reference"]
        job["stage"] = outcome
        if job.get("message") != "Session cleanup failed":
            job["message"] = {"done": "done", "cancelled": "cancelled"}.get(outcome, job.get("error") or "Collection failed")
        log = logger.info if outcome == "done" else logger.debug
        log("vinv job %s finished: outcome=%s in %d ms%s", job["id"][:8], outcome, int((time.monotonic() - started) * 1000),
            " code=%s reference=%s" % (job.get("error_code"), job.get("reference")) if job.get("error_code") else "")

    def _vinv_own_job(self, session: str, job_id: str) -> Optional[dict]:
        job = getattr(self.server, "vinv_job", None)
        if not job_id or not job or job.get("id") != job_id or job.get("session") != session:
            self._send_json({"error": "Not found"}, 404, extra_headers=_NO_STORE)
            return None
        return job

    def _api_vinv_job_get(self, path: str) -> None:
        session = self._vinv_guard()
        if session is None:
            return
        job_id, suffix = _token_after(path.split("?", 1)[0], _JOB_PREFIX)
        job = self._vinv_own_job(session, job_id)
        if job is None:
            return
        if suffix in ("", "/"):
            payload = {"id": job["id"], "lifecycle": LIFECYCLE, "warning": WARNING, "stage": job.get("stage"),
                       "completed": job.get("completed", 0), "total": job.get("total", 0),
                       "message": job.get("message") or job.get("stage")}
            for key in ("error_code", "reference"):
                if job.get(key):
                    payload[key] = job[key]
            if job.get("stage") == "done" and job.get("entry_id"):
                base = _JOB_PREFIX + job["id"]
                payload["entry"] = job.get("summary")
                payload["links"] = {"xlsx": base + "/export.xlsx", "zip": base + "/export.zip",
                                    "obfuscated_xlsx": base + "/export.xlsx?obfuscated=1",
                                    "obfuscated_zip": base + "/export.zip?obfuscated=1"}
            self._send_json(payload, extra_headers=_NO_STORE)
            return
        _, library = server_state(self.server)
        snapshot = library.get(session, job.get("entry_id") or "") if job.get("stage") == "done" else None
        if snapshot is None:
            self._send_json({"error": "The result is not ready."}, 409, extra_headers=_NO_STORE)
            return
        self._vinv_send_snapshot(snapshot, suffix, self._vinv_obfuscated_query())

    def _api_vinv_cancel(self, path: str) -> None:
        session = self._vinv_guard()
        if session is None:
            return
        job_id, _ = _token_after(path, _JOB_PREFIX)
        job = self._vinv_own_job(session, job_id)
        if job is None:
            return
        if job.get("stage") in _ACTIVE:
            job["cancel"] = True
        self._send_json({"id": job["id"], "message": "cancelled"}, extra_headers=_NO_STORE)

    # ── Library ──────────────────────────────────────────────────────────

    def _api_vinv_import(self) -> None:
        session = self._vinv_guard()
        if session is None:
            return
        data = self._vinv_body()
        if data is None:
            return
        raw = data.get("content_base64")
        if not isinstance(raw, str) or not raw:
            self._send_json({"error": "A workbook or snapshot payload is required."}, 400, extra_headers=_NO_STORE)
            return
        if len(raw) > 4 * ((MAX_UPLOAD_BYTES + 2) // 3):
            self._send_json({"error": "The upload exceeds the size limit."}, 413, extra_headers=_NO_STORE)
            return
        try:
            content = base64.b64decode(raw, validate=True)
        except (ValueError, TypeError):
            self._send_json({"error": "The upload payload is invalid."}, 400, extra_headers=_NO_STORE)
            return
        if len(content) > MAX_UPLOAD_BYTES:
            self._send_json({"error": "The upload exceeds the size limit."}, 413, extra_headers=_NO_STORE)
            return
        from vcf_hci.plugins.vinv.xlsx_io import parse_vinv_xlsx, snapshot_from_json
        filename = str(data.get("filename") or "upload")[:120]
        try:
            if content[:2] == b"PK":
                snapshot = parse_vinv_xlsx(content)
                source = "vinv-xlsx"
            else:
                if len(content) > MAX_RESULT_BYTES:
                    raise ValueError("snapshot exceeds the size limit")
                snapshot = snapshot_from_json(content.decode("utf-8"))
                source = "vinv-json"
        except (ValueError, KeyError, TypeError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
            from vcf_hci.plugins.vinv.sources.diagnostics import exception_summary
            logger.debug("vinv import rejected: bytes=%d kind=%s chain=%s", len(content),
                         "xlsx" if content[:2] == b"PK" else "json", exception_summary(exc))
            self._send_json({"error": "The file is not a readable vSphere inventory workbook: %s" % (str(exc)[:200] or "invalid"),
                             "error_code": "import_invalid", "stage": "import"}, 400, extra_headers=_NO_STORE)
            return
        except Exception as exc:
            failure = failure_payload(exc, "import")
            failure["error"] = "The file is not a readable vSphere inventory workbook."
            self._send_json(failure, 400, extra_headers=_NO_STORE)
            return
        _, library = server_state(self.server)
        try:
            entry = library.add(session, snapshot, source, filename)
        except ValueError as exc:
            logger.debug("vinv import not added to library: %s", type(exc).__name__)
            self._send_json({"error": str(exc), "error_code": "library_full", "stage": "library"}, 409, extra_headers=_NO_STORE)
            return
        logger.debug("vinv import added: source=%s hosts=%s vms=%s", source, entry.get("hosts"), entry.get("vms"))
        self._send_json({"entry": entry}, extra_headers=_NO_STORE)

    def _api_vinv_library_get(self, path: str) -> None:
        session = self._vinv_guard()
        if session is None:
            return
        _, library = server_state(self.server)
        clean = path.split("?", 1)[0]
        if clean in (_PREFIX + "/library", _LIB_PREFIX):
            self._send_json({"entries": library.list(session)}, extra_headers=_NO_STORE)
            return
        entry_id, suffix = _token_after(clean, _LIB_PREFIX)
        snapshot = library.get(session, entry_id) if entry_id else None
        if snapshot is None:
            self._send_json({"error": "Not found"}, 404, extra_headers=_NO_STORE)
            return
        self._vinv_send_snapshot(snapshot, suffix, self._vinv_obfuscated_query())

    def _api_vinv_library_post(self, path: str) -> None:
        session = self._vinv_guard()
        if session is None:
            return
        _, library = server_state(self.server)
        if path == _PREFIX + "/detach":
            library.detach()
            self._send_json({"entries": library.list(session)}, extra_headers=_NO_STORE)
            return
        entry_id, suffix = _token_after(path, _LIB_PREFIX)
        if suffix == "/attach":
            ok = library.attach(session, entry_id)
        elif suffix == "/delete":
            ok = library.remove(session, entry_id)
        else:
            ok = False
        if not ok:
            self._send_json({"error": "Not found"}, 404, extra_headers=_NO_STORE)
            return
        self._send_json({"entries": library.list(session)}, extra_headers=_NO_STORE)

    # ── Phase 2: reconciled reports ──────────────────────────────────────

    def _api_vinv_reconciled_fleet(self) -> None:
        """Combined fleet HTML for the current scan, enriched with the attached vSphere snapshot."""
        if self._vinv_guard() is None:
            return
        snapshot = attached_snapshot(self.server)
        if snapshot is None:
            self._send_json({"error": "vinv_not_attached"}, 409, extra_headers=_NO_STORE)
            return
        from vcf_hci.web.scan_worker import _state, _state_lock
        with _state_lock:
            results = list(_state.get("results", []))
        if not results:
            self._send_json({"error": "No scan results available"}, 400, extra_headers=_NO_STORE)
            return
        obfuscated = self._vinv_obfuscated_query()
        try:
            from vcf_hci.plugins.vinv.report_bridge import build_reconciled_fleet_html
            html = build_reconciled_fleet_html(results, snapshot, obfuscated, obfuscation_salt())
        except Exception as exc:
            failure = failure_payload(exc, "fleet report")
            failure["error"] = "The reconciled fleet report failed. Quote reference %s from the server log." % failure["reference"]
            self._send_json(failure, 500, extra_headers=_NO_STORE)
            return
        stem = ("00_OBFUSCATED_" if obfuscated else "") + "vinv_fleet_combined"
        self._vinv_bytes(html.encode("utf-8"), "text/html; charset=utf-8", stem + ".html")
