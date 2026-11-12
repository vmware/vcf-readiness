"""Bounded, read-only Operations REST collection with per-operation token lifetime."""
from __future__ import annotations

import http.client
import json
import ssl
import time
from dataclasses import asdict, replace
from decimal import Decimal, InvalidOperation
from functools import partial
from typing import Any, Callable, Mapping, Optional
from urllib.parse import quote, urlencode, urlsplit

from vcf_hci.plugins.mtat import limits
from vcf_hci.plugins.mtat.assess import assess
from vcf_hci.plugins.mtat.lifecycle import experimental_enabled
from vcf_hci.plugins.mtat.models import Assessment, HostEvidence, Provenance, SampleSeries
from vcf_hci.plugins.mtat.operations_columns import map_headers
from vcf_hci.plugins.mtat.sources.base import CollectionRequest, PreflightReport, ProgressSink

_PREFIX = "/suite-api/api"
_ALLOWED_PATHS = {"", "/ui", "/suite-api", "/suite-api/api"}


class OperationsHttpError(RuntimeError):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__("Operations HTTP request failed (%d)" % status)


class _Transport:
    """No redirects/cookies, and a separately bounded connect/read lifecycle."""
    def __init__(self, host: str, port: int) -> None:
        self.host, self.port = host, port

    def request(self, method: str, path: str, body: Optional[bytes], headers: dict,
                context: ssl.SSLContext, max_bytes: int) -> bytes:
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=limits.CONNECT_TIMEOUT_SECONDS, context=context)
        try:
            connection.connect()
            if connection.sock is not None:
                connection.sock.settimeout(limits.READ_TIMEOUT_SECONDS)
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise OperationsHttpError(response.status)
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError("Operations response byte limit exceeded")
            return data
        finally:
            connection.close()


def _series(values: list, source_key: str, unit: str = "KiB", cpu: bool = False) -> Optional[SampleSeries]:
    """Retain Decimal samples exactly; numeric JSON values may be fractional."""
    if any(value is None for value in values):
        return None
    try:
        values = [Decimal(str(value)) for value in values]
    except (InvalidOperation, ValueError):
        raise ValueError("Operations metric is not numeric") from None
    if not values or any(not value.is_finite() or value < 0 for value in values):
        return None
    if any(value.adjusted() > 18 for value in values):
        raise ValueError("Operations metric magnitude limit exceeded")
    if cpu:
        return SampleSeries(tuple(values), "percent", source_key)
    factors = {"B": 1, "BYTE": 1, "BYTES": 1, "KB": 1024, "KIB": 1024, "MB": 1024 ** 2,
               "MIB": 1024 ** 2, "GB": 1000 ** 3, "GIB": 1024 ** 3, "TB": 1000 ** 4, "TIB": 1024 ** 4}
    factor = factors.get(unit.upper())
    if factor is None:
        raise ValueError("unsupported Operations memory unit")
    return SampleSeries(tuple(int(value * factor) for value in values), "bytes", source_key)


def _metric(mapping: dict, values: dict, details: dict, alias: str, cpu: bool = False) -> Optional[SampleSeries]:
    source = mapping.get(alias)
    if not source:
        return None
    raw_unit = details.get(source, {}).get("unit")
    unit = str(raw_unit).strip() if raw_unit is not None and str(raw_unit).strip() else "KiB"
    return _series(values.get(source, []), source, unit, cpu)


class OperationsRestAdapter:
    kind = "operations-rest"

    def __init__(self, *, enabled: Optional[bool] = None, transport: Any = None,
                 windows: Optional[Mapping[str, tuple[int, int]]] = None,
                 cancelled: Callable[[], bool] = lambda: False) -> None:
        self.enabled, self.cancelled = enabled, cancelled
        self.windows = dict(windows or {})  # UTC epoch milliseconds
        self._transport = transport
        self._injected = transport is not None
        self._token = ""
        self._context = ssl.create_default_context()
        self._deadline = 0.0
        self._response_bytes = 0
        self._samples = 0

    def _check(self) -> None:
        if self.cancelled():
            raise RuntimeError("MTAT collection cancelled")
        if time.monotonic() > self._deadline:
            raise RuntimeError("MTAT collection deadline exceeded")

    def _request(self, method: str, path: str, payload: Optional[dict] = None, *, cleanup: bool = False) -> dict:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = "OpsToken " + self._token
        body = json.dumps(payload).encode() if payload is not None else None
        # Token acquisition is never retried: an unreceived response may have created a session.
        attempts = 1 if path.endswith("/token/acquire") or cleanup else 3
        for attempt in range(attempts):
            if not cleanup:
                self._check()
            try:
                data = self._transport.request(method, _PREFIX + path, body, headers, self._context, limits.MAX_RESULT_BYTES)
                if len(data) > limits.MAX_RESULT_BYTES:
                    raise ValueError("Operations response byte limit exceeded")
                self._response_bytes += len(data)
                if not cleanup and self._response_bytes > limits.MAX_RESULT_BYTES:
                    raise ValueError("Operations total response byte limit exceeded")
                if not data:
                    return {}
                try:
                    result = json.loads(data)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    raise ValueError("Operations response is not JSON") from None
                if not isinstance(result, dict):
                    raise ValueError("Operations response must be an object")
                return result
            except OperationsHttpError as exc:
                if exc.status not in {429, 502, 503, 504} or attempt + 1 == attempts:
                    raise
                time.sleep(0.1 * (attempt + 1))
            except (OSError, http.client.HTTPException):
                raise RuntimeError("Operations transport failed") from None
        raise RuntimeError("Operations retry limit exceeded")

    def _open(self, request: CollectionRequest) -> None:
        enabled = experimental_enabled() if self.enabled is None else self.enabled
        if not enabled or not request.acknowledged:
            raise PermissionError("Experimental enablement and per-run acknowledgement are required")
        if request.source_kind != self.kind:
            raise ValueError("incorrect source kind")
        endpoint = urlsplit(request.endpoint if "://" in request.endpoint else "https://" + request.endpoint)
        norm_path = endpoint.path.rstrip("/")
        if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password or norm_path not in _ALLOWED_PATHS or endpoint.query or endpoint.fragment:
            raise ValueError("Operations endpoint must be an HTTPS host without credentials")
        self._deadline = time.monotonic() + limits.JOB_TIMEOUT_SECONDS
        self._response_bytes = self._samples = 0
        self._context = ssl.create_default_context(cafile=request.ca_file) if request.verify_tls else ssl._create_unverified_context()
        if not self._injected:
            self._transport = _Transport(endpoint.hostname, endpoint.port or 443)
        self._check()
        payload = {"username": request.username, "password": request.password.reveal()}
        if request.auth_source:
            payload["authSource"] = request.auth_source
        try:
            response = self._request("POST", "/auth/token/acquire", payload)
            token = response.get("token")
            if not isinstance(token, str) or not token or any(c in token for c in "\r\n"):
                raise RuntimeError("Operations token response is invalid")
            self._token = token
        finally:
            payload.clear()
            request.password._value = ""

    def close(self) -> None:
        try:
            if self._token:
                self._request("POST", "/auth/token/release", cleanup=True)
        finally:
            self._token = ""

    def _pages(self, path: str, params: dict, maximum: int) -> list[dict]:
        rows: list[dict] = []
        seen = set()
        for page in range(maximum + 1):
            self._check()
            data = self._request("GET", path + "?" + urlencode(dict(params, page=page, pageSize=limits.MAX_OPS_PAGE_SIZE)))
            entries = data.get("resourceList", [])
            if not isinstance(entries, list) or len(entries) > limits.MAX_OPS_PAGE_SIZE:
                raise ValueError("Operations page size limit exceeded")
            for row in entries:
                key = row.get("identifier")
                if not key or key in seen:
                    raise ValueError("Operations pagination contains duplicate resource identifiers")
                seen.add(key)
                rows.append(row)
                if len(rows) > maximum:
                    raise ValueError("Operations resource limit exceeded")
            total = data.get("pageInfo", {}).get("totalCount")
            if total is not None and len(rows) >= int(total):
                break
            if not entries and total is not None and len(rows) < int(total):
                raise ValueError("Operations resource discovery is incomplete")
            if not entries or (total is None and len(entries) < limits.MAX_OPS_PAGE_SIZE):
                break
        else:
            raise ValueError("Operations page limit exceeded")
        return rows

    def _inventory(self, request: CollectionRequest) -> tuple[list[dict], dict[str, str], str]:
        clusters = self._pages("/resources", {"adapterKind": "VMWARE", "resourceKind": "ClusterComputeResource"}, limits.MAX_HOSTS)
        names = {r["identifier"]: str(r.get("resourceKey", {}).get("name", r["identifier"])) for r in clusters}
        selected = ""
        if request.cluster:
            candidates = [key for key, name in names.items() if key == request.cluster or name == request.cluster]
            if request.cluster in names:
                candidates = [request.cluster]
            if len(candidates) != 1:
                raise ValueError("select one unambiguous Operations cluster identifier")
            selected = candidates[0]
        params = {"adapterKind": "VMWARE", "resourceKind": "HostSystem"}
        if selected:
            params["parentId"] = selected
        hosts = self._pages("/resources", params, limits.MAX_HOSTS)
        parents = {}
        for host in hosts:
            relationships = self._pages("/resources/" + quote(host["identifier"], safe="") + "/relationships", {"relationshipType": "PARENT"}, limits.MAX_HOSTS)
            keys = {r["identifier"] for r in relationships if r["identifier"] in names}
            if selected and selected not in keys:
                raise ValueError("host does not belong to the selected cluster")
            parents[host["identifier"]] = names[selected] if selected else names[next(iter(keys))] if len(keys) == 1 else "(no cluster)"
        return hosts, parents, selected

    def _window(self, request: CollectionRequest) -> dict:
        if request.range_name == "realtime":
            return {"latestMaxSamples": 1}
        if request.range_name not in self.windows:
            raise ValueError("Operations collection requires an explicit named UTC window")
        begin, end = self.windows[request.range_name]
        if begin < 0 or begin > end or end > int(time.time() * 1000):
            raise ValueError("invalid Operations UTC window")
        return {"begin": begin, "end": end}

    def preflight(self, request: CollectionRequest) -> PreflightReport:
        try:
            self._open(request)
            self._window(request)
            self._inventory(request)
            return PreflightReport(True, "Unknown", request.verify_tls, {"host_metrics": True, "vm_eligibility": False},
                                   () if request.verify_tls else ("TLS certificate verification disabled",))
        finally:
            self.close()

    def collect(self, request: CollectionRequest, progress: ProgressSink) -> Assessment:
        try:
            self._open(request)
            window = self._window(request)
            hosts, parents, _selected = self._inventory(request)
            host_rows = []
            for start in range(0, len(hosts), limits.MAX_OPS_RESOURCE_IDS):
                self._check()
                batch = hosts[start:start + limits.MAX_OPS_RESOURCE_IDS]
                available: dict[str, dict] = {}
                for host in batch:
                    data = self._request("GET", "/resources/statkeys?" + urlencode({"resourceId": host["identifier"]}))
                    available[host["identifier"]] = {str(k["key"]): k for k in data.get("stat-key", [])}
                mappings = {key: map_headers(tuple(keys)) for key, keys in available.items()}
                keys = sorted({mapping[k] for mapping in mappings.values() for k in ("cpu", "active", "consumed", "alloc", "prov", "cap", "mhz") if k in mapping})
                stats: dict = {}
                for offset in range(0, len(keys), limits.MAX_OPS_STAT_KEYS):
                    payload = {"resourceId": [h["identifier"] for h in batch], "statKey": keys[offset:offset + limits.MAX_OPS_STAT_KEYS]}
                    payload.update(window)
                    response = self._request("POST", "/resources/stats/query", payload)
                    for resource in response.get("values", []):
                        identifier = resource.get("resourceId")
                        if identifier not in available:
                            raise ValueError("Operations returned an unrequested resource")
                        target = stats.setdefault(identifier, {})
                        for stat in resource.get("stat-list", {}).get("stat", []):
                            key = stat.get("statKey", {}).get("key")
                            if key not in payload["statKey"]:
                                raise ValueError("Operations returned an unrequested stat key")
                            values = stat.get("data", [])
                            self._samples += len(values)
                            if self._samples > limits.MAX_SAMPLES:
                                raise ValueError("Operations sample limit exceeded")
                            target[key] = values
                for host in batch:
                    key = host["identifier"]
                    mapping, values = mappings[key], stats.get(key, {})
                    metric = partial(_metric, mapping, values, available[key])
                    physical = metric("prov") or metric("cap")
                    consumed = metric("consumed")
                    proxy = consumed is None
                    if proxy:
                        consumed = metric("alloc")
                    mhz = metric("mhz", True)
                    result = assess(request.range_name, self.kind, "Operations REST", "Unknown", (
                        HostEvidence(parents[key], str(host.get("resourceKey", {}).get("name", key)), key, "historical",
                                     memory_size_bytes=max(physical.values) if physical else None, tier_properties_supported=False,
                                     cpu=metric("cpu", True), active=metric("active"), consumed=consumed,
                                     cpu_mhz=int(max(mhz.values)) if mhz else None),), (), request.policy,
                                     request.verify_tls, request.acknowledged)
                    row = result.hosts[0]
                    provenance = list(row.provenance)
                    for label, series in (("Consumed", consumed), ("Active", metric("active")), ("Physical_RAM", physical)):
                        if series:
                            provenance.append(Provenance(label, series.source_key, series.encoding, "proxy" if label == "Consumed" and proxy else "measured"))
                    host_rows.append(replace(row, provenance=tuple(provenance)))
                progress.update("hosts", min(start + len(batch), len(hosts)), len(hosts), "Collecting Operations host evidence")
            result = Assessment(request.range_name, self.kind, "Operations REST", "Unknown", request.policy, tuple(host_rows), (), (),
                                () if request.verify_tls else ("TLS certificate verification disabled",), request.verify_tls, acknowledged=request.acknowledged)
            if len(json.dumps(asdict(result), default=str).encode()) > limits.MAX_RESULT_BYTES:
                raise ValueError("assessment result byte limit exceeded")
            self._check()
            return result
        finally:
            self.close()
