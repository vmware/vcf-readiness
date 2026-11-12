"""Read-only vCenter inventory/performance adapter; SDK loading is per operation."""
from __future__ import annotations

import importlib
import json
import ssl
import time
from dataclasses import asdict, replace
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlsplit

from vcf_hci.plugins.mtat import limits, vendor
from vcf_hci.plugins.mtat.assess import assess
from vcf_hci.plugins.mtat.constants import (
    AGGREGATE_INSTANCE,
    HISTORICAL_COUNTERS,
    VCENTER_FULL_PROPERTIES,
    VCENTER_LEGACY_PROPERTIES,
)
from vcf_hci.plugins.mtat.diagnostics import MtatError, connection_error
from vcf_hci.plugins.mtat.intervals import HistoricalInterval, entity_batches, select_interval, validate_window
from vcf_hci.plugins.mtat.lifecycle import experimental_enabled
from vcf_hci.plugins.mtat.models import Assessment, HostEvidence, SampleSeries, TierEntry, VmEvidence
from vcf_hci.plugins.mtat.sources.base import CollectionRequest, PreflightReport, ProgressSink
from vcf_hci.plugins.mtat.tls import PinnedContext

_HOST_QUICK_PROPERTIES = ("summary.quickStats.overallCpuUsage",)
_VM_PROPERTIES = (
    "name", "runtime.host", "runtime.powerState", "runtime.faultToleranceState",
    "config.hardware.memoryMB", "config.hardware.device", "config.memoryAllocation",
    "config.memoryReservationLockedToMax", "config.latencySensitivity", "config.extraConfig",
    "summary.quickStats.guestMemoryUsage",
)
_OPTIONAL_MISSING_PROPERTIES = {
    "hardware.memoryTieringType",
    "hardware.memoryTierInfo",
    "config.product.version",
    "summary.quickStats.overallCpuUsage",
    "summary.quickStats.guestMemoryUsage",
    "summary.hardware.cpuMhz",
    "summary.hardware.numCpuCores",
}
_TIER_OBSERVATION_MAP = {
    "softwaretiering": "Enabled",
    "enabled": "Enabled",
    "notiering": "Disabled",
    "disabled": "Disabled",
}


def _connection_target(value: str) -> tuple[str, int]:
    """Accept a pasted vSphere Client URL, connecting only to its HTTPS authority."""
    value = value.strip()
    try:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError
        endpoint = urlsplit(value if "://" in value else "https://" + value)
        host, port = endpoint.hostname, endpoint.port
        if (endpoint.scheme != "https" or not host or endpoint.username is not None
                or endpoint.password is not None or any(c.isspace() or c == "\\" for c in host)
                or port == 0):
            raise ValueError
    except ValueError:
        raise ValueError("vCenter endpoint must be an HTTPS host or URL without embedded credentials and with a valid port") from None
    return host, port if port is not None else 443


def _key(obj: Any) -> str:
    return str(obj._moId)


def _option(options: Any, key: str) -> Optional[str]:
    return next((str(item.value) for item in options or () if item.key == key), None)


def _host_nvme_pct_fallback(host: dict) -> Optional[int]:
    direct = host.get("Mem.TierNVMePct")
    if direct is not None:
        try:
            val = int(direct)
            return val if val >= 0 else None
        except (TypeError, ValueError):
            return None
    obj = host.get("obj")
    try:
        adv = getattr(getattr(obj, "configManager", None), "advancedOption", None)
        query = getattr(adv, "QueryOptions", None)
    except Exception:
        return None
    if callable(query):
        try:
            options = query(name="Mem.TierNVMePct")
            if options and getattr(options[0], "value", None) is not None:
                val = int(options[0].value)
                return val if val >= 0 else None
        except Exception:
            return None
    return None


class VcenterAdapter:
    kind = "vcenter"

    def __init__(self, *, enabled: Optional[bool] = None,
                 windows: Optional[Mapping[str, tuple[str, int, int]]] = None,
                 cancelled: Callable[[], bool] = lambda: False,
                 sdk_loader: Callable[[], Any] = vendor.load_pyvmomi,
                 connect: Optional[Callable[..., Any]] = None,
                 disconnect: Optional[Callable[[Any], None]] = None) -> None:
        if (connect is None) != (disconnect is None):
            raise ValueError("connect and disconnect test hooks must be supplied together")
        self.enabled = enabled
        self.windows = dict(windows or {})  # range label -> interval key, UTC begin/end seconds
        self.cancelled = cancelled
        self._loader, self._connect, self._disconnect = sdk_loader, connect, disconnect
        self._session: Any = None
        self._content: Any = None
        self._sdk: Any = None
        self._deadline = 0.0
        self._samples = 0

    def _check(self) -> None:
        if self.cancelled():
            raise RuntimeError("MTAT collection cancelled")
        if time.monotonic() > self._deadline:
            raise RuntimeError("MTAT collection deadline exceeded")

    def _open(self, request: CollectionRequest) -> None:
        enabled = experimental_enabled() if self.enabled is None else self.enabled
        if not enabled or not request.acknowledged:
            raise PermissionError("Experimental enablement and per-run acknowledgement are required")
        if request.source_kind != self.kind:
            raise ValueError("incorrect source kind")
        host, port = _connection_target(request.endpoint)
        pinned_context = PinnedContext(request.certificate_pin) if request.certificate_pin else None
        self._deadline = time.monotonic() + limits.JOB_TIMEOUT_SECONDS
        self._samples = 0
        self._check()
        try:
            self._sdk = self._loader()
        except Exception:
            raise MtatError("sdk_unavailable", "The pinned vCenter SDK could not be loaded. Repair the VCF-R installation and its bundled pyVmomi wheel.", "sdk") from None
        if self._connect is None:
            connection = importlib.import_module("pyVim.connect")
            self._connect, self._disconnect = connection.SmartConnect, connection.Disconnect
        context = pinned_context if pinned_context is not None else (ssl.create_default_context(cafile=request.ca_file) if request.verify_tls else ssl._create_unverified_context())
        password = request.password.reveal()
        try:
            self._session = self._connect(host=host, port=port,
                                          user=request.username, pwd=password, sslContext=context,
                                          connectionPoolTimeout=limits.CONNECT_TIMEOUT_SECONDS,
                                          httpConnectionTimeout=min(limits.CONNECT_TIMEOUT_SECONDS, limits.READ_TIMEOUT_SECONDS))
        except Exception as exc:
            raise connection_error(exc) from None
        finally:
            password = ""
            request.password._value = ""  # Secret has no public clear API; never retain after handoff.
        self._content = self._read(self._session.RetrieveContent)

    def close(self) -> None:
        session, self._session = self._session, None
        self._content = None
        if session is not None and self._disconnect is not None:
            try:
                self._disconnect(session)
            except Exception:
                raise RuntimeError("vCenter session cleanup failed") from None

    def _read(self, operation: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        try:
            return operation(*args, **kwargs)
        except self._sdk.vmodl.fault.InvalidProperty:
            raise self._sdk.vmodl.fault.InvalidProperty() from None
        except Exception as exc:
            raise connection_error(exc, "inventory/performance query") from None

    def _properties(self, kind: Any, paths: tuple[str, ...], container: Any, maximum: int) -> list[dict]:
        pc = self._content.propertyCollector
        spec = self._sdk.vmodl.query.PropertyCollector
        view = self._read(self._content.viewManager.CreateContainerView, container, [kind], True)
        token = None
        rows: list[dict] = []
        identities = set()
        try:
            traversal = spec.TraversalSpec(name="inventory", type=self._sdk.vim.view.ContainerView, path="view", skip=False)
            selection = spec.ObjectSpec(obj=view, skip=True, selectSet=[traversal])
            filt = spec.FilterSpec(objectSet=[selection], propSet=[spec.PropertySpec(type=kind, pathSet=list(paths), all=False)])
            result = self._read(pc.RetrievePropertiesEx, specSet=[filt], options=spec.RetrieveOptions(maxObjects=min(250, maximum)))
            tokens = set()
            while result is not None:
                self._check()
                token = getattr(result, "token", None)
                for obj in result.objects or ():
                    if len(rows) >= maximum:
                        raise ValueError("inventory resource limit exceeded")
                    if _key(obj.obj) in identities:
                        raise ValueError("inventory pagination contains a duplicate identifier")
                    identities.add(_key(obj.obj))
                    row = {p.name: p.val for p in obj.propSet or ()}
                    missing = {str(item.path) for item in getattr(obj, "missingSet", ())}
                    row.update(obj=obj.obj, key=_key(obj.obj), error=bool(missing - _OPTIONAL_MISSING_PROPERTIES))
                    rows.append(row)
                if not token:
                    break
                if token in tokens or len(tokens) >= maximum:
                    raise ValueError("inventory pagination did not advance")
                tokens.add(token)
                result = self._read(pc.ContinueRetrievePropertiesEx, token=token)
            return rows
        finally:
            try:
                if token:
                    self._read(pc.CancelRetrievePropertiesEx, token=token)
            finally:
                self._read(view.Destroy)

    def _scope(self, request: CollectionRequest) -> tuple[Any, str]:
        clusters = self._properties(self._sdk.vim.ClusterComputeResource, ("name",), self._content.rootFolder, limits.MAX_HOSTS)
        matches = [r for r in clusters if r["key"] == request.cluster or r.get("name") == request.cluster]
        # A MoRef always disambiguates duplicate display names.
        exact = [r for r in matches if r["key"] == request.cluster]
        matches = exact or matches
        if len(matches) != 1:
            raise ValueError("select one unambiguous cluster identifier")
        return matches[0]["obj"], str(matches[0].get("name", request.cluster))

    def _intervals(self) -> tuple[HistoricalInterval, ...]:
        return tuple(HistoricalInterval(str(i.key), int(i.samplingPeriod), int(i.length), int(getattr(i, "level", 0) or 0), bool(i.enabled))
                     for i in self._read(lambda: self._content.perfManager.historicalInterval))

    def _window(self, request: CollectionRequest) -> tuple[str, int, Optional[datetime], Optional[datetime]]:
        if request.range_name.strip().lower() in {"realtime", "real-time", "real-time snapshot"} and request.range_name not in self.windows:
            return "realtime", 20, None, None
        if request.range_name not in self.windows:
            raise ValueError("historical collection requires an explicit named UTC window")
        key, begin, end = self.windows[request.range_name]
        now = int(datetime.now(timezone.utc).timestamp())
        intervals = self._intervals()
        if key == "auto":
            if end < begin or end > now:
                raise ValueError("invalid historical window")
            min_seconds = 300 if end - begin <= 86400 else 1800
            candidates = [i for i in intervals if i.enabled and i.level >= 2 and i.seconds >= min_seconds
                          and i.retention_seconds >= end - begin]
            if not candidates:
                raise ValueError("no retained historical interval of at least %d minutes is available" % (min_seconds // 60))
            interval = min(candidates, key=lambda i: i.seconds)
            if begin < now - interval.retention_seconds - interval.seconds:
                raise ValueError("historical window is outside retained history")
            # Trim only incomplete edge buckets. Retention is measured at query time.
            begin = max(begin, now - interval.retention_seconds)
            begin = ((begin + interval.seconds - 1) // interval.seconds) * interval.seconds
            end = (end // interval.seconds) * interval.seconds
            if end <= begin:
                raise ValueError("historical window has no complete sampling interval")
        else:
            interval = select_interval(intervals, key)
        validate_window(interval, begin, end)
        if begin < now - interval.retention_seconds or end > now:
            raise ValueError("historical window is outside retained history")
        return "historical", interval.seconds, datetime.fromtimestamp(begin, timezone.utc), datetime.fromtimestamp(end, timezone.utc)

    def preflight(self, request: CollectionRequest) -> PreflightReport:
        try:
            self._open(request)
            rows = self._properties(self._sdk.vim.ClusterComputeResource, ("name",), self._content.rootFolder, limits.MAX_HOSTS)
            clusters = tuple({"id": r["key"], "name": str(r.get("name") or r["key"])} for r in rows if not r["error"])
            messages = ("TLS identity verified using the reviewed SHA-256 certificate pin; CA-chain verification is replaced by pin verification.",) if request.certificate_pin else (() if request.verify_tls else ("TLS certificate verification disabled",))
            if request.cluster:
                self._scope(request)
            elif len(clusters) != 1:
                messages += ("Select a discovered cluster." if clusters else "No accessible clusters found.",)
            intervals = self._intervals()
            ready = bool(request.cluster or len(clusters) == 1)
            if ready:
                try:
                    mode, period, begin, end = self._window(request)
                except ValueError as exc:
                    ready = False
                    messages += ("Requested history is unavailable: " + str(exc),)
                else:
                    if mode == "historical" and begin is not None and end is not None:
                        messages += ("History window: %s to %s UTC; samples every %s seconds." %
                                     (begin.strftime("%Y-%m-%d %H:%M"), end.strftime("%Y-%m-%d %H:%M"), period),)
            capabilities = {"realtime": True}
            capabilities.update({str(i.key): i.enabled and i.level >= 2 for i in intervals})
            return PreflightReport(ready, str(self._content.about.version), request.verify_tls or bool(request.certificate_pin),
                                   capabilities, messages, clusters, intervals)
        finally:
            self.close()

    def _max_query_metrics(self) -> int:
        """Read vpxd.stats.maxQueryMetrics, using a conservative 64-metric fallback when settings are unavailable."""
        setting = getattr(self._content, "setting", None)
        query = getattr(setting, "QueryOptions", None)
        width = 64
        if callable(query):
            try:
                option = query(name="vpxd.stats.maxQueryMetrics")
                if option and getattr(option[0], "value", None) is not None:
                    parsed = int(option[0].value)
                    if parsed != 0:
                        width = parsed
            except Exception:
                width = 64
        if width == -1 or width > 256:
            width = 256  # Bound work even when the server declares unlimited metrics.
        return width

    def _metrics(self, entities: list[Any], period: int, begin: Optional[datetime], end: Optional[datetime]) -> dict:
        pm = self._content.perfManager
        counter_keys = {}
        for counter in self._read(lambda: pm.perfCounter):
            name = "%s.%s.%s" % (counter.groupInfo.key, counter.nameInfo.key, counter.rollupType)
            if name in HISTORICAL_COUNTERS:
                counter_keys[int(counter.key)] = name
        if not counter_keys:
            return {}
        width = self._max_query_metrics()
        if width < len(counter_keys):
            raise ValueError("server metric limit is below the required counter width")
        result: dict = {}
        for start, stop in entity_batches(len(entities), len(counter_keys), width):
            self._check()
            specs = [self._sdk.vim.PerformanceManager.QuerySpec(
                entity=entity, metricId=[self._sdk.vim.PerformanceManager.MetricId(counterId=k, instance=AGGREGATE_INSTANCE) for k in counter_keys],
                intervalId=period, startTime=begin, endTime=end, maxSample=limits.MAX_SAMPLES)
                     for entity in entities[start:stop]]
            for metric in self._read(pm.QueryPerf, querySpec=specs):
                if _key(metric.entity) not in {_key(entity) for entity in entities[start:stop]}:
                    raise ValueError("vCenter returned an unrequested performance entity")
                infos = metric.sampleInfo or ()
                if any(int(info.interval) != period for info in infos):
                    raise ValueError("returned performance interval does not match selection")
                values = result.setdefault(_key(metric.entity), {})
                for series in metric.value or ():
                    if series.id.instance != AGGREGATE_INSTANCE or series.id.counterId not in counter_keys:
                        continue
                    raw = tuple(series.value)
                    self._samples += len(raw)
                    if self._samples > limits.MAX_SAMPLES:
                        raise ValueError("performance sample limit exceeded")
                    if len(raw) != len(infos):
                        raise ValueError("performance sample metadata is incomplete")
                    if any(value < 0 for value in raw):
                        continue  # -1 is unavailable, never a passing zero.
                    name = counter_keys[series.id.counterId]
                    values[name] = SampleSeries(raw, "hundredths" if name.startswith("cpu.") else "kibibytes", name, period)
        return result

    def _vm(self, row: dict, host_names: dict) -> VmEvidence:
        host_key = _key(row["runtime.host"]) if row.get("runtime.host") is not None else ""
        host_name = host_names.get(host_key, host_key or "Unknown host")
        identity = VmEvidence(host_name, str(row.get("name", row["key"])), row["key"], host_key,
                              str(row.get("runtime.powerState", "poweredOn")))
        if row["error"]:
            return replace(identity, eligibility_assessed=False, collection_error="VM properties unavailable")
        options = row.get("config.extraConfig")
        assessed = all(k in row for k in ("config.extraConfig", "config.hardware.device", "config.memoryAllocation", "config.latencySensitivity", "runtime.faultToleranceState"))
        flags = []
        for device in (row.get("config.hardware.device") or ()):
            name = type(device).__name__.lower()
            backing = type(getattr(device, "backing", None)).__name__.lower()
            if "sriov" in name:
                flags.append("sriov")
            elif "pcipassthrough" in name:
                flags.append("vgpu" if "vgpu" in backing or "vmiop" in backing else "pci_passthrough")
            if "rdma" in name:
                flags.append("rdma")
        if any((_option(options, key) or "").lower() in {"true", "1"} for key in ("sched.mem.pin", "sched.mem.pinGuestMem")):
            flags.append("pinned_memory")
        if getattr(row.get("config.latencySensitivity"), "level", "") == "high":
            flags.append("latency_high")
        if str(row.get("runtime.faultToleranceState", "notConfigured")) not in ("notConfigured", "disabled"):
            flags.append("fault_tolerance")
        if (_option(options, "sched.mem.enableTiering") or "").lower() == "false":
            flags.append("tiering_disabled")
        active = row.get("summary.quickStats.guestMemoryUsage")
        active_mb = int(active) if active is not None and int(active) >= 0 else None
        memory = row.get("config.hardware.memoryMB")
        memory_mb = int(memory) if memory is not None and int(memory) > 0 else None
        return replace(identity, provisioned_bytes=memory_mb * 1024 * 1024 if memory_mb is not None else None,
                          active=SampleSeries((active_mb * 1024 * 1024,), "bytes", "summary.quickStats.guestMemoryUsage") if active_mb is not None else None,
                          eligibility_flags=tuple(flags), eligibility_assessed=assessed,
                          pages_1gb=(_option(options, "sched.mem.lpage.enable1GPage") or "False") if assessed else "Unknown",
                          pages_2mb=(_option(options, "sched.mem.lpage.enable") or "True (Default)") if assessed else "Unknown")

    def collect(self, request: CollectionRequest, progress: ProgressSink) -> Assessment:
        try:
            self._open(request)
            scope, cluster_name = self._scope(request)
            mode, period, begin, end = self._window(request)
            supported = True
            try:
                hosts = self._properties(self._sdk.vim.HostSystem, VCENTER_FULL_PROPERTIES + _HOST_QUICK_PROPERTIES, scope, limits.MAX_HOSTS)
            except self._sdk.vmodl.fault.InvalidProperty:
                supported = False
                hosts = self._properties(self._sdk.vim.HostSystem, VCENTER_LEGACY_PROPERTIES + _HOST_QUICK_PROPERTIES, scope, limits.MAX_HOSTS)
            raw_vms = self._properties(self._sdk.vim.VirtualMachine, _VM_PROPERTIES, scope, limits.MAX_VMS)
            names = {h["key"]: str(h.get("name", h["key"])) for h in hosts}
            vms = [self._vm(v, names) for v in raw_vms if str(v.get("runtime.powerState", "poweredOn")) == "poweredOn"]
            live_hosts = [
                h["obj"] for h in hosts
                if not h["error"] and str(h.get("runtime.connectionState", "connected")).lower() not in {"disconnected", "notresponding"}
            ]
            live_keys = {_key(h) for h in live_hosts}
            entities = live_hosts + ([v["obj"] for v in raw_vms if not v["error"] and v.get("runtime.host") is not None and _key(v["runtime.host"]) in live_keys and str(v.get("runtime.powerState")) == "poweredOn"] if mode == "historical" else [])
            metrics = self._metrics(entities, period, begin, end)
            if mode == "historical":
                vms = [replace(vm, active=metrics.get(vm.vm_key, {}).get("mem.active.average")) for vm in vms]
            evidence = []
            for index, host in enumerate(hosts):
                self._check()
                data = metrics.get(host["key"], {})
                entries = tuple(TierEntry("DRAM" if str(t.type).lower() == "dram" else "NVMe" if str(t.type).lower() == "nvme" else "other", int(t.size)) for t in (host.get("hardware.memoryTierInfo") or ()))
                raw_tier_type = str(host.get("hardware.memoryTieringType") or "").strip().lower()
                observation = _TIER_OBSERVATION_MAP.get(raw_tier_type)
                nvme_fallback = None
                if observation == "Enabled" and any(e.kind == "DRAM" for e in entries) and not any(e.kind == "NVMe" for e in entries):
                    nvme_fallback = _host_nvme_pct_fallback(host)
                active = data.get("mem.active.average")
                if mode == "realtime":
                    guest = [vm for vm in vms if vm.host_key == host["key"]]
                    active = SampleSeries((sum(vm.active.values[0] for vm in guest if vm.active),), "bytes", "powered-on VM guestMemoryUsage sum") if all(vm.active and not vm.collection_error for vm in guest) else None
                mhz, cores = host.get("summary.hardware.cpuMhz"), host.get("summary.hardware.numCpuCores")
                cpu = data.get("cpu.usage.average")
                quick_cpu = host.get("summary.quickStats.overallCpuUsage")
                if mode == "realtime" and cpu is None and quick_cpu is not None and int(quick_cpu) >= 0 and mhz and cores:
                    # Quick stats are MHz; convert once to percent, never raw counter hundredths.
                    values: list = [Decimal(int(quick_cpu)) * 100 / (int(mhz) * int(cores))]
                    cpu = SampleSeries(tuple(values), "percent", "summary.quickStats.overallCpuUsage / capacity")
                conn_state = str(host.get("runtime.connectionState", "unknown"))
                is_disconnected = conn_state.lower() in {"disconnected", "notresponding"} and "name" in host
                evidence.append(HostEvidence(cluster_name, names[host["key"]], host["key"], mode,
                    memory_size_bytes=host.get("hardware.memorySize"), tier_entries=entries,
                    tier_properties_supported=supported, tier_observation=observation,
                    nvme_pct_fallback=nvme_fallback,
                    cpu=cpu, consumed=data.get("mem.consumed.average"), active=active,
                    cpu_mhz=int(mhz) * int(cores) if mhz is not None and cores is not None else None,
                    connection_state=conn_state,
                    collection_error="Host properties unavailable" if (host["error"] and not is_disconnected) else ""))
                progress.update("hosts", index + 1, len(hosts), "Collecting host evidence")
            result = assess(request.range_name, self.kind, "vCenter", str(self._content.about.version), tuple(evidence), tuple(vms), request.policy, request.verify_tls or bool(request.certificate_pin), request.acknowledged)
            if request.certificate_pin:
                result = replace(result, warnings=("TLS identity verified using a reviewed SHA-256 certificate pin; CA-chain verification replaced by pin verification.",))
            if not request.verify_tls and not request.certificate_pin:
                result = replace(result, warnings=("TLS certificate verification disabled",))
            if len(json.dumps(asdict(result), default=str).encode()) > limits.MAX_RESULT_BYTES:
                raise ValueError("assessment result byte limit exceeded")
            self._check()
            return result
        finally:
            self.close()
