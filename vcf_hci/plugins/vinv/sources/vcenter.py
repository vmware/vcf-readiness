"""Read-only vCenter inventory adapter for the vSphere inventory workbook.

pyVmomi is loaded per operation through the pinned MTAT vendor loader and only after
the Experimental gate and per-run acknowledgement have been checked.
"""

from __future__ import annotations

import importlib
import logging
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from vcf_hci.plugins.mtat import vendor
from vcf_hci.plugins.mtat.tls import PinnedContext
from vcf_hci.plugins.vinv import limits
from vcf_hci.plugins.vinv.constants import (
    CLUSTER_PROPERTIES,
    COMPUTE_PROPERTIES,
    DATACENTER_PROPERTIES,
    DATASTORE_PROPERTIES,
    DVPG_PROPERTIES,
    DVS_PROPERTIES,
    FOLDER_PROPERTIES,
    HOST_PARITY_PROPERTIES,
    HOST_PROPERTIES,
    OPTIONAL_FILEINFO_TAB,
    RP_PROPERTIES,
    STORAGE_POD_PROPERTIES,
    VM_PARITY_PROPERTIES,
    VM_PROPERTIES,
)
from vcf_hci.plugins.vinv.lifecycle import experimental_enabled
from vcf_hci.plugins.vinv.models import ProgressSink, VinvPreflight, VinvRequest, VinvSnapshot
from vcf_hci.plugins.vinv.schema import assemble_snapshot_from_tab_dicts
from vcf_hci.plugins.vinv.sources import vcenter_rows as rows
from vcf_hci.plugins.vinv.sources.diagnostics import (
    VinvError,
    VinvRejected,
    connection_error,
    exception_summary,
    pin_label,
    unexpected_error,
)
from vcf_hci.plugins.vinv.xlsx_io import snapshot_to_json

logger = logging.getLogger("vcf_assess.vinv.vcenter")

_OPTIONAL_HOST_PATHS = (
    "hardware.memoryTieringType",
    "hardware.memoryTierInfo",
    "config.virtualNicManagerInfo.netConfig",
)
_TLS_WARNING = "TLS certificate verification disabled"
_PIN_NOTE = ("TLS identity verified using the reviewed SHA-256 certificate pin; "
             "CA-chain verification is replaced by pin verification.")


def connection_target(value: str) -> Tuple[str, int]:
    """Accept a host or pasted vSphere Client URL; only its HTTPS authority is used."""
    value = str(value or "").strip()
    try:
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError
        endpoint = urlsplit(value if "://" in value else "https://" + value)
        host, port = endpoint.hostname, endpoint.port
        if (endpoint.scheme != "https" or not host or endpoint.username is not None
                or endpoint.password is not None or any(c.isspace() or c == "\\" for c in host)
                or port == 0):
            raise ValueError
    except ValueError:
        raise VinvRejected("endpoint_invalid", "input") from None
    return host, port if port is not None else 443


def _tls_messages(request: VinvRequest) -> Tuple[str, ...]:
    if request.certificate_pin:
        return (_PIN_NOTE,)
    return () if request.verify_tls else (_TLS_WARNING,)


def _tls_mode(request: VinvRequest) -> str:
    if request.certificate_pin:
        return "pinned " + pin_label(request.certificate_pin)
    if not request.verify_tls:
        return "unverified"
    return "ca-file" if request.ca_file else "system-ca"


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


class _NullProgress:
    def update(self, stage: str, completed: int, total: int, message: str) -> None:
        return None


class VinvVcenterAdapter:
    kind = "vcenter"

    def __init__(
        self,
        *,
        enabled: Optional[bool] = None,
        cancelled: Callable[[], bool] = lambda: False,
        sdk_loader: Callable[[], Any] = vendor.load_pyvmomi,
        connect: Optional[Callable[..., Any]] = None,
        disconnect: Optional[Callable[[Any], None]] = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if (connect is None) != (disconnect is None):
            raise ValueError("connect and disconnect test hooks must be supplied together")
        self.enabled = enabled
        self.cancelled = cancelled
        self._loader, self._connect, self._disconnect = sdk_loader, connect, disconnect
        self._sleep = sleep
        self._clock = clock
        self._session: Any = None
        self._content: Any = None
        self._sdk: Any = None
        self._deadline = 0.0
        self._endpoint_host = ""

    # ── Session ──────────────────────────────────────────────────────────

    def _check(self) -> None:
        if self.cancelled():
            raise VinvError("cancelled", "collection")
        if time.monotonic() > self._deadline:
            raise VinvError("deadline_exceeded", "collection")

    def _open(self, request: VinvRequest) -> None:
        enabled = experimental_enabled() if self.enabled is None else self.enabled
        if not enabled or not request.acknowledged:
            raise PermissionError("Experimental enablement and per-run acknowledgement are required")
        host, port = connection_target(request.endpoint)
        try:
            pinned = PinnedContext(request.certificate_pin) if request.certificate_pin else None
        except ValueError:
            raise VinvRejected("certificate_pin_invalid", "input") from None
        self._endpoint_host = host
        self._deadline = time.monotonic() + limits.JOB_TIMEOUT_SECONDS
        logger.debug("vinv connect requested: host=%s port=%d tls=%s scope=%s file_info=%s",
                     host, port, _tls_mode(request), request.cluster or "all", request.include_file_info)
        self._check()
        started = time.monotonic()
        try:
            self._sdk = self._loader()
        except Exception as exc:
            logger.warning("vinv SDK load failed: %s", exception_summary(exc))
            raise VinvError("sdk_unavailable", "sdk") from None
        logger.debug("vinv SDK loaded in %d ms", _elapsed_ms(started))
        if self._connect is None:
            connection = importlib.import_module("pyVim.connect")
            self._connect, self._disconnect = connection.SmartConnect, connection.Disconnect
        if pinned is not None:
            context: ssl.SSLContext = pinned
        else:
            context = ssl.create_default_context(cafile=request.ca_file) if request.verify_tls else ssl._create_unverified_context()
        password = request.password.reveal()
        started = time.monotonic()
        try:
            self._session = self._connect(
                host=host,
                port=port,
                user=request.username,
                pwd=password,
                sslContext=context,
                connectionPoolTimeout=limits.CONNECT_TIMEOUT_SECONDS,
                httpConnectionTimeout=min(limits.CONNECT_TIMEOUT_SECONDS, limits.READ_TIMEOUT_SECONDS),
            )
        except Exception as exc:
            error = connection_error(exc)
            logger.debug("vinv connect failed after %d ms: code=%s", _elapsed_ms(started), error.code)
            raise error from None
        finally:
            password = ""
            request.password.clear()
        logger.debug("vinv connected in %d ms", _elapsed_ms(started))
        self._content = self._read(self._session.RetrieveContent)

    def close(self) -> None:
        session, self._session = self._session, None
        self._content = None
        if session is not None and self._disconnect is not None:
            try:
                self._disconnect(session)
            except Exception as exc:
                logger.warning("vinv session cleanup failed: %s", exception_summary(exc))
                raise VinvError("session_cleanup", "cleanup") from None
            logger.debug("vinv session closed")

    def _finish(self, succeeded: bool) -> None:
        """Close the session without letting a cleanup failure hide the original error."""
        try:
            self.close()
        except VinvError:
            if succeeded:
                raise

    def _read(self, operation: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        try:
            return operation(*args, **kwargs)
        except self._sdk.vmodl.query.InvalidProperty:
            raise self._sdk.vmodl.query.InvalidProperty() from None
        except VinvError:
            raise
        except Exception as exc:
            raise connection_error(exc, "inventory query") from None

    def _cleanup_read(self, operation: Callable[..., Any], **kwargs: Any) -> None:
        try:
            self._read(operation, **kwargs)
        except Exception as exc:
            logger.debug("vinv property collector cleanup failed: %s", exception_summary(exc))

    def _properties(self, kind: Any, paths: Sequence[str], container: Any, maximum: int) -> List[Dict[str, Any]]:
        pc = self._content.propertyCollector
        spec = self._sdk.vmodl.query.PropertyCollector
        kind_name = getattr(kind, "__name__", str(kind))
        started = time.monotonic()
        view = self._read(self._content.viewManager.CreateContainerView, container, [kind], True)
        token = None
        out: List[Dict[str, Any]] = []
        identities = set()
        pages = 0
        try:
            traversal = spec.TraversalSpec(name="inventory", type=self._sdk.vim.view.ContainerView, path="view", skip=False)
            selection = spec.ObjectSpec(obj=view, skip=True, selectSet=[traversal])
            filt = spec.FilterSpec(objectSet=[selection], propSet=[spec.PropertySpec(type=kind, pathSet=list(paths), all=False)])
            result = self._read(pc.RetrievePropertiesEx, specSet=[filt], options=spec.RetrieveOptions(maxObjects=min(250, maximum)))
            tokens = set()
            while result is not None:
                self._check()
                pages += 1
                token = getattr(result, "token", None)
                for obj in result.objects or ():
                    key = rows.moid(obj.obj)
                    if len(out) >= maximum:
                        logger.warning("vinv resource limit reached: kind=%s limit=%d", kind_name, maximum)
                        raise VinvRejected("resource_limit", "inventory query")
                    if key in identities:
                        logger.warning("vinv duplicate identifier in pages: kind=%s page=%d", kind_name, pages)
                        raise VinvRejected("pagination", "inventory query")
                    identities.add(key)
                    if hasattr(self, "_missing_fields"):
                        self._missing_fields.update(str(m.path) for m in getattr(obj, "missingSet", ()) or ())
                    row: Dict[str, Any] = {p.name: p.val for p in obj.propSet or ()}
                    row.update(obj=obj.obj, key=key, kind=rows.kind(obj.obj))
                    out.append(row)
                if not token:
                    break
                if token in tokens or len(tokens) >= maximum:
                    logger.warning("vinv pagination did not advance: kind=%s page=%d", kind_name, pages)
                    raise VinvRejected("pagination", "inventory query")
                tokens.add(token)
                result = self._read(pc.ContinueRetrievePropertiesEx, token=token)
            token = None
            logger.debug("vinv read %s: objects=%d pages=%d paths=%d in %d ms",
                         kind_name, len(out), pages, len(paths), _elapsed_ms(started))
            return out
        except self._sdk.vmodl.query.InvalidProperty:
            logger.debug("vinv %s rejected a requested property path; caller may retry with fewer paths", kind_name)
            raise
        except VinvError as exc:
            logger.debug("vinv read %s failed: code=%s pages=%d objects=%d", kind_name, exc.code, pages, len(out))
            raise
        finally:
            if token:
                self._cleanup_read(pc.CancelRetrievePropertiesEx, token=token)
            self._cleanup_read(view.Destroy)

    def _supplement(self, objects: List[Dict[str, Any]], kind: Any, paths: Sequence[str],
                    scope: Any, maximum: int, warnings: List[str]) -> None:
        """Fetch optional additions without sacrificing the base inventory on old APIs."""
        if not objects:
            return
        try:
            additions = self._properties(kind, paths, scope, maximum)
        except self._sdk.vmodl.query.InvalidProperty:
            additions = []
            for path in paths:
                self._check()
                try:
                    additions.extend(self._properties(kind, (path,), scope, maximum))
                except self._sdk.vmodl.query.InvalidProperty:
                    warnings.append("Optional inventory property unavailable: " + path)
                except VinvError as exc:
                    if exc.code != "permission":
                        raise
                    warnings.append("Optional inventory property denied: " + path)
        except VinvError as exc:
            if exc.code != "permission":
                raise
            warnings.append("Optional inventory property group denied: " + ", ".join(paths))
            return
        by_key = {r["key"]: r for r in objects}
        for row in additions:
            if row["key"] in by_key:
                by_key[row["key"]].update(row)

    def _scope(self, request: VinvRequest, clusters: Sequence[Mapping[str, Any]]) -> Tuple[Any, str]:
        if not request.cluster:
            logger.debug("vinv scope: all clusters (%d visible)", len(clusters))
            return self._content.rootFolder, ""
        matches = [c for c in clusters if c["key"] == request.cluster or c.get("name") == request.cluster]
        exact = [c for c in matches if c["key"] == request.cluster]
        matches = exact or matches
        if len(matches) != 1:
            logger.debug("vinv scope rejected: requested cluster matched %d of %d clusters", len(matches), len(clusters))
            raise VinvRejected("cluster_not_found", "scope")
        logger.debug("vinv scope: cluster id=%s", matches[0]["key"])
        return matches[0]["obj"], str(matches[0].get("name", request.cluster))

    def _about(self) -> Any:
        return self._read(lambda: self._content.about)

    # ── Preflight ────────────────────────────────────────────────────────

    def _unexpected(self, exc: Exception, operation: str, stage: str) -> Exception:
        """Return the exception to raise for a failure that is not already classified."""
        if isinstance(exc, (VinvError, PermissionError)) or self.cancelled():
            return exc
        logger.warning("vinv %s failed at stage=%s: %s", operation, stage, exception_summary(exc))
        return unexpected_error(exc, stage)

    def preflight(self, request: VinvRequest) -> VinvPreflight:
        succeeded = False
        stage = "connecting"
        started = time.monotonic()
        try:
            self._open(request)
            vim = self._sdk.vim
            root = self._content.rootFolder
            stage = "counting inventory"
            clusters = self._properties(vim.ClusterComputeResource, ("name",), root, limits.MAX_CLUSTERS)
            scope, _ = self._scope(request, clusters)
            hosts = self._properties(vim.HostSystem, ("name",), scope, limits.MAX_HOSTS)
            vms = self._properties(vim.VirtualMachine, ("name",), scope, limits.MAX_VMS)
            datastores = self._properties(vim.Datastore, ("name",), root, limits.MAX_DATASTORES)
            about = self._about()
            logger.debug("vinv preflight ok in %d ms: version=%s build=%s clusters=%d hosts=%d vms=%d datastores=%d",
                         _elapsed_ms(started), rows.g(about, "version", ""), rows.g(about, "build", ""),
                         len(clusters), len(hosts), len(vms), len(datastores))
            succeeded = True
            return VinvPreflight(
                ok=True,
                server_version=str(rows.g(about, "version", "")),
                server_build=str(rows.g(about, "build", "")),
                server_uuid=str(rows.g(about, "instanceUuid", "")),
                verify_tls=request.verify_tls or bool(request.certificate_pin),
                clusters=tuple(sorted(
                    ({"id": c["key"], "name": str(c.get("name") or c["key"])} for c in clusters),
                    key=lambda c: (c["name"].lower(), c["id"]),
                )),
                host_count=len(hosts),
                vm_count=len(vms),
                datastore_count=len(datastores),
                messages=_tls_messages(request),
            )
        except Exception as exc:
            error = self._unexpected(exc, "preflight", stage)
            if error is exc:
                raise
            raise error from None
        finally:
            self._finish(succeeded)

    # ── Collection ───────────────────────────────────────────────────────

    def _hosts(self, scope: Any, warnings: List[str]) -> List[Dict[str, Any]]:
        vim = self._sdk.vim
        try:
            return self._properties(vim.HostSystem, HOST_PROPERTIES, scope, limits.MAX_HOSTS)
        except self._sdk.vmodl.query.InvalidProperty:
            warnings.append("Memory tiering and VMkernel service properties are not supported by this vCenter")
            legacy = tuple(p for p in HOST_PROPERTIES if p not in _OPTIONAL_HOST_PATHS)
            return self._properties(vim.HostSystem, legacy, scope, limits.MAX_HOSTS)

    def _network_hints(self, host: Mapping[str, Any]) -> Dict[str, Any]:
        system = host.get("configManager.networkSystem")
        if system is None:
            return {}
        hints = self._read(system.QueryNetworkHint)
        return {str(rows.g(h, "device", "")): h for h in hints or ()}

    def _file_info(self, datastores: Sequence[Mapping[str, Any]], inv: rows.Inventory, warnings: List[str]) -> List[Dict[str, str]]:
        browser_ns = self._sdk.vim.host.DatastoreBrowser
        flags = self._sdk.vim.host.DatastoreBrowser.FileInfo.Details(
            fileType=True, fileSize=True, modification=True, fileOwner=True
        )
        records: List[Dict[str, str]] = []
        for ds in datastores:
            self._check()
            if len(records) >= limits.MAX_FILEINFO_FILES:
                warnings.append("vFileInfo truncated at the file limit")
                break
            if not ds.get("summary.accessible", True):
                warnings.append("vFileInfo skipped an inaccessible datastore")
                continue
            name = inv.names.get(ds["key"], str(ds.get("name", ds["key"])))
            try:
                browser = self._read(lambda ds=ds: ds["obj"].browser)
                spec = browser_ns.SearchSpec(details=flags, sortFoldersFirst=True)
                task = self._read(browser.SearchDatastoreSubFolders_Task, datastorePath=f"[{name}]", searchSpec=spec)
                deadline = time.monotonic() + limits.READ_TIMEOUT_SECONDS
                state = str(self._read(lambda task=task: task.info.state))
                while state in ("queued", "running"):
                    self._check()
                    if time.monotonic() > deadline:
                        raise VinvError("timeout", "datastore browse")
                    self._sleep(0.5)
                    state = str(self._read(lambda task=task: task.info.state))
                if state != "success":
                    raise VinvError("vcenter_query", "datastore browse")
                result = self._read(lambda task=task: task.info.result)
                remaining = limits.MAX_FILEINFO_FILES - len(records)
                if sum(len(rows.g(r, "file") or ()) for r in result or ()) > remaining:
                    warnings.append("vFileInfo truncated at the file limit")
                records.extend(rows.build_file_records(name, result, inv, remaining))
            except Exception as exc:
                if (isinstance(exc, VinvError) and exc.code in ("cancelled", "deadline_exceeded")) or self.cancelled():
                    raise
                code = exc.code if isinstance(exc, VinvError) else "internal"
                logger.debug("vinv vFileInfo skipped datastore %s: code=%s %s", ds["key"], code, exception_summary(exc))
                warnings.append(f"vFileInfo skipped for datastore {name}")
        return records

    def collect(self, request: VinvRequest, progress: Optional[ProgressSink] = None) -> VinvSnapshot:
        sink = progress or _NullProgress()
        warnings: List[str] = list(_tls_messages(request))
        succeeded = False
        stage = "connecting"
        started = step_started = time.monotonic()

        def step(index: int, message: str) -> None:
            nonlocal stage, step_started
            logger.debug("vinv stage done in %d ms: %s", _elapsed_ms(step_started), stage)
            stage, step_started = message.lower(), time.monotonic()
            sink.update("inventory", index, 9, message)

        self._missing_fields: Set[str] = set()
        try:
            self._open(request)
            vim = self._sdk.vim
            root = self._content.rootFolder
            about = self._about()
            vc_uuid = str(rows.g(about, "instanceUuid", ""))
            inv = rows.Inventory(
                self._endpoint_host,
                vc_uuid,
                api_type=str(rows.g(about, "apiType", "VirtualCenter")),
                api_version=str(rows.g(about, "apiVersion", "")),
            )

            step(0, "Reading inventory hierarchy")
            folders = self._properties(vim.Folder, FOLDER_PROPERTIES, root, limits.MAX_RESOURCE_POOLS)
            datacenters = self._properties(vim.Datacenter, DATACENTER_PROPERTIES, root, limits.MAX_CLUSTERS)
            computes = self._properties(vim.ComputeResource, COMPUTE_PROPERTIES, root, limits.MAX_HOSTS)
            for row in list(folders) + list(datacenters) + list(computes):
                inv.add(row, row["kind"])
            clusters_raw = [c for c in computes if c["kind"] == "ClusterComputeResource"]
            scope, scope_name = self._scope(request, clusters_raw)

            step(1, "Reading clusters")
            clusters = self._properties(vim.ClusterComputeResource, CLUSTER_PROPERTIES, root, limits.MAX_CLUSTERS)
            if scope_name:
                clusters = [c for c in clusters if c["key"] == rows.moid(scope)]
            step(2, "Reading resource pools")
            pools = self._properties(vim.ResourcePool, RP_PROPERTIES, scope, limits.MAX_RESOURCE_POOLS)
            for row in pools:
                inv.add(row, row["kind"])
                inv.pool_members[row["key"]] = [rows.moid(v) for v in row.get("vm") or ()]
                inv.pool_children.setdefault(rows.moid(row.get("parent")), []).append(row["key"])
            step(3, "Reading hosts")
            hosts = self._hosts(scope, warnings)
            for row in hosts:
                inv.add(row, "HostSystem")
            self._supplement(hosts, vim.HostSystem, HOST_PARITY_PROPERTIES, scope, limits.MAX_HOSTS, warnings)
            step(4, "Reading distributed switches")
            dvs_list = self._properties(vim.DistributedVirtualSwitch, DVS_PROPERTIES, root, limits.MAX_DVS)
            for row in dvs_list:
                inv.add(row, row["kind"])
                if row.get("uuid"):
                    inv.dvs_uuid_names[str(row["uuid"])] = inv.names[row["key"]]
            dvpgs = self._properties(vim.dvs.DistributedVirtualPortgroup, DVPG_PROPERTIES, root, limits.MAX_DVPG)
            for row in dvpgs:
                inv.add(row, "DistributedVirtualPortgroup")
                inv.dvpg_names[row["key"]] = str(row.get("name", ""))
            step(5, "Reading virtual machines")
            vms = self._properties(vim.VirtualMachine, VM_PROPERTIES, scope, limits.MAX_VMS)
            self._supplement(vms, vim.VirtualMachine, VM_PARITY_PROPERTIES, scope, limits.MAX_VMS, warnings)
            for row in vms:
                inv.add(row, "VirtualMachine")
                inv.vm_power[row["key"]] = str(row.get("runtime.powerState", ""))
                inv.vm_vcpus[row["key"]] = rows._int(row.get("config.hardware.numCPU")) or 0
                memory_mb = rows._int(row.get("config.hardware.memoryMB"))
                if memory_mb is not None:
                    inv.vm_memory[row["key"]] = memory_mb
            step(6, "Reading datastores")
            if hasattr(vim, "StoragePod"):
                pods = self._properties(vim.StoragePod, STORAGE_POD_PROPERTIES, root, limits.MAX_DATASTORES)
                for pod in pods:
                    inv.add(pod, "StoragePod")
                    inv.storage_pods[pod["key"]] = pod.get("summary")
            datastores = self._properties(vim.Datastore, DATASTORE_PROPERTIES, root, limits.MAX_DATASTORES)
            for row in datastores:
                inv.add(row, "Datastore")
            if scope_name:
                scoped_hosts = {h["key"] for h in hosts}
                datastores = [d for d in datastores if any(rows.moid(rows.g(m, "key")) in scoped_hosts for m in (d.get("host") or ()))]

            try:
                definitions = self._read(lambda: rows.g(self._content, "customFieldsManager.field", ())) or ()
            except VinvError as exc:
                if exc.code in ("cancelled", "deadline_exceeded"):
                    raise
                definitions = ()
                warnings.append("Custom field definitions unavailable")
            for kind, objects, container, maximum in (
                (vim.VirtualMachine, vms, scope, limits.MAX_VMS),
                (vim.HostSystem, hosts, scope, limits.MAX_HOSTS),
                (vim.ClusterComputeResource, clusters, root, limits.MAX_CLUSTERS),
                (vim.Datastore, datastores, root, limits.MAX_DATASTORES),
                (vim.DistributedVirtualSwitch, dvs_list, root, limits.MAX_DVS),
            ):
                if definitions:
                    self._supplement(objects, kind, ("customValue",), container, maximum, warnings)

            tabs: Dict[str, List[Dict[str, str]]] = {}
            now = self._clock()
            logger.debug("vinv stage done in %d ms: %s", _elapsed_ms(step_started), stage)
            stage, step_started = "building virtual machine tabs", time.monotonic()
            for index, vm in enumerate(vms):
                if index % 250 == 0:
                    self._check()
                    sink.update("vms", index, len(vms), "Building virtual machine tabs")
                vm_records = rows.build_vm_records(vm, inv, now)
                rows.add_custom_fields(vm, vm_records, definitions)
                host_key = rows.moid(vm.get("runtime.host"))
                cluster_key = inv.parents.get(host_key, "")
                cluster = next((c for c in clusters if c["key"] == cluster_key), {})
                cfg = cluster.get("configurationEx")
                setting = next((r for r in rows.g(cfg, "dasVmConfig") or () if rows.moid(rows.g(r, "key")) == vm["key"]), None)
                defaults = rows.g(cfg, "dasConfig.defaultVmSettings")
                override = rows.g(setting, "dasSettings")
                for column, path in (("HA Restart Priority", "restartPriority"), ("HA Isolation Response", "isolationResponse"), ("HA VM Monitoring", "vmToolsMonitoringSettings.vmMonitoring")):
                    value = rows.g(override, path)
                    if value in (None, "clusterRestartPriority", "clusterIsolationResponse", "clusterDefault"):
                        value = rows.g(defaults, path)
                    vm_records["vInfo"][0][column] = rows._s(value)
                for tab, recs in vm_records.items():
                    tabs.setdefault(tab, []).extend(recs)

            aggs = rows.vm_host_aggregates(vms)
            luns = rows.datastore_lun_map(datastores, inv)
            assignments = {}
            try:
                license_manager = self._read(lambda: rows.g(self._content, "licenseManager.licenseAssignmentManager"))
                if license_manager is not None:
                    assigned = self._read(license_manager.QueryAssignedLicenses)
                    assignments = {str(rows.g(a, "entityId")): rows._s(rows.g(a, "assignedLicense.name")) for a in assigned or ()}
            except VinvError as exc:
                if exc.code in ("cancelled", "deadline_exceeded"):
                    raise
                warnings.append("Host license assignments unavailable")
            compliance = {}
            compliance_manager = rows.g(self._content, "complianceManager")
            if compliance_manager is not None and hosts:
                try:
                    cached = self._read(compliance_manager.QueryComplianceStatus, entity=[h["obj"] for h in hosts])
                    compliance = {rows.moid(rows.g(c, "entity")): rows._s(rows.g(c, "complianceStatus")) for c in cached or ()}
                except VinvError as exc:
                    if exc.code in ("cancelled", "deadline_exceeded"):
                        raise
                    warnings.append("Cached host compliance information unavailable")
            host_services: Dict[str, Dict[str, bool]] = {}
            hint_failures = 0
            logger.debug("vinv stage done in %d ms: %s", _elapsed_ms(step_started), stage)
            stage, step_started = "building host tabs", time.monotonic()
            for index, host in enumerate(hosts):
                self._check()
                sink.update("hosts", index, len(hosts), "Building host tabs")
                hints: Dict[str, Any] = {}
                if request.include_network_hints and str(host.get("summary.runtime.connectionState", "connected")) == "connected":
                    try:
                        hints = self._network_hints(host)
                    except VinvError as exc:
                        if exc.code in ("cancelled", "deadline_exceeded"):
                            raise
                        hint_failures += 1
                        logger.debug("vinv network hints unavailable for host %s: code=%s", host["key"], exc.code)
                recs, services = rows.build_host_records(host, inv, aggs, luns, hints)
                recs["vHost"][0]["Assigned License(s)"] = assignments.get(host["key"], "")
                recs["vHost"][0]["Compliance Check State"] = compliance.get(host["key"], "")
                rows.add_custom_fields(host, recs, definitions)
                manager = host.get("configManager.certificateManager")
                if manager is not None:
                    try:
                        cert = self._read(lambda manager=manager: manager.certificateInfo)
                        for column, path in (("Issuer", "issuer"), ("Start Date", "notBefore"), ("Expiry Date", "notAfter"), ("Status", "status"), ("Subject", "subject")):
                            value = rows.g(cert, path)
                            recs["vHost"][0]["Certificate " + column] = rows._iso_utc(value) if path in ("notBefore", "notAfter") else rows._s(value)
                    except VinvError as exc:
                        if exc.code in ("cancelled", "deadline_exceeded"):
                            raise
                        warnings.append("Host certificate information unavailable")
                host_services[inv.names.get(host["key"], host["key"])] = services
                for tab, items in recs.items():
                    tabs.setdefault(tab, []).extend(items)
            if hint_failures:
                warnings.append(f"CDP/LLDP hints unavailable for {hint_failures} host(s)")

            step(7, "Building cluster, storage and switch tabs")
            for record in tabs.get("vInfo", ()):
                cluster = next((c for c in clusters if rows._s(c.get("name")) == record.get("Cluster")), {})
                rules = [r for r in rows.g(cluster.get("configurationEx"), "rule") or ()
                         if record.get("VM ID") in {rows.moid(v) for v in rows.g(r, "vm") or ()}]
                record["Cluster rule(s)"] = ", ".join(rows._s(rows.g(r, "key")) for r in rules)
                record["Cluster rule name(s)"] = ", ".join(rows._s(rows.g(r, "name")) for r in rules)
            tabs["vCluster"] = [rows.build_cluster_record(c, inv) for c in clusters]
            tabs["vRP"] = [rows.build_resource_pool_record(p, inv) for p in pools]
            tabs["vDatastore"] = [rows.build_datastore_record(d, inv) for d in datastores]
            tabs["dvSwitch"] = [rows.build_dvs_record(d, inv) for d in dvs_list]
            tabs["dvPort"] = [rows.build_dvpg_record(p, inv) for p in dvpgs]
            for tab, objects in (("vCluster", clusters), ("vDatastore", datastores), ("dvSwitch", dvs_list)):
                for record, built in zip(objects, tabs[tab]):
                    rows.add_custom_fields(record, {tab: [built]}, definitions)
            try:
                licenses = self._read(lambda: rows.g(self._content, "licenseManager.licenses", ()))
            except VinvError as exc:
                if exc.code in ("cancelled", "deadline_exceeded"):
                    raise
                licenses = ()
                warnings.append("License inventory unavailable")
            tabs["vLicense"] = rows.build_license_records(licenses, inv)
            tabs["vSource"] = [rows.build_source_record(about, inv)]

            if any(not r.get("Boot Required") for r in tabs.get("vInfo", ())):
                warnings.append("Boot Required unavailable for one or more VMs: guest reboot status requires API and SDK support")
            warnings.append("Required Version in vTools unavailable: the supported inventory API provides installed Tools versions, not a required-version baseline")
            if not request.include_file_info:
                warnings.append("vFileInfo not collected: datastore file listing disabled")
            if request.include_file_info:
                step(8, "Browsing datastores for vFileInfo")
                tabs[OPTIONAL_FILEINFO_TAB] = self._file_info(datastores, inv, warnings)

            declarations: Dict[str, List[str]] = {}
            for kind_name, names in (
                ("VirtualMachine", ("vInfo", "vCPU", "vMemory", "vDisk", "vPartition", "vNetwork", "vCD", "vUSB", "vSnapshot", "vTools")),
                ("HostSystem", ("vHost",)), ("ClusterComputeResource", ("vCluster",)),
                ("Datastore", ("vDatastore",)), ("DistributedVirtualSwitch", ("dvSwitch",)),
            ):
                for name in names:
                    placeholder: Dict[str, str] = {}
                    rows.add_custom_fields({"kind": kind_name}, {name: [placeholder]}, definitions)
                    declarations[name] = list(placeholder)
            if self._missing_fields:
                warnings.append("Inventory properties unavailable for one or more objects: " + ", ".join(sorted(self._missing_fields)))
            snapshot = assemble_snapshot_from_tab_dicts(
                vcenter_server=self._endpoint_host,
                vcenter_version=str(rows.g(about, "version", "")),
                vcenter_build=str(rows.g(about, "build", "")),
                vcenter_uuid=vc_uuid,
                vcenter_fullname=str(rows.g(about, "fullName", "")),
                generated_utc=now.strftime("%Y-%m-%d %H:%M:%S"),
                scope_cluster=scope_name,
                include_file_info=request.include_file_info,
                tls_verified=request.verify_tls or bool(request.certificate_pin),
                acknowledged=request.acknowledged,
                warnings=tuple(warnings),
                tab_records=tabs,
                host_services=host_services,
                extra_headers=declarations,
            )
            size = len(snapshot_to_json(snapshot).encode("utf-8"))
            if size > limits.MAX_RESULT_BYTES:
                logger.warning("vinv result too large: bytes=%d limit=%d", size, limits.MAX_RESULT_BYTES)
                raise VinvRejected("result_too_large", "result")
            self._check()
            step(9, "Inventory complete")
            logger.debug("vinv collection ok in %d ms: bytes=%d warnings=%d tabs=%s", _elapsed_ms(started), size,
                         len(warnings), ",".join("%s:%d" % (name, len(items)) for name, items in sorted(tabs.items())))
            succeeded = True
            return snapshot
        except Exception as exc:
            error = self._unexpected(exc, "collection", stage)
            if error is exc:
                raise
            raise error from None
        finally:
            self._finish(succeeded)
