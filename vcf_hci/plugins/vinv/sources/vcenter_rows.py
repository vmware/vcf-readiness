"""Convert vCenter property values into vSphere inventory tab records.

Accepts pyVmomi data objects or attribute-compatible stand-ins; never imports pyVmomi.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from vcf_hci.plugins.vinv.schema import _b, _iso_utc, _mib_from_bytes, _pct, _s, mask_license_key

_MIB = 1024 * 1024
_TIER_MAP = {
    "softwaretiering": "Enabled",
    "hardwaretiering": "Enabled",
    "enabled": "Enabled",
    "notiering": "Disabled",
    "disabled": "Disabled",
}
_VMK_SERVICES = {
    "vmotion": "vMotion",
    "vsan": "vSAN",
    "management": "Management",
    "faultToleranceLogging": "FT",
    "vSphereProvisioning": "Provisioning",
    "vSphereReplication": "vSphere Replication",
    "vSphereBackupNFC": "Backup",
}
_TOP_FOLDERS = {"vm", "host", "datastore", "network"}

Records = Dict[str, List[Dict[str, str]]]


def g(obj: Any, path: str, default: Any = None) -> Any:
    cur = obj
    for part in path.split("."):
        if cur is None:
            return default
        cur = cur.get(part) if isinstance(cur, Mapping) else getattr(cur, part, None)
    return default if cur is None else cur


def kind(obj: Any) -> str:
    name = getattr(obj, "_wsdlName", None) or type(obj).__name__
    return str(name).split(".")[-1]


def moid(ref: Any) -> str:
    if ref is None:
        return ""
    return str(getattr(ref, "_moId", "") or "")


def _int(val: Any) -> Optional[int]:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _num(val: Any) -> str:
    n = _int(val)
    return "" if n is None else str(n)


def _mb(val: Any) -> str:
    """Non-negative MB/MiB counter as text; vSphere reports -1 for unavailable."""
    n = _int(val)
    return "" if n is None or n < 0 else str(n)


def _option(options: Any, key: str) -> str:
    for item in options or ():
        if str(g(item, "key", "")) == key:
            return _s(g(item, "value"))
    return ""


def _shares(alloc: Any) -> Tuple[str, str, str, str]:
    return (
        _s(g(alloc, "shares.level")),
        _num(g(alloc, "shares.shares")),
        _num(g(alloc, "reservation")),
        _num(g(alloc, "limit")),
    )


def _policy_value(obj: Any, path: str) -> str:
    """Read a DVS inherited-policy wrapper (``.value``) or a plain value."""
    val = g(obj, path)
    if val is None:
        return ""
    inner = getattr(val, "value", val)
    return _s(inner)


class Inventory:
    """Name/parent/type index used to resolve datacenter, cluster and folder context."""

    def __init__(self, vc_server: str, vc_uuid: str, api_type: str = "VirtualCenter", api_version: str = "") -> None:
        self.vc_server = vc_server
        self.vc_uuid = vc_uuid
        self.api_type = api_type
        self.api_version = api_version
        self.names: Dict[str, str] = {}
        self.parents: Dict[str, str] = {}
        self.kinds: Dict[str, str] = {}
        self.dvpg_names: Dict[str, str] = {}
        self.dvpg_switch: Dict[str, str] = {}
        self.dvs_uuid_names: Dict[str, str] = {}
        self.vm_power: Dict[str, str] = {}
        self.vm_vcpus: Dict[str, int] = {}
        self.lun_datastore_ids: Dict[str, str] = {}
        self.pool_members: Dict[str, List[str]] = {}
        self.pool_children: Dict[str, List[str]] = {}
        self.vm_memory: Dict[str, int] = {}
        self.storage_pods: Dict[str, Any] = {}

    def add(self, row: Mapping[str, Any], kind_name: str) -> None:
        key = str(row.get("key") or "")
        if not key:
            return
        self.kinds[key] = kind_name
        self.names[key] = _s(row.get("name")) or key
        parent = moid(row.get("parent")) or moid(row.get("parentVApp"))
        if parent:
            self.parents[key] = parent

    def ancestor(self, key: str, kinds: Set[str]) -> str:
        seen: Set[str] = set()
        cur = self.parents.get(key, "")
        while cur and cur not in seen:
            seen.add(cur)
            if self.kinds.get(cur) in kinds:
                return cur
            cur = self.parents.get(cur, "")
        return ""

    def datacenter(self, key: str) -> str:
        dc = self.ancestor(key, {"Datacenter"})
        return self.names.get(dc, "") if dc else ""

    def cluster_of_host(self, host_key: str) -> str:
        parent = self.parents.get(host_key, "")
        if self.kinds.get(parent) == "ClusterComputeResource":
            return self.names.get(parent, "")
        return ""

    def folder_path(self, key: str) -> str:
        parts: List[str] = []
        seen: Set[str] = set()
        cur = self.parents.get(key, "")
        while cur and cur not in seen and self.kinds.get(cur) not in ("Datacenter", None):
            seen.add(cur)
            if self.kinds.get(cur) == "Folder":
                parts.append(self.names.get(cur, cur))
            cur = self.parents.get(cur, "")
        if parts and parts[-1] in _TOP_FOLDERS:
            parts.pop()
        return "/".join(reversed(parts))

    def pool_path(self, key: str) -> str:
        parts = [self.names.get(key, key)]
        seen: Set[str] = {key}
        cur = self.parents.get(key, "")
        while cur and cur not in seen and self.kinds.get(cur) in ("ResourcePool", "VirtualApp"):
            seen.add(cur)
            parts.append(self.names.get(cur, cur))
            cur = self.parents.get(cur, "")
        if cur and self.kinds.get(cur) in ("ClusterComputeResource", "ComputeResource"):
            parts.append(self.names.get(cur, cur))
        return "/".join(reversed(parts))

    def sdk(self) -> Dict[str, str]:
        return {"VI SDK Server": self.vc_server, "VI SDK UUID": self.vc_uuid}


# ── Virtual machines ─────────────────────────────────────────────────────────

def _network_name(device: Any, inv: Inventory) -> Tuple[str, str]:
    backing = g(device, "backing")
    pg_key = _s(g(backing, "port.portgroupKey"))
    if pg_key:
        switch_uuid = _s(g(backing, "port.switchUuid"))
        return inv.dvpg_names.get(pg_key, pg_key), inv.dvs_uuid_names.get(switch_uuid, "")
    name = _s(g(backing, "deviceName")) or inv.names.get(moid(g(backing, "network")), "")
    return name, ""


def _guest_ips(vm: Mapping[str, Any]) -> Dict[str, Tuple[List[str], List[str]]]:
    out: Dict[str, Tuple[List[str], List[str]]] = {}
    for nic in vm.get("guest.net") or ():
        mac = _s(g(nic, "macAddress")).lower()
        if not mac:
            continue
        v4: List[str] = []
        v6: List[str] = []
        addresses = [_s(g(a, "ipAddress")) for a in (g(nic, "ipConfig.ipAddress") or ())] or [_s(a) for a in (g(nic, "ipAddress") or ())]
        for addr in addresses:
            if not addr:
                continue
            (v6 if ":" in addr else v4).append(addr)
        out[mac] = (v4, v6)
    return out


def _flatten_snapshots(nodes: Any, depth: int = 0) -> Iterable[Any]:
    if depth > 64:
        return
    for node in nodes or ():
        yield node
        yield from _flatten_snapshots(g(node, "childSnapshotList"), depth + 1)


def _cd_type(device: Any) -> str:
    backing = g(device, "backing")
    b_kind = kind(backing) if backing is not None else ""
    if "Iso" in b_kind:
        return "ISO " + _s(g(backing, "fileName"))
    if "Remote" in b_kind:
        return "Client Device"
    if b_kind:
        return "Host Device " + _s(g(backing, "deviceName"))
    return ""


def build_vm_records(vm: Mapping[str, Any], inv: Inventory, now: Optional[datetime] = None) -> Records:
    now = now or datetime.now(timezone.utc)
    key = str(vm.get("key") or "")
    host_key = moid(vm.get("runtime.host"))
    power = _s(vm.get("runtime.powerState"))
    template = _b(vm.get("summary.config.template"))
    datacenter = inv.datacenter(key) or (inv.datacenter(host_key) if host_key else "")
    ctx = {
        "Annotation": _s(vm.get("summary.config.annotation")),
        "Datacenter": datacenter,
        "Cluster": inv.cluster_of_host(host_key),
        "Host": inv.names.get(host_key, ""),
        "Folder": inv.folder_path(key),
        "OS according to the configuration file": _s(vm.get("summary.config.guestFullName")),
        "OS according to the VMware Tools": _s(vm.get("summary.guest.guestFullName")),
        "VM ID": key,
        "VMRef": key,
        "SRM Placeholder": srm_placeholder(vm),
        "VM UUID": _s(vm.get("summary.config.instanceUuid")),
    }
    ctx.update(inv.sdk())
    base = {"VM": _s(vm.get("name")), "Powerstate": power, "Template": template}
    base.update(ctx)

    devices = list(vm.get("config.hardware.device") or ())
    by_key = {_int(g(d, "key")): d for d in devices}
    disks = [d for d in devices if kind(d) == "VirtualDisk"]
    nics = [d for d in devices if g(d, "macAddress") is not None]
    cds = [d for d in devices if kind(d) == "VirtualCdrom"]
    usbs = [d for d in devices if kind(d) in ("VirtualUSB", "VirtualUSBRemoteClient")]
    video = next((d for d in devices if kind(d) == "VirtualMachineVideoCard"), None)
    extra = vm.get("config.extraConfig")
    qs = vm.get("summary.quickStats")
    ips = _guest_ips(vm)
    records: Records = {name: [] for name in ("vInfo", "vCPU", "vMemory", "vDisk", "vPartition", "vNetwork", "vCD", "vUSB", "vSnapshot", "vTools")}

    networks = [_network_name(n, inv)[0] for n in nics]
    committed = _int(vm.get("summary.storage.committed")) or 0
    uncommitted = _int(vm.get("summary.storage.uncommitted")) or 0
    pool_key = moid(vm.get("resourcePool"))
    upgrade = vm.get("config.scheduledHardwareUpgradeInfo")
    boot = vm.get("config.bootOptions")
    info = dict(base)
    info.update({
        "Config status": _s(vm.get("configStatus")),
        "DNS Name": _s(vm.get("summary.guest.hostName")),
        "Connection state": _s(vm.get("runtime.connectionState")),
        "Guest state": _s(vm.get("guest.guestState")),
        "Heartbeat": _s(vm.get("guestHeartbeatStatus")),
        "Consolidation Needed": _b(vm.get("runtime.consolidationNeeded")),
        "PowerOn": _iso_utc(vm.get("runtime.bootTime")),
        "Suspend time": _iso_utc(vm.get("runtime.suspendTime")),
        "Creation date": _iso_utc(vm.get("config.createDate")),
        "Change Version": _s(vm.get("config.changeVersion")),
        "CPUs": _num(vm.get("config.hardware.numCPU")),
        "Memory": _num(vm.get("config.hardware.memoryMB")),
        "NICs": str(len(nics)),
        "Disks": str(len(disks)),
        "min Required EVC Mode Key": _s(vm.get("runtime.minRequiredEVCModeKey")),
        "Latency Sensitivity": _s(g(vm.get("config.latencySensitivity"), "level")),
        "EnableUUID": _b(_option(extra, "disk.EnableUUID")),
        "CBT": _b(vm.get("config.changeTrackingEnabled")),
        "Primary IP Address": _s(vm.get("summary.guest.ipAddress")),
        "Num Monitors": _num(g(video, "numDisplays")),
        "Video Ram KiB": _num(g(video, "videoRamSizeInKB")),
        "Resource pool": inv.names.get(pool_key, ""),
        "Folder ID": inv.parents.get(key, ""),
        "vApp": inv.names.get(pool_key, "") if inv.kinds.get(pool_key) == "VirtualApp" else "",
        "DAS protection": _b(g(vm.get("runtime.dasVmProtection"), "dasProtected"), ""),
        "FT State": _s(vm.get("runtime.faultToleranceState")),
        "Provisioned MiB": str((committed + uncommitted) // _MIB),
        "In Use MiB": str(committed // _MIB),
        "Unshared MiB": _mib_from_bytes(vm.get("summary.storage.unshared")),
        "Boot delay": _num(g(boot, "bootDelay")),
        "Boot retry delay": _num(g(boot, "bootRetryDelay")),
        "Boot retry enabled": _b(g(boot, "bootRetryEnabled"), ""),
        "Boot BIOS setup": _b(g(boot, "enterBIOSSetup"), ""),
        "Firmware": _s(vm.get("config.firmware")),
        "HW version": _s(vm.get("config.version")),
        "HW upgrade status": _s(g(upgrade, "scheduledHardwareUpgradeStatus")),
        "HW upgrade policy": _s(g(upgrade, "upgradePolicy")),
        "HW target": _s(g(upgrade, "versionKey")),
        "Path": _s(vm.get("summary.config.vmPathName")),
        "Log directory": _s(g(vm.get("config.files"), "logDirectory")),
        "Snapshot directory": _s(g(vm.get("config.files"), "snapshotDirectory")),
        "Suspend directory": _s(g(vm.get("config.files"), "suspendDirectory")),
        "SMBIOS UUID": _s(vm.get("summary.config.uuid")),
        "VI SDK Server type": inv.api_type,
        "VI SDK API Version": inv.api_version,
    })
    for index, net in enumerate(networks[:8], 1):
        info[f"Network #{index}"] = net
    info.update({
        "Suspended To Memory": _b(g(vm.get("runtime"), "suspendedToMemory"), ""),
        "Suspend Interval": _num(g(vm.get("runtime"), "suspendInterval")),
        "Overall Cpu Readiness": _mb(g(qs, "overallCpuReadiness")),
        "Active Memory": _mb(g(qs, "activeMemory")),
        "Total disk capacity MiB": str(sum((_int(g(d, "capacityInBytes")) or (_int(g(d, "capacityInKB")) or 0) * 1024) for d in disks) // _MIB),
        "Fixed Passthru HotPlug": _b(vm.get("config.fixedPassthruHotPlugEnabled"), ""),
        "Op Notification Timeout": _num(g(vm.get("runtime"), "opNotificationTimeout")),
        "FT Role": _num(g(vm.get("config.ftInfo"), "role")),
        "Vm Failover In Progress": _b(g(vm.get("runtime"), "vmFailoverInProgress"), ""),
        "Reboot PowerOff": _b(vm.get("config.rebootPowerOff"), ""),
        "EFI Secure boot": _b(g(boot, "efiSecureBootEnabled"), ""),
        "Customization Info": _s(vm.get("guest.customizationInfo")),
        "Guest Detailed Data": _s(vm.get("guest.guestDetailedData")),
        "FT Latency": _s(g(qs, "ftLatencyStatus")),
        "FT Bandwidth": _mb(g(qs, "ftLogBandwidth")),
        "FT Sec. Latency": _mb(g(qs, "ftSecondaryLatency")),
        "Boot Required": _b(g(vm.get("guest.guestRebootStatus") or g(vm.get("guest"), "guestRebootStatus"), "rebootRequested"), ""),
    })
    records["vInfo"].append(info)

    num_cpu = _int(vm.get("config.hardware.numCPU")) or 0
    cps = _int(vm.get("config.hardware.numCoresPerSocket")) or 0
    level, shares, reservation, limit = _shares(vm.get("config.cpuAllocation"))
    cpu = dict(base)
    cpu.update({
        "Max": _mb(g(vm.get("runtime"), "maxCpuUsage")),
        "CPUs": _num(num_cpu) if num_cpu else "",
        "Sockets": str(num_cpu // cps) if num_cpu and cps else "",
        "Cores p/s": _num(cps) if cps else "",
        "Overall": _mb(g(qs, "overallCpuUsage")),
        "Level": level, "Shares": shares, "Reservation": reservation, "Limit": limit,
        "Entitlement": _mb(g(qs, "staticCpuEntitlement")),
        "DRS Entitlement": _mb(g(qs, "distributedCpuEntitlement")),
        "Hot add": _b(vm.get("config.cpuHotAddEnabled"), ""),
        "Hot remove": _b(vm.get("config.cpuHotRemoveEnabled"), ""),
        "Numa Hotadd Exposed": _b(_option(extra, "numa.vcpu.hotadd.exposed") or None, ""),
    })
    records["vCPU"].append(cpu)

    level, shares, reservation, limit = _shares(vm.get("config.memoryAllocation"))
    mem = dict(base)
    mem.update({
        "Size MiB": _num(vm.get("config.hardware.memoryMB")),
        "Memory Reservation Locked To Max": _b(vm.get("config.memoryReservationLockedToMax"), ""),
        "Overhead": _mb(g(qs, "consumedOverheadMemory")),
        "Consumed": _mb(g(qs, "hostMemoryUsage")),
        "Consumed Overhead": _mb(g(qs, "consumedOverheadMemory")),
        "Private": _mb(g(qs, "privateMemory")),
        "Shared": _mb(g(qs, "sharedMemory")),
        "Swapped": _mb(g(qs, "swappedMemory")),
        "Ballooned": _mb(g(qs, "balloonedMemory")),
        "Active": _mb(g(qs, "guestMemoryUsage")),
        "Entitlement": _mb(g(qs, "staticMemoryEntitlement")),
        "DRS Entitlement": _mb(g(qs, "distributedMemoryEntitlement")),
        "Level": level, "Shares": shares, "Reservation": reservation, "Limit": limit,
        "Hot add": _b(vm.get("config.memoryHotAddEnabled"), ""),
    })
    mem["Max"] = _mb(g(vm.get("runtime"), "maxMemoryUsage"))
    records["vMemory"].append(mem)

    for disk in disks:
        backing = g(disk, "backing")
        controller = by_key.get(_int(g(disk, "controllerKey")))
        raw = "RawDisk" in kind(backing) if backing is not None else False
        unit = _num(g(disk, "unitNumber"))
        row = dict(base)
        row.update({
            "Disk": _s(g(disk, "deviceInfo.label")),
            "Disk Key": _num(g(disk, "key")),
            "Disk UUID": _s(g(backing, "uuid")),
            "Disk Path": _s(g(backing, "fileName")),
            "Capacity MiB": _mib_from_bytes(g(disk, "capacityInBytes")) or _num((_int(g(disk, "capacityInKB")) or 0) // 1024),
            "Raw": _b(raw),
            "Disk Mode": _s(g(backing, "diskMode")),
            "Sharing mode": _s(g(backing, "sharing")),
            "Thin": _b(g(backing, "thinProvisioned"), ""),
            "Eagerly Scrub": _b(g(backing, "eagerlyScrub"), ""),
            "Split": _b(g(backing, "split"), ""),
            "Write Through": _b(g(backing, "writeThrough"), ""),
            "Level": _s(g(disk, "storageIOAllocation.shares.level")),
            "Shares": _num(g(disk, "storageIOAllocation.shares.shares")),
            "Reservation": _num(g(disk, "storageIOAllocation.reservation")),
            "Limit": _num(g(disk, "storageIOAllocation.limit")),
            "Controller": _s(g(controller, "deviceInfo.label")),
            "Label": _s(g(disk, "deviceInfo.label")),
            "SCSI Unit #": f"{_num(g(controller, 'busNumber'))}:{unit}" if controller is not None and unit else "",
            "Unit #": unit,
            "Shared Bus": _s(g(controller, "sharedBus")),
            "Path": _s(g(backing, "fileName")),
            "Raw LUN ID": _s(g(backing, "lunUuid")) if raw else "",
            "Raw Comp. Mode": _s(g(backing, "compatibilityMode")) if raw else "",
            "Internal Sort Column": f"{key}-{_num(g(disk, 'key'))}",
        })
        records["vDisk"].append(row)

    for part in vm.get("guest.disk") or ():
        capacity = _int(g(part, "capacity")) or 0
        free = _int(g(part, "freeSpace")) or 0
        mappings = [_num(g(m, "key")) for m in (g(part, "mappings") or ())]
        row = dict(base)
        row.update({
            "Disk Key": ",".join(m for m in mappings if m),
            "Disk": _s(g(part, "diskPath")),
            "Capacity MiB": str(capacity // _MIB),
            "Consumed MiB": str(max(capacity - free, 0) // _MIB),
            "Free MiB": str(free // _MIB),
            "Free %": _pct(free, capacity),
            "Internal Sort Column": f"{key}-{_s(g(part, 'diskPath'))}",
        })
        records["vPartition"].append(row)

    for nic in nics:
        mac = _s(g(nic, "macAddress"))
        net_name, switch = _network_name(nic, inv)
        v4, v6 = ips.get(mac.lower(), ([], []))
        n_kind = kind(nic)
        row = dict(base)
        row.update({
            "NIC label": _s(g(nic, "deviceInfo.label")),
            "Adapter": n_kind.replace("Virtual", "", 1) if n_kind.startswith("Virtual") else n_kind,
            "Switch": switch,
            "Connected": _b(g(nic, "connectable.connected"), ""),
            "Starts Connected": _b(g(nic, "connectable.startConnected"), ""),
            "Mac Address": mac,
            "Type": _s(g(nic, "addressType")),
            "IPv4 Address": ", ".join(v4),
            "IPv6 Address": ", ".join(v6),
            "DirectPath IO": _b("Sriov" in n_kind or "Passthrough" in n_kind),
            "UptCompatibilityEnabled": _b(g(nic, "uptCompatibilityEnabled"), ""),
            "WakeOnLanEnabled": _b(g(nic, "wakeOnLanEnabled"), ""),
            "Network": net_name,
            "Internal Sort Column": f"{key}-{_s(g(nic, 'key'))}",
        })
        records["vNetwork"].append(row)

    for cd in cds:
        row = dict(base)
        row.update({
            "Device Node": _s(g(cd, "deviceInfo.label")),
            "Connected": _b(g(cd, "connectable.connected"), ""),
            "Starts Connected": _b(g(cd, "connectable.startConnected"), ""),
            "Device Type": _cd_type(cd),
        })
        records["vCD"].append(row)

    for usb in usbs:
        u_kind = kind(usb)
        is_controller = "Controller" in u_kind
        row = dict(base)
        row.update({
            "Device Node": _s(g(usb, "deviceInfo.label")),
            "Device Type": u_kind,
            "Connected": _b(g(usb, "connected"), "") if not is_controller else "",
            "Family": ", ".join(_s(f) for f in (g(usb, "family") or ())),
            "Speed": ", ".join(_s(s) for s in (g(usb, "speed") or ())),
            "EHCI enabled": _b(g(usb, "ehciEnabled"), "") if is_controller else "",
            "Auto connect": _b(g(usb, "autoConnectDevices"), "") if is_controller else "",
            "Bus number": _num(g(usb, "busNumber")),
            "Unit number": _num(g(usb, "unitNumber")),
        })
        records["vUSB"].append(row)

    for snap in _flatten_snapshots(g(vm.get("snapshot"), "rootSnapshotList")):
        created = g(snap, "createTime")
        age = ""
        if isinstance(created, datetime):
            stamp = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
            age = str(max((now - stamp).days, 0))
        row = dict(base)
        row.update({
            "Name": _s(g(snap, "name")),
            "Description": _s(g(snap, "description")),
            "Date / time": _iso_utc(created),
            "Quiesced": _b(g(snap, "quiesced"), ""),
            "State": _s(g(snap, "state")),
            "Age (days)": age,
        })
        row.update(snapshot_files(vm.get("layoutEx"), g(snap, "snapshot")))
        records["vSnapshot"].append(row)

    status2 = _s(vm.get("summary.guest.toolsVersionStatus2"))
    tools = dict(base)
    tools.update({
        "VM Version": _s(vm.get("config.version")),
        "Tools": _s(vm.get("summary.guest.toolsStatus")),
        "Tools Version": _s(vm.get("guest.toolsVersion")),
        "Required Version": _num(vm.get("requiredToolsVersion")),
        "Upgradeable": _b(status2 in ("guestToolsSupportedOld", "guestToolsNeedUpgrade", "guestToolsTooOld")),
        "Upgrade Policy": _s(g(vm.get("config.tools"), "toolsUpgradePolicy")),
        "Sync time": _b(g(vm.get("config.tools"), "syncTimeWithHost"), ""),
        "App status": _s(vm.get("guest.appHeartbeatStatus")),
        "Heartbeat status": _s(vm.get("guestHeartbeatStatus")),
        "Kernel Crash state": _b(vm.get("guest.guestKernelCrashed"), ""),
        "Operation Ready": _b(vm.get("guest.guestOperationsReady"), ""),
        "State change support": _b(vm.get("guest.guestStateChangeSupported"), ""),
        "Interactive Guest": _b(vm.get("guest.interactiveGuestOperationsReady"), ""),
    })
    records["vTools"].append(tools)
    return records


def vm_host_aggregates(vms: Sequence[Mapping[str, Any]]) -> Dict[str, Dict[str, int]]:
    aggs: Dict[str, Dict[str, int]] = {}
    for vm in vms:
        host_key = moid(vm.get("runtime.host"))
        if not host_key or _b(vm.get("summary.config.template")) == "True":
            continue
        agg = aggs.setdefault(host_key, {"total": 0, "on": 0, "vcpus": 0, "vram": 0, "used": 0, "swapped": 0, "ballooned": 0})
        agg["total"] += 1
        if _s(vm.get("runtime.powerState")) != "poweredOn":
            continue
        qs = vm.get("summary.quickStats")
        agg["on"] += 1
        agg["vcpus"] += _int(vm.get("config.hardware.numCPU")) or 0
        agg["vram"] += _int(vm.get("config.hardware.memoryMB")) or 0
        agg["used"] += max(_int(g(qs, "hostMemoryUsage")) or 0, 0)
        agg["swapped"] += max(_int(g(qs, "swappedMemory")) or 0, 0)
        agg["ballooned"] += max(_int(g(qs, "balloonedMemory")) or 0, 0)
    return aggs


# ── Hosts ────────────────────────────────────────────────────────────────────

def _identifier(host: Mapping[str, Any], wanted: str) -> str:
    for item in host.get("summary.hardware.otherIdentifyingInfo") or ():
        if _s(g(item, "identifierType.key")) == wanted:
            return _s(g(item, "identifierValue"))
    return ""


def _security(policy: Any) -> Tuple[str, str, str]:
    return (
        _b(g(policy, "security.allowPromiscuous"), ""),
        _b(g(policy, "security.macChanges"), ""),
        _b(g(policy, "security.forgedTransmits"), ""),
    )


def _shaping(policy: Any) -> Tuple[str, str, str, str]:
    return (
        _b(g(policy, "shapingPolicy.enabled"), ""),
        _num(g(policy, "shapingPolicy.averageBandwidth")),
        _num(g(policy, "shapingPolicy.peakBandwidth")),
        _num(g(policy, "shapingPolicy.burstSize")),
    )


def _teaming(policy: Any) -> Dict[str, str]:
    team = g(policy, "nicTeaming")
    return {
        "Policy": _s(g(team, "policy")),
        "Reverse Policy": _b(g(team, "reversePolicy"), ""),
        "Notify Switch": _b(g(team, "notifySwitches"), ""),
        "Rolling Order": _b(g(team, "rollingOrder"), ""),
        "Offload": _b(g(policy, "offloadPolicy.csumOffload"), ""),
        "TSO": _b(g(policy, "offloadPolicy.tcpSegmentation"), ""),
        "Zero Copy Xmit": _b(g(policy, "offloadPolicy.zeroCopyXmit"), ""),
    }


def _hba_type(hba: Any) -> Tuple[str, str, str]:
    h_kind = kind(hba)
    if "FibreChannel" in h_kind:
        wwpn = _int(g(hba, "portWorldWideName"))
        ident = format(wwpn & 0xFFFFFFFFFFFFFFFF, "016x") if wwpn is not None else ""
        ident = ":".join(ident[i:i + 2] for i in range(0, len(ident), 2))
        return "FibreChannel", ident, _num(g(hba, "speed"))
    if "InternetScsi" in h_kind:
        return "iSCSI", _s(g(hba, "iScsiName")), ""
    if "SerialAttached" in h_kind:
        return "SAS", _s(g(hba, "nodeWorldWideName")), ""
    if "Pcie" in h_kind or "Nvme" in h_kind:
        return "NVMe", _s(g(hba, "nqn") or g(hba, "nodeWorldWideName")), ""
    if "Tcp" in h_kind or "Rdma" in h_kind:
        return h_kind.replace("Host", "").replace("Hba", ""), _s(g(hba, "nqn") or g(hba, "driver")), ""
    if "Block" in h_kind:
        return "Block", "", ""
    if "ParallelScsi" in h_kind:
        return "ParallelSCSI", "", ""
    return h_kind.replace("Host", "") or "Unknown", "", ""


def build_host_records(
    host: Mapping[str, Any],
    inv: Inventory,
    vm_aggs: Mapping[str, Mapping[str, int]],
    lun_datastores: Mapping[str, str],
    hints: Optional[Mapping[str, Any]] = None,
) -> Tuple[Records, Dict[str, bool]]:
    key = str(host.get("key") or "")
    name = inv.names.get(key) or _s(host.get("name"))
    ctx = {"Host": name, "Datacenter": inv.datacenter(key), "Cluster": inv.cluster_of_host(key)}
    ctx.update(inv.sdk())
    records: Records = {n: [] for n in ("vHost", "vHBA", "vNIC", "vSwitch", "vPort", "vSC_VMK", "vMultiPath")}
    services = {_s(g(s, "key")): bool(g(s, "running", False)) for s in (g(host.get("config.service"), "service") or ())}

    pkgs = _int(host.get("summary.hardware.numCpuPkgs")) or 0
    cores = _int(host.get("summary.hardware.numCpuCores")) or 0
    mhz = _int(host.get("summary.hardware.cpuMhz")) or 0
    mem_bytes = _int(host.get("summary.hardware.memorySize")) or 0
    mem_mib = mem_bytes // _MIB
    agg = vm_aggs.get(key, {})
    tiers = list(host.get("hardware.memoryTierInfo") or ())
    nvme_bytes = sum(_int(g(t, "size")) or 0 for t in tiers if _s(g(t, "type")).lower() == "nvme")
    tier_raw = _s(host.get("hardware.memoryTieringType")).lower()
    tier_state = _TIER_MAP.get(tier_raw, "Unknown" if not tier_raw else _s(host.get("hardware.memoryTieringType")))
    network = host.get("config.network")
    dns = g(network, "dnsConfig")
    dt = host.get("config.dateTimeInfo")
    bios = host.get("hardware.biosInfo")
    sysinfo = host.get("hardware.systemInfo")
    power = host.get("hardware.cpuPowerManagementInfo")
    ht = host.get("config.hyperThread")
    vmk_list = list(g(network, "vnic") or ())
    console = next((_s(g(v, "spec.ip.ipAddress")) for v in vmk_list if _s(g(v, "device")) == "vmk0"), "")
    vhost = dict(ctx)
    vhost.update({
        "Config status": _s(host.get("configStatus")),
        "in Maintenance Mode": _b(host.get("summary.runtime.inMaintenanceMode")),
        "in Quarantine Mode": _b(host.get("summary.runtime.inQuarantineMode")),
        "CPU Model": _s(host.get("summary.hardware.cpuModel")),
        "Speed": _num(mhz) if mhz else "",
        "HT Available": _b(g(ht, "available"), ""),
        "HT Active": _b(g(ht, "active"), ""),
        "# CPU": _num(pkgs) if pkgs else "",
        "Cores per CPU": str(cores // pkgs) if cores and pkgs else "",
        "# Cores": _num(cores) if cores else "",
        "CPU usage %": _pct(host.get("summary.quickStats.overallCpuUsage"), mhz * cores),
        "# Memory": str(mem_mib) if mem_mib else "",
        "Memory Tiering": tier_state,
        "NVMe Tier MiB": str(nvme_bytes // _MIB) if tiers else "",
        "Memory usage %": _pct(host.get("summary.quickStats.overallMemoryUsage"), mem_mib),
        "Console": console,
        "# NICs": _num(host.get("summary.hardware.numNics")),
        "# HBAs": _num(host.get("summary.hardware.numHBAs")),
        "# VMs total": str(agg.get("total", 0)),
        "# VMs": str(agg.get("on", 0)),
        "VMs per Core": f"{agg.get('on', 0) / cores:.2f}" if cores else "",
        "# vCPUs": str(agg.get("vcpus", 0)),
        "vCPUs per Core": f"{agg.get('vcpus', 0) / cores:.2f}" if cores else "",
        "vRAM": str(agg.get("vram", 0)),
        "VM Used memory": str(agg.get("used", 0)),
        "VM Memory Swapped": str(agg.get("swapped", 0)),
        "VM Memory Ballooned": str(agg.get("ballooned", 0)),
        "VMotion support": _b(host.get("summary.config.vmotionEnabled"), ""),
        "Current EVC": _s(host.get("summary.currentEVCModeKey")),
        "Max EVC": _s(host.get("summary.maxEVCModeKey")),
        "Current CPU power man.": _s(g(power, "currentPolicy")),
        "Current CPU power man. policy": _s(g(power, "currentPolicy")),
        "Memory Tiering Type": _s(host.get("hardware.memoryTieringType")),
        "Serial number": _s(g(sysinfo, "serialNumber")),
        "BIOS Vendor": _s(g(bios, "vendor")),
        "vSAN Fault Domain Name": _s(g(host.get("config.vsanHostConfig"), "faultDomainInfo.name")),
        "Domain List": ", ".join(_s(v) for v in host.get("config.domainList") or ()),
        "DNS Search Order": ", ".join(_s(v) for v in g(dns, "searchDomain") or ()),
        "Host Power Policy": _s(g(host.get("config.powerSystemInfo"), "currentPolicy.shortName")),
        "Storage VMotion support": _b(host.get("capability.storageVMotionSupported"), ""),
        "ATS heartbeat": _option(host.get("config.option"), "VMFS3.UseATSForHBOnVMFS5"),
        "ATS locking": _option(host.get("config.option"), "VMFS3.HardwareAcceleratedLocking"),
        "Supported CPU power man.": _s(g(power, "hardwareSupport")),
        "ESX Version": _s(host.get("summary.config.product.fullName")),
        "Boot time": _iso_utc(host.get("summary.runtime.bootTime")),
        "DNS Servers": ", ".join(_s(a) for a in (g(dns, "address") or ())),
        "DHCP": _b(g(dns, "dhcp"), ""),
        "Domain": _s(g(dns, "domainName")),
        "Search domains": ", ".join(_s(a) for a in (g(dns, "searchDomain") or ())),
        "NTP Server(s)": ", ".join(_s(a) for a in (g(dt, "ntpConfig.server") or ())),
        "NTPD running": _b(services["ntpd"]) if "ntpd" in services else "",
        "Time Zone": _s(g(dt, "timeZone.key")),
        "Time Zone Name": _s(g(dt, "timeZone.name")),
        "GMT Offset": _num(g(dt, "timeZone.gmtOffset")),
        "Vendor": _s(host.get("summary.hardware.vendor")),
        "Model": _s(host.get("summary.hardware.model")),
        "Service tag": _s(g(sysinfo, "serialNumber")) or _identifier(host, "ServiceTag") or _identifier(host, "EnclosureSerialNumberTag"),
        "OEM specific string": _identifier(host, "OemSpecificString"),
        "BIOS Version": _s(g(bios, "biosVersion")),
        "BIOS Date": _iso_utc(g(bios, "releaseDate")),
        "Object ID": key,
        "UUID": _s(g(sysinfo, "uuid")) or _s(host.get("summary.hardware.uuid")),
    })
    records["vHost"].append(vhost)

    storage = host.get("config.storageDevice")
    for hba in g(storage, "hostBusAdapter") or ():
        h_type, ident, speed = _hba_type(hba)
        row = dict(ctx)
        row.update({
            "Device": _s(g(hba, "device")),
            "Driver": _s(g(hba, "driver")),
            "Status": _s(g(hba, "status")),
            "Bus": _num(g(hba, "bus")),
            "Pci": _s(g(hba, "pci")),
            "Model": _s(g(hba, "model")),
            "Type": h_type,
            "WWN / IQN / NQN": ident,
            "WWN": ident if h_type == "FibreChannel" else "",
            "Speed": speed,
        })
        records["vHBA"].append(row)

    pnic_switch: Dict[str, str] = {}
    for vswitch in g(network, "vswitch") or ():
        for pkey in g(vswitch, "pnic") or ():
            pnic_switch[_s(pkey)] = _s(g(vswitch, "name"))
    for proxy in g(network, "proxySwitch") or ():
        for pkey in g(proxy, "pnic") or ():
            pnic_switch[_s(pkey)] = _s(g(proxy, "dvsName"))
    uplinks = {}
    for proxy in g(network, "proxySwitch") or ():
        for spec in g(proxy, "spec.backing.pnicSpec") or ():
            uplinks[_s(g(spec, "pnicDevice"))] = _s(g(spec, "uplinkPortKey"))
    for pnic in g(network, "pnic") or ():
        device = _s(g(pnic, "device"))
        hint = (hints or {}).get(device)
        speed = g(pnic, "linkSpeed")
        row = dict(ctx)
        row.update({
            "Network Device": device,
            "Uplink port": uplinks.get(device, ""),
            "Driver": _s(g(pnic, "driver")),
            "Speed": _num(g(speed, "speedMb")) if speed is not None else "0",
            "Duplex": _b(g(speed, "duplex"), "") if speed is not None else "",
            "MAC": _s(g(pnic, "mac")),
            "Switch": pnic_switch.get(_s(g(pnic, "key")), ""),
            "PCI": _s(g(pnic, "pci")),
            "WakeOnLan": _b(g(pnic, "wakeOnLanSupported"), ""),
            "AutoDirectPath": _b(g(pnic, "autoNegotiateSupported"), ""),
            "CDP Switch": _s(g(hint, "connectedSwitchPort.devId")),
            "CDP Port": _s(g(hint, "connectedSwitchPort.portId")),
            "CDP VLAN": _num(g(hint, "connectedSwitchPort.vlan")),
            "LLDP Chassis ID": _s(g(hint, "lldpInfo.chassisId")),
            "LLDP Port ID": _s(g(hint, "lldpInfo.portId")),
            "LLDP System Name": next((_s(g(p, "value")) for p in (g(hint, "lldpInfo.parameter") or ()) if _s(g(p, "key")) == "System Name"), ""),
        })
        records["vNIC"].append(row)

    pnic_names = {_s(g(p, "key")): _s(g(p, "device")) for p in (g(network, "pnic") or ())}
    for vswitch in g(network, "vswitch") or ():
        policy = g(vswitch, "spec.policy")
        promisc, macs, forged = _security(policy)
        shaping, width, peak, burst = _shaping(policy)
        row = dict(ctx)
        row.update({
            "Switch": _s(g(vswitch, "name")),
            "# Ports": _num(g(vswitch, "numPorts")),
            "Free Ports": _num(g(vswitch, "numPortsAvailable")),
            "Promiscuous Mode": promisc, "Mac Changes": macs, "Forged Transmits": forged,
            "Traffic Shaping": shaping, "Width": width, "Peak": peak, "Burst": burst,
            "MTU": _num(g(vswitch, "mtu")),
            "Uplinks": ", ".join(pnic_names.get(_s(p), _s(p)) for p in (g(vswitch, "pnic") or ())),
        })
        row.update(_teaming(policy))
        records["vSwitch"].append(row)

    for pg in g(network, "portgroup") or ():
        spec = g(pg, "spec")
        policy = g(pg, "computedPolicy") or g(spec, "policy")
        promisc, macs, forged = _security(policy)
        shaping, width, peak, burst = _shaping(policy)
        row = dict(ctx)
        row.update({
            "Port Group": _s(g(spec, "name")),
            "Switch": _s(g(spec, "vswitchName")),
            "VLAN": _num(g(spec, "vlanId")),
            "Promiscuous Mode": promisc, "Mac Changes": macs, "Forged Transmits": forged,
            "Traffic Shaping": shaping, "Width": width, "Peak": peak, "Burst": burst,
            "Active Uplinks": ", ".join(_s(n) for n in (g(policy, "nicTeaming.nicOrder.activeNic") or ())),
            "Standby Uplinks": ", ".join(_s(n) for n in (g(policy, "nicTeaming.nicOrder.standbyNic") or ())),
        })
        row.update(_teaming(policy))
        records["vPort"].append(row)

    vmk_services: Dict[str, Set[str]] = {}
    for net_cfg in host.get("config.virtualNicManagerInfo.netConfig") or ():
        label = _VMK_SERVICES.get(_s(g(net_cfg, "nicType")))
        if not label:
            continue
        candidates = {_s(g(c, "key")): _s(g(c, "device")) for c in (g(net_cfg, "candidateVnic") or ())}
        for selected in g(net_cfg, "selectedVnic") or ():
            device = candidates.get(_s(selected), _s(selected).rsplit("-", 1)[-1])
            vmk_services.setdefault(device, set()).add(label)
    gateway = _s(g(network, "ipRouteConfig.defaultGateway"))
    gateway6 = _s(g(network, "ipRouteConfig.ipV6DefaultGateway"))
    for vmk in vmk_list:
        device = _s(g(vmk, "device"))
        spec = g(vmk, "spec")
        pg_name = _s(g(vmk, "portgroup")) or inv.dvpg_names.get(_s(g(spec, "distributedVirtualPort.portgroupKey")), "")
        v6 = [f"{_s(g(a, 'ipAddress'))}/{_num(g(a, 'prefixLength'))}" for a in (g(spec, "ip.ipV6Config.ipV6Address") or ())]
        enabled = vmk_services.get(device, set())
        row = dict(ctx)
        row.update({
            "Port Group": pg_name,
            "Device": device,
            "Mac Address": _s(g(spec, "mac")),
            "DHCP": _b(g(spec, "ip.dhcp"), ""),
            "IP Address": _s(g(spec, "ip.ipAddress")),
            "IP 6 Address": ", ".join(v6),
            "Subnet mask": _s(g(spec, "ip.subnetMask")),
            "Gateway": _s(g(spec, "ipRouteSpec.ipRouteConfig.defaultGateway")) or gateway,
            "IP 6 Gateway": gateway6,
            "MTU": _num(g(spec, "mtu")),
            "NetStack": _s(g(spec, "netStackInstanceKey")),
        })
        for label in _VMK_SERVICES.values():
            row[label] = _b(label in enabled)
        records["vSC_VMK"].append(row)

    luns = {_s(g(lun, "key")): lun for lun in (g(storage, "scsiLun") or ())}
    for mp in g(storage, "multipathInfo.lun") or ():
        lun = luns.get(_s(g(mp, "lun")))
        canonical = _s(g(lun, "canonicalName"))
        if canonical not in lun_datastores:
            continue
        paths = list(g(mp, "path") or ())
        row = dict(ctx)
        row.update({
            "Datastore": lun_datastores.get(canonical, ""),
            "Display name": _s(g(lun, "displayName")) or canonical,
            "Policy": _s(g(mp, "policy.policy")),
            "Oper. State": ", ".join(_s(s) for s in (g(lun, "operationalState") or ())),
            "vStorage": _s(g(lun, "vStorageSupport")),
            "Queue depth": _num(g(lun, "queueDepth")),
            "Vendor": _s(g(lun, "vendor")),
            "Model": _s(g(lun, "model")),
            "Revision": _s(g(lun, "revision")),
            "Level": _s(g(lun, "scsiLevel")),
            "Serial": _s(g(lun, "serialNumber")),
            "UUID": _s(g(lun, "uuid")),
            "Disk Key": _s(g(lun, "key")),
            "Disk": canonical,
            "SATP": _s(g(mp, "storageArrayTypePolicy.policy")),
            "Object ID": inv.lun_datastore_ids.get(canonical, ""),
        })
        for index, path in enumerate(paths[:8], 1):
            row[f"Path {index}"] = _s(g(path, "name"))
            row[f"Path {index} state"] = _s(g(path, "pathState") or g(path, "state"))
        records["vMultiPath"].append(row)
    return records, services


# ── Clusters, pools, datastores, switches, licenses ─────────────────────────

def build_cluster_record(cluster: Mapping[str, Any], inv: Inventory) -> Dict[str, str]:
    key = str(cluster.get("key") or "")
    summary = cluster.get("summary")
    cfg = cluster.get("configurationEx")
    das = g(cfg, "dasConfig")
    drs = g(cfg, "drsConfig")
    dpm = g(cfg, "dpmConfigInfo")
    vm_tools = g(das, "defaultVmSettings.vmToolsMonitoringSettings")
    row = {
        "Name": inv.names.get(key) or _s(cluster.get("name")),
        "Config status": _s(cluster.get("configStatus")),
        "OverallStatus": _s(cluster.get("overallStatus")),
        "NumHosts": _num(g(summary, "numHosts")),
        "numEffectiveHosts": _num(g(summary, "numEffectiveHosts")),
        "TotalCpu": _num(g(summary, "totalCpu")),
        "NumCpuCores": _num(g(summary, "numCpuCores")),
        "NumCpuThreads": _num(g(summary, "numCpuThreads")),
        "Effective Cpu": _num(g(summary, "effectiveCpu")),
        "TotalMemory": _mib_from_bytes(g(summary, "totalMemory")),
        "Effective Memory": _num(g(summary, "effectiveMemory")),
        "Num VMotions": _num(g(summary, "numVmotions")),
        "HA enabled": _b(g(das, "enabled")),
        "Failover Level": _num(g(das, "failoverLevel")),
        "AdmissionControlEnabled": _b(g(das, "admissionControlEnabled"), ""),
        "Host monitoring": _s(g(das, "hostMonitoring")),
        "HB Datastore Candidate Policy": _s(g(das, "hBDatastoreCandidatePolicy")),
        "Isolation Response": _s(g(das, "defaultVmSettings.isolationResponse")),
        "Restart Priority": _s(g(das, "defaultVmSettings.restartPriority")),
        "Cluster Settings": _b(g(vm_tools, "clusterSettings"), ""),
        "Max Failures": _num(g(vm_tools, "maxFailures")),
        "Max Failure Window": _num(g(vm_tools, "maxFailureWindow")),
        "Failure Interval": _num(g(vm_tools, "failureInterval")),
        "Min Up Time": _num(g(vm_tools, "minUpTime")),
        "VM Monitoring": _s(g(das, "vmMonitoring")),
        "DRS enabled": _b(g(drs, "enabled")),
        "DRS default VM behavior": _s(g(drs, "defaultVmBehavior")),
        "DRS vmotion rate": _num(g(drs, "vmotionRate")),
        "DPM enabled": _b(g(dpm, "enabled"), ""),
        "DPM default behavior": _s(g(dpm, "defaultDpmBehavior")),
        "DPM Host Power Action Rate": _num(g(dpm, "hostPowerActionRate")),
        "EVC Mode": _s(g(summary, "currentEVCModeKey")),
        "vSAN enabled": _b(g(cfg, "vsanConfigInfo.enabled")),
        "Datacenter": inv.datacenter(key),
        "Object ID": key,
    }
    row.update(inv.sdk())
    return row


def build_resource_pool_record(pool: Mapping[str, Any], inv: Inventory) -> Dict[str, str]:
    key = str(pool.get("key") or "")
    vms = {moid(v) for v in (pool.get("vm") or ())}
    pending = [key]
    seen: Set[str] = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        vms.update(inv.pool_members.get(current, ()))
        pending.extend(inv.pool_children.get(current, ()))
    cpu = pool.get("config.cpuAllocation")
    mem = pool.get("config.memoryAllocation")
    runtime = pool.get("runtime")
    qs = g(pool.get("summary"), "quickStats")
    row = {
        "Resource Pool name": inv.names.get(key) or _s(pool.get("name")),
        "Resource Pool path": inv.pool_path(key),
        "Status": _s(pool.get("configStatus")),
        "VMs total": str(len(vms)),
        "VMs": str(sum(1 for v in vms if inv.vm_power.get(v) == "poweredOn")),
        "vCPUs": str(sum(inv.vm_vcpus.get(v, 0) for v in vms)),
        "CPU limit": _num(g(cpu, "limit")),
        "CPU overheadLimit": _num(g(cpu, "overheadLimit")),
        "CPU reservation": _num(g(cpu, "reservation")),
        "CPU level": _s(g(cpu, "shares.level")),
        "CPU shares": _num(g(cpu, "shares.shares")),
        "CPU expandableReservation": _b(g(cpu, "expandableReservation"), ""),
        "CPU maxUsage": _num(g(runtime, "cpu.maxUsage")),
        "CPU overallUsage": _num(g(runtime, "cpu.overallUsage")),
        "Mem Configured": str(sum(inv.vm_memory[v] for v in vms)) if all(v in inv.vm_memory for v in vms) else "",
        "Mem limit": _num(g(mem, "limit")),
        "Mem overheadLimit": _num(g(mem, "overheadLimit")),
        "Mem reservation": _num(g(mem, "reservation")),
        "Mem level": _s(g(mem, "shares.level")),
        "Mem shares": _num(g(mem, "shares.shares")),
        "Mem expandableReservation": _b(g(mem, "expandableReservation"), ""),
        "Mem maxUsage": _mib_from_bytes(g(runtime, "memory.maxUsage")),
        "Mem overallUsage": _mib_from_bytes(g(runtime, "memory.overallUsage")),
        "Object ID": key,
    }
    for field in ("overallCpuDemand", "overallCpuUsage", "staticCpuEntitlement", "distributedCpuEntitlement",
                  "balloonedMemory", "compressedMemory", "consumedOverheadMemory", "distributedMemoryEntitlement",
                  "guestMemoryUsage", "hostMemoryUsage", "overheadMemory", "privateMemory", "sharedMemory",
                  "staticMemoryEntitlement", "swappedMemory"):
        row["QS " + field] = _mb(g(qs, field))
    for prefix, resource in (("CPU", "cpu"), ("Mem", "memory")):
        for field in ("reservationUsed", "reservationUsedForVm", "unreservedForPool", "unreservedForVm"):
            value = g(runtime, resource + "." + field)
            row[prefix + " " + field] = _mib_from_bytes(value) if resource == "memory" else _num(value)
    row.update(inv.sdk())
    return row


def datastore_lun_map(datastores: Sequence[Mapping[str, Any]], inv: Inventory) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for ds in datastores:
        for extent in g(ds.get("info"), "vmfs.extent") or ():
            name = _s(g(extent, "diskName"))
            if name:
                out[name] = inv.names.get(str(ds.get("key")), _s(ds.get("name")))
                inv.lun_datastore_ids[name] = str(ds.get("key") or "")
    return out


def build_datastore_record(ds: Mapping[str, Any], inv: Inventory) -> Dict[str, str]:
    key = str(ds.get("key") or "")
    capacity = _int(ds.get("summary.capacity")) or 0
    free = _int(ds.get("summary.freeSpace")) or 0
    uncommitted = _int(ds.get("summary.uncommitted")) or 0
    info = ds.get("info")
    vmfs = g(info, "vmfs")
    nas = g(info, "nas")
    host_keys = [moid(g(m, "key")) for m in (ds.get("host") or ())]
    vms = [moid(v) for v in (ds.get("vm") or ())]
    parent = inv.parents.get(key, "")
    address = ", ".join(_s(g(e, "diskName")) for e in g(vmfs, "extent") or ())
    if nas is not None:
        address = f"{_s(g(nas, 'remoteHost'))}:{_s(g(nas, 'remotePath'))}".strip(":")
    row = {
        "Name": inv.names.get(key) or _s(ds.get("name")),
        "Config status": _s(ds.get("configStatus")),
        "Address": address,
        "Accessible": _b(ds.get("summary.accessible"), ""),
        "Type": _s(ds.get("summary.type")),
        "Num VMs total": str(len(vms)),
        "Num VMs": str(sum(1 for v in vms if inv.vm_power.get(v) == "poweredOn")),
        "Capacity MiB": str(capacity // _MIB),
        "Provisioned MiB": str(max(capacity - free + uncommitted, 0) // _MIB),
        "In Use MiB": str(max(capacity - free, 0) // _MIB),
        "Free MiB": str(free // _MIB),
        "Free %": _pct(free, capacity),
        "SIOC enabled": _b(g(ds.get("iormConfiguration"), "enabled"), ""),
        "SIOC Threshold": _num(g(ds.get("iormConfiguration"), "congestionThreshold")),
        "Num Hosts": str(len(host_keys)),
        "Hosts": ", ".join(inv.names.get(h, h) for h in host_keys),
        "Cluster name": inv.names.get(parent, "") if inv.kinds.get(parent) == "StoragePod" else "",
        "Cluster capacity MiB": _mib_from_bytes(g(inv.storage_pods.get(parent), "capacity")),
        "Cluster free space MiB": _mib_from_bytes(g(inv.storage_pods.get(parent), "freeSpace")),
        "Block size": _num(g(vmfs, "blockSizeMb")),
        "Max Blocks": _num(g(vmfs, "maxBlocks")),
        "Num Extents": str(len(g(vmfs, "extent") or ())) if vmfs is not None else "",
        "Major Version": _num(g(vmfs, "majorVersion")),
        "Version": _s(g(vmfs, "version")),
        "VMFS Upgradeable": _b(g(vmfs, "vmfsUpgradable"), ""),
        "MHA": _b(ds.get("summary.multipleHostAccess"), ""),
        "URL": _s(ds.get("summary.url")),
        "Object ID": key,
    }
    row.update(inv.sdk())
    return row


def build_dvs_record(dvs: Mapping[str, Any], inv: Inventory) -> Dict[str, str]:
    key = str(dvs.get("key") or "")
    summary = dvs.get("summary")
    cfg = dvs.get("config")
    port = g(cfg, "defaultPortConfig")
    lacp = list(g(cfg, "lacpGroupConfig") or ())
    ipfix = g(cfg, "ipfixConfig")
    checks = {kind(c): _b(g(c, "enable"), "") for c in (g(cfg, "healthCheckConfig") or ())}
    name = inv.names.get(key) or _s(dvs.get("name"))
    row = {
        "Switch": name,
        "Datacenter": inv.datacenter(key),
        "Name": _s(g(summary, "name")) or name,
        "Vendor": _s(g(summary, "productInfo.vendor")),
        "Version": _s(g(summary, "productInfo.version")),
        "Description": _s(g(summary, "description")),
        "Created": _iso_utc(g(cfg, "createTime")),
        "Max Ports": _num(g(cfg, "maxPorts")),
        "# Ports": _num(g(summary, "numPorts")),
        "# VMs": str(len(g(summary, "vm") or ())),
        "# Hosts": str(len(g(summary, "hostMember") or ())),
        "Host members": ", ".join(inv.names.get(moid(h), moid(h)) for h in g(summary, "hostMember") or ()),
        "In Traffic Shaping": _policy_value(port, "inShapingPolicy.enabled"),
        "In Avg": _policy_value(port, "inShapingPolicy.averageBandwidth"),
        "In Peak": _policy_value(port, "inShapingPolicy.peakBandwidth"),
        "In Burst": _policy_value(port, "inShapingPolicy.burstSize"),
        "Out Traffic Shaping": _policy_value(port, "outShapingPolicy.enabled"),
        "Out Avg": _policy_value(port, "outShapingPolicy.averageBandwidth"),
        "Out Peak": _policy_value(port, "outShapingPolicy.peakBandwidth"),
        "Out Burst": _policy_value(port, "outShapingPolicy.burstSize"),
        "CDP Type": _s(g(cfg, "linkDiscoveryProtocolConfig.protocol")),
        "CDP Operation": _s(g(cfg, "linkDiscoveryProtocolConfig.operation")),
        "LACP Name": ", ".join(_s(g(l, "name")) for l in lacp),
        "LACP Mode": ", ".join(_s(g(l, "mode")) for l in lacp),
        "LACP Load Balance Alg.": ", ".join(_s(g(l, "loadbalanceAlgorithm")) for l in lacp),
        "Max MTU": _num(g(cfg, "maxMtu")),
        "Contact": _s(g(cfg, "contact.contact")),
        "Admin Name": _s(g(cfg, "contact.name")),
        "NetFlow Collector IP": _s(g(ipfix, "collectorIpAddress")),
        "NetFlow Collector Port": _num(g(ipfix, "collectorPort")),
        "NetFlow Observation Domain ID": _num(g(ipfix, "observationDomainId")),
        "NetFlow Active Flow Timeout": _num(g(ipfix, "activeFlowTimeout")),
        "NetFlow Idle Flow Timeout": _num(g(ipfix, "idleFlowTimeout")),
        "NetFlow Sampling Rate": _num(g(ipfix, "samplingRate")),
        "NetFlow Internal Flows Only": _b(g(ipfix, "internalFlowsOnly"), ""),
        "VLAN + MTU Check": next((v for k, v in checks.items() if "Vlan" in k), ""),
        "Teaming and Failover Check": next((v for k, v in checks.items() if "Teaming" in k), ""),
        "Object ID": key,
        "UUID": _s(dvs.get("uuid")),
    }
    row.update(inv.sdk())
    return row


def _vlan_text(vlan: Any) -> Tuple[str, str]:
    v_kind = kind(vlan) if vlan is not None else ""
    if "Trunk" in v_kind:
        ranges = [f"{_num(g(r, 'start'))}-{_num(g(r, 'end'))}" for r in (g(vlan, "vlanId") or ())]
        return "Trunk", ", ".join(ranges)
    if "Pvlan" in v_kind:
        return "Private VLAN", _num(g(vlan, "pvlanId"))
    if vlan is None:
        return "", ""
    return "VLAN", _num(g(vlan, "vlanId"))


def build_dvpg_record(pg: Mapping[str, Any], inv: Inventory) -> Dict[str, str]:
    cfg = pg.get("config")
    port = g(cfg, "defaultPortConfig")
    policy = g(cfg, "policy")
    vlan_type, vlan = _vlan_text(g(port, "vlan"))
    team = g(port, "uplinkTeamingPolicy")
    dvs_key = moid(g(cfg, "distributedVirtualSwitch"))
    row = {
        "Port": _s(g(cfg, "name")) or _s(pg.get("name")),
        "Switch": inv.names.get(dvs_key, ""),
        "Type": _s(g(cfg, "type")),
        "# Ports": _num(g(cfg, "numPorts")),
        "VLAN Type": vlan_type,
        "VLAN": vlan,
        "Blocked": _policy_value(port, "blocked"),
        "Allow Promiscuous": _policy_value(port, "securityPolicy.allowPromiscuous"),
        "Mac Changes": _policy_value(port, "securityPolicy.macChanges"),
        "Forged Transmits": _policy_value(port, "securityPolicy.forgedTransmits"),
        "Active Uplinks": ", ".join(_s(u) for u in (g(team, "uplinkPortOrder.activeUplinkPort") or ())),
        "Standby Uplinks": ", ".join(_s(u) for u in (g(team, "uplinkPortOrder.standbyUplinkPort") or ())),
        "Policy": _policy_value(team, "policy"),
        "In Traffic Shaping": _policy_value(port, "inShapingPolicy.enabled"),
        "In Avg": _policy_value(port, "inShapingPolicy.averageBandwidth"),
        "In Peak": _policy_value(port, "inShapingPolicy.peakBandwidth"),
        "In Burst": _policy_value(port, "inShapingPolicy.burstSize"),
        "Out Traffic Shaping": _policy_value(port, "outShapingPolicy.enabled"),
        "Out Avg": _policy_value(port, "outShapingPolicy.averageBandwidth"),
        "Out Peak": _policy_value(port, "outShapingPolicy.peakBandwidth"),
        "Out Burst": _policy_value(port, "outShapingPolicy.burstSize"),
        "Reverse Policy": _policy_value(team, "reversePolicy"),
        "Notify Switch": _policy_value(team, "notifySwitches"),
        "Rolling Order": _policy_value(team, "rollingOrder"),
        "Check Beacon": _policy_value(team, "failureCriteria.checkBeacon"),
        "Check Duplex": _policy_value(team, "failureCriteria.checkDuplex"),
        "Check Error %": _policy_value(team, "failureCriteria.checkErrorPercent"),
        "Check Speed": _policy_value(team, "failureCriteria.checkSpeed"),
        "Full Duplex": _policy_value(team, "failureCriteria.fullDuplex"),
        "Percentage": _policy_value(team, "failureCriteria.percentage"),
        "Speed": _policy_value(team, "failureCriteria.speed"),
        "Live Port Moving": _b(g(policy, "livePortMovingAllowed"), ""),
        "Block Override": _b(g(policy, "blockOverrideAllowed"), ""),
        "Config Reset": _b(g(policy, "portConfigResetAtDisconnect"), ""),
        "Shaping Override": _b(g(policy, "shapingOverrideAllowed"), ""),
        "Teaming Override": _b(g(policy, "uplinkTeamingOverrideAllowed"), ""),
        "Vendor Config Override": _b(g(policy, "vendorConfigOverrideAllowed"), ""),
        "Sec. Policy Override": _b(g(policy, "securityPolicyOverrideAllowed"), ""),
        "VLAN Override": _b(g(policy, "vlanOverrideAllowed"), ""),
        "Uplink Teaming Override": _b(g(policy, "uplinkTeamingOverrideAllowed"), ""),
        "Object ID": str(pg.get("key") or ""),
    }
    row.update(inv.sdk())
    return row


def build_license_records(licenses: Iterable[Any], inv: Inventory, mask_keys: bool = True) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for lic in licenses or ():
        props = list(g(lic, "properties") or ())
        expiration = next((g(p, "value") for p in props if _s(g(p, "key")) == "expirationDate"), None)
        features = [_s(g(g(p, "value"), "value") or g(p, "value")) for p in props if _s(g(p, "key")) == "feature"]
        row = {
            "Name": _s(g(lic, "name")),
            "Key": mask_license_key(_s(g(lic, "licenseKey")), mask=mask_keys),
            "Labels": ", ".join(f"{_s(g(l, 'key'))}={_s(g(l, 'value'))}" for l in (g(lic, "labels") or ())),
            "Cost Unit": _s(g(lic, "costUnit")),
            "Total": _num(g(lic, "total")),
            "Used": _num(g(lic, "used")),
            "Expiration Date": _iso_utc(expiration) if expiration is not None else "Never",
            "Features": ", ".join(f for f in features if f),
        }
        row.update(inv.sdk())
        rows.append(row)
    return rows


def build_source_record(about: Any, inv: Inventory) -> Dict[str, str]:
    row = {
        "Name": inv.vc_server,
        "OS type": _s(g(about, "osType")),
        "API type": _s(g(about, "apiType")),
        "API version": _s(g(about, "apiVersion")),
        "Version": _s(g(about, "version")),
        "Build": _s(g(about, "build")),
        "Patch level": _s(g(about, "patchLevel")),
        "Fullname": _s(g(about, "fullName")),
        "Product name": _s(g(about, "name")),
        "Product version": _s(g(about, "version")),
        "Product line": _s(g(about, "productLineId")),
        "Vendor": _s(g(about, "vendor")),
    }
    row.update(inv.sdk())
    return row


def build_file_records(datastore_name: str, results: Iterable[Any], inv: Inventory, limit: int) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for result in results or ():
        folder = _s(g(result, "folderPath"))
        for item in g(result, "file") or ():
            if len(rows) >= limit:
                return rows
            path = _s(g(item, "path"))
            friendly = f"{folder.rstrip('/')}/{path}" if folder and not folder.endswith("] ") else f"{folder}{path}"
            row = {
                "Datastore": datastore_name,
                "File Name": path,
                "Friendly Path Name": friendly,
                "Path": folder,
                "File Size in bytes": _num(g(item, "fileSize")),
                "File Type": kind(item),
                "Last Modified": _iso_utc(g(item, "modification")),
                "Owner": _s(g(item, "owner")),
                "Internal Sort Column": friendly,
            }
            row.update(inv.sdk())
            rows.append(row)
    return rows


def snapshot_files(layout: Any, snapshot: Any) -> Dict[str, str]:
    """Resolve a snapshot's layout keys once, without counting shared keys twice."""
    match = next((s for s in g(layout, "snapshot") or () if moid(g(s, "key")) == moid(snapshot) and moid(snapshot)), None)
    if match is None:
        return {}
    files = {g(f, "key"): f for f in g(layout, "file") or ()}
    data = files.get(g(match, "dataKey"))
    keys = {g(match, "dataKey"), g(match, "memoryKey")}
    for disk in g(match, "disk") or ():
        for chain in g(disk, "chain") or ():
            keys.update(g(chain, "fileKey") or ())
    selected = [files[k] for k in keys if k in files]
    sizes = [_int(g(f, "size")) for f in selected]
    required = {k for k in keys if k is not None and k >= 0}
    total = str(sum(v for v in sizes if v is not None) // _MIB) if sizes and required.issubset(files) and all(v is not None and v >= 0 for v in sizes) else ""
    return {"Filename": _s(g(data, "name")), "Size MiB (vmsn)": _mib_from_bytes(g(data, "size")), "Size MiB (total)": total}


def add_custom_fields(record: Mapping[str, Any], output: Records, definitions: Iterable[Any]) -> None:
    """Carry applicable custom fields to every row for the same managed object.

    Prefix colliding names, including the prefix itself, so built-in values survive.
    """
    from vcf_hci.plugins.vinv.constants import TAB_HEADERS
    from vcf_hci.plugins.vinv.parity import HEADER_ALIASES

    values = {g(v, "key"): _s(g(v, "value")) for v in record.get("customValue") or ()}
    object_kind = str(record.get("kind", ""))
    for tab, records in output.items():
        used = set(TAB_HEADERS[tab]) | set(HEADER_ALIASES.get(tab, {}).values())
        for definition in sorted(definitions, key=lambda d: (_s(g(d, "name")), _s(g(d, "key")))):
            owner = g(definition, "managedObjectType")
            owner_name = str(getattr(owner, "__name__", owner) or "").split(".")[-1]
            applicable = {object_kind, "ManagedEntity"}
            if object_kind == "VmwareDistributedVirtualSwitch":
                applicable.add("DistributedVirtualSwitch")
            if owner_name and owner_name not in applicable:
                continue
            name = _s(g(definition, "name"))
            if not name:
                continue
            while name in used:
                name = "Custom: " + name
            used.add(name)
            for row in records:
                row[name] = values.get(g(definition, "key"), "")


def srm_placeholder(vm: Mapping[str, Any]) -> str:
    """Use SRM's managed-by marker, never infer placeholder status from VM names."""
    manager = vm.get("config.managedBy")
    extension = _s(g(manager, "extensionKey")) or _option(vm.get("config.extraConfig"), "srm.managedBy.extKey")
    managed_type = _s(g(manager, "type")) or _option(vm.get("config.extraConfig"), "srm.managedBy.type")
    if manager is None and "config.extraConfig" not in vm and "config.managedBy" not in vm:
        return ""
    return _b(extension.lower() == "com.vmware.vcdr" and managed_type == "placeholderVm")
