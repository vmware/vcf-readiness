"""Pure schema row builders and health rule evaluators for vSphere Inventory Export."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from vcf_hci.constants import TOOL_VERSION
from vcf_hci.plugins.vinv import limits
from vcf_hci.plugins.vinv.constants import (
    CORE_TAB_NAMES,
    LIFECYCLE,
    OPTIONAL_FILEINFO_TAB,
    SCHEMA_VERSION,
    TAB_HEADERS,
)
from vcf_hci.plugins.vinv.models import VinvSnapshot, VinvTab
from vcf_hci.plugins.vinv.parity import HEADER_ALIASES, with_aliases


def _s(val: Any, default: str = "") -> str:
    if val is None:
        return default
    if isinstance(val, bool):
        return "True" if val else "False"
    return str(val).strip()


def _b(val: Any, default: str = "False") -> str:
    if val is None or val == "":
        return default
    if isinstance(val, bool):
        return "True" if val else "False"
    s = str(val).strip().lower()
    if s in ("true", "1", "yes", "enabled", "on"):
        return "True"
    if s in ("false", "0", "no", "disabled", "off"):
        return "False"
    return default


def _mib_from_bytes(val: Any) -> str:
    if val is None or val == "":
        return ""
    try:
        num = int(val)
        if num < 0:
            return ""
        return str(num // (1024 * 1024))
    except (TypeError, ValueError):
        return ""


def _kib_from_bytes(val: Any) -> str:
    if val is None or val == "":
        return ""
    try:
        num = int(val)
        if num < 0:
            return ""
        return str(num // 1024)
    except (TypeError, ValueError):
        return ""


def _pct(numerator: Any, denominator: Any, decimals: int = 1) -> str:
    try:
        num = float(numerator)
        den = float(denominator)
        if den <= 0 or num < 0:
            return ""
        return f"{round((num / den) * 100.0, decimals):.{decimals}f}"
    except (TypeError, ValueError, ZeroDivisionError):
        return ""


def _iso_utc(val: Any) -> str:
    if val is None or val == "":
        return ""
    if isinstance(val, datetime):
        dt = val.astimezone(timezone.utc) if val.tzinfo else val.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return str(val).strip()


def mask_license_key(raw_key: str, mask: bool = True) -> str:
    text = _s(raw_key)
    if not text or not mask:
        return text
    parts = text.split("-")
    if len(parts) == 5:
        return f"{parts[0]}-*****-*****-*****-{parts[4]}"
    if len(text) > 8:
        return text[:4] + ("*" * (len(text) - 8)) + text[-4:]
    return "*****"


def _row_from_mapping(tab_name: str, mapping: Mapping[str, Any]) -> Tuple[str, ...]:
    headers = TAB_HEADERS[tab_name]
    mapping = with_aliases(tab_name, mapping)
    return tuple(_s(mapping.get(col, "")) for col in headers)


def evaluate_vhealth_rows(
    vinfo_rows: Sequence[Mapping[str, Any]],
    vsnapshot_rows: Sequence[Mapping[str, Any]],
    vcd_rows: Sequence[Mapping[str, Any]],
    vtools_rows: Sequence[Mapping[str, Any]],
    vdatastore_rows: Sequence[Mapping[str, Any]],
    vhost_rows: Sequence[Mapping[str, Any]],
    host_services: Optional[Mapping[str, Mapping[str, bool]]] = None,
    vc_server: str = "",
    vc_uuid: str = "",
) -> List[Tuple[str, ...]]:
    """Synthesize deterministic vHealth findings from normalized tab dictionaries."""
    findings: List[Tuple[str, ...]] = []
    services_by_host = host_services or {}

    def add_finding(name: str, msg: str, msg_type: str, dc: str, cluster: str, host: str) -> None:
        findings.append(
            _row_from_mapping(
                "vHealth",
                {
                    "Name": name,
                    "Message": msg,
                    "Message type": msg_type,
                    "Datacenter": dc,
                    "Cluster": cluster,
                    "Host": host,
                    "VI SDK Server": vc_server,
                    "VI SDK UUID": vc_uuid,
                },
            )
        )

    # 1. VM connection state, consolidation, and folder consistency
    for vm in vinfo_rows:
        vm_name = _s(vm.get("VM"))
        dc = _s(vm.get("Datacenter"))
        cluster = _s(vm.get("Cluster"))
        host = _s(vm.get("Host"))
        conn = _s(vm.get("Connection state")).lower()
        if conn in ("inaccessible", "orphaned", "invalid", "disconnected"):
            add_finding(
                vm_name,
                f"VM is in '{conn}' connection state",
                "Zombie / Inaccessible VM",
                dc,
                cluster,
                host,
            )
        if _b(vm.get("Consolidation Needed")) == "True":
            add_finding(
                vm_name,
                "Virtual machine disks require snapshot consolidation",
                "Snapshot Consolidation",
                dc,
                cluster,
                host,
            )
        vm_path = _s(vm.get("Path"))
        if "]" in vm_path and "/" in vm_path:
            after_ds = vm_path.split("]", 1)[1].strip()
            folder_part = after_ds.split("/", 1)[0].strip()
            if folder_part and vm_name and folder_part != vm_name:
                add_finding(
                    vm_name,
                    f"VM datastore folder '{folder_part}' does not match display name '{vm_name}'",
                    "VM Consistent Foldername",
                    dc,
                    cluster,
                    host,
                )

    # 2. Snapshot count & age
    snap_counts: Dict[str, int] = {}
    for snap in vsnapshot_rows:
        vm_name = _s(snap.get("VM"))
        dc = _s(snap.get("Datacenter"))
        cluster = _s(snap.get("Cluster"))
        host = _s(snap.get("Host"))
        snap_counts[vm_name] = snap_counts.get(vm_name, 0) + 1
        try:
            age_days = int(float(_s(snap.get("Age (days)"), "0")))
        except ValueError:
            age_days = 0
        if age_days >= limits.SNAPSHOT_AGE_WARN_DAYS:
            add_finding(
                vm_name,
                f"Snapshot '{_s(snap.get('Name'))}' is {age_days} days old (threshold: {limits.SNAPSHOT_AGE_WARN_DAYS}d)",
                "Snapshot",
                dc,
                cluster,
                host,
            )

    for vm_name, count in sorted(snap_counts.items()):
        if count > limits.SNAPSHOT_COUNT_WARN:
            vm_meta = next((v for v in vinfo_rows if _s(v.get("VM")) == vm_name), {})
            add_finding(
                vm_name,
                f"VM has {count} active snapshots (threshold: {limits.SNAPSHOT_COUNT_WARN})",
                "Snapshot",
                _s(vm_meta.get("Datacenter")),
                _s(vm_meta.get("Cluster")),
                _s(vm_meta.get("Host")),
            )

    # 3. Connected CD-ROM on poweredOn VMs
    for cd in vcd_rows:
        if _s(cd.get("Powerstate")).lower() == "poweredon" and _b(cd.get("Connected")) == "True":
            add_finding(
                _s(cd.get("VM")),
                f"CD-ROM '{_s(cd.get('Device Node'))}' is connected and may impede vMotion",
                "CD-ROM Connected",
                _s(cd.get("Datacenter")),
                _s(cd.get("Cluster")),
                _s(cd.get("Host")),
            )

    # 4. VMware Tools status on poweredOn VMs
    for tools in vtools_rows:
        if _s(tools.get("Powerstate")).lower() != "poweredon" or _b(tools.get("Template")) == "True":
            continue
        status = _s(tools.get("Tools")).lower()
        if status in ("toolsnotinstalled", "guesttoolsnotinstalled", "toolsnotrunning", "guesttoolsnotrunning", "toolsold", "guesttoolsneedupgrade"):
            add_finding(
                _s(tools.get("VM")),
                f"VMware Tools status is '{_s(tools.get('Tools'))}'",
                "VMware Tools",
                _s(tools.get("Datacenter")),
                _s(tools.get("Cluster")),
                _s(tools.get("Host")),
            )

    # 5. Datastore free space & accessibility
    for ds in vdatastore_rows:
        ds_name = _s(ds.get("Name"))
        if _b(ds.get("Accessible"), "True") == "False":
            add_finding(
                ds_name,
                "Datastore is marked inaccessible",
                "Storage",
                "",
                _s(ds.get("Cluster name")),
                _s(ds.get("Hosts")),
            )
            continue
        try:
            free_pct = float(_s(ds.get("Free %"), "100"))
        except ValueError:
            free_pct = 100.0
        if free_pct < limits.DATASTORE_FREE_PCT_WARN:
            add_finding(
                ds_name,
                f"Datastore free space is {free_pct:.1f}% (threshold: {limits.DATASTORE_FREE_PCT_WARN:.1f}%)",
                "Datastore Free Space",
                "",
                _s(ds.get("Cluster name")),
                _s(ds.get("Hosts")),
            )

    # 6. Host health, quarantine, NTP, and SSH/Shell
    for host in vhost_rows:
        h_name = _s(host.get("Host"))
        dc = _s(host.get("Datacenter"))
        cluster = _s(host.get("Cluster"))
        cfg_status = _s(host.get("Config status")).lower()
        if cfg_status in ("red", "yellow"):
            add_finding(
                h_name,
                f"Host configuration status is '{cfg_status}'",
                "Host State",
                dc,
                cluster,
                h_name,
            )
        if _b(host.get("in Quarantine Mode")) == "True":
            add_finding(
                h_name,
                "Host is in Quarantine Mode",
                "Host State",
                dc,
                cluster,
                h_name,
            )
        if _b(host.get("NTPD running"), "True") == "False":
            add_finding(
                h_name,
                "NTP daemon (ntpd) is not running on ESXi host",
                "Host Security / Services",
                dc,
                cluster,
                h_name,
            )
        svc = services_by_host.get(h_name, {})
        if svc.get("TSM-SSH"):
            add_finding(
                h_name,
                "SSH service (TSM-SSH) is running on ESXi host",
                "Host Security / Services",
                dc,
                cluster,
                h_name,
            )
        if svc.get("TSM"):
            add_finding(
                h_name,
                "ESXi Shell (TSM) is running on ESXi host",
                "Host Security / Services",
                dc,
                cluster,
                h_name,
            )

    return findings


def assemble_snapshot_from_tab_dicts(
    *,
    vcenter_server: str,
    vcenter_version: str,
    vcenter_build: str,
    vcenter_uuid: str,
    vcenter_fullname: str,
    generated_utc: Optional[str] = None,
    scope_cluster: str = "",
    include_file_info: bool = False,
    tls_verified: bool = True,
    acknowledged: bool = True,
    warnings: Sequence[str] = (),
    tab_records: Mapping[str, Sequence[Mapping[str, Any]]],
    host_services: Optional[Mapping[str, Mapping[str, bool]]] = None,
    extra_headers: Optional[Mapping[str, Sequence[str]]] = None,
) -> VinvSnapshot:
    """Assemble a frozen 26-tab (or 27-tab with vFileInfo) VinvSnapshot from per-tab dictionaries."""
    gen_ts = generated_utc or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    vinfo_dicts = list(tab_records.get("vInfo", ()))
    vsnap_dicts = list(tab_records.get("vSnapshot", ()))
    vcd_dicts = list(tab_records.get("vCD", ()))
    vtools_dicts = list(tab_records.get("vTools", ()))
    vds_dicts = list(tab_records.get("vDatastore", ()))
    vhost_dicts = list(tab_records.get("vHost", ()))
    vcluster_dicts = list(tab_records.get("vCluster", ()))

    # Synthesize vHealth if not explicitly supplied
    explicit_health = list(tab_records.get("vHealth", ()))
    if explicit_health:
        health_rows = tuple(_row_from_mapping("vHealth", r) for r in explicit_health)
    else:
        health_rows = tuple(
            evaluate_vhealth_rows(
                vinfo_dicts,
                vsnap_dicts,
                vcd_dicts,
                vtools_dicts,
                vds_dicts,
                vhost_dicts,
                host_services=host_services,
                vc_server=vcenter_server,
                vc_uuid=vcenter_uuid,
            )
        )

    # Synthesize vMetaData if not explicitly supplied
    explicit_meta = list(tab_records.get("vMetaData", ()))
    if explicit_meta:
        meta_rows = tuple(_row_from_mapping("vMetaData", r) for r in explicit_meta)
    else:
        meta_rows = (
            _row_from_mapping(
                "vMetaData",
                {
                    "Tool": "VCF Readiness Assessment",
                    "Collection Warnings": "; ".join(warnings),
                    "TLS Verified": _b(tls_verified),
                    "Tool Version": TOOL_VERSION,
                    "Schema Version": SCHEMA_VERSION,
                    "Lifecycle": LIFECYCLE,
                    "Generated UTC": gen_ts,
                    "vCenter Server": vcenter_server,
                    "vCenter Version": vcenter_version,
                    "vCenter Build": vcenter_build,
                    "vCenter UUID": vcenter_uuid,
                    "Scope Cluster": scope_cluster or "All Clusters",
                    "Include FileInfo": _b(include_file_info),
                    "Total Hosts": str(len(vhost_dicts)),
                    "Total VMs": str(len(vinfo_dicts)),
                    "Total Clusters": str(len(vcluster_dicts)),
                    "Total Datastores": str(len(vds_dicts)),
                },
            ),
        )

    built_tabs: List[VinvTab] = []
    for tab_name in CORE_TAB_NAMES:
        headers = TAB_HEADERS[tab_name]
        if tab_name == "vHealth":
            rows = health_rows
        elif tab_name == "vMetaData":
            rows = meta_rows
        else:
            recs = tab_records.get(tab_name, ())
            dynamic = sorted(({str(h) for r in recs for h in r} | set((extra_headers or {}).get(tab_name, ()))) - set(headers) - set(HEADER_ALIASES.get(tab_name, {}).values()))
            headers = headers + tuple(dynamic)
            if len(headers) > limits.MAX_XLSX_COLUMNS:
                raise ValueError("inventory column limit exceeded")
            normalized = (with_aliases(tab_name, r) for r in recs)
            rows = tuple(tuple(_s(r.get(h, "")) for h in headers) for r in normalized)
        built_tabs.append(VinvTab(name=tab_name, headers=headers, rows=rows))

    if include_file_info or OPTIONAL_FILEINFO_TAB in tab_records:
        file_recs = tab_records.get(OPTIONAL_FILEINFO_TAB, ())
        built_tabs.append(
            VinvTab(
                name=OPTIONAL_FILEINFO_TAB,
                headers=TAB_HEADERS[OPTIONAL_FILEINFO_TAB],
                rows=tuple(_row_from_mapping(OPTIONAL_FILEINFO_TAB, r) for r in file_recs),
            )
        )

    return VinvSnapshot(
        vcenter_server=vcenter_server,
        vcenter_version=vcenter_version,
        vcenter_build=vcenter_build,
        vcenter_uuid=vcenter_uuid,
        vcenter_fullname=vcenter_fullname,
        generated_utc=gen_ts,
        scope_cluster=scope_cluster,
        include_file_info=include_file_info or (OPTIONAL_FILEINFO_TAB in tab_records),
        tls_verified=tls_verified,
        acknowledged=acknowledged,
        tabs=tuple(built_tabs),
        warnings=tuple(warnings),
    )


def snapshot_to_excel_sheet_dicts(
    snapshot: VinvSnapshot,
    unified_mode: bool = False,
) -> List[Dict[str, Any]]:
    """Convert VinvSnapshot tabs into sheet dicts compatible with excel_export._write_xlsx."""
    from vcf_hci.plugins.vinv.constants import UNIFIED_TAB_NAME_MAP

    sheets: List[Dict[str, Any]] = []
    for tab in snapshot.tabs:
        sheet_name = UNIFIED_TAB_NAME_MAP.get(tab.name, tab.name) if unified_mode else tab.name
        header_row = [(col, "header") for col in tab.headers]
        data_rows: List[List[Any]] = [header_row]
        for row in tab.rows:
            if tab.name == "vHealth" and len(row) >= 3:
                styled_row: List[Any] = list(row)
                styled_row[2] = (row[2], "yellow")
                data_rows.append(styled_row)
            else:
                data_rows.append(list(row))
        sheets.append({"name": sheet_name, "rows": data_rows})
    return sheets


__all__ = [
    "_b",
    "_iso_utc",
    "_kib_from_bytes",
    "_mib_from_bytes",
    "_pct",
    "_s",
    "assemble_snapshot_from_tab_dicts",
    "evaluate_vhealth_rows",
    "mask_license_key",
    "snapshot_to_excel_sheet_dicts",
]
