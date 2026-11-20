"""Reconcile Redfish BMC host scan results with vSphere Inventory (vinv) snapshots."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from vcf_hci.plugins.vinv.constants import RECONCILIATION_HEADERS, RECONCILIATION_TAB_NAME
from vcf_hci.plugins.vinv.models import HostMatchRecord, ReconciliationReport, VinvSnapshot

_INVALID_SERIALS = frozenset({
    "", "UNKNOWN", "NONE", "N/A", "NOT AVAILABLE", "DEFAULT STRING",
    "TO BE FILLED BY O.E.M.", "0000000", "00000000", "—", "-",
})


def normalize_uuid_hex(raw_uuid: Any) -> str:
    clean = re.sub(r"[^0-9a-fA-F]", "", str(raw_uuid or "")).lower()
    if len(clean) != 32 or clean == "0" * 32 or clean == "f" * 32:
        return ""
    return clean


def swap_smbios_uuid(clean_hex: str) -> str:
    """Convert between RFC 4122 big-endian and SMBIOS middle-endian UUID byte order."""
    if len(clean_hex) != 32:
        return ""
    return (
        clean_hex[6:8] + clean_hex[4:6] + clean_hex[2:4] + clean_hex[0:2]
        + clean_hex[10:12] + clean_hex[8:10]
        + clean_hex[14:16] + clean_hex[12:14]
        + clean_hex[16:]
    )


def uuid_variants(raw_uuid: Any) -> Tuple[str, str]:
    """Return (canonical_hex, swapped_hex) for a 32-hex UUID string, or ('', '')."""
    clean = normalize_uuid_hex(raw_uuid)
    if not clean:
        return "", ""
    return clean, swap_smbios_uuid(clean)


def _norm_serial(val: Any) -> str:
    s = str(val or "").strip().upper()
    return "" if s in _INVALID_SERIALS else s


def _norm_host_token(val: Any) -> str:
    s = str(val or "").strip().lower().rstrip(".")
    if not s or s in ("unknown", "none", "n/a", "localhost", "—", "-"):
        return ""
    return s


def _short_hostname(val: str) -> str:
    if not val or re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
        return val
    return val.split(".", 1)[0]


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        if val is None or val == "":
            return default
        return int(float(str(val).replace(",", "").strip()))
    except (TypeError, ValueError):
        return default


def _extract_bmc_ram_gib(host_data: Mapping[str, Any]) -> int:
    mem_sub = host_data.get("memory_subsystem") or {}
    total_gb = mem_sub.get("total_capacity_gb") or (host_data.get("system") or {}).get("total_memory_gb")
    return _safe_int(total_gb, 0)


def _extract_bmc_cores(host_data: Mapping[str, Any]) -> int:
    sys_info = host_data.get("system") or {}
    cpu_sum = sys_info.get("cpu_summary") or {}
    total_cores = cpu_sum.get("total_cores")
    if total_cores:
        return _safe_int(total_cores, 0)
    sockets = _safe_int(cpu_sum.get("populated_sockets") or cpu_sum.get("sockets"), 0)
    cps = _safe_int(cpu_sum.get("cores_per_socket"), 0)
    return sockets * cps if (sockets and cps) else 0


def _extract_bmc_macs(host_data: Mapping[str, Any]) -> Dict[str, Dict[str, str]]:
    macs: Dict[str, Dict[str, str]] = {}
    for nic in host_data.get("network_adapters") or ():
        if not isinstance(nic, dict):
            continue
        nic_name = str(nic.get("name") or nic.get("model") or nic.get("id") or "NIC")
        for port in nic.get("ports") or ():
            if not isinstance(port, dict):
                continue
            raw_mac = str(port.get("mac_address") or port.get("mac") or "").strip().lower()
            if len(raw_mac) >= 12 and raw_mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                macs[raw_mac] = {
                    "adapter": nic_name,
                    "port": str(port.get("port_id") or port.get("name") or ""),
                    "speed_gbps": str(port.get("speed_gbps") or port.get("link_speed_gbps") or ""),
                    "link_status": str(port.get("link_status") or ""),
                }
    return macs


def reconcile_fleet(
    all_results: Sequence[Mapping[str, Any]],
    snapshot: VinvSnapshot,
    manual_overrides: Optional[Mapping[str, str]] = None,
) -> ReconciliationReport:
    """Correlate Redfish BMC host dicts against vCenter vHost rows and evaluate discrepancies."""
    overrides = {str(k).strip().lower(): str(v).strip() for k, v in (manual_overrides or {}).items()}
    vhosts = list(snapshot.tab_dicts("vHost"))
    vclusters = {c.get("Name", ""): c for c in snapshot.tab_dicts("vCluster")}
    vnics_by_host: Dict[str, List[Dict[str, str]]] = {}
    for nic in snapshot.tab_dicts("vNIC"):
        vnics_by_host.setdefault(nic.get("Host", ""), []).append(nic)

    vswitches_by_host: Dict[str, List[Dict[str, str]]] = {}
    for vs in snapshot.tab_dicts("vSwitch"):
        vswitches_by_host.setdefault(vs.get("Host", ""), []).append(vs)

    vmks_by_host: Dict[str, List[Dict[str, str]]] = {}
    for vmk in snapshot.tab_dicts("vSC_VMK"):
        vmks_by_host.setdefault(vmk.get("Host", ""), []).append(vmk)

    vhealth_by_host: Dict[str, List[Dict[str, str]]] = {}
    for h_row in snapshot.tab_dicts("vHealth"):
        vhealth_by_host.setdefault(h_row.get("Host", ""), []).append(h_row)

    vms_by_host: Dict[str, List[Dict[str, str]]] = {}
    for vm in snapshot.tab_dicts("vInfo"):
        vms_by_host.setdefault(vm.get("Host", ""), []).append(vm)

    matched_vhost_indices: Set[int] = set()
    records: List[HostMatchRecord] = []
    matched_count = 0
    bmc_only_count = 0
    discrepancy_host_count = 0

    # Pre-index vHosts
    vhost_uuid_index: Dict[str, int] = {}
    vhost_serial_index: Dict[str, int] = {}
    vhost_name_index: Dict[str, int] = {}
    for idx, vh in enumerate(vhosts):
        u_canon, u_swap = uuid_variants(vh.get("UUID"))
        if u_canon:
            vhost_uuid_index.setdefault(u_canon, idx)
        if u_swap:
            vhost_uuid_index.setdefault(u_swap, idx)
        sn = _norm_serial(vh.get("Service tag"))
        if sn:
            vhost_serial_index.setdefault(sn, idx)
        h_tok = _norm_host_token(vh.get("Host"))
        if h_tok:
            vhost_name_index.setdefault(h_tok, idx)
            vhost_name_index.setdefault(_short_hostname(h_tok), idx)
        for vmk in vmks_by_host.get(vh.get("Host", ""), ()):
            vmk_ip = _norm_host_token(vmk.get("IP Address"))
            if vmk_ip:
                vhost_name_index.setdefault(vmk_ip, idx)

    for bmc in all_results:
        sys_info = bmc.get("system") or {}
        host_os = bmc.get("host_os") or {}
        bmc_ip = str(sys_info.get("ip") or sys_info.get("bmc_ip") or bmc.get("host") or "").strip()
        bmc_hostname = str(sys_info.get("dns_name") or sys_info.get("hostname") or host_os.get("hostname") or bmc_ip).strip()
        bmc_uuid_raw = sys_info.get("uuid") or sys_info.get("system_uuid") or ""
        b_canon, b_swap = uuid_variants(bmc_uuid_raw)
        bmc_serial = _norm_serial(sys_info.get("serial_number") or sys_info.get("service_tag"))

        matched_idx: Optional[int] = None
        match_method = "unmatched"
        uuid_detail = "Unmatched"

        # 1. Explicit override
        override_target = overrides.get(bmc_ip.lower()) or overrides.get(bmc_hostname.lower())
        if override_target:
            for idx, vh in enumerate(vhosts):
                if idx not in matched_vhost_indices and (
                    vh.get("Object ID") == override_target or vh.get("Host") == override_target
                ):
                    matched_idx = idx
                    match_method = "override"
                    uuid_detail = "Operator Override"
                    break

        # 2. UUID match (exact or SMBIOS byte-swapped)
        if matched_idx is None and b_canon:
            cand = vhost_uuid_index.get(b_canon)
            if cand is not None and cand not in matched_vhost_indices:
                matched_idx = cand
                vh_canon, _ = uuid_variants(vhosts[cand].get("UUID"))
                if vh_canon == b_canon:
                    match_method = "exact-uuid"
                    uuid_detail = "Exact UUID"
                else:
                    match_method = "swapped-uuid"
                    uuid_detail = "SMBIOS Byte-Swapped UUID"

        # 3. Serial / Service Tag match
        if matched_idx is None and bmc_serial:
            cand = vhost_serial_index.get(bmc_serial)
            if cand is not None and cand not in matched_vhost_indices:
                matched_idx = cand
                match_method = "exact-serial"
                uuid_detail = "Matched via Service Tag"

        # 4. Hostname / FQDN / VMK IP match
        if matched_idx is None:
            for candidate_name in (
                _norm_host_token(bmc_hostname),
                _short_hostname(_norm_host_token(bmc_hostname)),
                _norm_host_token(host_os.get("hostname")),
                _short_hostname(_norm_host_token(host_os.get("hostname"))),
                _norm_host_token(bmc_ip),
            ):
                if not candidate_name:
                    continue
                cand = vhost_name_index.get(candidate_name)
                if cand is not None and cand not in matched_vhost_indices:
                    matched_idx = cand
                    match_method = "hostname-ip"
                    uuid_detail = "Matched via Hostname/IP"
                    break

        bmc_cores = _extract_bmc_cores(bmc)
        bmc_ram_gib = _extract_bmc_ram_gib(bmc)
        bmc_bios = str(sys_info.get("bios_version") or "").strip()
        bmc_vendor_model = f"{sys_info.get('vendor', '')} {sys_info.get('model', '')}".strip()
        bmc_macs = _extract_bmc_macs(bmc)

        if matched_idx is None:
            bmc_only_count += 1
            records.append(
                HostMatchRecord(
                    match_status="BMC Only",
                    match_method="unmatched",
                    bmc_ip=bmc_ip,
                    bmc_hostname=bmc_hostname,
                    vcenter_server=snapshot.vcenter_server,
                    datacenter="—",
                    cluster="—",
                    esxi_host="Not found in vCenter",
                    esxi_object_id="",
                    connection_state="—",
                    vendor_model=bmc_vendor_model or "—",
                    service_tag_pair=f"{bmc_serial or '—'} / —",
                    uuid_match_detail="Not in vCenter",
                    bios_pair=f"{bmc_bios or '—'} / —",
                    cores_pair=f"{bmc_cores or '—'} / —",
                    ram_gib_pair=f"{bmc_ram_gib or '—'} / —",
                    memory_tiering="—",
                    esxi_version=str(host_os.get("version") or "—"),
                    vm_counts="—",
                    vcpu_allocation="—",
                    vram_gib="—",
                    nic_summary=f"{len(bmc_macs)} BMC MACs / —",
                    cluster_features="—",
                    vhealth_count=0,
                    discrepancies=("NOT_IN_VCENTER",),
                )
            )
            continue

        matched_vhost_indices.add(matched_idx)
        matched_count += 1
        vh = vhosts[matched_idx]
        vh_name = vh.get("Host", "")
        cluster_name = vh.get("Cluster", "")
        dc_name = vh.get("Datacenter", "")
        vh_serial = _norm_serial(vh.get("Service tag"))
        vh_bios = str(vh.get("BIOS Version") or "").strip()
        vh_cores = _safe_int(vh.get("# Cores"), 0)
        vh_ram_mib = _safe_int(vh.get("# Memory"), 0)
        vh_ram_gib = round(vh_ram_mib / 1024) if vh_ram_mib > 0 else 0
        vh_tiering = vh.get("Memory Tiering", "Unknown") or "Unknown"
        vh_nvme_mib = _safe_int(vh.get("NVMe Tier MiB"), 0)
        if vh_nvme_mib > 0:
            vh_tiering = f"{vh_tiering} ({round(vh_nvme_mib / 1024)} GiB NVMe)"

        vh_nics = vnics_by_host.get(vh_name, [])
        vh_macs = {str(n.get("MAC") or "").strip().lower(): n for n in vh_nics if n.get("MAC")}
        overlapping_macs = set(bmc_macs.keys()) & set(vh_macs.keys())

        discrepancies: List[str] = []
        if bmc_serial and vh_serial and bmc_serial != vh_serial:
            discrepancies.append(f"SERIAL_MISMATCH({bmc_serial} vs {vh_serial})")
        if bmc_bios and vh_bios and bmc_bios.lower() != vh_bios.lower():
            discrepancies.append(f"BIOS_MISMATCH({bmc_bios} vs {vh_bios})")
        if bmc_cores and vh_cores and bmc_cores != vh_cores:
            discrepancies.append(f"CPU_CORE_MISMATCH({bmc_cores} vs {vh_cores})")
        if bmc_ram_gib and vh_ram_gib and abs(bmc_ram_gib - vh_ram_gib) > 4:
            discrepancies.append(f"RAM_MISMATCH({bmc_ram_gib}GiB vs {vh_ram_gib}GiB)")

        # Check NIC speed degradation between BMC capability and vNIC negotiated speed
        for mac in sorted(overlapping_macs):
            b_spd = _safe_int(bmc_macs[mac].get("speed_gbps"), 0)
            v_spd_mbps = _safe_int(vh_macs[mac].get("Speed"), 0)
            v_spd_gbps = v_spd_mbps // 1000 if v_spd_mbps >= 1000 else 0
            if b_spd > 0 and v_spd_gbps > 0 and v_spd_gbps < b_spd:
                vmnic_dev = vh_macs[mac].get("Network Device", mac)
                discrepancies.append(f"NIC_DOWNSHIFT({vmnic_dev}:{v_spd_gbps}G<{b_spd}G)")

        if discrepancies:
            discrepancy_host_count += 1

        cl_row = vclusters.get(cluster_name, {})
        cl_features = (
            f"vSAN:{cl_row.get('vSAN enabled', '—')} | "
            f"EVC:{vh.get('Current EVC') or cl_row.get('EVC Mode') or 'None'} | "
            f"HA:{cl_row.get('HA enabled', '—')} | "
            f"DRS:{cl_row.get('DRS enabled', '—')}"
        )
        maint_str = "MaintMode" if vh.get("in Maintenance Mode") == "True" else "Active"
        conn_str = f"{vh.get('Config status', 'green')} / {maint_str}"
        vram_mib = _safe_int(vh.get("vRAM"), 0)
        vhealth_list = vhealth_by_host.get(vh_name, [])

        records.append(
            HostMatchRecord(
                match_status="Matched",
                match_method=match_method,
                bmc_ip=bmc_ip,
                bmc_hostname=bmc_hostname,
                vcenter_server=snapshot.vcenter_server,
                datacenter=dc_name or "—",
                cluster=cluster_name or "Standalone",
                esxi_host=vh_name,
                esxi_object_id=vh.get("Object ID", ""),
                connection_state=conn_str,
                vendor_model=bmc_vendor_model or f"{vh.get('Vendor', '')} {vh.get('Model', '')}".strip(),
                service_tag_pair=f"{bmc_serial or '—'} / {vh_serial or '—'}",
                uuid_match_detail=uuid_detail,
                bios_pair=f"{bmc_bios or '—'} / {vh_bios or '—'}",
                cores_pair=f"{bmc_cores or '—'} / {vh_cores or '—'}",
                ram_gib_pair=f"{bmc_ram_gib or '—'} / {vh_ram_gib or '—'}",
                memory_tiering=vh_tiering,
                esxi_version=vh.get("ESX Version") or "—",
                vm_counts=f"{vh.get('# VMs', '0')} / {vh.get('# VMs total', '0')}",
                vcpu_allocation=f"{vh.get('# vCPUs', '0')} ({vh.get('vCPUs per Core', '0')}:1)",
                vram_gib=f"{round(vram_mib / 1024, 1)}" if vram_mib else "0",
                nic_summary=f"{len(bmc_macs)} BMC / {len(vh_nics)} vNIC ({len(overlapping_macs)} MAC match)",
                cluster_features=cl_features,
                vhealth_count=len(vhealth_list),
                discrepancies=tuple(discrepancies),
            )
        )

    # Append vCenter-Only hosts (in vCenter inventory, but not scanned via Redfish BMC)
    vcenter_only_count = 0
    for idx, vh in enumerate(vhosts):
        if idx in matched_vhost_indices:
            continue
        vcenter_only_count += 1
        vh_name = vh.get("Host", "")
        cluster_name = vh.get("Cluster", "")
        dc_name = vh.get("Datacenter", "")
        vh_serial = _norm_serial(vh.get("Service tag"))
        vh_cores = _safe_int(vh.get("# Cores"), 0)
        vh_ram_mib = _safe_int(vh.get("# Memory"), 0)
        vh_ram_gib = round(vh_ram_mib / 1024) if vh_ram_mib > 0 else 0
        vh_nics = vnics_by_host.get(vh_name, [])
        vram_mib = _safe_int(vh.get("vRAM"), 0)
        vhealth_list = vhealth_by_host.get(vh_name, [])
        cl_row = vclusters.get(cluster_name, {})
        cl_features = (
            f"vSAN:{cl_row.get('vSAN enabled', '—')} | "
            f"EVC:{vh.get('Current EVC') or cl_row.get('EVC Mode') or 'None'} | "
            f"HA:{cl_row.get('HA enabled', '—')} | "
            f"DRS:{cl_row.get('DRS enabled', '—')}"
        )
        maint_str = "MaintMode" if vh.get("in Maintenance Mode") == "True" else "Active"
        records.append(
            HostMatchRecord(
                match_status="vCenter Only",
                match_method="unmatched",
                bmc_ip="Not scanned",
                bmc_hostname="—",
                vcenter_server=snapshot.vcenter_server,
                datacenter=dc_name or "—",
                cluster=cluster_name or "Standalone",
                esxi_host=vh_name,
                esxi_object_id=vh.get("Object ID", ""),
                connection_state=f"{vh.get('Config status', 'green')} / {maint_str}",
                vendor_model=f"{vh.get('Vendor', '')} {vh.get('Model', '')}".strip() or "—",
                service_tag_pair=f"— / {vh_serial or '—'}",
                uuid_match_detail="BMC Not Scanned",
                bios_pair=f"— / {vh.get('BIOS Version') or '—'}",
                cores_pair=f"— / {vh_cores or '—'}",
                ram_gib_pair=f"— / {vh_ram_gib or '—'}",
                memory_tiering=vh.get("Memory Tiering", "Unknown") or "Unknown",
                esxi_version=vh.get("ESX Version") or "—",
                vm_counts=f"{vh.get('# VMs', '0')} / {vh.get('# VMs total', '0')}",
                vcpu_allocation=f"{vh.get('# vCPUs', '0')} ({vh.get('vCPUs per Core', '0')}:1)",
                vram_gib=f"{round(vram_mib / 1024, 1)}" if vram_mib else "0",
                nic_summary=f"— / {len(vh_nics)} vNIC",
                cluster_features=cl_features,
                vhealth_count=len(vhealth_list),
                discrepancies=("BMC_NOT_SCANNED",),
            )
        )

    # Build Cluster Rollups
    cluster_map: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        if rec.cluster == "—":
            continue
        c_entry = cluster_map.setdefault(
            rec.cluster,
            {
                "cluster": rec.cluster,
                "datacenter": rec.datacenter,
                "vcenter_hosts": 0,
                "matched_bmc_hosts": 0,
                "unscanned_bmc_hosts": 0,
                "discrepancy_hosts": 0,
                "vhealth_findings": 0,
                "features": rec.cluster_features,
            },
        )
        c_entry["vcenter_hosts"] += 1
        if rec.match_status == "Matched":
            c_entry["matched_bmc_hosts"] += 1
            if rec.discrepancies:
                c_entry["discrepancy_hosts"] += 1
        elif rec.match_status == "vCenter Only":
            c_entry["unscanned_bmc_hosts"] += 1
        c_entry["vhealth_findings"] += rec.vhealth_count

    all_vms = snapshot.tab_dicts("vInfo")
    powered_on = sum(1 for v in all_vms if str(v.get("Powerstate", "")).lower() == "poweredon")

    return ReconciliationReport(
        vcenter_server=snapshot.vcenter_server,
        generated_utc=snapshot.generated_utc,
        matched_count=matched_count,
        bmc_only_count=bmc_only_count,
        vcenter_only_count=vcenter_only_count,
        discrepancy_host_count=discrepancy_host_count,
        total_vms=len(all_vms),
        powered_on_vms=powered_on,
        records=tuple(records),
        cluster_rollups=tuple(sorted(cluster_map.values(), key=lambda x: str(x["cluster"]))),
    )


_ESX_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")
_ESX_BUILD_RE = re.compile(r"build-(\d{6,9})")


def _backfilled_host_os(esx_full: str) -> Dict[str, Any]:
    """Return host_os fields in the collector's canonical shape for an ESXi version reported by vCenter."""
    from vcf_hci.collector.os_eval import _evaluate_os_info

    version = _ESX_VERSION_RE.search(esx_full)
    build = _ESX_BUILD_RE.search(esx_full)
    evaluated = _evaluate_os_info(
        {"name": "VMware ESXi", "version": version.group(1) if version else esx_full, "source": "vCenter Reconciliation"},
        {"os_build": build.group(1) if build else ""},
    )
    evaluated["agent_note"] = "Reported by vCenter reconciliation (experimental)"
    evaluated["os_description"] = esx_full
    evaluated["version"] = esx_full
    return evaluated


def enrich_redfish_results_with_vinv(
    all_results: Sequence[Dict[str, Any]],
    snapshot: VinvSnapshot,
    manual_overrides: Optional[Mapping[str, str]] = None,
) -> ReconciliationReport:
    """Attach vsphere_context to matched Redfish host dicts and backfill missing OS evidence."""
    report = reconcile_fleet(all_results, snapshot, manual_overrides=manual_overrides)
    vhosts_by_name = {vh.get("Host", ""): vh for vh in snapshot.tab_dicts("vHost")}
    vclusters_by_name = {c.get("Name", ""): c for c in snapshot.tab_dicts("vCluster")}
    vnics_by_host: Dict[str, List[Dict[str, str]]] = {}
    for nic in snapshot.tab_dicts("vNIC"):
        vnics_by_host.setdefault(nic.get("Host", ""), []).append(nic)
    vswitches_by_host: Dict[str, List[Dict[str, str]]] = {}
    for vs in snapshot.tab_dicts("vSwitch"):
        vswitches_by_host.setdefault(vs.get("Host", ""), []).append(vs)
    vmks_by_host: Dict[str, List[Dict[str, str]]] = {}
    for vmk in snapshot.tab_dicts("vSC_VMK"):
        vmks_by_host.setdefault(vmk.get("Host", ""), []).append(vmk)
    vhealth_by_host: Dict[str, List[Dict[str, str]]] = {}
    for h_row in snapshot.tab_dicts("vHealth"):
        vhealth_by_host.setdefault(h_row.get("Host", ""), []).append(h_row)
    vms_by_host: Dict[str, List[Dict[str, str]]] = {}
    for vm in snapshot.tab_dicts("vInfo"):
        vms_by_host.setdefault(vm.get("Host", ""), []).append(vm)

    matched_by_ip = {
        rec.bmc_ip: rec for rec in report.records if rec.match_status == "Matched" and rec.bmc_ip
    }

    for host_dict in all_results:
        sys_info = host_dict.get("system") or {}
        bmc_ip = str(sys_info.get("ip") or sys_info.get("bmc_ip") or host_dict.get("host") or "").strip()
        rec = matched_by_ip.get(bmc_ip)
        if rec is None:
            continue
        vh = vhosts_by_name.get(rec.esxi_host, {})
        cl = vclusters_by_name.get(rec.cluster, {})
        host_vnics = vnics_by_host.get(rec.esxi_host, [])
        mac_to_vnic = {
            str(n.get("MAC") or "").strip().lower(): {
                "vmnic": n.get("Network Device", ""),
                "driver": n.get("Driver", ""),
                "speed_mbps": n.get("Speed", ""),
                "switch": n.get("Switch", ""),
                "cdp_switch": n.get("CDP Switch", ""),
                "cdp_port": n.get("CDP Port", ""),
                "lldp_chassis": n.get("LLDP Chassis ID", ""),
                "lldp_port": n.get("LLDP Port ID", ""),
                "lldp_sysname": n.get("LLDP System Name", ""),
            }
            for n in host_vnics
            if n.get("MAC")
        }
        host_vms = vms_by_host.get(rec.esxi_host, [])
        host_dict["vsphere_context"] = {
            "vcenter_server": snapshot.vcenter_server,
            "vcenter_version": snapshot.vcenter_version,
            "datacenter": rec.datacenter,
            "cluster": rec.cluster,
            "esxi_host": rec.esxi_host,
            "esxi_object_id": rec.esxi_object_id,
            "match_method": rec.match_method,
            "uuid_match_detail": rec.uuid_match_detail,
            "esxi_version": vh.get("ESX Version", ""),
            "in_maintenance_mode": vh.get("in Maintenance Mode") == "True",
            "in_quarantine_mode": vh.get("in Quarantine Mode") == "True",
            "memory_tiering": vh.get("Memory Tiering", "Unknown"),
            "nvme_tier_mib": _safe_int(vh.get("NVMe Tier MiB"), 0),
            "evc_mode": vh.get("Current EVC") or cl.get("EVC Mode") or "Disabled",
            "max_evc_mode": vh.get("Max EVC", ""),
            "vsan_enabled": cl.get("vSAN enabled", "False") == "True",
            "ha_enabled": cl.get("HA enabled", "False") == "True",
            "drs_enabled": cl.get("DRS enabled", "False") == "True",
            "vm_count_active": _safe_int(vh.get("# VMs"), 0),
            "vm_count_total": _safe_int(vh.get("# VMs total"), 0),
            "vcpus_allocated": _safe_int(vh.get("# vCPUs"), 0),
            "vcpus_per_core": vh.get("vCPUs per Core", "0"),
            "vram_mib": _safe_int(vh.get("vRAM"), 0),
            "vm_used_memory_mib": _safe_int(vh.get("VM Used memory"), 0),
            "vswitches": [vs.get("Switch", "") for vs in vswitches_by_host.get(rec.esxi_host, [])],
            "vmk_ips": [
                {"device": vmk.get("Device", ""), "ip": vmk.get("IP Address", ""), "portgroup": vmk.get("Port Group", "")}
                for vmk in vmks_by_host.get(rec.esxi_host, [])
            ],
            "vnic_by_mac": mac_to_vnic,
            "vms_summary": [
                {
                    "name": v.get("VM", ""),
                    "powerstate": v.get("Powerstate", ""),
                    "cpus": v.get("CPUs", ""),
                    "memory_mib": v.get("Memory", ""),
                    "os": v.get("OS according to the configuration file", ""),
                }
                for v in host_vms[:50]
            ],
            "vhealth_findings": [
                {"name": f.get("Name", ""), "type": f.get("Message type", ""), "message": f.get("Message", "")}
                for f in vhealth_by_host.get(rec.esxi_host, [])
            ],
            "discrepancies": list(rec.discrepancies),
        }

        host_os = host_dict.get("host_os")
        if not isinstance(host_os, dict):
            host_os = host_dict["host_os"] = {}
        esx_full = str(vh.get("ESX Version") or "")
        if esx_full and not (host_os.get("os_name") or host_os.get("os_version")):
            host_os.update(_backfilled_host_os(esx_full))
        if not host_os.get("hostname") and rec.esxi_host:
            host_os["hostname"] = rec.esxi_host

    return report


def build_reconciliation_excel_sheet(report: ReconciliationReport) -> Dict[str, Any]:
    """Build the 'Reconciliation' worksheet dict for excel_export._write_xlsx."""
    header_row = [(h, "header") for h in RECONCILIATION_HEADERS]
    rows: List[List[Any]] = [header_row]
    for rec in report.records:
        if rec.match_status == "Matched":
            status_cell = (rec.match_status, "yellow" if rec.discrepancies else "green")
        elif rec.match_status == "BMC Only":
            status_cell = (rec.match_status, "yellow")
        else:
            status_cell = (rec.match_status, "red")

        disc_text = "; ".join(rec.discrepancies) if rec.discrepancies else "None"
        disc_cell = (disc_text, "yellow" if rec.discrepancies else "green")
        rows.append([
            status_cell,
            rec.match_method,
            rec.bmc_ip,
            rec.bmc_hostname,
            rec.vcenter_server,
            rec.datacenter,
            rec.cluster,
            rec.esxi_host,
            rec.connection_state,
            rec.vendor_model,
            rec.service_tag_pair,
            rec.uuid_match_detail,
            rec.bios_pair,
            rec.cores_pair,
            rec.ram_gib_pair,
            rec.memory_tiering,
            rec.esxi_version,
            rec.vm_counts,
            rec.vcpu_allocation,
            rec.vram_gib,
            rec.nic_summary,
            rec.cluster_features,
            str(rec.vhealth_count),
            disc_cell,
        ])
    return {"name": RECONCILIATION_TAB_NAME, "rows": rows}
