"""Turn normalized evidence into MTAT rows."""

from __future__ import annotations

from decimal import Decimal
from typing import Optional

from vcf_hci.plugins.mtat.constants import DEFAULT_CSV_POLICY, MISSING_ORDER, POLICY_VSPHERE_CURRENT
from vcf_hci.plugins.mtat.eligibility import dram_only_cell, reasons_for
from vcf_hci.plugins.mtat.models import Assessment, HostEvidence, HostRow, Provenance, VmEvidence, VmRow
from vcf_hci.plugins.mtat.numbers import bytes_to_gb, percent
from vcf_hci.plugins.mtat.series import average, maximum
from vcf_hci.plugins.mtat.tiering import physical_bytes, resolve_tiering


def _join_missing(tokens: list[str]) -> str:
    ordered = [token for token in MISSING_ORDER if token in tokens]
    return ", ".join(ordered)


def _metric(value: Optional[Decimal], token: str, missing: list[str]) -> Decimal:
    if value is None:
        missing.append(token)
        return Decimal(0)
    return value


def assess_host(host: HostEvidence) -> HostRow:
    if host.collection_error:
        return HostRow(host.cluster_name, host.host_name, "ERROR", Decimal(0), Decimal(0), Decimal(0), Decimal(0), Decimal(0), Decimal(0), None, None, "", None)
    tier = resolve_tiering(host.tier_entries, host.tier_properties_supported, host.tier_observation, host.tier_error, host.nvme_pct_fallback)
    dram_bytes = tier["dram_bytes"] if isinstance(tier["dram_bytes"], int) else None
    physical = physical_bytes(host.memory_size_bytes, dram_bytes)
    physical_gb = bytes_to_gb(physical) if physical else Decimal(0)
    missing: list[str] = []
    disconnected = host.connection_state.lower() in {"disconnected", "notresponding"}
    if disconnected:
        cpu = consumed = active = active_avg = Decimal(0)
        missing.extend(MISSING_ORDER)
    elif host.mode == "historical":
        cpu = _metric(average(host.cpu), "CPU", missing)
        consumed = _metric(average(host.consumed), "Consumed", missing)
        active = _metric(maximum(host.active), "Active", missing)
        active_avg = _metric(average(host.active), "Active", missing)
    else:
        cpu = _metric(average(host.cpu), "CPU", missing)
        consumed = _metric(average(host.consumed), "Consumed", missing)
        active = _metric(maximum(host.active), "Active", missing)
        active_avg = active
    nvme_gb = bytes_to_gb(tier["nvme_bytes"]) if isinstance(tier["nvme_bytes"], int) else None
    provenance = []
    if host.cpu is not None:
        provenance.append(Provenance("CPU", host.cpu.source_key, host.cpu.encoding, "measured"))
    if tier["fallback"]:
        provenance.append(Provenance("NVMe", "Mem.TierNVMePct", "percent", "proxy"))
    return HostRow(
        host.cluster_name,
        host.host_name,
        str(tier["status"]),
        cpu,
        physical_gb,
        consumed,
        active,
        percent(active, physical_gb, 1),
        tier["ratio"],
        active_avg,
        nvme_gb,
        _join_missing(missing),
        host.cpu_mhz,
        tuple(provenance),
    )


def assess_vm(vm: VmEvidence, policy: str = DEFAULT_CSV_POLICY) -> Optional[VmRow]:
    if vm.power_state.lower() not in {"poweredon", "powered_on"}:
        return None
    if vm.collection_error:
        return None
    missing: list[str] = []
    active = maximum(vm.active)
    if active is None:
        missing.append("Active")
        active = Decimal(0)
    provisioned = bytes_to_gb(vm.provisioned_bytes) if vm.provisioned_bytes else None
    active_pct = percent(active, provisioned, 1) if provisioned is not None else Decimal(0)
    return VmRow(
        vm.host_name,
        vm.vm_name,
        provisioned,
        active,
        active_pct,
        dram_only_cell(vm.eligibility_flags, policy, vm.eligibility_assessed),
        vm.pages_1gb,
        vm.pages_2mb,
        ", ".join(missing),
        policy,
        reasons_for(vm.eligibility_flags, policy) if vm.eligibility_assessed else (),
        reasons_for(vm.eligibility_flags, POLICY_VSPHERE_CURRENT) if vm.eligibility_assessed else (),
    )


def assess(range_name: str, source_kind: str, source_label: str, source_version: str, hosts: tuple[HostEvidence, ...], vms: tuple[VmEvidence, ...], policy: str = DEFAULT_CSV_POLICY, tls_verified: Optional[bool] = None, acknowledged: bool = False) -> Assessment:
    failed = tuple("%s/%s" % (vm.host_name, vm.vm_name) for vm in vms if vm.collection_error)
    rows = tuple(row for row in (assess_vm(vm, policy) for vm in vms) if row is not None)
    return Assessment(range_name, source_kind, source_label, source_version, policy, tuple(assess_host(host) for host in hosts), rows, failed, (), tls_verified, "unvalidated", acknowledged)
