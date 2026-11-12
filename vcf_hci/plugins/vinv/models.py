"""Data models for vSphere Inventory collection, workbooks, and BMC reconciliation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol, Tuple

from vcf_hci.plugins.vinv.parity import with_aliases


class Secret:
    """In-memory secret wrapper that never exposes credentials in repr or str."""

    def __init__(self, value: str) -> None:
        self._value = str(value or "")

    def reveal(self) -> str:
        return self._value

    def clear(self) -> None:
        self._value = ""

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


class ProgressSink(Protocol):
    def update(self, stage: str, completed: int, total: int, message: str) -> None: ...


@dataclass(frozen=True)
class VinvRequest:
    endpoint: str
    username: str
    password: Secret
    cluster: str = ""
    verify_tls: bool = True
    ca_file: Optional[str] = None
    include_network_hints: bool = True
    include_file_info: bool = False
    acknowledged: bool = False
    certificate_pin: str = ""


@dataclass(frozen=True)
class VinvPreflight:
    ok: bool
    server_version: str
    server_build: str
    server_uuid: str
    verify_tls: bool
    clusters: Tuple[Dict[str, str], ...]
    host_count: int
    vm_count: int
    datastore_count: int
    messages: Tuple[str, ...] = ()


@dataclass(frozen=True)
class VinvTab:
    name: str
    headers: Tuple[str, ...]
    rows: Tuple[Tuple[str, ...], ...]


@dataclass(frozen=True)
class VinvSnapshot:
    vcenter_server: str
    vcenter_version: str
    vcenter_build: str
    vcenter_uuid: str
    vcenter_fullname: str
    generated_utc: str
    scope_cluster: str
    include_file_info: bool
    tls_verified: bool
    acknowledged: bool
    tabs: Tuple[VinvTab, ...]
    warnings: Tuple[str, ...] = ()

    @property
    def verify_tls(self) -> bool:
        return self.tls_verified

    def get_tab(self, name: str) -> Optional[VinvTab]:
        for tab in self.tabs:
            if tab.name == name:
                return tab
        return None

    def tab_dicts(self, name: str) -> Tuple[Dict[str, str], ...]:
        tab = self.get_tab(name)
        if tab is None:
            return ()
        return tuple(with_aliases(name, dict(zip(tab.headers, row))) for row in tab.rows)


@dataclass(frozen=True)
class HostMatchRecord:
    match_status: str  # "Matched" | "BMC Only" | "vCenter Only"
    match_method: str  # "override" | "exact-uuid" | "swapped-uuid" | "exact-serial" | "hostname-ip" | "unmatched"
    bmc_ip: str
    bmc_hostname: str
    vcenter_server: str
    datacenter: str
    cluster: str
    esxi_host: str
    esxi_object_id: str
    connection_state: str
    vendor_model: str
    service_tag_pair: str
    uuid_match_detail: str
    bios_pair: str
    cores_pair: str
    ram_gib_pair: str
    memory_tiering: str
    esxi_version: str
    vm_counts: str
    vcpu_allocation: str
    vram_gib: str
    nic_summary: str
    cluster_features: str
    vhealth_count: int
    discrepancies: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ReconciliationReport:
    vcenter_server: str
    generated_utc: str
    matched_count: int
    bmc_only_count: int
    vcenter_only_count: int
    discrepancy_host_count: int
    total_vms: int
    powered_on_vms: int
    records: Tuple[HostMatchRecord, ...]
    cluster_rollups: Tuple[Dict[str, Any], ...] = ()
