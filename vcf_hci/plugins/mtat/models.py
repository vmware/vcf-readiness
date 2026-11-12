"""Evidence records. Adapters fill them; calculations and exporters do not query endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class Secret:
    """Credential that stays redacted in repr and str."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value:
            raise ValueError("credential must be a non-empty string")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(redacted)"

    def __str__(self) -> str:
        return "redacted"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and self._value == other._value


@dataclass(frozen=True)
class SampleSeries:
    values: tuple[int, ...]
    encoding: str
    source_key: str
    interval_seconds: Optional[int] = None

    def __post_init__(self) -> None:
        if self.encoding not in {"kibibytes", "bytes", "percent", "hundredths"}:
            raise ValueError("unsupported sample encoding")


@dataclass(frozen=True)
class TierEntry:
    kind: str
    size_bytes: int

    def __post_init__(self) -> None:
        if self.kind not in {"DRAM", "NVMe", "other"} or self.size_bytes < 0:
            raise ValueError("invalid tier entry")


@dataclass(frozen=True)
class HostEvidence:
    cluster_name: str
    host_name: str
    host_key: str
    mode: str
    memory_size_bytes: Optional[int] = None
    tier_entries: tuple[TierEntry, ...] = ()
    tier_properties_supported: bool = True
    tier_observation: Optional[str] = None
    tier_error: str = ""
    nvme_pct_fallback: Optional[int] = None
    cpu: Optional[SampleSeries] = None
    consumed: Optional[SampleSeries] = None
    active: Optional[SampleSeries] = None
    cpu_mhz: Optional[int] = None
    connection_state: str = "connected"
    collection_error: str = ""

    def __post_init__(self) -> None:
        if self.mode not in {"historical", "realtime"}:
            raise ValueError("unsupported collection mode")


@dataclass(frozen=True)
class VmEvidence:
    host_name: str
    vm_name: str
    vm_key: str
    host_key: str
    power_state: str
    provisioned_bytes: Optional[int] = None
    active: Optional[SampleSeries] = None
    eligibility_flags: tuple[str, ...] = ()
    eligibility_assessed: bool = True
    pages_1gb: str = "Unknown"
    pages_2mb: str = "Unknown"
    collection_error: str = ""


@dataclass(frozen=True)
class Provenance:
    metric: str
    source_key: str
    encoding: str
    authority: str


@dataclass(frozen=True)
class HostRow:
    cluster: str
    host_name: str
    tiering: str
    cpu_pct: object
    physical_ram_gb: object
    consumed_gb: object
    active_gb: object
    active_pct: object
    tier_ratio_pct: object
    active_avg_gb: object
    nvme_gb: object
    missing_metrics: str
    cpu_mhz: Optional[int]
    provenance: tuple[Provenance, ...] = ()


@dataclass(frozen=True)
class VmRow:
    host_name: str
    vm_name: str
    provisioned_gb: object
    active_gb: object
    active_pct: object
    dram_only: str
    pages_1gb: str
    pages_2mb: str
    missing_metrics: str
    eligibility_policy: str
    eligibility_reasons: tuple[str, ...] = ()
    current_policy_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class Assessment:
    range_name: str
    source_kind: str
    source_label: str
    source_version: str
    policy: str
    hosts: tuple[HostRow, ...]
    vms: tuple[VmRow, ...]
    failed_vms: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    tls_verified: Optional[bool] = None
    validation_lane: str = "unvalidated"
    acknowledged: bool = False
