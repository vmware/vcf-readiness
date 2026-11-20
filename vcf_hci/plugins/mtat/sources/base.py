"""Adapter boundary. Implementations arrive in later phases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

from vcf_hci.plugins.mtat.intervals import HistoricalInterval
from vcf_hci.plugins.mtat.models import Assessment, Secret


@dataclass(frozen=True)
class CollectionRequest:
    source_kind: str
    endpoint: str
    username: str
    password: Secret
    cluster: str
    range_name: str
    verify_tls: bool = True
    ca_file: Optional[str] = None
    auth_source: str = ""
    policy: str = "mtat-3.2"
    acknowledged: bool = False
    certificate_pin: str = ""


@dataclass(frozen=True)
class PreflightReport:
    ready: bool
    source_version: str
    tls_verified: bool
    capabilities: dict[str, bool]
    messages: tuple[str, ...]
    clusters: tuple[dict[str, str], ...] = ()
    historical_intervals: tuple[HistoricalInterval, ...] = ()


class ProgressSink(Protocol):
    def update(self, stage: str, completed: int, total: int, message: str) -> None:
        """Report bounded progress without secrets or raw endpoint faults."""


class SourceAdapter(Protocol):
    kind: str

    def preflight(self, request: CollectionRequest) -> PreflightReport:
        """Validate the selected endpoint without starting full collection."""

    def collect(self, request: CollectionRequest, progress: ProgressSink) -> Assessment:
        """Return normalized evidence for one endpoint and one selected scope."""

    def close(self) -> None:
        """Release sessions, tokens, and sockets."""
