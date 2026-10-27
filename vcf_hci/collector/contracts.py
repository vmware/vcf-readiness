"""Shared boundaries for gradual typing of normalized collector evidence.

Raw vendor JSON remains open-ended. Physical core/thread/socket fields describe
hardware, never VM allocations. Adapter identity and port identity are distinct.
"""
from typing import Dict, Optional, Protocol, TypedDict


class CollectorTransport(Protocol):
    """HTTP surface consumed by collection hooks; no compatibility dependencies."""

    def _get(self, endpoint: str, _retry: bool = True, timeout: int = 15,
             critical: bool = True) -> Optional[Dict]: ...

    def _get_members(self, endpoint_or_data, limit: int = 0, max_pages: int = 100) -> list: ...


class CPUInventory(TypedDict, total=False):
    count: int  # populated physical sockets
    core_count: int  # physical cores across sockets
    logical_count: int  # hardware threads, not allocated vCPUs
    model: str


class FCPortIdentity(TypedDict, total=False):
    physical_adapter_id: str
    adapter_id: str
    physical_port_id: str
    port_id: str
    pci_slot: str
    slot: str
    wwpn: str
    wwnn: str
