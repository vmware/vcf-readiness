"""Shared boundaries for gradual typing of normalized collector evidence.

Raw vendor JSON remains open-ended. Physical core/thread/socket fields describe
hardware, never VM allocations. Adapter identity and port identity are distinct.
"""
from typing import Any, Dict, Optional, Protocol, TypedDict


class CollectorTransport(Protocol):
    """HTTP surface consumed by collection hooks; no compatibility dependencies."""

    def _get(self, endpoint: str, _retry: bool = True, timeout: int = 15,
             critical: bool = True) -> Optional[Dict]: ...

    def _get_members(self, endpoint_or_data, limit: int = 0, max_pages: int = 100) -> list: ...


class NetworkCollector(CollectorTransport, Protocol):
    """Existing collector capabilities consumed by NIC acquisition and OEM hooks.

    Describes the passed collector; it is not a transport wrapper or runtime object.
    Optional fast paths still use their original hasattr/getattr guards.
    """

    sys_uri: Optional[str]
    chassis_uri: Optional[str]
    expand_supported: bool
    _request_cache: Dict
    host_url: str

    def _populate_request_cache(self, endpoint: str, data: dict) -> None: ...
    def _is_cancelled_or_skipped(self) -> bool: ...
    def _resolve_product_name(self, raw_obj: dict, pcie_cache: Optional[list] = None) -> str: ...
    def _extract_nic_speed_gbps(self, port: dict, adapter: dict, resolved_name: str = "") -> float: ...
    def oem_expandable_collections(self) -> Any: ...
    def oem_port_transceiver(self, port_json: dict) -> dict: ...
    def oem_vnic_capabilities(self, fn_json: dict) -> dict: ...
    def oem_nic_firmware(self, adapter_json: dict) -> str: ...
    def oem_pcie_link_status(self, dev_dict: dict) -> Optional[dict]: ...


class SystemCollector(CollectorTransport, Protocol):
    """Existing acquisition capabilities consumed by system evidence helpers."""

    host: str
    sys_uri: Optional[str]
    chassis_uri: Optional[str]
    chassis_uris: list

    def oem_sku(self, sys_data: dict) -> str: ...
    def oem_cpu_cache(self, proc_json: dict) -> list: ...
    def oem_os_info(self, sys_data: dict) -> dict: ...


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
