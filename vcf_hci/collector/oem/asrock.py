"""
VCF Readiness Tool — ASRock Rack Server BMC OEM adapter.

Handles ASRock Rack server BMC Redfish quirks:
  • Redfish root at standard path /redfish/v1.
  • Fast-path roots at /redfish/v1/Systems/Self, /redfish/v1/Chassis/Self, /redfish/v1/Managers/Self (AMI MegaRAC).
  • Fallback manager URIs include /redfish/v1/Managers/Self and /redfish/v1/Managers/1.
  • Motherboard FRU fallback via /redfish/v1/Systems/Self/FruInfo when SMBIOS DMI is unfilled.
  • SKU resolution prefers Board.PartNumber from FruInfo when DMI SKU is missing or placeholder.
  • Static license badge for AMI MegaRAC BMC.
"""
from typing import Any, Dict, List, Optional, Tuple

from ...logging_utils import get_nested
from ..base import ExpandableCollectionsMap
from .generic import GenericCollector


class ASRockCollector(GenericCollector):
    """ASRock Rack Server Redfish adapter."""

    vendor: str = "asrock"
    VENDOR_MATCH = (
        "ASROCK",
        "ASROCKRACK",
        "ASROCK RACK",
        "ROMED8",
        "EPYCD8",
        "GENOAD8",
        "BERGAMOD8",
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # ASRock Rack (AMI MegaRAC SP-X) supports OData $expand=* by default
        self.expand_syntax = "*"
        self.expand_max_levels = 2
        self.expand_supported = True

    def oem_expandable_collections(self) -> Dict[str, str]:
        """ASRock Rack (AMI MegaRAC) expandable collection endpoints.

        AMI MegaRAC BMCs support OData $expand=* on:
          - Systems/Self/Storage (and Systems/1/Storage)
          - Systems/Self/Memory (and Systems/1/Memory)
        """
        sys_uri = getattr(self, "sys_uri", None) or "/redfish/v1/Systems/Self"
        storage_ep = f"{sys_uri}/Storage"
        mem_ep = f"{sys_uri}/Memory"
        mapping = {
            "storage": storage_ep,
            storage_ep: storage_ep,
            "memory": mem_ep,
            mem_ep: mem_ep,
        }
        levels = {
            "storage": 1,
            storage_ep: 1,
            "memory": 1,
            mem_ep: 1,
        }
        for alt_sys in ("/redfish/v1/Systems/Self", "/redfish/v1/Systems/1"):
            mapping[f"{alt_sys}/Storage"] = f"{alt_sys}/Storage"
            mapping[f"{alt_sys}/Memory"] = f"{alt_sys}/Memory"
            levels[f"{alt_sys}/Storage"] = 1
            levels[f"{alt_sys}/Memory"] = 1
        return ExpandableCollectionsMap(mapping, levels=levels)

    def oem_fastpath_roots(self) -> Optional[Tuple[List[str], List[str], List[str]]]:
        """Probe /redfish/v1/Systems/Self fastpath for ASRock Rack BMCs."""
        test_sys = self._get("/redfish/v1/Systems/Self")
        if test_sys and isinstance(test_sys, dict) and not test_sys.get("error"):
            return (
                ["/redfish/v1/Systems/Self"],
                ["/redfish/v1/Chassis/Self"],
                ["/redfish/v1/Managers/Self"],
            )
        return None

    def oem_manager_paths(self) -> List[str]:
        """Add ASRock Rack-specific manager path fallbacks."""
        return [
            "/redfish/v1/Managers/Self",
            "/redfish/v1/Managers/1",
        ]

    def oem_sku(self, sys_data: dict) -> str:
        """Extract SKU or PartNumber for ASRock Rack platforms.

        Falls back to Board.PartNumber from FruInfo if SMBIOS SKU is blank or placeholder.
        """
        sku = str(sys_data.get("SKU") or "").strip()
        part = str(sys_data.get("PartNumber") or "").strip()
        model = str(sys_data.get("Model") or "").strip()
        sku_upper = sku.upper()
        is_placeholder = (
            not sku
            or any(token in sku_upper for token in ("PLACEHOLDER", "ANON", "REDACTED", "TO BE FILLED"))
            or sku.lower() == model.lower()
        )
        if not is_placeholder and sku:
            return sku
        if part and part.upper() not in ("TO BE FILLED BY O.E.M.", "UNKNOWN", "N/A", "NONE"):
            return part

        # Probe FruInfo endpoint
        sys_uri = getattr(self, "sys_uri", "") or "/redfish/v1/Systems/Self"
        fru_info = self._get(f"{sys_uri}/FruInfo")
        if isinstance(fru_info, dict):
            board_part = str(get_nested(fru_info, "Board", "PartNumber") or "").strip()
            if board_part and board_part.upper() not in ("UNKNOWN", "NONE", "N/A"):
                return board_part

        return part or sku

    def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict:
        """Return ASRock Rack BMC license information."""
        return {
            "license_name": "ASRock Rack BMC",
            "badge": "<span class='badge success'>🟢 ASRock Rack BMC — no inventory license required</span>",
            "vendor_note": (
                "ASRock Rack server BMC (AMI MegaRAC) provides full Redfish inventory access "
                "without additional licensing."
            ),
        }
