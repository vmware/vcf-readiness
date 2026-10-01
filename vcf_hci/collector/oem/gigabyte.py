"""
VCF Readiness Tool — GIGABYTE Server BMC OEM adapter.

Handles GIGABYTE server BMC Redfish quirks:
  • Redfish root at standard path /redfish/v1.
  • Fast-path roots at /redfish/v1/Systems/Self, /redfish/v1/Chassis/Self, /redfish/v1/Managers/Self (AMI MegaRAC).
  • Fallback manager URIs include /redfish/v1/Managers/Self and /redfish/v1/Managers/1.
  • Storage endpoints probed via /SimpleStorage (avoiding duplicate /Storage).
  • Drive OEM telemetry under Oem.GBT (with SlotNumber support) and legacy Oem.Gigabyte alias.
  • SKU resolution prefers PartNumber when SKU is composite, empty, or placeholder.
  • Honest static license badge for AMI MegaRAC BMC.
"""
from typing import Any, Dict, List, Optional, Tuple

from ...logging_utils import get_nested
from ..base import ExpandableCollectionsMap
from .generic import GenericCollector


class GigabyteCollector(GenericCollector):
    """GIGABYTE Server Redfish adapter."""

    vendor: str = "gigabyte"
    VENDOR_MATCH = ("GIGABYTE", "GIGA-BYTE")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # GIGABYTE (AMI MegaRAC SP-X / OpenBMC) supports OData $expand=* by default
        self.expand_syntax = "*"
        self.expand_max_levels = 2
        self.expand_supported = True

    def oem_expandable_collections(self) -> Dict[str, str]:
        """GIGABYTE (AMI MegaRAC) expandable collection endpoints.

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
        """Probe /redfish/v1/Systems/Self fastpath for GIGABYTE BMCs."""
        test_sys = self._get("/redfish/v1/Systems/Self")
        if test_sys and isinstance(test_sys, dict) and not test_sys.get("error"):
            return (
                ["/redfish/v1/Systems/Self"],
                ["/redfish/v1/Chassis/Self"],
                ["/redfish/v1/Managers/Self"],
            )
        return None

    def oem_manager_paths(self) -> List[str]:
        """Add GIGABYTE-specific manager path fallbacks."""
        return [
            "/redfish/v1/Managers/Self",
            "/redfish/v1/Managers/1",
        ]

    def oem_storage_endpoints(self) -> List[str]:
        """Add GIGABYTE SimpleStorage fallback path if available."""
        if self.sys_uri:
            return [f"{self.sys_uri}/SimpleStorage"]
        return []

    def oem_drive_metrics(self, drive_json: dict) -> dict:
        """Read GIGABYTE drive telemetry metrics from Oem.GBT or Oem.Gigabyte."""
        g_oem = None
        for key in ("GBT", "Gbt", "Gigabyte"):
            cand = get_nested(drive_json, "Oem", key, default=None)
            if isinstance(cand, dict) and cand:
                g_oem = cand
                break
        if not isinstance(g_oem, dict):
            return {}
        res = {}
        poh = g_oem.get("PowerOnHours") or g_oem.get("OperationHours")
        if poh is not None:
            try:
                res["power_on_hours"] = float(poh)
            except (TypeError, ValueError):
                pass
        part = g_oem.get("PartNumber") or g_oem.get("FRU")
        if part:
            res["part_number"] = str(part).strip()
        slot = g_oem.get("SlotNumber")
        if slot is not None:
            res["slot_number"] = str(slot).strip()
        return res

    def oem_sku(self, sys_data: dict) -> str:
        """Extract SKU or PartNumber for GIGABYTE platforms."""
        sku = str(sys_data.get("SKU") or "").strip()
        part = str(sys_data.get("PartNumber") or "").strip()
        model = str(sys_data.get("Model") or "").strip()
        sku_upper = sku.upper()
        is_placeholder = any(token in sku_upper for token in ("PLACEHOLDER", "ANON", "REDACTED"))
        if part and (not sku or " " in sku or "(" in sku or sku.lower() == model.lower() or is_placeholder):
            return part
        return sku

    def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict:
        """Return GIGABYTE BMC license information."""
        return {
            "license_name": "GIGABYTE BMC",
            "badge": "<span class='badge success'>🟢 GIGABYTE BMC — no inventory license required</span>",
            "vendor_note": (
                "GIGABYTE server BMC (AMI MegaRAC) provides full Redfish inventory access "
                "without additional licensing."
            ),
        }
