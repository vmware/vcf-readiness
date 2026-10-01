"""
VCF Readiness Tool — Quanta Cloud Technology (QCT) BMC OEM adapter.

Handles Quanta BMC (QuantaGrid / QuantaPlex) Redfish quirks:
  • Redfish root at standard path /redfish/v1.
  • Fast-path roots at /redfish/v1/Systems/Self, /redfish/v1/Chassis/Self, /redfish/v1/Managers/Self.
  • Fallback manager URIs include /redfish/v1/Managers/Self and /redfish/v1/Managers/1.
  • Storage endpoints probed via /SimpleStorage (avoiding duplicate /Storage).
  • Drive OEM telemetry under Oem.Quanta_RackScale (with legacy Oem.Quanta / Oem.QCT aliases).
  • SKU resolution prefers PartNumber when SKU is composite or empty.
  • Honest static license badge without extra network queries.
"""
from typing import Any, List, Optional, Tuple

from ...logging_utils import get_nested
from .generic import GenericCollector


class QuantaCollector(GenericCollector):
    """Quanta Cloud Technology (QCT) Redfish adapter."""

    vendor: str = "quanta"
    VENDOR_MATCH = ("QUANTA", "QCT")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Quanta BMC (QuantaGrid / QuantaPlex) does not support OData $expand;
        # enforce unexpanded iterative collection across shallow crawl leaves.
        self.expand_supported = False
        self.expand_syntax = None

    def oem_expandable_collections(self) -> dict:
        """Quanta BMC does not support collection expansion."""
        return {}

    def oem_fastpath_roots(self) -> Optional[Tuple[List[str], List[str], List[str]]]:
        """Probe /redfish/v1/Systems/Self fastpath for Quanta/QCT BMCs."""
        self.expand_supported = False
        self.expand_syntax = None
        test_sys = self._get("/redfish/v1/Systems/Self")
        if test_sys and isinstance(test_sys, dict) and not test_sys.get("error"):
            return (
                ["/redfish/v1/Systems/Self"],
                ["/redfish/v1/Chassis/Self"],
                ["/redfish/v1/Managers/Self"],
            )
        return None

    def oem_manager_paths(self) -> List[str]:
        """Add Quanta-specific manager path fallbacks."""
        return [
            "/redfish/v1/Managers/Self",
            "/redfish/v1/Managers/1",
        ]

    def oem_storage_endpoints(self) -> List[str]:
        """Add Quanta SimpleStorage fallback path if available."""
        if self.sys_uri:
            return [f"{self.sys_uri}/SimpleStorage"]
        return []

    def oem_drive_metrics(self, drive_json: dict) -> dict:
        """Read Quanta drive telemetry metrics from Oem.Quanta_RackScale, Quanta, or QCT."""
        q_oem = None
        for key in ("Quanta_RackScale", "Quanta", "QCT"):
            cand = get_nested(drive_json, "Oem", key, default=None)
            if isinstance(cand, dict) and cand:
                q_oem = cand
                break
        if not isinstance(q_oem, dict):
            return {}
        res = {}
        poh = q_oem.get("PowerOnHours") or q_oem.get("OperationHours")
        if poh is not None:
            try:
                res["power_on_hours"] = float(poh)
            except (TypeError, ValueError):
                pass
        part = q_oem.get("PartNumber") or q_oem.get("FRU")
        if part:
            res["part_number"] = str(part).strip()
        return res

    def oem_sku(self, sys_data: dict) -> str:
        """Extract SKU or PartNumber for Quanta platforms."""
        sku = str(sys_data.get("SKU") or "").strip()
        part = str(sys_data.get("PartNumber") or "").strip()
        model = str(sys_data.get("Model") or "").strip()
        if part and (not sku or " " in sku or "(" in sku or sku.lower() == model.lower()):
            return part
        return sku

    def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict:
        """Return Quanta BMC license information."""
        return {
            "license_name": "Quanta BMC",
            "badge": "<span class='badge success'>🟢 Quanta BMC — no inventory license required</span>",
            "vendor_note": (
                "Quanta BMC provides full Redfish inventory access without additional "
                "licensing."
            ),
        }
