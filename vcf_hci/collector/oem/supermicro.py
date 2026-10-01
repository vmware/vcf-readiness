"""
VCF Readiness Tool — Supermicro BMC OEM adapter.

Overrides OEM hook methods to handle Supermicro quirks:
  • SimpleStorage fallback : /Systems/{id}/SimpleStorage (drives not in /Storage)
  • HTML 404 pages         : Supermicro BMC (Lighttpd) returns HTML for missing endpoints
  • DCMS license gate      : /Storage returns OemLicenseNotPassed when not licensed

Known Supermicro quirks (handled inline in base methods):
  • BMC returns HTML 404 pages for missing endpoints — the JSONDecodeError trap in
    _get() silently returns None, which all collection methods handle gracefully.
  • Drives appear under /Systems/{id}/SimpleStorage (not /Storage) on older firmware.
  • /Storage endpoint may be blocked by DCMS license → _is_license_blocked() surfaces badge.
  • CPU string may be generic "Intel(R) Xeon(R) processor" on old firmware — advise BMC update.
"""
import re
from typing import Any, Optional

from ...logging_utils import get_nested
from .generic import GenericCollector


class SupermicroCollector(GenericCollector):
    """Supermicro BMC Redfish adapter."""

    vendor: str = "supermicro"
    VENDOR_MATCH = ("SUPERMICRO",)  # matched against Manufacturer string upper()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Supermicro BMC (X10-X13) does not reliably support OData $expand on storage,
        # which triggers DCMS license blocks (OemLicenseNotPassed) or HTTP 400/500 errors.
        self.expand_supported = False
        self.expand_syntax = None

    def oem_expandable_collections(self) -> dict:
        """Supermicro BMC does not support collection expansion on storage."""
        return {}

    def oem_manager_paths(self) -> list:
        """Add Supermicro AST2500/AST2600 X10/X11/X12/H12 manager path fallbacks."""
        return [
            "/redfish/v1/Managers/1",
            "/redfish/v1/Managers/Self",
            "/redfish/v1/Managers/BMC",
        ]

    def oem_storage_endpoints(self) -> list:
        """Route storage discovery directly to SimpleStorage for Supermicro.

        Supermicro BMCs (X10-X13) gate standard /Storage behind DCMS licenses
        (OemLicenseNotPassed) and do not support OData $expand reliably.
        Routing directly to SimpleStorage bypasses the license block.
        """
        if self.sys_uri:
            return [
                f"{self.sys_uri}/SimpleStorage",
            ]
        return []

    def oem_psu_capacity(self, psu_json: dict) -> Optional[int]:
        """Derive Supermicro PSU capacity from part number or model string."""
        if not isinstance(psu_json, dict):
            return None
        candidates = [
            str(psu_json.get("Model") or ""),
            str(psu_json.get("PartNumber") or ""),
            str(psu_json.get("Name") or ""),
        ]
        smc_oem = psu_json.get("Oem", {}).get("Supermicro", {})
        if isinstance(smc_oem, dict):
            candidates.append(str(smc_oem.get("PartNumber") or ""))
            candidates.append(str(smc_oem.get("FRU") or ""))

        catalog = {
            "PWS-2K22A": 2200,
            "PWS-2K21A": 2200,
            "PWS-2K09A": 2000,
            "PWS-2K05A": 2000,
            "PWS-2K04A": 2000,
            "PWS-2K02P": 2000,
            "PWS-1K66P": 1600,
            "PWS-1K62A": 1600,
            "PWS-1K41F": 1400,
            "PWS-1K28P": 1280,
            "PWS-1K23A": 1200,
            "PWS-1K21P": 1200,
            "PWS-1K02A": 1000,
            "PWS-920P": 920,
            "PWS-804P": 800,
            "PWS-801": 800,
            "PWS-741P": 740,
            "PWS-721P": 720,
            "PWS-704P": 700,
            "PWS-605P": 600,
            "PWS-504P": 500,
            "PWS-501P": 500,
        }

        for cand in candidates:
            c_up = cand.upper().strip()
            if not c_up or "PWS" not in c_up:
                continue
            for model_prefix, watts in catalog.items():
                if model_prefix in c_up:
                    return watts
            # Regex fallback: PWS-2K22A -> 2200W, PWS-1K21 -> 1200W
            m_kw = re.search(r'PWS-(\d+)K(\d+)', c_up)
            if m_kw:
                try:
                    kw_whole = int(m_kw.group(1))
                    kw_frac = m_kw.group(2)
                    if len(kw_frac) == 1:
                        return kw_whole * 1000 + int(kw_frac) * 100
                    elif len(kw_frac) == 2:
                        return kw_whole * 1000 + int(kw_frac) * 10
                    return int(float(f"{kw_whole}.{kw_frac}") * 1000)
                except (ValueError, TypeError):
                    pass
            m_w = re.search(r'PWS-(\d{3,4})', c_up)
            if m_w:
                try:
                    return int(m_w.group(1))
                except (ValueError, TypeError):
                    pass
        return None

    def oem_drive_metrics(self, drive_json: dict) -> dict:
        """Read Supermicro drive telemetry metrics from Oem.Supermicro."""
        smc_oem = get_nested(drive_json, "Oem", "Supermicro", default={})
        if not isinstance(smc_oem, dict):
            return {}
        res = {}
        poh = smc_oem.get("PowerOnHours") or smc_oem.get("OperationHours")
        if poh is not None:
            try:
                res["power_on_hours"] = float(poh)
            except (TypeError, ValueError):
                pass
        part = smc_oem.get("PartNumber") or smc_oem.get("FRU")
        if part:
            res["part_number"] = str(part).strip()
        return res

    def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict:
        """Probe Supermicro DCMS license status."""
        lic_msg = None
        if self.sys_uri:
            storage_coll = self._get(f"{self.sys_uri}/Storage") or {}
            lic_msg = self._is_license_blocked(storage_coll)
        if lic_msg:
            return {
                "license_name": "Supermicro (DCMS required)",
                "badge": "<span class='badge danger'>🔴 Supermicro DCMS License Required</span>",
                "vendor_note": (
                    f"Storage collection failed ({lic_msg}). Supermicro requires the "
                    "SFT-DCMS-SINGLE (DataCenter Management Suite) license. "
                    "In-band ESXi tools or out-of-band license activation is required."
                ),
            }
        return {
            "license_name": "Supermicro (DCMS / OOB)",
            "badge": "<span class='badge success'>🟢 Supermicro — OOB / DCMS Active</span>",
            "vendor_note": (
                "Redfish endpoints are accessible. If Storage or Network collections "
                "are missing, the SFT-DCMS-SINGLE license (DataCenter Management "
                "Suite) must be activated on this BMC."
            ),
        }
