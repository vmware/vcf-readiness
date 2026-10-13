"""
VCF Readiness Tool — Supermicro BMC OEM adapter.

Overrides OEM hook methods to handle Supermicro quirks:
  • Storage-first collection with SimpleStorage fallback (see collect_storage_subsystem)
  • HTML 404 pages         : Supermicro BMC (Lighttpd) returns HTML for missing endpoints
  • DCMS license gate      : /Storage returns OemLicenseNotPassed when not licensed
  • Always-404 skip list   : pre-seed negative cache for Dell Oem / Fabrics / etc.

Known Supermicro quirks (handled inline in base methods):
  • BMC returns HTML 404 pages for missing endpoints — the JSONDecodeError trap in
    _get() silently returns None, which all collection methods handle gracefully.
  • Prefer /Systems/{id}/Storage; append SimpleStorage only when Storage is empty/blocked.
  • /Storage endpoint may be blocked by DCMS license → _is_license_blocked() surfaces badge.
  • CPU string may be generic "Intel(R) Xeon(R) processor" on old firmware — advise BMC update.
  • Capacity NVMe drives often omit FirmwareVersion/Revision (BMC telemetry gap).
"""
import re
from typing import Any, Optional

from ...logging_utils import get_nested
from .generic import GenericCollector

# Paths that always 404 on Supermicro/Nutanix NX BMCs in SM Scan (seed negative cache).
_SUPERMICRO_ALWAYS_404_SUFFIXES = (
    "/redfish/v1/Fabrics",
    "/redfish/v1/Switches",
    "/redfish/v1/redfish",
    "/redfish/v1/ComponentIntegrity",
    "/redfish/v1/Chassis/1/EnvironmentMetrics",
    "/redfish/v1/Chassis/1/LogServices",
    "/redfish/v1/Systems/1/PCIeDevices",
    "/redfish/v1/Systems/1/BaseNetworkAdapters",
    "/redfish/v1/Systems/1/EthernetInterfaces/ToManager/NetworkPorts",
    "/redfish/v1/Systems/1/EthernetInterfaces/ToManager/NetworkDeviceFunctions",
    "/redfish/v1/Systems/1/NetworkPorts/Oem/Dell/DellSwitchConnections",
    "/redfish/v1/TelemetryService/MetricReports/SystemBoardMemoryUsage",
)


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
        # Pre-seed host negative cache so we do not re-probe known-missing paths.
        neg = getattr(self, "_negative_endpoints", None)
        if isinstance(neg, set):
            neg.update(_SUPERMICRO_ALWAYS_404_SUFFIXES)

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
        """Append SimpleStorage as a fallback after standard /Storage collection.

        collect_storage_subsystem always probes /Storage first; this hook adds
        SimpleStorage for older firmware or DCMS-blocked Storage responses.
        """
        if self.sys_uri:
            return [
                f"{self.sys_uri}/SimpleStorage",
            ]
        return []

    def oem_bios_date(self, sys_data: dict) -> str:
        """Parse BIOS release date from FirmwareInventory UniqueFilename / Version."""
        # Prefer FirmwareInventory/BIOS Version string: "BIOS Date: 04/28/2026 Ver EH52.003"
        inv = self._get("/redfish/v1/UpdateService/FirmwareInventory/BIOS", critical=False) or {}
        if isinstance(inv, dict) and inv:
            ver = str(inv.get("Version") or "")
            m = re.search(r"BIOS\s+Date:\s*(\d{1,2}/\d{1,2}/\d{4})", ver, re.I)
            if m:
                return m.group(1)
            smc = ((inv.get("Oem") or {}).get("Supermicro") or {})
            if isinstance(smc, dict):
                uniq = str(smc.get("UniqueFilename") or "")
                # e.g. BIOS_X13DEM-1C30-NI22_20260428_...
                m2 = re.search(r"_(\d{8})_", uniq)
                if m2:
                    d = m2.group(1)
                    return f"{d[4:6]}/{d[6:8]}/{d[0:4]}"
        # Fallback: system BiosVersion may embed a date
        bios_ver = str((sys_data or {}).get("BiosVersion") or "")
        m3 = re.search(r"(\d{1,2}/\d{1,2}/\d{4})", bios_ver)
        if m3:
            return m3.group(1)
        return "N/A"

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

    def oem_drive_endurance(self, drive_json: dict) -> Optional[float]:
        """Extract remaining write endurance percentage (0.0 to 100.0) from Supermicro OEM fields.

        Supermicro NVMe backplanes report flash wear used under
        Oem.Supermicro.PercentageDriveLifeUsed (0 = 100% life left, 1 = 99% life left, etc.).
        """
        smc_oem = get_nested(drive_json, "Oem", "Supermicro", default={})
        if not isinstance(smc_oem, dict):
            return None
        life_used = smc_oem.get("PercentageDriveLifeUsed")
        if life_used is not None:
            try:
                val = float(life_used)
                if 0 <= val <= 100:
                    return max(0.0, min(100.0, 100.0 - val))
            except (TypeError, ValueError):
                pass
        life_left = smc_oem.get("RemainingDriveLife") or smc_oem.get("PredictedMediaLifeLeftPercent")
        if life_left is not None:
            try:
                val = float(life_left)
                if 0 <= val <= 100:
                    return max(0.0, min(100.0, val))
            except (TypeError, ValueError):
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
        temp = smc_oem.get("Temperature") or smc_oem.get("TemperatureCelsius")
        if temp is not None:
            try:
                res["temperature_c"] = float(temp)
            except (TypeError, ValueError):
                pass
        life_used = smc_oem.get("PercentageDriveLifeUsed")
        if life_used is not None:
            try:
                val = float(life_used)
                if 0 <= val <= 100:
                    res["endurance_remaining_pct"] = max(0.0, min(100.0, 100.0 - val))
            except (TypeError, ValueError):
                pass
        return res

    def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict:
        """Probe Supermicro DCMS license status (prefer LicenseManager/QueryLicense)."""
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

        # Parse exact license key from LicenseManager when present (NX fleet: SFT-DCMS-SINGLE).
        license_name = "Supermicro (DCMS / OOB)"
        create_date = ""
        mgr_uri = getattr(self, "mgr_uri", None) or "/redfish/v1/Managers/1"
        qlic = self._get(f"{mgr_uri}/LicenseManager/QueryLicense", critical=False) or {}
        licenses = qlic.get("Licenses") if isinstance(qlic, dict) else None
        # Some BMCs return Licenses as a JSON string
        if isinstance(licenses, str):
            import json as _json
            try:
                licenses = _json.loads(licenses)
            except Exception:
                licenses = None
        if isinstance(licenses, list):
            for lic in licenses:
                if not isinstance(lic, dict):
                    continue
                name = str(lic.get("LicenseName") or lic.get("Name") or "").strip()
                if name:
                    license_name = name
                    create_date = str(lic.get("CreateDate") or lic.get("IssueDate") or "").strip()
                    if "DCMS" in name.upper() or "SFT-" in name.upper():
                        break

        badge = f"<span class='badge success'>🟢 {license_name}</span>"
        note = (
            f"License key {license_name} active"
            + (f" (created {create_date})" if create_date else "")
            + ". Redfish Storage/Network collection requires SFT-DCMS-SINGLE on this platform."
        )
        return {
            "license_name": license_name,
            "badge": badge,
            "vendor_note": note,
            "create_date": create_date,
        }
