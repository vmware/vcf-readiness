"""
VCF Readiness Tool — Lenovo XCC (ThinkSystem) OEM adapter.

Handles Lenovo XClarity Controller (XCC / XCC2) Redfish quirks.

Known Lenovo behaviour:
  • BIOS version format: "[IVE-2.93]" or "[TEE-2.00]" — parse_version_tuple extracts "2.93".
  • XCC does not expose BIOS release date via /Systems/1 — sourced from /UpdateService/FirmwareInventory.
  • Fast-path root probe resolves /Systems/1, /Chassis/1, /Managers/1 directly.
  • Gen-1 XCC licensing uses Features-on-Demand (FoD) keys fallback under /Managers/1/Oem/Lenovo/FoD/Keys.
  • ThinkAgile HX/VX nodes use the same ThinkSystem node internals.
"""
import json
from typing import Any, Dict, List, Optional, Tuple

from ...logging_utils import get_nested
from ..base import ExpandableCollectionsMap
from .generic import GenericCollector


class LenovoCollector(GenericCollector):
    """Lenovo XCC Redfish adapter."""

    VENDOR_MATCH = ("LENOVO",)  # matched against Manufacturer string upper()
    vendor: str = "lenovo"

    def oem_fastpath_roots(self) -> Optional[Tuple[List[str], List[str], List[str]]]:
        """Lenovo ThinkSystem fast-path root probe for standard rack/tower servers.
        Shortcuts /Systems/1, /Chassis/1, and /Managers/1 in a single check.
        Falls back to standard enumeration on modular or non-standard systems.
        """
        test_sys = self._get("/redfish/v1/Systems/1")
        if test_sys and isinstance(test_sys, dict) and not test_sys.get("error"):
            return (
                ["/redfish/v1/Systems/1"],
                ["/redfish/v1/Chassis/1"],
                ["/redfish/v1/Managers/1"],
            )
        return None

    def oem_expandable_collections(self) -> Dict[str, str]:
        """Lenovo ThinkSystem (XCC / XCC2) expandable collection endpoints.

        Lenovo XCC and XCC2 support OData $expand=* with MaxLevels: 2 on:
          - FirmwareInventory
          - Chassis NetworkAdapters (levels=2 returns NetworkPorts and NetworkDeviceFunctions)
          - Memory (Systems/1/Memory)
          - Chassis PCIeDevices (Chassis/1/PCIeDevices)
        """
        sys_uri = getattr(self, "sys_uri", None) or "/redfish/v1/Systems/1"
        chassis_uri = getattr(self, "chassis_uri", None) or "/redfish/v1/Chassis/1"
        net_ep = f"{chassis_uri}/NetworkAdapters"
        return ExpandableCollectionsMap(
            {
                "firmware": "/redfish/v1/UpdateService/FirmwareInventory",
                "network": net_ep,
                "network_adapters": net_ep,
                "memory": f"{sys_uri}/Memory",
                "pcie_devices": f"{chassis_uri}/PCIeDevices",
            },
            levels={
                "network": 2,
                "network_adapters": 2,
                net_ep: 2,
            },
        )

    def oem_bios_date(self, sys_data: dict) -> str:
        """Extract Lenovo BIOS release date from UpdateService/FirmwareInventory.

        Lenovo XCC does not expose BIOS release date directly on ComputerSystem.
        Queries /redfish/v1/UpdateService/FirmwareInventory to find the UEFI/BIOS
        software component, caching the result on self._cached_bios_date.
        """
        if hasattr(self, "_cached_bios_date") and self._cached_bios_date:
            return self._cached_bios_date

        self._cached_bios_date = "N/A"
        fw_uri = "/redfish/v1/UpdateService/FirmwareInventory"
        fetch_expand_fn = getattr(self, "_fetch_expanded_collection", None)
        if callable(fetch_expand_fn) and getattr(self, "expand_supported", False):
            fw_inv = fetch_expand_fn(fw_uri) or {}
        else:
            fw_inv = self._get(fw_uri) or {}
        if isinstance(fw_inv, dict) and not fw_inv.get("error"):
            members = self._get_members(fw_inv) if "Members" in fw_inv else []
            for m in members:
                if not isinstance(m, dict):
                    continue
                m_uri = m.get("@odata.id")
                m_id = str(m.get("Id", "") or m_uri or "").upper()
                m_name = str(m.get("Name", "")).upper()
                if "UEFI" in m_id or "BIOS" in m_id or "UEFI" in m_name or "BIOS" in m_name:
                    item = self._get(m_uri) if m_uri and ("ReleaseDate" not in m) else m
                    if isinstance(item, dict) and not item.get("error"):
                        rdate = item.get("ReleaseDate")
                        if rdate and str(rdate).strip() and str(rdate).strip().upper() not in ("N/A", "NONE"):
                            self._cached_bios_date = str(rdate).strip()
                            return self._cached_bios_date

            # If not matched by Id/Name in collection, inspect each member
            for m in members:
                if not isinstance(m, dict):
                    continue
                m_uri = m.get("@odata.id")
                if m_uri:
                    item = self._get(m_uri) or {}
                    if isinstance(item, dict) and not item.get("error"):
                        name_str = (str(item.get("Name", "")) + " " + str(item.get("Id", ""))).upper()
                        if "UEFI" in name_str or "BIOS" in name_str:
                            rdate = item.get("ReleaseDate")
                            if rdate and str(rdate).strip() and str(rdate).strip().upper() not in ("N/A", "NONE"):
                                self._cached_bios_date = str(rdate).strip()
                                return self._cached_bios_date

        return self._cached_bios_date

    def oem_drive_metrics(self, drive_json: dict) -> dict:
        """Read Lenovo drive telemetry metrics from Oem.Lenovo.Drive."""
        lnv_oem = get_nested(drive_json, "Oem", "Lenovo", "Drive", default={})
        if not isinstance(lnv_oem, dict):
            return {}
        res = {}
        poh = lnv_oem.get("PowerOnHours") or lnv_oem.get("OperationHours")
        if poh is not None:
            try:
                res["power_on_hours"] = float(poh)
            except (TypeError, ValueError):
                pass
        err_cnt = lnv_oem.get("DriveErrorCount")
        if err_cnt is None:
            err_cnt = lnv_oem.get("ErrorCount")
        if err_cnt is not None:
            try:
                res["drive_error_count"] = int(err_cnt)
            except (TypeError, ValueError):
                pass
        part = lnv_oem.get("PartNumber") or lnv_oem.get("FRUPartNumber")
        if part:
            res["part_number"] = str(part).strip()
        return res

    def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict:
        """Probe Lenovo XCC license status from LicenseService or FoD keys."""
        lic_svc = self._get("/redfish/v1/LicenseService/Licenses") or {}
        members = self._get_members(lic_svc) if isinstance(lic_svc, dict) and "Members" in lic_svc else []
        best_tier = "Standard"
        for lic in members:
            name = str(lic.get("Name", "") or lic.get("LicenseType", "")).upper()
            if "ADVANCED" in name or "ENTERPRISE" in name:
                best_tier = lic.get("Name") or lic.get("LicenseType", "Advanced")
                break

        # Fallback to Gen-1 XCC Features-on-Demand (FoD)
        if best_tier == "Standard":
            mgr_path = self.mgr_uri or "/redfish/v1/Managers/1"
            fod_data = self._get(f"{mgr_path}/Oem/Lenovo/FoD/Keys") or {}
            if isinstance(fod_data, dict) and not fod_data.get("error"):
                fod_members = self._get_members(fod_data) if "Members" in fod_data else fod_data.get("Keys", [])
                if isinstance(fod_members, list):
                    for key in fod_members:
                        k_str = json.dumps(key).upper() if isinstance(key, dict) else str(key).upper()
                        if "ENTERPRISE" in k_str:
                            best_tier = "Enterprise"
                            break
                        elif "ADVANCED" in k_str:
                            best_tier = "Advanced"

        return {
            "license_name": f"XCC {best_tier}",
            "badge": f"<span class='badge success'>🟢 Lenovo XCC {best_tier}</span>",
            "vendor_note": (
                "XCC Standard provides full Redfish hardware inventory access. "
                "Advanced / Enterprise adds remote console, virtual media, and LXCA "
                "centralised management."
            ),
        }

    def oem_normalize_bios_attributes(self, raw_attrs: dict) -> dict:
        """Normalize Lenovo ThinkSystem BIOS attributes."""
        boot_fallback = getattr(self, "sys_summary", {}).get("raw_boot_mode") or getattr(self, "sys_summary", {}).get("boot_mode")
        return normalize_lenovo_bios_attributes(raw_attrs, fallback_boot_mode=boot_fallback)


def normalize_lenovo_bios_attributes(
    raw_attrs: Dict[str, Any],
    fallback_boot_mode: Optional[str] = None,
) -> Dict[str, Any]:
    """Normalize Lenovo ThinkSystem BIOS attributes across generations (V1–V4).

    Extracts canonical baseline settings from Lenovo ThinkSystem Redfish or OneCLI
    representations (handling both V1-V3 OperatingModes/Processors/DevicesandIOPorts
    and V4 SystemSettings_WorkloadProfile / UEFI.* naming conventions).
    """
    normalized: Dict[str, Any] = {}
    if not isinstance(raw_attrs, dict):
        return normalized

    def _find_val(*keys: str) -> Optional[str]:
        for k in keys:
            if k in raw_attrs and raw_attrs[k] is not None:
                return str(raw_attrs[k]).strip()
            # Also try stripped dots vs underscores
            alt_us = k.replace(".", "_")
            if alt_us in raw_attrs and raw_attrs[alt_us] is not None:
                return str(raw_attrs[alt_us]).strip()
            alt_dot = k.replace("_", ".")
            if alt_dot in raw_attrs and raw_attrs[alt_dot] is not None:
                return str(raw_attrs[alt_dot]).strip()
            # Also try case-insensitive match
            k_low = k.lower()
            for rk, rv in raw_attrs.items():
                if rv is not None and (rk.lower() == k_low or rk.lower().endswith("." + k_low) or rk.lower().endswith("_" + k_low)):
                    return str(rv).strip()
        return None

    # 1. SysProfile (WorkloadProfile on V4, ChooseOperatingMode on V1-V3)
    val = _find_val(
        "SystemSettings_WorkloadProfile",
        "SystemSettings.WorkloadProfile",
        "UEFI.SystemSettings_WorkloadProfile",
        "OperatingModes_ChooseOperatingMode",
        "OperatingModes.ChooseOperatingMode",
        "ChooseOperatingMode",
        "OperatingMode",
        "WorkloadProfile",
    )
    if val:
        normalized["SysProfile"] = val
        normalized["OperatingModes_ChooseOperatingMode"] = val
        normalized["SystemSettings_WorkloadProfile"] = val

    # 2. Hardware-assisted virtualization (VT-x / AMD SVM)
    val = _find_val(
        "Processors_IntelVirtualizationTechnology",
        "Processors.IntelVirtualizationTechnology",
        "IntelVirtualizationTechnology",
        "ProcVirtualization",
        "SVM",
        "SVMMode",
    )
    if val:
        normalized["ProcVirtualization"] = val
        normalized["Processors_IntelVirtualizationTechnology"] = val

    # 3. VT-d / IOMMU (Directed I/O)
    val = _find_val(
        "DevicesandIOPorts_IntelVTforDirectedIOVTd",
        "DevicesandIOPorts.IntelVTforDirectedIOVTd",
        "IntelVTforDirectedIOVTd",
        "Processors_IntelVTforDirectedIOforVT_d",
        "IntelVTforDirectedIOforVT_d",
        "VT-d",
        "IOMMU",
    )
    if val:
        normalized["VtdSupport"] = val
        normalized["DevicesandIOPorts_IntelVTforDirectedIOVTd"] = val
        normalized["IntelVTforDirectedIOVTd"] = val

    # 4. SR-IOV
    val = _find_val(
        "DevicesandIOPorts_SRIOV",
        "DevicesandIOPorts.SRIOV",
        "SRIOV",
        "SriovGlobalEnable",
        "Sriov",
    )
    if val:
        normalized["SriovGlobalEnable"] = val
        normalized["DevicesandIOPorts_SRIOV"] = val

    # 5. Logical Processor / Hyper-Threading / SMT
    val = _find_val(
        "Processors_HyperThreading",
        "Processors.HyperThreading",
        "Processors_Hyper_Threading",
        "HyperThreading",
        "LogicalProc",
        "SMT",
    )
    if val:
        normalized["LogicalProc"] = val
        normalized["Processors_HyperThreading"] = val

    # 6. Turbo Mode / Core Performance Boost
    val = _find_val(
        "Processors_TurboMode",
        "Processors.TurboMode",
        "TurboMode",
        "ProcTurboMode",
        "CorePerformanceBoost",
    )
    if val:
        normalized["ProcTurboMode"] = val
        normalized["Processors_TurboMode"] = val

    # 7. Energy Efficient Turbo
    val = _find_val(
        "Processors_EnergyEfficientTurbo",
        "Processors.EnergyEfficientTurbo",
        "UEFI.Processors_EnergyEfficientTurbo",
        "EnergyEfficientTurbo",
    )
    if val:
        normalized["EnergyEfficientTurbo"] = val
        normalized["Processors_EnergyEfficientTurbo"] = val

    # 8. C-States
    val = _find_val(
        "Processors_CStates",
        "Processors.CStates",
        "Processors_C_States",
        "UEFI.Processors_C_States",
        "CStates",
        "ProcCStates",
    )
    if val:
        normalized["ProcCStates"] = val
        normalized["Processors_CStates"] = val
        normalized["Processors_C_States"] = val

    # 9. C1E Enhanced Mode
    val = _find_val(
        "Processors_C1EnhancedMode",
        "Processors.C1EnhancedMode",
        "Processors_C1_EnhancedMode",
        "UEFI.Processors_C1_EnhancedMode",
        "C1EnhancedMode",
        "ProcC1E",
    )
    if val:
        normalized["ProcC1E"] = val
        normalized["Processors_C1EnhancedMode"] = val

    # 10. MONITOR/MWAIT
    val = _find_val(
        "Processors_MONITORMWAIT",
        "Processors.MONITORMWAIT",
        "MONITORMWAIT",
        "MonitorMwait",
    )
    if val:
        normalized["MonitorMwait"] = val
        normalized["Processors_MONITORMWAIT"] = val

    # 11. Latency Optimized Mode (V3+/V4)
    val = _find_val(
        "Processors_LatencyOptimizedMode",
        "Processors.LatencyOptimizedMode",
        "UEFI.Processors_LatencyOptimizedMode",
        "LatencyOptimizedMode",
    )
    if val:
        normalized["LatencyOptimizedMode"] = val
        normalized["Processors_LatencyOptimizedMode"] = val

    # 12. Power & P-state controls
    val = _find_val(
        "Power_PlatformControlledType",
        "Power.PlatformControlledType",
        "UEFI.Power_PlatformControlledType",
        "PlatformControlledType",
    )
    if val:
        normalized["PlatformControlledType"] = val
    val = _find_val(
        "Power_PowerPerformanceBias",
        "Power.PowerPerformanceBias",
        "UEFI.Power_PowerPerformanceBias",
        "PowerPerformanceBias",
    )
    if val:
        normalized["PowerPerformanceBias"] = val
    val = _find_val(
        "Processors_CPUPstateControl",
        "Processors.CPUPstateControl",
        "CPUPstateControl",
    )
    if val:
        normalized["CpuPstateControl"] = val

    # 13. Sub-NUMA Clustering (SNC)
    val = _find_val(
        "Processors_SNC",
        "Processors.SNC",
        "SNC",
        "SubNumaCluster",
        "SubNumaClustering",
    )
    if val:
        normalized["SubNumaCluster"] = val
        normalized["Processors_SNC"] = val

    # 14. AMD NPS / Determinism
    val = _find_val(
        "OperatingModes_NUMANodesperSocket",
        "OperatingModes.NUMANodesperSocket",
        "NUMANodesperSocket",
        "NumaNodesPerSocket",
    )
    if val:
        normalized["NumaNodesPerSocket"] = val
        normalized["OperatingModes_NUMANodesperSocket"] = val
    val = _find_val(
        "OperatingModes_DeterminismSlider",
        "OperatingModes.DeterminismSlider",
        "DeterminismSlider",
        "Determinism",
    )
    if val:
        normalized["DeterminismSlider"] = val

    # 15. Node Interleave
    val = _find_val(
        "Memory_NodeInterleave",
        "Memory.NodeInterleave",
        "NodeInterleave",
    )
    if val:
        normalized["NodeInterleave"] = val
        normalized["Memory_NodeInterleave"] = val

    # 16. Intel VMD
    val = _find_val(
        "DevicesandIOPorts_EnableDisableIntelVMD",
        "DevicesandIOPorts.EnableDisableIntelVMD",
        "DevicesandIOPorts_IntelVMDTechnology",
        "DevicesandIOPorts.IntelVMDTechnology",
        "IntelVMDTechnology",
        "VmdSupport",
    )
    if val:
        normalized["VmdSupport"] = val
        normalized["DevicesandIOPorts_EnableDisableIntelVMD"] = val
        normalized["DevicesandIOPorts_IntelVMDTechnology"] = val
    else:
        # Detect from VMD key patterns across attributes
        vmd_keys = {
            k: v for k, v in raw_attrs.items()
            if any(s in k.lower() for s in ("vmd", "vroc", "nvmeraid", "nvme_raid"))
        }
        if vmd_keys:
            any_on = any(str(v).lower() in ("enabled", "true", "auto", "1", "enable") for v in vmd_keys.values())
            normalized["VmdSupport"] = "Enabled" if any_on else "Disabled"
        else:
            normalized["VmdSupport"] = "Disabled"

    # 17. BootMode
    val = _find_val(
        "BootMode",
        "BootSeqMode",
        "StartOptions_BootMode",
        "StartOptions.BootMode",
    )
    if val:
        normalized["BootMode"] = val
    elif fallback_boot_mode:
        normalized["BootMode"] = str(fallback_boot_mode).strip()

    # 18. Hardware Prefetchers
    val = _find_val(
        "Processors_HardwarePrefetcher",
        "Processors.HardwarePrefetcher",
        "HardwarePrefetcher",
        "HardwarePrefetch",
    )
    if val:
        normalized["HardwarePrefetch"] = val
        normalized["Processors_HardwarePrefetcher"] = val
    val = _find_val(
        "Processors_AdjacentCacheLinePrefetch",
        "Processors.AdjacentCacheLinePrefetch",
        "AdjacentCacheLinePrefetch",
    )
    if val:
        normalized["AdjacentCacheLinePrefetch"] = val
        normalized["Processors_AdjacentCacheLinePrefetch"] = val

    # 19. MM Config Base / 64-bit PCI Allocation
    val = _find_val(
        "DevicesandIOPorts_MMConfigBase",
        "DevicesandIOPorts.MMConfigBase",
        "MMConfigBase",
    )
    if val:
        normalized["MmConfigBase"] = val
    val = _find_val(
        "DevicesandIOPorts_PCI64BitResourceAllocation",
        "DevicesandIOPorts.PCI64BitResourceAllocation",
        "PCI64BitResourceAllocation",
    )
    if val:
        normalized["Pci64BitResourceAllocation"] = val

    return normalized
