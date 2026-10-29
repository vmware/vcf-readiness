"""BIOS settings, OEM dispatch and multi-socket telemetry; evaluators retain rule ownership."""
from typing import Any, Dict, Optional

from vcf_hci.bios.cisco_baseline import evaluate_cisco_bios_baseline
from vcf_hci.bios.dell_baseline import evaluate_dell_bios_baseline
from vcf_hci.bios.generic_baseline import evaluate_generic_bios_baseline
from vcf_hci.bios.hpe_baseline import evaluate_hpe_bios_baseline
from vcf_hci.bios.lenovo_baseline import evaluate_lenovo_bios_baseline
from vcf_hci.bios.x2apic import x2apic_recommendation


def enrich_bios_settings(host_data: Dict[str, Any]) -> None:
    """Describe current versus pending VMD settings without changing either."""
    # 10. BIOS VMD & Pending Settings Evaluation
    bios_checks = host_data.get("bios_checks")
    if isinstance(bios_checks, dict):
        active_vmd = bool(bios_checks.get("vmd_enabled_flag", False))
        pending_vmd = bios_checks.get("vmd_pending_flag")

        if active_vmd and pending_vmd is False:
            bios_checks["vmd_eval"] = {
                "badge": "Intel VMD: Enabled (Disabled PENDING Reboot)",
                "note": "VMD is currently Enabled in BIOS, but Disabled has been staged in Redfish. Power-cycle the server to apply.",
                "status": "pending_reboot",
                "staged_for_disable": True,
            }
        elif active_vmd:
            bios_checks["vmd_eval"] = {
                "badge": "Intel VMD: Enabled",
                "note": "Intel VMD is enabled in BIOS — disable for native NVMe pass-through under vSAN ESA.",
                "status": "enabled",
                "staged_for_disable": False,
            }
        else:
            bios_checks["vmd_eval"] = {
                "badge": "Intel VMD: Disabled (ESA Ready)",
                "note": "NVMe controller in native PCIe pass-through mode.",
                "status": "disabled",
                "staged_for_disable": False,
            }


def enrich_oem_baseline(host_data: Dict[str, Any], system: Dict[str, Any]) -> None:
    """Dispatch existing OEM evaluators, then evaluate telemetry from their normalized attributes."""
    bios_checks = host_data.get("bios_checks")
    # 11. Vendor BIOS Golden Baseline Drift Evaluation
    vendor_lower = str(system.get("vendor") or "").lower()
    model_lower = str(system.get("model") or "").lower()
    collector_cls = str(host_data.get("collector_class") or "")

    if not isinstance(bios_checks, dict):
        host_data["bios_checks"] = {}
        bios_checks = host_data["bios_checks"]

    raw_attrs = bios_checks.get("attributes") or host_data.get("bios_attributes") or {}
    norm_attrs = bios_checks.get("normalized_attributes") or {}
    cpu_info = system.get("cpu_summary") or {}
    compat = host_data.get("compatibility") or {}
    is_esa = bool(
        compat.get("esa_ready")
        or compat.get("esa_storage_met")
        or any(
            str(d.get("protocol", "")).upper() == "NVME"
            for d in (host_data.get("storage_subsystem") or [])
        )
    )

    if "dell" in vendor_lower or "poweredge" in model_lower or "dell" in collector_cls.lower():
        merged_attrs = dict(raw_attrs)
        merged_attrs.update(norm_attrs)
        if "BootMode" not in merged_attrs:
            bm = system.get("raw_boot_mode") or system.get("boot_mode")
            if bm:
                merged_attrs["BootMode"] = bm

        if "memory_ras" not in bios_checks and raw_attrs:
            from vcf_hci.bios.ras_modes import _detect_memory_ras_modes
            bios_checks["memory_ras"] = _detect_memory_ras_modes(raw_attrs, vendor="dell")
        if "cpu_power" not in bios_checks and raw_attrs:
            from vcf_hci.bios.power_modes import _detect_cpu_power_mode
            bios_checks["cpu_power"] = _detect_cpu_power_mode(raw_attrs, vendor="dell")

        drift = evaluate_dell_bios_baseline(
            merged_attrs,
            cpu_info=cpu_info,
            is_esa_candidate=is_esa,
            model=system.get("model"),
            bios_version=system.get("bios_version"),
        )
        bios_checks["dell_baseline_drift"] = drift
        bios_checks["bios_baseline_drift"] = drift

    elif "hpe" in vendor_lower or "proliant" in model_lower or "synergy" in model_lower or "hpe" in collector_cls.lower():
        if not norm_attrs and raw_attrs:
            from vcf_hci.collector.oem.hpe import normalize_hpe_bios_attributes
            norm_attrs = normalize_hpe_bios_attributes(
                raw_attrs,
                fallback_boot_mode=system.get("raw_boot_mode") or system.get("boot_mode"),
            )
            bios_checks["normalized_attributes"] = norm_attrs
        merged_attrs = dict(raw_attrs)
        merged_attrs.update(norm_attrs)
        if "BootMode" not in merged_attrs:
            bm = system.get("raw_boot_mode") or system.get("boot_mode")
            if bm:
                merged_attrs["BootMode"] = bm

        if "memory_ras" not in bios_checks and raw_attrs:
            from vcf_hci.bios.ras_modes import _detect_memory_ras_modes
            bios_checks["memory_ras"] = _detect_memory_ras_modes(raw_attrs, vendor="hpe")
        if "cpu_power" not in bios_checks and raw_attrs:
            from vcf_hci.bios.power_modes import _detect_cpu_power_mode
            bios_checks["cpu_power"] = _detect_cpu_power_mode(raw_attrs, vendor="hpe")

        drift = evaluate_hpe_bios_baseline(
            merged_attrs,
            cpu_info=cpu_info,
            is_esa_candidate=is_esa,
            model=system.get("model"),
            bios_version=system.get("bios_version"),
        )
        bios_checks["hpe_baseline_drift"] = drift
        bios_checks["bios_baseline_drift"] = drift

    elif "cisco" in vendor_lower or "ucs" in model_lower or "cisco" in collector_cls.lower():
        if not norm_attrs and raw_attrs:
            from vcf_hci.collector.oem.cisco import normalize_cisco_bios_attributes
            norm_attrs = normalize_cisco_bios_attributes(
                raw_attrs,
                fallback_boot_mode=system.get("boot_mode") or system.get("raw_boot_mode"),
            )
            bios_checks["normalized_attributes"] = norm_attrs
        bios_checks["attributes"] = raw_attrs
        merged_attrs = dict(raw_attrs)
        merged_attrs.update(norm_attrs)
        if "BootMode" not in merged_attrs or str(merged_attrs.get("BootMode")).strip().lower() in ("unknown", "none", ""):
            bm = system.get("boot_mode") or system.get("raw_boot_mode")
            if bm and str(bm).strip().lower() not in ("unknown", "none", ""):
                merged_attrs["BootMode"] = bm
                if "normalized_attributes" in bios_checks:
                    bios_checks["normalized_attributes"]["BootMode"] = bm

        if "memory_ras" not in bios_checks and raw_attrs:
            from vcf_hci.bios.ras_modes import _detect_memory_ras_modes
            bios_checks["memory_ras"] = _detect_memory_ras_modes(raw_attrs, vendor="cisco")
        if "cpu_power" not in bios_checks and raw_attrs:
            from vcf_hci.bios.power_modes import _detect_cpu_power_mode
            bios_checks["cpu_power"] = _detect_cpu_power_mode(raw_attrs, vendor="cisco")

        drift = evaluate_cisco_bios_baseline(
            merged_attrs,
            cpu_info=cpu_info,
            is_esa_candidate=is_esa,
            model=system.get("model"),
            bios_version=system.get("bios_version"),
        )
        bios_checks["cisco_baseline_drift"] = drift
        bios_checks["bios_baseline_drift"] = drift

    elif "lenovo" in vendor_lower or "thinksystem" in model_lower or "lenovo" in collector_cls.lower():
        if not norm_attrs and raw_attrs:
            from vcf_hci.collector.oem.lenovo import normalize_lenovo_bios_attributes
            norm_attrs = normalize_lenovo_bios_attributes(
                raw_attrs,
                fallback_boot_mode=system.get("raw_boot_mode") or system.get("boot_mode"),
            )
            bios_checks["normalized_attributes"] = norm_attrs
        merged_attrs = dict(raw_attrs)
        merged_attrs.update(norm_attrs)
        if "BootMode" not in merged_attrs:
            bm = system.get("raw_boot_mode") or system.get("boot_mode")
            if bm:
                merged_attrs["BootMode"] = bm

        if "memory_ras" not in bios_checks and raw_attrs:
            from vcf_hci.bios.ras_modes import _detect_memory_ras_modes
            bios_checks["memory_ras"] = _detect_memory_ras_modes(raw_attrs, vendor="lenovo")
        if "cpu_power" not in bios_checks and raw_attrs:
            from vcf_hci.bios.power_modes import _detect_cpu_power_mode
            bios_checks["cpu_power"] = _detect_cpu_power_mode(raw_attrs, vendor="lenovo")

        drift = evaluate_lenovo_bios_baseline(
            merged_attrs,
            cpu_info=cpu_info,
            is_esa_candidate=is_esa,
            model=system.get("model"),
            bios_version=system.get("bios_version"),
        )
        bios_checks["lenovo_baseline_drift"] = drift
        bios_checks["bios_baseline_drift"] = drift

    elif raw_attrs or norm_attrs:
        # Generic / Supermicro / Quanta / Gigabyte fallback
        merged_attrs = dict(raw_attrs)
        merged_attrs.update(norm_attrs)
        if "BootMode" not in merged_attrs:
            bm = system.get("raw_boot_mode") or system.get("boot_mode")
            if bm:
                merged_attrs["BootMode"] = bm

        drift = evaluate_generic_bios_baseline(
            merged_attrs,
            cpu_info=cpu_info,
            is_esa_candidate=is_esa,
            model=system.get("model"),
            bios_version=system.get("bios_version"),
            vendor=system.get("vendor"),
        )
        bios_checks["generic_baseline_drift"] = drift
        bios_checks["bios_baseline_drift"] = drift

    enrich_multi_socket_telemetry(host_data, bios_checks, raw_attrs, norm_attrs, cpu_info)


def enrich_multi_socket_telemetry(
    host_data: Dict[str, Any], bios_checks: Dict[str, Any],
    raw_attrs: Any, norm_attrs: Any, cpu_info: Any,
) -> None:
    """Share NUMA telemetry using the actual post-OEM attributes and CPU reference."""
    # 11.5 Multi-Socket & NUMA BIOS Telemetry Evaluation
    all_bios_attrs = {}
    if isinstance(raw_attrs, dict):
        all_bios_attrs.update(raw_attrs)
    if isinstance(norm_attrs, dict):
        all_bios_attrs.update(norm_attrs)

    def _find_bios_val(*candidates: str) -> Optional[str]:
        for c in candidates:
            c_low = c.lower()
            for k, v in all_bios_attrs.items():
                k_low = k.lower()
                if k_low == c_low or k_low.endswith("." + c_low):
                    if v is not None and str(v).strip():
                        return str(v).strip()
        return None

    cpu_cnt = int(cpu_info.get("count") or cpu_info.get("cpu_count") or 1)
    is_multi_sock = cpu_cnt >= 2
    is_quad_sock = cpu_cnt >= 4

    snc_val = _find_bios_val("SubNumaCluster", "SubNumaClustering", "SNC", "NumaNodesPerSocket")
    uma_val = _find_bios_val("UmaBasedClusteringStatus", "UmaBasedClustering", "ClusteringMode")
    node_interleave_val = _find_bios_val("NodeInterleave", "NodeInterleaving", "Memory_NodeInterleave", "NumaMemInterleave", "NumaInterleaving")
    x2apic_val = _find_bios_val("ProcX2Apic", "x2APIC", "ProcessorX2Apic", "X2ApicOptOut")
    upi_prefetch_val = _find_bios_val("UpiPrefetch", "UpiPrefetcher", "UPIPrefetch")
    upi_power_val = _find_bios_val("CpuInterconnectBusLinkPower", "InterconnectBusLinkPower", "UpiLinkPowerManagement")
    acpi_slit_val = _find_bios_val("AcpiSlit", "Slit")
    acpi_pxm_val = _find_bios_val("AcpiRootBridgePxm", "RootBridgePxm")
    numa_group_val = _find_bios_val("NumaGroupSizeOpt", "NumaGroupSizeOptimization")

    snc_mode = ""
    if snc_val:
        s_low = snc_val.lower()
        if "snc4" in s_low or s_low in ("4", "quad"):
            snc_mode = "SNC-4"
        elif "snc2" in s_low or s_low in ("2", "hemi", "hemisphere"):
            snc_mode = "SNC-2"
        elif s_low in ("disabled", "off", "0"):
            snc_mode = "Disabled"
        elif s_low in ("auto", "default"):
            snc_mode = "Auto"
        else:
            snc_mode = snc_val

    uma_mode = ""
    if uma_val:
        u_low = uma_val.lower()
        if "quad" in u_low or u_low == "4":
            uma_mode = "Quadrant"
        elif "hemi" in u_low or u_low == "2":
            uma_mode = "Hemisphere"
        elif "all" in u_low:
            uma_mode = "All-to-All"
        elif "disab" in u_low or u_low == "0":
            uma_mode = "Disabled"
        else:
            uma_mode = uma_val

    ni_warn = False
    if node_interleave_val and node_interleave_val.lower() in ("enabled", "enable", "on", "true", "1"):
        ni_warn = True
        ni_msg = "BIOS: Node Interleaving is Enabled. This flattens NUMA into UMA, degrading ESXi NUMA-aware scheduling. Disable in BIOS."
        if ni_msg not in host_data.setdefault("readiness_warnings", []):
            host_data["readiness_warnings"].append(ni_msg)

    x2_warn = False
    if x2apic_val and x2apic_val.lower() in ("disabled", "disable", "off", "false", "0"):
        if is_multi_sock or int(cpu_info.get("core_count") or cpu_info.get("cores") or 0) > 32:
            x2_warn = True
            x2_msg = x2apic_recommendation(cpu_info)
            if x2_msg not in host_data.setdefault("readiness_warnings", []):
                host_data["readiness_warnings"].append(x2_msg)

    mst = {
        "is_multi_socket": is_multi_sock,
        "is_quad_socket": is_quad_sock,
        "socket_count": cpu_cnt,
        "sub_numa_clustering": snc_val,
        "snc_mode": snc_mode,
        "uma_clustering": uma_mode or uma_val,
        "node_interleave": node_interleave_val,
        "node_interleave_warning": ni_warn,
        "proc_x2apic": x2apic_val,
        "proc_x2apic_warning": x2_warn,
        "upi_prefetch": upi_prefetch_val,
        "upi_link_power": upi_power_val,
        "acpi_slit": acpi_slit_val,
        "acpi_root_bridge_pxm": acpi_pxm_val,
        "numa_group_size_opt": numa_group_val,
    }
    host_data["multi_socket_telemetry"] = mst
    bios_checks["multi_socket_telemetry"] = mst
    if isinstance(cpu_info, dict):
        cpu_info["multi_socket_telemetry"] = mst
