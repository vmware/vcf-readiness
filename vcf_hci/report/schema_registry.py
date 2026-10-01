"""
VCF Readiness Tool — Extensible Schema Registry (Layer D).

Centralizes all field definitions, domain extractors, and color styling rules
for CSV and Excel exports (Schema v2.0). Provides stable column ordering,
forward-compatibility, and zero-crash defensive fallbacks.
"""

import re
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Set

from vcf_hci.compat_engine import VCF9CompatibilityEngine

SCHEMA_VERSION = "2.0"


def strip_html(s: Any) -> str:
    """Remove HTML tags and entities cleanly from a string or number."""
    if s is None:
        return ""
    clean = re.sub(r"<[^>]+>", "", str(s))
    clean = clean.replace("&nbsp;", " ").replace("&mdash;", "—").replace("&amp;", "&")
    return clean.strip()


def color_for_verdict(val: Any) -> str:
    """Classify text verdict into Excel badge fill style: green, yellow, red, or header."""
    v = str(val or "").lower()
    if any(k in v for k in ("unsupported", "not supported", "danger", "critical", "not present", "missing", "blocked", "insufficient", "time drift", "fail", "single")):
        return "red"
    if any(k in v for k in ("deprecated", "override", "warning", "check", "sub-optimal", "9.1 only", "storage met", "osa only", "partially", "power cap")):
        return "yellow"
    if any(k in v for k in ("supported", "success", "ready", "ok", "up-to-date", "redundant", "pass", "complete", "fully", "optimizer")):
        return "green"
    return "header"


class ExportField(NamedTuple):
    """Metadata specification for an exported report column."""
    key: str
    header: str
    group: str
    extractor: Callable[[Dict[str, Any]], Any]
    color_rule: Optional[Callable[[Any], str]] = None
    is_core: bool = True


# ── Domain Extractors for Fleet Summary ────────────────────────────────────────

def _extract_ip(data: Dict[str, Any]) -> str:
    si = data.get("system") or {}
    return str(si.get("ip") or data.get("host") or "").strip()


def _extract_hostname(data: Dict[str, Any]) -> str:
    si = data.get("system") or {}
    return str(si.get("hostname") or "").strip()


def _extract_dns(data: Dict[str, Any]) -> str:
    si = data.get("system") or {}
    return str(si.get("dns_name") or "").strip()


def _extract_vendor(data: Dict[str, Any]) -> str:
    si = data.get("system") or {}
    return str(si.get("vendor") or "").strip()


def _extract_model(data: Dict[str, Any]) -> str:
    si = data.get("system") or {}
    return str(si.get("model") or "").strip()


def _extract_serial(data: Dict[str, Any]) -> str:
    si = data.get("system") or {}
    return str(si.get("serial_number") or "").strip()


def _extract_asset_tag(data: Dict[str, Any]) -> str:
    si = data.get("system") or {}
    return str(si.get("asset_tag") or "").strip()


def _extract_sku(data: Dict[str, Any]) -> str:
    si = data.get("system") or {}
    return str(si.get("sku") or "").strip()


def _extract_scan_status(data: Dict[str, Any]) -> str:
    rem = data.get("remediation") or {}
    if rem.get("status") == "fully_remediated":
        return "Remediated"
    if data.get("partial_scan"):
        return "Partial" if rem.get("status") != "partially_remediated" else "Partially Remediated"
    return "Complete"


def _extract_vcf_support(data: Dict[str, Any]) -> str:
    blockers = data.get("vcf_blockers") or []
    if not blockers:
        sel = data.get("sel_alarms") or data.get("sel") or []
        blockers = [
            a for a in sel
            if a.get("is_vcf_blocker") or (isinstance(a.get("eems"), dict) and a["eems"].get("is_vcf_blocker"))
        ]
    if blockers:
        b_codes = ", ".join(dict.fromkeys(b.get("code") or b.get("eems_code") or "FAULT" for b in blockers))
        return f"Blocked ({b_codes})"
    si = data.get("system") or {}
    ci = si.get("cpu_summary") or {}
    return strip_html(ci.get("verdict", "Unknown"))


def _extract_cpu_verdict(data: Dict[str, Any]) -> str:
    si = data.get("system") or {}
    ci = si.get("cpu_summary") or {}
    v = ci.get("verdict", "")
    if "Unsupported" in v:
        return "Unsupported"
    if "Override Required" in v:
        return "Supported (Override Required)"
    if "9.1 Only" in v:
        return "Supported (Override Required)"
    if "Deprecated" in v:
        return "Supported (9.x Deprecated Mode)"
    if "Supported" in v:
        return "Supported (VCF 9.x)"
    return strip_html(v) or "Unknown"


def _extract_vsan_verdict(data: Dict[str, Any]) -> str:
    all_drives = [d for ctrl in data.get("storage_subsystem", []) for d in ctrl.get("drives", [])]
    esa_count = sum(1 for d in all_drives if d.get("category") == "vSAN ESA/OSA NVMe")
    osa_count = sum(1 for d in all_drives if d.get("category") in ("vSAN OSA Only", "vSAN OSA SAS/SATA"))
    vmd_on = (data.get("bios_checks") or {}).get("vmd_enabled_flag", False)
    trimode_nvme = sum(1 for d in all_drives if d.get("behind_trimode") or d.get("category") == "Unsupported NVMe Tri-Mode")
    raid_nvme = sum(1 for d in all_drives if d.get("category") == "Unsupported NVMe RAID" and not d.get("behind_trimode"))
    sw_raid_nvme = sum(1 for d in all_drives if d.get("behind_software_raid"))
    max_nic = max(
        (max((p.get("current_speed_gbps", 0) or 0 for p in n.get("ports", [])), default=0)
         for n in data.get("network_adapters", [])),
        default=0,
    )
    vsan_verdict, _ = VCF9CompatibilityEngine.evaluate_vsan(
        esa_count,
        osa_count,
        max_nic,
        vmd_enabled=vmd_on,
        trimode_nvme_count=trimode_nvme,
        raid_nvme_count=raid_nvme,
        software_raid_nvme_count=sw_raid_nvme,
    )
    return strip_html(vsan_verdict)


def _extract_mem_interleaving_verdict(data: Dict[str, Any]) -> str:
    mem_topo = data.get("memory_topology")
    if not mem_topo:
        si = data.get("system") or {}
        mem_topo = VCF9CompatibilityEngine.evaluate_memory_topology(
            data.get("memory_subsystem", {}), si.get("cpu_summary", {})
        )
    pct = mem_topo.get("interleaving_score_pct", 0) or 0
    badge = strip_html(mem_topo.get("status_badge", ""))
    return f"{badge} ({pct}%)" if badge else f"{pct}% Efficiency"


def _extract_nic_25g_ready(data: Dict[str, Any]) -> str:
    max_nic = max(
        (max((p.get("current_speed_gbps", 0) or 0 for p in n.get("ports", [])), default=0)
         for n in data.get("network_adapters", [])),
        default=0,
    )
    return "Yes (≥25 GbE)" if max_nic >= 25 else "No (<25 GbE)"


def _extract_tpm_status(data: Dict[str, Any]) -> str:
    si = data.get("system") or {}
    return strip_html(si.get("tpm_status_badge", "Unknown"))


def _extract_secure_boot(data: Dict[str, Any]) -> str:
    sb = data.get("secure_boot") or {}
    cur = sb.get("current_boot") or ("Enabled" if sb.get("enabled") else "Disabled")
    return str(cur)


def _extract_psu_redundant(data: Dict[str, Any]) -> str:
    psu = data.get("psu_status") or {}
    return "Redundant" if psu.get("redundant") else "Single"


def _extract_cpu_model(data: Dict[str, Any]) -> str:
    ci = (data.get("system") or {}).get("cpu_summary") or {}
    return str(ci.get("model") or "").strip()


def _extract_cpu_sockets(data: Dict[str, Any]) -> Any:
    ci = (data.get("system") or {}).get("cpu_summary") or {}
    return ci.get("count", "")


def _extract_cores_per_socket(data: Dict[str, Any]) -> Any:
    ci = (data.get("system") or {}).get("cpu_summary") or {}
    return ci.get("cores_per_socket", "")


def _extract_total_cores(data: Dict[str, Any]) -> Any:
    ci = (data.get("system") or {}).get("cpu_summary") or {}
    return ci.get("core_count", "")


def _extract_total_threads(data: Dict[str, Any]) -> Any:
    ci = (data.get("system") or {}).get("cpu_summary") or {}
    return ci.get("logical_count", "")


def _extract_cpu_base_ghz(data: Dict[str, Any]) -> Any:
    ci = (data.get("system") or {}).get("cpu_summary") or {}
    return ci.get("base_freq_ghz", "")


def _extract_cpu_max_ghz(data: Dict[str, Any]) -> Any:
    ci = (data.get("system") or {}).get("cpu_summary") or {}
    return ci.get("max_freq_ghz", "")


def _extract_cpu_arch(data: Dict[str, Any]) -> str:
    ci = (data.get("system") or {}).get("cpu_summary") or {}
    return str(ci.get("architecture") or "").strip()


def _extract_cpu_microcode(data: Dict[str, Any]) -> str:
    sc = (data.get("bios_checks") or {}).get("side_channel") or []
    codes = [c.get("label", "") for c in sc if "Microcode" in c.get("feature", "")]
    return ", ".join(codes) if codes else "N/A"


def _extract_ram_gb(data: Dict[str, Any]) -> Any:
    si = data.get("system") or {}
    return si.get("total_memory_gb", "")


def _extract_interleaving_pct(data: Dict[str, Any]) -> Any:
    topo = data.get("memory_topology") or {}
    return topo.get("interleaving_score_pct", "")


def _extract_operating_ram_speed(data: Dict[str, Any]) -> str:
    topo = data.get("memory_topology") or {}
    return str(topo.get("operating_speed_str") or "").strip()


def _extract_max_ram_speed(data: Dict[str, Any]) -> str:
    topo = data.get("memory_topology") or {}
    return str(topo.get("max_ram_speed_str") or "").strip()


def _extract_populated_dimms(data: Dict[str, Any]) -> Any:
    mem = data.get("memory_subsystem") or {}
    return mem.get("total_dimms_populated", len(mem.get("dimm_list", [])))


def _extract_channels_per_socket(data: Dict[str, Any]) -> Any:
    topo = data.get("memory_topology") or {}
    return topo.get("chan_per_cpu", "")


def _extract_dpc_status(data: Dict[str, Any]) -> str:
    topo = data.get("memory_topology") or {}
    issues = topo.get("issues") or []
    dpc_issues = [strip_html(i) for i in issues if "DPC" in str(i)]
    return "; ".join(dpc_issues) if dpc_issues else "Balanced / Uniform"


def _extract_memory_issues(data: Dict[str, Any]) -> str:
    topo = data.get("memory_topology") or {}
    issues = topo.get("issues") or []
    return "; ".join(strip_html(i) for i in issues)


def _extract_esa_nvme_count(data: Dict[str, Any]) -> int:
    all_drives = [d for ctrl in data.get("storage_subsystem", []) for d in ctrl.get("drives", [])]
    return sum(1 for d in all_drives if d.get("category") == "vSAN ESA/OSA NVMe")


def _extract_osa_drive_count(data: Dict[str, Any]) -> int:
    all_drives = [d for ctrl in data.get("storage_subsystem", []) for d in ctrl.get("drives", [])]
    return sum(1 for d in all_drives if d.get("category") in ("vSAN OSA Only", "vSAN OSA SAS/SATA"))


def _extract_raw_nvme_tb(data: Dict[str, Any]) -> float:
    all_drives = [d for ctrl in data.get("storage_subsystem", []) for d in ctrl.get("drives", [])]
    total_gb = sum(float(d.get("capacity_gb") or 0) for d in all_drives if d.get("category") == "vSAN ESA/OSA NVMe")
    return round(total_gb / 1024.0, 2)


def _extract_total_storage_tb(data: Dict[str, Any]) -> float:
    all_drives = [d for ctrl in data.get("storage_subsystem", []) for d in ctrl.get("drives", [])]
    total_gb = sum(float(d.get("capacity_gb") or 0) for d in all_drives if d.get("populated", True))
    return round(total_gb / 1024.0, 2)


def _extract_vmd_state(data: Dict[str, Any]) -> str:
    vmd = (data.get("bios_checks") or {}).get("vmd_enabled_flag", False)
    return "Enabled (Blocks ESA)" if vmd else "Disabled (OK)"


def _extract_trimode_blocked(data: Dict[str, Any]) -> str:
    all_drives = [d for ctrl in data.get("storage_subsystem", []) for d in ctrl.get("drives", [])]
    n = sum(1 for d in all_drives if d.get("behind_trimode") or d.get("category") == "Unsupported NVMe Tri-Mode")
    return f"Yes ({n} NVMe Blocked)" if n > 0 else "No"


def _extract_software_raid(data: Dict[str, Any]) -> str:
    all_drives = [d for ctrl in data.get("storage_subsystem", []) for d in ctrl.get("drives", [])]
    n = sum(1 for d in all_drives if d.get("behind_software_raid"))
    sw_ctrls = [ctrl.get("name") or ctrl.get("ctrl_model") for ctrl in data.get("storage_subsystem", []) if ctrl.get("is_software_raid")]
    if sw_ctrls:
        ctrl_str = ", ".join(str(s) for s in sw_ctrls if s)
        return f"Detected ({ctrl_str} — Bypass in BIOS)"
    if n > 0:
        return f"Detected ({n} NVMe drives — Bypass in BIOS)"
    return "None (Direct / HW HBA)"


def _extract_boot_device(data: Dict[str, Any]) -> str:
    si = data.get("system") or {}
    return str(si.get("boot_target") or "None").strip()


def _extract_boot_controller(data: Dict[str, Any]) -> str:
    for ctrl in data.get("storage_subsystem", []):
        if ctrl.get("is_boot_ctrl"):
            return str(ctrl.get("name") or ctrl.get("controller_model") or "Boot Controller").strip()
    return "N/A"


def _extract_max_nic_gbps(data: Dict[str, Any]) -> int:
    return max(
        (max((p.get("current_speed_gbps", 0) or 0 for p in n.get("ports", [])), default=0)
         for n in data.get("network_adapters", [])),
        default=0,
    )


def _extract_25g_ports_count(data: Dict[str, Any]) -> int:
    return sum(
        sum(1 for p in n.get("ports", []) if (p.get("current_speed_gbps", 0) or 0) >= 25)
        for n in data.get("network_adapters", [])
    )


def _extract_active_ports_count(data: Dict[str, Any]) -> int:
    return sum(
        sum(1 for p in n.get("ports", []) if str(p.get("link_status", "")).lower() in ("up", "linkup"))
        for n in data.get("network_adapters", [])
    )


def _extract_cna_npar_flag(data: Dict[str, Any]) -> str:
    adapters = data.get("network_adapters", [])
    has_cna = any(a.get("is_cna") for a in adapters)
    has_npar = any(a.get("is_npar") for a in adapters)
    if has_cna and has_npar:
        return "CNA & NPAR Detected"
    if has_cna:
        return "CNA Family Active"
    if has_npar:
        return "NPAR Partitioned"
    return "None (Standard)"


def _extract_connected_switches(data: Dict[str, Any]) -> str:
    switches: Set[str] = set()
    for n in data.get("lldp_neighbors", []):
        sw = n.get("switch_name")
        if sw:
            switches.add(str(sw))
    return "; ".join(sorted(switches)) if switches else "Not Discovered"


def _extract_connected_ports(data: Dict[str, Any]) -> str:
    ports: Set[str] = set()
    for n in data.get("lldp_neighbors", []):
        sw = n.get("switch_name", "")
        pt = n.get("switch_port", "")
        if pt:
            ports.add(f"{sw}:{pt}" if sw else str(pt))
    return "; ".join(sorted(ports)) if ports else "N/A"


def _extract_tpm_version(data: Dict[str, Any]) -> str:
    si = data.get("system") or {}
    badge = strip_html(si.get("tpm_status_badge", ""))
    return badge or "Not Present"


def _extract_bmc_model(data: Dict[str, Any]) -> str:
    bm = data.get("bmc_firmware") or {}
    return str(bm.get("bmc_model") or "").strip()


def _extract_bmc_fw(data: Dict[str, Any]) -> str:
    bm = data.get("bmc_firmware") or {}
    return str(bm.get("bmc_fw_version") or "").strip()


def _extract_bmc_license(data: Dict[str, Any]) -> str:
    lic = data.get("bmc_license") or {}
    return str(lic.get("license_name") or "").strip()


def _extract_ntp_skew(data: Dict[str, Any]) -> Any:
    net = data.get("bmc_net_proto") or {}
    return net.get("time_drift_seconds", 0)


def _extract_insecure_protocols(data: Dict[str, Any]) -> str:
    net = data.get("bmc_net_proto") or {}
    protos = net.get("protocols") or {}
    exposed: List[str] = []
    if protos.get("Telnet", {}).get("enabled"):
        exposed.append("Telnet")
    if protos.get("HTTP", {}).get("enabled"):
        exposed.append("HTTP(Plain)")
    if protos.get("IPMI", {}).get("enabled"):
        exposed.append("IPMI-over-LAN")
    return ", ".join(exposed) if exposed else "None (Secured)"


def _extract_psu_capacity_watts(data: Dict[str, Any]) -> Any:
    psu = data.get("psu_status") or {}
    return psu.get("total_capacity_watts", "")


def _extract_current_draw_watts(data: Dict[str, Any]) -> Any:
    psu = data.get("psu_status") or {}
    return psu.get("consumed_watts", "")


def _extract_power_cap_enforced(data: Dict[str, Any]) -> str:
    psu = data.get("psu_status") or {}
    return "Yes (Enforced)" if psu.get("power_limit_enforced") else "No"


def _extract_thermal_status(data: Dict[str, Any]) -> str:
    th = data.get("thermal_telemetry") or {}
    return strip_html(th.get("overall_status_badge", "In Spec"))


def _extract_exhaust_temp(data: Dict[str, Any]) -> str:
    th = data.get("thermal_telemetry") or {}
    ks = th.get("key_sensor") or {}
    return str(ks.get("reading") or "").strip()


def _extract_gpu_count(data: Dict[str, Any]) -> int:
    return len(data.get("gpu_accelerators", []))


def _extract_gpu_models(data: Dict[str, Any]) -> str:
    gpus = data.get("gpu_accelerators", [])
    names = [str(g.get("name") or "GPU").strip() for g in gpus]
    return "; ".join(names) if names else "None"


def _extract_gpu_vendor(data: Dict[str, Any]) -> str:
    gpus = data.get("gpu_accelerators", [])
    if not gpus:
        return "None"
    vendors: Set[str] = set()
    for g in gpus:
        raw = (str(g.get("name") or "") + " " + str(g.get("manufacturer") or "")).upper()
        if any(k in raw for k in ("NVIDIA", "TESLA", "H100", "A100", "L40", "T4")):
            vendors.add("NVIDIA")
        elif any(k in raw for k in ("AMD", "RADEON", "INSTINCT", "MI300")):
            vendors.add("AMD")
        elif any(k in raw for k in ("INTEL", "ARC", "GAUDI")):
            vendors.add("Intel")
        else:
            vendors.add("Other")
    return ", ".join(sorted(vendors))


def _extract_pcie_lane_util(data: Dict[str, Any]) -> Any:
    budget = data.get("pcie_lane_budget") or {}
    return budget.get("utilization_pct", "")


def _extract_host_os_name(data: Dict[str, Any]) -> str:
    hos = data.get("host_os") or {}
    return str(hos.get("os_name") or "").strip()


def _extract_host_os_ver(data: Dict[str, Any]) -> str:
    hos = data.get("host_os") or {}
    return str(hos.get("os_version") or "").strip()


def _extract_host_os_build(data: Dict[str, Any]) -> str:
    hos = data.get("host_os") or {}
    return str(hos.get("os_build") or "").strip()


def _extract_esxi_update_label(data: Dict[str, Any]) -> str:
    hos = data.get("host_os") or {}
    return str(hos.get("esxi_update_label") or "").strip()


def _extract_esxi_eol_status(data: Dict[str, Any]) -> str:
    hos = data.get("host_os") or {}
    return str(hos.get("eol_label") or "").strip()


def _extract_host_os_uptime(data: Dict[str, Any]) -> str:
    hos = data.get("host_os") or {}
    return str(hos.get("uptime_human") or "").strip()


def _extract_scan_profile(data: Dict[str, Any]) -> str:
    diag = data.get("diagnostics") or {}
    return str(diag.get("scan_profile") or data.get("scan_profile") or "readiness-full").strip()


def _extract_scan_duration(data: Dict[str, Any]) -> Any:
    diag = data.get("diagnostics") or {}
    return diag.get("total_scan_duration_s") or data.get("scan_duration_sec", "")


def _extract_avg_latency(data: Dict[str, Any]) -> Any:
    diag = data.get("diagnostics") or {}
    return diag.get("avg_get_latency_ms", "")


def _extract_tls_reuse_ratio(data: Dict[str, Any]) -> Any:
    diag = data.get("diagnostics") or {}
    cp = diag.get("connection_pool") or {}
    r = cp.get("tls_reuse_ratio", diag.get("tls_reuse_ratio", 0))
    return round(float(r) * 100, 1) if r else ""


def _extract_expand_syntax(data: Dict[str, Any]) -> str:
    diag = data.get("diagnostics") or {}
    if not diag.get("expand_supported"):
        return "Disabled / Unsupported"
    syn = diag.get("expand_syntax") or "*"
    levels = diag.get("expand_max_levels")
    if levels and int(levels) > 1:
        return f"$expand={syn}($levels={levels})"
    return f"$expand={syn}"


def _extract_pipelining_supported(data: Dict[str, Any]) -> str:
    diag = data.get("diagnostics") or {}
    if "multiple_http_requests" in diag:
        return "Yes" if diag.get("multiple_http_requests") else "No"
    return ""


def _extract_request_pacing(data: Dict[str, Any]) -> Any:
    diag = data.get("diagnostics") or {}
    p = diag.get("request_pacing_s")
    if p is not None:
        try:
            return round(float(p), 3)
        except (ValueError, TypeError):
            return str(p)
    return ""


# ── Full Column Registry for Fleet Summary (Schema v2.0) ──────────────────────

FLEET_SUMMARY_FIELDS: List[ExportField] = [
    # Group 1: Host & Identity
    ExportField("bmc_ip", "BMC IP", "Host", _extract_ip, is_core=True),
    ExportField("hostname", "Hostname", "Host", _extract_hostname, is_core=True),
    ExportField("dns_name", "FQDN / DNS", "Host", _extract_dns, is_core=True),
    ExportField("vendor", "Vendor", "Host", _extract_vendor, is_core=True),
    ExportField("model", "Model", "Host", _extract_model, is_core=True),
    ExportField("serial_number", "Serial / Service Tag", "Host", _extract_serial, is_core=True),
    ExportField("asset_tag", "Asset Tag", "Host", _extract_asset_tag, is_core=False),
    ExportField("sku", "SKU / Part Number", "Host", _extract_sku, is_core=False),
    ExportField("scan_status", "Scan Status", "Host", _extract_scan_status, color_rule=color_for_verdict, is_core=True),

    # Group 2: Readiness Summary Verdicts
    ExportField("vcf_support", "Overall VCF Support", "Verdicts", _extract_vcf_support, color_rule=color_for_verdict, is_core=True),
    ExportField("cpu_verdict", "CPU Support Tier", "Verdicts", _extract_cpu_verdict, color_rule=color_for_verdict, is_core=True),
    ExportField("vsan_verdict", "vSAN ESA Verdict", "Verdicts", _extract_vsan_verdict, color_rule=color_for_verdict, is_core=True),
    ExportField("mem_interleaving_verdict", "Memory Interleaving", "Verdicts", _extract_mem_interleaving_verdict, color_rule=color_for_verdict, is_core=True),
    ExportField("nic_25g_ready", "≥25GbE Network Ready", "Verdicts", _extract_nic_25g_ready, color_rule=color_for_verdict, is_core=True),
    ExportField("tpm_status", "TPM Status", "Verdicts", _extract_tpm_status, color_rule=color_for_verdict, is_core=True),
    ExportField("secure_boot", "Secure Boot", "Verdicts", _extract_secure_boot, color_rule=color_for_verdict, is_core=True),
    ExportField("psu_redundant", "PSU Redundancy", "Verdicts", _extract_psu_redundant, color_rule=color_for_verdict, is_core=True),

    # Group 3: Compute & Architecture
    ExportField("cpu_model", "CPU Model", "Compute", _extract_cpu_model, is_core=True),
    ExportField("cpu_sockets", "CPU Sockets", "Compute", _extract_cpu_sockets, is_core=True),
    ExportField("cores_per_socket", "Cores / Socket", "Compute", _extract_cores_per_socket, is_core=False),
    ExportField("total_physical_cores", "Total Physical Cores", "Compute", _extract_total_cores, is_core=True),
    ExportField("total_logical_threads", "Total Logical Threads", "Compute", _extract_total_threads, is_core=True),
    ExportField("cpu_base_ghz", "Base Clock (GHz)", "Compute", _extract_cpu_base_ghz, is_core=False),
    ExportField("cpu_max_ghz", "Max Boost Clock (GHz)", "Compute", _extract_cpu_max_ghz, is_core=False),
    ExportField("cpu_arch", "CPU Architecture", "Compute", _extract_cpu_arch, is_core=True),
    ExportField("cpu_microcode", "Microcode Revision", "Compute", _extract_cpu_microcode, is_core=False),

    # Group 4: Memory Topology
    ExportField("total_memory_gb", "Total Memory (GB)", "Memory", _extract_ram_gb, is_core=True),
    ExportField("interleaving_score_pct", "Interleaving Efficiency (%)", "Memory", _extract_interleaving_pct, color_rule=color_for_verdict, is_core=True),
    ExportField("operating_ram_speed", "Operating RAM Speed", "Memory", _extract_operating_ram_speed, is_core=False),
    ExportField("max_ram_speed", "Max CPU Rated RAM Speed", "Memory", _extract_max_ram_speed, is_core=False),
    ExportField("populated_dimms", "Populated DIMMs", "Memory", _extract_populated_dimms, is_core=True),
    ExportField("channels_per_socket", "Channels / Socket", "Memory", _extract_channels_per_socket, is_core=False),
    ExportField("dpc_status", "DPC Configuration", "Memory", _extract_dpc_status, color_rule=color_for_verdict, is_core=False),
    ExportField("memory_topology_issues", "Memory Topology Notes", "Memory", _extract_memory_issues, is_core=False),

    # Group 5: Storage & vSAN Architecture
    ExportField("esa_nvme_count", "ESA NVMe Drives Count", "Storage", _extract_esa_nvme_count, is_core=True),
    ExportField("osa_drive_count", "OSA SAS/SATA Drives Count", "Storage", _extract_osa_drive_count, is_core=True),
    ExportField("raw_nvme_capacity_tb", "Raw NVMe Capacity (TB)", "Storage", _extract_raw_nvme_tb, is_core=True),
    ExportField("total_storage_capacity_tb", "Total Storage Capacity (TB)", "Storage", _extract_total_storage_tb, is_core=True),
    ExportField("vmd_state", "Intel VMD State", "Storage", _extract_vmd_state, color_rule=color_for_verdict, is_core=True),
    ExportField("trimode_blocked", "Tri-Mode RAID Blocked", "Storage", _extract_trimode_blocked, color_rule=color_for_verdict, is_core=True),
    ExportField("software_raid", "Host Software RAID", "Storage", _extract_software_raid, is_core=False),
    ExportField("boot_device", "Boot Target Device", "Storage", _extract_boot_device, is_core=False),
    ExportField("boot_controller", "Boot Controller", "Storage", _extract_boot_controller, is_core=False),

    # Group 6: Network & Switch Fabric
    ExportField("max_nic_speed_gbps", "Max NIC Speed (Gbps)", "Network", _extract_max_nic_gbps, is_core=True),
    ExportField("nic_25g_ports_count", "≥25GbE Ports Count", "Network", _extract_25g_ports_count, is_core=True),
    ExportField("active_ports_count", "Active Ports Up", "Network", _extract_active_ports_count, is_core=False),
    ExportField("cna_npar_flag", "CNA / NPAR State", "Network", _extract_cna_npar_flag, color_rule=color_for_verdict, is_core=True),
    ExportField("connected_switches", "Connected LLDP Switch", "Network", _extract_connected_switches, is_core=True),
    ExportField("connected_ports", "Connected Switch Port", "Network", _extract_connected_ports, is_core=False),

    # Group 7: Security & BMC Baseline
    ExportField("tpm_version", "TPM Version & Health", "Security", _extract_tpm_version, color_rule=color_for_verdict, is_core=True),
    ExportField("bmc_model", "BMC Controller Model", "Security", _extract_bmc_model, is_core=True),
    ExportField("bmc_fw", "BMC Firmware Version", "Security", _extract_bmc_fw, is_core=True),
    ExportField("bmc_license", "BMC License Tier", "Security", _extract_bmc_license, is_core=False),
    ExportField("ntp_skew_seconds", "NTP Skew (seconds)", "Security", _extract_ntp_skew, color_rule=color_for_verdict, is_core=False),
    ExportField("insecure_protocols", "Insecure Protocols Exposed", "Security", _extract_insecure_protocols, color_rule=color_for_verdict, is_core=True),

    # Group 8: Power & Thermal
    ExportField("psu_capacity_watts", "Total PSU Capacity (W)", "Power", _extract_psu_capacity_watts, is_core=False),
    ExportField("current_draw_watts", "Current Power Draw (W)", "Power", _extract_current_draw_watts, is_core=False),
    ExportField("power_cap_enforced", "Power Cap Enforced", "Power", _extract_power_cap_enforced, color_rule=color_for_verdict, is_core=False),
    ExportField("thermal_status", "Thermal Status", "Power", _extract_thermal_status, color_rule=color_for_verdict, is_core=False),
    ExportField("exhaust_temp", "Exhaust Temperature (°C)", "Power", _extract_exhaust_temp, is_core=False),

    # Group 9: Accelerators & PCIe
    ExportField("gpu_count", "GPU Accelerator Count", "GPU", _extract_gpu_count, is_core=True),
    ExportField("gpu_models", "GPU Models", "GPU", _extract_gpu_models, is_core=True),
    ExportField("gpu_vendor", "GPU Vendor Family", "GPU", _extract_gpu_vendor, is_core=False),
    ExportField("pcie_lane_util", "PCIe Lane Utilization (%)", "GPU", _extract_pcie_lane_util, is_core=False),

    # Group 10: Host OS & ESXi Lifecycle
    ExportField("host_os_name", "Installed OS Name", "OS", _extract_host_os_name, is_core=False),
    ExportField("host_os_ver", "Installed OS Version", "OS", _extract_host_os_ver, is_core=False),
    ExportField("host_os_build", "OS Build Number", "OS", _extract_host_os_build, is_core=False),
    ExportField("host_os_uptime", "OS Continuous Uptime", "OS", _extract_host_os_uptime, is_core=False),
    ExportField("esxi_update_label", "ESXi Release Label", "OS", _extract_esxi_update_label, is_core=True),
    ExportField("esxi_eol_status", "ESXi Support Lifecycle EOL", "OS", _extract_esxi_eol_status, color_rule=color_for_verdict, is_core=True),

    # Group 11: Diagnostics & Performance
    ExportField("scan_profile", "Scan Profile", "Diagnostics", _extract_scan_profile, is_core=False),
    ExportField("scan_duration_sec", "Scan Duration (s)", "Diagnostics", _extract_scan_duration, is_core=False),
    ExportField("avg_latency_ms", "Avg BMC Latency (ms)", "Diagnostics", _extract_avg_latency, is_core=False),
    ExportField("tls_reuse_ratio", "TLS Keep-Alive Reuse (%)", "Diagnostics", _extract_tls_reuse_ratio, is_core=False),
    ExportField("redfish_expand_syntax", "Redfish Expand Syntax", "Diagnostics", _extract_expand_syntax, is_core=False),
    ExportField("pipelining_supported", "Pipelining Supported", "Diagnostics", _extract_pipelining_supported, is_core=False),
    ExportField("request_pacing_s", "Request Pacing (s)", "Diagnostics", _extract_request_pacing, is_core=False),
]
