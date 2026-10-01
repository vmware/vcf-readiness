"""Fleet health dashboard tiles generator."""
import json
import logging
import re

from vcf_hci.compat_engine import VCF9CompatibilityEngine
from vcf_hci.constants import (
    ESXI_KB_URL,
    VCF_MANAGEMENT_PROFILES,
    VCF_PLANNING_WORKBOOK_URL,
    VCF_SIZER_URL,
)
from vcf_hci.hcl import evaluate_drive_hcl_tier, load_optional_vsan_csv, load_vsan_hcl_json
from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.obfuscation import _pii_span
from vcf_hci.report.helpers import _h
from vcf_hci.report.styles import FLEET_EXTRA_CSS
from vcf_hci.report.switch_topology import build_fleet_switch_topology
from vcf_hci.security.scoring import aggregate_fleet_security

logger = logging.getLogger("vcf_assess")


def build_fleet_tiles_html(all_results: list, report_prefix: str = "vsphere_vsan_report_", page_salt: str = "") -> str:
    """Return a self-contained HTML snippet (style + tile grid + script) for the
    13-tile fleet health dashboard.  Callers embed the returned string wherever
    they need the tiles — both the standalone fleet_summary.html and the GUI's
    combined tabbed report use this single source of truth.
    """
    host_count = len(all_results)

    json_hcl = load_vsan_hcl_json()
    csv_db = load_optional_vsan_csv()
    for data in all_results:
        si = data.get("system") or {}
        ci = si.get("cpu_summary") or {}
        if ci.get("model"):
            v_fresh, arch_fresh, _, _, _ = VCF9CompatibilityEngine.evaluate_cpu(
                ci.get("model", ""), si.get("vendor", ""), si.get("model", "")
            )
            ci["verdict"] = v_fresh
            if not ci.get("architecture") or ci.get("architecture") == "Unknown":
                ci["architecture"] = arch_fresh
        for ctrl in data.get("storage_subsystem", []):
            for d in ctrl.get("drives", []):
                if d.get("populated", True):
                    eval_hcl = evaluate_drive_hcl_tier(d, json_hcl=json_hcl, csv_db=csv_db)
                    d["category"] = eval_hcl["category"]
                    d["status_badge"] = eval_hcl["status_badge"]
                    d["hcl_str"] = eval_hcl["hcl_str"]
                    d["vsan_eligible"] = eval_hcl["vsan_eligible"]

    # ── Tile 1: Resource Headroom ─────────────────────────────────────────────
    fleet_vcpu = 0
    fleet_ram_gb = 0
    fleet_nvme_tb = 0.0
    for data in all_results:
        si = data.get("system", {})
        ci = si.get("cpu_summary", {})
        sockets = ci.get("count", 1)
        cores = ci.get("core_count", 0)
        if isinstance(cores, int):
            fleet_vcpu += sockets * cores
        raw_mem = si.get("total_memory_gb")
        if isinstance(raw_mem, (int, float)):
            fleet_ram_gb += int(raw_mem)
        elif isinstance(raw_mem, str) and raw_mem.strip().isdigit():
            fleet_ram_gb += int(raw_mem.strip())
        for ctrl in data.get("storage_subsystem", []):
            for d in ctrl.get("drives", []):
                if d.get("category") == "vSAN ESA/OSA NVMe":
                    d_cap = d.get("capacity_gb")
                    if isinstance(d_cap, (int, float)) and d_cap > 0:
                        fleet_nvme_tb += d_cap / 1024
    fleet_nvme_tb = round(fleet_nvme_tb, 2)

    # ── Tile 2: BIOS Status ───────────────────────────────────────────────────
    bios_outdated = bios_update_avail = bios_no_baseline = 0
    bios_spectre_exposed = bios_spectre_ok = bios_spectre_unverified = 0
    for data in all_results:
        be = (data.get("system") or {}).get("bios_eval") or {}
        badge = be.get("badge", "")
        if "danger" in badge:
            bios_outdated += 1
        elif "warning" in badge:
            bios_update_avail += 1
        elif "info" in badge:
            bios_no_baseline += 1
        sp = be.get("spectre_status", "unverified")
        if sp == "exposed":
            bios_spectre_exposed += 1
        elif sp == "ok":
            bios_spectre_ok += 1
        else:
            bios_spectre_unverified += 1

    # ── Tile 3: CPU Fingerprint ───────────────────────────────────────────────
    cpu_fp: dict = {}
    for data in all_results:
        ci = (data.get("system") or {}).get("cpu_summary") or {}
        arch = ci.get("architecture", "Unknown")
        cores = ci.get("core_count", "?")
        sockets = ci.get("count", 1)
        key = (arch, cores, sockets)
        cpu_fp[key] = cpu_fp.get(key, 0) + 1
    cpu_fp_sorted = sorted(cpu_fp.items(), key=lambda x: -x[1])

    # ── GPU Fingerprint ───────────────────────────────────────────────────────
    # Classify each GPU by vendor family; track model name for the top entry per family
    _gpu_nvidia: dict = {}
    _gpu_amd: dict = {}
    _gpu_intel: dict = {}
    _gpu_other: dict = {}
    _nvidia_kw = {"NVIDIA", "TESLA", "H100", "H200", "A100", "A30", "A40", "L40", "V100", "L4", "T4", "A10", "A16"}
    _amd_kw = {"AMD", "RADEON", "INSTINCT", "MI300", "MI250", "MI200", "MI100"}
    _intel_kw = {"INTEL", "ARC", "GAUDI", "A770", "A750"}
    for data in all_results:
        for gpu in data.get("gpu_accelerators", []):
            _raw = (str(gpu.get("name") or "") + " " + str(gpu.get("manufacturer") or "")).upper()
            _model_key = str(gpu.get("name") or "Unknown GPU").strip()
            if any(k in _raw for k in _nvidia_kw):
                _gpu_nvidia[_model_key] = _gpu_nvidia.get(_model_key, 0) + 1
            elif any(k in _raw for k in _amd_kw):
                _gpu_amd[_model_key] = _gpu_amd.get(_model_key, 0) + 1
            elif any(k in _raw for k in _intel_kw):
                _gpu_intel[_model_key] = _gpu_intel.get(_model_key, 0) + 1
            else:
                _gpu_other[_model_key] = _gpu_other.get(_model_key, 0) + 1

    # ── Tile 4: VCF Support Tier ──────────────────────────────────────────────
    vcf_supported = vcf_deprecated = vcf_unsupported = 0
    for data in all_results:
        v = ((data.get("system") or {}).get("cpu_summary") or {}).get("verdict", "")
        if "Unsupported" in v:
            vcf_unsupported += 1
        elif "Deprecated" in v:
            vcf_deprecated += 1
        else:
            vcf_supported += 1

    # ── Tile 5: TPM Compliance ────────────────────────────────────────────────
    tpm_ok = sum(1 for data in all_results
                 if "success" in (data.get("system") or {}).get("tpm_status_badge", ""))

    # ── Tile 6: NIC Speed Tier ────────────────────────────────────────────────
    nic_100g = nic_25g = nic_10g = nic_sub10g = 0
    for data in all_results:
        max_spd = max(
            (max((p.get("current_speed_gbps", 0) or 0 for p in n.get("ports", [])), default=0)
             for n in data.get("network_adapters", [])),
            default=0,
        )
        if max_spd >= 100:
            nic_100g += 1
        elif max_spd >= 25:
            nic_25g += 1
        elif max_spd >= 10:
            nic_10g += 1
        else:
            nic_sub10g += 1

    # ── Tile 7: Power Health ──────────────────────────────────────────────────
    psu_redundant = psu_single = psu_unknown = 0
    psu_capped = 0
    fleet_power_draw_w = 0
    hosts_with_power = 0
    fleet_peak_power_w = 0
    hosts_with_peak = 0
    for data in all_results:
        p = data.get("psu_status", {})
        if p.get("redundant"):
            psu_redundant += 1
        elif p.get("psus"):
            psu_single += 1
        else:
            psu_unknown += 1
        if p.get("power_limit_enforced"):
            psu_capped += 1
        cw = p.get("consumed_watts")
        if cw is not None:
            fleet_power_draw_w += cw
            hosts_with_power += 1
        pm = p.get("power_metrics") or {}
        max_w = pm.get("max_w")
        if max_w is not None:
            fleet_peak_power_w += max_w
            hosts_with_peak += 1

    # ── Tile 8: vSAN Distribution ─────────────────────────────────────────────
    vsan_esa = vsan_osa = vsan_none = 0
    for data in all_results:
        drives = [d for ctrl in data.get("storage_subsystem", []) for d in ctrl.get("drives", [])]
        nvme_direct = sum(1 for d in drives if d.get("category") == "vSAN ESA/OSA NVMe")
        sas_sata = sum(1 for d in drives if d.get("category") in ("vSAN OSA Only", "vSAN OSA SAS/SATA"))
        vmd_on = (data.get("bios_checks") or {}).get("vmd_enabled_flag", False)
        trimode_nvme = sum(1 for d in drives if d.get("behind_trimode") or d.get("category") == "Unsupported NVMe Tri-Mode")
        raid_nvme = sum(1 for d in drives if d.get("category") == "Unsupported NVMe RAID" and not d.get("behind_trimode"))
        max_nic = max(
            (max((p.get("current_speed_gbps", 0) or 0 for p in n.get("ports", [])), default=0)
             for n in data.get("network_adapters", [])),
            default=0,
        )
        verdict, _ = VCF9CompatibilityEngine.evaluate_vsan(
            nvme_direct,
            sas_sata,
            max_nic,
            vmd_enabled=vmd_on,
            trimode_nvme_count=trimode_nvme,
            raid_nvme_count=raid_nvme,
        )
        if "ESA Ready" in verdict:
            vsan_esa += 1
        elif "OSA" in verdict or "ESA Storage Met" in verdict:
            vsan_osa += 1
        else:
            vsan_none += 1

    # ── Tile 9: Drive Endurance ───────────────────────────────────────────────
    drives_critical = drives_watch = 0
    for data in all_results:
        for ctrl in data.get("storage_subsystem", []):
            for d in ctrl.get("drives", []):
                ep = d.get("endurance_remaining_pct")
                if isinstance(ep, (int, float)):
                    if ep < 20:
                        drives_critical += 1
                    elif ep < 50:
                        drives_watch += 1

    # ── Tile 10: SEL Alarm Summary ────────────────────────────────────────────
    sel_critical_hosts = sel_warning_hosts = 0
    for data in all_results:
        alarms = data.get("sel_alarms", [])
        if any("danger" in a.get("badge", "") for a in alarms):
            sel_critical_hosts += 1
        elif any("warning" in a.get("badge", "") for a in alarms):
            sel_warning_hosts += 1

    # ── Tile 11: VMD Status ───────────────────────────────────────────────────
    vmd_on = sum(1 for data in all_results
                 if (data.get("bios_checks") or {}).get("vmd_enabled_flag", False))

    # ── Tile 12: Memory Distribution ──────────────────────────────────────────
    mem_lt256 = mem_256_511 = mem_512_1023 = mem_gt1023 = 0
    for data in all_results:
        ram = (data.get("system") or {}).get("total_memory_gb", 0)
        if ram < 256:
            mem_lt256 += 1
        elif ram < 512:
            mem_256_511 += 1
        elif ram <= 1024:
            mem_512_1023 += 1
        else:
            mem_gt1023 += 1

    # ── Tile 13: Hardware Fault Roster ────────────────────────────────────────
    fault_rows_html = ""
    any_faults = False
    fault_row_count = 0
    for idx, data in enumerate(all_results):
        si = data.get("system", {})
        hostname = si.get("hostname", si.get("ip", "Unknown"))
        ip = si.get("ip", "")
        report_file = f"{report_prefix}{sanitize_filename(si.get('ip', 'unknown'))}.html"
        faults = []
        for df in (data.get("memory_subsystem") or {}).get("failed_dimms") or []:
            faults.append(f"DIMM {df.get('slot','?')}: {df.get('state','?')} / {df.get('health','?')}")
        for pu in (data.get("psu_status") or {}).get("psus") or []:
            if pu.get("health") not in ("OK", "Ok", ""):
                faults.append(f"{pu.get('name', 'PSU')}: {pu.get('health', '?')}")
        for ff in (data.get("thermal_telemetry") or {}).get("fan_faults") or []:
            rpm = ff.get("reading_rpm", "N/A")
            rpm_str = f"{rpm} RPM" if isinstance(rpm, (int, float)) else "N/A"
            faults.append(f"{ff.get('name', 'Fan')}: {ff.get('health', '?')} ({rpm_str})")
        for ctrl in data.get("storage_subsystem", []):
            for d in ctrl.get("drives", []):
                if not d.get("populated", True):
                    continue
                dh = d.get("drive_health", "OK")
                dname = d.get("model") or d.get("name") or d.get("id", "Drive")
                slot_s = f"Slot {d.get('bay_slot')}" if d.get("bay_slot") is not None else dname
                if d.get("failure_predicted"):
                    faults.append(f"Drive {slot_s}: Predictive Failure Flagged")
                elif dh not in ("OK", "Ok", "", None):
                    faults.append(f"Drive {slot_s}: {dh}")
                elif isinstance(d.get("endurance_remaining_pct"), (int, float)) and d["endurance_remaining_pct"] < 20:
                    faults.append(f"Drive {slot_s}: Low Endurance ({d['endurance_remaining_pct']}%)")
                elif isinstance(d.get("media_errors"), (int, float)) and d["media_errors"] > 0:
                    faults.append(f"Drive {slot_s}: {d['media_errors']} Media Errors")
        if faults:
            any_faults = True
            fault_row_count += 1
            items_html = "&nbsp;&nbsp;|&nbsp;&nbsp;".join(faults)
            _is_obf_prefix = report_prefix.startswith("reports/OBFUSCATED_") or report_prefix.startswith("OBFUSCATED_")
            _disp_hostname = _h(hostname) if (not page_salt or _is_obf_prefix) else _pii_span(page_salt, hostname, "host")
            _disp_ip       = _h(ip) if (not page_salt or _is_obf_prefix) else _pii_span(page_salt, ip, "ip")
            if not report_prefix:
                link_html = f"<a href='#' class='btn-link tab-jump' data-tab='{idx + 2}' style='color:var(--primary,#2563eb);text-decoration:none;font-weight:600'>{_disp_hostname}</a>"
            else:
                link_html = f"<a href='{_h(report_file)}' data-href='{_h(report_file)}' style='color:var(--primary,#2563eb);text-decoration:none;font-weight:600'>{_disp_hostname}</a>"
            fault_rows_html += (
                f"<tr>"
                f"<td>{link_html}"
                f"<br><small style='color:var(--text-muted,#64748b)'>{_disp_ip}</small></td>"
                f"<td style='color:var(--danger,#dc2626)'>&#9888;&nbsp;{items_html}</td>"
                f"</tr>"
            )

    # ── OS Diversity tile data ────────────────────────────────────────────────
    os_esxi9  = os_esxi8  = os_esxi7  = os_esxi6  = 0
    os_win    = os_linux  = os_other  = os_unknown = 0
    os_eol_count = 0
    has_any_host_os = False
    for data in all_results:
        _hos = data.get("host_os", {})
        if isinstance(_hos, dict) and bool(
            _hos.get("os_name")
            or _hos.get("os_version")
            or _hos.get("esxi_update_label")
            or _hos.get("os_description")
            or _hos.get("os_build")
        ):
            has_any_host_os = True
        _oname = (_hos.get("os_name") or "").upper()
        _over  = (_hos.get("os_version") or "").upper()
        _oeol  = _hos.get("eol_label", "")
        _combo = f"{_oname} {_over}"
        if "EOL" in _oeol:
            os_eol_count += 1
        if re.search(r'ESXI|VMWARE|VSPHERE', _combo):
            _vm = re.search(r'(\d+)\.', _over)
            _major = int(_vm.group(1)) if _vm else 0
            if _major >= 9:
                os_esxi9 += 1
            elif _major == 8:
                os_esxi8 += 1
            elif _major == 7:
                os_esxi7 += 1
            elif _major in (6, 5):
                os_esxi6 += 1
            else:
                os_esxi8 += 1   # version unknown, count as ESXi generic
        elif re.search(r'WINDOWS|WIN SERVER', _combo):
            os_win += 1
        elif re.search(r'LINUX|RHEL|UBUNTU|CENTOS|SUSE|DEBIAN|FEDORA|ORACLE', _combo):
            os_linux += 1
        elif _oname:
            os_other += 1
        else:
            os_unknown += 1

    # ── HTML fragment helper ──────────────────────────────────────────────────
    def _bar_row(label: str, cnt: int, color: str) -> str:
        if not cnt:
            return ""
        pct = round(cnt / host_count * 100) if host_count else 0
        return (
            f"<div style='margin:.3rem 0;font-size:.83rem'>"
            f"<span style='color:{color};font-weight:600'>{cnt}\u00d7</span> {label}"
            f"<div style='height:6px;background:#e2e8f0;border-radius:3px;margin-top:2px'>"
            f"<div style='height:6px;width:{pct}%;background:{color};border-radius:3px'>"
            f"</div></div></div>"
        )

    # BIOS tile HTML
    if bios_outdated + bios_update_avail == 0:
        bios_html = "<div style='color:#16a34a;font-weight:600'>&#10003; All hosts with baselines are current</div>"
        if bios_no_baseline:
            bios_html += (f"<div style='color:#64748b;font-size:.82rem;margin-top:.4rem'>"
                          f"&#8505; {bios_no_baseline} host(s) \u2014 no baseline on file</div>")
    else:
        bios_parts = []
        if bios_outdated:
            bios_parts.append(f"<div style='color:#dc2626;font-weight:600'>&#128308; {bios_outdated} host(s) \u2014 Outdated</div>")
        if bios_update_avail:
            bios_parts.append(f"<div style='color:#ca8a04;font-weight:600'>&#128993; {bios_update_avail} host(s) \u2014 Update Available</div>")
        if bios_no_baseline:
            bios_parts.append(f"<div style='color:#64748b;font-size:.82rem'>&#8505; {bios_no_baseline} \u2014 No Baseline on File</div>")
        bios_html = "".join(bios_parts)
    # Append spectre sub-row to BIOS tile
    if bios_spectre_exposed:
        bios_html += (
            f"<div style='margin-top:.5rem;padding:.4rem .6rem;background:var(--tint-danger-bg,#fef2f2);"
            f"border-left:3px solid var(--danger,#dc2626);border-radius:3px;font-size:.82rem;"
            f"color:var(--tint-danger-text,#991b1b);font-weight:600'>"
            f"&#9888; {bios_spectre_exposed} host(s) \u2014 Pre-Spectre BIOS (update BIOS immediately)</div>"
        )
        if bios_spectre_unverified:
            bios_html += (
                f"<div style='margin-top:.25rem;font-size:.79rem;color:#64748b'>"
                f"&#8505; {bios_spectre_unverified} host(s) \u2014 no spectre baseline on file</div>"
            )
    elif bios_spectre_ok:
        bios_html += (
            f"<div style='margin-top:.5rem;font-size:.8rem;color:#16a34a'>"
            f"&#128737; {bios_spectre_ok} host(s) \u2014 Spectre/Meltdown microcode confirmed</div>"
        )
        if bios_spectre_unverified:
            bios_html += (
                f"<div style='margin-top:.25rem;font-size:.79rem;color:#64748b'>"
                f"&#8505; {bios_spectre_unverified} host(s) \u2014 no spectre baseline on file</div>"
            )
    else:
        bios_html += (
            f"<div style='margin-top:.5rem;font-size:.79rem;color:#64748b'>"
            f"&#8505; {bios_spectre_unverified} host(s) \u2014 no spectre baseline on file</div>"
        )

    # CPU fingerprint tile HTML
    fp_rows = ""
    for (arch, cores, sockets), cnt in cpu_fp_sorted[:6]:
        fp_rows += (
            f"<div style='display:flex;justify-content:space-between;padding:.3rem 0;"
            f"border-bottom:1px solid var(--border,#e2e8f0);font-size:.84rem'>"
            f"<span><b>{cnt}\u00d7</b>&nbsp;{arch}</span>"
            f"<span style='color:#64748b'>{cores}-core \u00d7 {sockets}-socket</span></div>"
        )
    if not fp_rows:
        fp_rows = "<div style='color:#94a3b8;font-size:.85rem'>No CPU data available</div>"

    # GPU fingerprint tile HTML
    def _gpu_vendor_rows(fp_dict: dict, label: str, color: str) -> str:
        if not fp_dict:
            return ""
        top_models = sorted(fp_dict.items(), key=lambda x: -x[1])
        total = sum(fp_dict.values())
        model_str = ", ".join(f"{c}\u00d7 {m}" for m, c in top_models[:3])
        return (
            f"<div style='padding:.3rem 0;border-bottom:1px solid var(--border,#e2e8f0);font-size:.84rem'>"
            f"<div style='display:flex;justify-content:space-between'>"
            f"<span style='font-weight:600;color:{color}'>{label}</span>"
            f"<span style='color:#64748b'>{total} GPU(s)</span></div>"
            f"<div style='color:#475569;font-size:.78rem;margin-top:.15rem'>{model_str}</div>"
            f"</div>"
        )
    gpu_fp_rows = (
        _gpu_vendor_rows(_gpu_nvidia, "Nvidia", "#16a34a") +
        _gpu_vendor_rows(_gpu_amd, "AMD", "#dc2626") +
        _gpu_vendor_rows(_gpu_intel, "Intel", "var(--primary,#2563eb)") +
        _gpu_vendor_rows(_gpu_other, "Other", "#64748b")
    )
    total_gpus = sum(sum(d.values()) for d in [_gpu_nvidia, _gpu_amd, _gpu_intel, _gpu_other])
    if not gpu_fp_rows:
        gpu_fp_html = "<div style='color:#94a3b8;font-size:.85rem'>No GPU accelerators detected</div>"
    else:
        gpu_fp_html = (
            f"<div style='font-size:.82rem;color:#475569;margin-bottom:.4rem'>"
            f"{total_gpus} GPU(s) across fleet</div>"
            f"{gpu_fp_rows}"
        )

    # VCF support tier tile HTML
    vcf_tier_parts = []
    if vcf_supported:
        vcf_tier_parts.append(f"<div style='color:#16a34a;font-weight:600'>&#128994; {vcf_supported} \u2014 Fully Supported</div>")
    if vcf_deprecated:
        vcf_tier_parts.append(f"<div style='color:#ca8a04;font-weight:600'>&#128993; {vcf_deprecated} \u2014 Deprecated Mode</div>")
    if vcf_unsupported:
        vcf_tier_parts.append(f"<div style='color:#dc2626;font-weight:600'>&#128308; {vcf_unsupported} \u2014 Unsupported for VCF 9.x</div>")
    vcf_tier_html = "".join(vcf_tier_parts) or "<div style='color:#94a3b8'>No data</div>"

    # TPM tile HTML
    tpm_pct = round(tpm_ok / host_count * 100) if host_count else 0
    tpm_color = "#16a34a" if tpm_pct == 100 else ("#ca8a04" if tpm_pct >= 50 else "#dc2626")
    tpm_html = (
        f"<div style='font-size:1.5rem;font-weight:700;color:{tpm_color}'>{tpm_ok}/{host_count}</div>"
        f"<div style='color:#64748b;font-size:.82rem'>{tpm_pct}% compliant \u2014 VCF 9.1 requires TPM 2.0</div>"
        f"<div style='height:8px;background:#e2e8f0;border-radius:4px;margin-top:.6rem'>"
        f"<div style='height:8px;width:{tpm_pct}%;background:{tpm_color};border-radius:4px'></div></div>"
    )

    # NIC tile HTML
    nic_html = (
        _bar_row("100 GbE+", nic_100g, "#16a34a") +
        _bar_row("25 GbE", nic_25g, "#16a34a") +
        _bar_row("10 GbE (upgrade needed for ESA)", nic_10g, "#ca8a04") +
        _bar_row("&lt;10 GbE / Unknown", nic_sub10g, "#dc2626")
    ) or "<div style='color:#94a3b8;font-size:.85rem'>No NIC data collected</div>"

    # Power Health tile HTML (PSU redundancy + live power consumption)
    psu_parts = []
    if psu_redundant:
        psu_parts.append(f"<div style='color:#16a34a;font-weight:600'>&#128994; {psu_redundant} redundant</div>")
    if psu_single:
        psu_parts.append(f"<div style='color:#ca8a04;font-weight:600'>&#128993; {psu_single} single PSU (no redundancy)</div>")
    if psu_unknown:
        psu_parts.append(f"<div style='color:#64748b'>&#8505; {psu_unknown} unknown</div>")
    if psu_capped:
        psu_parts.append(
            f"<div style='color:#ca8a04;font-weight:600'>"
            f"&#9888; {psu_capped} power cap enforced "
            f"<span style='font-weight:400'>(BIOS/BMC power limit — vSAN throttle risk)</span></div>"
        )
    # Power consumption section
    hosts_no_power = host_count - hosts_with_power
    psu_parts.append("<hr style='border:none;border-top:1px solid var(--border,#e2e8f0);margin:.5rem 0'>")
    if hosts_with_power:
        _no_pwr_note = (f" <span style='color:var(--text-muted,#94a3b8);font-size:.78rem'>({hosts_no_power} not reporting)</span>"
                        if hosts_no_power else "")
        psu_parts.append(
            f"<div style='font-size:.84rem'>"
            f"<span style='font-weight:600;color:var(--text)'>&#9889; Total Draw:</span> "
            f"<span style='color:var(--primary,#2563eb);font-weight:700'>{fleet_power_draw_w:,} W</span>"
            f" across {hosts_with_power} host(s){_no_pwr_note}</div>"
        )
        if hosts_with_peak:
            psu_parts.append(
                f"<div style='font-size:.84rem;margin-top:.25rem'>"
                f"<span style='font-weight:600;color:var(--text)'>&#128200; Peak Recorded:</span> "
                f"<span style='color:var(--warning,#ca8a04);font-weight:700'>{fleet_peak_power_w:,} W</span>"
                f" across {hosts_with_peak} host(s)</div>"
            )
    else:
        _no_pwr_note = "<span style='color:var(--text-muted,#94a3b8);font-size:.82rem'>&#8505; No live power draw data available</span>"
        if hosts_no_power:
            _no_pwr_note += f"<span style='color:var(--text-muted,#94a3b8);font-size:.78rem'> ({hosts_no_power} host(s) not reporting)</span>"
        psu_parts.append(f"<div>{_no_pwr_note}</div>")
    psu_tile_html = "".join(psu_parts) or "<div style='color:#94a3b8'>No PSU data</div>"

    # vSAN tile HTML (includes VMD status sub-section)
    vsan_parts = []
    if vsan_esa:
        vsan_parts.append(f"<div style='color:#16a34a;font-weight:600'>&#128994; {vsan_esa} \u2014 ESA Ready (\u22652 NVMe + 25 GbE)</div>")
    if vsan_osa:
        vsan_parts.append(f"<div style='color:#ca8a04;font-weight:600'>&#128993; {vsan_osa} \u2014 OSA / Needs NIC Upgrade</div>")
    if vsan_none:
        vsan_parts.append(f"<div style='color:#dc2626;font-weight:600'>&#128308; {vsan_none} \u2014 Needs Attention</div>")
    # VMD sub-section merged here
    vsan_parts.append("<hr style='border:none;border-top:1px solid var(--border,#e2e8f0);margin:.5rem 0'>")
    if vmd_on == 0:
        vsan_parts.append("<div style='color:#16a34a;font-size:.82rem;font-weight:600'>&#10003; Intel VMD: disabled on all hosts</div>")
    else:
        vsan_parts.append(
            f"<div style='color:#dc2626;font-size:.82rem;font-weight:600'>&#128308; Intel VMD: {vmd_on} host(s) \u2014 enabled</div>"
            f"<div style='color:#64748b;font-size:.79rem;margin-top:.2rem'>"
            f"Must be disabled in BIOS for native NVMe pass-through</div>"
        )
    vsan_tile_html = "".join(vsan_parts) or "<div style='color:#94a3b8'>No storage data</div>"

    # Drive endurance tile HTML
    if drives_critical == 0 and drives_watch == 0:
        endurance_html = "<div style='color:#16a34a;font-weight:600'>&#10003; All drives within healthy range</div>"
    else:
        end_parts = []
        if drives_critical:
            end_parts.append(f"<div style='color:#dc2626;font-weight:600'>&#128308; {drives_critical} drive(s) \u2014 Critical (&lt;20% life)</div>")
        if drives_watch:
            end_parts.append(f"<div style='color:#ca8a04;font-weight:600'>&#128993; {drives_watch} drive(s) \u2014 Watch (20\u201350% remaining)</div>")
        endurance_html = "".join(end_parts)

    # SEL tile HTML
    if sel_critical_hosts == 0 and sel_warning_hosts == 0:
        sel_tile_html = "<div style='color:#16a34a;font-weight:600'>&#10003; No active SEL alarms across fleet</div>"
    else:
        sel_parts = []
        if sel_critical_hosts:
            sel_parts.append(f"<div style='color:#dc2626;font-weight:600'>&#128308; {sel_critical_hosts} host(s) \u2014 Critical alarms</div>")
        if sel_warning_hosts:
            sel_parts.append(f"<div style='color:#ca8a04;font-weight:600'>&#128993; {sel_warning_hosts} host(s) \u2014 Warning alarms</div>")
        sel_tile_html = "".join(sel_parts)

    # Memory distribution tile HTML
    mem_tile_html = (
        _bar_row("&lt;256 GB", mem_lt256, "#dc2626") +
        _bar_row("256\u2013511 GB", mem_256_511, "#ca8a04") +
        _bar_row("512 GB \u2013 1 TB", mem_512_1023, "#16a34a") +
        _bar_row("&gt;1 TB", mem_gt1023, "var(--primary,#2563eb)")
    ) or "<div style='color:#94a3b8;font-size:.85rem'>No memory data</div>"

    # Fault roster tile HTML
    if any_faults:
        _fault_scroll_style = (
            "max-height:290px;overflow-y:auto;border:1px solid var(--border,#e2e8f0);border-radius:6px"
            if fault_row_count > 5 else ""
        )
        _scroll_hint = (
            f"<div style='font-size:.75rem;color:var(--text-muted,#64748b);margin-bottom:.4rem'>"
            f"Showing {fault_row_count} hosts with faults — scroll to view all</div>"
            if fault_row_count > 5 else ""
        )
        fault_tile_html = (
            f"{_scroll_hint}"
            f"<div style='{_fault_scroll_style}'>"
            "<table style='width:100%;border-collapse:collapse;font-size:.85rem'>"
            "<thead><tr>"
            "<th style='position:sticky;top:0;z-index:1;padding:.4rem .75rem;background:var(--th-bg,#f8fafc);"
            "color:var(--text,#1e293b);border-bottom:1px solid var(--border,#e2e8f0);text-align:left;width:220px'>Host</th>"
            "<th style='position:sticky;top:0;z-index:1;padding:.4rem .75rem;background:var(--th-bg,#f8fafc);"
            "color:var(--text,#1e293b);border-bottom:1px solid var(--border,#e2e8f0);text-align:left'>Faults Detected</th>"
            f"</tr></thead><tbody>{fault_rows_html}</tbody></table>"
            "</div>"
        )
    else:
        fault_tile_html = "<div style='color:var(--success,#16a34a);font-weight:600'>&#10003; No component faults detected across the fleet</div>"

    # OS diversity tile HTML
    _os_tile_parts = []
    if os_esxi9:
        _os_tile_parts.append(
            f"<div style='color:#16a34a;font-weight:600'>&#128994; {os_esxi9} &mdash; ESXi 9.x (VCF 9.1 Ready)</div>"
        )
    if os_esxi8:
        _os_tile_parts.append(
            f"<div style='color:#ca8a04;font-weight:600'>&#128993; {os_esxi8} &mdash; ESXi 8.x (Upgrade path to 9.1)</div>"
        )
    if os_esxi7:
        _os_tile_parts.append(
            f"<div style='color:#dc2626;font-weight:600'>&#128308; {os_esxi7} &mdash; ESXi 7.x <span style='font-weight:400'>(EOL Apr 2025)</span></div>"
        )
    if os_esxi6:
        _os_tile_parts.append(
            f"<div style='color:#dc2626;font-weight:600'>&#128308; {os_esxi6} &mdash; ESXi 6.x <span style='font-weight:400'>(EOL)</span></div>"
        )
    if os_win:
        _os_tile_parts.append(f"<div style='color:var(--primary,#60a5fa);font-weight:600'>&#128250; {os_win} &mdash; Windows Server</div>")
    if os_linux:
        _os_tile_parts.append(f"<div style='color:#64748b;font-weight:600'>&#128039; {os_linux} &mdash; Linux</div>")
    if os_other:
        _os_tile_parts.append(f"<div style='color:#64748b'>&bull; {os_other} &mdash; Other OS</div>")
    if os_unknown:
        _os_tile_parts.append(
            f"<div style='color:#94a3b8;font-size:.84rem'>&#8505; {os_unknown} &mdash; Not Reported "
            f"<span style='font-size:.78rem'>(install iSM/AMS host agent)</span></div>"
        )
    if os_eol_count:
        _os_tile_parts.append(
            f"<div style='margin-top:.5rem;padding:.4rem .6rem;background:var(--tint-danger-bg,#fef2f2);"
            f"border-left:3px solid var(--danger,#dc2626);border-radius:3px;font-size:.82rem;"
            f"color:var(--tint-danger-text,#991b1b);font-weight:600'>"
            f"&#9888; {os_eol_count} host(s) running EOL OS &mdash; upgrade required for VCF 9.1"
            f"&nbsp;<a href='{ESXI_KB_URL}' target='_blank' style='color:var(--primary,#2563eb);font-weight:400;font-size:.78rem'>KB ↗</a></div>"
        )
    os_diversity_tile_html = (
        "".join(_os_tile_parts)
        or "<div style='color:#94a3b8;font-size:.85rem'>No OS data collected &mdash; host agent (iSM/AMS) not detected</div>"
    )

    if has_any_host_os:
        os_tile_html = (
            "<!-- Tile 4b: OS Inventory & Lifecycle -->\n"
            "  <div class=\"tile\">\n"
            "    <h3>Host OS Inventory &amp; Lifecycle</h3>\n"
            f"    {os_diversity_tile_html}\n"
            "  </div>\n"
        )
    else:
        os_tile_html = ""

    # ── ToR Switch Fabric & Redundancy tile ────────────────────────────────────
    sw_topo = build_fleet_switch_topology(all_results)
    sw_stats = sw_topo.get("stats", {})
    total_sw = sw_stats.get("total_switches", 0)
    tor_sw = sw_stats.get("tor_switches_count", 0)
    mgmt_sw = sw_stats.get("mgmt_switches_count", 0)
    leaf_pairs_cnt = sw_stats.get("leaf_pairs_count", 0)
    dual_homed_cnt = sw_stats.get("dual_homed_count", 0)
    single_homed_cnt = sw_stats.get("single_homed_count", 0)
    red_pct = sw_stats.get("redundancy_pct", 0.0)
    deep_buf_cnt = sw_stats.get("deep_buffer_count", 0)
    fex_cnt = sw_stats.get("fex_count", 0)

    if total_sw > 0:
        red_badge_cls = "success" if red_pct >= 80.0 else ("warning" if red_pct >= 50.0 else "danger")
        sw_tile_content = f"""
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:.4rem;margin-bottom:.5rem">
          <div style="background:rgba(37,99,235,0.08);border-radius:4px;padding:.35rem;text-align:center">
            <div style="font-size:1.1rem;font-weight:700;color:var(--primary,#2563eb)">{tor_sw}</div>
            <div style="font-size:.68rem;color:var(--text-muted,#64748b)">ToR Switches</div>
          </div>
          <div style="background:rgba(22,163,74,0.08);border-radius:4px;padding:.35rem;text-align:center">
            <div style="font-size:1.1rem;font-weight:700;color:var(--success,#16a34a)">{leaf_pairs_cnt}</div>
            <div style="font-size:.68rem;color:var(--text-muted,#64748b)">Leaf Pairs</div>
          </div>
        </div>
        <div style="font-size:.78rem;line-height:1.4">
          <div style="display:flex;justify-content:space-between;border-bottom:1px solid var(--border);padding:.18rem 0">
            <span>Redundancy:</span>
            <span class="badge {red_badge_cls}" style="font-size:.7rem;padding:.08rem .35rem">{red_pct}% Dual-Homed</span>
          </div>
          <div style="display:flex;justify-content:space-between;border-bottom:1px solid var(--border);padding:.18rem 0">
            <span>Mgmt / OOB:</span>
            <span style="font-weight:600">{mgmt_sw} switch{"es" if mgmt_sw != 1 else ""}</span>
          </div>
          <div style="display:flex;justify-content:space-between;border-bottom:1px solid var(--border);padding:.18rem 0">
            <span>Deep Buffer / VOQ:</span>
            <span style="font-weight:600;color:var(--success,#16a34a)">{deep_buf_cnt}</span>
          </div>
          {f"<div style='display:flex;justify-content:space-between;padding:.18rem 0;color:var(--warning,#ca8a04)'><span>⚠️ Cisco FEX:</span><span style='font-weight:700'>{fex_cnt}</span></div>" if fex_cnt > 0 else ""}
        </div>
        """
        switch_tile_html = f"""
        <!-- Tile 14: ToR Switch Fabric -->
        <div class="tile">
          <h3>ToR Switch Fabric</h3>
          {sw_tile_content}
        </div>
        """
    else:
        switch_tile_html = ""

    # ── Tile 15: BMC Security Posture (Bead 19 & 22) ───────────────────────────
    sec_agg = aggregate_fleet_security(all_results)
    if sec_agg["assessed_hosts"] > 0:
        sec_parts = []
        if sec_agg["baseline_met_hosts"]:
            sec_parts.append(
                f"<div style='color:#16a34a;font-weight:600'>&#128994; {sec_agg['baseline_met_hosts']} host(s) &mdash; Baseline Met</div>"
            )
        if sec_agg["partially_assessed_hosts"]:
            sec_parts.append(
                f"<div style='color:#ca8a04;font-weight:600'>&#128993; {sec_agg['partially_assessed_hosts']} host(s) &mdash; Partially Assessed</div>"
            )
        if sec_agg["action_required_hosts"]:
            sec_parts.append(
                f"<div style='color:#dc2626;font-weight:600'>&#128308; {sec_agg['action_required_hosts']} host(s) &mdash; Action Required</div>"
            )
        if sec_agg["not_assessed_hosts"]:
            sec_parts.append(
                f"<div style='color:#64748b;font-size:.84rem'>&#8505; {sec_agg['not_assessed_hosts']} host(s) &mdash; Not Assessed</div>"
            )

        sec_summary_counts = (
            f"<div style='display:grid;grid-template-columns:1fr 1fr;gap:.4rem;margin-bottom:.5rem'>"
            f"<div style='background:rgba(22,163,74,0.08);border-radius:4px;padding:.35rem;text-align:center'>"
            f"<div style='font-size:1.1rem;font-weight:700;color:var(--success,#16a34a)'>{sec_agg['total_passes']}</div>"
            f"<div style='font-size:.68rem;color:var(--text-muted,#64748b)'>Passes</div>"
            f"</div>"
            f"<div style='background:rgba(220,38,38,0.08);border-radius:4px;padding:.35rem;text-align:center'>"
            f"<div style='font-size:1.1rem;font-weight:700;color:var(--danger,#dc2626)'>{sec_agg['total_fails']}</div>"
            f"<div style='font-size:.68rem;color:var(--text-muted,#64748b)'>Fails</div>"
            f"</div>"
            f"</div>"
            f"<div style='display:flex;justify-content:space-between;border-bottom:1px solid var(--border,#e2e8f0);padding:.18rem 0;font-size:.78rem'>"
            f"<span>Compliance:</span>"
            f"<span style='font-weight:700'>{sec_agg['fleet_compliance_pct']}%</span>"
            f"</div>"
            f"<div style='display:flex;justify-content:space-between;padding:.18rem 0;font-size:.78rem'>"
            f"<span>Unknown / Write-Only:</span>"
            f"<span style='color:var(--text-muted,#64748b)'>{sec_agg['total_unknowns']}</span>"
            f"</div>"
        )
        sec_tile_html = f"""
        <!-- Tile 15: BMC Security Posture -->
        <div class="tile">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.35rem">
            <h3 style="margin:0">BMC Security Posture</h3>
            <a href="#" class="btn-link" onclick="if(window.showTab){{showTab(1);var fn=window.showInvView||window.showInvTab;if(fn){{fn('security');}}}}return false;" style="font-size:.78rem;text-decoration:none" title="Jump to Detailed Security Inventory">Details &rarr;</a>
          </div>
          {sec_summary_counts}
          <div style="margin-top:.45rem;font-size:.82rem">
            {"".join(sec_parts)}
          </div>
          <div style="margin-top:.5rem;padding-top:.4rem;border-top:1px solid var(--border,#e2e8f0)">
            <a href="#" class="btn-link" onclick="if(window.showTab){{showTab(1);var fn=window.showInvView||window.showInvTab;if(fn){{fn('security');}}}}return false;" style="font-size:.8rem;font-weight:600;display:inline-flex;align-items:center;gap:.25rem">🛡️ View Detailed Security Inventory &rarr;</a>
          </div>
        </div>
        """
    else:
        sec_tile_html = ""

    _tile_css = FLEET_EXTRA_CSS

    sizing_options = []
    for idx, p in enumerate(VCF_MANAGEMENT_PROFILES):
        p_name = _h(p["name"])
        p_vcpu = p["vcpu"]
        p_ram = p["ram"]
        p_nvme = p["nvme"]
        sizing_options.append(
            f'<option value="{idx}">{p_name} ({p_vcpu} vCPU &middot; {p_ram} GB &middot; {p_nvme:.1f} TB)</option>'
        )
    sizing_options_html = "\n        ".join(sizing_options)
    initial_profile_desc = _h(VCF_MANAGEMENT_PROFILES[0]["desc"])

    if host_count >= 4:
        host_count_note = f'<span style="color:var(--success,#16a34a);font-weight:500">&#10003; Node minimum met ({host_count} hosts &ge; 4)</span>'
    elif host_count > 0:
        host_count_note = f'<span style="color:#d97706;font-weight:600">⚠️ VCF mgmt domain requires &ge;4 hosts ({host_count} scanned)</span>'
    else:
        host_count_note = ""

    profiles_json = json.dumps([
        {
            "id": p["id"],
            "name": p["name"],
            "shortName": p["short_name"],
            "vcpu": p["vcpu"],
            "ram": p["ram"],
            "nvme": p["nvme"],
            "min_hosts": p["min_hosts"],
            "desc": p["desc"],
        }
        for p in VCF_MANAGEMENT_PROFILES
    ])

    # ── JS (f-string injects fleet values; regular string literals for JS braces) ──
    _js = (
        "(function(){\n"
        f"  var FLEET = {{vcpu: {fleet_vcpu}, ram: {fleet_ram_gb}, nvme: {fleet_nvme_tb}}};\n"
        f"  var PROFILES = {profiles_json};\n"
        "  function updateHeadroom(){\n"
        "    var sel = document.getElementById('sizing-sel');\n"
        "    if (!sel) return;\n"
        "    var idx = parseInt(sel.value, 10);\n"
        "    if (isNaN(idx) || idx < 0 || idx >= PROFILES.length) idx = 0;\n"
        "    var p = PROFILES[idx];\n"
        "    var descEl = document.getElementById('hd-profile-desc');\n"
        "    if (descEl) descEl.textContent = p.desc;\n"
        "    var buckets = [\n"
        "      ['compute', p.vcpu, FLEET.vcpu, 'vCPU', false],\n"
        "      ['ram', p.ram, FLEET.ram, 'GB', false],\n"
        "      ['storage', p.nvme, FLEET.nvme, 'TB raw', true]\n"
        "    ];\n"
        "    buckets.forEach(function(r){\n"
        "      var el = document.getElementById('hd-' + r[0]);\n"
        "      if (!el) return;\n"
        "      var req = r[1], avail = r[2], unit = r[3], isFloat = r[4];\n"
        "      var availStr = isFloat ? avail.toFixed(2) : '' + avail;\n"
        "      var reqStr = isFloat ? req.toFixed(1) : '' + req;\n"
        "      if (avail >= req) {\n"
        "        var rem = avail - req;\n"
        "        var remStr = isFloat ? rem.toFixed(2) : '' + Math.round(rem);\n"
        "        el.innerHTML = '<span style=\"color:#16a34a;font-weight:700\">\u2705 ' + availStr + ' ' + unit + '</span> ' +\n"
        "          '<span style=\"color:var(--text-muted,#64748b);font-size:.78rem\">(needs ' + reqStr + ', +' + remStr + ' free)</span>';\n"
        "      } else {\n"
        "        var diff = req - avail;\n"
        "        var diffStr = isFloat ? diff.toFixed(2) : '' + Math.round(diff);\n"
        "        el.innerHTML = '<span style=\"color:#dc2626;font-weight:700\">\u2717 Short by ' + diffStr + ' ' + unit + '</span> ' +\n"
        "          '<span style=\"color:var(--text-muted,#64748b);font-size:.78rem\">(have ' + availStr + ', need ' + reqStr + ')</span>';\n"
        "      }\n"
        "    });\n"
        "  }\n"
        "  function initHeadroom(){\n"
        "    var maxIdx = -1;\n"
        "    for (var i = PROFILES.length - 1; i >= 0; i--) {\n"
        "      var p = PROFILES[i];\n"
        "      if (FLEET.vcpu >= p.vcpu && FLEET.ram >= p.ram && FLEET.nvme >= p.nvme) {\n"
        "        maxIdx = i;\n"
        "        break;\n"
        "      }\n"
        "    }\n"
        "    var maxBadge = document.getElementById('hd-max-badge');\n"
        "    var sel = document.getElementById('sizing-sel');\n"
        "    if (maxBadge) {\n"
        "      if (maxIdx >= 0) {\n"
        "        maxBadge.innerHTML = '<span style=\"color:#16a34a;font-weight:700\">\u2705 Max Supported: ' + PROFILES[maxIdx].shortName + '</span>';\n"
        "      } else {\n"
        "        maxBadge.innerHTML = '<span style=\"color:#dc2626;font-weight:700\">\u2717 Insufficient for Core MVP</span>';\n"
        "      }\n"
        "    }\n"
        "    if (sel) {\n"
        "      sel.value = '' + (maxIdx >= 0 ? maxIdx : 0);\n"
        "    }\n"
        "    updateHeadroom();\n"
        "  }\n"
        "  document.addEventListener('change', function(e){\n"
        "    var actionEl = e.target && e.target.closest ? e.target.closest('[data-action]') : null;\n"
        "    if (!actionEl) return;\n"
        "    if (actionEl.getAttribute('data-action') === 'change-sizing-profile') {\n"
        "      updateHeadroom();\n"
        "    }\n"
        "  });\n"
        "  if (document.readyState === 'loading') {\n"
        "    document.addEventListener('DOMContentLoaded', initHeadroom);\n"
        "  } else {\n"
        "    initHeadroom();\n"
        "  }\n"
        "})();\n"
    )

    return f"""<style>{_tile_css}</style>
<div class="tile-grid">

  <!-- Tile 1: VCF Resource Headroom -->
  <div class="tile tile-wide">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:.5rem;margin-bottom:.65rem">
      <div>
        <h3 style="margin:0 0 .2rem">VCF Management Resource Headroom</h3>
        <div style="font-size:.76rem;color:var(--text-muted,#64748b)">
          Management domain bring-up only &middot; <span id="hd-max-badge" style="font-weight:600">Evaluating...</span>
        </div>
      </div>
      <div style="display:flex;gap:.75rem;font-size:.78rem;align-items:center;padding-top:.1rem">
        <a href="{VCF_PLANNING_WORKBOOK_URL}" target="_blank" rel="noopener noreferrer" style="color:var(--primary,#2563eb);text-decoration:none;font-weight:600" title="Official Broadcom VCF Planning and Preparation Workbook">📋 Planning Workbook &#x2197;</a>
        <a href="{VCF_SIZER_URL}" target="_blank" rel="noopener noreferrer" style="color:var(--primary,#2563eb);text-decoration:none;font-weight:600" title="Official Broadcom VCF / vSAN Sizer">🧮 VCF Sizer &#x2197;</a>
      </div>
    </div>
    <div style="margin-bottom:.75rem">
      <div style="display:flex;align-items:center;flex-wrap:wrap;gap:.4rem">
        <label for="sizing-sel" style="font-size:.82rem;font-weight:600;color:var(--text-muted,#475569)">Target Model:</label>
        <select id="sizing-sel" data-action="change-sizing-profile"
          style="flex:1;min-width:260px;max-width:100%;padding:.25rem .5rem;border:1px solid var(--border,#e2e8f0);border-radius:5px;font-size:.82rem;background:var(--card,#fff);color:var(--text,#1e293b)">
          {sizing_options_html}
        </select>
      </div>
      <div id="hd-profile-desc" style="font-size:.74rem;color:var(--text-muted,#64748b);margin-top:.3rem;line-height:1.35">
        {initial_profile_desc}
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:.75rem">
      <div>
        <div style="font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8;margin-bottom:.35rem">Compute (vCPU)</div>
        <div id="hd-compute" style="font-size:.88rem">&mdash;</div>
      </div>
      <div>
        <div style="font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8;margin-bottom:.35rem">Memory (RAM)</div>
        <div id="hd-ram" style="font-size:.88rem">&mdash;</div>
      </div>
      <div>
        <div style="font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8;margin-bottom:.35rem">
          Storage (NVMe Raw)&nbsp;<span
            title="Raw NVMe capacity shown. Actual usable storage depends on RAID policy, metadata, deduplication, and compression applied by vSAN ESA."
            style="cursor:help;color:var(--primary,#60a5fa);font-size:.88rem">&#9432;</span>
        </div>
        <div id="hd-storage" style="font-size:.88rem">&mdash;</div>
      </div>
    </div>
    <div style="font-size:.75rem;color:var(--text-muted,#64748b);margin:.75rem 0 0;display:flex;justify-content:space-between;flex-wrap:wrap;gap:.3rem">
      <span>Fleet aggregate: {fleet_vcpu} vCPU &middot; {fleet_ram_gb} GB RAM &middot; {fleet_nvme_tb:.2f} TB NVMe raw &mdash; {host_count} host(s)</span>
      <span>{host_count_note}</span>
    </div>
  </div>

  <!-- Tile 2: BIOS Status -->
  <div class="tile">
    <h3>BIOS Firmware Status</h3>
    {bios_html}
  </div>

  <!-- Tile 3: CPU Fleet Fingerprint -->
  <div class="tile">
    <h3>CPU Fleet Fingerprint</h3>
    {fp_rows}
  </div>

  <!-- Tile 3b: GPU Fleet Fingerprint -->
  <div class="tile">
    <h3>GPU Fleet Fingerprint</h3>
    {gpu_fp_html}
  </div>

  <!-- Tile 4: VCF CPU Support Tier -->
  <div class="tile">
    <h3>VCF 9.1 CPU Support Tier</h3>
    {vcf_tier_html}
  </div>

  {os_tile_html}

  <!-- Tile 5: TPM 2.0 Compliance -->
  <div class="tile">
    <h3>TPM 2.0 Compliance</h3>
    {tpm_html}
  </div>

  <!-- Tile 6: NIC Speed Tier -->
  <div class="tile">
    <h3>NIC Speed Tier (ESA Readiness)</h3>
    {nic_html}
  </div>

  <!-- Tile 7: Power Health -->
  <div class="tile">
    <h3>Power Health</h3>
    {psu_tile_html}
  </div>

  <!-- Tile 8: vSAN Distribution -->
  <div class="tile">
    <h3>vSAN Readiness Distribution</h3>
    {vsan_tile_html}
  </div>

  <!-- Tile 9: Drive Endurance -->
  <div class="tile">
    <h3>Drive Endurance Alerts</h3>
    {endurance_html}
  </div>

  <!-- Tile 10: SEL Alarm Summary -->
  <div class="tile">
    <h3>SEL Alarm Summary</h3>
    {sel_tile_html}
  </div>

  <!-- Tile 12: Fleet Memory Distribution -->
  <div class="tile">
    <h3>Fleet Memory Distribution</h3>
    {mem_tile_html}
  </div>

  {switch_tile_html}

  <!-- Tile 15: BMC Security Posture -->
  {sec_tile_html}

  <!-- Tile 13: Hardware Fault Roster -->
  <div class="tile tile-full">
    <h3>Hardware Fault Roster (DIMMs &middot; PSUs &middot; Fans &middot; Drives)</h3>
    {fault_tile_html}
  </div>

</div>
<script>{_js}</script>"""
