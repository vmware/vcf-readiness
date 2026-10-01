"""
VCF Readiness Tool — fleet inventory / SE decision-matrix row builders.

Shared by the Detailed Inventory HTML panel and Excel export.
Zero third-party dependencies (Python 3.9+ standard library only).
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.compat_engine import (
    VCF9CompatibilityEngine,
    evaluate_driver_firmware_recommendation,
)
from vcf_hci.constants import NVME_FW_BASELINES
from vcf_hci.report.schema_registry import color_for_verdict, strip_html
from vcf_hci.report.sel_links import (
    normalize_vendor,
    resolve_cisco_event_info,
    resolve_dell_event_info,
    resolve_hpe_event_info,
)

ESA_CATEGORY = "vSAN ESA/OSA NVMe"
_PERC_7XX_PATTERN = re.compile(r"\bPERC\s*H?7\d\d\w*\b", re.IGNORECASE)


def _strip_html(s: Any) -> str:
    return strip_html(s)


def _vcf_color(verdict: str) -> str:
    return color_for_verdict(verdict)


def _host_ip(data: dict) -> str:
    si = data.get("system") or {}
    return str(si.get("ip") or si.get("bmc_ip") or si.get("hostname") or data.get("host") or "").strip()


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        if val is None:
            return default
        if isinstance(val, (int, float)):
            return int(val)
        val_str = str(val).strip()
        if not val_str or val_str.upper() in ("N/A", "NONE", "UNKNOWN", "—", "-"):
            return default
        return int(float(val_str))
    except (ValueError, TypeError):
        return default


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        if val is None:
            return default
        if isinstance(val, (int, float)):
            return float(val)
        val_str = str(val).strip()
        if not val_str or val_str.upper() in ("N/A", "NONE", "UNKNOWN", "—", "-"):
            return default
        return float(val_str)
    except (ValueError, TypeError):
        return default


def _all_drives(data: dict):
    for ctrl in data.get("storage_subsystem") or []:
        for d in ctrl.get("drives") or []:
            yield ctrl, d


def _gb_to_tb_label(gb: float) -> float:
    """Round capacity_gb to a display TB bucket (e.g. 14306 → 14)."""
    try:
        tb = float(gb) / 1024.0
    except (TypeError, ValueError):
        return 0.0
    if tb >= 0.95:
        rounded = round(tb, 1)
        if abs(rounded - round(rounded)) < 0.05:
            return float(int(round(rounded)))
        return rounded
    return round(tb, 2)


def summarize_esa_disks(data: dict) -> dict:
    """Return structured ESA disk summary for one host."""
    esa_caps: List[float] = []
    raid_blocked = 0
    sw_raid_count = 0
    for _ctrl, d in _all_drives(data):
        cat = d.get("category") or ""
        if cat == ESA_CATEGORY:
            try:
                esa_caps.append(float(d.get("capacity_gb") or 0))
            except (TypeError, ValueError):
                esa_caps.append(0.0)
        if d.get("behind_software_raid"):
            sw_raid_count += 1
        elif d.get("behind_trimode") or cat == "Unsupported NVMe Tri-Mode" or (cat == "Unsupported NVMe RAID" and not d.get("behind_trimode")):
            raid_blocked += 1

    count = len(esa_caps)
    total_gb = sum(esa_caps)
    total_tb = round(total_gb / 1024.0, 1) if total_gb else 0.0

    buckets: Counter = Counter()
    for gb in esa_caps:
        buckets[_gb_to_tb_label(gb)] += 1

    parts = []
    for tb in sorted(buckets.keys(), reverse=True):
        if tb <= 0:
            continue
        parts.append(f"{buckets[tb]}\u00d7{tb:g}TB")
    size_breakdown = " + ".join(parts) if parts else ""
    if count and size_breakdown:
        display = f"{size_breakdown} ({total_tb:g}TB)"
    elif count:
        display = f"{count}\u00d7 (?TB)"
    else:
        display = "\u2014"

    return {
        "count": count,
        "total_tb": total_tb,
        "size_breakdown": size_breakdown or "\u2014",
        "display": display,
        "raid_blocked": raid_blocked,
        "sw_raid_count": sw_raid_count,
        "storage_qualified": count >= 2 and raid_blocked == 0,
    }


def clean_model_code(vendor: Optional[str] = None, model: Optional[str] = None) -> str:
    """Return concise hardware model code by stripping redundant vendor/brand prefixes.

    Examples:
        "Dell Inc. PowerEdge R750" -> "R750"
        "PowerEdge R740xd"         -> "R740xd"
        "PowerEdge MX740c"         -> "MX740c"
        "PowerEdge FX2-630"        -> "FX2-630"
        "ProLiant DL380 Gen10"     -> "DL380 Gen10"
        "ThinkSystem SR650"        -> "SR650"
    """
    m = str(model or "").strip()
    if not m:
        return ""

    # 1. Strip vendor prefixes if present in model string
    vendor_prefixes = [
        r"^Dell(?:\s+Inc\.?|\s+EMC)?\s+",
        r"^HPE\s+|^Hewlett\s+Packard\s+Enterprise\s+|^HP\s+",
        r"^Lenovo\s+",
        r"^Cisco(?:\s+Systems)?\s+",
        r"^Supermicro\s+",
        r"^Huawei\s+",
        r"^Inspur\s+",
        r"^Fujitsu\s+",
    ]
    for pat in vendor_prefixes:
        m = re.sub(pat, "", m, flags=re.IGNORECASE).strip()

    # 2. Strip brand product-line prefixes
    brand_prefixes = [
        r"^PowerEdge\s+",
        r"^ProLiant\s+",
        r"^ThinkSystem\s+",
        r"^ThinkServer\s+",
        r"^PRIMERGY\s+",
        r"^FusionServer\s+",
    ]
    for pat in brand_prefixes:
        m = re.sub(pat, "", m, flags=re.IGNORECASE).strip()

    return m


def _link_is_up(status: Any) -> bool:
    s = str(status or "").strip().lower()
    if not s:
        return False
    if s in ("down", "linkdown", "link down", "nolink", "no link", "disconnected", "disabled", "inactive"):
        return False
    return s in ("up", "linkup", "link up", "connected", "active", "ok") or "up" in s


def _extract_nic_rated_speed(adapter: dict, port: dict) -> float:
    """Resolve rated link speed in Gbps when link is down or reporting 0 Gbps."""
    # 1. Check direct speed fields on port or adapter
    for k in ("max_speed_gbps", "speed_gbps", "rated_speed_gbps", "current_speed_gbps"):
        val = port.get(k) or adapter.get(k)
        try:
            if val is not None and float(val) > 0:
                return float(val)
        except (ValueError, TypeError):
            pass

    # 2. Check Mbps fields
    for k in ("max_speed_mbps", "speed_mbps", "current_speed_mbps"):
        val = port.get(k) or adapter.get(k)
        try:
            if val is not None and float(val) > 0:
                return float(val) / 1000.0
        except (ValueError, TypeError):
            pass

    # 3. Check supported speeds lists
    supp = port.get("supported_speeds_gbps") or adapter.get("supported_speeds_gbps") or []
    if isinstance(supp, list) and supp:
        valid = []
        for s in supp:
            try:
                if float(s or 0) > 0:
                    valid.append(float(s))
            except Exception:
                pass
        if valid:
            return max(valid)

    # 4. Regex match on adapter name / description / model / port_id
    search_str = " ".join([
        str(adapter.get("name") or ""),
        str(adapter.get("model") or ""),
        str(adapter.get("id") or ""),
        str(adapter.get("description") or ""),
        str(port.get("name") or ""),
        str(port.get("port_id") or ""),
    ])
    m = re.search(r"\b(400|200|100|50|40|25|10|1)\s*G(?:bE|b|bps)?\b", search_str, re.IGNORECASE)
    if m:
        return float(m.group(1))

    # Check 1000BASE / 1000 Mbps / 1Gb
    if re.search(r"\b1000\s*(?:base|mbps|mb)\b", search_str, re.IGNORECASE):
        return 1.0

    return 0.0


def summarize_nics(data: dict) -> dict:
    """Return NIC rollup for one host with fallback to rated speeds for down links."""
    groups: Counter = Counter()
    port_count = 0
    up = 0
    down = 0
    up_25g = 0
    max_gbps = 0.0

    for n in data.get("network_adapters") or []:
        for p in n.get("ports") or []:
            port_count += 1
            try:
                speed = float(p.get("current_speed_gbps") or 0)
            except (TypeError, ValueError):
                speed = 0.0

            is_up = _link_is_up(p.get("link_status"))
            if is_up:
                up += 1
            else:
                down += 1

            # If speed is 0 or unpopulated on a down link, resolve rated capability
            if speed <= 0:
                speed = _extract_nic_rated_speed(n, p)

            if is_up and speed >= 25:
                up_25g += 1

            max_gbps = max(max_gbps, speed)
            speed_i = int(speed) if speed == int(speed) else speed
            groups[(speed_i, is_up)] += 1

    parts = []
    html_parts = []
    for (speed_i, is_up), n in sorted(
        groups.items(), key=lambda x: (-float(x[0][0] or 0), not x[0][1])
    ):
        arrow = "\u2191" if is_up else "\u2193"
        if speed_i > 0:
            token = f"{n}\u00d7{speed_i:g}G{arrow}"
            if not is_up:
                h_token = f"<span class='inv-bad' title='{n} port(s) down ({speed_i:g} Gbps rated)'>{token}</span>"
            elif speed_i >= 25:
                h_token = f"<span class='inv-good' title='{n} port(s) active at {speed_i:g} Gbps'>{token}</span>"
            else:
                h_token = f"<span title='{n} port(s) active at {speed_i:g} Gbps'>{token}</span>"
            parts.append(token)
            html_parts.append(h_token)
        else:
            token = f"{n}\u00d7Down" if not is_up else f"{n}\u00d7Up"
            if not is_up:
                h_token = f"<span class='inv-bad' title='{n} port(s) disconnected/down'>{token}</span>"
            else:
                h_token = f"<span title='{n} port(s) connected'>{token}</span>"
            parts.append(token)
            html_parts.append(h_token)

    speed_groups = " ".join(parts)
    html_speed_groups = " ".join(html_parts)
    if port_count:
        display = f"{port_count}p \u00b7 {speed_groups}" if speed_groups else f"{port_count}p"
        html_display = f"{port_count}p &middot; {html_speed_groups}" if html_speed_groups else f"{port_count}p"
    else:
        display = "\u2014"
        html_display = "\u2014"

    # Tooltip summarizing ESA network readiness
    if up_25g >= 2:
        tooltip = f"vSAN ESA Network Ready: {up_25g} active \u226525 GbE ports (Total: {port_count} ports, {up} Up, {down} Down, Max: {max_gbps:g} Gbps)"
    elif max_gbps >= 25:
        tooltip = f"\u226525 GbE Capable ({max_gbps:g} Gbps), but only {up_25g} active \u226525G link(s) (Total: {port_count} ports, {up} Up, {down} Down; vSAN ESA recommends \u22652 active 25 GbE uplinks)"
    elif port_count > 0:
        tooltip = f"Sub-25 GbE NIC: Max link speed is {max_gbps:g} Gbps (vSAN ESA recommends \u226525 GbE uplinks)"
    else:
        tooltip = "No network interfaces detected"

    return {
        "port_count": port_count,
        "max_gbps": max_gbps,
        "up": up,
        "down": down,
        "up_25g": up_25g,
        "speed_groups": speed_groups,
        "display": display,
        "html_display": html_display,
        "tooltip": tooltip,
        "has_down": down > 0,
        "meets_25g": max_gbps >= 25,
    }


def evaluate_vsan_esa_profile(
    data: Optional[dict] = None,
    *,
    esa_count: Optional[int] = None,
    total_tb: Optional[float] = None,
    ram_gb: Optional[float] = None,
    cpu_cores: Optional[int] = None,
    max_gbps: Optional[float] = None,
    vmd_enabled: Optional[bool] = None,
    trimode_nvme_count: Optional[int] = None,
    raid_nvme_count: Optional[int] = None,
    software_raid_nvme_count: Optional[int] = None,
    has_hw_raid: Optional[bool] = None,
) -> Dict[str, Any]:
    """Evaluate host against VMware vSAN ESA ReadyNode hardware profiles (ESA-L, ESA-M, ESA-S, ESA-XS).

    Holistically analyzes direct NVMe drive count/capacity, RAM, CPU cores, and NIC speeds.
    Returns structured tier_code, tier_label, profile name, status badge, and detailed reason tooltip.
    """
    if data is not None and isinstance(data, dict):
        if esa_count is None or total_tb is None:
            esa_res = summarize_esa_disks(data)
            if esa_count is None:
                esa_count = int(esa_res.get("count") or 0)
            if total_tb is None:
                total_tb = float(esa_res.get("total_tb") or 0.0)

        if trimode_nvme_count is None:
            trimode_nvme_count = sum(
                1 for _ctrl, d in _all_drives(data)
                if d.get("behind_trimode") or d.get("category") == "Unsupported NVMe Tri-Mode"
            )
        if raid_nvme_count is None:
            raid_nvme_count = sum(
                1 for _ctrl, d in _all_drives(data)
                if d.get("category") == "Unsupported NVMe RAID" and not d.get("behind_trimode")
            )
        if software_raid_nvme_count is None:
            software_raid_nvme_count = sum(
                1 for _ctrl, d in _all_drives(data)
                if d.get("behind_software_raid")
            )
        if vmd_enabled is None:
            vmd_enabled = bool((data.get("bios_checks") or {}).get("vmd_enabled_flag", False))
        if has_hw_raid is None:
            has_hw_raid = any(
                ctrl.get("has_logical_volumes") and not ctrl.get("is_software_raid")
                for ctrl in data.get("storage_subsystem") or []
            )

        si = data.get("system") or {}
        ci = si.get("cpu_summary") or {}
        if ram_gb is None:
            ram_gb = _safe_float(si.get("total_memory_gb"), 0.0)
        if cpu_cores is None:
            cpu_cores = _safe_int(ci.get("core_count") or si.get("cpu_cores"), 0)
            if not cpu_cores:
                procs = ci.get("processors") or []
                cpu_cores = sum(_safe_int(p.get("cores"), 0) for p in procs if isinstance(p, dict))
        if max_gbps is None:
            nic_res = summarize_nics(data)
            max_gbps = _safe_float(nic_res.get("max_gbps"), 0.0)

    # Coerce defaults
    c_esa = _safe_int(esa_count, 0)
    c_tb = _safe_float(total_tb, 0.0)
    c_ram = _safe_float(ram_gb, 0.0)
    c_cores = _safe_int(cpu_cores, 0)
    c_nic = _safe_float(max_gbps, 0.0)
    c_vmd = bool(vmd_enabled)
    c_tri = _safe_int(trimode_nvme_count, 0)
    c_raid = _safe_int(raid_nvme_count, 0)
    c_sw = _safe_int(software_raid_nvme_count, 0)
    sw_note = " (Note: Host Software RAID detected — bypass in BIOS for direct ESXi pass-through)" if c_sw > 0 else ""

    # 1. Hardware Blockers (Tri-Mode, HW RAID, Intel VMD)
    if c_tri > 0 and (c_esa == 0 or c_tri >= c_esa):
        return {
            "tier_code": "Ineligible",
            "tier_label": "Blocked (Tri-Mode RAID)",
            "profile": "Ineligible",
            "status": "bad",
            "tooltip": (
                f"Ineligible: {c_tri} NVMe drive(s) behind Tri-Mode RAID controller. "
                "Native direct PCIe pass-through is required for vSAN ESA."
            ),
            "meets_storage": False,
            "meets_network": c_nic >= 25,
        }

    if c_raid > 0 and (c_esa == 0 or c_raid >= c_esa):
        return {
            "tier_code": "Ineligible",
            "tier_label": "Blocked (HW RAID)",
            "profile": "Ineligible",
            "status": "bad",
            "tooltip": (
                f"Ineligible: {c_raid} NVMe drive(s) behind HW RAID controller. "
                "Native direct PCIe pass-through is required for vSAN ESA."
            ),
            "meets_storage": False,
            "meets_network": c_nic >= 25,
        }

    if c_vmd and c_esa > 0:
        return {
            "tier_code": "Ineligible",
            "tier_label": "Blocked (VMD Enabled)",
            "profile": "Ineligible",
            "status": "bad",
            "tooltip": (
                "Ineligible: Intel VMD is enabled in BIOS. "
                "Disable VMD for native direct pass-through NVMe performance."
            ),
            "meets_storage": False,
            "meets_network": c_nic >= 25,
        }

    if c_esa < 2:
        return {
            "tier_code": "Ineligible",
            "tier_label": "Insufficient Disks (<2)",
            "profile": "Ineligible",
            "status": "muted",
            "tooltip": (
                f"Ineligible: {c_esa} direct NVMe drive(s) detected. "
                "vSAN ESA requires a minimum of 2 direct-attached NVMe SSDs."
            ),
            "meets_storage": False,
            "meets_network": c_nic >= 25,
        }

    # 2. Storage Meets Baseline (>=2 Direct NVMe). Determine Profile Fit.
    is_large = (c_esa >= 4 and (c_ram >= 512 or c_ram == 0) and (c_cores >= 48 or c_cores == 0))
    is_medium = (c_esa >= 2 and (c_ram >= 256 or c_ram == 0) and (c_cores >= 32 or c_cores == 0))
    is_small = (c_esa >= 2 and (c_ram >= 128 or c_ram == 0) and (c_cores >= 16 or c_cores == 0))

    if c_nic < 25:
        target_name = "ESA-L (Large)" if is_large else ("ESA-M (Medium)" if is_medium else "ESA-S (Small)")
        ram_str = f", {c_ram:g} GB RAM" if c_ram else ""
        core_str = f", {c_cores} cores" if c_cores else ""
        return {
            "tier_code": "Needs 25G",
            "tier_label": "Needs 25G NIC",
            "profile": "Needs 25G",
            "status": "warn",
            "tooltip": (
                f"Storage & compute qualify for vSAN ESA {target_name} ({c_esa} Direct NVMe{ram_str}{core_str}), "
                f"but max NIC speed is {c_nic:g} Gbps. Upgrade to \u226525 GbE NIC for ESA Ready status.{sw_note}"
            ),
            "meets_storage": True,
            "meets_network": False,
        }

    if is_large:
        ram_desc = f"{c_ram:g} GB RAM (\u2265512GB)" if c_ram else "RAM \u2265512GB"
        core_desc = f"{c_cores} cores (\u226548c)" if c_cores else "Cores \u226548"
        return {
            "tier_code": "ESA-L",
            "tier_label": "ESA-L (Large)",
            "profile": "Large",
            "status": "good",
            "tooltip": (
                f"vSAN ESA Large Profile (ESA-L): {c_esa} Direct NVMe ({c_tb:g} TB), "
                f"{ram_desc}, {core_desc}, {c_nic:g} GbE NIC. Meets high-performance cluster criteria.{sw_note}"
            ),
            "meets_storage": True,
            "meets_network": True,
        }

    if is_medium:
        ram_desc = f"{c_ram:g} GB RAM (\u2265256GB)" if c_ram else "RAM \u2265256GB"
        core_desc = f"{c_cores} cores (\u226532c)" if c_cores else "Cores \u226532"
        return {
            "tier_code": "ESA-M",
            "tier_label": "ESA-M (Medium)",
            "profile": "Medium",
            "status": "good",
            "tooltip": (
                f"vSAN ESA Medium Profile (ESA-M): {c_esa} Direct NVMe ({c_tb:g} TB), "
                f"{ram_desc}, {core_desc}, {c_nic:g} GbE NIC. Meets standard enterprise cluster criteria.{sw_note}"
            ),
            "meets_storage": True,
            "meets_network": True,
        }

    if is_small:
        ram_desc = f"{c_ram:g} GB RAM (\u2265128GB)" if c_ram else "RAM \u2265128GB"
        core_desc = f"{c_cores} cores (\u226516c)" if c_cores else "Cores \u226516"
        return {
            "tier_code": "ESA-S",
            "tier_label": "ESA-S (Small)",
            "profile": "Small",
            "status": "good",
            "tooltip": (
                f"vSAN ESA Small Profile (ESA-S): {c_esa} Direct NVMe ({c_tb:g} TB), "
                f"{ram_desc}, {core_desc}, {c_nic:g} GbE NIC. Meets entry datacenter cluster criteria.{sw_note}"
            ),
            "meets_storage": True,
            "meets_network": True,
        }

    return {
        "tier_code": "ESA-XS",
        "tier_label": "ESA-XS (Edge)",
        "profile": "Edge",
        "status": "good",
        "tooltip": (
            f"vSAN ESA Edge Profile (ESA-XS): {c_esa} Direct NVMe ({c_tb:g} TB), "
            f"{c_ram:g} GB RAM, {c_cores} cores, {c_nic:g} GbE NIC. Suitable for ROBO / Edge deployments.{sw_note}"
        ),
        "meets_storage": True,
        "meets_network": True,
    }


def summarize_fc_hbas(data: dict) -> dict:
    """Return FC HBA rollup for one host."""
    hbas = data.get("fc_hbas") or []
    count = len(hbas)
    if not count:
        return {
            "count": 0,
            "display": "\u2014",
            "speed_summary": "",
            "models": "",
        }
    speeds: Counter = Counter()
    models = []
    for h in hbas:
        name = h.get("adapter_name") or h.get("name") or h.get("model") or "FC HBA"
        models.append(str(name))
        spd = h.get("speed_gbps") or h.get("port_speed_gbps")
        try:
            spdf = float(spd) if spd else 0.0
            if spdf > 0:
                speeds[int(spdf) if spdf == int(spdf) else spdf] += 1
        except (ValueError, TypeError):
            pass

    spd_parts = []
    for s, n in sorted(speeds.items(), key=lambda x: -x[0]):
        spd_parts.append(f"{n}\u00d7{s:g}G" if n > 1 else f"{s:g}G")
    spd_str = " ".join(spd_parts)

    display = f"{count} HBA" + (f" ({spd_str})" if spd_str else "")
    return {
        "count": count,
        "display": display,
        "speed_summary": spd_str,
        "models": ", ".join(models),
    }


def cpu_tier(data: dict) -> str:
    """Return 'green' | 'yellow' | 'red' from cpu_summary.verdict."""
    verdict = ((data.get("system") or {}).get("cpu_summary") or {}).get("verdict", "") or ""
    return _vcf_color(_strip_html(str(verdict)))


_GOVERNOR_KEYS = {
    "sysprofile",
    "proccstates",
    "procturbomode",
    "powerregulator",
    "workloadprofile",
    "minprocidlepkgstate",
    "energyefficientturbo",
    "energyperfbias",
}

_BADGE_SEVERITY = {
    "danger": 3,
    "warning": 2,
    "info": 1,
    "success": 0,
}


def _is_noise_cpu_power(entry: dict, has_governor: bool = False) -> bool:
    raw_k = str(entry.get("raw_key") or "").lower()
    lbl = str(entry.get("label") or "").strip().lower()
    raw_v = str(entry.get("raw_val") or "").strip().lower()

    if raw_k == "workloadprofile" and (lbl in ("notavailable", "n/a", "") or raw_v in ("notavailable", "n/a", "")):
        return True
    if any(k in raw_k for k in ("logicalproc", "hyperthreading")):
        return True
    return bool(has_governor and any(k in raw_k for k in ("procturbomode", "procturbo")) and entry.get("badge") == "success")


def _is_governor_key(raw_k: str) -> bool:
    low = raw_k.lower()
    if low in _GOVERNOR_KEYS:
        return True
    return ("power" in low or "profile" in low) and not any(k in low for k in ("logicalproc", "hyperthreading"))


def select_cpu_power_entry(cpu_power: Optional[List[dict]]) -> Optional[dict]:
    """Select the most relevant CPU power governor entry for fleet display."""
    if not cpu_power:
        return None

    has_primary_gov = any(str(e.get("raw_key") or "").lower() in ("sysprofile", "powerregulator") for e in cpu_power)

    valid_govs = []
    all_non_noise = []
    for e in cpu_power:
        raw_k = str(e.get("raw_key") or "")
        is_noise = _is_noise_cpu_power(e, has_governor=has_primary_gov)
        if not is_noise:
            all_non_noise.append(e)
            if _is_governor_key(raw_k):
                valid_govs.append(e)

    # 1. Among valid governors, pick worst badge (danger > warning > info/success)
    # If multiple have the same worst badge, prefer primary governors (SysProfile, PowerRegulator, WorkloadProfile)
    if valid_govs:
        max_sev = max(_BADGE_SEVERITY.get(x.get("badge", ""), 0) for x in valid_govs)
        if max_sev >= 2:
            candidates = [x for x in valid_govs if _BADGE_SEVERITY.get(x.get("badge", ""), 0) == max_sev]
            for prim in ("sysprofile", "powerregulator", "workloadprofile"):
                for c in candidates:
                    if str(c.get("raw_key") or "").lower() == prim:
                        return c
            return candidates[0]

    # 2. Else among ALL non-noise entries, pick worst badge (danger > warning)
    if all_non_noise:
        worst_all = max(all_non_noise, key=lambda x: _BADGE_SEVERITY.get(x.get("badge", ""), 0))
        if _BADGE_SEVERITY.get(worst_all.get("badge", ""), 0) >= 2:
            return worst_all

    # 3. Else pick first valid governor, preferring primary governors
    if valid_govs:
        for prim in ("sysprofile", "powerregulator", "workloadprofile"):
            for e in valid_govs:
                if str(e.get("raw_key") or "").lower() == prim:
                    return e
        return valid_govs[0]

    # 4. Else first remaining non-noise entry
    if all_non_noise:
        return all_non_noise[0]

    # 5. Fallback to first element
    return cpu_power[0]


def select_memory_ras_entry(memory_ras: Optional[List[dict]]) -> Optional[dict]:
    """Select the most representative Memory RAS entry for fleet display."""
    if not memory_ras:
        return None

    warn_or_danger = [e for e in memory_ras if e.get("badge") in ("danger", "warning")]
    if warn_or_danger:
        return max(warn_or_danger, key=lambda x: _BADGE_SEVERITY.get(x.get("badge", ""), 0))

    preferred_keys = ("memopmode", "advancedmemprotection", "mempatrolscrub")
    for pref in preferred_keys:
        for e in memory_ras:
            if str(e.get("raw_key") or "").lower() == pref:
                return e

    return memory_ras[0]


def _map_esa_tier(vsan_verdict: str) -> str:
    v = vsan_verdict or ""
    if "ESA Ready" in v:
        return "Ready"
    if "ESA Storage Met" in v:
        return "StorageMet"
    if "Intel VMD" in v or "Tri-Mode" in v or "Behind RAID" in v:
        return "Blocked"
    if "OSA" in v:
        return "StorageMet"
    if "Not vSAN" in v or "Insufficient" in v or "NOT Supported" in v:
        return "Insufficient"
    return "Unknown"


def _tpm_ok(si: dict) -> Optional[bool]:
    badge = _strip_html(si.get("tpm_status_badge", "") or "").lower()
    if not badge or badge in ("n/a", "unknown", "—", "-"):
        return None
    raw_badge = str(si.get("tpm_status_badge") or "")
    if "success" in raw_badge or "enabled" in badge or "2.0" in badge:
        if "danger" in raw_badge or "disabled" in badge or "absent" in badge:
            return False
        if "warning" in raw_badge and "unknown" in badge:
            return None
        return True
    if "danger" in raw_badge or "disabled" in badge or "absent" in badge:
        return False
    if "success" in badge or "ok" in badge:
        return True
    return None


def build_host_decision_rows(all_results: List[dict]) -> List[dict]:
    """One dict per host for the HTML matrix and Excel Decision sheet."""
    from vcf_hci.report.fleet.vendor import normalize_oem_vendor
    from vcf_hci.security.scoring import score_host_security
    rows: List[dict] = []
    for idx, data in enumerate(all_results or []):
        si = data.get("system") or {}
        ci = si.get("cpu_summary") or {}
        mem = data.get("memory_subsystem") or {}
        mem_topo = data.get("memory_topology") or {}
        psu = data.get("psu_status") or {}
        hos = data.get("host_os") or {}
        esa = summarize_esa_disks(data)
        nic = summarize_nics(data)
        all_drives_list = [d for _c, d in _all_drives(data)]
        esa_count = esa["count"]
        osa_count = sum(
            1 for d in all_drives_list
            if d.get("category") in ("vSAN OSA Only", "vSAN OSA SAS/SATA")
        )
        vmd_on = (data.get("bios_checks") or {}).get("vmd_enabled_flag", False)
        trimode_nvme = sum(
            1 for d in all_drives_list
            if d.get("behind_trimode") or d.get("category") == "Unsupported NVMe Tri-Mode"
        )
        raid_nvme = sum(
            1 for d in all_drives_list
            if d.get("category") == "Unsupported NVMe RAID" and not d.get("behind_trimode")
        )
        sw_raid_nvme = sum(
            1 for d in all_drives_list
            if d.get("behind_software_raid")
        )
        has_hw_raid = any(
            ctrl.get("has_logical_volumes") and not ctrl.get("is_software_raid")
            for ctrl in data.get("storage_subsystem", [])
        )
        vsan_verdict, _detail = VCF9CompatibilityEngine.evaluate_vsan(
            esa_count,
            osa_count,
            nic.get("max_gbps") or 0,
            vmd_enabled=bool(vmd_on),
            trimode_nvme_count=trimode_nvme,
            raid_nvme_count=raid_nvme,
            software_raid_nvme_count=sw_raid_nvme,
        )
        esa_tier = _map_esa_tier(vsan_verdict)
        esa_profile = evaluate_vsan_esa_profile(
            esa_count=esa_count,
            total_tb=_safe_float(esa.get("total_tb"), 0.0),
            ram_gb=_safe_float(si.get("total_memory_gb"), 0.0),
            cpu_cores=_safe_int(ci.get("core_count") or si.get("cpu_cores"), 0),
            max_gbps=_safe_float(nic.get("max_gbps"), 0.0),
            vmd_enabled=bool(vmd_on),
            trimode_nvme_count=trimode_nvme,
            raid_nvme_count=raid_nvme,
            software_raid_nvme_count=sw_raid_nvme,
            has_hw_raid=has_hw_raid,
        )
        tier = cpu_tier(data)
        vendor_raw = si.get("vendor") or ""
        facet_oem = normalize_oem_vendor(vendor_raw) or vendor_raw or "Unknown"
        dimm_list = mem.get("dimm_list") or []
        dimm_count = mem.get("total_dimms_populated")
        if dimm_count is None:
            dimm_count = len(dimm_list)
        tpm = _tpm_ok(si)
        ip = _host_ip(data)
        hostname = si.get("hostname") or ip
        cpu_verdict = _strip_html(str(ci.get("verdict") or ""))
        interleaving_pct = mem_topo.get("interleaving_score_pct")
        interleaving_str = f"{interleaving_pct}%" if interleaving_pct is not None else ""
        psu_redundant = "Yes" if psu.get("redundant") else ("No" if psu else "")
        power_cap_on = bool(psu.get("power_limit_enforced"))
        esxi_eol = str(hos.get("eol_label") or hos.get("esxi_update_label") or "").strip()
        os_label = str(hos.get("esxi_update_label") or hos.get("os_name") or "").strip()
        os_eol_label = esxi_eol
        os_eol_is_eol = "EOL" in str(hos.get("eol_label") or "")

        model_raw = si.get("model") or ""
        clean_model = clean_model_code(vendor_raw, model_raw) or model_raw
        fc_hba = summarize_fc_hbas(data)
        has_osa_ctrl = any(
            any(k in str(c.get("name") or c.get("ctrl_model") or c.get("id") or "").upper() for k in ("HBA", "PASS-THROUGH", "PASSTHROUGH"))
            for c in data.get("storage_subsystem") or []
        )
        has_raid_ctrl = any(
            not c.get("is_software_raid")
            and re.search(r"\b(?:PERC|RAID|MEGARAID|SMART ARRAY)\b", str(c.get("name") or c.get("ctrl_model") or c.get("id") or ""), re.IGNORECASE)
            for c in data.get("storage_subsystem") or []
        )
        ctrl_esa = esa_count > 0
        ctrl_osa = osa_count > 0 or has_osa_ctrl
        ctrl_unsup = trimode_nvme > 0 or raid_nvme > 0 or has_hw_raid or has_raid_ctrl

        # BMC Security Posture
        sec_score = score_host_security(data)
        if sec_score.get("is_fleet_manager"):
            sec_posture = "excluded"
            sec_badge = "<span class='inv-muted' title='Central fleet orchestrator excluded from host BMC security scoring'>Excluded</span>"
            sec_tooltip = "Excluded from host BMC audit (central fleet manager)"
        elif sec_score.get("assessed"):
            p_cnt = _safe_int(sec_score.get("pass_count"), 0)
            f_cnt = _safe_int(sec_score.get("fail_count"), 0)
            u_cnt = _safe_int(sec_score.get("unknown_count"), 0)
            comp = sec_score.get("compliance_pct", 0.0)
            if f_cnt > 0:
                sec_posture = "action_req"
                sec_badge = f"<span class='inv-bad'>✗ Action Req ({f_cnt}F)</span>"
                sec_tooltip = f"BMC Security Audit: {f_cnt} failed, {p_cnt} passed, {u_cnt} unknown ({comp}% compliance)"
            elif u_cnt > 0:
                sec_posture = "partial"
                sec_badge = f"<span class='inv-warn'>▲ Partial ({u_cnt}U)</span>"
                sec_tooltip = f"BMC Security Audit: {p_cnt} passed, {u_cnt} unknown controls ({comp}% compliance)"
            else:
                sec_posture = "baseline_met"
                sec_badge = "<span class='inv-good'>✓ Met</span>"
                sec_tooltip = f"BMC Security Audit: all {p_cnt} evaluated controls passed"
        else:
            bmc_sec = data.get("bmc_security_config") or data.get("bmc_sec_cfg") or {}
            checks = bmc_sec.get("checks") or []
            crit_legacy = any(c.get("badge") == "danger" for c in checks)
            warn_legacy = any(c.get("badge") == "warning" for c in checks)
            if bmc_sec.get("overall_badge") == "danger" or crit_legacy or bmc_sec.get("default_pwd_changed") is False:
                sec_posture = "action_req"
                sec_badge = "<span class='inv-bad'>✗ Action Req</span>"
                sec_tooltip = "BMC security checks require action"
            elif bmc_sec.get("overall_badge") == "warning" or warn_legacy or bmc_sec.get("ipmi_lan_enabled") is True:
                sec_posture = "partial"
                sec_badge = "<span class='inv-warn'>▲ Partial</span>"
                sec_tooltip = "BMC security checks require review"
            elif bmc_sec.get("overall_badge") == "success" or (bmc_sec.get("default_pwd_changed") is True and bmc_sec.get("ipmi_lan_enabled") is False):
                sec_posture = "baseline_met"
                sec_badge = "<span class='inv-good'>✓ Met</span>"
                sec_tooltip = "BMC hardening baseline met"
            else:
                sec_posture = "not_assessed"
                sec_badge = "<span class='inv-muted'>—</span>"
                sec_tooltip = "BMC security not assessed"

        rows.append({
            "host_idx": idx,
            "ip": ip,
            "hostname": hostname,
            "vendor": vendor_raw,
            "model": model_raw,
            "clean_model": clean_model,
            "cpu_model": ci.get("model") or "",
            "cpu_tier": tier,
            "cpu_verdict": cpu_verdict,
            "esa": esa,
            "sw_raid_nvme": sw_raid_nvme,
            "esa_tier": esa_tier,
            "esa_profile": esa_profile,
            "nic": nic,
            "fc_hba": fc_hba,
            "ctrl_esa": ctrl_esa,
            "ctrl_osa": ctrl_osa,
            "ctrl_unsup": ctrl_unsup,
            "ram_gb": si.get("total_memory_gb") or "",
            "dimm_count": dimm_count or 0,
            "interleaving_pct": interleaving_pct,
            "interleaving_str": interleaving_str,
            "tpm_ok": tpm,
            "vmd_on": bool(vmd_on) if vmd_on is not None else None,
            "has_hw_raid": has_hw_raid,
            "psu_redundant": psu_redundant,
            "power_cap_on": power_cap_on,
            "bios_version": si.get("bios_version") or "",
            "esxi_eol": esxi_eol,
            "os_name": str(hos.get("os_name") or "").strip(),
            "os_label": os_label,
            "os_eol_label": os_eol_label,
            "os_eol_is_eol": os_eol_is_eol,
            "esa_profile_tier": (esa_profile.get("tier_label") or "") if esa_profile else "",
            "gpu_count": len(data.get("gpu_accelerators") or []),
            "partial": bool(data.get("partial_scan")),
            "facet_oem": facet_oem,
            "facet_cpu": tier,
            "facet_esa": esa_tier,
            "facet_nic": "25" if nic.get("meets_25g") else "lt25",
            "facet_link": "down" if nic.get("has_down") else ("up" if nic.get("port_count", 0) > 0 else "none"),
            "sec_posture": sec_posture,
            "sec_badge": sec_badge,
            "sec_tooltip": sec_tooltip,
        })
    return rows


def build_compact_fleet_inventory(
    all_results: List[dict],
    rows: Optional[List[dict]] = None,
    obfuscated: bool = False,
    page_salt: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a compact, JSON-serializable inventory structure for fleet reporting.

    Contains decision rows plus compact drive, NIC, and health dictionaries.
    PII is masked if obfuscated is True.
    """
    if rows is None:
        rows = build_host_decision_rows(all_results)

    compact_hosts: List[dict] = []
    for idx, r in enumerate(rows or []):
        h_idx = _safe_int(r.get("host_idx", idx), idx)
        h_name = f"Host-{h_idx+1}" if obfuscated else str(r.get("hostname") or "")
        h_ip = f"192.0.2.{(h_idx % 250) + 1}" if obfuscated else str(r.get("ip") or "")
        esa = r.get("esa") or {}
        nic = r.get("nic") or {}
        esa_profile = r.get("esa_profile") or {}
        compact_hosts.append({
            "host_idx": h_idx,
            "hostname": h_name,
            "ip": h_ip,
            "vendor": str(r.get("vendor") or ""),
            "model": str(r.get("model") or ""),
            "clean_model": str(r.get("clean_model") or ""),
            "facet_oem": str(r.get("facet_oem") or ""),
            "facet_cpu": str(r.get("facet_cpu") or ""),
            "facet_esa": str(r.get("facet_esa") or ""),
            "facet_nic": str(r.get("facet_nic") or ""),
            "facet_link": str(r.get("facet_link") or ""),
            "cpu_tier": str(r.get("cpu_tier") or ""),
            "cpu_model": str(r.get("cpu_model") or ""),
            "cpu_verdict": str(r.get("cpu_verdict") or ""),
            "os_label": str(r.get("os_label") or ""),
            "os_eol_label": str(r.get("os_eol_label") or ""),
            "esa_count": _safe_int(esa.get("count"), 0),
            "esa_tb": _safe_float(esa.get("total_tb"), 0.0),
            "esa_display": str(esa.get("display") or ""),
            "esa_tier": str(r.get("esa_tier") or ""),
            "esa_profile": str(esa_profile.get("tier_label") or esa_profile.get("tier_code") or ""),
            "nic_display": str(nic.get("display") or ""),
            "nic_max_gbps": _safe_float(nic.get("max_gbps"), 0.0),
            "ram_gb": r.get("ram_gb") or "",
            "dimm_count": _safe_int(r.get("dimm_count"), 0),
            "interleaving_str": str(r.get("interleaving_str") or ""),
            "tpm_ok": r.get("tpm_ok"),
            "sec_posture": str(r.get("sec_posture") or ""),
            "sec_badge": str(r.get("sec_badge") or ""),
            "vmd_on": bool(r.get("vmd_on")),
            "gpu_count": _safe_int(r.get("gpu_count"), 0),
            "ctrl_esa": int(bool(r.get("ctrl_esa"))),
            "ctrl_osa": int(bool(r.get("ctrl_osa"))),
            "ctrl_unsup": int(bool(r.get("ctrl_unsup"))),
        })

    drives: List[dict] = []
    nics: List[dict] = []
    health_list: List[dict] = []

    for idx, data in enumerate(all_results or []):
        si = data.get("system") or {}
        h_name = f"Host-{idx+1}" if obfuscated else str(si.get("hostname") or _host_ip(data) or f"Host {idx+1}")
        h_ip = f"192.0.2.{(idx % 250) + 1}" if obfuscated else _host_ip(data)

        # 1. Drives
        for ctrl in data.get("storage_subsystem") or []:
            ctrl_name = str(ctrl.get("name") or ctrl.get("ctrl_model") or ctrl.get("id") or "")
            is_perc7xx = bool(
                _PERC_7XX_PATTERN.search(ctrl_name)
                or _PERC_7XX_PATTERN.search(str(ctrl.get("id") or ""))
                or _PERC_7XX_PATTERN.search(str(ctrl.get("ctrl_model") or ""))
            )
            for d in ctrl.get("drives") or []:
                if (d.get("category") or "") == "Empty":
                    continue
                cat = str(d.get("category") or "")
                proto = str(d.get("protocol") or "")
                behind_tm = bool(d.get("behind_trimode"))
                behind_sw = bool(d.get("behind_software_raid"))
                is_sw_ctrl = bool(ctrl.get("is_software_raid"))

                if not is_sw_ctrl and not behind_sw and (is_perc7xx or "Tri-Mode" in cat or behind_tm or (cat == "Unsupported NVMe RAID")):
                    ctrl_type = "unsupported"
                elif cat == ESA_CATEGORY or proto.upper() in ("NVME", "PCIE"):
                    ctrl_type = "esa"
                elif "OSA" in cat or "HBA" in ctrl_name.upper():
                    ctrl_type = "osa"
                else:
                    ctrl_type = "unsupported"

                ep = d.get("endurance_remaining_pct", "")
                tbw_val = d.get("tbw_written") if d.get("tbw_written") is not None else d.get("tbw")
                drives.append({
                    "host_idx": idx,
                    "hostname": h_name,
                    "ip": h_ip,
                    "ctrl_name": ctrl_name,
                    "model": str(d.get("model") or ""),
                    "media_type": str(d.get("media_type") or ""),
                    "protocol": proto,
                    "capacity_gb": d.get("capacity_gb", 0),
                    "firmware": str(d.get("firmware") or ""),
                    "drive_health": str(d.get("drive_health") or d.get("status") or "OK"),
                    "endurance_pct": ep if ep not in ("", "N/A", None) else None,
                    "tbw_written": tbw_val,
                    "tbr_read": d.get("tbr_read"),
                    "power_on_hours": d.get("power_on_hours"),
                    "power_cycles": d.get("power_cycles"),
                    "critical_warnings": d.get("critical_warnings"),
                    "controller_duty_cycle_pct": d.get("controller_duty_cycle_pct"),
                    "temperature_c": d.get("temperature_c"),
                    "unsafe_shutdowns": d.get("unsafe_shutdowns"),
                    "category": cat,
                    "ctrl_type": ctrl_type,
                    "is_perc7xx": is_perc7xx,
                    "behind_sw": behind_sw or is_sw_ctrl,
                    "behind_tm": behind_tm,
                })

        # 2. NICs
        for ad in data.get("network_adapters") or []:
            ad_name = str(ad.get("name") or ad.get("model") or "Network Adapter")
            fw = str(ad.get("firmware_version") or ad.get("firmware") or "")
            for p in ad.get("ports") or []:
                spd = p.get("current_speed_gbps") or p.get("speed_gbps") or 0
                link = str(p.get("link_status") or ("Up" if _link_is_up(p.get("link_status")) else "Down"))
                mac = "02:00:00:00:00:00" if obfuscated else str(p.get("mac_address") or p.get("mac") or "")
                meets_25g = False
                try:
                    meets_25g = float(spd or 0) >= 25
                except (ValueError, TypeError):
                    meets_25g = False
                nics.append({
                    "host_idx": idx,
                    "hostname": h_name,
                    "ip": h_ip,
                    "adapter": ad_name,
                    "port_id": str(p.get("port_id") or p.get("id") or "Port"),
                    "speed_gbps": spd,
                    "link_status": link,
                    "mac_address": mac,
                    "firmware": fw,
                    "meets_25g": meets_25g,
                    "transceiver_type": str(p.get("transceiver_identifier") or ""),
                    "transceiver_interface": str(p.get("transceiver_interface") or ""),
                    "transceiver_vendor": str(p.get("transceiver_vendor") or ""),
                    "transceiver_part_number": str(p.get("transceiver_part_number") or ""),
                })

        # 3. Health & Alarms
        sel = data.get("sel_alarms") or data.get("system_event_log") or data.get("sel") or []
        for item in sel:
            sev_raw = str(item.get("severity") or item.get("badge") or "Warning").upper()
            sev = "Critical" if "CRIT" in sev_raw or "DANGER" in sev_raw else ("Warning" if "WARN" in sev_raw else "Info")
            msg = str(item.get("message") or item.get("msg") or item.get("description") or "Event entry")
            if obfuscated:
                msg = re.sub(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', '192.0.2.1', msg)
            ts = str(item.get("timestamp") or item.get("created") or item.get("time") or "")
            health_list.append({
                "host_idx": idx,
                "hostname": h_name,
                "ip": h_ip,
                "severity": sev,
                "subsystem": "SEL Event Log",
                "message": msg,
                "target": str(item.get("target") or "SEL Entry"),
                "timestamp": ts,
            })

        for _ctrl, d in _all_drives(data):
            dh = str(d.get("drive_health") or d.get("status") or "").upper()
            ep = d.get("endurance_remaining_pct")
            ep_val = None
            if ep is not None and ep != "" and ep != "N/A":
                try:
                    ep_val = float(ep)
                except (ValueError, TypeError):
                    ep_val = None

            is_degraded = dh in ("WARNING", "CRITICAL", "FAILED", "DEGRADED")
            is_low_endurance = ep_val is not None and ep_val < 10
            if is_degraded or is_low_endurance:
                sev = "Critical" if dh in ("CRITICAL", "FAILED") or (ep_val is not None and ep_val < 5) else "Warning"
                wear_msg = f", wear: {ep}% remaining" if (ep is not None and ep != "" and ep != "N/A") else ""
                health_list.append({
                    "host_idx": idx,
                    "hostname": h_name,
                    "ip": h_ip,
                    "severity": sev,
                    "subsystem": "Drive Health",
                    "message": f"Drive {d.get('model', '')} status: {dh}{wear_msg}",
                    "target": str(d.get("model") or "Drive"),
                    "timestamp": "",
                })

        psu = data.get("psu_status") or {}
        if psu and not psu.get("redundant", True):
            health_list.append({
                "host_idx": idx,
                "hostname": h_name,
                "ip": h_ip,
                "severity": "Warning",
                "subsystem": "Power Supply",
                "message": "Power supply redundancy degraded",
                "target": "Chassis PSU",
                "timestamp": "",
            })

    return {
        "meta": {
            "total_hosts": len(all_results),
            "obfuscated": bool(obfuscated),
        },
        "hosts": compact_hosts,
        "drives": drives,
        "nics": nics,
        "health": health_list,
    }


def _hdr(*names: str) -> List[Tuple[str, str]]:
    return [(n, "header") for n in names]



def build_inventory_sheets(
    all_results: List[dict],
    obfuscated: bool = False,
    json_hcl: Optional[dict] = None,
) -> List[Dict[str, Any]]:
    """SE Decision sheet first, followed by granular detail component sheets for Excel."""
    if json_hcl is None:
        try:
            from vcf_hci.hcl import load_vsan_hcl_json
            json_hcl = load_vsan_hcl_json()
        except Exception:
            json_hcl = {}

    decision_rows_data = build_host_decision_rows(all_results)
    dec_hdr = _hdr(
        "Host IP", "Hostname", "Vendor", "Model", "CPU Model", "CPU Verdict",
        "Host OS", "ESA Disks", "ESA Count", "ESA Total TB", "ESA Tier", "ESA Profile",
        "NIC Summary", "NIC Ports", "NIC Max Gbps", "NIC Up", "NIC Down",
        "RAM GB", "DIMMs", "Interleaving %", "TPM", "BMC Sec Posture", "VMD", "HW RAID", "PSU Redundant",
        "Power Cap", "BIOS", "OS / ESXi EOL", "GPU Count", "Partial",
    )
    dec_rows: List[list] = [dec_hdr]
    for r in decision_rows_data:
        tpm_ok = r.get("tpm_ok")
        tpm_txt = "Yes" if tpm_ok is True else ("No" if tpm_ok is False else "")
        vmd_txt = "On" if r.get("vmd_on") else "Off"
        verdict = r.get("cpu_verdict", "")
        os_disp = r.get("os_name") or r.get("os_label") or ""

        sec_posture = r.get("sec_posture") or "not_assessed"
        if sec_posture == "baseline_met":
            sec_cell = ("Baseline Met", "green")
        elif sec_posture == "action_req":
            sec_cell = ("Action Required", "red")
        elif sec_posture == "partial":
            sec_cell = ("Partially Assessed", "yellow")
        elif sec_posture == "excluded":
            sec_cell = ("Excluded", "yellow")
        else:
            sec_cell = ("Not Assessed", "yellow")

        dec_rows.append([
            r.get("ip", ""), r.get("hostname", ""), r.get("vendor", ""), r.get("model", ""),
            r.get("cpu_model", ""), (verdict, r.get("cpu_tier", "")),
            os_disp,
            r.get("esa", {}).get("display", ""), r.get("esa", {}).get("count", 0),
            r.get("esa", {}).get("total_tb", 0), r.get("esa_tier", ""),
            (r.get("esa_profile") or {}).get("tier_label", ""),
            r.get("nic", {}).get("display", ""), r.get("nic", {}).get("port_count", 0),
            r.get("nic", {}).get("max_gbps", 0), r.get("nic", {}).get("up", 0), r.get("nic", {}).get("down", 0),
            r.get("ram_gb", ""), r.get("dimm_count", 0), r.get("interleaving_str", ""),
            tpm_txt, sec_cell, vmd_txt, "Yes" if r.get("has_hw_raid") else "No",
            r.get("psu_redundant", ""), "Enforced" if r.get("power_cap_on") else "No",
            r.get("bios_version", ""), r.get("esxi_eol", ""), r.get("gpu_count", 0),
            "Yes" if r.get("partial") else "No",
        ])

    cpu_rows: List[list] = [_hdr(
        "Host IP", "Hostname", "Socket", "Model", "Cores", "Threads", "Base GHz", "Max Boost GHz",
        "Max MHz", "Operating MHz", "Health", "State", "Microcode", "Processor ID",
        "CPU Verdict", "Architecture",
    )]
    mem_rows: List[list] = [_hdr(
        "Host IP", "Hostname", "Slot", "Socket", "Channel", "Capacity GB", "Type",
        "Speed MHz", "Max Speed MHz", "Manufacturer", "Part Number",
        "Serial", "Health", "State", "Interleaving %", "Issues",
    )]
    stor_rows: List[list] = [_hdr(
        "Host IP", "Hostname", "Controller", "Controller Model", "Controller FW", "Drive", "Model",
        "Part Number", "Bay", "Form Factor", "Media", "Protocol", "Capacity GB", "Serial", "Firmware",
        "Certified FW", "FW Status", "Health", "Category", "HCL Tier", "Life %",
        "TBW (TB)", "TBR (TB)", "Power-On Hours", "Power Cycles", "Temp (°C)", "Unsafe Shutdowns", "Critical Warnings", "Duty Cycle %",
        "vSAN Eligible", "Behind Tri-Mode", "Boot",
    )]
    mac_hdr = "MAC (obfuscated)" if obfuscated else "MAC"
    pmac_hdr = "Permanent MAC (obfuscated)" if obfuscated else "Permanent MAC"
    net_rows: List[list] = [_hdr(
        "Host IP", "Hostname", "Adapter", "Adapter ID", "Manufacturer", "Part Number", "PCI Quad",
        "FW", "Port ID", mac_hdr, pmac_hdr, "Link", "Speed Gbps", "Meets ≥25GbE ESA", "CNA", "NPAR",
        "Transceiver Type", "Transceiver Media", "Transceiver Vendor", "Transceiver Part Number",
        "LLDP Switch", "LLDP Port",
    )]
    gpu_rows: List[list] = [_hdr(
        "Host IP", "Hostname", "Name", "Manufacturer", "Slot", "Firmware", "Health",
        "Temp (°C)", "Max Temp (°C)", "Power Brake",
        "VRAM GiB", "PCIe", "Lanes", "Part Number", "Serial", "PCI", "VCF AI Readiness",
    )]
    fw_rows: List[list] = [_hdr(
        "Host IP", "Hostname", "Name", "Version", "Component ID", "Description",
        "Device Context", "Updateable",
    )]
    hba_rows: List[list] = [_hdr(
        "Host IP", "Hostname", "Name", "Manufacturer", "Model", "WWPN", "WWNN",
        "Firmware", "Health", "Speed Gbps",
    )]
    bios_rows: List[list] = [_hdr(
        "Host IP", "Hostname", "Model", "BIOS Version", "Release Date",
        "CPU Power Profile", "Memory RAS", "Intel VMD", "Boot Mode", "Spectre / CVE Tier",
        "AMD Performance / NUMA",
    )]
    health_rows: List[list] = [_hdr(
        "Host IP", "Hostname", "Severity", "Subsystem", "Target", "Message", "Timestamp",
    )]

    for data in all_results or []:
        ip = _host_ip(data)
        si = data.get("system") or {}
        hostname = str(si.get("hostname") or ip).strip()
        vendor_raw = str(si.get("vendor") or "")
        model_raw = str(si.get("model") or "")
        clean_m = clean_model_code(vendor_raw, model_raw) or model_raw or "—"
        ci = si.get("cpu_summary") or {}
        mem_topo = data.get("memory_topology") or {}
        sc = (data.get("bios_checks") or {}).get("side_channel") or []
        ucode = ", ".join(c.get("label", "") for c in sc if "Microcode" in c.get("feature", "")) or "N/A"
        verdict = _strip_html(str(ci.get("verdict") or ""))
        procs = ci.get("processors") or []

        if procs:
            for p in procs:
                cpu_rows.append([
                    ip, hostname, p.get("socket", ""), p.get("model") or ci.get("model", ""),
                    p.get("cores", ""), p.get("threads", ""),
                    ci.get("base_freq_ghz", ""), ci.get("max_freq_ghz", ""),
                    p.get("max_speed_mhz", ""), p.get("operating_speed_mhz", ""),
                    p.get("health", ""), p.get("state", ""), ucode, p.get("processor_id", ""),
                    verdict, ci.get("architecture", ""),
                ])
        else:
            cpu_rows.append([
                ip, hostname, "", ci.get("model", ""), ci.get("core_count", ""),
                ci.get("logical_count", ""), ci.get("base_freq_ghz", ""), ci.get("max_freq_ghz", ""),
                "", "", "", "", ucode, ci.get("processor_id", ""),
                verdict, ci.get("architecture", ""),
            ])

        interleaving_val = mem_topo.get("interleaving_score_pct", "")
        topo_issues = "; ".join(strip_html(i) for i in (mem_topo.get("issues") or []))
        for dimm in (data.get("memory_subsystem") or {}).get("dimm_list") or []:
            mem_rows.append([
                ip, hostname, dimm.get("slot", ""), dimm.get("socket", ""), dimm.get("channel", ""),
                dimm.get("capacity_gb", ""), dimm.get("type", ""),
                dimm.get("speed_mhz", ""), dimm.get("max_speed_mhz", ""),
                dimm.get("manufacturer", ""), dimm.get("part_number", ""),
                dimm.get("serial_number", ""), dimm.get("health", ""), dimm.get("state", ""),
                interleaving_val, topo_issues,
            ])

        for ctrl, d in _all_drives(data):
            ep = d.get("endurance_remaining_pct", "")
            hcl = strip_html(d.get("hcl_str") or d.get("status_badge", ""))
            ctrl_fw = ctrl.get("ctrl_firmware") or ctrl.get("firmware_version") or ""
            d_fw = str(d.get("firmware") or d.get("firmware_version") or "").strip()
            d_vid = str(d.get("vendor_id") or "").strip()
            d_did = str(d.get("device_id") or "").strip()
            d_svid = str(d.get("subsystem_vendor_id") or "").strip()
            d_ssid = str(d.get("subsystem_id") or "").strip()
            d_model = str(d.get("model") or d.get("name") or "").strip()

            eval_res = evaluate_driver_firmware_recommendation(
                vid=d_vid, did=d_did, svid=d_svid, ssid=d_ssid, model_name=d_model, fw_ver=d_fw, hcl_data=json_hcl
            )
            st = eval_res.get("fw_status")
            rec = eval_res.get("recommended_firmware") or ""
            if st == "current":
                fw_status_cell = ("Certified Current", "green")
                cert_fw = rec or d_fw
            elif st in ("update_available", "outdated"):
                c_style = "red" if st == "outdated" else "yellow"
                lbl = "Outdated" if st == "outdated" else "Update Recommended"
                fw_status_cell = (lbl, c_style)
                cert_fw = rec or ""
            else:
                model_up = d_model.upper()
                baseline = next((NVME_FW_BASELINES[k] for k in NVME_FW_BASELINES if model_up.startswith(k)), None)
                if baseline and d_fw:
                    latest = str(baseline.get("latest") or "").upper()
                    min_rec = str(baseline.get("min_recommended") or "").upper()
                    fw_up = d_fw.upper()
                    cert_fw = latest
                    if fw_up >= latest:
                        fw_status_cell = ("Certified Current", "green")
                    elif fw_up >= min_rec:
                        fw_status_cell = ("Update Available", "yellow")
                    else:
                        fw_status_cell = ("Outdated", "red")
                else:
                    cert_fw = "—"
                    fw_status_cell = ""

            tbw_val = d.get("tbw_written") if d.get("tbw_written") is not None else d.get("tbw")
            tbw_str = f"{float(tbw_val):.2f}" if tbw_val is not None and isinstance(tbw_val, (int, float)) else (str(tbw_val) if tbw_val else "")
            tbr_val = d.get("tbr_read")
            tbr_str = f"{float(tbr_val):.2f}" if tbr_val is not None and isinstance(tbr_val, (int, float)) else (str(tbr_val) if tbr_val else "")
            poh_val = d.get("power_on_hours")
            pwr_cyc = d.get("power_cycles")
            temp_val = d.get("temperature_c")
            unsafe_val = d.get("unsafe_shutdowns")
            crit_warn = d.get("critical_warnings")
            duty_cycle = d.get("controller_duty_cycle_pct")
            duty_str = f"{duty_cycle}%" if duty_cycle is not None else ""

            stor_rows.append([
                ip, hostname,
                ctrl.get("name") or ctrl.get("id") or "",
                ctrl.get("ctrl_model") or ctrl.get("controller_model") or "",
                ctrl_fw,
                d.get("name") or d.get("id") or "",
                d_model,
                d.get("part_number", ""),
                d.get("bay_slot") or d.get("bay_position") or "",
                d.get("form_factor_label") or "",
                d.get("media_type", ""),
                d.get("protocol", ""),
                d.get("capacity_gb", ""),
                d.get("serial_number") or d.get("serial") or "",
                d_fw,
                cert_fw,
                fw_status_cell,
                d.get("drive_health", ""),
                d.get("category", ""),
                hcl,
                ep if ep != "" else "N/A",
                tbw_str,
                tbr_str,
                poh_val if poh_val is not None else "",
                pwr_cyc if pwr_cyc is not None else "",
                temp_val if temp_val is not None else "",
                unsafe_val if unsafe_val is not None else "",
                crit_warn if crit_warn is not None else "",
                duty_str,
                "Yes" if d.get("vsan_eligible") else "No",
                "Yes" if d.get("behind_trimode") else "No",
                "Yes" if d.get("is_boot") else "No",
            ])

        lldp_lookup: Dict[str, Dict[str, Any]] = {}
        for lldp in data.get("lldp_neighbors", []):
            if lldp.get("local_iface"):
                lldp_lookup[str(lldp["local_iface"]).strip()] = lldp
            if lldp.get("local_mac"):
                lldp_lookup[str(lldp["local_mac"]).strip().lower()] = lldp

        for n in data.get("network_adapters") or []:
            ports = n.get("ports") or [{}]
            pci = n.get("pci_quad") or n.get("pci_pair") or ""
            for p in ports:
                pid = str(p.get("port_id") or p.get("name") or "").strip()
                mac = str(p.get("mac_address") or "").strip()
                pmac = str(p.get("permanent_mac_address") or "").strip()
                lldp_info = lldp_lookup.get(pid) or lldp_lookup.get(mac.lower()) or {}
                link_st = str(p.get("link_status") or "")
                is_up = _link_is_up(link_st)
                link_cell = (link_st, "green" if is_up else "red") if link_st else ""
                spd = p.get("current_speed_gbps")
                spd_val = 0.0
                try:
                    spd_val = float(spd or 0)
                except (ValueError, TypeError):
                    pass
                meets_25g_cell = ("Yes", "green") if spd_val >= 25 else ("No", "yellow")
                net_rows.append([
                    ip, hostname, n.get("name", ""), n.get("id", ""),
                    n.get("manufacturer", ""), n.get("part_number", ""), pci,
                    n.get("firmware_version", ""),
                    pid, mac, pmac,
                    link_cell, spd if spd is not None else "",
                    meets_25g_cell,
                    "Yes" if n.get("is_cna") else "No",
                    "Yes" if n.get("is_npar") else "No",
                    p.get("transceiver_identifier", ""),
                    p.get("transceiver_interface", ""),
                    p.get("transceiver_vendor", ""),
                    p.get("transceiver_part_number", ""),
                    lldp_info.get("switch_name", ""), lldp_info.get("switch_port", ""),
                ])

        for g in data.get("gpu_accelerators") or []:
            raw_gpu = (str(g.get("name") or "") + " " + str(g.get("manufacturer") or "")).upper()
            vcf_ai = "High (Enterprise AI/LLM)" if any(k in raw_gpu for k in ("H100", "H200", "A100", "L40", "MI300")) else "Supported (vGPU / Compute)"
            gpu_rows.append([
                ip, hostname, g.get("name", ""), g.get("manufacturer", ""),
                g.get("slot_label") or g.get("slot", ""), g.get("firmware", ""), g.get("health", ""),
                g.get("temperature_c") if g.get("temperature_c") is not None else "",
                g.get("max_operating_temp_c") if g.get("max_operating_temp_c") is not None else "",
                g.get("power_brake_status") or "",
                g.get("memory_gib", ""), g.get("pcie_type", ""), g.get("lanes", ""),
                g.get("part_number", ""), g.get("serial_number", ""),
                g.get("pci_quad") or g.get("pci_pair") or "", vcf_ai,
            ])

        for fw in data.get("firmware_inventory") or []:
            fw_rows.append([
                ip, hostname, fw.get("name", ""), fw.get("version", ""),
                fw.get("component_id", ""), fw.get("description", ""),
                fw.get("device_context", ""),
                "Yes" if fw.get("updateable") else "No",
            ])

        for hba in data.get("fc_hbas") or []:
            hba_rows.append([
                ip, hostname,
                hba.get("adapter_name") or hba.get("name") or hba.get("id") or "",
                hba.get("manufacturer", ""),
                hba.get("model") or hba.get("cna_family_label") or hba.get("adapter_name") or "",
                hba.get("wwpn", ""),
                hba.get("wwnn", ""),
                hba.get("firmware_version") or hba.get("firmware") or "",
                hba.get("link_status") or hba.get("health") or "",
                hba.get("speed_gbps") or hba.get("port_speed_gbps") or "",
            ])

        # ── vBIOS row ─────────────────────────────────────────────────────────
        bios_checks = data.get("bios_checks") or {}
        bios_eval = si.get("bios_eval") or {}
        bios_ver = str(si.get("bios_version") or "—")
        bios_date = str(si.get("bios_release_date") or "—")

        # CPU Power Profile
        cpu_power = bios_checks.get("cpu_power") or []
        chosen_pwr = select_cpu_power_entry(cpu_power)
        if chosen_pwr:
            pwr_label = str(chosen_pwr.get("label") or "Performance")
            pwr_badge = str(chosen_pwr.get("badge") or "success")
            low_label = pwr_label.lower()
            if pwr_badge == "danger":
                pwr_cell = (pwr_label, "red")
            elif pwr_badge == "warning":
                pwr_cell = (pwr_label, "yellow")
            elif any(k in low_label for k in ("perf", "maximum", "os control")) or pwr_badge == "success":
                pwr_cell = (pwr_label, "green")
            else:
                pwr_cell = (pwr_label, "yellow")
        else:
            pwr_cell = "—"

        # Memory RAS
        mem_ras = bios_checks.get("memory_ras") or []
        chosen_ras = select_memory_ras_entry(mem_ras)
        ras_label = str(chosen_ras.get("label") or "Optimized") if chosen_ras else "Standard"

        # Intel VMD
        vmd_on = bool(bios_checks.get("vmd_enabled_flag"))
        vmd_cell = ("Enabled (VMD)", "red") if vmd_on else ("Disabled (Pass-thru)", "green")

        # Boot Mode
        boot_mode = str(si.get("boot_mode") or si.get("raw_boot_mode") or "UEFI")
        if "uefi" in boot_mode.lower():
            boot_cell = ("UEFI", "green")
        elif "legacy" in boot_mode.lower() or "bios" in boot_mode.lower():
            boot_cell = ("Legacy BIOS", "red")
        else:
            boot_cell = boot_mode

        # Spectre / CVE Tier
        cve_tier_int = bios_eval.get("cve_tier")
        cve_label = bios_eval.get("cve_tier_label")
        if cve_tier_int is not None and cve_tier_int >= 0:
            cve_str = f"Tier {cve_tier_int}: {cve_label or ''}".strip()
            cve_cell = (cve_str, "green" if cve_tier_int >= 4 else "red")
        else:
            cve_cell = "—"

        # AMD Performance / NUMA attributes
        amd_perf_items = [
            f"{c.get('feature')}: {c.get('label')}"
            for c in (bios_checks.get("cpu_power") or [])
            if any(k in str(c.get("feature", "")).lower() for k in ["determinism", "ccx as numa", "numa", "data fabric"])
        ]
        amd_perf_cell = "; ".join(amd_perf_items) if amd_perf_items else "—"

        bios_rows.append([
            ip, hostname, clean_m, bios_ver, bios_date,
            pwr_cell, ras_label, vmd_cell, boot_cell, cve_cell,
            amd_perf_cell,
        ])

        # ── Health_Alarms rows ────────────────────────────────────────────────
        host_has_alarms = False
        sel = data.get("sel_alarms") or data.get("system_event_log") or data.get("sel") or []
        norm_v = normalize_vendor(vendor_raw)
        for item in sel:
            sev_raw = str(item.get("severity") or item.get("badge") or "Warning").upper()
            sev = "Critical" if "CRIT" in sev_raw or "DANGER" in sev_raw else ("Warning" if "WARN" in sev_raw else "Info")
            c_style = "red" if sev == "Critical" else ("yellow" if sev == "Warning" else "")
            msg = str(item.get("message") or item.get("msg") or item.get("description") or "Event entry")
            ts = str(item.get("timestamp") or item.get("created") or item.get("time") or "—")
            msg_id = str(item.get("message_id") or item.get("id") or item.get("code") or "—")
            clean_mid = msg_id if msg_id != "—" else None
            if norm_v == "dell":
                info = resolve_dell_event_info(clean_mid, msg)
                target_label = f"Event {info['display']}" if info.get("display") else ("Event " + msg_id if clean_mid else "SEL Entry")
            elif norm_v == "hpe":
                info = resolve_hpe_event_info(clean_mid, msg)
                target_label = f"Event {info['display']}" if info.get("display") else ("Event " + msg_id if clean_mid else "SEL Entry")
            elif norm_v == "cisco":
                info = resolve_cisco_event_info(clean_mid, msg)
                target_label = f"Event {info['display']}" if info.get("display") else ("Event " + msg_id if clean_mid else "SEL Entry")
            else:
                target_label = f"Event {msg_id}" if clean_mid else "SEL Entry"

            health_rows.append([
                ip, hostname, (sev, c_style) if c_style else sev,
                "SEL Event Log", target_label, msg, ts,
            ])
            host_has_alarms = True

        for _ctrl, d in _all_drives(data):
            if (d.get("category") or "") == "Empty":
                continue
            bay = d.get("bay_slot") or d.get("bay_position") or d.get("id") or "Bay"
            d_model = str(d.get("model") or d.get("name") or "Drive")
            target_str = f"Slot {bay} ({d_model})"

            if d.get("failure_predicted") or (d.get("oem_metrics") or {}).get("predictive_failure"):
                health_rows.append([
                    ip, hostname, ("Critical", "red"),
                    "Drive SMART", target_str, "Predictive failure reported on drive", "—",
                ])
                host_has_alarms = True

            ep = d.get("endurance_remaining_pct")
            if ep is not None and ep != "" and ep != "N/A":
                try:
                    ep_val = float(ep)
                    if ep_val < 5:
                        health_rows.append([
                            ip, hostname, ("Critical", "red"),
                            "Drive Wear", target_str, f"Critical endurance limit reached: {ep}% remaining life", "—",
                        ])
                        host_has_alarms = True
                    elif ep_val < 10:
                        health_rows.append([
                            ip, hostname, ("Warning", "yellow"),
                            "Drive Wear", target_str, f"Low endurance threshold reached: {ep}% remaining life", "—",
                        ])
                        host_has_alarms = True
                except (ValueError, TypeError):
                    pass

            d_health = str(d.get("drive_health") or d.get("status") or "").upper()
            if d_health in ("WARNING", "CRITICAL", "FAILED", "DEGRADED"):
                sev_d = "Critical" if d_health in ("CRITICAL", "FAILED") else "Warning"
                health_rows.append([
                    ip, hostname, (sev_d, "red" if sev_d == "Critical" else "yellow"),
                    "Drive Health", target_str, f"Drive status degraded ({d_health})", "—",
                ])
                host_has_alarms = True

        psu = data.get("psu_status") or {}
        if psu.get("redundant") is False:
            health_rows.append([
                ip, hostname, ("Critical", "red"),
                "Power Supply", "Chassis PSU", "Power supply redundancy lost or non-redundant", "—",
            ])
            host_has_alarms = True

        therm = data.get("thermal") or {}
        if therm.get("status") in ("Warning", "Critical"):
            sev_t = "Critical" if therm.get("status") == "Critical" else "Warning"
            health_rows.append([
                ip, hostname, (sev_t, "red" if sev_t == "Critical" else "yellow"),
                "Thermal / Cooling", "Chassis Thermal", str(therm.get("message") or "Thermal threshold breach"), "—",
            ])
            host_has_alarms = True

        if not host_has_alarms and data:
            health_rows.append([
                ip, hostname, ("OK", "green"),
                "System Health", "All Subsystems", "No active hardware alarms or degraded components", "—",
            ])

    return [
        {"name": "Decision", "rows": dec_rows},
        {"name": "vCPU", "rows": cpu_rows},
        {"name": "vMemory", "rows": mem_rows},
        {"name": "vStorage", "rows": stor_rows},
        {"name": "vNetwork", "rows": net_rows},
        {"name": "vGPU", "rows": gpu_rows},
        {"name": "vFirmware", "rows": fw_rows},
        {"name": "vHBA", "rows": hba_rows},
        {"name": "vBIOS", "rows": bios_rows},
        {"name": "Health_Alarms", "rows": health_rows},
    ]
