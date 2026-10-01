"""
Inventory badge, chip, and cell formatting helpers.

Provides visual indicator chips, formatting utilities, and BCG deep links
for the Detailed Inventory table and subpanes.
"""
from __future__ import annotations

import html
import re
from typing import Any, Dict, Optional

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.compat_engine import (
    evaluate_driver_firmware_recommendation,
    evaluate_pci_compatibility,
)
from vcf_hci.constants import NVME_FW_BASELINES
from vcf_hci.hcl import lookup_unique_hcl_device
from vcf_hci.report.fleet.escape import _xe

_DASH = "—"

_SUBSYSTEM_SUBTABS: Dict[str, str] = {
    "SEL Event Log": "tab-overview",
    "Drive SMART": "tab-storage",
    "Drive Health": "tab-storage",
    "Drive Wear": "tab-storage",
    "Drive Thermal": "tab-storage",
    "Drive PCIe": "tab-storage",
    "Drive Media": "tab-storage",
    "Power Supply": "tab-health",
    "Thermal": "tab-health",
    "Memory": "tab-memory",
    "Scan Status": "tab-overview",
}


def _default_pii(v: Any, k: str = "host") -> str:
    return _xe(str(v or ""))


def _format_cpu_model(model: str) -> str:
    m = str(model or "").strip()
    if not m:
        return _DASH
    m_esc = html.escape(m)
    intel_pat = r"^(Intel(?:\(R\)|&reg;)?\s+Xeon(?:\(R\)|&reg;|\(TM\)|&trade;)?)\s+"
    if re.search(intel_pat, m_esc, flags=re.IGNORECASE):
        return re.sub(intel_pat, r"\1<br>", m_esc, count=1, flags=re.IGNORECASE)

    amd_pat = r"^((?:AMD\s+)?EPYC(?:\(TM\)|&trade;)?)\s+"
    if re.search(amd_pat, m_esc, flags=re.IGNORECASE):
        return re.sub(amd_pat, r"\1<br>", m_esc, count=1, flags=re.IGNORECASE)

    return m_esc


def _cpu_dot(tier: str, model: str, verdict: str) -> str:
    color_cls = {"green": "inv-good", "yellow": "inv-warn", "red": "inv-bad"}.get(tier, "inv-muted")
    tip = html.escape(f"{model} — {verdict}", quote=True)
    formatted_model = _format_cpu_model(model)
    return (
        f"<div style='display:inline-flex;align-items:flex-start;gap:4px'>"
        f"<span class='{color_cls}' title='{tip}' style='font-size:13px;line-height:1;margin-top:1px'>\u25cf</span>"
        f"<span style='font-size:10px;line-height:1.2;color:var(--text-muted,#64748b);max-width:130px;white-space:normal'>{formatted_model}</span>"
        f"</div>"
    )


def _storage_qualification_chip(r: dict) -> str:
    esa = r.get("esa") or {}
    count = int(esa.get("count") or 0)
    total_tb = esa.get("total_tb") or 0
    raid_blocked = int(esa.get("raid_blocked") or 0)
    sw_raid_count = int(esa.get("sw_raid_count") or r.get("sw_raid_nvme") or 0)
    vmd_on = bool(r.get("vmd_on"))
    ctrl_unsup = bool(r.get("ctrl_unsup"))
    ctrl_osa = bool(r.get("ctrl_osa"))

    if raid_blocked > 0 or (ctrl_unsup and sw_raid_count == 0):
        return "<span class='inv-bad' title='Ineligible for vSAN ESA: NVMe drives are attached to a HW RAID or Tri-Mode controller (direct PCIe pass-through required)'>✗ Behind RAID</span>"
    if vmd_on and count > 0:
        return "<span class='inv-bad' title='Ineligible for vSAN ESA: Intel VMD is enabled in BIOS (must be disabled for native NVMe pass-through)'>✗ VMD Enabled</span>"
    if count >= 2:
        if sw_raid_count > 0:
            return f"<span class='inv-good' title='vSAN ESA Storage Qualified: {count} direct-attached NVMe SSDs ({total_tb} TB total) — Host Software RAID detected; bypass in BIOS (AHCI / Non-RAID) for direct ESXi pass-through'>✓ Storage Qualified (SW RAID)</span>"
        return f"<span class='inv-good' title='vSAN ESA Storage Qualified: {count} direct-attached NVMe SSDs ({total_tb} TB total)'>✓ Storage Qualified</span>"
    if ctrl_osa:
        return "<span class='inv-warn' title='vSAN OSA Storage: SAS/SATA drives detected without direct NVMe SSDs'>▲ OSA (SAS/SATA)</span>"
    if count == 1:
        return "<span class='inv-muted' title='Insufficient storage: 1 direct NVMe SSD detected (minimum 2 required for vSAN ESA)'>— Insufficient (1/2)</span>"
    return "<span class='inv-muted' title='No direct NVMe SSDs detected for vSAN ESA'>— No NVMe Disks</span>"


def _esa_profile_chip(profile: dict) -> str:
    status = profile.get("status") or "muted"
    tier_label = profile.get("tier_label") or profile.get("tier_code") or _DASH
    tooltip = profile.get("tooltip") or ""
    cls_name = {
        "good": "inv-good",
        "warn": "inv-warn",
        "bad": "inv-bad",
    }.get(status, "inv-muted")
    icon = {
        "good": "✓ ",
        "warn": "▲ ",
        "bad": "✗ ",
    }.get(status, "— ")
    tier_code = profile.get("tier_code")
    if not tier_code or tier_code == "Ineligible":
        if status == "bad":
            return f"<span class='{cls_name}' title='{_xe(tooltip)}'>✗ {_xe(tier_label)}</span>"
        return f"<span class='{cls_name}' title='{_xe(tooltip)}'>— Ineligible</span>"
    return f"<span class='{cls_name}' title='{_xe(tooltip)}'>{icon}{_xe(tier_label)}</span>"


def _esa_tier_chip(tier: str) -> str:
    cls_name = {
        "Ready": "inv-good",
        "StorageMet": "inv-warn",
        "Blocked": "inv-bad",
        "Insufficient": "inv-bad",
        "Unknown": "inv-muted",
    }.get(tier, "inv-muted")
    icon = {
        "Ready": "✓ ",
        "StorageMet": "▲ ",
        "Blocked": "✗ ",
        "Insufficient": "✗ ",
        "Unknown": "",
    }.get(tier, "")
    label = {
        "Ready": "Ready",
        "StorageMet": "Storage met",
        "Blocked": "Blocked",
        "Insufficient": "Insufficient",
        "Unknown": "?",
    }.get(tier, tier)
    tip = {
        "Ready": "vSAN ESA Ready: Meets storage (>=2 direct NVMe SSDs) and networking (>=25 GbE) requirements.",
        "StorageMet": "ESA Storage Met: Meets vSAN ESA storage criteria (>=2 Direct NVMe SSDs), but host NIC is <25 GbE. Requires a 25 GbE+ NIC upgrade for full ESA readiness.",
        "Blocked": "vSAN ESA Ineligible: NVMe drives are behind RAID/Tri-Mode controller or Intel VMD is enabled.",
        "Insufficient": "Insufficient drives for vSAN ESA/OSA.",
        "Unknown": "vSAN status unknown",
    }.get(tier, "")
    return (
        f"<span class='{cls_name}' title='{_xe(tip)}'>{icon}{_xe(label)}</span>"
    )


def _dot_bool(ok: Optional[bool], title_yes: str, title_no: str, title_unk: str = "Unknown") -> str:
    if ok is True:
        return f"<span class='inv-good' title='{_xe(title_yes)}'>✓</span>"
    if ok is False:
        return f"<span class='inv-bad' title='{_xe(title_no)}'>✗</span>"
    return f"<span class='inv-muted' title='{_xe(title_unk)}'>—</span>"


def _vmd_cell(vmd_on: Optional[bool]) -> str:
    if vmd_on:
        return "<span class='inv-bad' title='VMD enabled (bad for ESA NVMe passthrough)'>✗ On</span>"
    return "<span class='inv-good' title='VMD off (pass-through ready)'>✓ Off</span>"


def _drive_fw_cell(d: dict, json_hcl: Optional[dict] = None) -> str:
    """Return color-coded firmware HTML cell for a drive (Green=supported, Orange=update needed)."""
    fw = str(d.get("firmware") or d.get("firmware_version") or "").strip()
    if not fw or fw == "N/A":
        return f"<span class='inv-muted'>{_DASH}</span>"

    vid = str(d.get("vendor_id") or "").strip()
    did = str(d.get("device_id") or "").strip()
    svid = str(d.get("subsystem_vendor_id") or "").strip()
    ssid = str(d.get("subsystem_id") or "").strip()
    model = str(d.get("model") or d.get("name") or "").strip()

    eval_res = evaluate_driver_firmware_recommendation(
        vid=vid, did=did, svid=svid, ssid=ssid, model_name=model, fw_ver=fw, hcl_data=json_hcl
    )
    st = eval_res.get("fw_status")
    rec = eval_res.get("recommended_firmware")

    if st == "current":
        return f"<code class='inv-good inv-code' title='Firmware Certified &amp; Current ({_xe(fw)})'>✓ {_xe(fw)}</code>"
    elif st in ("update_available", "outdated"):
        tip = f"Update recommended: latest certified is {rec}" if rec else "Firmware update recommended"
        return f"<code class='inv-warn inv-code' title='{_xe(tip)}'>▲ {_xe(fw)}</code>"

    # Fallback to NVME_FW_BASELINES
    model_up = model.upper()
    baseline = next((NVME_FW_BASELINES[k] for k in NVME_FW_BASELINES if model_up.startswith(k)), None)
    if baseline:
        latest = str(baseline.get("latest") or "").upper()
        min_rec = str(baseline.get("min_recommended") or "").upper()
        fw_up = fw.upper()
        if fw_up >= latest:
            return f"<code class='inv-good inv-code' title='Certified baseline ({latest})'>✓ {_xe(fw)}</code>"
        elif fw_up >= min_rec:
            return f"<code class='inv-warn inv-code' title='Update available → {latest}'>▲ {_xe(fw)}</code>"
        else:
            return f"<code class='inv-bad inv-code' title='Outdated (min {min_rec})'>▲ {_xe(fw)}</code>"

    return f"<code class='inv-code'>{_xe(fw)}</code>"


def _drive_model_link(d: dict, json_hcl: Optional[dict] = None) -> str:
    """Return drive model string with deep-link to Broadcom Compatibility Guide."""
    model = str(d.get("model") or d.get("name") or "").strip()
    if not model:
        return f"<span style='color:var(--text-muted,#94a3b8)'>{_DASH}</span>"

    vid = str(d.get("vendor_id") or "").strip()
    did = str(d.get("device_id") or "").strip()
    svid = str(d.get("subsystem_vendor_id") or "").strip()
    ssid = str(d.get("subsystem_id") or "").strip()
    pn = str(d.get("product_id") or d.get("part_number") or "").strip()
    media = str(d.get("media_type") or "").strip()

    _unique_item = lookup_unique_hcl_device(
        vid=vid, did=did, svid=svid, ssid=ssid, json_hcl=json_hcl, model_name=model
    )
    _pid = _unique_item.get("product_id", "") if _unique_item else ""
    _prog = _unique_item.get("hcl_program", "") if _unique_item else ""
    if not _prog:
        _prog = "hdd" if "HDD" in media.upper() else "ssd"

    bcg_url = BCGLinkGenerator.prefer_device_or_search(
        _pid, _prog,
        BCGLinkGenerator.storage_exact,
        model, pn, vid, did, svid, ssid, media_type=media
    )

    if bcg_url:
        return f"<a href='{_xe(bcg_url)}' target='_blank' class='btn-link' style='color:var(--primary,#3b82f6);text-decoration:none;font-weight:600' title='Open in Broadcom Compatibility Guide'>{_xe(model)} ↗</a>"
    return f"<strong>{_xe(model)}</strong>"


def _nic_fw_cell(n: dict, json_hcl: Optional[dict] = None) -> str:
    """Return color-coded firmware HTML cell for a NIC (Green=supported, Orange=update needed)."""
    fw = str(n.get("firmware_version") or "").strip()
    if not fw or fw == "N/A":
        return f"<span class='inv-muted'>{_DASH}</span>"

    vid = str(n.get("vendor_id") or "").strip()
    did = str(n.get("device_id") or "").strip()
    svid = str(n.get("subsystem_vendor_id") or "").strip()
    ssid = str(n.get("subsystem_id") or "").strip()
    name = str(n.get("name") or n.get("model") or "").strip()

    eval_res = evaluate_driver_firmware_recommendation(
        vid=vid, did=did, svid=svid, ssid=ssid, model_name=name, fw_ver=fw, hcl_data=json_hcl
    )
    st = eval_res.get("fw_status")
    rec = eval_res.get("recommended_firmware")

    if st == "current":
        return f"<code class='inv-good inv-code' title='Firmware Certified &amp; Current ({_xe(fw)})'>✓ {_xe(fw)}</code>"
    elif st in ("update_available", "outdated"):
        tip = f"Update recommended: latest certified is {rec}" if rec else "Firmware update recommended"
        return f"<code class='inv-warn inv-code' title='{_xe(tip)}'>▲ {_xe(fw)}</code>"

    return f"<code class='inv-code'>{_xe(fw)}</code>"


def _nic_name_link(n: dict, json_hcl: Optional[dict] = None) -> str:
    """Return NIC adapter model string with deep-link to Broadcom Compatibility Guide."""
    name = str(n.get("name") or n.get("model") or n.get("id") or "").strip()
    if not name:
        return f"<span class='inv-muted'>{_DASH}</span>"

    vid = str(n.get("vendor_id") or "").strip()
    did = str(n.get("device_id") or "").strip()
    svid = str(n.get("subsystem_vendor_id") or "").strip()
    ssid = str(n.get("subsystem_id") or "").strip()
    fw = str(n.get("firmware_version") or "").strip()

    bcg_nic, bcg_vsan_nic = BCGLinkGenerator.io_nic_exact(
        name, fw, vid, did, svid, ssid
    )

    if vid and did:
        pci_eval = evaluate_pci_compatibility(vid, did, svid, ssid, name, fw, hcl_data=json_hcl)
        if pci_eval.get("vcglink"):
            bcg_vsan_nic = pci_eval["vcglink"]
        elif pci_eval.get("product_id"):
            _nic_pid = str(pci_eval["product_id"]).strip()
            bcg_vsan_nic = BCGLinkGenerator.device_detail(_nic_pid, "rdmanic")

        if pci_eval.get("io_vcglink"):
            bcg_nic = pci_eval["io_vcglink"]
        elif pci_eval.get("io_product_id"):
            _io_pid = str(pci_eval["io_product_id"]).strip()
            bcg_nic = BCGLinkGenerator.device_detail(_io_pid, "io")
    elif json_hcl:
        _unique = lookup_unique_hcl_device(json_hcl=json_hcl, model_name=name)
        if _unique:
            if _unique.get("vcglink"):
                bcg_vsan_nic = _unique["vcglink"]
            elif _unique.get("product_id"):
                _nic_pid = str(_unique["product_id"]).strip()
                bcg_vsan_nic = BCGLinkGenerator.device_detail(_nic_pid, "rdmanic")

            if _unique.get("io_vcglink"):
                bcg_nic = _unique["io_vcglink"]
            elif _unique.get("io_product_id"):
                _io_pid = str(_unique["io_product_id"]).strip()
                bcg_nic = BCGLinkGenerator.device_detail(_io_pid, "io")

    bcg_url = bcg_nic or bcg_vsan_nic or BCGLinkGenerator.io_device(name)
    if bcg_url:
        return f"<a href='{_xe(bcg_url)}' target='_blank' class='btn-link' style='color:var(--primary,#3b82f6);text-decoration:none;font-weight:600' title='Open in Broadcom Compatibility Guide'>{_xe(name)} ↗</a>"
    return f"<strong>{_xe(name)}</strong>"
