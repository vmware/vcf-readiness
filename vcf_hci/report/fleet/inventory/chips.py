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
from vcf_hci.collector.pci_utils import clean_oem_adapter_title
from vcf_hci.compat.firmware import is_zero_or_null_firmware
from vcf_hci.compat_engine import (
    evaluate_driver_firmware_recommendation,
    evaluate_pci_compatibility,
)
from vcf_hci.constants import NVME_FW_BASELINES, is_generic_name, is_unfriendly_nic_name
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
    ctrl_osa = bool(r.get("ctrl_osa"))

    if vmd_on and count > 0:
        return "<span class='inv-bad' title='Ineligible for vSAN ESA: Intel VMD is enabled in BIOS (must be disabled for native NVMe pass-through)'>✗ VMD Enabled</span>"
    if count >= 2:
        if sw_raid_count > 0:
            return f"<span class='inv-good' title='vSAN ESA Storage Qualified: {count} direct-attached NVMe SSDs ({total_tb} TB total) — Host Software RAID detected; bypass in BIOS (AHCI / Non-RAID) for direct ESXi pass-through'>✓ Storage Qualified (SW RAID)</span>"
        return f"<span class='inv-good' title='vSAN ESA Storage Qualified: {count} direct-attached NVMe SSDs ({total_tb} TB total)'>✓ Storage Qualified</span>"
    if raid_blocked > 0:
        return "<span class='inv-bad' title='Ineligible for vSAN ESA: NVMe drives are attached to a HW RAID or Tri-Mode controller (direct PCIe pass-through required)'>✗ Behind RAID</span>"
    if count == 1:
        return "<span class='inv-muted' title='Insufficient storage: 1 direct NVMe SSD detected (minimum 2 required for vSAN ESA)'>— Insufficient (1/2)</span>"
    osa_nvme_c = int(r.get("osa_nvme_count") or 0)
    if osa_nvme_c > 0:
        return f"<span class='inv-warn' title='vSAN OSA Storage: {osa_nvme_c} direct NVMe drive(s) detected, but certified only for vSAN OSA on Broadcom BCG (not vSAN ESA)'>▲ OSA ({osa_nvme_c} NVMe)</span>"
    if ctrl_osa:
        return "<span class='inv-warn' title='vSAN OSA Storage: SAS/SATA drives detected without direct NVMe SSDs'>▲ OSA (SAS/SATA)</span>"
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
        if status == "warn":
            return f"<span class='{cls_name}' title='{_xe(tooltip)}'>▲ {_xe(tier_label)}</span>"
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
        "Ready": "vSAN ESA Ready: Meets storage (>=2 direct NVMe SSDs) and networking (>=10 GbE for Small, >=25 GbE for Medium/Large) requirements.",
        "StorageMet": "ESA Storage Met: Meets vSAN ESA storage criteria (>=2 Direct NVMe SSDs), but host NIC is <10 GbE. Requires a 10/25 GbE+ NIC upgrade for full ESA readiness.",
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

    if is_zero_or_null_firmware(fw):
        return f"<code class='inv-code' title='Firmware unread via BMC out-of-band query'>{_xe(fw)} (Unreported)</code>"

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
    if json_hcl is None:
        try:
            from vcf_hci.hcl.loader import load_vsan_hcl_json
            json_hcl = load_vsan_hcl_json()
        except Exception:
            json_hcl = None

    name = str(n.get("name") or n.get("model") or n.get("id") or "").strip()
    if not name:
        return f"<span class='inv-muted'>{_DASH}</span>"

    pn_val = str(n.get("part_number") or "").strip()
    slot_lbl = n.get("slot") or ""
    if not slot_lbl:
        m_s = re.search(r"\b(Slot\s+[0-9a-zA-Z_]+)\b", name, re.I)
        if m_s:
            slot_lbl = m_s.group(1).title()
        else:
            m_ids = re.search(r"\bSlot\.([0-9a-zA-Z_]+)\b", str(n.get("id") or ""), re.I)
            if m_ids:
                slot_lbl = f"Slot {m_ids.group(1)}"
    if is_unfriendly_nic_name(name, pn_val):
        cand_model = str(n.get("model") or "").strip()
        if cand_model and not is_unfriendly_nic_name(cand_model, pn_val):
            name = cand_model
        elif pn_val and not is_generic_name(pn_val):
            name = pn_val
    if slot_lbl and slot_lbl.lower() not in name.lower() and f"({slot_lbl})" not in name:
        name = f"{name} ({slot_lbl})"

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
        matched_entry = pci_eval.get("matched_entry")
        if isinstance(matched_entry, list) and matched_entry:
            matched_entry = matched_entry[0]
        matched_m = matched_entry.get("model") if isinstance(matched_entry, dict) else ""
        if is_unfriendly_nic_name(name, pn_val) and matched_m:
            name = str(matched_m).strip()
            if slot_lbl and slot_lbl.lower() not in name.lower() and f"({slot_lbl})" not in name:
                name = f"{name} ({slot_lbl})"

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
            if is_unfriendly_nic_name(name, pn_val) and _unique.get("model"):
                name = str(_unique["model"]).strip()
                if slot_lbl and slot_lbl.lower() not in name.lower() and f"({slot_lbl})" not in name:
                    name = f"{name} ({slot_lbl})"
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

    if not bcg_nic and n.get("io_vcglink"):
        bcg_nic = n["io_vcglink"]
    elif not bcg_nic and n.get("io_product_id"):
        bcg_nic = BCGLinkGenerator.device_detail(str(n["io_product_id"]).strip(), "io")

    if not bcg_vsan_nic and n.get("vcglink"):
        bcg_vsan_nic = n["vcglink"]
    elif not bcg_vsan_nic and n.get("product_id"):
        bcg_vsan_nic = BCGLinkGenerator.device_detail(str(n["product_id"]).strip(), "rdmanic")

    name = clean_oem_adapter_title(name, host_mfg=str(n.get("manufacturer") or ""), adapter_mfg=str(n.get("manufacturer") or ""), part_number=pn_val)
    bcg_url = bcg_nic or bcg_vsan_nic or BCGLinkGenerator.io_device(name)
    if bcg_url:
        return f"<a href='{_xe(bcg_url)}' target='_blank' class='btn-link' style='color:var(--primary,#3b82f6);text-decoration:none;font-weight:600' title='Open in Broadcom Compatibility Guide'>{_xe(name)} ↗</a>"
    return f"<strong>{_xe(name)}</strong>"
