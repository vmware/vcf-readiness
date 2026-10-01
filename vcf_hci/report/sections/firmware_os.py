"""
VCF Readiness Tool — OS information, firmware inventory, alignment & warranty report section builders (Layer D).
"""
from typing import Any, Dict, List, Optional

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.compat_engine import (
    evaluate_drive_fw,
    evaluate_driver_firmware_recommendation,
    evaluate_pci_compatibility,
)
from vcf_hci.hcl import lookup_unique_hcl_device
from vcf_hci.report.helpers import _h, badge


def render_warranty_card(warranty_info: Dict[str, Any]) -> str:
    """Render Dell TechDirect warranty / support contract card."""
    if not warranty_info:
        return ""
    _w_status = warranty_info.get("status", "Unknown")
    _w_badge_cls = {"Active": "success", "Expired": "danger"}.get(_w_status, "info")
    _w_badge = badge(_w_status, _w_badge_cls)
    _w_ship = _h(warranty_info.get("ship_date", ""))
    _w_expiry = _h(warranty_info.get("expiry_date", ""))
    _w_level = _h(warranty_info.get("service_level", ""))
    _w_tag = _h(warranty_info.get("service_tag", ""))
    _ents = warranty_info.get("entitlements") or []
    _ent_rows = "".join(
        f"<tr><td style='font-size:.78rem'>{_h(e.get('service_level',''))}</td>"
        f"<td style='font-size:.78rem'>{_h(e.get('start',''))}</td>"
        f"<td style='font-size:.78rem'>{_h(e.get('end',''))}</td></tr>"
        for e in _ents[:6]
    )
    _ent_table = (
        f'<table style="width:100%;border-collapse:collapse;margin-top:.5rem">'
        f'<thead><tr>'
        f'<th style="font-size:.72rem;text-align:left;padding:.2rem .3rem;background:#f1f5f9">Service Level</th>'
        f'<th style="font-size:.72rem;text-align:left;padding:.2rem .3rem;background:#f1f5f9">Start</th>'
        f'<th style="font-size:.72rem;text-align:left;padding:.2rem .3rem;background:#f1f5f9">End</th>'
        f'</tr></thead><tbody>{_ent_rows}</tbody></table>'
    ) if _ent_rows else ""
    return (
        f'<div class="card"><h3>Dell Support Contract</h3>'
        f'<div>{_w_badge}</div>'
        f'<p style="font-size:.82rem;color:var(--text-muted);margin-top:.5rem;line-height:1.6">'
        f'Service Tag: <b>{_w_tag}</b><br>'
        f'Ship Date: <b>{_w_ship}</b><br>'
        f'Expiry: <b>{_w_expiry}</b><br>'
        f'Level: <b>{_w_level}</b></p>'
        f'{_ent_table}'
        f'<p style="font-size:.72rem;color:#94a3b8;margin-top:.5rem">'
        f'Source: Dell TechDirect asset-entitlements API</p>'
        f'</div>'
    )


def render_bundle_card(hcl_bundle_metadata: Optional[Dict[str, Any]]) -> str:
    """Render Dark-Site HCL Bundle metadata card."""
    if not hcl_bundle_metadata:
        return ""
    _b_age = hcl_bundle_metadata.get("dataset_age_days", 0)
    _b_badge_cls = "success" if _b_age <= 30 else "warning"
    _b_fresh_str = f"Fresh ({_b_age} days old)" if _b_age <= 30 else f"Stale ({_b_age} days old)"
    _b_badge = badge(f"🔒 Dark-Site HCL ({_b_fresh_str})", _b_badge_cls)
    return (
        f'<div class="card"><h3>🔒 Dark-Site HCL Bundle</h3>'
        f'<div>{_b_badge}</div>'
        f'<p style="font-size:.85rem;color:var(--text-muted);margin-top:.5rem">'
        f'Archive: <b>{_h(hcl_bundle_metadata.get("bundle_filename", "N/A"))}</b><br>'
        f'Indexed Drives: <b>{hcl_bundle_metadata.get("json_models_count", 0) + hcl_bundle_metadata.get("csv_models_count", 0)} models</b></p></div>'
    )


def render_os_card(host_os: Dict[str, Any]) -> str:
    """Render Host Operating System card."""
    _os_name    = _h(host_os.get("os_name", ""))
    _os_ver     = _h(host_os.get("os_version", ""))
    _os_build   = _h(host_os.get("os_build", ""))
    _os_upd_lbl = _h(host_os.get("esxi_update_label", ""))
    _os_eol_b   = host_os.get("eol_badge", "")
    _os_src     = _h(host_os.get("source", ""))
    _os_kb_url  = host_os.get("kb_url", "")
    _os_agent_n = _h(host_os.get("agent_note", ""))
    _os_vcf_n   = _h(host_os.get("vcf_upgrade_note", ""))
    _os_badge   = host_os.get("badge", "")

    if not _os_name:
        return ""

    _os_version_line = ""
    if _os_ver:
        _os_version_line += f"<br><small style='color:var(--text-muted)'>Version: <strong>{_os_ver}</strong>"
        if _os_build:
            _os_version_line += f" &nbsp;·&nbsp; Build: <strong>{_os_build}</strong>"
        _os_version_line += "</small>"

    _os_label_line = ""
    if _os_upd_lbl:
        _os_label_line = (
            f"<br><small style='color:var(--text-muted)'>"
            f"<strong>{_os_upd_lbl}</strong> &nbsp; {_os_eol_b}"
            f"</small>"
        )
    elif _os_eol_b:
        _os_label_line = f"<br><small style='color:var(--text-muted)'>{_os_eol_b}</small>"

    _os_source_line = ""
    if _os_src:
        _os_source_line = (
            f"<br><small style='color:var(--text-muted)'>Source: {_os_src}"
            + (f" &nbsp;&nbsp;<a href='{_os_kb_url}' target='_blank' class='btn-link' style='font-size:.78rem'>🔗 KB ↗</a>" if _os_kb_url else "")
            + "</small>"
        )

    _os_uptime = _h(str(host_os.get("uptime_human") or ""))
    _os_uptime_line = f"<br><small style='color:var(--text-muted)'>⏱️ Continuous Power-on: <strong>{_os_uptime}</strong></small>" if _os_uptime else ""

    _os_vcf_line = ""
    if _os_vcf_n:
        _os_vcf_line = (
            f"<p style='margin:.5rem 0 0;font-size:.82rem;"
            f"background:var(--os-vcf-note-bg,#fef9c3);border-radius:4px;padding:.35rem .55rem;"
            f"color:var(--os-vcf-note-color,#78350f);line-height:1.4'>"
            f"⬆️ {_os_vcf_n}</p>"
        )

    return (
        f"<div class='card'>"
        f"<h3>💻 Host Operating System</h3>"
        f"<div>{_os_badge}</div>"
        f"<p style='font-size:.88rem;margin-top:.5rem'>"
        f"<strong>{_os_name}</strong>"
        f"{_os_version_line}"
        f"{_os_label_line}"
        f"{_os_uptime_line}"
        f"{_os_source_line}"
        f"</p>"
        f"{_os_vcf_line}"
        f"<p style='font-size:.78rem;color:var(--text-muted);margin-top:.4rem'>{_os_agent_n}</p>"
        f"</div>"
    )


def render_driver_fw_alignment_card(real_nics: List[Dict[str, Any]], storage_controllers: List[Dict[str, Any]], json_hcl: Optional[Dict[str, Any]] = None) -> str:
    """Render ESXi 9.1 Driver & Firmware Alignment card."""
    fw_matches = 0
    fw_updates = 0
    fw_outdated = 0
    fw_unverified = 0
    rec_drivers = []

    for n in (real_nics or []):
        vid = n.get("vendor_id", "")
        did = n.get("device_id", "")
        svid = n.get("subsystem_vendor_id", "")
        ssid = n.get("subsystem_id", "")
        fw = n.get("firmware_version", "")
        eval_res = evaluate_pci_compatibility(vid, did, svid, ssid, n.get("name", ""), fw, hcl_data=json_hcl)
        st = eval_res.get("fw_status", "unverified")
        if st == "current":
            fw_matches += 1
        elif st == "update_available":
            fw_updates += 1
        elif st == "outdated":
            fw_outdated += 1
        else:
            fw_unverified += 1
        drv = eval_res.get("recommended_driver")
        if drv and drv not in rec_drivers:
            rec_drivers.append(drv)

    for ctrl in (storage_controllers or []):
        cvid = ctrl.get("vendor_id", "")
        cdid = ctrl.get("device_id", "")
        csvid = ctrl.get("subsystem_vendor_id", "")
        cssid = ctrl.get("subsystem_id", "")
        fw = ctrl.get("ctrl_firmware", "")
        cname = ctrl.get("name", "") or ctrl.get("ctrl_model", "")
        eval_res = evaluate_pci_compatibility(cvid, cdid, csvid, cssid, cname, fw, hcl_data=json_hcl)
        st = eval_res.get("fw_status", "unverified")
        if st == "current":
            fw_matches += 1
        elif st == "update_available":
            fw_updates += 1
        elif st == "outdated":
            fw_outdated += 1
        else:
            fw_unverified += 1
        drv = eval_res.get("recommended_driver")
        if drv and drv not in rec_drivers:
            rec_drivers.append(drv)

    all_drives_flat = [d for ctrl in (storage_controllers or []) for d in ctrl.get("drives", []) if d.get("populated", True)]
    nvme_list = [
        d for d in all_drives_flat
        if "NVME" in str(d.get("protocol", "")).upper() or "PCIE" in str(d.get("protocol", "")).upper() or d.get("is_edsff") or d.get("is_nvme")
    ]
    for d in nvme_list:
        m = d.get("model", "")
        fw = d.get("firmware", "")
        vid = d.get("vendor_id", "")
        did = d.get("device_id", "")
        svid = d.get("subsystem_vendor_id", "")
        ssid = d.get("subsystem_id", "")
        eval_res = evaluate_driver_firmware_recommendation(vid, did, svid, ssid, m, fw, hcl_data=json_hcl)
        st = eval_res.get("fw_status", "unverified")
        if st == "current":
            fw_matches += 1
        elif st == "update_available":
            fw_updates += 1
        elif st == "outdated":
            fw_outdated += 1
        else:
            fw_unverified += 1

    total_checked = fw_matches + fw_updates + fw_outdated + fw_unverified
    if fw_outdated > 0:
        align_badge = "<span class='badge danger'>🔴 FW Update Required for ESXi 9.1</span>"
    elif fw_updates > 0:
        align_badge = "<span class='badge warning'>🟡 Firmware Updates Available for 9.1</span>"
    elif fw_matches > 0:
        align_badge = "<span class='badge success'>🟢 Driver &amp; FW Aligned for ESXi 9.1</span>"
    else:
        align_badge = "<span class='badge info'>ℹ️ Driver/FW Baseline Unverified</span>"

    drv_str = (", ".join(f"<code>{_h(d)}</code>" for d in rec_drivers[:3]) + (f" (+{len(rec_drivers)-3} more)" if len(rec_drivers) > 3 else "")) if rec_drivers else "Inbox Drivers"

    return (
        f"<div class='card'>"
        f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
        f"<h3 style='margin:0'>vSAN 9.1 Driver &amp; FW Alignment</h3>"
        f"<a href='#tab-firmware' data-jump-tab='tab-firmware' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to Firmware Inventory'>Details &rarr;</a>"
        f"</div>"
        f"<div style='margin-bottom:.35rem'>{align_badge}</div>"
        f"<p style='font-size:.85rem;color:var(--text-muted);margin:0 0 .25rem'>"
        f"Components checked: <b>{total_checked}</b> &nbsp;|&nbsp; Matches: <b style='color:var(--success)'>{fw_matches}</b> &nbsp;|&nbsp; "
        f"Updates: <b style='color:var(--warning-text, #ca8a04)'>{fw_updates}</b> &nbsp;|&nbsp; Outdated: <b style='color:var(--danger)'>{fw_outdated}</b>"
        f"</p>"
        f"<div style='border-top:1px solid var(--border);padding-top:.4rem;margin-top:.4rem'>"
        f"<span style='font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;color:var(--text-muted);font-weight:600'>Recommended ESXi 9.1 Drivers</span><br>"
        f"<div style='margin-top:.2rem;font-size:.8rem'>{drv_str}</div>"
        f"</div>"
        f"<div style='margin-top:.5rem;border-top:1px solid var(--border);padding-top:.4rem'>"
        f"<a href='#tab-firmware' data-jump-tab='tab-firmware' class='btn-link tab-jump-link' style='font-size:.78rem'>"
        f"Full details in Firmware tab &#8599;</a></div>"
        f"</div>"
    )


def render_firmware_inventory_section(data: Dict[str, Any], sys_info: Dict[str, Any], json_hcl: Optional[Dict[str, Any]] = None) -> str:
    """Render Complete Hardware Firmware Inventory section."""
    _collected_drives = []
    for _ctrl in data.get("storage_subsystem", []):
        for _drv in _ctrl.get("drives", []):
            if _drv.get("populated", True):
                _collected_drives.append(_drv)

    _collected_ctrls = data.get("storage_subsystem", [])
    _collected_nics = data.get("network_adapters", [])
    _collected_gpus = data.get("gpu_accelerators", [])
    _collected_fcs = data.get("fc_hbas", [])

    fw_inv = data.get("firmware_inventory", [])
    _fw_inv_rows = ""
    if not fw_inv:
        if data.get("partial_scan") or "firmware_inventory" in data.get("partial_sections", []):
            _empty_msg = '<p style="color:var(--warning,#ca8a04)">⚠️ Firmware inventory collection timed out or was incomplete due to BMC responsiveness. Perform a BMC reset (<code>racadm racreset</code> or <code>iloreset</code>) and re-scan.</p>'
        else:
            _empty_msg = '<p style="color:var(--text-muted)">No firmware inventory reported or scan run in Quick mode.</p>'
        return (
            f'<h2>Complete Hardware Firmware Inventory</h2>'
            f'{_empty_msg}'
        )

    for f in fw_inv:
        f_name = str(f.get("name") or "Unknown").strip()
        f_desc = str(f.get("description") or "").strip()
        f_comp_id = str(f.get("component_id") or "").strip()
        f_ver = str(f.get("version") or "N/A").strip()
        f_id = str(f.get("id") or "").strip()
        f_ctx = str(f.get("device_context") or "").strip()

        upd_val = f.get("updateable")
        if upd_val is True:
            upd_str = "Yes (Flashable)"
        elif upd_val is False:
            upd_str = "No (Fixed)"
        else:
            upd_str = "N/A"

        desc_parts = []
        if f_desc:
            desc_parts.append(f_desc)
        if f_ctx and f_id:
            desc_parts.append(f"{f_ctx} (Target {f_id})")
        elif f_ctx:
            desc_parts.append(f_ctx)
        elif f_id and sum(1 for item in fw_inv if item.get("name") == f_name) > 1:
            desc_parts.append(f"Target {f_id}")
        sub_desc = " • ".join(desc_parts)

        comb_text = f"{f_name} {f_desc} {f_comp_id}".upper()

        matched_drv = None
        for drv in _collected_drives:
            d_model = str(drv.get("model") or "").strip().upper()
            d_fw = str(drv.get("firmware") or "").strip().upper()
            d_slot = drv.get("bay_slot")
            if d_model and d_model in comb_text:
                matched_drv = drv
                break
            if d_fw and d_fw == f_ver.upper() and d_fw != "N/A" and any(kw in comb_text for kw in ["DRIVE", "DISK", "SSD", "NVME", "SOLID STATE"]):
                matched_drv = drv
                break
            if d_slot is not None and f"BAY.{d_slot}" in comb_text.replace(" ", ""):
                matched_drv = drv
                break

        is_drive_kw = any(
            kw in comb_text for kw in ["SSD", "NVME", "SOLID STATE", "DRIVE", "DISK", "FLASH"]
        ) and not any(
            kw in comb_text for kw in ["CONTROLLER", "BACKPLANE", "EXPANDER", "CPLD", "BIOS", "BMC", "IDRAC", "ILO", "CIMC"]
        )
        is_drive = bool(matched_drv) or is_drive_kw

        vid, did, svid, ssid = "", "", "", ""
        drv_model = ""

        if matched_drv:
            vid = str(matched_drv.get("vendor_id", "")).strip()
            did = str(matched_drv.get("device_id", "")).strip()
            svid = str(matched_drv.get("subsystem_vendor_id", "")).strip()
            ssid = str(matched_drv.get("subsystem_id", "")).strip()
            drv_model = str(matched_drv.get("model", "")).strip()
        elif not is_drive:
            for nic in _collected_nics:
                n_name = str(nic.get("name", "")).strip().upper()
                if n_name and (n_name in comb_text or f_name.upper() in n_name):
                    vid = str(nic.get("vendor_id", "")).strip()
                    did = str(nic.get("device_id", "")).strip()
                    svid = str(nic.get("subsystem_vendor_id", "")).strip()
                    ssid = str(nic.get("subsystem_id", "")).strip()
                    break
            if not (vid and did):
                for ctrl in _collected_ctrls:
                    c_name = str(ctrl.get("name", "")).strip().upper()
                    c_model = str(ctrl.get("ctrl_model", "")).strip().upper()
                    c_id = str(ctrl.get("id", "")).strip().upper()
                    if (c_name and c_name in comb_text) or (c_model and c_model in comb_text) or (c_id and c_id in comb_text):
                        vid = str(ctrl.get("vendor_id", "")).strip()
                        did = str(ctrl.get("device_id", "")).strip()
                        svid = str(ctrl.get("subsystem_vendor_id", "")).strip()
                        ssid = str(ctrl.get("subsystem_id", "")).strip()
                        break
            if not (vid and did):
                for gpu in _collected_gpus:
                    g_name = str(gpu.get("model") or gpu.get("name", "")).strip().upper()
                    if g_name and g_name in comb_text:
                        vid = str(gpu.get("vendor_id", "")).strip()
                        did = str(gpu.get("device_id", "")).strip()
                        svid = str(gpu.get("subsystem_vendor_id", "")).strip()
                        ssid = str(gpu.get("subsystem_id", "")).strip()
                        break
            if not (vid and did):
                for fc in _collected_fcs:
                    fc_name = str(fc.get("model") or fc.get("name", "")).strip().upper()
                    if fc_name and fc_name in comb_text:
                        vid = str(fc.get("vendor_id", "")).strip()
                        did = str(fc.get("device_id", "")).strip()
                        svid = str(fc.get("subsystem_vendor_id", "")).strip()
                        ssid = str(fc.get("subsystem_id", "")).strip()
                        break

        if is_drive and f_ver and f_ver.upper() != "N/A":
            model_for_eval = drv_model or f_name
            _fw_cell = evaluate_drive_fw(
                model_for_eval,
                f_ver,
                hcl_data=json_hcl,
                vid=vid,
                did=did,
                svid=svid,
                ssid=ssid,
            )
        else:
            _fw_cell = f"<code>{_h(f_ver)}</code>"

        if vid and did:
            drv_media = (matched_drv.get("media_type", "") if matched_drv else "") or ("HDD" if any(kw in comb_text for kw in ["HDD", "HARD", "MAGNETIC"]) else "")
            is_magnetic = any(k in str(drv_media or "").upper() for k in ("HDD", "SMR", "MAGNETIC", "HARD"))
            is_nvme_comp = any(kw in comb_text for kw in ["NVME", "EXPRESS", "EDSFF"])
            bcg_program = ("hdd" if is_magnetic else "ssd") if (is_drive or is_nvme_comp) else "io"

            _unique_item = lookup_unique_hcl_device(vid=vid, did=did, svid=svid, ssid=ssid, json_hcl=json_hcl, model_name=f_name)
            _pid = _unique_item.get("product_id", "") if _unique_item else ""
            _hcl_prog = _unique_item.get("hcl_program", "") if _unique_item else ""
            if _hcl_prog:
                bcg_program = _hcl_prog

            bcg_url = BCGLinkGenerator.prefer_device_or_search(
                _pid, bcg_program,
                BCGLinkGenerator.pci_exact,
                vid, did, svid, ssid, release_filter=True
            )
        else:
            if is_drive:
                drv_media = (matched_drv.get("media_type", "") if matched_drv else "") or ("HDD" if any(kw in comb_text for kw in ["HDD", "HARD", "MAGNETIC"]) else "")
                _unique_item = lookup_unique_hcl_device(json_hcl=json_hcl, model_name=drv_model or f_name)
                _pid = _unique_item.get("product_id", "") if _unique_item else ""
                _hcl_prog = _unique_item.get("hcl_program", "") if _unique_item else ("hdd" if "HDD" in str(drv_media or "").upper() else "ssd")
                bcg_url = BCGLinkGenerator.prefer_device_or_search(
                    _pid, _hcl_prog,
                    BCGLinkGenerator.storage_exact,
                    drv_model or f_name, part_number=f_comp_id, vid=vid, did=did, svid=svid, ssid=ssid, media_type=drv_media
                )
            elif any(kw in comb_text for kw in ["LPE", "QLE", "FIBRE", "FC HBA"]):
                _unique_item = lookup_unique_hcl_device(json_hcl=json_hcl, model_name=f_name)
                _pid = _unique_item.get("product_id", "") if _unique_item else ""
                _hcl_prog = _unique_item.get("hcl_program", "") if _unique_item else "io"
                bcg_url = BCGLinkGenerator.prefer_device_or_search(
                    _pid, _hcl_prog,
                    BCGLinkGenerator.fc_hba,
                    f_name
                )
            elif any(kw in comb_text for kw in ["NVIDIA", "TESLA", "AMDGPU", "GRID"]):
                _unique_item = lookup_unique_hcl_device(json_hcl=json_hcl, model_name=f_name)
                _pid = _unique_item.get("product_id", "") if _unique_item else ""
                _hcl_prog = _unique_item.get("hcl_program", "") if _unique_item else "sptg"
                bcg_url = BCGLinkGenerator.prefer_device_or_search(
                    _pid, _hcl_prog,
                    BCGLinkGenerator.gpu,
                    f_name
                )
            elif any(kw in comb_text for kw in ["BIOS", "SYSTEM", "IDRAC", "ILO", "CIMC"]):
                bcg_url = BCGLinkGenerator.server(sys_info.get("vendor", ""), sys_info.get("model", ""), sys_info.get("cpu_summary", {}))
            else:
                _unique_item = lookup_unique_hcl_device(json_hcl=json_hcl, model_name=f_name)
                _pid = _unique_item.get("product_id", "") if _unique_item else ""
                _hcl_prog = _unique_item.get("hcl_program", "") if _unique_item else "io"
                bcg_url = BCGLinkGenerator.prefer_device_or_search(
                    _pid, _hcl_prog,
                    BCGLinkGenerator.io_device_fw,
                    f_name, f_ver
                )

        bcg_link_html = f'<a href="{bcg_url}" target="_blank" class="btn-link" style="font-size:.78rem">🔗 BCG Search ↗</a>'

        sub_desc_html = f'<br><small style="color:var(--text-muted)">{_h(sub_desc)}</small>' if sub_desc else ''
        _fw_inv_rows += (
            f"<tr>"
            f"<td><strong>{_h(f_name)}</strong>"
            f"{sub_desc_html}</td>"
            f"<td>{_fw_cell}</td>"
            f"<td><code>{_h(f_comp_id or 'N/A')}</code></td>"
            f"<td>{_h(upd_str)}</td>"
            f"<td>{bcg_link_html}</td>"
            f"</tr>"
        )

    return (
        f'<h2>Complete Hardware Firmware Inventory</h2>'
        f'<div style="margin-top:1rem">'
        f'<table><thead><tr>'
        f'<th>Component Name</th>'
        f'<th>Firmware Version</th>'
        f'<th>Component / Software ID</th>'
        f'<th title="Indicates whether this component firmware can be flashed out-of-band via BMC / Redfish UpdateService (Yes = Flashable, No = Fixed/Read-Only). Does NOT indicate a pending software update is available.">Updateable ℹ️</th>'
        f'<th>BCG Links</th>'
        f'</tr></thead>'
        f'<tbody>{_fw_inv_rows}</tbody></table>'
        f'</div>'
    )
