"""
VCF Readiness Tool — PCIe slot inventory & GPU / accelerator report section builders (Layer D).
"""
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.constants import _lookup_gpu_specs
from vcf_hci.hcl import lookup_unique_hcl_device
from vcf_hci.obfuscation import _pii_span
from vcf_hci.report.helpers import _h


def render_pcie_slot_section(pcie_slots: List[Dict[str, Any]], page_salt: str, json_hcl: Optional[Dict[str, Any]] = None) -> str:
    """Render PCIe slot inventory accordion."""
    if not pcie_slots:
        return ""

    _total_slots = len(pcie_slots)
    _populated_slots = sum(1 for s in pcie_slots if s.get("populated"))
    _summary_cls = "success" if _populated_slots else "info"

    _slot_rows = ""
    for _s in pcie_slots:
        _pop = _s.get("populated", False)
        _lanes = _s.get("lanes")
        _lanes_str = f"x{_lanes}" if _lanes else "<span style='color:var(--text-muted)'>—</span>"
        _gen = _h(_s.get("pcie_type") or "") or "<span style='color:var(--text-muted)'>—</span>"
        _stype = _h(_s.get("slot_type") or "") or "<span style='color:var(--text-muted)'>—</span>"
        _hp = "Yes" if _s.get("hot_pluggable") else "No"
        _state = _h(_s.get("state", "Unknown"))

        if _pop:
            _dev_name = _s.get("device_name") or "Unknown Device"
            _dev_pn = _s.get("device_part_number", "")
            _dev_mfr = _s.get("device_manufacturer") or "—"
            _dev_health = str(_s.get("device_health") or "").strip()
            _health_badge = (
                "<span class='badge success'>OK</span>" if _dev_health.upper() == "OK"
                else f"<span class='badge warning'>{_h(_dev_health)}</span>" if _dev_health.upper() in ("WARNING", "DEGRADED")
                else f"<span class='badge danger'>{_h(_dev_health)}</span>" if _dev_health.upper() in ("CRITICAL", "FAILED")
                else f"<span style='color:var(--text-muted)'>{_h(_dev_health) or 'N/A'}</span>"
            )
            _svid = _s.get("vendor_id", "")
            _sdid = _s.get("device_id", "")
            _ssvid = _s.get("subsystem_vendor_id", "")
            _sssid = _s.get("subsystem_id", "")
            _pci_quad = _s.get("pci_quad") or (f"{_svid}:{_sdid}:{_ssvid}:{_sssid}" if (_svid and _sdid and _ssvid and _sssid) else f"{_svid}:{_sdid}" if (_svid and _sdid) else "")

            _dev_name_up = str(_dev_name or "").upper()
            _is_nvme_slot = any(kw in _dev_name_up for kw in ["NVME", "EXPRESS", "SSD", "EDSFF"])
            _is_storage_slot = any(kw in _dev_name_up for kw in ["BOSS", "PERC", "RAID", "SAS", "SATA", "SCSI", "STORAGE", "MEGARAID", "SMART ARRAY", "ARRAY"])
            _is_net_slot = (not _is_storage_slot) and any(kw in _dev_name_up for kw in ["NIC", "NETWORK", "ETHERNET", "CONNECTX", "NETXTREME", "OCP", "SFP", "QSFP", "10GB", "25GB", "40GB", "100GB", "200GB", "400GB", "GBE", "10GE", "25GE"])

            _unique_item = lookup_unique_hcl_device(
                vid=_svid, did=_sdid, svid=_ssvid, ssid=_sssid, json_hcl=json_hcl, model_name=_dev_name
            )
            _pid = _unique_item.get("product_id", "") if _unique_item else ""
            _hcl_prog = _unique_item.get("hcl_program", "") if _unique_item else ""
            if _hcl_prog in ("nic", "rdmanic"):
                _is_net_slot = True
            elif _hcl_prog in ("vsanio", "controller"):
                _is_storage_slot = True
                _is_net_slot = False

            if _is_net_slot:
                if _svid and _sdid:
                    _bcg_link = BCGLinkGenerator.pci_exact(_svid, _sdid, _ssvid, _sssid, program="io", release_filter=True, device_type="Network")
                elif _unique_item and _unique_item.get("vcglink"):
                    _bcg_link = _unique_item["vcglink"]
                elif _pid:
                    _bcg_link = BCGLinkGenerator.device_detail(_pid, "rdmanic")
                else:
                    _bcg_link = BCGLinkGenerator.io_device_fw(_dev_name, "")
            elif _is_nvme_slot:
                _slot_prog = "ssd"
                if _pid:
                    _bcg_link = BCGLinkGenerator.device_detail(_pid, _slot_prog)
                elif _svid and _sdid:
                    _bcg_link = BCGLinkGenerator.pci_exact(_svid, _sdid, _ssvid, _sssid, program=_slot_prog)
                else:
                    _bcg_link = BCGLinkGenerator.io_device_fw(_dev_name, "")
            else:
                _slot_prog = _hcl_prog if _hcl_prog else "io"
                if _svid and _sdid:
                    _bcg_link = BCGLinkGenerator.pci_exact(_svid, _sdid, _ssvid, _sssid, program="io", release_filter=True)
                elif _pid:
                    _bcg_link = BCGLinkGenerator.device_detail(_pid, _slot_prog)
                else:
                    _bcg_link = BCGLinkGenerator.io_device_fw(_dev_name, "")

            _pci_cell = f"<code style='font-size:.76rem;background:var(--pci-bg);color:var(--pci-color);padding:1px 4px;border-radius:3px;'>{_h(_pci_quad)}</code>" if _pci_quad else "<span style='color:var(--text-muted)'>—</span>"

            _dev_cell = (
                f"<strong>{_h(_dev_name)}</strong>"
                + ("<br><small style='color:var(--text-muted)'>PN: " + _h(_dev_pn) + "</small>" if _dev_pn else "")
                + f"<br><a href='{_bcg_link}' target='_blank' class='btn-link' style='font-size:.8rem'>BCG Exact ↗</a>"
            )
            fn_count = _s.get("function_count") or len(_s.get("functions", []))
            if fn_count > 1:
                _dev_cell += f"<br><span class='badge info' style='font-size:.72rem' title='Multi-Function PCIe Adapter'>⚡ {fn_count} Functions</span>"
            cur_s_gen = _s.get("current_pcie_type")
            cur_s_width = _s.get("current_pcie_width")
            if cur_s_gen or cur_s_width:
                link_str = f"{cur_s_gen or ''} x{cur_s_width}" if cur_s_width else f"{cur_s_gen}"
                _dev_cell += f"<br><small style='color:var(--text-muted);font-size:.74rem;'>Negotiated: <code>{_h(link_str.strip())}</code></small>"
            if _s.get("downgrade_badge"):
                _dev_cell += f"<br>{_s['downgrade_badge']}"
            _pop_badge = "<span class='badge success'>Populated</span>"
            _mfr_cell = _h(_dev_mfr)
        else:
            _pop_badge = "<span style='color:var(--text-muted)'>&#9675; Empty</span>"
            _dev_cell = "<span style='color:var(--text-muted)'>—</span>"
            _pci_cell = "<span style='color:var(--text-muted)'>—</span>"
            _mfr_cell = "<span style='color:var(--text-muted)'>—</span>"
            _health_badge = "<span style='color:var(--text-muted)'>—</span>"

        _slot_rows += (
            f"<tr>"
            f"<td><strong>{_h(_s.get('slot_label', 'Slot'))}</strong></td>"
            f"<td>{_pop_badge}</td>"
            f"<td><code>{_lanes_str}</code></td>"
            f"<td>{_gen}</td>"
            f"<td>{_stype}</td>"
            f"<td>{_hp}</td>"
            f"<td>{_state}</td>"
            f"<td>{_dev_cell}</td>"
            f"<td>{_pci_cell}</td>"
            f"<td>{_mfr_cell}</td>"
            f"<td>{_health_badge}</td>"
            f"</tr>"
        )

    return (
        f"<h2>PCIe Slot Inventory</h2>"
        f"<details class='accordion'>"
        f"<summary>"
        f"<div>&#128268; PCIe Slots &nbsp;"
        f"<span class='badge {_summary_cls}'>{_populated_slots} of {_total_slots} slots populated</span>"
        f"</div>"
        f"<span style='font-size:.85rem;color:var(--primary)'>Expand Slot Details &#9662;</span>"
        f"</summary>"
        f"<div class='accordion-body'>"
        f"<table><thead><tr>"
        f"<th>Slot</th><th>Populated</th><th>Lanes</th><th>PCIe Gen</th>"
        f"<th>Slot Type</th><th>Hot Plug</th><th>State</th>"
        f"<th>Device &amp; Part #</th><th>PCI ID (Quad)</th><th>Manufacturer</th><th>Health</th>"
        f"</tr></thead><tbody>{_slot_rows}</tbody></table>"
        f"</div></details>"
    )


def render_gpu_cards_and_section(
    gpus: List[Dict[str, Any]],
    page_salt: str,
    json_hcl: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """Render GPU accelerator cards and full section, return (gpu_cards_html, gpu_section_html)."""
    if not gpus:
        return "", ""

    _gpu_cards_html = ""
    for _gpu in gpus:
        _gname  = _gpu.get("name") or _gpu.get("model") or "GPU Accelerator"
        _gmfr   = _gpu.get("manufacturer") or "Unknown"
        _gpn    = _gpu.get("part_number", "") or ""
        _gsn    = _gpu.get("serial_number", "") or ""
        _gslot  = _gpu.get("slot", "") or ""
        _gtype  = _gpu.get("pcie_type", "") or ""
        _glanes = _gpu.get("lanes")
        _gbadge = _gpu.get("downgrade_badge", "")
        _gpu_fw_na = "<span style='color:var(--text-muted)'>N/A \u2014 not exposed via Redfish</span>"
        _gfw    = _gpu.get("firmware", "") or ""
        _ghealth= _gpu.get("health", "") or ""
        _gmem_gib = _gpu.get("memory_gib", 0) or 0

        _gvid = _gpu.get("vendor_id", "")
        _gdid = _gpu.get("device_id", "")
        _gsvid = _gpu.get("subsystem_vendor_id", "")
        _gssid = _gpu.get("subsystem_id", "")
        _gpci_quad = _gpu.get("pci_quad") or (f"{_gvid}:{_gdid}:{_gsvid}:{_gssid}" if (_gvid and _gdid and _gsvid and _gssid) else f"{_gvid}:{_gdid}" if (_gvid and _gdid) else "")

        _unique_item = lookup_unique_hcl_device(
            vid=_gvid, did=_gdid, svid=_gsvid, ssid=_gssid, json_hcl=json_hcl, model_name=_gname
        ) if json_hcl else None
        _gpid = _unique_item.get("product_id", "") if _unique_item else ""
        _ghcl_prog = _unique_item.get("hcl_program", "") if _unique_item else "sptg"

        if _gpid:
            _bcg_gpu = BCGLinkGenerator.device_detail(_gpid, _ghcl_prog)
        elif _gvid and _gdid:
            _bcg_gpu = BCGLinkGenerator.pci_exact(_gvid, _gdid, _gsvid, _gssid, program="sptg")
        else:
            _bcg_gpu = BCGLinkGenerator.gpu(_gname)
        _specs   = _lookup_gpu_specs(_gname)

        _ghealth_upper = str(_ghealth or "").upper()
        if _ghealth_upper == "OK":
            _health_badge = "<span class='badge success'>&#9679; OK</span>"
        elif _ghealth_upper in ("WARNING", "DEGRADED"):
            _health_badge = f"<span class='badge warning'>&#9888; {_h(_ghealth)}</span>"
        elif _ghealth_upper in ("CRITICAL", "FAILED"):
            _health_badge = f"<span class='badge danger'>&#9888; {_h(_ghealth)}</span>"
        elif _ghealth:
            _health_badge = f"<span style='color:var(--text-muted)'>{_h(_ghealth)}</span>"
        else:
            _health_badge = "<span style='color:var(--text-muted)'>N/A</span>"

        if _gmem_gib:
            _vram_str = f"{_gmem_gib} GiB (live)"
        elif _specs and _specs.get("vram"):
            _vram_str = _specs["vram"]
        else:
            _vram_str = "<span style='color:var(--text-muted)'>N/A</span>"

        _slot_parts = []
        if _gslot:
            _slot_parts.append(_h(_gslot))
        if _glanes or _gtype:
            _l_str = f"x{_glanes}" if _glanes else ""
            _t_str = f"{_gtype}" if _gtype else ""
            _bus_info = f"({_l_str} {_t_str})".replace("  ", " ").strip()
            if _bus_info and _bus_info != "()":
                _slot_parts.append(_bus_info)
        _slot_str = " ".join(_slot_parts) if _slot_parts else ""

        _arch_str = _specs["arch"] if _specs else ""
        _extra_badges = ""
        if _specs:
            if _specs.get("mig"):
                _extra_badges += "<span class='badge info' style='font-size:.75rem'>MIG</span> "
            if _specs.get("vgpu"):
                _extra_badges += "<span class='badge success' style='font-size:.75rem'>vGPU / SR-IOV</span> "
            else:
                _extra_badges += "<span class='badge warning' style='font-size:.75rem'>No vGPU</span> "

        _gtemp = _gpu.get("temperature_c")
        _gmax_temp = _gpu.get("max_operating_temp_c")
        _gslowdown_temp = _gpu.get("slowdown_temp_c")
        _gpower_brake = _gpu.get("power_brake_status")
        _thermal_row = ""
        if _gtemp is not None:
            _t_str = f"<b>{_gtemp} °C</b>"
            _t_details = []
            if _gmax_temp is not None:
                _t_details.append(f"Max: {_gmax_temp} °C")
            if _gslowdown_temp is not None:
                _t_details.append(f"Slowdown: {_gslowdown_temp} °C")
            if _t_details:
                _t_str += f" <small style='color:var(--text-muted)'>({', '.join(_t_details)})</small>"
            _thermal_row = f"<tr><th>Thermal Telemetry</th><td>{_t_str}</td></tr>"

        _pb_row = ""
        if _gpower_brake:
            _pb_upper = str(_gpower_brake).upper()
            _pb_badge = (
                "<span class='badge success'>Released (Normal)</span>" if "RELEASE" in _pb_upper or "NORMAL" in _pb_upper
                else f"<span class='badge danger'>{_h(str(_gpower_brake))}</span>"
            )
            _pb_row = f"<tr><th>Power Brake</th><td>{_pb_badge}</td></tr>"

        _spec_rows = (
            f"<tr><th style='width:38%'>Manufacturer</th><td>{_h(_gmfr)}</td></tr>"
            + (f"<tr><th>Part Number</th><td>{_pii_span('PN', _gpn, page_salt)}</td></tr>" if _gpn else "")
            + (f"<tr><th>Serial Number</th><td>{_pii_span('SN', _gsn, page_salt)}</td></tr>" if _gsn else "")
            + (f"<tr><th>Slot / Bus</th><td>{_slot_str} {_gbadge if _gbadge else ''}</td></tr>" if _slot_str else "")
            + (f"<tr><th>PCI ID</th><td><code style='font-size:.78rem;background:var(--pci-bg);color:var(--pci-color);padding:1px 4px;border-radius:3px;'>{_h(_gpci_quad)}</code></td></tr>" if _gpci_quad else "")
            + f"<tr><th>VRAM</th><td>{_vram_str}</td></tr>"
            + (f"<tr><th>Architecture</th><td>{_h(_arch_str)}</td></tr>" if _arch_str else "")
            + f"<tr><th>Firmware</th><td>{_h(_gfw) if _gfw else _gpu_fw_na}</td></tr>"
            + f"<tr><th>Health</th><td>{_health_badge}</td></tr>"
            + _thermal_row
            + _pb_row
        )

        _vgpu_html = ""
        if _specs:
            _vgpu_html = (
                f"<div style='margin-top:.75rem;padding:.6rem .8rem;background:var(--code-bg);"
                f"border:1px solid var(--border);border-radius:6px'>"
                f"<div style='font-weight:700;font-size:.85rem;margin-bottom:.35rem'>"
                f"vGPU / Virtualisation {_extra_badges}</div>"
                f"<p style='margin:0;font-size:.83rem;color:var(--text)'>{_h(_specs['vgpu_note'])}</p>"
                f"</div>"
            )

        _pais_html = ""
        if _specs and _specs.get("pais_note"):
            _pais_html = (
                f"<div style='margin-top:.6rem;padding:.6rem .8rem;background:var(--callout-blue-bg,#eff6ff);"
                f"border:1px solid var(--callout-blue-border,#bfdbfe);border-radius:6px'>"
                f"<div style='font-weight:700;font-size:.85rem;margin-bottom:.25rem;color:var(--callout-blue-title,#1d4ed8)'>"
                f"&#129504; PAIS / AI Workload</div>"
                f"<p style='margin:0;font-size:.83rem;color:var(--callout-blue-body,var(--text))'>{_h(_specs['pais_note'])}</p>"
                f"</div>"
            )

        _vdi_html = ""
        if _specs and _specs.get("vdi_note"):
            _vdi_html = (
                f"<div style='margin-top:.6rem;padding:.6rem .8rem;background:var(--callout-ok-bg,#f0fdf4);"
                f"border:1px solid var(--callout-ok-border,#bbf7d0);border-radius:6px'>"
                f"<div style='font-weight:700;font-size:.85rem;margin-bottom:.25rem;color:var(--callout-ok-h,#15803d)'>"
                f"&#128444; Horizon VDI</div>"
                f"<p style='margin:0;font-size:.83rem;color:var(--callout-ok-ul,var(--text))'>{_h(_specs['vdi_note'])}</p>"
                f"</div>"
            )

        _gpu_cards_html += (
            f"<div class='card' style='border:1px solid var(--border);border-radius:8px;padding:1rem 1.1rem;"
            f"margin-bottom:1.25rem;background:var(--card)'>"
            f"<div style='display:flex;justify-content:space-between;align-items:flex-start;"
            f"flex-wrap:wrap;gap:.5rem;margin-bottom:.75rem'>"
            f"<h3 style='margin:0;font-size:1rem;color:var(--h-color,var(--text))'>{_h(_gname)}</h3>"
            f"<a href='{_bcg_gpu}' target='_blank' class='btn-link' style='font-size:.82rem'>"
            f"BCG Search ↗</a>"
            f"</div>"
            f"<table style='font-size:.85rem;width:100%;border-collapse:collapse'>"
            f"<tbody>{_spec_rows}</tbody></table>"
            f"{_vgpu_html}{_pais_html}{_vdi_html}"
            f"</div>"
        )

    gpu_section = (
        f"<h2>GPU &amp; Hardware Accelerators "
        f"<span style='font-weight:400;font-size:.85rem;color:var(--text-muted)'>"
        f"({len(gpus)} device{'s' if len(gpus) != 1 else ''})</span></h2>"
        + _gpu_cards_html
    )

    return _gpu_cards_html, gpu_section
