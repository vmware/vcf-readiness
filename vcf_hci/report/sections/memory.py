"""
VCF Readiness Tool — memory interleaving & topology report section builders (Layer D).
"""
from typing import Any, Dict, Optional

from vcf_hci.report.helpers import _h


def render_memory_interleaving_section(
    mem_topo: Dict[str, Any],
    bios_info: Optional[Dict[str, Any]] = None,
) -> str:
    """Render physical DIMM slot visualizer & interleaving score section."""
    _mem_grid_html_parts = []
    _grid_data = mem_topo.get("visualizer_grid", {})
    for _sock_title, _chans in _grid_data.items():
        _slot_cells = []
        for _ch_letter, _info in _chans.items():
            _dpc = _info.get("dpc", 0)
            _dimms = _info.get("dimms", [])
            if _info.get("populated") and _dimms:
                _dpc_color  = "var(--ms-2dpc-color,#2563eb)" if _dpc == 2 else ("var(--ms-3dpc-color,#7c3aed)" if _dpc >= 3 else "var(--ms-1dpc-color,#16a34a)")
                _dpc_bg     = "var(--ms-2dpc-bg,#eff6ff)"    if _dpc == 2 else ("var(--ms-3dpc-bg,#f5f3ff)"    if _dpc >= 3 else "var(--ms-1dpc-bg,#f0fdf4)")
                _dpc_border = "var(--ms-2dpc-border,#93c5fd)" if _dpc == 2 else ("var(--ms-3dpc-border,#c4b5fd)" if _dpc >= 3 else "var(--ms-1dpc-border,#86efac)")
                _sub_rows = ""
                for _i, _d in enumerate(_dimms):
                    _dhealth = str(_d.get("health") or "OK").strip()
                    if _dhealth.lower() == "critical":
                        _row_bg     = "var(--ms-crit-bg,#fef2f2)"
                        _row_border = "var(--ms-crit-border,#fca5a5)"
                        _row_color  = "var(--ms-crit-color,#991b1b)"
                    elif _dhealth.lower() == "warning":
                        _row_bg     = "var(--ms-warn-bg,#fefce8)"
                        _row_border = "var(--ms-warn-border,#fde047)"
                        _row_color  = "var(--ms-warn-color,#854d0e)"
                    else:
                        _row_bg     = "var(--ms-slot1-bg,#f0fdf4)"  if _i == 0 else "var(--ms-slot2-bg,#f0f9ff)"
                        _row_border = "var(--ms-slot1-border,#86efac)" if _i == 0 else "var(--ms-slot2-border,#7dd3fc)"
                        _row_color  = "var(--ms-slot1-color,#166534)" if _i == 0 else "var(--ms-slot2-color,#075985)"
                    _health_icon = (
                        '🔴 ' if _dhealth.lower() == "critical" else
                        '⚠️ ' if _dhealth.lower() == "warning" else ""
                    )
                    _rated_line = (
                        f'<div style="font-size:.66rem;color:{_row_color};opacity:.75;font-style:italic;">'
                        f'{_h(str(_d.get("rated_speed", "")))}</div>'
                        if _d.get("rated_speed") else ""
                    )
                    _ce = _d.get("correctable_ecc")
                    _ue = _d.get("uncorrectable_ecc")
                    _ecc_line = ""
                    if (_ce and isinstance(_ce, (int, float)) and _ce > 0) or (_ue and isinstance(_ue, (int, float)) and _ue > 0):
                        _ecc_line = f'<div style="font-size:.65rem;color:var(--danger,#dc2626);font-weight:600;">⚠️ ECC: {_ce or 0} CE / {_ue or 0} UE</div>'

                    _sub_rows += (
                        f'<div style="background:{_row_bg};border:1px solid {_row_border};'
                        f'border-radius:4px;padding:.25rem .4rem;margin-top:{".2rem" if _i > 0 else "0"};">'
                        f'<div style="font-size:.75rem;font-weight:600;color:{_row_color};">'
                        f'{_health_icon}{_h(str(_d.get("slot", "")))}</div>'
                        f'<div style="font-size:.72rem;color:{_row_color};">{_h(str(_d.get("label", "")))}</div>'
                        f'<div style="font-size:.68rem;color:{_row_color};opacity:.8;">{_h(str(_d.get("speed", "")))}</div>'
                        f'{_rated_line}'
                        f'{_ecc_line}'
                        f'</div>'
                    )
                _slot_cells.append(
                    f'<div style="background:{_dpc_bg};border:1px solid {_dpc_border};border-radius:6px;padding:.4rem .5rem;">'
                    f'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.25rem;">'
                    f'<span style="font-weight:bold;font-size:.8rem;color:{_dpc_color};">Ch {_ch_letter}</span>'
                    f'<span style="font-size:.65rem;font-weight:700;color:{_dpc_color};background:var(--ms-badge-bg,white);'
                    f'border:1px solid {_dpc_border};border-radius:3px;padding:.05rem .25rem;">{_dpc}DPC</span>'
                    f'</div>'
                    f'{_sub_rows}'
                    f'</div>'
                )
            else:
                _slot_cells.append(
                    f'<div style="background:var(--ms-empty-bg,#f8fafc);border:1px dashed var(--ms-empty-border,#cbd5e1);border-radius:6px;padding:.4rem .5rem;">'
                    f'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.25rem;">'
                    f'<span style="font-weight:bold;font-size:.8rem;color:var(--ms-empty-text,#64748b);">Ch {_ch_letter}</span>'
                    f'<span style="font-size:.65rem;font-weight:700;color:var(--ms-empty-text,#94a3b8);background:var(--ms-badge-bg,white);'
                    f'border:1px solid var(--ms-empty-border,#e2e8f0);border-radius:3px;padding:.05rem .25rem;">0DPC</span>'
                    f'</div>'
                    f'<div style="background:var(--ms-empty-bg,#f1f5f9);border:1px dashed var(--ms-empty-border,#cbd5e1);border-radius:4px;padding:.25rem .4rem;text-align:center;">'
                    f'<div style="font-size:.72rem;color:var(--ms-empty-text,#94a3b8);">[ Empty ]</div>'
                    f'</div>'
                    f'</div>'
                )
        _slots_grid = "".join(_slot_cells)
        _sock_total = sum(_info.get("dpc", 0) for _info in _chans.values())
        _sock_ram_gb = sum(
            int(_d.get("capacity_gb") or 0)
            for _info in _chans.values()
            for _d in _info.get("dimms", [])
            if _d.get("populated", True)
        )
        _ram_str = f" ({_sock_ram_gb} GB)" if _sock_ram_gb > 0 else ""
        _mem_grid_html_parts.append(
            f'<div style="background:var(--ms-sock-bg,#ffffff);border:1px solid var(--border,#e2e8f0);border-radius:8px;padding:.8rem;">'
            f'<div style="display:flex;align-items:baseline;justify-content:space-between;gap:.6rem;margin-bottom:.6rem;">'
            f'<h4 style="margin:0;font-size:.9rem;color:var(--primary);">{_h(str(_sock_title))}</h4>'
            f'<span style="font-size:.75rem;color:var(--text-muted);">{_sock_total} DIMMs{_ram_str} across {len(_chans)} channels</span>'
            f'</div>'
            f'<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(120px, 1fr));gap:.5rem;">{_slots_grid}</div>'
            f'</div>'
        )
    _mem_grid_html = "".join(_mem_grid_html_parts)

    _issues_html = ""
    if mem_topo.get("issues"):
        _i_items = "".join(f"<li style='margin-bottom:.3rem;'>{iss}</li>" for iss in mem_topo["issues"])
        _issues_html = (
            f'<div style="margin-top:1rem;background:var(--callout-warn-bg,#fefce8);border:1px solid var(--callout-warn-border,#fef08a);border-left:4px solid var(--warning);padding:.8rem 1rem;border-radius:6px;">'
            f'<h4 style="margin:0 0 .4rem 0;font-size:.88rem;color:var(--callout-warn-h,#854d0e);">⚠️ Interleaving Bottlenecks & Diagnostic Findings</h4>'
            f'<ul style="margin:0;padding-left:1.2rem;font-size:.83rem;line-height:1.5;color:var(--callout-warn-ul,#713f12);">{_i_items}</ul>'
            f'</div>'
        )

    _recs_html = ""
    if mem_topo.get("recommendations"):
        _r_items = "".join(f"<li style='margin-bottom:.3rem;'>{rec}</li>" for rec in mem_topo["recommendations"])
        _recs_html = (
            f'<div style="margin-top:.8rem;background:var(--callout-ok-bg,#f0fdf4);border:1px solid var(--callout-ok-border,#bbf7d0);border-left:4px solid var(--success);padding:.8rem 1rem;border-radius:6px;">'
            f'<h4 style="margin:0 0 .4rem 0;font-size:.88rem;color:var(--callout-ok-h,#166534);">💡 SE Channel Re-seating & Optimization Guide</h4>'
            f'<ul style="margin:0;padding-left:1.2rem;font-size:.83rem;line-height:1.5;color:var(--callout-ok-ul,#15803d);">{_r_items}</ul>'
            f'</div>'
        )

    _score_color = "#16a34a" if mem_topo.get("interleaving_score_pct", 0) >= 95 else "#ca8a04" if mem_topo.get("interleaving_score_pct", 0) >= 75 else "#dc2626"

    # CXL (Compute Express Link 2.0 / 3.0) Memory Readiness Sub-Section
    _cxl_card = ""
    _mem_ras = bios_info.get("memory_ras", []) if bios_info else []
    _cxl_modes = [r for r in _mem_ras if "cxl" in r.get("feature", "").lower() or "cxl" in str(r.get("raw_key", "")).lower()]
    if _cxl_modes:
        _cxl_il = next((r.get("raw_val") for r in _cxl_modes if "interleave" in r.get("feature", "").lower()), "Heterogeneous")
        _cxl_mode = next((r.get("raw_val") for r in _cxl_modes if "mode" in r.get("feature", "").lower() and "interleave" not in r.get("feature", "").lower()), "Homogeneous")
        _cxl_card = (
            f'<div style="margin-top:1rem;background:var(--callout-blue-bg,#f0f9ff);border:1px solid var(--callout-blue-border,#bae6fd);'
            f'border-left:4px solid var(--primary,#0ea5e9);padding:.8rem 1rem;border-radius:6px;">'
            f'<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem;margin-bottom:.3rem">'
            f'<div style="font-weight:700;color:var(--callout-blue-title,#0369a1);font-size:.88rem">⚡ Compute Express Link (CXL 2.0 / 3.0) Memory Readiness</div>'
            f'<div><span class="badge info" style="font-size:.75rem">CXL 2.0 Ready (0 GB attached)</span> &nbsp; '
            f'<span class="badge success" style="font-size:.75rem">Interleave: {_h(str(_cxl_il))}</span></div>'
            f'</div>'
            f'<p style="margin:0;font-size:.82rem;color:var(--callout-blue-body,#0c4a6e);line-height:1.4">'
            f'PCIe Gen 5 CXL Type 3 memory expansion controllers enabled in BIOS (Mode: <b>{_h(str(_cxl_mode))}</b>, Interleave: <b>{_h(str(_cxl_il))}</b>). '
            f'Platform is primed for dynamic memory expansion and CXL pooled memory tiers in vSphere.</p>'
            f'</div>'
        )

    return (
        f'<h2>Memory Channel Interleaving &amp; Topology</h2>'
        f'<div class="card" style="margin-bottom:1.5rem;">'
        f'<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;margin-bottom:1rem;">'
        f'<div><h3 style="margin:0 0 .2rem 0;">Memory Bus Interleaving & Bandwidth Efficiency</h3>'
        f'<p style="margin:0;font-size:.85rem;color:var(--text-muted)">'
        f'Architecture: <b>{mem_topo.get("chan_per_cpu")}-Channel Memory Controller</b> | Peak Rated RAM Speed: <b>{mem_topo.get("max_ram_speed_str", "N/A")}</b> | Active: <b>{mem_topo.get("active_channels")} / {mem_topo.get("expected_channels")} Channels Populated</b>'
        f'</p></div>'
        f'<div>{mem_topo.get("status_badge")}</div>'
        f'</div>'
        f'<div style="margin-bottom:1rem;">'
        f'<div style="display:flex;justify-content:space-between;font-size:.85rem;margin-bottom:.3rem;font-weight:bold;">'
        f'<span>Channel Interleaving Efficiency Score</span>'
        f'<span>{mem_topo.get("interleaving_score_pct")}%</span>'
        f'</div>'
        f'<div style="background:var(--ms-score-track,#e2e8f0);border-radius:6px;height:12px;overflow:hidden;width:100%;">'
        f'<div style="width:{mem_topo.get("interleaving_score_pct")}%;background:{_score_color};height:100%;"></div>'
        f'</div>'
        f'</div>'
        f'{_issues_html}'
        f'{_recs_html}'
        f'{_cxl_card}'
        f'<details class="accordion" open style="margin-top:1.2rem;margin-bottom:0;">'
        f'<summary>'
        f'<div style="display:flex;align-items:center;justify-content:space-between;width:100%;padding-right:.5rem;flex-wrap:wrap;gap:.5rem;">'
        f'<div>🧩 Physical Motherboard DIMM Slot &amp; Channel Layout Visualizer</div>'
        f'<div style="font-size:.78rem;color:var(--text-muted);font-weight:normal;">Legend: '
        f'<span style="color:var(--success,#16a34a);font-weight:600;">● Populated (OK)</span> &nbsp; '
        f'<span style="color:var(--danger,#dc2626);font-weight:600;">🔴/⚠️ Degraded / ECC</span> &nbsp; '
        f'<span style="color:var(--text-muted,#94a3b8);font-weight:500;">○ Empty Slot</span></div>'
        f'</div>'
        f'</summary>'
        f'<div class="accordion-body">'
        f'<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(320px, 1fr));gap:1rem;">'
        f'{_mem_grid_html}'
        f'</div>'
        f'</div>'
        f'</details>'
        f'</div>'
    )


def render_memory_combined_card(
    mem_topo: Dict[str, Any],
    sys_info: Dict[str, Any],
    bios_info: Dict[str, Any],
) -> str:
    """Render Merged Memory card (channel interleaving + RAS sub-line)."""
    mem_ras_modes = bios_info.get("memory_ras", []) if bios_info else []
    if not mem_ras_modes:
        _ras_card_badge = "<span class=\"badge info\">ℹ️ BIOS attributes not exposed</span>"
        _ras_card_note  = "BIOS RAS attributes were not returned by this BMC. Run a full scan with iDRAC/iLO admin credentials."
    else:
        _has_danger  = any(r["badge"] == "danger"  for r in mem_ras_modes)
        _has_warning = any(r["badge"] == "warning" for r in mem_ras_modes)
        _info_modes  = [
            r for r in mem_ras_modes
            if r["badge"] == "info" and any(k in r["feature"].lower() for k in ("operating", "protection", "ras", "mirror", "sparing", "adddc"))
        ]
        if _has_danger:
            _ras_card_badge = "<span class=\"badge danger\">🔴 Memory RAS Alert</span>"
            _worst = next(r for r in mem_ras_modes if r["badge"] == "danger")
            _ras_card_note  = f"{_worst['label']} detected — {_worst['note']}"
        elif _has_warning:
            _ras_card_badge = "<span class=\"badge warning\">🟡 Memory RAS Configured</span>"
            _worst = next(r for r in mem_ras_modes if r["badge"] == "warning")
            _ras_card_note  = f"{_worst['label']} detected — {_worst['note']}"
        elif _info_modes:
            _first_info = _info_modes[0]
            _ras_card_badge = f"<span class=\"badge info\">ℹ️ {_h(_first_info['label'])}</span>"
            _ras_card_note  = f"{_first_info['label']} active — {_first_info['note']}"
        else:
            _ras_card_badge = "<span class=\"badge success\">🟢 Standard ECC / No Overhead</span>"
            _ras_card_note  = "No capacity-reducing or bandwidth-degrading memory protection modes detected."

    return (
        f"<div class='card'>"
        f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
        f"<h3 style='margin:0'>Memory</h3>"
        f"<a href='#tab-memory' data-jump-tab='tab-memory' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to Memory section'>Details &rarr;</a>"
        f"</div>"
        f"<div style='margin-bottom:.35rem'>{mem_topo.get('status_badge')}</div>"
        f"<p style='font-size:.85rem;color:var(--text-muted);margin:0 0 .35rem'>"
        f"Efficiency: <b>{mem_topo.get('interleaving_score_pct')}%</b> &nbsp;|&nbsp; "
        f"Speed: <b>{mem_topo.get('operating_speed_str', 'N/A')}</b> "
        f"(Max <b>{mem_topo.get('max_ram_speed_str', 'N/A')}</b>) &nbsp;|&nbsp; "
        f"Total: <b>{sys_info.get('total_memory_gb')} GB</b>"
        f"</p>"
        f"<div style='border-top:1px solid var(--border);padding-top:.4rem'>"
        f"<span style='font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;"
        f"color:var(--text-muted);font-weight:600'>Memory RAS / Protection</span><br>"
        f"<div style='margin-top:.2rem'>{_ras_card_badge}</div>"
        f"<p style='font-size:.8rem;color:var(--text-muted);margin:.2rem 0 0'>{_ras_card_note}</p>"
        f"</div>"
        f"<div style='margin-top:.5rem;border-top:1px solid var(--border);padding-top:.4rem'>"
        f"<a href='#tab-memory' data-jump-tab='tab-memory' class='btn-link tab-jump-link' style='font-size:.78rem'>"
        f"Full details in Memory tab &#8599;</a></div>"
        f"</div>"
    )
