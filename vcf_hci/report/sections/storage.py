"""
VCF Readiness Tool — storage subsystem & vSAN ESA report section builders (Layer D).
"""
import re
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.compat_engine import VCF9CompatibilityEngine
from vcf_hci.constants import (
    BROADCOM_KB_428874_URL,
    DELL_SKU_CHASSIS_DB,
    HPE_SKU_CHASSIS_DB,
    KB_TRIMODE,
)
from vcf_hci.hcl import evaluate_drive_hcl_tier
from vcf_hci.obfuscation import _pii_span
from vcf_hci.report.components import (
    _chassis_svg,
    _ctrl_meta_html,
    _is_nvme_d,
    _is_sas_sata_d,
    _render_ctrl_drives,
    _rn_dim_row,
    _software_raid_banner_html,
    _trimode_banner_html,
)
from vcf_hci.report.helpers import _h

_RN_HCI_PROFILES = [
    {"name": "vSAN-HCI-LRG", "short": "LRG", "cpu_cores": 48, "memory_gb": 512, "nic_gbps": 25, "nvme_count": 6},
    {"name": "vSAN-HCI-MED", "short": "MED", "cpu_cores": 32, "memory_gb": 256, "nic_gbps": 25, "nvme_count": 4},
    {"name": "vSAN-HCI-SM",  "short": "SM",  "cpu_cores": 16, "memory_gb": 128, "nic_gbps": 10, "nvme_count": 2},
]
_RN_SC_PROFILES = [
    {"name": "vSAN-SC-LRG", "short": "LRG", "cpu_cores": 48, "memory_gb": 256, "nic_gbps": 100, "nvme_count": 6},
    {"name": "vSAN-SC-MED", "short": "MED", "cpu_cores": 32, "memory_gb": 192, "nic_gbps": 25,  "nvme_count": 6},
    {"name": "vSAN-SC-SM",  "short": "SM",  "cpu_cores": 16, "memory_gb": 128, "nic_gbps": 25,  "nvme_count": 4},
]
_RN_CR_PROFILES = [
    {"name": "CyberRecovery-LRG", "short": "LRG", "cpu_cores": 32, "memory_gb": 256, "nic_gbps": 25, "nvme_count": 6},
    {"name": "CyberRecovery-MED", "short": "MED", "cpu_cores": 24, "memory_gb": 192, "nic_gbps": 25, "nvme_count": 6},
    {"name": "CyberRecovery-SM",  "short": "SM",  "cpu_cores": 16, "memory_gb": 128, "nic_gbps": 10, "nvme_count": 4},
]


def enrich_drives_hcl(storage: List[Dict[str, Any]], json_hcl: Optional[Dict[str, Any]] = None, csv_db: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Enrich drive inventory in storage subsystem with HCL tier cross-referencing."""
    for ctrl in (storage or []):
        for d in ctrl.get("drives", []):
            if d.get("populated", True):
                eval_hcl = evaluate_drive_hcl_tier(d, json_hcl=json_hcl, csv_db=csv_db)
                d["category"] = eval_hcl["category"]
                d["status_badge"] = eval_hcl["status_badge"]
                d["hcl_str"] = eval_hcl["hcl_str"]
                d["vsan_eligible"] = eval_hcl["vsan_eligible"]
    return [d for ctrl in (storage or []) for d in ctrl.get("drives", []) if d.get("populated", True)]


def render_vsan_esa_ready_node_cards(
    sys_info: Dict[str, Any],
    cpu_info: Dict[str, Any],
    nics: List[Dict[str, Any]],
    all_drives: List[Dict[str, Any]],
    esa_nvme_count: int,
    vmd_enabled: bool,
    is_skylake_deprecated: bool,
    data: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """Render vSAN ESA ReadyNode profile card and merged vSAN ESA readiness card."""
    max_nic_gbps = max((max((p["current_speed_gbps"] for p in n.get("ports", []) if p.get("current_speed_gbps")), default=0) for n in nics), default=0)
    _nic_capable_gbps = max_nic_gbps
    if _nic_capable_gbps == 0:
        for _n in nics:
            _nm = (str(_n.get("name") or "") + " " + str(_n.get("model") or "")).upper()
            if "100GBE" in _nm or "100G" in _nm or "HDR" in _nm or "EDR" in _nm:
                _nic_capable_gbps = max(_nic_capable_gbps, 100)
            elif "50GBE" in _nm or "50G" in _nm:
                _nic_capable_gbps = max(_nic_capable_gbps, 50)
            elif "25GBE" in _nm or "25G" in _nm or "SFP28" in _nm:
                _nic_capable_gbps = max(_nic_capable_gbps, 25)
            elif "10GBE" in _nm or "10G" in _nm or "SFP+" in _nm:
                _nic_capable_gbps = max(_nic_capable_gbps, 10)

    _rn_cores = cpu_info.get("core_count")
    if not isinstance(_rn_cores, int):
        _cs = cpu_info.get("cores_per_socket")
        _cc = cpu_info.get("count", 1)
        _rn_cores = (_cs * _cc) if (_cs and _cc) else None
    _rn_mem     = int(sys_info.get("total_memory_gb") or 0)
    _rn_nic     = _nic_capable_gbps
    _rn_nvme    = esa_nvme_count
    _rn_nvme_tb = round(sum(d.get("capacity_gb", 0) for d in all_drives if d.get("category") == "vSAN ESA/OSA NVMe") / 1000, 1)

    def _eval_rn_profile(profiles, top_note=""):
        _gaps: dict = {}
        _matched = None
        for _rp in profiles:
            _fails = []
            if _rn_cores is None or _rn_cores < _rp["cpu_cores"]:
                _fails.append(("CPU", f"{_rn_cores or '?'} cores", f"≥{_rp['cpu_cores']}"))
            if _rn_mem < _rp["memory_gb"]:
                _fails.append(("Memory", f"{_rn_mem} GB", f"≥{_rp['memory_gb']} GB"))
            if _rn_nic < _rp["nic_gbps"]:
                _nic_disp = f"{_rn_nic} GbE" if _rn_nic else "unknown"
                _fails.append(("NIC", _nic_disp, f"≥{_rp['nic_gbps']} GbE"))
            if _rn_nvme < _rp["nvme_count"]:
                _fails.append(("NVMe drives", str(_rn_nvme), f"≥{_rp['nvme_count']}"))
            _gaps[_rp["name"]] = _fails
            if not _fails and _matched is None:
                _matched = _rp
        _eval_p  = _matched or profiles[-1]
        _cpu_ok  = _rn_cores is not None and _rn_cores >= _eval_p["cpu_cores"]
        _mem_ok  = _rn_mem  >= _eval_p["memory_gb"]
        _nic_ok  = _rn_nic  >= _eval_p["nic_gbps"]
        _nvme_ok = _rn_nvme >= _eval_p["nvme_count"]
        _checklist = (
            _rn_dim_row("🖥️", "CPU cores",    f"{_rn_cores or '?'} total",  f"≥{_eval_p['cpu_cores']}",   _cpu_ok)
            + _rn_dim_row("💾", "Memory",      f"{_rn_mem} GB",              f"≥{_eval_p['memory_gb']} GB", _mem_ok)
            + _rn_dim_row("🌐", "NIC speed",   f"{_rn_nic or '?'} GbE",     f"≥{_eval_p['nic_gbps']} GbE", _nic_ok)
            + _rn_dim_row("💿", "NVMe drives", f"{_rn_nvme}" + (f" ({_rn_nvme_tb} TB)" if _rn_nvme_tb else ""), f"≥{_eval_p['nvme_count']}", _nvme_ok)
        )
        if _matched:
            _idx = next(i for i, p in enumerate(profiles) if p["name"] == _matched["name"])
            if _idx == 0:
                _badge = f"<span class='badge success'>🟢 {_matched['name']}</span>"
                _note  = top_note or f"All {_matched['name']} criteria met."
            else:
                _next_p     = profiles[_idx - 1]
                _next_gaps  = _gaps[_next_p["name"]]
                _gap_labels = [f"{g[0]}: {g[1]} (need {g[2]})" for g in _next_gaps]
                _badge = f"<span class='badge warning'>🟡 {_matched['name']}</span>"
                _note  = f"Gating factor for {_next_p['name']}: {' · '.join(_gap_labels)}"
        else:
            _sm_gaps    = _gaps.get(profiles[-1]["name"], [])
            _gap_labels = [f"{g[0]}: {g[1]} (need {g[2]})" for g in _sm_gaps]
            _badge = "<span class='badge danger'>🔴 Below Minimum</span>"
            _sm_name = profiles[-1]["name"]
            _note  = (f"Does not meet {_sm_name} minimums: " + " · ".join(_gap_labels)) if _gap_labels else "Insufficient data to evaluate."
        return _badge, _checklist, _note

    _rn_badge_hci, _rn_checklist_hci, _rn_note_hci = _eval_rn_profile(
        _RN_HCI_PROFILES, top_note="All ReadyNode criteria met. 100 GbE NIC strongly recommended for LRG."
    )
    _rn_badge_sc, _rn_checklist_sc, _rn_note_sc = _eval_rn_profile(
        _RN_SC_PROFILES, top_note="All Storage Cluster criteria met. Dedicated storage-only deployment."
    )
    _rn_badge_cr, _rn_checklist_cr, _rn_note_cr = _eval_rn_profile(
        _RN_CR_PROFILES, top_note="All Cyber Recovery criteria met. QLC NVMe enables ultra-dense retention."
    )
    rn_card_html = (
        "<div class='card' data-rn-card='1'>"
        "<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem'>"
        "<h3 style='margin:0'>Est. ReadyNode Profile</h3>"
        "<select onchange='switchRNProfile(this)'"
        " style='font-size:.75rem;padding:.15rem .45rem;border:1px solid var(--border);"
        "border-radius:4px;background:var(--bg-card);color:var(--text);cursor:pointer'>"
        "<option value='hci'>vSAN HCI</option>"
        "<option value='sc'>Storage Cluster</option>"
        "<option value='cr'>Cyber Recovery</option>"
        "</select></div>"
        f"<div data-rn-panel='hci'><div>{_rn_badge_hci}</div>"
        f"<div style='margin-top:.5rem'>{_rn_checklist_hci}</div>"
        f"<p style='font-size:.78rem;color:var(--text-muted);margin-top:.4rem'>{_rn_note_hci}</p></div>"
        f"<div data-rn-panel='sc' style='display:none'><div>{_rn_badge_sc}</div>"
        f"<div style='margin-top:.5rem'>{_rn_checklist_sc}</div>"
        f"<p style='font-size:.78rem;color:var(--text-muted);margin-top:.4rem'>{_rn_note_sc}</p></div>"
        f"<div data-rn-panel='cr' style='display:none'><div>{_rn_badge_cr}</div>"
        f"<div style='margin-top:.5rem'>{_rn_checklist_cr}</div>"
        f"<p style='font-size:.78rem;color:var(--text-muted);margin-top:.4rem'>{_rn_note_cr}</p></div>"
        "</div>"
        "<script>function switchRNProfile(sel){"
        "var v=sel.value;"
        "var card=sel.closest('[data-rn-card]');"
        "if(!card)return;"
        "card.querySelectorAll('[data-rn-panel]').forEach(function(el){"
        "el.style.display=(el.getAttribute('data-rn-panel')===v)?'block':'none';"
        "});}</script>"
    )

    sas_sata_count = sum(1 for d in all_drives if d.get("category") == "vSAN OSA SAS/SATA")
    trimode_nvme_count = sum(1 for d in all_drives if d.get("behind_trimode") or d.get("category") == "Unsupported NVMe Tri-Mode")
    raid_nvme_count = sum(1 for d in all_drives if d.get("category") == "Unsupported NVMe RAID" and not d.get("behind_trimode"))

    vsan_verdict, vsan_detail = VCF9CompatibilityEngine.evaluate_vsan(
        esa_nvme_count,
        sas_sata_count,
        max_nic_gbps,
        vmd_enabled=vmd_enabled,
        trimode_nvme_count=trimode_nvme_count,
        raid_nvme_count=raid_nvme_count,
    )

    if "ESA Ready" in vsan_verdict:
        esa_badge = '<span class="badge success">🟢 ESA Ready</span>'
        esa_subtext = f"Direct-attached NVMe ({esa_nvme_count} drives) + ≥25 GbE NIC ({max_nic_gbps} Gbps)."
    elif "ESA Storage Met" in vsan_verdict:
        esa_badge = '<span class="badge warning">🟡 ESA Storage Met</span>'
        esa_subtext = f"Direct-attached NVMe ({esa_nvme_count} drives) met; NIC speed is {max_nic_gbps} Gbps (needs ≥25 GbE)."
    elif "Tri-Mode RAID" in vsan_verdict:
        esa_badge = '<span class="badge danger">🔴 NOT Supported (Tri-Mode RAID)</span>'
        esa_subtext = vsan_detail
    elif "NVMe Behind RAID" in vsan_verdict or "Behind RAID" in vsan_verdict:
        esa_badge = '<span class="badge danger">🔴 NOT Supported (NVMe Behind RAID)</span>'
        esa_subtext = vsan_detail
    elif "VMD Enabled" in vsan_verdict:
        esa_badge = '<span class="badge danger">🔴 NOT Supported (Intel VMD Enabled)</span>'
        esa_subtext = vsan_detail
    else:
        esa_badge = '<span class="badge danger">🔴 NOT Supported</span>'
        esa_subtext = f"Requires ≥2 direct-attached NVMe SSDs (found {esa_nvme_count}) + ≥25 GbE NIC (found {max_nic_gbps} Gbps)."

    if is_skylake_deprecated and "ESA Ready" in vsan_verdict:
        esa_subtext += (
            " ⚠️ Intel Skylake-SP CPU requires install/upgrade override per "
            f"<a href='{BROADCOM_KB_428874_URL}' target='_blank' class='btn-link'>Broadcom KB 428874 ↗</a>."
        )

    vmd_eval = (data.get("bios_checks") or {}).get("vmd_eval") or {} if isinstance(data, dict) else {}
    if vmd_eval.get("staged_for_disable"):
        _vmd_badge = '<span class="badge warning">🟡 Intel VMD: Enabled (Disabled PENDING Reboot)</span>'
        _vmd_note  = vmd_eval.get("note", "VMD is currently Enabled in BIOS, but Disabled has been staged in Redfish. Power-cycle the server to apply.")
    elif vmd_enabled:
        _vmd_badge = '<span class="badge warning">🟡 Intel VMD Enabled</span>'
        _vmd_note  = "Intel VMD is enabled in BIOS — disable for native NVMe pass-through under vSAN ESA."
    else:
        _vmd_badge = '<span class="badge success">🟢 VMD Disabled / Pass-Through</span>'
        _vmd_note  = "NVMe controller in native PCIe pass-through mode."

    vsan_esa_card_html = (
        f"<div class='card'>"
        f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
        f"<h3 style='margin:0'>vSAN ESA (Express Storage Architecture)</h3>"
        f"<a href='#tab-storage' data-jump-tab='tab-storage' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to Storage section'>Details &rarr;</a>"
        f"</div>"
        f"<div style='margin-bottom:.35rem'>{esa_badge}</div>"
        f"<p style='font-size:.85rem;color:var(--text-muted);margin:0 0 .35rem'>{esa_subtext}</p>"
        f"<div style='border-top:1px solid var(--border);padding-top:.4rem'>"
        f"<span style='font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;color:var(--text-muted);font-weight:600'>Intel VMD Status</span><br>"
        f"<div style='margin-top:.2rem'>{_vmd_badge}</div>"
        f"<p style='font-size:.8rem;color:var(--text-muted);margin:.2rem 0 0'>{_vmd_note}</p>"
        f"</div>"
        f"<div style='margin-top:.5rem;border-top:1px solid var(--border);padding-top:.4rem'>"
        f"<a href='#tab-storage' data-jump-tab='tab-storage' class='btn-link tab-jump-link' style='font-size:.78rem'>"
        f"Full details in Storage tab &#8599;</a></div>"
        f"</div>"
    )

    return rn_card_html, vsan_esa_card_html


def render_storage_subsystem_section(
    storage: List[Dict[str, Any]],
    sys_info: Dict[str, Any],
    page_salt: str,
    pcie_switches: List[Dict[str, Any]],
    pcie_lane_budget: Dict[str, Any],
    json_hcl: Optional[Dict[str, Any]] = None,
    quick_mode: bool = False,
    bmc_lic: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Tuple[str, str]]:
    """Render Storage Subsystem section (topology alerts, midplane, bay layout, controller cards, badge label/class)."""
    bmc_lic = bmc_lic or {}
    data = data or {}
    _drive_table_header = (
        '<table class="table" style="width:100%;margin-top:1rem;border-collapse:collapse">'
        '<thead><tr>'
        '<th>Slot / Location</th>'
        '<th>Drive Model &amp; Serial</th>'
        '<th>Media / Protocol</th>'
        '<th>Capacity</th>'
        '<th>Firmware</th>'
        '<th>Endurance Remaining</th>'
        '<th>Health</th>'
        '<th>vSAN Category</th>'
        '<th>BCG Link</th>'
        '</tr></thead><tbody>'
    )

    all_enclosures = [
        enc
        for ctrl in (storage or [])
        for enc in ctrl.get("enclosures", [])
    ]
    midplane_section = ""
    if all_enclosures:
        _total_enc     = len(all_enclosures)
        _sas_exp_count = sum(1 for e in all_enclosures if e.get("has_sas_expander"))
        _lane_split    = sum(1 for e in all_enclosures if e.get("lane_split_hint"))

        _mp_alerts = ""
        if _sas_exp_count:
            _mp_alerts += (
                f"<div class='alert alert-warning' style='margin-bottom:.75rem'>"
                f"⚠️ <strong>{_sas_exp_count} SAS Expander(s) detected in backplane/midplane path.</strong> "
                f"SAS expanders add protocol overhead and a potential single point of failure. "
                f"Verify each expander's firmware is current — outdated SAS expander firmware "
                f"is a known cause of drive faults under vSAN write load."
                f"</div>"
            )
        if _lane_split:
            _mp_alerts += (
                "<div class='alert alert-warning' style='margin-bottom:.75rem'>"
                "⚠️ <strong>PCIe lane-splitting component detected in midplane path.</strong> "
                "A PCIe switch or bridge in the backplane may divide available bandwidth "
                "among multiple NVMe slots — verify actual per-drive lane width in PCIe Slot Details above."
                "</div>"
            )

        _enc_rows = ""
        for _e in all_enclosures:
            _fw = _e.get("firmware_version") or "N/A"
            _fw_cell = f"<code style='font-size:.82rem'>{_h(str(_fw))}</code>" if _fw != "N/A" else "<span style='color:var(--text-muted)'>N/A</span>"
            _slots = _e.get("slot_count")
            _slots_cell = str(_slots) if _slots else "<span style='color:var(--text-muted)'>—</span>"
            _type = _h(_e.get("enclosure_type", "Enclosure"))
            _sas_badge = "<span class='badge warning'>SAS Expander</span>&nbsp;" if _e.get("has_sas_expander") else ""
            _lane_badge = "<span class='badge warning'>PCIe Split</span>&nbsp;" if _e.get("lane_split_hint") else ""
            _type_cell = f"{_sas_badge}{_lane_badge}{_type}"
            _mfr = _h(_e.get("manufacturer") or "") or "<span style='color:var(--text-muted)'>—</span>"
            _model_str = _h(_e.get("model") or "")
            _serial_raw = _e.get("serial_number") or ""
            _serial = (
                _pii_span("serial", _serial_raw, page_salt)
                if _serial_raw else
                "<span style='color:var(--text-muted)'>—</span>"
            )
            _name_cell = (
                f"<strong>{_h(_e['name'])}</strong>"
                + (f"<br><small style='color:var(--text-muted)'>{_model_str}</small>" if _model_str else "")
            )
            _ctrl_link = _h(_e.get("linked_ctrl_name") or _e.get("linked_ctrl_id") or "—")
            _enc_rows += (
                f"<tr>"
                f"<td>{_name_cell}</td>"
                f"<td>{_mfr}</td>"
                f"<td>{_slots_cell}</td>"
                f"<td>{_type_cell}</td>"
                f"<td>{_fw_cell}</td>"
                f"<td><small style='color:var(--text-muted)'>{_serial}</small></td>"
                f"<td><small>{_ctrl_link}</small></td>"
                f"</tr>"
            )

        _mp_summary_cls = "warning" if _sas_exp_count or _lane_split else "info"
        _mp_summary_lbl = (
            f"{_sas_exp_count} SAS Expander(s)" if _sas_exp_count
            else f"{_total_enc} component(s)"
        )
        midplane_section = (
            f"<details class='accordion'>"
            f"<summary>"
            f"<div>&#128197; {_total_enc} backplane/enclosure component(s) &nbsp;"
            f"<span class='badge {_mp_summary_cls}'>{_mp_summary_lbl} found</span>"
            f"</div>"
            f"<span style='font-size:.85rem;color:var(--primary)'>Expand Details &#9662;</span>"
            f"</summary>"
            f"<div class='accordion-body'>"
            f"{_mp_alerts}"
            f"<table><thead><tr>"
            f"<th>Enclosure / Backplane</th><th>Manufacturer</th><th>Drive Slots</th>"
            f"<th>Type</th><th>Firmware</th><th>Serial</th><th>Attached Controller</th>"
            f"</tr></thead><tbody>{_enc_rows}</tbody></table>"
            f"</div></details>"
        )

    nvme_bay_section = ""
    _all_bay_ctrls = sorted(
        [
            c for c in (storage or [])
            if not c.get("is_boot_ctrl")
            and any(d.get("populated", True) for d in c.get("drives", []))
        ],
        key=lambda c: -sum(
            1 for d in c.get("drives", [])
            if d.get("populated", True)
            and ("NVME" in str(d.get("protocol", "")).upper()
                 or "PCIE" in str(d.get("protocol", "")).upper())
        ),
    )
    if _all_bay_ctrls:
        _all_host_drives = []
        for c in _all_bay_ctrls:
            ctrl_name = c.get("name") or c.get("id") or "Storage Subsystem"
            for d in c.get("drives", []):
                if not d.get("populated", True):
                    continue
                d_copy = dict(d)
                d_copy["attached_ctrl_name"] = ctrl_name
                _all_host_drives.append(d_copy)

        _sku_sys = str(sys_info.get("sku") or "").strip().upper()
        _sku_entry = DELL_SKU_CHASSIS_DB.get(_sku_sys) or HPE_SKU_CHASSIS_DB.get(_sku_sys)
        _chassis_cap = _sku_entry[0] if _sku_entry else None

        _front_drives = [
            d for d in _all_host_drives
            if "REAR" not in str(d.get("location") or d.get("bay_location") or "").upper()
        ]
        _rear_drives = [
            d for d in _all_host_drives
            if "REAR" in str(d.get("location") or d.get("bay_location") or "").upper()
        ]
        _has_rear     = bool(_rear_drives)

        _front_slots: list = [int(d["bay_slot"]) for d in _front_drives if isinstance(d.get("bay_slot"), int)]
        _max_front_slot = max(_front_slots) if _front_slots else -1
        _target_front_total = max(_chassis_cap or 0, _max_front_slot + 1, len(_front_drives))

        # Fleet-wide totals for summary badge
        _fleet_pop   = len(_all_host_drives)
        _fleet_total = max(_target_front_total + len(_rear_drives), _fleet_pop)
        _fleet_empty = max(0, _fleet_total - _fleet_pop)
        _fleet_edsff = sum(1 for d in _all_host_drives if d.get("is_edsff"))
        _sum_cls     = "warning" if _fleet_empty else "success"
        _free_lbl    = f"{_fleet_empty} free slot{'s' if _fleet_empty != 1 else ''}" if _fleet_empty else "All slots occupied"

        # Chassis label title
        _chassis_title_lbl = sys_info.get("chassis_label") or f"{_h(str(sys_info.get('model', 'Server')))} Front Drive Bays"
        if "/" in _chassis_title_lbl:
            _chassis_title_lbl = re.sub(r"\s*/\s*\d+\s*(?:LFF|SFF|EDSFF)[^·]*", "", _chassis_title_lbl)

        _legend = (
            "<div style='font-size:.82rem;color:var(--text-muted);margin-bottom:.75rem;"
            "display:flex;flex-wrap:wrap;gap:1.25rem;align-items:center;"
            "background:var(--sec-muted-bg,#1e293b);padding:.5rem .85rem;border-radius:6px;border:1px solid var(--border)'>"
            "<span><span style='color:#16a34a;font-size:1.1rem;vertical-align:-1px'>■</span> <b>NVMe SSD</b></span>"
            "<span><span style='color:#f97316;font-size:1.1rem;vertical-align:-1px'>■</span> <b>EDSFF NVMe</b></span>"
            "<span><span style='color:#6366f1;font-size:1.1rem;vertical-align:-1px'>■</span> <b>SATA / SAS SSD</b></span>"
            "<span><span style='color:#0ea5e9;font-size:1.1rem;vertical-align:-1px'>■</span> <b>HDD</b></span>"
            "<span><span style='color:#64748b;font-size:1.1rem;vertical-align:-1px'>■</span> <b>Empty Slot / Blank</b></span>"
            "</div>"
        )

        _front_svg = _chassis_svg(
            _front_drives,
            position_label="Front",
            chassis_title=_chassis_title_lbl,
            total_slots_override=_target_front_total,
        )
        _front_block = (
            ("<h5 style='margin:.4rem 0 .3rem'>Front Chassis Bays</h5>" if _has_rear else "")
            + _front_svg
        )

        _rear_block = ""
        if _has_rear:
            _rear_slots: list = [int(d["bay_slot"]) for d in _rear_drives if isinstance(d.get("bay_slot"), int)]
            _max_rear_slot = max(_rear_slots) if _rear_slots else -1
            _target_rear_total = max(_max_rear_slot + 1, len(_rear_drives))
            _rear_svg = _chassis_svg(
                _rear_drives,
                position_label="Rear",
                chassis_title=f"{_chassis_title_lbl} (Rear)",
                total_slots_override=_target_rear_total,
            )
            _rear_block = (
                f"<h5 style='margin:.9rem 0 .3rem'>Rear / Back Bays</h5>"
                f"{_rear_svg}"
            )

        # Build controller breakdown summary table
        _ctrl_rows = ""
        for _nc in _all_bay_ctrls:
            _c_drives = _nc.get("drives", [])
            _c_pop    = [d for d in _c_drives if d.get("populated", True)]
            _c_empty  = [d for d in _c_drives if not d.get("populated", True)]
            _c_nvme   = sum(1 for d in _c_pop if _is_nvme_d(d))
            _c_sas    = sum(1 for d in _c_pop if _is_sas_sata_d(d))
            _c_edsff  = sum(1 for d in _c_pop if d.get("is_edsff"))
            _fw       = _nc.get("ctrl_firmware") or "N/A"
            _fw_str   = f"<code>{_h(str(_fw))}</code>" if _fw != "N/A" else "N/A"
            _tri_b    = "<span class='badge warning'>Tri-Mode RAID</span> " if _nc.get("is_trimode") else ""
            _sw_b     = "<span class='badge warning'>Software RAID</span> " if _nc.get("is_software_raid") else ""

            _c_proto_parts = []
            if _c_nvme:
                _c_proto_parts.append(f"{_c_nvme} NVMe" + (f" ({_c_edsff} EDSFF)" if _c_edsff else ""))
            if _c_sas:
                _c_proto_parts.append(f"{_c_sas} SAS/SATA")
            if not _c_proto_parts:
                _c_proto_parts = [f"{len(_c_empty)} empty"]
            _c_proto_str = " + ".join(_c_proto_parts)

            _ctrl_rows += (
                f"<tr>"
                f"<td><strong>{_h(_nc.get('name', 'Storage Controller'))}</strong></td>"
                f"<td>{_tri_b}{_sw_b}{_c_proto_str}</td>"
                f"<td>{len(_c_pop)} / {len(_c_drives)} slots</td>"
                f"<td>{_fw_str}</td>"
                f"</tr>"
            )

        _ctrl_summary_table = (
            f"<details class='accordion' style='margin-top:1rem'>"
            f"<summary style='font-size:.88rem'>"
            f"<div>🗄️ Storage Controller Breakdown ({len(_all_bay_ctrls)} controllers)</div>"
            f"<span style='font-size:.82rem;color:var(--primary)'>Expand Controller Detail &#9662;</span>"
            f"</summary>"
            f"<div class='accordion-body' style='padding:.75rem 0'>"
            f"<table><thead><tr>"
            f"<th>Controller Card</th><th>Attached Protocols</th><th>Slot Population</th><th>Firmware Version</th>"
            f"</tr></thead><tbody>{_ctrl_rows}</tbody></table>"
            f"</div></details>"
        )

        _ctrl_blocks = f"{_legend}{_front_block}{_rear_block}{_ctrl_summary_table}"

        _edsff_badge = "&nbsp;<span class='badge info'>Includes EDSFF</span>" if _fleet_edsff else ""
        nvme_bay_section = (
            f"<details class='accordion' open>"
            f"<summary>"
            f"<div>&#128190; Drive Bays &nbsp;"
            f"<span class='badge {_sum_cls}'>{_fleet_pop} of {_fleet_total} populated &mdash; {_free_lbl}</span>"
            f"{_edsff_badge}</div>"
            f"<span style='font-size:.85rem;color:var(--primary)'>Collapse Bay Details &#9652;</span>"
            f"</summary>"
            f"<div class='accordion-body'>"
            f"<div style='font-size:.82rem;color:var(--text-muted);margin-bottom:1rem'>"
            f"<span style='color:var(--success)'>&#9608;</span> NVMe &ensp;"
            f"<span style='color:#f97316'>&#9632;</span> EDSFF NVMe (E1.S / E3.S) &ensp;"
            f"<span style='color:#6366f1'>&#9646;</span> SAS / SATA &ensp;"
            f"<span style='color:#cbd5e1'>&#9617;</span> Empty</div>"
            f"{_ctrl_blocks}"
            f"</div></details>"
        )

    populated_ctrls = [c for c in (storage or []) if any(d.get("populated", True) for d in c.get("drives", []))]
    empty_ctrls = [c for c in (storage or []) if not any(d.get("populated", True) for d in c.get("drives", []))]

    all_drives_flat = [d for ctrl in (storage or []) for d in ctrl.get("drives", []) if d.get("populated", True)]
    trimode_nvme       = [d for d in all_drives_flat if d.get("behind_trimode")]
    software_raid_nvme = [d for d in all_drives_flat if d.get("behind_software_raid")]
    single_lane_nv     = [d for d in all_drives_flat if d.get("single_lane_alert")]

    storage_topology_alerts = ""
    if trimode_nvme:
        storage_topology_alerts += (
            f"<div class='alert alert-danger' style='margin-bottom:1rem'>"
            f"<strong>🔴 {len(trimode_nvme)} NVMe drive(s) detected behind a Tri-Mode RAID controller</strong> — "
            f"This configuration is NOT supported for vSAN ESA or OSA. "
            f"NVMe drives must be directly attached to the CPU PCIe root complex or a native NVMe HBA.<br>"
            f"<a href='{KB_TRIMODE}' target='_blank' style='font-weight:600'>"
            f"Broadcom KB314305: vSAN Support of NVMe Devices Behind Tri-Mode Controllers ↗</a>"
            f"</div>"
        )
    if software_raid_nvme:
        storage_topology_alerts += (
            f"<div class='alert alert-warning' style='margin-bottom:1rem'>"
            f"<strong>⚠️ {len(software_raid_nvme)} NVMe drive(s) detected behind a Host Software RAID controller</strong> — "
            f"VMware ESXi does not support host software RAID (PERC S-series, Dynamic Smart Array, Intel RSTe). "
            f"Bypass or disable the software RAID controller in System BIOS (set Embedded SATA to AHCI and NVMe to Non-RAID / Pass-Through). "
            f"The physical NVMe drives are wired directly to CPU PCIe lanes and will be fully recognized for vSAN ESA once bypassed in BIOS."
            f"</div>"
        )
    if single_lane_nv:
        storage_topology_alerts += (
            f"<div class='alert alert-danger' style='margin-bottom:1rem'>"
            f"<strong>🔴 {len(single_lane_nv)} NVMe drive(s) operating on a single PCIe lane (x1)</strong> — "
            f"Performance is severely limited compared to a standard x4 connection "
            f"and may be worse than a SAS drive. This is often caused by single-lane "
            f"backplane cabling (seen on some HPE U.2 configurations). "
            f"Verify cabling and backplane PCIe lane allocation before qualifying for vSAN."
            f"</div>"
        )
    if pcie_switches:
        sw_names = ", ".join(_h(s.get("name", "?")) for s in pcie_switches)
        storage_topology_alerts += (
            f"<div class='alert alert-warning' style='margin-bottom:1rem'>"
            f"<strong>🟡 PCIe Switch detected: {sw_names}</strong> — "
            f"vSAN can function through PCIe switches, but ensure the switch and "
            f"any attached NVMe devices appear on the Broadcom HCL. "
            f"Switches add latency and may obscure per-drive fault isolation."
            f"</div>"
        )

    _plb_over  = pcie_lane_budget.get("over_budget",  False)
    _plb_near  = pcie_lane_budget.get("near_budget",  False)
    _plb_obs   = pcie_lane_budget.get("observed_lanes", 0)
    _plb_bud   = pcie_lane_budget.get("cpu_lane_budget", 0)
    _plb_pct   = pcie_lane_budget.get("utilization_pct", 0)
    _plb_note  = pcie_lane_budget.get("note", "")
    _plb_slots = pcie_lane_budget.get("populated_slot_count", 0)
    if _plb_over and _plb_bud:
        storage_topology_alerts += (
            f"<div class='alert alert-danger' style='margin-bottom:1rem'>"
            f"<strong>🔴 CPU PCIe Lane Budget Exceeded: {_plb_obs} observed vs {_plb_bud} max</strong> "
            f"({_plb_pct}% utilization across {_plb_slots} populated slot(s)) — "
            f"{_h(_plb_note)}"
            f"</div>"
        )
    elif _plb_near and _plb_bud:
        storage_topology_alerts += (
            f"<div class='alert alert-warning' style='margin-bottom:1rem'>"
            f"<strong>🟡 PCIe Lane Utilization High: {_plb_obs}/{_plb_bud} lanes ({_plb_pct}%)</strong> "
            f"across {_plb_slots} populated slot(s) — {_h(_plb_note)}"
            f"</div>"
        )

    storage_cards = ""
    for ctrl in populated_ctrls:
        storage_cards += (
            f"<div class='card card-nested' style='margin-bottom:2rem;'>"
            f"<h3>Storage Controller: {_h(ctrl.get('name', 'Storage Controller'))} (ID: {_h(str(ctrl.get('id', 'N/A')))})</h3>"
            f"{_ctrl_meta_html(ctrl, hcl_data=json_hcl)}"
            f"{_trimode_banner_html(ctrl)}"
            f"{_software_raid_banner_html(ctrl)}"
            f"{_drive_table_header}{_render_ctrl_drives(ctrl, json_hcl=json_hcl)}</tbody></table></div>"
        )
    if empty_ctrls:
        inner = "".join(
            f"<details class='accordion' style='margin-bottom:.5rem'>"
            f"<summary style='font-size:.9rem'>Storage Controller: {c['name']} (ID: {c['id']})"
            f" — <em style='font-weight:400;color:var(--text-muted)'>No drives</em></summary>"
            f"<div class='accordion-body'>{_ctrl_meta_html(c, hcl_data=json_hcl)}{_drive_table_header}"
            f"{_render_ctrl_drives(c, json_hcl=json_hcl)}</tbody></table></div></details>"
            for c in empty_ctrls
        )
        storage_cards += (
            f"<details class='accordion' style='margin-bottom:2rem'>"
            f"<summary>🗄️ {len(empty_ctrls)} Empty Storage Controller(s) — expand to view</summary>"
            f"<div class='accordion-body' style='padding:.5rem'>{inner}</div></details>"
        )

    _sys_info_st = (data or {}).get("system", {})
    _enc_info_st = _sys_info_st.get("enclosure_info") or {}
    _model_low = str(_sys_info_st.get("model", "")).lower()
    _is_blade_or_sled = (
        _sys_info_st.get("is_blade")
        or _enc_info_st.get("is_enclosure_contained")
        or any(k in _model_low for k in ("blade", "sled", "e910", "m640", "m630", "fc640", "b200", "b480", "sy 480", "sy 660", "sn550", "sn850"))
    )
    _is_diskless_detected = False

    if not storage_cards:
        if quick_mode:
            storage_cards = "<p style='color:var(--text-muted);padding:.5rem 0'>Storage collection skipped in Quick mode — re-run in Full mode.</p>"
        elif data.get("partial_scan") or "storage_subsystem" in data.get("partial_sections", []):
            storage_cards = (
                "<p style='color:var(--warning,#ca8a04);padding:.5rem 0'>"
                "⚠️ Storage collection timed out or was incomplete due to BMC responsiveness. "
                "Perform a BMC reset (<code>racadm racreset</code> or <code>iloreset</code>) and re-scan.</p>"
            )
        elif any(kw in bmc_lic.get("license_name", "").lower() for kw in ["required", "blocked", "missing"]):
            storage_cards = (
                f"<p style='color:#7f1d1d;padding:.5rem 0'>"
                f"⚠️ Storage collection was blocked by a license restriction "
                f"({bmc_lic.get('license_name', 'unknown')}). "
                f"See the BMC License row above for remediation steps.</p>"
            )
        elif _is_blade_or_sled or (data and not data.get("partial_scan") and "storage_subsystem" not in data.get("partial_sections", [])):
            _is_diskless_detected = True
            _node_lbl = "Blade Compute Node" if _is_blade_or_sled else "Server / Compute Node"
            storage_cards = (
                f"<div class='callout-box' style='margin:.5rem 0;border-left:4px solid var(--accent,#38bdf8);background:rgba(56,189,248,0.06);padding:.75rem 1rem;border-radius:6px'>"
                f"<strong>💻 Diskless {_node_lbl}:</strong> 0 physical storage controllers and 0 drives installed. "
                f"The Redfish <code>/Storage</code> endpoint responded with 0 populated controllers. "
                f"This is expected for stateless, SAN-booted (Fibre Channel / iSCSI), or PXE-booted compute nodes."
                f"</div>"
            )
        else:
            storage_cards = "<p style='color:var(--text-muted);padding:.5rem 0'>No storage controllers discovered via Redfish API. The BMC may require additional permissions, or the <code>/Storage</code> endpoint is not available on this platform.</p>"

    _stor_total_pop = sum(
        1 for d in all_drives_flat
        if d.get("populated", True) and d.get("category") != "Boot Device"
    )
    _stor_nvme_count = sum(1 for d in all_drives_flat if d.get("category") == "vSAN ESA/OSA NVMe")
    _stor_nvme_tb = round(sum(d.get("capacity_gb", 0) for d in all_drives_flat if d.get("category") == "vSAN ESA/OSA NVMe") / 1000, 1)
    _stor_badge_cls = "success" if _stor_nvme_count >= 2 else ("warning" if _stor_total_pop else "info")
    _stor_badge_lbl = (
        f"{_stor_total_pop} drive(s) &mdash; {_stor_nvme_count} NVMe ({_stor_nvme_tb} TB raw)"
        if _stor_nvme_count
        else ("Diskless Compute Node" if _is_diskless_detected else f"{_stor_total_pop} drive(s)")
    )

    fc_storage_callout = ""
    _fc_hbas = (data or {}).get("fc_hbas") or []
    if _fc_hbas:
        _hba_names = ", ".join(sorted({h.get("adapter_name", "FC HBA") for h in _fc_hbas}))
        _hba_port_s = "port" if len(_fc_hbas) == 1 else "ports"
        _speeds = sorted({f"{h['speed_gbps']} Gbps" for h in _fc_hbas if h.get("speed_gbps") and h.get("speed_gbps") != "N/A"})
        _speed_txt = f" @ {', '.join(_speeds)}" if _speeds else ""
        fc_storage_callout = (
            f"<div class='alert alert-info' style='margin-bottom:1.25rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem'>"
            f"<div>"
            f"<strong>🌐 Fibre Channel / SAN Storage Connectivity Detected</strong> — "
            f"{len(_fc_hbas)} FC {_hba_port_s}{_speed_txt} ({_h(_hba_names)}) discovered for external SAN / VMFS storage integration."
            f"</div>"
            f"<a href='#tab-network' data-jump-tab='tab-network' class='btn-link tab-jump-link' style='font-size:.82rem;font-weight:600;white-space:nowrap;text-decoration:none'>"
            f"View FC HBAs in Networking Tab &rarr;</a>"
            f"</div>"
        )

    storage_section_html = (
        f"{fc_storage_callout}"
        f"{storage_topology_alerts}"
        f"{nvme_bay_section}"
        f"{midplane_section}"
        f"<h3 style='margin:1.5rem 0 .75rem;color:var(--h-color,#0f172a)'>Storage Controllers</h3>"
        f"{storage_cards}"
    )

    return storage_section_html, (_stor_badge_cls, _stor_badge_lbl)
