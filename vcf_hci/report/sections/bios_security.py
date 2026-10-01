"""
VCF Readiness Tool — BIOS performance settings & security posture report section builders (Layer D).
"""
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.compat_engine import evaluate_boot_mode
from vcf_hci.constants import (
    _CVE_TIERS,
    _VENDOR_SIDE_CHANNEL_LINKS,
    DEFAULT_HARDENING_GUIDE,
    VENDOR_HARDENING_GUIDES,
)
from vcf_hci.report.helpers import _h, host_has_redfish_latency
from vcf_hci.security.metadata import (
    GROUP_LABELS,
    GROUP_ORDER,
    get_control_confidence,
    get_control_group,
    get_control_title,
    get_control_transport,
)


def _format_observed(observed: Any) -> str:
    """Format observed evidence value safely without rendering raw dicts, secrets, or certs."""
    if observed is None:
        return "—"
    if isinstance(observed, bool):
        return "Enabled" if observed else "Disabled"
    if isinstance(observed, (int, float)):
        return str(observed)
    if isinstance(observed, list):
        safe_items = []
        for x in observed:
            if isinstance(x, (str, int, float, bool)):
                s = str(x).strip()
                if not any(k in s.lower() for k in ("secret", "password", "key", "cert", "token", "hash")):
                    safe_items.append(s)
        if not safe_items:
            return f"{len(observed)} items"
        joined = ", ".join(safe_items)
        if len(joined) > 60:
            return joined[:57] + "…"
        return joined
    if isinstance(observed, dict):
        if "count" in observed:
            return f"Count: {observed['count']}"
        return f"{len(observed)} attributes"
    if isinstance(observed, str):
        s = observed.strip()
        if "-----BEGIN" in s or "CERTIFICATE" in s:
            return "[Certificate Installed]"
        if s.startswith("{") and s.endswith("}"):
            return "[Object Data]"
        if any(k in s.lower() for k in ("secret", "password", "hash", "private")):
            return "[Protected]"
        if len(s) > 60:
            return s[:57] + "…"
        return s
    return str(observed)[:60]


def _format_reason(reason_code: str) -> str:
    """Format an audit finding reason code into human-readable text."""
    if not reason_code:
        return "—"
    code = str(reason_code)
    _REASON_MAP = {
        "STANDARD_REDFISH_PASS": "Standard Redfish Pass",
        "OEM_REDFISH_PASS": "OEM Redfish Pass",
        "STANDARD_REDFISH_FAIL": "Standard Redfish Fail",
        "OEM_REDFISH_FAIL": "OEM Redfish Fail",
        "NOT_COLLECTED": "Not Collected",
        "PROPERTY_NOT_EXPOSED": "Property Not Exposed",
        "ENDPOINT_NOT_EXPOSED": "Endpoint Not Exposed",
        "WRITE_ONLY_SECRET": "Write-Only Secret",
        "INSUFFICIENT_PRIVILEGE": "Insufficient Privilege",
        "FEATURE_UNLICENSED": "Feature Unlicensed",
        "FEATURE_UNSUPPORTED": "Feature Unsupported",
        "AMBIGUOUS_EVIDENCE": "Ambiguous Evidence",
        "EXTERNAL_PROCESS_REQUIRED": "External Process Required",
        "CLIENT_BEHAVIOR_REQUIRED": "Client Behavior Required",
        "NOT_APPLICABLE": "Not Applicable",
    }
    return _REASON_MAP.get(code, code.replace("_", " ").title())


def _finding_status_badge(status: str) -> str:
    """Render a colored badge for an audit finding status."""
    if status == "pass":
        return "<span class='badge success'>Pass</span>"
    elif status == "fail":
        return "<span class='badge danger'>Fail</span>"
    elif status == "not_applicable":
        return "<span class='badge info'>N/A</span>"
    elif status == "unknown_write_only":
        return "<span class='badge info'>Unknown (Write-Only)</span>"
    elif status == "unknown_not_exposed":
        return "<span class='badge info'>Unknown (Not Exposed)</span>"
    elif status == "unknown_not_collected":
        return "<span class='badge info'>Unknown (Not Collected)</span>"
    elif status == "unknown_insufficient_privilege":
        return "<span class='badge warning'>Unknown (Denied)</span>"
    elif status == "unknown_unlicensed":
        return "<span class='badge warning'>Unknown (Unlicensed)</span>"
    elif status == "unknown_unsupported":
        return "<span class='badge info'>Unknown (Unsupported)</span>"
    elif status == "unknown_ambiguous":
        return "<span class='badge warning'>Unknown (Ambiguous)</span>"
    elif status.startswith("unknown"):
        clean_lbl = status.replace("unknown_", "").replace("_", " ").title()
        return f"<span class='badge info'>Unknown ({_h(clean_lbl)})</span>"
    return f"<span class='badge info'>{_h(status.title())}</span>"


def get_vendor_hardening_guide(
    vendor: Optional[str] = None,
    bmc_model: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve the official vendor server/BMC hardening guide metadata.

    Matches by server vendor name or BMC controller model identifier,
    falling back to standard VMware Cloud Foundation Security Guidelines.
    """
    v = (str(vendor or "").strip()).upper()
    m = (str(bmc_model or "").strip()).upper()
    v_compact = v.replace(" ", "").replace("-", "").replace("_", "")
    m_compact = m.replace(" ", "").replace("-", "").replace("_", "")

    for key, guide in VENDOR_HARDENING_GUIDES.items():
        if key in v or key in v_compact:
            return guide

    for key, guide in VENDOR_HARDENING_GUIDES.items():
        if key in m or key in m_compact:
            return guide

    return DEFAULT_HARDENING_GUIDE


def render_vendor_hardening_link(
    vendor: Optional[str] = None,
    bmc_model: Optional[str] = None,
) -> str:
    """Render styled button-link(s) to the vendor or baseline server hardening guide."""
    guide = get_vendor_hardening_guide(vendor, bmc_model)
    docs = guide.get("docs")
    if not docs or not isinstance(docs, list):
        docs = [guide]

    buttons = []
    for idx, doc in enumerate(docs[:2]):
        escaped_url = _h(doc.get("url", ""))
        escaped_label = _h(doc.get("label", doc.get("badge_label", "Hardening Guide")))
        escaped_title = _h(doc.get("title", doc.get("guide_title", escaped_label)))
        icon = "🛡️" if idx == 0 else "📄"
        buttons.append(
            f'<a href="{escaped_url}" target="_blank" rel="noopener noreferrer" '
            f'class="btn-link" style="display:inline-flex;align-items:center;gap:.35rem;'
            f'font-size:.8rem;padding:.2rem .55rem;border-radius:4px;border:1px solid var(--border);'
            f'background:var(--card);text-decoration:none;font-weight:500" '
            f'title="{escaped_title}">'
            f'<span>{icon} {escaped_label}</span> <span style="font-size:.72rem">↗</span></a>'
        )

    return " ".join(buttons)


def render_controls_explained_link() -> str:
    """Render a styled button-link pointing to the 84-control security audit catalog and guidance."""
    local_url = "/docs/user_guide_reference#bmc-84-control-catalog"
    github_url = "https://github.com/vmware/vcf-readiness/blob/main/docs/USER_GUIDE_REFERENCE.md#bmc-84-control-catalog"
    title_text = "View the 84-Control BMC Security Audit catalog, provenance, and CISA/NSA Joint hardening alignment in the User Guide"
    return (
        f'<a href="{local_url}" target="_blank" rel="noopener noreferrer" '
        f'class="btn-link" style="display:inline-flex;align-items:center;gap:.35rem;'
        f'font-size:.8rem;padding:.2rem .55rem;border-radius:4px;border:1px solid var(--border);'
        f'background:var(--card);text-decoration:none;font-weight:500" '
        f'data-offline-href="{github_url}" '
        f'onclick="if(window.location.protocol===\'file:\'){{this.href=this.getAttribute(\'data-offline-href\');}}" '
        f'title="{title_text}">'
        f'<span>❓ Controls Explained</span> <span style="font-size:.72rem">↗</span></a>'
    )


_HPE_BIOS_EXTRA_KEYS = (
    "Sriov",
    "UefiOptimizedBoot",
    "EnabledCoresPerProc",
    "ThermalConfig",
    "NicBoot1",
    "NicBoot2",
    "NicBoot3",
    "NicBoot4",
    "NicBoot5",
    "NicBoot6",
    "Slot2NicBoot1",
    "Slot2NicBoot2",
)


def _hpe_allowlisted_bios_rows(pending_attrs: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Filter HPE pending_attributes against safe allowlist and map to table row format."""
    if not pending_attrs:
        return []
    rows = []
    for key in _HPE_BIOS_EXTRA_KEYS:
        val = pending_attrs.get(key)
        if val is None or val == "":
            continue
        val_str = str(val).strip()
        val_upper = val_str.upper()

        if key == "Sriov":
            feature = "SR-IOV"
            if val_upper == "ENABLED":
                badge = "info"
                note = "Confirm VCF NIC/SR-IOV policy before enabling VF passthrough."
            else:
                badge = "info"
                note = "SR-IOV disabled in BIOS"
            rows.append({
                "feature": feature, "label": val_str, "badge": badge,
                "note": note, "raw_key": key, "raw_val": val_str,
            })
        elif key == "UefiOptimizedBoot":
            feature = "UEFI Optimized Boot"
            if val_upper == "ENABLED":
                badge = "success"
                note = "UEFI optimized boot enabled"
            else:
                badge = "info"
                note = "UEFI optimized boot disabled"
            rows.append({
                "feature": feature, "label": val_str, "badge": badge,
                "note": note, "raw_key": key, "raw_val": val_str,
            })
        elif key == "EnabledCoresPerProc":
            feature = "Enabled Cores per Processor"
            if val_str in ("0", "All", "all"):
                badge = "success"
                label = "All cores"
                note = "All physical processor cores enabled"
            else:
                badge = "warning"
                label = val_str
                note = "Core disablement active"
            rows.append({
                "feature": feature, "label": label, "badge": badge,
                "note": note, "raw_key": key, "raw_val": val_str,
            })
        elif key == "ThermalConfig":
            feature = "Thermal Configuration"
            if "OPTIMAL" in val_upper:
                badge = "info"
                note = "Optimal cooling profile"
            elif any(k in val_upper for k in ("INCREASED", "MAX")):
                badge = "info"
                note = "High fan cooling profile"
            elif any(k in val_upper for k in ("POWER", "ENERGY")):
                badge = "warning"
                note = "Energy saving thermal mode may impact peak performance"
            else:
                badge = "info"
                note = ""
            rows.append({
                "feature": feature, "label": val_str, "badge": badge,
                "note": note, "raw_key": key, "raw_val": val_str,
            })
        elif "NICBOOT" in key.upper():
            feature = f"NIC Boot {key}"
            if val_upper == "DISABLED":
                badge = "success"
                note = "NIC network boot disabled"
            else:
                badge = "warning"
                note = "NIC boot enabled"
            rows.append({
                "feature": feature, "label": val_str, "badge": badge,
                "note": note, "raw_key": key, "raw_val": val_str,
            })
    return rows


def render_bios_baseline_scorecard(bios_info: Optional[Dict[str, Any]]) -> str:
    """Render the VCF 9.1 BIOS Golden Baseline Scorecard accordion.

    Displays compliance metrics, drifted BIOS settings with severity badges,
    current vs recommended values, and VMware Best Practice rationales, as well as
    compliant golden baseline settings.
    """
    if not isinstance(bios_info, dict):
        return ""
    drift_data = (
        bios_info.get("bios_baseline_drift")
        or bios_info.get("hpe_baseline_drift")
        or bios_info.get("cisco_baseline_drift")
        or bios_info.get("lenovo_baseline_drift")
        or bios_info.get("dell_baseline_drift")
        or bios_info.get("generic_baseline_drift")
    )
    if not isinstance(drift_data, dict) or not drift_data.get("rules"):
        return ""

    compliance_pct = drift_data.get("compliance_pct", 100.0)
    total_rules = drift_data.get("total_rules", 0)
    passed_count = drift_data.get("passed_count", 0)
    drift_count = drift_data.get("drift_count", 0)
    blocker_count = drift_data.get("blocker_count", 0)
    warning_count = drift_data.get("warning_count", 0)
    info_count = drift_data.get("info_count", 0)
    badge = drift_data.get("badge", "")
    drifts = drift_data.get("drifts", [])
    rules = drift_data.get("rules", [])
    guide_info = drift_data.get("tuning_guide") or {}
    vmware_guide_title = drift_data.get("vmware_guide_title") or "VMware vSphere 9.0 Performance Best Practices"
    vmware_guide_url = (
        drift_data.get("vmware_guide_url")
        or "https://www.vmware.com/docs/vsphere-esxi-vcenter-server-90-performance-best-practices"
    )
    oem_guide_title = drift_data.get("oem_guide_title") or (guide_info.get("title") if guide_info else None)
    oem_guide_url = drift_data.get("oem_guide_url") or (guide_info.get("url") if guide_info else None)

    if blocker_count > 0:
        pct_color = "var(--danger, #dc2626)"
    elif warning_count > 0:
        pct_color = "var(--warning, #ca8a04)"
    elif info_count > 0:
        pct_color = "var(--info, #0284c7)"
    else:
        pct_color = "var(--success, #16a34a)"

    drift_color = (
        "var(--danger, #dc2626)"
        if blocker_count > 0
        else (
            "var(--warning, #ca8a04)"
            if warning_count > 0
            else ("var(--info, #0284c7)" if info_count > 0 else "var(--text-muted)")
        )
    )

    perf_guide_hdr = (
        f"<div style='margin-bottom:.85rem;font-size:.82rem;color:var(--text-muted);display:flex;flex-wrap:wrap;align-items:center;gap:.5rem'>"
        f"<span>Evaluated against Broadcom VCF 9.1 &amp;</span>"
        f"<a href='{_h(vmware_guide_url)}' target='_blank' rel='noopener noreferrer' "
        f"style='color:var(--primary);text-decoration:underline;font-weight:600'>📖 {_h(vmware_guide_title)}</a>"
    )
    if oem_guide_title and oem_guide_url and oem_guide_title != vmware_guide_title:
        perf_guide_hdr += (
            f"<span style='color:var(--border-color, #cbd5e1)'>|</span>"
            f"<span>OEM Reference:</span>"
            f"<a href='{_h(oem_guide_url)}' target='_blank' rel='noopener noreferrer' "
            f"style='color:var(--primary);text-decoration:underline;font-weight:600'>📑 {_h(oem_guide_title)}</a>"
        )
    perf_guide_hdr += "</div>"

    stats_html = (
        f"<div style='display:flex;gap:1.5rem;margin-bottom:1rem;flex-wrap:wrap;background:var(--bg-card);padding:.75rem 1rem;border-radius:6px;border:1px solid var(--border)'>"
        f"<div><span style='font-size:.75rem;text-transform:uppercase;color:var(--text-muted);font-weight:600'>Compliance</span><br><strong style='font-size:1.15rem;color:{pct_color}'>{compliance_pct}%</strong></div>"
        f"<div><span style='font-size:.75rem;text-transform:uppercase;color:var(--text-muted);font-weight:600'>Rules Evaluated</span><br><strong style='font-size:1.15rem'>{total_rules}</strong></div>"
        f"<div><span style='font-size:.75rem;text-transform:uppercase;color:var(--text-muted);font-weight:600'>Compliant</span><br><strong style='font-size:1.15rem;color:var(--success, #16a34a)'>{passed_count}</strong></div>"
        f"<div><span style='font-size:.75rem;text-transform:uppercase;color:var(--text-muted);font-weight:600'>Drift Count</span><br><strong style='font-size:1.15rem;color:{drift_color}'>{drift_count}</strong></div>"
        + (f"<div><span style='font-size:.75rem;text-transform:uppercase;color:var(--danger, #dc2626);font-weight:600'>Blockers</span><br><strong style='font-size:1.15rem;color:var(--danger, #dc2626)'>{blocker_count}</strong></div>" if blocker_count > 0 else "")
        + (f"<div><span style='font-size:.75rem;text-transform:uppercase;color:var(--warning, #ca8a04);font-weight:600'>Warnings</span><br><strong style='font-size:1.15rem;color:var(--warning, #ca8a04)'>{warning_count}</strong></div>" if warning_count > 0 else "")
        + (f"<div><span style='font-size:.75rem;text-transform:uppercase;color:var(--info, #0284c7);font-weight:600'>Info</span><br><strong style='font-size:1.15rem;color:var(--info, #0284c7)'>{info_count}</strong></div>" if info_count > 0 else "")
        + "</div>"
    )

    if drifts:
        drift_rows = []
        for d in drifts:
            attr = _h(str(d.get("attribute", "")))
            setting_name = _h(str(d.get("setting_name", attr)))
            cur_val = _h(str(d.get("current_value", "—")))
            exp_val = _h(str(d.get("expected_value", "—")))
            severity = str(d.get("severity", "warning")).lower()
            if severity == "blocker":
                sev_badge = "<span class='badge danger'>🔴 Blocker</span>"
            elif severity == "warning":
                sev_badge = "<span class='badge warning'>🟡 Warning</span>"
            elif severity == "info":
                sev_badge = "<span class='badge info'>ℹ️ Info</span>"
            else:
                sev_badge = f"<span class='badge warning'>{_h(severity.title())}</span>"

            rationale = _h(str(d.get("rationale", "")))
            citation = str(d.get("citation", "")).strip()
            citation_url = str(d.get("citation_url", "")).strip()
            citation_html = ""
            if citation:
                c_lbl = _h(citation)
                if citation_url:
                    citation_html = (
                        f"<div style='margin-top:.3rem;font-size:.75rem'>"
                        f"<a href='{_h(citation_url)}' target='_blank' rel='noopener noreferrer' "
                        f"style='color:var(--primary);text-decoration:underline'>📖 {c_lbl}</a></div>"
                    )
                else:
                    citation_html = f"<div style='margin-top:.3rem;font-size:.75rem;color:var(--text-muted)'>📖 {c_lbl}</div>"

            drift_rows.append(
                f"<tr>"
                f"<td><b>{setting_name}</b><br><code style='font-size:.75rem;color:var(--text-muted)'>{attr}</code></td>"
                f"<td><code style='font-size:.85rem;color:var(--danger,#dc2626);font-weight:600'>{cur_val}</code></td>"
                f"<td><code style='font-size:.85rem;color:var(--success,#16a34a);font-weight:600'>{exp_val}</code></td>"
                f"<td>{sev_badge}</td>"
                f"<td><div style='font-size:.85rem;color:var(--text-muted)'>{rationale}</div>{citation_html}</td>"
                f"</tr>"
            )

        drift_table_html = (
            f"<div style='margin-bottom:1.25rem'>"
            f"<div style='font-size:.9rem;font-weight:700;color:var(--danger,#dc2626);margin-bottom:.5rem'>"
            f"⚠️ Drifted Settings ({len(drifts)}) — Remediation Recommended for VCF 9.1 / vSAN ESA"
            f"</div>"
            f"<table style='width:100%;border-collapse:collapse'>"
            f"<thead><tr>"
            f"<th style='width:22%'>Setting Name</th>"
            f"<th style='width:15%'>Current Value</th>"
            f"<th style='width:18%'>Recommended Baseline</th>"
            f"<th style='width:12%'>Severity</th>"
            f"<th>VMware Best Practice Rationale</th>"
            f"</tr></thead><tbody>"
            f"{''.join(drift_rows)}"
            f"</tbody></table></div>"
        )
    else:
        drift_table_html = (
            "<div style='background:rgba(22,163,74,0.1);border-left:3px solid var(--success,#16a34a);padding:.6rem 1rem;border-radius:4px;margin-bottom:1rem'>"
            "<strong>🟢 100% Compliant:</strong> All BIOS settings comply with Broadcom VCF 9.1 and vSAN ESA golden performance baselines."
            "</div>"
        )

    compliant_rules = [r for r in rules if r.get("status") == "compliant"]
    compliant_table_html = ""
    if compliant_rules:
        comp_rows = []
        for r in compliant_rules:
            attr = _h(str(r.get("attribute", "")))
            setting_name = _h(str(r.get("setting_name", attr)))
            cur_val = _h(str(r.get("current_value", "—")))
            exp_val = _h(str(r.get("expected_value", "—")))
            rationale = _h(str(r.get("rationale", "")))
            citation = str(r.get("citation", "")).strip()
            citation_url = str(r.get("citation_url", "")).strip()
            citation_html = ""
            if citation:
                c_lbl = _h(citation)
                if citation_url:
                    citation_html = (
                        f"<div style='margin-top:.3rem;font-size:.75rem'>"
                        f"<a href='{_h(citation_url)}' target='_blank' rel='noopener noreferrer' "
                        f"style='color:var(--primary);text-decoration:underline'>📖 {c_lbl}</a></div>"
                    )
                else:
                    citation_html = f"<div style='margin-top:.3rem;font-size:.75rem;color:var(--text-muted)'>📖 {c_lbl}</div>"

            comp_rows.append(
                f"<tr>"
                f"<td><b>{setting_name}</b><br><code style='font-size:.75rem;color:var(--text-muted)'>{attr}</code></td>"
                f"<td><code style='font-size:.85rem;color:var(--success,#16a34a)'>{cur_val}</code></td>"
                f"<td><code style='font-size:.85rem'>{exp_val}</code></td>"
                f"<td><span class='badge success'>🟢 Compliant</span></td>"
                f"<td><div style='font-size:.85rem;color:var(--text-muted)'>{rationale}</div>{citation_html}</td>"
                f"</tr>"
            )

        open_attr = " open" if not drifts else ""
        compliant_table_html = (
            f"<details style='margin-top:.75rem'{open_attr}>"
            f"<summary style='font-size:.85rem;cursor:pointer;color:var(--primary);font-weight:600'>"
            f"✓ Compliant Golden Baseline Settings ({len(compliant_rules)} of {total_rules}) ▾"
            f"</summary>"
            f"<div style='margin-top:.5rem'>"
            f"<table style='width:100%;border-collapse:collapse'>"
            f"<thead><tr>"
            f"<th style='width:22%'>Setting Name</th>"
            f"<th style='width:15%'>Observed Value</th>"
            f"<th style='width:18%'>Golden Baseline</th>"
            f"<th style='width:12%'>Status</th>"
            f"<th>Rationale</th>"
            f"</tr></thead><tbody>"
            f"{''.join(comp_rows)}"
            f"</tbody></table></div></details>"
        )

    scorecard_title = "VCF 9.1 BIOS Golden Baseline Scorecard"
    if "cisco" in badge.lower():
        scorecard_title = "Cisco UCS VCF 9.1 Golden Baseline Scorecard"
    elif "lenovo" in badge.lower():
        scorecard_title = "Lenovo ThinkSystem VCF 9.1 Golden Baseline Scorecard"
    elif "dell" in badge.lower():
        scorecard_title = "Dell PowerEdge VCF 9.1 Golden Baseline Scorecard"

    catalog_callout = ""
    catalog_drift = next((d for d in drifts if d.get("attribute") == "BiosVersionCatalogAlignment"), None)
    if catalog_drift:
        catalog_callout = (
            f"<div style='background:rgba(202,138,4,0.1);border-left:3px solid var(--warning,#ca8a04);"
            f"padding:.75rem 1rem;border-radius:4px;margin-bottom:1rem;font-size:.85rem'>"
            f"<strong>⚠️ 17G AMD vSAN Ready Node Solution Catalog Advisory:</strong> "
            f"Installed BIOS <code>{_h(str(catalog_drift.get('current_value')))}</code> diverges from the certified Dell vSAN Ready Node Firmware Catalog baseline "
            f"(<code>{_h(str(catalog_drift.get('expected_value')))}</code>). While Dell pushes cumulative bare-metal patches to general support pages, "
            f"VMware and Dell hold vSAN catalog releases until full cluster I/O qualification. Flashing standalone BIOS ahead of catalog qualification can trigger "
            f"vLCM/vSphere Health Non-Compliance, PCIe ACS timing variations, and known 17G AMD AGESA warm-reboot memory initialization lockups ('Please wait while the system is initializing...'). "
            f"For production vSAN Ready Nodes, stay on or revert to v1.6.4."
            f"</div>"
        )

    proxy_tuning_tip = ""
    power_drift_attrs = {"SysProfile", "PcieAspm", "ProcPwrPerf", "ProcCStates", "ProcC1E", "ApbDis", "DfCState"}
    has_power_drifts = any(d.get("attribute") in power_drift_attrs for d in drifts)
    if has_power_drifts and ("dell" in scorecard_title.lower() or "dell" in badge.lower()):
        proxy_tuning_tip = (
            "<div style='background:rgba(2,132,199,0.08);border-left:3px solid var(--info,#0284c7);"
            "padding:.6rem 1rem;border-radius:4px;margin-top:.75rem;margin-bottom:1rem;font-size:.83rem;color:var(--text-main)'>"
            "<strong>💡 Proxy Tuning Tip (Easy Button):</strong> "
            "In Dell PowerEdge BIOS (F2 System Setup → System BIOS → System Profile Settings), setting "
            "<b>System Profile = Performance Optimized (PerfOptimized)</b> automatically locks CPU Power Management to Maximum Performance (MaxPerf), "
            "disables PCIe ASPM (L0sL1Off), disables Processor C-States, and disables C1E in a single configuration step without needing to manually tune each child knob."
            "</div>"
        )

    return (
        f"<details class=\"accordion\" open style=\"margin-bottom:1.5rem\">"
        f"<summary>"
        f"<div>📋 {scorecard_title} &nbsp;{badge}</div>"
        f"<span style=\"font-size:.85rem;color:var(--primary)\">Collapse Scorecard &#9652;</span>"
        f"</summary>"
        f"<div class=\"accordion-body\">"
        f"{perf_guide_hdr}"
        f"{stats_html}"
        f"{catalog_callout}"
        f"{drift_table_html}"
        f"{proxy_tuning_tip}"
        f"{compliant_table_html}"
        f"</div></details>"
    )


def render_bios_perf_card_and_accordion(
    bios_info: Dict[str, Any],
    sys_info: Dict[str, Any],
    bios_eval: Dict[str, Any],
) -> Tuple[str, str]:
    """Render BIOS & Performance summary card and combined BIOS Performance Settings accordion."""
    bios_info = bios_info or {}
    bios_eval = bios_eval or {}
    sys_info = sys_info or {}

    mem_ras_modes = bios_info.get("memory_ras", [])
    cpu_power_modes = bios_info.get("cpu_power", [])

    if not cpu_power_modes:
        _cpu_pwr_badge = "<span class=\"badge info\">ℹ️ Not exposed by BMC</span>"
        _cpu_pwr_note  = "CPU performance profile not returned via Redfish BIOS attributes."
    else:
        _cpu_has_warning = any(r["badge"] in ("danger", "warning") for r in cpu_power_modes)
        if _cpu_has_warning:
            _cpu_pwr_badge = "<span class=\"badge warning\">🟡 Review Required</span>"
            _cpu_worst = next(r for r in cpu_power_modes if r["badge"] in ("danger", "warning"))
            _cpu_pwr_note = f"{_cpu_worst['label']} — {_cpu_worst['note']}"
        else:
            _cpu_pwr_badge = "<span class=\"badge success\">🟢 Performance Mode</span>"
            _first = cpu_power_modes[0] if cpu_power_modes else {}
            _cpu_pwr_note  = _first.get("label", "Performance-oriented profile detected.")

    _default_bios_badge = '<span class="badge info">ℹ️ N/A</span>'
    _baseline_card_row = ""
    baseline_drift = (
        bios_info.get("bios_baseline_drift")
        or bios_info.get("hpe_baseline_drift")
        or bios_info.get("cisco_baseline_drift")
        or bios_info.get("lenovo_baseline_drift")
        or bios_info.get("dell_baseline_drift")
        or bios_info.get("generic_baseline_drift")
    )
    if isinstance(baseline_drift, dict) and baseline_drift:
        _b_badge = baseline_drift.get("badge", "")
        _baseline_card_row = (
            f"<div style='border-top:1px solid var(--border);padding-top:.4rem;margin-top:.4rem'>"
            f"<span style='font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;"
            f"color:var(--text-muted);font-weight:600'>VCF 9.1 Baseline Drift</span><br>"
            f"<div style='margin-top:.2rem'>{_b_badge}</div>"
            f"</div>"
        )

    _bios_perf_card_html = (
        f"<div class='card'>"
        f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
        f"<h3 style='margin:0'>BIOS &amp; Performance</h3>"
        f"<a href='#tab-bios' data-jump-tab='tab-bios' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to BIOS section'>Details &rarr;</a>"
        f"</div>"
        f"<div style='margin-bottom:.35rem'>{bios_eval.get('badge', _default_bios_badge)}</div>"
        f"<p style='font-size:.85rem;color:var(--text-muted);margin:0 0 .5rem'>"
        f"v{_h(str(sys_info.get('bios_version', '?')))} "
        f"({_h(str(sys_info.get('bios_release_date', 'N/A')))})</p>"
        f"<div style='border-top:1px solid var(--border);padding-top:.4rem'>"
        f"<span style='font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;"
        f"color:var(--text-muted);font-weight:600'>CPU Performance Profile</span><br>"
        f"<div style='margin-top:.2rem'>{_cpu_pwr_badge}</div>"
        f"<p style='font-size:.8rem;color:var(--text-muted);margin:.2rem 0 0'>{_cpu_pwr_note}</p>"
        f"</div>"
        f"{_baseline_card_row}"
        f"<div style='margin-top:.5rem;border-top:1px solid var(--border);padding-top:.4rem'>"
        f"<a href='#tab-bios' data-jump-tab='tab-bios' class='btn-link tab-jump-link' style='font-size:.78rem'>"
        f"Full details in BIOS tab &#8599;</a></div>"
        f"</div>"
    )

    def _build_bios_rows(modes):
        parts = []
        for r in modes:
            bdg = r["badge"]
            note_str = _h(r['note'])
            doc_url = r.get("doc_url")
            doc_label = r.get("doc_label")
            if doc_url and doc_label:
                note_str += f" &nbsp;·&nbsp; <a href='{doc_url}' target='_blank' class='btn-link' style='font-size:.78rem'>{_h(doc_label)}</a>"
            parts.append(
                f"<tr>"
                f"<td>{_h(r['feature'])}</td>"
                f"<td><span class='badge {bdg}'>{_h(r['label'])}</span></td>"
                f"<td style='font-size:.85rem;color:var(--text-muted)'>{note_str}</td>"
                f"<td><code style='font-size:.8rem'>{_h(r['raw_key'])}={_h(r['raw_val'])}</code></td>"
                f"</tr>"
            )
        return "".join(parts)

    _tbl_hdr = ("<table><thead><tr>"
                "<th>BIOS Feature</th><th>Setting Detected</th>"
                "<th>VCF / vSAN Impact</th><th>Raw BIOS Key</th>"
                "</tr></thead><tbody>")

    _bios_sections = []
    if cpu_power_modes:
        _bios_sections.append(
            "<tr><td colspan='4' style='background:var(--bg-card);font-weight:700;"
            "font-size:.85rem;color:var(--text-muted);padding:.4rem .75rem'>"
            "⚡ CPU Performance Profile</td></tr>"
            + _build_bios_rows(cpu_power_modes)
        )
    if mem_ras_modes:
        _bios_sections.append(
            "<tr><td colspan='4' style='background:var(--bg-card);font-weight:700;"
            "font-size:.85rem;color:var(--text-muted);padding:.4rem .75rem'>"
            "🛡️ Memory RAS / Protection</td></tr>"
            + _build_bios_rows(mem_ras_modes)
        )

    vendor_raw = str(sys_info.get("vendor") or "").upper()
    pending_attrs = bios_info.get("pending_attributes") or {}
    is_hpe = "HPE" in vendor_raw or "HEWLETT" in vendor_raw or any(k in pending_attrs for k in ("Sriov", "PowerRegulator"))

    hpe_extras = _hpe_allowlisted_bios_rows(pending_attrs) if is_hpe else []
    if hpe_extras:
        reboot_banner = ""
        if bios_info.get("bios_pending_reboot"):
            reboot_banner = (
                "<tr><td colspan='4' style='background:rgba(202,138,4,0.12);color:#ca8a04;font-weight:600;"
                "padding:.4rem .75rem;border-left:3px solid #ca8a04'>"
                "⚠️ BIOS settings staged — reboot required to take effect</td></tr>"
            )
        _bios_sections.append(
            reboot_banner
            + "<tr><td colspan='4' style='background:var(--bg-card);font-weight:700;"
            "font-size:.85rem;color:var(--text-muted);padding:.4rem .75rem'>"
            "HPE Platform BIOS (allowlisted)</td></tr>"
            + _build_bios_rows(hpe_extras)
        )

    if _bios_sections:
        _combined_rows = "".join(_bios_sections)
        _ras_detail_section = (
            f"<details class=\"accordion\" open style=\"margin-bottom:1.5rem\">"
            f"<summary>"
            f"<div>⚙️ BIOS Performance Settings &nbsp;{_cpu_pwr_badge}</div>"
            f"<span style=\"font-size:.85rem;color:var(--primary)\">Collapse BIOS Settings &#9652;</span>"
            f"</summary>"
            f"<div class=\"accordion-body\">"
            f"{_tbl_hdr}{_combined_rows}</tbody></table>"
            f"</div></details>"
        )
    else:
        _ras_detail_section = ""

    _baseline_scorecard = render_bios_baseline_scorecard(bios_info)
    _ras_detail_section = _baseline_scorecard + _ras_detail_section

    return _bios_perf_card_html, _ras_detail_section


def render_boot_order_card(sys_info: Dict[str, Any]) -> str:
    """Render UEFI / BIOS boot device order table and one-time boot override status card."""
    sys_info = sys_info or {}
    boot_mode = str(sys_info.get("boot_mode") or "Unknown")
    boot_target = str(sys_info.get("boot_target") or "None")
    boot_override = sys_info.get("boot_override") or {}
    is_override_active = bool(boot_override.get("is_active"))
    override_target = str(boot_override.get("target") or "None")
    override_enabled = str(boot_override.get("enabled") or "Disabled")
    override_mode = str(boot_override.get("mode") or "")

    # Boot mode badge
    if "uefi" in boot_mode.lower():
        mode_badge = "<span class='badge success'>🟢 UEFI Boot</span>"
    elif "legacy" in boot_mode.lower() or "bios" in boot_mode.lower():
        mode_badge = "<span class='badge danger'>🔴 Legacy BIOS Boot (Unsupported)</span>"
    else:
        mode_badge = f"<span class='badge info'>ℹ️ {_h(boot_mode)}</span>"

    # Override status badge
    if is_override_active:
        override_text = f"Active: {override_target}"
        if override_enabled and override_enabled.lower() not in ("disabled", "enabled", "none"):
            override_text += f" ({override_enabled})"
        if override_mode:
            override_text += f" [{override_mode}]"
        override_badge = f"<span class='badge warning'>⚠️ One-Time Override {_h(override_text)}</span>"
    else:
        override_badge = "<span class='badge success'>🟢 Standard Boot Order (No Override)</span>"

    boot_order_details = sys_info.get("boot_order_details") or []
    boot_order = sys_info.get("boot_order") or []

    rows = []
    if boot_order_details:
        for idx, opt in enumerate(boot_order_details, start=1):
            opt_id = opt.get("id") or f"Boot{idx:04d}"
            opt_name = opt.get("name") or opt.get("raw_name") or opt_id
            is_enabled = opt.get("enabled", True)
            is_current = opt.get("is_current", False) or (idx == 1 and not is_override_active)
            status_badge = "<span class='badge success' style='font-size:.72rem'>Enabled</span>" if is_enabled else "<span class='badge muted' style='font-size:.72rem'>Disabled</span>"

            active_tag = ""
            if is_override_active and override_target.lower() in opt_name.lower():
                active_tag = " &nbsp;<span class='badge warning' style='font-size:.7rem'>⚡ Active Override</span>"
            elif is_current and not is_override_active:
                active_tag = " &nbsp;<span class='badge success' style='font-size:.7rem'>✓ Current Target</span>"

            uefi_path = opt.get("uefi_path") or ""
            uefi_path_cell = f"<code style='font-size:.75rem;word-break:break-all'>{_h(uefi_path)}</code>" if uefi_path else "<span style='color:var(--text-muted);font-size:.75rem'>—</span>"

            rows.append(
                f"<tr>"
                f"<td style='text-align:center;font-weight:700'>{idx}</td>"
                f"<td><code style='font-size:.8rem'>{_h(opt_id)}</code></td>"
                f"<td><strong>{_h(opt_name)}</strong>{active_tag}</td>"
                f"<td>{status_badge}</td>"
                f"<td>{uefi_path_cell}</td>"
                f"</tr>"
            )
    elif boot_order:
        for idx, b_id in enumerate(boot_order, start=1):
            is_active = (idx == 1 and not is_override_active)
            active_tag = " &nbsp;<span class='badge success' style='font-size:.7rem'>✓ Primary Target</span>" if is_active else ""
            rows.append(
                f"<tr>"
                f"<td style='text-align:center;font-weight:700'>{idx}</td>"
                f"<td><code style='font-size:.8rem'>{_h(str(b_id))}</code></td>"
                f"<td><strong>{_h(str(b_id))}</strong>{active_tag}</td>"
                f"<td><span class='badge info' style='font-size:.72rem'>Configured</span></td>"
                f"<td><span style='color:var(--text-muted);font-size:.75rem'>—</span></td>"
                f"</tr>"
            )
    else:
        # Fallback if no boot order list is present
        target_disp = boot_target if boot_target and boot_target.lower() not in ("none", "n/a") else "Default UEFI Device Path"
        rows.append(
            f"<tr>"
            f"<td style='text-align:center;font-weight:700'>1</td>"
            f"<td><code style='font-size:.8rem'>Default</code></td>"
            f"<td><strong>{_h(target_disp)}</strong> &nbsp;<span class='badge success' style='font-size:.7rem'>✓ Detected Boot Target</span></td>"
            f"<td><span class='badge success' style='font-size:.72rem'>Active</span></td>"
            f"<td><span style='color:var(--text-muted);font-size:.75rem'>—</span></td>"
            f"</tr>"
        )

    rows_html = "".join(rows)

    return (
        f"<details class=\"accordion\" open style=\"margin-bottom:1.5rem\">"
        f"<summary>"
        f"<div>🥾 Boot Configuration &amp; Device Order &nbsp;{mode_badge} &nbsp;{override_badge}</div>"
        f"<span style=\"font-size:.85rem;color:var(--primary)\">Collapse Boot Details &#9652;</span>"
        f"</summary>"
        f"<div class=\"accordion-body\">"
        f"<div style='display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;margin-bottom:.75rem;padding:.5rem .75rem;background:var(--bg-card);border-radius:6px;border:1px solid var(--border)'>"
        f"<div><span style='font-size:.75rem;text-transform:uppercase;color:var(--text-muted);font-weight:600'>Primary Boot Target:</span> <strong style='font-size:.9rem'>{_h(boot_target)}</strong></div>"
        f"<div><span style='font-size:.75rem;text-transform:uppercase;color:var(--text-muted);font-weight:600'>Boot Mode:</span> {mode_badge}</div>"
        f"<div><span style='font-size:.75rem;text-transform:uppercase;color:var(--text-muted);font-weight:600'>One-Time Override:</span> {override_badge}</div>"
        f"</div>"
        f"<table style='width:100%;font-size:.85rem'>"
        f"<thead><tr>"
        f"<th style='width:45px;text-align:center'>#</th>"
        f"<th style='width:120px'>Boot Option ID</th>"
        f"<th>Device / Boot Target</th>"
        f"<th style='width:100px'>State</th>"
        f"<th>UEFI Device Path</th>"
        f"</tr></thead>"
        f"<tbody>{rows_html}</tbody>"
        f"</table>"
        f"</div>"
        f"</details>"
    )


def render_security_card_and_accordion(
    sys_info: Dict[str, Any],
    bios_info: Dict[str, Any],
    bios_eval: Dict[str, Any],
    cpu_info: Dict[str, Any],
    secure_boot: Dict[str, Any],
    bmc_firmware: Dict[str, Any],
    bmc_sec_cfg: Dict[str, Any],
    data: Dict[str, Any],
    page_salt: str,
) -> Tuple[str, str, str, str, str]:
    """Render security card and security posture accordion, return (security_card_html, security_accordion, tpm_badge_raw, sb_badge, spectre_badge_html)."""
    bios_info = bios_info or {}
    bios_eval = bios_eval or {}
    sys_info = sys_info or {}
    cpu_info = cpu_info or {}
    secure_boot = secure_boot or {}
    bmc_firmware = bmc_firmware or {}
    bmc_sec_cfg = bmc_sec_cfg or {}

    side_channel_modes = bios_info.get("side_channel", [])
    _ht = cpu_info.get("ht_enabled")
    _vendor_up_sc = str(sys_info.get("vendor") or "").upper()
    _adv_url_sc, _adv_label_sc = next(
        ((u, l) for k, (u, l) in _VENDOR_SIDE_CHANNEL_LINKS.items() if k in _vendor_up_sc),
        ("https://www.broadcom.com/support/security-center", "Broadcom Security Center")
    )

    _spectre_badge_html = bios_eval.get("spectre_badge", "")
    _spectre_no_baseline = "<span class='badge info'>\u2139\ufe0f No baseline</span>"
    _cve_tier_int = bios_eval.get("cve_tier", -1)
    _cve_tier_label = bios_eval.get("cve_tier_label", "")
    _cve_tier_badge_cls = bios_eval.get("cve_tier_badge", "info")
    _cve_tier_desc = bios_eval.get("cve_tier_desc", "")
    _bios_rel_date = sys_info.get("bios_release_date", "N/A")
    _bmc_fw_badge = bmc_firmware.get("badge", "<span class='badge info'>ℹ️ N/A</span>")
    _bmc_fw_ver   = _h(str(bmc_firmware.get("bmc_fw_version", "N/A")))
    _bmc_model_lbl = _h(str(bmc_firmware.get("bmc_model", "BMC")))
    _sb_badge = secure_boot.get("badge", "<span class='badge info'>ℹ️ Secure Boot: Not Exposed</span>")
    _vendor_for_adv = str(sys_info.get("vendor") or "").upper()
    _bios_adv_url, _bios_adv_label = next(
        ((u, l) for k, (u, l) in _VENDOR_SIDE_CHANNEL_LINKS.items() if k in _vendor_for_adv),
        ("", "")
    )

    if _bios_rel_date not in ("N/A", "Unknown", "") and _cve_tier_int >= 0:
        _tier_rows = ""
        for _tc, _ti, _tl, _tcls, _tdesc in _CVE_TIERS:
            _met = "✓" if _ti <= _cve_tier_int else "✗"
            _met_color = "var(--success)" if _ti <= _cve_tier_int else "var(--danger)"
            _tier_rows += (
                f"<tr><td style='color:{_met_color};font-weight:700'>{_met}</td>"
                f"<td>Tier {_ti}</td><td>{_h(_tl)}</td>"
                f"<td style='font-size:.78rem;color:var(--text-muted)'>{_h(_tdesc[:80])}{'…' if len(_tdesc)>80 else ''}</td></tr>"
            )
        _cve_table_html = (
            f"<details style='margin:.4rem 0 0'><summary style='font-size:.82rem;cursor:pointer;"
            f"color:var(--primary)'>CVE Coverage Detail ▾</summary>"
            f"<table style='width:100%;font-size:.8rem;margin-top:.4rem'>"
            f"<thead><tr><th></th><th>Tier</th><th>Coverage</th><th>Description</th></tr></thead>"
            f"<tbody>{_tier_rows}</tbody></table></details>"
        )
    else:
        _cve_table_html = ""

    _sec_tbl_hdr = (
        "<table style='width:100%;border-collapse:collapse'>"
        "<thead><tr>"
        "<th style='width:220px'>Security Check</th><th>Status</th><th>Detail</th>"
        "</tr></thead><tbody>"
    )
    _tpm_badge = sys_info.get("tpm_status_badge", "<span class='badge info'>ℹ️ Unknown</span>")
    _scan_data = data or {}
    _is_latency = host_has_redfish_latency(_scan_data)
    _latest_bmc_fw = bmc_firmware.get("bmc_fw_eval", {}).get("latest_version", "")
    _bmc_latency_note = ""
    if _is_latency:
        _latest_tag = f" to v{_h(_latest_bmc_fw)}" if (_latest_bmc_fw and _latest_bmc_fw != "N/A") else ""
        _bmc_latency_note = f" &nbsp;<span class='badge warning' style='font-size:.75rem'>⚠️ API Latency/Timeouts — Recommend {_bmc_model_lbl} Upgrade{_latest_tag}</span>"

    _sec_rows = (
        f"<tr><td><b>TPM 2.0</b></td><td>{_tpm_badge}</td>"
        f"<td style='font-size:.85rem;color:var(--text-muted)'>Required for vSphere 9.1 &amp; VCF security baselines</td></tr>"
        f"<tr><td><b>Secure Boot</b></td><td>{_sb_badge}</td>"
        f"<td style='font-size:.85rem;color:var(--text-muted)'>Recommended for VCF 9.1 hardening baseline</td></tr>"
        f"<tr><td><b>BIOS Spectre Microcode</b></td><td>{_spectre_badge_html if _spectre_badge_html else _spectre_no_baseline}</td>"
        f"<td style='font-size:.85rem;color:var(--text-muted)'>"
        f"Min required: v{_h(str(bios_eval.get('latest_version', 'N/A')))} &nbsp;|&nbsp; Installed: v{_h(str(sys_info.get('bios_version', '?')))} ({_h(_bios_rel_date)})"
        f"{_cve_table_html}</td></tr>"
        f"<tr><td><b>BMC Firmware</b></td><td>{_bmc_fw_badge}</td>"
        f"<td style='font-size:.85rem;color:var(--text-muted)'><b>{_bmc_model_lbl}</b> v{_bmc_fw_ver}{_bmc_latency_note}</td></tr>"
    )

    baseline_drift = (
        bios_info.get("bios_baseline_drift")
        or bios_info.get("hpe_baseline_drift")
        or bios_info.get("cisco_baseline_drift")
        or bios_info.get("lenovo_baseline_drift")
        or bios_info.get("dell_baseline_drift")
        or bios_info.get("generic_baseline_drift")
    )
    if isinstance(baseline_drift, dict) and baseline_drift:
        _b_badge = baseline_drift.get("badge", "")
        _d_cnt = baseline_drift.get("drift_count", 0)
        _c_pct = baseline_drift.get("compliance_pct", 100.0)
        _sec_rows += (
            f"<tr><td><b>BIOS Golden Baseline Drift</b></td>"
            f"<td>{_b_badge}</td>"
            f"<td style='font-size:.85rem;color:var(--text-muted)'>"
            f"VCF 9.1 performance baseline: {_c_pct}% compliant ({_d_cnt} drift(s) detected) &nbsp;·&nbsp; "
            f"<a href='#tab-bios' data-jump-tab='tab-bios' class='btn-link tab-jump-link' style='font-size:.78rem'>View Scorecard in BIOS Tab &rarr;</a>"
            f"</td></tr>"
        )

    if _cve_tier_int >= 0 and _bios_rel_date not in ("N/A", "Unknown", ""):
        _sec_rows += (
            f"<tr><td><b>CVE Coverage Tier</b></td>"
            f"<td><span class='badge {_cve_tier_badge_cls}'>Tier {_cve_tier_int}: {_h(_cve_tier_label)}</span></td>"
            f"<td style='font-size:.85rem;color:var(--text-muted)'>{_h(_cve_tier_desc[:120])}{'…' if len(_cve_tier_desc)>120 else ''}</td></tr>"
        )

    if side_channel_modes:
        _sec_rows += (
            "<tr><td colspan='3' style='background:var(--bg-card);font-weight:700;"
            "font-size:.82rem;color:var(--text-muted);padding:.4rem .75rem'>"
            "BIOS Side-Channel Attributes (via Redfish)</td></tr>"
        )
        for _r in side_channel_modes:
            _r_badge = _r["badge"]
            _sec_rows += (
                f"<tr><td style='padding-left:1.1rem'>{_h(_r['feature'])}</td>"
                f"<td><span class='badge {_r_badge}'>{_h(_r['label'])}</span></td>"
                f"<td style='font-size:.85rem;color:var(--text-muted)'>{_h(_r.get('note', ''))}</td></tr>"
            )
        if _ht is False:
            _sec_rows += (
                "<tr><td colspan='3' style='font-size:.82rem;color:var(--text-muted);"
                "padding:.35rem .75rem;background:var(--sec-muted-bg,#f8fafc)'>"
                "ℹ️ <b>Hyperthreading Disabled:</b> Logical processor multi-threading is disabled in BIOS.</td></tr>"
            )
        elif _ht is True:
            _sec_rows += (
                "<tr><td colspan='3' style='font-size:.82rem;color:var(--text-muted);"
                "padding:.35rem .75rem;background:var(--sec-muted-bg,#f8fafc)'>"
                "ℹ️ <b>Hyperthreading Enabled:</b> Logical processor multi-threading is active.</td></tr>"
            )
    else:
        _sec_rows += (
            "<tr><td colspan='3' style='font-size:.82rem;color:var(--text-muted);"
            "padding:.35rem .75rem;background:var(--sec-muted-bg,#f8fafc)'>"
            "ℹ️ BIOS side-channel attributes not exposed via Redfish for this OEM — "
            "version-based assessment only. "
            + (f"<a href='{_adv_url_sc}' target='_blank'>{_adv_label_sc} ↗</a>" if _adv_url_sc else "")
            + "</td></tr>"
        )

    _scan_data = data or {}
    bmc_sec_audit = _scan_data.get("bmc_security_audit") or {}
    _findings = bmc_sec_audit.get("findings") or []
    _findings_by_id = {
        f.get("control_id"): f
        for f in _findings
        if isinstance(f, dict) and f.get("control_id")
    }

    _oob_checks = bmc_sec_cfg.get("checks", [])
    _legacy_hdr_text = (
        "Legacy BMC Security Checks (Compatibility Reference — Normalized Audit Findings Below Take Precedence)"
        if _findings
        else "BMC / OOB Security Hardening (via Redfish NetworkProtocol &amp; AccountService)"
    )
    _sec_rows += (
        f"<tr><td colspan='3' style='background:var(--bg-card);font-weight:700;"
        f"font-size:.82rem;color:var(--text-muted);padding:.4rem .75rem'>"
        f"{_legacy_hdr_text}</td></tr>"
    )
    bmc_net_proto = data.get("bmc_net_proto") or {}
    _vmedia_mounted = bmc_net_proto.get("virtual_media_inserted", False)
    _td_detected = bmc_net_proto.get("time_drift_detected", False)
    _td_sec = bmc_net_proto.get("time_drift_seconds")

    if _td_detected and _td_sec is not None:
        _abs_d = abs(_td_sec)
        _m = _abs_d // 60
        _s = _abs_d % 60
        _d_str = f"{_m}m {_s}s" if _m > 0 else f"{_s}s"
        _offset_str = bmc_net_proto.get("datetime_local_offset") or ""
        _is_utc = bmc_net_proto.get("is_utc", True)
        _tz_detail = f" (includes local offset {_offset_str})" if (not _is_utc and _offset_str and _offset_str != "Unknown") else ""
        _sec_rows += (
            f"<tr style='background:var(--tint-danger-bg,#fef2f2)'>"
            f"<td style='padding-left:1.1rem;font-weight:600;color:var(--danger,#dc2626)'>⚠️ Time Skew Alert</td>"
            f"<td><span class='badge danger'>Time Drift</span></td>"
            f"<td style='font-size:.85rem;color:var(--tint-danger-text,#991b1b);font-weight:600'>"
            f"BMC clock is skewed by {_d_str}{_tz_detail} relative to scan time. Correct BMC NTP configuration and verify UTC timezone before VCF deployment.</td></tr>"
        )

    if _vmedia_mounted:
        _sec_rows += (
            "<tr><td style='padding-left:1.1rem'>Virtual Media (ISO)</td>"
            "<td><span class='badge warning'>Mounted</span></td>"
            "<td style='font-size:.85rem;color:var(--text-muted)'>⚠️ Virtual ISO image currently mounted on BMC. Dismount before automated VCF LCM update.</td></tr>"
        )

    _LEGACY_MAP = {
        "syslog": "C07",
        "http": "C01",
        "telnet": "C23",
        "snmp": "C24",
        "ipmi": "C21",
        "lockout": "C43",
        "password": "C41",
        "timeout": "C37",
    }

    if _oob_checks:
        for _oc in _oob_checks:
            _oc_bdg = _oc.get("badge", "info")
            _oc_feat = str(_oc.get("feature", ""))
            _matched_cid = None
            for _k, _cid in _LEGACY_MAP.items():
                if _k in _oc_feat.lower():
                    _matched_cid = _cid
                    break

            if _matched_cid and _matched_cid in _findings_by_id:
                _feat_lbl = f"{_h(_oc_feat)} <span style='font-size:.72rem;color:var(--text-muted);font-weight:normal'>[Legacy &mdash; {_matched_cid} authoritative]</span>"
                _cf = _findings_by_id[_matched_cid]
                _cf_stat = _cf.get("status", "")
                _note_extra = f"<span style='font-size:.78rem;color:var(--primary);display:block;margin-top:.2rem'>ℹ️ Normalized audit finding {_matched_cid} ({_h(_cf_stat)}) is authoritative.</span>"
                _sec_rows += (
                    f"<tr><td style='padding-left:1.1rem'>{_feat_lbl}</td>"
                    f"<td><span class='badge {_oc_bdg}'>{_h(_oc['label'])}</span></td>"
                    f"<td style='font-size:.85rem;color:var(--text-muted)'>{_h(_oc['note'])}{_note_extra}</td></tr>"
                )
            else:
                _sec_rows += (
                    f"<tr><td style='padding-left:1.1rem'>{_h(_oc_feat)}</td>"
                    f"<td><span class='badge {_oc_bdg}'>{_h(_oc['label'])}</span></td>"
                    f"<td style='font-size:.85rem;color:var(--text-muted)'>{_h(_oc['note'])}</td></tr>"
                )
    else:
        # Fallback when detailed checks array is absent
        _offset_str = bmc_net_proto.get("datetime_local_offset") or "+00:00"
        _is_utc = bmc_net_proto.get("is_utc", True)
        _tz_badge = "success" if _is_utc else "warning"
        _tz_lbl = f"UTC Standard ({_offset_str})" if _is_utc else f"Non-UTC Offset ({_offset_str})"
        _tz_note = "BMC timezone is configured for UTC." if _is_utc else f"BMC uses local timezone offset {_offset_str}. Set to UTC for VCF."

        _ntp_active = bmc_net_proto.get("ntp_enabled")
        _ntp_servers = bmc_net_proto.get("ntp_servers") or []
        if _ntp_active and _ntp_servers:
            _ntp_bdg, _ntp_lbl, _ntp_note = "success", "Configured", f"NTP active with server(s): {', '.join(_h(s) for s in _ntp_servers[:3])}"
        elif _ntp_active:
            _ntp_bdg, _ntp_lbl, _ntp_note = "warning", "Enabled (No Servers)", "NTP enabled on BMC but no NTP servers configured."
        else:
            _ntp_bdg, _ntp_lbl, _ntp_note = "warning", "Disabled", "NTP disabled on BMC. Configure NTP servers to avoid time-skew issues in VCF."

        _dns_active = bmc_net_proto.get("dns_enabled")
        _dns_servers = bmc_net_proto.get("dns_servers") or []
        if _dns_servers:
            _dns_bdg, _dns_lbl, _dns_note = "success", "Configured", f"DNS name servers configured: {', '.join(_h(s) for s in _dns_servers[:2])}"
        elif _dns_active:
            _dns_bdg, _dns_lbl, _dns_note = "warning", "Enabled (No Servers)", "DNS enabled on BMC but no DNS servers configured."
        else:
            _dns_bdg, _dns_lbl, _dns_note = "info", "Not Configured", "DNS name servers are not configured on the BMC."

        _fallback_items = [
            ("BMC Remote Syslog", "info", "Not Exposed", "Remote syslog destination status not assessed."),
            ("BMC HTTP (Plaintext)", "info", "Not Exposed", "Plaintext HTTP access status not assessed."),
            ("BMC Telnet", "info", "Not Exposed", "Telnet protocol status not assessed."),
            ("SNMP", "info", "Not Exposed", "SNMP protocol configuration not assessed."),
            ("IPMI over LAN", "info", "Not Exposed", "IPMI over LAN status not assessed."),
            ("Account Lockout", "info", "Not Exposed", "Account lockout threshold not assessed."),
            ("Min Password Length", "info", "Not Exposed", "Minimum password length not assessed."),
            ("BMC Session Timeout", "info", "Not Exposed", "Session timeout not assessed."),
            ("NTP Server Configuration", _ntp_bdg, _ntp_lbl, _ntp_note),
            ("DNS Configuration", _dns_bdg, _dns_lbl, _dns_note),
            ("BMC Timezone", _tz_badge, _tz_lbl, _tz_note),
        ]
        for _f_name, _f_bdg, _f_lbl, _f_nt in _fallback_items:
            _matched_cid = None
            for _k, _cid in _LEGACY_MAP.items():
                if _k in _f_name.lower():
                    _matched_cid = _cid
                    break
            if _matched_cid and _matched_cid in _findings_by_id:
                _feat_lbl = f"{_h(_f_name)} <span style='font-size:.72rem;color:var(--text-muted);font-weight:normal'>[Legacy &mdash; {_matched_cid} authoritative]</span>"
                _cf = _findings_by_id[_matched_cid]
                _cf_stat = _cf.get("status", "")
                _note_extra = f"<span style='font-size:.78rem;color:var(--primary);display:block;margin-top:.2rem'>ℹ️ Normalized audit finding {_matched_cid} ({_h(_cf_stat)}) is authoritative.</span>"
                _sec_rows += (
                    f"<tr><td style='padding-left:1.1rem'>{_feat_lbl}</td>"
                    f"<td><span class='badge {_f_bdg}'>{_h(_f_lbl)}</span></td>"
                    f"<td style='font-size:.85rem;color:var(--text-muted)'>{_h(_f_nt)}{_note_extra}</td></tr>"
                )
            else:
                _sec_rows += (
                    f"<tr><td style='padding-left:1.1rem'>{_h(_f_name)}</td>"
                    f"<td><span class='badge {_f_bdg}'>{_h(_f_lbl)}</span></td>"
                    f"<td style='font-size:.85rem;color:var(--text-muted)'>{_h(_f_nt)}</td></tr>"
                )

    _sec_footer_row = (
        "<tr style='background:var(--sec-footer-bg,#f8fafc)'><td colspan='3' style='font-size:.82rem;"
        "padding:.45rem .75rem;border-top:1px solid var(--sec-footer-border,#e2e8f0);color:var(--text)'>"
        "📖 <b>Layer 2 (ESXi):</b> "
        "<a href='https://kb.vmware.com/s/article/330041' target='_blank' class='btn-link' style='font-weight:600'>Broadcom KB 330041 — "
        "ESXi Speculative Execution Mitigations ↗</a>"
        + (f" &nbsp;|&nbsp; <b>OEM Advisory:</b> <a href='{_bios_adv_url}' target='_blank' class='btn-link' style='font-weight:600'>{_h(_bios_adv_label)} ↗</a>" if _bios_adv_url else "")
        + "</td></tr>"
    )

    _all_sec_badges = [
        sys_info.get("tpm_status_badge", ""),
        _sb_badge,
        _spectre_badge_html,
        _bmc_fw_badge,
    ]
    if not _findings and bmc_sec_cfg.get("overall_badge"):
        _all_sec_badges.append(f"<span class='badge {bmc_sec_cfg.get('overall_badge')}'>oob</span>")

    _audit_fails = sum(1 for f in _findings if f.get("status") == "fail")
    _audit_unknowns = sum(1 for f in _findings if str(f.get("status", "")).startswith("unknown"))
    _audit_passes = sum(1 for f in _findings if f.get("status") == "pass")

    if _audit_fails > 0 or any("danger" in b for b in _all_sec_badges):
        _sec_summary_badge = "<span class='badge danger'>🔴 Security: Action Required</span>"
    elif any("warning" in b for b in _all_sec_badges):
        _sec_summary_badge = "<span class='badge warning'>🟡 Security: Review Recommended</span>"
    elif _audit_unknowns > 0:
        # Unknown MUST produce "partially assessed", NEVER "baseline met"!
        _sec_summary_badge = "<span class='badge info'>ℹ️ Security: Partially Assessed</span>"
    elif (_findings and all(f.get("status") in ("pass", "not_applicable") for f in _findings) and all("success" in b for b in _all_sec_badges if b)) or (not _findings and all("success" in b for b in _all_sec_badges if b) and "success" in bmc_sec_cfg.get("overall_badge", "")):
        _sec_summary_badge = "<span class='badge success'>🟢 Security: Baseline Met</span>"
    else:
        _sec_summary_badge = "<span class='badge info'>ℹ️ Security: Partially Assessed</span>"

    if _findings:
        if _audit_fails > 0:
            _bmc_sec_badge = f"<span class='badge danger' title='{_audit_fails} failed, {_audit_passes} passed, {_audit_unknowns} unknown controls'>🔴 {_audit_fails} Failed &middot; {_audit_passes} Passed</span>"
        elif _audit_unknowns > 0:
            _bmc_sec_badge = f"<span class='badge warning' title='{_audit_passes} passed, {_audit_unknowns} unknown controls'>🟡 {_audit_passes} Passed ({_audit_unknowns} Unknown)</span>"
        elif _audit_passes > 0:
            _bmc_sec_badge = f"<span class='badge success' title='All {_audit_passes} evaluated controls passed'>🟢 {_audit_passes} Passed (Baseline Met)</span>"
        else:
            _bmc_sec_badge = "<span class='badge info'>ℹ️ Partially Assessed</span>"
    elif bmc_sec_cfg.get("overall_badge"):
        _bmc_sec_badge = f"<span class='badge {bmc_sec_cfg.get('overall_badge')}'>oob</span>"
    else:
        _bmc_sec_badge = ""

    _tpm_badge_raw = sys_info.get("tpm_status_badge", "<span class='badge info'>ℹ️ Unknown</span>")
    if "success" in _tpm_badge_raw:
        if "1.2" in _tpm_badge_raw:
            _tpm_display_badge = "<span class='badge warning'>⚠️ TPM 1.2 — Upgrade Required for VCF 9.1</span>"
        else:
            _tpm_display_badge = "<span class='badge success'>🟢 TPM Configured</span>"
    else:
        _tpm_display_badge = _tpm_badge_raw

    _spectre_display = _spectre_badge_html or "<span class='badge info'>ℹ️ No Baseline</span>"
    _sec_card_items  = [_tpm_badge_raw, _sb_badge, (_spectre_badge_html or "")]
    if _audit_fails > 0 or any("danger" in b for b in _sec_card_items):
        _sec_card_worst = "danger"
    elif any("warning" in b for b in _sec_card_items):
        _sec_card_worst = "warning"
    elif _audit_unknowns > 0:
        _sec_card_worst = "info"
    elif all("success" in b for b in _sec_card_items if b):
        _sec_card_worst = "success"
    else:
        _sec_card_worst = "info"

    _sec_card_border = {
        "danger":  "border-color:var(--danger);border-width:2px",
        "warning": "border-color:var(--warning);border-width:2px",
        "success": "",
        "info":    "",
    }.get(_sec_card_worst, "")

    _boot_eval = sys_info.get("boot_eval") or evaluate_boot_mode(sys_info.get("boot_mode", ""))
    _boot_mode_badge = _boot_eval.get("badge", "<span class='badge info'>ℹ️ Unknown</span>")

    _bmc_audit_row = ""
    if _bmc_sec_badge:
        _bmc_audit_row = (
            f"<div>"
            f"<span style='font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;"
            f"color:var(--text-muted);font-weight:600'>BMC Security Posture</span><br>"
            f"<div style='margin-top:.15rem'>{_bmc_sec_badge}</div>"
            f"</div>"
        )

    _security_card_html = (
        f"<div class='card' style='{_sec_card_border}'>"
        f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem'>"
        f"<h3 style='margin:0'>Security</h3>"
        f"<a href='#tab-security' data-jump-tab='tab-security' class='btn-link tab-jump-link' style='font-size:.8rem;text-decoration:none' title='Jump to Security section'>Details &rarr;</a>"
        f"</div>"
        f"<div style='display:flex;flex-direction:column;gap:.45rem'>"
        f"<div>"
        f"<span style='font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;"
        f"color:var(--text-muted);font-weight:600'>TPM</span><br>"
        f"<div style='margin-top:.15rem'>{_tpm_display_badge}</div>"
        f"</div>"
        f"<div>"
        f"<span style='font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;"
        f"color:var(--text-muted);font-weight:600'>UEFI Boot Mode</span><br>"
        f"<div style='margin-top:.15rem'>{_boot_mode_badge}</div>"
        f"</div>"
        f"<div>"
        f"<span style='font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;"
        f"color:var(--text-muted);font-weight:600'>Secure Boot</span><br>"
        f"<div style='margin-top:.15rem'>{_sb_badge}</div>"
        f"</div>"
        f"<div>"
        f"<span style='font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;"
        f"color:var(--text-muted);font-weight:600'>Spectre / Meltdown Baseline</span><br>"
        f"<div style='margin-top:.15rem'>{_spectre_display}</div>"
        f"</div>"
        f"{_bmc_audit_row}"
        f"</div>"
        f"<div style='margin-top:.35rem;padding-top:.45rem;border-top:1px solid var(--border,#334155)'>"
        f"<a href='#tab-security' data-jump-tab='tab-security' class='btn-link tab-jump-link' "
        f"style='font-size:.8rem;font-weight:600;display:inline-flex;align-items:center;gap:.3rem'>"
        f"🛡️ View Security &amp; Hardening Details &rarr;</a>"
        f"</div>"
        f"</div>"
    )

    # Build Normalized Audit Findings Table
    _findings_table_html = ""
    if _findings:
        _p_cnt = sum(1 for f in _findings if f.get("status") == "pass")
        _f_cnt = sum(1 for f in _findings if f.get("status") == "fail")
        _u_cnt = sum(1 for f in _findings if str(f.get("status", "")).startswith("unknown"))
        _na_cnt = sum(1 for f in _findings if f.get("status") == "not_applicable")

        _pills = (
            f"<span class='badge success'>Pass: {_p_cnt}</span> &nbsp;"
            f"<span class='badge danger'>Fail: {_f_cnt}</span> &nbsp;"
            f"<span class='badge info'>Unknown: {_u_cnt}</span>"
            + (f" &nbsp;<span class='badge' style='background:var(--bg-card);color:var(--text-muted);border:1px solid var(--border-color)'>N/A: {_na_cnt}</span>" if _na_cnt else "")
        )

        _f_rows = ""
        _grouped: Dict[str, List[Dict[str, Any]]] = {g: [] for g in GROUP_ORDER}
        for f in _findings:
            if isinstance(f, dict):
                cid = str(f.get("control_id", ""))
                grp = get_control_group(cid)
                if grp not in _grouped:
                    _grouped[grp] = []
                _grouped[grp].append(f)

        for grp in GROUP_ORDER:
            grp_findings = _grouped.get(grp, [])
            if not grp_findings:
                continue
            grp_label = GROUP_LABELS.get(grp, grp.replace("_", " ").title())
            _f_rows += (
                f"<tr><td colspan='7' style='background:var(--bg-card);font-weight:700;"
                f"font-size:.82rem;color:var(--text-muted);padding:.45rem .75rem'>"
                f"{_h(grp_label)} ({len(grp_findings)})</td></tr>"
            )
            for f in grp_findings:
                cid = str(f.get("control_id", ""))
                title = get_control_title(cid)
                status = str(f.get("status", ""))
                expected = f.get("expected", "")
                observed = f.get("observed")
                reason_code = f.get("reason_code", "")
                evidence = f.get("evidence", [])

                s_badge = _finding_status_badge(status)
                obs_str = _format_observed(observed)
                exp_str = str(expected or "—")
                obs_exp_cell = (
                    f"<div><b>Obs:</b> {_h(obs_str)}</div>"
                    f"<div style='font-size:.78rem;color:var(--text-muted);margin-top:.15rem'><b>Exp:</b> {_h(exp_str)}</div>"
                )
                reason_clean = _format_reason(reason_code)

                ev_transports = sorted({
                    str(item.get("transport", "")).replace("_", " ").title()
                    for item in evidence if isinstance(item, dict) and item.get("transport")
                }) if evidence else []
                if ev_transports:
                    transport_str = ", ".join(ev_transports)
                else:
                    transport_str = get_control_transport(cid)

                confidence_str = get_control_confidence(cid)

                _f_rows += (
                    f"<tr>"
                    f"<td><b>{_h(cid)}</b></td>"
                    f"<td>{_h(title)}</td>"
                    f"<td>{s_badge}</td>"
                    f"<td>{obs_exp_cell}</td>"
                    f"<td style='font-size:.82rem;color:var(--text-muted)'>{_h(reason_clean)}</td>"
                    f"<td style='font-size:.82rem'>{_h(transport_str)}</td>"
                    f"<td style='font-size:.82rem'>{_h(confidence_str)}</td>"
                    f"</tr>"
                )

        _v_cand = sys_info.get("vendor") or ""
        if str(_v_cand).strip().lower() in ("", "generic", "unknown", "n/a", "none"):
            _v_cand = (bmc_sec_audit.get("vendor") if isinstance(bmc_sec_audit, dict) else "") or _v_cand
        _bmc_m_cand = bmc_firmware.get("bmc_model") or (_scan_data.get("bmc_firmware") or {}).get("bmc_model") or ""
        _hardening_btn = render_vendor_hardening_link(_v_cand, _bmc_m_cand)
        _explained_btn = render_controls_explained_link()

        _findings_table_html = (
            f"<div style='margin-top:1.5rem;margin-bottom:.5rem;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem'>"
            f"<div style='display:flex;align-items:center;gap:.65rem;flex-wrap:wrap'>"
            f"<h3 style='margin:0;font-size:1.05rem'>BMC Hardware Security Audit Findings</h3>"
            f"{_hardening_btn}"
            f"{_explained_btn}"
            f"</div>"
            f"<div>{_pills}</div>"
            f"</div>"
            f"<table class='data-table' style='width:100%;margin-top:.5rem'>"
            f"<thead><tr>"
            f"<th style='width:8%'>ID</th>"
            f"<th style='width:22%'>Control</th>"
            f"<th style='width:12%'>Status</th>"
            f"<th style='width:24%'>Observed / Expected</th>"
            f"<th style='width:16%'>Reason</th>"
            f"<th style='width:10%'>Transport</th>"
            f"<th style='width:8%'>Confidence</th>"
            f"</tr></thead><tbody>"
            f"{_f_rows}"
            f"</tbody></table>"
        )

    # Platform Attestation & Supply Chain Verification (SPDM 1.2 / Dell SCV / Cisco SUDI)
    _sec_ev = _scan_data.get("bmc_security_evidence") or {}
    _caps = _sec_ev.get("capabilities") or {}
    _scv = _caps.get("dell_scv")
    _sudi = _caps.get("cisco_sudi")
    _spdm = _caps.get("spdm_integrity") or []

    # Confidential Computing & Hardware Shield
    _conf_badges = []
    for _m in side_channel_modes:
        _feat_low = str(_m.get("feature", "")).lower()
        _lbl = _m.get("label", "")
        _bdg = _m.get("badge", "info")
        if any(k in _feat_low for k in ("sev-snp", "sme", "freeze lock", "smm", "sgx", "tdx", "confidential")):
            _conf_badges.append(f"<span class='badge {_bdg}' style='font-size:.78rem'>{_h(_lbl)}</span> ")

    _conf_comp_html = ""
    if _conf_badges:
        _conf_comp_html = (
            f"<div style='margin-top:1rem;margin-bottom:1rem;background:var(--bg-card);border:1px solid var(--border-color,#cbd5e1);"
            f"border-left:4px solid #7c3aed;border-radius:6px;padding:.8rem 1rem'>"
            f"<div style='display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem;margin-bottom:.35rem'>"
            f"<div style='font-weight:700;font-size:.9rem;color:var(--text)'>🛡️ Confidential Computing &amp; Hardware Shield</div>"
            f"<div style='display:flex;flex-wrap:wrap;gap:.35rem'>{''.join(_conf_badges)}</div>"
            f"</div>"
            f"<div style='font-size:.82rem;color:var(--text-muted);line-height:1.4'>"
            f"Hardware-enforced memory encryption and BIOS POST freeze locks active. "
            f"Supports VMware Confidential VMs, multi-tenant memory isolation, and rootkit tamper prevention."
            f"</div></div>"
        )

    _attestation_html = ""
    if _scv or _spdm or _sudi:
        _attestation_cards = []
        if _scv:
            _attestation_cards.append(
                f"<div style='flex:1;min-width:280px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:6px;padding:.75rem'>"
                f"<div style='font-size:.78rem;font-weight:700;color:var(--text-muted);text-transform:uppercase'>Dell Secured Component Verification</div>"
                f"<div style='margin-top:.25rem;display:flex;align-items:center;gap:.5rem'>"
                f"<span class='badge success'>🟢 Cryptographically Verified</span>"
                f"<strong style='font-size:.9rem'>{_h(_scv)}</strong>"
                f"</div>"
                f"<div style='font-size:.78rem;color:var(--text-muted);margin-top:.35rem'>"
                f"Factory hardware manifest cryptographically signed at manufacturing matches BMC component inventory."
                f"</div></div>"
            )
        if _sudi:
            _attestation_cards.append(
                f"<div style='flex:1;min-width:280px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:6px;padding:.75rem'>"
                f"<div style='font-size:.78rem;font-weight:700;color:var(--text-muted);text-transform:uppercase'>Cisco Secure Unique Device Identifier (SUDI)</div>"
                f"<div style='margin-top:.25rem;display:flex;align-items:center;gap:.5rem'>"
                f"<span class='badge success'>🟢 Cryptographically Verified</span>"
                f"<strong style='font-size:.9rem'>{_h(_sudi)}</strong>"
                f"</div>"
                f"<div style='font-size:.78rem;color:var(--text-muted);margin-top:.35rem'>"
                f"IEEE 802.1AR Secure Unique Device Identifier (SUDI) cryptographic certificate validates genuine Cisco hardware and physical tamper-resistance."
                f"</div></div>"
            )
        if _spdm:
            _badge_items = []
            for s in _spdm:
                s_status = str(s.get("status") or "Success")
                s_cnt = s.get("measurement_count", 0)
                s_id = _h(str(s.get("id") or "Device"))
                s_ver = _h(str(s.get("version") or "1.2"))
                _badge_items.append(
                    f"<span class='badge success' title='Status: {s_status} ({s_cnt} measurements)'>🟢 {s_id} (SPDM {s_ver})</span>"
                )
            _dev_badges = " ".join(_badge_items)
            _total_meas = sum(s.get("measurement_count", 0) for s in _spdm)
            _attestation_cards.append(
                f"<div style='flex:1;min-width:280px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:6px;padding:.75rem'>"
                f"<div style='font-size:.78rem;font-weight:700;color:var(--text-muted);text-transform:uppercase'>SPDM 1.2 Hardware Measurements &amp; Root of Trust</div>"
                f"<div style='margin-top:.35rem;display:flex;flex-wrap:wrap;gap:.4rem'>"
                f"{_dev_badges}"
                f"</div>"
                f"<div style='font-size:.78rem;color:var(--text-muted);margin-top:.35rem'>"
                f"{len(_spdm)} component(s) attested with {_total_meas} signed hardware and mutable firmware measurements."
                f"</div></div>"
            )
        _attestation_html = (
            f"<div style='margin-top:1rem;margin-bottom:1rem'>"
            f"<h3 style='margin:0 0 .5rem 0;font-size:1.05rem'>Platform Integrity &amp; Supply Chain Attestation</h3>"
            f"<div style='display:flex;flex-wrap:wrap;gap:.75rem'>"
            f"{''.join(_attestation_cards)}"
            f"</div></div>"
        )

    _security_accordion = (
        f"<h2>Security Posture &amp; Hardware Hardening</h2>"
        f"<details class='accordion' open style='margin-bottom:1.5rem'>"
        f"<summary>"
        f"<div>🛡️ Hardware Security Baseline &nbsp;{_sec_summary_badge}</div>"
        f"<span style='font-size:.85rem;color:var(--primary)'>Collapse Security Details &#9652;</span>"
        f"</summary>"
        f"<div class='accordion-body'>"
        f"{_sec_tbl_hdr}{_sec_rows}{_sec_footer_row}</tbody></table>"
        f"{_conf_comp_html}"
        f"{_attestation_html}"
        f"{_findings_table_html}"
        f"</div></details>"
    )

    return _security_card_html, _security_accordion, _tpm_badge_raw, _sb_badge, _spectre_badge_html
