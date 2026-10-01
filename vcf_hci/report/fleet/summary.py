"""Fleet summary HTML report generator (Layer D)."""
import logging
import os
import re
from typing import Optional

from vcf_hci.compat_engine import VCF9CompatibilityEngine
from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.obfuscation import _pii_span
from vcf_hci.report.fleet.switch_matrix import build_fleet_switch_matrix_html
from vcf_hci.report.fleet.tiles import build_fleet_tiles_html
from vcf_hci.report.fleet.vendor import normalize_oem_vendor
from vcf_hci.report.helpers import _h
from vcf_hci.report.styles import FLEET_PAGE_CSS, THEME_TOGGLE_JS
from vcf_hci.security.scoring import score_host_security

logger = logging.getLogger("vcf_assess")


def generate_summary_html(
    all_results: list,
    output_filepath: str,
    hcl_bundle_metadata: Optional[dict] = None,
    obfuscated: bool = False,
    failed_hosts: Optional[list] = None,
):
    """One-page fleet health dashboard with 13 check tiles, per-host assessment table, and failed host roster."""
    _page_salt = os.urandom(16).hex()

    if obfuscated and all_results:
        from vcf_hci.obfuscation import obfuscate_host_data
        _needs_obf = any(
            not r.get("obfuscated") and not re.match(r"^Host-\d+$", str((r.get("system") or {}).get("hostname", "")))
            for r in all_results
        )
        if _needs_obf:
            all_results = [
                obfuscate_host_data(r, f"Host-{i+1}", _page_salt) if (not r.get("obfuscated") and not re.match(r"^Host-\d+$", str((r.get("system") or {}).get("hostname", "")))) else r
                for i, r in enumerate(all_results)
            ]

    host_count = len(all_results)

    _partial_count = sum(1 for d in all_results if d.get("partial_scan"))
    _remediated_count = sum(1 for d in all_results if (d.get("remediation") or {}).get("status") == "fully_remediated")
    remediated_banner_html = ""
    if _remediated_count > 0:
        remediated_banner_html = f"""
        <div class="alert alert-success" style="margin-top:1.5rem; margin-bottom:1rem; padding:0.85rem 1.25rem; border-left:4px solid var(--success,#16a34a); background:rgba(22,163,74,0.12); border-radius:8px">
          <strong style="color:var(--success,#16a34a); font-size:1.02rem">🔄 REMEDIATION RESCAN COMPLETED ({_remediated_count} host{"" if _remediated_count == 1 else "s"}):</strong>
          {_remediated_count} host(s) that previously completed with partial/timed-out data were successfully recovered and validated via targeted differential rescan.
        </div>
        """
    partial_banner_html = ""
    if _partial_count > 0:
        partial_banner_html = f"""
        <div class="alert alert-warning" style="margin-top:1.5rem; margin-bottom:1rem; padding:1rem 1.25rem; border-left:4px solid var(--warning,#ca8a04); background:rgba(202,138,4,0.12); border-radius:8px">
          <strong style="color:var(--warning,#ca8a04); font-size:1.02rem">⚠️ INCOMPLETE / PARTIAL SCAN WARNING ({_partial_count} host{"" if _partial_count == 1 else "s"}):</strong>
          {_partial_count} host(s) completed with partial Redfish data due to BMC responsiveness or subsystem timeouts.
          Missing hardware inventory (such as storage, NICs, or PCIe) is flagged with <span class="badge warning" style="font-size:0.75rem">⚠️ Partial</span> in the table below.
          <div style="margin-top:0.4rem; font-size:0.88rem"><b>💡 Recommended Action:</b> Soft reset affected BMC controllers (e.g. <code>racadm racreset</code> for Dell or <code>iloreset</code> for HPE) or update BMC firmware, then re-scan.</div>
        </div>
        """

    failed_table_html = ""
    if failed_hosts:
        if obfuscated:
            from vcf_hci.obfuscation import obfuscate_failed_hosts
            failed_hosts = obfuscate_failed_hosts(failed_hosts, salt=_page_salt, start_idx=len(all_results) + 1)
        failed_rows = ""
        for fh in failed_hosts:
            raw_ip = str(fh.get("ip", ""))
            raw_host = str(fh.get("hostname", "Unknown"))
            if obfuscated:
                ip = _h(raw_ip)
                host = _h(raw_host)
            else:
                ip = _pii_span(_page_salt, raw_ip, "ip")
                host = _pii_span(_page_salt, raw_host, "host")
            stg = _h(str(fh.get("stage", "N/A")))
            label = _h(str(fh.get("reason_label", "Failed")))
            detail = _h(str(fh.get("detail", "")))
            rcode = fh.get("reason_code", "")
            if rcode == "auth_failed":
                badge_html = "<span class='badge danger'>🔒 Auth Failed</span>"
            elif "timeout" in rcode:
                badge_html = "<span class='badge warning'>⚠️ Timed Out</span>"
            else:
                badge_html = "<span class='badge danger'>🔌 Unreachable</span>"

            failed_rows += f"""
            <tr>
              <td style="padding:0.5rem;">{badge_html}</td>
              <td style="padding:0.5rem;"><code>{ip}</code></td>
              <td style="padding:0.5rem;">{host}</td>
              <td style="padding:0.5rem;">{label}</td>
              <td style="padding:0.5rem;"><small style="color:#64748b">[{stg}] {detail}</small></td>
            </tr>"""

        failed_table_html = f"""
        <div style="margin-top: 2rem; background: var(--card,#ffffff); border: 1px solid var(--border,#e2e8f0); border-left: 4px solid var(--danger,#dc2626); border-radius: 8px; padding: 1.25rem;">
          <h3 style="margin-top:0; color:var(--text,#0f172a); font-size:1.1rem; display:flex; align-items:center; gap:0.5rem;">
            <span>⚠️ Failed / Incomplete Scans ({len(failed_hosts)})</span>
          </h3>
          <p style="margin:0 0 1rem; color:var(--text-muted,#64748b); font-size:0.85rem;">
            The following target hosts could not be fully scanned during this assessment run.
          </p>
          <div style="overflow-x:auto;">
            <table class="data-table" style="width:100%; border-collapse:collapse; font-size:0.88rem;">
              <thead>
                <tr style="text-align:left; border-bottom:2px solid var(--border,#e2e8f0);">
                  <th style="padding:0.5rem; background:var(--th-bg,#f8fafc); color:var(--text,#1e293b);">Status</th>
                  <th style="padding:0.5rem; background:var(--th-bg,#f8fafc); color:var(--text,#1e293b);">BMC IP</th>
                  <th style="padding:0.5rem; background:var(--th-bg,#f8fafc); color:var(--text,#1e293b);">Hostname</th>
                  <th style="padding:0.5rem; background:var(--th-bg,#f8fafc); color:var(--text,#1e293b);">Failure Reason</th>
                  <th style="padding:0.5rem; background:var(--th-bg,#f8fafc); color:var(--text,#1e293b);">Stage & Details</th>
                </tr>
              </thead>
              <tbody>
                {failed_rows}
              </tbody>
            </table>
          </div>
        </div>
        """
    has_any_host_os = any(
        isinstance(data.get("host_os"), dict) and bool(
            data["host_os"].get("os_name")
            or data["host_os"].get("os_version")
            or data["host_os"].get("esxi_update_label")
            or data["host_os"].get("os_description")
            or data["host_os"].get("os_build")
        )
        for data in all_results
    )
    rows = ""
    _report_prefix = "reports/OBFUSCATED_" if obfuscated else "reports/vsphere_vsan_report_"
    _oem_set: set = set()
    _nvidia_kw_t = {"NVIDIA", "TESLA", "H100", "H200", "A100", "A30", "A40", "L40", "V100", "L4", "T4", "A10", "A16"}
    _amd_kw_t    = {"AMD", "RADEON", "INSTINCT", "MI300", "MI250", "MI200", "MI100"}
    _intel_kw_t  = {"INTEL", "ARC", "GAUDI", "A770", "A750"}
    for idx, data in enumerate(all_results):
        sys_info = data.get("system", {})
        cpu_info = sys_info.get("cpu_summary", {})
        all_drives = [d for ctrl in data.get("storage_subsystem", []) for d in ctrl.get("drives", [])]
        esa_count = sum(1 for d in all_drives if d.get("category") == "vSAN ESA/OSA NVMe")
        osa_count = sum(1 for d in all_drives if d.get("category") in ("vSAN OSA Only", "vSAN OSA SAS/SATA"))
        verdict = cpu_info.get("verdict", "")
        if "Unsupported" in verdict:
            cpu_td = "<span class='badge danger'>🔴 Unsupported</span>"
            _cpu_sort = "4"
            _row_unsupported = "1"
        elif "Override Required" in verdict or "9.1 Only" in verdict:
            cpu_td = "<span class='badge warning'>🟡 Override Required</span>"
            _cpu_sort = "3"
            _row_unsupported = "0"
        elif "Deprecated" in verdict:
            cpu_td = "<span class='badge success'>🟢 Supported (9.x)</span>"
            _cpu_sort = "2"
            _row_unsupported = "0"
        else:
            cpu_td = "<span class='badge success'>🟢 Supported</span>"
            _cpu_sort = "1"
            _row_unsupported = "0"
        # CPU model display
        _cpu_model_raw = cpu_info.get("model", "—") or "—"
        _cpu_count = cpu_info.get("count", "")
        _cpu_socket_label = f"{_cpu_count}× " if _cpu_count else ""
        cpu_model_td = (
            f"<small style='display:block;line-height:1.35'>{_h(_cpu_model_raw)}</small>"
            f"<small style='color:#64748b'>{_cpu_socket_label}socket(s)</small>"
        )
        vmd_on = (data.get("bios_checks") or {}).get("vmd_enabled_flag", False)
        trimode_nvme = sum(1 for d in all_drives if d.get("behind_trimode") or d.get("category") == "Unsupported NVMe Tri-Mode")
        raid_nvme = sum(1 for d in all_drives if d.get("category") == "Unsupported NVMe RAID" and not d.get("behind_trimode"))
        max_nic = max(
            (max((p.get("current_speed_gbps", 0) or 0 for p in n.get("ports", [])), default=0)
             for n in data.get("network_adapters", [])),
            default=0,
        )
        vsan_verdict, vsan_detail = VCF9CompatibilityEngine.evaluate_vsan(
            esa_count,
            osa_count,
            max_nic,
            vmd_enabled=vmd_on,
            trimode_nvme_count=trimode_nvme,
            raid_nvme_count=raid_nvme,
        )
        if "ESA Ready" in vsan_verdict:
            esa_td = f"<span class='badge success'>🟢 ESA Ready</span> <small style='color:#64748b'>{esa_count} NVMe</small>"
        elif "ESA Storage Met" in vsan_verdict:
            esa_td = f"<span class='badge warning'>🟡 ESA Storage Met</span> <small style='color:#64748b'>{esa_count} NVMe</small>"
        elif "OSA" in vsan_verdict:
            if esa_count > 0 and osa_count > 0:
                _subtext = f"{esa_count} ESA + {osa_count} OSA"
            elif esa_count > 0:
                _subtext = f"{esa_count} NVMe"
            else:
                _subtext = f"{osa_count} drives"
            _title_attr = f" title='{_h(vsan_detail)}'" if vsan_detail else ""
            esa_td = f"<span class='badge warning'{_title_attr}>🟡 OSA</span> <small style='color:#64748b'>{_subtext}</small>"
        elif "Intel VMD Enabled" in vsan_verdict:
            esa_td = f"<span class='badge danger'>🔴 VMD Enabled</span> <small style='color:#64748b'>{esa_count} NVMe</small>"
        elif "Tri-Mode RAID" in vsan_verdict:
            esa_td = f"<span class='badge danger'>🔴 Tri-Mode RAID</span> <small style='color:#64748b'>{trimode_nvme} NVMe</small>"
        elif "Behind RAID" in vsan_verdict or "NVMe Behind RAID" in vsan_verdict:
            esa_td = f"<span class='badge danger'>🔴 Behind RAID</span> <small style='color:#64748b'>{raid_nvme} NVMe</small>"
        else:
            esa_td = f"<span class='badge danger'>🔴 Insufficient</span> <small style='color:#64748b'>{esa_count}</small>"
        _esa_sort = str(esa_count)
        psu = data.get("psu_status", {})
        is_redundant = bool(psu.get("redundant"))
        power_capped = bool(psu.get("power_limit_enforced"))
        cap_badge = ""
        if power_capped:
            limit_w = psu.get("power_limit_watts")
            tip_w = f"Power limit {limit_w} W" if limit_w is not None else "Power limit enforced"
            cap_badge = f" <span class='badge warning' title='{_h(tip_w)}'>Cap</span>"

        if is_redundant:
            psu_td = f"<span class='badge success'>🟢 Redundant</span>{cap_badge}"
            _psu_sort = "2" if power_capped else "1"
        else:
            psu_td = f"<span class='badge warning'>🟡 Single</span>{cap_badge}"
            _psu_sort = "4" if power_capped else "3"

        # GPU column — vendor-classified labels
        _gpus = data.get("gpu_accelerators", [])
        gpu_count = len(_gpus)
        if gpu_count:
            _gpu_parts: list = []
            _counted: dict = {}
            for _g in _gpus:
                _raw_g = (str(_g.get("name") or "") + " " + str(_g.get("manufacturer") or "")).upper()
                _name_g = str(_g.get("name") or "GPU").strip()
                if any(k in _raw_g for k in _nvidia_kw_t):
                    _vendor_label = "Nvidia"
                elif any(k in _raw_g for k in _amd_kw_t):
                    _vendor_label = "AMD"
                elif any(k in _raw_g for k in _intel_kw_t):
                    _vendor_label = "Intel"
                else:
                    _vendor_label = "GPU"
                _key_g = f"{_vendor_label}:{_name_g}"
                _counted[_key_g] = _counted.get(_key_g, 0) + 1
            for _k, _c in sorted(_counted.items(), key=lambda x: -x[1])[:3]:
                _vl, _ml = _k.split(":", 1)
                _gpu_parts.append(f"{_c}\u00d7 {_vl} {_ml}" if _vl != "GPU" else f"{_c}\u00d7 {_ml}")
            gpu_td = "\U0001f7e3 " + "; ".join(_gpu_parts)
        else:
            gpu_td = "—"

        tpm = sys_info.get("tpm_status_badge", "<span class='badge warning'>⚠️ Unknown</span>")
        _tpm_sort = "1" if "success" in tpm else ("3" if "danger" in tpm else "2")

        mem_topo = data.get("memory_topology") or VCF9CompatibilityEngine.evaluate_memory_topology(data.get("memory_subsystem", {}), sys_info.get("cpu_summary", {}))
        _mem_pct = mem_topo.get("interleaving_score_pct", 0) or 0
        mem_td = f"{mem_topo.get('status_badge')} <small style='color:#64748b'>({_mem_pct}%)</small>"

        # OS column
        _row_hos = data.get("host_os", {})
        _row_os_name   = _row_hos.get("os_name", "")
        _row_os_ver    = _row_hos.get("os_version", "")
        _row_os_upd    = _row_hos.get("esxi_update_label", "")
        _row_os_eol_b  = _row_hos.get("eol_badge", "")
        _row_os_src    = _row_hos.get("source", "")
        _row_os_lbl    = _row_os_upd or _row_os_name
        _row_os_sort   = _row_os_lbl or "zzz"  # sort unknowns to end
        if _row_os_lbl:
            _ver_small = f"<small style='display:block;line-height:1.3;color:#64748b'>{_h(_row_os_ver)}</small>" if _row_os_ver and not _row_os_upd else ""
            _src_small = f"<small style='display:block;line-height:1.2;color:#94a3b8;font-size:.75rem'>{_h(_row_os_src)}</small>" if _row_os_src else ""
            os_td = (
                f"<small style='display:block;line-height:1.35'>{_h(_row_os_lbl)}</small>"
                f"{_ver_small}"
                f"{_row_os_eol_b}"
                f"{_src_small}"
            )
        else:
            os_td = "<span style='color:#94a3b8'>—</span>"

        os_td_cell = f"<td data-sort='{_h(_row_os_sort)}'>{os_td}</td>" if has_any_host_os else ""
        report_file = f"{_report_prefix}{sanitize_filename(sys_info.get('ip', 'unknown'))}.html"
        _s_dns = sys_info.get("dns_name")
        _s_ip = sys_info.get("ip", "")
        if obfuscated and not str(_s_ip).startswith("192.0.2."):
            _s_ip = f"192.0.2.{(idx % 250) + 1}"
        link_label = f"{_s_dns} ({_s_ip})" if _s_dns and _s_dns != _s_ip else sys_info.get("hostname", _s_ip)
        if obfuscated:
            if not re.match(r"^Host-\d+", str(link_label)):
                link_label = f"Host-{idx+1}"
            _pii_link_label = _h(link_label)
            _pii_ip         = _h(_s_ip)
        else:
            _pii_link_label = _pii_span(_page_salt, link_label, "host")
            _pii_ip         = _pii_span(_page_salt, _s_ip, "ip")
        _partial_badge = ""
        _rem_info = data.get("remediation") or {}
        _rem_status = _rem_info.get("status")
        if _rem_status == "fully_remediated":
            _res_str = ", ".join(str(s) for s in _rem_info.get("resolved_sections", []))
            _partial_badge = f" <span class='badge success' style='font-size:.7rem' title='Remediated via targeted rescan (recovered: {_h(_res_str)})'>🔄 Remediated</span>"
        elif data.get("partial_scan"):
            if _rem_status == "partially_remediated":
                _res_str = ", ".join(str(s) for s in _rem_info.get("resolved_sections", []))
                _rem_str = ", ".join(str(s) for s in (_rem_info.get("remaining_sections") or data.get("partial_sections", [])))
                _partial_badge = f" <span class='badge warning' style='font-size:.7rem' title='Partially remediated (recovered: {_h(_res_str)}; missing: {_h(_rem_str)})'>⚠️ Partial (Remediated)</span>"
            else:
                _p_reason = _h(str(data.get("partial_reason") or "Incomplete data capture due to BMC timeouts"))
                _partial_badge = f" <span class='badge warning' style='font-size:.7rem' title='{_p_reason}'>⚠️ Partial</span>"
        _vendor_raw = sys_info.get("vendor", "") or ""
        _model_str = f"{_vendor_raw} {sys_info.get('model','')}".strip()
        # Normalise vendor for OEM filter
        _vendor_norm = normalize_oem_vendor(_vendor_raw)
        _oem_set.add(_vendor_norm)
        # BMC Security Posture column
        _sec_score = score_host_security(data)
        if _sec_score.get("is_fleet_manager"):
            sec_td = "<span class='badge' style='background:var(--card);color:var(--text-muted);border:1px solid var(--border)'>Excluded (Fleet Mgr)</span>"
            _sec_sort = "4"
        elif _sec_score.get("assessed"):
            _p_cnt = _sec_score.get("pass_count", 0)
            _f_cnt = _sec_score.get("fail_count", 0)
            _u_cnt = _sec_score.get("unknown_count", 0)
            _posture = _sec_score.get("posture", "")
            _comp_pct = _sec_score.get("compliance_pct", 0.0)
            _tip = f"{_f_cnt} Failed, {_p_cnt} Passed, {_u_cnt} Unknown ({_comp_pct}% compliance). Click to view BMC security audit."
            if _posture == "Baseline Met":
                sec_badge = f"<span class='badge success'>🟢 Met</span> <small style='color:#64748b'>{_p_cnt}P</small>"
                _sec_sort = "1"
            elif _posture == "Action Required":
                sec_badge = f"<span class='badge danger'>🔴 Action Req</span> <small style='color:#64748b'>{_f_cnt}F &middot; {_p_cnt}P</small>"
                _sec_sort = "3"
            else:
                sec_badge = f"<span class='badge warning'>🟡 Partial</span> <small style='color:#64748b'>{_u_cnt}U &middot; {_p_cnt}P</small>"
                _sec_sort = "2"
            sec_td = (
                f"<a href='{_h(report_file)}#tab-security' class='btn-link' "
                f"title='{_h(_tip)}' style='text-decoration:none;display:inline-block'>{sec_badge}</a>"
            )
        else:
            sec_td = "<span style='color:#94a3b8'>—</span>"
            _sec_sort = "5"

        _cpu_tip = f"{_cpu_model_raw} — Click to view host CPU details" if _cpu_model_raw and _cpu_model_raw != "—" else "Click to view host CPU details"
        cpu_jump = (
            f"<a href='{_h(report_file)}#tab-cpu' class='btn-link' "
            f"title='{_h(_cpu_tip)}' style='text-decoration:none;display:inline-block'>{cpu_td}</a>"
        )

        rows += (
            f"<tr data-vendor='{_h(_vendor_norm)}' data-unsupported='{_row_unsupported}'>"
            f"<td data-sort='{_h(link_label)}'>"
            f"<a href='{_h(report_file)}' class='btn-link'><strong>{_pii_link_label}</strong></a>"
            f"<br><small style='color:#64748b'>{_pii_ip}</small></td>"
            f"<td data-sort='{_h(_model_str)}'>{_h(_model_str)}{_partial_badge}</td>"
            f"<td data-sort='{_h(_cpu_model_raw)}'>{cpu_model_td}</td>"
            f"<td data-sort='{_cpu_sort}'>{cpu_jump}</td>"
            f"{os_td_cell}"
            f"<td data-sort='{_tpm_sort}'>{tpm}</td>"
            f"<td data-sort='{_sec_sort}'>{sec_td}</td>"
            f"<td data-sort='{_mem_pct}'>{mem_td}</td>"
            f"<td data-sort='{_esa_sort}'>{esa_td}</td>"
            f"<td data-sort='{_psu_sort}'>{psu_td}</td>"
            f"<td data-sort='{gpu_count}'>{gpu_td}</td>"
            f"</tr>"
        )
    # Build OEM dropdown options (sorted alphabetically, "All" first)
    _oem_options_html = "".join(
        f"<option value='{_h(v)}'>{_h(v)}</option>"
        for v in sorted(_oem_set)
    )
    tiles_block = build_fleet_tiles_html(all_results, report_prefix=_report_prefix, page_salt=_page_salt)
    switch_matrix_block = build_fleet_switch_matrix_html(all_results, report_prefix=_report_prefix, page_salt=_page_salt, obfuscated=obfuscated)

    dark_site_banner = ""
    if hcl_bundle_metadata:
        _age = hcl_bundle_metadata.get("dataset_age_days", 0)
        _b_cls = "success" if _age <= 45 else "warning"
        dark_site_banner = (
            f'<div class="alert alert-success" style="margin-bottom:1rem;">'
            f'<strong>🔒 Air-Gapped Dark-Site HCL Bundle Active:</strong> {_h(hcl_bundle_metadata.get("bundle_filename"))} '
            f'<span class="badge {_b_cls}">Dataset Age: {_age} days</span> '
            f'({hcl_bundle_metadata.get("json_models_count", 0) + hcl_bundle_metadata.get("csv_models_count", 0)} drives indexed)'
            f'</div>'
        )

    _page_css = FLEET_PAGE_CSS

    _obf_banner_sum = (
        '<div class="alert alert-danger" style="border-width:2px;border-style:solid;text-align:center;margin-bottom:1.5rem;padding:1rem 1.5rem">'
        '<strong style="color:var(--danger,#dc2626);font-size:1.05rem">&#128274; OBFUSCATED REPORT</strong>'
        '<p style="margin:.3rem 0 0;font-size:.82rem;color:var(--tint-danger-text,#991b1b)">'
        'Host identifiers have been replaced with hash tokens. '
        'Identical tokens&nbsp;=&nbsp;identical real values. '
        'Hardware specs and VCF verdicts are unmodified.</p></div>'
    ) if obfuscated else ""

    _obf_controls_sum = (
        '<span class="badge cyber-recovery" style="font-size:.82rem;padding:.3rem .75rem;border:1px solid #7c3aed">🔒 Obfuscated Fleet Summary</span>'
    ) if obfuscated else (
        '<label style="display:inline-flex;align-items:center;gap:.4rem;cursor:pointer;font-size:.82rem;color:#64748b" title="Cosmetic in-browser view mask. For external sharing, use generated 00_OBFUSCATED_*.html reports.">'
        '<input type="checkbox" id="maskPII" style="cursor:pointer">'
        'Obfuscate view (client-side)'
        '</label>'
        '<a id="dlObf" href="#" class="btn-link" style="display:none;margin-left:.5rem;font-size:.82rem;color:var(--primary,#60a5fa);text-decoration:none;border:1px solid var(--primary,#60a5fa);border-radius:4px;padding:.15rem .5rem" title="Download obfuscated HTML copy">&#11015; Save obfuscated copy</a>'
        '<a id="dlObfFleet" href="#" style="margin-left:.75rem;font-size:.82rem;color:var(--ms-3dpc-color,#a78bfa);text-decoration:none;border:1px solid var(--ms-3dpc-color,#a78bfa);border-radius:4px;padding:.15rem .5rem;white-space:nowrap" title="Download a copy of this fleet summary with all host identifiers replaced by hash tokens">&#11015; Save obfuscated fleet summary</a>'
    )

    os_th_cell = '<th title="Click to sort">Host OS<span class="sort-ind">⇅</span></th>\n    ' if has_any_host_os else ""
    html_content = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VCF Readiness \u2014 Fleet Health Dashboard</title>
  <style>{_page_css}</style>
</head>
<body>
<div class="container">
{_obf_banner_sum}
<h1>VCF / vSphere 9.1 Readiness \u2014 Fleet Health Dashboard</h1>
<p style="color:#64748b">
  {host_count} host(s) assessed &mdash; click a hostname to open the full per-host report.
  &nbsp;&nbsp;
  {_obf_controls_sum}
  &nbsp;&nbsp;<button id="themeToggle" title="Toggle dark/light mode">🌙 Dark</button>
</p>

{dark_site_banner}

<h2>Fleet Health Tiles</h2>
{tiles_block}

<h2>Per-Host Assessment Table</h2>
<div id="table-controls" style="display:flex;gap:1.25rem;align-items:center;margin:.5rem 0 .75rem;flex-wrap:wrap;background:var(--card);border:1px solid var(--border);border-radius:6px;padding:.6rem 1rem;font-size:.87rem">
  <label style="display:flex;align-items:center;gap:.45rem;font-weight:600;color:var(--text-muted)">
    OEM Filter:
    <select id="oem-filter" style="margin-left:.25rem;padding:.28rem .65rem;border:1px solid var(--border);border-radius:5px;font-size:.85rem;background:var(--card);color:var(--text)">
      <option value="all">All OEMs</option>
      {_oem_options_html}
    </select>
  </label>
  <label style="display:flex;align-items:center;gap:.4rem;cursor:pointer;color:var(--text-muted)">
    <input type="checkbox" id="hide-unsupported" style="cursor:pointer">
    Hide unsupportable hosts <small style="color:var(--text-muted)">(pre-Skylake)</small>
  </label>
</div>
{remediated_banner_html}
{partial_banner_html}
<table class="sortable-table">
  <thead><tr>
    <th title="Click to sort">Host / IP<span class="sort-ind">⇅</span></th>
    <th title="Click to sort">Model<span class="sort-ind">⇅</span></th>
    <th title="Click to sort">CPU Model<span class="sort-ind">⇅</span></th>
    <th title="Click to sort">CPU Support<span class="sort-ind">⇅</span></th>
    {os_th_cell}<th title="Click to sort">TPM 2.0<span class="sort-ind">⇅</span></th>
    <th title="Click to sort">BMC Security<span class="sort-ind">⇅</span></th>
    <th title="Click to sort">Memory Interleaving<span class="sort-ind">⇅</span></th>
    <th title="Click to sort">vSAN ESA Drives<span class="sort-ind">⇅</span></th>
    <th title="Power supply redundancy and power cap enforcement">PSU<span class="sort-ind">⇅</span></th>
    <th title="Click to sort">GPUs<span class="sort-ind">⇅</span></th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>
{switch_matrix_block}
{failed_table_html}

</div>
<script>
(function(){{
  /* PII mask toggle + obfuscated download */
  var cb = document.getElementById('maskPII');
  var dlBtn = document.getElementById('dlObf');
  if (cb) {{
    cb.addEventListener('change', function() {{
      document.querySelectorAll('.pii').forEach(function(el) {{
        el.textContent = cb.checked ? el.dataset.mask : el.dataset.real;
      }});
      if (dlBtn) dlBtn.style.display = cb.checked ? 'inline-block' : 'none';
    }});
  }}
  if (dlBtn) {{
    dlBtn.addEventListener('click', function(e) {{
      e.preventDefault();
      var clone = document.documentElement.cloneNode(true);
      clone.querySelectorAll('.pii').forEach(function(el) {{
        var mask = el.dataset.mask || el.textContent;
        el.textContent = mask;
        el.removeAttribute('data-real');
        el.setAttribute('data-mask', mask);
      }});
      clone.querySelectorAll('[data-tabs-ready]').forEach(function(el) {{
        el.removeAttribute('data-tabs-ready');
      }});
      clone.querySelectorAll('tbody tr td:first-child a.btn-link').forEach(function(a) {{
        var td = a.closest('td');
        var ipSpan = td && td.querySelector('small .pii');
        if (ipSpan) {{
          var safe = ipSpan.dataset.mask.replace(/[^a-zA-Z0-9._-]/g, '_');
          a.setAttribute('href', 'reports/OBFUSCATED_' + safe + '.html');
        }}
      }});
      clone.querySelectorAll('[data-href]').forEach(function(a) {{
        var td = a.closest('td');
        var ipSpan = td && td.querySelector('small .pii');
        if (ipSpan) {{
          var safe = ipSpan.dataset.mask.replace(/[^a-zA-Z0-9._-]/g, '_');
          a.setAttribute('href', 'reports/OBFUSCATED_' + safe + '.html');
        }}
      }});
      var cbClone = clone.querySelector('#maskPII');
      if (cbClone) cbClone.checked = true;
      var dlClone = clone.querySelector('#dlObf');
      if (dlClone) dlClone.style.display = 'inline-block';
      var blob = new Blob(['<!DOCTYPE html>' + clone.outerHTML], {{type: 'text/html'}});
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      var base = (window.location.pathname.split('/').pop() || '00_fleet_summary.html').replace(/^(00_)?OBFUSCATED_/i, '');
      a.download = '00_OBFUSCATED_' + base;
      a.href = url;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }});
  }}

  /* Standalone obfuscated fleet summary download (always visible) */
  var dlFleetBtn = document.getElementById('dlObfFleet');
  if (dlFleetBtn) {{
    dlFleetBtn.addEventListener('click', function(e) {{
      e.preventDefault();
      var clone = document.documentElement.cloneNode(true);
      clone.querySelectorAll('.pii').forEach(function(el) {{
        var mask = el.dataset.mask || el.textContent;
        el.textContent = mask;
        el.removeAttribute('data-real');
        el.setAttribute('data-mask', mask);
      }});
      clone.querySelectorAll('[data-tabs-ready]').forEach(function(el) {{
        el.removeAttribute('data-tabs-ready');
      }});
      clone.querySelectorAll('tbody tr td:first-child a.btn-link').forEach(function(a) {{
        var td = a.closest('td');
        var ipSpan = td && td.querySelector('small .pii');
        if (ipSpan) {{
          var safe = ipSpan.dataset.mask.replace(/[^a-zA-Z0-9._-]/g, '_');
          a.setAttribute('href', 'reports/OBFUSCATED_' + safe + '.html');
        }}
      }});
      clone.querySelectorAll('[data-href]').forEach(function(a) {{
        var td = a.closest('td');
        var ipSpan = td && td.querySelector('small .pii');
        if (ipSpan) {{
          var safe = ipSpan.dataset.mask.replace(/[^a-zA-Z0-9._-]/g, '_');
          a.setAttribute('href', 'reports/OBFUSCATED_' + safe + '.html');
        }}
      }});
      var cbClone = clone.querySelector('#maskPII');
      if (cbClone) cbClone.checked = true;
      var dlClone = clone.querySelector('#dlObf');
      if (dlClone) dlClone.style.display = 'inline-block';
      var fleetClone = clone.querySelector('#dlObfFleet');
      if (fleetClone) fleetClone.style.display = 'inline-block';
      var blob = new Blob(['<!DOCTYPE html>' + clone.outerHTML], {{type: 'text/html'}});
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      var base = (window.location.pathname.split('/').pop() || '00_fleet_summary.html').replace(/^(00_)?OBFUSCATED_/i, '');
      a.download = '00_OBFUSCATED_' + base;
      a.href = url;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }});
  }}

  /* Sortable table */
  var table = document.querySelector('.sortable-table');
  if (!table) return;
  var headers = table.querySelectorAll('thead th');
  var sortState = {{}};

  headers.forEach(function(th, colIdx) {{
    th.addEventListener('click', function() {{
      var tbody = table.querySelector('tbody');
      var rows = Array.from(tbody.querySelectorAll('tr'));
      var dir = (sortState[colIdx] === 'asc') ? -1 : 1;
      sortState = {{}};
      sortState[colIdx] = (dir === 1) ? 'asc' : 'desc';

      headers.forEach(function(h, i) {{
        h.classList.remove('sorted');
        var ind = h.querySelector('.sort-ind');
        if (ind) ind.textContent = (i === colIdx) ? (dir === 1 ? '\u25b2' : '\u25bc') : '\u21c5';
      }});
      th.classList.add('sorted');

      rows.sort(function(a, b) {{
        var aCell = a.querySelectorAll('td')[colIdx];
        var bCell = b.querySelectorAll('td')[colIdx];
        if (!aCell || !bCell) return 0;
        var aVal = (aCell.hasAttribute('data-sort') ? aCell.getAttribute('data-sort') : aCell.textContent).trim();
        var bVal = (bCell.hasAttribute('data-sort') ? bCell.getAttribute('data-sort') : bCell.textContent).trim();
        var aNum = parseFloat(aVal), bNum = parseFloat(bVal);
        if (!isNaN(aNum) && !isNaN(bNum)) return dir * (aNum - bNum);
        return dir * aVal.toLowerCase().localeCompare(bVal.toLowerCase());
      }});
      rows.forEach(function(row) {{ tbody.appendChild(row); }});
    }});
  }});

  /* OEM filter + hide-unsupportable */
  function applyTableFilters() {{
    var oem = (document.getElementById('oem-filter') || {{}}).value || 'all';
    var hideUnsup = (document.getElementById('hide-unsupported') || {{}}).checked || false;
    var tbody = table.querySelector('tbody');
    if (!tbody) return;
    Array.from(tbody.querySelectorAll('tr')).forEach(function(row) {{
      var vendor = row.getAttribute('data-vendor') || '';
      var unsup  = row.getAttribute('data-unsupported') === '1';
      var show = true;
      if (oem !== 'all' && vendor !== oem) show = false;
      if (hideUnsup && unsup) show = false;
      row.style.display = show ? '' : 'none';
    }});
  }}
  var oemSel = document.getElementById('oem-filter');
  var hideChk = document.getElementById('hide-unsupported');
  if (oemSel) oemSel.addEventListener('change', applyTableFilters);
  if (hideChk) hideChk.addEventListener('change', applyTableFilters);
}})();
</script>
{THEME_TOGGLE_JS}
</body>
</html>"""
    html_safe = html_content.encode("utf-8", errors="surrogatepass").decode("utf-8", errors="replace")
    with open(output_filepath, "w", encoding="utf-8", errors="replace") as f:
        f.write(html_safe)
