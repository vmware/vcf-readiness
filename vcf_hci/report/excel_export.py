"""
VCF Readiness Tool — Excel export generator (stdlib .xlsx writer).

Builds multi-tab Excel workbooks (.xlsx) from assessment host results (Schema v2.0 + Detailed Inventory).
Uses stdlib zipfile and xml formatting — zero third-party dependencies (no openpyxl).
"""
from __future__ import annotations

import json
import os
import time
import zipfile
from io import BytesIO
from typing import Any, Optional, Union
from xml.sax.saxutils import escape as _xe

from vcf_hci.report.inventory_tables import _safe_int, build_inventory_sheets
from vcf_hci.report.schema_registry import (
    FLEET_SUMMARY_FIELDS,
    color_for_verdict,
    strip_html,
)
from vcf_hci.security.metadata import get_control_title
from vcf_hci.security.scoring import score_host_security


def _strip_html(s: Any) -> str:
    """Backward compatibility alias for strip_html."""
    return strip_html(s)


def _vcf_color(verdict: str) -> str:
    """Backward compatibility alias for color_for_verdict."""
    return color_for_verdict(verdict)


def _build_excel_sheets(
    all_results: list,
    failed_hosts: Optional[list] = None,
    obfuscated: bool = False,
) -> list:
    """Build unified multi-tab spreadsheet structure for _write_xlsx.

    Includes:
    - Tab 1: Summary (Executive Overview — Schema v2.0 typed fields)
    - Tab 2: Decision (Dense SE Decision Matrix)
    - Tab 3: vCPU (Detailed Processors & Cores)
    - Tab 4: vMemory (Detailed DIMMs, Speeds & Interleaving)
    - Tab 5: vStorage (Detailed Controllers & Disks)
    - Tab 6: vNetwork (Detailed Adapters, Ports & LLDP)
    - Tab 7: vGPU (Accelerators & PCIe)
    - Tab 8: vFirmware (Component Firmware Inventory)
    - Tab 9: vHBA (Fibre Channel HBAs)
    - Tab 10: vBIOS (BIOS Settings & Side-Channel Mitigation)
    - Tab 11: Health_Alarms (Consolidated Subsystem Faults & Predictive Alerts)
    - Tab 12: Security (BMC, TPM, Secure Boot & Protocol Hardening)
    - Tab 13: Security_Audit (Normalized SCG Findings & Control Posture)
    - Tab 14: Failed_Hosts (Optional — Preflight & Scan Errors)
    """
    if obfuscated:
        _salt = os.urandom(16).hex()
        if all_results:
            import re

            from vcf_hci.obfuscation import obfuscate_host_data
            _needs_obf = any(
                not r.get("obfuscated") and not re.match(r"^Host-\d+$", str((r.get("system") or {}).get("hostname", "")))
                for r in all_results
            )
            if _needs_obf:
                all_results = [
                    obfuscate_host_data(r, f"Host-{i+1}", _salt) if (not r.get("obfuscated") and not re.match(r"^Host-\d+$", str((r.get("system") or {}).get("hostname", "")))) else r
                    for i, r in enumerate(all_results)
                ]
        if failed_hosts:
            import re

            from vcf_hci.obfuscation import obfuscate_failed_hosts
            _needs_fh_obf = any(
                not re.match(r"^Host-\d+$", str(fh.get("hostname", "")))
                for fh in failed_hosts
            )
            if _needs_fh_obf:
                failed_hosts = obfuscate_failed_hosts(failed_hosts, salt=_salt, start_idx=len(all_results) + 1)

    # ── Tab 1: Fleet Summary (Executive Overview) ─────────────────────────────
    sum_hdr = [(f.header, "header") for f in FLEET_SUMMARY_FIELDS]
    sum_rows = [sum_hdr]

    for data in all_results:
        row = []
        for f in FLEET_SUMMARY_FIELDS:
            try:
                val = f.extractor(data)
            except Exception:
                val = ""
            if isinstance(val, str):
                val = strip_html(val)
            if f.color_rule and val:
                c_style = f.color_rule(val)
                row.append((val, c_style) if c_style != "header" else val)
            else:
                row.append(val if val is not None else "")
        sum_rows.append(row)

    # ── Tabs 2..11: Decision Matrix & Granular Components ─────────────────────
    inv_sheets = build_inventory_sheets(all_results, obfuscated=obfuscated)

    # ── Tab 10: Security & BMC Configuration ──────────────────────────────────
    sec_hdr = [
        ("Host / IP", "header"), ("Hostname", "header"), ("BMC Model", "header"),
        ("BMC FW Version", "header"), ("License Tier", "header"), ("TPM Version", "header"),
        ("Secure Boot", "header"), ("NTP Configured", "header"), ("NTP Servers", "header"),
        ("Time Drift Skew (s)", "header"), ("HTTP Plaintext", "header"), ("Telnet", "header"),
        ("IPMI LAN", "header"), ("SNMP", "header"), ("SSH", "header"),
        ("Min Password Length", "header"),
        ("Supply Chain / SCV", "header"), ("SPDM 1.2 Integrity", "header"),
    ]
    sec_rows = [sec_hdr]

    for data in all_results:
        si = data.get("system") or {}
        ip = str(si.get("ip") or data.get("host") or "").strip()
        host = str(si.get("hostname") or "").strip()
        bm = data.get("bmc_firmware") or {}
        lic = data.get("bmc_license") or {}
        sb = data.get("secure_boot") or {}
        net = data.get("bmc_net_proto") or {}
        protos = net.get("protocols") or {}

        tpm = strip_html(si.get("tpm_status_badge", "Not Present"))
        sboot = str(sb.get("current_boot") or ("Enabled" if sb.get("enabled") else "Disabled"))
        ntp_conf = "Yes" if net.get("ntp_configured") else "No"
        ntp_servers = ", ".join(net.get("ntp_servers", []))
        skew = net.get("time_drift_seconds", 0)

        http_en = "Enabled (Insecure)" if protos.get("HTTP", {}).get("enabled") else "Disabled (Secure)"
        telnet_en = "Enabled (Critical Risk)" if protos.get("Telnet", {}).get("enabled") else "Disabled (Secure)"
        ipmi_en = "Enabled (Caution)" if protos.get("IPMI", {}).get("enabled") else "Disabled (Secure)"
        snmp_en = "Enabled" if protos.get("SNMP", {}).get("enabled") else "Disabled"
        ssh_en = "Enabled" if protos.get("SSH", {}).get("enabled") else "Disabled"

        sec_ev = data.get("bmc_security_evidence") or {}
        caps = sec_ev.get("capabilities") or {}
        scv_val = caps.get("dell_scv") or caps.get("cisco_sudi")
        scv_cell = (f"Verified ({scv_val})", "green") if scv_val else "Not Configured / N/A"

        spdm_list = caps.get("spdm_integrity") or []
        if spdm_list:
            spdm_desc = f"Verified ({len(spdm_list)} Devices: {', '.join(s.get('id', '') for s in spdm_list)})"
            spdm_cell = (spdm_desc, "green")
        else:
            spdm_cell = "Not Configured / N/A"

        sec_rows.append([
            ip, host,
            str(bm.get("bmc_model") or "").strip(),
            str(bm.get("bmc_fw_version") or "").strip(),
            str(lic.get("license_name") or "").strip(),
            (tpm, color_for_verdict(tpm)),
            (sboot, "green" if sboot.lower() == "enabled" else "yellow"),
            (ntp_conf, "green" if ntp_conf == "Yes" else "yellow"),
            ntp_servers,
            (skew, "red" if abs(_safe_int(skew, 0)) > 300 else "green"),
            (http_en, "yellow" if "Enabled" in http_en else "green"),
            (telnet_en, "red" if "Enabled" in telnet_en else "green"),
            (ipmi_en, "yellow" if "Enabled" in ipmi_en else "green"),
            snmp_en, ssh_en, "Standard (≥8 chars)",
            scv_cell, spdm_cell,
        ])

    sheets = [{"name": "Summary", "rows": sum_rows}]
    sheets.extend(inv_sheets)
    sheets.append({"name": "Security", "rows": sec_rows})

    # ── Tab 11: Security Audit Findings (Normalized SCG Findings) ─────────────
    audit_hdr = [
        ("Host / IP", "header"),
        ("Hostname", "header"),
        ("Vendor", "header"),
        ("Control ID", "header"),
        ("Control Title", "header"),
        ("Status", "header"),
        ("Expected", "header"),
        ("Observed", "header"),
        ("Reason Code", "header"),
    ]
    audit_rows = [audit_hdr]

    for data in all_results:
        si = data.get("system") or {}
        ip = str(si.get("ip") or data.get("host") or "").strip()
        host = str(si.get("hostname") or "").strip()
        vendor = str(si.get("vendor") or "").strip()

        sec_score = score_host_security(data)
        if sec_score.get("is_fleet_manager"):
            audit_rows.append([
                ip, host, vendor, "OUT_OF_SCOPE", "Central Fleet Orchestrator",
                ("N/A", "yellow"), "—", "Fleet management plane excluded from host BMC audit", "OUT_OF_SCOPE_FLEET",
            ])
            continue

        audit = data.get("bmc_security_audit") or {}
        findings = audit.get("findings") or []
        if not findings:
            audit_rows.append([
                ip, host, vendor, "—", "No Audit Findings",
                ("Not Assessed", "yellow"), "—", "—", "NOT_ASSESSED",
            ])
            continue

        for f in findings:
            cid = str(f.get("control_id") or "")
            title = get_control_title(cid)
            status = str(f.get("status") or "")
            expected = str(f.get("expected") or "—")
            observed = f.get("observed")
            if observed is None:
                obs_str = "—"
            elif isinstance(observed, bool):
                obs_str = "Enabled" if observed else "Disabled"
            else:
                obs_str = str(observed)[:60]
            reason = str(f.get("reason_code") or "")

            if status == "pass":
                c_style = "green"
            elif status == "fail":
                c_style = "red"
            else:
                c_style = "yellow"

            audit_rows.append([
                ip, host, vendor, cid, title,
                (status, c_style), expected, obs_str, reason,
            ])

    sheets.append({"name": "Security_Audit", "rows": audit_rows})

    # ── Tab 12: Failed Hosts (Optional) ───────────────────────────────────────
    if failed_hosts:
        failed_hdr = [
            ("BMC IP", "header"), ("Hostname", "header"),
            ("Failure Reason", "header"), ("Stage", "header"), ("Details", "header"),
        ]
        failed_rows = [failed_hdr]
        for fh in failed_hosts:
            failed_rows.append([
                str(fh.get("ip") or "").strip(),
                str(fh.get("hostname") or "Unknown").strip(),
                (str(fh.get("reason_label") or fh.get("reason_code") or "Failed").strip(), "red"),
                str(fh.get("stage") or "N/A").strip(),
                str(fh.get("detail") or "").strip(),
            ])
        sheets.append({"name": "Failed_Hosts", "rows": failed_rows})

    return sheets


def _write_xlsx(sheets: list) -> bytes:
    """Generate standard openxml .xlsx binary payload using stdlib zipfile and XML."""
    _STYLE = {"header": 1, "green": 2, "yellow": 3, "red": 4}
    STYLES = (
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="3">'
        '<font><sz val="10"/><name val="Calibri"/></font>'
        '<font><b/><sz val="10"/><name val="Calibri"/><color rgb="FF1E3A5F"/></font>'
        '<font><b/><sz val="10"/><name val="Calibri"/></font>'
        '</fonts>'
        '<fills count="6">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFD4EDDA"/></patternFill></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFFFF3CD"/></patternFill></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFF8D7DA"/></patternFill></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFCFE2FF"/></patternFill></fill>'
        '</fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="5">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="5" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
        '<xf numFmtId="0" fontId="0" fillId="2" borderId="0" xfId="0" applyFill="1"/>'
        '<xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1"/>'
        '<xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1"/>'
        '</cellXfs>'
        '</styleSheet>'
    )

    def _cell_ref(col_idx: int, row_idx: int) -> str:
        name = ""
        n = col_idx + 1
        while n:
            name = chr(64 + n % 26 or 26) + name
            n = (n - 1) // 26
        return f"{name}{row_idx + 1}"

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        wb_xml = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                  '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
                  ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                  '<sheets>')
        rels_xml = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                    'relationships/styles" Target="styles.xml"/>')
        ct_overrides = ""
        sheet_xmls = {}
        for si, sheet in enumerate(sheets, 1):
            sid = f"rId{si + 1}"
            wb_xml += f'<sheet name="{_xe(sheet["name"])}" sheetId="{si}" r:id="{sid}"/>'
            rels_xml += (f'<Relationship Id="{sid}" Type="http://schemas.openxmlformats.org/'
                         f'officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{si}.xml"/>')
            ct_overrides += (f'<Override PartName="/xl/worksheets/sheet{si}.xml" '
                             f'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
            sx = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                  '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                  '<sheetData>')
            for ri, row in enumerate(sheet["rows"]):
                sx += f'<row r="{ri+1}">'
                for ci, cell in enumerate(row):
                    ref = _cell_ref(ci, ri)
                    style, val = 0, cell
                    if isinstance(cell, tuple):
                        val, style_key = cell
                        style = _STYLE.get(style_key, 0)
                    val_str = _xe(str(val)) if val is not None else ""
                    sx += f'<c r="{ref}" t="inlineStr" s="{style}"><is><t>{val_str}</t></is></c>'
                sx += '</row>'
            sx += '</sheetData></worksheet>'
            sheet_xmls[f"xl/worksheets/sheet{si}.xml"] = sx

        wb_xml += '</sheets></workbook>'
        rels_xml += '</Relationships>'
        ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
              '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
              '<Default Extension="xml" ContentType="application/xml"/>'
              '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
              '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
              f'{ct_overrides}'
              '</Types>')

        def _write_entry(z: zipfile.ZipFile, p: str, s: Union[str, bytes]) -> None:
            if isinstance(s, str):
                z.writestr(p, s.encode("utf-8", errors="replace"))
            else:
                z.writestr(p, s)

        _write_entry(zf, "[Content_Types].xml", ct)
        _write_entry(
            zf,
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            'relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        )
        _write_entry(zf, "xl/workbook.xml", wb_xml)
        _write_entry(zf, "xl/styles.xml", STYLES)
        _write_entry(zf, "xl/_rels/workbook.xml.rels", rels_xml)
        for path, xml in sheet_xmls.items():
            _write_entry(zf, path, xml)

    return buf.getvalue()


def build_inventory_xlsx_bytes(
    all_results: list,
    failed_hosts: Optional[list] = None,
    obfuscated: bool = False,
) -> bytes:
    """Return in-memory .xlsx bytes for assessment host results."""
    return _write_xlsx(_build_excel_sheets(all_results, failed_hosts=failed_hosts, obfuscated=obfuscated))


def build_obfuscated_inventory_zip(
    all_results: list,
    failed_hosts: Optional[list] = None,
) -> bytes:
    """Return in-memory ZIP bytes with obfuscated .xlsx + private obfuscation_key.json."""
    from vcf_hci.obfuscation import obfuscate_failed_hosts, obfuscate_fleet_with_key
    salt = os.urandom(16).hex()
    obf_results, key = obfuscate_fleet_with_key(all_results, salt=salt)
    obf_failed = obfuscate_failed_hosts(failed_hosts, salt=salt, key=key, start_idx=len(obf_results) + 1)
    xlsx = build_inventory_xlsx_bytes(obf_results, failed_hosts=obf_failed, obfuscated=True)
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("inventory_obfuscated.xlsx", xlsx)
        zf.writestr(
            "obfuscation_key.json",
            json.dumps(key.to_dict(), indent=2, default=str),
        )
        zf.writestr(
            "README.txt",
            "inventory_obfuscated.xlsx is safe to share externally.\n"
            "obfuscation_key.json contains real customer identifiers — KEEP PRIVATE.\n",
        )
    return buf.getvalue()


def export_to_excel(
    results: list,
    output_path: str,
    failed_hosts: Optional[list] = None,
    obfuscated: bool = False,
) -> str:
    """Generate multi-tab Excel workbook and write to output_path.

    If output_path is a directory or does not end with .xlsx, a timestamped
    filename (normal or 00_OBFUSCATED_ prefix) will be generated inside it.
    """
    if os.path.isdir(output_path) or not output_path.lower().endswith(".xlsx"):
        ts = time.strftime("%Y%m%d_%H%M%S")
        filename = f"00_OBFUSCATED_vcf_readiness_{ts}.xlsx" if obfuscated else f"vcf_readiness_{ts}.xlsx"
        target_file = os.path.join(output_path, filename)
    else:
        target_file = output_path

    os.makedirs(os.path.dirname(os.path.abspath(target_file)), exist_ok=True)
    if obfuscated and failed_hosts:
        from vcf_hci.obfuscation import obfuscate_failed_hosts
        failed_hosts = obfuscate_failed_hosts(failed_hosts, salt=os.urandom(16).hex(), start_idx=len(results) + 1)
    sheets = _build_excel_sheets(results, failed_hosts=failed_hosts, obfuscated=obfuscated)
    xlsx_bytes = _write_xlsx(sheets)
    with open(target_file, "wb") as f:
        f.write(xlsx_bytes)
    return target_file
