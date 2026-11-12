"""Join vSphere inventory snapshots to Redfish results for the unified workbook and HTML reports."""

from __future__ import annotations

import copy
from dataclasses import replace
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from vcf_hci.plugins.vinv.models import HostMatchRecord, ReconciliationReport, VinvSnapshot
from vcf_hci.plugins.vinv.obfuscate import _scrub_message, _token, obfuscate_vinv_snapshot
from vcf_hci.plugins.vinv.reconcile import (
    build_reconciliation_excel_sheet,
    enrich_redfish_results_with_vinv,
    reconcile_fleet,
)
from vcf_hci.plugins.vinv.schema import snapshot_to_excel_sheet_dicts

_PLACEHOLDERS = frozenset({"", "—", "-", "Not scanned", "Not found in vCenter", "Standalone", "Unknown"})


def _bmc_identity(host: Mapping[str, Any]) -> Tuple[str, str]:
    sys_info = host.get("system") or {}
    host_os = host.get("host_os") or {}
    ip = str(sys_info.get("ip") or sys_info.get("bmc_ip") or host.get("host") or "").strip()
    name = str(sys_info.get("dns_name") or sys_info.get("hostname") or host_os.get("hostname") or ip).strip()
    return ip, name


def identity_maps(raw_results: Sequence[Mapping[str, Any]], shown_results: Sequence[Mapping[str, Any]]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Map raw BMC IPs and hostnames to their obfuscated counterparts by list position."""
    ip_map: Dict[str, str] = {}
    host_map: Dict[str, str] = {}
    for raw, shown in zip(raw_results, shown_results):
        raw_ip, raw_name = _bmc_identity(raw)
        shown_ip, shown_name = _bmc_identity(shown)
        if raw_ip:
            ip_map[raw_ip] = shown_ip
        if raw_name:
            host_map[raw_name] = shown_name
    return ip_map, host_map


def esxi_alias_map(report: ReconciliationReport, host_map: Mapping[str, str]) -> Dict[str, str]:
    return {
        rec.esxi_host: host_map[rec.bmc_hostname]
        for rec in report.records
        if rec.match_status == "Matched" and rec.bmc_hostname in host_map and rec.esxi_host
    }


def _tok(salt: str, kind: str, value: str) -> str:
    return value if value in _PLACEHOLDERS else _token(salt, kind, value)


def _pair(salt: str, kind: str, value: str) -> str:
    return " / ".join(_tok(salt, kind, part.strip()) for part in value.split(" / "))


def _discrepancy(item: str) -> str:
    return "SERIAL_MISMATCH" if item.startswith("SERIAL_MISMATCH") else item


def obfuscate_reconciliation_report(
    report: ReconciliationReport,
    salt: str,
    ip_map: Mapping[str, str],
    host_map: Mapping[str, str],
    esxi_aliases: Mapping[str, str],
) -> ReconciliationReport:
    def record(rec: HostMatchRecord) -> HostMatchRecord:
        return replace(
            rec,
            bmc_ip=ip_map.get(rec.bmc_ip) or _tok(salt, "IP", rec.bmc_ip),
            bmc_hostname=host_map.get(rec.bmc_hostname) or _tok(salt, "Host", rec.bmc_hostname),
            vcenter_server=_tok(salt, "vCenter", rec.vcenter_server),
            datacenter=_tok(salt, "DC", rec.datacenter),
            cluster=_tok(salt, "CL", rec.cluster),
            esxi_host=esxi_aliases.get(rec.esxi_host) or _tok(salt, "Host", rec.esxi_host),
            service_tag_pair=_pair(salt, "SN", rec.service_tag_pair),
            discrepancies=tuple(_discrepancy(d) for d in rec.discrepancies),
        )

    rollups = tuple(
        dict(item, cluster=_tok(salt, "CL", str(item.get("cluster", ""))), datacenter=_tok(salt, "DC", str(item.get("datacenter", ""))))
        for item in report.cluster_rollups
    )
    return replace(
        report,
        vcenter_server=_tok(salt, "vCenter", report.vcenter_server),
        records=tuple(record(r) for r in report.records),
        cluster_rollups=rollups,
    )


def prepare_reconciliation(
    source_results: Sequence[Mapping[str, Any]],
    shown_results: Sequence[Mapping[str, Any]],
    snapshot: VinvSnapshot,
    obfuscated: bool,
    salt: str,
    manual_overrides: Optional[Mapping[str, str]] = None,
) -> Tuple[ReconciliationReport, VinvSnapshot]:
    """Reconcile on raw results; when obfuscated, re-key every identifier to the shown aliases."""
    report = reconcile_fleet(source_results, snapshot, manual_overrides=manual_overrides)
    if not obfuscated:
        return report, snapshot
    ip_map, host_map = identity_maps(source_results, shown_results)
    aliases = esxi_alias_map(report, host_map)
    return (
        obfuscate_reconciliation_report(report, salt, ip_map, host_map, aliases),
        obfuscate_vinv_snapshot(snapshot, salt, host_alias_map=aliases),
    )


def insert_vinv_sheets(sheets: List[Dict[str, Any]], report: ReconciliationReport, snapshot: VinvSnapshot) -> List[Dict[str, Any]]:
    """Insert Reconciliation after Decision (or Summary) and append the unified-name vSphere tabs."""
    out = list(sheets)
    names = [s.get("name") for s in out]
    anchor = names.index("Decision") if "Decision" in names else (names.index("Summary") if "Summary" in names else -1)
    out.insert(anchor + 1, build_reconciliation_excel_sheet(report))
    taken = {s.get("name") for s in out}
    for sheet in snapshot_to_excel_sheet_dicts(snapshot, unified_mode=True):
        if sheet["name"] in taken:
            sheet = dict(sheet, name=("vs_" + sheet["name"])[:31])
        taken.add(sheet["name"])
        out.append(sheet)
    return out


def enrich_copies(
    all_results: Sequence[Mapping[str, Any]],
    snapshot: VinvSnapshot,
    manual_overrides: Optional[Mapping[str, str]] = None,
) -> Tuple[List[Dict[str, Any]], ReconciliationReport]:
    """Deep-copy the results and attach vsphere_context; the caller's data is never mutated."""
    copies = [copy.deepcopy(dict(r)) for r in all_results]
    report = enrich_redfish_results_with_vinv(copies, snapshot, manual_overrides=manual_overrides)
    return copies, report


def _switch(salt: str, name: str) -> str:
    return _token(salt, "DVS", name)


def scrub_vsphere_context(
    ctx: Mapping[str, Any],
    salt: str,
    host_alias: str,
    mac_map: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """Tokenize every customer identifier in a vsphere_context dict for obfuscated reports."""
    macs = {k.lower(): v for k, v in (mac_map or {}).items()}
    out = dict(ctx)
    out["vcenter_server"] = _tok(salt, "vCenter", str(ctx.get("vcenter_server", "")))
    out["datacenter"] = _tok(salt, "DC", str(ctx.get("datacenter", "")))
    out["cluster"] = _tok(salt, "CL", str(ctx.get("cluster", "")))
    out["esxi_host"] = host_alias or _tok(salt, "Host", str(ctx.get("esxi_host", "")))
    out["vswitches"] = [_switch(salt, str(s)) for s in ctx.get("vswitches") or ()]
    out["vmk_ips"] = [
        {"device": v.get("device", ""), "ip": _tok(salt, "IP", str(v.get("ip", ""))),
         "portgroup": _tok(salt, "PG", str(v.get("portgroup", "")))}
        for v in ctx.get("vmk_ips") or ()
    ]
    vnics: Dict[str, Dict[str, Any]] = {}
    for mac, info in (ctx.get("vnic_by_mac") or {}).items():
        key = macs.get(str(mac).lower()) or _token(salt, "MAC", str(mac))
        scrubbed = dict(info)
        scrubbed["switch"] = _switch(salt, str(info.get("switch", "")))
        for field in ("cdp_switch", "lldp_chassis", "lldp_sysname"):
            scrubbed[field] = _tok(salt, "SW", str(info.get(field, "")))
        vnics[key] = scrubbed
    out["vnic_by_mac"] = vnics
    out["vms_summary"] = [dict(v, name=_tok(salt, "VM", str(v.get("name", "")))) for v in ctx.get("vms_summary") or ()]
    out["vhealth_findings"] = [
        dict(f, name=_tok(salt, "OBJ", str(f.get("name", ""))), message=_scrub_message(salt, str(f.get("message", ""))))
        for f in ctx.get("vhealth_findings") or ()
    ]
    out["discrepancies"] = [_discrepancy(str(d)) for d in ctx.get("discrepancies") or ()]
    return out


def _port_macs(host: Mapping[str, Any]) -> List[str]:
    found: List[str] = []
    for nic in host.get("network_adapters") or ():
        if isinstance(nic, dict):
            for port in nic.get("ports") or ():
                if isinstance(port, dict):
                    found.append(str(port.get("mac_address") or port.get("mac") or "").strip().lower())
    return found


def obfuscated_report_inputs(
    enriched: Sequence[Dict[str, Any]],
    report: ReconciliationReport,
    salt: str,
) -> Tuple[List[Dict[str, Any]], ReconciliationReport]:
    """Obfuscate enriched results with the Redfish obfuscator, then scrub vsphere_context to match."""
    from vcf_hci.obfuscation import obfuscate_host_data

    shown: List[Dict[str, Any]] = []
    for index, host in enumerate(enriched):
        ctx = host.get("vsphere_context")
        base = {k: v for k, v in host.items() if k != "vsphere_context"}
        obf = obfuscate_host_data(base, f"Host-{index + 1}", salt)
        if isinstance(obf.get("host_os"), dict) and obf["host_os"].get("hostname"):
            obf["host_os"]["hostname"] = _bmc_identity(obf)[1]
        if ctx:
            mac_map = {raw: new for raw, new in zip(_port_macs(base), _port_macs(obf)) if raw}
            obf["vsphere_context"] = scrub_vsphere_context(ctx, salt, _bmc_identity(obf)[1], mac_map)
        shown.append(obf)
    ip_map, host_map = identity_maps(enriched, shown)
    return shown, obfuscate_reconciliation_report(report, salt, ip_map, host_map, esxi_alias_map(report, host_map))


def build_reconciled_fleet_html(
    results: Sequence[Mapping[str, Any]],
    snapshot: VinvSnapshot,
    obfuscated: bool,
    salt: str,
    json_hcl: Optional[dict] = None,
) -> str:
    """Render the combined fleet report with vSphere context; host reports are rendered into a temp dir."""
    import os
    import re
    import shutil
    import tempfile

    from vcf_hci.report.fleet.combined import _generate_combined_html
    from vcf_hci.report.host_report import generate_host_html_report

    enriched, report = enrich_copies(results, snapshot)
    workdir = tempfile.mkdtemp(prefix="vinv_fleet_")
    try:
        paths: List[str] = []
        if obfuscated:
            shown, shown_report = obfuscated_report_inputs(enriched, report, salt)
        else:
            shown, shown_report = enriched, report
            for index, host in enumerate(shown):
                ident = re.sub(r"[^A-Za-z0-9._-]", "_", _bmc_identity(host)[0]) or f"host{index + 1}"
                path = os.path.join(workdir, f"vsphere_vsan_report_{ident}.html")
                generate_host_html_report(host, path, json_hcl=json_hcl)
                paths.append(path)
        out = _generate_combined_html(
            shown, paths, workdir, obfuscated=obfuscated, output_filename="vinv_fleet_combined.html",
            embed_mode="inline", json_hcl=json_hcl, vinv_report=shown_report,
        )
        if not out:
            raise RuntimeError("combined report generation failed")
        with open(out, encoding="utf-8") as fh:
            return fh.read()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
