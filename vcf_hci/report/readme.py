"""
VCF Readiness Tool — Scan deliverables Readme generator (Layer D).

Generates a comprehensive, human-readable Readme.txt index inside scan output
directories and assembled fleet drops, guiding users on how to navigate HTML
dashboards, Excel workbooks, CSV inventories, individual host reports, and raw JSON.
Zero external dependencies (stdlib only).
"""

import datetime
import json
import logging
import os
from typing import Dict, List, Optional

from vcf_hci.constants import TOOL_VERSION

logger = logging.getLogger("vcf_assess")


def generate_scan_readme(
    outdir: str,
    host_count: int = 0,
    site: Optional[str] = None,
    collector_id: Optional[str] = None,
    scan_profile: Optional[str] = None,
    obfuscated: bool = False,
    tool_version: Optional[str] = None,
    scanned_at: Optional[str] = None,
    failed_count: int = 0,
) -> str:
    """Generate structured plain-text Readme.txt content describing scan artifacts.

    Inspects `outdir` dynamically to catalogue present deliverables and tailor
    navigation guidance.
    """
    outdir = os.path.abspath(os.path.expanduser(outdir)) if outdir else ""

    # Attempt to load metadata from MANIFEST.json if parameters were not explicitly provided
    if outdir and os.path.isdir(outdir):
        manifest_path = os.path.join(outdir, "MANIFEST.json")
        if os.path.isfile(manifest_path):
            try:
                with open(manifest_path, encoding="utf-8") as mf:
                    mdata = json.load(mf)
                if not host_count and mdata.get("host_count"):
                    host_count = int(mdata["host_count"])
                if not site and mdata.get("site"):
                    site = str(mdata["site"])
                if not collector_id and mdata.get("collector_id"):
                    collector_id = str(mdata["collector_id"])
                if not scan_profile and mdata.get("scan_profile"):
                    scan_profile = str(mdata["scan_profile"])
                if not obfuscated and mdata.get("obfuscated"):
                    obfuscated = bool(mdata["obfuscated"])
                if not tool_version and mdata.get("tool_version"):
                    tool_version = str(mdata["tool_version"])
                if not scanned_at and mdata.get("scanned_at"):
                    scanned_at = str(mdata["scanned_at"])
            except Exception as exc:
                logger.debug("Failed reading MANIFEST.json in %s: %s", outdir, exc)

    tool_ver = tool_version or TOOL_VERSION
    scan_time = scanned_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Inspect directory contents to adapt file catalog and quick-start recommendations
    existing_root_files = set(os.listdir(outdir)) if (outdir and os.path.isdir(outdir)) else set()

    reports_dir = os.path.join(outdir, "reports") if outdir else ""
    report_files = sorted(os.listdir(reports_dir)) if (reports_dir and os.path.isdir(reports_dir)) else []

    data_dir = os.path.join(outdir, "data") if outdir else ""
    data_files = sorted(os.listdir(data_dir)) if (data_dir and os.path.isdir(data_dir)) else []

    # If host_count is still 0, infer from reports or JSON files
    if host_count <= 0:
        html_reports = [f for f in report_files if f.endswith(".html") and not f.startswith("OBFUSCATED_")]
        if html_reports:
            host_count = len(html_reports)
        else:
            obf_reports = [f for f in report_files if f.endswith(".html") and f.startswith("OBFUSCATED_")]
            if obf_reports:
                host_count = len(obf_reports)

    # Check for obfuscated files presence
    has_obfuscated_artifacts = (
        obfuscated
        or any(f.startswith("00_OBFUSCATED_") for f in existing_root_files)
        or any(f.startswith("OBFUSCATED_") for f in report_files)
        or any(f.startswith("OBFUSCATED_") for f in data_files)
    )

    # Detect presence of primary deliverables
    has_fleet_combined = "00_fleet_combined.html" in existing_root_files
    has_fleet_summary = "00_fleet_summary.html" in existing_root_files
    has_obf_combined = "00_OBFUSCATED_fleet_combined.html" in existing_root_files
    has_obf_summary = "00_OBFUSCATED_fleet_summary.html" in existing_root_files

    excel_files = [f for f in existing_root_files if f.endswith(".xlsx") and not f.startswith("00_OBFUSCATED_")]
    obf_excel_files = [f for f in existing_root_files if f.endswith(".xlsx") and f.startswith("00_OBFUSCATED_")]
    primary_excel = excel_files[0] if excel_files else "vcf_readiness_<timestamp>.xlsx"
    primary_obf_excel = obf_excel_files[0] if obf_excel_files else "00_OBFUSCATED_vcf_readiness_<timestamp>.xlsx"

    has_excel = bool(excel_files or obf_excel_files)
    has_csvs = any(f.endswith(".csv") for f in existing_root_files)
    has_reports = bool(report_files)
    has_data = bool(data_files)

    # Check for failed hosts csv
    has_failed_csv = "00_failed_hosts.csv" in existing_root_files or "00_OBFUSCATED_failed_hosts.csv" in existing_root_files
    has_gpus_csv = "00_gpus_inventory.csv" in existing_root_files or "00_OBFUSCATED_gpus_inventory.csv" in existing_root_files

    # Build Header Section
    meta_parts: List[str] = [f"Version: {tool_ver}", f"Scan Date: {scan_time}"]
    if host_count > 0:
        meta_parts.append(f"Hosts: {host_count}")
    if site:
        meta_parts.append(f"Site: {site}")
    if scan_profile:
        meta_parts.append(f"Profile: {scan_profile}")
    if collector_id:
        meta_parts.append(f"Collector ID: {collector_id}")
    if has_obfuscated_artifacts and not obfuscated:
        meta_parts.append("Contains Obfuscated Copies")
    elif obfuscated:
        meta_parts.append("Obfuscated Package")

    meta_str = " | ".join(meta_parts)
    divider = "=" * 80

    lines: List[str] = []
    lines.append(divider)
    lines.append("VCF / vSphere 9.1 HCI Readiness Assessment — Scan Deliverables Package")
    lines.append(meta_str)
    lines.append(divider)
    lines.append("")

    # Section 1: Overview
    lines.append("OVERVIEW:")
    lines.append("-" * 80)
    lines.append("This directory contains the complete readiness assessment deliverables evaluating")
    lines.append("physical server hardware for VMware Cloud Foundation (VCF) 9.1 and vSAN ESA")
    lines.append("compatibility. All telemetry was collected via out-of-band Redfish BMC APIs")
    lines.append("without requiring hypervisor or operating system agents.")
    lines.append("")

    # Section 2: Where Do I Start?
    lines.append("WHERE DO I START? (RECOMMENDED NAVIGATION):")
    lines.append("-" * 80)
    step_num = 1

    if has_fleet_combined or has_obf_combined or host_count > 1:
        target_combined = "00_OBFUSCATED_fleet_combined.html" if obfuscated else "00_fleet_combined.html"
        lines.append(f"{step_num}. Interactive Fleet Dashboard & Inventory Matrix (Start Here):")
        lines.append(f"   -> Open \"{target_combined}\" in any modern web browser.")
        lines.append("      Self-contained single-page application featuring a multi-host switcher,")
        lines.append("      searchable inventory decision matrix, and embedded server drill-downs.")
        lines.append("      Requires no web server or internet connectivity.")
        lines.append("")
        step_num += 1

    if has_fleet_summary or has_obf_summary or host_count > 0:
        target_summary = "00_OBFUSCATED_fleet_summary.html" if obfuscated else "00_fleet_summary.html"
        lines.append(f"{step_num}. Executive / High-Level Cluster Summary:")
        lines.append(f"   -> Open \"{target_summary}\" in any modern web browser.")
        lines.append("      Provides executive cluster KPIs: CPU compatibility tiers, vSAN ESA")
        lines.append("      eligibility distribution, 25+ GbE NIC readiness, and security posture.")
        lines.append("")
        step_num += 1

    if has_excel or has_csvs:
        target_excel = primary_obf_excel if obfuscated else primary_excel
        pfx = "00_OBFUSCATED_" if obfuscated else "00_"
        lines.append(f"{step_num}. Sizing, Procurement & Hardware Analysis:")
        lines.append(f"   -> Open \"{target_excel}\" (Excel spreadsheet with styled tabs)")
        lines.append("   -> Or inspect CSV exports for automated ingestion into external pipelines:")
        lines.append(f"      - {pfx}fleet_summary.csv       (per-host readiness verdicts and specs)")
        lines.append(f"      - {pfx}drives_inventory.csv    (disk bus types, wear endurance %, ESA status)")
        lines.append(f"      - {pfx}nics_inventory.csv      (network adapters, link speeds, firmware, PCI IDs)")
        if has_gpus_csv:
            lines.append(f"      - {pfx}gpus_inventory.csv      (PCIe accelerators and GPU devices)")
        if has_failed_csv or failed_count > 0:
            lines.append(f"      - {pfx}failed_hosts.csv        (unreachable or authentication-failed targets)")
        lines.append("")
        step_num += 1

    if has_reports:
        if obfuscated:
            sample_report = next((f for f in report_files if f.startswith("OBFUSCATED_")), "OBFUSCATED_Host-1.html")
        else:
            sample_report = report_files[0] if report_files else "vsphere_vsan_report_<ip>.html"
        lines.append(f"{step_num}. Detailed Server Deep-Dives:")
        lines.append("   -> Inspect individual HTML reports in the \"reports/\" directory:")
        lines.append(f"      reports/{sample_report}")
        lines.append("      Each report provides component tables, Broadcom Compatibility Guide (BCG)")
        lines.append("      verification links, BIOS/BMC firmware baselines, Intel VMD pass-through")
        lines.append("      configuration checks, and actionable hardware remediation guidance.")
        lines.append("")

    # Section 3: Root File Catalog
    lines.append("ROOT FILE CATALOG:")
    lines.append("-" * 80)

    catalog_entries: List[Dict[str, str]] = []
    if not obfuscated and has_fleet_combined:
        catalog_entries.append({
            "name": "00_fleet_combined.html",
            "desc": "Interactive multi-host dashboard and component matrix with integrated drill-down viewer.",
        })
    if not obfuscated and has_fleet_summary:
        catalog_entries.append({
            "name": "00_fleet_summary.html",
            "desc": "Executive fleet summary dashboard with cluster-level readiness KPIs and statistics.",
        })
    if has_obf_combined:
        catalog_entries.append({
            "name": "00_OBFUSCATED_fleet_combined.html",
            "desc": "Sanitized interactive fleet dashboard (safe for external distribution and partner sharing).",
        })
    if has_obf_summary:
        catalog_entries.append({
            "name": "00_OBFUSCATED_fleet_summary.html",
            "desc": "Sanitized executive fleet summary dashboard with scrubbed IPs, hostnames, and serials.",
        })

    target_xlsx_files = obf_excel_files if obfuscated else (excel_files + obf_excel_files)
    for xf in target_xlsx_files:
        prefix_note = "Sanitized multi-tab" if "OBFUSCATED" in xf else "Multi-tab"
        catalog_entries.append({
            "name": xf,
            "desc": f"{prefix_note} Microsoft Excel workbook (Fleet Summary, Drives, NICs, GPUs, Failures).",
        })

    csv_items = [
        ("00_OBFUSCATED_fleet_summary.csv", "Sanitized cluster summary CSV with anonymous host identifiers."),
        ("00_OBFUSCATED_drives_inventory.csv", "Sanitized drives inventory CSV with scrubbed serials and addresses."),
        ("00_OBFUSCATED_nics_inventory.csv", "Sanitized network adapter CSV with normalized MAC addresses."),
        ("00_OBFUSCATED_gpus_inventory.csv", "Sanitized GPU accelerator CSV with scrubbed slot identifiers."),
        ("00_OBFUSCATED_failed_hosts.csv", "Sanitized unreachable host log with error codes."),
    ] if obfuscated else [
        ("00_fleet_summary.csv", "Cluster hardware inventory and VCF compatibility verdicts (CSV format)."),
        ("00_drives_inventory.csv", "Physical storage drives, bus types, wear endurance %, and ESA qualification."),
        ("00_nics_inventory.csv", "Network adapters, port speeds, firmware baselines, and driver compatibility."),
        ("00_gpus_inventory.csv", "PCIe GPUs and hardware accelerators with PCI IDs and subsystem information."),
        ("00_failed_hosts.csv", "Unreachable or authentication-failed targets with error diagnostic codes."),
        ("00_OBFUSCATED_fleet_summary.csv", "Sanitized cluster summary CSV with anonymous host identifiers."),
        ("00_OBFUSCATED_drives_inventory.csv", "Sanitized drives inventory CSV with scrubbed serials and addresses."),
        ("00_OBFUSCATED_nics_inventory.csv", "Sanitized network adapter CSV with normalized MAC addresses."),
        ("00_OBFUSCATED_gpus_inventory.csv", "Sanitized GPU accelerator CSV with scrubbed slot identifiers."),
        ("00_OBFUSCATED_failed_hosts.csv", "Sanitized unreachable host log with error codes."),
    ]
    for csv_name, csv_desc in csv_items:
        if csv_name in existing_root_files:
            catalog_entries.append({"name": csv_name, "desc": csv_desc})

    if "MANIFEST.json" in existing_root_files or outdir:
        catalog_entries.append({
            "name": "MANIFEST.json",
            "desc": "Machine-readable scan provenance (tool version, timestamp, host count, site ID).",
        })

    catalog_entries.append({
        "name": "Readme.txt",
        "desc": "This guide — documentation and index of all deliverables in this assessment package.",
    })

    if not obfuscated:
        zip_files = [f for f in existing_root_files if f.endswith(".zip")]
        for zf in zip_files:
            catalog_entries.append({
                "name": zf,
                "desc": "Compressed distribution archive containing this entire assessment deliverables package.",
            })

    for entry in catalog_entries:
        lines.append(f"• {entry['name']}")
        lines.append(f"  {entry['desc']}")
        lines.append("")

    # Section 4: Subdirectories
    lines.append("SUBDIRECTORIES:")
    lines.append("-" * 80)
    lines.append("reports/")
    lines.append("  Contains standalone, zero-dependency HTML evaluation reports for each host.")
    lines.append("  These reports can be opened directly in any browser, emailed individually, or")
    lines.append("  viewed within the combined fleet dashboard.")
    if not obfuscated:
        lines.append("  - vsphere_vsan_report_<ip>.html: Full report with authentic IP and hostnames.")
    if has_obfuscated_artifacts:
        lines.append("  - OBFUSCATED_Host-<N>.html: Sanitized report with scrubbed PII for external review.")
    lines.append("")

    lines.append("data/")
    lines.append("  Contains structured JSON data captures and API manifests:")
    if not obfuscated:
        lines.append("  - fleet_summary.json: Normalized dataset representing all assessed hosts.")
    if has_obfuscated_artifacts:
        lines.append("  - OBFUSCATED_fleet_summary.json: Sanitized fleet dataset.")
    if not obfuscated:
        lines.append("  - vcf_summary_<ip>.json: Per-host normalized hardware telemetry and evaluation.")
    else:
        lines.append("  - OBFUSCATED_Host-<N>.json: Sanitized per-host normalized hardware telemetry.")
    if not obfuscated:
        lines.append("  - endpoints_manifest_*.json / .csv: (If crawl enabled) Discovered Redfish URIs.")
        lines.append("  - actions_manifest_*.json / .csv: (If crawl enabled) Discovered write/POST actions.")
        lines.append("  - redfish_mockup_*.zip: (If crawl enabled) DMTF-compliant Redfish mockup archive.")
        lines.append("  - vcf_assess_debug.log: (If debug enabled) Comprehensive collection log.")
    lines.append("")

    # Section 5: Data Privacy & Obfuscation (if applicable)
    if has_obfuscated_artifacts:
        lines.append("DATA PRIVACY & OBFUSCATION NOTICE:")
        lines.append("-" * 80)
        lines.append("This assessment folder contains sanitized (\"OBFUSCATED\") deliverables designed")
        lines.append("for safe external distribution to Broadcom/VMware teams, partners, and customers:")
        lines.append("• Host identities are replaced with anonymous aliases (Host-1, Host-2, ...).")
        lines.append("• BMC IP addresses, hostnames, serial numbers, and service tags are scrubbed.")
        lines.append("• Network MAC addresses and sensitive identifiers are normalized.")
        lines.append("• OEM hardware models, CPU architectures, firmware revisions, and component")
        lines.append("  compatibility verdicts remain 100% authentic Redfish telemetry from live servers.")
        lines.append("")

    # Section 6: Offline Re-Import & Fleet Assembly
    lines.append("OFFLINE RE-IMPORT & FLEET ASSEMBLY:")
    lines.append("-" * 80)
    lines.append("All assessment data in this package can be reloaded into the VCF Readiness Tool")
    lines.append("at any time without requiring network connectivity to the physical server BMCs:")
    lines.append("")
    lines.append("1. Web Browser UI:")
    lines.append("   - Launch the web UI ('python vcfr_web.py' or start the desktop app).")
    lines.append("   - Navigate to 'Fleet Library' or 'Import Summary'.")
    lines.append("   - Select this scan directory, upload 'data/fleet_summary.json', or drag-and-drop")
    lines.append("     the compressed .zip bundle into the application.")
    lines.append("")
    lines.append("2. Command Line Interface (CLI):")
    lines.append("   - Re-generate reports or export fresh spreadsheets from existing scan data:")
    lines.append("     python vcfr_collector.py --from-summary <path-to-folder-or-zip>")
    lines.append("   - Merge multiple site scan packages into an assembled master fleet:")
    lines.append("     python vcfr_collector.py --from-summary /path/to/scans/ --site \"Datacenter-1\"")
    lines.append("")
    lines.append(divider)

    return "\n".join(lines) + "\n"


def write_scan_readme(
    outdir: str,
    host_count: int = 0,
    site: Optional[str] = None,
    collector_id: Optional[str] = None,
    scan_profile: Optional[str] = None,
    obfuscated: bool = False,
    tool_version: Optional[str] = None,
    scanned_at: Optional[str] = None,
    failed_count: int = 0,
) -> str:
    """Generate and write Readme.txt inside the specified scan output directory.

    Returns the absolute path to the written Readme.txt file, or empty string on error.
    """
    if not outdir:
        return ""

    outdir = os.path.abspath(os.path.expanduser(outdir))
    readme_path = os.path.join(outdir, "Readme.txt")

    try:
        os.makedirs(outdir, exist_ok=True)
        content = generate_scan_readme(
            outdir=outdir,
            host_count=host_count,
            site=site,
            collector_id=collector_id,
            scan_profile=scan_profile,
            obfuscated=obfuscated,
            tool_version=tool_version,
            scanned_at=scanned_at,
            failed_count=failed_count,
        )
        with open(readme_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        return readme_path
    except Exception as exc:
        logger.warning("Failed writing Readme.txt in %s: %s", outdir, exc)
        return ""
