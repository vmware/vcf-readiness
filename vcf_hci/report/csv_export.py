"""
VCF Readiness Tool — CSV export generator (stdlib CSV writer).

Generates standardized, forward-compatible CSV exports for fleet summaries,
storage drive inventories, NIC topologies, GPUs, and failed hosts (Schema v2.0).
Zero external dependencies (stdlib csv only).
"""

import csv
import io
import os
from typing import Any, Dict, List, Optional

from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.report.schema_registry import (
    FLEET_SUMMARY_FIELDS,
    strip_html,
)


def generate_fleet_summary_csv(
    results: List[Dict[str, Any]],
    output_path: Optional[str] = None,
) -> str:
    """Build standardized Fleet Summary CSV (1 row per host)."""
    headers = [f.header for f in FLEET_SUMMARY_FIELDS]
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(headers)

    for data in results:
        row = []
        for field in FLEET_SUMMARY_FIELDS:
            try:
                val = field.extractor(data)
            except Exception:
                val = ""
            if isinstance(val, str):
                val = strip_html(val)
            row.append(val if val is not None else "")
        writer.writerow(row)

    csv_content = buf.getvalue()
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8", errors="replace", newline="") as f:
            f.write(csv_content)

    return csv_content


def generate_drives_csv(
    results: List[Dict[str, Any]],
    output_path: Optional[str] = None,
) -> str:
    """Build comprehensive Storage & Drive Inventory CSV (1 row per drive)."""
    headers = [
        "Host / IP", "Hostname", "Controller", "Controller FW", "Drive ID",
        "Drive Name", "Model", "Serial Number", "Part Number", "Media Type",
        "Protocol", "Capacity GB", "Category", "HCL Tier", "Drive Health",
        "Endurance Life %", "TBW Written (TB)", "Power-On Hours", "Temperature (°C)",
        "Unsafe Shutdowns", "Behind Tri-Mode", "Form Factor", "Firmware",
    ]
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(headers)

    for data in results:
        si = data.get("system") or {}
        ip = str(si.get("ip") or data.get("host") or "").strip()
        host = str(si.get("hostname") or "").strip()
        for ctrl in data.get("storage_subsystem", []):
            ctrl_name = str(ctrl.get("name") or ctrl.get("controller_model") or "Controller").strip()
            ctrl_fw = str(ctrl.get("ctrl_firmware") or ctrl.get("firmware_version") or "").strip()
            for d in ctrl.get("drives", []):
                if not d.get("populated", True) and d.get("category") == "Empty":
                    continue
                ep = d.get("endurance_remaining_pct", "")
                ep_str = f"{ep}%" if (ep != "" and ep != "N/A" and ep is not None) else "N/A"
                writer.writerow([
                    ip,
                    host,
                    ctrl_name,
                    ctrl_fw,
                    str(d.get("id") or d.get("bay_slot") or "").strip(),
                    str(d.get("name") or "").strip(),
                    str(d.get("model") or "").strip(),
                    str(d.get("serial_number") or d.get("serial") or "").strip(),
                    str(d.get("part_number") or "").strip(),
                    str(d.get("media_type") or "").strip(),
                    str(d.get("protocol") or "").strip(),
                    d.get("capacity_gb", ""),
                    strip_html(d.get("category", "")),
                    strip_html(d.get("hcl_str") or d.get("status_badge", "")),
                    strip_html(d.get("drive_health", "")),
                    ep_str,
                    str(d.get("tbw_written") if d.get("tbw_written") is not None else ""),
                    str(d.get("power_on_hours") if d.get("power_on_hours") is not None else ""),
                    str(d.get("temperature_c") if d.get("temperature_c") is not None else ""),
                    str(d.get("unsafe_shutdowns") if d.get("unsafe_shutdowns") is not None else ""),
                    "Yes" if (d.get("behind_trimode") or d.get("category") == "Unsupported NVMe Tri-Mode") else "No",
                    str(d.get("form_factor_label") or "").strip(),
                    str(d.get("firmware") or "").strip(),
                ])

    csv_content = buf.getvalue()
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8", errors="replace", newline="") as f:
            f.write(csv_content)

    return csv_content


def generate_nics_csv(
    results: List[Dict[str, Any]],
    output_path: Optional[str] = None,
) -> str:
    """Build Network Adapters, Ports & Switch Topology CSV (1 row per port)."""
    headers = [
        "Host / IP", "Hostname", "Adapter Name", "Part Number", "Port ID",
        "MAC Address", "Link Status", "Speed Gbps", "Firmware Version",
        "PCI Quad", "CNA / NPAR", "LLDP Switch Name", "LLDP Switch Port",
        "LLDP Chassis ID", "LLDP Mgmt IP",
        "Transceiver Type", "Transceiver Media", "Transceiver Vendor", "Transceiver Part Number",
    ]
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(headers)

    for data in results:
        si = data.get("system") or {}
        ip = str(si.get("ip") or data.get("host") or "").strip()
        host = str(si.get("hostname") or "").strip()

        # Build lookup for LLDP neighbor by port_id / interface / mac
        lldp_lookup: Dict[str, Dict[str, Any]] = {}
        for lldp in data.get("lldp_neighbors", []):
            if lldp.get("local_iface"):
                lldp_lookup[str(lldp["local_iface"]).strip()] = lldp
            if lldp.get("local_mac"):
                lldp_lookup[str(lldp["local_mac"]).strip().lower()] = lldp

        for n in data.get("network_adapters", []):
            nic_name = str(n.get("name") or "Network Adapter").strip()
            pn = str(n.get("part_number") or "").strip()
            fw = str(n.get("firmware_version") or "").strip()
            pci = str(n.get("pci_quad") or n.get("pci_pair") or "").strip()
            cna_status = "CNA (VIC Virtual)" if n.get("is_vic_virtual") else "CNA & NPAR" if (n.get("is_cna") and n.get("is_npar")) else "CNA" if n.get("is_cna") else "NPAR" if n.get("is_npar") else "Standard"

            for p in n.get("ports", []):
                pid = str(p.get("port_id") or p.get("name") or "").strip()
                mac = str(p.get("mac_address") or "").strip()
                speed = p.get("current_speed_gbps", "")
                link = str(p.get("link_status") or "").strip()

                lldp_info = lldp_lookup.get(pid) or lldp_lookup.get(mac.lower()) or {}
                sw_name = str(lldp_info.get("switch_name") or "").strip()
                sw_port = str(lldp_info.get("switch_port") or "").strip()
                sw_chassis = str(lldp_info.get("chassis_id") or "").strip()
                sw_mgmt = str(lldp_info.get("mgmt_ipv4") or "").strip()

                writer.writerow([
                    ip, host, nic_name, pn, pid, mac, link, speed, fw,
                    pci, cna_status, sw_name, sw_port, sw_chassis, sw_mgmt,
                    str(p.get("transceiver_identifier") or "N/A"),
                    str(p.get("transceiver_interface") or "N/A"),
                    str(p.get("transceiver_vendor") or "N/A"),
                    str(p.get("transceiver_part_number") or "N/A"),
                ])

    csv_content = buf.getvalue()
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8", errors="replace", newline="") as f:
            f.write(csv_content)

    return csv_content


def generate_gpus_csv(
    results: List[Dict[str, Any]],
    output_path: Optional[str] = None,
) -> str:
    """Build GPU & Acceleration Hardware CSV (1 row per accelerator)."""
    headers = [
        "Host / IP", "Hostname", "GPU / Device Name", "Manufacturer",
        "PCIe Slot", "PCIe Gen", "Lanes", "PCI Quad", "Part Number",
        "Serial Number", "Health / State", "VCF AI / vGPU Readiness",
        "Temperature (°C)", "Max Operating Temp (°C)", "Power Brake Status",
    ]
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(headers)

    for data in results:
        si = data.get("system") or {}
        ip = str(si.get("ip") or data.get("host") or "").strip()
        host = str(si.get("hostname") or "").strip()

        for g in data.get("gpu_accelerators", []):
            raw = (str(g.get("name") or "") + " " + str(g.get("manufacturer") or "")).upper()
            vcf_ai = "High (Enterprise AI/LLM)" if any(k in raw for k in ("H100", "H200", "A100", "L40", "MI300")) else "Supported (vGPU / Compute)"
            writer.writerow([
                ip,
                host,
                str(g.get("name") or "GPU").strip(),
                str(g.get("manufacturer") or "").strip(),
                str(g.get("slot") or g.get("slot_label") or "").strip(),
                str(g.get("pcie_gen") or "").strip(),
                g.get("lanes", ""),
                str(g.get("pci_quad") or g.get("pci_pair") or "").strip(),
                str(g.get("part_number") or "").strip(),
                str(g.get("serial_number") or "").strip(),
                strip_html(g.get("health", "OK")),
                vcf_ai,
                str(g.get("temperature_c") if g.get("temperature_c") is not None else ""),
                str(g.get("max_operating_temp_c") if g.get("max_operating_temp_c") is not None else ""),
                str(g.get("power_brake_status") or "N/A"),
            ])

    csv_content = buf.getvalue()
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8", errors="replace", newline="") as f:
            f.write(csv_content)

    return csv_content


def generate_failed_hosts_csv(
    failed_hosts: List[Dict[str, Any]],
    output_path: Optional[str] = None,
) -> str:
    """Build Unreachable / Failed Hosts CSV."""
    headers = ["BMC IP", "Hostname", "Failure Reason", "Stage", "Details"]
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(headers)

    for fh in failed_hosts:
        writer.writerow([
            str(fh.get("ip") or "").strip(),
            str(fh.get("hostname") or "Unknown").strip(),
            str(fh.get("reason_label") or fh.get("reason_code") or "Failed").strip(),
            str(fh.get("stage") or "N/A").strip(),
            str(fh.get("detail") or "").strip(),
        ])

    csv_content = buf.getvalue()
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8", errors="replace", newline="") as f:
            f.write(csv_content)

    return csv_content


def export_all_csvs(
    results: List[Dict[str, Any]],
    outdir: str,
    obfuscated: bool = False,
    failed_hosts: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, str]:
    """Generate and write all CSV export files into outdir.

    Returns dict mapping artifact name -> absolute filepath.
    """
    prefix = "00_OBFUSCATED_" if obfuscated else "00_"
    os.makedirs(outdir, exist_ok=True)

    if obfuscated:
        _salt = os.urandom(16).hex()
        if results:
            import re

            from vcf_hci.obfuscation import obfuscate_host_data
            _needs_obf = any(
                not r.get("obfuscated") and not re.match(r"^Host-\d+$", str((r.get("system") or {}).get("hostname", "")))
                for r in results
            )
            if _needs_obf:
                results = [
                    obfuscate_host_data(r, f"Host-{i+1}", _salt) if (not r.get("obfuscated") and not re.match(r"^Host-\d+$", str((r.get("system") or {}).get("hostname", "")))) else r
                    for i, r in enumerate(results)
                ]
        if failed_hosts:
            import re

            from vcf_hci.obfuscation import obfuscate_failed_hosts
            _needs_fh_obf = any(
                not re.match(r"^Host-\d+$", str(fh.get("hostname", "")))
                for fh in failed_hosts
            )
            if _needs_fh_obf:
                failed_hosts = obfuscate_failed_hosts(failed_hosts, salt=_salt, start_idx=len(results) + 1)

    artifacts = {}

    # 1. Fleet Summary CSV
    sum_fname = sanitize_filename(f"{prefix}fleet_summary.csv")
    sum_path = os.path.join(outdir, sum_fname)
    generate_fleet_summary_csv(results, sum_path)
    artifacts["fleet_summary_csv"] = sum_path

    # 2. Drives Inventory CSV
    drives_fname = sanitize_filename(f"{prefix}drives_inventory.csv")
    drives_path = os.path.join(outdir, drives_fname)
    generate_drives_csv(results, drives_path)
    artifacts["drives_csv"] = drives_path

    # 3. NICs Inventory CSV
    nics_fname = sanitize_filename(f"{prefix}nics_inventory.csv")
    nics_path = os.path.join(outdir, nics_fname)
    generate_nics_csv(results, nics_path)
    artifacts["nics_csv"] = nics_path

    # 4. GPUs CSV (if any GPUs present)
    has_gpus = any(bool(r.get("gpu_accelerators")) for r in results)
    if has_gpus:
        gpus_fname = sanitize_filename(f"{prefix}gpus_inventory.csv")
        gpus_path = os.path.join(outdir, gpus_fname)
        generate_gpus_csv(results, gpus_path)
        artifacts["gpus_csv"] = gpus_path

    # 5. Failed Hosts CSV (if any failed targets)
    if failed_hosts:
        failed_fname = sanitize_filename(f"{prefix}failed_hosts.csv")
        failed_path = os.path.join(outdir, failed_fname)
        generate_failed_hosts_csv(failed_hosts, failed_path)
        artifacts["failed_hosts_csv"] = failed_path

    return artifacts
