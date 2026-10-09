"""
VCF Readiness Tool — Post-collection hardware enrichment pipeline.

Applies VCF 9.1 compatibility rules (Layer B) and BCG deep-links (Layer C)
to a normalized hardware payload (Layer A) in a single post-collection pass.
"""
import logging
import math
import re
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("vcf_assess")

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.bios.cisco_baseline import evaluate_cisco_bios_baseline
from vcf_hci.bios.dell_baseline import evaluate_dell_bios_baseline
from vcf_hci.bios.generic_baseline import evaluate_generic_bios_baseline
from vcf_hci.bios.hpe_baseline import evaluate_hpe_bios_baseline
from vcf_hci.bios.lenovo_baseline import evaluate_lenovo_bios_baseline
from vcf_hci.collector.collect_network import infer_nic_manufacturer
from vcf_hci.collector.collect_storage_drive import sanitize_endurance_pct
from vcf_hci.collector.pci_utils import extract_pci_ids_from_dict, normalize_pci_id, select_best_pci_pair_entry
from vcf_hci.compat_engine import (
    VCF9CompatibilityEngine,
    check_defective_drive_firmware,
    decode_dell_message_id,
    evaluate_bios_version,
    evaluate_bmc_fw_version,
    evaluate_boot_mode,
    evaluate_drive_fw,
    evaluate_pcie_link_health,
)
from vcf_hci.constants import is_generic_name
from vcf_hci.hcl import is_consumer_drive, lookup_unique_hcl_device
from vcf_hci.security.contract import empty_security_evidence
from vcf_hci.security.evaluation import evaluate_security_controls
from vcf_hci.security.redaction import redact_security_evidence, redact_security_findings


def evaluate_optical_link_health(
    port: Optional[Dict[str, Any]] = None,
    *,
    port_id: Optional[str] = None,
    rx_power_dbm: Optional[Union[float, int, str]] = None,
    transceiver_interface: Optional[str] = None,
    transceiver_identifier: Optional[str] = None,
) -> Optional[str]:
    """Evaluate optical transceiver signal health based on RX optical power (DDM).

    For standard Short Range (SR / 850nm) optics:
      • Normal range: >= -10.0 dBm (typically -1.0 to -7.0 dBm).
      • Marginal degradation: rx_power_dbm < -10.0 dBm (warning).
      • Critical degradation: rx_power_dbm < -13.0 dBm (critical optical degradation).

    Emits finding:
      "Marginal Optical Signal on [Port]: RX Power is [X] dBm. Clean fiber endfaces or check cable bend radius."

    Returns:
        Formatted warning string if optical health is degraded, or None if healthy or inapplicable.
    """
    if port and isinstance(port, dict):
        if port_id is None:
            port_id = str(port.get("port_id") or port.get("id") or port.get("name") or "Port")
        if rx_power_dbm is None:
            rx_power_dbm = port.get("rx_power_dbm")
            if rx_power_dbm is None and port.get("transceiver_rx_power_dbm") is not None:
                rx_power_dbm = port.get("transceiver_rx_power_dbm")
        if transceiver_interface is None:
            transceiver_interface = port.get("transceiver_interface") or port.get("interface_type")
        if transceiver_identifier is None:
            transceiver_identifier = port.get("transceiver_identifier") or port.get("identifier_type")

    # If copper / DAC, DDM optical power checks do not apply
    iface_str = str(transceiver_interface or "").lower()
    if any(c in iface_str for c in ("copper", "dac", "directattach", "backplane", "twistedpair", "10gbase-t", "1000base-t")):
        return None

    # Parse rx_power_dbm
    rx_val = None
    if rx_power_dbm is not None:
        if isinstance(rx_power_dbm, (int, float)):
            rx_val = float(rx_power_dbm)
        elif isinstance(rx_power_dbm, str):
            clean_rx = rx_power_dbm.replace("dBm", "").replace("dbm", "").strip()
            try:
                rx_val = float(clean_rx)
            except (ValueError, TypeError):
                rx_val = None
    elif port and isinstance(port, dict):
        rx_mw = port.get("rx_power_mw") or port.get("RXInputPowermW")
        if rx_mw is not None:
            try:
                flt_mw = float(rx_mw)
                if flt_mw > 0:
                    rx_val = round(10.0 * math.log10(flt_mw), 2)
            except (ValueError, TypeError):
                pass

    if rx_val is None:
        return None

    # Format port label
    pid_str = str(port_id or "Port").strip()
    if pid_str.isdigit():
        port_label = f"Port {pid_str}"
    else:
        port_label = pid_str

    rx_formatted = f"{round(rx_val, 2)}"

    # Check warning threshold (< -10.0 dBm)
    if rx_val < -10.0:
        return (
            f"Marginal Optical Signal on {port_label}: RX Power is {rx_formatted} dBm. "
            f"Clean fiber endfaces or check cable bend radius."
        )

    return None


def enrich_host_result(
    data: Union[Dict[str, Any], List[Dict[str, Any]]],
    json_hcl: Optional[Dict[str, Any]] = None,
    csv_db: Optional[Any] = None,
    force: bool = False,
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """Enrich a normalized hardware payload with Layer B verdicts and Layer C links.

    Mutates and returns data with:
      - CPU compatibility verdict, architecture tier, and memory/PCIe limits
      - BIOS and BMC firmware baseline evaluations
      - Boot mode verdict and evaluation
      - Memory topology and channel display calculations
      - PCIe lane budget calculations
      - CNA dual-persona BCG URLs
      - Storage drive firmware evaluations
      - BMC security audit evaluation and redacted findings

    Args:
        data: Host dictionary (or list of host dicts for multi-blade chassis)
        json_hcl: Optional vSAN HCL JSON dictionary
        csv_db: Optional vSAN HCL CSV database
        force: If True, re-run enrichment even if payload is marked as already enriched

    Returns:
        The enriched host dictionary or list of dictionaries.
    """
    if not data:
        return data

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                _enrich_single_host(item, json_hcl=json_hcl, csv_db=csv_db, force=force)
        return data

    if isinstance(data, dict):
        _enrich_single_host(data, json_hcl=json_hcl, csv_db=csv_db, force=force)
        return data

    return data


def synthesize_pcie_slots(
    host_data: Dict[str, Any],
    json_hcl: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Synthesize PCIe slot records for BMC platforms omitting /PCIeSlots.

    Discovers expansion devices from:
    1. host_data['pcie_devices'] (Phase 1 collection cache)
    2. host_data['raw_redfish_capture'] (crawled endpoints matching PCIeDevices)
    3. Peripheral subsystems: network_adapters, storage_subsystem (NVMe), gpu_accelerators, fc_hbas.
    """
    if host_data.get("pcie_slots"):
        return host_data["pcie_slots"]

    if json_hcl is None:
        try:
            from vcf_hci.hcl import load_vsan_hcl_json
            json_hcl = load_vsan_hcl_json()
        except Exception as exc:
            logger.debug("Failed loading vSAN HCL JSON for PCIe slot synthesis: %s", exc)
            json_hcl = None

    slots: List[Dict[str, Any]] = []
    seen_quads = set()
    seen_drives = set()

    # Source A: pcie_devices (populated during Phase 1)
    pcie_devs = host_data.get("pcie_devices") or []
    for idx, dev in enumerate(pcie_devs, start=1):
        if not isinstance(dev, dict):
            continue
        raw_dict = dev.get("_raw") or {}
        raw_desc = str(raw_dict.get("Description") or dev.get("description") or "")
        raw_name = str(raw_dict.get("Name") or dev.get("name") or "")
        raw_asset = str(raw_dict.get("AssetTag") or "")
        dev_class = str(dev.get("device_class") or "").upper()
        vid = str(dev.get("vendor_id") or "").lower()
        did = str(dev.get("device_id") or "").lower()
        svid = str(dev.get("subsystem_vendor_id") or "").lower()
        ssid = str(dev.get("subsystem_id") or "").lower()
        p_quad = dev.get("pci_quad") or (
            f"{vid}:{did}:{svid}:{ssid}" if (vid and did and svid and ssid) else f"{vid}:{did}" if (vid and did) else ""
        )

        if any(kw in raw_desc for kw in ("BRG Onboard", "UNCL Onboard", "MEM Onboard")):
            continue
        if any(kw in raw_desc.lower() for kw in ("root port", "host bridge", "internal bus", "pci-to-pci bridge")):
            continue
        if dev_class in ("BRIDGE", "NONESSENTIALINSTRUMENTATION", "ENCRYPTIONCONTROLLER") and not dev.get("slot_label") and not raw_asset:
            continue
        if vid == "1022" and not dev.get("slot_label") and not raw_asset and dev_class not in ("NETWORKCONTROLLER", "MASSSTORAGECONTROLLER", "DISPLAYCONTROLLER"):
            continue

        hcl_item = lookup_unique_hcl_device(vid=vid, did=did, svid=svid, ssid=ssid, json_hcl=json_hcl) if (vid and did and json_hcl) else None
        dev_name = (
            (hcl_item.get("model") if hcl_item else None)
            or (dev.get("name") if dev.get("name") and dev.get("name") != dev.get("id") else None)
            or dev.get("model")
            or raw_desc
            or "PCIe Peripheral"
        )
        dev_mfr = (hcl_item.get("vendor") if hcl_item else None) or dev.get("manufacturer") or ""

        slot_label = dev.get("slot_label")
        if not slot_label:
            if raw_asset.startswith("PCIE"):
                slot_label = f"PCIe Slot {raw_asset[4:]} ({raw_asset})"
            elif raw_asset.upper() == "LAN":
                slot_label = "Onboard LAN"
            elif raw_asset and not raw_asset.upper().startswith("TAG-"):
                slot_label = raw_asset
            elif "Slot" in raw_desc:
                slot_m = re.search(r"\bSlot\s+(\d+)\b", raw_desc, re.I)
                slot_label = f"PCIe Slot {slot_m.group(1)}" if slot_m else raw_desc
            else:
                slot_label = f"PCIe Slot {idx}"

        lanes = dev.get("lanes")
        if not lanes:
            if "100G" in dev_name or "Dx" in dev_name or dev_class == "PROCESSINGACCELERATORS":
                lanes = 16
            elif "25G" in dev_name or "Lx" in dev_name:
                lanes = 8
            elif "MASSSTORAGE" in dev_class or "NVME" in dev_name.upper():
                lanes = 4
            else:
                lanes = dev.get("max_pcie_width") or 8

        slots.append({
            "slot_label":          slot_label,
            "lanes":               lanes,
            "pcie_type":           dev.get("pcie_type") or "Gen4",
            "slot_type":           "FullLength",
            "hot_pluggable":       False,
            "state":               "Enabled",
            "populated":           True,
            "device_name":         dev_name,
            "device_manufacturer": dev_mfr,
            "device_part_number":  dev.get("part_number") or "",
            "device_serial":       dev.get("serial_number") or "",
            "device_health":       dev.get("health") or "OK",
            "functions":           dev.get("functions") or [],
            "function_count":      dev.get("function_count") or len(dev.get("functions") or []) or 1,
            "vendor_id":           vid,
            "device_id":           did,
            "subsystem_vendor_id": svid,
            "subsystem_id":        ssid,
            "pci_quad":            p_quad,
            "pci_pair":            dev.get("pci_pair") or (f"{vid}:{did}" if (vid and did) else ""),
            "downgraded":          dev.get("downgraded", False),
            "downgrade_reason":    dev.get("downgrade_reason", ""),
            "downgrade_badge":     dev.get("downgrade_badge", ""),
        })
        if p_quad:
            seen_quads.add(p_quad)

    # Source B: raw_redfish_capture (crawled endpoints)
    if not slots and host_data.get("raw_redfish_capture"):
        raw = host_data["raw_redfish_capture"]
        if isinstance(raw, dict):
            for k, v in raw.items():
                if ("/Chassis/" in k or "/Systems/" in k) and "/PCIeDevices/" in k and "/PCIeFunctions" not in k and not k.endswith("PCIeDevices"):
                    if not isinstance(v, dict):
                        continue
                    desc = str(v.get("Description") or "")
                    asset = str(v.get("AssetTag") or "")
                    name = str(v.get("Name") or "")
                    if any(kw in desc for kw in ("BRG Onboard", "UNCL Onboard", "MEM Onboard")):
                        continue
                    if any(kw in desc.lower() for kw in ("root port", "host bridge", "internal bus", "pci-to-pci bridge")):
                        continue
                    pci = extract_pci_ids_from_dict(v, get_fn=lambda u: raw.get(u))
                    vid = pci.get("vendor_id", "")
                    did = pci.get("device_id", "")
                    svid = pci.get("subsystem_vendor_id", "")
                    ssid = pci.get("subsystem_id", "")
                    quad = pci.get("pci_quad", "")
                    if vid == "1022" and not asset:
                        continue
                    hcl_item = lookup_unique_hcl_device(vid=vid, did=did, svid=svid, ssid=ssid, json_hcl=json_hcl) if (vid and did and json_hcl) else None
                    dev_name = (
                        (hcl_item.get("model") if hcl_item else None)
                        or v.get("Model")
                        or (name if name != v.get("Id") else "")
                        or desc
                        or "PCIe Device"
                    )
                    if asset.startswith("PCIE"):
                        slot_label = f"PCIe Slot {asset[4:]} ({asset})"
                    elif asset.upper() == "LAN":
                        slot_label = "Onboard LAN"
                    elif asset and not asset.upper().startswith("TAG-"):
                        slot_label = asset
                    elif "Slot" in desc:
                        m = re.search(r"\bSlot\s+(\d+)\b", desc)
                        slot_label = f"PCIe Slot {m.group(1)}" if m else desc
                    else:
                        slot_label = f"PCIe Slot ({v.get('Id')})"
                    lanes = 16 if ("100G" in dev_name or "Dx" in dev_name) else (8 if ("25G" in dev_name or "Lx" in dev_name) else 4)
                    slots.append({
                        "slot_label":          slot_label,
                        "lanes":               lanes,
                        "pcie_type":           "Gen4",
                        "slot_type":           "FullLength",
                        "hot_pluggable":       False,
                        "state":               "Enabled",
                        "populated":           True,
                        "device_name":         dev_name,
                        "device_manufacturer": (hcl_item.get("vendor") if hcl_item else None) or v.get("Manufacturer") or "",
                        "device_part_number":  v.get("PartNumber") or "",
                        "device_serial":       v.get("SerialNumber") or "",
                        "device_health":       "OK",
                        "functions":           [],
                        "function_count":      1,
                        "vendor_id":           vid,
                        "device_id":           did,
                        "subsystem_vendor_id": svid,
                        "subsystem_id":        ssid,
                        "pci_quad":            quad,
                        "pci_pair":            f"{vid}:{did}" if (vid and did) else "",
                        "downgraded":          False,
                        "downgrade_reason":    "",
                        "downgrade_badge":     "",
                    })
                    if quad:
                        seen_quads.add(quad)

    # Source C: Network Adapters, Storage NVMe SSDs, GPUs, FC HBAs
    # 1. Network Adapters
    for nic in (host_data.get("network_adapters") or []):
        if not isinstance(nic, dict):
            continue
        name = str(nic.get("name") or nic.get("model") or "")
        if any(kw in name.lower() for kw in ("virtual", "usb", "bmc")):
            continue
        quad = nic.get("pci_quad") or ""
        slot_label = nic.get("slot") or ""
        if quad and quad in seen_quads:
            for s in slots:
                if s.get("pci_quad") == quad:
                    s["function_count"] = s.get("function_count", 1) + 1
                    break
            continue
        parts = quad.split(":") if quad else []
        vid = parts[0] if len(parts) > 0 else ""
        did = parts[1] if len(parts) > 1 else ""
        svid = parts[2] if len(parts) > 2 else ""
        ssid = parts[3] if len(parts) > 3 else ""
        hcl_item = lookup_unique_hcl_device(vid=vid, did=did, svid=svid, ssid=ssid, json_hcl=json_hcl) if (vid and did and json_hcl) else None
        dev_name = (hcl_item.get("model") if hcl_item else None) or nic.get("name") or nic.get("model") or "Network Adapter"
        speed = nic.get("speed_gbps") or 0
        lanes = 16 if speed >= 100 or "100G" in dev_name else (8 if speed >= 25 or "25G" in dev_name else 4)
        if not slot_label:
            slot_label = f"PCIe Network Slot {len(slots)+1}"
        slots.append({
            "slot_label":          slot_label,
            "lanes":               lanes,
            "pcie_type":           "Gen4",
            "slot_type":           "FullLength",
            "hot_pluggable":       False,
            "state":               "Enabled",
            "populated":           True,
            "device_name":         dev_name,
            "device_manufacturer": (hcl_item.get("vendor") if hcl_item else None) or nic.get("manufacturer") or "",
            "device_part_number":  nic.get("part_number") or "",
            "device_serial":       nic.get("serial_number") or "",
            "device_health":       "OK",
            "functions":           [{"function_id": 0}],
            "function_count":      1,
            "vendor_id":           vid,
            "device_id":           did,
            "subsystem_vendor_id": svid,
            "subsystem_id":        ssid,
            "pci_quad":            quad,
            "pci_pair":            f"{vid}:{did}" if (vid and did) else "",
            "downgraded":          False,
            "downgrade_reason":    "",
            "downgrade_badge":     "",
        })
        if quad:
            seen_quads.add(quad)

    # 2. Storage NVMe SSDs
    for c in (host_data.get("storage_subsystem") or []):
        if not isinstance(c, dict):
            continue
        for drv in c.get("drives", []):
            if not isinstance(drv, dict):
                continue
            model = str(drv.get("model") or "")
            name = str(drv.get("name") or "")
            proto = str(drv.get("protocol") or drv.get("bus_protocol") or "")
            drv_id = str(drv.get("serial_number") or drv.get("name") or drv.get("id") or "")
            if "nvme" in proto.lower() or "nvme" in name.lower() or "nvme" in model.lower() or drv.get("category") == "vSAN ESA/OSA NVMe":
                if drv_id and drv_id in seen_drives:
                    continue
                if drv_id:
                    seen_drives.add(drv_id)
                slots.append({
                    "slot_label":          f"NVMe Slot ({name})" if name else f"NVMe Slot {len(slots)+1}",
                    "lanes":               4,
                    "pcie_type":           "Gen4",
                    "slot_type":           "M2",
                    "hot_pluggable":       True,
                    "state":               "Enabled",
                    "populated":           True,
                    "device_name":         model or name or "NVMe Solid State Drive",
                    "device_manufacturer": drv.get("manufacturer") or "NVMe SSD",
                    "device_part_number":  drv.get("part_number") or "",
                    "device_serial":       drv.get("serial_number") or "",
                    "device_health":       "OK",
                    "functions":           [{"function_id": 0}],
                    "function_count":      1,
                    "vendor_id":           "",
                    "device_id":           "",
                    "subsystem_vendor_id": "",
                    "subsystem_id":        "",
                    "pci_quad":            "",
                    "pci_pair":            "",
                    "downgraded":          False,
                    "downgrade_reason":    "",
                    "downgrade_badge":     "",
                })

    # 3. GPUs
    for gpu in (host_data.get("gpu_accelerators") or []):
        if not isinstance(gpu, dict):
            continue
        g_name = gpu.get("name") or gpu.get("model") or "GPU Accelerator"
        g_slot = gpu.get("slot") or f"PCIe GPU Slot {len(slots)+1}"
        slots.append({
            "slot_label":          g_slot,
            "lanes":               gpu.get("lanes") or 16,
            "pcie_type":           gpu.get("pcie_type") or "Gen4",
            "slot_type":           "FullLength",
            "hot_pluggable":       False,
            "state":               "Enabled",
            "populated":           True,
            "device_name":         g_name,
            "device_manufacturer": gpu.get("manufacturer") or "GPU",
            "device_part_number":  gpu.get("part_number") or "",
            "device_serial":       gpu.get("serial_number") or "",
            "device_health":       "OK",
            "functions":           [{"function_id": 0}],
            "function_count":      1,
            "vendor_id":           gpu.get("vendor_id") or "",
            "device_id":           gpu.get("device_id") or "",
            "subsystem_vendor_id": gpu.get("subsystem_vendor_id") or "",
            "subsystem_id":        gpu.get("subsystem_id") or "",
            "pci_quad":            gpu.get("pci_quad") or "",
            "pci_pair":            gpu.get("pci_pair") or "",
            "downgraded":          False,
            "downgrade_reason":    "",
            "downgrade_badge":     "",
        })

    # 4. FC HBAs
    for hba in (host_data.get("fc_hbas") or []):
        if not isinstance(hba, dict):
            continue
        h_name = hba.get("model") or hba.get("name") or "FC HBA"
        h_slot = hba.get("slot") or f"PCIe FC HBA Slot {len(slots)+1}"
        slots.append({
            "slot_label":          h_slot,
            "lanes":               hba.get("lanes") or 8,
            "pcie_type":           hba.get("pcie_type") or "Gen4",
            "slot_type":           "FullLength",
            "hot_pluggable":       False,
            "state":               "Enabled",
            "populated":           True,
            "device_name":         h_name,
            "device_manufacturer": hba.get("manufacturer") or "Fibre Channel",
            "device_part_number":  hba.get("part_number") or "",
            "device_serial":       hba.get("serial_number") or "",
            "device_health":       "OK",
            "functions":           [{"function_id": 0}],
            "function_count":      1,
            "vendor_id":           hba.get("vendor_id") or "",
            "device_id":           hba.get("device_id") or "",
            "subsystem_vendor_id": hba.get("subsystem_vendor_id") or "",
            "subsystem_id":        hba.get("subsystem_id") or "",
            "pci_quad":            hba.get("pci_quad") or "",
            "pci_pair":            hba.get("pci_pair") or "",
            "downgraded":          False,
            "downgrade_reason":    "",
            "downgrade_badge":     "",
        })

    return slots


def _enrich_single_host(
    host_data: Dict[str, Any],
    json_hcl: Optional[Dict[str, Any]] = None,
    csv_db: Optional[Any] = None,
    force: bool = False,
) -> None:
    """Enrich a single host data dictionary in place."""
    if not force and host_data.get("_enriched"):
        return

    if json_hcl is None:
        try:
            from vcf_hci.hcl import load_vsan_hcl_json
            json_hcl = load_vsan_hcl_json()
        except Exception as exc:
            logger.debug("Failed loading vSAN HCL JSON: %s", exc)
            json_hcl = None

    system = host_data.get("system")
    if not isinstance(system, dict):
        system = {}

    vendor = str(system.get("vendor") or "Unknown Vendor")
    model = str(system.get("model") or "Unknown Server")

    _placeholder_vendors = {
        "TO BE FILLED BY O.E.M.", "DEFAULT STRING", "SYSTEM MANUFACTURER",
        "UNKNOWN VENDOR", "UNKNOWN", "",
    }
    if vendor.upper().strip() in _placeholder_vendors:
        _model_up = model.upper().strip()
        if "ROMED8" in _model_up or "EPYCD8" in _model_up or "GENOAD8" in _model_up or "BERGAMOD8" in _model_up or "SP3" in _model_up:
            vendor = "ASRock Rack"
            system["vendor"] = "ASRock Rack"
        elif _model_up.startswith(("X11", "X12", "X13", "H11", "H12", "H13", "SYS-")):
            vendor = "Supermicro"
            system["vendor"] = "Supermicro"
        elif _model_up.startswith(("MZ31", "MZ32", "MZ71", "MZ72")):
            vendor = "Gigabyte"
            system["vendor"] = "Gigabyte"

    bios_version = str(system.get("bios_version") or "Unknown")
    bios_date = str(system.get("bios_release_date") or "")

    # 1. BIOS Version Evaluation
    try:
        system["bios_eval"] = evaluate_bios_version(model, bios_version, bios_date)
    except Exception as exc:
        logger.debug("Failed evaluating BIOS version for %s: %s", model, exc)
        if "bios_eval" not in system:
            system["bios_eval"] = {}

    # 2. Boot Mode Evaluation
    try:
        raw_boot_mode = str(system.get("raw_boot_mode") or system.get("boot_mode") or "").strip()
        if not raw_boot_mode or raw_boot_mode.lower() in ("unknown", "none", "n/a"):
            has_sb = bool(host_data.get("secure_boot") or any("secureboot" in str(k).lower() for k in (host_data.get("raw_redfish_capture") or {})))
            has_uefi_path = any("uefi" in str(b.get("uefi_path", "")).lower() or "uefi" in str(b.get("name", "")).lower() for b in system.get("boot_order_details", []))
            if has_sb or has_uefi_path:
                raw_boot_mode = "UEFI"
        if raw_boot_mode and raw_boot_mode != "N/A":
            boot_eval = evaluate_boot_mode(raw_boot_mode)
            system["boot_eval"] = boot_eval
            system["boot_mode"] = boot_eval.get("verdict", raw_boot_mode)
        elif not system.get("boot_eval"):
            system["boot_eval"] = evaluate_boot_mode(raw_boot_mode)
    except Exception as exc:
        logger.debug("Failed evaluating boot mode: %s", exc)
        if "boot_eval" not in system:
            system["boot_eval"] = {}

    # 3. CPU Compatibility & Specs Evaluation
    cpu_summary = system.get("cpu_summary")
    if isinstance(cpu_summary, dict):
        try:
            cpu_model = str(cpu_summary.get("model") or "Unknown")
            if cpu_model and cpu_model != "Modular Enclosure":
                (
                    cpu_verdict,
                    arch_label,
                    channels_per_socket,
                    max_ram_speed_mhz,
                    max_pcie_lanes_per_socket,
                ) = VCF9CompatibilityEngine.evaluate_cpu(cpu_model, vendor, model)

                if cpu_summary.get("asymmetry_detected"):
                    asymmetry_note = "CPU socket asymmetry detected: mismatched processor model, core count, speed, or socket state."
                    cpu_summary["asymmetry_note"] = asymmetry_note
                    if "Asymmetry" not in cpu_verdict:
                        cpu_verdict += " (⚠️ Socket Asymmetry Detected)"

                cpu_summary["verdict"] = cpu_verdict
                cpu_summary["architecture"] = arch_label
                cpu_summary["channels_per_socket"] = channels_per_socket
                cpu_summary["max_ram_speed_mhz"] = max_ram_speed_mhz
                cpu_summary["max_pcie_lanes_per_socket"] = max_pcie_lanes_per_socket
        except Exception as exc:
            logger.debug("Failed evaluating CPU compatibility for %s: %s", model, exc)

    # 4. BMC Firmware Evaluation
    bmc_fw_info = host_data.get("bmc_firmware")
    if isinstance(bmc_fw_info, dict):
        try:
            fw_ver = str(bmc_fw_info.get("bmc_fw_version") or "").strip() or "N/A"
            mgr_model = str(bmc_fw_info.get("bmc_model") or "").strip().upper()

            if fw_ver != "N/A" and mgr_model:
                bmc_eval = evaluate_bmc_fw_version(mgr_model, fw_ver, server_model=model)
                matched_key = bmc_eval.get("baseline_key")
                if matched_key and (
                    not bmc_fw_info.get("bmc_model")
                    or bmc_fw_info["bmc_model"] in (
                        "BMC", "13G MONOLITHIC", "14G MONOLITHIC", "15G MONOLITHIC",
                        "16G MONOLITHIC", "17G MONOLITHIC",
                    )
                ):
                    bmc_fw_info["bmc_model"] = matched_key


                bmc_fw_info["bmc_fw_eval"] = bmc_eval
                bmc_fw_info["badge"] = bmc_eval.get("badge", "")
        except Exception as exc:
            logger.debug("Failed evaluating BMC firmware: %s", exc)

    # 5. Memory Subsystem & Topology Evaluation
    cpu_count = int(cpu_summary.get("count") or 1) if isinstance(cpu_summary, dict) else 1
    chan_per_socket = int(cpu_summary.get("channels_per_socket") or 8) if isinstance(cpu_summary, dict) else 8

    mem_sub = host_data.get("memory_subsystem")
    if isinstance(mem_sub, dict):
        if chan_per_socket and cpu_count:
            mem_sub["expected_channels_total"] = cpu_count * chan_per_socket
        dimm_list = mem_sub.get("dimm_list")
        if isinstance(dimm_list, list) and chan_per_socket > 0:
            # Self-heal duplicate "DIMM 0" or identical slot names from older scans or broken BMCs
            raw_slots = [str(d.get("slot") or "").strip() for d in dimm_list if isinstance(d, dict)]
            if len(dimm_list) > 1 and len(set(raw_slots)) <= 1:
                for idx, d in enumerate(dimm_list):
                    if not isinstance(d, dict):
                        continue
                    cand_id = str(d.get("id") or d.get("name") or "").strip()
                    m_d = re.search(r"DIMM\s*(\d+)", cand_id, re.IGNORECASE)
                    slot_num = int(m_d.group(1)) if m_d else idx
                    d["slot"] = f"DIMM {slot_num}"
                    d["slot_locator"] = f"DIMM {slot_num}"

            # Self-heal 0-indexed sockets across all DIMMs
            raw_socks = [int(d.get("socket")) for d in dimm_list if isinstance(d, dict) and d.get("socket") is not None]
            if raw_socks and min(raw_socks) == 0:
                for d in dimm_list:
                    if isinstance(d, dict) and d.get("socket") is not None:
                        d["socket"] = int(d["socket"]) + 1

            active_channels_set = set()
            for d in dimm_list:
                if not isinstance(d, dict):
                    continue
                slot_str = str(d.get("slot") or "").strip().upper()
                m_dell = re.search(r"\bDIMM\s+([A-D])\s*(\d+)\b", slot_str)
                m_dimm_num = re.search(r"\bDIMM\s*(\d+)\b", slot_str)
                if m_dell:
                    s_idx = ord(m_dell.group(1)) - ord('A') + 1
                    slot_num = int(m_dell.group(2))
                    d["socket"] = s_idx
                    d["channel"] = chr(ord('A') + (slot_num - 1) % chan_per_socket)
                elif m_dimm_num:
                    raw_slot = int(m_dimm_num.group(1))
                    total_board_slots = int(mem_sub.get("slot_count") or mem_sub.get("total_slots") or len(dimm_list))
                    if total_board_slots <= chan_per_socket * max(1, cpu_count):
                        d["channel"] = chr(ord('A') + (raw_slot % chan_per_socket))
                    else:
                        slot_1based = raw_slot if raw_slot > 0 else (raw_slot + 1)
                        slot_in_sock = (slot_1based - 1) % (chan_per_socket * 2)
                        chan_idx = slot_in_sock // 2
                        d["channel"] = chr(ord('A') + (chan_idx % chan_per_socket))
                elif slot_str.isdigit():
                    raw_slot = int(slot_str)
                    if raw_slot > 0:
                        slot_in_sock = (raw_slot - 1) % (chan_per_socket * 2)
                        chan_idx = slot_in_sock // 2
                        d["channel"] = chr(ord('A') + (chan_idx % chan_per_socket))

                ch_val = str(d.get("channel") or "A").upper().strip()
                if len(ch_val) == 1 and ch_val.isalpha():
                    ch_offset = ord(ch_val) - ord('A')
                    if ch_offset >= chan_per_socket:
                        d["channel"] = chr(ord('A') + (ch_offset % chan_per_socket))

                if int(d.get("capacity_gb") or 0) > 0:
                    s_val = int(d.get("socket") or 1)
                    if s_val == 0:
                        s_val = 1
                        d["socket"] = 1
                    ch_final = d.get("channel", "A")
                    active_channels_set.add(f"S{s_val}-Ch{ch_final}")

            if active_channels_set:
                mem_sub["active_channels_count"] = len(active_channels_set)

        total_dimms = mem_sub.get("total_dimms_populated", 0)
        active_chan = mem_sub.get("active_channels_count", 0)
        mem_sub["channel_display"] = f"{total_dimms} DIMMs across {active_chan} Active Channel(s)"

    try:
        host_data["memory_topology"] = VCF9CompatibilityEngine.evaluate_memory_topology(
            mem_sub if isinstance(mem_sub, dict) else {},
            cpu_summary if isinstance(cpu_summary, dict) else {},
        )
    except Exception as exc:
        logger.debug("Failed evaluating memory topology: %s", exc)
        if "memory_topology" not in host_data:
            host_data["memory_topology"] = {}

    # 6. PCIe Lane Budget Evaluation
    pcie_slots = host_data.get("pcie_slots") or []
    if not pcie_slots:
        pcie_slots = synthesize_pcie_slots(host_data, json_hcl=json_hcl)
        if pcie_slots:
            host_data["pcie_slots"] = pcie_slots

    # Enrich generic slot device names & manufacturers from HCL
    if isinstance(pcie_slots, list):
        for s in pcie_slots:
            if not isinstance(s, dict):
                continue
            d_name = s.get("device_name", "")
            vid = s.get("vendor_id", "")
            did = s.get("device_id", "")
            svid = s.get("subsystem_vendor_id", "")
            ssid = s.get("subsystem_id", "")
            if is_generic_name(d_name) and vid and did:
                hcl_item = lookup_unique_hcl_device(vid=vid, did=did, svid=svid, ssid=ssid, json_hcl=json_hcl)
                if hcl_item:
                    s["device_name"] = hcl_item.get("model") or d_name
                    mfr_raw = str(s.get("device_manufacturer") or "").strip()
                    if not mfr_raw or is_generic_name(mfr_raw) or re.match(r"^[0-9a-fA-F]{4,8}$", mfr_raw):
                        s["device_manufacturer"] = hcl_item.get("vendor") or mfr_raw

    max_pcie_lanes = (
        int(cpu_summary.get("max_pcie_lanes_per_socket") or 0)
        if isinstance(cpu_summary, dict)
        else 0
    )
    try:
        host_data["pcie_lane_budget"] = VCF9CompatibilityEngine.evaluate_pcie_lane_budget(
            pcie_slots if isinstance(pcie_slots, list) else [],
            max_pcie_lanes,
            cpu_count,
        )
    except Exception as exc:
        logger.debug("Failed evaluating PCIe lane budget: %s", exc)
        if "pcie_lane_budget" not in host_data:
            host_data["pcie_lane_budget"] = {}

    # 7. CNA BCG URLs & Speed Enrichment on Network Adapters
    net_adapters = host_data.get("network_adapters")
    if isinstance(net_adapters, list):
        io_catalog = None
        for nic in net_adapters:
            if not isinstance(nic, dict):
                continue
            if nic.get("is_cna"):
                nic_name = str(nic.get("name") or nic.get("id") or "")
                eth_drv = str(nic.get("cna_eth_driver") or "")
                fc_drv = str(nic.get("cna_fc_driver") or "")
                if eth_drv and not nic.get("cna_eth_bcg_url"):
                    nic["cna_eth_bcg_url"] = BCGLinkGenerator.cna_ethernet(nic_name, eth_drv)
                if fc_drv and not nic.get("cna_fc_bcg_url"):
                    nic["cna_fc_bcg_url"] = BCGLinkGenerator.cna_fc(nic_name, fc_drv)

            if not nic.get("manufacturer") or str(nic.get("manufacturer")).lower() in ("unknown", "n/a", "none", "", "null"):
                nic["manufacturer"] = infer_nic_manufacturer(
                    nic.get("manufacturer", ""),
                    nic,
                    str(nic.get("name") or ""),
                )

            # Normalize and resolve PCI IDs
            vid = normalize_pci_id(nic.get("vendor_id") or "")
            did = normalize_pci_id(nic.get("device_id") or "")
            svid = normalize_pci_id(nic.get("subsystem_vendor_id") or "")
            ssid = normalize_pci_id(nic.get("subsystem_id") or "")
            if vid and did:
                if not nic.get("pci_pair"):
                    nic["pci_pair"] = f"{vid}:{did}"
                if svid and ssid and not nic.get("pci_quad"):
                    nic["pci_quad"] = f"{vid}:{did}:{svid}:{ssid}"

            pci_quad = (nic.get("pci_quad") or "").lower().strip()
            pci_pair = (nic.get("pci_pair") or "").lower().strip()

            dev = None
            matched_model = ""
            matched_speed = 0.0

            # 1. First check json_hcl if available
            if json_hcl and isinstance(json_hcl, dict):
                hcl_quads = json_hcl.get("quads") or json_hcl.get("_pci_quads") or {}
                if pci_quad and pci_quad in hcl_quads:
                    dev = hcl_quads[pci_quad]
                elif pci_quad and pci_quad in json_hcl:
                    dev = json_hcl[pci_quad]
                elif pci_pair:
                    hcl_pairs = json_hcl.get("pairs") or json_hcl.get("_pci_pairs") or {}
                    if pci_pair in hcl_pairs:
                        dev = select_best_pci_pair_entry(
                            hcl_pairs[pci_pair],
                            model_name=str(nic.get("name") or ""),
                            svid=svid or nic.get("subsystem_vendor_id", ""),
                            ssid=ssid or nic.get("subsystem_id", ""),
                        )

            # 2. Fallback to io_catalog
            if not dev and (pci_quad or pci_pair):
                if io_catalog is None:
                    try:
                        from vcf_hci.hcl.loader import load_io_nics_catalog
                        io_catalog = load_io_nics_catalog()
                    except Exception:
                        io_catalog = {}

                quads = io_catalog.get("quads") or {}
                pairs = io_catalog.get("pairs") or {}
                if pci_quad:
                    for qk, qv in quads.items():
                        if qk.lower() == pci_quad:
                            dev = qv
                            break
                if not dev and pci_pair and pci_pair in pairs:
                    dev = select_best_pci_pair_entry(
                        pairs[pci_pair],
                        model_name=str(nic.get("name") or ""),
                        svid=svid or nic.get("subsystem_vendor_id", ""),
                        ssid=ssid or nic.get("subsystem_id", ""),
                    )

            if isinstance(dev, dict):
                matched_model = dev.get("model") or ""
                if is_generic_name(nic.get("name")) and matched_model:
                    nic["name"] = matched_model
                if not nic.get("model") or is_generic_name(nic.get("model")):
                    if matched_model:
                        nic["model"] = matched_model
                if (not nic.get("manufacturer") or str(nic.get("manufacturer")).lower() in ("unknown", "n/a", "none", "", "null")) and dev.get("brand_name"):
                    nic["manufacturer"] = dev.get("brand_name")
                if dev.get("product_id") and not nic.get("product_id"):
                    nic["product_id"] = str(dev["product_id"])
                if dev.get("io_product_id") and not nic.get("io_product_id"):
                    nic["io_product_id"] = str(dev["io_product_id"])
                elif dev.get("product_id") and not nic.get("io_product_id"):
                    nic["io_product_id"] = str(dev["product_id"])
                if dev.get("io_vcglink") and not nic.get("io_vcglink"):
                    nic["io_vcglink"] = str(dev["io_vcglink"])
                elif dev.get("vcglink") and not nic.get("io_vcglink"):
                    nic["io_vcglink"] = str(dev["vcglink"])
                if dev.get("speed_gbps"):
                    try:
                        matched_speed = float(dev["speed_gbps"])
                    except Exception:
                        pass

            # Check if adapter or all its ports have 0/None speed
            ports = nic.get("ports") or []
            max_port_speed = max((float(p.get("current_speed_gbps") or p.get("speed_gbps") or 0) for p in ports if isinstance(p, dict)), default=0.0)
            nic_speed = float(nic.get("speed_gbps") or 0.0)

            if max_port_speed <= 0 and nic_speed <= 0:
                if matched_speed <= 0:
                    cand_text = f"{matched_model} {nic.get('name', '')} {nic.get('model', '')} {nic.get('id', '')}"
                    m_speeds = re.findall(r"\b(400|200|100|50|40|25|10|1)\s*(?:G(?:bE|b|E)?|Gigabit)\b", cand_text, re.IGNORECASE)
                    if m_speeds:
                        matched_speed = max(float(x) for x in m_speeds)
                    elif re.search(r"\b(?:Gigabit|GbE|1000Base)\b", cand_text, re.IGNORECASE) or re.search(r"\b(?:I350[A-Z0-9]*|I340[A-Z0-9]*|I210[A-Z0-9]*|I211[A-Z0-9]*|BCM5720|BCM5719|5720[-_]?[tT]|NetXtreme)\b", cand_text, re.IGNORECASE):
                        matched_speed = 1.0
                    elif re.search(r"\b(?:X550[A-Z0-9]*|X540[A-Z0-9]*|X520[A-Z0-9]*|BCM57810)\b", cand_text, re.IGNORECASE):
                        matched_speed = 10.0
                    elif re.search(r"\b(?:ConnectX[-_]?[56]|CX[-_]?[56])\b", cand_text, re.IGNORECASE):
                        matched_speed = 100.0
                    elif re.search(r"\b(?:ConnectX[-_]?4|CX[-_]?4)\b", cand_text, re.IGNORECASE):
                        matched_speed = 25.0

                if matched_speed > 0:
                    int_or_float = int(matched_speed) if matched_speed == int(matched_speed) else round(matched_speed, 2)
                    nic["speed_gbps"] = int_or_float
                    for p in ports:
                        if isinstance(p, dict):
                            p_spd = float(p.get("current_speed_gbps") or p.get("speed_gbps") or 0)
                            if p_spd <= 0:
                                p["current_speed_gbps"] = int_or_float
                                if "speed_gbps" in p:
                                    p["speed_gbps"] = int_or_float
            elif max_port_speed > 0 and nic_speed <= 0:
                nic["speed_gbps"] = int(max_port_speed) if max_port_speed == int(max_port_speed) else round(max_port_speed, 2)

            # If adapter has a known speed, ensure 0-speed ports inherit it
            eff_nic_speed = float(nic.get("speed_gbps") or 0.0)
            if eff_nic_speed > 0:
                val = int(eff_nic_speed) if eff_nic_speed == int(eff_nic_speed) else round(eff_nic_speed, 2)
                for p in ports:
                    if isinstance(p, dict):
                        p_spd = float(p.get("current_speed_gbps") or p.get("speed_gbps") or 0)
                        if p_spd <= 0:
                            p["current_speed_gbps"] = val
                            if "speed_gbps" in p:
                                p["speed_gbps"] = val

            # Cascade port speed down to virtual interfaces / partitions if missing
            parts = nic.get("vic_virtual_interfaces") or nic.get("npar_partitions") or []
            if isinstance(parts, list):
                eff_speed = max_port_speed if max_port_speed > 0 else float(nic.get("speed_gbps") or 0.0)
                if eff_speed > 0:
                    for part in parts:
                        if isinstance(part, dict) and float(part.get("speed_gbps") or 0.0) <= 0.0:
                            part["speed_gbps"] = int(eff_speed) if eff_speed == int(eff_speed) else round(eff_speed, 2)

            # Optical Transceiver DDM Signal Health Evaluation
            for p in ports:
                if not isinstance(p, dict):
                    continue
                finding = evaluate_optical_link_health(p)
                if finding:
                    p["optical_warning"] = finding
                    p["optical_signal_warning"] = finding
                    p["optical_finding"] = finding
                    p["ddm_warning"] = finding
                    rx_p = p.get("rx_power_dbm")
                    if rx_p is None:
                        rx_p = p.get("transceiver_rx_power_dbm")
                    try:
                        p["optical_signal_health"] = "critical" if (rx_p is not None and float(rx_p) < -13.0) else "marginal"
                    except (ValueError, TypeError):
                        p["optical_signal_health"] = "marginal"
                    p["optical_health"] = p["optical_signal_health"]
                    host_data.setdefault("optical_warnings", []).append(finding)
                    host_data.setdefault("optical_findings", []).append(finding)
                elif p.get("rx_power_dbm") is not None or p.get("transceiver_rx_power_dbm") is not None:
                    rx_p = p.get("rx_power_dbm") if p.get("rx_power_dbm") is not None else p.get("transceiver_rx_power_dbm")
                    try:
                        if float(rx_p) >= -10.0:
                            p["optical_signal_health"] = "good"
                            p["optical_health"] = "good"
                    except (ValueError, TypeError):
                        pass

            # PCIe Link Health & Degradation Evaluation
            link_health = evaluate_pcie_link_health(nic)
            if link_health.get("degraded"):
                finding = link_health["finding"]
                nic["pcie_link_eval"] = link_health
                nic["pcie_link_finding"] = finding
                nic["pcie_link_remediation"] = link_health["remediation"]
                nic["downgraded"] = True
                nic["downgrade_reason"] = finding
                nic["downgrade_badge"] = link_health["badge"]
                host_data.setdefault("pcie_link_warnings", []).append(finding)
                host_data.setdefault("warnings", []).append(finding)

    # 7b. FC HBA PCIe Link Health Evaluation
    fc_hbas = host_data.get("fc_hbas")
    if isinstance(fc_hbas, list):
        for hba in fc_hbas:
            if not isinstance(hba, dict):
                continue
            link_health = evaluate_pcie_link_health(hba)
            if link_health.get("degraded"):
                finding = link_health["finding"]
                hba["pcie_link_eval"] = link_health
                hba["pcie_link_finding"] = finding
                hba["pcie_link_remediation"] = link_health["remediation"]
                hba["downgraded"] = True
                hba["downgrade_reason"] = finding
                hba["downgrade_badge"] = link_health["badge"]
                if finding not in host_data.get("pcie_link_warnings", []):
                    host_data.setdefault("pcie_link_warnings", []).append(finding)
                    host_data.setdefault("warnings", []).append(finding)

    # 7c. PCIe Device Link Health Evaluation
    pcie_devs = host_data.get("pcie_devices")
    if isinstance(pcie_devs, list):
        for pdev in pcie_devs:
            if not isinstance(pdev, dict):
                continue
            p_class = str(pdev.get("device_class") or "").upper()
            if p_class in ("BRIDGE", "PROCESSOR"):
                continue
            link_health = evaluate_pcie_link_health(pdev)
            if link_health.get("degraded"):
                finding = link_health["finding"]
                pdev["pcie_link_eval"] = link_health
                pdev["pcie_link_finding"] = finding
                pdev["pcie_link_remediation"] = link_health["remediation"]
                pdev["downgraded"] = True
                pdev["downgrade_reason"] = finding
                pdev["downgrade_badge"] = link_health["badge"]
                if finding not in host_data.get("pcie_link_warnings", []):
                    host_data.setdefault("pcie_link_warnings", []).append(finding)
                    host_data.setdefault("warnings", []).append(finding)

    # 7d. GPU Accelerator PCIe Link & Signal Health Evaluation
    gpus = host_data.get("gpu_accelerators")
    if isinstance(gpus, list):
        for gpu in gpus:
            if not isinstance(gpu, dict):
                continue
            link_health = evaluate_pcie_link_health(gpu)
            if link_health.get("degraded"):
                finding = link_health["finding"]
                gpu["pcie_link_eval"] = link_health
                gpu["pcie_link_finding"] = finding
                gpu["pcie_link_remediation"] = link_health["remediation"]
                gpu["downgraded"] = True
                gpu["downgrade_reason"] = finding
                gpu["downgrade_badge"] = link_health["badge"]
                if finding not in host_data.get("pcie_link_warnings", []):
                    host_data.setdefault("pcie_link_warnings", []).append(finding)
                    host_data.setdefault("warnings", []).append(finding)
                if link_health.get("signal_severity") == "critical":
                    host_data.setdefault("critical_findings", []).append(finding)

    # 7e. TelemetryService PCIe Error Evaluation
    io_tel = host_data.get("io_telemetry") or {}
    pcie_tel = io_tel.get("pcie_telemetry") or {}
    if isinstance(pcie_tel, dict):
        rec_errs = pcie_tel.get("pcie_switch_recovery_errors") or 0
        if rec_errs > 0:
            finding = f"PCIe Switch Signal Degradation: {rec_errs} Switch Port Recovery/Retrain Error(s) detected via TelemetryService."
            if finding not in host_data.get("pcie_link_warnings", []):
                host_data.setdefault("pcie_link_warnings", []).append(finding)
                host_data.setdefault("warnings", []).append(finding)
        bad_tlp = pcie_tel.get("pcie_switch_bad_tlp_errors") or 0
        if bad_tlp > 0:
            finding = f"PCIe Switch Signal Degradation: {bad_tlp} Bad TLP Frame Error(s) detected via TelemetryService."
            if finding not in host_data.get("pcie_link_warnings", []):
                host_data.setdefault("pcie_link_warnings", []).append(finding)
                host_data.setdefault("warnings", []).append(finding)

    # 8. Storage Drive Firmware & PCIe Link Evaluations
    storage = host_data.get("storage_subsystem")
    if not isinstance(storage, list) and isinstance(host_data.get("storage"), dict):
        storage = host_data.get("storage", {}).get("controllers") or []
    if isinstance(storage, list):
        cur_boot_tgt = str(system.get("boot_target") or "").strip()
        if not cur_boot_tgt or cur_boot_tgt.lower() in ("none", "n/a", "unknown", "null", "unavailable"):
            for ctrl in storage:
                if isinstance(ctrl, dict) and (ctrl.get("is_boot_ctrl") or any(b in (ctrl.get("name") or "").upper() for b in ("BOSS", "NS204", "SATADOM"))):
                    b_name = ctrl.get("name") or ctrl.get("ctrl_model") or ctrl.get("id")
                    if b_name:
                        system["boot_target"] = str(b_name).strip()
                        if not system.get("persistent_boot_target") or str(system.get("persistent_boot_target")).lower() in ("none", "n/a", "unknown", "null", "unavailable"):
                            system["persistent_boot_target"] = str(b_name).strip()
                        break

        # Correlate boot drive when system boots local ESXi/OS and no drive is flagged is_boot
        all_drives = [
            d for ctrl in storage if isinstance(ctrl, dict)
            for d in (ctrl.get("drives") or []) if isinstance(d, dict) and d.get("populated", True)
        ]
        has_flagged_boot = any(d.get("is_boot") for d in all_drives)
        if not has_flagged_boot and all_drives:
            cur_boot_tgt_low = cur_boot_tgt.lower()
            is_os_boot = (
                any(k in cur_boot_tgt_low for k in ["esxi", "vmware", "uefi os", "red hat", "windows", "linux", "ubuntu", "centos"])
                or any(
                    "safeboot64.efi" in str(b.get("uefi_path", "")).lower()
                    or "bootx64.efi" in str(b.get("uefi_path", "")).lower()
                    for b in (system.get("boot_order_details") or [])
                )
            )
            if is_os_boot:
                nvme_drives = [d for d in all_drives if "NVME" in str(d.get("protocol", "")).upper() or "PCIE" in str(d.get("protocol", "")).upper() or d.get("is_edsff")]
                sata_drives = [d for d in all_drives if "SATA" in str(d.get("protocol", "")).upper() or "SAS" in str(d.get("protocol", "")).upper()]
                consumer_drives = [d for d in all_drives if d.get("is_consumer") or is_consumer_drive(d.get("model", ""), d.get("manufacturer", ""))]

                boot_candidate = None
                if len(consumer_drives) == 1:
                    boot_candidate = consumer_drives[0]
                elif len(sata_drives) == 1 and len(nvme_drives) >= 2:
                    boot_candidate = sata_drives[0]
                elif consumer_drives and len(nvme_drives) >= 2:
                    boot_candidate = min(consumer_drives, key=lambda x: x.get("capacity_gb") or 0)

                if boot_candidate:
                    boot_candidate["is_boot"] = True
                    boot_candidate["usage_role"] = "Boot Drive"
                    boot_candidate["category"] = "Boot Device"
                    boot_candidate["vsan_eligible"] = False
                    if boot_candidate.get("is_consumer") or is_consumer_drive(boot_candidate.get("model", ""), boot_candidate.get("manufacturer", "")):
                        boot_candidate["status_badge"] = (
                            "<span class='badge' style='background:#0284c7;color:#fff'>🚀 Boot Device</span>"
                            "<br><small style='color:var(--text-muted,#94a3b8);font-size:.75rem'>Consumer SSD (Boot Only — Not vSAN Eligible)</small>"
                        )
                    else:
                        boot_candidate["status_badge"] = (
                            "<span class='badge info'>⚙️ Boot Device Only (Non-vSAN)</span>"
                        )

        for ctrl in storage:
            if isinstance(ctrl, dict):
                ctrl_link = evaluate_pcie_link_health(ctrl)
                if ctrl_link.get("degraded"):
                    c_finding = ctrl_link["finding"]
                    ctrl["pcie_link_eval"] = ctrl_link
                    ctrl["pcie_link_finding"] = c_finding
                    ctrl["downgraded"] = True
                    ctrl["downgrade_reason"] = c_finding
                    ctrl["downgrade_badge"] = ctrl_link["badge"]
                    if c_finding not in host_data.get("pcie_link_warnings", []):
                        host_data.setdefault("pcie_link_warnings", []).append(c_finding)
                        host_data.setdefault("warnings", []).append(c_finding)
                    if ctrl_link.get("signal_severity") == "critical":
                        host_data.setdefault("critical_findings", []).append(c_finding)

                drives = ctrl.get("drives") or []
                if isinstance(drives, list):
                    for drive in drives:
                        if isinstance(drive, dict):
                            # Defensively sanitize 255 / invalid endurance telemetry
                            if "endurance_pct" in drive:
                                drive["endurance_pct"] = sanitize_endurance_pct(drive.get("endurance_pct"))

                            # Evaluate Drive PCIe Link & Signal Degradation
                            if drive.get("pcie_errors") or drive.get("pcie_bus_errors") or drive.get("lanes") or drive.get("negotiated_lanes") or drive.get("max_lanes"):
                                d_link = evaluate_pcie_link_health(drive)
                                if d_link.get("degraded"):
                                    drive["pcie_link_eval"] = d_link
                                    drive["pcie_link_finding"] = d_link["finding"]
                                    drive["downgraded"] = True
                                    drive["downgrade_reason"] = d_link["finding"]
                                    drive["downgrade_badge"] = d_link["badge"]
                                    if d_link["finding"] not in host_data.get("pcie_link_warnings", []):
                                        host_data.setdefault("pcie_link_warnings", []).append(d_link["finding"])
                                        host_data.setdefault("warnings", []).append(d_link["finding"])
                                    if d_link.get("signal_severity") == "critical":
                                        drive["is_failing"] = True
                                        drive["failure_reason"] = d_link["finding"]
                                        host_data.setdefault("critical_findings", []).append(d_link["finding"])

                            d_model = str(drive.get("model") or drive.get("name") or "")
                            d_fw = str(drive.get("firmware") or "")
                            if d_model and d_fw and d_fw != "N/A":
                                defect = check_defective_drive_firmware(d_model, d_fw)
                                if defect:
                                    drive["is_defective_fw"] = True
                                    drive["defective_fw_advisory"] = defect.get("advisory", "")
                                if "fw_eval" not in drive:
                                    try:
                                        drive["fw_eval"] = evaluate_drive_fw(d_model, d_fw)
                                    except Exception as exc:
                                        logger.debug("Failed evaluating drive firmware for %s: %s", d_model, exc)

    # 9. BMC Security Audit Evaluation
    try:
        # Preserve existing bmc_security_config for backward compatibility
        if "bmc_security_config" not in host_data:
            host_data["bmc_security_config"] = {}

        sec_evidence = host_data.get("bmc_security_evidence")
        existing_audit = host_data.get("bmc_security_audit")

        if isinstance(existing_audit, dict) and existing_audit.get("findings") and not sec_evidence:
            # Preserved from an imported summary where raw evidence was omitted
            pass
        else:
            norm_vendor = "dell" if vendor and "dell" in vendor.lower() else (vendor or "generic")
            if not isinstance(sec_evidence, dict) or not sec_evidence:
                sec_evidence = empty_security_evidence(norm_vendor)
                host_data["bmc_security_evidence"] = sec_evidence
            elif not sec_evidence.get("vendor") or sec_evidence.get("vendor") == "generic":
                sec_evidence["vendor"] = norm_vendor

            raw_findings = evaluate_security_controls(sec_evidence)
            findings = redact_security_findings(raw_findings)
            host_data["bmc_security_evidence"] = redact_security_evidence(sec_evidence)

            pass_count = sum(1 for f in findings if f.get("status") == "pass")
            fail_count = sum(1 for f in findings if f.get("status") == "fail")
            na_count = sum(1 for f in findings if f.get("status") == "not_applicable")
            unknown_count = sum(1 for f in findings if str(f.get("status", "")).startswith("unknown"))

            host_data["bmc_security_audit"] = {
                "schema_version": sec_evidence.get("schema_version", 1),
                "vendor": sec_evidence.get("vendor", norm_vendor),
                "matrix_id": sec_evidence.get("_matrix_id") or "dmtf-8",
                "findings": findings,
                "summary": {
                    "pass": pass_count,
                    "fail": fail_count,
                    "unknown": unknown_count,
                    "not_applicable": na_count,
                    "total": len(findings),
                },
            }
    except Exception as exc:
        logger.debug("Failed evaluating BMC security audit: %s", exc)
        if "bmc_security_audit" not in host_data:
            host_data["bmc_security_audit"] = {
                "schema_version": 1,
                "vendor": vendor or "generic",
                "findings": [],
                "summary": {"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0, "total": 0},
            }

    # 10. BIOS VMD & Pending Settings Evaluation
    bios_checks = host_data.get("bios_checks")
    if isinstance(bios_checks, dict):
        active_vmd = bool(bios_checks.get("vmd_enabled_flag", False))
        pending_vmd = bios_checks.get("vmd_pending_flag")

        if active_vmd and pending_vmd is False:
            bios_checks["vmd_eval"] = {
                "badge": "Intel VMD: Enabled (Disabled PENDING Reboot)",
                "note": "VMD is currently Enabled in BIOS, but Disabled has been staged in Redfish. Power-cycle the server to apply.",
                "status": "pending_reboot",
                "staged_for_disable": True,
            }
        elif active_vmd:
            bios_checks["vmd_eval"] = {
                "badge": "Intel VMD: Enabled",
                "note": "Intel VMD is enabled in BIOS — disable for native NVMe pass-through under vSAN ESA.",
                "status": "enabled",
                "staged_for_disable": False,
            }
        else:
            bios_checks["vmd_eval"] = {
                "badge": "Intel VMD: Disabled (ESA Ready)",
                "note": "NVMe controller in native PCIe pass-through mode.",
                "status": "disabled",
                "staged_for_disable": False,
            }

    # 11. Vendor BIOS Golden Baseline Drift Evaluation
    vendor_lower = str(system.get("vendor") or "").lower()
    model_lower = str(system.get("model") or "").lower()
    collector_cls = str(host_data.get("collector_class") or "")

    if not isinstance(bios_checks, dict):
        host_data["bios_checks"] = {}
        bios_checks = host_data["bios_checks"]

    raw_attrs = bios_checks.get("attributes") or host_data.get("bios_attributes") or {}
    norm_attrs = bios_checks.get("normalized_attributes") or {}
    cpu_info = system.get("cpu_summary") or {}
    compat = host_data.get("compatibility") or {}
    is_esa = bool(
        compat.get("esa_ready")
        or compat.get("esa_storage_met")
        or any(
            str(d.get("protocol", "")).upper() == "NVME"
            for d in (host_data.get("storage_subsystem") or [])
        )
    )

    if "dell" in vendor_lower or "poweredge" in model_lower or "dell" in collector_cls.lower():
        merged_attrs = dict(raw_attrs)
        merged_attrs.update(norm_attrs)
        if "BootMode" not in merged_attrs:
            bm = system.get("raw_boot_mode") or system.get("boot_mode")
            if bm:
                merged_attrs["BootMode"] = bm

        if "memory_ras" not in bios_checks and raw_attrs:
            from vcf_hci.bios.ras_modes import _detect_memory_ras_modes
            bios_checks["memory_ras"] = _detect_memory_ras_modes(raw_attrs, vendor="dell")
        if "cpu_power" not in bios_checks and raw_attrs:
            from vcf_hci.bios.power_modes import _detect_cpu_power_mode
            bios_checks["cpu_power"] = _detect_cpu_power_mode(raw_attrs, vendor="dell")

        drift = evaluate_dell_bios_baseline(
            merged_attrs,
            cpu_info=cpu_info,
            is_esa_candidate=is_esa,
            model=system.get("model"),
            bios_version=system.get("bios_version"),
        )
        bios_checks["dell_baseline_drift"] = drift
        bios_checks["bios_baseline_drift"] = drift

    elif "hpe" in vendor_lower or "proliant" in model_lower or "synergy" in model_lower or "hpe" in collector_cls.lower():
        if not norm_attrs and raw_attrs:
            from vcf_hci.collector.oem.hpe import normalize_hpe_bios_attributes
            norm_attrs = normalize_hpe_bios_attributes(
                raw_attrs,
                fallback_boot_mode=system.get("raw_boot_mode") or system.get("boot_mode"),
            )
            bios_checks["normalized_attributes"] = norm_attrs
        merged_attrs = dict(raw_attrs)
        merged_attrs.update(norm_attrs)
        if "BootMode" not in merged_attrs:
            bm = system.get("raw_boot_mode") or system.get("boot_mode")
            if bm:
                merged_attrs["BootMode"] = bm

        if "memory_ras" not in bios_checks and raw_attrs:
            from vcf_hci.bios.ras_modes import _detect_memory_ras_modes
            bios_checks["memory_ras"] = _detect_memory_ras_modes(raw_attrs, vendor="hpe")
        if "cpu_power" not in bios_checks and raw_attrs:
            from vcf_hci.bios.power_modes import _detect_cpu_power_mode
            bios_checks["cpu_power"] = _detect_cpu_power_mode(raw_attrs, vendor="hpe")

        drift = evaluate_hpe_bios_baseline(
            merged_attrs,
            cpu_info=cpu_info,
            is_esa_candidate=is_esa,
            model=system.get("model"),
            bios_version=system.get("bios_version"),
        )
        bios_checks["hpe_baseline_drift"] = drift
        bios_checks["bios_baseline_drift"] = drift

    elif "cisco" in vendor_lower or "ucs" in model_lower or "cisco" in collector_cls.lower():
        if not norm_attrs and raw_attrs:
            from vcf_hci.collector.oem.cisco import normalize_cisco_bios_attributes
            norm_attrs = normalize_cisco_bios_attributes(
                raw_attrs,
                fallback_boot_mode=system.get("raw_boot_mode") or system.get("boot_mode"),
            )
            bios_checks["normalized_attributes"] = norm_attrs
        bios_checks["attributes"] = raw_attrs
        merged_attrs = dict(raw_attrs)
        merged_attrs.update(norm_attrs)
        if "BootMode" not in merged_attrs:
            bm = system.get("raw_boot_mode") or system.get("boot_mode")
            if bm:
                merged_attrs["BootMode"] = bm

        if "memory_ras" not in bios_checks and raw_attrs:
            from vcf_hci.bios.ras_modes import _detect_memory_ras_modes
            bios_checks["memory_ras"] = _detect_memory_ras_modes(raw_attrs, vendor="cisco")
        if "cpu_power" not in bios_checks and raw_attrs:
            from vcf_hci.bios.power_modes import _detect_cpu_power_mode
            bios_checks["cpu_power"] = _detect_cpu_power_mode(raw_attrs, vendor="cisco")

        drift = evaluate_cisco_bios_baseline(
            merged_attrs,
            cpu_info=cpu_info,
            is_esa_candidate=is_esa,
            model=system.get("model"),
            bios_version=system.get("bios_version"),
        )
        bios_checks["cisco_baseline_drift"] = drift
        bios_checks["bios_baseline_drift"] = drift

    elif "lenovo" in vendor_lower or "thinksystem" in model_lower or "lenovo" in collector_cls.lower():
        if not norm_attrs and raw_attrs:
            from vcf_hci.collector.oem.lenovo import normalize_lenovo_bios_attributes
            norm_attrs = normalize_lenovo_bios_attributes(
                raw_attrs,
                fallback_boot_mode=system.get("raw_boot_mode") or system.get("boot_mode"),
            )
            bios_checks["normalized_attributes"] = norm_attrs
        merged_attrs = dict(raw_attrs)
        merged_attrs.update(norm_attrs)
        if "BootMode" not in merged_attrs:
            bm = system.get("raw_boot_mode") or system.get("boot_mode")
            if bm:
                merged_attrs["BootMode"] = bm

        if "memory_ras" not in bios_checks and raw_attrs:
            from vcf_hci.bios.ras_modes import _detect_memory_ras_modes
            bios_checks["memory_ras"] = _detect_memory_ras_modes(raw_attrs, vendor="lenovo")
        if "cpu_power" not in bios_checks and raw_attrs:
            from vcf_hci.bios.power_modes import _detect_cpu_power_mode
            bios_checks["cpu_power"] = _detect_cpu_power_mode(raw_attrs, vendor="lenovo")

        drift = evaluate_lenovo_bios_baseline(
            merged_attrs,
            cpu_info=cpu_info,
            is_esa_candidate=is_esa,
            model=system.get("model"),
            bios_version=system.get("bios_version"),
        )
        bios_checks["lenovo_baseline_drift"] = drift
        bios_checks["bios_baseline_drift"] = drift

    elif raw_attrs or norm_attrs:
        # Generic / Supermicro / Quanta / Gigabyte fallback
        merged_attrs = dict(raw_attrs)
        merged_attrs.update(norm_attrs)
        if "BootMode" not in merged_attrs:
            bm = system.get("raw_boot_mode") or system.get("boot_mode")
            if bm:
                merged_attrs["BootMode"] = bm

        drift = evaluate_generic_bios_baseline(
            merged_attrs,
            cpu_info=cpu_info,
            is_esa_candidate=is_esa,
            model=system.get("model"),
            bios_version=system.get("bios_version"),
            vendor=system.get("vendor"),
        )
        bios_checks["generic_baseline_drift"] = drift
        bios_checks["bios_baseline_drift"] = drift

    # 11.5 Multi-Socket & NUMA BIOS Telemetry Evaluation
    all_bios_attrs = {}
    if isinstance(raw_attrs, dict):
        all_bios_attrs.update(raw_attrs)
    if isinstance(norm_attrs, dict):
        all_bios_attrs.update(norm_attrs)

    def _find_bios_val(*candidates: str) -> Optional[str]:
        for c in candidates:
            c_low = c.lower()
            for k, v in all_bios_attrs.items():
                k_low = k.lower()
                if k_low == c_low or k_low.endswith("." + c_low):
                    if v is not None and str(v).strip():
                        return str(v).strip()
        return None

    cpu_cnt = int(cpu_info.get("count") or cpu_info.get("cpu_count") or 1)
    is_multi_sock = cpu_cnt >= 2
    is_quad_sock = cpu_cnt >= 4

    snc_val = _find_bios_val("SubNumaCluster", "SubNumaClustering", "SNC", "NumaNodesPerSocket")
    uma_val = _find_bios_val("UmaBasedClusteringStatus", "UmaBasedClustering", "ClusteringMode")
    node_interleave_val = _find_bios_val("NodeInterleave", "NodeInterleaving", "Memory_NodeInterleave", "NumaMemInterleave", "NumaInterleaving")
    x2apic_val = _find_bios_val("ProcX2Apic", "x2APIC", "ProcessorX2Apic", "X2ApicOptOut")
    upi_prefetch_val = _find_bios_val("UpiPrefetch", "UpiPrefetcher", "UPIPrefetch")
    upi_power_val = _find_bios_val("CpuInterconnectBusLinkPower", "InterconnectBusLinkPower", "UpiLinkPowerManagement")
    acpi_slit_val = _find_bios_val("AcpiSlit", "Slit")
    acpi_pxm_val = _find_bios_val("AcpiRootBridgePxm", "RootBridgePxm")
    numa_group_val = _find_bios_val("NumaGroupSizeOpt", "NumaGroupSizeOptimization")

    snc_mode = ""
    if snc_val:
        s_low = snc_val.lower()
        if "snc4" in s_low or s_low in ("4", "quad"):
            snc_mode = "SNC-4"
        elif "snc2" in s_low or s_low in ("2", "hemi", "hemisphere"):
            snc_mode = "SNC-2"
        elif s_low in ("disabled", "off", "0"):
            snc_mode = "Disabled"
        elif s_low in ("auto", "default"):
            snc_mode = "Auto"
        else:
            snc_mode = snc_val

    uma_mode = ""
    if uma_val:
        u_low = uma_val.lower()
        if "quad" in u_low or u_low == "4":
            uma_mode = "Quadrant"
        elif "hemi" in u_low or u_low == "2":
            uma_mode = "Hemisphere"
        elif "all" in u_low:
            uma_mode = "All-to-All"
        elif "disab" in u_low or u_low == "0":
            uma_mode = "Disabled"
        else:
            uma_mode = uma_val

    ni_warn = False
    if node_interleave_val and node_interleave_val.lower() in ("enabled", "enable", "on", "true", "1"):
        ni_warn = True
        host_data.setdefault("readiness_warnings", []).append(
            "BIOS: Node Interleaving is Enabled. This flattens NUMA into UMA, degrading ESXi NUMA-aware scheduling. Disable in BIOS."
        )

    x2_warn = False
    if x2apic_val and x2apic_val.lower() in ("disabled", "disable", "off", "false", "0"):
        if is_multi_sock or int(cpu_info.get("cores") or 0) > 32:
            x2_warn = True
            host_data.setdefault("readiness_warnings", []).append(
                "BIOS: Processor x2APIC Mode is Disabled on a multi-socket / high-core server. Must be Enabled in BIOS for vSphere 9.1 interrupt scaling."
            )

    mst = {
        "is_multi_socket": is_multi_sock,
        "is_quad_socket": is_quad_sock,
        "socket_count": cpu_cnt,
        "sub_numa_clustering": snc_val,
        "snc_mode": snc_mode,
        "uma_clustering": uma_mode or uma_val,
        "node_interleave": node_interleave_val,
        "node_interleave_warning": ni_warn,
        "proc_x2apic": x2apic_val,
        "proc_x2apic_warning": x2_warn,
        "upi_prefetch": upi_prefetch_val,
        "upi_link_power": upi_power_val,
        "acpi_slit": acpi_slit_val,
        "acpi_root_bridge_pxm": acpi_pxm_val,
        "numa_group_size_opt": numa_group_val,
    }
    host_data["multi_socket_telemetry"] = mst
    bios_checks["multi_socket_telemetry"] = mst
    if isinstance(cpu_info, dict):
        cpu_info["multi_socket_telemetry"] = mst

    # 12. Lifecycle Controller / BMC Job Queue Pre-Flight Evaluation
    job_q = host_data.get("job_queue")
    if isinstance(job_q, dict) and job_q:
        failed_jobs = int(job_q.get("failed_jobs") or 0)
        stale_jobs = int(job_q.get("stale_jobs") or 0)
        pending_reboot_jobs = int(job_q.get("pending_reboot_jobs") or 0)

        if failed_jobs > 0 or stale_jobs > 0:
            finding = f"Stale/Failed LC Jobs Detected ({failed_jobs} failed, {stale_jobs} stale). May block VCF host staging or reboot."
            remediation = "Log into iDRAC Web UI or run RACADM `jobqueue delete` to clear stalled tasks prior to VCF commissioning."
            eval_dict = {
                "severity": "WARNING",
                "finding": finding,
                "remediation": remediation,
                "failed_jobs": failed_jobs,
                "stale_jobs": stale_jobs,
                "pending_reboot_jobs": pending_reboot_jobs,
                "status": "warning",
            }
            job_q["evaluation"] = eval_dict
            host_data.setdefault("readiness_findings", []).append(finding)
            host_data.setdefault("readiness_warnings", []).append(finding)
            host_data.setdefault("warnings", []).append(f"{finding} Remediation: {remediation}")
        elif pending_reboot_jobs > 0:
            finding = f"Lifecycle Controller has {pending_reboot_jobs} job(s) pending reboot."
            eval_dict = {
                "severity": "INFO",
                "finding": finding,
                "remediation": "Power-cycle or reboot host to allow staged configuration jobs to complete.",
                "failed_jobs": 0,
                "stale_jobs": 0,
                "pending_reboot_jobs": pending_reboot_jobs,
                "status": "info",
            }
            job_q["evaluation"] = eval_dict
        else:
            job_q["evaluation"] = {
                "severity": "OK",
                "finding": "LC Job Queue clean (0 failed, 0 stale).",
                "remediation": "",
                "failed_jobs": 0,
                "stale_jobs": 0,
                "pending_reboot_jobs": 0,
                "status": "ok",
            }

    # 13. System Event Log (SEL / FaultList) EEMS Decoding & Blocker Prioritization
    sel_events = host_data.get("sel_alarms") or host_data.get("sel") or host_data.get("system_event_log") or []
    vcf_blockers = list(host_data.get("vcf_blockers") or [])
    if isinstance(sel_events, list) and sel_events:
        for event in sel_events:
            if not isinstance(event, dict):
                continue
            msg_id = event.get("message_id")
            msg_text = event.get("message")
            decoded = decode_dell_message_id(msg_id, msg_text)
            if decoded:
                event["eems"] = decoded.to_dict()
                event["is_vcf_blocker"] = decoded.is_vcf_blocker
                event["vcf_impact"] = decoded.vcf_impact
                event["explanation"] = decoded.explanation
                event["remediation"] = decoded.remediation
                event["doc_url"] = decoded.doc_url
                event["domain"] = decoded.domain
                event["eems_code"] = decoded.code

                if decoded.is_vcf_blocker:
                    blocker_info = {
                        "code": decoded.code,
                        "domain": decoded.domain,
                        "severity": decoded.severity,
                        "vcf_impact": decoded.vcf_impact,
                        "explanation": decoded.explanation,
                        "remediation": decoded.remediation,
                        "doc_url": decoded.doc_url,
                        "message": str(msg_text or ""),
                        "timestamp": str(event.get("timestamp") or ""),
                    }
                    if not any(b.get("code") == decoded.code and b.get("message") == blocker_info["message"] for b in vcf_blockers):
                        vcf_blockers.append(blocker_info)

                    finding = f"VCF Hardware Blocker ({decoded.code}): {decoded.vcf_impact} — {decoded.explanation}"
                    if finding not in host_data.setdefault("readiness_findings", []):
                        host_data["readiness_findings"].append(finding)
                    if finding not in host_data.setdefault("readiness_warnings", []):
                        host_data["readiness_warnings"].append(finding)
                    rem_warn = f"{finding} Remediation: {decoded.remediation}"
                    if rem_warn not in host_data.setdefault("warnings", []):
                        host_data["warnings"].append(rem_warn)

    if vcf_blockers:
        blocker_codes = [b["code"] for b in vcf_blockers]
        blocker_summary_str = f"BLOCKED: {len(vcf_blockers)} Critical Hardware Blocker(s) Detected ({', '.join(blocker_codes)})"
        host_data["vcf_blockers"] = vcf_blockers
        host_data["hardware_fault_blockers"] = vcf_blockers
        host_data["overall_verdict"] = "NON_COMPLIANT (Hardware Blocker)"
        host_data["vcf9_verdict"] = "NON_COMPLIANT (Hardware Blocker)"
        eval_summary = {
            "status": "BLOCKED",
            "is_blocked": True,
            "blocker_count": len(vcf_blockers),
            "blockers": vcf_blockers,
            "summary": blocker_summary_str,
        }
        host_data["assessment_verdict"] = eval_summary
        system["assessment_verdict"] = eval_summary
    else:
        eval_summary = {
            "status": "PASSED",
            "is_blocked": False,
            "blocker_count": 0,
            "blockers": [],
            "summary": "No hardware fault blockers detected.",
        }
        host_data["assessment_verdict"] = eval_summary
        system["assessment_verdict"] = eval_summary

    from vcf_hci.collector.hardware_findings import annotate_hardware_findings
    annotate_hardware_findings(host_data)
    host_data["_enriched"] = True

