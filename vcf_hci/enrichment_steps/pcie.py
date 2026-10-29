"""Collected/derived PCIe topology, device correlation and lane budgets."""
import logging
import re
from typing import Any, Dict, List, Optional

from vcf_hci.collector.pci_utils import extract_pci_ids_from_dict
from vcf_hci.compat_engine import VCF9CompatibilityEngine
from vcf_hci.constants import is_generic_name
from vcf_hci.hcl import lookup_unique_hcl_device

logger = logging.getLogger("vcf_assess")


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

    # Storage NVMe rows are rebuilt by correlate_direct_attached_nvme_pcie.

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
        h_name = hba.get("adapter_name") or hba.get("model") or hba.get("name") or "FC HBA"
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


def correlate_direct_attached_nvme_pcie(
    host_data: Dict[str, Any],
    json_hcl: Optional[Dict[str, Any]] = None,
) -> None:
    """Ensure direct-attached NVMe SSDs and unpopulated physical slots appear in pcie_slots."""
    pcie_slots = host_data.setdefault("pcie_slots", [])
    if not isinstance(pcie_slots, list):
        pcie_slots = []
        host_data["pcie_slots"] = pcie_slots

    # Historical derived rows had no provenance marker. Their exact label/type
    # signature distinguishes them from collected physical slot inventory.
    pcie_slots[:] = [s for s in pcie_slots if isinstance(s, dict) and not (
        s.get("source") == "storage_nvme"
        or (str(s.get("slot_label") or "").startswith(("NVMe Drive Bay ", "NVMe Bay ("))
            and s.get("slot_type") == "U.3 / U.2 NVMe")
        or (str(s.get("slot_label") or "").startswith("NVMe Slot")
            and s.get("slot_type") == "M2" and s.get("functions") == [{"function_id": 0}])
    )]
    seen_identities = set()
    seen_serials = {
        str(s.get("device_serial") or "").strip().lower()
        for s in pcie_slots if s.get("device_serial")
    }
    seen_names = {
        str(s.get("device_name") or "").strip().lower()
        for s in pcie_slots if s.get("device_name")
    }
    seen_labels = {
        str(s.get("slot_label") or "").strip().upper()
        for s in pcie_slots if s.get("slot_label")
    }

    # 1. Correlate direct-attached NVMe SSDs from storage_subsystem
    for ctrl in (host_data.get("storage_subsystem") or []):
        if not isinstance(ctrl, dict):
            continue
        c_name = str(ctrl.get("name") or ctrl.get("ctrl_model") or "")
        is_direct = "direct" in c_name.lower() or ctrl.get("direct_attached") is True
        is_raid = any(t in c_name.lower() for t in ("raid", "perc", "smart array")) and not any(
            t in c_name.lower() for t in ("hba", "pass-through", "passthrough"))
        for drv in ctrl.get("drives") or []:
            if not isinstance(drv, dict):
                continue
            proto = str(drv.get("protocol") or drv.get("bus_protocol") or "").lower()
            cat = str(drv.get("category") or "").lower()
            d_name = str(drv.get("name") or "")
            d_model = str(drv.get("model") or "")
            d_serial = str(drv.get("serial_number") or "").strip()

            is_nvme = ("nvme" in proto or "pcie" in proto) if proto else (
                "nvme" in cat or "nvme" in d_name.lower() or "nvme" in d_model.lower())
            if d_serial.lower() in ("n/a", "unknown", "none", "not available"):
                d_serial = ""
            absent = str(drv.get("state") or "").lower() == "absent" or str(drv.get("category") or "").lower() == "empty"
            if absent or drv.get("populated") is False or "empty bay" in d_name.lower():
                continue
            # Protocol alone does not establish direct CPU attachment.
            if not is_nvme or is_raid or drv.get("behind_trimode") or not (is_direct or drv.get("direct_attached") is True):
                continue
            identity = (str(ctrl.get("id") or c_name), str(drv.get("id") or drv.get("odata_id") or d_name))
            if not d_serial and (not identity[1] or identity in seen_identities):
                continue
            seen_identities.add(identity)

            if d_serial and d_serial.lower() in seen_serials:
                continue

            # Determine slot label
            m_bay = re.search(r"\b(?:Drive|Bay|Disk|Slot)\s*(\d+)\b", d_name, re.I)
            bay_num = m_bay.group(1) if m_bay else None
            if bay_num is not None:
                slot_label = f"NVMe Drive Bay {bay_num}"
            elif d_name:
                slot_label = f"NVMe Bay ({d_name})"
            else:
                slot_label = f"NVMe Drive Bay {len(pcie_slots) + 1}"

            if slot_label.upper() in seen_labels:
                slot_label = f"{slot_label} ({d_serial[-6:] if len(d_serial) >= 6 else len(pcie_slots)+1})"

            seen_labels.add(slot_label.upper())
            if d_serial:
                seen_serials.add(d_serial.lower())

            # Speed / lanes
            # Drive transfer rate is not PCIe link generation or lane width.
            # The parser may retain a controller's uplink as context. It must
            # never become a per-drive lane width and be counted repeatedly.
            pcie_gen = drv.get("current_pcie_type") or (
                drv.get("pcie_gen") if drv.get("pcie_gen_source") == "drive" else None) or "Unknown"
            lanes = drv.get("current_pcie_width") or (
                drv.get("pcie_lanes_in_use") if drv.get("pcie_lanes_source") == "drive" else None)
            bcg_link = drv.get("bcg_url") or ""

            pcie_slots.append({
                "slot_label": slot_label,
                "source": "storage_nvme",
                "lanes": lanes,
                "pcie_type": pcie_gen,
                "slot_type": "U.3 / U.2 NVMe",
                "hot_pluggable": drv.get("hot_pluggable"),
                "state": drv.get("state") or "Unknown",
                "populated": True,
                "device_name": d_model or d_name or "NVMe Solid State Drive",
                "device_manufacturer": drv.get("manufacturer") or "NVMe SSD",
                "device_part_number": drv.get("part_number") or "",
                "device_serial": d_serial,
                "device_health": str(drv.get("drive_health") or drv.get("health") or "Unknown").strip(),
                "functions": [{"function_id": 0}],
                "function_count": 1,
                "vendor_id": drv.get("vendor_id", ""),
                "device_id": drv.get("device_id", ""),
                "subsystem_vendor_id": drv.get("subsystem_vendor_id", ""),
                "subsystem_id": drv.get("subsystem_id", ""),
                "pci_quad": drv.get("pci_quad", ""),
                "pci_pair": drv.get("pci_pair", ""),
                "current_pcie_type": pcie_gen,
                "current_pcie_width": lanes,
                "downgraded": False,
                "downgrade_reason": "",
                "downgrade_badge": "",
                "bcg_url": bcg_link,
            })

    # 2. Add unpopulated PCIe slots for Lenovo ThinkSystem SR650 V4 when omitted by BMC
    sys_info = host_data.get("system") or {}
    model = str(sys_info.get("model") or "").upper()
    vendor = str(sys_info.get("vendor") or "").upper()
    is_sr650_v4 = ("SR650 V4" in model or "SR650V4" in model) and ("LENOVO" in vendor or "LNVO" in vendor)

    if is_sr650_v4:
        existing_slot_nums = set()
        for s in pcie_slots:
            m = re.search(r"\bPCIe\s*(\d+)\b", str(s.get("slot_label") or ""), re.I)
            if m:
                existing_slot_nums.add(int(m.group(1)))

        standard_slots = [
            (1, 8, "Gen5", "LowProfile"),
            (2, 16, "Gen5", "FullLength"),
            (3, 8, "Gen5", "FullLength"),
            (4, 16, "Gen5", "FullLength"),
            (6, 8, "Gen5", "FullLength"),
            (7, 16, "Gen5", "FullLength"),
            (8, 16, "Gen5", "FullLength"),
        ]
        for slot_num, lanes, gen, stype in standard_slots:
            if slot_num not in existing_slot_nums:
                pcie_slots.append({
                    "slot_label": f"PCIe {slot_num}",
                    "lanes": lanes,
                    "pcie_type": gen,
                    "slot_type": stype,
                    "hot_pluggable": False,
                    "state": "Absent",
                    "populated": False,
                    "device_name": "",
                    "device_manufacturer": "",
                    "device_part_number": "",
                    "device_serial": "",
                    "device_health": "",
                    "functions": [],
                    "function_count": 0,
                    "vendor_id": "",
                    "device_id": "",
                    "subsystem_vendor_id": "",
                    "subsystem_id": "",
                    "pci_quad": "",
                    "pci_pair": "",
                    "downgraded": False,
                    "downgrade_reason": "",
                    "downgrade_badge": "",
                })

    def _slot_sort_key(s: Dict[str, Any]) -> tuple:
        label = str(s.get("slot_label") or "")
        m_pcie = re.search(r"PCIe\s*(\d+)", label, re.I)
        m_bay = re.search(r"Bay\s*(\d+)", label, re.I)
        if m_pcie:
            return (0, int(m_pcie.group(1)), label)
        elif m_bay:
            return (1, int(m_bay.group(1)), label)
        elif "NVMe" in label:
            return (1, 999, label)
        return (2, 999, label)

    pcie_slots.sort(key=_slot_sort_key)


def enrich_pcie_topology(
    host_data: Dict[str, Any], cpu_summary: Any, cpu_count: int,
    json_hcl: Optional[Dict[str, Any]],
) -> None:
    """Synthesize and correlate slots after FC enrichment, then evaluate the CPU lane budget."""
    # 6. PCIe Lane Budget Evaluation
    pcie_slots = host_data.get("pcie_slots") or []
    if not pcie_slots:
        pcie_slots = synthesize_pcie_slots(host_data, json_hcl=json_hcl)
        if pcie_slots:
            host_data["pcie_slots"] = pcie_slots

    try:
        correlate_direct_attached_nvme_pcie(host_data, json_hcl=json_hcl)
        pcie_slots = host_data.get("pcie_slots") or []
    except Exception as exc:
        logger.debug("Failed correlating direct-attached NVMe PCIe slots: %s", exc)

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
