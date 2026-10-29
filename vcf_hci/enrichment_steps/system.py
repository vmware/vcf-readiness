"""System identity, CPU/firmware context, cooling and memory topology."""
import logging
import re
from typing import Any, Dict, Tuple

from vcf_hci.compat_engine import (
    VCF9CompatibilityEngine,
    evaluate_bios_version,
    evaluate_bmc_fw_version,
    evaluate_boot_mode,
)

logger = logging.getLogger("vcf_assess")


def detect_liquid_cooling(system: Dict[str, Any], host_data: Dict[str, Any]) -> Dict[str, Any]:
    """Detect Lenovo Neptune or other OEM direct-water / liquid cooling architecture."""
    model = str(system.get("model") or "").upper()
    sku = str(system.get("sku") or "").upper()
    vendor = str(system.get("vendor") or "").upper()

    is_lenovo = "LENOVO" in vendor or "LNVO" in vendor or "THINKSYSTEM" in model
    is_neptune = False
    is_liquid = False
    cooling_tech = ""

    # 1. Lenovo machine type / SKU / model checks
    if is_lenovo:
        if "7DK2" in sku or "7DK2" in model:
            is_neptune = True
            cooling_tech = "Lenovo Neptune Compute Complex DWC"
        elif any(m in model for m in ["SD650", "SD665", "SC777"]):
            is_neptune = True
            cooling_tech = "Lenovo Neptune Direct Water Cooling"
        elif any(kw in model or kw in sku for kw in ["NEPTUNE", "DWC", "DIRECT WATER", "WATER COOLED"]):
            is_neptune = True
            cooling_tech = "Lenovo Neptune DWC"

    # 2. General OEM model/SKU liquid keywords
    if not is_neptune and any(kw in model or kw in sku for kw in ["LIQUID", "DWC", "DIRECT WATER", "WATER COOLED", "NEPTUNE"]):
        is_liquid = True
        cooling_tech = "Direct Liquid Cooled"

    # 3. Telemetry / sensors inspection across all OEMs
    sensors = host_data.get("chassis_sensors") or []
    thermal = host_data.get("thermal_telemetry") or {}
    temp_sensors = thermal.get("temperatures") or []
    fan_sensors = thermal.get("fans") or []
    all_sensor_names = [
        str(s.get("name") or s.get("Name") or s.get("id") or "")
        for s in (sensors if isinstance(sensors, list) else []) +
                 (temp_sensors if isinstance(temp_sensors, list) else []) +
                 (fan_sensors if isinstance(fan_sensors, list) else [])
    ]
    cooling_keywords = ["coolant", "water inlet", "water outlet", "liquid", "pump", "leak detect", "neptune"]
    for s_name in all_sensor_names:
        s_low = s_name.lower()
        if any(kw in s_low for kw in cooling_keywords):
            is_liquid = True
            if is_lenovo:
                is_neptune = True
                cooling_tech = cooling_tech or "Lenovo Neptune DWC"
            else:
                cooling_tech = cooling_tech or "Direct Liquid Cooled"
            break

    if is_neptune:
        return {
            "is_liquid_cooled": True,
            "is_neptune": True,
            "cooling_type": cooling_tech or "Lenovo Neptune DWC",
            "badge": "<span class='badge info' style='background:rgba(14,165,233,0.15);color:#0284c7;border:1px solid rgba(14,165,233,0.3)'>💧 Lenovo Neptune DWC</span>",
        }
    elif is_liquid:
        return {
            "is_liquid_cooled": True,
            "is_neptune": False,
            "cooling_type": cooling_tech or "Direct Liquid Cooled",
            "badge": "<span class='badge info' style='background:rgba(14,165,233,0.15);color:#0284c7;border:1px solid rgba(14,165,233,0.3)'>💧 Liquid Cooled</span>",
        }
    return {
        "is_liquid_cooled": False,
        "is_neptune": False,
        "cooling_type": "Air Cooled",
        "badge": "",
    }


def enrich_system_identity_and_cpu(host_data: Dict[str, Any]) -> Tuple[Dict[str, Any], str, Any]:
    """Return the actual system/CPU references and resolved vendor; invalid systems stay detached."""
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

    # Blade / modular server detection enrichment
    model_str = str(model or "").lower()
    if not system.get("is_blade"):
        if any(k in model_str for k in ("ucsb", "ucsx", "e910", "blade", "sled")):
            system["is_blade"] = True
    if system.get("is_blade") and not system.get("chassis_label"):
        if "ucsb" in model_str:
            system["chassis_label"] = f"Cisco UCS B-Series Blade ({model})"
        elif "ucsx" in model_str:
            system["chassis_label"] = f"Cisco UCS X-Series Compute Node ({model})"
        else:
            system["chassis_label"] = f"Blade Server ({model})"

    bios_version = str(system.get("bios_version") or "Unknown")
    bios_date = str(system.get("bios_release_date") or "")

    # 1. BIOS Version Evaluation
    try:
        system["bios_eval"] = evaluate_bios_version(model, bios_version, bios_date, system_info=system)
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

    # Liquid Cooling / Lenovo Neptune Detection
    try:
        cooling_info = detect_liquid_cooling(system, host_data)
        system["cooling_type"] = cooling_info["cooling_type"]
        system["is_liquid_cooled"] = cooling_info["is_liquid_cooled"]
        system["is_neptune"] = cooling_info["is_neptune"]
        system["liquid_cooling_badge"] = cooling_info["badge"]
        if isinstance(cpu_summary, dict) and cooling_info["is_liquid_cooled"]:
            cpu_summary["cooling"] = cooling_info["cooling_type"]
            cpu_summary["cooling_badge"] = cooling_info["badge"]
    except Exception as exc:
        logger.debug("Failed detecting liquid cooling: %s", exc)

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

    return system, vendor, cpu_summary


def enrich_memory_topology(host_data: Dict[str, Any], cpu_summary: Any) -> int:
    """Normalize memory after CPU evaluation and return the socket count used for lane budgets."""
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
                m_dell = None
                if not re.search(r"(?:PROC|CPU|SOCKET)[._\s-]*[1-4]|(?:^|[._\s-])P[1-4][._\s-]", slot_str):
                    m_dell = re.search(r"^(?:DIMM(?:[._\s-]*SOCKET)?[._\s-]*)?([A-D])(\d+)$", slot_str) or re.search(r"\bDIMM(?:[._\s-]*SOCKET)?[._\s-]+([A-D])(\d+)\b", slot_str)
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

    return cpu_count
