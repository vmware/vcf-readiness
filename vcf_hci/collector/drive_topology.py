"""Pure drive attachment, existing qualification and negotiated/capable link evidence."""
from typing import Any, Optional

from vcf_hci.constants import KB_TRIMODE
from vcf_hci.hcl import detect_consumer_drive, detect_qlc_nvme


def _parse_lanes(val: Any) -> Optional[int]:
    if isinstance(val, int):
        return val
    if isinstance(val, str) and val.lower().startswith("x"):
        try:
            return int(val[1:])
        except ValueError:
            pass
    return None


def derive_drive_attachment(
    drive_json: dict, ctrl_id: str, ctrl_name: str, model: str, drive_name: str,
    proto: str, media: str, is_magnetic: bool, cap_gb: Any, ctrl_pcie: Optional[dict],
    location: dict, has_logical_vols: bool, sw_raid_names: list, trimode_names: list,
) -> dict:
    """Preserve boot/RAID/VMD/connector and eligibility precedence without I/O."""
    ctrl_id_up, ctrl_name_up = str(ctrl_id).upper(), str(ctrl_name).upper()
    model_up, drive_name_up = model.upper(), drive_name.upper()
    _ff_raw = location["raw_form_factor"]
    is_edsff, form_factor_label = location["is_edsff"], location["form_factor_label"]
    drive_id_up = str(drive_json.get("Id", "") or "").upper()
    is_boot = (
        bool(drive_json.get("Bootable") or drive_json.get("IsBootDisk"))
        or any(k in ctrl_id_up or k in ctrl_name_up for k in ["BOSS", "NS204I", "M.2", "AHCI.SLOT", "MARVELL", "MRVL", "88NR2241", "HA-RAID", "SATADOM", "IDSDM", "B545"])
        or "MTFDDAV240TCB" in model_up
        or any(k in model_up or k in drive_name_up or k in drive_id_up for k in ["BOOT", "BOSS", "NS204I", "SATADOM", "DOM", "IDSDM", "MARVELL", "KXG80ZNV", "BOOT_DRIVE_BAY"])
        or ("SATA" in proto and 0 < cap_gb <= 240 and any(k in model_up or k in drive_name_up for k in ["OS", "SYS", "HYPERVISOR", "M.2"]))
    )
    if is_boot and "KXG80ZNV" in model_up and cap_gb <= 0:
        cap_gb = 476.94
    _PASS_THROUGH_CTRL_PATTERNS = [
        "HBA", "NONRAID", "NON-RAID", "PASS", "CPU", "EXTENDER", "EXPANDER",
        "RETIMER", "SWITCH", "BRIDGE", "DIRECT", "AHCI", "CHIPSET", "UNMANAGED",
        "HBA3", "HBA 3", "JBOD", "NVME_CONTROLLER", "NVME CONTROLLER",
        "BIFURCATION", "GLOTRENDS", "PU41",
    ]
    is_hba = any(k in ctrl_name_up or k in ctrl_id_up for k in _PASS_THROUGH_CTRL_PATTERNS)
    _EXPLICIT_RAID_NAMES = ["RAID", "SMART ARRAY", "MEGA", "MR", "PERC H7", "PERC H8", "PERC H9", "PERC S", "PERC FD"]
    is_raid_ctrl = (has_logical_vols or any(k in ctrl_name_up for k in _EXPLICIT_RAID_NAMES)) and not is_hba
    is_nvme = "NVME" in proto or "PCIE" in proto

    # ── PCIe topology ──────────────────────────────────────────────────────
    cp = ctrl_pcie or {}
    # Controller PCIeInterface describes its uplink, not an individual drive link.
    drive_pcie_if = drive_json.get("PCIeInterface") or {}
    pcie_lanes = drive_pcie_if.get("LanesInUse")
    pcie_max = drive_pcie_if.get("MaxLanes")
    pcie_gen = drive_pcie_if.get("PCIeType")

    _is_m2 = (
        "M2" in _ff_raw or "M.2" in _ff_raw
        or any(k in ctrl_id_up or k in ctrl_name_up
               for k in ["BOSS", "NS204I", "MARVELL", "MRVL", "88NR2241", "HA-RAID", "B545"])
    )


    is_vmd_ctrl = cp.get("is_vmd", False) or any(k in ctrl_name_up or k in ctrl_id_up for k in ["VMD", "VROC"])

    # Software RAID: Host/chipset CPU-assisted RAID (e.g. Dell PERC S140/S150, HPE Dynamic Smart Array, Intel VROC)
    is_software_raid = (
        cp.get("is_software_raid", False)
        or is_vmd_ctrl
        or any(p in ctrl_name_up or p in ctrl_id_up for p in sw_raid_names)
    )

    # Tri-mode: controller supports both NVMe and SAS/SATA devices.
    # Also catch via well-known name patterns when the protocol list is absent.
    is_trimode_by_proto = cp.get("is_trimode", False) and not is_software_raid
    is_trimode_by_name  = (
        any(p in ctrl_name_up for p in [t.upper() for t in trimode_names])
        and not is_software_raid
    )

    # Exclude motherboard chipset/AHCI/VMD/direct PCIe/extender/HBA/software RAID controllers from tri-mode false positives
    _NON_TRIMODE_CTRL_PATTERNS = [
        "AHCI", "SATA", "INTEL", "VMD", "VROC", "CPU", "DIRECT", "CHIPSET", "ASMEDIA", "AMD", "ASROCK", "ASUS",
        "GLOTRENDS", "PU41", "BIFURCATION",
        "EXTENDER", "EXPANDER", "RETIMER", "SWITCH", "BRIDGE", "UNMANAGED", "HBA3", "HBA 3", "HBA330", "HBA350", "HBA355",
    ] + list(sw_raid_names)
    _is_known_non_trimode_ctrl = (
        any(p in ctrl_name_up or p in ctrl_id_up for p in _NON_TRIMODE_CTRL_PATTERNS)
        and not is_trimode_by_name
    )

    # M.2 drives and direct CPU/PCIe-attached drives on non-Tri-Mode controllers are never behind Tri-Mode RAID
    behind_trimode = (
        is_nvme and not is_boot and not _is_m2 and not is_software_raid
        and (is_trimode_by_name or (is_trimode_by_proto and not _is_known_non_trimode_ctrl))
    )
    behind_vmd = is_nvme and not is_boot and not _is_m2 and is_vmd_ctrl
    behind_software_raid = is_nvme and not is_boot and not _is_m2 and is_software_raid

    # Single-lane: x1 PCIe on a non-boot NVMe drive (performance risk)
    single_lane_alert = (
        is_nvme and not is_boot and not _is_m2 and not behind_trimode
        and isinstance(pcie_lanes, int) and pcie_lanes == 1
    )

    # ── NVMe connector type (U.2 / U.3 / M.2) ────────────────────────────
    # Redfish FormFactor does NOT distinguish U.2 from U.3 — both show as
    # 2.5" SFF (SFF-8639 connector).  The difference is tri-mode capability:
    # U.3 slots can switch between NVMe, SAS, and SATA on the same connector.
    # Detection strategy (in priority order):
    #   1. EDSFF form factor → use the E3.S / E1.S / EDSFF label directly
    #   2. M.2 → from FormFactor "M2*" or controller name (BOSS, NS204I, MARVELL)
    #   3. Known U.3 model prefixes (vendor datasheets confirm SFF-8639 tri-mode)
    #   4. Behind a tri-mode HBA → U.3 backplane (drive itself may be U.2 or U.3)
    #   5. All other NVMe 2.5" → U.2 (statistically the most common deployment)
    #   SAS / SATA drives: connector type irrelevant for vSAN ESA; leave blank.
    _U3_MODEL_PREFIXES = (
        "KCD8",    # Kioxia CD8P-V / CD8 family — explicitly marketed as U.3
        "KCM6",    # Kioxia CM6-V U.3 enterprise read-optimised
        "MTFDKCC", # Micron 6500 ION U.3 (SFF-8639, tri-mode backplane)
    )
    _is_m2 = (
        "M2" in _ff_raw or "M.2" in _ff_raw
        or any(k in ctrl_id_up or k in ctrl_name_up
               for k in ["BOSS", "NS204I", "MARVELL", "MRVL", "88NR2241", "HA-RAID", "B545"])
    )
    if is_edsff:
        nvme_connector = form_factor_label          # "E3.S" / "E1.S" / "EDSFF"
    elif _is_m2:
        nvme_connector = "M.2"
    elif is_nvme and not is_boot:
        if any(model_up.startswith(p) for p in _U3_MODEL_PREFIXES):
            nvme_connector = "U.3"
        elif behind_trimode:
            # Tri-mode HBA implies a U.3-capable backplane; the physical drive
            # plugged in may itself be U.2 or U.3 — label the slot, not the drive.
            nvme_connector = "U.3 slot"
        else:
            nvme_connector = "U.2"
    else:
        nvme_connector = ""

    # ── vSAN compatibility badge ───────────────────────────────────────────
    is_qlc = False  # overridden below for direct-attached NVMe only
    consumer_reason = detect_consumer_drive(model, manufacturer=drive_json.get("Manufacturer") or "")
    is_consumer = consumer_reason is not None

    if is_boot:
        if is_consumer:
            badge, category, vsan_ok = (
                "<span class='badge' style='background:#0284c7;color:#fff'>🚀 Boot Device Only</span>"
                "<br><small style='color:var(--text-muted,#94a3b8);font-size:.75rem'>Consumer SSD (Boot Only — Not vSAN Eligible)</small>",
                "Boot Device", False,
            )
        else:
            badge, category, vsan_ok = (
                "<span class='badge info'>⚙️ Boot Device Only (Non-vSAN)</span>",
                "Boot Device", False,
            )
    elif behind_trimode:
        badge, category, vsan_ok = (
            f"<span class='badge danger'>🔴 NOT Supported — NVMe Behind Tri-Mode RAID</span>"
            f"<br><a href='{KB_TRIMODE}' target='_blank' "
            f"style='font-size:.78rem;color:var(--danger)'>KB314305 ↗</a>",
            "Unsupported NVMe Tri-Mode", False,
        )
    elif behind_software_raid:
        badge, category, vsan_ok = (
            f"<span class='badge warning'>⚠️ Software RAID ({ctrl_name})</span>"
            f"<br><small style='font-size:.76rem;color:var(--warning)'>Bypass in BIOS (AHCI/Non-RAID) for direct vSAN ESA</small>",
            "vSAN ESA/OSA NVMe", True,
        )
    elif is_nvme and is_raid_ctrl and not is_hba and not is_software_raid:
        badge, category, vsan_ok = (
            "<span class='badge danger'>🔴 NOT Supported (NVMe Behind RAID)</span>",
            "Unsupported NVMe RAID", False,
        )
    elif any(k in model_up for k in ["OPTANE", "P4800X", "P4801X", "P5800X", "P1600X", "MEMPEK"]):
        badge, category, vsan_ok = (
            "<span class='badge danger'>🔴 Not vSAN Compatible</span>"
            "<br><span class='badge info' style='margin-top:4px;'>🔵 Memory Tiering Candidate</span>",
            "Optane Memory Tiering", False,
        )
    elif is_consumer:
        badge, category, vsan_ok = (
            "<span class='badge danger'>🔴 Unsupported (Consumer SSD)</span>"
            "<br><small style='color:var(--danger,#ef4444);font-size:.75rem'>Consumer drive — lacks Power Loss Protection (PLP) &amp; not vSAN certified</small>",
            "Unsupported Consumer SSD", False,
        )
    elif is_magnetic or "HDD" in media:
        badge, category, vsan_ok = (
            "<span class='badge' style='background:#78716c;color:#fff'>🧲 Magnetic HDD</span>",
            "Magnetic HDD", False,
        )
    elif "SAS" in proto or "SATA" in proto:
        badge, category, vsan_ok = (
            "<span class='badge warning'>🟡 vSAN OSA Only</span>",
            "vSAN OSA Only", True,
        )
    elif is_nvme:
        is_qlc = detect_qlc_nvme(model)
        if cap_gb > 0 and cap_gb < 1400:
            badge, category, vsan_ok = (
                "<span class='badge warning'>🟡 vSAN OSA Only (< 1.6TB NVMe — ESA requires ≥1.6TB)</span>",
                "vSAN OSA Only", True,
            )
        else:
            badge, category, vsan_ok = (
                "<span class='badge success'>🟢 ESA Compatible</span>",
                "vSAN ESA/OSA NVMe", True,
            )
    else:
        badge, category, vsan_ok = (
            "<span class='badge warning'>⚠️ Unknown / Unverified</span>",
            "Unknown", False,
        )

    # Append single-lane warning into the vSAN badge column
    if single_lane_alert:
        badge += (
            "<br><span class='badge danger' style='margin-top:4px;font-size:.78rem'>"
            "⚠️ Single PCIe Lane (x1) — severe performance limitation</span>"
        )

    result = {'nvme_connector': nvme_connector, 'category': category, 'is_boot': is_boot, 'vsan_eligible': vsan_ok, 'status_badge': badge, 'behind_trimode': behind_trimode, 'behind_software_raid': behind_software_raid, 'behind_vmd': behind_vmd, 'single_lane_alert': single_lane_alert, 'is_qlc': is_qlc, 'is_consumer': bool(is_consumer), 'consumer_reason': consumer_reason or '', 'pcie_lanes_in_use': pcie_lanes, 'pcie_max_lanes': pcie_max, 'pcie_gen': pcie_gen}
    result.update(_is_nvme=is_nvme, _is_m2=_is_m2, _drive_pcie_if=drive_pcie_if)
    return result


def derive_drive_pcie_link(attachment: dict, oem_metrics: dict) -> dict:
    """Apply late OEM widths without substituting a controller uplink for a drive."""
    pcie_lanes, pcie_max = attachment["pcie_lanes_in_use"], attachment["pcie_max_lanes"]
    pcie_gen, drive_pcie_if = attachment["pcie_gen"], attachment["_drive_pcie_if"]
    is_nvme, is_boot = attachment["_is_nvme"], attachment["is_boot"]
    _is_m2, behind_trimode = attachment["_is_m2"], attachment["behind_trimode"]
    pcie_cap_width = (
        (f"x{pcie_max}" if isinstance(pcie_max, int) else None)
        or oem_metrics.get("pcie_capable_width")
    )
    pcie_neg_width = (
        (f"x{pcie_lanes}" if isinstance(pcie_lanes, int) else None)
        or oem_metrics.get("pcie_negotiated_width")
    )

    n_lanes = _parse_lanes(pcie_neg_width)
    c_lanes = _parse_lanes(pcie_cap_width)
    if isinstance(n_lanes, int) and pcie_lanes is None:
        pcie_lanes = n_lanes
    if isinstance(c_lanes, int) and pcie_max is None:
        pcie_max = c_lanes

    pcie_downshifted = bool(
        is_nvme
        and not is_boot
        and not _is_m2
        and not behind_trimode
        and isinstance(n_lanes, int)
        and isinstance(c_lanes, int)
        and n_lanes < c_lanes
    )

    return {'pcie_lanes_in_use': pcie_lanes, 'pcie_lanes_source': 'drive' if drive_pcie_if.get('LanesInUse') is not None else 'oem' if oem_metrics.get('pcie_negotiated_width') else 'Unknown', 'pcie_max_lanes_source': 'drive' if drive_pcie_if.get('MaxLanes') is not None else 'oem' if oem_metrics.get('pcie_capable_width') else 'Unknown', 'pcie_gen_source': 'drive' if drive_pcie_if.get('PCIeType') else 'Unknown', 'pcie_max_lanes': pcie_max, 'pcie_gen': pcie_gen, 'pcie_capable_width': pcie_cap_width, 'pcie_capable_width_source': 'drive' if drive_pcie_if.get('MaxLanes') is not None else 'oem' if oem_metrics.get('pcie_capable_width') else 'Unknown', 'pcie_negotiated_width': pcie_neg_width, 'pcie_negotiated_width_source': 'drive' if drive_pcie_if.get('LanesInUse') is not None else 'oem' if oem_metrics.get('pcie_negotiated_width') else 'Unknown', 'pcie_downshifted': pcie_downshifted}
