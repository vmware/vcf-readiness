"""Controller consolidation, boot correlation and drive qualification."""
import logging
from typing import Any, Dict, List, Optional

from vcf_hci.collector.collect_storage_drive import sanitize_endurance_pct
from vcf_hci.compat_engine import check_defective_drive_firmware, evaluate_drive_fw, evaluate_pcie_link_health
from vcf_hci.hcl import evaluate_drive_hcl_tier, is_consumer_drive

logger = logging.getLogger("vcf_assess")


def is_vmd_active_in_bios(bios_checks: Optional[Dict[str, Any]]) -> bool:
    """Return True if Intel VMD is detected as active/enabled in BIOS settings."""
    if not isinstance(bios_checks, dict):
        return False
    if bios_checks.get("vmd_enabled_flag") is True:
        return True
    vmd_eval = bios_checks.get("vmd_eval")
    if isinstance(vmd_eval, dict):
        if vmd_eval.get("status") in ("enabled", "pending_reboot"):
            return True
        vmd_badge = str(vmd_eval.get("badge", "")).lower()
        if "enabled" in vmd_badge and "disabled" not in vmd_badge:
            return True
    # Check attributes or normalized_attributes
    attrs = bios_checks.get("attributes") or bios_checks.get("normalized_attributes") or {}
    if isinstance(attrs, dict):
        for k, v in attrs.items():
            if "vmd" in k.lower():
                val_str = str(v).lower()
                if any(on in val_str for on in ("enabled", "enable", "vmdenabled", "auto", "1", "true")):
                    return True
    return False


def consolidate_direct_attached_nvme_controllers(
    storage_subsystem: List[Dict[str, Any]],
    bios_checks: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Consolidate fragmented direct-attach NVMe controllers into a unified controller view.

    On platforms like HPE ProLiant Gen10/Gen11, Redfish exposes each direct-attached NVMe
    drive behind an isolated storage controller endpoint (DA000000..DA00000F).
    This function consolidates these fragmented 1-drive endpoints into a single controller card,
    updates controller names and topology flags, preserves underlying drive compatibility,
    and flags Intel VMD requirement when active.
    """
    if not isinstance(storage_subsystem, list) or not storage_subsystem:
        return storage_subsystem

    vmd_active = is_vmd_active_in_bios(bios_checks)
    if not vmd_active:
        vmd_active = any(bool(c.get("is_vmd")) for c in storage_subsystem if isinstance(c, dict))

    # Identify fragmented direct-attach NVMe controllers
    fragmented_ctrls: List[Dict[str, Any]] = []
    for ctrl in storage_subsystem:
        if not isinstance(ctrl, dict):
            continue
        if ctrl.get("is_boot_ctrl"):
            continue
        if ctrl.get("has_logical_volumes") or ctrl.get("volumes"):
            continue

        ctrl_id = str(ctrl.get("id") or "").strip().upper()
        ctrl_name = str(ctrl.get("name") or "").strip().upper()

        if any(k in ctrl_name or k in ctrl_id for k in ["BOSS", "NS204", "PERC", "SMART ARRAY", "MR GEN", "MEGA", "SR932", "SR416", "B545"]):
            continue

        is_da_pattern = (
            ctrl_id.startswith("DA00")
            or ctrl_name in ("NVME STORAGE SYSTEM", "NVME STORAGE CONTROLLER", "DIRECT-ATTACHED NVME", "NVME CONTROLLER")
            or ("NVME" in ctrl_name and any(p in ctrl_name for p in ["DIRECT", "PASS", "RISER", "ATTACH"]))
        )
        if not is_da_pattern:
            continue

        drives = ctrl.get("drives") or []
        if not isinstance(drives, list):
            continue
        pop_drives = [d for d in drives if isinstance(d, dict) and d.get("populated", True)]
        if len(pop_drives) > 1:
            continue
        if len(pop_drives) == 1:
            proto = str(pop_drives[0].get("protocol") or "").upper()
            if not ("NVME" in proto or "PCIE" in proto or pop_drives[0].get("is_edsff") or pop_drives[0].get("is_nvme")):
                continue

        fragmented_ctrls.append(ctrl)

    should_consolidate = len(fragmented_ctrls) >= 2 or (
        len(fragmented_ctrls) == 1 and any(str(c.get("id", "")).upper().startswith("DA00") for c in fragmented_ctrls)
    )

    if should_consolidate and fragmented_ctrls:
        first_ctrl = fragmented_ctrls[0]
        if vmd_active:
            consolidated_name = "Direct-Attached NVMe (Intel VMD Managed)"
            consolidated_id = "VMD-NVMe"
            consolidated_model = "Intel VMD Domain (Direct-Attached NVMe)"
            consolidated_fw = "N/A (Direct PCIe/VMD)"
            ctrl_is_vmd = True
        else:
            consolidated_name = "Direct-Attached NVMe / PCIe Riser"
            consolidated_id = "DirectAttach-NVMe"
            consolidated_model = "Direct-Attached PCIe Root Ports"
            consolidated_fw = "N/A (Pass-Through)"
            ctrl_is_vmd = False

        pop_drives: List[Dict[str, Any]] = []
        empty_drives: List[Dict[str, Any]] = []
        seen_drive_serials: set = set()

        for c in fragmented_ctrls:
            for d in (c.get("drives") or []):
                if not isinstance(d, dict):
                    continue
                if d.get("populated", True):
                    sn = d.get("serial_number") or d.get("id") or d.get("name")
                    if sn and sn in seen_drive_serials:
                        continue
                    if sn:
                        seen_drive_serials.add(sn)
                    pop_drives.append(d)
                else:
                    empty_drives.append(d)

        consolidated_drives = pop_drives + empty_drives
        for d in consolidated_drives:
            d["controller_id"] = consolidated_id
            d["controller_name"] = consolidated_name
            d["ctrl_name"] = consolidated_name
            d["behind_trimode"] = False
            if vmd_active:
                d["behind_vmd"] = True

        seen_enc_ids: set = set()
        merged_enclosures: List[Dict[str, Any]] = []
        for c in fragmented_ctrls:
            for enc in (c.get("enclosures") or []):
                if isinstance(enc, dict):
                    enc_id = enc.get("id") or enc.get("name")
                    if enc_id and enc_id not in seen_enc_ids:
                        seen_enc_ids.add(enc_id)
                        merged_enclosures.append(enc)

        consolidated_ctrl: Dict[str, Any] = dict(first_ctrl)
        consolidated_ctrl.update({
            "id":                  consolidated_id,
            "name":                consolidated_name,
            "ctrl_model":          consolidated_model,
            "ctrl_firmware":       consolidated_fw,
            "is_vmd":              ctrl_is_vmd,
            "is_trimode":          False,
            "is_software_raid":    False,
            "has_logical_volumes": False,
            "volumes":             [],
            "bbu_health":          None,
            "bbu_badge":           "",
            "is_boot_ctrl":        False,
            "device_protocols":    ["NVMe", "PCIe"],
            "drives":              consolidated_drives,
            "enclosures":          merged_enclosures,
        })
        if vmd_active and not consolidated_ctrl.get("vendor_id"):
            consolidated_ctrl["vendor_id"] = "8086"

        new_storage: List[Dict[str, Any]] = []
        consolidated_inserted = False
        for ctrl in storage_subsystem:
            if ctrl in fragmented_ctrls:
                if not consolidated_inserted:
                    new_storage.append(consolidated_ctrl)
                    consolidated_inserted = True
            else:
                new_storage.append(ctrl)
        storage_subsystem = new_storage

    # Ensure all remaining controllers/drives reflect VMD and non-TriMode state correctly
    for ctrl in storage_subsystem:
        if not isinstance(ctrl, dict):
            continue
        c_str = f"{ctrl.get('id', '')} {ctrl.get('name', '')}".upper()
        if "VROC" in c_str:
            ctrl["is_vmd"] = True
            ctrl["is_trimode"] = False
            ctrl["is_software_raid"] = True
            for drv in (ctrl.get("drives") or []):
                if isinstance(drv, dict):
                    drv["behind_trimode"] = False
                    drv["behind_vmd"] = True
                    drv["behind_software_raid"] = True
        elif ctrl.get("is_vmd") or (vmd_active and "NVME" in c_str and not ctrl.get("is_boot_ctrl") and not ctrl.get("has_logical_volumes")):
            ctrl["is_vmd"] = True
            ctrl["is_trimode"] = False
            for drv in (ctrl.get("drives") or []):
                if isinstance(drv, dict):
                    drv["behind_trimode"] = False
                    if vmd_active:
                        drv["behind_vmd"] = True

    return storage_subsystem


def enrich_storage(
    host_data: Dict[str, Any], system: Dict[str, Any], json_hcl: Optional[Dict[str, Any]],
) -> None:
    """Normalize storage and qualify drives using the shared system reference and existing evidence."""
    # 8. Storage Drive Firmware & PCIe Link Evaluations
    storage = host_data.get("storage_subsystem")
    if not isinstance(storage, list) and isinstance(host_data.get("storage"), dict):
        storage = host_data.get("storage", {}).get("controllers") or []
    if isinstance(storage, list):
        # Defensive deduplication of drives per controller & boot controller normalization
        for ctrl in storage:
            if not isinstance(ctrl, dict):
                continue
            ctrl_drives = ctrl.get("drives")
            if isinstance(ctrl_drives, list) and ctrl_drives:
                deduped_drives = []
                ctrl_seen_sns = set()
                ctrl_seen_ids = set()
                for d in ctrl_drives:
                    if not isinstance(d, dict):
                        continue
                    sn = str(d.get("serial_number") or "").strip().upper()
                    did = str(d.get("id") or "").strip().upper()
                    if sn and sn not in ("UNKNOWN", "NONE", "N/A", "NOT AVAILABLE") and sn in ctrl_seen_sns:
                        continue
                    if did and did in ctrl_seen_ids:
                        continue
                    if sn and sn not in ("UNKNOWN", "NONE", "N/A", "NOT AVAILABLE"):
                        ctrl_seen_sns.add(sn)
                    if did:
                        ctrl_seen_ids.add(did)
                    deduped_drives.append(d)
                ctrl["drives"] = deduped_drives

            # Normalize is_boot_ctrl if matching keywords or all populated drives are boot devices
            c_name = str(ctrl.get("name") or "").upper()
            c_id = str(ctrl.get("id") or "").upper()
            c_model = str(ctrl.get("ctrl_model") or "").upper()
            c_ident = f"{c_id} {c_name} {c_model}"
            if any(k in c_ident for k in ("BOSS", "NS204", "SATADOM", "IDSDM", "B545", "M.2 RAID", "M.2 BOOT", "M.2 ENABLEMENT", "M.2 ADAPTER")):
                ctrl["is_boot_ctrl"] = True

            pop_ctrl_drives = [d for d in (ctrl.get("drives") or []) if isinstance(d, dict) and d.get("populated", True)]
            if pop_ctrl_drives and all(d.get("is_boot") or str(d.get("category") or "") == "Boot Device" for d in pop_ctrl_drives):
                ctrl["is_boot_ctrl"] = True

        bios_checks = host_data.get("bios_checks") or {}
        storage = consolidate_direct_attached_nvme_controllers(storage, bios_checks)
        host_data["storage_subsystem"] = storage
        if isinstance(host_data.get("storage"), dict):
            host_data["storage"]["controllers"] = storage

        cur_boot_tgt = str(system.get("boot_target") or "").strip()
        if not cur_boot_tgt or cur_boot_tgt.lower() in ("none", "n/a", "unknown", "null", "unavailable"):
            for ctrl in storage:
                if isinstance(ctrl, dict) and (ctrl.get("is_boot_ctrl") or any(b in (ctrl.get("name") or "").upper() for b in ("BOSS", "NS204", "SATADOM", "B545"))):
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
                        if c_finding not in host_data.setdefault("critical_findings", []):
                            host_data["critical_findings"].append(c_finding)

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
                                        if d_link["finding"] not in host_data.setdefault("critical_findings", []):
                                            host_data["critical_findings"].append(d_link["finding"])

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

                            if drive.get("populated", True) and not drive.get("is_boot") and drive.get("category") != "Boot Device":
                                try:
                                    eval_hcl = evaluate_drive_hcl_tier(drive, json_hcl=json_hcl)
                                    drive["category"] = eval_hcl["category"]
                                    drive["status_badge"] = eval_hcl["status_badge"]
                                    drive["hcl_str"] = eval_hcl["hcl_str"]
                                    if "vsan_eligible" not in drive:
                                        drive["vsan_eligible"] = eval_hcl["vsan_eligible"]
                                except Exception as exc:
                                    logger.debug("Failed evaluating drive HCL tier for %s: %s", d_model, exc)
