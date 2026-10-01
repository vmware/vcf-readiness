"""
BMC and Drive Firmware & Driver evaluation for VCF 9.1.
"""
import re
from typing import Optional

from ..collector.pci_utils import normalize_pci_id, select_best_pci_pair_entry
from ..constants import BMC_FW_BASELINES, NVME_FW_BASELINES
from ..logging_utils import parse_version_tuple


def evaluate_bmc_fw_version(bmc_model: str, installed_version: str) -> dict:
    """Evaluate BMC/management-controller firmware against BMC_FW_BASELINES.

    Returns a dict with 'badge', 'spectre_status', and 'spectre_badge' keys,
    mirroring the evaluate_bios_version() interface for consistent HTML rendering.
    bmc_model is matched as a case-insensitive substring of the BMC_FW_BASELINES key.
    """
    key_up = str(bmc_model or "").upper().strip()
    if "13G" in key_up and "IDRAC" not in key_up:
        key_up = "IDRAC8"
    elif any(g in key_up for g in ("14G", "15G", "16G")) and "IDRAC" not in key_up:
        key_up = "IDRAC9"
    elif "17G" in key_up and "IDRAC" not in key_up:
        key_up = "IDRAC10"
    installed_str = str(installed_version or "N/A")
    baseline = next((BMC_FW_BASELINES[k] for k in BMC_FW_BASELINES if k in key_up or key_up in k), None)
    if not baseline:
        return {
            "badge": f"<span class='badge info'>ℹ️ {installed_str}</span>",
            "spectre_status": "unverified",
            "spectre_badge": "<span class='badge info'>ℹ️ No BMC Baseline</span>",
            "latest_version": "N/A",
            "update_recommended": False,
            "is_outdated": False,
            "upgrade_recommendation": "",
        }
    inst = parse_version_tuple(installed_str)
    latest = parse_version_tuple(baseline["latest"])
    min_rec = parse_version_tuple(baseline["min_recommended"])
    min_sp = parse_version_tuple(baseline.get("min_spectre", "0"))
    update_rec = inst < latest
    is_outdated = inst < min_rec
    if inst >= latest:
        badge = f"<span class='badge success'>\U0001f7e2 Up-to-Date ({installed_str})</span>"
    elif inst >= min_rec:
        badge = f"<span class='badge warning'>\U0001f7e1 Update Available ({installed_str} | Latest: {baseline['latest']})</span>"
    else:
        badge = f"<span class='badge danger'>\U0001f534 Outdated ({installed_str} | Latest: {baseline['latest']})</span>"
    spectre_status = "ok" if inst >= min_sp else "exposed"
    spectre_badge = (
        f"<span class='badge success'>\U0001f6e1️ OK (≥ {baseline['min_spectre']})</span>"
        if spectre_status == "ok"
        else f"<span class='badge danger'>⚠️ Pre-Spectre BMC: {installed_version} — min {baseline['min_spectre']}</span>"
    )
    rec_msg = f"Recommend {bmc_model or 'BMC'} firmware upgrade from v{installed_str} to v{baseline['latest']}." if update_rec else ""
    return {
        "badge": badge,
        "spectre_status": spectre_status,
        "spectre_badge": spectre_badge,
        "latest_version": baseline["latest"],
        "update_recommended": update_rec,
        "is_outdated": is_outdated,
        "upgrade_recommendation": rec_msg,
    }


def _parse_fw_version_tuple(v_str: str) -> tuple:
    nums = re.findall(r'\d+', str(v_str))
    return tuple(int(x) for x in nums) if nums else (0,)


def _compare_fw_versions(fw_installed: str, fw_recommended: str) -> int:
    """Return >0 if installed > recommended, 0 if equal, <0 if installed < recommended."""
    if not fw_installed or not fw_recommended or fw_installed == "N/A" or fw_recommended == "N/A":
        return 0
    t_inst = _parse_fw_version_tuple(fw_installed)
    t_rec = _parse_fw_version_tuple(fw_recommended)
    if t_inst and t_rec and len(t_inst) > 0 and len(t_rec) > 0:
        # Handle 3-part vs 4-part Mellanox/vendor sub-build notation (e.g. 14.32.21.04 vs 14.32.2004)
        if len(t_inst) == 4 and len(t_rec) == 3 and t_rec[2] >= 100:
            t_rec = (t_rec[0], t_rec[1], t_rec[2] // 100, t_rec[2] % 100)
        elif len(t_inst) == 3 and len(t_rec) == 4 and t_inst[2] >= 100:
            t_inst = (t_inst[0], t_inst[1], t_inst[2] // 100, t_inst[2] % 100)

        max_len = max(len(t_inst), len(t_rec))
        t_inst_pad = t_inst + (0,) * (max_len - len(t_inst))
        t_rec_pad = t_rec + (0,) * (max_len - len(t_rec))

        if t_inst_pad > t_rec_pad:
            return 1
        elif t_inst_pad < t_rec_pad:
            return -1
        return 0
    i_up = str(fw_installed or "").upper().strip()
    r_up = str(fw_recommended or "").upper().strip()
    if i_up > r_up:
        return 1
    elif i_up < r_up:
        return -1
    return 0


def evaluate_driver_firmware_recommendation(
    vid: str = "",
    did: str = "",
    svid: str = "",
    ssid: str = "",
    model_name: str = "",
    fw_ver: str = "",
    hcl_data: Optional[dict] = None,
    target_release: str = "ESXi 9.1",
) -> dict:
    """Evaluate driver recommendation and firmware match status against Broadcom HCL dataset."""
    v = normalize_pci_id(vid)
    d = normalize_pci_id(did)
    sv = normalize_pci_id(svid)
    ss = normalize_pci_id(ssid)

    quad = f"{v}:{d}:{sv}:{ss}" if (v and d and sv and ss) else ""
    pair = f"{v}:{d}" if (v and d) else ""
    key = str(model_name).strip().upper() if model_name else ""

    hcl = hcl_data or {}
    quads = (hcl.get("quads") or hcl.get("_pci_quads", {})) if isinstance(hcl, dict) else {}
    pairs = (hcl.get("pairs") or hcl.get("_pci_pairs", {})) if isinstance(hcl, dict) else {}
    models = hcl.get("models", {}) if isinstance(hcl, dict) else {}

    matched_entry = None
    if quad and quad in quads:
        matched_entry = quads[quad]
    elif quad and quad in hcl:
        matched_entry = hcl[quad]
    elif pair and pair in pairs:
        res_list = pairs[pair]
        matched_entry = select_best_pci_pair_entry(res_list, model_name=model_name, svid=sv, ssid=ss)
    elif pair and pair in hcl:
        val = hcl[pair]
        matched_entry = select_best_pci_pair_entry(val, model_name=model_name, svid=sv, ssid=ss)
    elif key and key in models:
        matched_entry = models[key]
    elif key and key in hcl:
        matched_entry = hcl[key]

    rec_driver = ""
    rec_fw = ""
    min_fw = ""
    if isinstance(matched_entry, dict):
        rec_driver = matched_entry.get("recommended_driver", "")
        rec_fw = matched_entry.get("recommended_firmware", "")
        min_fw = matched_entry.get("min_firmware", "") or rec_fw
        release_matrix = matched_entry.get("release_matrix", {})
        if isinstance(release_matrix, dict) and target_release in release_matrix:
            rel_info = release_matrix[target_release]
            if isinstance(rel_info, dict):
                rec_driver = rel_info.get("driver") or rel_info.get("recommended_driver") or rec_driver
                min_fw = rel_info.get("min_firmware") or rel_info.get("firmware") or min_fw
                rec_fw = rel_info.get("recommended_firmware") or rel_info.get("latest_firmware") or rel_info.get("firmware") or rec_fw

    fw_installed = str(fw_ver).strip() if fw_ver else "N/A"

    if not rec_fw or rec_fw == "N/A":
        fw_status = "unverified"
        fw_badge = "<span class='badge info'>ℹ️ FW Unverified</span>"
    else:
        target_min = min_fw or rec_fw
        cmp_min = _compare_fw_versions(fw_installed, target_min)
        cmp_rec = _compare_fw_versions(fw_installed, rec_fw)
        if cmp_min < 0:
            fw_status = "outdated"
            fw_badge = f"<span class='badge danger'>\U0001f534 FW Outdated ({fw_installed} &lt; {target_min})</span>"
        elif cmp_rec < 0:
            fw_status = "update_available"
            fw_badge = f"<span class='badge success'>\U0001f7e2 FW Certified ({fw_installed})</span> <span style='font-size:.75rem;color:#ca8a04;font-weight:600'>(Newer available → {rec_fw})</span>"
        else:
            fw_status = "current"
            fw_badge = f"<span class='badge success'>\U0001f7e2 FW Certified ({fw_installed})</span>"

    if rec_driver:
        driver_badge = f"<span class='badge info'>🚗 Recommended Driver: <code>{rec_driver}</code></span>"
    else:
        driver_badge = "<span class='badge info'>🚗 Inbox/Default Driver</span>"

    rdma_supported = False
    vcglink = ""
    product_id = ""
    io_product_id = ""
    io_vcglink = ""
    if isinstance(matched_entry, dict):
        rdma_supported = bool(matched_entry.get("rdma_supported"))
        vcglink = str(matched_entry.get("vcglink") or "")
        product_id = str(matched_entry.get("product_id") or "")
        io_product_id = str(matched_entry.get("io_product_id") or "")
        io_vcglink = str(matched_entry.get("io_vcglink") or "")
        if not io_product_id and matched_entry.get("hcl_program") == "io" and product_id:
            io_product_id = product_id
        if not io_vcglink and io_product_id:
            io_vcglink = f"https://compatibilityguide.broadcom.com/detail?program=io&productId={io_product_id}&persona=live"

    rdma_badge = "<span class='badge success' style='font-size:.72rem;'>⚡ vSAN RDMA Supported</span>" if rdma_supported else ""

    return {
        "recommended_driver": rec_driver,
        "recommended_firmware": rec_fw,
        "min_firmware": min_fw,
        "fw_status": fw_status,
        "fw_badge": fw_badge,
        "driver_badge": driver_badge,
        "rdma_supported": rdma_supported,
        "rdma_badge": rdma_badge,
        "vcglink": vcglink,
        "product_id": product_id,
        "io_product_id": io_product_id,
        "io_vcglink": io_vcglink,
        "matched_entry": matched_entry,
    }


KNOWN_DEFECTIVE_DRIVE_FIRMWARE: dict = {
    # HPE 32,768-Hour Failure Bug (Customer Advisory a00092491en_us)
    # Drives fail at 32,768 operating hours; data is permanently unrecoverable.
    # Fixed in HDP8 or later.
    "VO0480JFDGT": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VO0960JFDGU": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VO1920JFDGV": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VO3840JFDHA": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "MO0400JFFCF": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "MO0800JFFCH": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "MO1600JFFCK": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "MO3200JFFCL": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VO000480JWDAR": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VO000960JWDAT": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VO001920JWDAU": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VO003840JWDAV": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VO007680JWCNK": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VO015300JWCNL": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VK000960JWSSQ": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VK001920JWSSR": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VK003840JWSST": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VK007680JWSSU": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},
    "VO015300JWSSV": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"), "advisory": "HPE a00092491 (32,768-hr Failure Bug)"},

    # HPE 40,000-Hour Failure Bug (Customer Advisory a00097382en_us)
    # Drives fail at 40,000 operating hours; data is permanently unrecoverable.
    # Fixed in HDP7 or later.
    "EK0800JVYPN": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6"), "advisory": "HPE a00097382 (40,000-hr Failure Bug)"},
    "EO1600JVYPP": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6"), "advisory": "HPE a00097382 (40,000-hr Failure Bug)"},
    "MK0800JVYPQ": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6"), "advisory": "HPE a00097382 (40,000-hr Failure Bug)"},
    "MO1600JVYPR": {"affected": ("HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6"), "advisory": "HPE a00097382 (40,000-hr Failure Bug)"},

    # Fujitsu Support Bulletin SB-PRI-21010
    "PX02SMF020": {"affected": ("5202", "5203", "5204"), "advisory": "Fujitsu SB-PRI-21010 Critical Bug"},
    "PX02SMF040": {"affected": ("5202", "5203", "5204"), "advisory": "Fujitsu SB-PRI-21010 Critical Bug"},
    "PX02SMF080": {"affected": ("5202", "5203", "5204"), "advisory": "Fujitsu SB-PRI-21010 Critical Bug"},
    "PX02SMB160": {"affected": ("5202", "5203", "5204"), "advisory": "Fujitsu SB-PRI-21010 Critical Bug"},
}


def check_defective_drive_firmware(model: str, fw_ver: str) -> Optional[dict]:
    """Check if drive model and firmware match known catastrophic failure advisories."""
    if not model or not fw_ver or fw_ver == "N/A":
        return None
    model_clean = str(model).strip().upper()
    fw_clean = str(fw_ver).strip().upper()
    for m_key, entry in KNOWN_DEFECTIVE_DRIVE_FIRMWARE.items():
        if m_key in model_clean:
            if fw_clean in entry["affected"]:
                return entry
    return None


def evaluate_drive_fw(
    model: str,
    installed_fw: str,
    hcl_data: Optional[dict] = None,
    vid: str = "",
    did: str = "",
    svid: str = "",
    ssid: str = "",
) -> str:
    """Return a color-coded firmware HTML cell for NVMe drives.

    Checks HCL data for exact PCI IDs or model match. When installed firmware meets
    the certified minimum version, it is marked as Certified (green). If a newer certified
    firmware version exists on the HCL, it displays a yellow note indicating the newer version.
    """
    fw = str(installed_fw).strip() if installed_fw else "N/A"
    if fw == "N/A" or not fw:
        return f"<code>{fw}</code> <span style='font-size:.75rem;color:#94a3b8'>Unknown</span>"

    defect = check_defective_drive_firmware(model, fw)
    if defect:
        advisory = defect.get("advisory", "Known Fatal Firmware Defect")
        return (
            f"<code style='color:var(--danger);font-weight:700'>{fw}</code>"
            f"<br><span class='badge danger' style='font-size:.72rem;'>⚠️ Critical FW Defect</span>"
            f"<br><span style='font-size:.70rem;color:var(--danger);font-weight:600'>{advisory} — Upgrade Required</span>"
        )

    if hcl_data:
        eval_res = evaluate_driver_firmware_recommendation(
            vid=vid, did=did, svid=svid, ssid=ssid, model_name=model, fw_ver=fw, hcl_data=hcl_data
        )
        rec_fw = eval_res.get("recommended_firmware")
        min_fw = eval_res.get("min_firmware") or rec_fw
        if rec_fw or min_fw:
            target_min = min_fw or rec_fw
            if target_min:
                cmp_min = _compare_fw_versions(fw, str(target_min))
                cmp_rec = _compare_fw_versions(fw, str(rec_fw)) if rec_fw else 0
                if cmp_min < 0:
                    return (
                        f"<code style='color:var(--danger);font-weight:600'>{fw}</code>"
                        f"<br><span style='font-size:.72rem;color:var(--danger)'>✗ Outdated — min certified: {target_min}</span>"
                    )
                elif cmp_rec < 0:
                    return (
                        f"<code style='color:var(--success);font-weight:600'>{fw}</code>"
                        f"<br><span style='font-size:.72rem;color:var(--success)'>✓ Certified</span> "
                        f"<span style='font-size:.72rem;color:#ca8a04;font-weight:600'>(Newer available → {rec_fw})</span>"
                    )
                else:
                    return (
                        f"<code style='color:var(--success);font-weight:600'>{fw}</code>"
                        f"<br><span style='font-size:.72rem;color:var(--success)'>✓ Certified &amp; Current</span>"
                    )

    model_up = str(model or "").upper().strip()
    baseline = next(
        (NVME_FW_BASELINES[k] for k in NVME_FW_BASELINES if model_up.startswith(k)),
        None,
    )
    if not baseline:
        return f"<code>{fw}</code>"
    latest  = str(baseline.get("latest") or "").upper()
    min_rec = str(baseline.get("min_recommended") or "").upper()
    fw_up   = str(fw or "").upper()
    if fw_up >= latest:
        return (
            f"<code style='color:var(--success);font-weight:600'>{fw}</code>"
            f"<br><span style='font-size:.72rem;color:var(--success)'>✓ Certified ({latest})</span>"
        )
    if fw_up >= min_rec:
        return (
            f"<code style='color:var(--success);font-weight:600'>{fw}</code>"
            f"<br><span style='font-size:.72rem;color:var(--success)'>✓ Certified</span> "
            f"<span style='font-size:.72rem;color:#ca8a04;font-weight:600'>(Newer available → {latest})</span>"
        )
    return (
        f"<code style='color:var(--danger);font-weight:600'>{fw}</code>"
        f"<br><span style='font-size:.72rem;color:var(--danger)'>✗ Outdated — latest: {latest}</span>"
    )
