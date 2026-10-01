"""
VCF Readiness Tool — drive cross-reference against vSAN HCL and QLC detection.
"""
import re
from typing import Optional

from vcf_hci.collector.pci_utils import normalize_pci_id, select_best_pci_pair_entry
from vcf_hci.constants import QLC_NVME_PREFIXES

_GENERIC_DRIVE_TOKENS = {
    "INTEL", "DELL", "CISCO", "MICRON", "SAMSUNG", "SEAGATE", "TOSHIBA",
    "SOLIDIGM", "KINGSTON", "LENOVO", "HPE", "HGST", "WESTERN", "DIGITAL",
    "AMAZON", "AWS", "FUJITSU", "HITACHI", "KIOXIA", "SK", "HYNIX",
    "SATA", "SAS", "NVME", "PCIE", "DRIVE", "DISK", "SSD", "HDD",
    "SOLID", "STATE", "SERIES", "EXPRESS", "FLASH", "MIXED", "USE",
    "READ", "INTENSIVE", "WRITE", "CLASS", "ENTERPRISE",
}


_MODEL_FAMILY_ALIASES = [
    # Samsung PM1733 / PM1733a (PCIe Gen4 enterprise NVMe)
    (r"MZXLR|MZWLR|MZ3LR", ["PM1733A", "PM1733"]),
    (r"MZWLJ", ["PM1733", "PM9A1"]),
    # Samsung PM9A3 / PM983
    (r"MZQL2|MZQLB|MZ1L2|MZ7L2", ["PM9A3", "PM983"]),
    # Samsung PM1743 / BM1743 (Gen5)
    (r"MZ361|MZ363|MZ3WM|MZWMO|MZ3MO", ["PM1743", "BM1743"]),
    # Samsung PM1753 (Gen5)
    (r"MZWL6|MZ3L6", ["PM1753"]),
    # Kioxia CM6 / CM7 / CM9
    (r"KCM6|KCMY|KCM7|KCM9", ["CM6", "CM7", "CM9"]),
    # Kioxia CD6 / CD8 / CD9
    (r"KCD6|KCD8|KCD9", ["CD6", "CD8", "CD9"]),
    # Micron 6500 ION / 7450 / 7400 / 6600
    (r"MTFDKCC|MTFDKBN", ["6500"]),
    (r"MTFDKCB|MTFDKAK", ["7450", "7400"]),
    (r"MTFDL", ["6600"]),
    # Solidigm / Intel P5430 / P5520 / P5620
    (r"SBFPF", ["P5430"]),
    (r"SSDPF", ["P5520", "P5620"]),
]


def _detect_vendor_hint(model_name: str) -> str:
    m = str(model_name or "").upper()
    if "-000H" in m or "HPE" in m or "HEWLETT" in m or "-00000" in m or "-000AU" in m:
        return "HPE"
    if "/0" in m or "DELL" in m:
        return "DELL"
    if "THINKSYSTEM" in m or "LENOVO" in m:
        return "LENOVO"
    if "CISCO" in m or "UCS" in m:
        return "CISCO"
    return ""


def _clean_drive_model(model_name: str) -> str:
    """Strip common OEM part suffixes (e.g. -000H3, -000H1, -000AU, /092P6) from model string."""
    m = str(model_name or "").strip().upper()
    m = re.sub(r'-(?:000|00)[A-Z0-9]{1,4}$', '', m)
    m = re.sub(r'/(?:000|00)?[A-Z0-9]{4,6}$', '', m)
    return m


def _get_capacity_tokens(capacity_gb: float) -> list:
    """Return capacity search tokens (e.g., ['15.36', '15.3', '15.36TB']) for a given GB capacity."""
    if not capacity_gb or capacity_gb <= 0:
        return []
    if 13000 <= capacity_gb <= 17000:
        return ["15.36", "15.3", "15.36TB", "15.3TB"]
    elif 6800 <= capacity_gb <= 8500:
        return ["7.68", "7.68TB", "7.68 TB", "7.68G"]
    elif 3200 <= capacity_gb <= 4400:
        return ["3.84", "3.2", "3.84TB", "3.2TB"]
    elif 1400 <= capacity_gb <= 2200:
        return ["1.92", "1.6", "1.92TB", "1.6TB"]
    elif 27000 <= capacity_gb <= 34000:
        return ["30.72", "30.7", "30.72TB"]
    return []


_CROSS_REF_DEVICE_CACHE = {}
_CROSS_REF_DRIVE_CACHE = {}
_EVAL_DRIVE_CACHE = {}
_MAX_CACHE_SIZE = 2048


def cross_reference_device(
    model_name: str,
    json_hcl: Optional[dict] = None,
    csv_db: Optional[dict] = None,
    vid: str = "",
    did: str = "",
    svid: str = "",
    ssid: str = "",
    capacity_gb: float = 0.0,
) -> Optional[str]:
    cache_key = (
        model_name,
        vid,
        did,
        svid,
        ssid,
        capacity_gb,
        id(json_hcl) if json_hcl else 0,
        id(csv_db) if csv_db else 0,
    )
    if cache_key in _CROSS_REF_DEVICE_CACHE:
        return _CROSS_REF_DEVICE_CACHE[cache_key]

    v = normalize_pci_id(vid)
    d = normalize_pci_id(did)
    sv = normalize_pci_id(svid)
    ss = normalize_pci_id(ssid)

    quad = f"{v}:{d}:{sv}:{ss}" if (v and d and sv and ss) else ""
    pair = f"{v}:{d}" if (v and d) else ""

    res_val = None
    if json_hcl:
        quads = (json_hcl.get("quads") or json_hcl.get("_pci_quads", {})) if isinstance(json_hcl, dict) else {}
        pairs = (json_hcl.get("pairs") or json_hcl.get("_pci_pairs", {})) if isinstance(json_hcl, dict) else {}

        if quad and quad in quads:
            res = quads[quad]
            tier = res.get("tier", res) if isinstance(res, dict) else res
            res_val = f"JSON HCL (Exact PCI Quad {quad}): {tier}"
        elif quad and quad in json_hcl:
            res = json_hcl[quad]
            tier = res.get("tier", res) if isinstance(res, dict) else res
            res_val = f"JSON HCL (Exact PCI Quad {quad}): {tier}"
        elif pair and pair in pairs:
            res_list = pairs[pair]
            first_res = res_list[0] if isinstance(res_list, list) and res_list else res_list
            tier = first_res.get("tier", first_res) if isinstance(first_res, dict) else first_res
            res_val = f"JSON HCL (PCI Chipset {pair}): {tier}"
        elif pair and pair in json_hcl:
            res = json_hcl[pair]
            tier = res.get("tier", res) if isinstance(res, dict) else res
            res_val = f"JSON HCL (PCI Chipset {pair}): {tier}"

    if res_val is None:
        res_val = cross_reference_drive(model_name, json_hcl, csv_db, capacity_gb=capacity_gb)

    if len(_CROSS_REF_DEVICE_CACHE) > _MAX_CACHE_SIZE:
        _CROSS_REF_DEVICE_CACHE.clear()
    _CROSS_REF_DEVICE_CACHE[cache_key] = res_val
    return res_val


def lookup_unique_hcl_device(
    vid: str = "",
    did: str = "",
    svid: str = "",
    ssid: str = "",
    json_hcl: Optional[dict] = None,
    model_name: str = "",
) -> Optional[dict]:
    """Returns the single matching HCL device dict if the PCI quad/pair or model
    lookup uniquely identifies one item in json_hcl. Returns None if zero or multiple
    items match.
    """
    if not json_hcl or not isinstance(json_hcl, dict):
        return None

    v = normalize_pci_id(vid)
    d = normalize_pci_id(did)
    sv = normalize_pci_id(svid)
    ss = normalize_pci_id(ssid)

    quad = f"{v}:{d}:{sv}:{ss}" if (v and d and sv and ss) else ""
    pair = f"{v}:{d}" if (v and d) else ""

    quads = json_hcl.get("quads") or json_hcl.get("_pci_quads", {})
    pairs = json_hcl.get("pairs") or json_hcl.get("_pci_pairs", {})

    if quad and quad in quads:
        res = quads[quad]
        if isinstance(res, dict):
            return res
    elif quad and quad in json_hcl:
        res = json_hcl[quad]
        if isinstance(res, dict):
            return res

    if pair and pair in pairs:
        res_list = pairs[pair]
        if isinstance(res_list, list):
            if len(res_list) == 1 and isinstance(res_list[0], dict):
                return res_list[0]
            elif len(res_list) > 1:
                best = select_best_pci_pair_entry(res_list, model_name=model_name, svid=sv, ssid=ss)
                if best:
                    return best
        elif isinstance(res_list, dict):
            return res_list
    elif pair and pair in json_hcl:
        res = json_hcl[pair]
        if isinstance(res, list):
            if len(res) == 1 and isinstance(res[0], dict):
                return res[0]
            elif len(res) > 1:
                best = select_best_pci_pair_entry(res, model_name=model_name, svid=sv, ssid=ss)
                if best:
                    return best
        elif isinstance(res, dict):
            return res

    if model_name and model_name != "Unknown":
        models = json_hcl.get("models", {}) if isinstance(json_hcl.get("models"), dict) else {}
        key = str(model_name).strip().upper()
        cleaned_key = _clean_drive_model(key)
        for k in (key, cleaned_key):
            if k in models and isinstance(models[k], dict):
                return models[k]

    return None


def cross_reference_drive(
    model_name: str,
    json_hcl: Optional[dict] = None,
    csv_db: Optional[dict] = None,
    capacity_gb: float = 0.0,
) -> Optional[str]:
    if not model_name or model_name == "Unknown":
        return None

    cache_key = (
        model_name,
        capacity_gb,
        id(json_hcl) if json_hcl else 0,
        id(csv_db) if csv_db else 0,
    )
    if cache_key in _CROSS_REF_DRIVE_CACHE:
        return _CROSS_REF_DRIVE_CACHE[cache_key]

    key = str(model_name).strip().upper()
    cleaned_key = _clean_drive_model(key)

    # 1. Exact and Cleaned Key Lookups
    if json_hcl and isinstance(json_hcl, dict):
        models = json_hcl.get("models", {}) if isinstance(json_hcl.get("models"), dict) else {}
        for k in (key, cleaned_key):
            if k in models:
                res = models[k]
                tier = res.get("tier", res) if isinstance(res, dict) else res
                return f"JSON HCL: {tier}"
            if k in json_hcl and not str(k).startswith("_") and k not in ("quads", "pairs", "models", "csv_drives", "_pci_quads", "_pci_pairs"):
                res = json_hcl[k]
                tier = res.get("tier", res) if isinstance(res, dict) else res
                return f"JSON HCL: {tier}"

    if csv_db and isinstance(csv_db, dict):
        for k in (key, cleaned_key):
            if k in csv_db:
                tiers = csv_db[k]
                if isinstance(tiers, (list, tuple, set)):
                    return f"CSV HCL: {', '.join(str(t) for t in tiers)}"
                return f"CSV HCL: {tiers}"

    # 2. Tokenized and Capacity-Aware Fuzzy Search
    search_keys = [cleaned_key]
    if key != cleaned_key:
        search_keys.insert(0, key)

    alias_tokens = []
    for pat, aliases in _MODEL_FAMILY_ALIASES:
        if re.search(pat, cleaned_key):
            for alias in aliases:
                if alias not in search_keys and alias not in alias_tokens:
                    alias_tokens.append(alias)

    cap_tokens = _get_capacity_tokens(capacity_gb)
    vendor_hint = _detect_vendor_hint(key)

    def _score_candidate(cm_up: str, tiers_list: list) -> int:
        score = 0
        matched_key = False
        matched_by_short_or_alias = False

        # Direct substring match using long keys (len >= 5)
        for sk in search_keys:
            if len(sk) >= 5 and sk in cm_up:
                matched_key = True
                score += 18 if len(sk) >= 8 else 15
                break

        # Token match (tokens len >= 5 and non-generic)
        if not matched_key:
            for sk in search_keys:
                tokens = [t for t in sk.split() if len(t) >= 5 and t not in _GENERIC_DRIVE_TOKENS]
                if tokens and any(t in cm_up for t in tokens):
                    matched_key = True
                    score += 10
                    break

        # Model family alias match (e.g. CD6, CM6, PM1733)
        if not matched_key and alias_tokens:
            if any(alias in cm_up for alias in alias_tokens):
                matched_key = True
                matched_by_short_or_alias = True
                score += 5

        if not matched_key:
            return -1

        # Capacity alignment logic
        has_cap_match = bool(cap_tokens and any(ct in cm_up for ct in cap_tokens))
        if cap_tokens:
            if has_cap_match:
                score += 20
            elif matched_by_short_or_alias:
                # Reject alias-only match if capacity is specified but doesn't align
                return -1

        if vendor_hint and vendor_hint in cm_up:
            score += 15

        if any("ESA" in str(t).upper() for t in tiers_list):
            score += 5

        return score

    best_match = None
    best_match_score = -1

    if json_hcl and isinstance(json_hcl, dict):
        json_models = json_hcl.get("models", {}) if isinstance(json_hcl.get("models"), dict) else {}
        for cm, res in json_models.items():
            tier = res.get("tier", res) if isinstance(res, dict) else res
            tier_str = str(tier)
            sc = _score_candidate(str(cm).upper(), [tier_str])
            if sc >= 15 and sc > best_match_score:
                best_match_score = sc
                best_match = f"JSON HCL Match: {tier_str}"

    if csv_db and isinstance(csv_db, dict):
        for cm, tiers in csv_db.items():
            tiers_list = list(tiers) if isinstance(tiers, (list, tuple, set)) else [str(tiers)]
            sc = _score_candidate(str(cm).upper(), tiers_list)
            if sc >= 15 and sc > best_match_score:
                best_match_score = sc
                best_match = f"CSV HCL Match: {', '.join(str(t) for t in tiers_list)}"

    res_match = best_match if (best_match and best_match_score >= 15) else None
    if len(_CROSS_REF_DRIVE_CACHE) > _MAX_CACHE_SIZE:
        _CROSS_REF_DRIVE_CACHE.clear()
    _CROSS_REF_DRIVE_CACHE[cache_key] = res_match
    return res_match


def detect_qlc_nvme(model: str) -> bool:
    """Return True if the NVMe drive model matches a known QLC NAND family.

    Detection has two tiers:
      1. Literal "QLC" anywhere in the model string (some vendors stamp this).
      2. startswith check against QLC_NVME_PREFIXES — every prefix verified
         against vendor datasheets across all capacity and form-factor SKUs.
    """
    m = str(model or "").strip().upper()
    if "QLC" in m:
        return True
    return any(m.startswith(p.upper()) for p in QLC_NVME_PREFIXES)


def evaluate_drive_hcl_tier(
    drive: dict,
    json_hcl: Optional[dict] = None,
    csv_db: Optional[dict] = None,
) -> dict:
    """Evaluate drive against vSAN HCL data to determine category, status badge, and HCL string.

    Distinguishes vSAN ESA Certified NVMe drives from OSA-Only NVMe drives (e.g., drives certified
    only for All Flash Caching/Capacity Tier) and Unverified NVMe drives.
    """
    if not isinstance(drive, dict):
        return {
            "category": "Unknown",
            "status_badge": "<span class='badge warning'>⚠️ Unknown</span>",
            "hcl_str": "",
            "vsan_eligible": False,
            "hcl_matched_info": None,
        }

    cache_key = (
        drive.get("model"),
        drive.get("protocol"),
        drive.get("category"),
        drive.get("status_badge"),
        drive.get("vendor_id"),
        drive.get("device_id"),
        drive.get("subsystem_vendor_id"),
        drive.get("subsystem_id"),
        drive.get("capacity_gb"),
        drive.get("is_qlc"),
        drive.get("single_lane_alert"),
        drive.get("behind_software_raid"),
        id(json_hcl) if json_hcl else 0,
        id(csv_db) if csv_db else 0,
    )
    if cache_key in _EVAL_DRIVE_CACHE:
        return _EVAL_DRIVE_CACHE[cache_key]

    model = drive.get("model", "")
    proto = str(drive.get("protocol", "")).upper()
    is_nvme = "NVME" in proto or "PCIE" in proto or drive.get("is_edsff") or drive.get("is_nvme")
    cat_orig = str(drive.get("category", ""))
    badge_orig = str(drive.get("status_badge", ""))
    is_boot = cat_orig == "Boot Device" or "Boot Device" in badge_orig
    behind_trimode = drive.get("behind_trimode", False) or "Behind Tri-Mode" in badge_orig
    is_raid_ctrl = cat_orig in ("Unsupported NVMe RAID", "Unsupported NVMe Tri-Mode") or "Behind RAID" in badge_orig

    # Don't override special non-vSAN categories (Boot Device, Tri-mode RAID, Optane, Magnetic HDD)
    if is_boot or behind_trimode or is_raid_ctrl or cat_orig in ("Optane Memory Tiering", "Magnetic HDD"):
        return {
            "category": cat_orig,
            "status_badge": badge_orig,
            "hcl_str": "",
            "vsan_eligible": drive.get("vsan_eligible", False),
            "hcl_matched_info": None,
        }

    vid = drive.get("vendor_id", "")
    did = drive.get("device_id", "")
    svid = drive.get("subsystem_vendor_id", "")
    ssid = drive.get("subsystem_id", "")

    m_info = cross_reference_device(
        model, json_hcl, csv_db,
        vid=vid, did=did, svid=svid, ssid=ssid,
        capacity_gb=drive.get("capacity_gb", 0),
    )

    if m_info:
        m_info_low = m_info.lower()
        has_cyber = "cyber" in m_info_low
        has_esa = "esa" in m_info_low

        # Physical / policy overrides:
        # 1) Non-NVMe drives (SATA / SAS) can NEVER be vSAN ESA or Cyber Recovery
        if not is_nvme:
            has_esa = False
            has_cyber = False

        # 2) vSAN ESA Storage Tier requires direct-attached NVMe >= 1.6TB (1600 GB / ~1400 GiB)
        cap_gb = drive.get("capacity_gb", 0) or 0
        if is_nvme and has_esa and not has_cyber and cap_gb > 0 and cap_gb < 1400:
            has_esa = False

        # 1. Cyber Recovery Certified
        if has_cyber and is_nvme:
            badge = (
                "<span class='badge cyber-recovery'>🔷 ESA Cyber Recovery</span>"
                "<br><small style='color:#7c3aed;font-size:.77rem'>vSAN Cyber Recovery — QLC NVMe Certified</small>"
            )
            cat = "vSAN ESA/OSA NVMe"
            hcl_html = f"<br><small style='color:#7c3aed;font-weight:600'>{m_info}</small>"
            vsan_ok = True
        # 2. vSAN ESA Certified (Storage Tier, NVMe Tier, or explicit ESA)
        elif has_esa and is_nvme:
            badge = "<span class='badge success'>🟢 ESA Compatible</span>"
            cat = "vSAN ESA/OSA NVMe"
            hcl_html = f"<br><small style='color:var(--success);font-weight:600;'>{m_info}</small>"
            vsan_ok = True
        # 3. OSA-Only Certified (All Flash Caching, All Flash Capacity, Hybrid Caching/Capacity)
        elif any(k in m_info_low for k in ["all flash", "caching", "capacity", "hybrid", "osa"]) or ("esa" in m_info_low and (not is_nvme or cap_gb < 1400)):
            if is_nvme and cap_gb < 1400 and "esa" in m_info_low:
                badge = "<span class='badge warning'>🟡 vSAN OSA Only (< 1.6TB NVMe — ESA requires ≥1.6TB)</span>"
            else:
                badge = "<span class='badge warning'>🟡 vSAN OSA Only (Not ESA Certified)</span>" if is_nvme else "<span class='badge warning'>🟡 vSAN OSA Only</span>"
            cat = "vSAN OSA Only"
            hcl_html = f"<br><small style='color:var(--warning-text, #ca8a04);font-weight:600;'>{m_info}</small>"
            vsan_ok = True
        # 4. NVMe Certified on HCL (General / Certified status)
        elif is_nvme and ("esa" in m_info_low or "certified" in m_info_low) and not any(k in m_info_low for k in ["unverified", "unsupported"]):
            if cap_gb > 0 and cap_gb < 1400:
                badge = "<span class='badge warning'>🟡 vSAN OSA Only (< 1.6TB NVMe — ESA requires ≥1.6TB)</span>"
                cat = "vSAN OSA Only"
            else:
                badge = "<span class='badge success'>🟢 ESA Compatible</span>"
                cat = "vSAN ESA/OSA NVMe"
            hcl_html = f"<br><small style='color:var(--success);font-weight:600;'>{m_info}</small>"
            vsan_ok = True
        else:
            if is_nvme:
                if cap_gb > 0 and cap_gb < 1400 and "esa" in m_info_low:
                    badge = "<span class='badge warning'>🟡 vSAN OSA Only (< 1.6TB NVMe — ESA requires ≥1.6TB)</span>"
                else:
                    badge = "<span class='badge warning'>🟡 vSAN OSA Only (Not ESA Certified)</span>"
            else:
                badge = "<span class='badge warning'>🟡 vSAN OSA Only</span>"
            cat = "vSAN OSA Only"
            hcl_html = f"<br><small style='color:var(--warning-text, #ca8a04);font-weight:600;'>{m_info}</small>"
            vsan_ok = True
    else:
        # Not on HCL
        hcl_html = ""
        if is_nvme:
            _is_qlc = drive.get("is_qlc", False) or detect_qlc_nvme(model)
            _cap_gb = drive.get("capacity_gb", 0)
            if _is_qlc:
                badge = (
                    "<span class='badge cyber-recovery' style='margin-top:4px;font-size:.77rem'>🔮 QLC NVMe — Not vSAN Certified</span>"
                    "<br><small style='font-size:.75rem;color:#6d28d9;margin-top:2px'>For qualification info: "
                    "<a href='mailto:vsan-hcl.pdl@broadcom.com' style='color:#7c3aed'>vsan-hcl.pdl@broadcom.com</a></small>"
                )
            elif _cap_gb > 4096:
                badge = (
                    "<span class='badge cyber-recovery' style='margin-top:4px;font-size:.77rem'>🔮 Large NVMe (>4TB) — Not vSAN Certified</span>"
                    "<br><small style='font-size:.75rem;color:#6d28d9;margin-top:2px'>For qualification info: "
                    "<a href='mailto:vsan-hcl.pdl@broadcom.com' style='color:#7c3aed'>vsan-hcl.pdl@broadcom.com</a></small>"
                )
            else:
                badge = "<span class='badge warning'>⚠️ Unverified (Not on vSAN HCL)</span>"
            cat = "Unverified NVMe"
            vsan_ok = False
        elif "SAS" in proto or "SATA" in proto:
            badge = "<span class='badge warning'>🟡 vSAN OSA Only</span>"
            cat = "vSAN OSA Only"
            vsan_ok = True
        else:
            badge = "<span class='badge warning'>⚠️ Unknown / Unverified</span>"
            cat = "Unknown"
            vsan_ok = False

    if drive.get("single_lane_alert"):
        badge += (
            "<br><span class='badge danger' style='margin-top:4px;font-size:.78rem'>"
            "⚠️ Single PCIe Lane (x1) — severe performance limitation</span>"
        )
    if drive.get("behind_software_raid"):
        badge += (
            "<br><span class='badge warning' style='margin-top:4px;font-size:.78rem'>"
            "⚠️ Software RAID Detected — Bypass in BIOS for native vSAN ESA pass-through</span>"
        )

    return {
        "category": cat,
        "status_badge": badge,
        "hcl_str": hcl_html,
        "vsan_eligible": vsan_ok,
        "hcl_matched_info": m_info,
    }


