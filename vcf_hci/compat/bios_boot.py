"""
BIOS and Boot mode compatibility evaluation for VCF 9.1.
"""
import re

from ..constants import _CVE_TIERS, BIOS_BASELINES
from ..logging_utils import parse_version_tuple


def evaluate_boot_mode(boot_mode: str) -> dict:
    bm_raw = str(boot_mode or "").strip()
    if not bm_raw or bm_raw.upper() in ("UNKNOWN", "N/A", "NONE"):
        return {
            "verdict": "Unknown",
            "badge": "<span class='badge warning'>\U0001f7e1 Boot Mode Unknown</span>",
            "is_compatible": False,
        }
    bm = bm_raw.upper()
    if "UEFI" in bm:
        return {
            "verdict": "UEFI",
            "badge": "<span class='badge success'>\U0001f7e2 UEFI Boot</span>",
            "is_compatible": True,
        }
    elif any(k in bm for k in ("LEGACY", "BIOS")):
        return {
            "verdict": "Legacy",
            "badge": "<span class='badge danger'>\U0001f534 Legacy CSM (Unsupported — VCF 9.1 Mandates Pure UEFI)</span>",
            "is_compatible": False,
        }
    else:
        return {
            "verdict": bm_raw,
            "badge": f"<span class='badge info'>ℹ️ {bm_raw}</span>",
            "is_compatible": True,
        }


def _cve_tier_from_date(bios_date: str) -> tuple:
    """Map a BIOS release date string to a CVE coverage tier.

    Returns (tier_int, tier_label, badge_class, description).
    Falls back to tier 0 when the date cannot be parsed or predates all thresholds.
    Only fires when bios_date is a recognisable ISO-like date string.
    For OEMs that don't expose a release date (Lenovo, Supermicro, Cisco), callers
    should rely on the version-based spectre_status badge instead.
    """
    if not bios_date or bios_date in ("N/A", "Unknown", ""):
        return (-1, "N/A", "info", "BIOS release date not available — version-based assessment only.")
    # Normalise common OEM date formats → YYYY-MM-DD
    # Dell:  "2024-03-15T00:00:00+00:00" or "2024-03-15"
    # HPE:   "03/15/2024" or "15 Mar 2024"
    normalised = bios_date.strip()
    m_iso = re.match(r"(\d{4}-\d{2}-\d{2})", normalised)
    m_mdy = re.match(r"(\d{1,2})/(\d{1,2})/(\d{4})", normalised)
    if m_iso:
        normalised = m_iso.group(1)
    elif m_mdy:
        normalised = f"{m_mdy.group(3)}-{m_mdy.group(1).zfill(2)}-{m_mdy.group(2).zfill(2)}"
    else:
        return (-1, "N/A", "info", "BIOS release date format unrecognised.")

    tier_result = _CVE_TIERS[0][1:4] + (_CVE_TIERS[0][4],)  # default to tier 0 data
    for cutoff, tier_int, label, badge_cls, desc in _CVE_TIERS:
        if cutoff is None or normalised < cutoff:
            tier_result = (tier_int, label, badge_cls, desc)
            break
    else:
        # All explicit cutoffs passed — bios_date is beyond the final tier boundary
        _last = _CVE_TIERS[-1]
        tier_result = (_last[1], _last[2], _last[3], _last[4])
    return tier_result


def evaluate_bios_version(model_name: str, installed_version: str, release_date: str = "N/A") -> dict:
    model_key = str(model_name or "").upper().strip()
    installed_str = str(installed_version or "N/A")
    baseline = next((v for k, v in BIOS_BASELINES.items() if k in model_key), None)
    cve_tier_int, cve_tier_label, _cve_badge, cve_tier_desc = _cve_tier_from_date(release_date)
    if not baseline:
        return {
            "badge": f"<span class='badge info'>ℹ️ v{installed_str} ({release_date})</span>",
            "spectre_status": "unverified",
            "spectre_badge": "<span class='badge info'>ℹ️ No Baseline</span>",
            "cve_tier": cve_tier_int,
            "cve_tier_label": cve_tier_label,
            "cve_tier_badge": _cve_badge,
            "cve_tier_desc": cve_tier_desc,
        }
    inst = parse_version_tuple(installed_str)
    latest = parse_version_tuple(baseline["latest"])
    min_rec = parse_version_tuple(baseline["min_recommended"])
    min_sp = parse_version_tuple(baseline.get("min_spectre", "0"))
    if inst >= latest:
        badge = f"<span class='badge success'>\U0001f7e2 Up-to-Date (v{installed_str})</span>"
    elif inst >= min_rec:
        badge = f"<span class='badge warning'>\U0001f7e1 Update Available (v{installed_str} | Latest: v{baseline['latest']})</span>"
    else:
        badge = f"<span class='badge danger'>\U0001f534 Outdated BIOS (v{installed_str} | Latest: v{baseline['latest']})</span>"
    # Spectre/microcode assessment
    if inst >= min_sp:
        spectre_status = "ok"
        spectre_badge = (
            f"<span class='badge success'>\U0001f6e1️ Spectre Microcode: OK "
            f"(≥ v{baseline['min_spectre']})</span>"
        )
    else:
        spectre_status = "exposed"
        spectre_badge = (
            f"<span class='badge danger'>⚠️ Pre-Spectre BIOS: v{installed_str} "
            f"— min required v{baseline['min_spectre']}</span>"
        )
    return {
        "badge": badge,
        "latest_version": baseline["latest"],
        "spectre_status": spectre_status,
        "spectre_badge": spectre_badge,
        "cve_tier": cve_tier_int,
        "cve_tier_label": cve_tier_label,
        "cve_tier_badge": _cve_badge,
        "cve_tier_desc": cve_tier_desc,
    }
