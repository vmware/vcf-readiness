"""
BIOS and Boot mode compatibility evaluation for VCF 9.1.
"""
import datetime
import re
from typing import Optional

from ..bios.advisories import evaluate_bios_advisories
from ..constants import _CVE_TIERS, BIOS_BASELINES
from ..logging_utils import parse_version_tuple
from .firmware_currency import _cmp, classify_currency, currency_badge, match_baseline, parse_version


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
    """Return a historical BIOS-date estimate, never microcode assurance."""
    if not isinstance(bios_date, str) or not bios_date.strip():
        return (-1, "Not Assessed", "info", "BIOS release date unavailable; mitigation state is not verified.")
    value = bios_date.strip()
    m_iso = re.fullmatch(r"(\d{4}-\d{2}-\d{2})(?:T[^\s]+)?", value)
    m_mdy = re.fullmatch(r"(\d{1,2})/(\d{1,2})/(\d{4})", value)
    try:
        if m_iso:
            parsed = datetime.date.fromisoformat(m_iso.group(1))
        elif m_mdy:
            parsed = datetime.date(int(m_mdy.group(3)), int(m_mdy.group(1)), int(m_mdy.group(2)))
        else:
            return (-1, "Not Assessed", "info", "BIOS date missing or unrecognized; mitigation state is not verified.")
    except ValueError:
        return (-1, "Not Assessed", "info", "Invalid BIOS release date; mitigation state is not verified.")
    if parsed > datetime.datetime.now(datetime.timezone.utc).date():
        return (-1, "Not Assessed", "info", "BIOS release date is in the future; mitigation state is not verified.")
    normalised = parsed.isoformat()

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


def bios_date_estimate_fields(release_date: str) -> dict:
    """Refresh legacy cve_* fields from date evidence, including offline renders."""
    tier, label, badge, description = _cve_tier_from_date(release_date)
    return {
        "cve_tier": tier, "cve_tier_label": label, "cve_tier_badge": badge,
        "cve_tier_desc": description, "cve_assessment_basis": "bios_release_date_estimate",
        "cve_mitigations_verified": False,
    }


def evaluate_bios_version(model_name: str, installed_version: str, release_date: str = "N/A", system_info: Optional[dict] = None) -> dict:
    model_key = str(model_name or "").upper().strip()
    installed_str = str(installed_version or "N/A")
    baseline_key, baseline = match_baseline(BIOS_BASELINES, model_key)
    cve_fields = {**bios_date_estimate_fields(release_date), "baseline_key": baseline_key,
                  "firmware_advisories": evaluate_bios_advisories({**(system_info or {}), "bios_release_date": release_date}),
                  "security_floor_version": baseline.get("min_spectre") if baseline else None}
    if not baseline:
        return {
            "badge": f"<span class='badge info'>ℹ️ v{installed_str} ({release_date})</span>",
            "spectre_status": "unverified",
            "spectre_badge": "<span class='badge info'>ℹ️ No Baseline</span>",
            "currency": "unverified",
            "age_note": "",
            "latest_version": "N/A",
            **cve_fields,
        }
    verdict = classify_currency(installed_str, baseline, installed_date=release_date)
    badge = currency_badge(installed_str, verdict, bios=True)
    spectre_status, spectre_badge = _spectre_badge(installed_str, baseline)
    return {
        "badge": badge,
        "latest_version": verdict["latest_version"],
        "currency": verdict["currency"],
        "age_note": verdict["age_note"],
        "update_recommended": verdict["update_recommended"],
        "is_outdated": verdict["is_outdated"],
        "spectre_status": spectre_status,
        "spectre_badge": spectre_badge,
        **cve_fields,
    }


def _spectre_badge(installed_str: str, baseline: dict) -> tuple:
    """Security floor. Family changes do not invent a pre-Spectre failure."""
    inst_clean = str(installed_str or "").strip().upper()
    floor = str(baseline.get("min_spectre") or "0").strip()
    floor_clean = floor.upper()

    if inst_clean and inst_clean == floor_clean and inst_clean not in ("0", "NONE", "UNKNOWN", "N/A"):
        return (
            "ok",
            (
                f"<span class='badge success'>\U0001f6e1️ Recorded BIOS Security Floor Met "
                f"(≥ v{floor})</span>"
            ),
        )

    _inst_fam, inst_nums, _inst_kind = parse_version(installed_str)
    _sp_fam, sp_nums, _sp_kind = parse_version(floor)
    if not inst_nums or not sp_nums:
        inst = parse_version_tuple(installed_str)
        sp = parse_version_tuple(floor)
        if inst == (0, 0, 0, 0) or sp == (0, 0, 0, 0):
            return ("unverified", "<span class='badge info'>Recorded BIOS Security Floor: Not Assessed</span>")
        covered = inst >= sp
    else:
        covered = _cmp(inst_nums, sp_nums) >= 0
    if covered:
        return (
            "ok",
            (
                f"<span class='badge success'>\U0001f6e1️ Recorded BIOS Security Floor Met "
                f"(≥ v{floor})</span>"
            ),
        )
    return (
        "exposed",
        (
            f"<span class='badge danger'>⚠️ Below Recorded BIOS Security Floor: v{installed_str} "
            f"— min required v{floor}</span>"
        ),
    )
