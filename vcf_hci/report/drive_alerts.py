"""Shared reasons for drive aging and wear advisories."""
from typing import Any, Dict, List

from vcf_hci.compat.firmware import check_defective_drive_firmware

AGING_POWER_ON_HOURS = 30000
AGING_ENDURANCE_REMAINING_PCT = 50


def drive_aging_wear_reasons(drive: Dict[str, Any]) -> List[str]:
    """Return substantive age, endurance, or known firmware defect reasons."""
    reasons = []
    power_on_hours = drive.get("power_on_hours")
    if power_on_hours is None:
        power_on_hours = (drive.get("oem_metrics") or {}).get("power_on_hours")
    if isinstance(power_on_hours, (int, float)) and power_on_hours >= AGING_POWER_ON_HOURS:
        reasons.append(f"High power-on hours ({int(power_on_hours):,}h; threshold {AGING_POWER_ON_HOURS:,}h)")

    endurance = drive.get("endurance_remaining_pct")
    if endurance in (255, "255", "255%"):
        endurance = None
    if isinstance(endurance, (int, float)) and 0 <= endurance < AGING_ENDURANCE_REMAINING_PCT:
        reasons.append(f"Low remaining endurance ({endurance:g}%; threshold below {AGING_ENDURANCE_REMAINING_PCT}%)")

    defect = check_defective_drive_firmware(str(drive.get("model") or ""), str(drive.get("firmware") or ""))
    if defect:
        reasons.append(f"Known firmware issue ({defect.get('advisory', 'affected firmware')})")
    return reasons
