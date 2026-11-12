"""Validate physical-drive capacity consistently across collection and reporting."""
import math
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Union

# A conservative data-quality ceiling for one physical drive, not an array/volume.
# Keep large legitimate drives; reject firmware sentinels and corrupt unit conversions.
MAX_PHYSICAL_DRIVE_CAPACITY_GB = 1_000_000


def normalize_drive_capacity(drive: dict) -> None:
    """Use numeric zero for unknown totals and retain rejected source evidence.

    Zero is the existing internal unknown-capacity sentinel. It must not be
    presented as an observed zero-capacity drive when a quality note is present.
    Repeated normalization preserves the first rejected value and its reason.
    """
    raw = drive.get("capacity_gb")
    if raw is None or raw == "":
        drive["capacity_gb"] = 0
        return
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError):
        value = -1.0
    if isinstance(raw, bool) or not math.isfinite(value) or value < 0 or value > MAX_PHYSICAL_DRIVE_CAPACITY_GB:
        evidence = str(raw) if isinstance(raw, float) and not math.isfinite(raw) else raw
        drive.setdefault("source_reported_capacity_gb", evidence)
        drive["capacity_gb"] = 0
        drive["capacity_data_quality_note"] = (
            "Capacity unknown: invalid or implausible physical-drive capacity excluded "
            "from totals; original retained in source_reported_capacity_gb."
        )
    elif isinstance(raw, str):
        drive["capacity_gb"] = value


def normalize_storage_capacities(storage: Any) -> None:
    """Normalize physical drives in place, tolerating incomplete saved summaries."""
    if not isinstance(storage, list):
        return
    for controller in storage:
        if not isinstance(controller, dict):
            continue
        drives = controller.get("drives")
        if not isinstance(drives, list):
            continue
        for drive in drives:
            if isinstance(drive, dict):
                normalize_drive_capacity(drive)


def drive_capacity_display(drive: dict, include_unit: bool = False) -> Union[int, float, str]:
    """Keep valid export cells numeric; identify rejected capacities as unknown."""
    normalize_drive_capacity(drive)
    if drive.get("capacity_data_quality_note"):
        return "Unknown"
    value = drive.get("capacity_gb", 0)
    return f"{value} GB" if include_unit else value


def gib_to_tib_display(value: Any) -> str:
    """Format a binary GiB capacity as TiB for human-facing drive tables."""
    try:
        gib = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError, OverflowError):
        return "Unknown"
    if not gib.is_finite() or gib <= 0:
        return "Unknown"
    tib = (gib / Decimal(1024)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    return f"{tib} TiB"


def drive_capacity_tib_display(drive: dict) -> str:
    """Display normalized physical-drive capacity in TiB."""
    capacity = drive_capacity_display(drive)
    return gib_to_tib_display(capacity)
