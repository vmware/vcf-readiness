"""Validation shared by collected and previously saved drive I/O totals."""
import math
from typing import Any, Optional


def nonnegative_io_total(value: Any) -> Optional[float]:
    """Reject unavailable/invalid counters, including rounded negative zero."""
    if value is None or isinstance(value, bool):
        return None
    try:
        total = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(total) or math.copysign(1.0, total) < 0:
        return None
    return total
