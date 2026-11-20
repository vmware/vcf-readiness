"""Half-even decimal rounding compatible with MTAT's Math.Round defaults."""

from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Decimal
from typing import Optional, Union

Number = Union[int, Decimal]
_GB = Decimal(1000000000)


def _decimal(value: Number) -> Decimal:
    return value if isinstance(value, Decimal) else Decimal(value)


def quantize(value: Number, places: int) -> Decimal:
    quantum = Decimal(1).scaleb(-places)
    return _decimal(value).quantize(quantum, rounding=ROUND_HALF_EVEN)


def format_number(value: Optional[Number], places: int) -> str:
    if value is None:
        return ""
    text = format(quantize(value, places), "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text in {"", "-0"} else text


def bytes_to_gb(value: int) -> Decimal:
    return quantize(Decimal(value) / _GB, 3)


def kibibytes_to_gb(value: int) -> Decimal:
    return quantize(Decimal(value) * Decimal(1024) / _GB, 3)


def percent(part: Number, whole: Number, places: int) -> Decimal:
    if _decimal(whole) <= 0:
        return Decimal(0)
    return quantize(_decimal(part) / _decimal(whole) * Decimal(100), places)
