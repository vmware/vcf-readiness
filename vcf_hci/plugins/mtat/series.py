"""Aggregate raw samples after applying their declared encoding."""

from __future__ import annotations

from decimal import Decimal
from typing import Optional

from vcf_hci.plugins.mtat.models import SampleSeries
from vcf_hci.plugins.mtat.numbers import quantize


def _values(series: SampleSeries) -> tuple[Decimal, ...]:
    output = []
    for value in series.values:
        if series.encoding == "kibibytes":
            output.append(Decimal(value) * Decimal(1024) / Decimal(1000000000))
        elif series.encoding == "bytes":
            output.append(Decimal(value) / Decimal(1000000000))
        elif series.encoding == "percent":
            output.append(Decimal(value))
        else:
            output.append(Decimal(value) / Decimal(100))
    return tuple(output)


def average(series: Optional[SampleSeries]) -> Optional[Decimal]:
    if series is None or not series.values:
        return None
    values = _values(series)
    places = 3 if series.encoding in {"kibibytes", "bytes"} else 2
    return quantize(sum(values, Decimal(0)) / Decimal(len(values)), places)


def maximum(series: Optional[SampleSeries]) -> Optional[Decimal]:
    if series is None or not series.values:
        return None
    places = 3 if series.encoding in {"kibibytes", "bytes"} else 2
    return quantize(max(_values(series)), places)
