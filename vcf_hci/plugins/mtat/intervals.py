"""Historical interval selection and QueryPerf batch widths."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HistoricalInterval:
    key: str
    seconds: int
    retention_seconds: int
    level: int
    enabled: bool


def select_interval(intervals: tuple[HistoricalInterval, ...], key: str) -> HistoricalInterval:
    matches = [item for item in intervals if item.key == key]
    if len(matches) != 1:
        raise ValueError("historical interval was not found")
    interval = matches[0]
    if not interval.enabled or interval.level < 2 or interval.seconds <= 0:
        raise ValueError("historical interval is below Level 2 or disabled")
    return interval


def validate_window(interval: HistoricalInterval, begin: int, end: int) -> None:
    if end < begin:
        raise ValueError("end precedes begin")
    if end - begin > interval.retention_seconds:
        raise ValueError("requested range exceeds retention")
    if begin % interval.seconds or end % interval.seconds:
        raise ValueError("range is not aligned to the sampling period")


def entity_batches(entity_count: int, counter_count: int, max_query_metrics: int) -> tuple[tuple[int, int], ...]:
    if entity_count < 0 or counter_count <= 0 or max_query_metrics <= 0:
        raise ValueError("invalid batch dimensions")
    width = max(1, max_query_metrics // counter_count)
    return tuple((start, min(start + width, entity_count)) for start in range(0, entity_count, width))
