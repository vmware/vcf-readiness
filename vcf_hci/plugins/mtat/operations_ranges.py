"""Keep overlapping Operations histories as separate ranges."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class TimedHost:
    source: int
    cluster: str
    host: str
    first_ms: Optional[int]
    last_ms: Optional[int]


def _date(value: int) -> str:
    return datetime.fromtimestamp(value / 1000, timezone.utc).strftime("%Y-%m-%d")


def partition_ranges(base: str, rows: tuple[TimedHost, ...]) -> tuple[str, ...]:
    known: dict[str, set[str]] = {}
    normalized = []
    for row in rows:
        cluster = row.cluster
        if cluster != "(no cluster)":
            known.setdefault(row.host, set()).add(cluster)
        normalized.append(row)
    adjusted = []
    for row in normalized:
        names = sorted(known.get(row.host, ()))
        cluster = names[0] if row.cluster == "(no cluster)" and len(names) == 1 else row.cluster
        adjusted.append(TimedHost(row.source, cluster, row.host, row.first_ms, row.last_ms))
    timed = [row for row in adjusted if row.first_ms is not None and row.last_ms is not None]
    overlap = False
    for left in timed:
        for right in timed:
            if left.source != right.source and left.cluster == right.cluster and left.host == right.host:
                if left.first_ms <= right.last_ms and right.first_ms <= left.last_ms:
                    overlap = True
    if not overlap:
        return (base,)
    labels = []
    sources = sorted({row.source for row in timed})
    for source in sources:
        group = [row for row in timed if row.source == source]
        labels.append("%s - Export %s (%s to %s)" % (base, source + 1, _date(min(row.first_ms for row in group)), _date(max(row.last_ms for row in group))))
    timed_ids = {(row.cluster, row.host) for row in timed}
    if any(row.first_ms is None and (row.cluster, row.host) not in timed_ids for row in adjusted):
        labels.append("%s - Supplemental snapshot" % base)
    return tuple(labels)
