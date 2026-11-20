"""MTAT 3.2 Operations workbook header aliases."""

from __future__ import annotations

import re

COLUMNS = {
    "host": ("hostname", "host", "name", "resource name", "object name"),
    "cluster": ("cluster", "cluster name", "parent cluster", "summary|parentcluster", "summary|parent cluster"),
    "ts": ("timestamp", "time", "date time", "datetime"),
    "alloc": ("mem|memory_allocated_on_all_powered_on_vms", "memory allocated on all powered on consumers", "memory allocated on all powered on vms"),
    "active": ("mem|active_average", "guest active", "active memory"),
    "consumed": ("mem|consumed_average", "consumed", "consumed memory"),
    "cap": ("mem|totalcapacity_average", "capacity available to vms"),
    "prov": ("mem|host_provisioned", "total capacity", "host provisioned", "provisioned memory"),
    "cpu": ("cpu|utilization_average", "cpu|usage_average", "cpu|capacity_usagepct_average", "cpu|utilization", "cpu|usage", "cpu utilization", "cpu usage", "cpu_pct"),
    "core": ("cpu|coreutilization_average", "cpu|core utilization", "cpu core utilization"),
    "mhz": ("cpu|capacity_provisioned", "cpu|totalcapacity_average", "cpu|total capacity", "cpu_mhz"),
}
_NAME = re.compile(r"\s*\((?:bytes?|[kmgt]i?b|b|%|mhz)\)\s*$", re.IGNORECASE)
_UNIT = re.compile(r"\((bytes?|[kmgt]i?b|b)\)\s*$", re.IGNORECASE)


def header_name(label: str) -> str:
    text = str(label).replace("\ufeff", "").strip().lower()
    text = re.sub(r"^memory\s*\|\s*", "", text)
    text = _NAME.sub("", text)
    text = re.sub(r"\s*\|\s*", "|", text)
    return re.sub(r"\s+", " ", text).strip()


def header_unit(label: str) -> str:
    match = _UNIT.search(str(label).strip())
    return match.group(1).upper() if match else ""


def map_headers(headers: tuple[str, ...]) -> dict[str, str]:
    by_name = {header_name(header): header for header in headers}
    mapped: dict[str, str] = {}
    units: dict[str, str] = {}
    for key, aliases in COLUMNS.items():
        for alias in aliases:
            if alias in by_name:
                original = by_name[alias]
                mapped[key] = original
                unit = header_unit(original)
                if unit == "GB" and not re.match(r"^(?:memory\s*\||mem\|)", original.strip(), re.IGNORECASE):
                    unit = ""
                units[key] = unit
                break
    mapped["units"] = units
    return mapped
