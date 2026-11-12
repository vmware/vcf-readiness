"""DRAM and NVMe resolution. Absent tier properties remain Unknown."""

from __future__ import annotations

from decimal import Decimal
from typing import Optional

from vcf_hci.plugins.mtat.models import TierEntry
from vcf_hci.plugins.mtat.numbers import percent


def resolve_tiering(
    entries: tuple[TierEntry, ...],
    properties_supported: bool,
    observation: Optional[str],
    error: str,
    nvme_pct_fallback: Optional[int],
) -> dict:
    dram_entries = [item.size_bytes for item in entries if item.kind == "DRAM"]
    nvme_entries = [item.size_bytes for item in entries if item.kind == "NVMe"]
    dram = sum(dram_entries) if dram_entries else None
    nvme = sum(nvme_entries) if nvme_entries else None
    if error:
        return {"status": "ERROR", "dram_bytes": None, "nvme_bytes": None, "ratio": Decimal(0), "fallback": False}
    if not properties_supported or observation is None:
        return {"status": "Unknown", "dram_bytes": dram, "nvme_bytes": None, "ratio": None, "fallback": False}
    if observation not in {"Enabled", "Disabled"}:
        raise ValueError("tier observation must be Enabled, Disabled, or absent")
    if observation == "Disabled":
        return {"status": "Disabled", "dram_bytes": dram, "nvme_bytes": None, "ratio": Decimal(0), "fallback": False}
    if dram is not None and nvme is not None:
        return {"status": "Enabled", "dram_bytes": dram, "nvme_bytes": nvme, "ratio": percent(nvme, dram, 3), "fallback": False}
    if dram is not None and nvme is None and nvme_pct_fallback is not None:
        inferred = int(Decimal(dram) * Decimal(nvme_pct_fallback) / Decimal(100))
        return {"status": "Enabled", "dram_bytes": dram, "nvme_bytes": inferred, "ratio": percent(nvme_pct_fallback, 100, 3), "fallback": True}
    if dram is not None:
        return {"status": "Enabled", "dram_bytes": dram, "nvme_bytes": None, "ratio": None, "fallback": False}
    return {"status": "Enabled", "dram_bytes": None, "nvme_bytes": None, "ratio": None, "fallback": False}


def physical_bytes(memory_size_bytes: Optional[int], dram_bytes: Optional[int]) -> Optional[int]:
    if dram_bytes is not None:
        return dram_bytes
    return memory_size_bytes
