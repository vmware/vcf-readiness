"""Short GPU model tokens for fleet summary / BCG keyword search."""

from __future__ import annotations

import re

_NVIDIA_RE = re.compile(
    r"\b(H\d{3}[A-Z]?|A\d{2,3}[A-Z]?|L\d{2,3}[A-Z]?|V100|T4|RTX\s*\d{4}\s*[A-Za-z]*)\b",
    re.I,
)
_AMD_MI_RE = re.compile(r"\bMI\s*\d{3}[A-Z]?\b", re.I)
_INTEL_RE = re.compile(r"\b(Flex\s*\d{3}|Gaudi\s*\d)\b", re.I)
_VENDOR_PREFIX_RE = re.compile(r"^(?:nvidia|amd|intel)\b[\s\-]*", re.I)
_DATA_CENTER_GPU_RE = re.compile(r"^data\s+center\s+gpu\b[\s\-]*", re.I)
_WHITESPACE_RE = re.compile(r"\s+")


def short_gpu_model(gpu_model: str) -> str:
    """Return a concise GPU model token from a raw Redfish / BMC name.

    Priority: NVIDIA card code → AMD MI code → Intel Flex/Gaudi → strip
    vendor / "Data Center GPU" prefixes → first two meaningful tokens.

    Examples:
        "Intel Data Center GPU Flex 140" → "Flex 140"
        "NVIDIA A100-PCIE-40GB" → "A100"
        "AMD Instinct MI210" → "MI210"
        "Tesla T4" → "T4"
    """
    name = (gpu_model or "").strip()
    if not name:
        return ""

    m = _NVIDIA_RE.search(name)
    if m:
        return _WHITESPACE_RE.sub(" ", m.group(1).strip())

    m = _AMD_MI_RE.search(name)
    if m:
        return _WHITESPACE_RE.sub(" ", m.group(0).strip()).replace(" ", "")

    m = _INTEL_RE.search(name)
    if m:
        return _WHITESPACE_RE.sub(" ", m.group(1).strip())

    cleaned = name
    for _ in range(2):
        cleaned = _VENDOR_PREFIX_RE.sub("", cleaned).strip()
        cleaned = _DATA_CENTER_GPU_RE.sub("", cleaned).strip()
    cleaned = _WHITESPACE_RE.sub(" ", cleaned).strip()
    if not cleaned:
        return name
    tokens = [t for t in cleaned.split(" ") if len(t) > 2][:2]
    return " ".join(tokens) if tokens else cleaned


def format_gpu_count_label(count: int, vendor_label: str, raw_name: str) -> str:
    """Format a fleet GPU cell fragment like ``1× Intel Flex 140``."""
    token = short_gpu_model(raw_name) or (raw_name or "GPU").strip() or "GPU"
    if vendor_label and vendor_label != "GPU":
        return f"{count}\u00d7 {vendor_label} {token}"
    return f"{count}\u00d7 {token}"
