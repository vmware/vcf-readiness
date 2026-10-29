"""Keep unknown physical media distinct from an observed storage protocol."""
from typing import Any

_UNKNOWN = {"", "NONE", "NULL", "N/A", "UNKNOWN", "NOT REPORTED", "NOTREPORTED", "NOT AVAILABLE", "?", "—"}


def normalize_media_type(value: Any) -> str:
    """Normalize an observed media enum without inferring SSD from NVMe."""
    if not isinstance(value, str):
        return ""
    text = value.strip().upper()
    return "" if text in _UNKNOWN else text


def storage_protocol_display(value: Any) -> str:
    """Use a readable name for equivalent NVMe aliases; retain other protocols."""
    if not isinstance(value, str) or value.strip().upper() in _UNKNOWN:
        return "Not reported"
    text = value.strip()
    if text.upper().replace(" ", "") in ("NVME", "PCIE/NVME", "NVMEXPRESS", "PCIE/NVMEXPRESS"):
        return "NVMe"
    return text


def media_type_display(value: Any) -> str:
    return normalize_media_type(value) or "Not reported"


def drive_type_display(media: Any, protocol: Any) -> str:
    """Omit unknown halves rather than printing NONE / NVMe or inventing media."""
    media_text = normalize_media_type(media)
    protocol_text = storage_protocol_display(protocol)
    parts = ([media_text] if media_text else []) + ([protocol_text] if protocol_text != "Not reported" else [])
    return " / ".join(parts) or "Not reported"
