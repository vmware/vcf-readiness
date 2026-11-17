"""Protocol boundaries for Ethernet partitioning and pure Fibre Channel HBAs."""
import re
from typing import Any, Dict


def is_fibre_channel_function(function: Dict[str, Any]) -> bool:
    """Recognize native FC functions; FCoE/Ethernet personas retain their rules."""
    protocol = re.sub(r"[\s_-]", "", str(function.get("protocol") or "").casefold())
    if protocol:
        return protocol in ("fibrechannel", "fiberchannel", "fc")
    return bool(re.match(r"^FC[.:]", str(function.get("partition_id") or ""), re.I))


def is_pure_fc_adapter(adapter: Dict[str, Any]) -> bool:
    """Identify native FC hardware without classifying CNA or VIC as pure FC."""
    name = str(adapter.get("name") or "")
    if (adapter.get("is_cna") or adapter.get("is_vic_virtual")
            or adapter.get("cna_family") == "cisco_vic" or adapter.get("vic_virtual_interfaces")
            or re.search(r"\bVIC\b", name, re.I)):
        return False
    functions = adapter.get("npar_partitions") or []
    if functions and all(is_fibre_channel_function(p) for p in functions):
        return True
    return bool(
        re.match(r"^FC[.:]", str(adapter.get("id") or ""), re.I)
        or re.search(r"\b(?:fibre channel|fiber channel|FC HBA)\b", name, re.I)
    )
