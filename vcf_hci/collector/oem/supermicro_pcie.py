"""Decode Supermicro per-port PCIe capabilities without inventing current links."""
import re
from typing import Any, Dict

from vcf_hci.collector.pci_utils import normalize_pcie_width

_SPEED_GEN = {2.5: 1, 5.0: 2, 8.0: 3, 16.0: 4, 32.0: 5, 64.0: 6, 128.0: 7}


def with_supermicro_pcie_evidence(device: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy enriched only from already-collected OEM capability fields."""
    result = dict(device)
    raw_value = device.get("_raw")
    raw = raw_value if isinstance(raw_value, dict) else {}
    oem_value = raw.get("Oem")
    oem = oem_value if isinstance(oem_value, dict) else {}
    smc_value = oem.get("Supermicro")
    smc = smc_value if isinstance(smc_value, dict) else {}
    ports = []
    for port in (0, 1):
        speed_key, width_key = f"Port{port}MaxLinkSpeed", f"Port{port}MaxLinkWidth"
        speed = str(smc.get(speed_key) or "").strip()
        match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*GT/s", speed, re.I)
        generation = _SPEED_GEN.get(float(match[1])) if match else None
        width_value = smc.get(width_key)
        try:
            width = normalize_pcie_width(width_value) if not isinstance(width_value, bool) else None
        except (ValueError, OverflowError):
            width = None
        if width and width > 32:
            width = None
        if generation or width:
            ports.append({"port": port, "max_pcie_type": f"Gen{generation}" if generation else None,
                          "max_pcie_width": width,
                          "source": f"Oem.Supermicro.{speed_key}/{width_key}"})
    if ports:
        result["oem_link_capabilities"] = ports
    if raw.get("DeviceType"):
        result.setdefault("device_type", raw["DeviceType"])
    return result
