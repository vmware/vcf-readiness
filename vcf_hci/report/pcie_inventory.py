"""Collected PCIe device records, distinct from physical expansion slot inventory."""
from typing import Any, Dict, List, Optional

from vcf_hci.collector.oem.supermicro_pcie import with_supermicro_pcie_evidence
from vcf_hci.collector.pci_utils import normalize_pcie_type, normalize_pcie_width
from vcf_hci.report.helpers import _h


def _raw(device: Dict[str, Any]) -> Dict[str, Any]:
    value = device.get("_raw")
    return value if isinstance(value, dict) else {}


def _uri(device: Dict[str, Any]) -> str:
    raw = _raw(device)
    return str(raw.get("@odata.id") or device.get("uri") or "").rstrip("/")


def _slot_labels(device: Dict[str, Any], slots: List[Dict[str, Any]]) -> str:
    if device.get("slot_label"):
        return str(device["slot_label"])
    uri = _uri(device)
    labels = []
    if uri:
        for slot in slots:
            if not isinstance(slot, dict):
                continue
            for function in slot.get("functions") or []:
                if isinstance(function, dict) and str(function.get("uri") or "").split("/PCIeFunctions", 1)[0].rstrip("/") == uri:
                    label = str(slot.get("slot_label") or "")
                    if label and label not in labels:
                        labels.append(label)
    return ", ".join(labels) or "No reported slot mapping"


def _link(generation: Any, width: Any) -> str:
    parts = [str(generation)] if generation else []
    if width:
        parts.append(f"x{width}")
    return " ".join(parts) or "Not reported"


def _kind(device: Dict[str, Any]) -> str:
    text = " ".join(str(device.get(key) or "") for key in ("id", "name", "device_class")).upper()
    classes = " ".join(str(f.get("device_class") or "") for f in device.get("functions") or [] if isinstance(f, dict)).upper()
    if "NVME" in text:
        return "NVMe"
    if any(word in text + classes for word in ("NETWORK", "ETHERNET")):
        return "Network"
    if "MASSSTORAGE" in classes or "STORAGE" in text:
        return "Storage controller"
    if "DISPLAY" in text + classes:
        return "Display"
    return str(device.get("device_class") or "PCIe device")


def render_pcie_device_inventory(devices: Optional[List[Dict[str, Any]]], slots: Optional[List[Dict[str, Any]]] = None) -> str:
    """Show reported endpoint identity, link evidence and inventory limitations."""
    records = []
    seen = set()
    for index, device in enumerate(devices or []):
        if not isinstance(device, dict):
            continue
        key = _uri(device) or str(device.get("id") or f"record-{index}")
        if key in seen:
            continue
        seen.add(key)
        records.append(with_supermicro_pcie_evidence(device))
    if not records:
        return ('<section class="report-pcie-devices"><h2>PCIe Device Inventory</h2>'
                '<p>PCIe device records were not captured. This does not establish that the host has no PCIe devices. '
                'Physical slots and subsystem inventory are shown separately.</p></section>')

    rows = []
    simulated_count = 0
    for device in records:
        raw = _raw(device)
        name = str(device.get("name") or raw.get("Name") or device.get("id") or "PCIe device")
        model = str(raw.get("Model") or "").strip()
        part = str(device.get("part_number") or raw.get("PartNumber") or "").strip()
        identity = " · ".join(value for value in dict.fromkeys([model, part]) if value and value != name)
        maker = str(device.get("manufacturer") or raw.get("Manufacturer") or "").strip()
        vid, did = str(device.get("vendor_id") or ""), str(device.get("device_id") or "")
        pci = str(device.get("pci_quad") or device.get("pci_pair") or (f"{vid}:{did}" if vid and did else ""))
        pci_cell = f"<code>{_h(pci)}</code>" if pci else (_h(f"Vendor {vid}; device ID not reported") if vid else "Not reported")
        negotiated = _link(device.get("current_pcie_type"), device.get("current_pcie_width"))
        interface = raw.get("PCIeInterface")
        if isinstance(interface, dict):
            # The legacy normalized helper can fill missing maxima from current
            # values. A raw interface lets this table keep that uncertainty visible.
            max_gen = normalize_pcie_type(interface.get("MaxPCIeType") or interface.get("MaxPCIeGeneration"))
            max_width = normalize_pcie_width(interface.get("MaxLanes") or interface.get("MaxPCIeLanes"))
        else:
            max_gen, max_width = device.get("max_pcie_type"), device.get("max_pcie_width")
        capability = _link(max_gen, max_width)
        ports = device.get("oem_link_capabilities") or []
        if ports:
            port_lines = [f"Port {_h(str(port['port']))}: {_h(_link(port.get('max_pcie_type'), port.get('max_pcie_width')))}"
                          for port in ports if isinstance(port, dict)]
            capability = ("" if capability == "Not reported" else _h(capability) + "<br>") + "<br>".join(port_lines)
            capability += "<br><small>Supermicro OEM maximum</small>"
        else:
            capability = _h(capability)
        device_type = str(device.get("device_type") or raw.get("DeviceType") or "").strip()
        simulated = device_type.lower() == "simulated"
        simulated_count += int(simulated)
        evidence = ("<span class='badge info' title='BMC DeviceType is Simulated; this record does not verify a physically installed device.'>Simulated (BMC)</span>"
                    if simulated else _h(device_type or "Device type not reported"))
        if not did or not identity:
            evidence += "<br><small>Partial identity</small>"
        kind = _kind(device)
        target = "tab-network" if kind == "Network" else "tab-storage" if kind in ("NVMe", "Storage controller") else ""
        kind_cell = f"<a class='tab-jump-link' href='#{target}' data-jump-tab='{target}'>{_h(kind)}</a>" if target else _h(kind)
        rows.append(
            f"<tr data-pcie-device='true' data-simulated='{str(simulated).lower()}'>"
            f"<td><strong>{_h(name)}</strong>" + (f"<br><small>{_h(identity)}</small>" if identity else "")
            + (f"<br><small>{_h(maker)}</small>" if maker else "")
            + f"</td><td>{kind_cell}</td><td>{_h(_slot_labels(device, slots or []))}</td><td>{pci_cell}</td>"
            f"<td>{_h(negotiated)}</td><td>{capability}</td><td>{_h(str(device.get('health') or 'Not reported'))}</td>"
            f"<td>{evidence}</td></tr>"
        )
    note = (f" {simulated_count} marked Simulated by the BMC; these are not verified installed-device counts." if simulated_count else "")
    return (
        '<section class="report-pcie-devices"><h2>PCIe Device Inventory</h2>'
        f'<p>{len(records)} reported PCIe records.{note} Physical expansion slots are listed separately below.</p>'
        '<table><thead><tr><th>Device</th><th>Kind</th><th>Slot mapping</th><th>PCI IDs</th>'
        '<th>Negotiated link</th><th>Maximum capability</th><th>BMC health</th><th>Inventory evidence</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></section>'
    )
