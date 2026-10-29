"""Per-adapter association and hardware assembly; the mixin owns discovery order."""
import logging
import re
from typing import Any, Optional, cast

from vcf_hci.collector.contracts import NetworkCollector
from vcf_hci.collector.network_identity import (
    _clean_mac_address,
    _find_parent_pcie_device,
    _get_parent_iface_id,
    classify_cna_adapter,
    infer_nic_manufacturer,
)
from vcf_hci.collector.network_ports import _evaluate_npar_partitions
from vcf_hci.collector.network_resources import (
    collect_adapter_ports,
    collect_ethernet_port,
    collect_network_functions,
    collect_partition_details,
)
from vcf_hci.collector.pci_utils import (
    extract_pci_ids_from_dict,
    extract_pcie_link_status,
    match_firmware_inventory_pci,
    match_pcie_cache,
)
from vcf_hci.constants import is_generic_name
from vcf_hci.logging_utils import get_nested

logger = logging.getLogger("vcf_assess")


def merge_parent_interface(self: NetworkCollector, uid: str, adapter: dict, parent_uid: str, nic_list: list, seen_ids: set) -> None:
    """Merge a logical observation into the selected parent without creating another card."""
    # Append or merge partition details to parent adapter if present in nic_list
    for p_nic in nic_list:
        if p_nic.get("id") == parent_uid:
            if p_nic.get("is_vic_virtual") or p_nic.get("cna_family") == "cisco_vic":
                logger.debug("Deduplicated duplicate logical interface %s on Cisco VIC %s", uid, parent_uid)
                if (not p_nic.get("part_number") or p_nic.get("part_number") in ("N/A", "Unknown", "")) and adapter.get("PartNumber"):
                    p_nic["part_number"] = str(adapter.get("PartNumber")).strip()
                seen_ids.add(uid)
                break
            sub_speed = self._extract_nic_speed_gbps(adapter, adapter, "")
            sub_link = adapter.get("LinkStatus") or "Down"
            sub_mac = _clean_mac_address(adapter.get("MACAddress"))
            sub_parts_raw = p_nic.setdefault("npar_partitions", [])
            sub_parts = sub_parts_raw if isinstance(sub_parts_raw, list) else []
            # Deduplicate / merge by partition_id or matching MAC address
            existing_part = None
            for sp in sub_parts:
                if not isinstance(sp, dict):
                    continue
                if sp.get("partition_id") == uid:
                    existing_part = sp
                    break
                sp_mac = _clean_mac_address(sp.get("mac_address"))
                if sub_mac and sp_mac and sp_mac.lower() == sub_mac.lower():
                    existing_part = sp
                    break
            if existing_part is not None:
                if sub_speed > 0:
                    existing_part["speed_gbps"] = int(sub_speed) if sub_speed == int(sub_speed) else round(sub_speed, 2)
                if (sub_link and sub_link != "Down") or not existing_part.get("link_status"):
                    existing_part["link_status"] = sub_link
                if sub_mac and not existing_part.get("mac_address"):
                    existing_part["mac_address"] = sub_mac
            else:
                # Match against physical ports to avoid treating host OS interfaces as NPAR partitions
                port_match = None
                for pt in p_nic.get("ports") or []:
                    pt_mac = _clean_mac_address(pt.get("mac_address"))
                    if sub_mac and pt_mac and pt_mac.lower() == sub_mac.lower():
                        port_match = pt
                        break
                if port_match:
                    if sub_speed > 0 and not port_match.get("current_speed_gbps"):
                        port_match["current_speed_gbps"] = int(sub_speed) if sub_speed == int(sub_speed) else round(sub_speed, 2)
                    if sub_link and sub_link != "Down" and port_match.get("link_status") in ("Down", None, ""):
                        port_match["link_status"] = sub_link
                elif p_nic.get("npar_enabled") is False:
                    # Explicitly not an NPAR adapter - do not create artificial NPAR partitions
                    pass
                else:
                    sub_parts.append({
                        "partition_id": uid,
                        "speed_gbps": int(sub_speed) if sub_speed == int(sub_speed) else round(sub_speed, 2),
                        "link_status": sub_link,
                        "mac_address": sub_mac,
                    })
            p_ports = p_nic.get("ports")
            p_ports_len = len(p_ports) if isinstance(p_ports, (list, tuple)) else 0
            p_nic["is_npar"] = False if p_nic.get("npar_enabled") is False else _evaluate_npar_partitions(sub_parts, p_ports_len)
            seen_ids.add(uid)
            break
    return


def associate_pcie_interface(
    self: NetworkCollector, uid: str, adapter_uri: str, adapter: dict, adapter_mac: str,
    pcie_cache: list, nic_list: list, seen_ids: set,
) -> bool:
    """Return whether a standalone Ethernet observation was consumed by PCIe association."""
    pdev_match = _find_parent_pcie_device(uid, adapter_uri, pcie_cache)
    if pdev_match:
        parent_dev, parent_fn = pdev_match
        parent_adapter_id = str(parent_dev.get("Id") or parent_dev.get("id") or "").strip()
        raw_pdev = cast(dict, parent_dev.get("_raw")) if isinstance(parent_dev.get("_raw"), dict) else parent_dev
        if parent_adapter_id == "MLOM" or any(adapter_mac and p.get("mac_address") and adapter_mac.lower() == str(p.get("mac_address")).lower() for n in nic_list for p in n.get("ports", [])):
            logger.debug("Deduplicated logical interface %s to parent adapter", uid)
            seen_ids.add(uid)
            return True

        existing_parent = next((n for n in nic_list if n.get("id") == parent_adapter_id), None)
        sub_speed = self._extract_nic_speed_gbps(adapter, adapter, "")
        sub_link = adapter.get("LinkStatus") or "Down"
        sub_mac = _clean_mac_address(adapter.get("MACAddress"))

        if existing_parent:
            if sub_speed <= 0:
                if "X550" in str(existing_parent.get("name", "")).upper() or "1563" in str(existing_parent.get("device_id", "")).lower():
                    sub_speed = 10.0
            existing_parent["ports"].append({
                "port_id": uid,
                "link_status": sub_link,
                "current_speed_gbps": int(sub_speed) if sub_speed == int(sub_speed) else round(sub_speed, 2),
                "mac_address": sub_mac,
            })
            seen_ids.add(uid)
            return True
        else:
            p_name = str(parent_dev.get("Name") or parent_dev.get("name") or "").strip() or f"PCIe Device {parent_adapter_id}"
            if is_generic_name(p_name):
                p_name = f"PCIe Network Adapter {parent_adapter_id}"
            p_pci = {
                "vendor_id": parent_dev.get("vendor_id", ""),
                "device_id": parent_dev.get("device_id", ""),
                "subsystem_vendor_id": parent_dev.get("subsystem_vendor_id", ""),
                "subsystem_id": parent_dev.get("subsystem_id", ""),
                "pci_quad": parent_dev.get("pci_quad", ""),
                "pci_pair": parent_dev.get("pci_pair", ""),
            }
            if not p_pci["pci_quad"]:
                p_pci = extract_pci_ids_from_dict(parent_fn or parent_dev, get_fn=self._get)
            if not p_pci["pci_quad"]:
                p_pci = match_pcie_cache(parent_dev, pcie_cache, get_fn=self._get)
            if not p_pci["pci_quad"]:
                p_pci = match_firmware_inventory_pci(p_name, get_fn=self._get)

            vid = str(p_pci.get("vendor_id") or "").lower().replace("0x", "")
            p_pair = str(p_pci.get("pci_pair") or "").lower()
            # Filter out non-network controllers (e.g. Matrox VGA 102b:0522, ASPEED 1a03:2000)
            if vid in ("102b", "1a03") or p_pair in ("102b:0522", "1a03:2000"):
                logger.debug("Skipping non-network parent device %s (%s, VID=%s)", parent_adapter_id, p_name, vid)
                seen_ids.add(uid)
                return True

            if vid in ("8086", "0x8086") or "intel" in p_name.lower():
                p_mfg = "Intel"
            elif vid in ("14e4", "0x14e4") or "broadcom" in p_name.lower():
                p_mfg = "Broadcom"
            elif vid in ("15b3", "0x15b3") or "mellanox" in p_name.lower():
                p_mfg = "Mellanox"
            elif vid in ("1137", "0x1137") or "cisco" in p_name.lower():
                p_mfg = "Cisco Systems Inc"
            else:
                p_mfg = str(parent_dev.get("Manufacturer") or parent_dev.get("manufacturer") or "Unknown")

            if sub_speed <= 0:
                if "X550" in p_name.upper() or "1563" in str(p_pci.get("device_id", "")).lower():
                    sub_speed = 10.0
            p_fw = parent_dev.get("firmware_version") or raw_pdev.get("FirmwareVersion") or parent_dev.get("FirmwareVersion") or "N/A"
            p_link = extract_pcie_link_status(raw_pdev)
            new_nic = {
                "id": parent_adapter_id,
                "name": p_name,
                "manufacturer": p_mfg,
                "part_number": parent_dev.get("part_number") or raw_pdev.get("PartNumber") or parent_dev.get("PartNumber") or "N/A",
                "firmware_version": p_fw,
                "ports": [{
                    "port_id": uid,
                    "link_status": sub_link,
                    "current_speed_gbps": int(sub_speed) if sub_speed == int(sub_speed) else round(sub_speed, 2),
                    "mac_address": sub_mac,
                }],
                "speed_gbps": int(sub_speed) if sub_speed == int(sub_speed) else round(sub_speed, 2),
                "vendor_id": p_pci["vendor_id"],
                "device_id": p_pci["device_id"],
                "subsystem_vendor_id": p_pci["subsystem_vendor_id"],
                "subsystem_id": p_pci["subsystem_id"],
                "pci_quad": p_pci["pci_quad"],
                "pci_pair": p_pci["pci_pair"],
                "current_pcie_type": p_link.get("current_pcie_type"),
                "max_pcie_type": p_link.get("max_pcie_type"),
                "current_pcie_width": p_link.get("current_pcie_width"),
                "max_pcie_width": p_link.get("max_pcie_width"),
                "downgraded": p_link["downgraded"],
                "downgrade_reason": p_link["reason"],
                "downgrade_badge": p_link["badge"],
                "is_cna": False,
                "is_npar": False,
                "is_vic_virtual": False,
                "meets_esa_25g": (sub_speed >= 25.0),
            }
            nic_list.append(new_nic)
            seen_ids.add(uid)
            seen_ids.add(parent_adapter_id)
            return True
    return False


def collect_physical_adapter(
    self: NetworkCollector, adapter: dict, adapter_uri: str, uid: str, adapter_mac: str,
    is_eth_iface_ep: bool, pcie_cache: Optional[list], nic_list: list,
) -> None:
    """Acquire and assemble one physical adapter after logical-parent association."""
    dynamic_ports = []

    # ── Resolve display name and OEM model info ─────────────────────
    resolved_name = self._resolve_product_name(adapter, pcie_cache)
    # For EthernetInterfaces, supplement bare names with OEM fields
    if is_eth_iface_ep and is_generic_name(resolved_name):
        dell_nic = get_nested(adapter, "Oem", "Dell", "DellNIC", default={})
        oem_name = dell_nic.get("ProductName") or dell_nic.get("BusProtocol") or ""
        if not oem_name:
            # HPE iLO: AdapterDetails carries human-readable product name
            hpe_det = get_nested(adapter, "Oem", "Hpe", "AdapterDetails", default={})
            oem_name = hpe_det.get("Name") or hpe_det.get("Model") or ""
        if oem_name and not is_generic_name(oem_name):
            resolved_name = oem_name

    if is_generic_name(resolved_name):
        alt_model = str(adapter.get("Model") or adapter.get("PartNumber") or "").strip()
        if alt_model and not is_generic_name(alt_model):
            resolved_name = alt_model

    # Exclude pure Fibre Channel controllers (handled by collect_fc_hbas)
    cna_check = classify_cna_adapter(
        resolved_name,
        str(adapter.get("Manufacturer") or ""),
        str(adapter.get("Model") or ""),
        str(adapter.get("PartNumber") or ""),
        adapter_id=str(uid),
    )
    _name_fc_check = f"{resolved_name} {adapter.get('Name', '')} {adapter.get('Description', '')} {adapter.get('Model', '')} {adapter.get('Id', '')} {uid}".lower()
    is_pure_fc = (
        not cna_check.get("is_cna")
        and (
            "fibre channel" in _name_fc_check
            or bool(re.search(r"\bFC\s+(?:Adapter|HBA|Port)\b", _name_fc_check, re.I))
            or bool(re.search(r"\bQLE2[5678]\d{2}\b|\bLPe3[125678]\d{3}\b", _name_fc_check, re.I))
            or bool(re.search(r"\bFC\.", str(uid)))
            or bool(re.search(r"\bFC\.", str(adapter.get("Id", ""))))
            or bool(adapter.get("FcPorts"))
            or str(adapter.get("PortType") or "").lower() == "fibrechannel"
            or any(
                set(controller.get("ControllerCapabilities", {}).get("NetworkDeviceFunctionTypes") or []) == {"FibreChannel"}
                for controller in adapter.get("Controllers") or [] if isinstance(controller, dict)
            )
        )
    )
    if is_pure_fc:
        return

    manufacturer = (adapter.get("Manufacturer")
                    or get_nested(adapter, "Oem", "Dell", "DellNIC", "BusProtocol")
                    or "Unknown")
    part_number  = adapter.get("PartNumber") or "N/A"

    dynamic_ports = collect_adapter_ports(self, adapter, adapter_uri, resolved_name)

    # ── EthernetInterface path (logical port view) ──────────────────
    # These resources ARE a port: link status and speed live at the
    # top level, not in a NetworkPorts sub-collection.
    if is_eth_iface_ep and not dynamic_ports:
        collect_ethernet_port(self, adapter, uid, resolved_name, dynamic_ports)

    ndf_jsons = collect_network_functions(self, adapter, adapter_uri)

    # ── Classify CNA Dual-Persona (VIC / FlexFabric / FastLinQ / OneConnect) ──
    cna_info = classify_cna_adapter(
        resolved_name,
        manufacturer,
        str(adapter.get("Model") or ""),
        part_number,
        net_dev_funcs=ndf_jsons
    )
    is_vic = bool(
        cna_info.get("is_vic")
        or cna_info.get("cna_family") == "cisco_vic"
        or "VIC" in resolved_name.upper()
        or "VIC" in str(adapter.get("Model") or "").upper()
    )

    (npar_partitions, is_npar, is_vic_virtual, npar_enabled_flag,
     adapter_max_vfs, adapter_vfs_enabled) = collect_partition_details(self, adapter, ndf_jsons, dynamic_ports, is_vic)

    # Skip BMC virtual management NICs — e.g. VirtualNic, VirtualEthernet, or generic name + no port data
    if re.search(r"virtual(?:nic|ethernet)", str(uid), re.I) or re.search(r"virtual(?:nic|ethernet)", str(adapter.get("Name") or ""), re.I):
        logger.debug("Skipping BMC USB virtual NIC %s", uid)
        return
    if is_generic_name(resolved_name) and not dynamic_ports:
        return

    # Firmware version: standard field first, then OEM hook fallbacks
    fw_version = self.oem_nic_firmware(adapter)

    adapter["resolved_name"] = resolved_name
    pci_info = extract_pci_ids_from_dict(adapter, get_fn=self._get)
    if not pci_info["pci_quad"] and pcie_cache:
        pci_info = match_pcie_cache(adapter, pcie_cache, get_fn=self._get)
    if not pci_info["pci_quad"]:
        fw_pci = match_firmware_inventory_pci(str(resolved_name or adapter.get("Name") or ""), get_fn=self._get)
        if fw_pci.get("pci_quad"):
            pci_info = fw_pci
        else:
            for k, v in fw_pci.items():
                if v and not pci_info.get(k):
                    pci_info[k] = v

    # Filter out non-network controllers (e.g. Matrox VGA 102b:0522, ASPEED 1a03:2000)
    vid_norm = str(pci_info.get("vendor_id") or "").lower().replace("0x", "")
    pair_norm = str(pci_info.get("pci_pair") or "").lower()
    mfg_raw = str(adapter.get("Manufacturer") or "").lower()
    if (
        vid_norm in ("102b", "1a03")
        or pair_norm in ("102b:0522", "1a03:2000")
        or mfg_raw in ("matrox", "aspeed")
        or "matrox" in resolved_name.lower()
        or "aspeed" in resolved_name.lower()
    ):
        logger.debug("Skipping non-network controller %s (%s, VID=%s, pair=%s)", uid, resolved_name, vid_norm, pair_norm)
        return

    if is_generic_name(resolved_name):
        quad = pci_info.get("pci_quad")
        pair = pci_info.get("pci_pair")
        if quad or pair:
            try:
                from vcf_hci.hcl.loader import load_io_nics_catalog
                cat = load_io_nics_catalog()
                if isinstance(cat, dict):
                    h_dev = cat.get("quads", {}).get(quad)
                    if not h_dev and pair:
                        p_items = cat.get("pairs", {}).get(pair)
                        if p_items:
                            from vcf_hci.collector.pci_utils import select_best_pci_pair_entry
                            h_dev = select_best_pci_pair_entry(
                                p_items,
                                svid=pci_info.get("subsystem_vendor_id", ""),
                                ssid=pci_info.get("subsystem_id", ""),
                            )
                    if isinstance(h_dev, dict) and h_dev.get("model"):
                        resolved_name = str(h_dev["model"]).strip()
                        adapter["resolved_name"] = resolved_name
                        if h_dev.get("brand_name") and manufacturer in ("Unknown", "N/A", "", None):
                            manufacturer = h_dev["brand_name"]
            except Exception:
                pass

    if is_generic_name(resolved_name):
        mfg_hint = infer_nic_manufacturer(manufacturer, pci_info, resolved_name)
        resolved_name = (
            str(adapter.get("Model") or "").strip()
            or (f"{mfg_hint} Network Adapter" if mfg_hint and mfg_hint not in ("Unknown", "N/A") else f"Network Adapter {uid}")
        )
        if is_generic_name(resolved_name):
            resolved_name = f"Network Adapter {uid}"

    # Suppress orphaned generic EthernetInterfaces when physical NICs are already present
    is_generic_or_partition = (
        is_generic_name(resolved_name)
        or bool(re.search(r"\b(?:Partition\s+\d+|Embedded NIC\s+\d+\s+Port\s+\d+)\b", resolved_name, re.IGNORECASE))
    )
    if (is_eth_iface_ep
            and is_generic_or_partition
            and manufacturer in ("Unknown", "N/A", "")
            and part_number in ("N/A", "Unknown", "")
            and not pci_info["pci_quad"]
            and any(n.get("pci_quad") or n.get("manufacturer") not in ("Unknown", "") for n in nic_list)):
        logger.debug("Suppressing orphaned generic EthernetInterface %s (%s)", uid, resolved_name)
        return

    link_info = extract_pcie_link_status(adapter)
    if not link_info.get("max_gen") and not link_info.get("max_lanes"):
        if hasattr(self, "oem_pcie_link_status"):
            oem_link = self.oem_pcie_link_status(adapter)
            if oem_link:
                for k, v in oem_link.items():
                    if v is not None:
                        link_info[k] = v

    # If link status is missing width or type, inherit from parent/matching PCIeDevice in pcie_cache
    if (link_info.get("current_pcie_width") is None or link_info.get("current_pcie_type") is None) and pcie_cache:
        pdev_match = _find_parent_pcie_device(uid, adapter_uri, pcie_cache)
        if pdev_match:
            p_dev, _ = pdev_match
            p_raw = cast(dict, p_dev.get("_raw")) if isinstance(p_dev.get("_raw"), dict) else p_dev
            p_link = extract_pcie_link_status(p_raw)
            for k in (
                "current_pcie_type", "max_pcie_type",
                "current_pcie_width", "max_pcie_width",
                "downgraded", "badge", "reason",
                "max_gen", "negotiated_gen", "max_lanes", "negotiated_lanes",
            ):
                if p_link.get(k) is not None and link_info.get(k) is None:
                    link_info[k] = p_link[k]

    logger.debug(
        f"NIC '{resolved_name}' ({uid}): PCI IDs -> VID='{pci_info['vendor_id']}', "
        f"DID='{pci_info['device_id']}', SVID='{pci_info['subsystem_vendor_id']}', "
        f"SSID='{pci_info['subsystem_id']}' (quad='{pci_info['pci_quad']}')"
    )

    adapter_max_speed = max((p.get("current_speed_gbps") or 0 for p in dynamic_ports), default=0)
    adapter_speed = adapter_max_speed if adapter_max_speed > 0 else None
    if not adapter_speed or adapter_speed <= 0:
        m_speeds = re.findall(r"\b(400|200|100|50|40|25|10|1)\s*(?:G(?:bE|b|E)?|Gigabit)\b", resolved_name, re.IGNORECASE)
        if m_speeds:
            inferred_speed = max(float(x) for x in m_speeds)
            adapter_speed = int(inferred_speed) if inferred_speed == int(inferred_speed) else round(inferred_speed, 2)
        elif re.search(r"\b(?:X550|X540|X520)\b", resolved_name, re.IGNORECASE):
            adapter_speed = 10
        elif re.search(r"\b(?:ConnectX[-_]?[56]|CX[-_]?[56])\b", resolved_name, re.IGNORECASE):
            adapter_speed = 100
        elif re.search(r"\b(?:ConnectX[-_]?4|CX[-_]?4)\b", resolved_name, re.IGNORECASE):
            adapter_speed = 25
        if adapter_speed and adapter_speed > 0:
            for p in dynamic_ports:
                if not p.get("current_speed_gbps"):
                    p["current_speed_gbps"] = adapter_speed
    mfg_resolved = infer_nic_manufacturer(manufacturer, pci_info, resolved_name)

    # Safeguard: do not add pure Fibre Channel HBAs to Ethernet nic_list
    if not cna_info["is_cna"] and (
        bool(re.search(r"\bFC\.", str(uid)))
        or (dynamic_ports and all(str(p.get("port_id", "")).startswith("FC.") for p in dynamic_ports))
    ):
        logger.debug("Skipping pure Fibre Channel adapter %s from network_adapters list", uid)
        return

    # For Cisco VIC / MLOM blade adapters where physical ports are routed through
    # the chassis fabric midplane (omitted by CIMC Redfish NetworkPorts API):
    # synthesize an active fabric uplink port if adapter has rated speed and no ports.
    if not dynamic_ports and (cna_info.get("cna_family") == "cisco_vic" or is_vic or "MLOM" in str(uid).upper()):
        synth_speed = adapter_speed or 0
        if synth_speed <= 0:
            adp_spd = self._extract_nic_speed_gbps(adapter, adapter, resolved_name)
            if adp_spd > 0:
                synth_speed = int(adp_spd) if adp_spd == int(adp_spd) else round(adp_spd, 2)
        if synth_speed > 0:
            synth_port = {
                "port_id": 1,
                "link_status": "Up",
                "link_reported": True,
                "speed_source": "VIC Fabric Link",
                "current_speed_gbps": synth_speed,
                "mac_address": adapter_mac or "",
                "transceiver_identifier": "Chassis Fabric Backplane",
                "transceiver_interface": "Internal KR/CR Fabric",
                "transceiver_vendor": "Cisco",
                "transceiver_part_number": part_number if part_number not in ("N/A", "Unknown", "") else "",
                "transceiver_serial": "",
            }
            dynamic_ports.append(synth_port)
            if not adapter_speed:
                adapter_speed = synth_speed

    nic_list.append({
        "id": uid,
        "name": resolved_name,
        "manufacturer": mfg_resolved,
        "part_number": part_number,
        "firmware_version": str(fw_version).strip() or "N/A",
        "ports": dynamic_ports,
        "speed_gbps": adapter_speed,
        "vendor_id": pci_info["vendor_id"],
        "device_id": pci_info["device_id"],
        "subsystem_vendor_id": pci_info["subsystem_vendor_id"],
        "subsystem_id": pci_info["subsystem_id"],
        "pci_quad": pci_info["pci_quad"],
        "pci_pair": pci_info["pci_pair"],
        "current_pcie_type": link_info.get("current_pcie_type"),
        "max_pcie_type": link_info.get("max_pcie_type"),
        "current_pcie_width": link_info.get("current_pcie_width"),
        "max_pcie_width": link_info.get("max_pcie_width"),
        "downgraded": link_info["downgraded"],
        "downgrade_reason": link_info["reason"],
        "downgrade_badge": link_info["badge"],
        "is_cna": cna_info["is_cna"],
        "cna_family": cna_info["cna_family"],
        "cna_family_label": cna_info["family_label"],
        "cna_eth_driver": cna_info["eth_driver"],
        "cna_fc_driver": cna_info["fc_driver"],
        "cna_eth_bcg_url": "",
        "cna_fc_bcg_url": "",
        "is_npar": is_npar,
        "npar_enabled": npar_enabled_flag,
        "npar_partitions": npar_partitions,
        "is_vic_virtual": is_vic_virtual,
        "vic_virtual_interfaces": npar_partitions if is_vic else [],
        "max_virtual_functions": adapter_max_vfs,
        "virtual_functions_enabled": adapter_vfs_enabled,
    })


def collect_network_adapter_member(
    self: NetworkCollector, member: Any, is_eth_iface_ep: bool, pcie_cache: Optional[list],
    nic_list: list, seen_ids: set,
) -> None:
    """Resolve a member and dispatch association before physical collection; caller owns errors."""
    adapter_uri = member.get("@odata.id") if isinstance(member, dict) else (member if isinstance(member, str) else None)
    if not adapter_uri:
        return
    if isinstance(member, dict) and len(member) > 2 and (member.get("Id") or member.get("MACAddress")):
        adapter = member
    else:
        adapter = self._get(adapter_uri)
    if not adapter:
        return
    if adapter_uri and len(adapter) > 2 and hasattr(self, "_populate_request_cache"):
        self._populate_request_cache(adapter_uri, adapter)
    uid = adapter.get("Id", adapter_uri)
    # Exact duplicate
    if uid in seen_ids:
        return
    # Skip BMC virtual management NICs early
    if (
        re.search(r"virtual(?:nic|ethernet)", str(uid), re.I)
        or re.search(r"virtual(?:nic|ethernet)", str(adapter.get("Name") or ""), re.I)
        or str(uid).lower() in ("tomanager", "hostinterface", "usb0", "bmc_nic")
        or "tomanager" in str(adapter_uri).lower()
        or str(adapter.get("Name") or "").strip().lower() in ("host ethernet interface", "system ethernet interface")
        or get_nested(adapter, "Links", "HostInterface")
        or get_nested(adapter, "Oem", "Supermicro", "USBConnection")
    ):
        return
    # Deduplicate logical NetworkInterface resources linking directly to a physical NetworkAdapter
    net_adapter_link = (
        get_nested(adapter, "Links", "NetworkAdapter", "@odata.id")
        or get_nested(adapter, "Links", "NetworkAdapter")
    )
    if isinstance(net_adapter_link, dict):
        net_adapter_link = net_adapter_link.get("@odata.id")
    if net_adapter_link and isinstance(net_adapter_link, str):
        target_id = net_adapter_link.rstrip("/").split("/")[-1]
        if target_id in seen_ids or any(n.get("id") == target_id for n in nic_list):
            logger.debug("Deduplicated logical NetworkInterface %s linking to physical adapter %s", uid, target_id)
            seen_ids.add(uid)
            return

    # Sub-interface / partition of a NetworkAdapter already captured
    adapter_mac = _clean_mac_address(adapter.get("MACAddress"))
    parent_uid = _get_parent_iface_id(
        uid, seen_ids, nic_list,
        eth_mac=adapter_mac,
        iface_uri=adapter_uri,
        pcie_cache=pcie_cache,
    )
    if parent_uid:
        merge_parent_interface(self, uid, adapter, parent_uid, nic_list, seen_ids)
        return

    # Correlate standalone EthernetInterfaces with PCIeDevice (e.g. onboard LOM)
    if is_eth_iface_ep and pcie_cache:
        if associate_pcie_interface(self, uid, adapter_uri, adapter, adapter_mac, pcie_cache, nic_list, seen_ids):
            return
    seen_ids.add(uid)
    collect_physical_adapter(self, adapter, adapter_uri, uid, adapter_mac, is_eth_iface_ep, pcie_cache, nic_list)
