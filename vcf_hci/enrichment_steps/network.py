"""FC identity, NIC/HCL enrichment and I/O signal findings."""
import math
import re
from typing import Any, Dict, Optional, Union

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.collector.collect_network import classify_cna_adapter, infer_nic_manufacturer
from vcf_hci.collector.pci_utils import clean_oem_adapter_title, normalize_pci_id, select_best_pci_pair_entry
from vcf_hci.compat_engine import evaluate_pcie_link_health
from vcf_hci.constants import (
    is_generic_name,
    is_raw_part_number,
    is_unfriendly_nic_name,
    normalize_component_manufacturer,
)
from vcf_hci.fc_inventory import normalize_fc_ports


def evaluate_optical_link_health(
    port: Optional[Dict[str, Any]] = None,
    *,
    port_id: Optional[str] = None,
    rx_power_dbm: Optional[Union[float, int, str]] = None,
    transceiver_interface: Optional[str] = None,
    transceiver_identifier: Optional[str] = None,
) -> Optional[str]:
    """Evaluate optical transceiver signal health based on RX optical power (DDM).

    For standard Short Range (SR / 850nm) optics:
      • Normal range: >= -10.0 dBm (typically -1.0 to -7.0 dBm).
      • Marginal degradation: rx_power_dbm < -10.0 dBm (warning).
      • Critical degradation: rx_power_dbm < -13.0 dBm (critical optical degradation).

    Emits finding:
      "Marginal Optical Signal on [Port]: RX Power is [X] dBm. Clean fiber endfaces or check cable bend radius."

    Returns:
        Formatted warning string if optical health is degraded, or None if healthy or inapplicable.
    """
    if port and isinstance(port, dict):
        if port_id is None:
            port_id = str(port.get("port_id") or port.get("id") or port.get("name") or "Port")
        if rx_power_dbm is None:
            rx_power_dbm = port.get("rx_power_dbm")
            if rx_power_dbm is None and port.get("transceiver_rx_power_dbm") is not None:
                rx_power_dbm = port.get("transceiver_rx_power_dbm")
        if transceiver_interface is None:
            transceiver_interface = port.get("transceiver_interface") or port.get("interface_type")
        if transceiver_identifier is None:
            transceiver_identifier = port.get("transceiver_identifier") or port.get("identifier_type")

    # If copper / DAC, DDM optical power checks do not apply
    iface_str = str(transceiver_interface or "").lower()
    if any(c in iface_str for c in ("copper", "dac", "directattach", "backplane", "twistedpair", "10gbase-t", "1000base-t")):
        return None

    # Parse rx_power_dbm
    rx_val = None
    if rx_power_dbm is not None:
        if isinstance(rx_power_dbm, (int, float)):
            rx_val = float(rx_power_dbm)
        elif isinstance(rx_power_dbm, str):
            clean_rx = rx_power_dbm.replace("dBm", "").replace("dbm", "").strip()
            try:
                rx_val = float(clean_rx)
            except (ValueError, TypeError):
                rx_val = None
    elif port and isinstance(port, dict):
        rx_mw = port.get("rx_power_mw") or port.get("RXInputPowermW")
        if rx_mw is not None:
            try:
                flt_mw = float(rx_mw)
                if flt_mw > 0:
                    rx_val = round(10.0 * math.log10(flt_mw), 2)
            except (ValueError, TypeError):
                pass

    if rx_val is None:
        return None

    # Format port label
    pid_str = str(port_id or "Port").strip()
    if pid_str.isdigit():
        port_label = f"Port {pid_str}"
    else:
        port_label = pid_str

    rx_formatted = f"{round(rx_val, 2)}"

    # Check warning threshold (< -10.0 dBm)
    if rx_val < -10.0:
        return (
            f"Marginal Optical Signal on {port_label}: RX Power is {rx_formatted} dBm. "
            f"Clean fiber endfaces or check cable bend radius."
        )

    return None


def enrich_fc_hbas(host_data: Dict[str, Any]) -> None:
    """Enrich Fibre Channel HBAs by correlating generic names with firmware inventory and PCIe devices."""
    fc_hbas = host_data.get("fc_hbas")
    if not isinstance(fc_hbas, list) or not fc_hbas:
        return

    fc_hbas = normalize_fc_ports(fc_hbas)
    host_data["fc_hbas"] = fc_hbas
    fw_inv = host_data.get("firmware_inventory") or []
    pcie_devs = host_data.get("pcie_devices") or []

    # Map existing non-generic HBA names by slot base to share among siblings
    slot_name_map = {}
    for hba in fc_hbas:
        if not isinstance(hba, dict):
            continue
        aname = str(hba.get("adapter_name") or "").strip()
        port_id = str(hba.get("port_id") or "").strip()
        slot_base = port_id.split("-")[0] if "-" in port_id else port_id
        if slot_base and aname and not is_generic_name(aname) and "view" not in aname.lower():
            slot_name_map[slot_base] = aname

    for hba in fc_hbas:
        if not isinstance(hba, dict):
            continue
        cur_name = str(hba.get("adapter_name") or "").strip()
        port_id = str(hba.get("port_id") or "").strip()
        slot_base = port_id.split("-")[0] if "-" in port_id else port_id

        needs_better_name = (
            not cur_name
            or is_generic_name(cur_name)
            or cur_name.lower() in ("fc hba", "fibre channel hba", "fibre channel")
            or "view" in cur_name.lower()
        )

        matched_name = ""
        matched_fw_ver = ""
        matched_pci_dev = None

        # 1. Match against firmware_inventory
        if needs_better_name or not hba.get("firmware_version") or hba.get("firmware_version") in ("00.00.00", "N/A", ""):
            for fw in fw_inv:
                fid = str(fw.get("id") or "")
                fname = str(fw.get("name") or "").strip()
                if not fname or is_generic_name(fname) or "firmware inventory" in fname.lower():
                    continue
                is_fc = any(t in fname.lower() or t in fid.lower() for t in ("fibre channel", "fc", "lpe", "qle", "emulex", "qlogic", "marvell", "sn1700", "sn1600"))
                if not is_fc:
                    continue
                is_match = False
                if (port_id and (fid.endswith(f"__{port_id}") or f"__{port_id}" in fid or fid == port_id)) or (slot_base and (fid.endswith(f"__{slot_base}") or f"__{slot_base}" in fid or f"__{slot_base}-" in fid or f"__{slot_base}." in fid)):
                    is_match = True
                if is_match:
                    c_name = re.sub(r"\s*-\s*(?:FC|[0-9A-Fa-f]{16})\s*$", "", fname).strip()
                    if c_name.endswith(" Adapt"):
                        c_name += "er"
                    matched_name = c_name
                    if fw.get("version") and fw.get("version") not in ("00.00.00", "N/A"):
                        matched_fw_ver = str(fw.get("version"))
                    break

        # 2. Match against pcie_devices
        for pdev in pcie_devs:
            if not isinstance(pdev, dict):
                continue
            pd_name = str(pdev.get("name") or "").strip()
            pd_match = False
            for func in pdev.get("functions") or []:
                fid = str(func.get("id") or func.get("function_id") or "")
                raw_func = func.get("_raw") or {}
                oem_dell_id = ((raw_func.get("Oem") or {}).get("Dell") or {}).get("DellPCIeFunction", {}).get("Id", "")
                if port_id and (port_id in fid or port_id == oem_dell_id):
                    pd_match = True
                    break
                if slot_base and (slot_base in fid or slot_base in oem_dell_id):
                    pd_match = True
                    break
            if not pd_match and slot_base:
                slot_num = re.search(r"slot[._\s]*(\d+)", slot_base, re.I)
                pdev_slot_num = re.search(r"slot[._\s]*(\d+)", str(pdev.get("slot_label") or ""), re.I)
                if slot_num and pdev_slot_num and slot_num.group(1) == pdev_slot_num.group(1):
                    if any(t in pd_name.lower() for t in ("fibre channel", "fc", "lpe", "qle", "emulex", "qlogic")):
                        pd_match = True
            if pd_match:
                matched_pci_dev = pdev
                if needs_better_name and not matched_name and pd_name and not is_generic_name(pd_name):
                    matched_name = pd_name
                break

        if needs_better_name and matched_name:
            hba["adapter_name"] = matched_name
        elif needs_better_name and slot_base in slot_name_map:
            hba["adapter_name"] = slot_name_map[slot_base]
        elif needs_better_name:
            mfg = normalize_component_manufacturer(hba.get("manufacturer"))
            if mfg and mfg not in ("Unknown", "N/A"):
                hba["adapter_name"] = f"{mfg} FC HBA"
            else:
                hba["adapter_name"] = "Fibre Channel HBA"

        if matched_fw_ver and (not hba.get("firmware_version") or hba.get("firmware_version") in ("00.00.00", "N/A", "")):
            hba["firmware_version"] = matched_fw_ver

        if matched_pci_dev:
            for k in ("pci_quad", "pci_pair", "vendor_id", "device_id", "subsystem_vendor_id", "subsystem_id"):
                if not hba.get(k) and matched_pci_dev.get(k):
                    hba[k] = matched_pci_dev.get(k)
            for k in ("current_pcie_type", "max_pcie_type", "current_pcie_width", "max_pcie_width"):
                if not hba.get(k) and matched_pci_dev.get(k):
                    hba[k] = matched_pci_dev.get(k)

        # Normalize manufacturer
        if not hba.get("manufacturer") or hba.get("manufacturer") in ("Unknown", "N/A", ""):
            cur_a = hba.get("adapter_name", "")
            if "emulex" in cur_a.lower() or re.search(r"\bLPe\d+", cur_a, re.I):
                hba["manufacturer"] = "Emulex"
            elif "qlogic" in cur_a.lower() or "marvell" in cur_a.lower() or re.search(r"\bQLE\d+", cur_a, re.I):
                hba["manufacturer"] = "QLogic / Marvell"
            elif "broadcom" in cur_a.lower():
                hba["manufacturer"] = "Broadcom"
            elif "cisco" in cur_a.lower() or "vic" in cur_a.lower():
                hba["manufacturer"] = "Cisco"
        elif hba.get("manufacturer"):
            hba["manufacturer"] = normalize_component_manufacturer(hba.get("manufacturer"))


def enrich_network_adapters(host_data: Dict[str, Any], json_hcl: Optional[Dict[str, Any]]) -> None:
    """Enrich physical adapters in source order, preserving local catalog fallback and port evidence."""
    # 7. CNA BCG URLs & Speed Enrichment on Network Adapters
    net_adapters = host_data.get("network_adapters")
    if isinstance(net_adapters, list):
        io_catalog = None
        deduped_adapters = []
        seen_adapter_bases = {}
        for nic in net_adapters:
            if not isinstance(nic, dict):
                continue
            nid = str(nic.get("id") or "")
            base_id = nid.split("_")[0] if any(k in nid.upper() for k in ("UCSB-MLOM", "UCSC-MLOM", "UCSB-VIC", "UCSC-VIC", "UCSX-MLOM", "UCSX-VIC", "UCSX-V4", "UCSX-V5")) else nid
            if base_id in seen_adapter_bases:
                prev = seen_adapter_bases[base_id]
                if (not prev.get("part_number") or prev.get("part_number") in ("N/A", "Unknown", "")) and nic.get("part_number") not in ("N/A", "Unknown", "", None):
                    prev["part_number"] = nic["part_number"]
                if (not prev.get("manufacturer") or str(prev.get("manufacturer")).lower() in ("unknown", "n/a", "", "none")) and nic.get("manufacturer") not in ("Unknown", "N/A", "", None):
                    prev["manufacturer"] = nic["manufacturer"]
                continue
            seen_adapter_bases[base_id] = nic
            deduped_adapters.append(nic)
        net_adapters = deduped_adapters
        host_data["network_adapters"] = deduped_adapters

        for nic in net_adapters:
            if not isinstance(nic, dict):
                continue
            if not nic.get("is_cna"):
                cna_info = classify_cna_adapter(
                    str(nic.get("name") or ""),
                    str(nic.get("manufacturer") or ""),
                    str(nic.get("model") or ""),
                    str(nic.get("part_number") or ""),
                    adapter_id=str(nic.get("id") or ""),
                )
                if cna_info.get("is_cna"):
                    nic["is_cna"] = True
                    nic["is_vic"] = cna_info.get("is_vic", False)
                    nic["cna_family"] = cna_info.get("cna_family", "")
                    nic["cna_family_label"] = cna_info.get("family_label", "")
                    nic["cna_eth_driver"] = cna_info.get("eth_driver", "")
                    nic["cna_fc_driver"] = cna_info.get("fc_driver", "")

            if nic.get("is_cna"):
                nic_name = str(nic.get("name") or nic.get("id") or "")
                eth_drv = str(nic.get("cna_eth_driver") or "")
                fc_drv = str(nic.get("cna_fc_driver") or "")
                if eth_drv and not nic.get("cna_eth_bcg_url"):
                    nic["cna_eth_bcg_url"] = BCGLinkGenerator.cna_ethernet(nic_name, eth_drv)
                if fc_drv and not nic.get("cna_fc_bcg_url"):
                    nic["cna_fc_bcg_url"] = BCGLinkGenerator.cna_fc(nic_name, fc_drv)

            if not nic.get("manufacturer") or str(nic.get("manufacturer")).lower() in ("unknown", "n/a", "none", "", "null"):
                nic["manufacturer"] = infer_nic_manufacturer(
                    nic.get("manufacturer", ""),
                    nic,
                    str(nic.get("name") or ""),
                )
            else:
                nic["manufacturer"] = normalize_component_manufacturer(nic.get("manufacturer"))

            # Normalize and resolve PCI IDs
            vid = normalize_pci_id(nic.get("vendor_id") or "")
            did = normalize_pci_id(nic.get("device_id") or "")
            svid = normalize_pci_id(nic.get("subsystem_vendor_id") or "")
            ssid = normalize_pci_id(nic.get("subsystem_id") or "")
            if vid and did:
                if not nic.get("pci_pair"):
                    nic["pci_pair"] = f"{vid}:{did}"
                if svid and ssid and not nic.get("pci_quad"):
                    nic["pci_quad"] = f"{vid}:{did}:{svid}:{ssid}"

            pci_quad = (nic.get("pci_quad") or "").lower().strip()
            pci_pair = (nic.get("pci_pair") or "").lower().strip()

            dev = None
            matched_model = ""
            matched_speed = 0.0

            # 1. First check json_hcl if available
            if json_hcl and isinstance(json_hcl, dict):
                hcl_quads = json_hcl.get("quads") or json_hcl.get("_pci_quads") or {}
                if pci_quad and pci_quad in hcl_quads:
                    dev = hcl_quads[pci_quad]
                elif pci_quad and pci_quad in json_hcl:
                    dev = json_hcl[pci_quad]
                elif pci_pair:
                    hcl_pairs = json_hcl.get("pairs") or json_hcl.get("_pci_pairs") or {}
                    if pci_pair in hcl_pairs:
                        dev = select_best_pci_pair_entry(
                            hcl_pairs[pci_pair],
                            model_name=str(nic.get("name") or ""),
                            svid=svid or nic.get("subsystem_vendor_id", ""),
                            ssid=ssid or nic.get("subsystem_id", ""),
                        )

            # 2. Fallback to io_catalog
            if not dev and (pci_quad or pci_pair):
                if io_catalog is None:
                    try:
                        from vcf_hci.hcl.loader import load_io_nics_catalog
                        io_catalog = load_io_nics_catalog()
                    except Exception:
                        io_catalog = {}

                quads = io_catalog.get("quads") or {}
                pairs = io_catalog.get("pairs") or {}
                if pci_quad:
                    for qk, qv in quads.items():
                        if qk.lower() == pci_quad:
                            dev = qv
                            break
                if not dev and pci_pair and pci_pair in pairs:
                    dev = select_best_pci_pair_entry(
                        pairs[pci_pair],
                        model_name=str(nic.get("name") or ""),
                        svid=svid or nic.get("subsystem_vendor_id", ""),
                        ssid=ssid or nic.get("subsystem_id", ""),
                    )

            if isinstance(dev, dict):
                matched_model = dev.get("model") or ""
                cur_pn = str(nic.get("part_number") or "").strip()
                if not cur_pn and is_raw_part_number(nic.get("model")):
                    cur_pn = str(nic.get("model")).strip()

                # Prefer canonical IO catalog marketing title when available
                if pci_quad or dev.get("io_product_id"):
                    if io_catalog is None:
                        try:
                            from vcf_hci.hcl.loader import load_io_nics_catalog
                            io_catalog = load_io_nics_catalog()
                        except Exception:
                            io_catalog = {}
                    io_dev = io_catalog.get("quads", {}).get(pci_quad) if pci_quad else None
                    if not io_dev and dev.get("io_product_id"):
                        io_dev = (io_catalog.get("pids") or {}).get(str(dev["io_product_id"]))
                    if isinstance(io_dev, dict) and io_dev.get("model"):
                        matched_model = io_dev["model"]

                cur_pn = str(nic.get("part_number") or "").strip()
                if not cur_pn and is_raw_part_number(nic.get("model")):
                    cur_pn = str(nic.get("model")).strip()

                # Extract slot if available from name or id before name is updated
                slot_val = nic.get("slot") or ""
                if not slot_val:
                    m_slot = re.search(r"\b(Slot\s+[0-9a-zA-Z_]+)\b", str(nic.get("name") or ""), re.I)
                    if m_slot:
                        slot_val = m_slot.group(1).title()
                    else:
                        m_id_slot = re.search(r"\bSlot\.([0-9a-zA-Z_]+)\b", str(nic.get("id") or ""), re.I)
                        if m_id_slot:
                            slot_val = f"Slot {m_id_slot.group(1)}"
                if slot_val and not nic.get("slot"):
                    nic["slot"] = slot_val

                # Prepend brand name if not already in matched_model
                brand = (
                    nic.get("manufacturer")
                    or dev.get("brand_name")
                    or (io_dev.get("brand_name") if isinstance(io_dev, dict) else "")
                    or ""
                )
                matched_title = matched_model
                if brand and matched_model and brand.lower() not in matched_model.lower():
                    if not re.match(r"^(?:ConnectX|BlueField|BCM\d+)\b", matched_model, re.I):
                        matched_title = f"{brand} {matched_model}"

                if slot_val and matched_title and slot_val.lower() not in matched_title.lower() and f"({slot_val})" not in matched_title:
                    matched_title_with_slot = f"{matched_title} ({slot_val})"
                else:
                    matched_title_with_slot = matched_title

                if is_unfriendly_nic_name(nic.get("name"), cur_pn) and matched_title:
                    nic["name"] = matched_title_with_slot
                if not nic.get("model") or is_unfriendly_nic_name(nic.get("model"), cur_pn):
                    if matched_model:
                        nic["model"] = matched_model
                if (not nic.get("manufacturer") or str(nic.get("manufacturer")).lower() in ("unknown", "n/a", "none", "", "null")) and dev.get("brand_name"):
                    nic["manufacturer"] = normalize_component_manufacturer(dev.get("brand_name"))
                if nic.get("manufacturer"):
                    nic["manufacturer"] = normalize_component_manufacturer(nic.get("manufacturer"))
                if dev.get("product_id") and not nic.get("product_id"):
                    nic["product_id"] = str(dev["product_id"])
                if dev.get("io_product_id") and not nic.get("io_product_id"):
                    nic["io_product_id"] = str(dev["io_product_id"])
                elif dev.get("product_id") and not nic.get("io_product_id"):
                    nic["io_product_id"] = str(dev["product_id"])
                if dev.get("io_vcglink") and not nic.get("io_vcglink"):
                    nic["io_vcglink"] = str(dev["io_vcglink"])
                elif dev.get("vcglink") and not nic.get("io_vcglink"):
                    nic["io_vcglink"] = str(dev["vcglink"])
                if dev.get("speed_gbps"):
                    try:
                        matched_speed = float(dev["speed_gbps"])
                    except Exception:
                        pass

            # Fallback if name is still generic/unfriendly but model or part number is present
            cur_pn = str(nic.get("part_number") or "").strip()
            slot_val = nic.get("slot") or ""
            if not slot_val:
                m_slot = re.search(r"\b(Slot\s+[0-9a-zA-Z_]+)\b", str(nic.get("name") or ""), re.I)
                if m_slot:
                    slot_val = m_slot.group(1).title()
                else:
                    m_id_slot = re.search(r"\bSlot\.([0-9a-zA-Z_]+)\b", str(nic.get("id") or ""), re.I)
                    if m_id_slot:
                        slot_val = f"Slot {m_id_slot.group(1)}"
            if slot_val and not nic.get("slot"):
                nic["slot"] = slot_val

            if is_unfriendly_nic_name(nic.get("name"), cur_pn):
                cand_m = str(nic.get("model") or "").strip()
                if cand_m and not is_unfriendly_nic_name(cand_m, cur_pn):
                    brand = nic.get("manufacturer") or ""
                    if brand and brand.lower() not in cand_m.lower():
                        if not re.match(r"^(?:ConnectX|BlueField|BCM\d+)\b", cand_m, re.I):
                            cand_m = f"{brand} {cand_m}"
                    if slot_val and slot_val.lower() not in cand_m.lower() and f"({slot_val})" not in cand_m:
                        cand_m = f"{cand_m} ({slot_val})"
                    nic["name"] = cand_m
                elif cur_pn and not is_generic_name(cur_pn):
                    if not nic.get("name"):
                        nic["name"] = cur_pn

            # Sanitize reseller OEM marketing suffixes if host OEM differs
            sys_mfr = (host_data.get("system") or {}).get("manufacturer") or ""
            if nic.get("name"):
                nic["name"] = clean_oem_adapter_title(
                    nic["name"],
                    host_mfg=sys_mfr,
                    adapter_mfg=nic.get("manufacturer", ""),
                    part_number=str(nic.get("part_number") or ""),
                )

            # Check if adapter or all its ports have 0/None speed
            ports = nic.get("ports") or []
            if not ports and (nic.get("is_cna") or nic.get("is_vic") or nic.get("cna_family") == "cisco_vic" or "MLOM" in str(nic.get("id", "")).upper()):
                eff_spd = float(nic.get("speed_gbps") or 0.0)
                if eff_spd <= 0:
                    cand_text = f"{nic.get('name', '')} {nic.get('model', '')} {nic.get('id', '')}"
                    m_speeds = re.findall(r"\b(400|200|100|50|40|25|10|1)\s*(?:G(?:bE|b|E)?|Gigabit)\b", cand_text, re.IGNORECASE)
                    if m_speeds:
                        eff_spd = max(float(x) for x in m_speeds)
                if eff_spd > 0:
                    val = int(eff_spd) if eff_spd == int(eff_spd) else round(eff_spd, 2)
                    nic["speed_gbps"] = val
                    synth_port = {
                        "port_id": 1,
                        "link_status": "Up",
                        "link_reported": True,
                        "speed_source": "VIC Fabric Link",
                        "current_speed_gbps": val,
                        "mac_address": "",
                        "transceiver_identifier": "Chassis Fabric Backplane",
                        "transceiver_interface": "Internal KR/CR Fabric",
                        "transceiver_vendor": "Cisco",
                        "transceiver_part_number": nic.get("part_number") or "",
                        "transceiver_serial": "",
                    }
                    nic["ports"] = [synth_port]
                    ports = nic["ports"]

            max_port_speed = max((float(p.get("current_speed_gbps") or p.get("speed_gbps") or 0) for p in ports if isinstance(p, dict)), default=0.0)
            nic_speed = float(nic.get("speed_gbps") or 0.0)

            if max_port_speed <= 0 and nic_speed <= 0:
                if matched_speed <= 0:
                    cand_text = f"{matched_model} {nic.get('name', '')} {nic.get('model', '')} {nic.get('id', '')}"
                    m_speeds = re.findall(r"\b(400|200|100|50|40|25|10|1)\s*(?:G(?:bE|b|E)?|Gigabit)\b", cand_text, re.IGNORECASE)
                    if m_speeds:
                        matched_speed = max(float(x) for x in m_speeds)
                    elif re.search(r"\b(?:Gigabit|GbE|1000Base)\b", cand_text, re.IGNORECASE) or re.search(r"\b(?:I350[A-Z0-9]*|I340[A-Z0-9]*|I210[A-Z0-9]*|I211[A-Z0-9]*|BCM5720|BCM5719|5720[-_]?[tT]|NetXtreme)\b", cand_text, re.IGNORECASE):
                        matched_speed = 1.0
                    elif re.search(r"\b(?:X550[A-Z0-9]*|X540[A-Z0-9]*|X520[A-Z0-9]*|BCM57810)\b", cand_text, re.IGNORECASE):
                        matched_speed = 10.0
                    elif re.search(r"\b(?:ConnectX[-_]?[56]|CX[-_]?[56])\b", cand_text, re.IGNORECASE):
                        matched_speed = 100.0
                    elif re.search(r"\b(?:ConnectX[-_]?4|CX[-_]?4)\b", cand_text, re.IGNORECASE):
                        matched_speed = 25.0

                if matched_speed > 0:
                    int_or_float = int(matched_speed) if matched_speed == int(matched_speed) else round(matched_speed, 2)
                    nic["speed_gbps"] = int_or_float
                    for p in ports:
                        if isinstance(p, dict):
                            p_spd = float(p.get("current_speed_gbps") or p.get("speed_gbps") or 0)
                            if p_spd <= 0:
                                p["current_speed_gbps"] = int_or_float
                                if "speed_gbps" in p:
                                    p["speed_gbps"] = int_or_float
            elif max_port_speed > 0 and nic_speed <= 0:
                nic["speed_gbps"] = int(max_port_speed) if max_port_speed == int(max_port_speed) else round(max_port_speed, 2)

            # If adapter has a known speed, ensure 0-speed ports inherit it
            eff_nic_speed = float(nic.get("speed_gbps") or 0.0)
            if eff_nic_speed > 0:
                val = int(eff_nic_speed) if eff_nic_speed == int(eff_nic_speed) else round(eff_nic_speed, 2)
                for p in ports:
                    if isinstance(p, dict):
                        p_spd = float(p.get("current_speed_gbps") or p.get("speed_gbps") or 0)
                        if p_spd <= 0:
                            p["current_speed_gbps"] = val
                            if "speed_gbps" in p:
                                p["speed_gbps"] = val

            # Cascade port speed down to virtual interfaces / partitions if missing
            parts = nic.get("vic_virtual_interfaces") or nic.get("npar_partitions") or []
            if isinstance(parts, list):
                eff_speed = max_port_speed if max_port_speed > 0 else float(nic.get("speed_gbps") or 0.0)
                if eff_speed > 0:
                    for part in parts:
                        if isinstance(part, dict) and float(part.get("speed_gbps") or 0.0) <= 0.0:
                            part["speed_gbps"] = int(eff_speed) if eff_speed == int(eff_speed) else round(eff_speed, 2)

            # Optical Transceiver DDM Signal Health Evaluation
            for p in ports:
                if not isinstance(p, dict):
                    continue
                finding = evaluate_optical_link_health(p)
                if finding:
                    p["optical_warning"] = finding
                    p["optical_signal_warning"] = finding
                    p["optical_finding"] = finding
                    p["ddm_warning"] = finding
                    rx_p = p.get("rx_power_dbm")
                    if rx_p is None:
                        rx_p = p.get("transceiver_rx_power_dbm")
                    try:
                        p["optical_signal_health"] = "critical" if (rx_p is not None and float(rx_p) < -13.0) else "marginal"
                    except (ValueError, TypeError):
                        p["optical_signal_health"] = "marginal"
                    p["optical_health"] = p["optical_signal_health"]
                    if finding not in host_data.setdefault("optical_warnings", []):
                        host_data["optical_warnings"].append(finding)
                    if finding not in host_data.setdefault("optical_findings", []):
                        host_data["optical_findings"].append(finding)
                elif p.get("rx_power_dbm") is not None or p.get("transceiver_rx_power_dbm") is not None:
                    rx_p = p.get("rx_power_dbm") if p.get("rx_power_dbm") is not None else p.get("transceiver_rx_power_dbm")
                    try:
                        if float(rx_p) >= -10.0:
                            p["optical_signal_health"] = "good"
                            p["optical_health"] = "good"
                    except (ValueError, TypeError):
                        pass

            # PCIe Link Health & Degradation Evaluation
            link_health = evaluate_pcie_link_health(nic)
            if link_health.get("degraded"):
                finding = link_health["finding"]
                nic["pcie_link_eval"] = link_health
                nic["pcie_link_finding"] = finding
                nic["pcie_link_remediation"] = link_health["remediation"]
                nic["downgraded"] = True
                nic["downgrade_reason"] = finding
                nic["downgrade_badge"] = link_health["badge"]
                if finding not in host_data.get("pcie_link_warnings", []):
                    host_data.setdefault("pcie_link_warnings", []).append(finding)
                    host_data.setdefault("warnings", []).append(finding)


def enrich_io_link_health(host_data: Dict[str, Any]) -> None:
    """Append FC, PCIe, GPU and telemetry findings after the NIC findings."""
    # 7b. FC HBA PCIe Link Health Evaluation
    fc_hbas = host_data.get("fc_hbas")
    if isinstance(fc_hbas, list):
        for hba in fc_hbas:
            if not isinstance(hba, dict):
                continue
            if hba.get("manufacturer"):
                hba["manufacturer"] = normalize_component_manufacturer(hba.get("manufacturer"))
            link_health = evaluate_pcie_link_health(hba)
            if link_health.get("degraded"):
                finding = link_health["finding"]
                hba["pcie_link_eval"] = link_health
                hba["pcie_link_finding"] = finding
                hba["pcie_link_remediation"] = link_health["remediation"]
                hba["downgraded"] = True
                hba["downgrade_reason"] = finding
                hba["downgrade_badge"] = link_health["badge"]
                if finding not in host_data.get("pcie_link_warnings", []):
                    host_data.setdefault("pcie_link_warnings", []).append(finding)
                    host_data.setdefault("warnings", []).append(finding)

    # 7c. PCIe Device Link Health Evaluation
    pcie_devs = host_data.get("pcie_devices")
    if isinstance(pcie_devs, list):
        for pdev in pcie_devs:
            if not isinstance(pdev, dict):
                continue
            p_class = str(pdev.get("device_class") or "").upper()
            if p_class in ("BRIDGE", "PROCESSOR"):
                continue
            link_health = evaluate_pcie_link_health(pdev)
            if link_health.get("degraded"):
                finding = link_health["finding"]
                pdev["pcie_link_eval"] = link_health
                pdev["pcie_link_finding"] = finding
                pdev["pcie_link_remediation"] = link_health["remediation"]
                pdev["downgraded"] = True
                pdev["downgrade_reason"] = finding
                pdev["downgrade_badge"] = link_health["badge"]
                if finding not in host_data.get("pcie_link_warnings", []):
                    host_data.setdefault("pcie_link_warnings", []).append(finding)
                    host_data.setdefault("warnings", []).append(finding)

    # 7d. GPU Accelerator PCIe Link & Signal Health Evaluation
    gpus = host_data.get("gpu_accelerators")
    if isinstance(gpus, list):
        for gpu in gpus:
            if not isinstance(gpu, dict):
                continue
            link_health = evaluate_pcie_link_health(gpu)
            if link_health.get("degraded"):
                finding = link_health["finding"]
                gpu["pcie_link_eval"] = link_health
                gpu["pcie_link_finding"] = finding
                gpu["pcie_link_remediation"] = link_health["remediation"]
                gpu["downgraded"] = True
                gpu["downgrade_reason"] = finding
                gpu["downgrade_badge"] = link_health["badge"]
                if finding not in host_data.get("pcie_link_warnings", []):
                    host_data.setdefault("pcie_link_warnings", []).append(finding)
                    host_data.setdefault("warnings", []).append(finding)
                if link_health.get("signal_severity") == "critical":
                    if finding not in host_data.setdefault("critical_findings", []):
                        host_data["critical_findings"].append(finding)

    # 7e. TelemetryService PCIe Error Evaluation
    io_tel = host_data.get("io_telemetry") or {}
    pcie_tel = io_tel.get("pcie_telemetry") or {}
    if isinstance(pcie_tel, dict):
        rec_errs = pcie_tel.get("pcie_switch_recovery_errors") or 0
        if rec_errs > 0:
            finding = f"PCIe Switch Signal Degradation: {rec_errs} Switch Port Recovery/Retrain Error(s) detected via TelemetryService."
            if finding not in host_data.get("pcie_link_warnings", []):
                host_data.setdefault("pcie_link_warnings", []).append(finding)
                host_data.setdefault("warnings", []).append(finding)
        bad_tlp = pcie_tel.get("pcie_switch_bad_tlp_errors") or 0
        if bad_tlp > 0:
            finding = f"PCIe Switch Signal Degradation: {bad_tlp} Bad TLP Frame Error(s) detected via TelemetryService."
            if finding not in host_data.get("pcie_link_warnings", []):
                host_data.setdefault("pcie_link_warnings", []).append(finding)
                host_data.setdefault("warnings", []).append(finding)
