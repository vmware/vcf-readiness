"""Pure port normalization, speed evidence and final adapter contracts."""
import re
from typing import Any, Optional

from vcf_hci.collector.network_identity import _clean_mac_address
from vcf_hci.logging_utils import get_nested


def _evaluate_npar_partitions(partitions: list, port_count: int = 1, is_vic: bool = False) -> bool:
    """Determine if a list of partition/function dicts represents genuine NPAR.

    True NPAR is present when:
      1. Multiple distinct functions/partitions map to the SAME physical port
         (e.g., NIC.Slot.2-1-1 and NIC.Slot.2-1-2, or partition index >= 2).
      2. Any partition has a carved, non-standard speed
         (e.g., 2, 4, 6, 8 Gbps; not standard 1/2.5/5/10/25/40/50/100/200/400 GbE).
      3. Sibling partitions share a physical port with explicit bandwidth allocations < 100%.

    Cisco VIC virtual interfaces (vNIC/vHBA) are hardware-virtualized ASIC endpoints with
    dedicated queues and native nenic/fnic drivers, and are excluded from NPAR classification.
    """
    if is_vic or not partitions or len(partitions) < 2:
        return False

    # Check if partitions follow Cisco VIC naming and architecture
    if all(re.match(r"^(?:eth|fc|vnic|vhba)\d+$", str(p.get("partition_id") or "").strip(), re.I) for p in partitions):
        return False

    # Check for carved non-standard Ethernet speeds
    standard_speeds = {1.0, 2.5, 5.0, 10.0, 25.0, 40.0, 50.0, 100.0, 200.0, 400.0}
    for p in partitions:
        spd = float(p.get("speed_gbps") or 0.0)
        if 10.2 <= spd <= 10.3:
            spd = 10.0
        elif 20.4 <= spd <= 20.6:
            spd = 20.0
        elif 25.5 <= spd <= 25.7:
            spd = 25.0
        if spd > 0.0 and spd not in standard_speeds:
            return True

    # Count distinct partition IDs
    unique_pids = {str(p.get("partition_id") or "").strip() for p in partitions if str(p.get("partition_id") or "").strip()}
    if len(unique_pids) < 2:
        return False

    # Group partitions by physical port identifier
    port_map = {}
    port_distinct_nums = {}
    port_distinct_ids = {}

    for p in partitions:
        pid = str(p.get("partition_id") or "").strip()
        if not pid:
            continue
        p_port = str(p.get("physical_port") or p.get("physical_port_assignment") or "").strip()
        if p_port:
            phys_port = p_port.split("/")[-1].upper()
            part_num = "1"
        else:
            # Match standard vendor partition schemes:
            # Dell: NIC.Slot.2-1-1 -> port "NIC.Slot.2-1", part "1"
            # HPE: LOM:1:1 -> port "LOM:1", part "1"
            # Cisco: Port-1-1 -> port "Port-1", part "1"
            m = re.match(r"^(.*?[-_.:](?:P|Port|p)?\d+)[-_.:](\d+)$", pid, re.I)
            if not m:
                m = re.match(r"^(.*?)[-_.:](\d+)$", pid, re.I)
            if m:
                phys_port = m.group(1).upper()
                part_num = m.group(2)
            else:
                phys_port = pid.upper()
                part_num = "1"

        port_map.setdefault(phys_port, []).append((part_num, p))
        port_distinct_nums.setdefault(phys_port, set()).add(part_num)
        port_distinct_ids.setdefault(phys_port, set()).add(pid.upper())

    # If any physical port has 2 or more distinct partitions, or partition index > 1, it is genuine NPAR
    for phys_port, distinct_nums in port_distinct_nums.items():
        if len(distinct_nums) >= 2:
            return True
        if len(port_distinct_ids.get(phys_port, set())) >= 2:
            return True
        for pnum in distinct_nums:
            try:
                if int(pnum) > 1:
                    return True
            except (ValueError, TypeError):
                pass

        plist = port_map.get(phys_port, [])
        for pnum, pdata in plist:
            bw = pdata.get("allocated_pct")
            if bw is not None:
                try:
                    if 0 < float(bw) < 100 and (len(port_distinct_ids.get(phys_port, set())) > 1 or len(unique_pids) > port_count):
                        return True
                except (ValueError, TypeError):
                    pass

    return bool(
        port_count > 0
        and len(unique_pids) > port_count
        and len(port_distinct_ids) <= port_count
    )


def link_fields_from_payload(payload: Any) -> dict:
    """Copy permanent MAC, MTU, duplex, and autoneg already present on a port."""
    if not isinstance(payload, dict):
        return {}
    ethernet = payload.get("Ethernet") if isinstance(payload.get("Ethernet"), dict) else {}
    link_cfg = payload.get("LinkConfiguration") if isinstance(payload.get("LinkConfiguration"), dict) else {}
    permanent = _clean_mac_address(
        payload.get("PermanentMACAddress")
        or ethernet.get("PermanentMACAddress")
        or ""
    )
    mtu = payload.get("MTUSize")
    if mtu in (None, ""):
        mtu = ethernet.get("MTUSize")
    duplex = payload.get("FullDuplex")
    if duplex is None:
        duplex = ethernet.get("FullDuplex")
    autoneg = payload.get("AutoNeg")
    if autoneg is None:
        autoneg = link_cfg.get("AutoSpeedNegotiationEnabled")
    if autoneg is None:
        autoneg = ethernet.get("AutoNeg")
    fields = {}
    if permanent:
        fields["permanent_mac_address"] = permanent
    if mtu not in (None, "", 0):
        fields["mtu"] = mtu
    if isinstance(duplex, bool):
        fields["full_duplex"] = duplex
    if isinstance(autoneg, bool):
        fields["auto_neg"] = autoneg
    return fields


def extract_nic_speed_gbps(port: dict, adapter: dict, resolved_name: str = "") -> float:
    """Extract NIC speed in Gbps with fallbacks for down links / rated speeds."""
    # 1. Active current link speed
    cur_gbps = port.get("CurrentSpeedGbps")
    if cur_gbps and float(cur_gbps) > 0:
        return float(cur_gbps)
    cur_mbps = port.get("CurrentLinkSpeedMbps")
    if cur_mbps and float(cur_mbps) > 0:
        c_val = float(cur_mbps)
        if 10200 <= c_val <= 10300:
            return 10.0
        if 20400 <= c_val <= 20600:
            return 20.0
        if 25500 <= c_val <= 25700:
            return 25.0
        return c_val / 1000.0

    # Cisco VIC Port OEM telemetry
    cisco_vic = get_nested(port, "Oem", "Cisco", "VicPort", default={}) or get_nested(port, "Oem", "CIMC", "VicPort", default={})
    if isinstance(cisco_vic, dict) and cisco_vic:
        oper_mbps = cisco_vic.get("OperatingLinkSpeedMbps") or cisco_vic.get("OperLinkSpeedMbps")
        if oper_mbps and float(oper_mbps) > 0:
            return float(oper_mbps) / 1000.0
        admin_spd = str(cisco_vic.get("AdminLinkSpeed") or "").strip().upper()
        m_admin = re.search(r"\b(100|40|25|10|1)\s*G?\b", admin_spd)
        if m_admin:
            return float(m_admin.group(1))
        conn_type = str(cisco_vic.get("ConnectorType") or "").strip().upper()
        if "100" in conn_type:
            return 100.0
        if "40" in conn_type:
            return 40.0
        if "25" in conn_type:
            return 25.0
        if "10" in conn_type:
            return 10.0

    # 2. Max capability speed on port or adapter
    max_gbps = port.get("MaxSpeedGbps") or adapter.get("MaxSpeedGbps")
    if max_gbps and float(max_gbps) > 0:
        return float(max_gbps)
    max_mbps = (
        port.get("MaxSpeedMbps")
        or adapter.get("MaxSpeedMbps")
        or port.get("SpeedMbps")
        or adapter.get("SpeedMbps")
    )
    if max_mbps and float(max_mbps) > 0:
        m_val = float(max_mbps)
        if 10200 <= m_val <= 10300:
            return 10.0
        if 20400 <= m_val <= 20600:
            return 20.0
        if 25500 <= m_val <= 25700:
            return 25.0
        return m_val / 1000.0

    # 3. Supported speeds list
    supp = port.get("SupportedSpeedsGbps") or adapter.get("SupportedSpeedsGbps") or []
    if isinstance(supp, list) and supp:
        valid = []
        for s in supp:
            try:
                if float(s or 0) > 0:
                    valid.append(float(s))
            except Exception:
                pass
        if valid:
            return max(valid)

    # 4. Name regex matching for common NIC speeds (25G, 10G, 100G, 40G, 1G)
    port_id_str = str(port.get("Id") or port.get("port_id") or "")
    search_str = f"{resolved_name} {adapter.get('Name','')} {adapter.get('Model','')} {adapter.get('Id','')} {adapter.get('Description','')} {port.get('Name','')} {port.get('Description','')} {port_id_str}"

    # Dual-rate combo NDC ports (e.g. Dell "2P X550/2P I350" -> ports 1-2 are 10G, ports 3-4 are 1G)
    if "X550" in search_str and "I350" in search_str:
        if re.search(r"[-_.]?[34]$", port_id_str):
            return 1.0
        if re.search(r"[-_.]?[12]$", port_id_str):
            return 10.0

    matches = re.findall(r"\b(400|200|100|50|40|25|10|1)\s*(?:G(?:bE|b|E)?|Gigabit)\b", search_str, re.IGNORECASE)
    if matches:
        try:
            return max(float(x) for x in matches)
        except Exception:
            pass

    # 5. Bare Gigabit, GbE, 1000Base
    if re.search(r"\b(?:Gigabit|GbE|1000Base(?:-[A-Z0-9]+)?)\b", search_str, re.IGNORECASE):
        return 1.0

    # 6. Controller family heuristics for down-link ports
    # 1GbE: Intel I350, I340, I210, I211; Broadcom BCM5720, BCM5719, 5720-t, NetXtreme
    if re.search(r"\b(?:I350[A-Z0-9]*|I340[A-Z0-9]*|I210[A-Z0-9]*|I211[A-Z0-9]*|BCM5720|BCM5719|5720[-_]?[tT]|NetXtreme)\b", search_str, re.IGNORECASE):
        return 1.0

    # 10GbE: Intel X550, X540, X520; Broadcom BCM57810
    if re.search(r"\b(?:X550[A-Z0-9]*|X540[A-Z0-9]*|X520[A-Z0-9]*|BCM57810)\b", search_str, re.IGNORECASE):
        return 10.0

    # 100GbE / 25GbE Mellanox / Intel controllers
    if re.search(r"\b(?:ConnectX[-_]?6|CX[-_]?6)\b", search_str, re.IGNORECASE):
        return 100.0
    if re.search(r"\b(?:ConnectX[-_]?5|CX[-_]?5)\b", search_str, re.IGNORECASE):
        return 100.0
    if re.search(r"\b(?:ConnectX[-_]?4|CX[-_]?4)\b", search_str, re.IGNORECASE):
        return 25.0
    # Supermicro/Nutanix NX NIC SKUs often omit Port MaxSpeedMbps
    if re.search(r"\b(?:MCX631102|MCX631102AS|ConnectX[-_]?6\s*Lx)\b", search_str, re.IGNORECASE):
        return 25.0
    if re.search(r"\b(?:AOC-S25GC|AOC-ATG|AOC-A25G)\b", search_str, re.IGNORECASE):
        return 25.0
    if re.search(r"\bE810\b", search_str, re.IGNORECASE):
        return 100.0

    # Cisco VIC model rated speeds
    if re.search(r"\b(?:VIC\s*149[57]|VIC[-_]?149[57]|MLOM[-_]?C100|1497)\b", search_str, re.IGNORECASE):
        return 100.0
    if re.search(r"\b(?:VIC\s*15[24]\d{2}|VIC[-_]?15[24]\d{2})\b", search_str, re.IGNORECASE):
        return 100.0
    if re.search(r"\b(?:VIC\s*145[57]|VIC[-_]?145[57])\b", search_str, re.IGNORECASE):
        return 25.0
    if re.search(r"\b(?:VIC\s*138[57]|VIC[-_]?138[57]|VIC\s*1440|VIC\s*1340)\b", search_str, re.IGNORECASE):
        return 40.0
    if re.search(r"\b(?:VIC\s*122[57]|VIC[-_]?122[57])\b", search_str, re.IGNORECASE):
        return 10.0

    return 0.0


def network_port_mac(port: dict) -> str:
    """Resolve the original port address precedence before OEM transceiver acquisition."""
    assoc_macs = (
        get_nested(port, "Ethernet", "AssociatedMACAddresses")
        or port.get("AssociatedNetworkAddresses")
        or get_nested(port, "Oem", "Cisco", "AssociatedNetworkAddresses")
        or get_nested(port, "Oem", "CIMC", "AssociatedNetworkAddresses")
        or get_nested(port, "Oem", "Cisco", "VicPort", "AssociatedNetworkAddresses")
        or get_nested(port, "Oem", "CIMC", "VicPort", "AssociatedNetworkAddresses")
        or []
    )
    if isinstance(assoc_macs, str):
        assoc_macs = [assoc_macs]
    port_mac = _clean_mac_address(
        assoc_macs[0]
        if (isinstance(assoc_macs, list) and assoc_macs)
        else (
            port.get("MACAddress")
            or port.get("MacAddress")
            or get_nested(port, "Oem", "Cisco", "VicPort", "MacAddress")
            or get_nested(port, "Oem", "CIMC", "VicPort", "MacAddress")
            or get_nested(port, "Oem", "Cisco", "MacAddress")
            or get_nested(port, "Oem", "CIMC", "MacAddress")
            or ""
        )
    )
    return port_mac


def parse_network_port(port: dict, idx: int, final_speed: float, port_mac: str, t_info: dict) -> dict:
    """Normalize supplied port facts without fetching resources or calling OEM hooks."""
    port_id = str(
        port.get("Id")
        or get_nested(port, "Oem", "Hpe", "PortNumber")
        or port.get("PortNumber")
        or port.get("PhysicalPortNumber")
        or idx
    )
    raw_link = port.get("LinkStatus")
    has_explicit_link = (
        raw_link is not None and str(raw_link).strip() != ""
    ) or bool(port.get("CurrentSpeedGbps")) or bool(port.get("CurrentLinkSpeedMbps"))

    link_status_raw = str(raw_link or "Down").strip()
    link_status = (
        "Up" if link_status_raw.lower() in ("up", "linkup")
        else ("Down" if link_status_raw.lower() in ("down", "linkdown", "nolink", "no_link", "notconnected")
        else link_status_raw)
    )
    speed_source = "unreported" if not has_explicit_link else ("current_speed_gbps" if link_status == "Up" else "capability")
    port_record = {
        "port_id": port_id,
        "link_status": link_status,
        "current_speed_gbps": int(final_speed) if final_speed == int(final_speed) else round(final_speed, 2),
        "mac_address": port_mac,
        "link_reported": has_explicit_link,
        "speed_source": speed_source,
        "transceiver_identifier": t_info.get("identifier_type") or "",
        "transceiver_interface": t_info.get("interface_type") or "",
        "transceiver_vendor": t_info.get("vendor_name") or "",
        "transceiver_part_number": t_info.get("part_number") or "",
        "transceiver_serial": t_info.get("serial_number") or "",
        "rx_power_dbm": t_info.get("rx_power_dbm"),
        "tx_power_dbm": t_info.get("tx_power_dbm"),
        "temperature_c": t_info.get("temperature_c"),
        "transceiver_temperature_c": t_info.get("temperature_c"),
        "laser_bias_current_ma": t_info.get("laser_bias_current_ma"),
        "voltage_v": t_info.get("voltage_v"),
    }
    port_record.update(link_fields_from_payload(port))
    return port_record


def finalize_network_adapters(nic_list: list, license_blocked_note: Optional[str]) -> list:
    """Finalize NPAR/VIC aliases, sort ports and annotate exactly once after discovery."""
    # Clean up npar_partitions on unpartitioned adapters so native NICs don't retain partition artifacts
    for nic in nic_list:
        nic_parts = nic.get("npar_partitions")
        nic_parts_list = nic_parts if isinstance(nic_parts, list) else []
        nic_ports = nic.get("ports")
        nic_ports_len = len(nic_ports) if isinstance(nic_ports, (list, tuple)) else 0
        if nic.get("is_vic_virtual") or nic.get("cna_family") == "cisco_vic" or "VIC" in str(nic.get("name", "")).upper():
            nic["is_npar"] = False
            nic["is_vic_virtual"] = bool(nic_parts_list)
            nic["vic_virtual_interfaces"] = nic_parts_list
        elif nic.get("npar_enabled") is False:
            nic["is_npar"] = False
            nic["npar_partitions"] = []
        else:
            nic["is_npar"] = _evaluate_npar_partitions(nic_parts_list, nic_ports_len)
            if not nic["is_npar"]:
                nic["npar_partitions"] = []
        if isinstance(nic.get("ports"), list):
            nic["ports"].sort(key=lambda p: str(p.get("port_id") or ""))

    # Surface a license-blocked sentinel so the HTML renderer can show a
    # specific warning instead of the generic "no NICs discovered" message.
    if license_blocked_note and not nic_list:
        nic_list.append({
            "id": "_license_blocked",
            "name": f"⚠️ Network API Unavailable — {license_blocked_note}",
            "_license_blocked": True,
            "manufacturer": "",
            "part_number": "",
            "firmware_version": "N/A",
            "ports": [],
        })
    from vcf_hci.collector.hardware_findings import annotate_port_contract
    annotate_port_contract(nic_list)
    return nic_list
