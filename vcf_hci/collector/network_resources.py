"""Collector-bound discovery, expanded cache priming and port/function acquisition."""
import logging
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Any, Optional, Tuple

from vcf_hci.collector.contracts import NetworkCollector
from vcf_hci.collector.network_identity import _clean_mac_address
from vcf_hci.collector.network_ports import (
    _evaluate_npar_partitions,
    link_fields_from_payload,
    network_port_mac,
    parse_network_port,
)
from vcf_hci.logging_utils import get_nested

logger = logging.getLogger("vcf_assess")


def linked_adapter_ports(collector: NetworkCollector, adapter: dict) -> list:
    """Recover ports through explicit links only, bounded to 32 requests/resources."""
    pending = [adapter]
    seen = set()
    ports = []
    remaining = 32
    while pending and remaining > 0:
        resource = pending.pop(0)
        if not isinstance(resource, dict):
            continue
        if resource.get("error"):
            continue
        links = resource.get("Links") or {}
        containers = [resource, links]
        for controller in resource.get("Controllers") or []:
            if isinstance(controller, dict):
                containers.append(controller.get("Links") or {})
        for container in containers:
            for field in ("NetworkAdapter", "NetworkPorts", "Ports"):
                values = container.get(field)
                if isinstance(values, dict):
                    values = values.get("Members") or [values]
                if not isinstance(values, list):
                    continue
                for value in values:
                    if remaining <= 0:
                        break
                    if not isinstance(value, dict):
                        continue
                    uri = value.get("@odata.id")
                    if uri and uri in seen:
                        continue
                    remaining -= 1
                    if uri:
                        seen.add(uri)
                    payload = collector._get(uri, timeout=5, critical=False) if uri and len(value) <= 2 else value
                    if not isinstance(payload, dict) or payload.get("error"):
                        continue
                    if field == "NetworkAdapter":
                        pending.append(payload)
                    elif isinstance(payload.get("Members"), list):
                        pending.append({"Ports": payload["Members"]})
                    else:
                        ports.append(payload)
    return ports


def network_adapter_endpoints(chassis_uri: Optional[str], sys_uri: Optional[str]) -> list:
    """Retain physical-adapter and logical-interface fallback precedence."""
    endpoints = []
    if chassis_uri:
        endpoints.append(f"{chassis_uri}/NetworkAdapters")
    if sys_uri:
        endpoints.append(f"{sys_uri}/BaseNetworkAdapters")
        endpoints.append(f"{sys_uri}/NetworkInterfaces")
        endpoints.append(f"{sys_uri}/EthernetInterfaces")

    return endpoints


def prime_network_cache(self: NetworkCollector) -> Any:
    """Prime existing expanded caches and return the original bound expansion callable."""
    # Fast-path: probe expanded EthernetInterfaces early to populate request cache
    fetch_expand_fn = getattr(self, "_fetch_expanded_collection", None)
    if getattr(self, "vendor", "") in ("supermicro", "quanta"):
        self.expand_supported = False
    if callable(fetch_expand_fn) and getattr(self, "expand_supported", False) and self.sys_uri:
        fetch_expand_fn(f"{self.sys_uri}/EthernetInterfaces")

    # Fast-path: probe expanded Chassis NetworkAdapters early if supported
    if callable(fetch_expand_fn) and getattr(self, "expand_supported", False) and self.chassis_uri:
        chassis_net_ep = f"{self.chassis_uri}/NetworkAdapters"
        expandable_map: Any = self.oem_expandable_collections() if hasattr(self, "oem_expandable_collections") else {}
        req_levels = 1
        if hasattr(expandable_map, "get_levels"):
            req_levels = expandable_map.get_levels(chassis_net_ep, 1)
        elif getattr(self, "expand_max_levels", 1) >= 2 and ("NetworkAdapters" in expandable_map or chassis_net_ep in expandable_map):
            req_levels = 2
        net_coll = fetch_expand_fn(chassis_net_ep, levels=req_levels)
        if isinstance(net_coll, dict) and isinstance(net_coll.get("Members"), list):
            for m in net_coll["Members"]:
                if not isinstance(m, dict):
                    continue
                m_uri = m.get("@odata.id")
                if m_uri and len(m) > 1 and hasattr(self, "_populate_request_cache"):
                    self._populate_request_cache(m_uri, m)

                # Cache NetworkPorts collection and subordinate port items
                raw_np = (
                    m.get("NetworkPorts")
                    or m.get("Ports")
                    or m.get("PhysicalPorts")
                    or get_nested(m, "Oem", "Cisco", "NetworkPorts")
                    or get_nested(m, "Oem", "Cisco", "Ports")
                    or get_nested(m, "Oem", "CIMC", "NetworkPorts")
                    or get_nested(m, "Oem", "CIMC", "Ports")
                )
                if isinstance(raw_np, dict):
                    np_uri = raw_np.get("@odata.id")
                    if np_uri and len(raw_np) > 1 and hasattr(self, "_populate_request_cache"):
                        self._populate_request_cache(np_uri, raw_np)
                    p_members = raw_np.get("Members") or raw_np.get("Ports") or []
                    if isinstance(p_members, list):
                        for p in p_members:
                            if isinstance(p, dict) and p.get("@odata.id") and len(p) > 1 and hasattr(self, "_populate_request_cache"):
                                if not p.get("AssociatedNetworkAddresses"):
                                    oem_addrs = (
                                        get_nested(p, "Oem", "Cisco", "AssociatedNetworkAddresses")
                                        or get_nested(p, "Oem", "CIMC", "AssociatedNetworkAddresses")
                                        or get_nested(p, "Oem", "Cisco", "VicPort", "AssociatedNetworkAddresses")
                                        or get_nested(p, "Oem", "CIMC", "VicPort", "AssociatedNetworkAddresses")
                                    )
                                    if oem_addrs:
                                        p["AssociatedNetworkAddresses"] = oem_addrs if isinstance(oem_addrs, list) else [oem_addrs]
                                    else:
                                        v_mac = (
                                            get_nested(p, "Oem", "Cisco", "VicPort", "MacAddress")
                                            or get_nested(p, "Oem", "CIMC", "VicPort", "MacAddress")
                                            or get_nested(p, "Oem", "Cisco", "MacAddress")
                                            or get_nested(p, "Oem", "CIMC", "MacAddress")
                                        )
                                        if v_mac:
                                            p["AssociatedNetworkAddresses"] = [v_mac] if isinstance(v_mac, str) else v_mac
                                self._populate_request_cache(p["@odata.id"], p)
                elif isinstance(raw_np, list):
                    for p in raw_np:
                        if isinstance(p, dict) and p.get("@odata.id") and len(p) > 1 and hasattr(self, "_populate_request_cache"):
                            if not p.get("AssociatedNetworkAddresses"):
                                oem_addrs = (
                                    get_nested(p, "Oem", "Cisco", "AssociatedNetworkAddresses")
                                    or get_nested(p, "Oem", "CIMC", "AssociatedNetworkAddresses")
                                    or get_nested(p, "Oem", "Cisco", "VicPort", "AssociatedNetworkAddresses")
                                    or get_nested(p, "Oem", "CIMC", "VicPort", "AssociatedNetworkAddresses")
                                )
                                if oem_addrs:
                                    p["AssociatedNetworkAddresses"] = oem_addrs if isinstance(oem_addrs, list) else [oem_addrs]
                                else:
                                    v_mac = (
                                        get_nested(p, "Oem", "Cisco", "VicPort", "MacAddress")
                                        or get_nested(p, "Oem", "CIMC", "VicPort", "MacAddress")
                                        or get_nested(p, "Oem", "Cisco", "MacAddress")
                                        or get_nested(p, "Oem", "CIMC", "MacAddress")
                                    )
                                    if v_mac:
                                        p["AssociatedNetworkAddresses"] = [v_mac] if isinstance(v_mac, str) else v_mac
                            self._populate_request_cache(p["@odata.id"], p)

                # Cache NetworkDeviceFunctions collection and subordinate function items
                raw_ndf = (
                    m.get("NetworkDeviceFunctions")
                    or get_nested(m, "Oem", "Cisco", "NetworkDeviceFunctions")
                    or get_nested(m, "Oem", "CIMC", "NetworkDeviceFunctions")
                )
                if isinstance(raw_ndf, dict):
                    ndf_uri = raw_ndf.get("@odata.id")
                    if ndf_uri and len(raw_ndf) > 1 and hasattr(self, "_populate_request_cache"):
                        self._populate_request_cache(ndf_uri, raw_ndf)
                    f_members = raw_ndf.get("Members") or raw_ndf.get("NetworkDeviceFunctions") or []
                    if isinstance(f_members, list):
                        for f in f_members:
                            if isinstance(f, dict) and f.get("@odata.id") and len(f) > 1 and hasattr(self, "_populate_request_cache"):
                                self._populate_request_cache(f["@odata.id"], f)
                elif isinstance(raw_ndf, list):
                    for f in raw_ndf:
                        if isinstance(f, dict) and f.get("@odata.id") and len(f) > 1 and hasattr(self, "_populate_request_cache"):
                            self._populate_request_cache(f["@odata.id"], f)

    return fetch_expand_fn


def fetch_network_collection(self: NetworkCollector, ep: str, fetch_expand_fn: Any, expandable_map: Any) -> dict:
    """Fetch one collection using the existing expansion eligibility and level policy."""
    if callable(fetch_expand_fn) and getattr(self, "expand_supported", False):
        if "EthernetInterfaces" in ep:
            coll = fetch_expand_fn(ep) or {}
        elif ep in expandable_map or (ep.endswith("/NetworkAdapters") and not ep.endswith("/BaseNetworkAdapters")):
            req_levels = 1
            if hasattr(expandable_map, "get_levels"):
                req_levels = expandable_map.get_levels(ep, 1)
            elif getattr(self, "expand_max_levels", 1) >= 2:
                req_levels = 2
            coll = fetch_expand_fn(ep, levels=req_levels) or {}
        else:
            coll = self._get(ep) or {}
    else:
        coll = self._get(ep) or {}
    return coll


def collect_adapter_ports(self: NetworkCollector, adapter: dict, adapter_uri: str, resolved_name: str) -> list:
    """Acquire port observations with original cache reuse, worker limits and error containment."""
    dynamic_ports = []
    # ── Physical adapter path (NetworkAdapters / NetworkInterfaces / BaseNetworkAdapters) ──
    raw_ports = (
        adapter.get("PhysicalPorts")
        or adapter.get("FcPorts")
        or adapter.get("NetworkPorts")
        or adapter.get("Ports")
        or get_nested(adapter, "Oem", "Cisco", "NetworkPorts")
        or get_nested(adapter, "Oem", "Cisco", "Ports")
        or get_nested(adapter, "Oem", "CIMC", "NetworkPorts")
        or get_nested(adapter, "Oem", "CIMC", "Ports")
    )
    if isinstance(raw_ports, dict) and isinstance(raw_ports.get("Members"), list):
        port_members = raw_ports.get("Members", [])
    elif isinstance(raw_ports, dict) and isinstance(raw_ports.get("Ports"), list):
        port_members = raw_ports.get("Ports", [])
    elif isinstance(raw_ports, list):
        port_members = raw_ports
    else:
        ports_uri = (
            get_nested(adapter, "NetworkPorts", "@odata.id")
            or get_nested(adapter, "Ports", "@odata.id")
            or get_nested(adapter, "Oem", "Cisco", "NetworkPorts", "@odata.id")
            or get_nested(adapter, "Oem", "Cisco", "Ports", "@odata.id")
            or get_nested(adapter, "Oem", "CIMC", "NetworkPorts", "@odata.id")
            or get_nested(adapter, "Oem", "CIMC", "Ports", "@odata.id")
            or f"{adapter_uri}/NetworkPorts"
        )
        port_members = self._get_members(ports_uri)

    if not port_members:
        port_members = linked_adapter_ports(self, adapter)

    if port_members:
        def _fetch_port(pm):
            port_uri = pm.get("@odata.id") if isinstance(pm, dict) else (pm if isinstance(pm, str) else None)
            if isinstance(pm, dict) and len(pm) > 2:
                return pm
            return self._get(port_uri) if port_uri else (pm if isinstance(pm, dict) else None)

        port_jsons = []
        ports_to_fetch = []
        for pm in port_members:
            if isinstance(pm, dict) and len(pm) > 2 and (
                pm.get("LinkStatus")
                or pm.get("CurrentLinkSpeedMbps")
                or pm.get("AssociatedNetworkAddresses")
                or pm.get("MACAddress")
                or pm.get("Status")
                or pm.get("Id")
                or get_nested(pm, "Oem", "Cisco")
                or get_nested(pm, "Oem", "CIMC")
            ):
                port_jsons.append(pm)
            else:
                p_uri = pm.get("@odata.id") if isinstance(pm, dict) else (pm if isinstance(pm, str) else None)
                if p_uri and hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
                    cached_p = self._request_cache.get(p_uri)
                    if not cached_p and getattr(self, "host_url", ""):
                        cached_p = self._request_cache.get(f"{self.host_url}{p_uri}")
                    if isinstance(cached_p, dict) and len(cached_p) > 2:
                        port_jsons.append(cached_p)
                        continue
                ports_to_fetch.append(pm)

        if ports_to_fetch:
            max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(4), max(1, len(ports_to_fetch)))
            _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
            pool = ThreadPoolExecutor(max_workers=max_w)
            try:
                futures = [pool.submit(_wrap_task(_fetch_port), pm) for pm in ports_to_fetch]
                wait(futures, timeout=15.0)
                for fut in futures:
                    if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                        break
                    try:
                        if fut.done():
                            res = fut.result()
                            if res:
                                port_jsons.append(res)
                    except Exception as p_exc:
                        logger.debug("Error processing NIC port: %s", p_exc)
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

        for idx, port in enumerate(port_jsons, start=1):
            try:
                final_speed = self._extract_nic_speed_gbps(port, adapter, resolved_name)
                port_mac = network_port_mac(port)
                t_info = self.oem_port_transceiver(port) if hasattr(self, "oem_port_transceiver") else {}
                port_record = parse_network_port(port, idx, final_speed, port_mac, t_info)
                dynamic_ports.append(port_record)
            except Exception as p_exc:
                logger.debug("Error parsing NIC port detail: %s", p_exc)

    return dynamic_ports


def collect_network_functions(self: NetworkCollector, adapter: dict, adapter_uri: str) -> list:
    """Acquire function observations with the existing bounded worker/cancellation policy."""
    # ── Check NetworkDeviceFunctions for NPAR partitions & CNA functions ──
    raw_ndf = (
        adapter.get("NetworkDeviceFunctions")
        or get_nested(adapter, "Oem", "Cisco", "NetworkDeviceFunctions")
        or get_nested(adapter, "Oem", "CIMC", "NetworkDeviceFunctions")
    )
    if isinstance(raw_ndf, dict) and isinstance(raw_ndf.get("Members"), list):
        ndf_members = raw_ndf.get("Members", [])
    elif isinstance(raw_ndf, list):
        ndf_members = raw_ndf
    else:
        ndf_uri = (
            get_nested(adapter, "NetworkDeviceFunctions", "@odata.id")
            or get_nested(adapter, "Oem", "Cisco", "NetworkDeviceFunctions", "@odata.id")
            or get_nested(adapter, "Oem", "CIMC", "NetworkDeviceFunctions", "@odata.id")
            or f"{adapter_uri}/NetworkDeviceFunctions"
        )
        ndf_members = self._get_members(ndf_uri)

    ndf_jsons = []
    if ndf_members:
        def _fetch_ndf(nm):
            n_uri = nm.get("@odata.id") if isinstance(nm, dict) else (nm if isinstance(nm, str) else None)
            return self._get(n_uri) if n_uri else (nm if isinstance(nm, dict) else None)

        ndf_to_fetch = []
        for nm in ndf_members:
            if isinstance(nm, dict) and len(nm) > 2 and (
                nm.get("NetDevFuncType")
                or nm.get("Ethernet")
                or nm.get("FibreChannel")
                or nm.get("AssignablePhysicalNetworkPorts")
                or get_nested(nm, "Oem", "Cisco")
                or get_nested(nm, "Oem", "CIMC")
            ):
                ndf_jsons.append(nm)
            else:
                n_uri = nm.get("@odata.id") if isinstance(nm, dict) else (nm if isinstance(nm, str) else None)
                if n_uri and hasattr(self, "_request_cache") and isinstance(self._request_cache, dict):
                    cached_n = self._request_cache.get(n_uri)
                    if not cached_n and getattr(self, "host_url", ""):
                        cached_n = self._request_cache.get(f"{self.host_url}{n_uri}")
                    if isinstance(cached_n, dict) and len(cached_n) > 2:
                        ndf_jsons.append(cached_n)
                        continue
                ndf_to_fetch.append(nm)

        if ndf_to_fetch:
            max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(4), max(1, len(ndf_to_fetch)))
            _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
            pool = ThreadPoolExecutor(max_workers=max_w)
            try:
                futures = [pool.submit(_wrap_task(_fetch_ndf), nm) for nm in ndf_to_fetch]
                wait(futures, timeout=15.0)
                for fut in futures:
                    if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                        break
                    try:
                        if fut.done():
                            res = fut.result()
                            if res:
                                ndf_jsons.append(res)
                    except Exception as n_exc:
                        logger.debug("Error processing NDF: %s", n_exc)
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

    return ndf_jsons


def collect_ethernet_port(self: NetworkCollector, adapter: dict, uid: str, resolved_name: str, dynamic_ports: list) -> None:
    """Acquire OEM transceiver facts and normalize the standalone logical-port fallback."""
    raw_link = adapter.get("LinkStatus")
    has_explicit_link = raw_link is not None and str(raw_link).strip() != ""
    link_status = str(raw_link or "Down").strip()
    if link_status.lower() in ("up", "linkup"):
        link_status = "Up"
    elif link_status.lower() in ("down", "linkdown", "nolink", "no_link", "notconnected"):
        link_status = "Down"
    final_speed = self._extract_nic_speed_gbps(adapter, adapter, resolved_name)
    eth_mac = _clean_mac_address(adapter.get("MACAddress"))
    if link_status or final_speed > 0 or eth_mac:
        t_info = self.oem_port_transceiver(adapter) if hasattr(self, "oem_port_transceiver") else {}
        speed_source = "unreported" if not has_explicit_link else ("current_speed_gbps" if link_status == "Up" else "capability")
        eth_port = {
            "port_id": uid,
            "link_status": link_status,
            "link_reported": has_explicit_link,
            "speed_source": speed_source,
            "current_speed_gbps": int(final_speed) if final_speed == int(final_speed) else round(final_speed, 2),
            "mac_address": eth_mac,
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
        eth_port.update(link_fields_from_payload(adapter))
        dynamic_ports.append(eth_port)


def collect_partition_details(
    self: NetworkCollector, adapter: dict, ndf_jsons: list, dynamic_ports: list, is_vic: bool,
) -> Tuple[list, bool, bool, Any, Any, bool]:
    """Read OEM vNIC facts and return partitions, NPAR/VIC flags and VF limits."""
    npar_partitions = []
    is_npar = False
    is_vic_virtual = False
    adapter_max_speed = max((p.get("current_speed_gbps") or 0 for p in dynamic_ports), default=0)
    if ndf_jsons and (len(ndf_jsons) > len(dynamic_ports) or len(ndf_jsons) >= 2 or is_vic):
        for fn in ndf_jsons:
            fn_id = str(fn.get("Id") or "").strip()
            fn_type = str(fn.get("NetDevFuncType") or "").strip()
            eth_blk = fn.get("Ethernet") or {}
            fc_blk = fn.get("FibreChannel") or {}
            fn_mac = _clean_mac_address(eth_blk.get("MACAddress"))
            fn_bw_pct = (
                get_nested(fn, "Oem", "Dell", "DellNIC", "BandwidthAllocationPercent")
                or get_nested(fn, "Oem", "Dell", "DellNIC", "MaxBandwidthPercent")
                or fn.get("MaxBandwidthPercent")
            )
            fn_speed_mbps = (
                get_nested(fn, "Oem", "Dell", "DellNIC", "SpeedMbps")
                or fn.get("MaxSpeedMbps")
                or eth_blk.get("MaxSpeedMbps")
            )
            if fn_speed_mbps:
                f_spd = float(fn_speed_mbps)
                if 10200 <= f_spd <= 10300:
                    fn_speed_gbps = 10.0
                elif 20400 <= f_spd <= 20600:
                    fn_speed_gbps = 20.0
                elif 25500 <= f_spd <= 25700:
                    fn_speed_gbps = 25.0
                else:
                    fn_speed_gbps = round(f_spd / 1000.0, 2)
            else:
                fn_speed_gbps = 0.0

            phys_port_ref = (
                get_nested(fn, "Links", "PhysicalPortAssignment", "@odata.id")
                or get_nested(fn, "Links", "PhysicalNetworkPortAssignment", "@odata.id")
                or get_nested(fn, "PhysicalPortAssignment", "@odata.id")
                or get_nested(fn, "PhysicalNetworkPortAssignment", "@odata.id")
                or ""
            )
            if not phys_port_ref and fn.get("AssignablePhysicalNetworkPorts"):
                _assign_ports = fn.get("AssignablePhysicalNetworkPorts")
                if isinstance(_assign_ports, list) and _assign_ports:
                    _p0 = _assign_ports[0]
                    phys_port_ref = _p0.get("@odata.id") if isinstance(_p0, dict) else str(_p0)

            # Cisco VIC & OEM VnicConfiguration extraction
            oem_caps = self.oem_vnic_capabilities(fn)
            if not oem_caps:
                cisco_oem = (
                    get_nested(fn, "Oem", "Cisco", default={})
                    or get_nested(fn, "Oem", "CIMC", default={})
                )
                if isinstance(cisco_oem, dict) and cisco_oem.get("VnicConfiguration"):
                    vnic_cfg = cisco_oem.get("VnicConfiguration") or {}
                    eth_cfg = vnic_cfg.get("EthConfiguration") or {}
                    vhba_cfg = vnic_cfg.get("VHBAConfiguration") or {}
                    features = eth_cfg.get("Features") or {}
                    offload = eth_cfg.get("OffloadProfile") or {}
                    rss = eth_cfg.get("RssProfile") or {}
                    oem_caps = {
                        "cdn": eth_cfg.get("Cdn") or "",
                        "uplink_port": vnic_cfg.get("UplinkPort"),
                        "pci_order": vnic_cfg.get("PCIOrder") or "",
                        "cos": vnic_cfg.get("ClassOfService"),
                        "vlan_mode": vnic_cfg.get("VlanMode") or "",
                        "geneve_offload": bool(features.get("GeneveEnabled")),
                        "vxlan_offload": bool(features.get("VxlanEnabled")),
                        "rocev2": bool(features.get("Rocev2Enabled")),
                        "multiqueue": bool(features.get("MultiQueueEnabled")),
                        "tso_enabled": bool(offload.get("TcpSegmentEnabled")),
                        "lro_enabled": bool(offload.get("TcpLargeReceiveEnabled")),
                        "rx_csum": bool(offload.get("TcpRxChecksumEnabled")),
                        "tx_csum": bool(offload.get("TcpTxChecksumEnabled")),
                        "rss_enabled": bool(rss.get("RssEnabled")),
                        "vhba_type": vhba_cfg.get("VHBAType") or [],
                        "max_data_field_size": vhba_cfg.get("MaxDataFieldSize"),
                        "fc_work_queue_ring_size": vhba_cfg.get("FcWorkQueueRingSize"),
                        "fc_recv_queue_ring_size": vhba_cfg.get("FcRecvQueueRingSize"),
                    }

            # Sub-interface speed inheritance from physical uplink
            if fn_speed_gbps <= 0.0:
                matched_port = None
                if phys_port_ref:
                    for p in dynamic_ports:
                        p_uri = p.get("_uri") or ""
                        p_id = str(p.get("port_id") or "")
                        if (p_uri and phys_port_ref == p_uri) or (p_id and phys_port_ref.endswith("/" + p_id)):
                            matched_port = p
                            break
                if not matched_port and "uplink_port" in oem_caps:
                    u_idx = oem_caps.get("uplink_port")
                    if isinstance(u_idx, int) and 0 <= u_idx < len(dynamic_ports):
                        matched_port = dynamic_ports[u_idx]
                if matched_port and matched_port.get("current_speed_gbps"):
                    fn_speed_gbps = float(matched_port["current_speed_gbps"])
                elif adapter_max_speed > 0:
                    fn_speed_gbps = float(adapter_max_speed)

            mtu = eth_blk.get("MTUSize") or 0
            vlan_blk = eth_blk.get("VLAN") or {}
            vlan_id = vlan_blk.get("VLANId") if vlan_blk.get("VLANEnable") else None
            wwnn = fc_blk.get("WWNN") or ""
            wwpn = fc_blk.get("WWPN") or ""

            if fn_id:
                npar_partitions.append({
                    "partition_id": fn_id,
                    "protocol": fn_type or ("FibreChannel" if fc_blk else "Ethernet"),
                    "mac_address": fn_mac,
                    "permanent_mac_address": _clean_mac_address(eth_blk.get("PermanentMACAddress")),
                    "full_duplex": eth_blk.get("FullDuplex") if isinstance(eth_blk.get("FullDuplex"), bool) else None,
                    "auto_neg": eth_blk.get("AutoNeg") if isinstance(eth_blk.get("AutoNeg"), bool) else None,
                    "allocated_pct": fn_bw_pct,
                    "speed_gbps": fn_speed_gbps,
                    "physical_port": phys_port_ref,
                    "cdn": oem_caps.get("cdn", ""),
                    "mtu": mtu,
                    "vlan_id": vlan_id,
                    "vlan_mode": oem_caps.get("vlan_mode", ""),
                    "geneve_offload": oem_caps.get("geneve_offload", False),
                    "vxlan_offload": oem_caps.get("vxlan_offload", False),
                    "rocev2": oem_caps.get("rocev2", False),
                    "multiqueue": oem_caps.get("multiqueue", False),
                    "tso_enabled": oem_caps.get("tso_enabled", False),
                    "lro_enabled": oem_caps.get("lro_enabled", False),
                    "rx_csum": oem_caps.get("rx_csum", False),
                    "tx_csum": oem_caps.get("tx_csum", False),
                    "rss_enabled": oem_caps.get("rss_enabled", False),
                    "wwnn": wwnn,
                    "wwpn": wwpn,
                    "cos": oem_caps.get("cos"),
                    "pci_order": oem_caps.get("pci_order", ""),
                    "vhba_type": oem_caps.get("vhba_type", []),
                })
    ctrl_list = adapter.get("Controllers") or []
    ctrl0 = ctrl_list[0] if isinstance(ctrl_list, list) and ctrl_list else {}
    ctrl_caps = ctrl0.get("ControllerCapabilities") if isinstance(ctrl0, dict) else {}
    npar_info = ctrl_caps.get("NPAR") if isinstance(ctrl_caps, dict) else {}
    npar_enabled_flag = npar_info.get("NparEnabled") if isinstance(npar_info, dict) else None
    vf_info = get_nested(ctrl_caps, "VirtualizationOffload", "VirtualFunction", default={}) or {}
    sriov_dev_max = vf_info.get("DeviceMaxCount")

    adapter_max_vfs = sriov_dev_max or sum(int(fn.get("MaxVirtualFunctions") or 0) for fn in ndf_jsons if fn.get("MaxVirtualFunctions"))
    adapter_vfs_enabled = any(fn.get("VirtualFunctionsEnabled") is True for fn in ndf_jsons) or bool(adapter_max_vfs)

    if is_vic:
        is_npar = False
        is_vic_virtual = bool(npar_partitions)
    elif npar_enabled_flag is False:
        is_npar = False
        is_vic_virtual = False
    else:
        is_npar = _evaluate_npar_partitions(npar_partitions, len(dynamic_ports), is_vic=is_vic)
        is_vic_virtual = False

    return npar_partitions, is_npar, is_vic_virtual, npar_enabled_flag, adapter_max_vfs, adapter_vfs_enabled
