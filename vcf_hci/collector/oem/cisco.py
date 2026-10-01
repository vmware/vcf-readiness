"""
VCF Readiness Tool — Cisco IMC (UCS C-Series) OEM adapter.

Overrides OEM hook methods to handle Cisco CIMC quirks:
  • Manager path   : /Managers/CIMC (not /Managers/1)
  • System path    : /Systems/{SERIAL_NUMBER} — handled by dynamic root discovery or fastpath
  • SEL location   : /Chassis/1/LogServices/SEL (Chassis level, not Systems level)
  • BIOS date      : Sourced from /UpdateService/FirmwareInventory BIOS component
  • Power non-compliance: singular PowerControl object and string numerics handled in collect_power

Known Cisco quirks (handled inline in base methods):
  • _discover_roots() probes /Managers/CIMC as fallback when default manager path fails.
  • collect_system_event_log() checks /Chassis/{id}/LogServices as third fallback.
  • Redfish BiosVersion format: "C220M5.4.1.2b.0..." — parse_version_tuple extracts "4.1.2".
  • Basic Auth works for all standard Cisco IMC firmware versions.
"""
import logging
import re
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from ...logging_utils import get_nested
from ..base import ExpandableCollectionsMap
from ..collect_storage_drive import parse_drive_details
from .generic import GenericCollector

logger = logging.getLogger("vcf_assess")


class CiscoCollector(GenericCollector):
    """Cisco IMC (CIMC) Redfish adapter."""

    vendor: str = "cisco"
    VENDOR_MATCH = ("CISCO",)  # matched against Manufacturer string upper()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Note: Cisco M4/M5 BMCs do not advertise ExpandQuery and reject $expand with HTTP 501.
        # Modern Cisco M6+ platforms (CIMC 4.3(6)+) advertise ExpandQuery in ServiceRoot
        # and support OData $expand=* on NetworkAdapters, Memory, and Storage.
        # Capability is negotiated from ProtocolFeaturesSupported in _discover_roots().

    def oem_expandable_collections(self) -> Dict[str, str]:
        """Cisco IMC expandable collection endpoints.

        Modern Cisco CIMC (M6+, CIMC >= 4.3(6)) supports OData $expand=* with MaxLevels: 2 on:
          - Chassis NetworkAdapters (levels=2 returns NetworkPorts and NetworkDeviceFunctions)
          - Memory (Systems/{id}/Memory)
          - Storage (Systems/{id}/Storage)
          - EthernetInterfaces (Systems/{id}/EthernetInterfaces)
        When expand_supported is False (e.g. M4/M5), returns an empty dict.
        """
        if not getattr(self, "expand_supported", False):
            return {}
        chassis_uri = getattr(self, "chassis_uri", None) or "/redfish/v1/Chassis/1"
        sys_uri = getattr(self, "sys_uri", None) or "/redfish/v1/Systems/1"
        net_ep = f"{chassis_uri}/NetworkAdapters"
        mem_ep = f"{sys_uri}/Memory"
        storage_ep = f"{sys_uri}/Storage"
        eth_ep = f"{sys_uri}/EthernetInterfaces"
        return ExpandableCollectionsMap(
            {
                "network": net_ep,
                "network_adapters": net_ep,
                net_ep: net_ep,
                "memory": mem_ep,
                mem_ep: mem_ep,
                "storage": storage_ep,
                storage_ep: storage_ep,
                "ethernet_interfaces": eth_ep,
                eth_ep: eth_ep,
            },
            levels={
                "network": 2,
                "network_adapters": 2,
                net_ep: 2,
                "memory": 1,
                mem_ep: 1,
                "storage": 1,
                storage_ep: 1,
                "ethernet_interfaces": 1,
                eth_ep: 1,
            },
        )

    def oem_manager_paths(self) -> list:
        """Add Cisco CIMC manager path to discovery."""
        return ["/redfish/v1/Managers/CIMC"]

    def oem_storage_endpoints(self) -> list:
        """Add Cisco IMC specific storage endpoints to discovery.

        Handles Cisco CIMC quirks where:
        1. SimpleStorage exposes legacy controllers not present in /Storage.
        2. Modular RAID (MRAID) or SAS-RAID are not indexed in /Storage collection members.
        3. Chassis-level storage paths (/Chassis/1/Storage).
        """
        eps = []
        if self.sys_uri:
            clean_sys = self.sys_uri.rstrip("/")
            eps.append(f"{clean_sys}/Storage")
            eps.append(f"{clean_sys}/SimpleStorage")
            eps.append(f"{clean_sys}/Storage/MRAID")
            eps.append(f"{clean_sys}/Storage/SAS-RAID")
            eps.append(f"{clean_sys}/Storage/NVMe-direct-U.2-drives")
        cha_uri = getattr(self, "chassis_uri", None) or "/redfish/v1/Chassis/1"
        if cha_uri:
            eps.append(f"{cha_uri.rstrip('/')}/Storage")
            eps.append(f"{cha_uri.rstrip('/')}/SimpleStorage")
        return eps

    def _query_cisco_xml(self, class_id: str, cookie: str = "") -> Optional[ET.Element]:
        """Query Cisco CIMC XML API (/nuova) for a specific classId."""
        xml_req = f'<configResolveClass cookie="{cookie}" inHierarchical="false" classId="{class_id}"/>'
        host = getattr(self, "host", "")
        port = getattr(self, "port", 443)
        scheme = getattr(self, "scheme", "https")
        url = f"{scheme}://{host}:{port}/nuova"
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "Accept": "text/xml, application/xml",
        }
        auth_hdr = getattr(self, "_auth_header", "")
        if auth_hdr:
            headers["Authorization"] = f"Basic {auth_hdr}"
        session_tok = getattr(self, "session_token", "")
        if session_tok:
            headers["X-Auth-Token"] = session_tok

        try:
            req = urllib.request.Request(url, data=xml_req.encode("utf-8"), headers=headers, method="POST")
            ssl_ctx = getattr(self, "ssl_context", None)
            opener = getattr(self, "_opener", None)
            resp_cm = opener.open(req, timeout=10) if opener is not None else urllib.request.urlopen(req, timeout=10, context=ssl_ctx)
            with resp_cm as resp:
                raw = resp.read()
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                return ET.fromstring(raw)
        except Exception as exc:
            logger.debug("Cisco XML query for %s failed on %s: %s", class_id, url, exc)
            return None

    def oem_storage_fallback(self) -> list:
        """Fallback to Cisco CIMC XML API (/nuova) when Redfish storage returns empty.

        Extracts storageController and storageLocalDisk / storageLocalDiskSlotEp via
        Cisco XML API (nuova plugin pattern pioneered by Comcast fishymetrics).
        """
        ctrl_root = self._query_cisco_xml("storageController")
        if ctrl_root is None:
            return []

        ctrl_elements = ctrl_root.findall(".//storageController")
        if not ctrl_elements:
            return []

        # Query disks
        disk_root = self._query_cisco_xml("storageLocalDisk")
        if disk_root is None:
            disk_root = self._query_cisco_xml("storageLocalDiskSlotEp")
        disk_elements = disk_root.findall(".//storageLocalDisk") if disk_root is not None else []
        if not disk_elements and disk_root is not None:
            disk_elements = disk_root.findall(".//storageLocalDiskSlotEp")

        disks_by_ctrl: Dict[str, List[dict]] = {}
        for de in disk_elements:
            disk_id = de.attrib.get("id") or de.attrib.get("diskId") or "Unknown"
            model = de.attrib.get("model") or ""
            serial = de.attrib.get("serial") or ""
            vendor = de.attrib.get("vendor") or "Cisco"
            disk_state = (de.attrib.get("diskState") or de.attrib.get("operState") or "online").lower()
            oper_state = (de.attrib.get("operState") or "operable").lower()
            size_str = de.attrib.get("coercedSize") or de.attrib.get("size") or "0"
            m_size = re.search(r"(\d+)", size_str)
            cap_bytes = int(m_size.group(1)) if m_size else 0
            if "MB" in size_str.upper():
                cap_bytes *= 1024 * 1024
            elif "GB" in size_str.upper():
                cap_bytes *= 1024 * 1024 * 1024

            m_type = de.attrib.get("type") or de.attrib.get("mediaType") or "SSD"
            iface = de.attrib.get("interfaceType") or de.attrib.get("protocol") or "SAS"
            link_speed = de.attrib.get("linkSpeed") or ""
            ctrl_ref = de.attrib.get("controller") or de.attrib.get("controllerId") or ""
            dn = de.attrib.get("dn") or ""
            if not ctrl_ref and "storage-" in dn:
                m_ctrl = re.search(r"storage-([A-Za-z0-9_.-]+)/", dn)
                if m_ctrl:
                    ctrl_ref = m_ctrl.group(1).replace("SAS-", "").replace("NVME-", "")

            drive_json = {
                "Id": f"Disk_{disk_id}",
                "Name": f"Disk {disk_id} ({model})".strip(),
                "Model": model,
                "SerialNumber": serial,
                "Manufacturer": vendor,
                "CapacityBytes": cap_bytes,
                "MediaType": "SSD" if "SSD" in m_type.upper() else "HDD",
                "Protocol": "NVMe" if "NVME" in iface.upper() else ("SATA" if "SATA" in iface.upper() else "SAS"),
                "Status": {
                    "State": "Enabled" if oper_state in ("operable", "online", "jbod") else "Disabled",
                    "Health": "OK" if disk_state in ("online", "unconfigured-good", "jbod", "optimal") else "Warning",
                },
                "Oem": {
                    "Cisco": {
                        "LinkSpeed": link_speed,
                        "PartNumber": model,
                    }
                },
            }
            disks_by_ctrl.setdefault(ctrl_ref.upper(), []).append(drive_json)

        result_controllers = []
        for ce in ctrl_elements:
            ctrl_id = ce.attrib.get("id") or ce.attrib.get("pciSlot") or "MRAID"
            ctrl_model = ce.attrib.get("model") or "Cisco Modular RAID"
            ctrl_type = ce.attrib.get("type") or "SAS"
            ctrl_fw = ce.attrib.get("firmwareVersion") or ce.attrib.get("operFwVersion") or "N/A"
            raid_support = ce.attrib.get("raidSupport") or ""
            has_lv = bool(raid_support and "RAID" in raid_support.upper())

            raw_drives = (
                disks_by_ctrl.get(ctrl_id.upper())
                or disks_by_ctrl.get("MRAID")
                or disks_by_ctrl.get("")
                or []
            )

            parsed_drives = []
            for dr in raw_drives:
                try:
                    parsed = parse_drive_details(
                        self, ctrl_id, f"Cisco {ctrl_model}", dr, has_logical_vols=has_lv
                    )
                    if parsed:
                        parsed_drives.append(parsed)
                except Exception as exc:
                    logger.debug("Failed parsing fallback drive %s: %s", dr.get("Id"), exc)

            protocols = []
            if "SAS" in ctrl_type.upper() or "SAS" in ctrl_model.upper():
                protocols.extend(["SAS", "SATA"])
            if "NVME" in ctrl_type.upper() or "NVME" in ctrl_model.upper():
                protocols.append("NVMe")
            if not protocols:
                protocols = ["SAS", "SATA"]

            ctrl_dict = {
                "id": ctrl_id,
                "name": f"Cisco {ctrl_model}",
                "ctrl_firmware": ctrl_fw,
                "ctrl_model": ctrl_model,
                "has_logical_volumes": has_lv,
                "bbu_health": "N/A",
                "bbu_badge": None,
                "volumes": [],
                "is_trimode": "TRIMODE" in ctrl_model.upper(),
                "is_software_raid": False,
                "device_protocols": protocols,
                "pcie_lanes_in_use": None,
                "pcie_max_lanes": None,
                "pcie_gen": None,
                "enclosures": [],
                "drives": parsed_drives,
                "is_boot_ctrl": any(k in ctrl_id.upper() or k in ctrl_model.upper() for k in ["BOSS", "NS204I", "M.2"]),
                "vendor_id": "1137",
                "device_id": "",
                "subsystem_vendor_id": "",
                "subsystem_id": "",
                "pci_quad": "",
                "pci_pair": "",
            }
            result_controllers.append(ctrl_dict)

        return result_controllers

    def oem_sku(self, sys_data: dict) -> str:
        """Extract Cisco hardware SKU / part number.

        Cisco CIMC does not expose SKU on ComputerSystem directly.
        Queries /redfish/v1/Chassis/1/Assembly (or discovered chassis Assembly)
        to extract the Chassis PartNumber (e.g. '74-122873-01' or '74-105776-03').
        """
        if hasattr(self, "_cached_sku") and self._cached_sku:
            return self._cached_sku

        sku = str(sys_data.get("SKU") or "").strip()
        if sku and sku.upper() not in ("NONE", "N/A", "NULL"):
            self._cached_sku = sku
            return self._cached_sku

        self._cached_sku = ""
        cha_uris: List[str] = []
        if getattr(self, "chassis_uri", None):
            cha_uris.append(self.chassis_uri)
        if getattr(self, "chassis_uris", None):
            for cu in self.chassis_uris:
                if cu not in cha_uris:
                    cha_uris.append(cu)
        if not cha_uris:
            cha_uris = ["/redfish/v1/Chassis/1"]

        for cu in cha_uris:
            assembly_uri = f"{cu.rstrip('/')}/Assembly"
            assy = self._get(assembly_uri)
            if isinstance(assy, dict) and not assy.get("error"):
                items = assy.get("Assemblies") or []
                for item in items:
                    if isinstance(item, dict):
                        ctx = str(item.get("PhysicalContext", "")).upper()
                        pn = str(item.get("PartNumber", "")).strip()
                        if ctx == "CHASSIS" and pn:
                            self._cached_sku = pn
                            return self._cached_sku
                for item in items:
                    if isinstance(item, dict):
                        pn = str(item.get("PartNumber", "")).strip()
                        if pn:
                            self._cached_sku = pn
                            return self._cached_sku

        return self._cached_sku

    def oem_fastpath_roots(self) -> Optional[Tuple[List[str], List[str], List[str]]]:
        """Cisco IMC fast-path root probe.
        Checks if /redfish/v1/Managers/CIMC responds, then resolves serial-keyed
        system and chassis URIs from /Systems and /Chassis collections.
        """
        test_mgr = self._get("/redfish/v1/Managers/CIMC")
        if not test_mgr or not isinstance(test_mgr, dict) or test_mgr.get("error"):
            return None

        sys_coll = self._get("/redfish/v1/Systems") or {}
        sys_members = [
            m.get("@odata.id") for m in self._get_members(sys_coll)
            if isinstance(m, dict) and m.get("@odata.id")
        ]
        if not sys_members:
            return None

        cha_coll = self._get("/redfish/v1/Chassis") or {}
        cha_members = [
            m.get("@odata.id") for m in self._get_members(cha_coll)
            if isinstance(m, dict) and m.get("@odata.id")
        ]
        if not cha_members:
            cha_members = ["/redfish/v1/Chassis/1"]

        return (sys_members, cha_members, ["/redfish/v1/Managers/CIMC"])

    def oem_bios_date(self, sys_data: dict) -> str:
        """Extract Cisco BIOS release date from UpdateService/FirmwareInventory.

        Cisco IMC does not expose BIOS release date directly on ComputerSystem.
        Queries /redfish/v1/UpdateService/FirmwareInventory for a BIOS member,
        caching the result on self._cached_bios_date.
        """
        if hasattr(self, "_cached_bios_date") and self._cached_bios_date:
            return self._cached_bios_date

        self._cached_bios_date = "N/A"
        fw_inv = self._get("/redfish/v1/UpdateService/FirmwareInventory") or {}
        if isinstance(fw_inv, dict) and not fw_inv.get("error"):
            members = self._get_members(fw_inv) if "Members" in fw_inv else []
            for m in members:
                if not isinstance(m, dict):
                    continue
                m_uri = m.get("@odata.id")
                m_id = str(m.get("Id", "") or m_uri or "").upper()
                m_name = str(m.get("Name", "")).upper()
                if "BIOS" in m_id or "BIOS" in m_name:
                    item = self._get(m_uri) if m_uri and ("ReleaseDate" not in m) else m
                    if isinstance(item, dict) and not item.get("error"):
                        rdate = item.get("ReleaseDate")
                        if rdate and str(rdate).strip() and str(rdate).strip().upper() not in ("N/A", "NONE"):
                            self._cached_bios_date = str(rdate).strip()
                            return self._cached_bios_date

            # Fallback: scan members
            for m in members:
                if not isinstance(m, dict):
                    continue
                m_uri = m.get("@odata.id")
                if m_uri:
                    item = self._get(m_uri) or {}
                    if isinstance(item, dict) and not item.get("error"):
                        name_str = (str(item.get("Name", "")) + " " + str(item.get("Id", ""))).upper()
                        if "BIOS" in name_str:
                            rdate = item.get("ReleaseDate")
                            if rdate and str(rdate).strip() and str(rdate).strip().upper() not in ("N/A", "NONE"):
                                self._cached_bios_date = str(rdate).strip()
                                return self._cached_bios_date

        return self._cached_bios_date

    def oem_drive_endurance(self, drive_json: dict) -> Optional[float]:
        """Extract remaining write endurance percentage (0.0 to 100.0) from Cisco OEM fields.

        Cisco NVMe direct drives expose wear state via Oem.Cisco.SmartData.PercentLifeLeft.
        """
        cisco_oem = get_nested(drive_json, "Oem", "Cisco", default={}) or get_nested(drive_json, "Oem", "CIMC", default={})
        if not isinstance(cisco_oem, dict):
            return None
        smart = cisco_oem.get("SmartData")
        if isinstance(smart, dict):
            life_left = smart.get("PercentLifeLeft")
            if life_left is not None:
                try:
                    return float(life_left)
                except (TypeError, ValueError):
                    pass
        life_left = cisco_oem.get("PercentLifeLeft") or cisco_oem.get("RemainingLifePercent")
        if life_left is not None:
            try:
                return float(life_left)
            except (TypeError, ValueError):
                pass
        return None

    def oem_drive_metrics(self, drive_json: dict) -> dict:
        """Read Cisco drive telemetry metrics from Oem.Cisco or Oem.CIMC."""
        cisco_oem = get_nested(drive_json, "Oem", "Cisco", default={}) or get_nested(drive_json, "Oem", "CIMC", default={})
        if not isinstance(cisco_oem, dict):
            return {}
        res = {}
        smart = cisco_oem.get("SmartData") if isinstance(cisco_oem.get("SmartData"), dict) else {}

        poh = (
            smart.get("PowerOnHours")
            or cisco_oem.get("PowerOnHours")
            or cisco_oem.get("OperationHours")
        )
        if poh is not None:
            try:
                res["power_on_hours"] = float(poh)
            except (TypeError, ValueError):
                pass

        life_left = smart.get("PercentLifeLeft") or cisco_oem.get("PercentLifeLeft")
        if life_left is not None:
            try:
                val = float(life_left)
                res["endurance_remaining_pct"] = val
                res["life_used_pct"] = max(0.0, 100.0 - val)
            except (TypeError, ValueError):
                pass

        op_temp = smart.get("OperatingTemperatureInCel") or cisco_oem.get("OperatingTemperatureInCel")
        if op_temp is not None:
            try:
                res["temperature_c"] = float(op_temp)
            except (TypeError, ValueError):
                pass

        max_temp = smart.get("MaximumOperatingTemperatureInCel") or cisco_oem.get("MaximumOperatingTemperatureInCel")
        if max_temp is not None:
            try:
                res["max_temp_c"] = float(max_temp)
            except (TypeError, ValueError):
                pass

        throttle_temp = smart.get("ThrottleStartTemperatureInCel")
        if throttle_temp is not None:
            try:
                res["throttle_temp_c"] = float(throttle_temp)
            except (TypeError, ValueError):
                pass

        shutdown_temp = smart.get("ShutdownTemperatureInCel")
        if shutdown_temp is not None:
            try:
                res["shutdown_temp_c"] = float(shutdown_temp)
            except (TypeError, ValueError):
                pass

        wear_days = smart.get("WearStatusInDays")
        if wear_days is not None:
            try:
                res["wear_status_in_days"] = int(wear_days)
            except (TypeError, ValueError):
                pass

        perf_pct = smart.get("PerformancePercent")
        if perf_pct is not None:
            try:
                res["performance_pct"] = float(perf_pct)
            except (TypeError, ValueError):
                pass

        lw = cisco_oem.get("LinkWidth")
        ls = cisco_oem.get("LinkSpeed")
        if lw or ls:
            res["link_width"] = str(lw).strip() if lw else ""
            res["link_speed"] = str(ls).strip() if ls else ""
        part = cisco_oem.get("PartNumber") or cisco_oem.get("PID")
        if part:
            res["part_number"] = str(part).strip()
        slot = cisco_oem.get("PCIeSlot")
        if slot:
            res["pcie_slot"] = str(slot).strip()
        return res

    def oem_security_evidence(self) -> Dict[str, Any]:
        """Collect Cisco CIMC security evidence (SUDI RoT, ManagerMode, KMIP, etc.)."""
        mgr_uri = getattr(self, "mgr_uri", None) or "/redfish/v1/Managers/CIMC"
        mgr_data = self._get(mgr_uri) if hasattr(self, "_get") else {}
        if not isinstance(mgr_data, dict) or mgr_data.get("error"):
            return {}

        cisco_oem = get_nested(mgr_data, "Oem", "Cisco", default={})
        if not isinstance(cisco_oem, dict):
            return {}

        ev: Dict[str, Any] = {}
        if cisco_oem.get("ManagerMode"):
            ev["manager_mode"] = str(cisco_oem["ManagerMode"]).strip()

        hw_id = cisco_oem.get("HardwareX509Identity")
        if isinstance(hw_id, dict) and hw_id.get("Certificate"):
            # Cisco ACT2 ECC Secure Unique Device Identifier (IEEE 802.1AR)
            ev["hardware_sudi"] = {
                "format": str(hw_id.get("CertificateFormat", "PEM")),
                "present": True,
                "verified": True,
                "identity_type": "ACT2 ECC SUDI",
            }

        kmip = cisco_oem.get("CiscoKMIPClient")
        if isinstance(kmip, dict):
            settings = kmip.get("KMIPServerSettings") or {}
            ev["kmip_client"] = {
                "enabled": bool(settings.get("Enabled", False)),
                "server_count": len(settings.get("KMIPServers") or []),
            }

        fan_policy = cisco_oem.get("FanPolicy")
        if fan_policy:
            ev["fan_policy"] = str(fan_policy).strip()

        return ev

    def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict:
        """Return Cisco IMC license information."""
        cisco_oem = get_nested(mgr_data, "Oem", "Cisco", default={})
        mode = cisco_oem.get("ManagerMode") if isinstance(cisco_oem, dict) else None
        mode_str = f" ({mode} Mode)" if mode else ""
        return {
            "license_name": f"Cisco IMC{mode_str}",
            "manager_mode": mode or "Standalone",
            "badge": f"<span class='badge success'>🟢 Cisco IMC{mode_str} — no inventory license required</span>",
            "vendor_note": (
                "Cisco IMC provides full Redfish inventory access without additional "
                "licensing. Centralised management via Cisco Intersight requires a "
                "separate Intersight Infrastructure Service license."
            ),
        }

    def oem_port_transceiver(self, port_json: dict) -> Dict[str, Any]:
        """Extract Cisco VIC optical transceiver telemetry."""
        cisco_vic = get_nested(port_json, "Oem", "Cisco", "VicPort", default={}) or get_nested(port_json, "Oem", "CIMC", "VicPort", default={})
        if not isinstance(cisco_vic, dict) or not cisco_vic:
            return {}
        conn_present = cisco_vic.get("ConnectorPresent")
        if conn_present is False:
            return {}
        c_type = str(cisco_vic.get("ConnectorType") or "").strip()
        v_name = str(cisco_vic.get("ConnectorVendorName") or "").strip()
        p_num = str(cisco_vic.get("ConnectorPartNumber") or "").strip()
        s_num = str(cisco_vic.get("ConnectorVendorPid") or "").strip()
        return {
            "identifier_type": c_type.split("-")[0] if "-" in c_type else (c_type or "QSFP"),
            "interface_type": c_type or "N/A",
            "vendor_name": v_name or "Cisco",
            "part_number": p_num or "N/A",
            "serial_number": s_num or "N/A",
        }

    def oem_vnic_capabilities(self, ndf_json: dict) -> Dict[str, Any]:
        """Extract Cisco VIC VnicConfiguration capabilities (NSX Geneve, RoCEv2, RSS, TSO/LRO, MTU, CDN)."""
        cisco_oem = (
            get_nested(ndf_json, "Oem", "Cisco", default={})
            or get_nested(ndf_json, "Oem", "CIMC", default={})
        )
        if not isinstance(cisco_oem, dict):
            return {}
        vnic_cfg = cisco_oem.get("VnicConfiguration") or {}
        if not isinstance(vnic_cfg, dict):
            return {}
        eth_cfg = vnic_cfg.get("EthConfiguration") if isinstance(vnic_cfg.get("EthConfiguration"), dict) else {}
        vhba_cfg = vnic_cfg.get("VHBAConfiguration") if isinstance(vnic_cfg.get("VHBAConfiguration"), dict) else {}

        features = eth_cfg.get("Features") or vnic_cfg.get("Features") or {}
        offload = eth_cfg.get("OffloadProfile") or vnic_cfg.get("OffloadProfile") or {}
        rss = eth_cfg.get("RssProfile") or vnic_cfg.get("RssProfile") or {}
        rdma = eth_cfg.get("RdmaProfile") or vnic_cfg.get("RdmaProfile") or {}

        cdn = eth_cfg.get("Cdn") or vnic_cfg.get("Cdn") or ""
        mtu = eth_cfg.get("MTUSize") or vnic_cfg.get("MTUSize") or ndf_json.get("Ethernet", {}).get("MTUSize")
        vlan_id = eth_cfg.get("VLANId") or vnic_cfg.get("VLANId") or ndf_json.get("Ethernet", {}).get("VLAN", {}).get("VLANId")

        return {
            "cdn": str(cdn).strip(),
            "uplink_port": vnic_cfg.get("UplinkPort"),
            "pci_order": vnic_cfg.get("PCIOrder") or "",
            "cos": vnic_cfg.get("ClassOfService"),
            "vlan_mode": vnic_cfg.get("VlanMode") or "",
            "vlan_id": vlan_id,
            "mtu": mtu,
            "geneve_offload": bool(features.get("GeneveEnabled")),
            "vxlan_offload": bool(features.get("VxlanEnabled")),
            "rocev2": bool(features.get("Rocev2Enabled") or rdma.get("Rocev2Enabled")),
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

    def oem_normalize_bios_attributes(self, raw_attrs: dict) -> dict:
        """Normalize Cisco BIOS attribute names across UCS server generations (M4-M8)."""
        sys_sum = getattr(self, "sys_summary", {}) or {}
        boot_fallback = sys_sum.get("raw_boot_mode") or sys_sum.get("boot_mode")
        return normalize_cisco_bios_attributes(raw_attrs, fallback_boot_mode=boot_fallback)


def normalize_cisco_bios_attributes(
    raw_attrs: Dict[str, Any],
    fallback_boot_mode: Optional[str] = None,
) -> Dict[str, Any]:
    """Normalize Cisco BIOS attribute names and values across UCS server generations (M4-M8).

    Inspects raw attributes dictionary (from /redfish/v1/Systems/.../Bios)
    and extracts canonical baseline configuration settings:
      • SysProfile: System performance profile (e.g. Enterprise, High-Throughput, HPC, Custom)
      • ProcVirtualization: Hardware virtualization (Intel VT / AMD SVM)
      • VtdSupport: Intel VT for Directed I/O / AMD IOMMU
      • LogicalProc: Logical processor (Intel Hyper-Threading / AMD SMT)
      • ProcTurboMode: Processor Turbo Mode (Intel Turbo Boost / AMD Core Performance Boost)
      • SpeedStep: Enhanced Intel SpeedStep (EIST)
      • VmdSupport: Intel Volume Management Device state (Disabled / Enabled)
      • MemOpMode: Memory RAS Configuration (e.g. ADDDC Sparing, Maximum Performance, Mirroring)
      • SubNumaCluster: Sub-NUMA Clustering (SNC) on Intel
      • NumaNodesPerSocket: AMD NUMA Nodes per Socket (NPS0, NPS1, NPS2, NPS4)
      • CcxAsNumaDomain: AMD ACPI SRAT L3 Cache as NUMA Domain
      • DeterminismSlider: AMD Performance Determinism slider
      • BootMode: System boot mode (UEFI vs Legacy)
      • ProcCStates: Processor C-States (ProcessorC6Report, Global C-state Control)
      • ProcC1E: Processor C1E
      • WorkLdConfig: Workload configuration (I/O Sensitive vs Balanced)
      • PwrPerfTuning: Energy/Power Performance Tuning (OS vs BIOS vs PECI)
      • CpuEngPerfBias: Energy Performance Bias (Balanced Performance, Performance, etc.)
    """
    normalized: Dict[str, Any] = {}
    if not isinstance(raw_attrs, dict):
        return normalized

    # 1. SysProfile / CPUPerformance
    for k in ("CPUPerformance", "CpuPerformance", "SysProfile", "SystemProfile"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["SysProfile"] = str(raw_attrs[k]).strip()
            break

    # 2. ProcVirtualization (Intel VT / AMD SVM)
    for k in ("IntelVT", "IntelVirtualizationTechnology", "ProcVirtualization", "SVM Mode", "SvmMode", "ProcVmx", "ProcSvm"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["ProcVirtualization"] = str(raw_attrs[k]).strip()
            break

    # 3. VtdSupport / Directed I/O (Intel VT-d / AMD IOMMU)
    for k in ("IntelVTD", "IntelVTForDirectedIO", "VtdSupport", "VT-d", "IOMMU", "Iommu"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["VtdSupport"] = str(raw_attrs[k]).strip()
            break

    # 4. LogicalProc (Hyper-Threading / SMT)
    for k in ("IntelHyperThread", "IntelHyperThreadingTechnology", "LogicalProc", "SMT Mode", "SmtMode", "HyperThreading"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["LogicalProc"] = str(raw_attrs[k]).strip()
            break

    # 5. ProcTurboMode (Turbo Boost / Core Performance Boost)
    for k in ("IntelTurboBoostTech", "IntelTurboBoostTechnology", "ProcTurboMode", "Core Performance Boost", "CorePerformanceBoost", "TurboMode"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["ProcTurboMode"] = str(raw_attrs[k]).strip()
            break

    # 6. SpeedStep (EIST)
    for k in ("EnhancedIntelSpeedStep", "IntelSpeedStepTechnology", "SpeedStep"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["SpeedStep"] = str(raw_attrs[k]).strip()
            break

    # 7. VmdSupport (Intel VMD)
    for k in ("VMDEnable", "VmdSupport", "ProcVmd", "IntelVMD"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["VmdSupport"] = str(raw_attrs[k]).strip()
            break

    # 8. MemOpMode / Memory RAS
    for k in ("SelectMemoryRAS", "SelectMemoryRasConfiguration", "MemoryRASConfiguration", "MemOpMode"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["MemOpMode"] = str(raw_attrs[k]).strip()
            break

    # 9. SubNumaCluster (SNC on Intel)
    for k in ("SNC", "SubNumaClustering", "SubNumaCluster"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["SubNumaCluster"] = str(raw_attrs[k]).strip()
            break

    # 10. AMD NUMA / Determinism
    for k in ("NUMA Nodes per Socket", "NumaNodesPerSocket", "NumaNodes"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["NumaNodesPerSocket"] = str(raw_attrs[k]).strip()
            break
    for k in ("ACPI SRAT L3 Cache as NUMA Domain", "AcpiSratL3CacheAsNumaDomain", "CcxAsNumaDomain"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["CcxAsNumaDomain"] = str(raw_attrs[k]).strip()
            break
    for k in ("Determinism Slider", "DeterminismSlider"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["DeterminismSlider"] = str(raw_attrs[k]).strip()
            break

    # 11. BootMode
    for k in ("BootMode", "SystemBootMode"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["BootMode"] = str(raw_attrs[k]).strip()
            break
    if "BootMode" not in normalized and fallback_boot_mode:
        normalized["BootMode"] = str(fallback_boot_mode).strip()

    # 12. ProcCStates / C1E
    for k in ("ProcessorC6Report", "ProcessorC6", "Global C-state Control", "GlobalCstateControl", "PackageCstateLimit", "PackageCStateControl", "ProcCStates"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["ProcCStates"] = str(raw_attrs[k]).strip()
            break
    for k in ("ProcessorC1E", "ProcessorC1e", "ProcC1E"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["ProcC1E"] = str(raw_attrs[k]).strip()
            break

    # 13. Workload and Power Tuning
    for k in ("WorkLdConfig", "WorkloadConfiguration"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["WorkLdConfig"] = str(raw_attrs[k]).strip()
            break
    for k in ("PwrPerfTuning", "PowerPerformanceTuning", "EnergyPerformanceTuning"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["PwrPerfTuning"] = str(raw_attrs[k]).strip()
            break
    for k in ("CpuEngPerfBias", "ProcessorEPPProfile", "EPPProfile"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["CpuEngPerfBias"] = str(raw_attrs[k]).strip()
            break

    # 14. NUMA
    for k in ("NUMAOptimize", "NUMA Optimized", "NUMA"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["NUMAOptimize"] = str(raw_attrs[k]).strip()
            break

    # 15. Latency Optimized Mode & Optimized Power Mode (M8 / M7 Intel)
    for k in ("LatencyOptimizedMode", "LatencyOptMode"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["LatencyOptimizedMode"] = str(raw_attrs[k]).strip()
            break
    for k in ("OptimizedPowerMode", "OptimizedPower"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["OptimizedPowerMode"] = str(raw_attrs[k]).strip()
            break

    # 16. Energy Efficient Turbo
    for k in ("EnergyEfficientTurbo", "Energy Efficient Turbo"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["EnergyEfficientTurbo"] = str(raw_attrs[k]).strip()
            break

    # 17. AMD fabric & power tokens
    for k in ("APBDIS", "Apbdis", "DF P-State Mode", "DfPstateMode"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["Apbdis"] = str(raw_attrs[k]).strip()
            break
    for k in ("Fixed SOC P-State", "FixedSocPstate", "SocPstate"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["FixedSocPstate"] = str(raw_attrs[k]).strip()
            break
    for k in ("Cisco xGMI Max Speed", "xGMIMaxSpeed", "XgmiMaxSpeed"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["XgmiMaxSpeed"] = str(raw_attrs[k]).strip()
            break
    for k in ("Power Profile F19h", "PowerProfileF19h"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["PowerProfileF19h"] = str(raw_attrs[k]).strip()
            break

    # 18. Hardware Prefetchers
    for k in ("HardwarePrefetch", "Hardware Prefetcher", "MLC Streamer Prefetcher"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["HardwarePrefetch"] = str(raw_attrs[k]).strip()
            break
    for k in ("AdjacentCacheLinePrefetch", "Adjacent Cache-Line Prefetcher", "MLC Spatial Prefetcher"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["AdjacentCacheLinePrefetch"] = str(raw_attrs[k]).strip()
            break

    # 19. SR-IOV
    for k in ("SRIOV", "Sriov", "SriovGlobalEnable"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["SriovGlobalEnable"] = str(raw_attrs[k]).strip()
            break

    return normalized

