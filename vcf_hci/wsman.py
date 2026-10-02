"""
VCF Readiness Tool — WS-Man collector for Intel vPro/AMT and AMD DASH.

Collects hardware inventory from AMT and AMD DASH endpoints using
WS-Management (WS-Man) over HTTP/HTTPS on ports 16992/16993 (AMT)
and 623/624 (DASH).
"""
import base64
import ipaddress
import logging
import re
import socket
import ssl
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from typing import Optional
from urllib.error import HTTPError, URLError

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.compat_engine import VCF9CompatibilityEngine, evaluate_bios_version
from vcf_hci.protocol import _AMT_BASE, _CIM_BASE, _DCIM_BASE, _MEM_TYPE_MAP
from vcf_hci.tls_utils import (
    MetadataPinnedHTTPHandler,
    MetadataPinnedHTTPSHandler,
    build_ssl_context,
)

logger = logging.getLogger("vcf_assess")


class WsManCollector:
    """Out-of-band hardware inventory via WS-Man SOAP/XML.

    Supports Intel vPro/AMT (ports 16992/16993) with Digest auth and
    AMD DASH (ports 623/624) with Basic auth.  Returns the same result-dict
    structure as UniversalRedfishCollector.run_assessment() so the existing
    HTML report generator needs no structural changes.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        protocol: str = "amt",
        port: int = 16992,
        ssl_context: Optional[ssl.SSLContext] = None,
        verify_ssl: bool = False,
        ca_bundle: Optional[str] = None,
        host_timeout: float = 30.0,
    ):
        self.host = host
        self.protocol = protocol   # "amt" or "dash"
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.ca_bundle = ca_bundle
        self.host_timeout = host_timeout
        scheme = "https" if port in (16993, 624) else "http"
        if scheme == "http":
            logger.warning(
                f"{host}: connecting to WS-Man on port {port} over plain HTTP — "
                "credentials and hardware data will be transmitted unencrypted. "
                "Upgrade firmware to use TLS port (16993 for AMT, 624 for DASH)."
            )
        self.endpoint = f"{scheme}://{host}:{port}/wsman"
        self.amt_mode = "N/A"      # populated in run_assessment
        self.auth_failed = False
        self.skip_host_set = None
        self.cancel_event = None
        self.skipped = False
        self.timed_out = False
        self.host_timeout = 300  # Default 5-minute max runtime limit per host (0 to disable)
        self.scan_start_time = None
        self.stage_callback = None
        self.ssl_context = ssl_context or build_ssl_context(verify_ssl=verify_ssl, ca_bundle=ca_bundle)
        self.ssl_error = None

        # AMT uses Digest auth; DASH uses Basic auth.
        if protocol == "amt":
            pw_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            pw_mgr.add_password(None, self.endpoint, username, password)
            digest_h = urllib.request.HTTPDigestAuthHandler(pw_mgr)
            http_h = MetadataPinnedHTTPHandler()
            https_h = MetadataPinnedHTTPSHandler(context=self.ssl_context)
            self._opener = urllib.request.build_opener(digest_h, http_h, https_h)
        else:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            self._basic_auth = f"Basic {token}"
            http_h = MetadataPinnedHTTPHandler()
            https_h = MetadataPinnedHTTPSHandler(context=self.ssl_context)
            self._opener = urllib.request.build_opener(http_h, https_h)

    def close(self):
        """No-op close method for context manager compatibility."""
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ------------------------------------------------------------------
    # SOAP plumbing
    # ------------------------------------------------------------------
    def _build_envelope(self, action: str, resource_uri: str,
                        body_xml: str = "", selector_set: Optional[dict] = None) -> str:
        msg_id = f"uuid:{uuid.uuid4()}"
        selectors = ""
        if selector_set:
            items = "".join(
                f'<wsman:Selector Name="{k}">{v}</wsman:Selector>'
                for k, v in selector_set.items()
            )
            selectors = f"<wsman:SelectorSet>{items}</wsman:SelectorSet>"
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope'
            ' xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
            ' xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"'
            ' xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">'
            "<s:Header>"
            f"<wsa:Action>{action}</wsa:Action>"
            f"<wsa:To>{self.endpoint}</wsa:To>"
            f"<wsman:ResourceURI>{resource_uri}</wsman:ResourceURI>"
            f"<wsa:MessageID>{msg_id}</wsa:MessageID>"
            "<wsa:ReplyTo><wsa:Address>"
            "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
            "</wsa:Address></wsa:ReplyTo>"
            f"{selectors}"
            "</s:Header>"
            f"<s:Body>{body_xml}</s:Body>"
            "</s:Envelope>"
        )

    def _is_cancelled_or_skipped(self) -> bool:
        """Centralized check for cancellation, user skip, or runtime timeout."""
        cancel_evt = getattr(self, "cancel_event", None)
        if cancel_evt is not None and getattr(cancel_evt, "is_set", lambda: False)():
            if not getattr(self, "skipped", False):
                self.skipped = True
            return True

        skip_set = getattr(self, "skip_host_set", None)
        if skip_set is not None and self.host in skip_set:
            if not getattr(self, "skipped", False):
                self.skipped = True
                logger.info("[%s] Host scan skipped by user request", self.host)
            return True

        if getattr(self, "skipped", False):
            return True

        if getattr(self, "host_timeout", 0) > 0 and self.scan_start_time is not None:
            if (time.time() - self.scan_start_time) > self.host_timeout:
                if not getattr(self, "skipped", False):
                    self.skipped = True
                    self.timed_out = True
                    logger.warning(
                        "[%s] Host scan exceeded max total runtime limit (%ds / %.1fm) — skipping remaining endpoints.",
                        self.host, self.host_timeout, self.host_timeout / 60
                    )
                return True

        return False

    def _post(self, resource_uri: str, action: str,
              body_xml: str = "", selector_set: Optional[dict] = None) -> Optional[ET.Element]:
        if self._is_cancelled_or_skipped():
            return None
        envelope = self._build_envelope(action, resource_uri, body_xml, selector_set)
        req = urllib.request.Request(
            self.endpoint,
            data=envelope.encode("utf-8"),
            method="POST",
        )
        req.add_header("Content-Type", "application/soap+xml;charset=UTF-8")
        req.add_header("Accept", "application/soap+xml")
        if self.protocol == "dash":
            req.add_header("Authorization", self._basic_auth)
        try:
            with self._opener.open(req, timeout=10) as r:
                raw = r.read().decode("utf-8", errors="replace")
                root = ET.fromstring(raw)
                # Return the Body child element for convenience
                body = root.find("{http://www.w3.org/2003/05/soap-envelope}Body")
                return body if body is not None else root
        except ET.ParseError as e:
            logger.debug(f"WS-Man XML parse error ({resource_uri}): {e}")
            return None
        except HTTPError as e:
            logger.debug(f"WS-Man HTTP {e.code} for {resource_uri}")
            if e.code in (401, 403):
                self.auth_failed = True
            return None
        except URLError as e:
            logger.debug(f"WS-Man URLError for {resource_uri}: {e.reason}")
            return None
        except Exception as e:
            logger.debug(f"WS-Man unexpected error ({resource_uri}): {e}")
            return None

    def _item_to_dict(self, item_el: "ET.Element") -> dict:
        """Flatten a wsman:Item XML subtree to a plain {localname: text} dict."""
        result = {}
        for child in item_el:
            # Strip namespace: {http://...}TagName → TagName
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if child.text and child.text.strip():
                result[tag] = child.text.strip()
            # Also recurse one level for nested simple elements
            for gc_el in child:
                sub_tag = gc_el.tag.split("}")[-1] if "}" in gc_el.tag else gc_el.tag
                if gc_el.text and gc_el.text.strip():
                    result[f"{tag}.{sub_tag}"] = gc_el.text.strip()
        return result

    def _enumerate(self, resource_uri: str) -> list:
        """Enumerate all instances of a CIM class; returns list of flat dicts."""
        enum_action  = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
        pull_action  = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
        enum_body    = "<wsen:Enumerate/>"

        body_el = self._post(resource_uri, enum_action, enum_body)
        if body_el is None:
            return []

        # Extract EnumerationContext
        ctx_el = body_el.find(".//{http://schemas.xmlsoap.org/ws/2004/09/enumeration}EnumerationContext")
        if ctx_el is None or not ctx_el.text:
            # Some implementations return results directly in the Enumerate response
            items = body_el.findall(".//{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}Item")
            return [self._item_to_dict(i) for i in items]

        enum_ctx = ctx_el.text.strip()
        results = []
        max_pulls = 20  # guard against runaway loops
        for _ in range(max_pulls):
            if self._is_cancelled_or_skipped():
                break
            pull_body = (
                f"<wsen:Pull>"
                f"<wsen:EnumerationContext>{enum_ctx}</wsen:EnumerationContext>"
                f"<wsen:MaxElements>50</wsen:MaxElements>"
                f"</wsen:Pull>"
            )
            pull_el = self._post(resource_uri, pull_action, pull_body)
            if pull_el is None:
                break
            items = pull_el.findall(".//{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}Item")
            for item in items:
                results.append(self._item_to_dict(item))
            end_el = pull_el.find(".//{http://schemas.xmlsoap.org/ws/2004/09/enumeration}EndOfSequence")
            if end_el is not None:
                break
            new_ctx = pull_el.find(".//{http://schemas.xmlsoap.org/ws/2004/09/enumeration}EnumerationContext")
            if new_ctx is None or not new_ctx.text:
                break
            enum_ctx = new_ctx.text.strip()
        return results

    def _get_instance(self, resource_uri: str, selector_set: Optional[dict] = None) -> dict:
        """Fetch a single CIM instance by GET; returns flat dict."""
        get_action = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
        body_el = self._post(resource_uri, get_action, selector_set=selector_set)
        if body_el is None:
            return {}
        # Flatten the entire body
        return self._item_to_dict(body_el)

    # ------------------------------------------------------------------
    # AMT provisioning mode
    # ------------------------------------------------------------------
    def _probe_amt_mode(self) -> str:
        """Read AMT provisioning mode: CCM (1) or ACM (2). Returns 'CCM'/'ACM'/'Unknown'."""
        uri = f"{_AMT_BASE}AMT_SetupAndConfigurationService"
        data = self._get_instance(uri)
        mode_val = data.get("ProvisioningMode", data.get("ProvisioningState", ""))
        mapping = {"0": "Unprovisioned", "1": "CCM", "2": "ACM"}
        return mapping.get(str(mode_val), "Unknown")

    # ------------------------------------------------------------------
    # Collection methods
    # ------------------------------------------------------------------
    def collect_system_summary(self) -> dict:
        """CIM_ComputerSystem + CIM_BIOSElement + CIM_Chassis."""
        sys_uri   = f"{_CIM_BASE}CIM_ComputerSystem"
        bios_uri  = f"{_CIM_BASE}CIM_BIOSElement"
        chassis_uri = f"{_CIM_BASE}CIM_Chassis"

        sys_instances  = self._enumerate(sys_uri)
        bios_instances = self._enumerate(bios_uri)
        chassis_list   = self._enumerate(chassis_uri)

        sys_data    = sys_instances[0]  if sys_instances  else {}
        bios_data   = bios_instances[0] if bios_instances else {}
        chassis_data = chassis_list[0]  if chassis_list   else {}

        vendor = (sys_data.get("Manufacturer")
                  or chassis_data.get("Manufacturer") or "Unknown Vendor")
        model  = (sys_data.get("Model")
                  or sys_data.get("Name")
                  or chassis_data.get("Model") or "Unknown Model")
        serial = (sys_data.get("SerialNumber")
                  or chassis_data.get("SerialNumber") or "Unknown")
        asset_tag = sys_data.get("OtherIdentifyingInfo", "N/A")

        bios_ver  = bios_data.get("Version", bios_data.get("Name", "Unknown"))
        bios_date = bios_data.get("ReleaseDate", bios_data.get("InstallDate", "N/A"))

        return {
            "vendor": vendor, "model": model,
            "serial_number": serial, "asset_tag": asset_tag,
            "bios_version": bios_ver, "bios_release_date": bios_date,
        }

    def collect_cpu(self, vendor: str = "", model: str = "") -> dict:
        """CIM_Processor — returns CPU summary sub-dict."""
        procs = self._enumerate(f"{_CIM_BASE}CIM_Processor")
        if not procs:
            return {
                "model": "Unknown", "count": 0,
                "verdict": "🔴 Not VCF-Eligible", "arch_label": "No CPU data",
                "channels_per_socket": 2, "max_ram_speed_mhz": 3200, "stepping": "",
            }
        cpu0 = procs[0]
        cpu_name = (cpu0.get("Name") or cpu0.get("Caption")
                    or cpu0.get("Description") or "Unknown")
        # Some AMT implementations report "Intel(R) Core(TM) i7-1355U CPU @ 1.70GHz"
        cpu_name_clean = re.sub(r"\(R\)|\(TM\)|@\s*[\d.]+\s*GHz?", "", cpu_name).strip()
        stepping = cpu0.get("Stepping", "")
        verdict, arch_label, channels, max_ram_speed_mhz, max_pcie_lanes = VCF9CompatibilityEngine.evaluate_cpu(cpu_name_clean, vendor=vendor, model=model)
        if stepping:
            arch_label = f"{arch_label} — Stepping {stepping}"
        return {
            "model": cpu_name_clean,
            "count": len(procs),
            "verdict": verdict,
            "arch_label": arch_label,
            "channels_per_socket": channels,
            "max_ram_speed_mhz": max_ram_speed_mhz,
            "max_pcie_lanes_per_socket": max_pcie_lanes,
            "stepping": stepping,
        }

    def collect_memory_details(self, cpu_count: int = 1, channels_per_socket: int = 2) -> dict:
        """CIM_PhysicalMemory — total, DIMM count, DDR generation."""
        dimms = self._enumerate(f"{_CIM_BASE}CIM_PhysicalMemory")
        total_bytes = sum(int(d.get("Capacity", 0)) for d in dimms if d.get("Capacity", "").isdigit())
        total_gb = round(total_bytes / (1024 ** 3)) if total_bytes else 0

        # DDR generation from MemoryType enum
        mem_type_vals = [d.get("MemoryType", "") for d in dimms if d.get("MemoryType")]
        ddr_gen = "Unknown"
        if mem_type_vals:
            ddr_gen = _MEM_TYPE_MAP.get(mem_type_vals[0], f"Type-{mem_type_vals[0]}")

        # Speed
        speeds = [int(d.get("ConfiguredMemoryClockSpeed", d.get("Speed", 0)))
                  for d in dimms
                  if str(d.get("ConfiguredMemoryClockSpeed", d.get("Speed", "0"))).isdigit()]
        speed_mhz = max(speeds) if speeds else 0

        slot_count = len(dimms)
        channels_used = min(slot_count, cpu_count * channels_per_socket)
        channel_display = (
            f"{channels_used} Channel {'DDR5' if '5' in ddr_gen else 'DDR4' if '4' in ddr_gen else 'DDR'}"
            f" @ {speed_mhz} MHz" if speed_mhz else f"{channels_used} Channel {ddr_gen}"
        )
        return {
            "total_gb": total_gb,
            "slot_count": slot_count,
            "ddr_gen": ddr_gen,
            "speed_mhz": speed_mhz,
            "channel_display": channel_display,
            "dimm_details": dimms,
        }

    def collect_tpm(self) -> str:
        """CIM_TPM — returns tpm_status_badge HTML string."""
        tpms = self._enumerate(f"{_CIM_BASE}CIM_TPM")
        if not tpms:
            # AMT also exposes TPM via IPS_TPM (AMT-specific extension)
            tpms = self._enumerate(f"{_AMT_BASE}IPS_TPM")
        if not tpms:
            return "<span class='badge warning'>🟡 TPM: Not Detected via WS-Man</span>"
        tpm0 = tpms[0]
        spec = tpm0.get("TPMSpecVersion", tpm0.get("SpecMajorVersion", ""))
        enabled = tpm0.get("IsEnabled", tpm0.get("EnabledState", ""))
        if str(enabled) in ("1", "2", "true", "True", "Enabled"):
            ver_str = f" (v{spec})" if spec else ""
            return f"<span class='badge success'>🟢 Enabled{ver_str}</span>"
        return "<span class='badge danger'>🔴 TPM Present but Disabled</span>"

    def collect_secure_boot(self) -> str:
        """AMT_BootCapabilities (AMT) / CIM_BIOSElement attributes (DASH)."""
        # AMT path
        if self.protocol == "amt":
            bc = self._get_instance(f"{_AMT_BASE}AMT_BootCapabilities")
            sb = bc.get("SecureBoot", bc.get("SecureBootEnabled", ""))
            if str(sb).lower() in ("true", "1", "enabled"):
                return "Enabled"
            if str(sb).lower() in ("false", "0", "disabled"):
                return "Disabled"
        # DASH: try DCIM_BootConfigSetting or CIM_BIOSElement
        # CIM_BIOSElement.BIOSCharacteristics is a list of capability flags;
        # bit 0x4000 (16384) = BIOS supports EFI but secure boot flag isn't standardised.
        # Best effort: look for an explicit SecureBoot field in DCIM extensions.
        bios_list = self._enumerate(f"{_CIM_BASE}CIM_BIOSElement")
        for b in bios_list:
            for k, v in b.items():
                if "secure" in k.lower() and "boot" in k.lower():
                    if str(v).lower() in ("true", "1", "enabled"):
                        return "Enabled"
                    if str(v).lower() in ("false", "0", "disabled"):
                        return "Disabled"
        return "Unknown"

    def collect_network_adapters(self) -> list:
        """CIM_NetworkPort + AMT_EthernetPortSettings — basic NIC inventory.

        Returns Redfish-compatible structure (adapters with a `ports` sub-list)
        so the existing HTML report renderer works without changes.
        """
        ports = self._enumerate(f"{_CIM_BASE}CIM_NetworkPort")
        nics = []
        for p in ports:
            speed_bps = 0
            raw_speed = p.get("Speed") or p.get("MaxSpeed") or "0"
            if str(raw_speed).isdigit():
                speed_bps = int(raw_speed)
            speed_gbps = round(speed_bps / 1e9, 1) if speed_bps >= 1_000_000 else 0
            name = (p.get("Name") or p.get("Description")
                    or p.get("ElementName") or "Network Port")
            op_status = str(p.get("OperationalStatus", ""))
            link_up = op_status in ("2", "Up")
            mac = p.get("PermanentAddress", p.get("NetworkAddresses", ""))
            nics.append({
                "name": name,
                "part_number": mac or "N/A",
                "manufacturer": p.get("Manufacturer", "Unknown"),
                "firmware_version": "N/A",
                "ports": [
                    {
                        "port_id": p.get("PortNumber", "1"),
                        "current_speed_gbps": speed_gbps,
                        "link_status": "Up" if link_up else "Unknown",
                        "mac": mac,
                    }
                ],
                "bcg_url": BCGLinkGenerator.io_device(name),
            })
        return nics

    def collect_storage_subsystem(self) -> list:
        """CIM_DiskDrive + CIM_StorageExtent — basic drive inventory.

        Returns Redfish-compatible structure (controller + drives list).
        Note: WS-Man cannot determine drive interface type (NVMe/SATA/SAS),
        so vSAN ESA flags are left as "Unknown (WS-Man)" — the report will
        show a "cannot determine" ESA banner for WS-Man hosts.
        """
        drives_raw = (
            self._enumerate(f"{_CIM_BASE}CIM_DiskDrive")
            or self._enumerate(f"{_CIM_BASE}CIM_StorageExtent")
        )
        drives = []
        for d in drives_raw:
            name = (d.get("Name") or d.get("Caption")
                    or d.get("ElementName") or "Unknown Drive")
            # Capacity: CIM_DiskDrive uses MaxMediaSize (blocks) or Size (bytes)
            size_bytes = 0
            if d.get("Size") and str(d["Size"]).isdigit():
                size_bytes = int(d["Size"])
            elif d.get("MaxMediaSize") and str(d["MaxMediaSize"]).isdigit():
                # MaxMediaSize is in KB for CIM_DiskDrive
                size_bytes = int(d["MaxMediaSize"]) * 1024
            size_gb = round(size_bytes / (1024 ** 3), 1) if size_bytes > 0 else 0
            media = d.get("MediaType", d.get("DriveType", ""))
            media_label = {"3": "HDD", "4": "SSD", "5": "Hybrid"}.get(str(media), "Unknown")
            drives.append({
                "model": name,
                "product_id": d.get("PartNumber", d.get("OtherIdentifyingInfo", "N/A")),
                "serial": d.get("SerialNumber", "N/A"),
                "capacity_gb": size_gb,
                "media_type": media_label,
                "protocol": "Unknown",
                "category": "Unknown (WS-Man)",
                "endurance_remaining_pct": "N/A",
                "firmware_version": d.get("FirmwareRevision", "N/A"),
                "bcg_url": BCGLinkGenerator.storage(name, media_type=media_label),
                "pcie_gen": None,
                "pcie_lanes_in_use": None,
            })
        if drives:
            return [{"controller": "WS-Man Storage Inventory (interface type unknown)", "drives": drives}]
        return []

    def collect_thermal_telemetry(self) -> dict:
        """CIM_NumericSensor (SensorType=2=Temperature) + DCIM_Fan for DASH."""
        sensors = self._enumerate(f"{_CIM_BASE}CIM_NumericSensor")
        temp_sensors = []
        for s in sensors:
            # SensorType 2 = Temperature
            if str(s.get("SensorType", "")) not in ("2", ""):
                continue
            name = s.get("Name") or s.get("Caption") or "Sensor"
            reading = s.get("CurrentReading", "")
            warn = s.get("UpperThresholdNonCritical", "")
            crit = s.get("UpperThresholdCritical", "")
            # AMT reports in milli-degrees Celsius
            def _to_c(val):
                if not val or not str(val).lstrip("-").isdigit():
                    return None
                v = int(val)
                return round(v / 1000, 1) if v > 1000 else float(v)
            temp_sensors.append({
                "name": name,
                "reading_c": _to_c(reading),
                "warn_c": _to_c(warn),
                "crit_c": _to_c(crit),
                "status": s.get("OperationalStatus", "Unknown"),
            })

        fan_sensors = []
        if self.protocol == "dash":
            fans = self._enumerate(f"{_DCIM_BASE}Fan")
            for f in fans:
                fan_name = f.get("ElementName") or f.get("Name") or "Fan"
                rpm = f.get("CurrentReading", "")
                op_status = f.get("OperationalStatus", "")
                fan_sensors.append({
                    "name": fan_name,
                    "rpm": rpm,
                    "status": "OK" if str(op_status) == "2" else "Unknown",
                })

        overall = "OK" if temp_sensors else "N/A"
        return {
            "overall_status_badge": f"<span class='badge {'success' if overall == 'OK' else 'info'}'>{'🟢 OK' if overall == 'OK' else 'ℹ️ N/A'}</span>",
            "sensors": temp_sensors,
            "fans": fan_sensors,
        }

    def collect_psu(self) -> dict:
        """DCIM_PowerSupply (DASH only). AMT has no PSU visibility."""
        if self.protocol != "dash":
            return {}
        psus = self._enumerate(f"{_DCIM_BASE}PowerSupply")
        if not psus:
            return {}
        total_w = sum(float(p.get("TotalOutputPower", 0) or 0) for p in psus)
        statuses = [str(p.get("OperationalStatus", "")) for p in psus]
        all_ok = all(s == "2" for s in statuses if s)
        redundant = len(psus) >= 2
        badge = (
            "<span class='badge success'>🟢 Redundant PSU</span>"
            if redundant and all_ok else
            "<span class='badge warning'>🟡 Single PSU</span>"
            if not redundant else
            "<span class='badge danger'>🔴 PSU Fault</span>"
        )
        return {
            "badge": badge,
            "summary": f"{len(psus)} PSU(s), {int(total_w)}W total",
            "redundant": redundant,
        }

    def collect_system_event_log(self, max_entries: int = 10) -> list:
        """AMT_MessageLog (AMT) or CIM_RecordLog (DASH) — recent events."""
        if self.protocol == "amt":
            log_uri = f"{_AMT_BASE}AMT_MessageLog"
        else:
            log_uri = f"{_CIM_BASE}CIM_RecordLog"
        entries_raw = self._enumerate(log_uri)
        events = []
        for e in entries_raw[:max_entries]:
            msg = (e.get("RecordData") or e.get("Message")
                   or e.get("PerceivedSeverity") or "")
            ts  = e.get("CreationTimeStamp") or e.get("TimeStamp") or "N/A"
            sev = e.get("PerceivedSeverity", "")
            sev_badge = {
                "1": "<span class='badge info'>ℹ️ Info</span>",
                "3": "<span class='badge warning'>🟡 Warning</span>",
                "5": "<span class='badge danger'>🔴 Error</span>",
                "7": "<span class='badge danger'>🔴 Fatal</span>",
            }.get(str(sev), "<span class='badge info'>ℹ️ Info</span>")
            if msg:
                events.append({
                    "severity_badge": sev_badge,
                    "message_id": e.get("LogInstanceID", e.get("RecordID", "N/A")),
                    "message": msg,
                    "timestamp": ts,
                })
        return events

    def _update_stage(self, stage: str) -> None:
        cb = getattr(self, "stage_callback", None)
        if callable(cb):
            try:
                cb(self.host, stage)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Full assessment
    # ------------------------------------------------------------------
    def run_assessment(self, allow_partial: bool = False, **kwargs) -> Optional[dict]:
        """Collect all WS-Man data for this host and return a report dict."""
        self.scan_start_time = time.time()
        if self._is_cancelled_or_skipped():
            return None

        self._update_stage("Connecting via WS-Man")
        proto_label = "Intel vPro/AMT" if self.protocol == "amt" else "AMD DASH"
        logger.info(f"  [→] {self.host} — connecting via {proto_label} (port {self.port})...")

        # Probe AMT provisioning mode first (gates subsequent requests)
        if self.protocol == "amt":
            self.amt_mode = self._probe_amt_mode()
            logger.debug(f"{self.host}: AMT mode = {self.amt_mode}")
            if self.amt_mode == "Unprovisioned":
                logger.warning(f"  [✗] {self.host} — AMT is not provisioned (no inventory accessible)")
                return None

        self._update_stage("Collecting System Summary & CPU")
        sys_data = self.collect_system_summary()
        if not sys_data or sys_data.get("vendor") == "Unknown Vendor":
            if getattr(self, "auth_failed", False):
                logger.warning(f"  [✗] {self.host} — bad credentials (HTTP 401/403)")
            else:
                logger.warning(f"  [✗] {self.host} — no system data (check IP / network)")
            return None

        cpu_summary = self.collect_cpu(
            vendor=sys_data.get("vendor", ""),
            model=sys_data.get("model", ""),
        )
        self._update_stage("Collecting Memory, Storage & NICs")
        mem_info    = self.collect_memory_details(
            cpu_count=cpu_summary.get("count", 1),
            channels_per_socket=cpu_summary.get("channels_per_socket", 2),
        )
        tpm_badge    = self.collect_tpm()
        secure_boot  = self.collect_secure_boot()
        nics         = self.collect_network_adapters()
        storage      = self.collect_storage_subsystem()
        thermal      = self.collect_thermal_telemetry()
        psu          = self.collect_psu()
        lean_mode    = getattr(self, "lean_mode", False)
        sel          = self.collect_system_event_log() if not lean_mode else []

        # AMT mode badge for report
        if self.protocol == "amt":
            if self.amt_mode == "ACM":
                amt_mode_badge = "<span class='badge success'>🟢 AMT: Admin Control Mode</span>"
            elif self.amt_mode == "CCM":
                amt_mode_badge = "<span class='badge warning'>⚠️ AMT: Client Control Mode (limited)</span>"
            else:
                amt_mode_badge = "<span class='badge info'>ℹ️ AMT: Mode Unknown</span>"
        else:
            amt_mode_badge = ""

        # Secure Boot badge
        if secure_boot == "Enabled":
            sb_badge = "<span class='badge success'>🟢 Enabled</span>"
        elif secure_boot == "Disabled":
            sb_badge = "<span class='badge danger'>🔴 Disabled (Required for vSphere 9.1)</span>"
        else:
            sb_badge = "<span class='badge info'>ℹ️ Unknown — Not reported via WS-Man</span>"

        # BIOS eval (no baselines for consumer hardware — informational only)
        bios_eval = evaluate_bios_version(
            sys_data.get("model", ""),
            sys_data.get("bios_version", "Unknown"),
            sys_data.get("bios_release_date", "N/A"),
        )

        dns_name = None
        try:
            ipaddress.ip_address(self.host)
            dns_name = socket.gethostbyaddr(self.host)[0]
        except Exception:
            pass

        system = {
            "ip": self.host,
            "hostname": dns_name or self.host,
            "dns_name": dns_name,
            "vendor": sys_data.get("vendor", "Unknown"),
            "model": sys_data.get("model", "Unknown"),
            "serial_number": sys_data.get("serial_number", "Unknown"),
            "asset_tag": sys_data.get("asset_tag", "N/A"),
            "bios_version": sys_data.get("bios_version", "Unknown"),
            "bios_release_date": sys_data.get("bios_release_date", "N/A"),
            "bios_eval": bios_eval,
            "cpu_summary": cpu_summary,
            "total_memory_gb": mem_info.get("total_gb", 0),
            "tpm_status_badge": tpm_badge,
            "secure_boot": secure_boot,
            "secure_boot_badge": sb_badge,
            "amt_mode": self.amt_mode,
            "amt_mode_badge": amt_mode_badge,
            "ddr_gen": mem_info.get("ddr_gen", "Unknown"),
            "cpu_stepping": cpu_summary.get("stepping", ""),
            "data_source": f"wsman_{self.protocol}",
            "wsman_port": self.port,
            "wsman_proto_label": proto_label,
        }

        logger.info(f"  [✓] {self.host} — {system['vendor']} {system['model']} ({proto_label})")
        res = {
            "system": system,
            "bios_checks": {},
            "sel_alarms": sel,
            "memory_subsystem": mem_info,
            "memory_telemetry": {},
            "cpu_telemetry": {},
            "io_telemetry": {},
            "thermal_telemetry": thermal,
            "network_adapters": nics,
            "storage_subsystem": storage,
            "gpu_accelerators": [],
            "fc_hbas": [],
            "psu_status": psu,
            "bmc_license": {"license_name": f"N/A ({proto_label} native)"},
        }
        self._update_stage("Evaluating Compatibility Baseline")
        res["memory_topology"] = VCF9CompatibilityEngine.evaluate_memory_topology(mem_info, cpu_summary)
        res["collector_class"] = type(self).__name__
        return res

    def rescan_partial_sections(self, prior_data: dict, sections_to_rescan: Optional[list] = None) -> Optional[dict]:
        """Perform a targeted differential rescan of missing sections for WS-Man targets.

        Re-runs collection and merges newly collected non-empty sections into a copy of prior_data.
        """
        if not prior_data or not isinstance(prior_data, dict):
            return None

        import copy
        merged = copy.deepcopy(prior_data)
        orig_missing = list(sections_to_rescan if sections_to_rescan is not None else prior_data.get("partial_sections", []))
        if not orig_missing:
            merged["partial_scan"] = False
            merged["partial_sections"] = []
            merged["partial_reason"] = ""
            return merged

        res = self.run_assessment(allow_partial=True)
        if not res or not isinstance(res, dict):
            return None

        # Merge non-empty / updated sections into prior_data copy
        for key, val in res.items():
            if key == "system" and isinstance(val, dict):
                merged_sys = merged.get("system", {})
                if isinstance(merged_sys, dict):
                    merged_sys.update({k: v for k, v in val.items() if v not in ("", "Unknown", "N/A", None)})
                    merged["system"] = merged_sys
                else:
                    merged["system"] = val
            elif key not in ("partial_scan", "partial_sections", "partial_reason", "remediation"):
                if val or key in orig_missing:
                    merged[key] = val

        curr_missing = list(res.get("partial_sections", []))
        resolved = [s for s in orig_missing if s not in curr_missing]

        merged["partial_scan"] = bool(curr_missing)
        merged["partial_sections"] = curr_missing
        merged["partial_reason"] = f"Collection incomplete (missing: {', '.join(curr_missing)})" if curr_missing else ""
        merged["remediation"] = {
            "is_rescan": True,
            "original_missing": orig_missing,
            "resolved_sections": resolved,
            "remaining_sections": curr_missing,
            "status": "fully_remediated" if not curr_missing else "partially_remediated",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        merged["collector_class"] = type(self).__name__
        return merged


