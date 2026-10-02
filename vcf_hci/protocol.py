"""
VCF Readiness Tool — management protocol detection.

Probes TCP ports to distinguish Redfish BMCs, Intel AMT/vPro, AMD DASH,
and legacy IPMI targets.
"""
import json
import logging
import socket
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Optional
from urllib.error import HTTPError, URLError

from vcf_hci.logging_utils import create_pinned_connection
from vcf_hci.tls_utils import build_bmc_opener, build_pinned_opener, build_ssl_context

logger = logging.getLogger("vcf_assess")


def _tcp_reachable(host: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection can be established within timeout seconds."""
    try:
        with create_pinned_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _redfish_probe(
    host: str,
    timeout: float = 8.0,
    verify_ssl: bool = False,
    ca_bundle: Optional[str] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    port: int = 443,
    max_retries: int = 1,
    pinned_thumbprints: Optional[Dict[str, str]] = None,
) -> bool:
    """Return True if the host responds with valid Redfish JSON on port (443 or 80)."""
    ctx = ssl_context or build_ssl_context(verify_ssl=verify_ssl, ca_bundle=ca_bundle)
    opener = build_bmc_opener(ssl_context=ctx, pinned_thumbprints=pinned_thumbprints)
    schemes = ("https", "http") if port == 443 else ("http", "https")
    port_suffix = f":{port}" if port not in (443, 80) else ""
    for scheme in schemes:
        url = f"{scheme}://{host}{port_suffix}/redfish/v1"
        for attempt in range(max_retries + 1):
            req = urllib.request.Request(url)
            req.add_header("Accept", "application/json")
            # Adaptive timeout: allow up to 1.5x timeout (capped at 12.0s) on retry for slow/busy BMCs
            cur_timeout = min(12.0, timeout * 1.5) if attempt > 0 else timeout
            try:
                with opener.open(req, timeout=cur_timeout) as r:
                    raw = r.read()
                    data = json.loads(raw.decode("utf-8", errors="replace"))
                    if data.get("RedfishVersion") or data.get("v1") or "redfish" in str(data.get("@odata.type", "")).lower():
                        return True
            except HTTPError as e:
                if e.code in (401, 403):
                    return True
            except (ConnectionResetError, ConnectionRefusedError, TimeoutError, URLError, OSError):
                if attempt < max_retries:
                    time.sleep(0.5)
                    continue
            except Exception:
                pass
    return False


_WSMAN_IDENTIFY_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">'
    '<s:Header/>'
    '<s:Body><wsmid:Identify/></s:Body>'
    '</s:Envelope>'
)


def _wsman_identify_probe(
    host: str,
    port: int,
    timeout: float = 3.5,
    verify_ssl: bool = False,
    ca_bundle: Optional[str] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    max_retries: int = 1,
) -> bool:
    """Return True when the host responds with a valid WS-Man IdentifyResponse."""
    scheme = "https" if port in (16993, 624) else "http"
    url = f"{scheme}://{host}:{port}/wsman"
    req = urllib.request.Request(
        url,
        data=_WSMAN_IDENTIFY_BODY.encode("utf-8"),
        method="POST",
    )
    req.add_header("Content-Type", "application/soap+xml;charset=UTF-8")
    req.add_header("Accept", "application/soap+xml")
    ctx = ssl_context or build_ssl_context(verify_ssl=verify_ssl, ca_bundle=ca_bundle)
    opener = build_bmc_opener(ssl_context=ctx)
    for attempt in range(max_retries + 1):
        try:
            with opener.open(req, timeout=timeout) as r:
                raw = r.read(2048).decode("utf-8", errors="replace")
                return "IdentifyResponse" in raw or "ProductVendor" in raw
        except (ConnectionResetError, ConnectionRefusedError, TimeoutError, URLError, OSError):
            if attempt < max_retries:
                time.sleep(0.5)
                continue
        except Exception:
            return False
    return False


_CANDIDATE_PORTS = (443, 80, 16993, 16992, 624, 623)
_DEFAULT_CANDIDATE_PORTS = (443, 80, 16993, 16992)


def _probe_ports_parallel(host: str, ports: tuple = _CANDIDATE_PORTS, timeout: float = 3.5) -> dict:
    """Probe candidate TCP ports concurrently and return a map of port -> reachable (bool)."""
    reachable = {}
    with ThreadPoolExecutor(max_workers=len(ports)) as ex:
        futures = {ex.submit(_tcp_reachable, host, port, timeout): port for port in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                reachable[port] = fut.result()
            except Exception:
                reachable[port] = False
    return reachable


def probe_fleet_network_latency(
    hosts: list,
    sample_size: int = 8,
    timeout: float = 2.0,
) -> dict:
    """Sample candidate BMC hosts to measure TCP RTT latency across WAN / VPN links.

    Returns dict with keys:
      avg_rtt_ms: float
      max_rtt_ms: float
      min_rtt_ms: float
      high_latency: bool (True if avg > 80ms or max > 150ms)
      sampled_count: int
      reachable_count: int
    """
    if not hosts:
        return {
            "avg_rtt_ms": 0.0,
            "max_rtt_ms": 0.0,
            "min_rtt_ms": 0.0,
            "high_latency": False,
            "sampled_count": 0,
            "reachable_count": 0,
        }

    sample = list(dict.fromkeys(hosts))[:sample_size]

    def _measure_host(h: str) -> Optional[float]:
        t0 = time.time()
        for p in (443, 80):
            try:
                with create_pinned_connection((h, p), timeout=timeout):
                    return round((time.time() - t0) * 1000, 1)
            except OSError:
                continue
        return None

    latencies = []
    with ThreadPoolExecutor(max_workers=min(len(sample), 8)) as ex:
        futures = [ex.submit(_measure_host, h) for h in sample]
        for f in futures:
            try:
                res = f.result()
                if res is not None:
                    latencies.append(res)
            except Exception:
                pass

    if not latencies:
        return {
            "avg_rtt_ms": 0.0,
            "max_rtt_ms": 0.0,
            "min_rtt_ms": 0.0,
            "high_latency": False,
            "sampled_count": len(sample),
            "reachable_count": 0,
        }

    avg_rtt = round(sum(latencies) / len(latencies), 1)
    max_rtt = round(max(latencies), 1)
    min_rtt = round(min(latencies), 1)
    high_lat = bool(avg_rtt > 80.0 or max_rtt > 150.0)

    return {
        "avg_rtt_ms": avg_rtt,
        "max_rtt_ms": max_rtt,
        "min_rtt_ms": min_rtt,
        "high_latency": high_lat,
        "sampled_count": len(sample),
        "reachable_count": len(latencies),
    }


def detect_management_protocol(
    host: str,
    timeout: float = 8.0,
    verify_ssl: bool = False,
    ca_bundle: Optional[str] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    enable_dash: bool = False,
    return_diagnostics: bool = False,
    pinned_thumbprints: Optional[Dict[str, str]] = None,
) -> tuple:
    """Probe a host and return (protocol, port) for the first reachable interface.

    Probe order:
      Redfish (443/80) → Intel AMT (16993, 16992) → AMD DASH (624, 623 if enable_dash=True)

    Port 623 is shared by AMD DASH and IPMI RMCP. A WS-Man Identify SOAP probe
    distinguishes them: valid XML → DASH; no/binary response → IPMI (skipped).

    Returns one of:
      ("redfish", 443|80)
      ("amt",     16993|16992)
      ("dash",    624|623)
      ("ipmi",    623)      — reachable but IPMI, not WS-Man
      ("none",    0)        — nothing found

    If return_diagnostics=True, returns (protocol, port, diagnostics_dict).
    """
    # Test TCP connectivity to candidate ports concurrently (using fast TCP timeout)
    tcp_timeout = min(float(timeout), 4.0)
    ports_to_probe = _CANDIDATE_PORTS if enable_dash else _DEFAULT_CANDIDATE_PORTS
    open_ports = _probe_ports_parallel(host, ports_to_probe, timeout=tcp_timeout)

    diagnostics = {
        "open_ports": open_ports,
        "tcp_reachable": any(open_ports.values()),
        "port_443_open": bool(open_ports.get(443)),
        "port_80_open": bool(open_ports.get(80)),
        "probe_timeout": False,
        "probe_timeout_seconds": timeout,
    }

    # Fast return if no candidate port responded to TCP connection
    if not any(open_ports.values()):
        logger.debug(f"{host}: no management interface found on standard ports")
        return ("none", 0, diagnostics) if return_diagnostics else ("none", 0)

    # --- Redfish (BMC / enterprise) ---
    for port in (443, 80):
        if open_ports.get(port):
            if _redfish_probe(
                host,
                timeout,
                verify_ssl=verify_ssl,
                ca_bundle=ca_bundle,
                ssl_context=ssl_context,
                port=port,
                pinned_thumbprints=pinned_thumbprints,
            ):
                logger.debug(f"{host}: Redfish detected on port {port}")
                return ("redfish", port, diagnostics) if return_diagnostics else ("redfish", port)

    # If port 443 or 80 was open but Redfish probe failed/timed out, record diagnostic
    if open_ports.get(443) or open_ports.get(80):
        diagnostics["probe_timeout"] = True

    # --- Intel vPro / AMT ---
    for port in (16993, 16992):
        if open_ports.get(port):
            if _wsman_identify_probe(
                host,
                port,
                timeout,
                verify_ssl=verify_ssl,
                ca_bundle=ca_bundle,
                ssl_context=ssl_context,
            ):
                logger.debug(f"{host}: Intel AMT/WS-Man detected on port {port}")
                return ("amt", port, diagnostics) if return_diagnostics else ("amt", port)

    # --- AMD DASH (only if enabled) ---
    if enable_dash:
        if open_ports.get(624):
            if _wsman_identify_probe(
                host,
                624,
                timeout,
                verify_ssl=verify_ssl,
                ca_bundle=ca_bundle,
                ssl_context=ssl_context,
            ):
                logger.debug(f"{host}: AMD DASH detected on port 624")
                return ("dash", 624, diagnostics) if return_diagnostics else ("dash", 624)

        # Port 623: DASH or IPMI? Disambiguate with WS-Man Identify
        if open_ports.get(623):
            if _wsman_identify_probe(
                host,
                623,
                timeout,
                verify_ssl=verify_ssl,
                ca_bundle=ca_bundle,
                ssl_context=ssl_context,
            ):
                logger.debug(f"{host}: AMD DASH detected on port 623")
                return ("dash", 623, diagnostics) if return_diagnostics else ("dash", 623)
            logger.debug(f"{host}: TCP 623 reachable but not WS-Man — likely IPMI RMCP")
            return ("ipmi", 623, diagnostics) if return_diagnostics else ("ipmi", 623)

    logger.debug(f"{host}: no management interface found on standard ports")
    return ("none", 0, diagnostics) if return_diagnostics else ("none", 0)


# ---------------------------------------------------------------------------
# WS-Man / Intel AMT / AMD DASH collector (Layer A2)
# ---------------------------------------------------------------------------

# WS-Man namespace map used for ET.find / ET.findall path expressions
_WS_NS = {
    "s":      "http://www.w3.org/2003/05/soap-envelope",
    "wsa":    "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "wsman":  "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
    "wsen":   "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
    "wsmid":  "http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd",
}

# Base URIs for CIM schema namespaces
_CIM_BASE  = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
_AMT_BASE  = "http://intel.com/wbem/wscim/1/amt-schema/1/"
_DCIM_BASE = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/DCIM_"

# CIM_PhysicalMemory.MemoryType enum → human label
_MEM_TYPE_MAP = {
    "20": "DDR3", "21": "DDR3", "24": "DDR4", "26": "DDR4",
    "34": "DDR5", "35": "DDR5",
}


