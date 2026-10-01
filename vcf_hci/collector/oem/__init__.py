"""
VCF Readiness Tool — OEM collector registry and factory.

To add support for a new BMC vendor:
1. Copy oem/generic.py to oem/<vendor>.py
2. Rename GenericCollector → <Vendor>Collector
3. Override only the oem_* hook methods that differ from DMTF defaults
4. Add an entry to _REGISTRY below
5. Submit a PR with sample Redfish JSON in samples/<vendor>/

The factory create_collector() probes /redfish/v1, reads the Manufacturer
field, and returns the best-matching OEM subclass (falling back to
GenericCollector for unknown vendors).
"""
import json
import logging
import ssl
import urllib.request
from typing import Optional

logger = logging.getLogger("vcf_assess")

from vcf_hci.logging_utils import strip_url_userinfo
from vcf_hci.tls_utils import build_pinned_opener, build_ssl_context

from .cisco import CiscoCollector
from .dell import DellCollector
from .generic import GenericCollector
from .gigabyte import GigabyteCollector
from .hpe import HPECollector
from .intel import IntelBMCCollector
from .lenovo import LenovoCollector
from .quanta import QuantaCollector
from .supermicro import SupermicroCollector

# Registry: maps uppercase vendor substrings → collector class.
# The factory iterates in definition order; first match wins.
_REGISTRY: list = [
    (DellCollector.VENDOR_MATCH,        DellCollector),
    (HPECollector.VENDOR_MATCH,         HPECollector),
    (SupermicroCollector.VENDOR_MATCH,  SupermicroCollector),
    (CiscoCollector.VENDOR_MATCH,       CiscoCollector),
    (LenovoCollector.VENDOR_MATCH,      LenovoCollector),
    (IntelBMCCollector.VENDOR_MATCH,    IntelBMCCollector),
    (QuantaCollector.VENDOR_MATCH,      QuantaCollector),
    (GigabyteCollector.VENDOR_MATCH,    GigabyteCollector),
]


def create_collector(
    host: str,
    username: str,
    password: str,
    host_timeout: int = 300,
    verify_ssl: bool = False,
    ca_bundle: Optional[str] = None,
    server_hostname: Optional[str] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    scheme: str = "https",
    port: Optional[int] = None,
    pinned_thumbprints: Optional[dict] = None,
    probe_timeout: Optional[int] = None,
    tls_min_version: Optional[str] = None,
    legacy_ciphers: bool = False,
):
    """Probe /redfish/v1 and /Systems/{id}, read Manufacturer and OEM keys,
    and return the best-matching OEM collector subclass.

    Falls back to GenericCollector for unrecognised vendors so the tool
    still collects all standard DMTF data even without a dedicated adapter.
    """
    import base64
    import time
    raw_host = str(host or "").strip()
    if raw_host.startswith("http://"):
        scheme = "http"
        raw_host = raw_host[7:]
    elif raw_host.startswith("https://"):
        scheme = "https"
        raw_host = raw_host[8:]
    clean_host = strip_url_userinfo(raw_host.rstrip("/"))

    if port is not None:
        port_suffix = f":{port}" if ((scheme == "https" and port != 443) or (scheme == "http" and port != 80)) and ":" not in clean_host else ""
    elif ":" in clean_host:
        port_suffix = ""
    else:
        port_suffix = ""

    base_host_url = f"{scheme}://{clean_host}{port_suffix}"
    auth = base64.b64encode(f"{username}:{password}".encode()).decode()
    ctx = ssl_context or build_ssl_context(
        verify_ssl=verify_ssl,
        ca_bundle=ca_bundle,
        tls_min_version=tls_min_version,
        legacy_ciphers=legacy_ciphers,
    )
    opener = build_pinned_opener(ssl_context=ctx, pinned_thumbprints=pinned_thumbprints) if pinned_thumbprints else None

    effective_probe_timeout = probe_timeout if probe_timeout is not None else min(12, max(8, int(host_timeout * 0.05)))

    def _fetch_json(endpoint: str, timeout: Optional[int] = None) -> dict:
        if not endpoint:
            return {}
        if not endpoint.startswith("http"):
            url = f"{base_host_url}{endpoint if endpoint.startswith('/') else '/' + endpoint}"
        else:
            url = endpoint
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Basic {auth}")
        req.add_header("Accept", "application/json")
        t_out = timeout or effective_probe_timeout
        for attempt in range(2):
            try:
                if opener is not None:
                    with opener.open(req, timeout=t_out) as r:
                        return json.loads(r.read().decode("utf-8", errors="replace"))
                else:
                    with urllib.request.urlopen(req, timeout=t_out, context=ctx) as r:
                        return json.loads(r.read().decode("utf-8", errors="replace"))
            except Exception as e:
                err_str = str(e).lower()
                is_timeout = "timeout" in err_str or "timed out" in err_str
                # Fast bail out: do not retry on timeouts or auth rejections to avoid sequential hangs
                if is_timeout or "401" in err_str or "403" in err_str or "404" in err_str:
                    logger.debug(f"create_collector: probe to '{url}' failed: {e}")
                    return {}
                if attempt == 0:
                    time.sleep(0.2)
                    continue
                logger.debug(f"create_collector: probe to '{url}' failed: {e}")
                return {}
        return {}

    def _extract_vendor_text(data: dict) -> str:
        if not isinstance(data, dict):
            return ""
        parts = [
            str(data.get("Manufacturer") or ""),
            str(data.get("Vendor") or ""),
            str(data.get("Model") or ""),
            str(data.get("Name") or ""),
            str(data.get("Product") or ""),
            str(data.get("Description") or ""),
            str(data.get("@Redfish.Copyright") or ""),
            str(data.get("@odata.copyright") or ""),
        ]
        oem = data.get("Oem")
        if isinstance(oem, dict):
            parts.extend(oem.keys())
            for k, val in oem.items():
                if isinstance(val, str):
                    parts.append(val)
                elif isinstance(val, dict):
                    if "Manufacturer" in val:
                        parts.append(str(val["Manufacturer"]))
                    if "Vendor" in val:
                        parts.append(str(val["Vendor"]))
                    if "Model" in val:
                        parts.append(str(val["Model"]))
        return " ".join(parts).upper()

    def _match_vendor(candidate_text: str):
        if not candidate_text:
            return None
        for vendor_strings, cls in _REGISTRY:
            if any(v in candidate_text for v in vendor_strings):
                return cls
        return None

    # Step 1: Probe /redfish/v1 root
    root_data = _fetch_json("/redfish/v1")
    cand_text = _extract_vendor_text(root_data)
    matched_cls = _match_vendor(cand_text)

    # Step 2: If root didn't yield a match, probe /Systems
    if not matched_cls:
        sys_coll_uri = "/redfish/v1/Systems"
        if isinstance(root_data.get("Systems"), dict) and "@odata.id" in root_data["Systems"]:
            sys_coll_uri = root_data["Systems"]["@odata.id"]

        sys_coll = _fetch_json(sys_coll_uri)
        members = sys_coll.get("Members") or []
        if members and isinstance(members, list):
            first_m = members[0]
            sys_uri = first_m.get("@odata.id") if isinstance(first_m, dict) else str(first_m)
            if sys_uri:
                sys_data = _fetch_json(sys_uri)
                sys_cand_text = _extract_vendor_text(sys_data)
                matched_cls = _match_vendor(sys_cand_text)
                if matched_cls:
                    cand_text = sys_cand_text

    # Step 3: If still not matched and root was responsive, probe /Managers and /Chassis
    if not matched_cls and root_data:
        for coll_name in ("Managers", "Chassis"):
            coll_uri = f"/redfish/v1/{coll_name}"
            if isinstance(root_data.get(coll_name), dict) and "@odata.id" in root_data[coll_name]:
                coll_uri = root_data[coll_name]["@odata.id"]
            coll = _fetch_json(coll_uri)
            members = coll.get("Members") or []
            if members and isinstance(members, list):
                first_m = members[0]
                m_uri = first_m.get("@odata.id") if isinstance(first_m, dict) else str(first_m)
                if m_uri:
                    m_data = _fetch_json(m_uri)
                    m_cand_text = _extract_vendor_text(m_data)
                    matched_cls = _match_vendor(m_cand_text)
                    if matched_cls:
                        cand_text = m_cand_text
                        break

    collector_cls = matched_cls or GenericCollector
    if matched_cls:
        logger.debug(f"create_collector: matched {matched_cls.__name__} for host '{clean_host}' (text: '{cand_text}')")
    else:
        logger.debug(f"create_collector: no OEM match for host '{clean_host}', using GenericCollector")

    c = collector_cls(
        clean_host,
        username,
        password,
        ssl_context=ctx,
        verify_ssl=verify_ssl,
        ca_bundle=ca_bundle,
        server_hostname=server_hostname,
        scheme=scheme,
        port=port,
        pinned_thumbprints=pinned_thumbprints,
        tls_min_version=tls_min_version,
        legacy_ciphers=legacy_ciphers,
    )
    c.host_timeout = host_timeout
    return c


__all__ = [
    "CiscoCollector",
    "DellCollector",
    "GenericCollector",
    "GigabyteCollector",
    "HPECollector",
    "IntelBMCCollector",
    "LenovoCollector",
    "QuantaCollector",
    "SupermicroCollector",
    "create_collector",
]
