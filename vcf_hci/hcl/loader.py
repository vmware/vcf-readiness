"""
VCF Readiness Tool — vSAN HCL JSON and CSV loaders.
"""
import csv
import glob
import gzip
import json
import logging
import os
import re
import ssl
import threading
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("vcf_assess")

from vcf_hci.collector.pci_utils import normalize_pci_id
from vcf_hci.constants import LIVE_VSAN_HCL_JSON_URL

_HCL_CACHE_LOCK = threading.Lock()
_HCL_JSON_CACHE: Dict[str, Tuple[float, dict]] = {}
_CSV_DB_CACHE: Dict[str, Tuple[float, dict]] = {}
_IO_NICS_CACHE: Dict[str, Tuple[float, dict]] = {}


def clear_hcl_caches() -> None:
    """Clear all in-memory caches for HCL JSON and CSV datasets."""
    with _HCL_CACHE_LOCK:
        _HCL_JSON_CACHE.clear()
        _CSV_DB_CACHE.clear()
        _IO_NICS_CACHE.clear()


def extract_tier_from_hcl_entry(entry: dict) -> str:
    """Extracts or derives HCL tier string from a raw HCL entry.

    Checks top-level 'tier', 'Tier', or 'usedFor'. If missing, inspects
    'vsanSupport' structures at top-level and inside 'releases' to determine
    whether the device is certified for vSAN ESA, vSAN ESA Cyber Recovery,
    vSAN OSA (AF-Cache, AF-Cap, HY-Cache), or general Certification.
    """
    if not isinstance(entry, dict):
        return "Unverified / Unsupported"

    raw_tier = entry.get("tier") or entry.get("Tier") or entry.get("usedFor")
    if raw_tier:
        return str(raw_tier).strip()

    vs = entry.get("vsanSupport")
    vs_modes = set()
    vs_tiers = set()

    def _collect_vs(v_dict):
        if isinstance(v_dict, dict):
            for m in v_dict.get("mode", []):
                vs_modes.add(str(m))
            for t in v_dict.get("tier", []):
                vs_tiers.add(str(t))

    _collect_vs(vs)

    raw_releases = entry.get("releases")
    if isinstance(raw_releases, dict):
        for r_data in raw_releases.values():
            if isinstance(r_data, dict):
                for d_data in r_data.values():
                    if isinstance(d_data, dict):
                        for v_data in d_data.values():
                            if isinstance(v_data, dict):
                                for fw in v_data.get("firmwares", []):
                                    _collect_vs(fw.get("vsanSupport"))

    if "vSANESA-cyberrecoverytier" in vs_tiers or any("cyber" in t.lower() for t in vs_tiers):
        return "vSAN ESA Cyber Recovery Tier"
    elif any("esa" in m.lower() for m in vs_modes) or any("esa" in t.lower() for t in vs_tiers):
        if any(t in ("AF-Cache", "AF-Cap") for t in vs_tiers):
            return "vSAN ESA Storage Tier, vSAN All Flash Caching Tier, vSAN All Flash Capacity Tier"
        else:
            return "vSAN ESA Storage Tier"
    elif any("vsan" in m.lower() for m in vs_modes) or any(t in ("AF-Cache", "AF-Cap", "HY-Cache") for t in vs_tiers):
        t_parts = []
        if "AF-Cache" in vs_tiers:
            t_parts.append("vSAN All Flash Caching Tier")
        if "AF-Cap" in vs_tiers:
            t_parts.append("vSAN All Flash Capacity Tier")
        if "HY-Cache" in vs_tiers:
            t_parts.append("vSAN Hybrid Caching Tier")
        if not t_parts:
            t_parts.append("vSAN All Flash Capacity Tier")
        return ", ".join(t_parts)
    elif vs_modes or vs_tiers or raw_releases or entry.get("supportedReleases") or entry.get("supported_releases"):
        return "Certified"

    has_ident = bool(entry.get("vendorId") or entry.get("vid") or entry.get("vendor_id") or entry.get("model") or entry.get("Model"))
    return "Certified" if has_ident else "Unverified / Unsupported"


def _build_release_matrix_from_dict(raw_releases: dict) -> Tuple[List[str], Dict[str, Any]]:
    """Parse nested release dictionary from Broadcom all.json format into
    (releases_list, release_matrix_dict).
    """
    if not isinstance(raw_releases, dict):
        return [], {}
    release_matrix = {}
    for rel_name, rel_data in raw_releases.items():
        if isinstance(rel_data, dict):
            drv_name = ""
            drv_ver = ""
            fw_list = []
            for d_name, d_ver_map in rel_data.items():
                if isinstance(d_ver_map, dict):
                    for v_str, v_info in d_ver_map.items():
                        if d_name.lower() in ("nvme_pcie", "nvme", "nknvme", "lsi_msgpt3", "lsi_mr3", "pvscsi", "qcnic", "icen", "bnxt_en", "bnxtroce", "nmlx5_core", "i40en", "ionic_en") or not drv_ver:
                            drv_name = d_name
                            drv_ver = v_str
                        if isinstance(v_info, dict):
                            for fw_obj in v_info.get("firmwares", []):
                                if isinstance(fw_obj, dict) and fw_obj.get("firmware"):
                                    fw_list.append(str(fw_obj["firmware"]).strip())
            if drv_ver or fw_list or drv_name:
                unique_fw = list(set(fw_list))
                unique_fw.sort(key=lambda f: tuple(int(n) for n in re.findall(r"\d+", f)) if re.findall(r"\d+", f) else (f,))
                release_matrix[rel_name] = {
                    "driver": f"{drv_name} {drv_ver}".strip() if drv_ver else drv_name,
                    "driver_version": drv_ver,
                    "firmwares": unique_fw,
                    "recommended_firmware": unique_fw[-1] if unique_fw else "",
                    "min_firmware": unique_fw[0] if unique_fw else "",
                }
            else:
                release_matrix[rel_name] = {
                    "driver": "Inbox",
                    "driver_version": "",
                    "firmwares": [],
                    "recommended_firmware": "",
                    "min_firmware": "",
                }
    rel_keys = list(release_matrix.keys()) if release_matrix else [str(k).strip() for k in raw_releases if str(k).strip()]
    return rel_keys, release_matrix


def sanitize_hcl_entry(raw_entry: dict) -> dict:
    """Sanitizes raw HCL JSON objects to guarantee structural integrity
    before passing entries to the compatibility engine.
    """
    if not isinstance(raw_entry, dict):
        raw_entry = {}

    model = str(raw_entry.get("model") or raw_entry.get("Model") or "").strip()
    tier = extract_tier_from_hcl_entry(raw_entry)

    raw_rel = raw_entry.get("supportedReleases") or raw_entry.get("releases") or raw_entry.get("supported_releases")
    releases = []
    matrix_from_dict = {}
    if isinstance(raw_rel, str):
        releases = [r.strip() for r in raw_rel.split(",") if r.strip()]
    elif isinstance(raw_rel, dict):
        releases, matrix_from_dict = _build_release_matrix_from_dict(raw_rel)
    elif isinstance(raw_rel, list):
        releases = [str(r).strip() for r in raw_rel if str(r).strip()]

    vid = normalize_pci_id(raw_entry.get("vendorId") or raw_entry.get("vid") or raw_entry.get("vendor_id") or raw_entry.get("VendorId"))
    did = normalize_pci_id(raw_entry.get("deviceId") or raw_entry.get("did") or raw_entry.get("device_id") or raw_entry.get("DeviceId"))
    svid = normalize_pci_id(raw_entry.get("subVendorId") or raw_entry.get("svid") or raw_entry.get("subsystem_vendor_id") or raw_entry.get("SubsystemVendorId"))
    ssid = normalize_pci_id(raw_entry.get("subDeviceId") or raw_entry.get("ssid") or raw_entry.get("subsystem_id") or raw_entry.get("SubsystemId"))

    release_matrix = raw_entry.get("releaseMatrix") or raw_entry.get("release_matrix") or raw_entry.get("matrix") or matrix_from_dict or {}
    if not isinstance(release_matrix, dict):
        release_matrix = {}

    if not releases and release_matrix:
        releases = list(release_matrix.keys())

    rec_driver = (
        raw_entry.get("recommendedDriver") or raw_entry.get("recommended_driver") or
        raw_entry.get("driverVersion") or raw_entry.get("driver_version") or
        raw_entry.get("driver") or raw_entry.get("Driver") or ""
    )
    if isinstance(rec_driver, dict):
        rec_driver = (
            rec_driver.get("ESXi 9.1") or rec_driver.get("9.1") or
            rec_driver.get("ESXi 9.0") or rec_driver.get("9.0") or
            next((v for k, v in rec_driver.items() if str(v).strip()), "N/A")
        )
    if (not rec_driver or rec_driver in ("N/A", "")) and release_matrix:
        rel_entry = release_matrix.get("ESXi 9.1") or release_matrix.get("ESXi 9.0") or next(iter(release_matrix.values()), {})
        if isinstance(rel_entry, dict) and rel_entry.get("driver"):
            rec_driver = rel_entry["driver"]

    rec_fw = (
        raw_entry.get("recommendedFirmware") or raw_entry.get("recommended_firmware") or
        raw_entry.get("minFirmware") or raw_entry.get("min_firmware") or
        raw_entry.get("firmwareVersion") or raw_entry.get("firmware_version") or
        raw_entry.get("firmware") or raw_entry.get("Firmware") or ""
    )
    if isinstance(rec_fw, dict):
        rec_fw = (
            rec_fw.get("ESXi 9.1") or rec_fw.get("9.1") or
            rec_fw.get("ESXi 9.0") or rec_fw.get("9.0") or
            next((v for k, v in rec_fw.items() if str(v).strip()), "N/A")
        )
    if (not rec_fw or rec_fw in ("N/A", "")) and release_matrix:
        rel_entry = release_matrix.get("ESXi 9.1") or release_matrix.get("ESXi 9.0") or next(iter(release_matrix.values()), {})
        if isinstance(rel_entry, dict) and (rel_entry.get("recommended_firmware") or rel_entry.get("min_firmware")):
            rec_fw = rel_entry.get("recommended_firmware") or rel_entry.get("min_firmware")

    product_id = str(raw_entry.get("id") or raw_entry.get("vcgId") or raw_entry.get("productId") or raw_entry.get("product_id") or "").strip()
    model_code = str(raw_entry.get("productid") or raw_entry.get("productId") or "").strip()
    part_number = str(raw_entry.get("partnumber") or raw_entry.get("partNumber") or "").strip()
    hcl_program = str(raw_entry.get("hcl_program") or raw_entry.get("category") or raw_entry.get("program") or "").strip().lower()
    vcglink = str(raw_entry.get("vcglink") or raw_entry.get("vcgLink") or raw_entry.get("link") or "").strip()

    if "program=" in vcglink:
        parsed = urllib.parse.urlparse(vcglink)
        params = urllib.parse.parse_qs(parsed.query)
        link_prog = (params.get("program") or [""])[0].lower()
        if link_prog:
            hcl_program = link_prog

    prog_map = {
        "nic": "rdmanic",
        "controller": "vsanio",
        "drives": "ssd",
    }
    hcl_program = prog_map.get(hcl_program, hcl_program)

    # Check RDMA / RoCE qualification
    rdma_supported = False
    vs_support = []
    vs = raw_entry.get("vsanSupport")
    if isinstance(vs, (list, tuple)):
        vs_support.extend(vs)
    elif isinstance(vs, dict):
        vs_support.extend(vs.get("mode", []))

    if isinstance(raw_rel, dict):
        for r_name, r_data in raw_rel.items():
            if isinstance(r_data, dict):
                r_vs = r_data.get("vsanSupport")
                if isinstance(r_vs, (list, tuple)):
                    vs_support.extend(r_vs)

    vs_str = " ".join(str(s).upper() for s in vs_support)
    if "ROCE" in vs_str or "RDMA" in vs_str or "VSAN ESA" in vs_str or "rdmanic" in vcglink:
        rdma_supported = True

    return {
        "model": model,
        "tier": tier,
        "releases": releases,
        "vendorId": vid,
        "deviceId": did,
        "subVendorId": svid,
        "subDeviceId": ssid,
        "vendor_id": vid,
        "device_id": did,
        "subsystem_vendor_id": svid,
        "subsystem_id": ssid,
        "recommendedDriver": str(rec_driver).strip() if rec_driver else "N/A",
        "recommendedFirmware": str(rec_fw).strip() if rec_fw else "N/A",
        "recommended_driver": str(rec_driver).strip() if rec_driver else "N/A",
        "recommended_firmware": str(rec_fw).strip() if rec_fw else "N/A",
        "releaseMatrix": release_matrix,
        "release_matrix": release_matrix,
        "product_id": product_id,
        "model_code": model_code,
        "part_number": part_number,
        "hcl_program": hcl_program,
        "vcglink": vcglink,
        "rdma_supported": rdma_supported,
    }


def load_vsan_hcl_json(local_path: Optional[str] = None, refresh_live: bool = False, max_age_days: int = 30) -> dict:
    from vcf_hci.hcl.bundle_manager import get_hcl_dir

    if not local_path:
        local_path = os.path.join(get_hcl_dir(), "all.json")

    resolved_path = os.path.abspath(local_path)

    if not refresh_live and os.path.exists(resolved_path):
        try:
            mtime = os.path.getmtime(resolved_path)
            age = (time.time() - mtime) / 86400
            if age <= max_age_days:
                with _HCL_CACHE_LOCK:
                    if resolved_path in _HCL_JSON_CACHE:
                        cached_mtime, cached_index = _HCL_JSON_CACHE[resolved_path]
                        if cached_mtime == mtime:
                            return cached_index
        except Exception:
            pass

    should_download = refresh_live
    if not os.path.exists(resolved_path):
        should_download = True
    else:
        age = (time.time() - os.path.getmtime(resolved_path)) / 86400
        if age > max_age_days:
            should_download = True

    data_payload = None
    if should_download:
        urls_to_try = [LIVE_VSAN_HCL_JSON_URL]
        if LIVE_VSAN_HCL_JSON_URL.endswith(".gz"):
            urls_to_try.append(LIVE_VSAN_HCL_JSON_URL[:-3])

        for url in urls_to_try:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip"})
                ctx = ssl.create_default_context()
                with urllib.request.urlopen(req, context=ctx, timeout=12) as r:
                    raw = r.read()
                    if raw.startswith(b"\x1f\x8b"):
                        try:
                            raw = gzip.decompress(raw)
                        except Exception as ge:
                            logger.debug(f"gzip.decompress error on {url}: {ge}")
                    data_payload = json.loads(raw.decode("utf-8"))
                    with open(resolved_path, "wb") as f:
                        f.write(raw)
                logger.debug(f"Refreshed live vSAN HCL JSON from {url}")
                break
            except Exception as e:
                logger.warning(f"Could not refresh vSAN HCL from {url}: {e}")

    if not data_payload and os.path.exists(resolved_path):
        try:
            with open(resolved_path, "rb") as f:
                raw_bytes = f.read()
                if raw_bytes.startswith(b"\x1f\x8b"):
                    try:
                        raw_bytes = gzip.decompress(raw_bytes)
                    except Exception as ge:
                        logger.debug(f"gzip.decompress error reading {resolved_path}: {ge}")
                data_payload = json.loads(raw_bytes.decode("utf-8"))
        except Exception:
            pass

    hcl_index = {
        "quads": {},
        "pairs": {},
        "models": {},
        "csv_drives": {},
        "_pci_quads": {},
        "_pci_pairs": {},
    }
    if data_payload:
        dev_list = []
        sub_data = data_payload.get("data", {})
        if isinstance(sub_data, dict):
            cat_prog_map = {
                "nic": "rdmanic",
                "controller": "vsanio",
                "drives": "ssd",
            }
            for cat in ["ssd", "hdd", "controller", "drives", "nic"]:
                prog = cat_prog_map.get(cat, cat)
                for entry in sub_data.get(cat, []):
                    if isinstance(entry, dict) and "hcl_program" not in entry:
                        entry["hcl_program"] = prog
                dev_list.extend(sub_data.get(cat, []))
            if not dev_list:
                for k, v in sub_data.items():
                    if isinstance(v, list):
                        dev_list.extend(v)
        elif isinstance(sub_data, list):
            dev_list = sub_data

        if not dev_list:
            dev_list = (
                data_payload.get("drives", [])
                or (data_payload if isinstance(data_payload, list) else [])
            )

        for entry in dev_list:
            if isinstance(entry, dict):
                sanitized = sanitize_hcl_entry(entry)
                model = sanitized["model"]
                tier = sanitized["tier"]
                releases = sanitized["releases"]
                vid = sanitized["vendor_id"]
                did = sanitized["device_id"]
                svid = sanitized["subsystem_vendor_id"]
                ssid = sanitized["subsystem_id"]
                rec_driver = sanitized["recommended_driver"]
                rec_fw = sanitized["recommended_firmware"]
                release_matrix = sanitized["release_matrix"]

                item = {
                    "model": model,
                    "tier": tier if tier else "Unverified / Unsupported",
                    "releases": releases if isinstance(releases, list) else [],
                    "vendor_id": vid,
                    "device_id": did,
                    "subsystem_vendor_id": svid,
                    "subsystem_id": ssid,
                    "recommended_driver": str(rec_driver).strip() if rec_driver else "N/A",
                    "recommended_firmware": str(rec_fw).strip() if rec_fw else "N/A",
                    "release_matrix": release_matrix if isinstance(release_matrix, dict) else {},
                    "product_id": sanitized.get("product_id", ""),
                    "hcl_program": sanitized.get("hcl_program", ""),
                    "vcglink": sanitized.get("vcglink", ""),
                    "rdma_supported": sanitized.get("rdma_supported", False),
                }

                model_code = sanitized.get("model_code", "")
                part_number = sanitized.get("part_number", "")

                if model:
                    hcl_index["models"][model.upper()] = item
                    hcl_index[model.upper()] = item
                if model_code:
                    hcl_index["models"][model_code.upper()] = item
                    hcl_index[model_code.upper()] = item
                if part_number:
                    hcl_index["models"][part_number.upper()] = item
                    hcl_index[part_number.upper()] = item

                if vid and did:
                    if svid and ssid:
                        quad_key = f"{vid}:{did}:{svid}:{ssid}"
                        hcl_index["quads"][quad_key] = item
                        hcl_index["_pci_quads"][quad_key] = item
                        hcl_index[quad_key] = item
                    pair_key = f"{vid}:{did}"
                    hcl_index["pairs"].setdefault(pair_key, []).append(item)
                    hcl_index["_pci_pairs"].setdefault(pair_key, []).append(item)
                    hcl_index[pair_key] = item

    _apply_io_nics_catalog(hcl_index)
    _apply_hcl_supplements(hcl_index)
    if os.path.exists(resolved_path):
        try:
            mtime = os.path.getmtime(resolved_path)
            with _HCL_CACHE_LOCK:
                _HCL_JSON_CACHE[resolved_path] = (mtime, hcl_index)
        except Exception:
            pass
    return hcl_index


KNOWN_HCL_SUPPLEMENTS = {
    # ── Mellanox ConnectX-4 Lx 25GbE Adapters (Broadcom Hypervisor IO HCL ESXi 9.1 Certified) ──
    # Dell Mellanox ConnectX-4 LX Dual Port 25 GbE SFP Rack NDC (PID 42911 / 50014)
    "15b3:1015:15b3:0025": {
        "model": "Mellanox ConnectX-4 LX Dual Port 25 GbE SFP Rack NDC",
        "tier": "vSAN ESA Certified, vSAN All Flash Caching Tier, vSAN All Flash Capacity Tier",
        "releases": ["ESXi 9.1", "ESXi 9.0", "ESXi 8.0 U3", "ESXi 8.0 U2", "ESXi 8.0 U1", "ESXi 8.0", "ESXi 7.0 U3", "ESXi 7.0 U2"],
        "vendor_id": "15b3",
        "device_id": "1015",
        "subsystem_vendor_id": "15b3",
        "subsystem_id": "0025",
        "recommended_driver": "nmlx5_core 4.25.0.25-1vmw.910",
        "recommended_firmware": "14.32.2004",
        "min_firmware": "14.32.2004",
        "release_matrix": {
            "ESXi 9.1": {
                "driver": "nmlx5_core 4.25.0.25-1vmw.910",
                "driver_version": "4.25.0.25-1vmw.910",
                "firmwares": ["14.32.2004"],
                "recommended_firmware": "14.32.2004",
                "min_firmware": "14.32.2004",
            },
            "ESXi 9.0": {
                "driver": "nmlx5_core 4.24.0.7-16vmw.900",
                "driver_version": "4.24.0.7-16vmw.900",
                "firmwares": ["14.32.2004", "14.32.1010"],
                "recommended_firmware": "14.32.2004",
                "min_firmware": "14.32.1010",
            },
        },
        "product_id": "42911",
        "hcl_program": "io",
        "vcglink": "https://compatibilityguide.broadcom.com/detail?program=rdmanic&productId=50014&persona=live",
        "rdma_supported": True,
    },
    # Mellanox ConnectX-4 Lx EN NIC; 25GbE; dual-port SFP28; (MCX4121A-ACA) (PID 48480)
    "15b3:1015:15b3:0003": {
        "model": "ConnectX-4 Lx EN NIC; 25GbE; dual-port SFP28; (MCX4121A-ACA)",
        "tier": "vSAN ESA Certified, vSAN All Flash Caching Tier, vSAN All Flash Capacity Tier",
        "releases": ["ESXi 9.1", "ESXi 9.0", "ESXi 8.0 U3", "ESXi 8.0 U2", "ESXi 8.0 U1", "ESXi 8.0", "ESXi 7.0 U3", "ESXi 7.0 U2"],
        "vendor_id": "15b3",
        "device_id": "1015",
        "subsystem_vendor_id": "15b3",
        "subsystem_id": "0003",
        "recommended_driver": "nmlx5_core 4.25.0.25-1vmw.910",
        "recommended_firmware": "14.32.2004",
        "min_firmware": "14.32.2004",
        "release_matrix": {
            "ESXi 9.1": {
                "driver": "nmlx5_core 4.25.0.25-1vmw.910",
                "driver_version": "4.25.0.25-1vmw.910",
                "firmwares": ["14.32.2004"],
                "recommended_firmware": "14.32.2004",
                "min_firmware": "14.32.2004",
            },
            "ESXi 9.0": {
                "driver": "nmlx5_core 4.24.0.7-16vmw.900",
                "driver_version": "4.24.0.7-16vmw.900",
                "firmwares": ["14.32.1010"],
                "recommended_firmware": "14.32.1010",
                "min_firmware": "14.32.1010",
            },
        },
        "product_id": "48480",
        "hcl_program": "io",
        "vcglink": "https://compatibilityguide.broadcom.com/detail?program=rdmanic&productId=48480&persona=live",
        "rdma_supported": True,
    },
    # Mellanox ConnectX®-4 LX Dual Port 25 GbE KR Mezzanine Card (PID 50012)
    "15b3:1015:15b3:0116": {
        "model": "Mellanox ConnectX®-4 LX Dual Port 25 GbE KR Mezzanine Card",
        "tier": "vSAN ESA Certified, vSAN All Flash Caching Tier, vSAN All Flash Capacity Tier",
        "releases": ["ESXi 9.1", "ESXi 9.0", "ESXi 8.0 U3", "ESXi 8.0 U2", "ESXi 8.0 U1", "ESXi 8.0", "ESXi 7.0 U3", "ESXi 7.0 U2"],
        "vendor_id": "15b3",
        "device_id": "1015",
        "subsystem_vendor_id": "15b3",
        "subsystem_id": "0116",
        "recommended_driver": "nmlx5_core 4.25.0.25-1vmw.910",
        "recommended_firmware": "14.32.2004",
        "min_firmware": "14.32.2004",
        "release_matrix": {
            "ESXi 9.1": {
                "driver": "nmlx5_core 4.25.0.25-1vmw.910",
                "driver_version": "4.25.0.25-1vmw.910",
                "firmwares": ["14.32.2004"],
                "recommended_firmware": "14.32.2004",
                "min_firmware": "14.32.2004",
            },
            "ESXi 9.0": {
                "driver": "nmlx5_core 4.24.0.7-16vmw.900",
                "driver_version": "4.24.0.7-16vmw.900",
                "firmwares": ["14.32.2004", "14.32.1010"],
                "recommended_firmware": "14.32.2004",
                "min_firmware": "14.32.1010",
            },
        },
        "product_id": "50012",
        "hcl_program": "io",
        "vcglink": "https://compatibilityguide.broadcom.com/detail?program=rdmanic&productId=50012&persona=live",
        "rdma_supported": True,
    },
    # ConnectX-4 Lx EN NIC; 25GbE; dual-port SFP28; PCIe3.0 x8; (MCX4121A-ACHT) (PID 53187)
    "15b3:1015:15b3:0098": {
        "model": "ConnectX-4 Lx EN NIC; 25GbE; dual-port SFP28; PCIe3.0 x8; (MCX4121A-ACHT)",
        "tier": "vSAN ESA Certified, vSAN All Flash Caching Tier, vSAN All Flash Capacity Tier",
        "releases": ["ESXi 9.1", "ESXi 9.0", "ESXi 8.0 U3", "ESXi 8.0 U2", "ESXi 8.0 U1", "ESXi 8.0", "ESXi 7.0 U3", "ESXi 7.0 U2"],
        "vendor_id": "15b3",
        "device_id": "1015",
        "subsystem_vendor_id": "15b3",
        "subsystem_id": "0098",
        "recommended_driver": "nmlx5_core 4.25.0.25-1vmw.910",
        "recommended_firmware": "14.32.2004",
        "min_firmware": "14.32.2004",
        "release_matrix": {
            "ESXi 9.1": {
                "driver": "nmlx5_core 4.25.0.25-1vmw.910",
                "driver_version": "4.25.0.25-1vmw.910",
                "firmwares": ["14.32.2004"],
                "recommended_firmware": "14.32.2004",
                "min_firmware": "14.32.2004",
            },
            "ESXi 9.0": {
                "driver": "nmlx5_core 4.24.0.7-16vmw.900",
                "driver_version": "4.24.0.7-16vmw.900",
                "firmwares": ["14.32.1010"],
                "recommended_firmware": "14.32.1010",
                "min_firmware": "14.32.1010",
            },
        },
        "product_id": "53187",
        "hcl_program": "io",
        "vcglink": "https://compatibilityguide.broadcom.com/detail?program=rdmanic&productId=53187&persona=live",
        "rdma_supported": True,
    },
    # ConnectX-4 Lx EN NIC; 25GbE; dual-port SFP28; PCIe3.0 x8; (MCX4121A-ACU) (PID 53752)
    "15b3:1015:15b3:0069": {
        "model": "ConnectX-4 Lx EN NIC; 25GbE; dual-port SFP28; PCIe3.0 x8; (MCX4121A-ACU)",
        "tier": "vSAN ESA Certified, vSAN All Flash Caching Tier, vSAN All Flash Capacity Tier",
        "releases": ["ESXi 9.1", "ESXi 9.0", "ESXi 8.0 U3", "ESXi 8.0 U2", "ESXi 8.0 U1", "ESXi 8.0", "ESXi 7.0 U3", "ESXi 7.0 U2"],
        "vendor_id": "15b3",
        "device_id": "1015",
        "subsystem_vendor_id": "15b3",
        "subsystem_id": "0069",
        "recommended_driver": "nmlx5_core 4.25.0.25-1vmw.910",
        "recommended_firmware": "14.32.2004",
        "min_firmware": "14.32.2004",
        "release_matrix": {
            "ESXi 9.1": {
                "driver": "nmlx5_core 4.25.0.25-1vmw.910",
                "driver_version": "4.25.0.25-1vmw.910",
                "firmwares": ["14.32.2004"],
                "recommended_firmware": "14.32.2004",
                "min_firmware": "14.32.2004",
            },
            "ESXi 9.0": {
                "driver": "nmlx5_core 4.24.0.7-16vmw.900",
                "driver_version": "4.24.0.7-16vmw.900",
                "firmwares": ["14.32.1010"],
                "recommended_firmware": "14.32.1010",
                "min_firmware": "14.32.1010",
            },
        },
        "product_id": "53752",
        "hcl_program": "io",
        "vcglink": "https://compatibilityguide.broadcom.com/detail?program=rdmanic&productId=53752&persona=live",
        "rdma_supported": True,
    },
    # ConnectX-4 Lx EN NIC; OCP2.0, Type 1; 25GbE; dual-port SFP28; PCIe3.0 x8; (MCX4421A-ACA) (PID 53754)
    "15b3:1015:15b3:0009": {
        "model": "ConnectX-4 Lx EN NIC; OCP2.0, Type 1; 25GbE; dual-port SFP28; PCIe3.0 x8; (MCX4421A-ACA)",
        "tier": "vSAN ESA Certified, vSAN All Flash Caching Tier, vSAN All Flash Capacity Tier",
        "releases": ["ESXi 9.1", "ESXi 9.0", "ESXi 8.0 U3", "ESXi 8.0 U2", "ESXi 8.0 U1", "ESXi 8.0", "ESXi 7.0 U3", "ESXi 7.0 U2"],
        "vendor_id": "15b3",
        "device_id": "1015",
        "subsystem_vendor_id": "15b3",
        "subsystem_id": "0009",
        "recommended_driver": "nmlx5_core 4.25.0.25-1vmw.910",
        "recommended_firmware": "14.32.2004",
        "min_firmware": "14.32.2004",
        "release_matrix": {
            "ESXi 9.1": {
                "driver": "nmlx5_core 4.25.0.25-1vmw.910",
                "driver_version": "4.25.0.25-1vmw.910",
                "firmwares": ["14.32.2004"],
                "recommended_firmware": "14.32.2004",
                "min_firmware": "14.32.2004",
            },
            "ESXi 9.0": {
                "driver": "nmlx5_core 4.24.0.7-16vmw.900",
                "driver_version": "4.24.0.7-16vmw.900",
                "firmwares": ["14.32.1010"],
                "recommended_firmware": "14.32.1010",
                "min_firmware": "14.32.1010",
            },
        },
        "product_id": "53754",
        "hcl_program": "io",
        "vcglink": "https://compatibilityguide.broadcom.com/detail?program=rdmanic&productId=53754&persona=live",
        "rdma_supported": True,
    },
}


def _apply_hcl_supplements(hcl_index: dict) -> None:
    """Overlay authoritative General VMware ESXi Hypervisor IO HCL certifications
    into the HCL index to supplement lagging or missing entries in the vSAN JSON feed.
    """
    if not isinstance(hcl_index, dict):
        return
    quads = hcl_index.setdefault("quads", {})
    pci_quads = hcl_index.setdefault("_pci_quads", {})
    pairs = hcl_index.setdefault("pairs", {})
    pci_pairs = hcl_index.setdefault("_pci_pairs", {})
    models = hcl_index.setdefault("models", {})

    for quad_key, supp in KNOWN_HCL_SUPPLEMENTS.items():
        if supp.get("hcl_program") == "io" or supp.get("product_id"):
            supp.setdefault("io_product_id", supp.get("product_id"))
            if not supp.get("io_vcglink") and supp.get("io_product_id"):
                supp["io_vcglink"] = f"https://compatibilityguide.broadcom.com/detail?program=io&productId={supp['io_product_id']}&persona=live"

        quads[quad_key] = supp
        pci_quads[quad_key] = supp
        hcl_index[quad_key] = supp
        if supp.get("model") and isinstance(supp["model"], str):
            m_up = supp["model"].upper()
            models[m_up] = supp
            hcl_index[m_up] = supp

        pair_key = f"{supp.get('vendor_id')}:{supp.get('device_id')}"
        if pair_key in pairs:
            existing_list = pairs[pair_key]
            updated = False
            for idx, item in enumerate(existing_list):
                if (
                    isinstance(item, dict)
                    and item.get("subsystem_vendor_id") == supp.get("subsystem_vendor_id")
                    and item.get("subsystem_id") == supp.get("subsystem_id")
                ):
                    existing_list[idx] = supp
                    updated = True
                    break
            if not updated:
                existing_list.append(supp)
        else:
            pairs.setdefault(pair_key, []).append(supp)
            pci_pairs.setdefault(pair_key, []).append(supp)


def load_io_nics_catalog(custom_path: Optional[str] = None) -> dict:
    """Load offline Broadcom BCG program=io Network I/O adapter catalog (io_nics.json)."""
    from vcf_hci.hcl.bundle_manager import get_hcl_dir

    candidate_paths = []
    if custom_path:
        candidate_paths.append(custom_path)
    hcl_dir = get_hcl_dir()
    candidate_paths.extend([
        os.path.join(hcl_dir, "io_nics.json"),
        os.path.join(os.path.dirname(__file__), "io_nics.json"),
        os.path.abspath("io_nics.json"),
        os.path.abspath("vcf_hci/hcl/io_nics.json"),
    ])

    target_path = None
    for p in candidate_paths:
        if os.path.exists(p):
            target_path = os.path.abspath(p)
            break

    if not target_path:
        try:
            from vcf_hci.hcl.packaged_catalog import load_packaged_io_nics
            packaged = load_packaged_io_nics()
        except Exception:
            packaged = None
        if isinstance(packaged, dict) and packaged:
            return packaged
        return {}

    try:
        mtime = os.path.getmtime(target_path)
        with _HCL_CACHE_LOCK:
            if target_path in _IO_NICS_CACHE:
                cached_mtime, cached_cat = _IO_NICS_CACHE[target_path]
                if cached_mtime == mtime:
                    return cached_cat
    except Exception:
        pass

    try:
        with open(target_path, encoding="utf-8") as f:
            catalog = json.load(f)
        try:
            mtime = os.path.getmtime(target_path)
            with _HCL_CACHE_LOCK:
                _IO_NICS_CACHE[target_path] = (mtime, catalog)
        except Exception:
            pass
        return catalog
    except Exception as e:
        logger.warning(f"Failed to load IO NICs catalog from {target_path}: {e}")
        return {}


def _apply_io_nics_catalog(hcl_index: dict, io_catalog: Optional[dict] = None) -> None:
    """Overlay Broadcom BCG program=io network devices into the HCL index.

    Enriches existing devices with io_product_id and io_vcglink, and inserts
    non-RDMA ESXi 9.1/9.0 certified NICs so PCI compatibility and firmware
    baselines can evaluate them accurately.
    """
    if not isinstance(hcl_index, dict):
        return

    cat = io_catalog if (io_catalog and isinstance(io_catalog, dict)) else load_io_nics_catalog()
    if not cat or not isinstance(cat, dict):
        return

    hcl_index["io_nics"] = cat
    quads = hcl_index.setdefault("quads", {})
    pci_quads = hcl_index.setdefault("_pci_quads", {})
    pairs = hcl_index.setdefault("pairs", {})
    pci_pairs = hcl_index.setdefault("_pci_pairs", {})
    models = hcl_index.setdefault("models", {})

    devices = cat.get("devices") or list(cat.get("quads", {}).values())
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        quad = dev.get("pci_quad") or (
            f"{dev.get('vendor_id')}:{dev.get('device_id')}:{dev.get('subsystem_vendor_id')}:{dev.get('subsystem_id')}"
            if (dev.get("vendor_id") and dev.get("device_id") and dev.get("subsystem_vendor_id") and dev.get("subsystem_id"))
            else ""
        )
        vid = dev.get("vendor_id", "")
        did = dev.get("device_id", "")
        svid = dev.get("subsystem_vendor_id", "")
        ssid = dev.get("subsystem_id", "")
        pair = dev.get("pci_pair") or (f"{vid}:{did}" if (vid and did) else "")
        model_name = dev.get("model", "")
        io_pid = str(dev.get("product_id") or dev.get("uuid") or "").strip()
        io_vcglink = str(dev.get("vcglink") or "").strip()
        if not io_vcglink and io_pid:
            io_vcglink = f"https://compatibilityguide.broadcom.com/detail?program=io&productId={io_pid}&persona=live"

        rec_driver = dev.get("recommended_driver", "")
        rec_fw = dev.get("recommended_firmware", "")
        min_fw = dev.get("min_firmware", "")
        rel_matrix = dev.get("release_matrix", {})
        releases = dev.get("supported_releases") or ["ESXi 9.1", "ESXi 9.0"]

        if quad and quad in quads:
            existing = quads[quad]
            if isinstance(existing, dict):
                existing["io_product_id"] = io_pid
                existing["io_vcglink"] = io_vcglink
                if not existing.get("recommended_driver") or existing.get("recommended_driver") in ("N/A", ""):
                    existing["recommended_driver"] = rec_driver or "N/A"
                if not existing.get("recommended_firmware") or existing.get("recommended_firmware") in ("N/A", ""):
                    existing["recommended_firmware"] = rec_fw or "N/A"
                if not existing.get("min_firmware") or existing.get("min_firmware") in ("N/A", ""):
                    existing["min_firmware"] = min_fw or rec_fw or "N/A"

                if rel_matrix and isinstance(existing.get("release_matrix"), dict):
                    for rel_k, rel_v in rel_matrix.items():
                        if rel_k not in existing["release_matrix"]:
                            existing["release_matrix"][rel_k] = rel_v
                        elif isinstance(rel_v, dict) and isinstance(existing["release_matrix"][rel_k], dict):
                            cur_fws = existing["release_matrix"][rel_k].setdefault("firmwares", [])
                            for fw in rel_v.get("firmwares", []):
                                if fw not in cur_fws:
                                    cur_fws.append(fw)
        elif quad and vid and did and svid and ssid:
            item = {
                "model": model_name,
                "tier": "ESXi 9.1 Certified",
                "releases": releases,
                "vendor_id": vid,
                "device_id": did,
                "subsystem_vendor_id": svid,
                "subsystem_id": ssid,
                "recommended_driver": rec_driver or "N/A",
                "recommended_firmware": rec_fw or "N/A",
                "min_firmware": min_fw or rec_fw or "N/A",
                "release_matrix": rel_matrix,
                "product_id": io_pid,
                "io_product_id": io_pid,
                "hcl_program": "io",
                "vcglink": io_vcglink,
                "io_vcglink": io_vcglink,
                "rdma_supported": False,
            }
            quads[quad] = item
            pci_quads[quad] = item
            hcl_index[quad] = item

            if pair:
                pairs.setdefault(pair, []).append(item)
                pci_pairs.setdefault(pair, []).append(item)
                if pair not in hcl_index:
                    hcl_index[pair] = item

            if model_name:
                m_up = model_name.strip().upper()
                if m_up not in models:
                    models[m_up] = item
                    hcl_index[m_up] = item


def load_optional_vsan_csv(custom_csv_path: Optional[str] = None) -> dict:
    from vcf_hci.hcl.bundle_manager import get_hcl_dir

    target_path = None
    if custom_csv_path and os.path.exists(custom_csv_path):
        target_path = custom_csv_path

    if not target_path:
        hcl_dir = get_hcl_dir()
        candidate_paths = [
            os.path.join(hcl_dir, "vsan_drives.csv"),
            "vsan_drives.csv",
        ]
        for p in candidate_paths:
            if os.path.exists(p):
                target_path = p
                break

    if not target_path:
        matches = glob.glob("*vsan*.csv") + glob.glob("*VSAN*.csv") + glob.glob("hcl/*SSD*.csv") + glob.glob(os.path.join(get_hcl_dir(), "*vsan*.csv"))
        target_path = matches[0] if matches else None
    if not target_path or not os.path.exists(target_path):
        return {}

    resolved_target = os.path.abspath(target_path)
    try:
        mtime = os.path.getmtime(resolved_target)
        with _HCL_CACHE_LOCK:
            if resolved_target in _CSV_DB_CACHE:
                cached_mtime, cached_db = _CSV_DB_CACHE[resolved_target]
                if cached_mtime == mtime:
                    return cached_db
    except Exception:
        pass

    db = {}
    try:
        with open(resolved_target, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                model = str(row.get("Model", "")).strip()
                tier = str(row.get("Tier", "")).strip()
                if model:
                    db.setdefault(model, set())
                    for t in tier.split("\n"):
                        if t.strip():
                            db[model].add(t.strip())
    except Exception:
        pass

    try:
        mtime = os.path.getmtime(resolved_target)
        with _HCL_CACHE_LOCK:
            _CSV_DB_CACHE[resolved_target] = (mtime, db)
    except Exception:
        pass

    return db


def _format_short_date(val: Any) -> str:
    """Format an epoch timestamp or date string into 'Mon Day' (e.g. 'Aug 25')."""
    if not val:
        return ""
    if isinstance(val, (int, float)):
        try:
            return time.strftime("%b %d", time.gmtime(val)).replace(" 0", " ")
        except Exception:
            pass
    s = str(val).strip()
    if s.isdigit():
        try:
            return time.strftime("%b %d", time.gmtime(float(s))).replace(" 0", " ")
        except Exception:
            pass
    for fmt in [
        "%B %d, %Y, %I:%M %p %Z",
        "%B %d, %Y, %H:%M %Z",
        "%B %d, %Y",
        "%b %d, %Y %H:%M %Z",
        "%b %d, %Y",
        "%Y-%m-%d %H:%M %Z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%SZ",
    ]:
        try:
            clean_s = s
            clean_fmt = fmt
            if fmt.endswith("%Z") and s.endswith(" UTC"):
                clean_s = s[:-4].strip()
                clean_fmt = fmt[:-3].strip()
            parsed = time.strptime(clean_s, clean_fmt)
            return time.strftime("%b %d", parsed).replace(" 0", " ")
        except Exception:
            continue

    month_names = {
        "january": "Jan", "jan": "Jan",
        "february": "Feb", "feb": "Feb",
        "march": "Mar", "mar": "Mar",
        "april": "Apr", "apr": "Apr",
        "may": "May",
        "june": "Jun", "jun": "Jun",
        "july": "Jul", "jul": "Jul",
        "august": "Aug", "aug": "Aug",
        "september": "Sep", "sep": "Sep",
        "october": "Oct", "oct": "Oct",
        "november": "Nov", "nov": "Nov",
        "december": "Dec", "dec": "Dec",
    }
    m = re.search(r"([A-Za-z]+)\s+(\d{1,2})", s)
    if m and m.group(1).lower() in month_names:
        return f"{month_names[m.group(1).lower()]} {int(m.group(2))}"
    m_iso = re.search(r"\d{4}-(\d{2})-(\d{2})", s)
    if m_iso:
        try:
            month_idx = int(m_iso.group(1))
            day = int(m_iso.group(2))
            mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][month_idx - 1]
            return f"{mon} {day}"
        except Exception:
            pass
    return s


def get_hcl_cache_status(local_path: Optional[str] = None) -> dict:
    """Return status and freshness metadata for the cached HCL JSON dataset."""
    from vcf_hci.hcl.bundle_manager import get_hcl_dir
    is_custom_target = bool(local_path)
    if not local_path:
        local_path = os.path.join(get_hcl_dir(), "all.json")

    file_exists = os.path.exists(local_path)
    if not file_exists and not is_custom_target:
        if os.path.exists("all.json"):
            local_path = os.path.abspath("all.json")
            file_exists = True

    if not file_exists:
        return {
            "file_exists": False,
            "file_path": local_path,
            "last_downloaded_timestamp": None,
            "last_downloaded_display": "Never",
            "last_downloaded_short": "Never",
            "last_downloaded_iso": None,
            "age_days": None,
            "is_fresh": False,
            "upstream_updated_time": None,
            "upstream_updated_short": None,
            "upstream_timestamp": None,
            "counts": {"ssd": 0, "nic": 0, "controller": 0, "hdd": 0, "total": 0},
            "source_type": "missing",
            "file_size_mb": 0.0,
            "file_size_mb_int": 0,
        }

    mtime = os.path.getmtime(local_path)
    file_size_bytes = os.path.getsize(local_path)
    file_size_mb = round(file_size_bytes / (1024.0 * 1024.0), 2)
    file_size_mb_int = int(round(file_size_bytes / (1024.0 * 1024.0)))
    age_days = round((time.time() - mtime) / 86400.0, 1)
    is_fresh = age_days <= 30.0
    last_downloaded_display = time.strftime("%b %d, %Y %H:%M UTC", time.gmtime(mtime))
    last_downloaded_short = _format_short_date(mtime)
    last_downloaded_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))

    upstream_updated_time = None
    upstream_timestamp = None
    counts = {"ssd": 0, "nic": 0, "controller": 0, "hdd": 0, "total": 0}

    try:
        with open(local_path, "rb") as f:
            raw_bytes = f.read()
            if raw_bytes.startswith(b"\x1f\x8b"):
                try:
                    raw_bytes = gzip.decompress(raw_bytes)
                except Exception:
                    pass
            payload = json.loads(raw_bytes.decode("utf-8"))
            upstream_updated_time = payload.get("jsonUpdatedTime")
            upstream_timestamp = payload.get("timestamp")
            sub_data = payload.get("data", {})
            if isinstance(sub_data, dict):
                for cat in ["ssd", "nic", "controller", "hdd"]:
                    c_list = sub_data.get(cat, [])
                    if isinstance(c_list, list):
                        counts[cat] = len(c_list)
                counts["total"] = sum(counts.values())
            elif isinstance(sub_data, list):
                counts["total"] = len(sub_data)
            else:
                drives = payload.get("drives", [])
                if isinstance(drives, list):
                    counts["total"] = len(drives)
    except Exception as e:
        logger.debug(f"Error inspecting HCL payload for cache status: {e}")

    upstream_updated_short = _format_short_date(upstream_timestamp or upstream_updated_time)

    return {
        "file_exists": True,
        "file_path": local_path,
        "last_downloaded_timestamp": mtime,
        "last_downloaded_display": last_downloaded_display,
        "last_downloaded_short": last_downloaded_short,
        "last_downloaded_iso": last_downloaded_iso,
        "age_days": age_days,
        "is_fresh": is_fresh,
        "upstream_updated_time": upstream_updated_time,
        "upstream_updated_short": upstream_updated_short,
        "upstream_timestamp": upstream_timestamp,
        "counts": counts,
        "source_type": "live_cache",
        "file_size_mb": file_size_mb,
        "file_size_mb_int": file_size_mb_int,
    }

