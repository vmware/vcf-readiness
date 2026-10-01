"""
VCF Readiness Tool — Fleet Library crawl, discovery, manifest I/O, and assembly.

Provides discovery and merging across multiple scan drops (folders or zip archives)
into a unified fleet inventory with identity deduplication and provenance tracking.
"""

import datetime
import gc
import json
import logging
import os
import time
import zipfile
from typing import Any, Dict, List, Optional, Set, Union

from vcf_hci.constants import TOOL_VERSION
from vcf_hci.summary_io import load_summary

logger = logging.getLogger(__name__)

# Sensitive key names that must never be written into MANIFEST.json
_FORBIDDEN_MANIFEST_KEYS = (
    "password", "passwd", "secret", "token", "cred", "auth", "key", "passphrase", "vault"
)

_INVALID_ID_VALUES = {"unknown", "n/a", "none", "redacted", "—", "", "00000000-0000-0000-0000-000000000000"}


def write_scan_manifest(
    outdir: str,
    host_count: int,
    site: Optional[str] = None,
    collector_id: Optional[str] = None,
    scan_profile: Optional[str] = None,
    obfuscated: bool = False,
    scanned_at: Optional[str] = None,
    tool_version: Optional[str] = None,
    extra_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Write tiny, secret-free MANIFEST.json to scan directory.

    Fields: tool_version, scanned_at, host_count, collector_id, site, scan_profile, obfuscated.
    """
    os.makedirs(outdir, exist_ok=True)
    manifest_path = os.path.join(outdir, "MANIFEST.json")

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    manifest: Dict[str, Any] = {
        "tool_version": str(tool_version or TOOL_VERSION),
        "scanned_at": str(scanned_at or now_iso),
        "host_count": int(host_count),
        "collector_id": str(collector_id or ""),
        "site": str(site or ""),
        "scan_profile": str(scan_profile or ""),
        "obfuscated": bool(obfuscated),
    }

    if extra_meta and isinstance(extra_meta, dict):
        for k, v in extra_meta.items():
            if not isinstance(k, str):
                continue
            k_lower = k.lower()
            if any(bad in k_lower for bad in _FORBIDDEN_MANIFEST_KEYS):
                continue
            if k not in manifest:
                manifest[k] = v

    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, default=str)
    except Exception as exc:
        logger.warning("Could not write MANIFEST.json to %s: %s", outdir, exc)

    return manifest


def read_scan_manifest(scan_path: str) -> Optional[Dict[str, Any]]:
    """Read MANIFEST.json from a scan directory or zip archive if present."""
    if not scan_path or not os.path.exists(scan_path):
        return None

    if os.path.isdir(scan_path):
        mpath = os.path.join(scan_path, "MANIFEST.json")
        if os.path.isfile(mpath):
            try:
                with open(mpath, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("Failed reading MANIFEST.json in %s: %s", scan_path, exc)
        return None

    if zipfile.is_zipfile(scan_path):
        try:
            with zipfile.ZipFile(scan_path, "r") as zf:
                for name in zf.namelist():
                    if os.path.basename(name) == "MANIFEST.json":
                        raw = zf.read(name).decode("utf-8")
                        data = json.loads(raw)
                        if isinstance(data, dict):
                            return data
        except (json.JSONDecodeError, OSError, zipfile.BadZipFile) as exc:
            logger.debug("Failed reading MANIFEST.json in zip %s: %s", scan_path, exc)
        return None

    return None


def parse_timestamp(ts: Any) -> float:
    """Parse various timestamp formats into POSIX epoch seconds for ordering."""
    if ts is None:
        return 0.0
    if isinstance(ts, (int, float)):
        return float(ts)
    if not isinstance(ts, str):
        return 0.0

    ts_str = ts.strip()
    if not ts_str:
        return 0.0

    # 1. ISO 8601 (e.g. 2026-09-21T14:30:00Z or with offset)
    try:
        iso_clean = ts_str.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(iso_clean)
        return dt.timestamp()
    except (ValueError, AttributeError):
        pass

    # 2. Folder / filename formats (e.g. 20260921_143000, 2026-09-21_1430, etc.)
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y%m%d_%H%M%S",
        "%Y%m%d_%H%M",
        "%Y-%m-%d_%H%M",
        "%Y-%m-%d",
    ):
        try:
            t_struct = time.strptime(ts_str, fmt)
            return time.mktime(t_struct)
        except ValueError:
            pass

    # 3. Numeric string
    try:
        return float(ts_str)
    except ValueError:
        pass

    return 0.0


def get_scan_identity(host_data: Dict[str, Any]) -> str:
    """Derive deterministic identity key for deduplication.

    Order of priority (first non-empty, non-sentinel match wins):
      1. Redfish system UUID
      2. Serial number + Server model
      3. BMC IP address
      4. Hostname / FQDN
    """
    sys_data = host_data.get("system") or {}
    if not isinstance(sys_data, dict):
        sys_data = {}

    # 1. System UUID
    uuid = str(
        sys_data.get("system_uuid")
        or sys_data.get("uuid")
        or host_data.get("system_uuid")
        or host_data.get("uuid")
        or ""
    ).strip()
    if uuid and uuid.lower() not in _INVALID_ID_VALUES:
        return f"uuid:{uuid.lower()}"

    # 2. Serial + Model
    serial = str(
        sys_data.get("serial_number")
        or sys_data.get("serial")
        or host_data.get("serial_number")
        or host_data.get("serial")
        or ""
    ).strip()
    model = str(
        sys_data.get("model")
        or host_data.get("model")
        or ""
    ).strip()
    if (
        serial
        and serial.lower() not in _INVALID_ID_VALUES
        and model
        and model.lower() not in _INVALID_ID_VALUES
        and model.lower() != "unknown server"
    ):
        return f"serial_model:{serial.upper()}_{model.upper()}"

    # 3. BMC IP
    bmc_ip = str(
        sys_data.get("bmc_ip")
        or sys_data.get("ip")
        or host_data.get("bmc_ip")
        or host_data.get("ip")
        or host_data.get("host")
        or ""
    ).strip()
    if bmc_ip and bmc_ip.lower() not in _INVALID_ID_VALUES:
        return f"bmc_ip:{bmc_ip}"

    # 4. Hostname
    hostname = str(
        sys_data.get("hostname")
        or host_data.get("hostname")
        or ""
    ).strip()
    if hostname and hostname.lower() not in _INVALID_ID_VALUES:
        return f"hostname:{hostname.lower()}"

    # Fallback
    return f"raw:{id(host_data)}"


def _is_scan_dir(dir_path: str) -> bool:
    """Check if dir_path is a scan output directory."""
    if not os.path.isdir(dir_path):
        return False
    if os.path.isfile(os.path.join(dir_path, "MANIFEST.json")):
        return True
    if os.path.isfile(os.path.join(dir_path, "data", "fleet_summary.json")):
        return True
    if os.path.isfile(os.path.join(dir_path, "data", "fleet_summary.json.gz")):
        return True
    if os.path.isfile(os.path.join(dir_path, "fleet_summary.json")):
        return True
    if os.path.isfile(os.path.join(dir_path, "fleet_summary.json.gz")):
        return True
    try:
        entries = os.listdir(dir_path)
        if any(e.startswith("vcf_summary_") and (e.endswith(".json") or e.endswith(".json.gz")) for e in entries):
            return True
    except OSError:
        pass
    return False


def _is_scan_zip(zip_path: str) -> bool:
    """Check if zip_path is a valid scan zip archive."""
    if not zip_path.lower().endswith(".zip") or not os.path.isfile(zip_path):
        return False
    if not zipfile.is_zipfile(zip_path):
        return False
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            namelist = zf.namelist()
            for name in namelist:
                base = os.path.basename(name)
                if base == "MANIFEST.json":
                    return True
                if base in ("fleet_summary.json", "fleet_summary.json.gz"):
                    return True
                if base.startswith("vcf_summary_") and (base.endswith(".json") or base.endswith(".json.gz")):
                    return True
    except (zipfile.BadZipFile, OSError):
        return False
    return False


def _build_scan_ref(scan_path: str, is_zip: bool) -> Dict[str, Any]:
    """Extract scan reference metadata from directory or zip."""
    abs_path = os.path.abspath(scan_path)
    scan_id = os.path.splitext(os.path.basename(abs_path))[0] if is_zip else os.path.basename(abs_path)
    manifest = read_scan_manifest(abs_path) or {}
    try:
        mtime = os.path.getmtime(abs_path)
    except OSError:
        mtime = time.time()

    mtime_iso = datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc).isoformat()
    scanned_at = str(manifest.get("scanned_at") or mtime_iso)
    tool_version = str(manifest.get("tool_version") or "")
    host_count = manifest.get("host_count")
    collector_id = str(manifest.get("collector_id") or "")
    site = str(manifest.get("site") or "")
    scan_profile = str(manifest.get("scan_profile") or "")

    is_obf = bool(manifest.get("obfuscated"))
    if not is_obf:
        base_name = os.path.basename(abs_path)
        if base_name.startswith("OBFUSCATED_") or "_obfuscated" in base_name.lower():
            is_obf = True

    return {
        "scan_id": scan_id,
        "path": abs_path,
        "is_zip": is_zip,
        "manifest": manifest,
        "tool_version": tool_version,
        "scanned_at": scanned_at,
        "host_count": host_count,
        "collector_id": collector_id,
        "site": site,
        "scan_profile": scan_profile,
        "obfuscated": is_obf,
        "mtime": mtime,
    }


def discover_scans(library_dir: str, max_depth: int = 4) -> List[Dict[str, Any]]:
    """Discover scan directories and zip archives in library_dir.

    Shallow-smart recursive search up to max_depth.
    Skips obfuscated duplicate scans when a plain counterpart exists.
    """
    if not library_dir or not os.path.exists(library_dir):
        return []

    abs_lib = os.path.abspath(os.path.expanduser(library_dir))

    if os.path.isfile(abs_lib) and _is_scan_zip(abs_lib):
        return [_build_scan_ref(abs_lib, is_zip=True)]

    if not os.path.isdir(abs_lib):
        return []

    # Check if library_dir itself is a single scan directory with no child scans
    if _is_scan_dir(abs_lib):
        # Check if it has any subdirectories that are also scans
        has_sub_scans = False
        try:
            for entry in os.listdir(abs_lib):
                sub = os.path.join(abs_lib, entry)
                if os.path.isdir(sub) and entry not in ("data", "reports", "logs") and _is_scan_dir(sub):
                    has_sub_scans = True
                    break
                if os.path.isfile(sub) and _is_scan_zip(sub):
                    has_sub_scans = True
                    break
        except OSError:
            pass

        if not has_sub_scans:
            return [_build_scan_ref(abs_lib, is_zip=False)]

    discovered: List[Dict[str, Any]] = []
    base_depth = abs_lib.rstrip(os.sep).count(os.sep)

    for root, dirs, files in os.walk(abs_lib):
        cur_depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if cur_depth > max_depth:
            dirs.clear()
            continue

        # Prune hidden or system directories
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("__pycache__", ".venv", "node_modules")]

        # Check for zip archives in current directory
        for f in files:
            if f.lower().endswith(".zip"):
                zpath = os.path.join(root, f)
                if _is_scan_zip(zpath):
                    discovered.append(_build_scan_ref(zpath, is_zip=True))

        # Check subdirectories: if a subdirectory is a scan dir, add it and do not recurse into it
        subdirs_to_prune = []
        for d in dirs:
            cand_dir = os.path.join(root, d)
            if _is_scan_dir(cand_dir):
                discovered.append(_build_scan_ref(cand_dir, is_zip=False))
                subdirs_to_prune.append(d)

        for d in subdirs_to_prune:
            dirs.remove(d)

    # Filter out obfuscated duplicates when a plain version exists
    plain_scan_ids: Set[str] = set()
    for s in discovered:
        if not s["obfuscated"]:
            plain_scan_ids.add(s["scan_id"])
            parent_dir = os.path.dirname(s["path"])
            plain_scan_ids.add(f"{parent_dir}::{s['scan_id']}")

    filtered: List[Dict[str, Any]] = []
    for s in discovered:
        if s["obfuscated"]:
            sid = s["scan_id"]
            parent_dir = os.path.dirname(s["path"])
            plain_equiv = sid
            if plain_equiv.startswith("OBFUSCATED_"):
                plain_equiv = plain_equiv[len("OBFUSCATED_"):]
            elif plain_equiv.endswith("_obfuscated"):
                plain_equiv = plain_equiv[:-len("_obfuscated")]

            if plain_equiv in plain_scan_ids or f"{parent_dir}::{plain_equiv}" in plain_scan_ids:
                logger.debug("Skipping obfuscated duplicate scan %s in favor of plain %s", sid, plain_equiv)
                continue
        filtered.append(s)

    # Sort descending by scanned_at / mtime
    filtered.sort(key=lambda x: parse_timestamp(x.get("scanned_at") or x.get("mtime")), reverse=True)
    return filtered


def assemble_fleet(
    scan_refs: Union[str, List[Any]],
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble and deduplicate hosts across multiple scans into a single fleet dataset.

    Args:
        scan_refs: Directory path, zip path, or list of scan dicts / paths.
        policy: Optional dict for policy overrides (e.g. {'site': 'default_site'}).

    Returns:
        dict with:
          - 'results': list of deduplicated host dicts with stamped provenance
          - 'total_scans': count of scanned sources processed
          - 'total_hosts_loaded': raw count of host entries before deduplication
          - 'total_hosts_unique': count of unique hosts after deduplication
          - 'duplicates_count': count of older/duplicate host records merged
          - 'scans': list of scan metadata records
    """
    if isinstance(scan_refs, str):
        if os.path.isdir(scan_refs):
            disc = discover_scans(scan_refs)
            refs = disc if disc else [_build_scan_ref(scan_refs, is_zip=False)]
        elif zipfile.is_zipfile(scan_refs):
            refs = [_build_scan_ref(scan_refs, is_zip=True)]
        else:
            refs = [{"path": scan_refs, "scan_id": os.path.basename(scan_refs)}]
    else:
        refs = []
        for item in scan_refs:
            if isinstance(item, dict):
                refs.append(item)
            elif isinstance(item, str):
                is_zip = zipfile.is_zipfile(item) if os.path.exists(item) else False
                refs.append(_build_scan_ref(item, is_zip=is_zip))

    policy = policy or {}
    default_site = str(policy.get("site") or "")

    dedup_map: Dict[str, Dict[str, Any]] = {}
    total_hosts_loaded = 0
    duplicates_count = 0
    scans_meta: List[Dict[str, Any]] = []

    for ref in refs:
        scan_path = ref.get("path")
        if not scan_path or not os.path.exists(scan_path):
            continue

        source_scan = ref.get("scan_id") or os.path.basename(scan_path)
        site = ref.get("site") or default_site
        collector_id = ref.get("collector_id") or ""
        scanned_at = ref.get("scanned_at") or ""
        if not scanned_at:
            try:
                mtime = os.path.getmtime(scan_path)
                scanned_at = datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc).isoformat()
            except OSError:
                scanned_at = ""

        scans_meta.append({
            "scan_id": source_scan,
            "path": scan_path,
            "site": site,
            "collector_id": collector_id,
            "scanned_at": scanned_at,
        })

        try:
            loaded_hosts = load_summary(scan_path)
        except Exception as exc:
            logger.warning("Failed loading scan from %s: %s", scan_path, exc)
            continue

        total_hosts_loaded += len(loaded_hosts)

        for host in loaded_hosts:
            if not isinstance(host, dict):
                continue

            host_copy = dict(host)
            host_copy["source_scan"] = source_scan
            host_copy["site"] = host_copy.get("site") or site
            host_copy["collector_id"] = host_copy.get("collector_id") or collector_id
            host_copy["scanned_at"] = host_copy.get("scanned_at") or scanned_at
            host_copy.setdefault("previous_scan_ids", [])

            ident = get_scan_identity(host_copy)
            if ident not in dedup_map:
                dedup_map[ident] = host_copy
            else:
                existing = dedup_map[ident]
                cand_time = parse_timestamp(host_copy.get("scanned_at"))
                exist_time = parse_timestamp(existing.get("scanned_at"))

                if cand_time > exist_time:
                    # Candidate is newer -> candidate wins!
                    prev = list(existing.get("previous_scan_ids") or [])
                    ex_scan = existing.get("source_scan")
                    if ex_scan and ex_scan not in prev:
                        prev.append(ex_scan)
                    host_copy["previous_scan_ids"] = prev
                    host_copy["replaced_by"] = None
                    dedup_map[ident] = host_copy
                    duplicates_count += 1
                else:
                    # Existing is newer or equal -> existing stays!
                    prev = list(existing.get("previous_scan_ids") or [])
                    cand_scan = host_copy.get("source_scan")
                    if cand_scan and cand_scan not in prev:
                        prev.append(cand_scan)
                    existing["previous_scan_ids"] = prev
                    duplicates_count += 1

        gc.collect()

    def _sort_key(h: Dict[str, Any]) -> str:
        sys_info = h.get("system") or {}
        ip = str(sys_info.get("bmc_ip") or sys_info.get("ip") or h.get("host") or "")
        hostname = str(sys_info.get("hostname") or "")
        return f"{ip}_{hostname}_{get_scan_identity(h)}"

    sorted_results = sorted(dedup_map.values(), key=_sort_key)

    return {
        "results": sorted_results,
        "total_scans": len(scans_meta),
        "total_hosts_loaded": total_hosts_loaded,
        "total_hosts_unique": len(sorted_results),
        "duplicates_count": duplicates_count,
        "scans": scans_meta,
    }
