"""
VCF Readiness Tool — HCL bundle manager.

Manages creation, import, and auto-refresh of dark-site HCL zip bundles
for air-gapped environments.
"""
import csv
import glob
import gzip
import json
import logging
import os
import ssl
import time
import urllib.request
import zipfile
from typing import Optional

logger = logging.getLogger("vcf_assess")

from vcf_hci.constants import LIVE_VSAN_HCL_JSON_URL, TOOL_VERSION
from vcf_hci.hcl.loader import _apply_hcl_supplements, _apply_io_nics_catalog, sanitize_hcl_entry


def get_hcl_dir() -> str:
    """Returns stable user HCL directory path (~/.vcf-readiness/hcl/).
    Creates directory if it does not exist. Fallbacks to current working directory
    if home directory is not accessible/writable.
    """
    try:
        hcl_dir = os.path.expanduser("~/.vcf-readiness/hcl")
        os.makedirs(hcl_dir, exist_ok=True)
        return hcl_dir
    except Exception:
        return os.path.abspath(".")


class HCLBundleManager:
    """Air-Gapped Dark-Site HCL Bundle Manager.
    Bundles live Broadcom vSAN HCL JSON and CSV datasets into an offline ZIP archive,
    or loads HCL datasets from an imported dark-site bundle ZIP.
    """
    @staticmethod
    def get_dir() -> str:
        return get_hcl_dir()

    @staticmethod
    def create_bundle(output_zip_path: Optional[str] = None) -> str:
        return create_hcl_bundle(output_zip_path)

    @staticmethod
    def load_bundle(bundle_zip_path: str) -> tuple:
        return import_hcl_bundle(bundle_zip_path)

    @staticmethod
    def ensure_bundle(bundle_name: str = "vcf_hcl_bundle_latest.zip", max_age_days: int = 30) -> Optional[str]:
        return ensure_auto_hcl_bundle(bundle_name, max_age_days)


def ensure_auto_hcl_bundle(bundle_name: str = "vcf_hcl_bundle_latest.zip", max_age_days: int = 30) -> Optional[str]:
    """
    Auto-builds or updates an HCL dark-site bundle zip on app startup if missing
    or older than max_age_days (30 days). Returns the bundle file path.
    Searches in ~/.vcf-readiness/hcl/ and current working directory.
    """
    hcl_dir = get_hcl_dir()
    candidates = set()

    # Search in ~/.vcf-readiness/hcl/
    candidates.update([p for p in glob.glob(os.path.join(hcl_dir, "vcf_hcl_bundle_*.zip")) if os.path.exists(p)])

    # Search in cwd only if hcl_dir is different from cwd
    cwd = os.path.abspath(".")
    if os.path.abspath(hcl_dir) != cwd:
        candidates.update([os.path.abspath(p) for p in glob.glob("vcf_hcl_bundle_*.zip") if os.path.exists(p)])

    existing_bundles = sorted(
        list(candidates),
        key=lambda p: os.path.getmtime(p),
        reverse=True
    )

    should_build = False
    if os.path.isabs(bundle_name):
        target_path = bundle_name
    else:
        target_path = os.path.join(hcl_dir, bundle_name)

    if existing_bundles:
        newest_bundle = existing_bundles[0]
        age_days = (time.time() - os.path.getmtime(newest_bundle)) / 86400.0
        if age_days > max_age_days:
            logger.info(f"Auto-HCL bundle '{newest_bundle}' is {age_days:.1f} days old (> {max_age_days} days). Refreshing...")
            should_build = True
        else:
            target_path = newest_bundle
    else:
        logger.info(f"No local HCL bundle found. Auto-building '{target_path}'...")
        should_build = True

    if should_build:
        try:
            target_path = create_hcl_bundle(target_path)
        except Exception as e:
            logger.warning(f"Could not auto-build HCL bundle: {e}")
            if existing_bundles:
                target_path = existing_bundles[0]
                logger.info(f"Falling back to existing bundle: {target_path}")

    return target_path if (target_path and os.path.exists(target_path)) else None


def create_hcl_bundle(output_zip_path: Optional[str] = None) -> str:
    """
    Downloads Broadcom live vSAN HCL JSON and CSV datasets, creates bundle metadata,
    and packages them into a dark-site zip archive.
    """
    hcl_dir = get_hcl_dir()
    if not output_zip_path or output_zip_path == "DEFAULT":
        today_str = time.strftime("%Y%m%d")
        output_zip_path = os.path.join(hcl_dir, f"vcf_hcl_bundle_{today_str}.zip")
    elif not os.path.isabs(output_zip_path) and not os.path.dirname(output_zip_path):
        output_zip_path = os.path.join(hcl_dir, output_zip_path)

    logger.info(f"Generating dark-site HCL bundle: {output_zip_path}")
    raw_json = None
    urls_to_try = [LIVE_VSAN_HCL_JSON_URL]
    if LIVE_VSAN_HCL_JSON_URL.endswith(".gz"):
        urls_to_try.append(LIVE_VSAN_HCL_JSON_URL[:-3])

    for url in urls_to_try:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip"})
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
                raw_bytes = r.read()
                if raw_bytes.startswith(b"\x1f\x8b"):
                    try:
                        raw_bytes = gzip.decompress(raw_bytes)
                    except Exception as ge:
                        logger.debug(f"gzip decompress error on {url}: {ge}")
                raw_json = raw_bytes
                break
        except Exception as e:
            logger.warning(f"Could not download live vSAN HCL JSON for bundle from {url}: {e}")

    if not raw_json:
        for json_path in [os.path.join(hcl_dir, "all.json"), "all.json", os.path.join("hcl", "all.json")]:
            if os.path.exists(json_path):
                with open(json_path, "rb") as f:
                    raw_json = f.read()
                break

    if not raw_json:
        raw_json = json.dumps({
            "status": "baseline_offline",
            "drives": [
                {"model": "DELL PERC H755N", "tier": "vSAN ESA Certified"},
                {"model": "SAMSUNG MZQL21T9HCJR-00A07", "tier": "vSAN ESA NVMe Tier"},
                {"model": "KIOXIA KCD61LUL1T92", "tier": "vSAN ESA NVMe Tier"}
            ]
        }, indent=2).encode("utf-8")

    csv_content = None
    for csv_path in [os.path.join(hcl_dir, "vsan_drives.csv"), "vsan_drives.csv", os.path.join("hcl", "vsan_drives.csv")]:
        if os.path.exists(csv_path):
            with open(csv_path, encoding="utf-8") as f:
                csv_content = f.read()
            break

    if not csv_content:
        csv_content = "Model,Tier,Interface,CapacityGB,Vendor\n" \
                      "SAMSUNG MZQL21T9HCJR-00A07,ESA NVMe,NVMe Direct,1920,Samsung\n" \
                      "KIOXIA KCD61LUL1T92,ESA NVMe,NVMe Direct,1920,Kioxia\n" \
                      "DELL PERC H755N,OSA RAID,SAS/SATA,N/A,Dell\n"

    io_nics_content = None
    for io_path in [
        os.path.join(hcl_dir, "io_nics.json"),
        os.path.join(os.path.dirname(__file__), "io_nics.json"),
        "io_nics.json",
        "vcf_hci/hcl/io_nics.json",
    ]:
        if os.path.exists(io_path):
            with open(io_path, "rb") as f:
                io_nics_content = f.read()
            break

    metadata = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "created_timestamp": time.time(),
        "tool_version": TOOL_VERSION,
        "schema_version": "1.0",
        "source": "Broadcom VCF / vSAN Dark-Site HCL Bundle Manager",
        "hcl_json_url": LIVE_VSAN_HCL_JSON_URL,
        "files": ["all.json", "vsan_drives.csv", "bundle_metadata.json"]
    }
    if io_nics_content:
        metadata["files"].append("io_nics.json")

    try:
        compression = zipfile.ZIP_DEFLATED
    except Exception:
        compression = zipfile.ZIP_STORED

    with zipfile.ZipFile(output_zip_path, "w", compression=compression) as z:
        z.writestr("all.json", raw_json)
        z.writestr("vsan_drives.csv", csv_content)
        if io_nics_content:
            z.writestr("io_nics.json", io_nics_content)
        z.writestr("bundle_metadata.json", json.dumps(metadata, indent=2))

    logger.info(f"Successfully created dark-site HCL bundle archive: {output_zip_path}")
    return output_zip_path


def import_hcl_bundle(bundle_zip_path: str) -> tuple:
    """
    Imports an air-gapped dark-site HCL bundle zip archive.
    Returns (json_hcl: dict, csv_db: dict, metadata: dict).
    """
    if not os.path.exists(bundle_zip_path):
        logger.error(f"Dark-site HCL bundle not found at {bundle_zip_path}")
        return {}, {}, {}

    json_hcl = {
        "quads": {},
        "pairs": {},
        "models": {},
        "csv_drives": {},
        "_pci_quads": {},
        "_pci_pairs": {},
    }
    csv_db = {}
    metadata = {}

    try:
        with zipfile.ZipFile(bundle_zip_path, "r") as z:
            if "bundle_metadata.json" in z.namelist():
                try:
                    metadata = json.loads(z.read("bundle_metadata.json").decode("utf-8"))
                except Exception:
                    pass

            if not metadata:
                mtime = os.path.getmtime(bundle_zip_path)
                metadata = {
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime)),
                    "created_timestamp": mtime,
                    "schema_version": "1.0",
                    "source": os.path.basename(bundle_zip_path),
                }

            created_ts = metadata.get("created_timestamp")
            ts_val = float(created_ts) if isinstance(created_ts, (int, float)) else os.path.getmtime(bundle_zip_path)
            dataset_age_days = round((time.time() - ts_val) / 86400.0, 1)
            metadata["dataset_age_days"] = dataset_age_days
            metadata["bundle_filename"] = os.path.basename(bundle_zip_path)

            if "all.json" in z.namelist():
                try:
                    raw_bytes = z.read("all.json")
                    if raw_bytes.startswith(b"\x1f\x8b"):
                        try:
                            raw_bytes = gzip.decompress(raw_bytes)
                        except Exception:
                            pass
                    raw_data = json.loads(raw_bytes.decode("utf-8"))
                    dev_list = []
                    sub_data = raw_data.get("data", {})
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
                    elif isinstance(sub_data, list):
                        dev_list = sub_data

                    if not dev_list:
                        dev_list = (
                            raw_data.get("drives", [])
                            or (raw_data if isinstance(raw_data, list) else [])
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
                                "tier": tier,
                                "releases": releases,
                                "vendor_id": vid,
                                "device_id": did,
                                "subsystem_vendor_id": svid,
                                "subsystem_id": ssid,
                                "recommended_driver": rec_driver,
                                "recommended_firmware": rec_fw,
                                "release_matrix": release_matrix,
                                "product_id": sanitized.get("product_id", ""),
                                "hcl_program": sanitized.get("hcl_program", ""),
                                "vcglink": sanitized.get("vcglink", ""),
                                "rdma_supported": sanitized.get("rdma_supported", False),
                            }

                            if model:
                                json_hcl["models"][model.upper()] = item
                                json_hcl[model.upper()] = item

                            if vid and did:
                                if svid and ssid:
                                    quad_key = f"{vid}:{did}:{svid}:{ssid}"
                                    json_hcl["quads"][quad_key] = item
                                    json_hcl["_pci_quads"][quad_key] = item
                                    json_hcl[quad_key] = item
                                pair_key = f"{vid}:{did}"
                                json_hcl["pairs"].setdefault(pair_key, []).append(item)
                                json_hcl["_pci_pairs"].setdefault(pair_key, []).append(item)
                                json_hcl[pair_key] = item
                except Exception as e:
                    logger.warning(f"Error parsing all.json from bundle: {e}")

            if "io_nics.json" in z.namelist():
                try:
                    raw_io_bytes = z.read("io_nics.json")
                    io_cat = json.loads(raw_io_bytes.decode("utf-8"))
                    _apply_io_nics_catalog(json_hcl, io_catalog=io_cat)
                    cached_io_path = os.path.join(get_hcl_dir(), "io_nics.json")
                    try:
                        with open(cached_io_path, "wb") as f_out:
                            f_out.write(raw_io_bytes)
                    except Exception:
                        pass
                except Exception as e:
                    logger.warning(f"Error parsing io_nics.json from bundle: {e}")
            else:
                _apply_io_nics_catalog(json_hcl)

            _apply_hcl_supplements(json_hcl)

            csv_files = [f for f in z.namelist() if f.endswith(".csv")]
            for csv_name in csv_files:
                try:
                    lines = z.read(csv_name).decode("utf-8", errors="ignore").splitlines()
                    reader = csv.DictReader(lines)
                    for row in reader:
                        model = str(row.get("Model", "")).strip()
                        tier = str(row.get("Tier", "")).strip()
                        if model:
                            csv_db.setdefault(model, set())
                            for t in tier.split("\n"):
                                if t.strip():
                                    csv_db[model].add(t.strip())
                except Exception as e:
                    logger.warning(f"Error parsing {csv_name} from bundle: {e}")

            metadata["json_models_count"] = len(json_hcl)
            metadata["csv_models_count"] = len(csv_db)

    except Exception as e:
        logger.error(f"Failed to open HCL bundle zip {bundle_zip_path}: {e}")

    return json_hcl, csv_db, metadata
