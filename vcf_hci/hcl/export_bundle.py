"""Bounded, offline snapshots of the datasets used by the scanner.

CPU support and built-in HCL supplements are scanner code and are deliberately
not transported in a data bundle. Import on a matching scanner version for the
same policy results. No cached archive is passed through to the browser.
"""

import csv
import glob
import gzip
import hashlib
import io
import json
import math
import os
import time
import zipfile
from typing import Optional

from vcf_hci.constants import TOOL_VERSION
from vcf_hci.hcl import bundle_manager, loader

MAX_ARCHIVE_BYTES = 23 * 1024 * 1024  # Fits base64 + JSON in the existing 32 MiB request body limit.
MAX_DATA_BYTES = 96 * 1024 * 1024
MAX_METADATA_BYTES = 256 * 1024
MAX_MEMBERS = 128
DATA_MEMBERS = ("all.json", "vsan_drives.csv", "io_nics.json")


class HclExportError(ValueError):
    """A fixed, safe explanation suitable for a browser response."""


def _fingerprint(path: str) -> tuple:
    stat = os.stat(path)
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


def _read_file(path: str, snapshots: dict) -> bytes:
    before = _fingerprint(path)
    if path in snapshots and snapshots[path] != before:
        raise HclExportError("HCL data changed during export. Retry after the update finishes.")
    if before[2] > MAX_DATA_BYTES:
        raise HclExportError("An HCL dataset exceeds the offline export size limit.")
    with open(path, "rb") as source:
        data = source.read(MAX_DATA_BYTES + 1)
    if len(data) > MAX_DATA_BYTES or before != _fingerprint(path):
        raise HclExportError("HCL data changed during export. Retry after the update finishes.")
    snapshots[path] = before
    return data


def _json_dataset(raw: bytes, name: str) -> bytes:
    if raw.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            raw = compressed.read(MAX_DATA_BYTES + 1)
    if len(raw) > MAX_DATA_BYTES:
        raise HclExportError("An HCL dataset exceeds the offline export size limit.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HclExportError("An HCL dataset is invalid. Refresh or import a valid HCL bundle first.") from exc
    if not isinstance(data, dict):
        raise HclExportError("An HCL dataset has an unsupported structure.")
    if name == "all.json":
        entries = data.get("data", data.get("drives"))
        if isinstance(entries, dict):
            entries = [item for key in ("ssd", "hdd", "controller", "drives", "nic")
                       for item in entries.get(key, []) if isinstance(item, dict)]
        if not isinstance(entries, list) or not any(isinstance(item, dict) and item for item in entries):
            raise HclExportError("The active vSAN HCL dataset is empty or unsupported. Refresh or import HCL data first.")
    elif not any(isinstance(data.get(key), dict) and data[key] for key in ("quads", "pairs", "models")):
        raise HclExportError("The active network I/O HCL dataset is empty or unsupported.")
    return raw


def _csv_snapshot(csv_payloads: list) -> Optional[bytes]:
    """Keep only the model/tier fields consumed by the existing importer."""
    rows = {}
    for raw in csv_payloads:
        try:
            reader = csv.DictReader(io.StringIO(raw.decode("utf-8")))
            if not reader.fieldnames or not {"Model", "Tier"}.issubset(reader.fieldnames):
                raise HclExportError("An active HCL CSV has an unsupported structure.")
            for row in reader:
                model = (row.get("Model") or "").strip()
                if model:
                    rows.setdefault(model, set()).update(t.strip() for t in (row.get("Tier") or "").splitlines() if t.strip())
        except (UnicodeError, csv.Error) as exc:
            raise HclExportError("An active HCL CSV is invalid.") from exc
    if not rows:
        return None
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["Model", "Tier"])
    for model, tiers in sorted(rows.items()):
        writer.writerow([model, "\n".join(sorted(tiers))])
    return output.getvalue().encode("utf-8")


def _bundle_snapshot(path: str, snapshots: dict) -> tuple:
    raw = _read_file(path, snapshots)
    files = {}
    metadata = {}
    csv_payloads = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS or len({m.filename for m in members}) != len(members):
            raise HclExportError("The active HCL bundle has too many or duplicate entries.")
        # Other files are ignored, never unpacked or included in the export.
        selected = [m for m in members if m.filename in DATA_MEMBERS or m.filename.endswith(".csv")
                    or m.filename == "bundle_metadata.json"]
        if sum(m.file_size for m in selected) > MAX_DATA_BYTES:
            raise HclExportError("The active HCL bundle exceeds the offline export size limit.")
        for member in selected:
            if member.filename == "bundle_metadata.json":
                if member.file_size <= MAX_METADATA_BYTES:
                    try:
                        metadata = json.loads(archive.read(member).decode("utf-8"))
                    except (UnicodeError, json.JSONDecodeError):
                        metadata = {}
            elif member.filename.endswith(".csv"):
                csv_payloads.append(archive.read(member))
            else:
                files[member.filename] = _json_dataset(archive.read(member), member.filename)
    csv_data = _csv_snapshot(csv_payloads)
    if csv_data is not None:
        files["vsan_drives.csv"] = csv_data
    return files, metadata if isinstance(metadata, dict) else {}


def _loose_snapshot(snapshots: dict) -> dict:
    hcl_dir = bundle_manager.get_hcl_dir()
    path = os.path.join(hcl_dir, "all.json")
    if not os.path.isfile(path):
        raise HclExportError("No active vSAN HCL dataset is available. Refresh or import HCL data first.")
    files = {"all.json": _json_dataset(_read_file(path, snapshots), "all.json")}
    # Match load_optional_vsan_csv source precedence without its process cache.
    candidates = [os.path.join(hcl_dir, "vsan_drives.csv"), "vsan_drives.csv"]
    candidates += (glob.glob("*vsan*.csv") + glob.glob("*VSAN*.csv")
                   + glob.glob("hcl/*SSD*.csv") + glob.glob(os.path.join(hcl_dir, "*vsan*.csv")))
    csv_path = next((item for item in candidates if os.path.exists(item)), None)
    if csv_path:
        csv_data = _csv_snapshot([_read_file(csv_path, snapshots)])
        if csv_data is not None:
            files["vsan_drives.csv"] = csv_data
    return files


def export_active_hcl_bundle(custom_bundle_path: Optional[str] = None) -> bytes:
    """Return an import-compatible ZIP using current scan source precedence.

    The legacy writers have no shared filesystem lock. Read a bounded snapshot,
    check its source fingerprints, and reject concurrent updates rather than
    mixing partially written datasets. The caller snapshots its selected custom
    path under the web state lock. No refresh/download or import side effects run.
    """
    try:
        snapshots = {}
        bundle_path = custom_bundle_path or bundle_manager.ensure_auto_hcl_bundle()
        if bundle_path:
            files, previous = _bundle_snapshot(bundle_path, snapshots)
            source_type = "custom_bundle" if custom_bundle_path else "local_bundle"
            default_timestamp = snapshots[bundle_path][3] / 1e9
        else:
            files = _loose_snapshot(snapshots)
            previous = {}
            source_type = "local_cache"
            default_timestamp = next(iter(snapshots.values()))[3] / 1e9
        if "all.json" not in files:
            raise HclExportError("The active HCL bundle has no vSAN dataset. Import a complete HCL bundle first.")
        if "io_nics.json" not in files:
            # Same fallback as import_hcl_bundle when a legacy ZIP has no NIC catalog.
            candidates = [os.path.join(bundle_manager.get_hcl_dir(), "io_nics.json"),
                          os.path.join(os.path.dirname(loader.__file__), "io_nics.json"),
                          os.path.abspath("io_nics.json"), os.path.abspath("vcf_hci/hcl/io_nics.json")]
            io_path = next((item for item in candidates if os.path.exists(item)), None)
            if io_path:
                files["io_nics.json"] = _json_dataset(_read_file(io_path, snapshots), "io_nics.json")
            else:
                from vcf_hci.hcl.packaged_catalog import load_packaged_io_nics
                catalog = load_packaged_io_nics()
                if catalog:
                    files["io_nics.json"] = _json_dataset(json.dumps(catalog).encode("utf-8"), "io_nics.json")
        if sum(len(raw) for raw in files.values()) > MAX_DATA_BYTES:
            raise HclExportError("Active HCL datasets exceed the offline export size limit.")
        if any(before != _fingerprint(path) for path, before in snapshots.items()):
            raise HclExportError("HCL data changed during export. Retry after the update finishes.")
        timestamp = previous.get("dataset_timestamp", previous.get("created_timestamp", default_timestamp))
        if timestamp is not None and (not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp)):
            timestamp = default_timestamp
        now = time.time()
        metadata = {
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "created_timestamp": now,
            "dataset_timestamp": timestamp,
            "tool_version": TOOL_VERSION,
            "schema_version": "1.0",
            "source": "VCF Readiness offline dataset export",
            "source_type": source_type,
            "cpu_policy": "Built into scanner; not included in HCL data imports",
            "files": sorted(list(files) + ["bundle_metadata.json"]),
            "sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()},
        }
        if bundle_path:
            metadata["source_bundle_sha256"] = hashlib.sha256(_read_file(bundle_path, snapshots)).hexdigest()
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in DATA_MEMBERS:
                if name in files:
                    archive.writestr(name, files[name])
            archive.writestr("bundle_metadata.json", json.dumps(metadata, indent=2).encode("utf-8"))
        payload = output.getvalue()
        if len(payload) > MAX_ARCHIVE_BYTES:
            raise HclExportError("The offline bundle exceeds the browser transfer limit (23 MB ZIP).")
        return payload
    except HclExportError:
        raise
    except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise HclExportError("Could not read the active HCL datasets. Refresh or import a valid bundle, then retry.") from exc
