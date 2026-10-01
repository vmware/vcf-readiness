"""
VCF Readiness Tool — Summary report I/O helper.

Handles reading and writing fleet assessment summaries across multiple file
formats: plain JSON, gzipped JSON (.json.gz), chunked v2 manifests,
directories of vcf_summary_*.json files, and zip archives.
"""

import gzip
import json
import os
import zipfile
from typing import Any, Dict, List, Optional, Set

from vcf_hci.constants import (
    FLEET_JSON_CHUNK_HOSTS,
    FLEET_JSON_CHUNK_MAX_BYTES,
    FLEET_JSON_GZIP_MIN_BYTES,
)


def write_fleet_summary(
    results: List[Dict[str, Any]],
    outdir: str,
    prefix: str = "fleet_summary",
    indent: Optional[int] = None,
    separators: Optional[tuple] = (",", ":"),
) -> Dict[str, Any]:
    """Write fleet summary results to outdir using version 2 schema.

    Decision logic:
      1. If host count <= FLEET_JSON_CHUNK_HOSTS and uncompressed size <= FLEET_JSON_CHUNK_MAX_BYTES:
         - If uncompressed size < FLEET_JSON_GZIP_MIN_BYTES:
           Write prefix.json as {"version": 2, "results": [...]}.
         - Else (>= FLEET_JSON_GZIP_MIN_BYTES):
           Write prefix.json.gz (compressed) and a manifest prefix.json:
           {"version": 2, "gzip": "prefix.json.gz", "host_count": N}.
      2. Else (large fleet):
         Chunk results into parts where each part has <= FLEET_JSON_CHUNK_HOSTS hosts
         and uncompressed size <= FLEET_JSON_CHUNK_MAX_BYTES.
         Write prefix_part01.json.gz, prefix_part02.json.gz, ... and a manifest prefix.json:
         {"version": 2, "host_count": N, "parts": ["prefix_part01.json.gz", ...]}.

    Returns:
      dict with details of paths written:
        {"manifest_path": str, "written_files": List[str], "is_chunked": bool, "is_gzipped": bool}
    """
    os.makedirs(outdir, exist_ok=True)
    payload_dict = {"version": 2, "results": results}
    raw_json_bytes = json.dumps(payload_dict, indent=indent, separators=separators, default=str).encode("utf-8")
    uncompressed_size = len(raw_json_bytes)
    host_count = len(results)

    manifest_fname = f"{prefix}.json"
    manifest_path = os.path.join(outdir, manifest_fname)
    written_files = [manifest_path]

    if host_count <= FLEET_JSON_CHUNK_HOSTS and uncompressed_size <= FLEET_JSON_CHUNK_MAX_BYTES:
        if uncompressed_size < FLEET_JSON_GZIP_MIN_BYTES:
            with open(manifest_path, "wb") as f:
                f.write(raw_json_bytes)
            return {
                "manifest_path": manifest_path,
                "written_files": written_files,
                "is_chunked": False,
                "is_gzipped": False,
            }
        else:
            gz_fname = f"{prefix}.json.gz"
            gz_path = os.path.join(outdir, gz_fname)
            with gzip.open(gz_path, "wb") as gz:
                gz.write(raw_json_bytes)
            manifest_data = {
                "version": 2,
                "gzip": gz_fname,
                "host_count": host_count,
            }
            with open(manifest_path, "w", encoding="utf-8", errors="replace") as f:
                json.dump(manifest_data, f, indent=indent, separators=separators, default=str)
            written_files.append(gz_path)
            return {
                "manifest_path": manifest_path,
                "written_files": written_files,
                "is_chunked": False,
                "is_gzipped": True,
            }

    # Split into parts
    parts_fnames: List[str] = []
    current_chunk: List[Dict[str, Any]] = []
    chunk_index = 1

    def _flush_chunk(chunk_items: List[Dict[str, Any]], idx: int) -> str:
        part_fname = f"{prefix}_part{idx:02d}.json.gz"
        part_path = os.path.join(outdir, part_fname)
        part_dict = {"version": 2, "results": chunk_items}
        part_bytes = json.dumps(part_dict, indent=indent, separators=separators, default=str).encode("utf-8")
        with gzip.open(part_path, "wb") as gz:
            gz.write(part_bytes)
        written_files.append(part_path)
        return part_fname

    for item in results:
        test_chunk = current_chunk + [item]
        test_bytes = json.dumps({"version": 2, "results": test_chunk}, indent=indent, separators=separators, default=str).encode("utf-8")
        if len(test_chunk) > FLEET_JSON_CHUNK_HOSTS or len(test_bytes) > FLEET_JSON_CHUNK_MAX_BYTES:
            if current_chunk:
                parts_fnames.append(_flush_chunk(current_chunk, chunk_index))
                chunk_index += 1
                current_chunk = [item]
            else:
                # Item itself exceeds max chunk size; flush anyway
                parts_fnames.append(_flush_chunk([item], chunk_index))
                chunk_index += 1
                current_chunk = []
        else:
            current_chunk = test_chunk

    if current_chunk:
        parts_fnames.append(_flush_chunk(current_chunk, chunk_index))

    manifest_data = {
        "version": 2,
        "host_count": host_count,
        "parts": parts_fnames,
    }
    with open(manifest_path, "w", encoding="utf-8", errors="replace") as f:
        json.dump(manifest_data, f, indent=indent, separators=separators, default=str)

    return {
        "manifest_path": manifest_path,
        "written_files": written_files,
        "is_chunked": True,
        "is_gzipped": True,
    }


def _is_safe_subpath(base_dir: str, subpath: str) -> bool:
    """Verify that resolving subpath within base_dir does not escape base_dir."""
    if not base_dir or not subpath or not isinstance(subpath, str):
        return False
    abs_base = os.path.realpath(os.path.abspath(base_dir))
    abs_target = os.path.realpath(os.path.abspath(os.path.join(base_dir, subpath)))
    return abs_target == abs_base or abs_target.startswith(abs_base + os.sep)


def _is_safe_zip_entry(base_zip_dir: str, entry_name: str) -> Optional[str]:
    """Return the zip member name if it stays under base_zip_dir."""
    if not entry_name or not isinstance(entry_name, str):
        return None
    name = entry_name.replace("\\", "/")
    if name.startswith("/") or ":" in name:
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    base = (base_zip_dir or "").replace("\\", "/")
    base_parts = [p for p in base.split("/") if p not in ("", ".")]
    if any(p == ".." for p in base_parts):
        return None
    candidate = "/".join(base_parts + parts)
    base_norm = "/".join(base_parts)
    if base_norm and candidate != base_norm and not candidate.startswith(base_norm + "/"):
        return None
    return candidate or None


def load_summary(
    path: str,
    _visited: Optional[Set[str]] = None,
    _depth: int = 0,
) -> List[Dict[str, Any]]:
    """Load host scan dicts from file, directory, or archive.

    Supports:
      - Plain .json (list or dict with 'results')
      - .json.gz
      - v2 manifest JSON (with 'gzip' or 'parts')
      - Directory containing vcf_summary_*.json files or data/fleet_summary.json
      - .zip file containing full scan output or JSON summary files
    """
    if _depth > 5:
        return []

    if not os.path.exists(path):
        raise FileNotFoundError(f"Summary path not found: {path}")

    real_path = os.path.realpath(path)
    if _visited is None:
        _visited = set()
    if real_path in _visited:
        return []
    _visited.add(real_path)

    # 1. Directory of summary files
    if os.path.isdir(path):
        for candidate in (
            os.path.join(path, "data", "fleet_summary.json"),
            os.path.join(path, "fleet_summary.json"),
            os.path.join(path, "data", "fleet_summary.json.gz"),
            os.path.join(path, "fleet_summary.json.gz"),
        ):
            if os.path.isfile(candidate):
                return load_summary(candidate, _visited=_visited, _depth=_depth + 1)

        results: List[Dict[str, Any]] = []
        scan_dirs = [path]
        data_sub = os.path.join(path, "data")
        if os.path.isdir(data_sub):
            scan_dirs.append(data_sub)

        seen_hosts = set()
        for sdir in scan_dirs:
            files = sorted(os.listdir(sdir))
            has_plain = any(f.startswith("vcf_summary_") for f in files)
            for fname in files:
                if has_plain and fname.startswith("OBFUSCATED_"):
                    continue
                if fname.startswith("fleet_summary"):
                    continue
                if fname.endswith(".json") or fname.endswith(".json.gz"):
                    fpath = os.path.join(sdir, fname)
                    try:
                        loaded = load_summary(fpath, _visited=_visited, _depth=_depth + 1)
                        for h in loaded:
                            hip = ((h.get("system") or {}).get("ip") or (h.get("system") or {}).get("bmc_ip") or h.get("host") or (h.get("system") or {}).get("hostname") or str(h))
                            if hip not in seen_hosts:
                                seen_hosts.add(hip)
                                results.append(h)
                    except Exception:
                        pass
        return results

    # 2. Zip archive
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path, "r") as zf:
            namelist = zf.namelist()
            # Check for fleet_summary.json manifest or gzip
            fleet_json_entry = None
            for name in namelist:
                if os.path.basename(name) == "fleet_summary.json":
                    fleet_json_entry = name
                    break

            if fleet_json_entry:
                base_zip_dir = os.path.dirname(fleet_json_entry)
                raw = zf.read(fleet_json_entry).decode("utf-8")
                parsed = json.loads(raw)
                return _extract_results_from_zip_obj(parsed, zf, base_zip_dir, _depth=_depth + 1)

            fleet_gz_entry = None
            for name in namelist:
                if os.path.basename(name) == "fleet_summary.json.gz":
                    fleet_gz_entry = name
                    break

            if fleet_gz_entry:
                content = gzip.decompress(zf.read(fleet_gz_entry))
                parsed = json.loads(content.decode("utf-8"))
                return _extract_results_from_zip_obj(parsed, zf, os.path.dirname(fleet_gz_entry), _depth=_depth + 1)

            results = []
            seen_hosts = set()
            has_plain = any(os.path.basename(n).startswith("vcf_summary_") for n in namelist)
            for name in sorted(namelist):
                base = os.path.basename(name)
                if has_plain and base.startswith("OBFUSCATED_"):
                    continue
                if base.startswith("fleet_summary"):
                    continue
                if name.endswith(".json") or name.endswith(".json.gz"):
                    try:
                        content = zf.read(name)
                        if name.endswith(".gz"):
                            content = gzip.decompress(content)
                        parsed = json.loads(content.decode("utf-8"))
                        extracted = _extract_results_from_obj(parsed, "", _visited=_visited, _depth=_depth + 1)
                        for h in extracted:
                            hip = ((h.get("system") or {}).get("ip") or (h.get("system") or {}).get("bmc_ip") or h.get("host") or (h.get("system") or {}).get("hostname") or str(h))
                            if hip not in seen_hosts:
                                seen_hosts.add(hip)
                                results.append(h)
                    except Exception:
                        pass
            return results

    # 3. .json.gz file
    if path.endswith(".gz"):
        with gzip.open(path, "rb") as gz:
            content = gz.read()
        parsed = json.loads(content.decode("utf-8"))
        return _extract_results_from_obj(parsed, os.path.dirname(path), _visited=_visited, _depth=_depth + 1)

    # 4. Plain .json file or v2 manifest
    with open(path, encoding="utf-8") as f:
        parsed = json.load(f)

    return _extract_results_from_obj(parsed, os.path.dirname(path), _visited=_visited, _depth=_depth + 1)


def _extract_results_from_zip_obj(
    obj: Any,
    zf: zipfile.ZipFile,
    base_zip_dir: str,
    _depth: int = 0,
) -> List[Dict[str, Any]]:
    if _depth > 5:
        return []

    if isinstance(obj, list):
        return obj

    if isinstance(obj, dict):
        if "gzip" in obj and isinstance(obj["gzip"], str):
            gz_name = _is_safe_zip_entry(base_zip_dir, obj["gzip"])
            if gz_name and gz_name in zf.namelist():
                try:
                    content = gzip.decompress(zf.read(gz_name))
                    parsed = json.loads(content.decode("utf-8"))
                    return _extract_results_from_zip_obj(parsed, zf, base_zip_dir, _depth=_depth + 1)
                except Exception:
                    return []

        if "parts" in obj and isinstance(obj["parts"], list):
            results: List[Dict[str, Any]] = []
            for part_fname in obj["parts"]:
                if isinstance(part_fname, str):
                    part_name = _is_safe_zip_entry(base_zip_dir, part_fname)
                    if part_name and part_name in zf.namelist():
                        try:
                            content = gzip.decompress(zf.read(part_name))
                            part_parsed = json.loads(content.decode("utf-8"))
                            results.extend(_extract_results_from_zip_obj(part_parsed, zf, base_zip_dir, _depth=_depth + 1))
                        except Exception:
                            pass
            return results

        if "results" in obj and isinstance(obj["results"], list):
            return obj["results"]

        if "system" in obj or "vendor" in obj or "bmc_ip" in obj or "host" in obj:
            return [obj]

    return []


def _extract_results_from_obj(
    obj: Any,
    base_dir: str,
    _visited: Optional[Set[str]] = None,
    _depth: int = 0,
) -> List[Dict[str, Any]]:
    if _depth > 5:
        return []

    if isinstance(obj, list):
        return obj

    if isinstance(obj, dict):
        # Manifest v2: gzip field
        if "gzip" in obj and isinstance(obj["gzip"], str):
            if base_dir and _is_safe_subpath(base_dir, obj["gzip"]):
                gz_path = os.path.join(base_dir, obj["gzip"])
                return load_summary(gz_path, _visited=_visited, _depth=_depth + 1)
            return []

        # Manifest v2: parts field
        if "parts" in obj and isinstance(obj["parts"], list):
            results: List[Dict[str, Any]] = []
            for part_fname in obj["parts"]:
                if isinstance(part_fname, str) and base_dir and _is_safe_subpath(base_dir, part_fname):
                    part_path = os.path.join(base_dir, part_fname)
                    results.extend(load_summary(part_path, _visited=_visited, _depth=_depth + 1))
            return results

        if "results" in obj and isinstance(obj["results"], list):
            return obj["results"]

        # Single host dict
        if "system" in obj or "vendor" in obj or "bmc_ip" in obj or "host" in obj:
            return [obj]

    return []
