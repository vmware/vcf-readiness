"""
VCF Readiness Tool — Code Version & Subsystem Fingerprint Tracking.

Provides zero-dependency introspection of git commit state, dirty working trees,
and layer-by-layer source code SHA-256 fingerprints (collector, compat, bcg_links,
report, web, protocol, hcl). Enables multi-agent scan re-use and cross-agent cache validation.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.constants import TOOL_VERSION

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_REPO_ROOT = os.path.dirname(_MODULE_DIR)

# Subsystem definition mappings (relative to repo root)
SUBSYSTEM_PATHS: Dict[str, List[str]] = {
    "collector": ["vcf_hci/collector"],
    "compat": ["vcf_hci/compat", "vcf_hci/compat_engine.py"],
    "bcg_links": ["vcf_hci/bcg_links.py"],
    "report": ["vcf_hci/report"],
    "web": ["vcf_hci/web"],
    "hcl": ["vcf_hci/hcl"],
    "protocol": ["vcf_hci/protocol.py"],
    "enrichment": ["vcf_hci/enrichment.py"],
    "scan": ["vcf_hci/scan.py"],
}


def _hash_file(filepath: str) -> str:
    """Compute SHA-256 of a single file."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()[:16]
    except (OSError, PermissionError):
        return "unreadable"


def compute_subsystem_fingerprints(repo_root: Optional[str] = None) -> Dict[str, str]:
    """Compute SHA-256 fingerprints for each architectural subsystem.

    Returns a dict mapping subsystem names ('collector', 'compat', etc.) to 16-character
    hex hash digests of all Python source code files within that subsystem.
    """
    root = repo_root or _DEFAULT_REPO_ROOT
    fingerprints: Dict[str, str] = {}

    for name, relative_paths in SUBSYSTEM_PATHS.items():
        sub_hasher = hashlib.sha256()
        files_found = 0

        for rel_path in relative_paths:
            abs_path = os.path.join(root, rel_path)
            if os.path.isfile(abs_path):
                file_hash = _hash_file(abs_path)
                sub_hasher.update(f"{rel_path}:{file_hash}".encode())
                files_found += 1
            elif os.path.isdir(abs_path):
                py_files: List[str] = []
                for dirpath, _, filenames in os.walk(abs_path):
                    for fn in filenames:
                        if fn.endswith((".py", ".html", ".css", ".js", ".json")) and not fn.startswith(
                            (".", "__")
                        ):
                            rel_f = os.path.relpath(os.path.join(dirpath, fn), root)
                            py_files.append(rel_f)
                py_files.sort()
                for rel_f in py_files:
                    f_hash = _hash_file(os.path.join(root, rel_f))
                    sub_hasher.update(f"{rel_f}:{f_hash}".encode())
                    files_found += 1

        fingerprints[name] = sub_hasher.hexdigest()[:16] if files_found > 0 else "empty"

    return fingerprints


def get_git_metadata(repo_root: Optional[str] = None) -> Dict[str, Any]:
    """Extract git commit, branch, and dirty status using stdlib subprocess or metadata file.

    Falls back cleanly if git is not installed or the directory is not a git clone
    (e.g., in a slot sandbox synced via rsync).
    """
    root = repo_root or _DEFAULT_REPO_ROOT
    meta_path = os.path.join(root, ".workspace_metadata.json")

    # If an exported metadata file exists, prefer it as baseline
    cached_meta: Dict[str, Any] = {}
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, encoding="utf-8") as f:
                cached_meta = json.load(f)
        except Exception:
            pass

    commit = cached_meta.get("git_commit") or "unknown"
    branch = cached_meta.get("git_branch") or "unknown"
    dirty = cached_meta.get("git_dirty", False)
    dirty_files: List[str] = cached_meta.get("git_dirty_files", [])

    # Check live git if available
    try:
        res_commit = subprocess.run(
            ["git", "-C", root, "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if res_commit.returncode == 0:
            commit = res_commit.stdout.strip()

        res_branch = subprocess.run(
            ["git", "-C", root, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if res_branch.returncode == 0:
            branch = res_branch.stdout.strip()

        res_status = subprocess.run(
            ["git", "-C", root, "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if res_status.returncode == 0:
            lines = [ln.strip() for ln in res_status.stdout.splitlines() if ln.strip()]
            dirty = len(lines) > 0
            dirty_files = [ln.split()[-1] for ln in lines[:30]]
    except Exception:
        pass

    return {
        "git_commit": commit,
        "git_branch": branch,
        "git_dirty": dirty,
        "git_dirty_files": dirty_files,
    }


def get_full_code_metadata(repo_root: Optional[str] = None) -> Dict[str, Any]:
    """Return complete code version, git status, and subsystem fingerprints dictionary."""
    root = repo_root or _DEFAULT_REPO_ROOT
    git_meta = get_git_metadata(root)
    fingerprints = compute_subsystem_fingerprints(root)

    return {
        "tool_version": TOOL_VERSION,
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "git_commit": git_meta.get("git_commit", "unknown"),
        "git_branch": git_meta.get("git_branch", "unknown"),
        "git_dirty": git_meta.get("git_dirty", False),
        "git_dirty_files": git_meta.get("git_dirty_files", []),
        "subsystem_fingerprints": fingerprints,
    }


def save_workspace_metadata(output_path: Optional[str] = None, repo_root: Optional[str] = None) -> str:
    """Save .workspace_metadata.json in root or custom path for cross-environment rsync."""
    root = repo_root or _DEFAULT_REPO_ROOT
    target = output_path or os.path.join(root, ".workspace_metadata.json")
    meta = get_full_code_metadata(root)
    try:
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass
    return target


def can_reuse_collector_scan(
    prior_meta: Optional[Dict[str, Any]],
    current_meta: Optional[Dict[str, Any]],
    allow_unversioned_local: bool = False,
) -> Tuple[bool, str]:
    """Check if a prior scan's raw hardware collection is valid for re-use.

    A prior scan is valid for collector re-use if the 'collector' and 'protocol'
    subsystems have identical source fingerprints in both runs.
    """
    if not prior_meta or not isinstance(prior_meta, dict):
        if allow_unversioned_local:
            return True, "Reusing local scan capture without explicit code metadata"
        return False, "No prior code metadata available in scan"
    if not current_meta or not isinstance(current_meta, dict):
        return False, "No current code metadata available"

    prior_fps = prior_meta.get("subsystem_fingerprints") or {}
    curr_fps = current_meta.get("subsystem_fingerprints") or {}

    prior_coll = prior_fps.get("collector")
    curr_coll = curr_fps.get("collector")
    if not prior_coll or not curr_coll or prior_coll != curr_coll:
        return (
            False,
            f"Collector code changed ({prior_coll or 'none'} -> {curr_coll or 'none'})",
        )

    prior_proto = prior_fps.get("protocol")
    curr_proto = curr_fps.get("protocol")
    if prior_proto and curr_proto and prior_proto != curr_proto:
        return (
            False,
            f"Protocol code changed ({prior_proto} -> {curr_proto})",
        )

    return True, "Collector and protocol code are identical"
