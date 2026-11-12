"""Lazy pyVmomi loader. Importing this module does not import pyVmomi."""

from __future__ import annotations

import hashlib
import importlib
import sys
import zipfile
from pathlib import Path

from vcf_hci.plugins.mtat.constants import PYVMOMI_FILENAME, PYVMOMI_SHA256, PYVMOMI_VERSION


def wheel_path() -> Path:
    return Path(__file__).resolve().parents[2] / "_vendor" / PYVMOMI_FILENAME


def load_pyvmomi():
    """Insert the pinned wheel and import pyVmomi. Leave sys.path unchanged on failure."""
    path = wheel_path()
    if path.name != PYVMOMI_FILENAME or not path.is_file():
        raise RuntimeError("pinned pyVmomi wheel is missing")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != PYVMOMI_SHA256:
        raise RuntimeError("pinned pyVmomi wheel hash does not match")
    version = _wheel_version(path)
    if version != PYVMOMI_VERSION:
        raise RuntimeError("pinned pyVmomi wheel version does not match")
    location = str(path)
    inserted = location not in sys.path
    if inserted:
        sys.path.insert(0, location)
    try:
        pyVmomi = importlib.import_module("pyVmomi")
    except Exception:
        if inserted and location in sys.path:
            sys.path.remove(location)
        raise
    return pyVmomi


def _wheel_version(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise RuntimeError("pinned pyVmomi wheel metadata is missing")
        for line in archive.read(names[0]).decode("utf-8", "replace").splitlines():
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
    raise RuntimeError("pinned pyVmomi wheel version is missing")
