"""
Build a stdlib zipapp of the vcf_hci package.

The archive root contains ``vcf_hci/`` plus ``__main__.py``. Running
``python3 worker.pyz`` imports ``vcf_hci`` the same way a normal checkout does.
Do not zip the package directory itself: that drops ``vcf_hci`` off the import path.
"""

import os
import shutil
import tempfile
import zipapp
from typing import Optional

__all__ = ["build_collector_pyz"]

_MAIN = (
    "import sys\n"
    "from vcf_hci.cli import main\n"
    "if __name__ == \"__main__\":\n"
    "    sys.exit(main() or 0)\n"
)


def _ignore_junk(_directory: str, names: list) -> set:
    skip = set()
    for name in names:
        if name == "__pycache__" or name == ".DS_Store" or name.endswith(".pyc"):
            skip.add(name)
    return skip


def build_collector_pyz(output_path: str, package_root: Optional[str] = None) -> str:
    """Write a collector zipapp. ``package_root`` is the repo root that contains ``vcf_hci/``."""
    if package_root is None:
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    package_dir = os.path.join(package_root, "vcf_hci")
    if not os.path.isdir(package_dir):
        raise FileNotFoundError("vcf_hci package not found under %s" % package_root)
    output_path = os.path.abspath(output_path)
    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    stage = tempfile.mkdtemp(prefix="vcfr_pyz_")
    try:
        shutil.copytree(package_dir, os.path.join(stage, "vcf_hci"), ignore=_ignore_junk)
        with open(os.path.join(stage, "__main__.py"), "w", encoding="utf-8") as fh:
            fh.write(_MAIN)
        zipapp.create_archive(
            stage,
            target=output_path,
            interpreter="/usr/bin/env python3",
            compressed=True,
        )
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return output_path
