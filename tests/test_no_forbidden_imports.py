"""Guard: vcf_hci/ package code must import ONLY the Python standard library.

Mirrors the .cursorrules hard constraint. Scans module ASTs (no imports executed).
"""
import ast
import sys
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "vcf_hci"

FORBIDDEN = {
    "requests", "urllib3", "aiohttp", "pandas", "jinja2",
    "bs4", "beautifulsoup4", "lxml",
}

# Generated/bundled assets excluded from source hygiene checks.
EXCLUDED_FILES = {"assets.py", "docs_data.py"}


def _iter_package_sources():
    for py in sorted(PACKAGE_ROOT.rglob("*.py")):
        if py.name in EXCLUDED_FILES or "__pycache__" in py.parts:
            continue
        yield py


def _imported_roots(source: str, filename: str):
    tree = ast.parse(source, filename=filename)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module.split(".")[0]


# Optional dependencies allowed for progressive enhancement (e.g. pycryptodomex in vault)
OPTIONAL_ALLOWED = {"Cryptodome", "Crypto"}


@pytest.mark.parametrize("py_file", list(_iter_package_sources()), ids=lambda p: p.name)
def test_no_forbidden_imports(py_file):
    roots = set(_imported_roots(py_file.read_text(encoding="utf-8"), str(py_file)))
    banned = roots & FORBIDDEN
    assert not banned, f"{py_file} imports forbidden non-stdlib modules: {sorted(banned)}"


@pytest.mark.parametrize("py_file", list(_iter_package_sources()), ids=lambda p: p.name)
def test_only_stdlib_imports(py_file):
    """Stronger check on 3.10+: every absolute import must be stdlib or vcf_hci itself."""
    if sys.version_info < (3, 10):
        pytest.skip("sys.stdlib_module_names requires Python 3.10+")
    allowed = set(sys.stdlib_module_names) | {"vcf_hci"} | OPTIONAL_ALLOWED
    roots = set(_imported_roots(py_file.read_text(encoding="utf-8"), str(py_file)))
    unknown = roots - allowed
    assert not unknown, f"{py_file} imports outside stdlib/vcf_hci: {sorted(unknown)}"
