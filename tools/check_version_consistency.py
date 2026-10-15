#!/usr/bin/env python3
"""Validate that release versions declared in source agree.

The checker reads ``pyproject.toml`` and ``vcf_hci`` as text. It does not import
the package, install it, or contact a package index. A static ``[project] version``
must equal ``TOOL_VERSION``. The packaging pack's dynamic form is also accepted:
``dynamic = ["version"]`` together with
``[tool.setuptools.dynamic] version = { attr = "vcf_hci.constants.TOOL_VERSION" }``.
"""
import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){2}(?:[A-Za-z0-9.+-]*)?$")
DYNAMIC_VERSION_ATTR = "vcf_hci.constants.TOOL_VERSION"
_ASSIGNMENT_RE = re.compile(r"^([A-Za-z0-9_-]+)\s*=\s*([\"'])(.*?)\2\s*(?:#.*)?$")
_DYNAMIC_RE = re.compile(r"^dynamic\s*=\s*\[(.*)\]\s*(?:#.*)?$")
_ATTR_RE = re.compile(r"^version\s*=\s*\{\s*attr\s*=\s*([\"'])(.*?)\1\s*\}\s*(?:#.*)?$")
_QUOTED_RE = re.compile(r"""(["']).*?\1""")


class VersionConsistencyError(ValueError):
    """Raised when release version declarations are missing or inconsistent."""


def _string_list(body: str, description: str) -> List[str]:
    values = [match.group(2) for match in re.finditer(r"""(["'])(.*?)\1""", body)]
    remainder = _QUOTED_RE.sub(" ", body)
    if remainder.replace(",", " ").strip():
        raise VersionConsistencyError(f"cannot parse {description}")
    return values


def _read_project_version(pyproject_path: Path) -> Tuple[str, Optional[str]]:
    """Return the project name and its static version.

    The version is ``None`` when the packaging pack declares it dynamically from
    ``TOOL_VERSION``.
    """
    section = ""
    name = ""
    static_version = ""
    saw_static_version = False
    dynamic_values: Optional[List[str]] = None
    dynamic_attr = ""

    for raw_line in pyproject_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line
            continue
        if section == "[project]":
            assignment = _ASSIGNMENT_RE.match(line)
            if assignment and assignment.group(1) == "name":
                name = assignment.group(3)
                continue
            if assignment and assignment.group(1) == "version":
                static_version = assignment.group(3)
                saw_static_version = True
                continue
            dynamic_match = _DYNAMIC_RE.match(line)
            if dynamic_match:
                dynamic_values = _string_list(dynamic_match.group(1), "[project] dynamic")
            continue
        if section == "[tool.setuptools.dynamic]":
            attr_match = _ATTR_RE.match(line)
            if attr_match:
                dynamic_attr = attr_match.group(2)

    if not name:
        raise VersionConsistencyError(f"{pyproject_path} is missing [project] name")

    version_is_dynamic = dynamic_values is not None and "version" in dynamic_values
    if saw_static_version and version_is_dynamic:
        raise VersionConsistencyError("project version cannot be both static and dynamic")
    if saw_static_version:
        return name, static_version
    if version_is_dynamic:
        if dynamic_attr != DYNAMIC_VERSION_ATTR:
            found = dynamic_attr or "<missing>"
            raise VersionConsistencyError(
                f"dynamic project version must use attr {DYNAMIC_VERSION_ATTR!r}, found {found!r}"
            )
        return name, None
    raise VersionConsistencyError(f"{pyproject_path} is missing [project] version")


def _read_string_assignment(path: Path, variable: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = ""
    seen = False
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id != variable:
            continue
        if seen:
            raise VersionConsistencyError(f"{variable} is assigned more than once in {path}")
        seen = True
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            raise VersionConsistencyError(f"{variable} must be assigned a string literal in {path}")
        found = node.value.value
    if not seen:
        raise VersionConsistencyError(f"{variable} is not assigned in {path}")
    return found


def _assert_package_version_alias(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values = []
    for node in tree.body:
        target = None
        value = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target = node.target.id
            value = node.value
        if target == "__version__":
            values.append(value)
    if len(values) != 1 or not isinstance(values[0], ast.Name) or values[0].id != "TOOL_VERSION":
        raise VersionConsistencyError("vcf_hci.__version__ must alias TOOL_VERSION")


def version_info(repo_root: Path) -> Dict[str, str]:
    """Return statically declared project identity after validating consistency."""
    root = Path(repo_root).resolve()
    project_name, declared_version = _read_project_version(root / "pyproject.toml")
    tool_version = _read_string_assignment(root / "vcf_hci" / "constants.py", "TOOL_VERSION")
    _assert_package_version_alias(root / "vcf_hci" / "__init__.py")

    if declared_version is None:
        project_version = tool_version
    elif declared_version != tool_version:
        raise VersionConsistencyError(
            f"version mismatch: pyproject.toml={declared_version!r}, TOOL_VERSION={tool_version!r}"
        )
    else:
        project_version = declared_version

    if not VERSION_RE.fullmatch(project_version):
        raise VersionConsistencyError(f"project version is not a three-part release version: {project_version!r}")
    return {
        "project_name": project_name,
        "project_version": project_version,
        "tool_version": tool_version,
    }


def validate_version(repo_root: Path, expected_version: Optional[str] = None) -> Dict[str, str]:
    """Validate source declarations and, when supplied, an expected release version."""
    info = version_info(repo_root)
    if expected_version is not None and info["project_version"] != expected_version:
        raise VersionConsistencyError(
            f"expected version {expected_version!r}, found {info['project_version']!r}"
        )
    return info


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--expected-version")
    parser.add_argument("--json", action="store_true", help="emit machine-readable version details")
    parser.add_argument("--print-version", action="store_true", help="print only the validated version")
    args = parser.parse_args(argv)

    try:
        info = validate_version(args.repo_root, args.expected_version)
    except (OSError, SyntaxError, VersionConsistencyError) as exc:
        print(f"VERSION CHECK FAILED: {exc}", file=sys.stderr)
        return 1

    if args.print_version:
        print(info["project_version"])
    elif args.json:
        print(json.dumps(info, sort_keys=True))
    else:
        print(f"VERSION CHECK PASSED: {info['project_name']} {info['project_version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
