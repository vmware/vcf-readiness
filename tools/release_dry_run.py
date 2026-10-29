#!/usr/bin/env python3
"""Create a deterministic local release manifest without publishing anything.

The tool reads Git state, validates locally supplied or locally built wheel and
sdist files, and writes ``release-manifest.json`` plus ``SHA256SUMS``. It never
creates tags, pushes commits, calls GitHub, or uploads artifacts. Publish-like
flags are refused before any work is done.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Sequence, Tuple

from check_version_consistency import VersionConsistencyError, validate_version

REPO_ROOT = Path(__file__).resolve().parent.parent
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PUBLISH_PREFIXES = (
    "--gh",
    "--github",
    "--publish",
    "--push",
    "--pypi",
    "--release",
    "--repository",
    "--tag",
    "--twine",
    "--upload",
)
OUTPUT_NAMES = ("release-manifest.json", "SHA256SUMS")


class ReleaseDryRunError(ValueError):
    """Raised when local release inputs fail validation."""


def _run(command: Sequence[str], cwd: Path) -> str:
    result = subprocess.run(
        list(command),
        cwd=str(cwd),
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise ReleaseDryRunError(f"{' '.join(command)}: {detail}")
    return result.stdout.strip()


def _git(repo_root: Path, *args: str) -> str:
    return _run(["git", *args], repo_root)


def _porcelain_path(line: str) -> str:
    payload = line[3:]
    if " -> " in payload:
        payload = payload.split(" -> ", 1)[1]
    if len(payload) >= 2 and payload.startswith('"') and payload.endswith('"'):
        payload = payload[1:-1].replace("\\\\", "\\").replace('\\"', '"')
    return payload.replace("\\", "/")


def _is_build_byproduct(relative_path: str) -> bool:
    parts = PurePosixPath(relative_path).parts
    if not parts:
        return False
    if parts[0] == "build":
        return True
    return any(part.endswith(".egg-info") for part in parts)


def validate_git_state(
    repo_root: Path,
    expected_sha: str,
    allowed_untracked: Optional[Sequence[Path]] = None,
    allow_build_byproducts: bool = False,
) -> str:
    """Require the supplied full commit SHA and a clean source worktree.

    Untracked release artifacts and this tool's own output files may be ignored.
    After a local build, untracked setuptools ``build/`` and ``*.egg-info``
    byproducts may be ignored as well. Tracked modifications are never ignored.
    """
    if not FULL_SHA_RE.fullmatch(expected_sha):
        raise ReleaseDryRunError("--commit-sha must be a lowercase 40-character Git SHA")

    root = Path(repo_root).resolve()
    head_sha = _git(root, "rev-parse", "--verify", "HEAD^{commit}").lower()
    if not FULL_SHA_RE.fullmatch(head_sha):
        raise ReleaseDryRunError(f"Git HEAD is not a full SHA: {head_sha}")
    if head_sha != expected_sha:
        raise ReleaseDryRunError(f"commit mismatch: expected {expected_sha}, Git HEAD is {head_sha}")

    allowed = {Path(path).resolve() for path in (allowed_untracked or ())}
    unexpected: List[str] = []
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    for line in status.splitlines():
        if not line.strip():
            continue
        relative = _porcelain_path(line)
        if line.startswith("??"):
            if allow_build_byproducts and _is_build_byproduct(relative):
                continue
            if (root / relative).resolve() in allowed:
                continue
        unexpected.append(relative)
    if unexpected:
        preview = ", ".join(unexpected[:5])
        raise ReleaseDryRunError(f"Git worktree is not clean: {preview}")
    return head_sha


def _metadata_fields(text: str, artifact: Path) -> Tuple[str, str]:
    metadata = Parser().parsestr(text)
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not name or not version:
        raise ReleaseDryRunError(f"{artifact.name} metadata is missing Name or Version")
    return name, version


def _read_wheel_identity(path: Path) -> Tuple[str, str]:
    try:
        with zipfile.ZipFile(str(path)) as archive:
            if any(re.search(r"vdt[-_]lite|vsphere[-_]quick[-_]check|quick_check_ssh|(?:^|/)(?:lite|quick_check)_(?:api|html)[.]py$|/web/js/(?:lite|quick_check)[.]py$", name, re.I) for name in archive.namelist()):
                raise ReleaseDryRunError("Private vSphere quick check experiment in release wheel")
            metadata_names = sorted(
                name
                for name in archive.namelist()
                if len(PurePosixPath(name).parts) == 2
                and PurePosixPath(name).parts[0].endswith(".dist-info")
                and PurePosixPath(name).name == "METADATA"
            )
            if len(metadata_names) != 1:
                raise ReleaseDryRunError(f"{path.name} must contain exactly one dist-info/METADATA")
            text = archive.read(metadata_names[0]).decode("utf-8")
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        raise ReleaseDryRunError(f"cannot read wheel {path.name}: {exc}") from exc
    return _metadata_fields(text, path)


def _read_sdist_identity(path: Path) -> Tuple[str, str]:
    try:
        with tarfile.open(str(path), mode="r:*") as archive:
            if any(re.search(r"vdt[-_]lite|vsphere[-_]quick[-_]check|quick_check_ssh|(?:^|/)(?:lite|quick_check)_(?:api|html)[.]py$|/web/js/(?:lite|quick_check)[.]py$", name, re.I) for name in archive.getnames()):
                raise ReleaseDryRunError("Private vSphere quick check experiment in release sdist")
            metadata_members = sorted(
                (
                    member
                    for member in archive.getmembers()
                    if PurePosixPath(member.name).name == "PKG-INFO" and len(PurePosixPath(member.name).parts) == 2
                ),
                key=lambda member: member.name,
            )
            if len(metadata_members) != 1:
                raise ReleaseDryRunError(f"{path.name} must contain exactly one top-level PKG-INFO")
            extracted = archive.extractfile(metadata_members[0])
            if extracted is None:
                raise ReleaseDryRunError(f"cannot extract metadata from {path.name}")
            text = extracted.read().decode("utf-8")
    except (OSError, UnicodeDecodeError, tarfile.TarError) as exc:
        raise ReleaseDryRunError(f"cannot read sdist {path.name}: {exc}") from exc
    return _metadata_fields(text, path)


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _artifact_identity(path: Path) -> Tuple[str, str, str]:
    if path.name.endswith(".whl"):
        name, version = _read_wheel_identity(path)
        return "wheel", name, version
    if path.name.endswith(".tar.gz"):
        name, version = _read_sdist_identity(path)
        return "sdist", name, version
    raise ReleaseDryRunError(f"unsupported release artifact (expected .whl or .tar.gz): {path.name}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_artifacts(
    artifact_paths: Sequence[Path],
    project_name: str,
    version: str,
) -> List[Dict[str, object]]:
    """Validate a wheel and sdist pair and return metadata sorted by filename."""
    if not artifact_paths:
        raise ReleaseDryRunError("no release artifacts were supplied")

    resolved = [Path(path).expanduser().resolve() for path in artifact_paths]
    basenames = [path.name for path in resolved]
    if len(set(basenames)) != len(basenames):
        raise ReleaseDryRunError("artifact filenames must be unique")

    records: List[Dict[str, object]] = []
    kinds = set()
    for path in sorted(resolved, key=lambda candidate: candidate.name):
        if not path.is_file():
            raise ReleaseDryRunError(f"artifact does not exist or is not a file: {path}")
        kind, artifact_name, artifact_version = _artifact_identity(path)
        if _canonical_name(artifact_name) != _canonical_name(project_name):
            raise ReleaseDryRunError(
                f"{path.name} project mismatch: expected {project_name!r}, found {artifact_name!r}"
            )
        if artifact_version != version:
            raise ReleaseDryRunError(
                f"{path.name} version mismatch: expected {version!r}, found {artifact_version!r}"
            )
        kinds.add(kind)
        records.append(
            {
                "filename": path.name,
                "sha256": _sha256(path),
                "size": path.stat().st_size,
                "type": kind,
            }
        )

    if kinds != {"sdist", "wheel"}:
        raise ReleaseDryRunError("release artifacts must include at least one wheel and one sdist")
    return records


def _build_artifacts(repo_root: Path, artifact_dir: Path) -> List[Path]:
    artifact_dir = artifact_dir.resolve()
    existing = list(artifact_dir.glob("*.whl")) + list(artifact_dir.glob("*.tar.gz"))
    if existing:
        raise ReleaseDryRunError(f"build output directory already contains release artifacts: {artifact_dir}")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    _run([sys.executable, "-m", "build", "--outdir", str(artifact_dir)], repo_root)
    built = sorted(list(artifact_dir.glob("*.whl")) + list(artifact_dir.glob("*.tar.gz")))
    if not built:
        raise ReleaseDryRunError(f"python -m build produced no wheel or sdist in {artifact_dir}")
    return built


def _output_paths(output_dir: Path) -> List[Path]:
    return [output_dir / name for name in OUTPUT_NAMES]


def _write_bytes(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8"))


def prepare_release(
    repo_root: Path,
    version: str,
    commit_sha: str,
    output_dir: Path,
    artifact_paths: Optional[Sequence[Path]] = None,
    build: bool = False,
    artifact_dir: Optional[Path] = None,
) -> Dict[str, object]:
    """Validate local release state and write deterministic dry-run outputs."""
    if build and artifact_paths:
        raise ReleaseDryRunError("--build cannot be combined with --artifact")

    root = Path(repo_root).resolve()
    destination = Path(output_dir).expanduser().resolve()
    supplied = [Path(path).expanduser().resolve() for path in (artifact_paths or [])]
    validate_git_state(root, commit_sha, allowed_untracked=[*supplied, *_output_paths(destination)])
    try:
        identity = validate_version(root, version)
    except (OSError, SyntaxError, VersionConsistencyError) as exc:
        raise ReleaseDryRunError(str(exc)) from exc

    if build:
        paths = _build_artifacts(root, artifact_dir or (root / "dist"))
        validate_git_state(
            root,
            commit_sha,
            allowed_untracked=[*paths, *_output_paths(destination)],
            allow_build_byproducts=True,
        )
    else:
        paths = supplied

    artifacts = validate_artifacts(paths, identity["project_name"], version)
    manifest: Dict[str, object] = {
        "artifacts": artifacts,
        "commit_sha": commit_sha,
        "mode": "dry-run",
        "project": identity["project_name"],
        "schema_version": 1,
        "version": version,
    }

    destination.mkdir(parents=True, exist_ok=True)
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    checksum_text = "".join(f"{record['sha256']}  {record['filename']}\n" for record in artifacts)
    _write_bytes(destination / OUTPUT_NAMES[0], manifest_text)
    _write_bytes(destination / OUTPUT_NAMES[1], checksum_text)
    return manifest


def _refused_flag(argv: Sequence[str]) -> Optional[str]:
    for argument in argv:
        if argument == "--":
            break
        option = argument.split("=", 1)[0]
        if option == "--repo-root":
            continue
        if any(option.startswith(prefix) for prefix in PUBLISH_PREFIXES):
            return option
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    refused = _refused_flag(raw_args)
    if refused:
        print(
            f"RELEASE DRY RUN REFUSED: {refused} is publish-like; this tool only creates local checksums",
            file=sys.stderr,
        )
        return 2

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("dist/release-dry-run"))
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--artifact", action="append", type=Path, dest="artifacts")
    source.add_argument("--build", action="store_true")
    parser.add_argument("--artifact-dir", type=Path, default=Path("dist"))
    try:
        args = parser.parse_args(raw_args)
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, int):
            return code
        return 2

    artifact_dir = args.artifact_dir
    if not artifact_dir.is_absolute():
        artifact_dir = args.repo_root / artifact_dir
    output_dir = args.output_dir
    if not output_dir.is_absolute():
        output_dir = args.repo_root / output_dir

    try:
        manifest = prepare_release(
            repo_root=args.repo_root,
            version=args.version,
            commit_sha=args.commit_sha,
            output_dir=output_dir,
            artifact_paths=args.artifacts,
            build=args.build,
            artifact_dir=artifact_dir,
        )
    except (OSError, ReleaseDryRunError) as exc:
        print(f"RELEASE DRY RUN FAILED: {exc}", file=sys.stderr)
        return 1

    print(f"RELEASE DRY RUN PASSED: {manifest['project']} {manifest['version']} at {manifest['commit_sha']}")
    print(f"Wrote {output_dir / OUTPUT_NAMES[0]}")
    print(f"Wrote {output_dir / OUTPUT_NAMES[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
