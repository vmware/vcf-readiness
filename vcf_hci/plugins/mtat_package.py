"""MTAT package contract v1: deterministic builds and inert, verified installs.

The package API deliberately does not activate the embedded MTAT wizard adapter.
Upstream code is data during build, inspection, discovery and installation.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import stat
import tempfile
import threading
import unicodedata
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Any

from vcf_hci.logging_utils import sanitize_filename

MAX_ZIP_BYTES = 32 * 1024 * 1024
MAX_FILES = 2000
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 96 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,79}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *('COM%d' % n for n in range(1, 10)), *('LPT%d' % n for n in range(1, 10))}
_LOCK = threading.Lock()
REQUIRED = {'mtat_py/__init__.py', 'mtat_py/__main__.py', 'mtat_py/server.py',
            'mtat_py/vcenter.py', 'mtat_py/ops.py', 'mtat_py/web/index.html', 'LICENSE.md'}


def safe_path(name: str) -> str:
    """Require portable regular-file names, including on Windows/macOS."""
    if not isinstance(name, str) or len(name.encode('utf-8')) > 1024:
        raise ValueError('Invalid package path.')
    parts = name.split('/')
    if any(not p or p in ('.', '..') or p != sanitize_filename(p) or p.endswith((' ', '.'))
           or p.split('.')[0].upper() in _RESERVED
           or any(ord(c) < 32 or ord(c) == 127 or c in '\\:<>"|?*' for c in p) for p in parts):
        raise ValueError('Unsafe package path.')
    return name


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate manifest key.')
        result[key] = value
    return result


def _manifest(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError('Package manifest is too large.')
    try:
        doc = json.loads(raw, object_pairs_hook=_object)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ValueError('Package manifest is not valid JSON.') from None
    if not isinstance(doc, dict) or doc.get('package_api') != 1 or isinstance(doc.get('package_api'), bool) or doc.get('id') != 'mtat':
        raise ValueError('Unsupported MTAT package contract.')
    if set(doc) != {'package_api', 'id', 'version', 'source_build', 'runtime', 'integration', 'files'}:
        raise ValueError('Unsupported MTAT manifest fields.')
    for field in ('version', 'source_build'):
        if not isinstance(doc[field], str) or not _VERSION.fullmatch(doc[field]):
            raise ValueError('Invalid package version or source build.')
    if doc['runtime'] != {'kind': 'python-source', 'module': 'mtat_py', 'python_min': '3.11'}:
        raise ValueError('Unsupported MTAT runtime. Contract v1 requires Python 3.11+ source.')
    if doc['integration'] not in ('standalone-http-alpha1', 'vcfr-mtat/1'):
        raise ValueError('Unsupported MTAT integration interface.')
    files = doc['files']
    if not isinstance(files, dict) or not REQUIRED.issubset(files) or len(files) >= MAX_FILES:
        raise ValueError('Package is missing required runtime or license files.')
    if 'licenses/pyvmomi/LICENSE.txt' not in files or not any(
            name.startswith('mtat_py/_vendor/pyvmomi-') and name.endswith('.whl') for name in files):
        raise ValueError('Package is missing the SDK or its license notices.')
    if doc['integration'] == 'vcfr-mtat/1' and not {'mtat_py/bridge.py', 'mtat_py/integration.py'}.issubset(files):
        raise ValueError('The versioned integration entry points are missing.')
    for name, digest in files.items():
        safe_path(name)
        if name == 'plugin.json' or not isinstance(digest, str) or not _SHA.fullmatch(digest):
            raise ValueError('Invalid package file digest.')
    return doc


def inspect_package(data: bytes) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Validate every archive member and declared byte before any installation."""
    if not data or len(data) > MAX_ZIP_BYTES:
        raise ValueError('Choose an MTAT ZIP no larger than 32 MiB.')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_FILES:
                raise ValueError('Package member limit exceeded.')
            total = 0
            seen: set[str] = set()
            spellings: dict[str, str] = {}
            files: dict[str, bytes] = {}
            for info in infos:
                name = info.orig_filename
                if name != info.filename or info.is_dir():
                    raise ValueError('Use file-only MTAT archives produced by the builder.')
                safe_path(name)
                if stat.S_IFMT(info.external_attr >> 16) not in (0, stat.S_IFREG) or info.flag_bits & 1:
                    raise ValueError('Package links, special files and encryption are not supported.')
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ValueError('Unsupported ZIP compression.')
                if info.file_size > MAX_FILE_BYTES or info.file_size > 200 * max(info.compress_size, 1):
                    raise ValueError('Package member size or compression ratio limit exceeded.')
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise ValueError('Package extracted-byte limit exceeded.')
                for index in range(1, len(name.split('/')) + 1):
                    prefix = '/'.join(name.split('/')[:index])
                    folded = unicodedata.normalize('NFC', prefix).casefold()
                    if folded in spellings and spellings[folded] != prefix:
                        raise ValueError('Package paths collide on this platform.')
                    spellings[folded] = prefix
                if name in seen:
                    raise ValueError('Duplicate package path.')
                seen.add(name)
            for info in infos:
                files[info.filename] = archive.read(info)
            if 'plugin.json' not in files:
                raise ValueError('The ZIP has no root plugin.json. Upload a built MTAT plugin, not a developer handoff.')
            doc = _manifest(files.pop('plugin.json'))
            if set(files) != set(doc['files']):
                raise ValueError('Package contains missing or undeclared files.')
            if any(parent.as_posix() in files for name in files for parent in PurePosixPath(name).parents if parent.as_posix() != '.'):
                raise ValueError('Conflicting package files and directories.')
            if any(hashlib.sha256(raw).hexdigest() != doc['files'][name] for name, raw in files.items()):
                raise ValueError('Package file hash mismatch.')
            return doc, files
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, RuntimeError, NotImplementedError, zlib.error):
        raise ValueError('The upload is not a supported intact MTAT ZIP.') from None


def _summary(doc: dict[str, Any], folder: str) -> dict[str, Any]:
    result = {key: doc[key] for key in ('version', 'source_build', 'package_api', 'runtime', 'integration')}
    result['folder'] = folder
    return result


def _verify_folder(folder: Path) -> dict[str, Any]:
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError('Invalid installed MTAT folder.')
    manifest = folder / 'plugin.json'
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError('Invalid installed MTAT manifest.')
    doc = _manifest(manifest.read_bytes())
    found = set()
    total = 0
    for path in folder.rglob('*'):
        if path.is_symlink():
            raise ValueError('Installed MTAT contains a symbolic link.')
        if path.is_dir():
            continue
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError('Installed MTAT contains a special file.')
        name = path.relative_to(folder).as_posix()
        safe_path(name)
        total += path.stat().st_size
        if total > MAX_TOTAL_BYTES or path.stat().st_size > MAX_FILE_BYTES or len(found) >= MAX_FILES:
            raise ValueError('Installed MTAT byte/file limit exceeded.')
        if name != 'plugin.json':
            if name not in doc['files'] or hashlib.sha256(path.read_bytes()).hexdigest() != doc['files'][name]:
                raise ValueError('Installed MTAT has changed.')
            found.add(name)
    if found != set(doc['files']):
        raise ValueError('Installed MTAT is incomplete.')
    return doc


def discover_packages(root: Path) -> dict[str, Any]:
    """Read bounded metadata only; execution requires separate runtime integration."""
    installations = []
    invalid = 0
    if not root.is_symlink() and root.is_dir():
        for folder in sorted(root.glob('mtat-*'))[:32]:
            try:
                doc = _verify_folder(folder)
                installations.append(_summary(doc, folder.name))
            except (OSError, ValueError):
                invalid += 1
    return {'installations': installations, 'invalid_installations': invalid,
            'activation': 'embedded', 'package_api': 1}


def install_package(data: bytes, root: Path) -> dict[str, Any]:
    """Install side by side atomically, without importing or executing payloads."""
    doc, files = inspect_package(data)
    digest = hashlib.sha256(data).hexdigest()
    name = sanitize_filename('mtat-' + doc['version'] + '-' + digest[:16])
    with _LOCK:
        if root.is_symlink():
            raise ValueError('The plugin root must not be a symbolic link.')
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination = root / name
        if destination.exists() or destination.is_symlink():
            if _verify_folder(destination) != doc:
                raise ValueError('The existing MTAT installation has changed.')
            already = True
        else:
            with tempfile.TemporaryDirectory(prefix='.mtat-install-', dir=str(root)) as temporary:
                stage = Path(temporary) / sanitize_filename('payload')
                stage.mkdir(mode=0o700)
                payload = dict(files, **{'plugin.json': (json.dumps(doc, indent=2, sort_keys=True) + '\n').encode()})
                for relative, content in payload.items():
                    path = stage / relative
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    with path.open('xb') as stream:
                        stream.write(content)
                    path.chmod(0o600)
                _verify_folder(stage)
                stage.rename(destination)
            already = False
    return {'installation': _summary(doc, name), 'archive_sha256': digest, 'already_installed': already}


def build_package(source: Path, license_file: Path, version: str, source_build: str) -> bytes:
    """Build from an upstream Python source root; never run upstream code."""
    files: dict[str, bytes] = {}
    runtime = source / 'mtat_py'
    if source.is_symlink() or runtime.is_symlink() or not runtime.is_dir() or license_file.is_symlink() or (source / 'licenses').is_symlink():
        raise ValueError('Supply a real upstream Python source folder and license file.')
    for path in sorted(runtime.rglob('*')):
        if path.is_symlink():
            raise ValueError('Upstream source must not contain symbolic links.')
        if '__pycache__' in path.parts or not path.is_file():
            continue
        if path.suffix not in ('.py', '.html', '.whl'):
            raise ValueError('Unexpected runtime file: ' + path.relative_to(source).as_posix())
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError('Upstream runtime file exceeds the member limit.')
        files[path.relative_to(source).as_posix()] = path.read_bytes()
        if len(files) >= MAX_FILES or sum(map(len, files.values())) > MAX_TOTAL_BYTES:
            raise ValueError('Upstream runtime size/file limit exceeded.')
    for path in sorted((source / 'licenses').rglob('*')):
        if path.is_symlink():
            raise ValueError('License files must not be symbolic links.')
        if path.is_file():
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError('License file exceeds the member limit.')
            files[path.relative_to(source).as_posix()] = path.read_bytes()
            if len(files) >= MAX_FILES or sum(map(len, files.values())) > MAX_TOTAL_BYTES:
                raise ValueError('Upstream license size/file limit exceeded.')
    if license_file.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError('License file exceeds the size limit.')
    files['LICENSE.md'] = license_file.read_bytes()
    if not any(name.startswith('licenses/') for name in files) or not any(name.endswith('.whl') for name in files):
        raise ValueError('Include the pinned SDK wheel and its license notices.')
    doc = {'package_api': 1, 'id': 'mtat', 'version': version, 'source_build': source_build,
           'runtime': {'kind': 'python-source', 'module': 'mtat_py', 'python_min': '3.11'},
           'integration': 'vcfr-mtat/1' if {'mtat_py/bridge.py', 'mtat_py/integration.py'}.issubset(files) else 'standalone-http-alpha1',
           'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}}
    files['plugin.json'] = (json.dumps(doc, indent=2, sort_keys=True) + '\n').encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, raw in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, raw)
    data = output.getvalue()
    inspect_package(data)
    return data
