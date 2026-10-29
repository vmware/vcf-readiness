"""Bounded ZIP installation of optional VDT payloads without executing them."""

import hashlib
import io
import os
import stat
import tempfile
import threading
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath
from typing import Dict, List, Tuple

from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.plugins.vdt import discover_vdt

MAX_ZIP_BYTES = 32 * 1024 * 1024
MAX_EXTRACTED_BYTES = 96 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ZIP_MEMBERS = 2000
MAX_COMPRESSION_RATIO = 200
_MAX_PATH_BYTES = 1024
_INSTALL_LOCK = threading.Lock()
_RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *('COM' + str(i) for i in range(1, 10)),
             *('LPT' + str(i) for i in range(1, 10))}


def _member_path(member: zipfile.ZipInfo) -> PurePosixPath:
    name = member.orig_filename
    if name != member.filename or not name or len(name.encode('utf-8')) > _MAX_PATH_BYTES:
        raise ValueError('The ZIP contains an invalid or overlong path.')
    if '\\' in name or name.startswith('/'):
        raise ValueError('The ZIP contains an absolute or Windows-style path.')
    parts = name[:-1].split('/') if name.endswith('/') else name.split('/')
    for index, part in enumerate(parts):
        finder_icon = part == 'Icon\r' and index == len(parts) - 1
        if (part in ('', '.', '..') or ':' in part or part.endswith((' ', '.'))
                or any(char in part for char in '<>"|?*')
                or (not finder_icon and any(ord(char) < 32 or ord(char) == 127 for char in part))
                or part.split('.', 1)[0].upper() in _RESERVED):
            raise ValueError('The ZIP contains an unsafe member path.')
    return PurePosixPath(*parts)


def _metadata_file(path: PurePosixPath) -> bool:
    return '__MACOSX' in path.parts or path.name in ('.DS_Store', 'Icon\r')


def _checked_members(archive: zipfile.ZipFile) -> List[Tuple[zipfile.ZipInfo, PurePosixPath]]:
    members = archive.infolist()
    if not members or len(members) > MAX_ZIP_MEMBERS:
        raise ValueError('The ZIP is empty or exceeds the 2,000-member installation limit.')
    total = 0
    spellings: Dict[str, str] = {}
    explicit = set()
    kinds: Dict[str, str] = {}
    accepted = []
    for member in members:
        path = _member_path(member)
        mode = member.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or (kind == stat.S_IFDIR and not member.is_dir()):
            raise ValueError('The ZIP contains a link or special filesystem member.')
        if member.is_dir() and kind == stat.S_IFREG:
            raise ValueError('The ZIP contains conflicting member types.')
        if member.flag_bits & 1:
            raise ValueError('Encrypted ZIP members cannot be installed.')
        if member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise ValueError('Use a standard stored or deflated ZIP archive.')
        if member.file_size < 0 or member.file_size > MAX_MEMBER_BYTES:
            raise ValueError('The ZIP contains a file larger than the 16 MiB member limit.')
        total += member.file_size
        if total > MAX_EXTRACTED_BYTES:
            raise ValueError('The ZIP exceeds the 96 MiB extracted installation limit.')
        if member.file_size > MAX_COMPRESSION_RATIO * max(member.compress_size, 1):
            raise ValueError('The ZIP exceeds the supported compression-ratio limit.')
        keys = []
        for index in range(1, len(path.parts) + 1):
            prefix = PurePosixPath(*path.parts[:index]).as_posix()
            key = unicodedata.normalize('NFC', prefix).casefold()
            if key in spellings and spellings[key] != prefix:
                raise ValueError('ZIP paths collide on case-insensitive or Unicode-normalizing filesystems.')
            spellings[key] = prefix
            keys.append(key)
        key = keys[-1]
        if key in explicit:
            raise ValueError('The ZIP contains duplicate member paths.')
        explicit.add(key)
        if any(kinds.get(parent) == 'file' for parent in keys[:-1]):
            raise ValueError('The ZIP contains conflicting file and directory paths.')
        if not member.is_dir() and kinds.get(key) in ('directory', 'implicit'):
            raise ValueError('The ZIP contains conflicting file and directory paths.')
        for parent in keys[:-1]:
            kinds.setdefault(parent, 'implicit')
        kinds[key] = 'directory' if member.is_dir() else 'file'
        if not _metadata_file(path):
            accepted.append((member, path))
    if not accepted:
        raise ValueError('The ZIP does not contain an installable VDT folder.')
    return accepted


def _extract(archive: zipfile.ZipFile, members: List[Tuple[zipfile.ZipInfo, PurePosixPath]], stage: Path) -> None:
    total = 0
    for member, relative in members:
        destination = stage.joinpath(*relative.parts)
        if member.is_dir():
            destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            continue
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        mode = 0o700 if (member.external_attr >> 16) & 0o111 else 0o600
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        copied = 0
        with os.fdopen(fd, 'wb') as output, archive.open(member) as source:
            while True:
                chunk = source.read(64 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                total += len(chunk)
                if copied > MAX_MEMBER_BYTES or total > MAX_EXTRACTED_BYTES:
                    raise ValueError('Decompressed ZIP content exceeds the installation limits.')
                output.write(chunk)
        if copied != member.file_size:
            raise ValueError('The ZIP contains a truncated or inconsistent member.')


def _file_digests(folder: Path) -> Dict[str, str]:
    """Bounded content comparison for idempotence; never trust an existing link."""
    result = {}
    entries = 0
    total = 0
    for path in folder.rglob('*'):
        entries += 1
        if entries > MAX_ZIP_MEMBERS or path.is_symlink():
            raise ValueError('The existing installation has changed; it will not be overwritten.')
        if path.is_dir():
            continue
        if not path.is_file() or path.stat().st_size > MAX_MEMBER_BYTES:
            raise ValueError('The existing installation has changed; it will not be overwritten.')
        digest = hashlib.sha256()
        size = 0
        with path.open('rb') as source:
            while True:
                chunk = source.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                total += len(chunk)
                if size > MAX_MEMBER_BYTES or total > MAX_EXTRACTED_BYTES:
                    raise ValueError('The installation content exceeds the supported size limits.')
                digest.update(chunk)
        result[path.relative_to(folder).as_posix()] = digest.hexdigest()
    return result


def install_vdt_zip(zip_bytes: bytes, plugin_root: Path) -> dict:
    """Install one recognized VDT payload atomically, preserving its original files.

    The content-addressed folder name provides idempotence, not publisher
    authentication. Installing never imports code or authorizes its execution.
    Only Finder archive metadata is discarded. No receipt is added to the
    payload, so reviewed source-hash gates can still verify original files.
    """
    if not isinstance(zip_bytes, bytes) or not zip_bytes or len(zip_bytes) > MAX_ZIP_BYTES:
        raise ValueError('Upload a VDT ZIP no larger than 32 MiB.')
    digest = hashlib.sha256(zip_bytes).hexdigest()
    folder_name = sanitize_filename('vdt-' + digest[:24])
    root = Path(plugin_root).expanduser().absolute()
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            members = _checked_members(archive)
            with _INSTALL_LOCK:
                if root.is_symlink():
                    raise ValueError('The configured plugin folder must not be a symbolic link.')
                root.mkdir(mode=0o700, parents=True, exist_ok=True)
                if not root.is_dir():
                    raise ValueError('The configured plugin path is not a directory.')
                root = root.resolve()
                with tempfile.TemporaryDirectory(prefix='.vdt-install-', dir=str(root)) as temporary:
                    stage = Path(temporary)
                    _extract(archive, members, stage)
                    installations = discover_vdt(stage)['installations']
                    if len(installations) != 1:
                        raise ValueError('The ZIP must contain exactly one recognized VDT installation.')
                    installation = installations[0]
                    payload = stage / installation['folder']
                    payload.chmod(0o700)
                    for member, relative in members:
                        path = stage.joinpath(*relative.parts)
                        if not member.is_dir() and payload != path and payload not in path.parents:
                            raise ValueError('The ZIP contains files outside its VDT folder; upload one complete VDT distribution.')
                    destination = root / folder_name
                    if destination.exists() or destination.is_symlink():
                        if destination.is_symlink() or not destination.is_dir() or _file_digests(destination) != _file_digests(payload):
                            raise ValueError('The existing installation has changed; it will not be overwritten.')
                        already_installed = True
                    else:
                        # The single application installer lock serializes publication.
                        # Staging is on this filesystem, so readers see a complete tree.
                        payload.rename(destination)
                        already_installed = False
                    return {'installation': {**installation, 'folder': folder_name},
                            'archive_sha256': digest, 'already_installed': already_installed}
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, RuntimeError, NotImplementedError) as exc:
        raise ValueError('The upload is not a supported, intact ZIP archive.') from exc
    except OSError as exc:
        raise ValueError('Could not install into the configured plugin folder. Check its permissions and available space.') from exc
