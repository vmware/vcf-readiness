"""Static VDT discovery and bounded parsing of native VDT 2.x JSON exports."""

import configparser
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from vcf_hci.logging_utils import sanitize_filename

PRODUCTS = ('vcenter', 'vks', 'sddc_manager')
MAX_EXPORT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 10000
_PRODUCT_CONFIGS = {
    'vcenter': 'vcenter/vc_cfg/vc_vdt.ini',
    'vks': 'vks/vks_cfg/vks_vdt.ini',
    'sddc_manager': 'sddc_manager/sddc_cfg/sddc_vdt.ini',
}
_MAX_CONFIG_BYTES = 256 * 1024


def _payload_file(folder: Path, relative: str) -> Optional[Path]:
    """Keep static metadata reads inside real, non-symlinked payload paths."""
    current = folder
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            return None
    return current if current.is_file() else None


def _read_config(folder: Path, relative: str) -> Optional[configparser.ConfigParser]:
    path = _payload_file(folder, relative)
    if path is None:
        return None
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open('rb') as source:
            raw = source.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            return None
        parser.read_string(raw.decode('utf-8-sig'))
    except (OSError, UnicodeError, configparser.Error):
        return None
    return parser



def _legacy_installation(folder: Path) -> Optional[dict]:
    """Read the legacy release literal without importing Python 2-era code."""
    required = ('vdt.py', 'cfg/config_log.ini', 'lib/utils.py', 'lib/cisutils.py',
                'lib/pformatting.py', 'scripts/__vc_info_auth.py', 'scripts/vc_disk_space.py')
    if any(_payload_file(folder, name) is None for name in required):
        return None
    try:
        with (folder / 'vdt.py').open('rb') as stream:
            raw = stream.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            return None
        text = raw.decode('utf-8-sig')
    except (OSError, UnicodeError):
        return None
    match = re.search(r"^__version__\s*=\s*['\"](1\.1\.4)['\"]\s*(?:#.*)?$", text, re.MULTILINE)
    if match is None:
        return None
    return {'products': ['vcenter'], 'versions': {'vcenter': match.group(1)}, 'family': '1'}


def _installation(folder: Path) -> Optional[dict]:
    """Identify the VDT layout and read versions without trusting its name."""
    required = ('vdt.py', 'LICENSE', 'lib/vdt_formatter.py', 'cfg/vdt.ini')
    if any(_payload_file(folder, name) is None for name in required):
        return _legacy_installation(folder)
    config = _read_config(folder, 'cfg/vdt.ini')
    if config is None:
        return None
    products = [name for name in PRODUCTS if config.has_section('product:' + name)]
    if not products:
        return None
    versions = {}
    for product in products:
        product_config = _read_config(folder, _PRODUCT_CONFIGS[product])
        version = product_config.get('vdt', 'version', fallback='') if product_config is not None else ''
        # The metadata is displayed as text. Unknown versions remain unknown;
        # folder suffixes and build dates are never interpreted as versions.
        versions[product] = version.strip().strip('"\'')[:80]
    return {'products': products, 'versions': versions, 'family': '2'}


def default_plugin_root() -> Path:
    """Source checkout or directory beside a frozen executable."""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent / 'Plugins'
    return Path(__file__).resolve().parents[2] / 'Plugins'


def discover_vdt(root: Optional[Union[str, Path]] = None) -> dict:
    """Recognize an extracted VDT folder without executing/importing any code.

    A deliberately fixed adapter recognizes VDT, not arbitrary Python plugins.
    Names and build suffixes are unrestricted. Scan the root and up to two
    directory levels to tolerate an extra extracted-archive wrapper. ZIP installs
    refresh the catalog immediately. Symlinked and hidden payloads are ignored.
    """
    root = Path(root) if root is not None else default_plugin_root()
    installations = []
    pending = [(root, 0)]
    while pending:
        candidate, depth = pending.pop(0)
        if candidate.is_symlink() or not candidate.is_dir():
            continue
        metadata = _installation(candidate)
        if metadata is not None:
            metadata['folder'] = candidate.relative_to(root).as_posix()
            installations.append(metadata)
            continue
        if depth < 2:
            try:
                children = sorted(candidate.iterdir(), key=lambda path: path.name.lower())
            except OSError:
                children = []
            pending.extend((child, depth + 1) for child in children if not child.name.startswith('.') and not child.is_symlink() and child.is_dir())
    installations.sort(key=lambda item: item['folder'].lower())
    return {'id': 'vdt', 'present': bool(installations),
            'folders': [item['folder'] for item in installations], 'installations': installations,
            'products': [name for name in PRODUCTS if any(name in item['products'] for item in installations)],
            'mode': 'appliance-export-import',
            'license_note': 'Preserve upstream licenses and per-file copyright notices; installation does not execute VDT.'}


def _text(value: object) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', str(value or ''))
    return ''.join(char for char in text if char in '\n\t' or ord(char) >= 32)


def parse_vdt_export(content: str, product: str, target: str, filename: str = 'vdt.json') -> dict:
    """Normalize native ``{timestamp, version, report: {...}}`` VDT output.

    Target/product are operator annotations, since VDT does not reliably emit
    them. INFO, missing and unrecognized results never become PASS. The hash
    covers the supplied UTF-8 file text, including whitespace and any BOM.
    """
    if product not in PRODUCTS:
        raise ValueError('Choose vCenter, VKS, or SDDC Manager.')
    if not isinstance(target, str) or not target.strip() or len(target) > 255:
        raise ValueError('Supply an appliance or environment label (maximum 255 characters).')
    if not isinstance(content, str) or not content.strip():
        raise ValueError('Choose a native VDT JSON export.')
    raw = content.encode('utf-8')
    if len(raw) > MAX_EXPORT_BYTES:
        raise ValueError('VDT exports must be no larger than 8 MiB.')
    try:
        payload = json.loads(content.lstrip('\ufeff'))
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError('The selected file is not valid VDT JSON.') from exc
    if not isinstance(payload, dict) or not isinstance(payload.get('report'), dict):
        raise ValueError('Expected a native VDT export with a report object.')
    findings: list[dict] = []
    nodes = 0
    aliases = {'OK': 'PASS', 'SUCCESS': 'PASS', 'WARNING': 'WARN', 'SKIPPED': 'SKIP'}

    def walk(node: object, category: str, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > 32 or nodes > 100000 or len(findings) > MAX_FINDINGS:
            raise ValueError('The VDT export exceeds the supported nesting or check limit.')
        if isinstance(node, list):
            for item in node:
                walk(item, category, depth + 1)
        elif isinstance(node, dict):
            if 'result' in node or ('title' in node and 'checks' not in node):
                status = _text(node.get('result')).strip().upper()
                status = aliases.get(status, status)
                if status not in ('PASS', 'FAIL', 'WARN', 'INFO', 'SKIP'):
                    status = 'UNKNOWN'
                details = {key: value for key, value in node.items() if key not in ('title', 'result')}
                findings.append({'status': status, 'category': category,
                                 'title': _text(node.get('title')) or 'Untitled VDT check',
                                 'details': _text(details)})
            elif 'checks' in node:
                walk(node['checks'], category + ' / ' + _text(node.get('title') or node.get('subheading') or 'Checks'), depth + 1)
            else:
                for name, value in node.items():
                    walk(value, (category + ' / ' if category else '') + _text(name), depth + 1)

    walk(payload['report'], '', 0)
    if len(findings) > MAX_FINDINGS:
        raise ValueError('The VDT export exceeds 10,000 checks.')
    if not findings:
        raise ValueError('No recognizable checks were found in this VDT export.')
    filename = sanitize_filename(Path(str(filename).replace('\\', '/')).name) or 'vdt.json'
    sha256 = hashlib.sha256(raw).hexdigest()
    source_scope = payload.get('vcfr_collection')
    collection_scope: dict = {}
    if isinstance(source_scope, dict):
        for key in ('adapter', 'profile', 'source_version'):
            collection_scope[key] = _text(source_scope.get(key))[:200]
        for key in ('scope_notes', 'checks_selected', 'checks_excluded', 'checks_not_executed'):
            values = source_scope.get(key)
            if isinstance(values, list) and len(values) <= 1000:
                collection_scope[key] = [_text(value)[:2000] for value in values]
    return {'product': product, 'target': _text(target.strip()), 'filename': filename,
            'collection_scope': collection_scope,
            'sha256': sha256, 'id': hashlib.sha256((product + '\0' + target.strip() + '\0' + sha256).encode()).hexdigest(),
            'collected_at': _text(payload.get('timestamp')), 'version': _text(payload.get('version')),
            'imported_at': datetime.now(timezone.utc).isoformat(), 'findings': findings}
