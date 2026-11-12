"""Validated Memory Tiering data, explicit live refresh and offline fallback."""
import datetime
import json
import logging
import os
import tempfile
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Optional

from vcf_hci.hcl.memory_tiering_catalog import ENTRIES, FETCHED

logger = logging.getLogger('vcf_assess')
MEMBER = 'memory_tiering.json'
URL = 'https://compatibilityguide.broadcom.com/compguide/programs/viewResults?limit=3000&page=1&sortBy=partnerName&sortType=ASC'


def validate_catalog(data: dict) -> dict:
    if not isinstance(data, dict) or data.get('schema_version') != 1:
        raise ValueError('Unsupported Memory Tiering catalog')
    datetime.date.fromisoformat(data['fetched_at'])
    rows = data.get('entries')
    if not isinstance(rows, list) or not rows or len(rows) > 10000:
        raise ValueError('Empty or oversized Memory Tiering catalog')
    for row in rows:
        if (not isinstance(row, list) or len(row) != 4
                or not all(isinstance(v, str) and v.strip() for v in row[:3])
                or not row[2].isdigit() or not isinstance(row[3], list)
                or not all(isinstance(v, str) for v in row[3])):
            raise ValueError('Invalid Memory Tiering entry')
    return data


@lru_cache(maxsize=1)
def packaged_catalog() -> dict:
    return {'schema_version': 1, 'fetched_at': FETCHED, 'source_url': URL,
            'entries': [[name, partner, pid, list(releases)] for name, partner, pid, releases in ENTRIES]}


@lru_cache(maxsize=4)
def _read_catalog(path: str, mtime_ns: int, size: int) -> dict:
    if size > 8 * 1024 * 1024:
        raise ValueError('Oversized Memory Tiering catalog')
    try:
        with open(path, encoding='utf-8') as source:
            return validate_catalog(json.load(source))
    except json.JSONDecodeError as exc:
        raise ValueError('Invalid Memory Tiering JSON') from exc


def load_memory_tiering_catalog(refresh_live: bool = False) -> dict:
    """Use local data, or a packaged snapshot; only explicit refresh uses HTTPS."""
    from vcf_hci.hcl.bundle_manager import get_hcl_dir

    path = Path(get_hcl_dir()) / MEMBER
    if refresh_live:
        try:
            catalog = fetch_memory_tiering_catalog()
            # Atomic replacement keeps concurrent offline readers on a complete file.
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=str(path.parent),
                                             prefix='memory-tiering-', suffix='.tmp', delete=False) as output:
                temporary = output.name
            try:
                with open(temporary, 'w', encoding='utf-8') as output:
                    json.dump(catalog, output)
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            from vcf_hci.hcl.loader import clear_hcl_caches
            clear_hcl_caches()
            return catalog
        except Exception as exc:
            logger.warning('Memory Tiering refresh failed; retaining offline data: %s', exc)
    try:
        stat = path.stat()
        return _read_catalog(str(path), stat.st_mtime_ns, stat.st_size)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        logger.debug('Using packaged Memory Tiering snapshot: %s', exc)
        return packaged_catalog()


def fetch_memory_tiering_catalog() -> dict:
    """Retrieve all public BCG rows with normal public-service TLS verification."""
    request = urllib.request.Request(URL, data=json.dumps({
        'programId': 'memorytier', 'filters': [], 'keyword': [],
    }).encode(), headers={'Content-Type': 'application/json', 'USER-PERSONA': 'live',
                         'User-Agent': 'Mozilla/5.0 (VCF Readiness HCL)', 'Accept': 'application/json'})
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError('Oversized Memory Tiering response')
    try:
        payload = json.loads(raw.decode('utf-8'))
    except json.JSONDecodeError as exc:
        raise ValueError('BCG returned invalid Memory Tiering JSON') from exc
    data = payload.get('data', {})
    rows = data.get('fieldValues', [])
    if not payload.get('success') or not rows or len(rows) != data.get('count'):
        raise ValueError('Incomplete Memory Tiering response')
    entries = []
    for row in rows:
        for model in row['model']:
            entries.append([model['name'].strip(), row['partnerName'], str(row['uuid']),
                            row.get('supportedReleases', [])])
    return validate_catalog({'schema_version': 1,
                             'fetched_at': datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
                             'source_url': URL, 'entries': entries})


def active_catalog(json_hcl: Optional[dict] = None) -> dict:
    """Imported bundle evidence wins over the local refresh/cache."""
    if json_hcl is not None and '_memory_tiering' in json_hcl:
        return json_hcl['_memory_tiering']
    return load_memory_tiering_catalog()
