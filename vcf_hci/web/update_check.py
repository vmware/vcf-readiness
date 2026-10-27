"""Best-effort, once-per-launch stable release notice for the scanner UI."""

import json
import logging
import os
import re
import threading
import urllib.parse
import urllib.request
from typing import Optional, Tuple

logger = logging.getLogger("vcf_assess")

RELEASE_API = 'https://api.github.com/repos/vmware/vcf-readiness/releases/latest'
RELEASE_PAGES = 'https://github.com/vmware/vcf-readiness/releases/tag/'
_MAX_RESPONSE_BYTES = 256 * 1024


def _version(value: str) -> Optional[Tuple[int, int, int]]:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r'[vV]?(\d+)\.(\d+)\.(\d+)', value.strip())
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _newer_release(current_version: str, release: dict) -> dict:
    if not isinstance(release, dict) or release.get('draft') or release.get('prerelease'):
        return {}
    tag = release.get('tag_name')
    if not isinstance(tag, str):
        return {}
    current, latest = _version(current_version), _version(tag)
    if current is None or latest is None or latest <= current:
        return {}
    return {
        'latest_version': '.'.join(str(part) for part in latest),
        # Do not turn arbitrary remote URLs or release-note HTML into UI links.
        'release_url': RELEASE_PAGES + urllib.parse.quote(tag.strip(), safe=''),
    }


def _fetch_release(current_version: str) -> dict:
    request = urllib.request.Request(RELEASE_API, headers={
        'Accept': 'application/vnd.github+json',
        'User-Agent': f'VCFReadiness/{current_version}',
    })
    # Public GitHub uses normal HTTPS certificate verification, unlike BMCs.
    with urllib.request.urlopen(request, timeout=3) as response:
        body = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(body) > _MAX_RESPONSE_BYTES:
        return {}
    try:
        release = json.loads(body.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return _newer_release(current_version, release)


class ReleaseUpdateChecker:
    """Cache one bounded request in memory; never delay the scanner's launch."""

    def __init__(self, current_version: str):
        self.current_version = current_version
        self._lock = threading.Lock()
        self._started = False
        self._worker = None
        self._state = {
            'checked': False, 'update_available': False,
            'current_version': current_version, 'latest_version': '', 'release_url': '',
        }

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._state)

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            if os.environ.get('VCF_READINESS_CHECK_UPDATES', '1').strip().lower() in ('0', 'false', 'no', 'off'):
                self._state['checked'] = True
                return
        try:
            self._worker = threading.Thread(target=self._run, name='release-update-check', daemon=True)
            self._worker.start()
        except RuntimeError as exc:
            logger.debug('Release update check unavailable: %s', exc)
            with self._lock:
                self._state['checked'] = True

    def _run(self) -> None:
        info = {}
        try:
            info = _fetch_release(self.current_version)
        except Exception as exc:
            # Offline, proxy, TLS, API and rate-limit failures stay unobtrusive.
            logger.debug('Release update check skipped: %s', exc)
        with self._lock:
            self._state.update(info)
            self._state['update_available'] = bool(info)
            self._state['checked'] = True
