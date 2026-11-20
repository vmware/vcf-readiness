"""Session-owned MTAT subprocesses over private pipes; no managed operations here."""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.plugins.mtat_package import _verify_folder

PROTOCOL = 'vcfr-mtat/1'
MAX_LINE = 48 * 1024 * 1024
_ID = re.compile(r'[0-9a-f]{32}\Z')


class RuntimeErrorMTAT(ValueError):
    """Authored, credential-safe bridge failure."""


class Worker:
    """One isolated upstream engine, verified before execution and stopped on close."""

    def __init__(self, folder: Path, data_root: Path, python: Optional[str] = None) -> None:
        self.manifest = _verify_folder(folder)
        if self.manifest['integration'] != PROTOCOL:
            raise RuntimeErrorMTAT('This package supports installation only. Install a vcfr-mtat/1 integration release.')
        if not (folder / 'mtat_py/bridge.py').is_file():
            raise RuntimeErrorMTAT('The integration entry point is missing.')
        executable = python or os.environ.get('VCFR_MTAT_PYTHON')
        if not executable:
            if getattr(sys, 'frozen', False) or sys.version_info < (3, 11):
                raise RuntimeErrorMTAT('Configure VCFR_MTAT_PYTHON with a Python 3.11+ interpreter for source plugins.')
            executable = sys.executable
        executable = shutil.which(executable) or executable
        if not Path(executable).is_file():
            raise RuntimeErrorMTAT('The configured MTAT Python interpreter is unavailable.')
        if data_root.is_symlink():
            raise RuntimeErrorMTAT('The MTAT data root must not be a symbolic link.')
        data_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.folder, self.data_root = folder, data_root
        self.lock = threading.Lock()
        self.responses: queue.Queue[Any] = queue.Queue(maxsize=4)
        self.closed = False
        self.cleanup = 'not_closed'
        self._stderr = (data_root / sanitize_filename('worker-stderr.log')).open('ab')
        env = {k: v for k, v in os.environ.items() if k in ('PATH', 'SYSTEMROOT', 'WINDIR', 'LANG', 'LC_ALL', 'TMPDIR', 'TEMP', 'TMP', 'SSL_CERT_FILE', 'SSL_CERT_DIR')}
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        try:
            self.process = subprocess.Popen([str(executable), '-B', '-m', 'mtat_py.bridge', '--data-root', str(data_root)],
                                            cwd=folder, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=self._stderr)
        except OSError:
            self._stderr.close()
            raise RuntimeErrorMTAT('Could not start the configured MTAT runtime.') from None
        threading.Thread(target=self._read, daemon=True).start()
        try:
            description = self.request('describe', {}, timeout=20)
            if not isinstance(description, dict) or description.get('protocol') != PROTOCOL:
                raise RuntimeErrorMTAT('The worker protocol does not match the installed package.')
        except Exception:
            self.close()
            raise

    def _read(self) -> None:
        stream = self.process.stdout
        if stream is None:
            return
        try:
            while True:
                raw = stream.readline(MAX_LINE + 1)
                if not raw or len(raw) > MAX_LINE or not raw.endswith(b'\n'):
                    break
                try:
                    result = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    break
                self.responses.put(result, timeout=1)
        except (OSError, queue.Full):
            pass
        finally:
            try:
                self.responses.put(None, timeout=1)
            except queue.Full:
                pass

    def request(self, op: str, payload: dict, timeout: float = 120) -> Any:
        with self.lock:
            if self.closed or self.process.poll() is not None or self.process.stdin is None:
                raise RuntimeErrorMTAT('MTAT stopped. Activate the package again to reopen saved work and resume.')
            request_id = uuid.uuid4().hex
            raw = (json.dumps({'id': request_id, 'op': op, 'payload': payload}, allow_nan=False) + '\n').encode()
            if len(raw) > MAX_LINE:
                raise RuntimeErrorMTAT('MTAT request exceeds the bridge byte limit.')
            try:
                written: queue.Queue[bool] = queue.Queue(maxsize=1)
                def write() -> None:
                    try:
                        assert self.process.stdin is not None
                        self.process.stdin.write(raw)
                        self.process.stdin.flush()
                        written.put(True)
                    except (OSError, ValueError):
                        written.put(False)
                deadline = time.monotonic() + timeout
                threading.Thread(target=write, daemon=True).start()
                if not written.get(timeout=timeout):
                    raise OSError('pipe closed')
                answer = self.responses.get(timeout=max(0.01, deadline - time.monotonic()))
            except (OSError, queue.Empty):
                self.process.terminate()
                raise RuntimeErrorMTAT('MTAT communication failed or timed out. Saved results remain available.') from None
            if not isinstance(answer, dict) or answer.get('id') != request_id:
                raise RuntimeErrorMTAT('MTAT returned an invalid protocol response.')
            if answer.get('error'):
                # Upstream owns structured messages; never echo arbitrary SDK faults.
                error = answer['error']
                code = error.get('code') if isinstance(error, dict) else 'worker_error'
                code = code if isinstance(code, str) and re.fullmatch(r'[a-z0-9_]{1,64}', code) else 'worker_error'
                guidance = {
                    'tls_certificate': 'Certificate validation failed. Review certificate trust, pin or the enterprise CA bundle.',
                    'authentication_failed': 'Authentication failed. Review credentials and the Operations authentication source.',
                    'permission_denied': 'Access denied. Review inventory and metric read permissions.',
                    'invalid_request': 'Input was rejected. Review the endpoint, credentials and operation fields.',
                    'job_busy': 'An operation is active. Wait for it to finish before reconnecting.',
                }.get(code, 'Review source access, input and job diagnostics.')
                raise RuntimeErrorMTAT('MTAT operation failed (%s). %s' % (code, guidance))
            return answer.get('result')

    def close(self) -> None:
        if self.closed:
            return
        try:
            self.cleanup = 'graceful' if self.process.poll() is None else 'already_stopped; remote session cleanup is unverified'
            if self.process.poll() is None:
                try:
                    result = self.request('close', {}, timeout=8)
                    if isinstance(result, dict) and result.get('cleanup_verified') is False:
                        self.cleanup = 'worker stopped; remote session cleanup is unverified'
                except (ValueError, OSError):
                    self.cleanup = 'forced; remote session cleanup is unverified'
                try:
                    self.process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self.cleanup = 'forced; remote session cleanup is unverified'
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=5)
        finally:
            self.closed = True
            for stream in (self.process.stdin, self.process.stdout):
                if stream is not None:
                    stream.close()
            self._stderr.close()


class RuntimeManager:
    def __init__(self, plugin_root: Path, data_root: Optional[Path] = None) -> None:
        self.root = plugin_root
        self.data_root = data_root or plugin_root.parent / '.vcf-readiness' / 'mtat'
        self.lock = threading.RLock()
        self.workers: dict[str, Worker] = {}
        self.workspaces: dict[str, str] = {}

    def activate(self, session: str, folder: str, workspace_id: str = '') -> dict:
        if not session or not folder.startswith('mtat-') or folder != sanitize_filename(folder):
            raise RuntimeErrorMTAT('Select an installed MTAT package.')
        if workspace_id and not _ID.fullmatch(workspace_id):
            raise RuntimeErrorMTAT('Invalid saved MTAT workspace reference.')
        with self.lock:
            old = self.workers.get(session)
            if old is not None:
                active = old.request('jobs.list', {}) if old.process.poll() is None else {}
                if any(j.get('status') in ('running', 'cancelling', 'queued') for j in (active.get('jobs', []) if isinstance(active, dict) else [])):
                    raise RuntimeErrorMTAT('Cancel or finish the active collection before switching MTAT engines.')
                old.close()
                self.workers.pop(session, None)
            workspace_id = workspace_id or self.workspaces.get(session) or uuid.uuid4().hex
            if any(value == workspace_id for key, value in self.workspaces.items() if key != session and key in self.workers):
                raise RuntimeErrorMTAT('This workspace is already open in another session.')
            worker = Worker(self.root / folder, self.data_root / workspace_id)
            self.workers[session] = worker
            self.workspaces[session] = workspace_id
            return self.describe(session)

    def get(self, session: str) -> Worker:
        with self.lock:
            if not session or session not in self.workers:
                raise RuntimeErrorMTAT('Activate an installed MTAT integration package first.')
            return self.workers[session]

    def describe(self, session: str) -> dict:
        with self.lock:
            if session not in self.workers:
                return {'active': False, 'protocol': PROTOCOL}
            worker = self.workers[session]
            return dict(worker.request('describe', {}), active=True, folder=worker.folder.name,
                        workspace_id=self.workspaces[session], package=worker.manifest['version'])

    def close(self, session: str = '') -> dict:
        with self.lock:
            outcomes = []
            keys = [session] if session else list(self.workers)
            for key in keys:
                worker = self.workers.pop(key, None)
                if worker is not None:
                    worker.close()
                    outcomes.append(worker.cleanup)
            return {'active': False, 'cleanup': outcomes}
