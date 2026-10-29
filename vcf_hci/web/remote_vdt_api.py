"""Session-scoped appliance VDT deployment jobs for the local plugin UI."""

import ipaddress
import json
import re
import secrets
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

from vcf_hci.logging_utils import normalize_output_dir
from vcf_hci.plugins import remote_vdt
from vcf_hci.plugins.vcenter_probe import probe_vcenter, select_vdt
from vcf_hci.remote.executor import RemoteExecError, _redact, probe_jump_host_key
from vcf_hci.web.desktop import _is_safe_desktop_folder
from vcf_hci.web.export_api import _ApiMixinBase

_TERMINAL = ('completed', 'failed', 'cancelled', 'needs_credentials')
_MESSAGES = {
    'preflight': 'Verifying appliance access and prerequisites',
    'upload': 'Uploading the selected VDT payload into a temporary collection directory',
    'run': 'Running the reviewed vCenter diagnostic checks',
    'validate': 'Validating the generated artifact manifest',
    'pull': 'Retrieving and checking the diagnostic exports',
    'cleanup': 'Removing the completed remote collection directory',
    'import': 'Adding validated diagnostics to this assessment',
}



def _normalize_appliance_host(value: object) -> str:
    """Extract a pasted web URL's host; its port never changes the SSH port."""
    error = 'Enter an appliance hostname, address, or HTTP(S) URL without embedded credentials.'
    if not isinstance(value, str):
        raise ValueError(error)
    host = value.strip()
    if not host or len(host) > 2048 or any(ord(char) <= 32 or ord(char) == 127 for char in host):
        raise ValueError(error)
    if '://' in host:
        try:
            parsed = urllib.parse.urlsplit(host)
            if parsed.scheme.lower() not in ('http', 'https') or parsed.username is not None or parsed.password is not None:
                raise ValueError(error)
            # Validate an explicit web port, but keep the separate SSH port.
            _ = parsed.port
            host = parsed.hostname or ''
        except ValueError:
            raise ValueError(error) from None
    if not host or len(host) > 255:
        raise ValueError(error)
    return host


def remote_collection_capabilities(available: bool = True) -> dict:
    return {'available': available, 'products': ['vcenter'], 'versions': ['2.3.2'],
            'reason': '' if available else 'Appliance collection is available only from the local web listener.',
            'scope_notes': ['Reviewed VDT 2.3.2 for vCenter checks only; this is a partial VDT collection.',
                            'Support-bundle registration and unreviewed checks are excluded.',
                            'SSH upload, temporary execution files and diagnostic outputs are required.']}



def remote_collection_available(server: Any) -> bool:
    bind = str(getattr(server, 'bind_host', '127.0.0.1'))
    try:
        local = bind == 'localhost' or ipaddress.ip_address(bind).is_loopback
    except ValueError:
        local = False
    return local and not bool(getattr(server, 'allow_remote', False))


def cancel_remote_jobs(server: Any, wait: float = 0) -> None:
    lock = getattr(server, 'vdt_lock', None)
    if lock is None:
        return
    with lock:
        active = [job for job in getattr(server, 'vdt_remote_jobs', {}).values() if job['status'] not in _TERMINAL]
        for job in active:
            job['_cancel'].set()
        threads = [job.get('_worker') for job in active]
    deadline = time.monotonic() + wait
    for thread in threads:
        if thread is not None and thread is not threading.current_thread() and thread.is_alive():
            thread.join(timeout=max(0, deadline - time.monotonic()))

def _selected_payload(server: Any, folder: object, product: object) -> Path:
    if product != 'vcenter':
        raise ValueError('Remote collection currently supports the reviewed VDT 2.3.2 for vCenter profile. Other products remain importable.')
    if not isinstance(folder, str):
        raise ValueError('Select an installed VDT payload.')
    entries = server.vdt_plugin.get('installations', [])
    selected = next((item for item in entries if item.get('folder') == folder), None)
    if selected is None or selected.get('versions', {}).get('vcenter') != '2.3.2':
        raise ValueError('Select a detected VDT payload with vCenter version 2.3.2.')
    root = Path(server.vdt_plugin_root).resolve()
    path = root / folder
    resolved = path.resolve()
    if path.is_symlink() or (resolved != root and root not in resolved.parents):
        raise ValueError('The selected payload is outside the plugin folder.')
    if not resolved.is_dir():
        raise ValueError('The selected payload is unavailable. Restart after reinstalling it.')
    return resolved


def _public_job(job: dict) -> dict:
    return {name: value for name, value in job.items() if not name.startswith('_')}


def _import_exports(server: Any, session: str, exports: list) -> int:
    with server.vdt_lock:
        runs = list(server.vdt_sessions.get(session, []))
        added = 0
        for run in exports:
            if not isinstance(run, dict) or not run.get('id') or not run.get('findings'):
                raise ValueError('Collection did not produce a valid normalized VDT export.')
            if any(item['id'] == run['id'] for item in runs):
                continue
            runs.append(run)
            added += 1
        if len(runs) > 20 or sum(len(json.dumps(run).encode('utf-8')) for run in runs) > 24 * 1024 * 1024:
            raise ValueError('Collection was saved locally, but the assessment import limit was reached. Clear older imports and import the saved JSON.')
        server.vdt_sessions[session] = runs
    return added


def _collect_worker(server: Any, job_id: str, target: dict, payload: Path,
                    sso: dict, output_dir: Path) -> None:
    sensitive = [str(value) for value in (target.get('password'), target.get('private_key'), sso.get('password')) if value]
    with server.vdt_lock:
        job = server.vdt_remote_jobs[job_id]
        session = job['_session']
        cancel = job['_cancel']

    def event(value: dict) -> None:
        stage = str(value.get('stage') or 'run')
        if stage not in _MESSAGES:
            return
        with server.vdt_lock:
            job['stage'] = stage
            job['events'] = [*job['events'][-49:], {'stage': stage, 'message': _MESSAGES[stage]}]
            remote_dir = str(value.get('remote_dir') or '')
            if re.fullmatch(r'/tmp/vcfr_vdt_[a-f0-9]{32}', remote_dir):
                job['remote_dir'] = remote_dir

    try:
        result = remote_vdt.collect_vdt(target, payload, 'vcenter', sso, output_dir,
                                       on_event=event, cancel_event=cancel)
        # Valid exports have already passed native schema and hash validation in
        # the transfer layer; no raw SSH output enters UI state or evidence.
        event({'stage': 'import'})
        import_error = ''
        try:
            count = _import_exports(server, session, result.get('exports') or [])
        except ValueError as exc:
            count = 0
            import_error = str(exc)
        with server.vdt_lock:
            job.update(status='completed', stage='completed', finished_at=time.time(),
                       imported_exports=count, artifacts=[Path(name).name for name in result.get('artifacts', [])],
                       output_dir=str(result.get('local_dir') or output_dir),
                       cleaned=bool(result.get('cleaned')), scope_notes=result.get('scope_notes') or [],
                       warning=import_error or _redact(str(result.get('cleanup_error') or ''), sensitive))
            if result.get('cleaned'):
                job.pop('remote_dir', None)
            job['events'].append({'stage': 'completed', 'message': 'Validated VDT collection saved locally' + (' and added to the assessment.' if count else '.')})
    except Exception as exc:
        error = _redact(str(exc), sensitive)[:2000]
        code = str(getattr(exc, 'error_code', '') or '')
        if isinstance(exc, remote_vdt.VdtCancelled):
            state = 'cancelled'
        elif isinstance(exc, remote_vdt.VdtCredentialsRequired) or any(term in error.lower() for term in ('permission denied', 'authentication failed')):
            state = 'needs_credentials'
        else:
            state = 'failed'
        with server.vdt_lock:
            job.update(status=state, stage=state, error=error, error_code=code, finished_at=time.time())
            retained = str(getattr(exc, 'remote_dir', '') or '')
            if re.fullmatch(r'/tmp/vcfr_vdt_[a-f0-9]{32}', retained):
                job['remote_dir'] = retained
            else:
                job.pop('remote_dir', None)
            if getattr(exc, 'stop_confirmed', None) is False:
                job['stop_confirmed'] = False
                job['warning'] = 'The remote stop request could not be confirmed. Restore connectivity and inspect the retained directory; the bounded runner may continue until its 15-minute limit.'
            job['events'].append({'stage': state, 'message': error})
    finally:
        target.clear()
        sso.clear()
        sensitive.clear()


class RemoteVdtApiMixin(_ApiMixinBase):
    """Probe, preflight, launch, poll and cancel a trusted appliance collection."""

    def _api_remote_vdt(self, action: str) -> None:
        handler: Any = self
        server: Any = self.server
        if not server.vdt_plugin.get('present'):
            self._send_json({'error': 'Install VDT in the plugin folder and restart the server.'}, 404)
            return
        if not remote_collection_available(server):
            self._send_json({'error': remote_collection_capabilities(False)['reason']}, 403)
            return
        session = handler._current_session()
        if action == 'status':
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            identifier = query.get('job_id', [''])[0]
            with server.vdt_lock:
                if identifier:
                    job = server.vdt_remote_jobs.get(identifier)
                else:
                    jobs = [job for job in server.vdt_remote_jobs.values() if job['_session'] == session]
                    job = max(jobs, key=lambda item: item['created_at']) if jobs else None
                if job is not None and job['_session'] != session:
                    job = None
                data = {'job': _public_job(job) if job else None}
            if identifier and data['job'] is None:
                self._send_json({'error': 'Collection job not found.'}, 404)
                return
            self._send_json(data, extra_headers={'Cache-Control': 'no-store'})
            return
        data = self._read_json_body()
        if not isinstance(data, dict):
            self._send_json({'error': 'Expected a JSON object.'}, 400)
            return
        sensitive = []
        try:
            if action == 'cancel':
                with server.vdt_lock:
                    job = server.vdt_remote_jobs.get(data.get('job_id'))
                    if job is None or job['_session'] != session:
                        self._send_json({'error': 'Collection job not found.'}, 404)
                        return
                    if job['status'] not in _TERMINAL:
                        job['_cancel'].set()
                        job['events'].append({'stage': 'cancelling', 'message': 'Stopping this collection; partial remote evidence will be retained.'})
                    public = _public_job(job)
                self._send_json({'job': public}, extra_headers={'Cache-Control': 'no-store'})
                return
            if action == 'probe':
                host = _normalize_appliance_host(data.get('host'))
                port = int(data.get('port') or 22)
                if not 1 <= port <= 65535:
                    raise ValueError('Enter an SSH port from 1 through 65535.')
                response = probe_jump_host_key(host, port=port)
                if not response.get('ok'):
                    raise ValueError(response.get('error') or 'Could not inspect the appliance SSH host key.')
                self._send_json({'ok': True, 'host_key': response['public_key'],
                                 'fingerprint': response['fingerprint']}, extra_headers={'Cache-Control': 'no-store'})
                return
            if action not in ('preflight', 'run'):
                self._send_json({'error': 'Unknown VDT remote action.'}, 404)
                return
            payload = _selected_payload(server, data.get('folder'), data.get('product'))
            target = data.get('target', data)
            if not isinstance(target, dict):
                raise ValueError('Supply appliance SSH connection settings.')
            target = {name: target.get(name) for name in ('host', 'port', 'username', 'auth_type', 'password', 'host_key', 'private_key', 'key_path')}
            sensitive = [str(value) for value in (target.get('password'), target.get('private_key'), data.get('sso_password')) if value]
            target['host'] = _normalize_appliance_host(target.get('host'))
            detected = probe_vcenter(target['host'], port=data.get('https_port', 443))
            selection = select_vdt(server.vdt_plugin.get('installations', []), detected['version'])
            if not any(item['folder'] == data.get('folder') and item['remote_supported']
                       for item in selection['candidates']):
                raise ValueError(selection['reason'] or 'The selected VDT is not supported for this vCenter version.')
            if action == 'preflight':
                result = remote_vdt.preflight_vdt(target)
                result['vcenter'] = detected
                result['selection'] = selection
                result['warnings'] = [*remote_collection_capabilities()['scope_notes'], *result.get('warnings', [])]
                self._send_json(result, extra_headers={'Cache-Control': 'no-store'})
                target.clear()
                return
            sso = {'username': data.get('sso_username'), 'password': data.get('sso_password')}
            if not all(isinstance(value, str) and value for value in sso.values()):
                raise ValueError('Supply the vCenter SSO username and password separately from SSH credentials.')
            raw_output = data.get('output_dir', '')
            if not isinstance(raw_output, str):
                raise ValueError('Choose a local assessment output folder.')
            output = normalize_output_dir(raw_output)
            if not _is_safe_desktop_folder(output):
                raise ValueError('Choose an output folder under your home, report output, or temporary directory.')
            with server.vdt_lock:
                if any(job['status'] not in _TERMINAL for job in server.vdt_remote_jobs.values()):
                    self._send_json({'error': 'A VDT collection is already active. Wait for it or cancel it first.'}, 409)
                    return
                own_jobs = sorted((job for job in server.vdt_remote_jobs.values() if job['_session'] == session), key=lambda item: item['created_at'])
                for old in own_jobs[:-7]:
                    server.vdt_remote_jobs.pop(old['id'], None)
                identifier = secrets.token_hex(16)
                job = {'id': identifier, 'status': 'running', 'stage': 'preflight', 'created_at': time.time(),
                       'product': 'vcenter', 'target': str(target.get('host') or ''),
                       'vcenter_version': detected['version'], 'vdt_version': '2.3.2', 'events': [],
                       '_session': session, '_cancel': threading.Event()}
                server.vdt_remote_jobs[identifier] = job
            worker = threading.Thread(target=_collect_worker, args=(server, identifier, target, payload, sso, Path(output)), daemon=True)
            with server.vdt_lock:
                job['_worker'] = worker
            try:
                worker.start()
            except RuntimeError:
                with server.vdt_lock:
                    server.vdt_remote_jobs.pop(identifier, None)
                raise ValueError('Could not start the appliance collection worker.') from None
            with server.vdt_lock:
                public = _public_job(job)
            self._send_json({'job': public}, extra_headers={'Cache-Control': 'no-store'})
        except (ValueError, TypeError, OSError, RemoteExecError) as exc:
            message = _redact(str(exc), sensitive)[:2000]
            self._send_json({'error': message, 'needs_credentials': isinstance(exc, remote_vdt.VdtCredentialsRequired) or 'permission denied' in message.lower()}, 400)
