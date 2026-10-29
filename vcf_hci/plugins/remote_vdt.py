"""Pinned-SSH VDT deployment and private artifact collection (stdlib only).

The payload remains external to the scanner. SSH authentication and appliance
SSO credentials are separate; SSO values travel only over SSH stdin.
"""

import hashlib
import io
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Callable, Optional

from vcf_hci.plugins.appliance_runner import appliance_runner_source
from vcf_hci.plugins.vdt import MAX_EXPORT_BYTES, PRODUCTS, parse_vdt_export
from vcf_hci.remote import executor

MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_FILES = 2048
MAX_WIRE_BYTES = 72 * 1024 * 1024
_MARKER = 'vcfr-vdt-sandbox-v1'


class VdtRemoteError(executor.RemoteExecError):
    """A failed operation; remote_dir identifies retained diagnostic evidence."""

    def __init__(self, message: str, remote_dir: str = '', error_code: str = 'remote_failed'):
        super().__init__(message)
        self.remote_dir = remote_dir
        self.error_code = error_code
        self.stop_confirmed: Optional[bool] = None
        self.stop_error = ""


class VdtCredentialsRequired(VdtRemoteError):
    """The appliance runner requires separate SSO authentication."""


class VdtCancelled(VdtRemoteError):
    """An operator cancelled this deployment or collection."""


def _target(value: dict) -> dict:
    target = dict(value)
    host = str(target.get('host') or '')
    executor._check_target(host)
    username = str(target.get('username') or '')
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', username):
        raise VdtRemoteError('Supply a valid appliance SSH username.')
    try:
        port = int(target.get('port') or 22)
    except (TypeError, ValueError):
        raise VdtRemoteError('Supply an SSH port from 1 through 65535.') from None
    if not 1 <= port <= 65535:
        raise VdtRemoteError('Supply an SSH port from 1 through 65535.')
    key = executor._require_host_key(target)
    if '\n' in key or '\r' in key or len(key.split()) < 2:
        raise VdtRemoteError('Supply one pinned SSH public host key.')
    target['port'] = port
    return target


def _safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if not name or any(ord(c) < 32 for c in name) or '\\' in name or path.is_absolute() or any(p in ('', '.', '..') for p in name.split('/')):
        raise VdtRemoteError('Archive contains an unsafe member path.')
    for part in name.split('/'):
        stem = part.split('.', 1)[0].upper()
        if ':' in part or part.endswith(('.', ' ')) or stem in {'CON', 'PRN', 'AUX', 'NUL', *('COM'+str(i) for i in range(1,10)), *('LPT'+str(i) for i in range(1,10))}:
            raise VdtRemoteError('Archive member is unsafe on supported platforms.')
    if len(name) > 1024:
        raise VdtRemoteError('Archive member path is too long.')
    return name


def _archive_payload(payload_dir: Path) -> bytes:
    root = Path(payload_dir)
    if root.is_symlink() or not root.is_dir():
        raise VdtRemoteError('Select an extracted, non-symlinked VDT payload folder.')
    records = []
    total = 0
    for base, dirs, names in os.walk(str(root), followlinks=False):
        for entry in dirs:
            if (Path(base) / entry).is_symlink():
                raise VdtRemoteError('VDT payload contains a symlinked directory.')
        for name in sorted(names):
            path = Path(base) / name
            if path.is_symlink() or not path.is_file():
                raise VdtRemoteError('VDT payload contains a link or special file.')
            if '__pycache__' in path.parts or name.endswith('.pyc') or name in ('.DS_Store', 'Icon\r'):
                continue
            relative = _safe_name(path.relative_to(root).as_posix())
            size = path.stat().st_size
            total += size
            if total > MAX_PAYLOAD_BYTES or len(records) >= MAX_FILES:
                raise VdtRemoteError('VDT payload exceeds the transfer size or file limit.')
            records.append((path, 'payload/' + relative, size))
    if not any(name == 'payload/vdt.py' for _, name, _ in records):
        raise VdtRemoteError('The selected payload does not contain vdt.py.')
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for path, name, size in records:
            info = tarfile.TarInfo(name)
            info.size = size
            info.mode = 0o600
            with path.open('rb') as stream:
                archive.addfile(info, stream)
        source = appliance_runner_source().encode('utf-8')
        info = tarfile.TarInfo('runner.py')
        info.mode = 0o600
        info.size = len(source)
        archive.addfile(info, io.BytesIO(source))
    if len(output.getvalue()) > MAX_WIRE_BYTES:
        raise VdtRemoteError('VDT transfer archive is too large.')
    return output.getvalue()


def _process_run(argv, stdin=None, env=None, timeout=None, cancel_event=None):
    """Bound stdout/stderr on disk while polling timeout and cancellation."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=out, stderr=err, env=env)
        except FileNotFoundError:
            raise VdtRemoteError('OpenSSH is not installed on this workstation.') from None
        writer_error = []

        def write_input():
            try:
                assert process.stdin is not None
                process.stdin.write(stdin or b'')
                process.stdin.close()
            except (BrokenPipeError, OSError) as exc:
                writer_error.append(exc)

        writer = threading.Thread(target=write_input, daemon=True)
        writer.start()
        deadline = time.monotonic() + (timeout or 120)
        failure = None
        try:
            while process.poll() is None:
                if cancel_event is not None and cancel_event.is_set():
                    failure = VdtCancelled('VDT collection was cancelled.', error_code='cancelled')
                    break
                if time.monotonic() >= deadline:
                    failure = VdtRemoteError('VDT SSH operation timed out.', error_code='timeout')
                    break
                if os.fstat(out.fileno()).st_size > MAX_WIRE_BYTES or os.fstat(err.fileno()).st_size > 1024 * 1024:
                    failure = VdtRemoteError('VDT SSH output exceeded its transfer limit.')
                    break
                time.sleep(0.1)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            writer.join(timeout=2)
        if failure is not None:
            raise failure
        out.seek(0)
        err.seek(0)
        data = out.read(MAX_WIRE_BYTES + 1)
        diagnostic = err.read(1024 * 1024 + 1)
        if len(data) > MAX_WIRE_BYTES or len(diagnostic) > 1024 * 1024:
            raise VdtRemoteError('VDT SSH output exceeded its transfer limit.')
        return process.returncode, data, diagnostic


def _command(source: str) -> str:
    return 'python3 -c ' + shlex.quote(source)


_PREFLIGHT = '''# VCFR_VDT_STAGE_PREFLIGHT
import json, os, pathlib, sys
if sys.version_info < (3, 9):
    raise SystemExit("VDT deployment requires appliance Python 3.9 or newer")
s = os.statvfs('/tmp')
appliance = any(pathlib.Path(p).exists() for p in ('/etc/vmware-vpx', '/usr/lib/vmware-vpx', '/usr/lib/vmware-vmafd'))
print(json.dumps({'ok': True, 'python': list(sys.version_info[:3]), 'free_bytes': s.f_bavail*s.f_frsize, 'uid': os.geteuid(), 'shell': os.environ.get('SHELL', ''), 'python_executable': sys.executable, 'supported_products': ['vcenter'] if appliance else [], 'capabilities': {'noninteractive_python': True, 'vcenter_appliance': appliance}, 'warnings': ['Reduced audited vCenter checks only; VKS and SDDC Manager execution are unsupported.']}))
'''


def _guard(remote_dir: str, token: str) -> str:
    if not re.fullmatch(r'/tmp/vcfr_vdt_[0-9a-f]{32}', remote_dir):
        raise VdtRemoteError('Refusing an invalid remote sandbox path.')
    return '''import json, os, pathlib, stat
root = pathlib.Path(%r)
token = %r
if root.is_symlink() or not root.is_dir():
    raise RuntimeError('Sandbox directory is missing or unsafe')
marker = root / '.vcfr-vdt.json'
if marker.is_symlink() or not marker.is_file() or marker.stat().st_size > 4096:
    raise RuntimeError('Sandbox marker is missing or unsafe')
if json.loads(marker.read_text()) != {'kind': %r, 'token': token}:
    raise RuntimeError('Sandbox ownership marker mismatch')
''' % (remote_dir, token, _MARKER)


def _upload_source(remote_dir: str, token: str, archive_hash: str) -> str:
    return '''# VCFR_VDT_STAGE_UPLOAD
import hashlib, io, json, os, pathlib, sys, tarfile
root = pathlib.Path(%r)
os.umask(0o077)
root.mkdir(mode=0o700)
(root / '.vcfr-vdt.json').write_text(json.dumps({'kind': %r, 'token': %r}))
blob = sys.stdin.buffer.read(%d + 1)
if len(blob) > %d:
    raise RuntimeError('Payload archive is too large')
if hashlib.sha256(blob).hexdigest() != %r:
    raise RuntimeError('Payload archive integrity check failed')
with tarfile.open(fileobj=io.BytesIO(blob), mode='r:') as archive:
    seen=set(); total=0
    members=archive.getmembers()
    if len(members) > %d + 1:
        raise RuntimeError('Payload contains too many files')
    for member in members:
        name=member.name
        if not member.isfile() or name in seen or '\\\\' in name or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/')):
            raise RuntimeError('Unsafe payload archive member')
        if name != 'runner.py' and not name.startswith('payload/'):
            raise RuntimeError('Unexpected payload archive member')
        total += member.size
        if total > %d + 1024*1024:
            raise RuntimeError('Payload exceeds the expanded size limit')
        seen.add(name)
    for member in members:
        path=root/member.name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with archive.extractfile(member) as src, path.open('xb') as dst:
            import shutil
            shutil.copyfileobj(src, dst)
        path.chmod(0o600)
print(json.dumps({'ok':True}))
''' % (remote_dir, _MARKER, token, MAX_WIRE_BYTES, MAX_WIRE_BYTES, archive_hash, MAX_FILES, MAX_PAYLOAD_BYTES)


def _run_source(remote_dir: str, token: str, timeout: int) -> str:
    return '# VCFR_VDT_STAGE_RUN\n' + _guard(remote_dir, token) + '''
import signal, subprocess, sys
os.umask(0o077)
credentials = sys.stdin.buffer.read(65537)
if len(credentials) > 65536:
    raise RuntimeError('Credential input exceeds limit')
process = subprocess.Popen([sys.executable, str(root/'runner.py')], cwd=str(root), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
start = pathlib.Path('/proc/%%s/stat' %% process.pid).read_text().rsplit(')',1)[1].split()[19]
(root/'.process.json').write_text(json.dumps({'pid':process.pid,'start':start}))
try:
    output, _ = process.communicate(credentials, timeout=%d)
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    raise SystemExit('VDT run timed out; artifacts retained')
if len(output) > 1024*1024:
    raise SystemExit('Runner response exceeded limit')
sys.stdout.buffer.write(output)
raise SystemExit(process.returncode)
''' % timeout


def _kill_source(remote_dir: str, token: str) -> str:
    return '# VCFR_VDT_STAGE_STOP\n' + _guard(remote_dir, token) + '''
import signal, time
record=root/'.process.json'
if record.is_symlink():
    raise RuntimeError('Unsafe process record')
if record.exists():
    state=json.loads(record.read_text())
    pid=int(state['pid'])
    proc=pathlib.Path('/proc/%s' % pid)
    if pid > 1 and proc.exists():
        actual=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
        args=(proc/'cmdline').read_bytes()
        if actual != str(state['start']) or str(root/'runner.py').encode() not in args or os.getpgid(pid) != pid:
            raise RuntimeError('Refusing to stop a process with mismatched identity')
        os.killpg(pid, signal.SIGTERM)
        time.sleep(1)
        if proc.exists() and (proc/'stat').read_text().rsplit(')',1)[1].split()[19] == actual:
            os.killpg(pid, signal.SIGKILL)
print(json.dumps({'ok':True}))
'''


def _manifest_source(remote_dir: str, token: str, names: list, pull: bool = False) -> str:
    source = ('# VCFR_VDT_STAGE_PULL\n' if pull else '# VCFR_VDT_STAGE_VALIDATE\n') + _guard(remote_dir, token)
    source += '''
import hashlib, sys, tarfile
names=%r
seen=set(); records=[]; total=0
if not names or len(names)>%d:
    raise RuntimeError('Invalid artifact count')
for name in names:
    if not isinstance(name,str) or name in seen or '\\\\' in name or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/')) or not name.startswith('artifacts/'):
        raise RuntimeError('Unsafe artifact path')
    seen.add(name)
    path=root
    for part in name.split('/'):
        path=path/part
        if path.is_symlink():
            raise RuntimeError('Artifact symlink is prohibited')
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise RuntimeError('Artifact is not a regular file')
    size=path.stat().st_size
    total+=size
    if total>%d:
        raise RuntimeError('Artifacts exceed transfer size limit')
    records.append({'name':name,'size':size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
''' % (names, MAX_FILES, MAX_ARTIFACT_BYTES)
    if pull:
        source += '''with tarfile.open(fileobj=sys.stdout.buffer, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
    for record in records:
        archive.add(str(root/record['name']),arcname=record['name'],recursive=False)
'''
    else:
        source += "print(json.dumps({'ok':True,'files':records}))\n"
    return source


def _unpack(blob: bytes, manifest: list, directory: Path, product: str, host: str) -> tuple:
    if len(blob) > MAX_WIRE_BYTES or not blob:
        raise VdtRemoteError('Artifact archive is empty or exceeds the transfer limit.')
    expected = {}
    total = 0
    for entry in manifest:
        if not isinstance(entry, dict):
            raise VdtRemoteError('Invalid artifact manifest.')
        name = _safe_name(str(entry.get('name') or ''))
        if name in expected or not name.startswith('artifacts/'):
            raise VdtRemoteError('Invalid or duplicate artifact manifest path.')
        size = entry.get('size')
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise VdtRemoteError('Invalid artifact manifest size.')
        total += size
        if total > MAX_ARTIFACT_BYTES or len(expected) >= MAX_FILES:
            raise VdtRemoteError('Artifacts exceed transfer limits.')
        if not re.fullmatch(r'[0-9a-f]{64}', str(entry.get('sha256') or '')):
            raise VdtRemoteError('Invalid artifact checksum.')
        expected[name] = entry
    artifacts, exports = [], []
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:') as archive:
        members = []
        for member in archive:
            members.append(member)
            if len(members) > MAX_FILES:
                raise VdtRemoteError('Artifact archive contains too many members.')
        seen = set()
        for member in members:
            name = _safe_name(member.name)
            if not member.isfile() or name in seen or name not in expected or member.size != expected[name]['size']:
                raise VdtRemoteError('Artifact archive does not match the validated manifest.')
            seen.add(name)
        if seen != set(expected):
            raise VdtRemoteError('Artifact archive is incomplete.')
        for member in members:
            stream = archive.extractfile(member)
            if stream is None:
                raise VdtRemoteError('Artifact archive member is unreadable.')
            with stream:
                data = stream.read(member.size + 1)
            if len(data) != member.size or hashlib.sha256(data).hexdigest() != expected[member.name]['sha256']:
                raise VdtRemoteError('Artifact checksum validation failed.')
            if member.name.lower().endswith('.json'):
                if len(data) > MAX_EXPORT_BYTES:
                    raise VdtRemoteError('Native VDT JSON export exceeds its size limit.')
                exports.append(parse_vdt_export(data.decode('utf-8'), product, host, member.name))
            path = directory.joinpath(*PurePosixPath(member.name).parts)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open('xb') as dest:
                dest.write(data)
            path.chmod(0o600)
            artifacts.append(str(path))
    if not exports:
        raise VdtRemoteError('No valid native VDT JSON export was returned.')
    return artifacts, exports


class _Connection:
    def __init__(self, target, ssh_run=None, cancel_event=None):
        self.target = _target(target)
        self.runtime = tempfile.mkdtemp(prefix='vcfr_vdt_ssh_')
        self.cancel_event = cancel_event
        self.runner = ssh_run
        self.sensitive = [str(target.get(key) or '') for key in ('password', 'private_key')]
        try:
            self.identity, _, self.env = executor._prepare_identity(self.target, self.runtime)
        except Exception:
            self.close()
            raise

    def close(self):
        shutil.rmtree(self.runtime, ignore_errors=True)

    def call(self, source, stdin=None, timeout=120, cancellable=True):
        if cancellable and self.cancel_event is not None and self.cancel_event.is_set():
            raise VdtCancelled('VDT collection was cancelled.', error_code='cancelled')
        try:
            argv = executor.build_ssh_argv(self.target, os.path.join(self.runtime, 'control'), _command(source), self.identity, batch_mode='VCFR_SSH_PASS' not in self.env)
        except executor.RemoteExecError as exc:
            raise VdtRemoteError(executor._redact(str(exc), self.sensitive)) from None
        # Each operation is bounded and independently authenticated. Do not leave
        # an OpenSSH multiplexing master alive with authentication state.
        index = argv.index('ControlMaster=auto')
        argv[index] = 'ControlMaster=no'
        argv[argv.index('ControlPersist=60')] = 'ControlPersist=no'
        argv[1:1] = ['-o', 'ConnectTimeout=15', '-o', 'ConnectionAttempts=1', '-o', 'NumberOfPasswordPrompts=1', '-o', 'HostKeyAlias=' + str(self.target['host'])]
        if self.target.get('auth_type') == 'password':
            argv[1:1] = ['-o', 'PreferredAuthentications=password,keyboard-interactive']
        try:
            runner = self.runner
            if runner is None:
                code, out, err = _process_run(argv, stdin=stdin, env=executor._merged_env(self.env), timeout=timeout, cancel_event=self.cancel_event if cancellable else None)
            else:
                code, out, err = runner(argv, stdin=stdin, env=executor._merged_env(self.env), timeout=timeout)
        except VdtRemoteError:
            raise
        except subprocess.TimeoutExpired:
            raise VdtRemoteError('VDT SSH operation timed out.', error_code='timeout') from None
        except Exception as exc:
            raise VdtRemoteError(executor._redact(str(exc), self.sensitive)) from None
        detail = executor._redact(err.decode('utf-8', 'replace') if isinstance(err, bytes) else str(err), self.sensitive)
        if code:
            actionable = ' The appliance must permit noninteractive Bash/Python commands; appliancesh is unsupported. No shell settings were changed.' if 'VCFR_VDT_STAGE_PREFLIGHT' in source else ''
            error_code = 'ssh_auth_failed' if 'permission denied' in detail.lower() or 'authentication failed' in detail.lower() else 'remote_failed'
            raise VdtRemoteError('Appliance SSH operation failed: ' + detail[:1200] + actionable, error_code=error_code)
        return out

    def json_call(self, source, stdin=None, timeout=120):
        raw = self.call(source, stdin, timeout)
        if len(raw) > 1024 * 1024:
            raise VdtRemoteError('Appliance response exceeded its size limit.')
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):
            raise VdtRemoteError('Appliance did not return the expected JSON response; verify its noninteractive shell.') from None
        if not isinstance(value, dict):
            raise VdtRemoteError('Invalid appliance response.')
        return value


def preflight_vdt(target: dict, ssh_run=None) -> dict:
    """Read Python, shell and scratch-space availability over pinned SSH."""
    connection = _Connection(target, ssh_run)
    try:
        result = connection.json_call(_PREFLIGHT, timeout=30)
        if result.get('uid') != 0:
            raise VdtRemoteError('Use an appliance SSH account with root privileges for this VDT profile. Automatic sudo is not supported.')
        if not result.get('ok') or result.get('free_bytes', 0) < MAX_PAYLOAD_BYTES * 3:
            raise VdtRemoteError('Appliance needs Python 3.9+ and at least 192 MiB free in /tmp.')
        return result
    finally:
        connection.close()


def collect_vdt(target: dict, payload_dir: Path, product: str, sso: dict, output_dir: Path,
                on_event: Optional[Callable] = None, cancel_event: Optional[threading.Event] = None,
                ssh_run=None, timeout: int = 1800) -> dict:
    """Deploy, run, validate, pull and clean only a marker-owned VDT sandbox.

    Failures retain remote evidence and expose ``error.remote_dir``. Cleanup
    failures return a successful collection with ``cleaned=False``.
    """
    if product not in PRODUCTS:
        raise VdtRemoteError('Choose vCenter, VKS, or SDDC Manager.')
    if product != 'vcenter':
        raise VdtRemoteError('Remote VDT execution currently supports audited vCenter checks only.', error_code='unsupported_product')
    if not isinstance(timeout, int) or not 10 <= timeout <= 3600:
        raise VdtRemoteError('VDT timeout must be between 10 and 3600 seconds.')
    document = {'product': product, 'sso_username': str(sso.get('username') or ''), 'sso_password': str(sso.get('password') or '')}
    credentials = json.dumps(document).encode('utf-8')
    if len(credentials) > 65536:
        raise VdtRemoteError('SSO credentials exceed the supported size limit.')
    blob = _archive_payload(Path(payload_dir))
    token = secrets.token_hex(16)
    remote_dir = '/tmp/vcfr_vdt_' + token
    connection = _Connection(target, ssh_run, cancel_event)
    connection.sensitive.extend([document['sso_username'], document['sso_password']])
    remote_created = False
    local_dir = None

    def event(stage):
        if on_event is not None:
            on_event({'stage': stage, 'remote_dir': remote_dir})

    try:
        event('preflight')
        preflight = connection.json_call(_PREFLIGHT, timeout=30)
        if preflight.get('uid') != 0:
            raise VdtRemoteError('Use an appliance SSH account with root privileges for this VDT profile. Automatic sudo is not supported.')
        if not preflight.get('ok') or preflight.get('free_bytes', 0) < MAX_PAYLOAD_BYTES * 3:
            raise VdtRemoteError('Appliance needs at least 192 MiB free in /tmp.')
        if product not in preflight.get('supported_products', []):
            raise VdtRemoteError('The target does not expose the expected vCenter appliance files.', error_code='unsupported_appliance')
        event('upload')
        # An interrupted upload can create this sandbox. Retain its path even
        # when the SSH acknowledgement is lost.
        remote_created = True
        connection.json_call(_upload_source(remote_dir, token, hashlib.sha256(blob).hexdigest()), blob, timeout=120)
        event('run')
        response = connection.json_call(_run_source(remote_dir, token, timeout), credentials, timeout=timeout + 15)
        if not response.get('ok'):
            code = str(response.get('error_code') or 'runner_failed')
            message = executor._redact(str(response.get('error') or 'The appliance runner failed.'), connection.sensitive)
            audit = response.get('audit_event')
            binary = response.get('audit_binary')
            if isinstance(audit, str):
                message += ' Audit=' + audit[:80]
            if isinstance(binary, str):
                message += ' Executable=' + binary[:80]
            diagnostic = response.get('error_type')
            frames = response.get('stack_frames')
            if isinstance(diagnostic, str) and diagnostic:
                message += ' [' + diagnostic[:100] + ']'
            if isinstance(frames, list):
                for frame in frames[-12:]:
                    if isinstance(frame, dict):
                        message += ' ' + str(frame.get('file', ''))[:100] + ':' + str(frame.get('line', ''))[:10] + ':' + str(frame.get('function', ''))[:100]
            message = executor._redact(message, connection.sensitive)
            cls = VdtCredentialsRequired if code == 'credentials_required' else VdtRemoteError
            raise cls(message, remote_dir, code)
        if response.get('product') != product:
            raise VdtRemoteError('Appliance returned diagnostics for a different product.')
        names = response.get('artifact_files')
        if not isinstance(names, list) or not names or len(names) > MAX_FILES:
            raise VdtRemoteError('The appliance runner returned no valid artifact list.')
        for name in names:
            if not isinstance(name, str) or not _safe_name(name).startswith('artifacts/'):
                raise VdtRemoteError('The appliance runner returned an unsafe artifact path.')
        event('validate')
        manifest = connection.json_call(_manifest_source(remote_dir, token, names))
        if not manifest.get('ok') or not isinstance(manifest.get('files'), list):
            raise VdtRemoteError('Artifact manifest validation failed.')
        event('pull')
        output = Path(output_dir)
        output.mkdir(mode=0o700, parents=True, exist_ok=True)
        local_dir = Path(tempfile.mkdtemp(prefix='vdt_', dir=str(output)))
        archive = connection.call(_manifest_source(remote_dir, token, names, pull=True), timeout=120)
        artifacts, exports = _unpack(archive, manifest['files'], local_dir, product, str(target.get('host') or ''))
        event('cleanup')
        cleanup = '# VCFR_VDT_STAGE_CLEANUP\n' + _guard(remote_dir, token) + "\nimport shutil\nshutil.rmtree(str(root))\nprint(json.dumps({'ok':True}))\n"
        cleaned, cleanup_error = True, ''
        try:
            connection.json_call(cleanup, timeout=30)
        except Exception as exc:
            cleaned = False
            cleanup_error = executor._redact(str(exc), connection.sensitive)
        notes = response.get('scope_notes')
        return {'artifacts': artifacts, 'exports': exports, 'manifest': manifest['files'],
                'remote_dir': remote_dir, 'local_dir': str(local_dir), 'cleaned': cleaned,
                'cleanup_error': cleanup_error, 'scope_notes': notes if isinstance(notes, list) else []}
    except Exception as exc:
        stop_confirmed = None
        stop_error = ''
        if remote_created:
            try:
                connection.call(_kill_source(remote_dir, token), timeout=20, cancellable=False)
                stop_confirmed = True
            except Exception as stopping:
                stop_confirmed = False
                stop_error = executor._redact(str(stopping), connection.sensitive)[:1200]
        if local_dir is not None:
            shutil.rmtree(str(local_dir), ignore_errors=True)
        if isinstance(exc, VdtRemoteError):
            exc.remote_dir = remote_dir if remote_created else ''
            exc.stop_confirmed = stop_confirmed
            exc.stop_error = stop_error
            exc.args = (executor._redact(str(exc), connection.sensitive),)
            raise
        failure = VdtRemoteError(executor._redact(str(exc), connection.sensitive), remote_dir if remote_created else '')
        failure.stop_confirmed = stop_confirmed
        failure.stop_error = stop_error
        raise failure from None
    finally:
        connection.close()
