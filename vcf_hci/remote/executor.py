"""
Run one ephemeral collector on a single Linux jump host over the system ``ssh`` binary.

No Paramiko. BMC passwords travel on the SSH stdin of the remote Python process
and are not placed in argv. An embedded SSH private key is written to a 0600
file for OpenSSH IdentityFile and removed in ``finally``. OpenSSH cannot read
a key from memory.

Inject ``ssh_run`` in tests. The default runner is subprocess.
"""

import json
import os
import select
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from vcf_hci.creds_stdin import dump_creds_document
from vcf_hci.logging_utils import is_cloud_metadata_target
from vcf_hci.remote.guardrails import (
    MARKER_TOKEN,
    SecurityError,
    assert_sandbox_path,
    cleanup_python_source,
    kill_scan_python_source,
    maintenance_python_source,
    marker_document,
    preflight_python_source,
    probe_active_scans_python_source,
    sandbox_path_for_run,
    tailer_python_source,
)

__all__ = [
    "ActiveScanError",
    "JumpHostConnectionLostError",
    "RemoteExecError",
    "build_remote_resume_shell",
    "build_remote_scan_shell",
    "build_ssh_argv",
    "inspect_jump_scans",
    "is_ssh_connection_lost",
    "kill_remote_scan",
    "preflight_jump",
    "probe_jump_host_key",
    "resume_remote_scan",
    "run_remote_scan",
    "tailer_python_source",
]

_PROFILES = {"readiness-full", "readiness-lean", "inventory-lite"}
_TARGET_RE_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")

SshRun = Callable[..., Tuple[int, bytes, bytes]]


class RemoteExecError(Exception):
    """The jump host could not run or return the scan."""


class JumpHostConnectionLostError(RemoteExecError):
    """The SSH connection or VPN to the jump host was lost."""

    def __init__(
        self,
        message: str,
        host: Optional[str] = None,
        detail: Optional[str] = None,
        run_id: Optional[str] = None,
        remote_dir: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.host = host
        self.detail = detail
        self.run_id = run_id
        self.remote_dir = remote_dir


class ActiveScanError(RemoteExecError):
    """A live collector already holds the remote lock."""


_CONNECTION_LOST_PATTERNS = (
    "broken pipe",
    "connection reset",
    "network is unreachable",
    "no route to host",
    "operation timed out",
    "connection timed out",
    "host is down",
    "network is down",
    "connection refused",
    "client_loop: send disconnect",
    "connection closed by remote host",
    "closed by remote host",
    "kex_exchange_identification",
    "banner exchange",
    "packet_write_wait",
    "ssh_dispatch_run_fatal",
    "killed by signal 1",
    "terminated",
)


def is_ssh_connection_lost(code: int, detail: str) -> bool:
    """Return True if the SSH process failure indicates a network/VPN disconnection."""
    lower = (detail or "").lower()
    return code == 255 or any(p in lower for p in _CONNECTION_LOST_PATTERNS)


def _redact(text: str, secrets: Sequence[str]) -> str:
    for secret in secrets:
        if secret and secret in text:
            text = text.replace(secret, "[redacted]")
    return text


def _check_target(target: str) -> str:
    if not target or any(ch not in _TARGET_RE_OK for ch in target):
        raise RemoteExecError("refusing target with unsupported characters")
    return target


def _check_profile(profile: str) -> str:
    if profile not in _PROFILES:
        raise RemoteExecError("unsupported scan profile")
    return profile


def _remote_python_stdin_cmd(*args: str) -> str:
    """Build ``python3 - [args]`` with each argument shell-quoted.

    OpenSSH runs the remote command via the login shell, so unquoted
    arguments are command-injection. Callers must still pass only
    allowlisted values (sandbox paths, ``all``, or small integers).
    """
    if not args:
        return "python3 -"
    return "python3 - " + " ".join(shlex.quote(str(item)) for item in args)


def _normalize_kill_remote_dir(remote_dir: str) -> str:
    """Return ``all`` or a sandbox path. Raises SecurityError otherwise."""
    raw = (remote_dir or "all").strip()
    if raw == "all":
        return "all"
    return assert_sandbox_path(raw)


def _write_private(directory: str, name: str, data: str, mode: int) -> str:
    path = os.path.join(directory, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, mode)
    return path


def _ensure_known_hosts(jump: Dict[str, Any], runtime_dir: str) -> Optional[str]:
    """If jump has a pinned host_key, write an isolated 0600 known_hosts file."""
    host_key = str(jump.get("host_key") or "").strip()
    if not host_key:
        return None
    if not runtime_dir or not os.path.isdir(runtime_dir):
        return None
    host = str(jump.get("host") or "").strip()
    try:
        port = int(jump.get("port") or 22)
    except (TypeError, ValueError):
        port = 22
    kh_path = os.path.join(runtime_dir, "known_hosts")
    if not os.path.exists(kh_path):
        line = f"{host},[{host}]:{port} {host_key}\n" if port == 22 else f"[{host}]:{port} {host_key}\n"
        _write_private(runtime_dir, "known_hosts", line, 0o600)
    return kh_path


def _ensure_tofu_known_hosts(runtime_dir: str) -> Optional[str]:
    """Empty isolated known_hosts so accept-new does not write ~/.ssh/known_hosts."""
    if not runtime_dir or not os.path.isdir(runtime_dir):
        return None
    kh_path = os.path.join(runtime_dir, "known_hosts.tofu")
    if not os.path.exists(kh_path):
        _write_private(runtime_dir, "known_hosts.tofu", "", 0o600)
    return kh_path


def build_ssh_argv(jump: Dict[str, Any], control_path: str, remote_command: str,
                   identity_file: Optional[str] = None, batch_mode: bool = True,
                   known_hosts_file: Optional[str] = None) -> List[str]:
    """Build an argv list. The remote command is one argument, not a local shell.

    Password auth omits BatchMode so OpenSSH will call SSH_ASKPASS. The password
    stays in the child environment, not in argv.
    """
    host = str(jump.get("host") or "")
    user = str(jump.get("username") or "")
    if not host or not user or any(ch.isspace() for ch in host + user):
        raise RemoteExecError("jump host and username are required")
    try:
        port = int(jump.get("port") or 22)
    except (TypeError, ValueError):
        raise RemoteExecError("invalid jump host port") from None

    if known_hosts_file is None and jump.get("host_key") and control_path:
        runtime_dir = os.path.dirname(control_path)
        known_hosts_file = _ensure_known_hosts(jump, runtime_dir)

    argv = ["ssh", "-T"]
    if batch_mode:
        argv.extend(["-o", "BatchMode=yes"])

    if known_hosts_file:
        argv.extend([
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=%s" % known_hosts_file,
            "-o", "GlobalKnownHostsFile=/dev/null",
        ])
    else:
        tofu = None
        if control_path:
            tofu = _ensure_tofu_known_hosts(os.path.dirname(control_path))
        tofu_path = tofu or "/dev/null"
        argv.extend([
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=%s" % tofu_path,
            "-o", "GlobalKnownHostsFile=/dev/null",
        ])

    argv.extend([
        "-o", "HostKeyAlgorithms=ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256",
        "-o", "ControlMaster=auto",
        "-o", "ControlPersist=60",
        "-o", "ControlPath=%s" % control_path,
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        "-p", str(port),
    ])
    if identity_file:
        argv.extend(["-i", identity_file, "-o", "IdentitiesOnly=yes"])
    argv.append("%s@%s" % (user, host))
    argv.append(remote_command)
    return argv


def build_remote_scan_shell(
    remote_dir: str,
    targets: Sequence[str],
    threads: int,
    profile: str,
    host_timeout: int = 300,
    debug: bool = False,
) -> str:
    """Shell run on the jump host. ``remote_dir`` must already pass the sandbox check."""
    remote_dir = assert_sandbox_path(remote_dir)
    profile = _check_profile(profile)
    try:
        threads_i = int(threads)
    except (TypeError, ValueError):
        raise RemoteExecError("threads must be an integer") from None
    if threads_i < 1 or threads_i > 96:
        raise RemoteExecError("threads must be 1-96")
    try:
        timeout_i = int(host_timeout)
    except (TypeError, ValueError):
        raise RemoteExecError("host_timeout must be an integer") from None
    if timeout_i < 1:
        raise RemoteExecError("host_timeout must be at least 1")
    run_id = os.path.basename(remote_dir)[len("vcfr_remote_"):]
    targets_count = len(targets)
    quoted_targets = ",".join(shlex.quote(_check_target(item)) for item in targets)
    debug_flag = " --debug" if debug else ""
    tailer_src = tailer_python_source().strip()
    # remote_dir is regex-limited to hex, so it is safe to embed.
    return (
        "set -u; umask 077; export HISTFILE=/dev/null; "
        "cd %s; mkdir -p out; "
        "touch .vcfr_progress.ndjson; "
        "trap '' HUP; "
        "( python3 worker.pyz --no-input --creds-stdin --progress-ndjson "
        "--targets %s --threads %d --profile %s --output-dir %s/out --save-json "
        "--host-timeout %d%s "
        ">> .vcfr_progress.ndjson 2>&1; echo $? > .vcfr_exit ) 0<&0 & "
        "WPID=$!; "
        "printf '{\"pid\":%%s,\"run_id\":\"%s\",\"start_time\":%%s,\"target_count\":%d}\\n' \"$WPID\" \"$(date +%%s)\" > .vcfr_lock; "
        "if command -v vcf-log-activity >/dev/null 2>&1; then vcf-log-activity start --mechanism jumphost_framework --run-id \"%s\" --targets-count %d; fi; "
        "trap 'kill \"$WPID\" 2>/dev/null || true' INT TERM; "
        "cat << 'EOF' > .vcfr_tailer.py\n"
        "%s\n"
        "EOF\n"
        "python3 .vcfr_tailer.py 0 \"$WPID\"; "
        "RC=$?; "
        "if command -v vcf-log-activity >/dev/null 2>&1; then vcf-log-activity complete --mechanism jumphost_framework --run-id \"%s\" --exit-code \"$RC\" --targets-count %d --artifacts-dir \"%s/out\"; fi; "
        "if [ -f .vcfr_exit ]; then exit $(cat .vcfr_exit); fi; "
        "exit $RC"
        % (remote_dir, quoted_targets, threads_i, profile, remote_dir, timeout_i, debug_flag, run_id, targets_count, run_id, targets_count, tailer_src, run_id, targets_count, remote_dir)
    )


def build_remote_resume_shell(remote_dir: str, offset: int = 0) -> str:
    """Shell run on the jump host to resume streaming an in-progress or completed scan."""
    remote_dir = assert_sandbox_path(remote_dir)
    tailer_src = tailer_python_source().strip()
    return (
        "set -u; umask 077; export HISTFILE=/dev/null; "
        "cd %s; "
        "cat << 'EOF' > .vcfr_tailer.py\n"
        "%s\n"
        "EOF\n"
        "python3 .vcfr_tailer.py %d; "
        "RC=$?; "
        "if [ -f .vcfr_exit ]; then exit $(cat .vcfr_exit); fi; "
        "exit $RC"
        % (remote_dir, tailer_src, max(0, int(offset)))
    )


def default_ssh_run(argv: List[str], stdin: Optional[bytes] = None,
                    env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> Tuple[int, bytes, bytes]:
    try:
        proc = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            env=env,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise RemoteExecError("ssh client not found on this workstation") from None
    except subprocess.TimeoutExpired:
        raise RemoteExecError("ssh command timed out") from None
    return proc.returncode, proc.stdout or b"", proc.stderr or b""


def _run(ssh_run: SshRun, argv: List[str], stdin: Optional[bytes], env: Optional[Dict[str, str]],
         timeout: Optional[int], secrets: Sequence[str]) -> Tuple[int, bytes, bytes]:
    try:
        code, out, err = ssh_run(argv, stdin=stdin, env=env, timeout=timeout)
    except RemoteExecError:
        raise
    except Exception as exc:
        raise RemoteExecError(_redact(str(exc), secrets)) from None
    err_text = err.decode("utf-8", "replace") if isinstance(err, (bytes, bytearray)) else str(err)
    if not isinstance(out, (bytes, bytearray)):
        out = str(out).encode("utf-8")
    return int(code), bytes(out), _redact(err_text, secrets).encode("utf-8")


def _prepare_identity(jump: Dict[str, Any], runtime_dir: str) -> Tuple[Optional[str], Optional[str], Dict[str, str]]:
    """Return (identity_file, askpass_file, extra_env)."""
    auth = str(jump.get("auth_type") or "key")
    env: Dict[str, str] = {}
    if auth == "password":
        password = str(jump.get("password") or "")
        if not password:
            raise RemoteExecError("jump host password is empty")
        askpass = _write_private(runtime_dir, "askpass.sh", "#!/bin/sh\nprintf '%s\\n' \"$VCFR_SSH_PASS\"\n", 0o700)
        env["SSH_ASKPASS"] = askpass
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["VCFR_SSH_PASS"] = password
        env["DISPLAY"] = env.get("DISPLAY") or "vcfr:0"
        return None, askpass, env
    private_key = str(jump.get("private_key") or "")
    if private_key:
        if not private_key.endswith("\n"):
            private_key += "\n"
        return _write_private(runtime_dir, "id_jump", private_key, 0o600), None, env
    key_path = os.path.expanduser(str(jump.get("key_path") or ""))
    if not key_path:
        raise RemoteExecError("jump host has no SSH key")
    if not os.path.isfile(key_path):
        raise RemoteExecError("SSH key file does not exist")
    return key_path, None, env


def _merged_env(extra: Dict[str, str]) -> Optional[Dict[str, str]]:
    if not extra:
        return None
    env = dict(os.environ)
    env.update(extra)
    return env


def _ssh(jump: Dict[str, Any], control_path: str, identity: Optional[str], remote_command: str,
         stdin: Optional[bytes], ssh_run: SshRun, extra_env: Dict[str, str], timeout: Optional[int],
         secrets: Sequence[str]) -> Tuple[int, bytes, bytes]:
    argv = build_ssh_argv(
        jump, control_path, remote_command, identity,
        batch_mode="VCFR_SSH_PASS" not in extra_env,
    )
    return _run(ssh_run, argv, stdin, _merged_env(extra_env), timeout, secrets)


def _require_ok(code: int, err: Union[bytes, str], what: str,
                jump: Optional[Dict[str, Any]] = None,
                run_id: Optional[str] = None,
                remote_dir: Optional[str] = None) -> None:
    if code != 0:
        detail = err.decode("utf-8", "replace").strip() if isinstance(err, (bytes, bytearray)) else str(err).strip()
        host = str(jump.get("host") or "") if jump else ""
        if is_ssh_connection_lost(code, detail):
            msg = "Connection to jump host '%s' was lost (VPN or network link dropped)%s" % (
                host or "remote", (": " + detail) if detail else ""
            )
            raise JumpHostConnectionLostError(msg, host=host, detail=detail, run_id=run_id, remote_dir=remote_dir)
        raise RemoteExecError("%s failed (exit %s)%s" % (what, code, (": " + detail) if detail else ""))


def preflight_jump(
    jump: Dict[str, Any],
    ssh_run: Optional[SshRun] = None,
    timeout: int = 60,
    check_active_scans: bool = True,
) -> Dict[str, Any]:
    """SSH to the jump host and check Python 3.9+, writable /tmp, free space, and active scans."""
    runner = ssh_run or default_ssh_run
    runtime = tempfile.mkdtemp(prefix="vcfrssh")
    os.chmod(runtime, 0o700)
    secrets: List[str] = []
    try:
        identity, _askpass, extra_env = _prepare_identity(jump, runtime)
        if extra_env.get("VCFR_SSH_PASS"):
            secrets.append(extra_env["VCFR_SSH_PASS"])
        control = os.path.join(runtime, "cm")
        code, out, err = _ssh(
            jump, control, identity, "python3 -",
            preflight_python_source().encode("utf-8"),
            runner, extra_env, timeout, secrets,
        )
        _require_ok(code, err, "preflight", jump=jump)
        text = out.decode("utf-8", "replace").strip()
        free = 0
        py_ver = ""
        for line in text.splitlines():
            if line.startswith("PREFLIGHT_OK"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        free = int(parts[1])
                    except (TypeError, ValueError):
                        free = 0
                if len(parts) >= 3:
                    py_ver = parts[2]
        if "PREFLIGHT_OK" not in text:
            raise RemoteExecError("preflight did not report success")

        active_scans: List[Dict[str, Any]] = []
        if check_active_scans:
            try:
                s_code, s_out, _ = _ssh(
                    jump, control, identity, "python3 -",
                    probe_active_scans_python_source().encode("utf-8"),
                    runner, extra_env, min(timeout, 30), secrets,
                )
                if s_code == 0:
                    s_data = json.loads(s_out.decode("utf-8", "replace").strip())
                    if isinstance(s_data, dict) and isinstance(s_data.get("active_scans"), list):
                        active_scans = s_data["active_scans"]
            except Exception:
                pass

        return {
            "ok": True,
            "free_bytes": free,
            "python_version": py_ver,
            "host": jump.get("host"),
            "active_scans": active_scans,
        }
    finally:
        shutil.rmtree(runtime, ignore_errors=True)


def inspect_jump_scans(
    jump: Dict[str, Any],
    ssh_run: Optional[SshRun] = None,
    timeout: int = 30,
) -> List[Dict[str, Any]]:
    """SSH to jump host and return list of active scan dictionaries."""
    runner = ssh_run or default_ssh_run
    runtime = tempfile.mkdtemp(prefix="vcfrssh")
    os.chmod(runtime, 0o700)
    secrets: List[str] = []
    try:
        identity, _askpass, extra_env = _prepare_identity(jump, runtime)
        if extra_env.get("VCFR_SSH_PASS"):
            secrets.append(extra_env["VCFR_SSH_PASS"])
        control = os.path.join(runtime, "cm")
        code, out, err = _ssh(
            jump, control, identity, "python3 -",
            probe_active_scans_python_source().encode("utf-8"),
            runner, extra_env, timeout, secrets,
        )
        if code != 0:
            return []
        try:
            parsed = json.loads(out.decode("utf-8", "replace").strip())
            if isinstance(parsed, dict) and isinstance(parsed.get("active_scans"), list):
                return parsed["active_scans"]
        except Exception:
            pass
        return []
    finally:
        shutil.rmtree(runtime, ignore_errors=True)


def kill_remote_scan(
    jump: Dict[str, Any],
    remote_dir: str = "all",
    ssh_run: Optional[SshRun] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """SSH to jump host and terminate active scan process(es) safely via SIGTERM -> SIGKILL."""
    runner = ssh_run or default_ssh_run
    runtime = tempfile.mkdtemp(prefix="vcfrssh")
    os.chmod(runtime, 0o700)
    secrets: List[str] = []
    try:
        identity, _askpass, extra_env = _prepare_identity(jump, runtime)
        if extra_env.get("VCFR_SSH_PASS"):
            secrets.append(extra_env["VCFR_SSH_PASS"])
        control = os.path.join(runtime, "cm")
        try:
            safe_dir = _normalize_kill_remote_dir(remote_dir)
        except SecurityError as exc:
            return {"ok": False, "error": "refusing remote_dir: %s" % exc}
        cmd = _remote_python_stdin_cmd(safe_dir)
        code, out, err = _ssh(
            jump, control, identity, cmd,
            kill_scan_python_source().encode("utf-8"),
            runner, extra_env, timeout, secrets,
        )
        out_text = out.decode("utf-8", "replace").strip()
        if code != 0:
            err_text = _redact(err.decode("utf-8", "replace").strip(), secrets)
            return {"ok": False, "error": err_text or out_text or ("exit %s" % code)}
        if "KILL_OK" in out_text:
            return {"ok": True, "killed": [remote_dir], "message": out_text}
        try:
            parsed = json.loads(out_text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        return {"ok": True, "output": out_text}
    finally:
        shutil.rmtree(runtime, ignore_errors=True)


_KEY_TYPE_PREFERENCE = {
    "ssh-ed25519": 1,
    "ecdsa-sha2-nistp256": 2,
    "ecdsa-sha2-nistp384": 3,
    "ecdsa-sha2-nistp521": 4,
    "rsa-sha2-512": 5,
    "rsa-sha2-256": 6,
    "ssh-rsa": 7,
}


def probe_jump_host_key(
    host: str,
    port: int = 22,
    timeout: float = 5.0,
    keyscan_run: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """Inspect remote SSH host public keys and fingerprint without transmitting credentials.

    Uses ssh-keyscan to probe ed25519, ecdsa, and rsa public keys.
    Returns dict with keys: ok, host, port, key_type, public_key, fingerprint, all_keys, error.
    """
    clean_host = str(host or "").strip()
    if not clean_host:
        return {"ok": False, "error": "Host required", "host": clean_host, "port": port}
    if is_cloud_metadata_target(clean_host):
        return {
            "ok": False,
            "error": f"Target '{clean_host}' is a prohibited cloud metadata endpoint.",
            "category": "security",
            "host": clean_host,
            "port": port,
        }
    try:
        port_i = int(port or 22)
    except (ValueError, TypeError):
        port_i = 22

    timeout_s = max(1, int(timeout))
    cmd = ["ssh-keyscan", "-p", str(port_i), "-T", str(timeout_s), "-t", "ed25519,ecdsa,rsa", clean_host]
    try:
        if keyscan_run:
            proc_res = keyscan_run(cmd, timeout=timeout_s + 2)
            if isinstance(proc_res, tuple):
                code, out_b, err_b = proc_res
                out_text = out_b.decode("utf-8", "replace") if isinstance(out_b, bytes) else str(out_b or "")
                err_text = err_b.decode("utf-8", "replace") if isinstance(err_b, bytes) else str(err_b or "")
            else:
                out_text = proc_res.stdout.decode("utf-8", "replace") if getattr(proc_res, "stdout", None) else ""
                err_text = proc_res.stderr.decode("utf-8", "replace") if getattr(proc_res, "stderr", None) else ""
        else:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout_s + 2)
            out_text = proc.stdout.decode("utf-8", "replace") if proc.stdout else ""
            err_text = proc.stderr.decode("utf-8", "replace") if proc.stderr else ""
    except FileNotFoundError:
        return {
            "ok": False,
            "host": clean_host,
            "port": port_i,
            "error": "ssh-keyscan executable not found on this workstation",
            "category": "prerequisite",
            "troubleshooting": "Ensure OpenSSH client tools are installed and in PATH.",
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "host": clean_host,
            "port": port_i,
            "error": f"Connection timed out while probing host key on {clean_host}:{port_i}",
            "category": "timeout",
            "troubleshooting": f"Connection timed out to {clean_host}. Verify IP/hostname, firewall rules, and ensure VPN is active.",
        }
    except Exception as exc:
        return {
            "ok": False,
            "host": clean_host,
            "port": port_i,
            "error": f"Failed probing host key: {exc}",
            "category": "general",
            "troubleshooting": "Check jump host reachability.",
        }

    keys = []
    from vcf_hci.vault.jump_hosts import compute_ssh_fingerprint

    for line in out_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            ktype, kb64 = parts[1], parts[2]
            canonical_key = f"{ktype} {kb64}"
            _, fp = compute_ssh_fingerprint(canonical_key)
            if fp:
                keys.append({
                    "key_type": ktype,
                    "public_key": canonical_key,
                    "fingerprint": fp,
                    "raw_line": line,
                })

    if not keys:
        diag_err = err_text.strip() or f"No SSH host key returned by {clean_host}:{port_i}"
        from vcf_hci.web.jump_api import diagnose_jump_error

        diag = diagnose_jump_error(diag_err, clean_host)
        return {
            "ok": False,
            "host": clean_host,
            "port": port_i,
            "error": diag_err,
            "category": diag["category"],
            "troubleshooting": diag["troubleshooting"],
        }

    keys.sort(key=lambda k: _KEY_TYPE_PREFERENCE.get(k["key_type"], 99))
    best = keys[0]
    return {
        "ok": True,
        "host": clean_host,
        "port": port_i,
        "key_type": best["key_type"],
        "public_key": best["public_key"],
        "fingerprint": best["fingerprint"],
        "all_keys": keys,
    }


def _member_is_safe(dest_dir: str, name: str) -> None:
    if not name or name.startswith("/") or any(part == ".." for part in name.split("/")):
        raise RemoteExecError("archive member escapes the output directory")
    dest_real = os.path.realpath(dest_dir)
    target = os.path.realpath(os.path.join(dest_dir, name))
    if target != dest_real and not target.startswith(dest_real + os.sep):
        raise RemoteExecError("archive member escapes the output directory")


def _extract_tar_members_no_links(archive: tarfile.TarFile, dest_dir: str) -> None:
    """Extract members, skipping symlinks and hardlinks safely on all Python versions."""
    for member in archive.getmembers():
        if member.issym() or member.islnk():
            continue
        _member_is_safe(dest_dir, member.name)
        archive.extract(member, dest_dir)


def _extract_tar(blob: bytes, dest_dir: str) -> None:
    if not blob:
        raise RemoteExecError("artifact archive is empty")
    os.makedirs(dest_dir, exist_ok=True)
    tmp = os.path.join(dest_dir, ".vcfr_pull.tar")
    with open(tmp, "wb") as fh:
        fh.write(blob)
    try:
        try:
            archive = tarfile.open(tmp, "r:")
        except tarfile.TarError as exc:
            raise RemoteExecError("artifact archive is unreadable") from exc
        with archive:
            try:
                _extract_tar_members_no_links(archive, dest_dir)
            except tarfile.TarError as exc:
                raise RemoteExecError("artifact archive is unreadable") from exc
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    inner = os.path.join(dest_dir, "out")
    if os.path.isdir(inner):
        for name in os.listdir(inner):
            shutil.move(os.path.join(inner, name), os.path.join(dest_dir, name))
        os.rmdir(inner)

    # If the remote CLI wrapped outputs in a nested VCF-Scans/ container folder, unnest it
    _unnest_folder(dest_dir, "vcf-scans")

    # If dest_dir itself is named Scan_* and contains a single nested Scan_* folder, unnest it
    if os.path.basename(os.path.normpath(dest_dir)).startswith("Scan_"):
        scan_children = [
            e for e in os.listdir(dest_dir)
            if e.startswith("Scan_") and os.path.isdir(os.path.join(dest_dir, e))
        ]
        if len(scan_children) == 1:
            _unnest_folder(dest_dir, scan_children[0])


def _unnest_folder(dest_dir: str, folder_name: str) -> None:
    target = None
    for entry in os.listdir(dest_dir):
        if entry.lower() == folder_name.lower():
            full = os.path.join(dest_dir, entry)
            if os.path.isdir(full):
                target = full
                break
    if not target:
        return

    for name in os.listdir(target):
        src = os.path.join(target, name)
        dst = os.path.join(dest_dir, name)
        if os.path.exists(dst):
            if os.path.isdir(dst) and not os.listdir(dst):
                os.rmdir(dst)
                shutil.move(src, dst)
            elif os.path.isfile(dst):
                os.remove(dst)
                shutil.move(src, dst)
            elif os.path.isdir(dst) and os.path.isdir(src):
                for sub in os.listdir(src):
                    sub_src = os.path.join(src, sub)
                    sub_dst = os.path.join(dst, sub)
                    if os.path.exists(sub_dst):
                        if os.path.isdir(sub_dst):
                            shutil.rmtree(sub_dst, ignore_errors=True)
                        else:
                            os.remove(sub_dst)
                    shutil.move(sub_src, sub_dst)
                shutil.rmtree(src, ignore_errors=True)
        else:
            shutil.move(src, dst)
    shutil.rmtree(target, ignore_errors=True)


def _file_is_new_artifact(path: str, min_mtime: Optional[float] = None) -> bool:
    if not (os.path.isfile(path) and os.path.getsize(path) > 0):
        return False
    if min_mtime is not None:
        try:
            return os.path.getmtime(path) >= min_mtime
        except OSError:
            return False
    return True


def _artifacts_ok(
    dest_dir: str,
    min_mtime: Optional[float] = None,
    existing_subdirs: Optional[Set[str]] = None,
) -> bool:
    candidates = [
        os.path.join(dest_dir, "data", "fleet_summary.json"),
        os.path.join(dest_dir, "data", "fleet_summary.json.gz"),
        os.path.join(dest_dir, "fleet_summary.json"),
        os.path.join(dest_dir, "00_fleet_summary.html"),
        os.path.join(dest_dir, "00_fleet_combined.html"),
    ]
    if any(_file_is_new_artifact(path, min_mtime) for path in candidates):
        return True

    # Check inside child subdirectories (e.g. Scan_*, from-*, etc.)
    try:
        for entry in os.listdir(dest_dir):
            child = os.path.join(dest_dir, entry)
            if not os.path.isdir(child) or entry.startswith("."):
                continue
            is_new_dir = existing_subdirs is not None and entry not in existing_subdirs
            sub_mtime = None if is_new_dir else min_mtime
            sub_candidates = [
                os.path.join(child, "data", "fleet_summary.json"),
                os.path.join(child, "data", "fleet_summary.json.gz"),
                os.path.join(child, "fleet_summary.json"),
                os.path.join(child, "00_fleet_summary.html"),
                os.path.join(child, "00_fleet_combined.html"),
            ]
            if any(_file_is_new_artifact(path, sub_mtime) for path in sub_candidates):
                return True
            for sub_entry in os.listdir(child):
                grandchild = os.path.join(child, sub_entry)
                if not os.path.isdir(grandchild) or sub_entry.startswith("."):
                    continue
                grandchild_candidates = [
                    os.path.join(grandchild, "data", "fleet_summary.json"),
                    os.path.join(grandchild, "data", "fleet_summary.json.gz"),
                    os.path.join(grandchild, "fleet_summary.json"),
                    os.path.join(grandchild, "00_fleet_summary.html"),
                    os.path.join(grandchild, "00_fleet_combined.html"),
                ]
                if any(_file_is_new_artifact(path, sub_mtime) for path in grandchild_candidates):
                    return True
    except OSError:
        pass

    return False


def _emit_ndjson(blob: Union[bytes, str], callback: Optional[Callable[[Dict[str, Any]], None]]) -> None:
    if callback is None:
        return
    text = blob.decode("utf-8", "replace") if isinstance(blob, (bytes, bytearray)) else str(blob or "")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    callback(event)
                    continue
            except json.JSONDecodeError:
                pass
        callback({"event": "log", "channel": "log", "msg": line})


def _build_rsync_ssh_cmd(
    jump: Dict[str, Any],
    control_path: str,
    identity: Optional[str],
    extra_env: Dict[str, str],
) -> str:
    argv = build_ssh_argv(
        jump, control_path, "", identity_file=identity,
        batch_mode="VCFR_SSH_PASS" not in extra_env,
    )
    # Exclude remote host (second to last) and empty command (last)
    ssh_flags = argv[:-2]
    return " ".join(shlex.quote(arg) for arg in ssh_flags)


def _rsync_pull(
    jump: Dict[str, Any],
    control_path: str,
    identity: Optional[str],
    remote_dir: str,
    local_outdir: str,
    extra_env: Dict[str, str],
    timeout: Optional[int],
    secrets: Sequence[str],
) -> Tuple[bool, str]:
    host = str(jump.get("host") or "")
    user = str(jump.get("username") or "")
    ssh_cmd = _build_rsync_ssh_cmd(jump, control_path, identity, extra_env)
    remote_src = f"{user}@{host}:{remote_dir}/out/"

    cmd = [
        "rsync",
        "-avz",
        "--partial",
        "-e", ssh_cmd,
        remote_src,
        f"{local_outdir}/",
    ]
    env = _merged_env(extra_env)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout or 600,
            env=env,
        )
        if proc.returncode == 0:
            _unnest_folder(local_outdir, "out")
            _unnest_folder(local_outdir, "vcf-scans")
            return True, ""
        err_msg = proc.stderr.decode("utf-8", "replace") if proc.stderr else ""
        return False, _redact(err_msg, secrets)
    except Exception as exc:
        return False, str(exc)


def _pull_artifacts(
    jump: Dict[str, Any],
    control_path: str,
    identity: Optional[str],
    remote_dir: str,
    local_outdir: str,
    runner: SshRun,
    extra_env: Dict[str, str],
    timeout: Optional[int],
    secrets: Sequence[str],
    min_mtime: Optional[float] = None,
    existing_subdirs: Optional[Set[str]] = None,
) -> Tuple[bool, str]:
    """Pull artifacts using rsync when available, falling back to safe tar stream."""
    os.makedirs(local_outdir, exist_ok=True)
    if runner is default_ssh_run and shutil.which("rsync"):
        try:
            rsync_ok, rsync_err = _rsync_pull(
                jump, control_path, identity, remote_dir, local_outdir, extra_env, timeout, secrets
            )
            if rsync_ok and _artifacts_ok(local_outdir, min_mtime=min_mtime, existing_subdirs=existing_subdirs):
                return True, ""
        except Exception:
            pass

    # Fallback to tar stream
    code, out, err = _ssh(
        jump, control_path, identity, "tar -C %s -cf - out" % shlex.quote(remote_dir),
        None, runner, extra_env, timeout, secrets,
    )
    if code != 0:
        err_msg = err.decode("utf-8", "replace") if isinstance(err, (bytes, bytearray)) else str(err)
        return False, err_msg or "tar artifact pull failed"
    _extract_tar(out, local_outdir)
    return True, ""


def _save_remote_execution_log(
    local_outdir: str,
    scan_out: Union[bytes, str],
    scan_err: Union[bytes, str],
    secrets: Sequence[str],
) -> str:
    """Save raw remote stdout and stderr to outdir/remote_execution.log for diagnostic transparency."""
    try:
        os.makedirs(local_outdir, exist_ok=True)
        log_path = os.path.join(local_outdir, "remote_execution.log")
        out_str = scan_out.decode("utf-8", "replace") if isinstance(scan_out, (bytes, bytearray)) else str(scan_out or "")
        err_str = scan_err.decode("utf-8", "replace") if isinstance(scan_err, (bytes, bytearray)) else str(scan_err or "")
        out_clean = _redact(out_str, secrets)
        err_clean = _redact(err_str, secrets)
        with open(log_path, "w", encoding="utf-8") as fh:
            fh.write("=== REMOTE SCAN EXECUTION LOG ===\n")
            fh.write("--- STDOUT ---\n")
            fh.write(out_clean)
            if not out_clean.endswith("\n"):
                fh.write("\n")
            fh.write("--- STDERR ---\n")
            fh.write(err_clean)
            if not err_clean.endswith("\n"):
                fh.write("\n")
        return log_path
    except Exception:
        return ""


def run_remote_scan(
    jump: Dict[str, Any],
    pyz_bytes: bytes,
    targets: Sequence[str],
    creds: Any,
    local_outdir: str,
    threads: int = 8,
    profile: str = "readiness-full",
    force: bool = False,
    ssh_run: Optional[SshRun] = None,
    on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
    run_id: Optional[str] = None,
    timeout: int = 7200,
    auto_reconnect: bool = True,
    max_reconnect_attempts: int = 24,
    reconnect_interval: float = 5.0,
    host_timeout: int = 300,
    debug: bool = False,
    cancel_event: Optional[Any] = None,
    on_sandbox: Optional[Callable[[Dict[str, Any]], None]] = None,
    sandbox_retain: int = 0,
) -> Dict[str, Any]:
    """Upload a zipapp, scan, pull artifacts, then delete the remote sandbox.

    Remote deletion is skipped when the pulled artifacts do not contain a
    non-empty fleet summary.
    """
    if not pyz_bytes:
        raise RemoteExecError("collector zipapp is empty")
    if not targets:
        raise RemoteExecError("no targets")
    remote_dir = sandbox_path_for_run(run_id or os.urandom(6).hex())
    try:
        retain_n = int(sandbox_retain)
    except (TypeError, ValueError):
        retain_n = 0
    if retain_n < 0:
        retain_n = 0
    if retain_n > 32:
        retain_n = 32
    runner = ssh_run or default_ssh_run
    runtime = tempfile.mkdtemp(prefix="vcfrssh")
    os.chmod(runtime, 0o700)
    secrets: List[str] = []
    cleaned = False
    scan_start_time = time.time()
    prior_subdirs = set(os.listdir(local_outdir)) if os.path.isdir(local_outdir) else set()
    try:
        identity, _askpass, extra_env = _prepare_identity(jump, runtime)
        if extra_env.get("VCFR_SSH_PASS"):
            secrets.append(extra_env["VCFR_SSH_PASS"])
        # Redact BMC passwords if a remote error echoes stdin (it should not).
        try:
            cred_doc = dump_creds_document(creds, list(targets))
        except ValueError as exc:
            raise RemoteExecError(str(exc)) from None
        try:
            parsed = json.loads(cred_doc.decode("utf-8"))
            for pair in parsed.get("creds", {}).values():
                if isinstance(pair, list) and len(pair) == 2:
                    secrets.append(str(pair[1]))
        except json.JSONDecodeError:
            raise RemoteExecError("could not encode credentials") from None

        control = os.path.join(runtime, "cm")
        code, out, err = _ssh(
            jump, control, identity, "python3 -",
            preflight_python_source().encode("utf-8"),
            runner, extra_env, 60, secrets,
        )
        _require_ok(code, err, "preflight", jump=jump, run_id=run_id, remote_dir=remote_dir)

        maint_cmd = "python3 - 1" if force else "python3 -"
        code, out, err = _ssh(
            jump, control, identity, maint_cmd,
            maintenance_python_source().encode("utf-8"),
            runner, extra_env, 60, secrets,
        )
        if code == 10:
            raise ActiveScanError("a collector is already running on this jump host; pass force to replace stale locks only after you confirm")
        _require_ok(code, err, "stale-run check", jump=jump, run_id=run_id, remote_dir=remote_dir)

        user = str(jump.get("username") or "")
        run_token = os.path.basename(remote_dir)[len("vcfr_remote_"):]
        marker = marker_document(run_token, int(time.time()), user)
        marker_json = json.dumps(marker, separators=(",", ":"))
        create_src = (
            "import json, os, sys\n"
            "path = sys.argv[1]\n"
            "os.makedirs(path, 0o700)\n"
            "os.chmod(path, 0o700)\n"
            "marker = os.path.join(path, '.vcfr_marker')\n"
            "with open(marker, 'w', encoding='utf-8') as fh:\n"
            "    fh.write(%r)\n"
            "os.chmod(marker, 0o600)\n"
            "sys.stdout.write('CREATE_OK\\n')\n"
            % marker_json
        )
        code, out, err = _ssh(
            jump, control, identity, _remote_python_stdin_cmd(remote_dir),
            create_src.encode("utf-8"),
            runner, extra_env, 60, secrets,
        )
        _require_ok(code, err, "create sandbox", jump=jump, run_id=run_id, remote_dir=remote_dir)

        upload = (
            "python3 -c \"import sys; open(sys.argv[1], 'wb').write(sys.stdin.buffer.read()); "
            "os_chmod = __import__('os').chmod; os_chmod(sys.argv[1], 0o700)\" %s"
            % shlex.quote(remote_dir + "/worker.pyz")
        )
        code, out, err = _ssh(jump, control, identity, upload, pyz_bytes, runner, extra_env, 120, secrets)
        _require_ok(code, err, "upload collector", jump=jump, run_id=run_id, remote_dir=remote_dir)

        shell = build_remote_scan_shell(
            remote_dir, list(targets), threads, profile, host_timeout=host_timeout, debug=debug
        )
        if on_sandbox:
            try:
                on_sandbox({
                    "jump_host": jump.get("id"),
                    "host": jump.get("host"),
                    "remote_dir": remote_dir,
                    "run_id": run_id or run_token,
                })
            except Exception:
                pass
        try:
            scan_code, scan_out, scan_err = _ssh_scan(
                jump, control, identity, shell, cred_doc, runner, extra_env, timeout, secrets, on_progress,
                remote_dir=remote_dir, run_id=run_id, auto_reconnect=auto_reconnect,
                max_reconnect_attempts=max_reconnect_attempts, reconnect_interval=reconnect_interval,
                cancel_event=cancel_event,
            )
        except (KeyboardInterrupt, Exception) as scan_exc:
            if isinstance(scan_exc, KeyboardInterrupt) or (cancel_event and cancel_event.is_set()):
                try:
                    _ssh(
                        jump, control, identity, _remote_python_stdin_cmd(remote_dir),
                        kill_scan_python_source().encode("utf-8"),
                        runner, extra_env, 15, secrets,
                    )
                except Exception:
                    pass
            raise

        if cancel_event and cancel_event.is_set():
            try:
                _ssh(
                    jump, control, identity, _remote_python_stdin_cmd(remote_dir),
                    kill_scan_python_source().encode("utf-8"),
                    runner, extra_env, 15, secrets,
                )
            except Exception:
                pass
            raise RemoteExecError("scan cancelled by operator")

        # Unconditionally preserve raw remote execution log
        _save_remote_execution_log(local_outdir, scan_out, scan_err, secrets)

        # Unconditionally pull artifacts before checking exit code
        pull_ok, pull_err = _pull_artifacts(
            jump, control, identity, remote_dir, local_outdir, runner, extra_env, timeout, secrets,
            min_mtime=scan_start_time - 120.0, existing_subdirs=prior_subdirs,
        )
        has_artifacts = _artifacts_ok(local_outdir, min_mtime=scan_start_time - 120.0, existing_subdirs=prior_subdirs)

        # Also copy remote_execution.log into any child Scan_* directory that was pulled
        try:
            for entry in os.listdir(local_outdir):
                child = os.path.join(local_outdir, entry)
                if os.path.isdir(child) and entry.startswith("Scan_"):
                    child_log = os.path.join(child, "remote_execution.log")
                    root_log = os.path.join(local_outdir, "remote_execution.log")
                    if os.path.isfile(root_log) and not os.path.isfile(child_log):
                        shutil.copy2(root_log, child_log)
        except OSError:
            pass

        err_text = scan_err.decode("utf-8", "replace") if isinstance(scan_err, (bytes, bytearray)) else str(scan_err)
        if scan_code != 0 and is_ssh_connection_lost(scan_code, err_text) and not has_artifacts:
            msg = "Connection to jump host '%s' was lost (VPN or network link dropped)%s" % (
                str(jump.get("host") or "remote"), (": " + err_text.strip()) if err_text else ""
            )
            raise JumpHostConnectionLostError(
                msg, host=str(jump.get("host") or ""), detail=err_text, run_id=run_id, remote_dir=remote_dir
            )

        if not has_artifacts:
            if scan_code != 0:
                _require_ok(scan_code, scan_err, "remote scan", jump=jump, run_id=run_id, remote_dir=remote_dir)
            if not pull_ok and pull_err:
                raise RemoteExecError("artifact pull failed: %s" % pull_err)
            raise RemoteExecError(
                "transfer did not include a fleet summary; remote artifacts preserved at %s@%s:%s"
                % (jump.get("username"), jump.get("host"), remote_dir)
            )

        # Artifacts exist! Apply retention cleanup if scan completed cleanly
        cleaned = False
        if scan_code == 0:
            code, out, err = _ssh(
                jump, control, identity, _remote_python_stdin_cmd(remote_dir, str(retain_n)),
                cleanup_python_source().encode("utf-8"),
                runner, extra_env, 60, secrets,
            )
            _require_ok(code, err, "remote cleanup", jump=jump, run_id=run_id, remote_dir=remote_dir)
            if b"CLEANUP_OK" not in out:
                raise RemoteExecError("remote cleanup did not confirm deletion")
            cleaned = True
        else:
            # Leave remote sandbox intact for operator inspection on non-zero exit
            cleaned = False

        return {
            "ok": scan_code == 0,
            "scan_exit": scan_code,
            "remote_dir": remote_dir,
            "local_outdir": local_outdir,
            "cleaned": cleaned,
            "host": jump.get("host"),
            "marker": MARKER_TOKEN,
        }
    finally:
        shutil.rmtree(runtime, ignore_errors=True)


def _ssh_scan(
    jump: Dict[str, Any],
    control_path: str,
    identity: Optional[str],
    remote_command: str,
    stdin: Optional[bytes],
    ssh_run: SshRun,
    extra_env: Dict[str, str],
    timeout: Optional[int],
    secrets: Sequence[str],
    on_progress: Optional[Callable[[Dict[str, Any]], None]],
    remote_dir: Optional[str] = None,
    run_id: Optional[str] = None,
    auto_reconnect: bool = True,
    max_reconnect_attempts: int = 24,
    reconnect_interval: float = 5.0,
    cancel_event: Optional[Any] = None,
) -> Tuple[int, bytes, bytes]:
    """Stream NDJSON when using the real ssh client. Injected runners stay buffered.

    If the SSH connection terminates unexpectedly with a network/VPN failure,
    enters an auto-reconnect retry loop to resume streaming from the jump host sandbox.
    """
    if ssh_run is not default_ssh_run:
        code, out, err = _ssh(
            jump, control_path, identity, remote_command, stdin, ssh_run, extra_env, timeout, secrets,
        )
        _emit_ndjson(out, on_progress)
        err_text = err.decode("utf-8", "replace") if isinstance(err, (bytes, bytearray)) else str(err)
        if code != 0 and err_text and on_progress:
            for err_line in _redact(err_text, secrets).splitlines():
                err_line = err_line.strip()
                if err_line:
                    on_progress({"event": "log", "channel": "log", "msg": f"[stderr] {err_line}"})
        if code != 0 and is_ssh_connection_lost(code, err_text) and auto_reconnect and remote_dir:
            host_label = str(jump.get("host") or "remote")
            attempt = 1
            while attempt <= max_reconnect_attempts:
                if on_progress:
                    on_progress({
                        "event": "log",
                        "channel": "log",
                        "msg": f"[🔄] Lost SSH connection to jump host '{host_label}'. Attempting to reconnect (attempt {attempt}/{max_reconnect_attempts} — is VPN active?)...",
                    })
                time.sleep(reconnect_interval)
                resume_shell = build_remote_resume_shell(remote_dir, offset=len(out))
                try:
                    res_code, res_out, res_err = _ssh_scan(
                        jump, control_path, identity, resume_shell, None,
                        ssh_run, extra_env, timeout, secrets, on_progress,
                        remote_dir=remote_dir, run_id=run_id, auto_reconnect=False,
                    )
                    res_err_text = res_err.decode("utf-8", "replace") if isinstance(res_err, (bytes, bytearray)) else str(res_err)
                    if not is_ssh_connection_lost(res_code, res_err_text):
                        if on_progress:
                            on_progress({
                                "event": "log",
                                "channel": "log",
                                "msg": f"[✓] Reconnected to jump host '{host_label}'. Resumed assessment session.",
                            })
                        return int(res_code), out + res_out, res_err
                except Exception:
                    pass
                attempt += 1
        return code, out, err

    argv = build_ssh_argv(
        jump, control_path, remote_command, identity,
        batch_mode="VCFR_SSH_PASS" not in extra_env,
    )
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_merged_env(extra_env),
        )
    except FileNotFoundError:
        raise RemoteExecError("ssh client not found on this workstation") from None
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    if stdin:
        proc.stdin.write(stdin)
    proc.stdin.close()
    chunks: List[bytes] = []
    bytes_streamed = 0
    while True:
        if cancel_event is not None and cancel_event.is_set():
            try:
                proc.terminate()
            except OSError:
                pass
            break
        try:
            rlist, _, _ = select.select([proc.stdout], [], [], 0.5)
        except (ValueError, OSError):
            break
        if not rlist:
            if proc.poll() is not None:
                break
            continue
        line = proc.stdout.readline()
        if not line:
            break
        bytes_streamed += len(line)
        chunks.append(line)
        _emit_ndjson(line, on_progress)
    err = proc.stderr.read() or b""
    code = proc.wait(timeout=timeout)
    err_text = _redact(err.decode("utf-8", "replace"), secrets)
    if code != 0 and err_text and on_progress:
        for err_line in err_text.splitlines():
            err_line = err_line.strip()
            if err_line:
                on_progress({"event": "log", "channel": "log", "msg": f"[stderr] {err_line}"})

    if code != 0 and is_ssh_connection_lost(int(code), err_text) and auto_reconnect and remote_dir:
        host_label = str(jump.get("host") or "remote")
        attempt = 1
        while attempt <= max_reconnect_attempts:
            if on_progress:
                on_progress({
                    "event": "log",
                    "channel": "log",
                    "msg": f"[🔄] Lost SSH connection to jump host '{host_label}'. Attempting to reconnect (attempt {attempt}/{max_reconnect_attempts} — is VPN active?)...",
                })
            time.sleep(reconnect_interval)
            resume_shell = build_remote_resume_shell(remote_dir, offset=bytes_streamed)
            try:
                res_code, res_out, res_err = _ssh_scan(
                    jump, control_path, identity, resume_shell, None,
                    ssh_run, extra_env, timeout, secrets, on_progress,
                    remote_dir=remote_dir, run_id=run_id, auto_reconnect=False,
                )
                res_err_text = res_err.decode("utf-8", "replace") if isinstance(res_err, (bytes, bytearray)) else str(res_err)
                if not is_ssh_connection_lost(res_code, res_err_text):
                    if on_progress:
                        on_progress({
                            "event": "log",
                            "channel": "log",
                            "msg": f"[✓] Reconnected to jump host '{host_label}'. Resumed assessment session.",
                        })
                    chunks.append(res_out)
                    return int(res_code), b"".join(chunks), res_err
            except Exception:
                pass
            attempt += 1

    return int(code), b"".join(chunks), err_text.encode("utf-8")


def resume_remote_scan(
    jump: Dict[str, Any],
    remote_dir: str,
    local_outdir: str,
    run_id: Optional[str] = None,
    ssh_run: Optional[SshRun] = None,
    on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
    offset: int = 0,
    timeout: int = 7200,
) -> Dict[str, Any]:
    """Resume an existing in-progress or completed scan on the jump host and pull artifacts."""
    remote_dir = assert_sandbox_path(remote_dir)
    runner = ssh_run or default_ssh_run
    runtime = tempfile.mkdtemp(prefix="vcfrssh")
    os.chmod(runtime, 0o700)
    secrets: List[str] = []
    cleaned = False
    resume_start_time = time.time()
    prior_subdirs = set(os.listdir(local_outdir)) if os.path.isdir(local_outdir) else set()
    try:
        identity, _askpass, extra_env = _prepare_identity(jump, runtime)
        if extra_env.get("VCFR_SSH_PASS"):
            secrets.append(extra_env["VCFR_SSH_PASS"])
        control = os.path.join(runtime, "cm")

        resume_shell = build_remote_resume_shell(remote_dir, offset=offset)
        scan_code, scan_out, scan_err = _ssh_scan(
            jump, control, identity, resume_shell, None,
            runner, extra_env, timeout, secrets, on_progress,
            remote_dir=remote_dir, run_id=run_id, auto_reconnect=False,
        )

        _save_remote_execution_log(local_outdir, scan_out, scan_err, secrets)

        pull_ok, pull_err = _pull_artifacts(
            jump, control, identity, remote_dir, local_outdir, runner, extra_env, timeout, secrets,
            min_mtime=resume_start_time - 120.0, existing_subdirs=prior_subdirs,
        )
        has_artifacts = _artifacts_ok(local_outdir, min_mtime=resume_start_time - 120.0, existing_subdirs=prior_subdirs)

        try:
            for entry in os.listdir(local_outdir):
                child = os.path.join(local_outdir, entry)
                if os.path.isdir(child) and entry.startswith("Scan_"):
                    child_log = os.path.join(child, "remote_execution.log")
                    root_log = os.path.join(local_outdir, "remote_execution.log")
                    if os.path.isfile(root_log) and not os.path.isfile(child_log):
                        shutil.copy2(root_log, child_log)
        except OSError:
            pass

        if not has_artifacts:
            if scan_code != 0:
                _require_ok(scan_code, scan_err, "resume remote scan", jump=jump, run_id=run_id, remote_dir=remote_dir)
            if not pull_ok and pull_err:
                raise RemoteExecError("artifact pull failed: %s" % pull_err)
            raise RemoteExecError(
                "transfer did not include a fleet summary; remote artifacts preserved at %s@%s:%s"
                % (jump.get("username"), jump.get("host"), remote_dir)
            )

        cleaned = False
        if scan_code == 0:
            code, out, err = _ssh(
                jump, control, identity, _remote_python_stdin_cmd(remote_dir, "0"),
                cleanup_python_source().encode("utf-8"),
                runner, extra_env, 60, secrets,
            )
            _require_ok(code, err, "remote cleanup", jump=jump, run_id=run_id, remote_dir=remote_dir)
            if b"CLEANUP_OK" not in out:
                raise RemoteExecError("remote cleanup did not confirm deletion")
            cleaned = True
        else:
            cleaned = False

        return {
            "ok": scan_code == 0,
            "scan_exit": scan_code,
            "remote_dir": remote_dir,
            "local_outdir": local_outdir,
            "cleaned": cleaned,
            "host": jump.get("host"),
            "marker": MARKER_TOKEN,
        }
    finally:
        shutil.rmtree(runtime, ignore_errors=True)
