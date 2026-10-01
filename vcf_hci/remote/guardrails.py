"""
Path and marker checks for ephemeral remote scan directories.

Cleanup refuses every path that is not exactly
``/tmp/vcfr_remote_<8-16 hex>`` or the macOS realpath form
``/private/tmp/vcfr_remote_<8-16 hex>``, and it refuses to delete unless
``.vcfr_marker`` inside that directory carries the expected token.
"""

import re
from typing import Any, Dict, Optional

SANDBOX_RE = re.compile(r"^(/private)?/tmp/vcfr_remote_[a-f0-9]{8,16}$")
RUN_ID_RE = re.compile(r"^[a-f0-9]{8,16}$")
MARKER_FILENAME = ".vcfr_marker"
LOCK_FILENAME = ".vcfr_lock"
MARKER_TOKEN = "vcf-readiness-ephemeral-sandbox"
FORBIDDEN = frozenset([
    "",
    "/",
    "/tmp",
    "/tmp/",
    "/private",
    "/private/tmp",
    "/private/tmp/",
    "/var",
    "/home",
    "/root",
    "/etc",
    "/usr",
    "/opt",
])
MIN_FREE_BYTES = 500 * 1024 * 1024

__all__ = [
    "FORBIDDEN",
    "MARKER_FILENAME",
    "MARKER_TOKEN",
    "MIN_FREE_BYTES",
    "SANDBOX_RE",
    "SecurityError",
    "assert_sandbox_path",
    "cleanup_python_source",
    "kill_scan_python_source",
    "maintenance_python_source",
    "marker_document",
    "preflight_python_source",
    "probe_active_scans_python_source",
    "sandbox_path_for_run",
    "tailer_python_source",
    "validate_marker",
]


class SecurityError(Exception):
    """Raised when a path or marker is not safe to delete or create."""


def _collapse(path: str) -> str:
    return re.sub(r"/+", "/", path)


def assert_sandbox_path(path: str) -> str:
    """Return the normalized sandbox path or raise SecurityError.

    Does not call realpath(). The remote cleanup script realpath's the
    candidate so a symlink cannot escape /tmp.
    """
    if not isinstance(path, str):
        raise SecurityError("path must be a string")
    raw = path.strip()
    if raw != path:
        raise SecurityError("path has surrounding whitespace")
    if not raw or "\x00" in raw:
        raise SecurityError("empty path")
    if not raw.startswith("/"):
        raise SecurityError("relative path refused")
    if any(part == ".." for part in raw.split("/")):
        raise SecurityError("parent segment refused")
    raw = _collapse(raw)
    if raw in FORBIDDEN or raw.rstrip("/") in FORBIDDEN:
        raise SecurityError("forbidden path")
    if not SANDBOX_RE.match(raw):
        raise SecurityError("path is outside the remote sandbox: %s" % raw)
    return raw


def sandbox_path_for_run(run_id: str) -> str:
    if not isinstance(run_id, str) or not RUN_ID_RE.match(run_id):
        raise SecurityError("run id must be 8-16 lowercase hex characters")
    return assert_sandbox_path("/tmp/vcfr_remote_%s" % run_id)


def marker_document(run_id: str, created_at: int, user: str) -> Dict[str, Any]:
    sandbox_path_for_run(run_id)
    return {
        "marker": MARKER_TOKEN,
        "run_id": run_id,
        "created_at": int(created_at),
        "user": str(user or ""),
    }


def validate_marker(data: Any, expected_run_id: Optional[str] = None) -> None:
    if not isinstance(data, dict):
        raise SecurityError("marker is not an object")
    if data.get("marker") != MARKER_TOKEN:
        raise SecurityError("marker token mismatch")
    run_id = data.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.match(run_id):
        raise SecurityError("marker run id invalid")
    if expected_run_id is not None and run_id != expected_run_id:
        raise SecurityError("marker run id does not match")


def cleanup_python_source() -> str:
    """Python source run on the jump host. Path arrives as argv[1], retain_count as optional argv[2]."""
    return r"""
import json, os, re, shutil, sys
path = os.path.realpath(sys.argv[1])
retain = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 0
if not re.match(r"^(/private)?/tmp/vcfr_remote_[a-f0-9]{8,16}$", path):
    sys.stderr.write("refusing path\n")
    sys.exit(1)
marker_path = os.path.join(path, ".vcfr_marker")
if not os.path.isfile(marker_path):
    sys.stderr.write("missing marker\n")
    sys.exit(2)
try:
    with open(marker_path, encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    sys.stderr.write("bad marker\n")
    sys.exit(3)
if not isinstance(data, dict) or data.get("marker") != "vcf-readiness-ephemeral-sandbox":
    sys.stderr.write("marker mismatch\n")
    sys.exit(3)
run_id = str(data.get("run_id") or "")
if run_id not in os.path.basename(path):
    sys.stderr.write("run id mismatch\n")
    sys.exit(3)

if retain > 0:
    root = "/tmp"
    name_re = re.compile(r"^vcfr_remote_[a-f0-9]{8,16}$")
    sandboxes = []
    try:
        entries = list(os.scandir(root))
    except OSError:
        entries = []
    for entry in entries:
        name = entry.name
        if not name_re.match(name):
            continue
        raw = os.path.join(root, name)
        rp = os.path.realpath(raw)
        mp = os.path.join(rp, ".vcfr_marker")
        if os.path.isfile(mp):
            try:
                mtime = os.path.getmtime(rp)
                sandboxes.append((mtime, rp))
            except OSError:
                pass
    sandboxes.sort(key=lambda item: item[0], reverse=True)
    # Retain the newest `retain` sandboxes across /tmp, prune older ones
    for _, sp in sandboxes[retain:]:
        try:
            shutil.rmtree(sp)
        except OSError:
            pass
    sys.stdout.write("CLEANUP_OK\n")
    sys.exit(0)

shutil.rmtree(path)
sys.stdout.write("CLEANUP_OK\n")
""".strip() + "\n"


def tailer_python_source() -> str:
    """Python source for streaming .vcfr_progress.ndjson and monitoring collector process."""
    return r"""
import sys, time, os, json
log_f, lock_f, exit_f = '.vcfr_progress.ndjson', '.vcfr_lock', '.vcfr_exit'
pos = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 0
wpid = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else None
if not wpid and os.path.isfile(lock_f):
    try:
        with open(lock_f, 'r', encoding='utf-8') as f:
            wpid = int(json.load(f).get('pid'))
    except Exception:
        pass

while True:
    if os.path.isfile(log_f):
        try:
            with open(log_f, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(pos)
                chunk = f.read()
                if chunk:
                    sys.stdout.write(chunk)
                    sys.stdout.flush()
                    pos = f.tell()
        except (BrokenPipeError, IOError):
            sys.exit(255)
        except Exception:
            pass
    if os.path.isfile(exit_f):
        if os.path.isfile(log_f):
            try:
                with open(log_f, 'r', encoding='utf-8', errors='replace') as f:
                    f.seek(pos)
                    chunk = f.read()
                    if chunk:
                        sys.stdout.write(chunk)
                        sys.stdout.flush()
            except Exception:
                pass
        try:
            with open(exit_f, 'r', encoding='utf-8') as ef:
                sys.exit(int(ef.read().strip() or 0))
        except Exception:
            sys.exit(0)
    alive = False
    if wpid:
        try:
            os.kill(wpid, 0)
            alive = True
        except OSError:
            alive = False
    if not alive and not os.path.isfile(exit_f):
        time.sleep(0.5)
        if os.path.isfile(exit_f):
            continue
        sys.exit(1)
    time.sleep(0.15)
""".strip() + "\n"


def preflight_python_source() -> str:
    """Remote preflight: Python >= 3.9, /tmp writable, >= 500 MiB free."""
    return r"""
import os, sys
version = sys.version_info
if version < (3, 9):
    sys.stderr.write("python %s.%s is older than 3.9\n" % (version[0], version[1]))
    sys.exit(2)
if not os.access("/tmp", os.W_OK):
    sys.stderr.write("/tmp is not writable\n")
    sys.exit(3)
stats = os.statvfs("/tmp")
free = int(stats.f_bavail) * int(stats.f_frsize)
if free < 500 * 1024 * 1024:
    sys.stderr.write("less than 500 MiB free on /tmp\n")
    sys.exit(4)
sys.stdout.write("PREFLIGHT_OK %d %s\n" % (free, sys.version.split()[0]))
""".strip() + "\n"


def maintenance_python_source() -> str:
    """List sandbox dirs under /tmp, drop stale ones, refuse when a live scan holds the lock.

    Exit 10 when an active vcf scan is found and VCFR_FORCE is not ``1``.
    """
    return r"""
import json, os, re, shutil, sys, time
root = "/tmp"
force = os.environ.get("VCFR_FORCE") == "1" or (len(sys.argv) > 1 and sys.argv[1] == "1")
name_re = re.compile(r"^vcfr_remote_[a-f0-9]{8,16}$")
path_re = re.compile(r"^(/private)?/tmp/vcfr_remote_[a-f0-9]{8,16}$")
active = []
removed = []
try:
    names = os.listdir(root)
except OSError as exc:
    sys.stderr.write("cannot list /tmp: %s\n" % exc)
    sys.exit(1)
now = time.time()
for name in names:
    if not name_re.match(name):
        continue
    raw = os.path.join(root, name)
    path = os.path.realpath(raw)
    if not path_re.match(path):
        continue
    marker_path = os.path.join(path, ".vcfr_marker")
    if not os.path.isfile(marker_path):
        continue
    try:
        with open(marker_path, encoding="utf-8") as fh:
            marker = json.load(fh)
    except Exception:
        continue
    if not isinstance(marker, dict) or marker.get("marker") != "vcf-readiness-ephemeral-sandbox":
        continue
    if str(marker.get("run_id") or "") not in os.path.basename(path):
        continue
    lock_path = os.path.join(path, ".vcfr_lock")
    alive = False
    if os.path.isfile(lock_path):
        try:
            with open(lock_path, encoding="utf-8") as fh:
                lock = json.load(fh)
            pid = int(lock.get("pid"))
        except Exception:
            pid = None
        if pid:
            try:
                os.kill(pid, 0)
                alive = True
            except OSError:
                alive = False
            if alive:
                cmdline_path = "/proc/%d/cmdline" % pid
                if os.path.exists(cmdline_path):
                    try:
                        with open(cmdline_path, "rb") as fh:
                            cmdline = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace")
                    except OSError:
                        cmdline = ""
                    if "vcf" not in cmdline and "worker.pyz" not in cmdline and "python" not in cmdline:
                        alive = False
    if alive and not force:
        active.append(path)
        continue
    stale = True
    if alive and force:
        stale = True
        if pid and pid > 1:
            try:
                pgid = os.getpgid(pid)
                if pgid > 1 and pgid != os.getpgrp():
                    os.killpg(pgid, 15)
                else:
                    os.kill(pid, 15)
            except OSError:
                try:
                    os.kill(pid, 15)
                except OSError:
                    pass
            t_end = time.time() + 3.0
            while time.time() < t_end:
                try:
                    os.kill(pid, 0)
                    time.sleep(0.1)
                except OSError:
                    alive = False
                    break
            if alive:
                try:
                    pgid = os.getpgid(pid)
                    if pgid > 1 and pgid != os.getpgrp():
                        os.killpg(pgid, 9)
                    else:
                        os.kill(pid, 9)
                except OSError:
                    try:
                        os.kill(pid, 9)
                    except OSError:
                        pass
                time.sleep(0.2)
    if not os.path.isfile(lock_path):
        try:
            age = now - os.path.getmtime(path)
        except OSError:
            age = 0
        stale = age > 24 * 3600
    if not stale:
        continue
    shutil.rmtree(path)
    removed.append(path)
report = {"active": active, "removed": removed}
sys.stdout.write(json.dumps(report) + "\n")
if active and not force:
    sys.exit(10)
""".strip() + "\n"


def probe_active_scans_python_source() -> str:
    """Python source to probe for running scans and return active scan details as JSON."""
    return r"""
import json, os, re, sys, time
root = "/tmp"
name_re = re.compile(r"^vcfr_remote_[a-f0-9]{8,16}$")
path_re = re.compile(r"^(/private)?/tmp/vcfr_remote_[a-f0-9]{8,16}$")
active_scans = []
try:
    names = os.listdir(root)
except OSError as exc:
    sys.stderr.write("cannot list /tmp: %s\n" % exc)
    sys.exit(1)
now = time.time()
for name in names:
    if not name_re.match(name):
        continue
    raw = os.path.join(root, name)
    path = os.path.realpath(raw)
    if not path_re.match(path):
        continue
    marker_path = os.path.join(path, ".vcfr_marker")
    if not os.path.isfile(marker_path):
        continue
    try:
        with open(marker_path, encoding="utf-8") as fh:
            marker = json.load(fh)
    except Exception:
        continue
    if not isinstance(marker, dict) or marker.get("marker") != "vcf-readiness-ephemeral-sandbox":
        continue
    run_id = str(marker.get("run_id") or "")
    if run_id not in os.path.basename(path):
        continue
    lock_path = os.path.join(path, ".vcfr_lock")
    if not os.path.isfile(lock_path):
        continue
    try:
        with open(lock_path, encoding="utf-8") as fh:
            lock = json.load(fh)
    except Exception:
        continue
    if not isinstance(lock, dict):
        continue
    pid = lock.get("pid")
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        pid = None
    if not pid:
        continue

    alive = False
    try:
        os.kill(pid, 0)
        alive = True
    except OSError:
        alive = False

    cmdline = ""
    if alive:
        cmdline_path = "/proc/%d/cmdline" % pid
        if os.path.exists(cmdline_path):
            try:
                with open(cmdline_path, "rb") as fh:
                    cmdline = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace")
            except OSError:
                cmdline = ""
            if "vcf" not in cmdline and "worker.pyz" not in cmdline and "python" not in cmdline:
                alive = False

    if not alive:
        continue

    completed_count = 0
    total_count = int(lock.get("target_count") or 0)
    progress_file = os.path.join(path, ".vcfr_progress.ndjson")
    last_msg = ""
    if os.path.isfile(progress_file):
        try:
            with open(progress_file, "r", encoding="utf-8", errors="replace") as pf:
                for line in pf:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                        if isinstance(ev, dict):
                            if ev.get("event") == "progress":
                                completed_count = int(ev.get("completed") or completed_count)
                                if not total_count:
                                    total_count = int(ev.get("total") or 0)
                            elif ev.get("event") == "host_done":
                                completed_count += 1
                            if ev.get("msg"):
                                last_msg = str(ev.get("msg"))
                    except Exception:
                        pass
        except OSError:
            pass

    start_time = int(lock.get("start_time") or marker.get("created_at") or os.path.getmtime(path))
    duration_s = max(0, int(now - start_time))

    active_scans.append({
        "sandbox": path,
        "sandbox_path": path,
        "run_id": run_id,
        "pid": pid,
        "created_at": int(marker.get("created_at") or os.path.getmtime(path)),
        "start_time": start_time,
        "duration_seconds": duration_s,
        "user": marker.get("user") or "",
        "target_count": total_count,
        "completed_count": completed_count,
        "last_message": last_msg,
    })

sys.stdout.write(json.dumps({"ok": True, "active_scans": active_scans}) + "\n")
""".strip() + "\n"


def kill_scan_python_source() -> str:
    """Python source to terminate remote scan process(es) safely via SIGTERM -> SIGKILL."""
    return r"""
import json, os, re, shutil, sys, time

path_re = re.compile(r"^(/private)?/tmp/vcfr_remote_[a-f0-9]{8,16}$")
target_path = sys.argv[1] if len(sys.argv) > 1 else ""

def kill_pid_tree(pid):
    if not pid or pid <= 1:
        return
    alive = True
    try:
        os.kill(pid, 0)
    except OSError:
        return
    cmdline_path = "/proc/%d/cmdline" % pid
    if os.path.exists(cmdline_path):
        try:
            with open(cmdline_path, "rb") as fh:
                cmdline = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace")
        except OSError:
            cmdline = ""
        if "vcf" not in cmdline and "worker.pyz" not in cmdline and "python" not in cmdline:
            return
    try:
        pgid = os.getpgid(pid)
        if pgid > 1 and pgid != os.getpgrp():
            os.killpg(pgid, 15)
        else:
            os.kill(pid, 15)
    except OSError:
        try:
            os.kill(pid, 15)
        except OSError:
            pass

    t_end = time.time() + 3.0
    while time.time() < t_end:
        try:
            os.kill(pid, 0)
            time.sleep(0.1)
        except OSError:
            alive = False
            break

    if alive:
        try:
            pgid = os.getpgid(pid)
            if pgid > 1 and pgid != os.getpgrp():
                os.killpg(pgid, 9)
            else:
                os.kill(pid, 9)
        except OSError:
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        time.sleep(0.2)

def terminate_sandbox(path):
    rp = os.path.realpath(path)
    if not path_re.match(rp):
        return False, "refusing path"
    marker_path = os.path.join(rp, ".vcfr_marker")
    if not os.path.isfile(marker_path):
        return False, "missing marker"
    try:
        with open(marker_path, encoding="utf-8") as fh:
            marker = json.load(fh)
        if not isinstance(marker, dict) or marker.get("marker") != "vcf-readiness-ephemeral-sandbox":
            return False, "marker mismatch"
    except Exception:
        return False, "bad marker"

    lock_path = os.path.join(rp, ".vcfr_lock")
    if os.path.isfile(lock_path):
        try:
            with open(lock_path, encoding="utf-8") as fh:
                lock = json.load(fh)
            pid = int(lock.get("pid"))
        except Exception:
            pid = None
        if pid:
            kill_pid_tree(pid)

    try:
        shutil.rmtree(rp)
    except OSError as exc:
        return False, str(exc)
    return True, "killed"

if target_path and target_path != "all":
    ok, msg = terminate_sandbox(target_path)
    if not ok:
        sys.stderr.write("KILL_FAILED: %s\n" % msg)
        sys.exit(1)
    sys.stdout.write("KILL_OK %s\n" % target_path)
    sys.exit(0)
else:
    root = "/tmp"
    name_re = re.compile(r"^vcfr_remote_[a-f0-9]{8,16}$")
    try:
        names = os.listdir(root)
    except OSError as exc:
        sys.stderr.write("cannot list /tmp: %s\n" % exc)
        sys.exit(1)
    killed = []
    for name in names:
        if name_re.match(name):
            p = os.path.join(root, name)
            ok, _ = terminate_sandbox(p)
            if ok:
                killed.append(p)
    sys.stdout.write(json.dumps({"ok": True, "killed": killed}) + "\n")
    sys.exit(0)
""".strip() + "\n"
