"""
VCF Readiness Tool — Desktop & Folder Helpers (vcf_hci.web.desktop)

Native OS folder browsing dialogs and desktop folder launcher utilities
for macOS, Windows, and Linux.
"""

import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Optional

from vcf_hci.logging_utils import get_default_output_dir

logger = logging.getLogger("vcf_assess")


def _browse_folder_dialog(initial_dir: Optional[str] = None) -> Optional[str]:
    """
    Display a native desktop folder chooser dialog.
    Supports macOS (AppleScript / osascript), Windows (PowerShell FolderBrowserDialog),
    and Linux (zenity / kdialog / yad).
    Returns the chosen folder path, or None if cancelled or unavailable.
    """
    # macOS
    if sys.platform == "darwin" and shutil.which("osascript"):
        script = 'POSIX path of (choose folder with prompt "Select VCF Assessment Output Folder"'
        if initial_dir and os.path.isdir(os.path.expanduser(initial_dir)):
            exp = os.path.abspath(os.path.expanduser(initial_dir)).replace("\\", "\\\\").replace('"', '\\"')
            script += f' default location (POSIX file "{exp}")'
        script += ')'
        try:
            res = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if res.returncode == 0:
                chosen = res.stdout.strip()
                if chosen:
                    return os.path.abspath(os.path.expanduser(chosen))
            return None
        except Exception:
            return None

    # Windows
    if sys.platform == "win32":
        init_cmd = ""
        if initial_dir and os.path.isdir(os.path.expanduser(initial_dir)):
            exp = os.path.abspath(os.path.expanduser(initial_dir)).replace("'", "''")
            init_cmd = f"$f.SelectedPath = '{exp}';"

        ps = (
            "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null; "
            "$f = New-Object System.Windows.Forms.FolderBrowserDialog; "
            "$f.Description = 'Select VCF Assessment Output Folder'; "
            "$f.ShowNewFolderButton = $true; "
            f"{init_cmd} "
            "if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $f.SelectedPath }"
        )
        try:
            _CREATE_NO_WINDOW = 0x08000000
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=_CREATE_NO_WINDOW,
            )
            if res.returncode == 0:
                chosen = res.stdout.strip()
                if chosen and os.path.isdir(chosen):
                    return os.path.abspath(chosen)
            return None
        except Exception:
            return None

    # Linux / other Unix desktop
    if shutil.which("zenity"):
        cmd = ["zenity", "--file-selection", "--directory", "--title=Select VCF Assessment Output Folder"]
        if initial_dir and os.path.isdir(os.path.expanduser(initial_dir)):
            cmd.extend(["--filename", os.path.abspath(os.path.expanduser(initial_dir))])
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0:
                chosen = res.stdout.strip()
                if chosen:
                    return os.path.abspath(os.path.expanduser(chosen))
            return None
        except Exception:
            return None

    if shutil.which("kdialog"):
        start_dir = os.path.abspath(os.path.expanduser(initial_dir)) if initial_dir and os.path.isdir(os.path.expanduser(initial_dir)) else os.path.expanduser("~")
        cmd = ["kdialog", "--getexistingdirectory", start_dir, "--title", "Select VCF Assessment Output Folder"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0:
                chosen = res.stdout.strip()
                if chosen:
                    return os.path.abspath(os.path.expanduser(chosen))
            return None
        except Exception:
            return None

    if shutil.which("yad"):
        cmd = ["yad", "--file", "--directory", "--title=Select VCF Assessment Output Folder"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0:
                chosen = res.stdout.strip()
                if chosen:
                    return os.path.abspath(os.path.expanduser(chosen))
            return None
        except Exception:
            return None

    return None


def _is_safe_desktop_folder(path: str) -> bool:
    """Validate that path is within the user home, cwd, temporary directory, or designated report output directory."""
    if not path or not isinstance(path, str):
        return False
    clean = path.strip()
    if not clean:
        return False
    # Reject Windows drive-letter / backslash paths on POSIX to prevent relative path confusion
    if sys.platform != "win32" and ("\\" in clean or re.match(r"^[a-zA-Z]:", clean)):
        return False
    try:
        abs_p = os.path.realpath(os.path.abspath(os.path.expanduser(clean)))
        home_dir = os.path.realpath(os.path.abspath(os.path.expanduser("~")))
        cwd_dir = os.path.realpath(os.path.abspath(os.getcwd()))
        default_out = os.path.realpath(os.path.abspath(os.path.expanduser(get_default_output_dir())))
        temp_dir = os.path.realpath(os.path.abspath(tempfile.gettempdir()))

        # System root directories that must never be opened directly
        system_roots = {"/", "/root", "/bin", "/sbin", "/etc", "/usr", "/var", "/private", "C:\\", "C:\\Windows", "C:\\Windows\\System32"}
        if abs_p in system_roots or clean in system_roots:
            return False

        for safe_root in (home_dir, cwd_dir, default_out, temp_dir):
            if abs_p == safe_root or abs_p.startswith(safe_root + os.sep):
                return True
        return False
    except Exception:
        return False


def _components_escape(path: str) -> bool:
    """True when any slash-separated component is '..'."""
    return any(part == ".." for part in re.split(r"[\\/]", path))


def _within_directory(candidate: str, root: str) -> bool:
    cand = os.path.normcase(os.path.abspath(candidate))
    base = os.path.normcase(os.path.abspath(root))
    if cand == base:
        return True
    prefix = base if base.endswith(os.sep) else base + os.sep
    return cand.startswith(prefix)


def _resolve_desktop_open_path(folder_path: str, allowed_root: str) -> Optional[str]:
    """Return a real directory inside allowed_root, or None.

    Rejects '..', absolute paths outside allowed_root, and symlink escapes.
    Creates a missing directory only when the resolved path is allowed_root
    or a child of it.
    """
    if not isinstance(folder_path, str) or not isinstance(allowed_root, str):
        return None
    clean = folder_path.strip()
    root_text = allowed_root.strip()
    if not clean or not root_text:
        return None
    if _components_escape(clean) or _components_escape(root_text):
        return None
    if sys.platform != "win32" and ("\\" in clean or re.match(r"^[A-Za-z]:", clean)):
        return None

    root_real = os.path.realpath(os.path.abspath(os.path.expanduser(root_text)))
    raw = os.path.expanduser(clean)
    if os.path.isabs(raw):
        expanded = os.path.abspath(raw)
    else:
        expanded = os.path.abspath(os.path.join(root_real, raw))

    resolved = os.path.realpath(expanded)
    if not _within_directory(resolved, root_real):
        return None

    if os.path.isfile(resolved):
        resolved = os.path.realpath(os.path.dirname(resolved))
        if not _within_directory(resolved, root_real):
            return None

    if not os.path.isdir(resolved):
        same_root = os.path.normcase(resolved) == os.path.normcase(root_real)
        parent = os.path.dirname(resolved)
        if not same_root:
            if os.path.islink(parent) or not _within_directory(os.path.realpath(parent), root_real):
                return None
        try:
            os.makedirs(resolved, exist_ok=True)
        except OSError:
            return None
        resolved = os.path.realpath(resolved)
        if not _within_directory(resolved, root_real):
            return None

    if os.path.islink(resolved) or not os.path.isdir(resolved):
        return None
    final = os.path.realpath(resolved)
    if not _within_directory(final, root_real):
        return None
    return final


def _open_folder_in_desktop(folder_path: str, allowed_root: Optional[str] = None) -> bool:
    """
    Open a directory or file's parent directory in the native OS desktop file manager
    (Finder on macOS, Windows Explorer on Windows, xdg-open on Linux).

    folder_path must resolve inside allowed_root. When allowed_root is omitted,
    the anchor is the default scan output directory.
    """
    if not folder_path or not str(folder_path).strip():
        return False

    root = allowed_root if isinstance(allowed_root, str) and allowed_root.strip() else get_default_output_dir()
    target = _resolve_desktop_open_path(str(folder_path), root)
    if not target:
        logger.warning("Blocked attempt to open unsafe directory path: %s", folder_path)
        return False

    try:
        if sys.platform == "darwin" and shutil.which("open"):
            subprocess.run(["open", target], check=False, timeout=10)
            return True
        if sys.platform == "win32":
            _CREATE_NO_WINDOW = 0x08000000
            subprocess.run(
                ["explorer", os.path.normpath(target)],
                check=False,
                timeout=10,
                creationflags=_CREATE_NO_WINDOW,
            )
            return True
        if shutil.which("xdg-open"):
            subprocess.run(["xdg-open", target], check=False, timeout=10)
            return True
    except Exception:
        return False
    return False
