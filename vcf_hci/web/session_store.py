"""
VCF Readiness Tool — Web Session & Profile Store (vcf_hci.web.session_store)

Handles secrets persistence (macOS Keychain, Windows DPAPI, Linux libsecret),
profile configuration persistence, and session state persistence.
"""

import base64
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from typing import Any, Optional, Tuple

logger = logging.getLogger("vcf_assess")

SESSION_FILE = os.path.expanduser("~/.vcf-readiness-session.json")
PROFILE_FILE = os.path.expanduser("~/.vcf-readiness-profiles.json")
DPAPI_FILE   = os.path.expanduser("~/.vcf-readiness-secrets.json")
KEYCHAIN_SVC = "vcf-readiness"


def _get_profile_file() -> str:
    srv = sys.modules.get("vcf_hci.web.server")
    if srv is not None and hasattr(srv, "PROFILE_FILE"):
        return srv.PROFILE_FILE
    return PROFILE_FILE


def _get_session_file() -> str:
    srv = sys.modules.get("vcf_hci.web.server")
    if srv is not None and hasattr(srv, "SESSION_FILE"):
        return srv.SESSION_FILE
    return SESSION_FILE


def _get_dpapi_file() -> str:
    srv = sys.modules.get("vcf_hci.web.server")
    if srv is not None and hasattr(srv, "DPAPI_FILE"):
        return srv.DPAPI_FILE
    return DPAPI_FILE


# =============================================================================
# Secret store  (macOS Keychain / Windows DPAPI / Linux libsecret)
# =============================================================================
class _SecretStore:
    _CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

    @classmethod
    def _run(cls, cmd: list, stdin_text: Optional[str] = None) -> Tuple[int, str]:
        try:
            p = subprocess.run(
                cmd, input=stdin_text, capture_output=True, text=True,
                timeout=15, creationflags=cls._CREATE_NO_WINDOW,
            )
            return p.returncode, p.stdout
        except Exception:
            return 1, ""

    @staticmethod
    def backend() -> str:
        if sys.platform == "darwin" and shutil.which("security"):
            return "keychain"
        if sys.platform == "win32":
            return "dpapi"
        if shutil.which("secret-tool"):
            return "secret-tool"
        return "none"

    @classmethod
    def label(cls) -> str:
        return {
            "keychain":    "macOS Keychain",
            "dpapi":       "Windows DPAPI",
            "secret-tool": "Linux keyring (libsecret)",
            "none":        "unavailable",
        }.get(cls.backend(), "unavailable")

    @staticmethod
    def _enc(s: str) -> str:
        return base64.b64encode(s.encode("utf-8")).decode("ascii")

    @staticmethod
    def _dec(s: str) -> str:
        try:
            return base64.b64decode(s.encode("ascii")).decode("utf-8")
        except Exception:
            return s

    @classmethod
    def store(cls, key: str, value: str) -> bool:
        enc = cls._enc(value)
        backend = cls.backend()
        if backend == "keychain":
            rc, _ = cls._run(["security", "add-generic-password",
                               "-s", KEYCHAIN_SVC, "-a", key, "-U", "-w"], f"{enc}\n{enc}\n")
            return rc == 0
        if backend == "dpapi":
            return cls._dpapi_store(key, enc)
        if backend == "secret-tool":
            rc, _ = cls._run(["secret-tool", "store", "--label",
                               f"{KEYCHAIN_SVC}:{key}", "service", KEYCHAIN_SVC,
                               "account", key], enc + "\n")
            return rc == 0
        return False

    @classmethod
    def retrieve(cls, key: str) -> Optional[str]:
        backend = cls.backend()
        if backend == "keychain":
            rc, out = cls._run(["security", "find-generic-password",
                                 "-s", KEYCHAIN_SVC, "-a", key, "-w"], None)
            return cls._dec(out.strip()) if rc == 0 and out.strip() else None
        if backend == "dpapi":
            enc = cls._dpapi_retrieve(key)
            return cls._dec(enc) if enc else None
        if backend == "secret-tool":
            rc, out = cls._run(["secret-tool", "lookup",
                                 "service", KEYCHAIN_SVC, "account", key], None)
            return cls._dec(out.strip()) if rc == 0 and out.strip() else None
        return None

    @classmethod
    def delete(cls, key: str) -> bool:
        backend = cls.backend()
        if backend == "keychain":
            rc, _ = cls._run(["security", "delete-generic-password",
                               "-s", KEYCHAIN_SVC, "-a", key], None)
            return rc == 0
        if backend == "dpapi":
            return cls._dpapi_delete(key)
        if backend == "secret-tool":
            rc, _ = cls._run(["secret-tool", "clear",
                               "service", KEYCHAIN_SVC, "account", key], None)
            return rc == 0
        return False

    @classmethod
    def _dpapi_store(cls, key: str, enc: str) -> bool:
        try:
            import ctypes
            import ctypes.wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char)),
                ]

            raw_bytes = enc.encode("utf-8")
            buf_in = ctypes.create_string_buffer(raw_bytes, len(raw_bytes))
            blob_in = DATA_BLOB(
                cbData=len(raw_bytes),
                pbData=ctypes.cast(buf_in, ctypes.POINTER(ctypes.c_char)),
            )
            blob_out = DATA_BLOB()

            windll = getattr(ctypes, "windll", None)
            if not windll:
                return False

            ok = windll.crypt32.CryptProtectData(
                ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
            )
            if not ok:
                return False

            ciphertext = base64.b64encode(
                ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ).decode("ascii")
            windll.kernel32.LocalFree(blob_out.pbData)

            secrets = cls._dpapi_load()
            secrets[key] = ciphertext
            cls._dpapi_save(secrets)
            return True
        except Exception:
            return False

    @classmethod
    def _dpapi_retrieve(cls, key: str) -> Optional[str]:
        try:
            import ctypes
            import ctypes.wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char)),
                ]

            secrets = cls._dpapi_load()
            ct = secrets.get(key)
            if not ct:
                return None

            raw_bytes = base64.b64decode(ct)
            buf_in = ctypes.create_string_buffer(raw_bytes, len(raw_bytes))
            blob_in = DATA_BLOB(
                cbData=len(raw_bytes),
                pbData=ctypes.cast(buf_in, ctypes.POINTER(ctypes.c_char)),
            )
            blob_out = DATA_BLOB()

            windll = getattr(ctypes, "windll", None)
            if not windll:
                return None

            ok = windll.crypt32.CryptUnprotectData(
                ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
            )
            if not ok:
                return None

            result = ctypes.string_at(blob_out.pbData, blob_out.cbData).decode("utf-8")
            windll.kernel32.LocalFree(blob_out.pbData)
            return result
        except Exception:
            return None

    @classmethod
    def _dpapi_delete(cls, key: str) -> bool:
        secrets = cls._dpapi_load()
        if key in secrets:
            del secrets[key]
            cls._dpapi_save(secrets)
        return True

    @staticmethod
    def _dpapi_load() -> dict:
        target_file = _get_dpapi_file()
        try:
            with open(target_file, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}

    @staticmethod
    def _dpapi_save(d: dict) -> None:
        target_file = _get_dpapi_file()
        try:
            with open(target_file, "w", encoding="utf-8") as fh:
                json.dump(d, fh)
            try:
                os.chmod(target_file, 0o600)
            except Exception:
                pass
            if sys.platform == "win32" and shutil.which("icacls"):
                try:
                    user = os.environ.get("USERNAME", "")
                    if user:
                        subprocess.run(
                            ["icacls", target_file, "/inheritance:r", "/grant:r", f"{user}:(R,W)"],
                            capture_output=True,
                            timeout=5,
                        )
                except Exception:
                    pass
        except Exception:
            pass


# =============================================================================
# Profile / Session persistence
# =============================================================================
def _load_profiles() -> dict:
    target_file = _get_profile_file()
    try:
        with open(target_file, encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("profiles", {}) if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_profiles(profiles: dict) -> bool:
    target_file = _get_profile_file()
    try:
        with open(target_file, "w", encoding="utf-8") as fh:
            json.dump({"profiles": profiles,
                       "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}, fh, indent=2)
        try:
            os.chmod(target_file, 0o600)
        except Exception:
            pass
        return True
    except Exception:
        return False


def _load_session() -> dict:
    target_file = _get_session_file()
    try:
        with open(target_file, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _sanitize_session_dict(obj: Any) -> Any:
    """Recursively strip password, token, and credential keys from session persistence."""
    if isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            k_lower = str(k).lower()
            if any(term in k_lower for term in ("password", "pass", "secret", "token", "creds", "auth")):
                continue
            sanitized[k] = _sanitize_session_dict(v)
        return sanitized
    elif isinstance(obj, list):
        return [_sanitize_session_dict(item) for item in obj]
    return obj


def _save_session(data: dict) -> bool:
    target_file = _get_session_file()
    try:
        sanitized = _sanitize_session_dict(data) if isinstance(data, dict) else {}
        sanitized["saved_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        sess_dir = os.path.dirname(os.path.abspath(target_file))
        os.makedirs(sess_dir, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        fd = os.open(target_file, flags, mode)
        with open(fd, "w", encoding="utf-8") as fh:
            json.dump(sanitized, fh, indent=2)
        try:
            os.chmod(target_file, 0o600)
        except Exception:
            pass
        return True
    except Exception:
        return False
