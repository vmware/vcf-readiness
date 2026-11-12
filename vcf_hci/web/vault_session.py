"""
VCF Readiness Tool — Web UI vault session holder (vcf_hci.web.vault_session)

Keeps at most ONE unlocked ``CredentialVault`` in server memory for the local
Web UI.  OFF unless the user explicitly creates / unlocks a vault from the UI.

* Guarded by a ``threading.Lock`` (the HTTP server is multi-threaded).
* Auto-locks after ``IDLE_LOCK_SECONDS`` of inactivity.
* Secrets are available only to server-side scan consumers through :func:`get`
  and explicit typed plugin resolution through :func:`service_action`.
"""

import os
import threading
import time
from typing import Any, Dict, Optional

from vcf_hci.vault import DEFAULT_VAULT_PATH, CredentialVault
from vcf_hci.vault.crypto import cipher_display_name, get_default_cipher, is_aes_available

IDLE_LOCK_SECONDS = 3600

_lock = threading.Lock()
_vault: Optional[CredentialVault] = None
_last_used: float = 0.0


def vault_path() -> str:
    """Resolve the vault path (test suites may override ``VAULT_FILE`` on vcf_hci.web.server)."""
    import sys
    srv = sys.modules.get("vcf_hci.web.server")
    if srv is not None and hasattr(srv, "VAULT_FILE"):
        return str(srv.VAULT_FILE)
    return DEFAULT_VAULT_PATH


def _expire_if_idle_locked() -> None:
    global _vault
    if _vault is not None and (time.time() - _last_used) > IDLE_LOCK_SECONDS:
        try:
            _vault.lock()
        finally:
            _vault = None


def status() -> Dict[str, Any]:
    path = vault_path()
    exists = os.path.isfile(os.path.expanduser(path))
    aes_ok = is_aes_available()
    with _lock:
        _expire_if_idle_locked()
        unlocked = _vault is not None
        count = _vault.entry_count if _vault is not None else 0
        service_count = len(_vault.list_service_credentials()) if _vault is not None else 0
        if _vault is not None:
            cipher = _vault.cipher
            cipher_disp = _vault.cipher_display
        elif exists:
            cipher = CredentialVault.inspect_cipher(path) or ""
            cipher_disp = cipher_display_name(cipher) if cipher else ""
        else:
            cipher = get_default_cipher()
            cipher_disp = cipher_display_name(cipher)
    return {
        "enabled": True,
        "path": path,
        "exists": exists,
        "unlocked": unlocked,
        "entry_count": count,
        "service_count": service_count,
        "idle_lock_seconds": IDLE_LOCK_SECONDS,
        "cipher": cipher,
        "cipher_display": cipher_disp,
        "aes_available": aes_ok,
    }


def create(passphrase: str) -> CredentialVault:
    global _vault, _last_used
    with _lock:
        v = CredentialVault.create(vault_path(), passphrase)   # raises before touching current state
        if _vault is not None:
            _vault.lock()
        _vault, _last_used = v, time.time()
        return v


def unlock(passphrase: str) -> CredentialVault:
    global _vault, _last_used
    with _lock:
        v = CredentialVault.open(vault_path(), passphrase)     # raises before touching current state
        if _vault is not None:
            _vault.lock()
        _vault, _last_used = v, time.time()
        return v


def lock() -> None:
    global _vault
    with _lock:
        if _vault is not None:
            try:
                _vault.lock()
            finally:
                _vault = None


def get() -> Optional[CredentialVault]:
    """Return the unlocked vault (refreshing the idle timer) or ``None``."""
    global _last_used
    with _lock:
        _expire_if_idle_locked()
        if _vault is not None:
            _last_used = time.time()
        return _vault


def service_action(action: str, data: Optional[Dict[str, Any]] = None) -> Any:
    """Atomically resolve or update a service entry while the vault stays unlocked."""
    from vcf_hci.vault.store import VaultError

    global _last_used
    body = data or {}
    with _lock:
        _expire_if_idle_locked()
        if _vault is None:
            raise VaultError("Vault is locked. Unlock it in Credential Vault.")
        _last_used = time.time()
        if action == "list":
            return _vault.list_service_credentials()
        if action == "resolve":
            return _vault.get_service_credential(body.get("id"), body.get("kind"))
        previous = dict(_vault._service_credentials)
        try:
            if action == "save":
                result = _vault.set_service_credential(body)
            elif action == "remove":
                result = _vault.remove_service_credential(body.get("id"))
            else:
                raise ValueError("Unknown service credential action.")
            _vault.save()
        except Exception:
            _vault._service_credentials = previous
            raise
        return result
