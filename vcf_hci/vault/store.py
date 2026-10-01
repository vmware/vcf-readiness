"""
VCF Readiness Tool — Encrypted Credential Vault (vcf_hci.vault.store)

Optional, opt-in, stdlib-only encrypted store for per-host / per-subnet /
default BMC credentials.  Nothing in this module runs unless the user
explicitly creates or opens a vault (``python -m vcf_hci.vault init``,
``vcfr_collector.py --vault``, or the Web UI Vault card).

On-disk format (JSON, binary fields base64):

    {
      "format":  "vcf-readiness-vault",
      "version": 1,
      "kdf":     {"name": "pbkdf2-hmac-sha256", "iterations": 600000, "salt": "<b64>"},
      "cipher":  "hmac-sha256-ctr+hmac-sha256-etm",
      "nonce":   "<b64>", "ciphertext": "<b64>", "tag": "<b64>",
      "created": "<iso>", "updated": "<iso>"
    }

The canonical serialization of ``{format, version, kdf, cipher}`` is bound
into the authentication tag as AAD, so any header tampering (for example
lowering the iteration count) is detected before decryption.

Decrypted payload:

    {"entries": [{"target": "192.0.2.10", "kind": "exact", "username": "root",
                  "password": "...", "note": ""}, ...]}

Credential resolution precedence:  exact host  >  longest-prefix CIDR  >  default.

Guardrails: this module never logs or returns passwords except through
``resolve()`` / ``resolve_for_targets()``, whose output is handed straight to
``scan_hosts(creds=...)``.  It never imports ``vcf_hci.web``.
"""

import base64
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from vcf_hci.vault.crypto import (
    CIPHER_AES_256_GCM,
    CIPHER_NAME,
    KDF_NAME,
    PBKDF2_ITERATIONS,
    SUPPORTED_CIPHERS,
    VaultAuthError,
    VaultCryptoError,
    cipher_display_name,
    decrypt,
    derive_master_key,
    encrypt,
    get_default_cipher,
    is_aes_available,
    new_salt,
)

logger = logging.getLogger("vcf_assess")

VAULT_FORMAT = "vcf-readiness-vault"
VAULT_VERSION = 1
DEFAULT_VAULT_PATH = os.path.expanduser("~/.vcf-readiness/credentials.vault")
MIN_PASSPHRASE_LEN = 12
MAX_RANGE_EXPANSION = 1024

KIND_EXACT = "exact"
KIND_CIDR = "cidr"
KIND_DEFAULT = "default"
_DEFAULT_ALIASES = ("default", "*", "__default__")

_RANGE_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})-(\d{1,3})$")
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*\.?$")

__all__ = [
    "DEFAULT_VAULT_PATH",
    "MIN_PASSPHRASE_LEN",
    "CredentialVault",
    "VaultError",
    "VaultAuthError",
    "VaultExistsError",
    "VaultFormatError",
    "VaultNotFoundError",
    "normalize_target",
]


class VaultError(Exception):
    """Base class for vault store errors (usage / format / I/O)."""


class VaultNotFoundError(VaultError):
    """No vault file exists at the requested path."""


class VaultExistsError(VaultError):
    """Refusing to create a vault over an existing file."""


class VaultFormatError(VaultError):
    """The file is not a recognisable vault (corrupt, truncated, or a different format/version)."""


# ---------------------------------------------------------------------------
# Target normalisation
# ---------------------------------------------------------------------------
def normalize_target(raw: str) -> Tuple[str, str]:
    """Return ``(kind, canonical_target)`` for a user-supplied target string.

    Accepts: ``default`` / ``*`` / ``__default__``, IPv4/IPv6 literals, CIDR
    (``strict=False``, so ``192.0.2.5/24`` becomes ``192.0.2.0/24``), and
    hostnames / FQDNs (lower-cased).  IPv4 ranges (``a.b.c.d-e``) are NOT
    accepted here; see :func:`expand_range_target`.
    """
    if raw is None:
        raise VaultError("target is required")
    t = str(raw).strip()
    if not t:
        raise VaultError("target is required")
    if len(t) > 255:
        raise VaultError("target is too long")
    low = t.lower()
    if low in _DEFAULT_ALIASES:
        return KIND_DEFAULT, KIND_DEFAULT
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError as exc:
            raise VaultError(f"invalid CIDR '{t}': {exc}") from None
        if net.num_addresses == 1:
            return KIND_EXACT, str(net.network_address)
        return KIND_CIDR, str(net)
    try:
        return KIND_EXACT, str(ipaddress.ip_address(t))
    except ValueError:
        pass
    if _RANGE_RE.match(t):
        raise VaultError(f"IPv4 range '{t}' must be expanded before storing (use expand_range_target)")
    if re.match(r"^[\d.]+$", low):
        raise VaultError(f"invalid IP address '{t}'")
    if _HOSTNAME_RE.match(low):
        return KIND_EXACT, low.rstrip(".")
    raise VaultError(f"invalid target '{t}': expected IP, CIDR, hostname, or 'default'")


def expand_range_target(raw: str, cap: int = MAX_RANGE_EXPANSION) -> List[str]:
    """Expand ``a.b.c.d-e`` into individual IPv4 strings; return ``[raw]`` if not a range."""
    t = str(raw or "").strip()
    m = _RANGE_RE.match(t)
    if not m:
        return [t]
    o1, o2, o3, start, end = (int(g) for g in m.groups())
    if not all(0 <= o <= 255 for o in (o1, o2, o3, start, end)):
        raise VaultError(f"invalid octet in range '{t}'")
    if start > end:
        raise VaultError(f"invalid range '{t}': start > end")
    if end - start + 1 > cap:
        raise VaultError(f"range '{t}' expands to more than {cap} hosts; use a CIDR entry instead")
    return [f"{o1}.{o2}.{o3}.{i}" for i in range(start, end + 1)]


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# File hardening helpers (no dependency on vcf_hci.web)
# ---------------------------------------------------------------------------
def _harden_file(path: str) -> bool:
    """Owner-only permissions. False when Windows icacls did not apply."""
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    if sys.platform != "win32":
        return True
    icacls = shutil.which("icacls")
    user = os.environ.get("USERNAME", "")
    if not icacls or not user:
        return False
    try:
        result = subprocess.run(
            ["icacls", path, "/inheritance:r", "/grant:r", "%s:(R,W)" % user],
            capture_output=True, timeout=5,
            creationflags=0x08000000,
        )
    except Exception:
        return False
    return result.returncode == 0


def _atomic_write_private(path: str, data: bytes) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except Exception:
        pass
    tmp_path = os.path.join(directory, ".%s.%d.tmp" % (os.path.basename(path), os.getpid()))
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    owned = True
    try:
        if not _harden_file(tmp_path):
            raise VaultError("could not restrict vault file to the current user")
        with os.fdopen(fd, "wb") as fh:
            owned = False
            fh.write(data)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except Exception:
                pass
        os.replace(tmp_path, path)
    except Exception:
        if owned:
            try:
                os.close(fd)
            except Exception:
                pass
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise
    # The temp inode is already owner-only. replace keeps that DACL.
    _harden_file(path)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: Any) -> bytes:
    if not isinstance(s, str):
        raise VaultFormatError("binary field is not a string")
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except Exception:
        raise VaultFormatError("binary field is not valid base64") from None


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _canonical_header(header: Dict[str, Any]) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------
from vcf_hci.vault.jump_hosts import JumpHostStore, normalize_jump_host


class CredentialVault(JumpHostStore):
    """An unlocked credential vault held in memory.

    Construct via :meth:`create` or :meth:`open`; call :meth:`lock` when done.
    """

    def __init__(self, path: str, master_key: bytes, header: Dict[str, Any],
                 entries: Dict[str, Dict[str, str]], created: str,
                 jump_hosts: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self._path = path
        self._master = master_key
        self._header = header
        self._entries: Dict[str, Dict[str, str]] = entries
        self._jump_hosts: Dict[str, Dict[str, Any]] = dict(jump_hosts or {})
        self._created = created
        self._locked = False

    # -- lifecycle -----------------------------------------------------------
    @staticmethod
    def _check_passphrase(passphrase: str) -> None:
        if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE_LEN:
            raise VaultError(f"passphrase must be at least {MIN_PASSPHRASE_LEN} characters")

    @classmethod
    def create(cls, path: str, passphrase: str, iterations: int = PBKDF2_ITERATIONS,
               cipher: Optional[str] = None) -> "CredentialVault":
        path = os.path.expanduser(path)
        if os.path.exists(path):
            raise VaultExistsError(f"vault already exists: {path}")
        cls._check_passphrase(passphrase)
        cipher_to_use = cipher or get_default_cipher()
        if cipher_to_use not in SUPPORTED_CIPHERS:
            raise VaultError(f"unsupported cipher: {cipher_to_use}")
        salt = new_salt()
        header = {
            "format": VAULT_FORMAT,
            "version": VAULT_VERSION,
            "kdf": {"name": KDF_NAME, "iterations": int(iterations), "salt": _b64e(salt)},
            "cipher": cipher_to_use,
        }
        master = derive_master_key(passphrase, salt, iterations)
        vault = cls(path, master, header, {}, _now_iso())
        vault.save()
        logger.info("Credential vault created at %s [cipher: %s]", path, cipher_to_use)
        return vault

    @classmethod
    def exists(cls, path: str) -> bool:
        return os.path.isfile(os.path.expanduser(path))

    @classmethod
    def inspect_cipher(cls, path: str) -> Optional[str]:
        """Read the unencrypted JSON header to determine the cipher without opening the vault."""
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            doc = json.loads(raw.decode("utf-8"))
            if isinstance(doc, dict) and doc.get("format") == VAULT_FORMAT:
                return doc.get("cipher")
        except Exception:
            pass
        return None

    @classmethod
    def open(cls, path: str, passphrase: str) -> "CredentialVault":
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            raise VaultNotFoundError(f"no vault at {path}")
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            doc = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultFormatError(f"cannot read vault: {exc}") from None
        if not isinstance(doc, dict) or doc.get("format") != VAULT_FORMAT:
            raise VaultFormatError("not a vcf-readiness vault file")
        if doc.get("version") != VAULT_VERSION:
            raise VaultFormatError(f"unsupported vault version {doc.get('version')!r}")
        kdf = doc.get("kdf")
        vault_cipher = doc.get("cipher")
        if not isinstance(kdf, dict) or kdf.get("name") != KDF_NAME or vault_cipher not in SUPPORTED_CIPHERS:
            raise VaultFormatError("unsupported KDF or cipher")
        if vault_cipher == CIPHER_AES_256_GCM and not is_aes_available():
            raise VaultCryptoError(
                "Vault is encrypted with AES-256-GCM. "
                "Install 'pycryptodomex' to unlock: pip install pycryptodomex"
            )
        try:
            iterations = int(kdf.get("iterations"))
        except (TypeError, ValueError):
            raise VaultFormatError("invalid KDF iterations") from None
        header = {"format": VAULT_FORMAT, "version": VAULT_VERSION,
                  "kdf": {"name": KDF_NAME, "iterations": iterations, "salt": kdf.get("salt")},
                  "cipher": vault_cipher}
        salt = _b64d(kdf.get("salt"))
        nonce = _b64d(doc.get("nonce"))
        ct = _b64d(doc.get("ciphertext"))
        tag = _b64d(doc.get("tag"))
        try:
            master = derive_master_key(passphrase if isinstance(passphrase, str) else "", salt, iterations)
            plain = decrypt(master, nonce, ct, tag, _canonical_header(header), cipher=vault_cipher)
        except VaultAuthError:
            raise
        except VaultCryptoError as exc:
            raise VaultFormatError(str(exc)) from None
        try:
            payload = json.loads(plain.decode("utf-8"))
            rows = payload.get("entries", []) if isinstance(payload, dict) else []
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise VaultFormatError("decrypted payload is not valid JSON") from None
        entries: Dict[str, Dict[str, str]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            tgt = str(row.get("target", ""))
            if not tgt:
                continue
            entries[tgt] = {
                "target": tgt,
                "kind": str(row.get("kind", KIND_EXACT)),
                "username": str(row.get("username", "")),
                "password": str(row.get("password", "")),
                "note": str(row.get("note", "")),
            }
        raw_jumps = payload.get("jump_hosts") if isinstance(payload, dict) else None
        jump_hosts: Dict[str, Dict[str, Any]] = {}
        if isinstance(raw_jumps, dict):
            for _jkey, _jrow in raw_jumps.items():
                if not isinstance(_jrow, dict):
                    continue
                try:
                    _profile = normalize_jump_host(_jrow)
                except VaultError:
                    logger.warning("Skipping invalid jump host entry in vault")
                    continue
                jump_hosts[_profile["id"]] = _profile
        return cls(path, master, header, entries, str(doc.get("created") or _now_iso()), jump_hosts)

    def _require_unlocked(self) -> None:
        if self._locked:
            raise VaultError("vault is locked")

    def save(self) -> None:
        self._require_unlocked()
        payload = json.dumps({"entries": list(self._entries.values()), "jump_hosts": self._jump_hosts}, separators=(",", ":")).encode("utf-8")
        nonce, ct, tag = encrypt(self._master, payload, _canonical_header(self._header), cipher=self._header.get("cipher"))
        doc = dict(self._header)
        doc.update({
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ct),
            "tag": _b64e(tag),
            "created": self._created,
            "updated": _now_iso(),
        })
        _atomic_write_private(self._path, json.dumps(doc, indent=1).encode("utf-8"))
        logger.debug("Credential vault saved (%d entries) [cipher: %s]", len(self._entries), self._header.get("cipher"))

    def change_passphrase(self, new_passphrase: str) -> None:
        self._require_unlocked()
        self._check_passphrase(new_passphrase)
        salt = new_salt()
        iterations = int(self._header["kdf"]["iterations"])
        current_cipher = self._header.get("cipher", CIPHER_NAME)
        self._header = {
            "format": VAULT_FORMAT, "version": VAULT_VERSION,
            "kdf": {"name": KDF_NAME, "iterations": iterations, "salt": _b64e(salt)},
            "cipher": current_cipher,
        }
        self._master = derive_master_key(new_passphrase, salt, iterations)
        self.save()

    def lock(self) -> None:
        """Discard all secret material held by this instance."""
        self._entries = {}
        self._jump_hosts = {}
        self._master = b"\x00" * len(self._master) if self._master else b""
        self._locked = True

    # -- properties ----------------------------------------------------------
    @property
    def path(self) -> str:
        return self._path

    @property
    def cipher(self) -> str:
        return str(self._header.get("cipher") or CIPHER_NAME)

    @property
    def cipher_display(self) -> str:
        return cipher_display_name(self.cipher)

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    @property
    def locked(self) -> bool:
        return self._locked

    # -- entry management ----------------------------------------------------
    def set_entry(self, target: str, username: str, password: str, note: str = "") -> List[str]:
        """Upsert an entry.  Returns the list of canonical targets written (ranges expand to many)."""
        self._require_unlocked()
        if not isinstance(username, str) or not username.strip():
            raise VaultError(f"username is required for target '{target}'")
        if not isinstance(password, str) or password == "":
            raise VaultError(f"password is required for target '{target}'")
        written: List[str] = []
        for piece in expand_range_target(target):
            kind, canon = normalize_target(piece)
            self._entries[canon] = {
                "target": canon, "kind": kind,
                "username": username.strip(), "password": password,
                "note": str(note or "")[:200],
            }
            written.append(canon)
        return written

    def remove_entry(self, target: str) -> bool:
        self._require_unlocked()
        try:
            _, canon = normalize_target(target)
        except VaultError:
            canon = str(target).strip()
        return self._entries.pop(canon, None) is not None

    def clear(self) -> None:
        self._require_unlocked()
        self._entries = {}

    def list_entries(self) -> List[Dict[str, str]]:
        """Entries WITHOUT passwords, sorted default-last for display."""
        self._require_unlocked()
        order = {KIND_EXACT: 0, KIND_CIDR: 1, KIND_DEFAULT: 2}
        rows = [
            {"target": e["target"], "kind": e["kind"], "username": e["username"], "note": e.get("note", "")}
            for e in self._entries.values()
        ]
        rows.sort(key=lambda r: (order.get(r["kind"], 9), r["target"]))
        return rows

    # -- resolution ----------------------------------------------------------
    def _match(self, target: str) -> Optional[Dict[str, str]]:
        t = str(target or "").strip()
        if not t:
            return None
        canon = t
        try:
            _, canon = normalize_target(t)
        except VaultError:
            canon = t.lower()
        hit = self._entries.get(canon)
        if hit is not None:
            return hit
        if _is_ip(canon):
            addr = ipaddress.ip_address(canon)
            best: Optional[Dict[str, str]] = None
            best_len = -1
            for e in self._entries.values():
                if e["kind"] != KIND_CIDR:
                    continue
                try:
                    net = ipaddress.ip_network(e["target"], strict=False)
                except ValueError:
                    continue
                if addr.version == net.version and addr in net and net.prefixlen > best_len:
                    best, best_len = e, net.prefixlen
            if best is not None:
                return best
        return self._entries.get(KIND_DEFAULT)

    def resolve(self, target: str) -> Optional[Tuple[str, str]]:
        """Return ``(username, password)`` for a target or ``None``."""
        self._require_unlocked()
        hit = self._match(target)
        return (hit["username"], hit["password"]) if hit else None

    def resolve_kind(self, target: str) -> Optional[str]:
        self._require_unlocked()
        hit = self._match(target)
        return hit["kind"] if hit else None

    def resolve_for_targets(self, targets: List[str]) -> Dict[str, Tuple[str, str]]:
        """Build the ``creds`` dict consumed by ``scan_hosts``.

        Includes a ``"default"`` key when the vault holds a default entry so that
        hosts discovered later (e.g. two-pass discovery) still inherit it.
        """
        self._require_unlocked()
        out: Dict[str, Tuple[str, str]] = {}
        for t in targets or []:
            pair = self.resolve(t)
            if pair is not None:
                out[str(t)] = pair
        dflt = self._entries.get(KIND_DEFAULT)
        if dflt is not None:
            out.setdefault("default", (dflt["username"], dflt["password"]))
        return out

    def coverage(self, targets: List[str]) -> Dict[str, Any]:
        """Password-free coverage summary for a target list (for CLI/UI previews)."""
        self._require_unlocked()
        counts = {KIND_EXACT: 0, KIND_CIDR: 0, KIND_DEFAULT: 0}
        unmatched: List[str] = []
        for t in targets or []:
            k = self.resolve_kind(t)
            if k is None:
                unmatched.append(str(t))
            else:
                counts[k] = counts.get(k, 0) + 1
        total = len(targets or [])
        return {
            "total": total,
            "matched": total - len(unmatched),
            "exact": counts[KIND_EXACT],
            "cidr": counts[KIND_CIDR],
            "default": counts[KIND_DEFAULT],
            "unmatched": unmatched,
            "has_default": KIND_DEFAULT in self._entries,
        }

    # -- bulk ----------------------------------------------------------------
    def import_rows(self, rows: List[Dict[str, str]], replace: bool = False,
                    skip_invalid: bool = False) -> Dict[str, Union[int, List[str]]]:
        """Validate then apply parsed CSV rows.  All-or-nothing unless ``skip_invalid``.

        Each row: ``{"target", "username", "password", "note", "line"}``.
        Returns ``{"imported": n, "skipped": m, "errors": [...]}``; on
        all-or-nothing failure nothing is written and ``imported`` is 0.
        Does NOT call :meth:`save`.
        """
        self._require_unlocked()
        errors: List[str] = []
        good: List[Dict[str, str]] = []
        for row in rows:
            line = row.get("line", "?")
            try:
                for piece in expand_range_target(row.get("target", "")):
                    normalize_target(piece)
                if not str(row.get("username", "")).strip():
                    raise VaultError("empty username")
                if row.get("password", "") == "":
                    raise VaultError("empty password")
                good.append(row)
            except VaultError as exc:
                errors.append(f"line {line}: {exc}")
        if errors and not skip_invalid:
            return {"imported": 0, "skipped": len(rows), "errors": errors}
        if replace:
            self._entries = {}
        imported = 0
        for row in good:
            imported += len(self.set_entry(row["target"], row["username"], row["password"], row.get("note", "")))
        return {"imported": imported, "skipped": len(rows) - len(good), "errors": errors}
