"""
Jump-host connection profiles stored inside the encrypted credential vault.

This module is pure data validation. It does not open SSH connections.
Profiles are held in the vault ciphertext next to BMC entries. Callers that
display profiles must use public_jump_host(), which strips secrets.
"""

import base64
import csv
import hashlib
import io
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.vault.store import VaultError

JUMP_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TRUE = {"1", "true", "yes", "y"}
_FALSE = {"0", "false", "no", "n", ""}

JUMP_HOST_CSV_TEMPLATE = (
    "id,host,port,username,key_path,subnets,note,is_default\n"
    "dal-jump-01,192.0.2.10,22,ubuntu,~/.ssh/id_ed25519,192.0.2.0/24;192.0.3.0/24,Dallas lab,false\n"
    "lon-jump-01,198.51.100.20,22,ubuntu,~/.ssh/id_ed25519,198.51.100.0/24,London lab,false\n"
    "fallback-jump,jump.rainpole.net,22,admin,~/.ssh/id_ed25519,,Fallback jump host,true\n"
)

__all__ = [
    "JUMP_HOST_CSV_TEMPLATE",
    "JumpHostStore",
    "compute_ssh_fingerprint",
    "normalize_jump_host",
    "parse_jump_hosts_csv",
    "public_jump_host",
]


def compute_ssh_fingerprint(host_key: str) -> Tuple[str, str]:
    """Compute (key_type, sha256_fingerprint) from an OpenSSH public key string.

    Supports formats like 'ssh-ed25519 AAAAC3...' or with host prefix '[10.0.0.1]:22 ssh-ed25519 AAAAC3...'.
    Returns ('', '') if key cannot be parsed.
    """
    if not host_key or not isinstance(host_key, str):
        return "", ""
    parts = host_key.strip().split()
    # Handle optional host prefix (e.g. from known_hosts: "[host]:22 ssh-ed25519 AAAA...")
    ktype = ""
    kb64 = ""
    for idx, part in enumerate(parts):
        if part.startswith("ssh-") or part.startswith("ecdsa-") or part.startswith("sk-"):
            ktype = part
            if idx + 1 < len(parts):
                kb64 = parts[idx + 1]
            break
    if not ktype or not kb64:
        if len(parts) >= 2:
            ktype, kb64 = parts[0], parts[1]
    if not ktype or not kb64:
        return "", ""
    try:
        raw = base64.b64decode(kb64)
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
        return ktype, fp
    except Exception:
        return ktype, ""


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise VaultError("is_default must be true or false")


def _normalize_subnets(raw: Any) -> List[str]:
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        parts = re.split(r"[;,\s]+", raw.strip())
    elif isinstance(raw, (list, tuple)):
        parts = []
        for item in raw:
            parts.extend(re.split(r"[;,\s]+", str(item).strip()))
    else:
        raise VaultError("subnets must be a list of CIDR strings")
    out: List[str] = []
    for part in parts:
        if not part or part.lower() == "default":
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            raise VaultError("invalid subnet %r" % part) from None
        text = str(net)
        if text not in out:
            out.append(text)
    return out


def normalize_jump_host(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Return a canonical jump-host profile or raise VaultError.

    Secrets (private_key, password) are kept. Use public_jump_host() to display.
    """
    if not isinstance(raw, dict):
        raise VaultError("jump host profile must be an object")
    jump_id = str(raw.get("id") or "").strip()
    if not JUMP_ID_RE.match(jump_id):
        raise VaultError("jump host id must be 1-64 letters, digits, '.', '_' or '-'")
    host = str(raw.get("host") or "").strip()
    if not host or any(ch.isspace() for ch in host) or "/" in host:
        raise VaultError("jump host address is required")
    try:
        port = int(raw.get("port") if raw.get("port") not in (None, "") else 22)
    except (TypeError, ValueError):
        raise VaultError("jump host port must be an integer") from None
    if port < 1 or port > 65535:
        raise VaultError("jump host port must be 1-65535")
    username = str(raw.get("username") or raw.get("user") or "").strip()
    if not username:
        raise VaultError("jump host username is required")
    auth_type = str(raw.get("auth_type") or "key").strip().lower()
    if auth_type not in ("key", "password"):
        raise VaultError("auth_type must be 'key' or 'password'")
    key_path = str(raw.get("key_path") or "").strip()
    private_key = str(raw.get("private_key") or "")
    password = str(raw.get("password") or "")
    if auth_type == "key" and not key_path and not private_key.strip():
        raise VaultError("key auth requires key_path or private_key")
    if auth_type == "password" and password == "":
        raise VaultError("password auth requires a password")
    if private_key and "PRIVATE KEY" not in private_key:
        raise VaultError("private_key does not look like a PEM or OpenSSH key")
    subnets = _normalize_subnets(raw.get("subnets"))
    is_default = _as_bool(raw.get("is_default", False))
    tags_raw = raw.get("tags") or []
    if isinstance(tags_raw, str):
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
    elif isinstance(tags_raw, (list, tuple)):
        tags = [str(t).strip() for t in tags_raw if str(t).strip()]
    else:
        raise VaultError("tags must be a list")
    note = str(raw.get("note") or "")[:200]
    host_key = str(raw.get("host_key") or "").strip()
    host_key_fingerprint = str(raw.get("host_key_fingerprint") or "").strip()
    host_key_type = str(raw.get("host_key_type") or "").strip()
    if host_key and (not host_key_fingerprint or not host_key_type):
        inferred_type, inferred_fp = compute_ssh_fingerprint(host_key)
        if not host_key_type:
            host_key_type = inferred_type
        if not host_key_fingerprint:
            host_key_fingerprint = inferred_fp

    return {
        "id": jump_id,
        "host": host,
        "port": port,
        "username": username,
        "auth_type": auth_type,
        "key_path": key_path,
        "private_key": private_key.strip(),
        "password": password,
        "subnets": subnets,
        "tags": tags,
        "note": note,
        "is_default": is_default,
        "host_key": host_key,
        "host_key_fingerprint": host_key_fingerprint,
        "host_key_type": host_key_type,
    }


def public_jump_host(profile: Dict[str, Any]) -> Dict[str, Any]:
    """Profile safe to print or return to the browser. No key material, no password."""
    canon = normalize_jump_host(profile)
    return {
        "id": canon["id"],
        "host": canon["host"],
        "port": canon["port"],
        "username": canon["username"],
        "auth_type": canon["auth_type"],
        "key_path": canon["key_path"],
        "has_private_key": bool(canon["private_key"]),
        "has_password": bool(canon["password"]),
        "subnets": list(canon["subnets"]),
        "tags": list(canon["tags"]),
        "note": canon["note"],
        "is_default": canon["is_default"],
        "host_key": canon["host_key"],
        "host_key_fingerprint": canon["host_key_fingerprint"],
        "host_key_type": canon["host_key_type"],
    }


def parse_jump_hosts_csv(text: str) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    """Parse jump-host CSV. Returns (profiles, errors, warnings).

    Passwords and private keys are not accepted in CSV. Use key_path.
    """
    if text is None:
        return [], ["empty CSV"], []
    if text.startswith("\ufeff"):
        text = text[1:]
    kept: List[Tuple[int, str]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        kept.append((idx, line))
    if not kept:
        return [], ["empty CSV: no header row found"], []
    try:
        header_cells = next(csv.reader(io.StringIO(kept[0][1])))
    except (csv.Error, StopIteration):
        return [], ["line %d: cannot parse header" % kept[0][0]], []
    header_map: Dict[str, str] = {}
    for cell in header_cells:
        key = (cell or "").strip().lower()
        if key and key not in header_map:
            header_map[key] = cell
    required = ("id", "host", "username")
    missing = [name for name in required if name not in header_map]
    if missing:
        return [], ["line %d: missing required column(s): %s" % (kept[0][0], ", ".join(missing))], []

    def col(name: str) -> str:
        return header_map.get(name, "")

    profiles: List[Dict[str, Any]] = []
    errors: List[str] = []
    warnings: List[str] = []
    seen: Dict[str, int] = {}
    for phys_no, line in kept[1:]:
        try:
            cells = next(csv.reader(io.StringIO(line)))
        except (csv.Error, StopIteration):
            errors.append("line %d: malformed CSV" % phys_no)
            continue
        record = dict(zip(header_cells, cells))
        raw = {
            "id": (record.get(col("id")) or "").strip(),
            "host": (record.get(col("host")) or "").strip(),
            "port": (record.get(col("port")) or "").strip() if col("port") else 22,
            "username": (record.get(col("username")) or record.get(col("user")) or "").strip(),
            "auth_type": (record.get(col("auth_type")) or "key").strip() if col("auth_type") else "key",
            "key_path": (record.get(col("key_path")) or "").strip() if col("key_path") else "",
            "subnets": (record.get(col("subnets")) or "").strip() if col("subnets") else "",
            "note": (record.get(col("note")) or "").strip() if col("note") else "",
            "is_default": (record.get(col("is_default")) or "").strip() if col("is_default") else False,
            "tags": (record.get(col("tags")) or "").strip() if col("tags") else "",
            "host_key": (record.get(col("host_key")) or "").strip() if col("host_key") else "",
            "host_key_fingerprint": (record.get(col("host_key_fingerprint")) or "").strip() if col("host_key_fingerprint") else "",
            "host_key_type": (record.get(col("host_key_type")) or "").strip() if col("host_key_type") else "",
        }
        subnet_cell = str(raw["subnets"]).strip().lower()
        if subnet_cell == "default":
            raw["subnets"] = ""
            raw["is_default"] = True
        try:
            profile = normalize_jump_host(raw)
        except VaultError as exc:
            errors.append("line %d: %s" % (phys_no, exc))
            continue
        if profile["id"] in seen:
            warnings.append("line %d: duplicate id %s; last row wins" % (phys_no, profile["id"]))
        seen[profile["id"]] = phys_no
        profiles.append(profile)
    return profiles, errors, warnings


class JumpHostStore:
    """Methods mixed into CredentialVault. The vault owns persistence."""

    def jump_host_map(self) -> Dict[str, Dict[str, Any]]:
        self._require_unlocked()
        return self._jump_hosts

    def list_jump_hosts(self) -> List[Dict[str, Any]]:
        self._require_unlocked()
        rows = [public_jump_host(p) for p in self._jump_hosts.values()]
        rows.sort(key=lambda r: r["id"])
        return rows

    def get_jump_host(self, jump_id: str) -> Optional[Dict[str, Any]]:
        self._require_unlocked()
        profile = self._jump_hosts.get(str(jump_id))
        if profile is None:
            return None
        return dict(profile)

    def set_jump_host(self, raw: Dict[str, Any]) -> str:
        self._require_unlocked()
        profile = normalize_jump_host(raw)
        self._jump_hosts[profile["id"]] = profile
        return profile["id"]

    def update_jump_host(self, jump_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update fields of an existing jump host while preserving secrets and unmodified fields."""
        self._require_unlocked()
        jid = str(jump_id)
        profile = self._jump_hosts.get(jid)
        if profile is None:
            raise VaultError("jump host %r not found" % jid)
        if not isinstance(updates, dict):
            raise VaultError("updates must be a dictionary")
        merged = dict(profile)
        for k, v in updates.items():
            if k == "id":
                continue  # ID cannot be renamed in place
            if k in ("password", "private_key") and not v:
                continue
            if k == "host_key" and not v and ("host" not in updates or updates["host"] == profile.get("host")):
                continue
            merged[k] = v
        if "host_key" in updates and "host_key_fingerprint" not in updates:
            merged.pop("host_key_fingerprint", None)
            merged.pop("host_key_type", None)
        canon = normalize_jump_host(merged)
        self._jump_hosts[jid] = canon
        return canon

    def update_jump_host_subnets(
        self,
        jump_id: str,
        subnets: Any,
        mode: str = "replace",
    ) -> List[str]:
        """Update subnets for an existing jump host without modifying other fields or secrets.

        mode can be:
        - 'replace': replace entire subnet list
        - 'add': append subnets to existing list (deduplicated)
        - 'remove': remove subnets from existing list
        Returns the updated normalized subnet list.
        """
        self._require_unlocked()
        jid = str(jump_id)
        profile = self._jump_hosts.get(jid)
        if profile is None:
            raise VaultError("jump host %r not found" % jid)
        new_subnets = _normalize_subnets(subnets)
        existing = list(profile.get("subnets") or [])
        if mode == "replace":
            profile["subnets"] = new_subnets
        elif mode == "add":
            for s in new_subnets:
                if s not in existing:
                    existing.append(s)
            profile["subnets"] = existing
        elif mode == "remove":
            remove_set = set(new_subnets)
            profile["subnets"] = [s for s in existing if s not in remove_set]
        else:
            raise VaultError("invalid mode %r; must be 'replace', 'add', or 'remove'" % mode)
        return list(profile["subnets"])

    def remove_jump_host(self, jump_id: str) -> bool:
        self._require_unlocked()
        return self._jump_hosts.pop(str(jump_id), None) is not None

    def import_jump_hosts(self, profiles: List[Dict[str, Any]], replace: bool = False) -> List[str]:
        self._require_unlocked()
        if replace:
            self._jump_hosts = {}
        written: List[str] = []
        for raw in profiles:
            written.append(self.set_jump_host(raw))
        return written
