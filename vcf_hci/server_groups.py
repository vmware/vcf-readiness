"""Server groups: portable host metadata and a private local membership registry.

Groups are organizational metadata only. Opaque IDs survive rename/export/import;
identity aliases bridge pending BMC targets to UUID/serial identities after collection.
Explicit removals and deleted groups remain authoritative when old scans reopen.
"""

import hashlib
import json
import os
import tempfile
import threading
import unicodedata
import uuid
from typing import Any, Dict, List, Optional

_LOCK = threading.RLock()
_INVALID = {"", "unknown", "n/a", "none", "redacted", "—", "00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "to be filled by o.e.m.", "to be filled by oem", "default string", "system serial number", "not specified", "not available", "not applicable", "o.e.m.", "00000000", "0123456789"}


def normalize_name(value: Any) -> str:
    """Normalize whitespace and Unicode, keeping case for presentation."""
    if not isinstance(value, str):
        raise ValueError("Group name must be text")
    name = " ".join(unicodedata.normalize("NFKC", value).split())
    if not name or len(name) > 120 or any(unicodedata.category(c).startswith("C") for c in name):
        raise ValueError("Group name must contain 1–120 visible characters")
    return name


def normalize_groups(value: Any) -> List[dict]:
    """Read backward-compatible, well-formed memberships without trusting labels as keys."""
    out: List[dict] = []
    seen = set()
    for group in value if isinstance(value, list) else []:
        if not isinstance(group, dict):
            continue
        ident = group.get("id")
        if not isinstance(ident, str) or not ident or len(ident) > 128 or ident in seen:
            continue
        try:
            name = normalize_name(group.get("name"))
        except ValueError:
            continue
        seen.add(ident)
        out.append({"id": ident, "name": name})
    return out


def merge_groups(*values: Any) -> List[dict]:
    """Union duplicate observations by ID; later observations supply current labels."""
    groups = {}
    for value in values:
        for group in normalize_groups(value):
            groups[group["id"]] = group
    return list(groups.values())


def identity_value(value: Any) -> str:
    """Normalize hardware identity, rejecting manufacturing placeholders."""
    text = str(value or "").strip().casefold()
    return text if text not in _INVALID else ""


def host_aliases(host: dict) -> List[str]:
    """Strong hardware identity first, BMC target fallback; never use display hostname alone."""
    system = host.get("system") or {}
    if not isinstance(system, dict):
        system = {}
    aliases = []
    system_uuid = identity_value(system.get("system_uuid") or system.get("uuid") or host.get("system_uuid") or host.get("uuid"))
    if system_uuid:
        aliases.append("uuid:" + system_uuid)
    serial = identity_value(system.get("serial_number") or system.get("serial") or host.get("serial_number") or host.get("serial"))
    model = identity_value(system.get("model") or host.get("model"))
    if serial and model and model != "unknown server":
        aliases.append("serial_model:" + serial + ":" + model)
    target = identity_value(system.get("bmc_ip") or system.get("ip") or host.get("bmc_ip") or host.get("ip") or host.get("host"))
    if target:
        aliases.append("target:" + target.rstrip("."))
    return aliases


def portable_host_id(host: dict) -> str:
    """Stable fallback for legacy summaries even before local registration."""
    stored = host.get("server_group_host_id")
    if isinstance(stored, str) and stored:
        return stored
    aliases = host_aliases(host)
    if aliases:
        return "asset_" + hashlib.sha256(aliases[0].encode()).hexdigest()[:32]
    # Identity-free observations are deliberately distinct; persist the assigned ID.
    stored = "asset_" + uuid.uuid4().hex
    host["server_group_host_id"] = stored
    return stored


class GroupRegistry:
    """Atomic stdlib-only local store. Callers serialize read/modify/write with _LOCK."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or os.environ.get("VCF_SERVER_GROUPS_PATH") or os.path.expanduser("~/.vcf-readiness/server_groups.json")
        self.data: Dict[str, Any] = {"version": 1, "groups": {}, "assets": {}, "aliases": {}, "deleted": []}
        try:
            with open(self.path, encoding="utf-8") as stream:
                loaded = json.load(stream)
            if not isinstance(loaded, dict) or loaded.get("version") != 1:
                raise ValueError("Unsupported server group metadata")
            for key in ("groups", "assets", "aliases"):
                if not isinstance(loaded.get(key), dict):
                    raise ValueError("Invalid server group metadata")
            self.data.update(loaded)
        except FileNotFoundError:
            pass
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            # Never silently overwrite an unreadable membership store.
            raise ValueError("Cannot read saved server groups: " + str(exc)) from exc

    def save(self) -> None:
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".server-groups-", suffix=".json", dir=parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self.data, stream, ensure_ascii=False, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def groups(self) -> List[dict]:
        return sorted(({"id": ident, "name": name} for ident, name in self.data["groups"].items()), key=lambda g: (g["name"].casefold(), g["id"]))

    def create(self, name: Any) -> dict:
        name = normalize_name(name)
        for group in self.groups():
            if group["name"].casefold() == name.casefold():
                return group
        ident = "grp_" + uuid.uuid4().hex
        self.data["groups"][ident] = name
        return {"id": ident, "name": name}

    def rename(self, ident: str, name: Any) -> None:
        self.require_groups([ident])
        name = normalize_name(name)
        if any(g["id"] != ident and g["name"].casefold() == name.casefold() for g in self.groups()):
            raise ValueError("A group with this name already exists")
        self.data["groups"][ident] = name

    def require_groups(self, ids: Any) -> List[str]:
        if not isinstance(ids, list) or not ids or any(not isinstance(i, str) or i not in self.data["groups"] for i in ids):
            raise ValueError("Choose at least one existing group")
        return list(dict.fromkeys(ids))

    def delete(self, ident: str) -> None:
        self.require_groups([ident])
        del self.data["groups"][ident]
        if ident not in self.data["deleted"]:
            self.data["deleted"].append(ident)
        for asset in self.data["assets"].values():
            asset["groups"] = [g for g in asset["groups"] if g != ident]

    def register(self, host: dict) -> str:
        aliases = host_aliases(host)
        known = self.data["aliases"]
        assets = self.data["assets"]
        strong = [a for a in aliases if not a.startswith("target:")]
        matches = [known[a] for a in aliases if a in known and known[a] in assets]
        ident = next((known[a] for a in strong if a in known and known[a] in assets), None)
        if ident is None:
            # Do not transfer groups when a BMC address has been reused for a different asset.
            ident = next((i for i in matches if not strong or not assets[i].get("strong")), None)
        if ident is None:
            ident = portable_host_id(host)
            assets.setdefault(ident, {"groups": [], "removed": [], "strong": []})
        asset = assets[ident]
        # Join pending-target metadata when a previously known UUID returns at that target.
        for other_id in set(matches):
            other = assets[other_id]
            if other_id != ident and not other.get("strong"):
                asset["groups"] = list(dict.fromkeys(asset["groups"] + other["groups"]))
                asset["removed"] = list(dict.fromkeys(asset["removed"] + other.get("removed", [])))
                for alias, owner in list(known.items()):
                    if owner == other_id:
                        known[alias] = ident
                del assets[other_id]
        asset["strong"] = list(dict.fromkeys(asset.get("strong", []) + strong))
        for alias in aliases:
            known[alias] = ident
        for group in normalize_groups(host.get("server_groups")):
            gid = group["id"]
            if gid in self.data["deleted"] or gid in asset.get("removed", []):
                continue
            self.data["groups"].setdefault(gid, group["name"])
            if gid not in asset["groups"]:
                asset["groups"].append(gid)
        host["server_group_host_id"] = ident
        host["server_groups"] = [{"id": gid, "name": self.data["groups"][gid]} for gid in asset["groups"] if gid in self.data["groups"] and gid not in asset.get("removed", [])]
        return ident

    def assign(self, host_ids: List[str], group_ids: List[str], remove: bool = False) -> None:
        gids = self.require_groups(group_ids)
        if not host_ids or any(i not in self.data["assets"] for i in host_ids):
            raise ValueError("Select known hosts or parsed scan targets")
        for ident in dict.fromkeys(host_ids):
            asset = self.data["assets"][ident]
            for gid in gids:
                if remove:
                    asset["groups"] = [g for g in asset["groups"] if g != gid]
                    if gid not in asset["removed"]:
                        asset["removed"].append(gid)
                else:
                    asset["removed"] = [g for g in asset["removed"] if g != gid]
                    if gid not in asset["groups"]:
                        asset["groups"].append(gid)


def hydrate_groups(hosts: List[dict], path: Optional[str] = None) -> List[dict]:
    """Reconcile portable memberships with local edits, mutating host metadata only."""
    with _LOCK:
        registry = GroupRegistry(path)
        for host in hosts:
            if isinstance(host, dict) and not host.get("obfuscated"):
                registry.register(host)
        if registry.data["groups"] or registry.data["deleted"] or os.path.exists(registry.path):
            registry.save()
    return hosts
