"""
Jump-host subcommands for ``python -m vcf_hci.vault jump-host ...``.

Output uses sys.stdout.write / sys.stderr.write so this module stays free of
print() (ruff T20). SSH connectivity tests are not implemented here.
"""

import getpass
import os
import sys
from typing import Callable, Optional

from vcf_hci.vault.jump_hosts import JUMP_HOST_CSV_TEMPLATE, parse_jump_hosts_csv
from vcf_hci.vault.store import VaultError

EXIT_OK = 0
EXIT_VAULT = 1
EXIT_USAGE = 2


def _out(msg: str) -> None:
    sys.stdout.write(msg + "\n")


def _err(msg: str) -> None:
    sys.stderr.write("[x] %s\n" % msg)


def _interactive() -> bool:
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


def _read_secret_env(var_name: Optional[str], label: str) -> Optional[str]:
    if not var_name:
        return None
    value = os.environ.get(var_name, "")
    if not value:
        _err("environment variable %s is empty" % var_name)
        return None
    return value


def _load_private_key(args) -> str:
    inline = _read_secret_env(getattr(args, "key_env", None), "key")
    if getattr(args, "key_env", None) and inline is None:
        raise VaultError("missing key material")
    if inline:
        return inline
    key_file = getattr(args, "key_file", None)
    if not key_file:
        return ""
    path = os.path.expanduser(key_file)
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        raise VaultError("cannot read key file: %s" % exc) from None


def _profile_from_args(args) -> dict:
    private_key = ""
    password = ""
    auth_type = getattr(args, "auth_type", None) or "key"
    if auth_type == "password":
        password = _read_secret_env(getattr(args, "password_env", None), "password") or ""
        if not password:
            if _interactive():
                password = getpass.getpass("Jump host SSH password: ")
            else:
                raise VaultError("no TTY; supply --password-env VAR")
    else:
        private_key = _load_private_key(args)
    subnets = getattr(args, "subnets", "") or ""
    return {
        "id": args.id,
        "host": args.host,
        "port": args.port,
        "username": args.user,
        "auth_type": auth_type,
        "key_path": getattr(args, "key", "") or "",
        "private_key": private_key,
        "password": password,
        "subnets": subnets,
        "note": getattr(args, "note", "") or "",
        "is_default": bool(getattr(args, "default", False)),
        "tags": getattr(args, "tags", "") or "",
    }


def _with_vault(args, open_vault: Callable, fn: Callable) -> int:
    vault = open_vault(args)
    if vault is None:
        return EXIT_VAULT
    try:
        return int(fn(vault))
    except VaultError as exc:
        _err(str(exc))
        return EXIT_VAULT
    finally:
        vault.lock()


def _cmd_add(args, open_vault: Callable) -> int:
    def run(vault) -> int:
        profile = _profile_from_args(args)
        jump_id = vault.set_jump_host(profile)
        vault.save()
        _out("[ok] Stored jump host %s (%s@%s:%s)." % (
            jump_id, profile["username"], profile["host"], profile["port"]))
        return EXIT_OK
    return _with_vault(args, open_vault, run)


def _cmd_list(args, open_vault: Callable) -> int:
    def run(vault) -> int:
        rows = vault.list_jump_hosts()
        if not rows:
            _out("(no jump hosts)")
            return EXIT_OK
        for row in rows:
            flags = []
            if row["is_default"]:
                flags.append("default")
            if row["has_private_key"]:
                flags.append("embedded-key")
            if row["has_password"]:
                flags.append("password")
            flag_txt = (" [" + ",".join(flags) + "]") if flags else ""
            subnets = ",".join(row["subnets"]) or "-"
            _out("%s  %s@%s:%s  subnets=%s  key_path=%s%s" % (
                row["id"], row["username"], row["host"], row["port"],
                subnets, row["key_path"] or "-", flag_txt))
            if row["note"]:
                _out("    note: %s" % row["note"])
        return EXIT_OK
    return _with_vault(args, open_vault, run)


def _cmd_remove(args, open_vault: Callable) -> int:
    def run(vault) -> int:
        if not vault.remove_jump_host(args.id):
            _err("no jump host with id %s" % args.id)
            return EXIT_VAULT
        vault.save()
        _out("[ok] Removed jump host %s." % args.id)
        return EXIT_OK
    return _with_vault(args, open_vault, run)


def _cmd_import(args, open_vault: Callable) -> int:
    try:
        with open(args.file, encoding="utf-8-sig") as fh:
            text = fh.read()
    except OSError as exc:
        _err("cannot read %s: %s" % (args.file, exc))
        return EXIT_USAGE
    profiles, errors, warnings = parse_jump_hosts_csv(text)
    for warning in warnings:
        _out("  [!] %s" % warning)
    if errors and not args.skip_invalid:
        for err in errors:
            _err(err)
        _err("import aborted; fix the rows or pass --skip-invalid")
        return EXIT_USAGE
    for err in errors:
        _err(err)

    def run(vault) -> int:
        written = vault.import_jump_hosts(profiles, replace=bool(args.replace))
        vault.save()
        _out("[ok] Imported %d jump host(s)." % len(written))
        return EXIT_OK
    return _with_vault(args, open_vault, run)


def _cmd_template(_args, _open_vault: Callable) -> int:
    sys.stdout.write(JUMP_HOST_CSV_TEMPLATE)
    return EXIT_OK


def _cmd_set_subnets(args, open_vault: Callable) -> int:
    def run(vault) -> int:
        raw = []
        if getattr(args, "subnets_pos", None):
            raw.extend(args.subnets_pos)
        if getattr(args, "subnets", ""):
            raw.append(args.subnets)
        subnets_arg = raw if raw else []
        updated = vault.update_jump_host_subnets(args.id, subnets_arg, mode="replace")
        vault.save()
        _out("[ok] Updated subnets for %s: %s" % (args.id, ", ".join(updated) or "(none)"))
        return EXIT_OK
    return _with_vault(args, open_vault, run)


def _cmd_add_subnet(args, open_vault: Callable) -> int:
    def run(vault) -> int:
        raw = []
        if getattr(args, "subnets_pos", None):
            raw.extend(args.subnets_pos)
        if getattr(args, "subnets", ""):
            raw.append(args.subnets)
        if not raw:
            _err("no subnets specified; supply CIDR(s) as arguments or with --subnets")
            return EXIT_USAGE
        updated = vault.update_jump_host_subnets(args.id, raw, mode="add")
        vault.save()
        _out("[ok] Added subnet(s) to %s. Current subnets: %s" % (args.id, ", ".join(updated) or "(none)"))
        return EXIT_OK
    return _with_vault(args, open_vault, run)


def _cmd_remove_subnet(args, open_vault: Callable) -> int:
    def run(vault) -> int:
        raw = []
        if getattr(args, "subnets_pos", None):
            raw.extend(args.subnets_pos)
        if getattr(args, "subnets", ""):
            raw.append(args.subnets)
        if not raw:
            _err("no subnets specified; supply CIDR(s) as arguments or with --subnets")
            return EXIT_USAGE
        updated = vault.update_jump_host_subnets(args.id, raw, mode="remove")
        vault.save()
        _out("[ok] Removed subnet(s) from %s. Current subnets: %s" % (args.id, ", ".join(updated) or "(none)"))
        return EXIT_OK
    return _with_vault(args, open_vault, run)


def _cmd_edit(args, open_vault: Callable) -> int:
    def run(vault) -> int:
        updates = {}
        if getattr(args, "host", None) is not None:
            updates["host"] = args.host
        if getattr(args, "port", None) is not None:
            updates["port"] = args.port
        if getattr(args, "user", None) is not None:
            updates["username"] = args.user
        if getattr(args, "auth_type", None) is not None:
            updates["auth_type"] = args.auth_type
        if getattr(args, "key", None) is not None:
            updates["key_path"] = args.key
        if getattr(args, "note", None) is not None:
            updates["note"] = args.note
        if getattr(args, "tags", None) is not None:
            updates["tags"] = args.tags
        if getattr(args, "default", False):
            updates["is_default"] = True
        elif getattr(args, "no_default", False):
            updates["is_default"] = False

        if getattr(args, "key_file", None) or getattr(args, "key_env", None):
            updates["private_key"] = _load_private_key(args)
        if getattr(args, "password_env", None):
            pwd = _read_secret_env(args.password_env, "password")
            if pwd:
                updates["password"] = pwd

        if getattr(args, "subnets", None) is not None:
            updates["subnets"] = args.subnets

        vault.update_jump_host(args.id, updates)
        if getattr(args, "add_subnets", None):
            vault.update_jump_host_subnets(args.id, args.add_subnets, mode="add")
        if getattr(args, "remove_subnets", None):
            vault.update_jump_host_subnets(args.id, args.remove_subnets, mode="remove")

        vault.save()
        profile = vault.get_jump_host(args.id) or {}
        subnets_txt = ", ".join(profile.get("subnets") or []) or "(none)"
        _out("[ok] Updated jump host %s (subnets: %s)." % (args.id, subnets_txt))
        return EXIT_OK
    return _with_vault(args, open_vault, run)


def register_jump_commands(subparsers, open_vault: Callable) -> None:
    """Attach ``jump-host`` to the vault CLI parser."""
    parent = subparsers.add_parser(
        "jump-host",
        help="Manage jump-host SSH profiles stored in the vault (no secrets printed)",
    )
    commands = parent.add_subparsers(dest="jump_cmd")
    commands.required = True

    add = commands.add_parser("add", help="Add or replace one jump host")
    add.add_argument("--id", required=True)
    add.add_argument("--host", required=True)
    add.add_argument("--port", type=int, default=22)
    add.add_argument("--user", required=True)
    add.add_argument("--auth-type", choices=("key", "password"), default="key")
    add.add_argument("--key", default="", help="Path to a private key on this workstation (stored as a path, not copied)")
    add.add_argument("--key-file", default=None, help="Read a private key from this file and store it encrypted in the vault")
    add.add_argument("--key-env", default=None, help="Environment variable holding PEM text to store encrypted")
    add.add_argument("--password-env", default=None, help="Environment variable holding the SSH password")
    add.add_argument("--subnets", default="", help="Comma-separated CIDRs this jump host can reach")
    add.add_argument("--tags", default="")
    add.add_argument("--note", default="")
    add.add_argument("--default", action="store_true", help="Use this host when a target matches no subnet")
    add.set_defaults(fn=lambda args: _cmd_add(args, open_vault))

    commands.add_parser("list", help="List jump hosts without secrets").set_defaults(
        fn=lambda args: _cmd_list(args, open_vault))

    edit = commands.add_parser("edit", help="Edit jump host settings and subnets without recreating it")
    edit.add_argument("--id", required=True, help="Jump host ID")
    edit.add_argument("--host", default=None)
    edit.add_argument("--port", type=int, default=None)
    edit.add_argument("--user", default=None)
    edit.add_argument("--auth-type", choices=("key", "password"), default=None)
    edit.add_argument("--key", default=None, help="Path to private key on workstation")
    edit.add_argument("--key-file", default=None, help="Store encrypted private key from file")
    edit.add_argument("--key-env", default=None, help="Store encrypted private key from env var")
    edit.add_argument("--password-env", default=None, help="Store encrypted password from env var")
    edit.add_argument("--subnets", default=None, help="Replace subnets with comma-separated CIDRs")
    edit.add_argument("--add-subnets", default=None, help="Add comma-separated CIDRs")
    edit.add_argument("--remove-subnets", default=None, help="Remove comma-separated CIDRs")
    edit.add_argument("--note", default=None)
    edit.add_argument("--tags", default=None)
    edit.add_argument("--default", action="store_true", default=False, help="Set as default jump host")
    edit.add_argument("--no-default", action="store_true", default=False, help="Unset as default jump host")
    edit.set_defaults(fn=lambda args: _cmd_edit(args, open_vault))

    set_sub = commands.add_parser("set-subnets", help="Set/replace subnets attached to a jump host")
    set_sub.add_argument("--id", required=True, help="Jump host ID")
    set_sub.add_argument("subnets_pos", nargs="*", metavar="SUBNET", help="CIDR subnet(s) to attach")
    set_sub.add_argument("--subnets", default="", help="Comma- or semicolon-separated CIDRs")
    set_sub.set_defaults(fn=lambda args: _cmd_set_subnets(args, open_vault))

    add_sub = commands.add_parser("add-subnet", help="Add one or more subnets to a jump host without recreating it")
    add_sub.add_argument("--id", required=True, help="Jump host ID")
    add_sub.add_argument("subnets_pos", nargs="*", metavar="SUBNET", help="CIDR subnet(s) to add")
    add_sub.add_argument("--subnets", default="", help="Comma- or semicolon-separated CIDRs to add")
    add_sub.set_defaults(fn=lambda args: _cmd_add_subnet(args, open_vault))

    rm_sub = commands.add_parser("remove-subnet", help="Remove one or more subnets from a jump host")
    rm_sub.add_argument("--id", required=True, help="Jump host ID")
    rm_sub.add_argument("subnets_pos", nargs="*", metavar="SUBNET", help="CIDR subnet(s) to remove")
    rm_sub.add_argument("--subnets", default="", help="Comma- or semicolon-separated CIDRs to remove")
    rm_sub.set_defaults(fn=lambda args: _cmd_remove_subnet(args, open_vault))

    remove = commands.add_parser("remove", help="Remove one jump host")
    remove.add_argument("--id", required=True)
    remove.set_defaults(fn=lambda args: _cmd_remove(args, open_vault))

    imp = commands.add_parser("import-csv", help="Import jump hosts from CSV (key paths only, no passwords)")
    imp.add_argument("file")
    imp.add_argument("--replace", action="store_true")
    imp.add_argument("--skip-invalid", action="store_true")
    imp.set_defaults(fn=lambda args: _cmd_import(args, open_vault))

    commands.add_parser("template", help="Print a jump-host CSV template").set_defaults(
        fn=lambda args: _cmd_template(args, open_vault))
