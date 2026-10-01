"""
VCF Readiness Tool — Credential Vault management CLI.

    python -m vcf_hci.vault init
    python -m vcf_hci.vault add --target 192.0.2.10 --username root
    python -m vcf_hci.vault import-csv credentials.csv [--replace] [--skip-invalid]
    python -m vcf_hci.vault list
    python -m vcf_hci.vault remove --target 192.0.2.10
    python -m vcf_hci.vault resolve 192.0.2.10 192.0.2.77
    python -m vcf_hci.vault change-passphrase
    python -m vcf_hci.vault template > credentials.csv

Global options:  --vault PATH   (default ~/.vcf-readiness/credentials.vault)
                 --passphrase-env VAR   (read the passphrase from an env var; otherwise prompt)

Passphrases and passwords are NEVER accepted on the command line (argv is
visible to other local processes).  This is the only module under
``vcf_hci/vault/`` allowed to use ``print()``.
"""

import argparse
import getpass
import os
import sys
from typing import List, Optional

from vcf_hci.vault.crypto import is_aes_available
from vcf_hci.vault.csv_import import CSV_TEMPLATE, parse_credentials_csv
from vcf_hci.vault.jump_cli import register_jump_commands
from vcf_hci.vault.store import (
    DEFAULT_VAULT_PATH,
    MIN_PASSPHRASE_LEN,
    CredentialVault,
    VaultAuthError,
    VaultError,
    VaultExistsError,
    VaultFormatError,
    VaultNotFoundError,
)

EXIT_OK = 0
EXIT_VAULT = 1
EXIT_USAGE = 2


def _err(msg: str) -> None:
    print(f"[✗] {msg}", file=sys.stderr)


def _interactive() -> bool:
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


def _get_passphrase(args: argparse.Namespace, confirm: bool = False, prompt: str = "Vault passphrase: ") -> Optional[str]:
    if args.passphrase_env:
        val = os.environ.get(args.passphrase_env)
        if val is None or val == "":
            _err(f"environment variable {args.passphrase_env} is not set or empty")
            return None
        return val
    if not _interactive():
        _err("no TTY available; supply --passphrase-env VAR in non-interactive mode")
        return None
    p1 = getpass.getpass(prompt)
    if confirm:
        p2 = getpass.getpass("Confirm passphrase: ")
        if p1 != p2:
            _err("passphrases do not match")
            return None
    return p1


def _open(args: argparse.Namespace) -> Optional[CredentialVault]:
    pw = _get_passphrase(args)
    if pw is None:
        return None
    try:
        return CredentialVault.open(args.vault, pw)
    except VaultNotFoundError:
        _err(f"no vault at {args.vault} — run: python -m vcf_hci.vault init")
    except VaultAuthError:
        _err("wrong passphrase (or the vault file has been tampered with)")
    except VaultFormatError as exc:
        _err(f"unreadable vault: {exc}")
    return None


# ── commands ────────────────────────────────────────────────────────────────
def cmd_init(args: argparse.Namespace) -> int:
    if CredentialVault.exists(args.vault):
        _err(f"vault already exists at {args.vault}")
        return EXIT_VAULT
    print(f"Creating encrypted credential vault at {args.vault}")
    print(f"Choose a passphrase of at least {MIN_PASSPHRASE_LEN} characters. THERE IS NO RECOVERY if it is lost.")
    pw = _get_passphrase(args, confirm=True, prompt="New vault passphrase: ")
    if pw is None:
        return EXIT_USAGE
    try:
        vault = CredentialVault.create(args.vault, pw)
    except (VaultError, VaultExistsError) as exc:
        _err(str(exc))
        return EXIT_VAULT
    print(f"[✔] Vault created (0 entries) [mode: {vault.cipher_display}]. Add credentials with 'add' or 'import-csv'.")
    return EXIT_OK


def cmd_add(args: argparse.Namespace) -> int:
    vault = _open(args)
    if vault is None:
        return EXIT_VAULT
    if args.password_env:
        pwd = os.environ.get(args.password_env, "")
        if not pwd:
            _err(f"environment variable {args.password_env} is not set or empty")
            return EXIT_USAGE
    elif _interactive():
        pwd = getpass.getpass(f"BMC password for {args.target}: ")
    else:
        _err("no TTY; supply --password-env VAR")
        return EXIT_USAGE
    try:
        written = vault.set_entry(args.target, args.username, pwd, args.note or "")
        vault.save()
    except VaultError as exc:
        _err(str(exc))
        return EXIT_VAULT
    finally:
        vault.lock()
    print(f"[✔] Stored {len(written)} entr{'y' if len(written) == 1 else 'ies'} for {args.target} (user {args.username}).")
    return EXIT_OK


def cmd_import_csv(args: argparse.Namespace) -> int:
    try:
        with open(args.file, encoding="utf-8-sig") as fh:
            text = fh.read()
    except OSError as exc:
        _err(f"cannot read {args.file}: {exc}")
        return EXIT_USAGE
    rows, errors, warnings = parse_credentials_csv(text)
    for w in warnings:
        print(f"  [!] {w}")
    if errors and not args.skip_invalid:
        for e in errors:
            _err(e)
        _err("import aborted: fix the rows above or pass --skip-invalid")
        return EXIT_USAGE
    vault = _open(args)
    if vault is None:
        return EXIT_VAULT
    try:
        result = vault.import_rows(rows, replace=args.replace, skip_invalid=args.skip_invalid)
        for e in errors + list(result.get("errors", [])):
            print(f"  [!] skipped {e}")
        if result["imported"] == 0 and result.get("errors") and not args.skip_invalid:
            _err("import aborted: no changes written")
            return EXIT_USAGE
        vault.save()
    except VaultError as exc:
        _err(str(exc))
        return EXIT_VAULT
    finally:
        vault.lock()
    print(f"[✔] Imported {result['imported']} entr{'y' if result['imported'] == 1 else 'ies'}, "
          f"skipped {result['skipped'] + len(errors)}.")
    print("    Reminder: delete the plaintext CSV now that it is in the vault.")
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    vault = _open(args)
    if vault is None:
        return EXIT_VAULT
    try:
        rows = vault.list_entries()
        cipher_disp = vault.cipher_display
    finally:
        vault.lock()
    if not rows:
        print(f"(vault is empty) [mode: {cipher_disp}]")
        return EXIT_OK
    width = max(len(r["target"]) for r in rows)
    print(f"{'TARGET'.ljust(width)}  KIND     USERNAME          NOTE")
    for r in rows:
        print(f"{r['target'].ljust(width)}  {r['kind'].ljust(8)} {r['username'][:16].ljust(17)} {r['note']}")
    print(f"\n{len(rows)} entr{'y' if len(rows) == 1 else 'ies'} [mode: {cipher_disp}] (passwords are never displayed)")
    return EXIT_OK


def cmd_info(args: argparse.Namespace) -> int:
    vault = _open(args)
    if vault is None:
        return EXIT_VAULT
    try:
        print(f"Vault path:    {vault.path}")
        print(f"Cipher:        {vault.cipher} ({vault.cipher_display})")
        print(f"Entries:       {vault.entry_count}")
        print(f"AES available: {'yes' if is_aes_available() else 'no'}")
    finally:
        vault.lock()
    return EXIT_OK


def cmd_remove(args: argparse.Namespace) -> int:
    vault = _open(args)
    if vault is None:
        return EXIT_VAULT
    try:
        removed = vault.remove_entry(args.target)
        if removed:
            vault.save()
    finally:
        vault.lock()
    if not removed:
        _err(f"no entry for {args.target}")
        return EXIT_VAULT
    print(f"[✔] Removed {args.target}")
    return EXIT_OK


def cmd_resolve(args: argparse.Namespace) -> int:
    vault = _open(args)
    if vault is None:
        return EXIT_VAULT
    try:
        for t in args.targets:
            kind = vault.resolve_kind(t)
            pair = vault.resolve(t)
            if pair is None:
                print(f"{t}: (no match)")
            else:
                print(f"{t}: {kind} -> user {pair[0]}")
    finally:
        vault.lock()
    return EXIT_OK


def cmd_change_passphrase(args: argparse.Namespace) -> int:
    vault = _open(args)
    if vault is None:
        return EXIT_VAULT
    try:
        if not _interactive():
            _err("change-passphrase requires an interactive terminal")
            return EXIT_USAGE
        p1 = getpass.getpass("New vault passphrase: ")
        p2 = getpass.getpass("Confirm new passphrase: ")
        if p1 != p2:
            _err("passphrases do not match")
            return EXIT_USAGE
        vault.change_passphrase(p1)
    except VaultError as exc:
        _err(str(exc))
        return EXIT_VAULT
    finally:
        vault.lock()
    print("[✔] Passphrase changed.")
    return EXIT_OK


def cmd_template(_args: argparse.Namespace) -> int:
    sys.stdout.write(CSV_TEMPLATE)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m vcf_hci.vault",
        description="Manage the optional encrypted local BMC credential vault (off by default).",
    )
    p.add_argument("--vault", default=DEFAULT_VAULT_PATH, help=f"Vault file path (default: {DEFAULT_VAULT_PATH})")
    p.add_argument("--passphrase-env", default=None, metavar="VAR",
                   help="Environment variable holding the vault passphrase (otherwise prompt)")
    sub = p.add_subparsers(dest="cmd")
    sub.required = True

    sub.add_parser("init", help="Create a new, empty vault").set_defaults(fn=cmd_init)

    sp = sub.add_parser("add", help="Add or replace one entry (password prompted or via --password-env)")
    sp.add_argument("--target", required=True, help="IP, CIDR, hostname, IPv4 range a.b.c.d-e, or 'default'")
    sp.add_argument("--username", required=True)
    sp.add_argument("--password-env", default=None, metavar="VAR")
    sp.add_argument("--note", default="")
    sp.set_defaults(fn=cmd_add)

    sp = sub.add_parser("import-csv", help="Bulk import from CSV (target,username,password[,note])")
    sp.add_argument("file")
    sp.add_argument("--replace", action="store_true", help="Delete all existing entries first")
    sp.add_argument("--skip-invalid", action="store_true", help="Import valid rows even if some rows are invalid")
    sp.set_defaults(fn=cmd_import_csv)

    sub.add_parser("list", help="List entries (never shows passwords)").set_defaults(fn=cmd_list)
    sub.add_parser("info", help="Show vault metadata and cipher mode").set_defaults(fn=cmd_info)

    sp = sub.add_parser("remove", help="Remove one entry")
    sp.add_argument("--target", required=True)
    sp.set_defaults(fn=cmd_remove)

    sp = sub.add_parser("resolve", help="Show which entry would be used for each target")
    sp.add_argument("targets", nargs="+")
    sp.set_defaults(fn=cmd_resolve)

    sub.add_parser("change-passphrase", help="Re-encrypt the vault under a new passphrase").set_defaults(fn=cmd_change_passphrase)
    sub.add_parser("template", help="Print a CSV template to stdout").set_defaults(fn=cmd_template)
    register_jump_commands(sub, _open)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.vault = os.path.expanduser(args.vault)
    try:
        return int(args.fn(args))
    except KeyboardInterrupt:
        print()
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
