"""
VCF Readiness Tool — Optional Encrypted Local Credential Vault (vcf_hci.vault)

OFF BY DEFAULT.  Nothing here runs unless the user explicitly opts in via
``python -m vcf_hci.vault init``, ``vcfr_collector.py --vault``, or the
Web UI "Encrypted Credential Vault" card.

Layout:
    crypto.py      — stdlib-only PBKDF2 + HMAC-SHA256 Encrypt-then-MAC primitives
    store.py       — file format, atomic 0600 writes, entry management, resolver
    csv_import.py  — CSV text parser for bulk import
    __main__.py    — ``python -m vcf_hci.vault`` management commands

This package must never import ``vcf_hci.web``, ``compat_engine`` or ``bcg_links``.
"""

from vcf_hci.vault.crypto import VaultAuthError, VaultCryptoError
from vcf_hci.vault.csv_import import CSV_TEMPLATE, parse_credentials_csv
from vcf_hci.vault.providers import (
    BaseCredentialProvider,
    ChainedCredentialProvider,
    HashiCorpVaultProvider,
    LocalVaultProvider,
    SddcManagerSecretProvider,
)
from vcf_hci.vault.store import (
    DEFAULT_VAULT_PATH,
    MIN_PASSPHRASE_LEN,
    CredentialVault,
    VaultError,
    VaultExistsError,
    VaultFormatError,
    VaultNotFoundError,
    normalize_target,
)

__all__ = [
    "BaseCredentialProvider",
    "CSV_TEMPLATE",
    "ChainedCredentialProvider",
    "DEFAULT_VAULT_PATH",
    "HashiCorpVaultProvider",
    "LocalVaultProvider",
    "MIN_PASSPHRASE_LEN",
    "CredentialVault",
    "SddcManagerSecretProvider",
    "VaultAuthError",
    "VaultCryptoError",
    "VaultError",
    "VaultExistsError",
    "VaultFormatError",
    "VaultNotFoundError",
    "normalize_target",
    "parse_credentials_csv",
]
