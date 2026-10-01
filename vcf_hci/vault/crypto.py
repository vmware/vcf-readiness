"""
VCF Readiness Tool — Credential Vault cryptographic primitives (vcf_hci.vault.crypto)

Authenticated encryption for the optional local credential vault with dual-mode support:
1. NIST AES-256-GCM via 'pycryptodomex' / 'pycryptodome' when available (hardware accelerated).
2. Pure standard-library Encrypt-then-MAC fallback (HMAC-SHA256-CTR + HMAC-SHA256-EtM).

This module performs NO file or network I/O.

Why dual-cipher?
    The Python standard library ships no AES implementation, and this project is
    stdlib-only by default. When 'pycryptodomex' is installed (or bundled in binary
    distributions), new vaults default to standard AES-256-GCM. When running from
    source on a bare host without external wheels, the vault falls back cleanly to
    the OpenSSL-backed HMAC-SHA256 counter mode PRF stream cipher with Encrypt-then-MAC.
    Both ciphers verify integrity and authenticity (AEAD / EtM) before decrypting.

Security notes:
    * The nonce MUST never repeat under the same key.
    * Callers must treat ``VaultAuthError`` as "wrong passphrase OR tampered
      file" and must not distinguish the two to the user.
"""

import hashlib
import hmac
import importlib
import secrets
import struct
from typing import Optional, Tuple

PBKDF2_ITERATIONS = 600_000
SALT_LEN = 16
NONCE_LEN = 16
KEY_LEN = 32
TAG_LEN = 32

AES_GCM_NONCE_LEN = 12
AES_GCM_TAG_LEN = 16

KDF_NAME = "pbkdf2-hmac-sha256"
CIPHER_AES_256_GCM = "aes-256-gcm"
CIPHER_HMAC_SHA256 = "hmac-sha256-ctr+hmac-sha256-etm"
CIPHER_NAME = CIPHER_HMAC_SHA256  # legacy alias
SUPPORTED_CIPHERS = (CIPHER_AES_256_GCM, CIPHER_HMAC_SHA256)

_ENC_LABEL = b"vcf-vault-enc-v1"
_MAC_LABEL = b"vcf-vault-mac-v1"
_AES_GCM_LABEL = b"vcf-vault-aes-gcm-v1"


def _get_aes_module():
    """Dynamically load AES cipher module from pycryptodomex or pycryptodome if installed."""
    for mod_name in ("Cryptodome.Cipher.AES", "Crypto.Cipher.AES"):
        try:
            return importlib.import_module(mod_name)
        except (ImportError, AttributeError, ValueError):
            continue
    return None


def is_aes_available() -> bool:
    """Return True if pycryptodomex or pycryptodome is available for AES-256-GCM."""
    return _get_aes_module() is not None


def get_default_cipher() -> str:
    """Return default cipher for new vaults: AES-256-GCM if available, else stdlib HMAC-SHA256."""
    return CIPHER_AES_256_GCM if is_aes_available() else CIPHER_HMAC_SHA256


def cipher_display_name(cipher: Optional[str]) -> str:
    """Return a human-readable display label for the cipher."""
    if cipher == CIPHER_AES_256_GCM:
        return "AES-256-GCM"
    if cipher == CIPHER_HMAC_SHA256:
        return "HMAC-SHA256 (Stdlib)"
    return str(cipher or "Unknown")


class VaultCryptoError(Exception):
    """Base class for vault cryptographic failures."""


class VaultAuthError(VaultCryptoError):
    """Authentication failed: wrong passphrase or tampered data."""


def new_salt() -> bytes:
    """Return a fresh random KDF salt."""
    return secrets.token_bytes(SALT_LEN)


def derive_master_key(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive the 32-byte master key from a passphrase and salt (PBKDF2-HMAC-SHA256)."""
    if not isinstance(passphrase, str):
        raise VaultCryptoError("passphrase must be a str")
    if len(salt) < 8:
        raise VaultCryptoError("salt too short")
    if iterations < 100_000:
        raise VaultCryptoError("iteration count below safety floor")
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=KEY_LEN)


def _subkey(master: bytes, label: bytes) -> bytes:
    return hmac.new(master, label, hashlib.sha256).digest()


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < length:
        out += hmac.new(enc_key, nonce + struct.pack(">Q", ctr), hashlib.sha256).digest()
        ctr += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    if not a:
        return b""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _check_master(master: bytes) -> None:
    if not isinstance(master, (bytes, bytearray)) or len(master) != KEY_LEN:
        raise VaultCryptoError("master key must be %d bytes" % KEY_LEN)


def _encrypt_aes_gcm(master: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes, bytes]:
    aes = _get_aes_module()
    if aes is None:
        raise VaultCryptoError(
            "AES-256-GCM encryption requires 'pycryptodomex'. "
            "Install it via: pip install pycryptodomex"
        )
    key = _subkey(master, _AES_GCM_LABEL)
    nonce = secrets.token_bytes(AES_GCM_NONCE_LEN)
    cipher = aes.new(key, aes.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(bytes(aad))
    ct, tag = cipher.encrypt_and_digest(bytes(plaintext))
    return nonce, ct, tag


def _decrypt_aes_gcm(master: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    aes = _get_aes_module()
    if aes is None:
        raise VaultCryptoError(
            "Vault is encrypted with AES-256-GCM. "
            "Install 'pycryptodomex' to unlock: pip install pycryptodomex"
        )
    if len(nonce) != AES_GCM_NONCE_LEN or len(tag) != AES_GCM_TAG_LEN:
        raise VaultAuthError("authentication failed")
    key = _subkey(master, _AES_GCM_LABEL)
    try:
        cipher = aes.new(key, aes.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(bytes(aad))
        return cipher.decrypt_and_verify(bytes(ciphertext), bytes(tag))
    except (ValueError, KeyError):
        raise VaultAuthError("authentication failed") from None


def encrypt(
    master: bytes,
    plaintext: bytes,
    aad: bytes,
    cipher: Optional[str] = None,
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt-then-MAC / AEAD. Returns ``(nonce, ciphertext, tag)``.

    ``aad`` (additional authenticated data) is bound into the tag but not
    encrypted; the vault passes its serialized header so header tampering
    (e.g. lowering the KDF iteration count) is detected.
    """
    _check_master(master)
    if cipher == CIPHER_AES_256_GCM:
        return _encrypt_aes_gcm(master, plaintext, aad)
    if cipher is None or cipher == CIPHER_HMAC_SHA256:
        nonce = secrets.token_bytes(NONCE_LEN)
        ct = _xor(bytes(plaintext), _keystream(_subkey(master, _ENC_LABEL), nonce, len(plaintext)))
        tag = hmac.new(_subkey(master, _MAC_LABEL), bytes(aad) + nonce + ct, hashlib.sha256).digest()
        return nonce, ct, tag
    raise VaultCryptoError(f"unsupported cipher: {cipher}")


def decrypt(
    master: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes,
    cipher: Optional[str] = None,
) -> bytes:
    """Verify the tag in constant time, then decrypt. Raises ``VaultAuthError`` on mismatch."""
    _check_master(master)
    if cipher == CIPHER_AES_256_GCM or (
        cipher is None and len(nonce) == AES_GCM_NONCE_LEN and len(tag) == AES_GCM_TAG_LEN
    ):
        return _decrypt_aes_gcm(master, nonce, ciphertext, tag, aad)
    if cipher is None or cipher == CIPHER_HMAC_SHA256:
        if len(nonce) != NONCE_LEN or len(tag) != TAG_LEN:
            raise VaultAuthError("authentication failed")
        expected = hmac.new(
            _subkey(master, _MAC_LABEL), bytes(aad) + bytes(nonce) + bytes(ciphertext), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, bytes(tag)):
            raise VaultAuthError("authentication failed")
        return _xor(bytes(ciphertext), _keystream(_subkey(master, _ENC_LABEL), bytes(nonce), len(ciphertext)))
    raise VaultCryptoError(f"unsupported cipher: {cipher}")

