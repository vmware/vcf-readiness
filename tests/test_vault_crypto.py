"""Tests for vcf_hci/vault/crypto.py — stdlib-only Encrypt-then-MAC primitives."""
import hashlib
import hmac
import os
import time

import pytest

from vcf_hci.vault.crypto import (
    AES_GCM_NONCE_LEN,
    AES_GCM_TAG_LEN,
    CIPHER_AES_256_GCM,
    CIPHER_HMAC_SHA256,
    KEY_LEN,
    NONCE_LEN,
    SUPPORTED_CIPHERS,
    TAG_LEN,
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

SALT = b"\x01" * 16
MASTER = derive_master_key("correct horse battery staple", SALT, iterations=100_000)
OTHER = derive_master_key("correct horse battery stable", SALT, iterations=100_000)
AAD = b'{"format":"vcf-readiness-vault","version":1}'


@pytest.mark.parametrize(
    "plaintext",
    [b"", b"x", b"hello world", b"\xa5" * 1000, b"\x5a" * 65],
    ids=["empty", "single", "short", "large1000", "large65"],
)
def test_round_trip(plaintext):
    nonce, ct, tag = encrypt(MASTER, plaintext, AAD)
    assert len(nonce) == NONCE_LEN and len(tag) == TAG_LEN and len(ct) == len(plaintext)
    assert decrypt(MASTER, nonce, ct, tag, AAD) == plaintext


def test_large_payload_is_fast():
    data = os.urandom(1024 * 1024)
    t0 = time.time()
    nonce, ct, tag = encrypt(MASTER, data, AAD)
    assert decrypt(MASTER, nonce, ct, tag, AAD) == data
    assert time.time() - t0 < 3.0


def test_nonce_freshness_and_ciphertext_differs():
    n1, c1, _ = encrypt(MASTER, b"same plaintext", AAD)
    n2, c2, _ = encrypt(MASTER, b"same plaintext", AAD)
    assert n1 != n2
    assert c1 != c2


def test_ciphertext_not_plaintext():
    _, ct, _ = encrypt(MASTER, b"SuperSecretPassword!", AAD)
    assert b"SuperSecret" not in ct


def test_wrong_key_rejected():
    nonce, ct, tag = encrypt(MASTER, b"secret", AAD)
    with pytest.raises(VaultAuthError):
        decrypt(OTHER, nonce, ct, tag, AAD)


@pytest.mark.parametrize("field", ["nonce", "ct", "tag", "aad"])
def test_tamper_detection(field):
    nonce, ct, tag = encrypt(MASTER, b"payload-of-some-length", AAD)
    parts = {"nonce": bytearray(nonce), "ct": bytearray(ct), "tag": bytearray(tag), "aad": bytearray(AAD)}
    parts[field][0] ^= 0x01
    with pytest.raises(VaultAuthError):
        decrypt(MASTER, bytes(parts["nonce"]), bytes(parts["ct"]), bytes(parts["tag"]), bytes(parts["aad"]))


def test_truncated_tag_rejected():
    nonce, ct, tag = encrypt(MASTER, b"payload", AAD)
    with pytest.raises(VaultAuthError):
        decrypt(MASTER, nonce, ct, tag[:-1], AAD)


def test_derive_master_key_deterministic_and_salt_sensitive():
    k1 = derive_master_key("passphrase-abc", SALT, iterations=100_000)
    k2 = derive_master_key("passphrase-abc", SALT, iterations=100_000)
    k3 = derive_master_key("passphrase-abc", b"\x02" * 16, iterations=100_000)
    assert k1 == k2 and k1 != k3 and len(k1) == KEY_LEN


def test_new_salt_random():
    assert new_salt() != new_salt()
    assert len(new_salt()) == 16


def test_iteration_floor_and_bad_master():
    with pytest.raises(VaultCryptoError):
        derive_master_key("x" * 20, SALT, iterations=1000)
    with pytest.raises(VaultCryptoError):
        encrypt(b"short", b"data", AAD)


def test_cipher_constants_and_helpers():
    assert CIPHER_AES_256_GCM in SUPPORTED_CIPHERS
    assert CIPHER_HMAC_SHA256 in SUPPORTED_CIPHERS
    assert cipher_display_name(CIPHER_AES_256_GCM) == "AES-256-GCM"
    assert cipher_display_name(CIPHER_HMAC_SHA256) == "HMAC-SHA256 (Stdlib)"
    assert cipher_display_name(None) == "Unknown"


def test_aes_missing_behavior(monkeypatch):
    from vcf_hci.vault import crypto
    monkeypatch.setattr(crypto, "_get_aes_module", lambda: None)
    assert not is_aes_available()
    assert get_default_cipher() == CIPHER_HMAC_SHA256
    with pytest.raises(VaultCryptoError) as exc_enc:
        encrypt(MASTER, b"secret", AAD, cipher=CIPHER_AES_256_GCM)
    assert "pycryptodomex" in str(exc_enc.value)
    with pytest.raises(VaultCryptoError) as exc_dec:
        decrypt(MASTER, b"\x00" * AES_GCM_NONCE_LEN, b"ct", b"\x00" * AES_GCM_TAG_LEN, AAD, cipher=CIPHER_AES_256_GCM)
    assert "pycryptodomex" in str(exc_dec.value)


class _MockAESCipher:
    def __init__(self, key, mode, nonce):
        self.key = key
        self.mode = mode
        self.nonce = nonce
        self.aad = b""

    def update(self, data):
        self.aad += bytes(data)

    def encrypt_and_digest(self, plaintext):
        ct = bytes(b ^ 0x5a for b in plaintext)
        tag = hashlib.sha256(self.key + self.nonce + self.aad + ct).digest()[:16]
        return ct, tag

    def decrypt_and_verify(self, ciphertext, tag):
        expected_tag = hashlib.sha256(self.key + self.nonce + self.aad + bytes(ciphertext)).digest()[:16]
        if not hmac.compare_digest(expected_tag, bytes(tag)):
            raise ValueError("MAC check failed")
        return bytes(b ^ 0x5a for b in ciphertext)


class _MockAESModule:
    MODE_GCM = 9

    @staticmethod
    def new(key, mode, nonce):
        return _MockAESCipher(key, mode, nonce)


def test_aes_gcm_round_trip_and_tampering(monkeypatch):
    from vcf_hci.vault import crypto
    monkeypatch.setattr(crypto, "_get_aes_module", lambda: _MockAESModule)
    assert is_aes_available()
    assert get_default_cipher() == CIPHER_AES_256_GCM

    plaintext = b"super confidential payload"
    nonce, ct, tag = encrypt(MASTER, plaintext, AAD, cipher=CIPHER_AES_256_GCM)
    assert len(nonce) == AES_GCM_NONCE_LEN
    assert len(tag) == AES_GCM_TAG_LEN
    assert ct != plaintext

    decrypted = decrypt(MASTER, nonce, ct, tag, AAD, cipher=CIPHER_AES_256_GCM)
    assert decrypted == plaintext

    # Auto-detect cipher by nonce/tag length when cipher=None
    assert decrypt(MASTER, nonce, ct, tag, AAD) == plaintext

    # Tampering checks
    with pytest.raises(VaultAuthError):
        decrypt(MASTER, nonce, bytes(b ^ 0x01 for b in ct), tag, AAD, cipher=CIPHER_AES_256_GCM)
    with pytest.raises(VaultAuthError):
        decrypt(MASTER, nonce, ct, bytes(b ^ 0x01 for b in tag), AAD, cipher=CIPHER_AES_256_GCM)
    with pytest.raises(VaultAuthError):
        decrypt(MASTER, bytes(b ^ 0x01 for b in nonce), ct, tag, AAD, cipher=CIPHER_AES_256_GCM)
    with pytest.raises(VaultAuthError):
        decrypt(MASTER, nonce, ct, tag, AAD + b"tamper", cipher=CIPHER_AES_256_GCM)


def test_unsupported_cipher_rejected():
    with pytest.raises(VaultCryptoError) as exc_enc:
        encrypt(MASTER, b"payload", AAD, cipher="custom-unknown-cipher")
    assert "unsupported cipher" in str(exc_enc.value)
    with pytest.raises(VaultCryptoError) as exc_dec:
        decrypt(MASTER, b"\x00" * 16, b"ct", b"\x00" * 32, AAD, cipher="custom-unknown-cipher")
    assert "unsupported cipher" in str(exc_dec.value)
