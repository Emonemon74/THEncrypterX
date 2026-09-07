"""First Milestone (Build Guide Section 28).

Proves the three crypto primitives compose into a working encrypt/decrypt
path on an in-memory blob:

    password --Argon2id(salt)--> master_key --HKDF--> data_key
             --> XChaCha20-Poly1305 seal / open

No files, no container format yet - that is the next phase.
"""

from __future__ import annotations

import os

import pytest

from app.core.errors import AuthenticationError
from app.crypto.cipher import ALGO_XCHACHA20_POLY1305, nonce_size, open_, seal
from app.crypto.kdf import Argon2Params, derive_master_key, generate_salt
from app.crypto.keys import derive_subkeys

CHEAP = Argon2Params(memory_cost_kib=8, time_cost=1, parallelism=1)
ALGO = ALGO_XCHACHA20_POLY1305


def _encrypt(plaintext: bytes, password: str) -> tuple[bytes, bytes, bytes]:
    salt = generate_salt()
    master = derive_master_key(password, salt, CHEAP)
    data_key = derive_subkeys(master).data_key
    nonce = os.urandom(nonce_size(ALGO))
    ct = seal(ALGO, data_key, nonce, plaintext, b"AD")
    return salt, nonce, ct


def _decrypt(salt: bytes, nonce: bytes, ct: bytes, password: str) -> bytes:
    master = derive_master_key(password, salt, CHEAP)
    data_key = derive_subkeys(master).data_key
    return open_(ALGO, data_key, nonce, ct, b"AD")


def test_encrypt_then_decrypt_returns_original() -> None:
    salt, nonce, ct = _encrypt(b"top secret data", "hunter2")
    assert _decrypt(salt, nonce, ct, "hunter2") == b"top secret data"


def test_wrong_password_fails() -> None:
    salt, nonce, ct = _encrypt(b"top secret data", "hunter2")
    with pytest.raises(AuthenticationError):
        _decrypt(salt, nonce, ct, "wrong")


def test_modified_ciphertext_fails() -> None:
    salt, nonce, ct = _encrypt(b"top secret data", "hunter2")
    ct = bytearray(ct)
    ct[3] ^= 0x01
    with pytest.raises(AuthenticationError):
        _decrypt(salt, nonce, bytes(ct), "hunter2")


def test_modified_nonce_fails() -> None:
    salt, nonce, ct = _encrypt(b"top secret data", "hunter2")
    nonce = bytearray(nonce)
    nonce[0] ^= 0x01
    with pytest.raises(AuthenticationError):
        _decrypt(salt, bytes(nonce), ct, "hunter2")


def test_modified_associated_data_fails() -> None:
    salt = generate_salt()
    data_key = derive_subkeys(derive_master_key("pw", salt, CHEAP)).data_key
    nonce = os.urandom(nonce_size(ALGO))
    ct = seal(ALGO, data_key, nonce, b"data", b"AD-v1")
    with pytest.raises(AuthenticationError):
        open_(ALGO, data_key, nonce, ct, b"AD-v2")


def test_fresh_nonce_makes_ciphertext_differ() -> None:
    _, _, c1 = _encrypt(b"identical", "pw")
    _, _, c2 = _encrypt(b"identical", "pw")
    assert c1 != c2
