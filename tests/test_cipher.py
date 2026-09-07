"""Tests for app.crypto.cipher.

The security properties proved here are the foundation the whole format rests
on: tamper anything and decryption fails loudly.
"""

from __future__ import annotations

import os

import pytest

from app.core.errors import AuthenticationError
from app.crypto.cipher import (
    ALGO_AES_256_GCM,
    ALGO_XCHACHA20_POLY1305,
    key_size,
    nonce_size,
    open_,
    seal,
    tag_size,
)

ALGOS = [ALGO_XCHACHA20_POLY1305, ALGO_AES_256_GCM]


def _fresh(algo: int) -> tuple[bytes, bytes]:
    return os.urandom(key_size(algo)), os.urandom(nonce_size(algo))


@pytest.mark.parametrize("algo", ALGOS)
def test_roundtrip(algo: int) -> None:
    key, nonce = _fresh(algo)
    pt = b"the quick brown fox"
    ct = seal(algo, key, nonce, pt, b"header-AD")
    assert open_(algo, key, nonce, ct, b"header-AD") == pt


@pytest.mark.parametrize("algo", ALGOS)
def test_ciphertext_is_not_plaintext(algo: int) -> None:
    key, nonce = _fresh(algo)
    pt = b"A" * 32
    ct = seal(algo, key, nonce, pt, b"")
    assert pt not in ct
    assert len(ct) == len(pt) + tag_size(algo)


@pytest.mark.parametrize("algo", ALGOS)
def test_empty_plaintext_roundtrips(algo: int) -> None:
    key, nonce = _fresh(algo)
    ct = seal(algo, key, nonce, b"", b"ad")
    assert open_(algo, key, nonce, ct, b"ad") == b""


@pytest.mark.parametrize("algo", ALGOS)
def test_wrong_key_fails(algo: int) -> None:
    key, nonce = _fresh(algo)
    ct = seal(algo, key, nonce, b"secret", b"")
    other_key = os.urandom(key_size(algo))
    with pytest.raises(AuthenticationError):
        open_(algo, other_key, nonce, ct, b"")


@pytest.mark.parametrize("algo", ALGOS)
def test_modified_ciphertext_fails(algo: int) -> None:
    key, nonce = _fresh(algo)
    ct = bytearray(seal(algo, key, nonce, b"secret message", b""))
    ct[0] ^= 0x01
    with pytest.raises(AuthenticationError):
        open_(algo, key, nonce, bytes(ct), b"")


@pytest.mark.parametrize("algo", ALGOS)
def test_modified_tag_fails(algo: int) -> None:
    key, nonce = _fresh(algo)
    ct = bytearray(seal(algo, key, nonce, b"secret", b""))
    ct[-1] ^= 0x80
    with pytest.raises(AuthenticationError):
        open_(algo, key, nonce, bytes(ct), b"")


@pytest.mark.parametrize("algo", ALGOS)
def test_modified_nonce_fails(algo: int) -> None:
    key, nonce = _fresh(algo)
    ct = seal(algo, key, nonce, b"secret", b"")
    bad_nonce = bytearray(nonce)
    bad_nonce[0] ^= 0x01
    with pytest.raises(AuthenticationError):
        open_(algo, key, bytes(bad_nonce), ct, b"")


@pytest.mark.parametrize("algo", ALGOS)
def test_modified_associated_data_fails(algo: int) -> None:
    key, nonce = _fresh(algo)
    ct = seal(algo, key, nonce, b"secret", b"header-v1")
    with pytest.raises(AuthenticationError):
        open_(algo, key, nonce, ct, b"header-v2")


@pytest.mark.parametrize("algo", ALGOS)
def test_fresh_nonce_changes_ciphertext(algo: int) -> None:
    key = os.urandom(key_size(algo))
    pt = b"same plaintext both times"
    c1 = seal(algo, key, os.urandom(nonce_size(algo)), pt, b"")
    c2 = seal(algo, key, os.urandom(nonce_size(algo)), pt, b"")
    assert c1 != c2


@pytest.mark.parametrize("algo", ALGOS)
def test_truncated_ciphertext_fails(algo: int) -> None:
    key, nonce = _fresh(algo)
    ct = seal(algo, key, nonce, b"secret", b"")
    with pytest.raises(AuthenticationError):
        open_(algo, key, nonce, ct[:8], b"")


@pytest.mark.parametrize("algo", ALGOS)
def test_bad_key_length_rejected(algo: int) -> None:
    _, nonce = _fresh(algo)
    with pytest.raises(ValueError, match="key"):
        seal(algo, b"short", nonce, b"x", b"")


@pytest.mark.parametrize("algo", ALGOS)
def test_bad_nonce_length_rejected(algo: int) -> None:
    key = os.urandom(key_size(algo))
    with pytest.raises(ValueError, match="nonce"):
        seal(algo, key, b"short", b"x", b"")


def test_unknown_algo_rejected() -> None:
    with pytest.raises(ValueError, match="unknown AEAD id"):
        nonce_size(99)


def test_nonce_sizes() -> None:
    assert nonce_size(ALGO_XCHACHA20_POLY1305) == 24
    assert nonce_size(ALGO_AES_256_GCM) == 12
