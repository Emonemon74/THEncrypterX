"""Tests for app.crypto.keys."""

from __future__ import annotations

import pytest

from app.crypto.keys import SUBKEY_LEN, derive_subkeys, zeroize

MASTER = bytes(range(32))  # a fixed, valid 32-byte master key


def test_subkey_lengths() -> None:
    sk = derive_subkeys(MASTER)
    assert len(sk.meta_key) == SUBKEY_LEN
    assert len(sk.data_key) == SUBKEY_LEN


def test_subkeys_are_distinct() -> None:
    sk = derive_subkeys(MASTER)
    assert sk.meta_key != sk.data_key


def test_subkeys_differ_from_master() -> None:
    sk = derive_subkeys(MASTER)
    assert sk.meta_key != MASTER
    assert sk.data_key != MASTER


def test_derivation_is_deterministic() -> None:
    a = derive_subkeys(MASTER)
    b = derive_subkeys(MASTER)
    assert a == b


def test_different_master_gives_different_subkeys() -> None:
    other = bytes(range(1, 33))
    assert derive_subkeys(MASTER).data_key != derive_subkeys(other).data_key


def test_wrong_master_length_rejected() -> None:
    with pytest.raises(ValueError, match="master_key"):
        derive_subkeys(b"short")


def test_zeroize_wipes_buffer() -> None:
    buf = bytearray(b"super secret key material")
    zeroize(buf)
    assert buf == bytearray(len(buf))  # all zero bytes
