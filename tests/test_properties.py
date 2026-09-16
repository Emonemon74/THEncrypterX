"""Property-based tests (Hypothesis).

Where tests/test_security.py checks specific, hand-picked scenarios, these
tests check properties that should hold for *any* input: Hypothesis
generates hundreds of random plaintexts, passwords, and corruption points
and checks the property holds for every one it tries.

`suppress_health_check=[HealthCheck.function_scoped_fixture]` is used
because `tmp_path` is a function-scoped pytest fixture that Hypothesis
reuses across all examples of one test - each example fully writes, reads,
and asserts before the next one runs, so reusing the same directory is safe
here even though Hypothesis normally warns against it.
"""

from __future__ import annotations

from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.core.errors import ThexError
from app.crypto.kdf import Argon2Params
from app.files.decrypt import decrypt_file
from app.files.encrypt import encrypt_file

CHEAP = Argon2Params(memory_cost_kib=8, time_cost=1, parallelism=1)
_SUPPRESS = [HealthCheck.function_scoped_fixture]


# max_examples and max data/chunk sizes are deliberately modest: every
# example does 2-4 real file writes through atomic_writer, each ending in an
# fsync, so this is I/O-bound rather than CPU-bound. A chunk_size floor of 8
# (not 1) avoids the pathological "thousands of 1-byte chunks" case, which
# buys nothing property-wise but multiplies the number of fsync calls.
@settings(max_examples=20, deadline=None, suppress_health_check=_SUPPRESS)
@given(
    data=st.binary(max_size=2000),
    password=st.text(min_size=1, max_size=80),
    chunk_size=st.integers(min_value=8, max_value=64),
)
def test_property_roundtrip(tmp_path: Path, data: bytes, password: str, chunk_size: int) -> None:
    """decrypt(encrypt(data, password), password) == data, for any data/password."""
    src = tmp_path / "in.bin"
    src.write_bytes(data)
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"

    encrypt_file(src, enc, password, argon2_params=CHEAP, chunk_size=chunk_size)
    metadata = decrypt_file(enc, dec, password)

    assert dec.read_bytes() == data
    assert metadata.original_size == len(data)


@settings(max_examples=20, deadline=None, suppress_health_check=_SUPPRESS)
@given(
    data=st.binary(min_size=1, max_size=800),
    password=st.text(min_size=1, max_size=40),
    draw_point=st.data(),
)
def test_property_any_single_bit_flip_is_caught(
    tmp_path: Path, data: bytes, password: str, draw_point: st.DataObject
) -> None:
    """Flipping any single bit anywhere in a valid .thex file must cause a
    typed failure (never a crash, and never a silent wrong success) and must
    never leave output behind.
    """
    src = tmp_path / "in.bin"
    src.write_bytes(data)
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, password, argon2_params=CHEAP, chunk_size=32)

    raw = bytearray(enc.read_bytes())
    byte_index = draw_point.draw(st.integers(min_value=0, max_value=len(raw) - 1))
    bit = draw_point.draw(st.integers(min_value=0, max_value=7))
    raw[byte_index] ^= 1 << bit
    enc.write_bytes(bytes(raw))

    dec = tmp_path / "dec.bin"
    try:
        decrypt_file(enc, dec, password)
    except ThexError:
        pass
    else:
        raise AssertionError("a single-bit-flipped file decrypted without error")
    assert not dec.exists()


@settings(max_examples=15, deadline=None, suppress_health_check=_SUPPRESS)
@given(data=st.binary(max_size=500), password=st.text(min_size=1, max_size=40))
def test_property_encrypting_twice_gives_different_ciphertext(
    tmp_path: Path, data: bytes, password: str
) -> None:
    """Fresh randomness (salt + nonces) means encrypting the same data with
    the same password twice never produces the same file - even though both
    decrypt back to the same plaintext.
    """
    src = tmp_path / "in.bin"
    src.write_bytes(data)
    enc1 = tmp_path / "out1.thex"
    enc2 = tmp_path / "out2.thex"

    encrypt_file(src, enc1, password, argon2_params=CHEAP, chunk_size=64)
    encrypt_file(src, enc2, password, argon2_params=CHEAP, chunk_size=64)

    assert enc1.read_bytes() != enc2.read_bytes()

    dec1, dec2 = tmp_path / "d1.bin", tmp_path / "d2.bin"
    decrypt_file(enc1, dec1, password)
    decrypt_file(enc2, dec2, password)
    assert dec1.read_bytes() == dec2.read_bytes() == data
