"""Tests for app.format.header.

Header.read_from must never raise anything other than FormatError /
UnsupportedVersionError / UnsupportedAlgorithmError, no matter what bytes it
is fed.
"""

from __future__ import annotations

import io

import pytest

from app.core.errors import FormatError, UnsupportedAlgorithmError, UnsupportedVersionError
from app.crypto.cipher import ALGO_AES_256_GCM, ALGO_XCHACHA20_POLY1305
from app.crypto.kdf import Argon2Params
from app.format.constants import FIXED_HEADER_LEN
from app.format.header import Header

PARAMS = Argon2Params(memory_cost_kib=8, time_cost=1, parallelism=1)
SALT = bytes(range(16))


def make_header(aead_id: int = ALGO_XCHACHA20_POLY1305, chunk_size: int = 1024) -> Header:
    return Header(aead_id=aead_id, chunk_size=chunk_size, argon2_params=PARAMS, salt=SALT)


def test_pack_length_is_fixed_plus_params_plus_salt() -> None:
    h = make_header()
    assert len(h.pack()) == FIXED_HEADER_LEN + 13 + 16


def test_roundtrip_via_stream() -> None:
    h = make_header(chunk_size=2_097_152)
    stream = io.BytesIO(h.pack())
    parsed = Header.read_from(stream)
    assert parsed == h


@pytest.mark.parametrize("aead_id", [ALGO_XCHACHA20_POLY1305, ALGO_AES_256_GCM])
def test_roundtrip_both_algorithms(aead_id: int) -> None:
    h = make_header(aead_id=aead_id)
    parsed = Header.read_from(io.BytesIO(h.pack()))
    assert parsed.aead_id == aead_id


def test_associated_data_equals_pack() -> None:
    h = make_header()
    assert h.associated_data == h.pack()


def test_trailing_bytes_after_header_are_not_consumed() -> None:
    h = make_header()
    stream = io.BytesIO(h.pack() + b"REST-OF-FILE")
    parsed = Header.read_from(stream)
    assert parsed == h
    assert stream.read() == b"REST-OF-FILE"


# --- corruption / fuzz-safety cases -----------------------------------------


def test_bad_magic_rejected() -> None:
    blob = bytearray(make_header().pack())
    blob[0:4] = b"NOPE"
    with pytest.raises(FormatError, match="magic"):
        Header.read_from(io.BytesIO(bytes(blob)))


def test_unknown_version_rejected() -> None:
    blob = bytearray(make_header().pack())
    blob[4] = 99  # format_version low byte
    with pytest.raises(UnsupportedVersionError):
        Header.read_from(io.BytesIO(bytes(blob)))


def test_unknown_kdf_id_rejected() -> None:
    blob = bytearray(make_header().pack())
    blob[6] = 250
    with pytest.raises(UnsupportedAlgorithmError):
        Header.read_from(io.BytesIO(bytes(blob)))


def test_unknown_aead_id_rejected() -> None:
    blob = bytearray(make_header().pack())
    blob[7] = 250
    with pytest.raises(UnsupportedAlgorithmError):
        Header.read_from(io.BytesIO(bytes(blob)))


def test_wrong_kdf_params_len_rejected() -> None:
    blob = bytearray(make_header().pack())
    blob[8] = 99
    with pytest.raises(FormatError, match="kdf_params_len"):
        Header.read_from(io.BytesIO(bytes(blob)))


def test_wrong_salt_len_rejected() -> None:
    blob = bytearray(make_header().pack())
    blob[9] = 5
    with pytest.raises(FormatError, match="salt_len"):
        Header.read_from(io.BytesIO(bytes(blob)))


def test_chunk_size_zero_rejected() -> None:
    blob = bytearray(make_header().pack())
    blob[10:14] = (0).to_bytes(4, "little")
    with pytest.raises(FormatError, match="chunk_size"):
        Header.read_from(io.BytesIO(bytes(blob)))


def test_absurd_chunk_size_rejected_without_huge_allocation() -> None:
    blob = bytearray(make_header().pack())
    blob[10:14] = (0xFFFFFFFF).to_bytes(4, "little")
    with pytest.raises(FormatError, match="chunk_size"):
        Header.read_from(io.BytesIO(bytes(blob)))


def test_nonzero_reserved_field_rejected() -> None:
    blob = bytearray(make_header().pack())
    blob[14:16] = (1).to_bytes(2, "little")
    with pytest.raises(FormatError, match="reserved"):
        Header.read_from(io.BytesIO(bytes(blob)))


def test_nonzero_argon2_reserved_field_rejected() -> None:
    blob = bytearray(make_header().pack())
    # reserved bytes of the argon2 params block: offset 16+11 .. 16+12
    blob[16 + 11 : 16 + 13] = (7).to_bytes(2, "little")
    with pytest.raises(FormatError, match="reserved"):
        Header.read_from(io.BytesIO(bytes(blob)))


def test_absurd_memory_cost_rejected_without_hanging() -> None:
    """Regression test: memory_cost_kib is read straight from the file and
    wasn't bounded above, so a single flipped bit turning it into a huge
    value made the KDF call inside decrypt/verify hang for a very long time
    on a corrupted or malicious file instead of parsing failing fast (see
    tests/test_kdf.py::test_oversized_params_from_a_corrupted_header_are_rejected_instantly
    for the underlying Argon2Params-level test)."""
    blob = bytearray(make_header().pack())
    blob[16 : 16 + 4] = (0xFFFFFFFF).to_bytes(4, "little")  # memory_cost_kib
    with pytest.raises(FormatError, match="invalid KDF params"):
        Header.read_from(io.BytesIO(bytes(blob)))


def test_absurd_time_cost_rejected_without_hanging() -> None:
    blob = bytearray(make_header().pack())
    blob[16 + 4 : 16 + 8] = (0xFFFFFFFF).to_bytes(4, "little")  # time_cost
    with pytest.raises(FormatError, match="invalid KDF params"):
        Header.read_from(io.BytesIO(bytes(blob)))


def test_invalid_argon2_type_in_bytes_rejected() -> None:
    blob = bytearray(make_header().pack())
    blob[16 + 10] = 1  # argon2_type byte -> Argon2i, not supported
    with pytest.raises(FormatError, match="invalid KDF params"):
        Header.read_from(io.BytesIO(bytes(blob)))


@pytest.mark.parametrize("truncate_to", [0, 1, 4, 8, 15, 20, 28])
def test_truncated_header_rejected(truncate_to: int) -> None:
    blob = make_header().pack()[:truncate_to]
    with pytest.raises(FormatError, match="unexpected end of stream"):
        Header.read_from(io.BytesIO(blob))


def test_empty_stream_rejected() -> None:
    with pytest.raises(FormatError):
        Header.read_from(io.BytesIO(b""))


def test_random_garbage_never_crashes() -> None:
    """Fuzz-safety smoke test: random bytes only ever raise our typed errors."""
    import contextlib
    import os

    for _ in range(200):
        blob = os.urandom(64)
        with contextlib.suppress(FormatError, UnsupportedVersionError, UnsupportedAlgorithmError):
            Header.read_from(io.BytesIO(blob))
