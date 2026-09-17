"""Tests for app.format.container."""

from __future__ import annotations

import io
import os

import pytest

from app.core.errors import AuthenticationError, FormatError
from app.crypto.cipher import (
    ALGO_AES_256_GCM,
    ALGO_XCHACHA20_POLY1305,
    key_size,
    nonce_size,
    open_,
    seal,
)
from app.format.container import (
    chunk_associated_data,
    read_footer_at_end,
    read_raw_frame,
    read_sealed_section,
    write_footer,
    write_raw_frame,
    write_sealed_section,
)

ALGOS = [ALGO_XCHACHA20_POLY1305, ALGO_AES_256_GCM]


# --- sealed section ----------------------------------------------------------


@pytest.mark.parametrize("algo", ALGOS)
def test_sealed_section_roundtrip(algo: int) -> None:
    key = os.urandom(key_size(algo))
    nonce = os.urandom(nonce_size(algo))
    stream = io.BytesIO()
    write_sealed_section(stream, algo, key, nonce, b"hello, container", b"AD")

    stream.seek(0)
    plaintext = read_sealed_section(stream, algo, key, b"AD", max_ciphertext_len=1024)
    assert plaintext == b"hello, container"


@pytest.mark.parametrize("algo", ALGOS)
def test_sealed_section_empty_plaintext(algo: int) -> None:
    key = os.urandom(key_size(algo))
    nonce = os.urandom(nonce_size(algo))
    stream = io.BytesIO()
    write_sealed_section(stream, algo, key, nonce, b"", b"AD")
    stream.seek(0)
    assert read_sealed_section(stream, algo, key, b"AD", max_ciphertext_len=1024) == b""


def test_sealed_section_wrong_key_fails() -> None:
    algo = ALGO_XCHACHA20_POLY1305
    key = os.urandom(key_size(algo))
    nonce = os.urandom(nonce_size(algo))
    stream = io.BytesIO()
    write_sealed_section(stream, algo, key, nonce, b"secret", b"AD")
    stream.seek(0)
    with pytest.raises(AuthenticationError):
        read_sealed_section(stream, algo, os.urandom(32), b"AD", max_ciphertext_len=1024)


def test_sealed_section_wrong_ad_fails() -> None:
    algo = ALGO_XCHACHA20_POLY1305
    key = os.urandom(key_size(algo))
    nonce = os.urandom(nonce_size(algo))
    stream = io.BytesIO()
    write_sealed_section(stream, algo, key, nonce, b"secret", b"AD-v1")
    stream.seek(0)
    with pytest.raises(AuthenticationError):
        read_sealed_section(stream, algo, key, b"AD-v2", max_ciphertext_len=1024)


def test_sealed_section_tampered_ciphertext_fails() -> None:
    algo = ALGO_XCHACHA20_POLY1305
    key = os.urandom(key_size(algo))
    nonce = os.urandom(nonce_size(algo))
    buf = io.BytesIO()
    write_sealed_section(buf, algo, key, nonce, b"secret", b"AD")
    blob = bytearray(buf.getvalue())
    blob[-1] ^= 0x01  # flip a bit in the tag
    with pytest.raises(AuthenticationError):
        read_sealed_section(io.BytesIO(bytes(blob)), algo, key, b"AD", max_ciphertext_len=1024)


def test_sealed_section_length_over_max_rejected() -> None:
    algo = ALGO_XCHACHA20_POLY1305
    key = os.urandom(key_size(algo))
    nonce = os.urandom(nonce_size(algo))
    stream = io.BytesIO()
    write_sealed_section(stream, algo, key, nonce, b"x" * 100, b"AD")
    stream.seek(0)
    with pytest.raises(FormatError, match="exceeds"):
        read_sealed_section(stream, algo, key, b"AD", max_ciphertext_len=8)


def test_sealed_section_truncated_rejected() -> None:
    algo = ALGO_XCHACHA20_POLY1305
    key = os.urandom(key_size(algo))
    nonce = os.urandom(nonce_size(algo))
    stream = io.BytesIO()
    write_sealed_section(stream, algo, key, nonce, b"secret data", b"AD")
    truncated = stream.getvalue()[:-3]
    with pytest.raises(FormatError, match="unexpected end of stream"):
        read_sealed_section(io.BytesIO(truncated), algo, key, b"AD", max_ciphertext_len=1024)


def test_sealed_section_length_shorter_than_tag_rejected() -> None:
    algo = ALGO_XCHACHA20_POLY1305
    key = os.urandom(key_size(algo))
    nonce = os.urandom(nonce_size(algo))
    # Hand-craft a frame claiming a ciphertext shorter than the 16-byte tag.
    blob = nonce + (5).to_bytes(4, "little") + b"short"
    with pytest.raises(FormatError, match="shorter than the auth tag"):
        read_sealed_section(io.BytesIO(blob), algo, key, b"AD", max_ciphertext_len=1024)


# --- raw frame (seal/read split for the parallel-worker pipeline) ------------


@pytest.mark.parametrize("algo", ALGOS)
def test_raw_frame_roundtrip_via_manual_seal_open(algo: int) -> None:
    key = os.urandom(key_size(algo))
    nonce = os.urandom(nonce_size(algo))
    ciphertext = seal(algo, key, nonce, b"hello, raw frame", b"AD")

    stream = io.BytesIO()
    write_raw_frame(stream, nonce, ciphertext)

    stream.seek(0)
    read_nonce, read_ct = read_raw_frame(stream, algo, max_ciphertext_len=1024)
    assert read_nonce == nonce
    assert read_ct == ciphertext
    assert open_(algo, key, read_nonce, read_ct, b"AD") == b"hello, raw frame"


def test_write_raw_frame_matches_write_sealed_section_layout() -> None:
    # write_sealed_section should just be seal() + write_raw_frame() - lock
    # that in so the two never silently diverge in on-disk shape.
    algo = ALGO_XCHACHA20_POLY1305
    key = os.urandom(key_size(algo))
    nonce = os.urandom(nonce_size(algo))

    via_sealed_section = io.BytesIO()
    write_sealed_section(via_sealed_section, algo, key, nonce, b"data", b"AD")

    via_raw = io.BytesIO()
    ciphertext = seal(algo, key, nonce, b"data", b"AD")
    write_raw_frame(via_raw, nonce, ciphertext)

    assert via_sealed_section.getvalue() == via_raw.getvalue()


def test_read_raw_frame_enforces_same_length_limits_as_read_sealed_section() -> None:
    algo = ALGO_XCHACHA20_POLY1305
    key = os.urandom(key_size(algo))
    nonce = os.urandom(nonce_size(algo))
    stream = io.BytesIO()
    write_sealed_section(stream, algo, key, nonce, b"x" * 100, b"AD")
    stream.seek(0)
    with pytest.raises(FormatError, match="exceeds"):
        read_raw_frame(stream, algo, max_ciphertext_len=8)


# --- chunk associated data ---------------------------------------------------


def test_chunk_ad_exact_bytes() -> None:
    header_ad = b"H" * 16
    ad = chunk_associated_data(header_ad, index=5, is_final=True)
    assert ad == header_ad + b"CHUNK" + (5).to_bytes(8, "little") + b"\x01"


def test_chunk_ad_is_final_false() -> None:
    ad = chunk_associated_data(b"H", index=0, is_final=False)
    assert ad.endswith(b"\x00")


def test_chunk_ad_differs_by_index() -> None:
    assert chunk_associated_data(b"H", 0, False) != chunk_associated_data(b"H", 1, False)


def test_chunk_ad_differs_by_final_flag() -> None:
    assert chunk_associated_data(b"H", 0, False) != chunk_associated_data(b"H", 0, True)


def test_chunk_ad_differs_by_header() -> None:
    assert chunk_associated_data(b"H1", 0, False) != chunk_associated_data(b"H2", 0, False)


# --- footer -------------------------------------------------------------------


def test_footer_roundtrip() -> None:
    stream = io.BytesIO()
    stream.write(b"some chunk bytes before the footer")
    footer_offset_expected = stream.tell()
    write_footer(stream, total_chunks=42)

    total_chunks, footer_offset = read_footer_at_end(stream)
    assert total_chunks == 42
    assert footer_offset == footer_offset_expected


def test_footer_bad_magic_rejected() -> None:
    stream = io.BytesIO()
    stream.write(b"BADMAGIC" + (1).to_bytes(8, "little"))
    with pytest.raises(FormatError, match="footer magic"):
        read_footer_at_end(stream)


def test_footer_zero_total_chunks_rejected() -> None:
    stream = io.BytesIO()
    write_footer(stream, total_chunks=0)
    with pytest.raises(FormatError, match="total_chunks"):
        read_footer_at_end(stream)


def test_footer_missing_rejected() -> None:
    stream = io.BytesIO(b"too short")
    with pytest.raises(FormatError, match="too short"):
        read_footer_at_end(stream)
