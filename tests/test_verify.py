"""app.files.verify.verify_file: integrity verification without ever writing
plaintext anywhere.

Mirrors the relevant rows of tests/test_security.py's tamper matrix but
against verify_file instead of decrypt_file, plus checks specific to
verify's own contract: it needs the password (unlike InspectJob), and it
must never create any file besides the input container.
"""

from __future__ import annotations

import io
import os
import struct
from pathlib import Path

import pytest

from app.core.errors import (
    FormatError,
    IntegrityError,
    UnsupportedVersionError,
    WrongPasswordError,
)
from app.crypto.cipher import nonce_size
from app.crypto.kdf import Argon2Params
from app.files.decrypt import decrypt_file
from app.files.encrypt import encrypt_file
from app.files.verify import VerifyResult, verify_file
from app.format.container import read_footer_at_end, write_footer
from app.format.header import Header

CHEAP = Argon2Params(memory_cost_kib=8, time_cost=1, parallelism=1)
PASSWORD = "correct horse battery staple"
CHUNK_SIZE = 8


def _encrypted(tmp_path: Path, data: bytes, *, chunk_size: int = CHUNK_SIZE) -> Path:
    src = tmp_path / "in.bin"
    src.write_bytes(data)
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, PASSWORD, argon2_params=CHEAP, chunk_size=chunk_size)
    return enc


def _split(path: Path) -> tuple[bytes, bytes, list[bytes], bytes]:
    raw = path.read_bytes()
    with path.open("rb") as f:
        header = Header.read_from(f)
        header_len = f.tell()
        nonce_len = nonce_size(header.aead_id)

        meta_start = f.tell()
        f.read(nonce_len)
        (meta_ct_len,) = struct.unpack("<I", f.read(4))
        f.read(meta_ct_len)
        meta_end = f.tell()

        total_chunks, footer_offset = read_footer_at_end(f)
        f.seek(meta_end)

        chunk_frames = []
        for _ in range(total_chunks):
            start = f.tell()
            f.read(nonce_len)
            (ct_len,) = struct.unpack("<I", f.read(4))
            f.read(ct_len)
            chunk_frames.append(raw[start : f.tell()])
        assert f.tell() == footer_offset

    return raw[:header_len], raw[meta_start:meta_end], chunk_frames, raw[footer_offset:]


def _rebuild(header: bytes, meta: bytes, chunks: list[bytes]) -> bytes:
    buf = io.BytesIO()
    write_footer(buf, len(chunks))
    return header + meta + b"".join(chunks) + buf.getvalue()


def _snapshot(tmp_path: Path) -> set[str]:
    return {p.name for p in tmp_path.iterdir()}


# --- success -----------------------------------------------------------------------


def test_correct_password_succeeds_and_reports_real_values(tmp_path: Path) -> None:
    data = os.urandom(37)
    enc = _encrypted(tmp_path, data)

    result = verify_file(enc, PASSWORD)

    assert isinstance(result, VerifyResult)
    assert result.original_size == len(data)
    assert result.total_chunks >= 1
    assert result.chunk_size == CHUNK_SIZE


def test_verify_never_creates_any_file(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(500), chunk_size=64)
    before = _snapshot(tmp_path)
    verify_file(enc, PASSWORD)
    # No plaintext, no temp file, nothing left over - the directory is
    # unchanged by a successful verify.
    assert _snapshot(tmp_path) == before


def test_verify_agrees_with_decrypt_on_a_good_file(tmp_path: Path) -> None:
    data = os.urandom(2000)
    enc = _encrypted(tmp_path, data, chunk_size=64)
    result = verify_file(enc, PASSWORD)
    dec = tmp_path / "restored.bin"
    metadata = decrypt_file(enc, dec, PASSWORD)
    assert result.original_size == metadata.original_size == len(data)
    assert result.total_chunks * 1 >= 1


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_verify_agrees_across_worker_counts(tmp_path: Path, workers: int) -> None:
    enc = _encrypted(tmp_path, os.urandom(5000), chunk_size=64)
    result = verify_file(enc, PASSWORD, workers=workers)
    assert result.original_size == 5000


# --- failure modes, mirroring test_security.py -------------------------------------


def test_wrong_password_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"secret")
    before = _snapshot(tmp_path)
    with pytest.raises(WrongPasswordError):
        verify_file(enc, "not-the-password")
    assert _snapshot(tmp_path) == before


def test_modified_chunk_ciphertext_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(30))
    header, meta, chunks, _footer = _split(enc)
    tampered = bytearray(chunks[0])
    tampered[-1] ^= 0x01
    chunks[0] = bytes(tampered)
    enc.write_bytes(_rebuild(header, meta, chunks))
    with pytest.raises(IntegrityError):
        verify_file(enc, PASSWORD)


def test_reordered_chunks_fail(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(24))
    header, meta, chunks, _footer = _split(enc)
    chunks[0], chunks[-1] = chunks[-1], chunks[0]
    enc.write_bytes(_rebuild(header, meta, chunks))
    with pytest.raises(IntegrityError):
        verify_file(enc, PASSWORD)


def test_duplicated_chunk_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(24))
    header, meta, chunks, _footer = _split(enc)
    chunks.insert(1, chunks[0])
    enc.write_bytes(_rebuild(header, meta, chunks))
    with pytest.raises((IntegrityError, FormatError)):
        verify_file(enc, PASSWORD)


def test_dropped_last_chunk_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(30), chunk_size=8)
    header, meta, chunks, _footer = _split(enc)
    assert len(chunks) >= 2
    del chunks[-1]
    enc.write_bytes(_rebuild(header, meta, chunks))
    with pytest.raises((IntegrityError, FormatError)):
        verify_file(enc, PASSWORD)


def test_truncated_container_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(500), chunk_size=64)
    enc.write_bytes(enc.read_bytes()[:-30])
    with pytest.raises(FormatError):
        verify_file(enc, PASSWORD)


def test_truncated_mid_chunk_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(500), chunk_size=64)
    raw = enc.read_bytes()
    enc.write_bytes(raw[: len(raw) - 5])
    with pytest.raises(FormatError):
        verify_file(enc, PASSWORD)


def test_tampered_metadata_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"data")
    header, meta, chunks, _footer = _split(enc)
    tampered_meta = bytearray(meta)
    tampered_meta[-1] ^= 0x01
    enc.write_bytes(_rebuild(header, bytes(tampered_meta), chunks))
    with pytest.raises(WrongPasswordError):
        verify_file(enc, PASSWORD)


def test_bad_magic_raises_format_error(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"x")
    blob = bytearray(enc.read_bytes())
    blob[0:4] = b"NOPE"
    enc.write_bytes(bytes(blob))
    with pytest.raises(FormatError):
        verify_file(enc, PASSWORD)


def test_unsupported_version_raises(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"x")
    blob = bytearray(enc.read_bytes())
    blob[4] = 99  # format_version byte
    enc.write_bytes(bytes(blob))
    with pytest.raises(UnsupportedVersionError):
        verify_file(enc, PASSWORD)


def test_corrupted_footer_magic_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(24))
    raw = bytearray(enc.read_bytes())
    raw[-1] ^= 0xFF  # inside the footer's own magic/structure
    enc.write_bytes(bytes(raw))
    with pytest.raises(FormatError):
        verify_file(enc, PASSWORD)


def test_forged_footer_claiming_more_chunks_than_present_raises(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(24))
    header, meta, chunks, _footer = _split(enc)
    buf = io.BytesIO()
    write_footer(buf, len(chunks) + 1000)  # declared count wildly exceeds real data
    enc.write_bytes(header + meta + b"".join(chunks) + buf.getvalue())
    with pytest.raises(FormatError):
        verify_file(enc, PASSWORD)


def test_empty_file_verifies(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"")
    result = verify_file(enc, PASSWORD)
    assert result.original_size == 0
