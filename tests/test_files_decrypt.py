"""Tests for app.files.decrypt.

Round-trip and basic fail-closed behaviour live here (paired with
app.files.encrypt through the public API). The exhaustive 22-case tamper
matrix lives in tests/test_security.py.
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
    TruncatedFileError,
    UnsupportedVersionError,
    WrongPasswordError,
)
from app.crypto.cipher import nonce_size
from app.crypto.kdf import Argon2Params
from app.files.decrypt import decrypt_file
from app.files.encrypt import encrypt_file
from app.format.container import read_footer_at_end, write_footer
from app.format.header import Header

CHEAP = Argon2Params(memory_cost_kib=8, time_cost=1, parallelism=1)


def split_container(path: Path) -> tuple[bytes, bytes, list[bytes], bytes]:
    """Split a .thex file into (header, metadata_frame, [chunk_frames...], footer)
    without decrypting anything - used to hand-craft tampered containers.
    """
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

        chunks_start = meta_end
        total_chunks, footer_offset = read_footer_at_end(f)
        f.seek(chunks_start)

        chunk_frames = []
        for _ in range(total_chunks):
            start = f.tell()
            f.read(nonce_len)
            (ct_len,) = struct.unpack("<I", f.read(4))
            f.read(ct_len)
            chunk_frames.append(raw[start : f.tell()])
        assert f.tell() == footer_offset

    return raw[:header_len], raw[meta_start:meta_end], chunk_frames, raw[footer_offset:]


def rebuild(
    header: bytes, meta: bytes, chunks: list[bytes], total_chunks: int | None = None
) -> bytes:
    footer_buf = io.BytesIO()
    write_footer(footer_buf, total_chunks if total_chunks is not None else len(chunks))
    return header + meta + b"".join(chunks) + footer_buf.getvalue()


# --- round trip through the public API -----------------------------------------


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 100, 10_000])
def test_roundtrip_public_api(tmp_path: Path, size: int) -> None:
    src = tmp_path / "in.bin"
    data = os.urandom(size)
    src.write_bytes(data)
    enc = tmp_path / "out.thex"
    dec = tmp_path / "roundtrip.bin"

    encrypt_file(src, enc, "correct horse", argon2_params=CHEAP, chunk_size=16)
    metadata = decrypt_file(enc, dec, "correct horse")

    assert dec.read_bytes() == data
    assert metadata.original_name == "in.bin"
    assert metadata.original_size == size


def test_progress_callback_reaches_original_size(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    data = os.urandom(1000)
    src.write_bytes(data)
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"
    encrypt_file(src, enc, "pw", argon2_params=CHEAP, chunk_size=64)

    calls: list[tuple[int, int]] = []
    decrypt_file(enc, dec, "pw", progress_cb=lambda done, total: calls.append((done, total)))

    assert calls[-1] == (len(data), len(data))


# --- fail-closed: wrong password / tampering -----------------------------------


def test_wrong_password_raises_and_touches_nothing(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(b"secret contents")
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"
    encrypt_file(src, enc, "right", argon2_params=CHEAP)

    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, dec, "wrong")
    assert not dec.exists()


def test_tampered_chunk_raises_integrity_error_and_touches_nothing(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(64))
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"
    encrypt_file(src, enc, "pw", argon2_params=CHEAP, chunk_size=16)

    blob = bytearray(enc.read_bytes())
    # Flip a byte inside the last chunk's tag, not in the 12-byte footer that
    # follows it - the footer's own bytes are checked separately (see
    # test_forged_footer_* below).
    blob[-13] ^= 0x01
    enc.write_bytes(bytes(blob))

    with pytest.raises(IntegrityError):
        decrypt_file(enc, dec, "pw")
    assert not dec.exists()


def test_existing_output_untouched_on_failure(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(b"content")
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"
    dec.write_bytes(b"pre-existing, must survive")
    encrypt_file(src, enc, "right", argon2_params=CHEAP)

    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, dec, "wrong")
    assert dec.read_bytes() == b"pre-existing, must survive"


def test_bad_magic_raises_format_error(tmp_path: Path) -> None:
    enc = tmp_path / "out.thex"
    enc.write_bytes(b"NOPE" + os.urandom(60))
    with pytest.raises(FormatError):
        decrypt_file(enc, tmp_path / "dec.bin", "pw")


def test_unsupported_version_raises(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(b"data")
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, "pw", argon2_params=CHEAP)

    blob = bytearray(enc.read_bytes())
    blob[4] = 250  # format_version low byte
    enc.write_bytes(bytes(blob))

    with pytest.raises(UnsupportedVersionError):
        decrypt_file(enc, tmp_path / "dec.bin", "pw")


def test_truncated_file_raises(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(1000))
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, "pw", argon2_params=CHEAP, chunk_size=64)

    truncated = enc.read_bytes()[:-50]
    enc.write_bytes(truncated)

    with pytest.raises(FormatError):  # TruncatedFileError is a FormatError
        decrypt_file(enc, tmp_path / "dec.bin", "pw")


# --- structural tamper: reorder / duplicate / drop chunks -----------------------


def test_reordered_chunks_raise_integrity_error(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(24))  # chunk_size 8 -> 3 chunks
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, "pw", argon2_params=CHEAP, chunk_size=8)

    header, meta, chunks, _ = split_container(enc)
    assert len(chunks) == 3
    chunks[0], chunks[1] = chunks[1], chunks[0]
    enc.write_bytes(rebuild(header, meta, chunks))

    with pytest.raises(IntegrityError):
        decrypt_file(enc, tmp_path / "dec.bin", "pw")


def test_duplicated_chunk_raises(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(24))
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, "pw", argon2_params=CHEAP, chunk_size=8)

    header, meta, chunks, _ = split_container(enc)
    chunks_with_dup = [chunks[0], chunks[0], chunks[1], chunks[2]]
    enc.write_bytes(rebuild(header, meta, chunks_with_dup))

    with pytest.raises((IntegrityError, FormatError)):
        decrypt_file(enc, tmp_path / "dec.bin", "pw")


def test_dropped_last_chunk_raises(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(24))
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, "pw", argon2_params=CHEAP, chunk_size=8)

    header, meta, chunks, _ = split_container(enc)
    enc.write_bytes(rebuild(header, meta, chunks[:-1]))

    # The remaining "final" chunk was sealed with is_final=False originally,
    # so it fails authentication against is_final=True at its new position.
    with pytest.raises(IntegrityError):
        decrypt_file(enc, tmp_path / "dec.bin", "pw")


def test_forged_footer_hiding_extra_chunk_raises(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(24))
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, "pw", argon2_params=CHEAP, chunk_size=8)

    header, meta, chunks, _ = split_container(enc)
    # Claim only 2 chunks exist while leaving all 3 chunks' bytes present.
    tampered = header + meta + b"".join(chunks)
    footer_buf = io.BytesIO()
    write_footer(footer_buf, 2)
    tampered += footer_buf.getvalue()
    enc.write_bytes(tampered)

    # The chunk at the forged "last" position was actually sealed with
    # is_final=False, so it fails authentication before the leftover-bytes
    # check is even reached - both outcomes are correctly fail-closed.
    with pytest.raises((IntegrityError, FormatError)):
        decrypt_file(enc, tmp_path / "dec.bin", "pw")


# --- output_path=None: derive the name from authenticated metadata --------------


def test_none_output_path_uses_metadata_name(tmp_path: Path) -> None:
    src = tmp_path / "report.pdf"
    src.write_bytes(b"pdf-like content")
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, "pw", argon2_params=CHEAP)
    src.unlink()  # remove the original so the auto-derived path is free

    metadata = decrypt_file(enc, None, "pw")

    recovered = tmp_path / "report.pdf"
    assert recovered.read_bytes() == b"pdf-like content"
    assert metadata.original_name == "report.pdf"


def test_none_output_path_refuses_to_overwrite(tmp_path: Path) -> None:
    src = tmp_path / "report.pdf"
    src.write_bytes(b"new content")
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, "pw", argon2_params=CHEAP)

    existing = tmp_path / "report.pdf"
    # Overwrite the source with something else to prove it survives untouched.
    existing.write_bytes(b"pre-existing content, must survive")

    with pytest.raises(FileExistsError):
        decrypt_file(enc, None, "pw")
    assert existing.read_bytes() == b"pre-existing content, must survive"


def test_explicit_output_path_still_overwrites(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(b"content")
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"
    dec.write_bytes(b"stale")
    encrypt_file(src, enc, "pw", argon2_params=CHEAP)

    decrypt_file(enc, dec, "pw")  # explicit path -> overwrite allowed
    assert dec.read_bytes() == b"content"


def test_forged_footer_claiming_more_chunks_than_present_raises(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(24))
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, "pw", argon2_params=CHEAP, chunk_size=8)

    header, meta, chunks, _ = split_container(enc)
    enc.write_bytes(rebuild(header, meta, chunks, total_chunks=1000))

    with pytest.raises(TruncatedFileError):
        decrypt_file(enc, tmp_path / "dec.bin", "pw")
