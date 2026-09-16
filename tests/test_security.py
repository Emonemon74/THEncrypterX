"""The THEncrypterX security test matrix (Build Guide §19).

Each test below is one row of the matrix. The table documents what each row
proves; docs/threat-model.md references this file as the evidence behind
every security claim in the README (Build Guide §29: Claim -> Design decision
-> Implementation -> Test -> Evidence).

| # | Scenario                                         | Expected result        |
|---|---------------------------------------------------|-------------------------|
| 1 | Correct password                                   | Success, bytes identical|
| 2 | Wrong password                                     | WrongPasswordError      |
| 3 | Modified chunk ciphertext                          | IntegrityError          |
| 4 | Modified chunk nonce                               | IntegrityError          |
| 5 | Modified header field (chunk_size, still in range) | WrongPasswordError      |
| 6 | Removed a middle chunk                             | IntegrityError          |
| 7 | Reordered chunks                                   | IntegrityError          |
| 8 | Truncated container (chopped tail)                 | FormatError             |
| 9 | Tampered metadata ciphertext                       | WrongPasswordError      |
|10 | Empty file                                         | Success (round-trips)   |
|11 | Larger multi-chunk file                            | Success (round-trips)   |
|12 | Duplicated chunk                                   | IntegrityError/FormatError |
|13 | Chunk spliced in from a different .thex            | IntegrityError          |
|14 | Corrupted footer magic                             | FormatError             |
|15 | Modified Argon2 memory_cost in header               | WrongPasswordError      |
|16 | Modified salt byte                                 | WrongPasswordError      |
|17 | Empty password rejected at derivation               | ValueError              |
|18 | Truncated mid-chunk (not on a frame boundary)      | FormatError             |
|19 | Unicode/emoji password                             | Success (round-trips)   |
|20 | Corrupted aead_id (swapped to the other valid id)  | a ThexError, not a crash|
|21 | Footer total_chunks forged to 0                    | FormatError             |
|22 | Two different files, same password                | Independent, no collision|
"""

from __future__ import annotations

import io
import os
import struct
from pathlib import Path

import pytest

from app.core.errors import FormatError, IntegrityError, ThexError, WrongPasswordError
from app.crypto.cipher import ALGO_AES_256_GCM, ALGO_XCHACHA20_POLY1305, nonce_size
from app.crypto.kdf import Argon2Params, derive_master_key
from app.files.decrypt import decrypt_file
from app.files.encrypt import encrypt_file
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


def _dec_target(tmp_path: Path) -> Path:
    return tmp_path / "decrypted.bin"


def split_container(path: Path) -> tuple[bytes, bytes, list[bytes], bytes]:
    """(header_bytes, metadata_frame_bytes, [chunk_frame_bytes...], footer_bytes)."""
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


def rebuild(
    header: bytes, meta: bytes, chunks: list[bytes], total_chunks: int | None = None
) -> bytes:
    buf = io.BytesIO()
    write_footer(buf, total_chunks if total_chunks is not None else len(chunks))
    return header + meta + b"".join(chunks) + buf.getvalue()


# --- 1: correct password --------------------------------------------------------


def test_01_correct_password_succeeds(tmp_path: Path) -> None:
    data = os.urandom(37)
    enc = _encrypted(tmp_path, data)
    dec = _dec_target(tmp_path)
    decrypt_file(enc, dec, PASSWORD)
    assert dec.read_bytes() == data


# --- 2: wrong password -----------------------------------------------------------


def test_02_wrong_password_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"secret")
    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, _dec_target(tmp_path), "not-the-password")


# --- 3: modified chunk ciphertext -------------------------------------------------


def test_03_modified_chunk_ciphertext_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(30))
    header, meta, chunks, _footer = split_container(enc)
    tampered = bytearray(chunks[0])
    tampered[-1] ^= 0x01  # inside chunk 0's tag
    chunks[0] = bytes(tampered)
    enc.write_bytes(rebuild(header, meta, chunks))
    with pytest.raises(IntegrityError):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 4: modified chunk nonce ------------------------------------------------------


def test_04_modified_chunk_nonce_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(30))
    header, meta, chunks, _footer = split_container(enc)
    tampered = bytearray(chunks[0])
    tampered[0] ^= 0x01  # first byte of the nonce
    chunks[0] = bytes(tampered)
    enc.write_bytes(rebuild(header, meta, chunks))
    with pytest.raises(IntegrityError):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 5: modified header field (still structurally valid) --------------------------


def test_05_modified_header_field_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"some content")
    blob = bytearray(enc.read_bytes())
    # chunk_size field, offset 10..14 (u32 LE) - change it but keep it in range.
    new_chunk_size = 4096
    blob[10:14] = new_chunk_size.to_bytes(4, "little")
    enc.write_bytes(bytes(blob))
    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 6: removed a middle chunk -----------------------------------------------------


def test_06_removed_middle_chunk_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(30))  # 4 chunks at chunk_size=8
    header, meta, chunks, _footer = split_container(enc)
    assert len(chunks) >= 3
    del chunks[1]
    enc.write_bytes(rebuild(header, meta, chunks))
    with pytest.raises(IntegrityError):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 7: reordered chunks -----------------------------------------------------------


def test_07_reordered_chunks_fail(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(24))
    header, meta, chunks, _footer = split_container(enc)
    chunks[0], chunks[-1] = chunks[-1], chunks[0]
    enc.write_bytes(rebuild(header, meta, chunks))
    with pytest.raises(IntegrityError):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 8: truncated container --------------------------------------------------------


def test_08_truncated_container_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(500), chunk_size=64)
    truncated = enc.read_bytes()[:-30]
    enc.write_bytes(truncated)
    with pytest.raises(FormatError):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 9: tampered metadata ciphertext ------------------------------------------------


def test_09_tampered_metadata_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"data")
    header, meta, chunks, _footer = split_container(enc)
    tampered_meta = bytearray(meta)
    tampered_meta[-1] ^= 0x01  # inside the metadata tag
    enc.write_bytes(rebuild(header, bytes(tampered_meta), chunks))
    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 10: empty file -----------------------------------------------------------------


def test_10_empty_file_roundtrips(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"")
    dec = _dec_target(tmp_path)
    metadata = decrypt_file(enc, dec, PASSWORD)
    assert dec.read_bytes() == b""
    assert metadata.original_size == 0


# --- 11: larger multi-chunk file -----------------------------------------------------


def test_11_larger_file_roundtrips(tmp_path: Path) -> None:
    data = os.urandom(2_000_000)
    enc = _encrypted(tmp_path, data, chunk_size=65536)
    dec = _dec_target(tmp_path)
    decrypt_file(enc, dec, PASSWORD)
    assert dec.read_bytes() == data


# --- 12: duplicated chunk -------------------------------------------------------------


def test_12_duplicated_chunk_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(24))
    header, meta, chunks, _footer = split_container(enc)
    chunks.insert(1, chunks[0])
    enc.write_bytes(rebuild(header, meta, chunks))
    with pytest.raises((IntegrityError, FormatError)):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 13: chunk spliced in from a different .thex ----------------------------------------


def test_13_spliced_chunk_from_different_file_fails(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    enc_a = _encrypted(tmp_path / "a", os.urandom(24))
    enc_b = _encrypted(tmp_path / "b", os.urandom(24))

    header_a, meta_a, chunks_a, _ = split_container(enc_a)
    _, _, chunks_b, _ = split_container(enc_b)

    chunks_a[0] = chunks_b[0]  # splice in a chunk sealed under a different data_key
    enc_a.write_bytes(rebuild(header_a, meta_a, chunks_a))

    with pytest.raises(IntegrityError):
        decrypt_file(enc_a, _dec_target(tmp_path), PASSWORD)


# --- 14: corrupted footer magic ---------------------------------------------------------


def test_14_corrupted_footer_magic_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"data")
    blob = bytearray(enc.read_bytes())
    blob[-12:-8] = b"NOPE"  # footer magic field
    enc.write_bytes(bytes(blob))
    with pytest.raises(FormatError):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 15: modified Argon2 memory_cost in header --------------------------------------------


def test_15_modified_argon2_params_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"data")
    blob = bytearray(enc.read_bytes())
    # memory_cost_kib is the first 4 bytes of the Argon2 params block,
    # which starts right after the 16-byte fixed header.
    blob[16:20] = (16).to_bytes(4, "little")
    enc.write_bytes(bytes(blob))
    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 16: modified salt byte -----------------------------------------------------------------


def test_16_modified_salt_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"data")
    blob = bytearray(enc.read_bytes())
    # salt is the last 16 bytes of the header (fixed header 16 + params 13 = offset 29).
    blob[29] ^= 0x01
    enc.write_bytes(bytes(blob))
    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 17: empty password rejected -------------------------------------------------------------


def test_17_empty_password_rejected_at_derivation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="password"):
        derive_master_key("", os.urandom(16), CHEAP)


# --- 18: truncated mid-chunk (not on a frame boundary) -----------------------------------------


def test_18_truncated_mid_chunk_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(500), chunk_size=64)
    raw = enc.read_bytes()
    enc.write_bytes(raw[: len(raw) - 12 - 5])  # cut into the last chunk, before the footer
    with pytest.raises(FormatError):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 19: unicode/emoji password ----------------------------------------------------------------


def test_19_unicode_password_roundtrips(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    data = b"data protected by a unicode password"
    src.write_bytes(data)
    enc = tmp_path / "out.thex"
    password = "pÀsswörd_🔐_ñ" * 5
    encrypt_file(src, enc, password, argon2_params=CHEAP)
    dec = _dec_target(tmp_path)
    decrypt_file(enc, dec, password)
    assert dec.read_bytes() == data


# --- 20: corrupted aead_id (swapped to the other valid id) ------------------------------------


def test_20_swapped_aead_id_fails_without_crashing(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, os.urandom(64))
    blob = bytearray(enc.read_bytes())
    current = blob[7]
    blob[7] = ALGO_AES_256_GCM if current == ALGO_XCHACHA20_POLY1305 else ALGO_XCHACHA20_POLY1305
    enc.write_bytes(bytes(blob))
    with pytest.raises(ThexError):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 21: footer total_chunks forged to 0 --------------------------------------------------------


def test_21_footer_total_chunks_zero_fails(tmp_path: Path) -> None:
    enc = _encrypted(tmp_path, b"data")
    header, meta, chunks, _ = split_container(enc)
    buf = io.BytesIO()
    # Bypass write_footer's own validation to hand-craft an invalid footer.
    buf.write(b"THXE" + (0).to_bytes(8, "little"))
    enc.write_bytes(header + meta + b"".join(chunks) + buf.getvalue())
    with pytest.raises(FormatError, match="total_chunks"):
        decrypt_file(enc, _dec_target(tmp_path), PASSWORD)


# --- 22: two different files, same password, no collision --------------------------------------


def test_22_two_files_same_password_are_independent(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    data_a = b"first file's secret content"
    data_b = b"second file's completely different content"

    enc_a = _encrypted(tmp_path / "a", data_a)
    enc_b = _encrypted(tmp_path / "b", data_b)

    header_a, *_ = split_container(enc_a)
    header_b, *_ = split_container(enc_b)
    assert header_a != header_b  # different random salts -> different headers

    dec_a, dec_b = _dec_target(tmp_path / "a"), _dec_target(tmp_path / "b")
    decrypt_file(enc_a, dec_a, PASSWORD)
    decrypt_file(enc_b, dec_b, PASSWORD)
    assert dec_a.read_bytes() == data_a
    assert dec_b.read_bytes() == data_b
