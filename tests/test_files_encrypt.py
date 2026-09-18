"""Tests for app.files.encrypt.

Decryption proper doesn't exist yet (that's the next module), so these tests
manually replay the read side using the same low-level primitives decrypt.py
will wrap: this both proves encrypt_file() produces a spec-compliant
container *and* previews exactly how decrypt.py's loop will work.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.core.errors import AuthenticationError
from app.crypto.cipher import ALGO_AES_256_GCM, ALGO_XCHACHA20_POLY1305, tag_size
from app.crypto.kdf import Argon2Params, derive_master_key
from app.crypto.keys import derive_subkeys
from app.files.encrypt import encrypt_file
from app.format.constants import MAGIC, MAX_METADATA_CT_LEN
from app.format.container import chunk_associated_data, read_footer_at_end, read_sealed_section
from app.format.header import Header
from app.metadata.metadata import FileMetadata, deserialize

CHEAP = Argon2Params(memory_cost_kib=8, time_cost=1, parallelism=1)


def manual_decrypt(path: Path, password: str) -> tuple[FileMetadata, bytes]:
    """Replay the planned decrypt loop (Build Guide §13) by hand."""
    with path.open("rb") as f:
        header = Header.read_from(f)
        ad_header = header.associated_data

        master_key = derive_master_key(password, header.salt, header.argon2_params)
        subkeys = derive_subkeys(master_key)

        meta_bytes = read_sealed_section(
            f, header.aead_id, subkeys.meta_key, ad_header, max_ciphertext_len=MAX_METADATA_CT_LEN
        )
        metadata = deserialize(meta_bytes)

        chunks_start = f.tell()
        total_chunks, footer_offset = read_footer_at_end(f)
        f.seek(chunks_start)

        max_chunk_ct_len = header.chunk_size + tag_size(header.aead_id)
        plaintext = bytearray()
        for i in range(total_chunks):
            is_final = i == total_chunks - 1
            chunk_ad = chunk_associated_data(ad_header, i, is_final)
            plaintext += read_sealed_section(
                f, header.aead_id, subkeys.data_key, chunk_ad, max_ciphertext_len=max_chunk_ct_len
            )

        assert f.tell() == footer_offset, "leftover or missing bytes before the footer"
        return metadata, bytes(plaintext)


# --- basic shape --------------------------------------------------------------


def test_output_starts_with_magic_and_parses_as_header(tmp_path: Path) -> None:
    src = tmp_path / "in.txt"
    src.write_bytes(b"hello world")
    dest = tmp_path / "out.thex"

    encrypt_file(src, dest, "pw", argon2_params=CHEAP, chunk_size=16)

    raw = dest.read_bytes()
    assert raw[:4] == MAGIC
    with dest.open("rb") as f:
        header = Header.read_from(f)
    assert header.aead_id == ALGO_XCHACHA20_POLY1305
    assert header.chunk_size == 16


def test_does_not_touch_output_if_input_missing(tmp_path: Path) -> None:
    dest = tmp_path / "out.thex"
    with pytest.raises(FileNotFoundError):
        encrypt_file(tmp_path / "missing.txt", dest, "pw", argon2_params=CHEAP)
    assert not dest.exists()
    assert list(tmp_path.iterdir()) == []


def test_insufficient_disk_space_fails_before_writing_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import shutil as shutil_module

    from app.core.errors import InsufficientSpaceError

    src = tmp_path / "in.bin"
    src.write_bytes(b"some data")
    dest = tmp_path / "out.thex"

    fake_usage = shutil_module.disk_usage(tmp_path)._replace(free=0)
    monkeypatch.setattr(shutil_module, "disk_usage", lambda _path: fake_usage)

    with pytest.raises(InsufficientSpaceError):
        encrypt_file(src, dest, "pw", argon2_params=CHEAP)

    assert not dest.exists()
    assert list(tmp_path.iterdir()) == [src]  # no temp file left behind either


# --- round trip -----------------------------------------------------------------


@pytest.mark.parametrize(
    "size",
    [0, 1, 15, 16, 17, 31, 32, 33, 100],
)
def test_roundtrip_across_chunk_boundaries(tmp_path: Path, size: int) -> None:
    src = tmp_path / "in.bin"
    data = os.urandom(size)
    src.write_bytes(data)
    dest = tmp_path / "out.thex"

    encrypt_file(src, dest, "correct horse", argon2_params=CHEAP, chunk_size=16)
    metadata, plaintext = manual_decrypt(dest, "correct horse")

    assert plaintext == data
    assert metadata.original_name == "in.bin"
    assert metadata.original_size == size


@pytest.mark.parametrize("aead_id", [ALGO_XCHACHA20_POLY1305, ALGO_AES_256_GCM])
def test_roundtrip_both_algorithms(tmp_path: Path, aead_id: int) -> None:
    src = tmp_path / "in.bin"
    data = os.urandom(5000)
    src.write_bytes(data)
    dest = tmp_path / "out.thex"

    encrypt_file(src, dest, "pw", aead_id=aead_id, argon2_params=CHEAP, chunk_size=512)
    _, plaintext = manual_decrypt(dest, "pw")
    assert plaintext == data


def test_many_chunks_reassemble_in_order(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    data = os.urandom(50_000)
    src.write_bytes(data)
    dest = tmp_path / "out.thex"

    encrypt_file(src, dest, "pw", argon2_params=CHEAP, chunk_size=1024)
    _, plaintext = manual_decrypt(dest, "pw")
    assert plaintext == data


def test_footer_chunk_count_matches_expected(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(100))  # chunk_size 16 -> 7 chunks (96 + 4 remainder)
    dest = tmp_path / "out.thex"

    encrypt_file(src, dest, "pw", argon2_params=CHEAP, chunk_size=16)
    with dest.open("rb") as f:
        Header.read_from(f)  # advance past header before seeking from the end
    with dest.open("rb") as f:
        total_chunks, _ = read_footer_at_end(f)
    assert total_chunks == 7


# --- security -------------------------------------------------------------------


def test_wrong_password_fails_on_metadata(tmp_path: Path) -> None:
    src = tmp_path / "in.txt"
    src.write_bytes(b"secret contents")
    dest = tmp_path / "out.thex"

    encrypt_file(src, dest, "right-password", argon2_params=CHEAP)
    with pytest.raises(AuthenticationError):
        manual_decrypt(dest, "wrong-password")


def test_tampered_chunk_fails(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(64))
    dest = tmp_path / "out.thex"
    encrypt_file(src, dest, "pw", argon2_params=CHEAP, chunk_size=16)

    blob = bytearray(dest.read_bytes())
    blob[-1] ^= 0x01  # corrupt the very last byte (inside the last chunk's tag)
    dest.write_bytes(bytes(blob))

    with pytest.raises(AuthenticationError):
        manual_decrypt(dest, "pw")


# --- progress + output handling --------------------------------------------------


def test_progress_callback_reaches_total_size(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    data = os.urandom(1000)
    src.write_bytes(data)
    dest = tmp_path / "out.thex"

    calls: list[tuple[int, int]] = []
    encrypt_file(
        src,
        dest,
        "pw",
        argon2_params=CHEAP,
        chunk_size=64,
        progress_cb=lambda done, total: calls.append((done, total)),
    )

    assert calls, "progress callback was never called"
    assert all(total == len(data) for _, total in calls)
    assert [done for done, _ in calls] == sorted(done for done, _ in calls)
    assert calls[-1][0] == len(data)


def test_overwrites_existing_output(tmp_path: Path) -> None:
    dest = tmp_path / "out.thex"
    src1 = tmp_path / "a.bin"
    src1.write_bytes(b"first file contents")
    src2 = tmp_path / "b.bin"
    src2.write_bytes(b"second, different contents")

    encrypt_file(src1, dest, "pw", argon2_params=CHEAP)
    encrypt_file(src2, dest, "pw", argon2_params=CHEAP)

    _, plaintext = manual_decrypt(dest, "pw")
    assert plaintext == b"second, different contents"


def test_default_params_env_override_is_recorded_in_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("THEX_ARGON2_MEMORY_KIB", "4096")
    src = tmp_path / "in.txt"
    src.write_bytes(b"data")
    dest = tmp_path / "out.thex"

    encrypt_file(src, dest, "pw")  # no explicit argon2_params -> uses default_params()

    with dest.open("rb") as f:
        header = Header.read_from(f)
    assert header.argon2_params.memory_cost_kib == 4096
