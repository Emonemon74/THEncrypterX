"""Integration tests for key-file mode (roadmap Phase 6): encrypt_file,
decrypt_file, and verify_file with `key=` instead of `password=`.

app/files/keyfile.py and app/crypto/kdf.py's derive_master_key_from_keyfile
are unit-tested elsewhere (tests/test_keyfile.py, tests/test_kdf.py); this
file is the full round-trip through the public app.files API, the same
level test_files_decrypt.py and test_verify.py cover for password mode.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.core.errors import WrongPasswordError
from app.files.decrypt import decrypt_file
from app.files.encrypt import encrypt_file
from app.files.keyfile import generate_key_file, read_key_file
from app.files.verify import verify_file
from app.format.constants import KDF_ID_KEYFILE
from app.format.header import Header


def test_encrypt_decrypt_roundtrip_with_key_file(tmp_path: Path) -> None:
    key_path = tmp_path / "k.thexkey"
    generate_key_file(key_path)
    key = read_key_file(key_path)

    src = tmp_path / "doc.txt"
    src.write_bytes(b"secret data, no password involved")
    enc = tmp_path / "doc.txt.thex"
    dec = tmp_path / "restored.txt"

    encrypt_file(src, enc, key=key)
    metadata = decrypt_file(enc, dec, key=key)

    assert dec.read_bytes() == src.read_bytes()
    assert metadata.original_size == len(src.read_bytes())


def test_encrypted_header_records_keyfile_kdf(tmp_path: Path) -> None:
    key = read_key_file(_make_key(tmp_path))
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")
    enc = tmp_path / "doc.txt.thex"

    encrypt_file(src, enc, key=key)

    with enc.open("rb") as f:
        header = Header.read_from(f)
    assert header.kdf_id == KDF_ID_KEYFILE
    assert header.argon2_params is None


def test_verify_with_key_file(tmp_path: Path) -> None:
    key = read_key_file(_make_key(tmp_path))
    src = tmp_path / "doc.txt"
    src.write_bytes(os.urandom(5000))
    enc = tmp_path / "doc.txt.thex"
    encrypt_file(src, enc, key=key)

    result = verify_file(enc, key=key)

    assert result.original_size == 5000


def test_wrong_key_file_rejected(tmp_path: Path) -> None:
    right_key = read_key_file(_make_key(tmp_path, "right.thexkey"))
    wrong_key = read_key_file(_make_key(tmp_path, "wrong.thexkey"))
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")
    enc = tmp_path / "doc.txt.thex"
    encrypt_file(src, enc, key=right_key)

    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, tmp_path / "out.txt", key=wrong_key)


def test_password_encrypted_file_rejects_key_file_decrypt(tmp_path: Path) -> None:
    """A clear ValueError, not a confusing WrongPasswordError, when the
    caller uses the wrong key-source *type* for this file - see
    app.files.decrypt.derive_master_key_for_header."""
    key = read_key_file(_make_key(tmp_path))
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")
    enc = tmp_path / "doc.txt.thex"
    encrypt_file(src, enc, "a real password")

    with pytest.raises(ValueError, match="encrypted with a password"):
        decrypt_file(enc, tmp_path / "out.txt", key=key)


def test_keyfile_encrypted_file_rejects_password_decrypt(tmp_path: Path) -> None:
    key = read_key_file(_make_key(tmp_path))
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")
    enc = tmp_path / "doc.txt.thex"
    encrypt_file(src, enc, key=key)

    with pytest.raises(ValueError, match="encrypted with a key file"):
        decrypt_file(enc, tmp_path / "out.txt", "some password")


def test_encrypt_file_requires_exactly_one_of_password_or_key(tmp_path: Path) -> None:
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")

    with pytest.raises(ValueError, match="exactly one"):
        encrypt_file(src, tmp_path / "out.thex")  # neither given

    with pytest.raises(ValueError, match="exactly one"):
        encrypt_file(src, tmp_path / "out.thex", "pw", key=b"\x00" * 32)  # both given


def test_same_key_file_reused_across_files_gets_different_master_keys(tmp_path: Path) -> None:
    """Regression guard for the design point in
    derive_master_key_from_keyfile's docstring: reusing one key file across
    many files must not reuse the same master key, since that would make
    AES-256-GCM's per-file 32-bit nonce prefix eventually collision-unsafe."""
    key = read_key_file(_make_key(tmp_path))
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_bytes(b"same content")
    b.write_bytes(b"same content")
    enc_a = tmp_path / "a.thex"
    enc_b = tmp_path / "b.thex"

    encrypt_file(a, enc_a, key=key)
    encrypt_file(b, enc_b, key=key)

    with enc_a.open("rb") as f:
        header_a = Header.read_from(f)
    with enc_b.open("rb") as f:
        header_b = Header.read_from(f)
    assert header_a.salt != header_b.salt  # different salt -> different master key


def _make_key(tmp_path: Path, name: str = "k.thexkey") -> Path:
    path = tmp_path / name
    generate_key_file(path)
    return path
