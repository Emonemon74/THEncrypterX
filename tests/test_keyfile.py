"""Tests for app.files.keyfile."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.errors import FormatError
from app.crypto.kdf import KEY_LEN
from app.files.keyfile import generate_key_file, read_key_file


def test_generate_and_read_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "mykey.thexkey"
    generate_key_file(path)

    key = read_key_file(path)

    assert isinstance(key, bytes)
    assert len(key) == KEY_LEN


def test_generated_keys_are_random(tmp_path: Path) -> None:
    generate_key_file(tmp_path / "a.thexkey")
    generate_key_file(tmp_path / "b.thexkey")

    assert read_key_file(tmp_path / "a.thexkey") != read_key_file(tmp_path / "b.thexkey")


def test_generate_refuses_to_overwrite_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "mykey.thexkey"
    generate_key_file(path)
    original = path.read_bytes()

    with pytest.raises(FileExistsError):
        generate_key_file(path)

    assert path.read_bytes() == original  # untouched, not partially overwritten


def test_read_rejects_wrong_size(tmp_path: Path) -> None:
    path = tmp_path / "bad.thexkey"
    path.write_bytes(b"too short")

    with pytest.raises(FormatError, match="expected"):
        read_key_file(path)


def test_read_rejects_bad_magic(tmp_path: Path) -> None:
    path = tmp_path / "bad.thexkey"
    good = tmp_path / "good.thexkey"
    generate_key_file(good)
    blob = bytearray(good.read_bytes())
    blob[0:4] = b"XXXX"
    path.write_bytes(bytes(blob))

    with pytest.raises(FormatError, match="magic"):
        read_key_file(path)


def test_read_rejects_unsupported_version(tmp_path: Path) -> None:
    path = tmp_path / "bad.thexkey"
    good = tmp_path / "good.thexkey"
    generate_key_file(good)
    blob = bytearray(good.read_bytes())
    blob[4] = 99
    path.write_bytes(bytes(blob))

    with pytest.raises(FormatError, match="version"):
        read_key_file(path)


def test_read_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_key_file(tmp_path / "does-not-exist.thexkey")
