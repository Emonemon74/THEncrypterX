"""Tests for app.files.shred."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.files.shred import shred_file


def test_shred_deletes_the_file(tmp_path: Path) -> None:
    target = tmp_path / "secret.bin"
    target.write_bytes(b"sensitive content")

    shred_file(target)

    assert not target.exists()


def test_shred_rejects_a_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a regular file"):
        shred_file(tmp_path)


def test_shred_rejects_a_missing_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a regular file"):
        shred_file(tmp_path / "does-not-exist.bin")


def test_shred_handles_empty_file(tmp_path: Path) -> None:
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")
    shred_file(target)
    assert not target.exists()
