"""Tests for app.files.stream: chunk iteration and atomic writes."""

from __future__ import annotations

import io
import os
import stat
import sys
from pathlib import Path

import pytest

from app.files.stream import atomic_writer, iter_chunks

# --- iter_chunks --------------------------------------------------------------


def test_empty_stream_yields_one_final_empty_chunk() -> None:
    chunks = list(iter_chunks(io.BytesIO(b""), chunk_size=16))
    assert chunks == [(b"", True)]


def test_data_shorter_than_chunk_size_is_one_final_chunk() -> None:
    chunks = list(iter_chunks(io.BytesIO(b"hello"), chunk_size=16))
    assert chunks == [(b"hello", True)]


def test_data_exactly_one_chunk_size_is_one_final_chunk() -> None:
    data = b"x" * 16
    chunks = list(iter_chunks(io.BytesIO(data), chunk_size=16))
    assert chunks == [(data, True)]


def test_data_one_byte_over_chunk_size_is_two_chunks() -> None:
    data = b"x" * 16 + b"y"
    chunks = list(iter_chunks(io.BytesIO(data), chunk_size=16))
    assert chunks == [(b"x" * 16, False), (b"y", True)]


def test_multiple_full_chunks() -> None:
    data = b"A" * 10 + b"B" * 10 + b"C" * 10
    chunks = list(iter_chunks(io.BytesIO(data), chunk_size=10))
    assert chunks == [(b"A" * 10, False), (b"B" * 10, False), (b"C" * 10, True)]


def test_only_last_chunk_is_marked_final() -> None:
    data = os.urandom(10_000)
    chunks = list(iter_chunks(io.BytesIO(data), chunk_size=1024))
    finals = [is_final for _, is_final in chunks]
    assert finals == [False] * (len(finals) - 1) + [True]


def test_concatenated_chunks_reconstruct_original(tmp_path: Path) -> None:
    data = os.urandom(50_000)
    chunks = list(iter_chunks(io.BytesIO(data), chunk_size=4096))
    assert b"".join(c for c, _ in chunks) == data


def test_no_chunk_exceeds_requested_size() -> None:
    data = os.urandom(5000)
    for c, _ in iter_chunks(io.BytesIO(data), chunk_size=777):
        assert len(c) <= 777


def test_chunk_size_zero_rejected() -> None:
    with pytest.raises(ValueError, match="chunk_size"):
        list(iter_chunks(io.BytesIO(b"x"), chunk_size=0))


# --- atomic_writer --------------------------------------------------------------


def test_successful_write_creates_destination_with_content(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    with atomic_writer(dest) as f:
        f.write(b"final content")
    assert dest.read_bytes() == b"final content"


def test_no_tmp_file_left_behind_after_success(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    with atomic_writer(dest) as f:
        f.write(b"data")
    leftovers = [p for p in tmp_path.iterdir() if p != dest]
    assert leftovers == []


def test_exception_during_write_leaves_no_destination(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    with pytest.raises(RuntimeError), atomic_writer(dest) as f:
        f.write(b"partial")
        raise RuntimeError("boom")
    assert not dest.exists()


def test_exception_during_write_leaves_no_tmp_file(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    with pytest.raises(RuntimeError), atomic_writer(dest) as f:
        f.write(b"partial")
        raise RuntimeError("boom")
    assert list(tmp_path.iterdir()) == []


def test_overwrites_existing_destination_atomically(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    dest.write_bytes(b"old content")
    with atomic_writer(dest) as f:
        f.write(b"new content")
    assert dest.read_bytes() == b"new content"


def test_failed_write_does_not_touch_existing_destination(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    dest.write_bytes(b"untouched")
    with pytest.raises(RuntimeError), atomic_writer(dest) as f:
        f.write(b"partial")
        raise RuntimeError("boom")
    assert dest.read_bytes() == b"untouched"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode bits")
def test_temp_file_created_with_owner_only_permissions(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    seen_mode = {}

    with atomic_writer(dest) as f:
        mode = stat.S_IMODE(os.fstat(f.fileno()).st_mode)
        seen_mode["mode"] = mode

    assert seen_mode["mode"] == 0o600
