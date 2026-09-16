"""Tests for app.metadata.metadata."""

from __future__ import annotations

import json

import pytest

from app.core.errors import FormatError
from app.metadata.metadata import (
    FileMetadata,
    deserialize,
    from_path,
    sanitize_filename,
    serialize,
)

# --- sanitize_filename --------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("report.pdf", "report.pdf"),
        ("/etc/passwd", "passwd"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\me\\secret.docx", "secret.docx"),
        ("  spaced.txt  ", "spaced.txt"),
        ("a/b/c/d.txt", "d.txt"),
    ],
)
def test_sanitize_filename_strips_paths(raw: str, expected: str) -> None:
    assert sanitize_filename(raw) == expected


@pytest.mark.parametrize("bad", ["", "   ", ".", "..", "a/../..", "a/."])
def test_sanitize_filename_rejects_bad_names(bad: str) -> None:
    with pytest.raises(ValueError, match="invalid filename"):
        sanitize_filename(bad)


def test_sanitize_filename_rejects_too_long() -> None:
    with pytest.raises(ValueError, match="longer than"):
        sanitize_filename("a" * 300)


# --- FileMetadata construction -----------------------------------------------


def test_construction_sanitizes_embedded_path() -> None:
    m = FileMetadata(original_name="/tmp/secret.txt", original_size=10, mtime_ns=0)
    assert m.original_name == "secret.txt"


def test_negative_size_rejected() -> None:
    with pytest.raises(ValueError, match="original_size"):
        FileMetadata(original_name="f.txt", original_size=-1, mtime_ns=0)


def test_negative_mtime_rejected() -> None:
    with pytest.raises(ValueError, match="mtime_ns"):
        FileMetadata(original_name="f.txt", original_size=0, mtime_ns=-1)


def test_default_created_with() -> None:
    m = FileMetadata(original_name="f.txt", original_size=0, mtime_ns=0)
    assert m.created_with == "THEncrypterX/1.0"


# --- serialize / deserialize --------------------------------------------------


def test_roundtrip() -> None:
    m = FileMetadata(original_name="notes.md", original_size=12345, mtime_ns=1_700_000_000_000)
    assert deserialize(serialize(m)) == m


def test_serialize_is_deterministic() -> None:
    m = FileMetadata(original_name="notes.md", original_size=1, mtime_ns=1)
    assert serialize(m) == serialize(m)


def test_serialize_has_no_incidental_whitespace() -> None:
    m = FileMetadata(original_name="f.txt", original_size=1, mtime_ns=1)
    assert b" " not in serialize(m)


def test_serialize_keys_sorted() -> None:
    m = FileMetadata(original_name="f.txt", original_size=1, mtime_ns=1)
    obj = json.loads(serialize(m))
    assert list(obj.keys()) == sorted(obj.keys())


def test_deserialize_rejects_non_utf8() -> None:
    with pytest.raises(FormatError, match="UTF-8"):
        deserialize(b"\xff\xfe\xfd")


def test_deserialize_rejects_invalid_json() -> None:
    with pytest.raises(FormatError, match="JSON"):
        deserialize(b"{not json")


def test_deserialize_rejects_non_object_json() -> None:
    with pytest.raises(FormatError, match="object"):
        deserialize(b"[1, 2, 3]")


def test_deserialize_rejects_missing_field() -> None:
    payload = json.dumps({"original_name": "f", "original_size": 1, "mtime_ns": 1}).encode()
    with pytest.raises(FormatError, match="unexpected metadata fields"):
        deserialize(payload)


def test_deserialize_rejects_extra_field() -> None:
    payload = json.dumps(
        {
            "original_name": "f",
            "original_size": 1,
            "mtime_ns": 1,
            "created_with": "x",
            "extra": "surprise",
        }
    ).encode()
    with pytest.raises(FormatError, match="unexpected metadata fields"):
        deserialize(payload)


def test_deserialize_rejects_wrong_type_size() -> None:
    payload = json.dumps(
        {"original_name": "f", "original_size": "12", "mtime_ns": 1, "created_with": "x"}
    ).encode()
    with pytest.raises(FormatError, match="original_size"):
        deserialize(payload)


def test_deserialize_rejects_bool_as_size() -> None:
    payload = json.dumps(
        {"original_name": "f", "original_size": True, "mtime_ns": 1, "created_with": "x"}
    ).encode()
    with pytest.raises(FormatError, match="original_size"):
        deserialize(payload)


def test_deserialize_rejects_bool_as_mtime() -> None:
    payload = json.dumps(
        {"original_name": "f", "original_size": 1, "mtime_ns": False, "created_with": "x"}
    ).encode()
    with pytest.raises(FormatError, match="mtime_ns"):
        deserialize(payload)


def test_deserialize_rejects_path_like_name_via_validation() -> None:
    # A crafted name still passes JSON/type checks, but FileMetadata's own
    # validation sanitizes it rather than erroring - confirm that happens.
    payload = json.dumps(
        {
            "original_name": "../../etc/passwd",
            "original_size": 1,
            "mtime_ns": 1,
            "created_with": "x",
        }
    ).encode()
    m = deserialize(payload)
    assert m.original_name == "passwd"


def test_deserialize_rejects_empty_name_via_validation() -> None:
    payload = json.dumps(
        {"original_name": "..", "original_size": 1, "mtime_ns": 1, "created_with": "x"}
    ).encode()
    with pytest.raises(FormatError, match="invalid filename"):
        deserialize(payload)


# --- from_path ----------------------------------------------------------------


def test_from_path_reads_real_file(tmp_path: object) -> None:
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    f = tmp_path / "example.txt"
    f.write_bytes(b"hello world")

    m = from_path(f)
    assert m.original_name == "example.txt"
    assert m.original_size == 11
    assert m.mtime_ns > 0
