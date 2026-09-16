"""File metadata: what we protect about a file besides its content.

Plain encryption hides file *contents* but a plaintext filename, size, or
timestamp sitting next to the ciphertext can still leak a lot ("Q3_layoffs
list.xlsx", exactly 4,096 bytes, modified the night of an incident). We
serialize a small, fixed set of fields and encrypt them as their own AEAD
section (see app/format/container.py), so none of this is visible without
the password - and even then, only after the section's tag verifies.

We deliberately store the bare filename only, never a path, and never
permissions/owner/xattrs - see docs/threat-model.md for what is and isn't
protected (the .thex file's own length is still an observable, residual
leak; padding to hide it is future work, not v1).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import FormatError

CREATED_WITH = "THEncrypterX/1.0"
_REQUIRED_FIELDS = frozenset({"original_name", "original_size", "mtime_ns", "created_with"})
_MAX_NAME_LEN = 255  # matches common filesystem filename limits


def sanitize_filename(name: str) -> str:
    """Reduce `name` to a bare filename with no directory component.

    Metadata never stores a path - only a bare name - so that decrypting a
    file can never be tricked (via a crafted "../../etc/passwd"-style name)
    into writing outside the directory the user chose for the output.
    """
    base = name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    if not base or base in {".", ".."}:
        raise ValueError(f"invalid filename: {name!r}")
    if len(base) > _MAX_NAME_LEN:
        raise ValueError(f"filename longer than {_MAX_NAME_LEN} characters")
    return base


@dataclass(frozen=True, slots=True)
class FileMetadata:
    """The authenticated facts we record about the original file."""

    original_name: str
    original_size: int
    mtime_ns: int
    created_with: str = CREATED_WITH

    def __post_init__(self) -> None:
        sanitized = sanitize_filename(self.original_name)
        if sanitized != self.original_name:
            object.__setattr__(self, "original_name", sanitized)
        if self.original_size < 0:
            raise ValueError("original_size must be >= 0")
        if self.mtime_ns < 0:
            raise ValueError("mtime_ns must be >= 0")


def from_path(path: str | os.PathLike[str]) -> FileMetadata:
    """Build FileMetadata by stat-ing a real file on disk."""
    p = Path(path)
    st = p.stat()
    return FileMetadata(original_name=p.name, original_size=st.st_size, mtime_ns=st.st_mtime_ns)


def serialize(metadata: FileMetadata) -> bytes:
    """Canonical encoding: UTF-8 JSON, sorted keys, no incidental whitespace.

    Deterministic so the same FileMetadata always produces the same bytes -
    useful for tests and for the known-answer test vector.
    """
    payload = {
        "original_name": metadata.original_name,
        "original_size": metadata.original_size,
        "mtime_ns": metadata.mtime_ns,
        "created_with": metadata.created_with,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def deserialize(data: bytes) -> FileMetadata:
    """Strictly parse metadata bytes. Raises FormatError on anything unexpected.

    "Strict" means: valid UTF-8, valid JSON, a JSON *object*, exactly the
    expected field names (no more, no fewer), and the expected type for each
    field. Anything else is a FormatError, not a crash or a silent guess.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FormatError(f"metadata is not valid UTF-8: {exc}") from exc

    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FormatError(f"metadata is not valid JSON: {exc}") from exc

    if not isinstance(obj, dict):
        raise FormatError("metadata JSON must be an object")
    if set(obj.keys()) != _REQUIRED_FIELDS:
        raise FormatError(f"unexpected metadata fields: {sorted(obj.keys())}")

    name, size, mtime, created_with = (
        obj["original_name"],
        obj["original_size"],
        obj["mtime_ns"],
        obj["created_with"],
    )
    # bool is a subclass of int in Python - reject it explicitly so `true`
    # can't silently pass as a size or timestamp.
    if not isinstance(name, str):
        raise FormatError("metadata original_name must be a string")
    if not isinstance(size, int) or isinstance(size, bool):
        raise FormatError("metadata original_size must be an integer")
    if not isinstance(mtime, int) or isinstance(mtime, bool):
        raise FormatError("metadata mtime_ns must be an integer")
    if not isinstance(created_with, str):
        raise FormatError("metadata created_with must be a string")

    try:
        return FileMetadata(
            original_name=name, original_size=size, mtime_ns=mtime, created_with=created_with
        )
    except ValueError as exc:
        raise FormatError(str(exc)) from exc
