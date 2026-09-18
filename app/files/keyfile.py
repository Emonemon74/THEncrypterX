"""Optional key-file based key material (roadmap Phase 6).

An alternative to a password: a 32-byte cryptographically random key,
generated once by `keygen` and stored in a small `.thexkey` file, used
directly (via `app.crypto.kdf.derive_master_key_from_keyfile`) instead of a
stretched password. There is no way to recover a lost key file, and no
"forgot my key file" flow - unlike a password, it can't be re-typed from
memory. Anyone who has a copy of the key file can decrypt anything
encrypted with it, so it needs the same handling as any other secret:
never committed to version control, ideally stored separately from the
files it protects, and backed up somewhere at least as secure as the data
itself. See docs/threat-model.md.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

from app.core.errors import FormatError
from app.crypto.kdf import KEY_LEN
from app.files.stream import atomic_writer

_MAGIC = b"TKEY"
_VERSION = 1
_STRUCT = struct.Struct(f"<4sB{KEY_LEN}s")


def generate_key_file(path: str | os.PathLike[str]) -> None:
    """Write a fresh, cryptographically random key to `path`.

    Refuses to overwrite an existing file (`must_not_exist=True` - see
    app.files.stream.atomic_writer): silently replacing a key file would
    make anything encrypted with the old one unrecoverable, so this is
    never a place for a casual clobber.
    """
    key = os.urandom(KEY_LEN)
    blob = _STRUCT.pack(_MAGIC, _VERSION, key)
    with atomic_writer(path, must_not_exist=True) as f:
        f.write(blob)


def read_key_file(path: str | os.PathLike[str]) -> bytes:
    """Read and validate a key file, returning its raw 32-byte key.

    Raises FormatError (not a bare struct/ValueError) for anything that
    isn't a genuine key file this version understands - wrong size, bad
    magic, or an unsupported version - matching how a malformed `.thex`
    container is rejected.
    """
    data = Path(path).read_bytes()
    if len(data) != _STRUCT.size:
        raise FormatError(
            f"not a THEncrypterX key file: expected {_STRUCT.size} bytes, got {len(data)}"
        )
    magic, version, key = _STRUCT.unpack(data)
    if magic != _MAGIC:
        raise FormatError("not a THEncrypterX key file (bad magic bytes)")
    if version != _VERSION:
        raise FormatError(f"unsupported key file version {version}")
    return bytes(key)
