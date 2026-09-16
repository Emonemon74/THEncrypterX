"""Best-effort file shredding: overwrite with random bytes, then delete.

Overwriting a file's bytes in place is *not* a guarantee of unrecoverable
erasure on modern storage. SSD wear-leveling, copy-on-write filesystems
(APFS, Btrfs, ZFS), journaling, and any existing snapshots or backups can all
leave the original data recoverable elsewhere on the device regardless of
what this function does. This is best-effort only - see docs/threat-model.md
for exactly what is and is not guaranteed. Do not rely on this for data that
must be provably unrecoverable; use full-disk encryption and destroy the key,
or physical destruction, for that.
"""

from __future__ import annotations

import os
from pathlib import Path


def shred_file(path: str | os.PathLike[str]) -> None:
    """Overwrite `path` with random bytes, fsync, then unlink it."""
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"{p} is not a regular file")

    size = p.stat().st_size
    with p.open("r+b") as f:
        f.write(os.urandom(size))
        f.flush()
        os.fsync(f.fileno())
    p.unlink()
