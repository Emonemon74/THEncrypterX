"""Streaming primitives: bounded-memory chunk iteration and atomic writes.

Two independent responsibilities live here, both about *not corrupting
things halfway through*:

  - `iter_chunks` reads a file in fixed-size pieces without ever holding more
    than ~one chunk in memory, and tells the caller which chunk is the last
    one using a one-buffer read-ahead (no second pass, no seeking).

  - `atomic_writer` writes output to a temp file in the same directory and
    only makes it visible under its real name if the whole operation
    succeeded, so a crash or an exception never leaves a half-written file
    where the real output is expected.

  - `check_disk_space` is a fast preflight check for large files: fail in
    milliseconds instead of partway through writing several gigabytes.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from app.core.errors import InsufficientSpaceError

# One (chunk_bytes, is_final) pair per chunk.
ChunkResult = tuple[bytes, bool]


def iter_chunks(stream: BinaryIO, chunk_size: int) -> Iterator[ChunkResult]:
    """Yield (chunk_bytes, is_final) for `stream`, reading at most chunk_size
    bytes into memory ahead of what is yielded.

    Determining `is_final` without seeking or reading twice: keep one chunk
    "pending" and read the *next* one before yielding the pending chunk.
    Once a read comes back empty, the pending chunk is the last one.

    An empty stream yields exactly one chunk: (b"", True) - this is what
    makes an empty input file round-trip correctly instead of becoming a
    zero-chunk (and therefore ambiguous) container.
    """
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")

    pending = stream.read(chunk_size)
    while True:
        nxt = stream.read(chunk_size)
        is_final = nxt == b""
        yield pending, is_final
        if is_final:
            return
        pending = nxt


@contextlib.contextmanager
def atomic_writer(
    destination: str | os.PathLike[str], *, must_not_exist: bool = False
) -> Iterator[BinaryIO]:
    """Write to a private temp file next to `destination`; publish it atomically.

    On success: flush, fsync, then publish the temp file onto `destination`
    (atomic on the same filesystem - the destination either has the old
    content or the fully-written new content, never a partial file).

    `must_not_exist=True` publishes via `os.link` (hard link) followed by
    unlinking the temp file, instead of `os.replace`. `os.link` raises
    `FileExistsError` if `destination` already exists, and does so
    atomically at the filesystem level - unlike checking `destination.exists()`
    before writing, this closes the TOCTOU window where another process
    could create `destination` while a large file is still being
    written, which would otherwise let a caller's own "don't overwrite"
    check pass and then still get silently clobbered at publish time.

    On any exception raised inside the `with` block, or if publishing itself
    fails (including the `must_not_exist` case above): the temp file is
    unlinked and the exception propagates. `destination` is left untouched.
    """
    dest = Path(destination)
    fd, tmp_name = tempfile.mkstemp(prefix=dest.name + ".", suffix=".tmp", dir=dest.parent)
    tmp_path = Path(tmp_name)
    try:
        os.chmod(tmp_path, 0o600)  # mkstemp already does this on POSIX; explicit for clarity
        with os.fdopen(fd, "wb") as f:
            yield f
            f.flush()
            os.fsync(f.fileno())
        if must_not_exist:
            os.link(tmp_path, dest)
        else:
            os.replace(tmp_path, dest)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    else:
        if must_not_exist:
            tmp_path.unlink(missing_ok=True)


def check_disk_space(destination: str | os.PathLike[str], required_bytes: int) -> None:
    """Fail fast if `destination`'s filesystem clearly doesn't have room.

    A courtesy check, not a guarantee: `shutil.disk_usage` is a snapshot -
    another process can consume the free space between this check and the
    real write, and atomic_writer's own exception handling already cleans
    up safely on a genuine ENOSPC failure regardless of this check running
    first. What this buys is failing in milliseconds instead of partway
    through writing a multi-gigabyte file, which is the difference that
    actually matters at large-file sizes: discovering "not enough space"
    the slow way can mean minutes of wasted I/O for the same outcome.
    """
    free = shutil.disk_usage(Path(destination).parent).free
    if free < required_bytes:
        raise InsufficientSpaceError(
            f"not enough free space at {Path(destination).parent}: "
            f"need ~{required_bytes} bytes, {free} available"
        )
