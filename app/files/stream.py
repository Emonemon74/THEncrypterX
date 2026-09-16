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
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

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
def atomic_writer(destination: str | os.PathLike[str]) -> Iterator[BinaryIO]:
    """Write to a private temp file next to `destination`; publish it atomically.

    On success: flush, fsync, then os.replace the temp file onto `destination`
    (atomic on the same filesystem - the destination either has the old
    content or the fully-written new content, never a partial file).

    On any exception raised inside the `with` block: the temp file is
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
        os.replace(tmp_path, dest)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
