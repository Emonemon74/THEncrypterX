"""Tiny shared stream-reading helper for the format package (not public API)."""

from __future__ import annotations

from typing import BinaryIO

from app.core.errors import FormatError


def read_exact(stream: BinaryIO, n: int) -> bytes:
    """Read exactly n bytes or raise FormatError. Never allocates more than n."""
    data = stream.read(n)
    if len(data) != n:
        raise FormatError(f"unexpected end of stream while reading {n} bytes")
    return data
