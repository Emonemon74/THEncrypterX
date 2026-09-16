"""Container-level framing shared by the metadata section and file chunks.

Both the encrypted metadata section and every encrypted chunk use the same
on-disk shape:

    [ nonce ][ u32 ciphertext_len ][ ciphertext || tag ]

This module provides that framing once (`write_sealed_section` /
`read_sealed_section`) so `metadata/metadata.py` and `files/encrypt.py` /
`files/decrypt.py` don't each reimplement it slightly differently. It also
owns the footer (end-of-file sanity check) and the per-chunk associated-data
format, since both are part of the container's on-disk shape rather than
belonging to any one section's content.

See docs/file-format.md for the full spec this code implements.
"""

from __future__ import annotations

import io
import struct
from typing import BinaryIO

from app.core.errors import FormatError, TruncatedFileError
from app.crypto.cipher import nonce_size, open_, seal, tag_size
from app.format._io import read_exact
from app.format.constants import FOOTER_LEN, MAGIC_END, SECTION_LEN_FIELD_SIZE

_LEN_STRUCT = struct.Struct("<I")
_FOOTER_STRUCT = struct.Struct("<4sQ")
assert _LEN_STRUCT.size == SECTION_LEN_FIELD_SIZE
assert _FOOTER_STRUCT.size == FOOTER_LEN

_CHUNK_AD_TAG = b"CHUNK"
_CHUNK_AD_STRUCT = struct.Struct("<QB")  # index (u64) + is_final (u8)


def write_sealed_section(
    stream: BinaryIO,
    algo: int,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: bytes,
) -> None:
    """Seal `plaintext` and write `nonce || u32 len || ciphertext+tag`."""
    ciphertext = seal(algo, key, nonce, plaintext, associated_data)
    stream.write(nonce)
    stream.write(_LEN_STRUCT.pack(len(ciphertext)))
    stream.write(ciphertext)


def read_sealed_section(
    stream: BinaryIO,
    algo: int,
    key: bytes,
    associated_data: bytes,
    max_ciphertext_len: int,
) -> bytes:
    """Read one `nonce || u32 len || ciphertext+tag` frame and return plaintext.

    Raises FormatError for structural problems (bad length, truncation) and
    AuthenticationError (via app.crypto.cipher.open_) if the tag doesn't
    verify. Length is validated *before* the ciphertext is read, so a forged
    length field can only ever fail fast, never trigger an oversized read.
    """
    nonce = read_exact(stream, nonce_size(algo))
    (ct_len,) = _LEN_STRUCT.unpack(read_exact(stream, SECTION_LEN_FIELD_SIZE))

    if ct_len < tag_size(algo):
        raise FormatError(f"section length {ct_len} shorter than the auth tag")
    if ct_len > max_ciphertext_len:
        raise FormatError(f"section length {ct_len} exceeds the {max_ciphertext_len} limit")

    ciphertext = read_exact(stream, ct_len)
    return open_(algo, key, nonce, ciphertext, associated_data)


def chunk_associated_data(header_ad: bytes, index: int, is_final: bool) -> bytes:
    """AD_CHUNK_i = AD_HEADER || b"CHUNK" || uint64_LE(index) || uint8(is_final).

    Binding the chunk's index and final-flag into the associated data is what
    lets a single AEAD call per chunk also authenticate the chunk's *position*
    in the file: reordering, duplicating, or dropping chunks changes what
    index/is_final a chunk is checked against, so tampering of that kind
    breaks authentication even though no chunk's own bytes were touched.
    """
    return header_ad + _CHUNK_AD_TAG + _CHUNK_AD_STRUCT.pack(index, 1 if is_final else 0)


def write_footer(stream: BinaryIO, total_chunks: int) -> None:
    """Write the (unencrypted) footer: magic_end || total_chunks (u64)."""
    stream.write(_FOOTER_STRUCT.pack(MAGIC_END, total_chunks))


def read_footer_at_end(stream: BinaryIO) -> tuple[int, int]:
    """Seek to the end of a seekable stream, validate and read the footer.

    Returns (total_chunks, footer_offset). `footer_offset` is where chunk
    data must end - callers use it to detect leftover/missing bytes between
    the last chunk and the footer.
    """
    stream.seek(0, io.SEEK_END)
    end = stream.tell()
    footer_offset = end - FOOTER_LEN
    if footer_offset < 0:
        raise TruncatedFileError("file too short to contain a footer")

    stream.seek(footer_offset)
    magic_end, total_chunks = _FOOTER_STRUCT.unpack(read_exact(stream, FOOTER_LEN))
    if magic_end != MAGIC_END:
        raise FormatError(f"bad footer magic: {magic_end!r}")
    if total_chunks < 1:
        raise FormatError("total_chunks must be at least 1")

    return total_chunks, footer_offset
