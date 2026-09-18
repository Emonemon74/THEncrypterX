"""Integrity verification: authenticate a .thex container without ever
writing plaintext anywhere.

Reuses app.files.decrypt's chunk-authentication loops
(`_decrypt_chunks_sequential` / `_decrypt_chunks_parallel`), handing them a
`_DiscardSink` instead of a real file - every chunk is still fully
authenticated (the same AEAD `open_()` call runs), its plaintext is just
thrown away immediately instead of being written out. `verify_file` never
creates, opens for writing, or otherwise touches any file besides
`input_path`, which it only reads.

This needs the password, unlike `InspectJob` (app.core.service), because
authenticating the metadata and every chunk requires deriving the actual
AEAD keys - there is no way to confirm a container is genuinely intact
without the key that proves it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import (
    AuthenticationError,
    FormatError,
    TruncatedFileError,
    WrongPasswordError,
)
from app.crypto.cipher import nonce_size, tag_size
from app.crypto.kdf import derive_master_key
from app.crypto.keys import derive_subkeys
from app.files.decrypt import _decrypt_chunks_parallel, _decrypt_chunks_sequential
from app.files.encrypt import DEFAULT_WORKERS, ProgressCallback
from app.format.constants import MAX_METADATA_CT_LEN, SECTION_LEN_FIELD_SIZE
from app.format.container import read_footer_at_end, read_sealed_section
from app.format.header import Header
from app.metadata.metadata import deserialize


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Everything confirmed authentic by a successful verify_file() call."""

    format_version: int
    aead_id: int
    chunk_size: int
    total_chunks: int
    original_size: int


class _DiscardSink:
    """Accepts and immediately discards every chunk's plaintext.

    Structurally satisfies app.files.decrypt.WriteSink (it has a
    compatible `write`), so the exact same chunk-authentication loops used
    by decrypt_file run unmodified here - the only difference is what
    happens to the plaintext once a chunk has already been authenticated.
    """

    def write(self, data: bytes) -> int:
        return len(data)


def verify_file(
    input_path: str | os.PathLike[str],
    password: str,
    *,
    progress_cb: ProgressCallback | None = None,
    workers: int = DEFAULT_WORKERS,
) -> VerifyResult:
    """Authenticate a .thex container's header, metadata, and every chunk.

    Raises the same exceptions as `app.files.decrypt.decrypt_file` on
    failure: `WrongPasswordError` (also raised for a tampered salt, KDF
    params, or metadata ciphertext - indistinguishable by design),
    `IntegrityError` (a chunk failed to authenticate),
    `TruncatedFileError`, `FormatError`, `UnsupportedVersionError`, or
    `UnsupportedAlgorithmError`.

    Success means the container is fully valid: the password is correct,
    nothing was tampered with, and nothing is missing, reordered, or
    duplicated - the same guarantee `decrypt_file` provides, without
    needing anywhere to write the result.
    """
    input_path = Path(input_path)

    with input_path.open("rb") as inp:
        header = Header.read_from(inp)
        ad_header = header.associated_data

        master_key = derive_master_key(password, header.salt, header.argon2_params)
        subkeys = derive_subkeys(master_key)

        try:
            meta_bytes = read_sealed_section(
                inp,
                header.aead_id,
                subkeys.meta_key,
                ad_header,
                max_ciphertext_len=MAX_METADATA_CT_LEN,
            )
        except AuthenticationError as exc:
            raise WrongPasswordError("wrong password or corrupted file") from exc
        metadata = deserialize(meta_bytes)

        chunks_start = inp.tell()
        total_chunks, footer_offset = read_footer_at_end(inp)

        tag_len = tag_size(header.aead_id)
        min_frame_len = nonce_size(header.aead_id) + SECTION_LEN_FIELD_SIZE + tag_len
        available = footer_offset - chunks_start
        if available < 0 or total_chunks * min_frame_len > available:
            raise TruncatedFileError("declared chunk count exceeds the data actually present")

        inp.seek(chunks_start)
        max_chunk_ct_len = header.chunk_size + tag_len
        sink = _DiscardSink()

        if workers <= 1:
            _decrypt_chunks_sequential(
                inp,
                sink,
                header.aead_id,
                subkeys.data_key,
                ad_header,
                total_chunks,
                max_chunk_ct_len,
                progress_cb,
                metadata.original_size,
            )
        else:
            _decrypt_chunks_parallel(
                inp,
                sink,
                header.aead_id,
                subkeys.data_key,
                ad_header,
                total_chunks,
                max_chunk_ct_len,
                progress_cb,
                metadata.original_size,
                workers,
            )

        if inp.tell() != footer_offset:
            raise FormatError("leftover or missing bytes between the last chunk and the footer")

        return VerifyResult(
            format_version=header.format_version,
            aead_id=header.aead_id,
            chunk_size=header.chunk_size,
            total_chunks=total_chunks,
            original_size=metadata.original_size,
        )
