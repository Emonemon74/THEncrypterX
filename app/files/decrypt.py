"""Streaming file decryption: .thex container -> original file.

Fail-closed by construction: header parsing, key derivation, metadata
authentication, and a chunk-count sanity check all happen *before*
`output_path` is touched, and the chunk loop writes through
`app.files.stream.atomic_writer`, which only publishes the output if every
chunk in the file authenticates. A failure at any point leaves `output_path`
exactly as it was - never a partial or corrupted file.

`workers > 1` parallelizes the per-chunk `open_()` calls across threads
(_decrypt_chunks_parallel), mirroring app.files.encrypt's parallel path -
see its module docstring for why threads genuinely help here (both AEAD
backends release the GIL during their C-level work).
"""

from __future__ import annotations

import os
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import BinaryIO

from app.core.errors import (
    AuthenticationError,
    FormatError,
    IntegrityError,
    TruncatedFileError,
    WrongPasswordError,
)
from app.crypto.cipher import nonce_size, open_, tag_size
from app.crypto.kdf import derive_master_key
from app.crypto.keys import derive_subkeys
from app.files.encrypt import DEFAULT_WORKERS, ProgressCallback
from app.files.stream import atomic_writer
from app.format.constants import MAX_METADATA_CT_LEN, SECTION_LEN_FIELD_SIZE
from app.format.container import (
    chunk_associated_data,
    read_footer_at_end,
    read_raw_frame,
    read_sealed_section,
)
from app.format.header import Header
from app.metadata.metadata import FileMetadata, deserialize


def _decrypt_chunks_sequential(
    inp: BinaryIO,
    out: BinaryIO,
    aead_id: int,
    data_key: bytes,
    ad_header: bytes,
    total_chunks: int,
    max_chunk_ct_len: int,
    progress_cb: ProgressCallback | None,
    total_size: int,
) -> None:
    bytes_done = 0
    for index in range(total_chunks):
        is_final = index == total_chunks - 1
        chunk_ad = chunk_associated_data(ad_header, index, is_final)
        try:
            plaintext = read_sealed_section(
                inp, aead_id, data_key, chunk_ad, max_ciphertext_len=max_chunk_ct_len
            )
        except AuthenticationError as exc:
            raise IntegrityError(f"chunk {index} failed authentication") from exc

        out.write(plaintext)
        bytes_done += len(plaintext)
        if progress_cb is not None:
            progress_cb(bytes_done, total_size)


def _decrypt_chunks_parallel(
    inp: BinaryIO,
    out: BinaryIO,
    aead_id: int,
    data_key: bytes,
    ad_header: bytes,
    total_chunks: int,
    max_chunk_ct_len: int,
    progress_cb: ProgressCallback | None,
    total_size: int,
    workers: int,
) -> None:
    """Same output as _decrypt_chunks_sequential, opening up to `workers`
    chunks concurrently on a thread pool.

    Reading each frame's bytes off disk stays strictly sequential on the
    calling thread - a frame's length is only known after reading its
    length prefix, so there is no way to read frame i+1 without having
    already read frame i - but that read is cheap I/O, not the bottleneck.
    The CPU-bound open_() call for each frame is handed to the pool as soon
    as its bytes are in hand, so reading frame i+1 can proceed while frame
    i is still being authenticated on another core. Plaintext is written in
    the same FIFO-window order as app.files.encrypt._encrypt_chunks_parallel,
    for the same reason: file order must not depend on which chunk's
    computation happens to finish first.
    """
    window: deque[tuple[int, Future[bytes]]] = deque()
    max_window = max(1, workers * 2)
    bytes_done = 0

    def _drain_one() -> None:
        nonlocal bytes_done
        index, future = window.popleft()
        try:
            plaintext = future.result()
        except AuthenticationError as exc:
            raise IntegrityError(f"chunk {index} failed authentication") from exc
        out.write(plaintext)
        bytes_done += len(plaintext)
        if progress_cb is not None:
            progress_cb(bytes_done, total_size)

    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        for index in range(total_chunks):
            is_final = index == total_chunks - 1
            chunk_ad = chunk_associated_data(ad_header, index, is_final)
            nonce, ciphertext = read_raw_frame(inp, aead_id, max_chunk_ct_len)
            future = executor.submit(open_, aead_id, data_key, nonce, ciphertext, chunk_ad)
            window.append((index, future))
            if len(window) >= max_window:
                _drain_one()
        while window:
            _drain_one()
    finally:
        executor.shutdown(wait=True, cancel_futures=True)


def decrypt_file(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str] | None,
    password: str,
    *,
    progress_cb: ProgressCallback | None = None,
    workers: int = DEFAULT_WORKERS,
) -> FileMetadata:
    """Decrypt `input_path` (a .thex container) into `output_path`.

    If `output_path` is None, the output name is taken from the authenticated
    metadata's `original_name` and placed next to `input_path` - and, unlike
    an explicit `output_path` (which is always overwritten, matching
    app.files.encrypt's semantics), this auto-derived path refuses to
    overwrite an existing file: raises FileExistsError rather than silently
    clobbering something the caller didn't explicitly name.

    `workers`: number of chunks to authenticate/decrypt concurrently
    (default 1). Independent of how many workers were used to *encrypt* the
    file - any value can decrypt a container produced with any other, since
    chunk order in the file never depends on it.

    Returns the authenticated FileMetadata (original filename/size/mtime) on
    success. Raises WrongPasswordError, IntegrityError, TruncatedFileError,
    FormatError, UnsupportedVersionError, or UnsupportedAlgorithmError on
    failure. The output path is left completely untouched on any failure - it
    is only created/replaced once decryption has fully succeeded.
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
            # Indistinguishable, by design, from a genuinely wrong password:
            # this also fires if the salt, KDF params, or metadata ciphertext
            # were tampered with.
            raise WrongPasswordError("wrong password or corrupted file") from exc
        metadata = deserialize(meta_bytes)

        must_not_exist = output_path is None
        if output_path is None:
            resolved_output = input_path.parent / metadata.original_name
            # Fast, friendly failure for the common case. This check alone
            # would be a TOCTOU race for a large file (something else could
            # create resolved_output while decryption is still running) -
            # atomic_writer's must_not_exist=True below is what actually
            # closes that window at publish time.
            if resolved_output.exists():
                raise FileExistsError(
                    f"refusing to overwrite existing file {resolved_output} "
                    "- pass an explicit output path to overwrite it"
                )
        else:
            resolved_output = Path(output_path)

        chunks_start = inp.tell()
        total_chunks, footer_offset = read_footer_at_end(inp)

        # Cheap, O(1) sanity check: if the declared chunk count could not
        # possibly fit in the bytes actually present, fail now rather than
        # looping (and rather than trusting an attacker-controlled u64).
        tag_len = tag_size(header.aead_id)
        min_frame_len = nonce_size(header.aead_id) + SECTION_LEN_FIELD_SIZE + tag_len
        available = footer_offset - chunks_start
        if available < 0 or total_chunks * min_frame_len > available:
            raise TruncatedFileError("declared chunk count exceeds the data actually present")

        inp.seek(chunks_start)
        max_chunk_ct_len = header.chunk_size + tag_len

        with atomic_writer(resolved_output, must_not_exist=must_not_exist) as out:
            if workers <= 1:
                _decrypt_chunks_sequential(
                    inp,
                    out,
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
                    out,
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

        return metadata
