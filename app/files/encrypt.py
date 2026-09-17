"""Streaming file encryption: source file -> spec-compliant .thex container.

This is the first module that uses everything built so far together:

    Argon2id (crypto.kdf) -> HKDF subkeys (crypto.keys) -> AEAD (crypto.cipher)
    -> header + sealed sections + footer (format.*) -> encrypted metadata
    (metadata.metadata) -> chunked, bounded-memory I/O and an atomic write
    (files.stream)

See docs/file-format.md for the exact byte layout this produces.

`workers > 1` parallelizes the per-chunk `seal()` calls across threads
(_encrypt_chunks_parallel). This works because both AEAD backends release
the GIL for the duration of their C-level work - PyNaCl/libsodium and
OpenSSL (via `cryptography`) alike - so multiple chunks can genuinely
encrypt on different cores at once, even though Python's threading can't
parallelize pure-Python work. This matters most for XChaCha20-Poly1305:
benchmarking showed it running in software at roughly 1/10th AES-256-GCM's
throughput on hardware with AES acceleration (docs/threat-model.md), so
spreading that software cost across cores is the natural way to close (part
of) the gap without giving up the nonce-safety reason XChaCha20 is the
default. Chunks are always written to the file in order regardless of which
one finishes computing first - see _encrypt_chunks_parallel's docstring.
"""

from __future__ import annotations

import os
from collections import deque
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import BinaryIO

from app.crypto.cipher import ALGO_AES_256_GCM, ALGO_XCHACHA20_POLY1305, nonce_size, seal
from app.crypto.kdf import Argon2Params, default_params, derive_master_key, generate_salt
from app.crypto.keys import derive_subkeys
from app.files.stream import atomic_writer, iter_chunks
from app.format.container import (
    chunk_associated_data,
    write_footer,
    write_raw_frame,
    write_sealed_section,
)
from app.format.header import Header
from app.metadata.metadata import from_path, serialize

DEFAULT_AEAD_ID = ALGO_XCHACHA20_POLY1305
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB
DEFAULT_WORKERS = 1

# (bytes_done, total_bytes) -> None. Called after every chunk is written.
ProgressCallback = Callable[[int, int], None]

# One raw (unenumerated) chunk from iter_chunks: (chunk_bytes, is_final).
_ChunkSource = Iterator[tuple[int, tuple[bytes, bool]]]


def _data_chunk_nonce(aead_id: int, index: int, aes_gcm_prefix: bytes) -> bytes:
    """Nonce for chunk `index`, sealed under the shared data_key.

    XChaCha20-Poly1305: fresh random 24 bytes per chunk - safe because the
    nonce space is large enough that random collisions are negligible.

    AES-256-GCM: 96-bit nonces are not safe to pick at random across many
    messages under one key, so this profile uses a per-file random 4-byte
    prefix plus an 8-byte little-endian chunk counter, which guarantees
    uniqueness across the whole chunk stream by construction rather than by
    chance.
    """
    if aead_id == ALGO_XCHACHA20_POLY1305:
        return os.urandom(nonce_size(aead_id))
    return aes_gcm_prefix + index.to_bytes(8, "little")


def _encrypt_chunks_sequential(
    chunk_source: _ChunkSource,
    out: BinaryIO,
    aead_id: int,
    data_key: bytes,
    ad_header: bytes,
    aes_gcm_prefix: bytes,
    progress_cb: ProgressCallback | None,
    total_size: int,
) -> int:
    total_chunks = 0
    bytes_done = 0
    for index, (chunk, is_final) in chunk_source:
        nonce = _data_chunk_nonce(aead_id, index, aes_gcm_prefix)
        chunk_ad = chunk_associated_data(ad_header, index, is_final)
        write_sealed_section(out, aead_id, data_key, nonce, chunk, chunk_ad)
        total_chunks = index + 1
        bytes_done += len(chunk)
        if progress_cb is not None:
            progress_cb(bytes_done, total_size)
    return total_chunks


def _encrypt_chunks_parallel(
    chunk_source: _ChunkSource,
    out: BinaryIO,
    aead_id: int,
    data_key: bytes,
    ad_header: bytes,
    aes_gcm_prefix: bytes,
    progress_cb: ProgressCallback | None,
    total_size: int,
    workers: int,
) -> int:
    """Same output as _encrypt_chunks_sequential, sealing up to `workers`
    chunks concurrently on a thread pool.

    Chunks are read from `chunk_source` (hence submitted for encryption) in
    file order, but a thread pool makes no promise about which one
    *finishes* first. Writing out of order would produce a container whose
    bytes don't match the chunk indices baked into each chunk's own
    associated data - not silently wrong, since that would fail to decrypt,
    but pointless to risk. Instead, a fixed-size FIFO window holds futures
    in submission order: only once the *oldest* outstanding future is done
    do we write it and move on, regardless of whether newer ones already
    finished. This also bounds memory - at most `workers * 2` chunks'
    plaintext/ciphertext are ever alive at once - the same "bounded
    lookahead" principle as app.files.stream.iter_chunks, just widened to
    fit the pool.
    """
    window: deque[tuple[bytes, Future[bytes], int]] = deque()
    max_window = max(1, workers * 2)
    total_chunks = 0
    bytes_done = 0

    def _drain_one() -> None:
        nonlocal total_chunks, bytes_done
        nonce, future, chunk_len = window.popleft()
        ciphertext = future.result()
        write_raw_frame(out, nonce, ciphertext)
        total_chunks += 1
        bytes_done += chunk_len
        if progress_cb is not None:
            progress_cb(bytes_done, total_size)

    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        for index, (chunk, is_final) in chunk_source:
            nonce = _data_chunk_nonce(aead_id, index, aes_gcm_prefix)
            chunk_ad = chunk_associated_data(ad_header, index, is_final)
            future = executor.submit(seal, aead_id, data_key, nonce, chunk, chunk_ad)
            window.append((nonce, future, len(chunk)))
            if len(window) >= max_window:
                _drain_one()
        while window:
            _drain_one()
    finally:
        # cancel_futures drops any not-yet-started work immediately (relevant
        # if we're unwinding because progress_cb raised CancelledError);
        # wait=True still lets already-running seal() calls finish cleanly
        # rather than tearing down mid-call.
        executor.shutdown(wait=True, cancel_futures=True)

    return total_chunks


def encrypt_file(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str,
    *,
    aead_id: int = DEFAULT_AEAD_ID,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    argon2_params: Argon2Params | None = None,
    progress_cb: ProgressCallback | None = None,
    workers: int = DEFAULT_WORKERS,
) -> None:
    """Encrypt `input_path` into a .thex container at `output_path`.

    Streams the input in `chunk_size`-byte pieces; memory use stays roughly
    constant regardless of input file size (see app.files.stream.iter_chunks).
    Writes atomically: `output_path` is only created or replaced if the
    whole operation succeeds (see app.files.stream.atomic_writer). Raises
    FileNotFoundError before touching `output_path` at all if `input_path`
    does not exist.

    `workers`: number of chunks to seal concurrently (default 1, i.e. the
    original sequential behaviour, unchanged). Values > 1 use a thread pool
    - see _encrypt_chunks_parallel for why threads (not processes) work here
    and how chunk order is preserved regardless of completion order. The
    produced container is byte-for-byte structurally identical either way
    (aside from the random nonces every run picks regardless) and any
    `workers` value can decrypt a file encrypted with any other.
    """
    input_path = Path(input_path)
    params = argon2_params or default_params()

    # Stat the input (and validate it exists) before creating any output.
    metadata = from_path(input_path)

    salt = generate_salt()
    header = Header(aead_id=aead_id, chunk_size=chunk_size, argon2_params=params, salt=salt)
    ad_header = header.associated_data

    master_key = derive_master_key(password, salt, params)
    subkeys = derive_subkeys(master_key)

    aes_gcm_prefix = os.urandom(4) if aead_id == ALGO_AES_256_GCM else b""
    total_size = metadata.original_size

    with atomic_writer(output_path) as out, input_path.open("rb") as inp:
        out.write(header.pack())

        # Metadata is a single message under meta_key: a plain random nonce
        # is always safe here, regardless of algorithm (see file-format.md §7).
        meta_nonce = os.urandom(nonce_size(aead_id))
        write_sealed_section(
            out, aead_id, subkeys.meta_key, meta_nonce, serialize(metadata), ad_header
        )

        chunk_source = enumerate(iter_chunks(inp, chunk_size))
        if workers <= 1:
            total_chunks = _encrypt_chunks_sequential(
                chunk_source,
                out,
                aead_id,
                subkeys.data_key,
                ad_header,
                aes_gcm_prefix,
                progress_cb,
                total_size,
            )
        else:
            total_chunks = _encrypt_chunks_parallel(
                chunk_source,
                out,
                aead_id,
                subkeys.data_key,
                ad_header,
                aes_gcm_prefix,
                progress_cb,
                total_size,
                workers,
            )

        write_footer(out, total_chunks)
