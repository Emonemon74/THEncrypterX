"""Streaming file encryption: source file -> spec-compliant .thex container.

This is the first module that uses everything built so far together:

    Argon2id (crypto.kdf) -> HKDF subkeys (crypto.keys) -> AEAD (crypto.cipher)
    -> header + sealed sections + footer (format.*) -> encrypted metadata
    (metadata.metadata) -> chunked, bounded-memory I/O and an atomic write
    (files.stream)

See docs/file-format.md for the exact byte layout this produces.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from app.crypto.cipher import ALGO_AES_256_GCM, ALGO_XCHACHA20_POLY1305, nonce_size
from app.crypto.kdf import Argon2Params, default_params, derive_master_key, generate_salt
from app.crypto.keys import derive_subkeys
from app.files.stream import atomic_writer, iter_chunks
from app.format.container import chunk_associated_data, write_footer, write_sealed_section
from app.format.header import Header
from app.metadata.metadata import from_path, serialize

DEFAULT_AEAD_ID = ALGO_XCHACHA20_POLY1305
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB

# (bytes_done, total_bytes) -> None. Called after every chunk is written.
ProgressCallback = Callable[[int, int], None]


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


def encrypt_file(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str,
    *,
    aead_id: int = DEFAULT_AEAD_ID,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    argon2_params: Argon2Params | None = None,
    progress_cb: ProgressCallback | None = None,
) -> None:
    """Encrypt `input_path` into a .thex container at `output_path`.

    Streams the input in `chunk_size`-byte pieces; memory use stays roughly
    constant regardless of input file size (see app.files.stream.iter_chunks).
    Writes atomically: `output_path` is only created or replaced if the
    whole operation succeeds (see app.files.stream.atomic_writer). Raises
    FileNotFoundError before touching `output_path` at all if `input_path`
    does not exist.
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
    bytes_done = 0

    with atomic_writer(output_path) as out, input_path.open("rb") as inp:
        out.write(header.pack())

        # Metadata is a single message under meta_key: a plain random nonce
        # is always safe here, regardless of algorithm (see file-format.md §7).
        meta_nonce = os.urandom(nonce_size(aead_id))
        write_sealed_section(
            out, aead_id, subkeys.meta_key, meta_nonce, serialize(metadata), ad_header
        )

        total_chunks = 0
        for index, (chunk, is_final) in enumerate(iter_chunks(inp, chunk_size)):
            nonce = _data_chunk_nonce(aead_id, index, aes_gcm_prefix)
            chunk_ad = chunk_associated_data(ad_header, index, is_final)
            write_sealed_section(out, aead_id, subkeys.data_key, nonce, chunk, chunk_ad)
            total_chunks = index + 1
            bytes_done += len(chunk)
            if progress_cb is not None:
                progress_cb(bytes_done, total_size)

        write_footer(out, total_chunks)
