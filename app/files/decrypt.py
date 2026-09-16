"""Streaming file decryption: .thex container -> original file.

Fail-closed by construction: header parsing, key derivation, metadata
authentication, and a chunk-count sanity check all happen *before*
`output_path` is touched, and the chunk loop writes through
`app.files.stream.atomic_writer`, which only publishes the output if every
chunk in the file authenticates. A failure at any point leaves `output_path`
exactly as it was - never a partial or corrupted file.
"""

from __future__ import annotations

import os
from pathlib import Path

from app.core.errors import (
    AuthenticationError,
    FormatError,
    IntegrityError,
    TruncatedFileError,
    WrongPasswordError,
)
from app.crypto.cipher import nonce_size, tag_size
from app.crypto.kdf import derive_master_key
from app.crypto.keys import derive_subkeys
from app.files.encrypt import ProgressCallback
from app.files.stream import atomic_writer
from app.format.constants import MAX_METADATA_CT_LEN, SECTION_LEN_FIELD_SIZE
from app.format.container import chunk_associated_data, read_footer_at_end, read_sealed_section
from app.format.header import Header
from app.metadata.metadata import FileMetadata, deserialize


def decrypt_file(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str] | None,
    password: str,
    *,
    progress_cb: ProgressCallback | None = None,
) -> FileMetadata:
    """Decrypt `input_path` (a .thex container) into `output_path`.

    If `output_path` is None, the output name is taken from the authenticated
    metadata's `original_name` and placed next to `input_path` - and, unlike
    an explicit `output_path` (which is always overwritten, matching
    app.files.encrypt's semantics), this auto-derived path refuses to
    overwrite an existing file: raises FileExistsError rather than silently
    clobbering something the caller didn't explicitly name.

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

        if output_path is None:
            resolved_output = input_path.parent / metadata.original_name
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
        bytes_done = 0

        with atomic_writer(resolved_output) as out:
            for index in range(total_chunks):
                is_final = index == total_chunks - 1
                chunk_ad = chunk_associated_data(ad_header, index, is_final)
                try:
                    plaintext = read_sealed_section(
                        inp,
                        header.aead_id,
                        subkeys.data_key,
                        chunk_ad,
                        max_ciphertext_len=max_chunk_ct_len,
                    )
                except AuthenticationError as exc:
                    raise IntegrityError(f"chunk {index} failed authentication") from exc

                out.write(plaintext)
                bytes_done += len(plaintext)
                if progress_cb is not None:
                    progress_cb(bytes_done, metadata.original_size)

            if inp.tell() != footer_offset:
                raise FormatError("leftover or missing bytes between the last chunk and the footer")

        return metadata
