"""Orchestration jobs shared by the CLI and GUI: encrypt, decrypt, inspect.

No cryptographic or format logic lives here - each job only wires an
app.files function to the richer Progress/CancellationToken interface in
app.core.progress, instead of the raw (bytes_done, bytes_total) callback
app.files.encrypt/decrypt expose directly. This is the layer app.gui.workers
runs on a background thread; app.cli could use it too, though it currently
calls app.files directly since it runs synchronously either way.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass

from app.core.progress import CancellationToken, Progress, ProgressCallback
from app.crypto.cipher import ALGO_XCHACHA20_POLY1305
from app.crypto.kdf import Argon2Params
from app.files.decrypt import decrypt_file
from app.files.encrypt import DEFAULT_CHUNK_SIZE, DEFAULT_WORKERS, encrypt_file
from app.files.verify import VerifyResult, verify_file
from app.format.container import read_footer_at_end
from app.format.header import Header
from app.metadata.metadata import FileMetadata


def _bridge(
    on_progress: ProgressCallback | None, cancel_token: CancellationToken | None
) -> Callable[[int, int], None]:
    """Build the raw (bytes_done, total) callback app.files functions expect,
    checking cancellation and forwarding a Progress object.
    """

    def _cb(done: int, total: int) -> None:
        if cancel_token is not None:
            cancel_token.raise_if_cancelled()
        if on_progress is not None:
            on_progress(Progress(bytes_done=done, bytes_total=total))

    return _cb


@dataclass(frozen=True, slots=True)
class EncryptJob:
    """Encrypt `input_path` into `output_path`. See app.files.encrypt.encrypt_file.

    Exactly one of `password`/`key` should be set - not yet exposed in the
    GUI (roadmap Step 9 is CLI-first; `key` exists here for API parity with
    app.files.encrypt.encrypt_file so a future GUI key-file picker is a
    thin addition, not a redesign).
    """

    input_path: str | os.PathLike[str]
    output_path: str | os.PathLike[str]
    password: str | None = None
    key: bytes | None = None
    aead_id: int = ALGO_XCHACHA20_POLY1305
    chunk_size: int = DEFAULT_CHUNK_SIZE
    argon2_params: Argon2Params | None = None
    workers: int = DEFAULT_WORKERS

    def run(
        self,
        *,
        on_progress: ProgressCallback | None = None,
        cancel_token: CancellationToken | None = None,
    ) -> None:
        encrypt_file(
            self.input_path,
            self.output_path,
            self.password,
            key=self.key,
            aead_id=self.aead_id,
            chunk_size=self.chunk_size,
            argon2_params=self.argon2_params,
            progress_cb=_bridge(on_progress, cancel_token),
            workers=self.workers,
        )


@dataclass(frozen=True, slots=True)
class DecryptJob:
    """Decrypt `input_path` into `output_path`. See app.files.decrypt.decrypt_file.

    Exactly one of `password`/`key` should be set - see EncryptJob's
    docstring for why `key` exists here ahead of any GUI support for it.
    """

    input_path: str | os.PathLike[str]
    output_path: str | os.PathLike[str] | None
    password: str | None = None
    key: bytes | None = None
    workers: int = DEFAULT_WORKERS

    def run(
        self,
        *,
        on_progress: ProgressCallback | None = None,
        cancel_token: CancellationToken | None = None,
    ) -> FileMetadata:
        return decrypt_file(
            self.input_path,
            self.output_path,
            self.password,
            key=self.key,
            progress_cb=_bridge(on_progress, cancel_token),
            workers=self.workers,
        )


@dataclass(frozen=True, slots=True)
class VerifyJob:
    """Authenticate `input_path` in full - header, metadata, every chunk -
    without writing plaintext anywhere. See app.files.verify.verify_file.

    Exactly one of `password`/`key` should be set - see EncryptJob's
    docstring for why `key` exists here ahead of any GUI support for it.
    """

    input_path: str | os.PathLike[str]
    password: str | None = None
    key: bytes | None = None
    workers: int = DEFAULT_WORKERS

    def run(
        self,
        *,
        on_progress: ProgressCallback | None = None,
        cancel_token: CancellationToken | None = None,
    ) -> VerifyResult:
        return verify_file(
            self.input_path,
            self.password,
            key=self.key,
            progress_cb=_bridge(on_progress, cancel_token),
            workers=self.workers,
        )


@dataclass(frozen=True, slots=True)
class HeaderInfo:
    """A read-only snapshot of a .thex container's unencrypted header.

    Everything here is visible without a password - that is the whole point
    of InspectJob. `argon2_*` fields are None when `kdf_id` is
    `KDF_ID_KEYFILE` (see app/format/header.py) - the file needs a key file,
    not a password, and has no Argon2 parameters to show.
    """

    format_version: int
    aead_id: int
    chunk_size: int
    kdf_id: int
    argon2_memory_cost_kib: int | None
    argon2_time_cost: int | None
    argon2_parallelism: int | None
    salt_hex: str
    total_chunks: int


@dataclass(frozen=True, slots=True)
class InspectJob:
    """Read a .thex container's header and footer. Needs no password."""

    input_path: str | os.PathLike[str]

    def run(self) -> HeaderInfo:
        with open(self.input_path, "rb") as f:
            header = Header.read_from(f)
            total_chunks, _ = read_footer_at_end(f)

        p = header.argon2_params
        return HeaderInfo(
            format_version=header.format_version,
            aead_id=header.aead_id,
            chunk_size=header.chunk_size,
            kdf_id=header.kdf_id,
            argon2_memory_cost_kib=p.memory_cost_kib if p is not None else None,
            argon2_time_cost=p.time_cost if p is not None else None,
            argon2_parallelism=p.parallelism if p is not None else None,
            salt_hex=header.salt.hex(),
            total_chunks=total_chunks,
        )
