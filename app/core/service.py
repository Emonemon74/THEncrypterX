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
    """Encrypt `input_path` into `output_path`. See app.files.encrypt.encrypt_file."""

    input_path: str | os.PathLike[str]
    output_path: str | os.PathLike[str]
    password: str
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
            aead_id=self.aead_id,
            chunk_size=self.chunk_size,
            argon2_params=self.argon2_params,
            progress_cb=_bridge(on_progress, cancel_token),
            workers=self.workers,
        )


@dataclass(frozen=True, slots=True)
class DecryptJob:
    """Decrypt `input_path` into `output_path`. See app.files.decrypt.decrypt_file."""

    input_path: str | os.PathLike[str]
    output_path: str | os.PathLike[str] | None
    password: str
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
            progress_cb=_bridge(on_progress, cancel_token),
            workers=self.workers,
        )


@dataclass(frozen=True, slots=True)
class VerifyJob:
    """Authenticate `input_path` in full - header, metadata, every chunk -
    without writing plaintext anywhere. See app.files.verify.verify_file.
    """

    input_path: str | os.PathLike[str]
    password: str
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
            progress_cb=_bridge(on_progress, cancel_token),
            workers=self.workers,
        )


@dataclass(frozen=True, slots=True)
class HeaderInfo:
    """A read-only snapshot of a .thex container's unencrypted header.

    Everything here is visible without a password - that is the whole point
    of InspectJob.
    """

    format_version: int
    aead_id: int
    chunk_size: int
    argon2_memory_cost_kib: int
    argon2_time_cost: int
    argon2_parallelism: int
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

        return HeaderInfo(
            format_version=header.format_version,
            aead_id=header.aead_id,
            chunk_size=header.chunk_size,
            argon2_memory_cost_kib=header.argon2_params.memory_cost_kib,
            argon2_time_cost=header.argon2_params.time_cost,
            argon2_parallelism=header.argon2_params.parallelism,
            salt_hex=header.salt.hex(),
            total_chunks=total_chunks,
        )
