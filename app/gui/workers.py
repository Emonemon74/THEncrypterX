"""Background QThread workers for encryption/decryption.

app.gui.main_window previously ran EncryptJob/DecryptJob directly on the GUI
thread, which freezes the whole window for the duration of any real file.
This module is the fix: each worker runs one job on its own QThread and
communicates back to the GUI thread only through Qt signals. Signals are
safe to emit across threads by construction - Qt queues a cross-thread
signal emission onto the receiving object's own thread (the GUI thread's
event loop) rather than calling the connected slot immediately in the
worker thread - so no manual locking is needed anywhere in this file.

Cancellation is still cooperative (app.core.progress.CancellationToken):
`cancel()` just sets a flag; the worker thread notices it the next time a
chunk's progress callback runs and stops itself by letting CancelledError
propagate, which app.files.stream.atomic_writer turns into "no output left
behind" exactly as it does for any other exception.
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from app.core.errors import CancelledError, ThexError
from app.core.progress import CancellationToken, Progress
from app.core.service import DecryptJob, EncryptJob
from app.crypto.cipher import ALGO_XCHACHA20_POLY1305
from app.files.encrypt import DEFAULT_CHUNK_SIZE, DEFAULT_WORKERS
from app.metadata.metadata import FileMetadata


class EncryptWorker(QThread):
    """Runs one EncryptJob on a background thread."""

    progress = Signal(object)  # Progress (bytes_done, bytes_total)
    finished_ok = Signal(str)  # output path
    failed = Signal(str)  # user-facing error message
    cancelled = Signal()

    def __init__(
        self,
        input_path: str | os.PathLike[str],
        output_path: str | os.PathLike[str],
        password: str,
        *,
        aead_id: int = ALGO_XCHACHA20_POLY1305,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        workers: int = DEFAULT_WORKERS,
        parent: QThread | None = None,
    ) -> None:
        super().__init__(parent)
        self._job = EncryptJob(
            Path(input_path),
            Path(output_path),
            password,
            aead_id=aead_id,
            chunk_size=chunk_size,
            workers=workers,
        )
        self._cancel_token = CancellationToken()
        self._output_path = str(output_path)

    def cancel(self) -> None:
        """Thread-safe: called from the GUI thread while run() executes here."""
        self._cancel_token.cancel()

    def run(self) -> None:
        def on_progress(p: Progress) -> None:
            self.progress.emit(p)

        try:
            self._job.run(on_progress=on_progress, cancel_token=self._cancel_token)
        except CancelledError:
            self.cancelled.emit()
        except ThexError as exc:
            self.failed.emit(str(exc))
        else:
            self.finished_ok.emit(self._output_path)


class DecryptWorker(QThread):
    """Runs one DecryptJob on a background thread."""

    progress = Signal(object)  # Progress (bytes_done, bytes_total)
    finished_ok = Signal(object)  # FileMetadata
    failed = Signal(str)
    cancelled = Signal()

    def __init__(
        self,
        input_path: str | os.PathLike[str],
        output_path: str | os.PathLike[str] | None,
        password: str,
        *,
        workers: int = DEFAULT_WORKERS,
        parent: QThread | None = None,
    ) -> None:
        super().__init__(parent)
        self._job = DecryptJob(
            Path(input_path),
            Path(output_path) if output_path else None,
            password,
            workers=workers,
        )
        self._cancel_token = CancellationToken()

    def cancel(self) -> None:
        self._cancel_token.cancel()

    def run(self) -> None:
        def on_progress(p: Progress) -> None:
            self.progress.emit(p)

        try:
            metadata: FileMetadata = self._job.run(
                on_progress=on_progress, cancel_token=self._cancel_token
            )
        except CancelledError:
            self.cancelled.emit()
        except (ThexError, FileExistsError) as exc:
            self.failed.emit(str(exc))
        else:
            self.finished_ok.emit(metadata)
