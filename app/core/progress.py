"""Progress reporting and cooperative cancellation, shared by the CLI and GUI.

Encryption/decryption run synchronously from the CLI but on a background
QThread from the GUI (app.gui.workers) so the window stays responsive. Both
need the same two primitives: a richer progress update than the raw
(bytes_done, bytes_total) callback app.files.encrypt/decrypt expose, and a
way to ask a running job to stop between chunks.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass

from app.core.errors import CancelledError


@dataclass(frozen=True, slots=True)
class Progress:
    """A single progress update."""

    bytes_done: int
    bytes_total: int

    @property
    def fraction(self) -> float:
        """0.0-1.0. A non-positive total (e.g. an empty file) reports 1.0 -
        there is nothing left to do, not "0% forever"."""
        if self.bytes_total <= 0:
            return 1.0
        return min(1.0, self.bytes_done / self.bytes_total)


ProgressCallback = Callable[[Progress], None]


class CancellationToken:
    """Cooperative cancellation.

    A running job calls `raise_if_cancelled()` between chunks; `cancel()` may
    be called from a different thread - e.g. the GUI thread reacting to a
    Cancel button while the worker thread is mid-encryption -
    `threading.Event` is thread-safe by design, so no extra locking is
    needed here.
    """

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise CancelledError("operation cancelled")
