"""Tests for app.core.progress."""

from __future__ import annotations

import threading

import pytest

from app.core.errors import CancelledError
from app.core.progress import CancellationToken, Progress


def test_progress_fraction_midway() -> None:
    assert Progress(bytes_done=5, bytes_total=10).fraction == 0.5


def test_progress_fraction_complete() -> None:
    assert Progress(bytes_done=10, bytes_total=10).fraction == 1.0


def test_progress_fraction_zero_total_reports_complete() -> None:
    # An empty file: nothing left to do, not "0% forever".
    assert Progress(bytes_done=0, bytes_total=0).fraction == 1.0


def test_progress_fraction_clamped_to_one() -> None:
    assert Progress(bytes_done=15, bytes_total=10).fraction == 1.0


def test_token_not_cancelled_initially() -> None:
    token = CancellationToken()
    assert not token.cancelled
    token.raise_if_cancelled()  # must not raise


def test_token_cancel_sets_flag_and_raises() -> None:
    token = CancellationToken()
    token.cancel()
    assert token.cancelled
    with pytest.raises(CancelledError):
        token.raise_if_cancelled()


def test_token_cancel_is_idempotent() -> None:
    token = CancellationToken()
    token.cancel()
    token.cancel()
    assert token.cancelled


def test_token_cancel_from_another_thread_is_observed() -> None:
    token = CancellationToken()
    observed_cancelled = threading.Event()

    def worker() -> None:
        while not token.cancelled:
            pass
        observed_cancelled.set()

    t = threading.Thread(target=worker)
    t.start()
    token.cancel()
    t.join(timeout=5)

    assert observed_cancelled.is_set()
