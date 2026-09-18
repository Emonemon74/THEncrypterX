"""Tests for app.gui.main_window (pytest-qt, offscreen Qt platform).

QMessageBox.critical() is a modal call that would otherwise block waiting
for a click that never comes in an automated test - every test stubs it out
via the `no_blocking_dialogs` fixture.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from PySide6.QtCore import QMimeData, QUrl
from pytestqt.qtbot import QtBot

from app.gui import main_window as mw

CHEAP_ENV = {"THEX_ARGON2_MEMORY_KIB": "8192"}


@pytest.fixture(autouse=True)
def no_blocking_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mw.QMessageBox, "critical", lambda *a, **k: None)


class _FakeDragEvent:
    def __init__(self, mime: QMimeData) -> None:
        self._mime = mime
        self.accepted = False

    def mimeData(self) -> QMimeData:
        return self._mime

    def acceptProposedAction(self) -> None:
        self.accepted = True


def _mime_with_file(path: Path) -> QMimeData:
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(path))])
    return mime


def _wait_for_job(qtbot: QtBot, window: mw.MainWindow, timeout: int = 5000) -> None:
    """Jobs run on a background QThread now - wait for it to finish (or fail
    or be cancelled) rather than asserting immediately after a click.

    Also explicitly joins the worker's OS thread (QThread.wait()) once its
    finished/failed/cancelled signal has fired, instead of just letting the
    Python object go out of scope. By the time the signal is emitted, run()
    is essentially done, so this returns almost immediately - it exists so
    no test leaves a not-quite-joined thread lingering into the next one,
    which is standard Qt practice (see QThread's own docs) and one less
    variable when a test is slow on an unfamiliar CI machine.
    """
    worker = window._worker
    qtbot.waitUntil(lambda: window._worker is None, timeout=timeout)
    if worker is not None:
        worker.wait(2000)


def test_window_title(qtbot: QtBot) -> None:
    window = mw.MainWindow()
    qtbot.addWidget(window)
    assert window.windowTitle() == "THEncrypterX"


def test_initial_state(qtbot: QtBot) -> None:
    window = mw.MainWindow()
    qtbot.addWidget(window)
    assert "none" in window.selected_label.text()
    assert not window.cancel_button.isEnabled()
    assert window.progress_bar.value() == 0


def test_select_file_updates_label(qtbot: QtBot, tmp_path: Path) -> None:
    window = mw.MainWindow()
    qtbot.addWidget(window)
    target = tmp_path / "doc.txt"
    target.write_bytes(b"data")

    window._set_selected_file(target)

    assert str(target) in window.selected_label.text()


def test_drag_enter_accepts_file_urls(qtbot: QtBot, tmp_path: Path) -> None:
    window = mw.MainWindow()
    qtbot.addWidget(window)
    target = tmp_path / "doc.txt"
    target.write_bytes(b"data")

    event = _FakeDragEvent(_mime_with_file(target))
    window.drop_area.dragEnterEvent(event)  # type: ignore[arg-type]

    assert event.accepted


def test_drop_event_selects_the_file(qtbot: QtBot, tmp_path: Path) -> None:
    window = mw.MainWindow()
    qtbot.addWidget(window)
    target = tmp_path / "dropped.bin"
    target.write_bytes(b"payload")

    event = _FakeDragEvent(_mime_with_file(target))
    window.drop_area.dropEvent(event)  # type: ignore[arg-type]

    assert window._selected_file == target
    assert "dropped.bin" in window.selected_label.text()


def test_show_password_toggle(qtbot: QtBot) -> None:
    window = mw.MainWindow()
    qtbot.addWidget(window)
    assert window.password_edit.echoMode() == mw.QLineEdit.EchoMode.Password

    qtbot.mouseClick(window.show_password_button, mw.Qt.MouseButton.LeftButton)

    assert window.password_edit.echoMode() == mw.QLineEdit.EchoMode.Normal
    assert window.show_password_button.text() == "Hide"


def test_encrypt_without_file_shows_error(qtbot: QtBot) -> None:
    window = mw.MainWindow()
    qtbot.addWidget(window)
    window.password_edit.setText("pw")

    qtbot.mouseClick(window.encrypt_button, mw.Qt.MouseButton.LeftButton)

    assert "Select a file" in window.status_label.text()


def test_encrypt_without_password_shows_error(qtbot: QtBot, tmp_path: Path) -> None:
    window = mw.MainWindow()
    qtbot.addWidget(window)
    target = tmp_path / "doc.txt"
    target.write_bytes(b"data")
    window._set_selected_file(target)

    qtbot.mouseClick(window.encrypt_button, mw.Qt.MouseButton.LeftButton)

    assert "Enter a password" in window.status_label.text()


def test_encrypt_then_decrypt_roundtrip_via_buttons(qtbot: QtBot, tmp_path: Path) -> None:
    src = tmp_path / "secret.txt"
    src.write_bytes(b"gui roundtrip content")

    encrypt_window = mw.MainWindow()
    qtbot.addWidget(encrypt_window)
    encrypt_window._set_selected_file(src)
    encrypt_window.password_edit.setText("pw")

    qtbot.mouseClick(encrypt_window.encrypt_button, mw.Qt.MouseButton.LeftButton)
    _wait_for_job(qtbot, encrypt_window)

    enc_path = tmp_path / "secret.txt.thex"
    assert enc_path.exists()
    assert "Encrypted" in encrypt_window.status_label.text()
    assert encrypt_window.progress_bar.value() == 100
    assert not encrypt_window.cancel_button.isEnabled()
    src.unlink()  # so decrypt's default output path is free

    decrypt_window = mw.MainWindow()
    qtbot.addWidget(decrypt_window)
    decrypt_window._set_selected_file(enc_path)
    decrypt_window.password_edit.setText("pw")

    qtbot.mouseClick(decrypt_window.decrypt_button, mw.Qt.MouseButton.LeftButton)
    _wait_for_job(qtbot, decrypt_window)

    assert "Decrypted" in decrypt_window.status_label.text()
    assert src.read_bytes() == b"gui roundtrip content"


def test_decrypt_wrong_password_shows_error(qtbot: QtBot, tmp_path: Path) -> None:
    src = tmp_path / "secret.txt"
    src.write_bytes(b"content")

    encrypt_window = mw.MainWindow()
    qtbot.addWidget(encrypt_window)
    encrypt_window._set_selected_file(src)
    encrypt_window.password_edit.setText("right-pw")
    qtbot.mouseClick(encrypt_window.encrypt_button, mw.Qt.MouseButton.LeftButton)
    _wait_for_job(qtbot, encrypt_window)

    decrypt_window = mw.MainWindow()
    qtbot.addWidget(decrypt_window)
    decrypt_window._set_selected_file(tmp_path / "secret.txt.thex")
    decrypt_window.password_edit.setText("wrong-pw")

    qtbot.mouseClick(decrypt_window.decrypt_button, mw.Qt.MouseButton.LeftButton)
    _wait_for_job(qtbot, decrypt_window)

    assert "Error" in decrypt_window.status_label.text()


def test_explicit_output_path_used(qtbot: QtBot, tmp_path: Path) -> None:
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")
    custom_out = tmp_path / "custom.thex"

    window = mw.MainWindow()
    qtbot.addWidget(window)
    window._set_selected_file(src)
    window.password_edit.setText("pw")
    window._output_path = custom_out

    qtbot.mouseClick(window.encrypt_button, mw.Qt.MouseButton.LeftButton)
    _wait_for_job(qtbot, window)

    assert custom_out.exists()


def test_cancel_button_disabled_when_idle(qtbot: QtBot) -> None:
    window = mw.MainWindow()
    qtbot.addWidget(window)
    assert not window.cancel_button.isEnabled()


def test_encrypt_click_starts_a_worker_synchronously(qtbot: QtBot, tmp_path: Path) -> None:
    # worker.start() launches the OS thread asynchronously, but _start_worker
    # assigns window._worker and enables Cancel *before* calling start() - so
    # this must be true immediately, regardless of how fast the job itself is.
    src = tmp_path / "in.bin"
    src.write_bytes(b"data")
    window = mw.MainWindow()
    qtbot.addWidget(window)
    window._set_selected_file(src)
    window.password_edit.setText("pw")

    qtbot.mouseClick(window.encrypt_button, mw.Qt.MouseButton.LeftButton)

    assert window._worker is not None
    _wait_for_job(qtbot, window)


def test_algorithm_choice_is_passed_to_the_worker(qtbot: QtBot, tmp_path: Path) -> None:
    from app.crypto.cipher import ALGO_AES_256_GCM
    from app.format.header import Header

    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")
    window = mw.MainWindow()
    qtbot.addWidget(window)
    window._set_selected_file(src)
    window.password_edit.setText("pw")
    window.algo_combo.setCurrentText("AES-256-GCM (faster, less nonce headroom)")

    qtbot.mouseClick(window.encrypt_button, mw.Qt.MouseButton.LeftButton)
    _wait_for_job(qtbot, window)

    out = tmp_path / "doc.txt.thex"
    with out.open("rb") as f:
        header = Header.read_from(f)
    assert header.aead_id == ALGO_AES_256_GCM


def test_chunk_size_choice_is_passed_to_the_worker(qtbot: QtBot, tmp_path: Path) -> None:
    from app.format.header import Header

    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")
    window = mw.MainWindow()
    qtbot.addWidget(window)
    window._set_selected_file(src)
    window.password_edit.setText("pw")
    window.chunk_size_combo.setCurrentText("1 MiB")

    qtbot.mouseClick(window.encrypt_button, mw.Qt.MouseButton.LeftButton)
    _wait_for_job(qtbot, window)

    out = tmp_path / "doc.txt.thex"
    with out.open("rb") as f:
        header = Header.read_from(f)
    assert header.chunk_size == 1024 * 1024


def test_settings_combos_disabled_while_busy_and_re_enabled_after(
    qtbot: QtBot, tmp_path: Path
) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(500_000))
    out = tmp_path / "out.thex"

    window = mw.MainWindow()
    qtbot.addWidget(window)
    worker = mw.EncryptWorker(src, out, "pw", chunk_size=16)
    worker.finished_ok.connect(window._on_encrypt_finished)
    window._start_worker(worker)

    assert not window.algo_combo.isEnabled()
    assert not window.workers_combo.isEnabled()

    _wait_for_job(qtbot, window)

    assert window.algo_combo.isEnabled()
    assert window.workers_combo.isEnabled()


def test_progress_detail_shows_throughput_and_eta_during_a_job(
    qtbot: QtBot, tmp_path: Path
) -> None:
    from app.core.progress import Progress

    window = mw.MainWindow()
    qtbot.addWidget(window)
    window._job_started_at = time.monotonic() - 1.0

    window._on_progress(Progress(bytes_done=1_000_000, bytes_total=10_000_000))

    detail = window.progress_detail_label.text()
    assert "MB/s" in detail or "KB/s" in detail
    assert "ETA" in detail


def test_progress_detail_cleared_when_job_finishes(qtbot: QtBot, tmp_path: Path) -> None:
    from app.core.progress import Progress

    window = mw.MainWindow()
    qtbot.addWidget(window)
    window._job_started_at = time.monotonic() - 1.0
    window._on_progress(Progress(bytes_done=1_000_000, bytes_total=10_000_000))
    assert window.progress_detail_label.text() != ""

    window._finish_job()

    assert window.progress_detail_label.text() == ""


def test_close_with_no_job_running_accepts_immediately(qtbot: QtBot) -> None:
    window = mw.MainWindow()
    qtbot.addWidget(window)
    event = mw.QCloseEvent()

    window.closeEvent(event)

    assert event.isAccepted()


def test_close_while_running_prompts_and_cancels_on_yes(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(2_000_000))
    out = tmp_path / "out.thex"

    window = mw.MainWindow()
    qtbot.addWidget(window)
    worker = mw.EncryptWorker(src, out, "pw", chunk_size=16)
    worker.finished_ok.connect(window._on_encrypt_finished)
    window._start_worker(worker)

    monkeypatch.setattr(
        mw.QMessageBox, "question", lambda *a, **k: mw.QMessageBox.StandardButton.Yes
    )
    event = mw.QCloseEvent()
    window.closeEvent(event)

    assert event.isAccepted()
    assert not out.exists()


def test_close_while_running_prompts_and_stays_open_on_no(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(2_000_000))
    out = tmp_path / "out.thex"

    window = mw.MainWindow()
    qtbot.addWidget(window)
    worker = mw.EncryptWorker(src, out, "pw", chunk_size=16)
    worker.finished_ok.connect(window._on_encrypt_finished)
    window._start_worker(worker)

    monkeypatch.setattr(
        mw.QMessageBox, "question", lambda *a, **k: mw.QMessageBox.StandardButton.No
    )
    event = mw.QCloseEvent()
    window.closeEvent(event)

    assert not event.isAccepted()
    window._worker.cancel()  # type: ignore[union-attr]
    _wait_for_job(qtbot, window)


def test_cancel_stops_the_job_and_leaves_no_output(qtbot: QtBot, tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(2_000_000))
    out = tmp_path / "out.thex"

    window = mw.MainWindow()
    qtbot.addWidget(window)

    # A tiny chunk_size (many chunks) keeps this running long enough to
    # reliably cancel before it finishes on its own - the click path always
    # uses the default chunk size, so the worker is started directly here.
    worker = mw.EncryptWorker(src, out, "pw", chunk_size=16)
    worker.finished_ok.connect(window._on_encrypt_finished)
    window._start_worker(worker)

    qtbot.mouseClick(window.cancel_button, mw.Qt.MouseButton.LeftButton)
    _wait_for_job(qtbot, window)

    assert "Cancelled" in window.status_label.text()
    assert not out.exists()
