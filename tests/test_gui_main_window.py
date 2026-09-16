"""Tests for app.gui.main_window (pytest-qt, offscreen Qt platform).

QMessageBox.critical() is a modal call that would otherwise block waiting
for a click that never comes in an automated test - every test stubs it out
via the `no_blocking_dialogs` fixture.
"""

from __future__ import annotations

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

    enc_path = tmp_path / "secret.txt.thex"
    assert enc_path.exists()
    assert "Encrypted" in encrypt_window.status_label.text()
    assert encrypt_window.progress_bar.value() == 100
    src.unlink()  # so decrypt's default output path is free

    decrypt_window = mw.MainWindow()
    qtbot.addWidget(decrypt_window)
    decrypt_window._set_selected_file(enc_path)
    decrypt_window.password_edit.setText("pw")

    qtbot.mouseClick(decrypt_window.decrypt_button, mw.Qt.MouseButton.LeftButton)

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

    decrypt_window = mw.MainWindow()
    qtbot.addWidget(decrypt_window)
    decrypt_window._set_selected_file(tmp_path / "secret.txt.thex")
    decrypt_window.password_edit.setText("wrong-pw")

    qtbot.mouseClick(decrypt_window.decrypt_button, mw.Qt.MouseButton.LeftButton)

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

    assert custom_out.exists()
