"""THEncrypterX desktop GUI (PySide6).

Encrypt/Decrypt button clicks start a background app.gui.workers
EncryptWorker/DecryptWorker (a QThread) instead of running the job on the
GUI thread, so the window stays responsive on large files and the Cancel
button can actually interrupt a running job. This window never touches
app.files or app.crypto directly - it only starts a worker and reacts to
its Qt signals (progress, finished_ok, failed, cancelled).
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.gui.workers import DecryptWorker, EncryptWorker
from app.metadata.metadata import FileMetadata


class DropArea(QLabel):
    """A label that accepts one dropped file and reports it via a callback."""

    def __init__(self, on_file_dropped: Callable[[Path], None]) -> None:
        super().__init__("Drop a file here\nor click 'Select File'")
        self._on_file_dropped = on_file_dropped
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setAcceptDrops(True)
        self.setMinimumHeight(120)
        self.setStyleSheet("QLabel { border: 2px dashed #888; border-radius: 8px; padding: 16px; }")

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        if not urls:
            return
        path = Path(urls[0].toLocalFile())
        if path.is_file():
            self._on_file_dropped(path)


class MainWindow(QMainWindow):
    """The main application window. See the module docstring for the
    GUI-thread-blocking caveat this class currently has.
    """

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("THEncrypterX")
        self.resize(520, 420)

        self._selected_file: Path | None = None
        self._output_path: Path | None = None
        self._worker: EncryptWorker | DecryptWorker | None = None

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        self.drop_area = DropArea(self._set_selected_file)
        layout.addWidget(self.drop_area)

        select_row = QHBoxLayout()
        self.select_button = QPushButton("Select File")
        self.select_button.clicked.connect(self._choose_file)
        select_row.addWidget(self.select_button)
        self.selected_label = QLabel("Selected: (none)")
        select_row.addWidget(self.selected_label, stretch=1)
        layout.addLayout(select_row)

        pw_row = QHBoxLayout()
        pw_row.addWidget(QLabel("Password:"))
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        pw_row.addWidget(self.password_edit, stretch=1)
        self.show_password_button = QPushButton("Show")
        self.show_password_button.setCheckable(True)
        self.show_password_button.toggled.connect(self._toggle_password_visibility)
        pw_row.addWidget(self.show_password_button)
        layout.addLayout(pw_row)

        out_row = QHBoxLayout()
        self.output_button = QPushButton("Choose Output...")
        self.output_button.clicked.connect(self._choose_output)
        out_row.addWidget(self.output_button)
        self.output_label = QLabel("Output: (default)")
        out_row.addWidget(self.output_label, stretch=1)
        layout.addLayout(out_row)

        button_row = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.clicked.connect(self._on_encrypt_clicked)
        button_row.addWidget(self.encrypt_button)
        self.decrypt_button = QPushButton("Decrypt")
        self.decrypt_button.clicked.connect(self._on_decrypt_clicked)
        button_row.addWidget(self.decrypt_button)
        layout.addLayout(button_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)  # Qt's own default is -1 (undetermined), not 0
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Ready.")
        layout.addWidget(self.status_label)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._on_cancel_clicked)
        layout.addWidget(self.cancel_button)

    # --- file / output selection --------------------------------------------

    def _set_selected_file(self, path: Path) -> None:
        self._selected_file = path
        self.selected_label.setText(f"Selected: {path}")
        self.status_label.setText("Ready.")

    def _choose_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "Select a file")
        if filename:
            self._set_selected_file(Path(filename))

    def _choose_output(self) -> None:
        filename, _ = QFileDialog.getSaveFileName(self, "Choose output location")
        if filename:
            self._output_path = Path(filename)
            self.output_label.setText(f"Output: {self._output_path}")

    def _toggle_password_visibility(self, checked: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        self.password_edit.setEchoMode(mode)
        self.show_password_button.setText("Hide" if checked else "Show")

    # --- actions ---------------------------------------------------------------

    def _require_file(self) -> Path | None:
        if self._selected_file is None:
            self._show_error("Select a file first.")
            return None
        return self._selected_file

    def _show_error(self, message: str) -> None:
        # A safe, user-facing message only - never a stack trace or a raw
        # exception repr that might include a temp-file path.
        self.status_label.setText(f"Error: {message}")
        QMessageBox.critical(self, "THEncrypterX", message)

    def _set_busy(self, busy: bool) -> None:
        for widget in (self.encrypt_button, self.decrypt_button, self.select_button):
            widget.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.cancel_button.setText("Cancel")

    def _on_progress_fraction(self, fraction: float) -> None:
        self.progress_bar.setValue(int(fraction * 100))

    def _start_worker(self, worker: EncryptWorker | DecryptWorker) -> None:
        self._worker = worker
        worker.progress.connect(self._on_progress_fraction)
        worker.failed.connect(self._on_job_failed)
        worker.cancelled.connect(self._on_job_cancelled)
        self._set_busy(True)
        worker.start()

    def _finish_job(self) -> None:
        self._set_busy(False)
        self._worker = None

    def _on_job_failed(self, message: str) -> None:
        self._finish_job()
        self._show_error(message)

    def _on_job_cancelled(self) -> None:
        self._finish_job()
        self.status_label.setText("Cancelled.")

    def _on_cancel_clicked(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self.cancel_button.setEnabled(False)
            self.cancel_button.setText("Cancelling...")
            self.status_label.setText("Cancelling...")

    def _on_encrypt_clicked(self) -> None:
        src = self._require_file()
        if src is None:
            return
        password = self.password_edit.text()
        if not password:
            self._show_error("Enter a password.")
            return
        output = self._output_path or src.with_name(src.name + ".thex")

        self.status_label.setText("Encrypting...")
        worker = EncryptWorker(src, output, password)
        worker.finished_ok.connect(self._on_encrypt_finished)
        self._start_worker(worker)

    def _on_encrypt_finished(self, output_path: str) -> None:
        self._finish_job()
        self.status_label.setText(f"Encrypted -> {output_path}")

    def _on_decrypt_clicked(self) -> None:
        src = self._require_file()
        if src is None:
            return
        password = self.password_edit.text()
        if not password:
            self._show_error("Enter a password.")
            return

        self.status_label.setText("Decrypting...")
        worker = DecryptWorker(src, self._output_path, password)
        worker.finished_ok.connect(self._on_decrypt_finished)
        self._start_worker(worker)

    def _on_decrypt_finished(self, metadata: FileMetadata) -> None:
        self._finish_job()
        self.status_label.setText(f"Decrypted -> {metadata.original_name}")


def run() -> None:
    """Launch the GUI. Entry point used by main.py."""
    application = QApplication.instance() or QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(application.exec())
