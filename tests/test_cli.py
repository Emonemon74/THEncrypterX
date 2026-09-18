"""Tests for app.cli using typer's CliRunner.

The CLI is a thin wrapper - these tests check argument handling, password
input precedence, exit codes, and output framing, not cryptography itself
(that's covered everywhere else).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from app.cli import EXIT_CANCELLED, EXIT_UNEXPECTED, EXIT_WRONG_PASSWORD, app

runner = CliRunner()


def test_encrypt_default_output_path(tmp_path: Path) -> None:
    src = tmp_path / "doc.txt"
    src.write_bytes(b"hello cli")

    result = runner.invoke(app, ["encrypt", str(src)], input="pw\npw\n")

    assert result.exit_code == 0, result.output
    expected_out = tmp_path / "doc.txt.thex"
    assert expected_out.exists()
    assert "Encrypted" in result.output


def test_encrypt_explicit_output_path(tmp_path: Path) -> None:
    src = tmp_path / "doc.txt"
    src.write_bytes(b"hello cli")
    out = tmp_path / "custom.thex"

    result = runner.invoke(app, ["encrypt", str(src), "-o", str(out)], input="pw\npw\n")

    assert result.exit_code == 0, result.output
    assert out.exists()


def test_encrypt_and_decrypt_with_explicit_workers(tmp_path: Path) -> None:
    src = tmp_path / "doc.txt"
    src.write_bytes(os.urandom(20_000))
    out = tmp_path / "custom.thex"

    result = runner.invoke(
        app, ["encrypt", str(src), "-o", str(out), "--workers", "4"], input="pw\npw\n"
    )
    assert result.exit_code == 0, result.output

    dec_out = tmp_path / "restored.bin"
    result = runner.invoke(
        app, ["decrypt", str(out), "-o", str(dec_out), "--workers", "4"], input="pw\n"
    )
    assert result.exit_code == 0, result.output
    assert dec_out.read_bytes() == src.read_bytes()


def test_encrypt_password_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THEX_PASSWORD", "envpassword")
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")

    # No stdin input provided - if the env var weren't honoured this would hang
    # waiting for a prompt, and CliRunner would raise/return non-zero instead.
    result = runner.invoke(app, ["encrypt", str(src)])

    assert result.exit_code == 0, result.output


def test_encrypt_password_from_file(tmp_path: Path) -> None:
    pw_file = tmp_path / "pw.txt"
    pw_file.write_text("filepassword\n")
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")

    result = runner.invoke(app, ["encrypt", str(src), "--password-file", str(pw_file)])

    assert result.exit_code == 0, result.output


def test_encrypt_rejects_unknown_aead(tmp_path: Path) -> None:
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")

    result = runner.invoke(
        app, ["encrypt", str(src), "--aead", "not-a-real-cipher"], input="pw\npw\n"
    )

    assert result.exit_code == EXIT_UNEXPECTED
    assert "Unknown --aead" in result.output


def test_encrypt_missing_input_fails_cleanly(tmp_path: Path) -> None:
    result = runner.invoke(app, ["encrypt", str(tmp_path / "nope.txt")], input="pw\npw\n")
    assert result.exit_code != 0


# --- decrypt --------------------------------------------------------------------


def _encrypt_via_cli(tmp_path: Path, name: str, content: bytes, password: str) -> Path:
    src = tmp_path / name
    src.write_bytes(content)
    result = runner.invoke(app, ["encrypt", str(src)], input=f"{password}\n{password}\n")
    assert result.exit_code == 0, result.output
    return tmp_path / f"{name}.thex"


def test_decrypt_roundtrip_default_output(tmp_path: Path) -> None:
    enc = _encrypt_via_cli(tmp_path, "report.txt", b"secret report", "pw")
    (tmp_path / "report.txt").unlink()  # remove the original to prove it's recreated

    result = runner.invoke(app, ["decrypt", str(enc)], input="pw\n")

    assert result.exit_code == 0, result.output
    assert (tmp_path / "report.txt").read_bytes() == b"secret report"


def test_decrypt_explicit_output(tmp_path: Path) -> None:
    enc = _encrypt_via_cli(tmp_path, "report.txt", b"secret", "pw")
    out = tmp_path / "elsewhere.bin"

    result = runner.invoke(app, ["decrypt", str(enc), "-o", str(out)], input="pw\n")

    assert result.exit_code == 0, result.output
    assert out.read_bytes() == b"secret"


def test_decrypt_wrong_password_exit_code(tmp_path: Path) -> None:
    enc = _encrypt_via_cli(tmp_path, "report.txt", b"secret", "right-pw")

    result = runner.invoke(app, ["decrypt", str(enc)], input="wrong-pw\n")

    assert result.exit_code == EXIT_WRONG_PASSWORD
    assert "Wrong password" in result.output


def test_decrypt_refuses_to_overwrite_existing_file(tmp_path: Path) -> None:
    enc = _encrypt_via_cli(tmp_path, "report.txt", b"original content", "pw")
    # the original "report.txt" that was encrypted still sits next to the .thex file

    result = runner.invoke(app, ["decrypt", str(enc)], input="pw\n")

    assert result.exit_code == EXIT_UNEXPECTED
    assert (tmp_path / "report.txt").read_bytes() == b"original content"


# --- keygen / --key-file ----------------------------------------------------------


def test_keygen_creates_a_key_file(tmp_path: Path) -> None:
    out = tmp_path / "mykey.thexkey"

    result = runner.invoke(app, ["keygen", "-o", str(out)])

    assert result.exit_code == 0, result.output
    assert out.exists()
    assert "Generated key file" in result.output


def test_keygen_refuses_to_overwrite(tmp_path: Path) -> None:
    out = tmp_path / "mykey.thexkey"
    runner.invoke(app, ["keygen", "-o", str(out)])

    result = runner.invoke(app, ["keygen", "-o", str(out)])

    assert result.exit_code == EXIT_UNEXPECTED
    assert "already exists" in result.output


def test_encrypt_decrypt_roundtrip_with_key_file(tmp_path: Path) -> None:
    key_path = tmp_path / "mykey.thexkey"
    runner.invoke(app, ["keygen", "-o", str(key_path)])
    src = tmp_path / "doc.txt"
    src.write_bytes(b"secret via key file")
    enc = tmp_path / "doc.txt.thex"

    result = runner.invoke(app, ["encrypt", str(src), "-o", str(enc), "--key-file", str(key_path)])
    assert result.exit_code == 0, result.output

    dec = tmp_path / "restored.txt"
    result = runner.invoke(app, ["decrypt", str(enc), "-o", str(dec), "--key-file", str(key_path)])
    assert result.exit_code == 0, result.output
    assert dec.read_bytes() == src.read_bytes()


def test_verify_with_key_file(tmp_path: Path) -> None:
    key_path = tmp_path / "mykey.thexkey"
    runner.invoke(app, ["keygen", "-o", str(key_path)])
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")
    enc = tmp_path / "doc.txt.thex"
    runner.invoke(app, ["encrypt", str(src), "-o", str(enc), "--key-file", str(key_path)])

    result = runner.invoke(app, ["verify", str(enc), "--key-file", str(key_path)])

    assert result.exit_code == 0, result.output
    assert "VALID" in result.output


def test_decrypt_wrong_key_file_exit_code(tmp_path: Path) -> None:
    right_key = tmp_path / "right.thexkey"
    wrong_key = tmp_path / "wrong.thexkey"
    runner.invoke(app, ["keygen", "-o", str(right_key)])
    runner.invoke(app, ["keygen", "-o", str(wrong_key)])
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")
    enc = tmp_path / "doc.txt.thex"
    runner.invoke(app, ["encrypt", str(src), "-o", str(enc), "--key-file", str(right_key)])

    result = runner.invoke(
        app, ["decrypt", str(enc), "-o", str(tmp_path / "out.txt"), "--key-file", str(wrong_key)]
    )

    assert result.exit_code == EXIT_WRONG_PASSWORD


def test_decrypt_rejects_key_file_for_password_encrypted_file(tmp_path: Path) -> None:
    enc = _encrypt_via_cli(tmp_path, "report.txt", b"secret", "pw")
    key_path = tmp_path / "mykey.thexkey"
    runner.invoke(app, ["keygen", "-o", str(key_path)])

    result = runner.invoke(
        app, ["decrypt", str(enc), "-o", str(tmp_path / "out.txt"), "--key-file", str(key_path)]
    )

    assert result.exit_code == EXIT_UNEXPECTED
    assert "password" in result.output.lower()


def test_encrypt_rejects_password_file_and_key_file_together(tmp_path: Path) -> None:
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")
    pw_file = tmp_path / "pw.txt"
    pw_file.write_text("pw\n")
    key_path = tmp_path / "mykey.thexkey"
    runner.invoke(app, ["keygen", "-o", str(key_path)])

    result = runner.invoke(
        app,
        [
            "encrypt",
            str(src),
            "--password-file",
            str(pw_file),
            "--key-file",
            str(key_path),
        ],
    )

    assert result.exit_code == EXIT_UNEXPECTED
    assert "mutually exclusive" in result.output


def test_inspect_shows_keyfile_kdf(tmp_path: Path) -> None:
    key_path = tmp_path / "mykey.thexkey"
    runner.invoke(app, ["keygen", "-o", str(key_path)])
    src = tmp_path / "doc.txt"
    src.write_bytes(b"data")
    enc = tmp_path / "doc.txt.thex"
    runner.invoke(app, ["encrypt", str(src), "-o", str(enc), "--key-file", str(key_path)])

    result = runner.invoke(app, ["inspect", str(enc)])

    assert result.exit_code == 0, result.output
    assert "kdf: key-file" in result.output


# --- inspect --------------------------------------------------------------------


def test_inspect_needs_no_password(tmp_path: Path) -> None:
    enc = _encrypt_via_cli(tmp_path, "doc.txt", b"data", "pw")

    result = runner.invoke(app, ["inspect", str(enc)])  # no input provided at all

    assert result.exit_code == 0, result.output
    assert "format_version: 1" in result.output
    assert "aead: xchacha20" in result.output
    assert "total_chunks:" in result.output


def test_inspect_bad_file_fails_cleanly(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.thex"
    bogus.write_bytes(b"not a real container")

    result = runner.invoke(app, ["inspect", str(bogus)])

    assert result.exit_code != 0


# --- verify -----------------------------------------------------------------------


def test_verify_valid_container_passes(tmp_path: Path) -> None:
    enc = _encrypt_via_cli(tmp_path, "report.txt", b"secret report", "pw")

    result = runner.invoke(app, ["verify", str(enc)], input="pw\n")

    assert result.exit_code == 0, result.output
    assert "Container:" in result.output and "VALID" in result.output
    assert "Integrity:" in result.output and "PASS" in result.output
    # verify never writes plaintext - only the source + the .thex exist.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["report.txt", "report.txt.thex"]


def test_verify_wrong_password_fails(tmp_path: Path) -> None:
    enc = _encrypt_via_cli(tmp_path, "report.txt", b"secret", "right-pw")

    result = runner.invoke(app, ["verify", str(enc)], input="wrong-pw\n")

    assert result.exit_code == EXIT_WRONG_PASSWORD
    assert "INVALID" in result.output


def test_verify_tampered_container_fails(tmp_path: Path) -> None:
    enc = _encrypt_via_cli(tmp_path, "report.txt", os.urandom(2000), "pw")
    raw = bytearray(enc.read_bytes())
    raw[-40] ^= 0x01  # inside a chunk's ciphertext/tag, not the footer
    enc.write_bytes(bytes(raw))

    result = runner.invoke(app, ["verify", str(enc)], input="pw\n")

    assert result.exit_code != 0
    assert "INVALID" in result.output


# --- benchmark ----------------------------------------------------------------------


def test_benchmark_reports_throughput_for_each_worker_count() -> None:
    result = runner.invoke(
        app,
        [
            "benchmark",
            "--size-mb",
            "1",
            "--runs",
            "1",
            "--workers",
            "1",
            "--workers",
            "2",
            "--aead",
            "xchacha20",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "xchacha20" in result.output
    assert "Workers: 1" in result.output
    assert "Workers: 2" in result.output
    assert "MB/s" in result.output


def test_benchmark_rejects_unknown_aead() -> None:
    result = runner.invoke(app, ["benchmark", "--size-mb", "1", "--aead", "rot13"])

    assert result.exit_code == EXIT_UNEXPECTED
    assert "Unknown --aead value" in result.output


# --- shred ------------------------------------------------------------------------


def test_shred_with_yes_flag_deletes_file(tmp_path: Path) -> None:
    target = tmp_path / "secret.bin"
    target.write_bytes(b"sensitive")

    result = runner.invoke(app, ["shred", str(target), "--yes"])

    assert result.exit_code == 0, result.output
    assert not target.exists()


def test_shred_without_confirmation_aborts(tmp_path: Path) -> None:
    target = tmp_path / "secret.bin"
    target.write_bytes(b"sensitive")

    result = runner.invoke(app, ["shred", str(target)], input="n\n")

    assert result.exit_code == EXIT_CANCELLED
    assert target.exists()
