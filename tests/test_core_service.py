"""Tests for app.core.service: EncryptJob, DecryptJob, InspectJob."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.core.errors import CancelledError
from app.core.progress import CancellationToken, Progress
from app.core.service import DecryptJob, EncryptJob, InspectJob
from app.crypto.cipher import ALGO_AES_256_GCM, ALGO_XCHACHA20_POLY1305
from app.crypto.kdf import Argon2Params

CHEAP = Argon2Params(memory_cost_kib=8, time_cost=1, parallelism=1)


def test_encrypt_then_decrypt_job_roundtrip(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    data = os.urandom(500)
    src.write_bytes(data)
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"

    EncryptJob(src, enc, "pw", chunk_size=64, argon2_params=CHEAP).run()
    metadata = DecryptJob(enc, dec, "pw").run()

    assert dec.read_bytes() == data
    assert metadata.original_size == len(data)


def test_encrypt_job_reports_progress_to_completion(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(1000))
    enc = tmp_path / "out.thex"

    updates: list[Progress] = []
    EncryptJob(src, enc, "pw", chunk_size=64, argon2_params=CHEAP).run(on_progress=updates.append)

    assert updates, "no progress updates were reported"
    assert updates[-1].fraction == 1.0
    fractions = [u.fraction for u in updates]
    assert fractions == sorted(fractions)  # monotonically increasing


def test_decrypt_job_reports_progress_to_completion(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(1000))
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"
    EncryptJob(src, enc, "pw", chunk_size=64, argon2_params=CHEAP).run()

    updates: list[Progress] = []
    DecryptJob(enc, dec, "pw").run(on_progress=updates.append)

    assert updates[-1].fraction == 1.0


def test_encrypt_job_pre_cancelled_raises_and_leaves_no_output(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(1000))
    enc = tmp_path / "out.thex"

    token = CancellationToken()
    token.cancel()

    with pytest.raises(CancelledError):
        EncryptJob(src, enc, "pw", chunk_size=32, argon2_params=CHEAP).run(cancel_token=token)
    assert not enc.exists()


def test_encrypt_job_cancelled_mid_run_leaves_no_output(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(2000))
    enc = tmp_path / "out.thex"
    token = CancellationToken()

    def cancel_after_first_update(_: Progress) -> None:
        token.cancel()

    with pytest.raises(CancelledError):
        EncryptJob(src, enc, "pw", chunk_size=32, argon2_params=CHEAP).run(
            on_progress=cancel_after_first_update, cancel_token=token
        )
    assert not enc.exists()


def test_decrypt_job_cancelled_mid_run_leaves_no_output(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(2000))
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"
    EncryptJob(src, enc, "pw", chunk_size=32, argon2_params=CHEAP).run()

    token = CancellationToken()

    def cancel_after_first_update(_: Progress) -> None:
        token.cancel()

    with pytest.raises(CancelledError):
        DecryptJob(enc, dec, "pw").run(on_progress=cancel_after_first_update, cancel_token=token)
    assert not dec.exists()


def test_inspect_job_needs_no_password(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(200))
    enc = tmp_path / "out.thex"
    EncryptJob(src, enc, "pw", aead_id=ALGO_AES_256_GCM, chunk_size=64, argon2_params=CHEAP).run()

    info = InspectJob(enc).run()

    assert info.format_version == 1
    assert info.aead_id == ALGO_AES_256_GCM
    assert info.chunk_size == 64
    assert info.argon2_memory_cost_kib == CHEAP.memory_cost_kib
    assert info.total_chunks == 4  # 200 bytes / 64-byte chunks, rounded up
    assert len(bytes.fromhex(info.salt_hex)) == 16


def test_inspect_job_default_algo(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(b"x")
    enc = tmp_path / "out.thex"
    EncryptJob(src, enc, "pw", argon2_params=CHEAP).run()

    info = InspectJob(enc).run()
    assert info.aead_id == ALGO_XCHACHA20_POLY1305
