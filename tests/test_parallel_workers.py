"""Tests for the parallel chunk-processing path (workers > 1).

The container format doesn't know or care how many threads produced or
consumed it - these tests check that property directly (cross-compatible
worker counts), plus that every guarantee proven for the sequential path
(order, tamper detection, cancellation-leaves-no-output) still holds when
chunks are sealed/opened out of computation order but written in file order.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.core.errors import CancelledError, IntegrityError, WrongPasswordError
from app.core.progress import CancellationToken, Progress
from app.core.service import DecryptJob, EncryptJob
from app.crypto.cipher import ALGO_AES_256_GCM, ALGO_XCHACHA20_POLY1305
from app.crypto.kdf import Argon2Params
from app.files.decrypt import decrypt_file
from app.files.encrypt import encrypt_file

CHEAP = Argon2Params(memory_cost_kib=8, time_cost=1, parallelism=1)


@pytest.mark.parametrize("workers", [1, 2, 4, 8])
def test_roundtrip_with_various_worker_counts(tmp_path: Path, workers: int) -> None:
    src = tmp_path / "in.bin"
    data = os.urandom(50_000)
    src.write_bytes(data)
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"

    encrypt_file(src, enc, "pw", argon2_params=CHEAP, chunk_size=1024, workers=workers)
    decrypt_file(enc, dec, "pw", workers=workers)

    assert dec.read_bytes() == data


@pytest.mark.parametrize(("encrypt_workers", "decrypt_workers"), [(1, 4), (4, 1), (2, 8), (8, 2)])
def test_worker_counts_are_cross_compatible(
    tmp_path: Path, encrypt_workers: int, decrypt_workers: int
) -> None:
    src = tmp_path / "in.bin"
    data = os.urandom(30_000)
    src.write_bytes(data)
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"

    encrypt_file(src, enc, "pw", argon2_params=CHEAP, chunk_size=512, workers=encrypt_workers)
    decrypt_file(enc, dec, "pw", workers=decrypt_workers)

    assert dec.read_bytes() == data


def test_parallel_encrypt_output_decrypts_with_sequential_reference(tmp_path: Path) -> None:
    """A container built with workers=8 is byte-for-byte a normal .thex file -
    it round-trips through the plain sequential decrypt path with no special
    handling."""
    src = tmp_path / "in.bin"
    data = os.urandom(20_000)
    src.write_bytes(data)
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"

    encrypt_file(src, enc, "pw", argon2_params=CHEAP, chunk_size=256, workers=8)
    metadata = decrypt_file(enc, dec, "pw")  # workers=1 default

    assert dec.read_bytes() == data
    assert metadata.original_size == len(data)


@pytest.mark.parametrize("aead_id", [ALGO_XCHACHA20_POLY1305, ALGO_AES_256_GCM])
def test_parallel_roundtrip_both_algorithms(tmp_path: Path, aead_id: int) -> None:
    src = tmp_path / "in.bin"
    data = os.urandom(20_000)
    src.write_bytes(data)
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"

    encrypt_file(src, enc, "pw", aead_id=aead_id, argon2_params=CHEAP, chunk_size=512, workers=4)
    decrypt_file(enc, dec, "pw", workers=4)

    assert dec.read_bytes() == data


def test_progress_is_monotonic_and_complete_with_parallel_workers(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    data = os.urandom(40_000)
    src.write_bytes(data)
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"

    enc_updates: list[tuple[int, int]] = []
    encrypt_file(
        src,
        enc,
        "pw",
        argon2_params=CHEAP,
        chunk_size=512,
        workers=4,
        progress_cb=lambda done, total: enc_updates.append((done, total)),
    )
    dec_updates: list[tuple[int, int]] = []
    decrypt_file(
        enc,
        dec,
        "pw",
        workers=4,
        progress_cb=lambda done, total: dec_updates.append((done, total)),
    )

    # Even though chunks may finish computing out of order across threads,
    # they are only ever *reported* once written in file order, so bytes_done
    # must be strictly non-decreasing and reach the true total exactly once.
    enc_bytes = [done for done, _ in enc_updates]
    assert enc_bytes == sorted(enc_bytes)
    assert enc_updates[-1] == (len(data), len(data))

    dec_bytes = [done for done, _ in dec_updates]
    assert dec_bytes == sorted(dec_bytes)
    assert dec_updates[-1] == (len(data), len(data))


def test_tampered_chunk_still_detected_with_parallel_decrypt(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(20_000))
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, "pw", argon2_params=CHEAP, chunk_size=256, workers=4)

    blob = bytearray(enc.read_bytes())
    blob[-20] ^= 0x01  # inside the last chunk's tag, before the footer
    enc.write_bytes(bytes(blob))

    with pytest.raises(IntegrityError):
        decrypt_file(enc, tmp_path / "dec.bin", "pw", workers=4)


def test_wrong_password_still_detected_with_parallel_workers(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(5000))
    enc = tmp_path / "out.thex"
    encrypt_file(src, enc, "right-pw", argon2_params=CHEAP, chunk_size=512, workers=4)

    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, tmp_path / "dec.bin", "wrong-pw", workers=4)


# --- cancellation -------------------------------------------------------------


def test_cancelling_parallel_encrypt_leaves_no_output(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(2_000_000))
    enc = tmp_path / "out.thex"
    token = CancellationToken()

    def cancel_after_first_update(_: Progress) -> None:
        token.cancel()

    with pytest.raises(CancelledError):
        EncryptJob(src, enc, "pw", chunk_size=16, argon2_params=CHEAP, workers=4).run(
            on_progress=cancel_after_first_update, cancel_token=token
        )
    assert not enc.exists()


def test_cancelling_parallel_decrypt_leaves_no_output(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(os.urandom(2_000_000))
    enc = tmp_path / "out.thex"
    dec = tmp_path / "dec.bin"
    EncryptJob(src, enc, "pw", chunk_size=16, argon2_params=CHEAP).run()

    token = CancellationToken()

    def cancel_after_first_update(_: Progress) -> None:
        token.cancel()

    with pytest.raises(CancelledError):
        DecryptJob(enc, dec, "pw", workers=4).run(
            on_progress=cancel_after_first_update, cancel_token=token
        )
    assert not dec.exists()
