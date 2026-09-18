"""Tests for app.benchmark: the shared measurement core behind
`thencrypterx benchmark` and `benchmarks/benchmark_files.py`.

Runs use tiny files and the low Argon2 memory cost set globally in
conftest.py, so this stays fast - it's checking the measurement wiring
(the dict shape, the formatting helpers), not asserting on throughput
numbers, which are inherently machine-dependent.
"""

from __future__ import annotations

from app.benchmark import format_chunk_row, format_size_row, run_benchmark
from app.crypto.cipher import ALGO_XCHACHA20_POLY1305


def test_run_benchmark_returns_expected_keys() -> None:
    result = run_benchmark(size_bytes=1024, aead_id=ALGO_XCHACHA20_POLY1305, chunk_size=256, runs=1)

    expected_keys = {
        "size_mb",
        "aead",
        "chunk_size_kib",
        "workers",
        "argon2_seconds",
        "encrypt_seconds",
        "decrypt_seconds",
        "encrypt_mb_s",
        "decrypt_mb_s",
        "encrypt_peak_rss_mb",
        "decrypt_peak_rss_mb",
        "encrypt_cpu_percent",
        "decrypt_cpu_percent",
    }
    assert set(result) == expected_keys


def test_run_benchmark_reports_positive_throughput_and_memory() -> None:
    result = run_benchmark(size_bytes=1024, aead_id=ALGO_XCHACHA20_POLY1305, chunk_size=256, runs=1)

    assert result["encrypt_mb_s"] > 0
    assert result["decrypt_mb_s"] > 0
    assert result["encrypt_peak_rss_mb"] > 0
    assert result["decrypt_peak_rss_mb"] > 0
    # CPU% is a real psutil measurement, not synthetic - it can legitimately
    # read 0 for a sub-millisecond call on a fast machine, so only check it
    # isn't negative (a real percentage) rather than asserting it's positive.
    assert result["encrypt_cpu_percent"] >= 0
    assert result["decrypt_cpu_percent"] >= 0


def test_run_benchmark_respects_workers_param() -> None:
    result = run_benchmark(
        size_bytes=1024, aead_id=ALGO_XCHACHA20_POLY1305, chunk_size=256, runs=1, workers=4
    )
    assert result["workers"] == 4


def test_format_size_row_includes_cpu_columns() -> None:
    result = run_benchmark(size_bytes=1024, aead_id=ALGO_XCHACHA20_POLY1305, chunk_size=256, runs=1)
    row = format_size_row("1 MB", result)
    assert row.count("|") == 10  # 9 columns -> 10 pipe separators


def test_format_chunk_row_includes_cpu_columns() -> None:
    result = run_benchmark(size_bytes=1024, aead_id=ALGO_XCHACHA20_POLY1305, chunk_size=256, runs=1)
    row = format_chunk_row(result)
    assert row.count("|") == 8  # 7 columns -> 8 pipe separators
