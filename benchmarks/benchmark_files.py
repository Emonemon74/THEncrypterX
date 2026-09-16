"""Performance benchmarks for THEncrypterX (Build Guide Section 20/11.3).

Run manually - this is not part of the pytest suite. It intentionally spends
real wall-clock time against real files on disk and is meant to be read, not
asserted on:

    python benchmarks/benchmark_files.py --quick     # fast sanity check
    python benchmarks/benchmark_files.py             # full run, several minutes

Prints Markdown tables meant to be pasted directly into README.md. Only
measured numbers belong there - see Build Guide Section 20: "Only put
measured numbers in the resume."

Peak memory is sampled by polling this process's RSS from a background
thread while each encrypt/decrypt call runs, rather than trusting any single
snapshot - a true "peak" requires watching continuously, since a spike
between two manual checks would otherwise be invisible.

Every encrypt_file()/decrypt_file() call performs its own Argon2id key
derivation - that is real behavior, not something this script can subtract
out without bypassing the actual code path being measured. Argon2id's cost
is fixed per call regardless of file size, so it is *also* measured in
isolation and reported alongside the per-size table as context: at small
file sizes it can dominate the total time (making throughput look low for
reasons that have nothing to do with streaming/AEAD performance), while at
large file sizes it becomes negligible relative to the actual data
processing. Read the throughput numbers with that in mind rather than
assuming they isolate pure cipher speed.
"""

from __future__ import annotations

import argparse
import os
import platform
import statistics
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import psutil

from app.crypto.cipher import ALGO_AES_256_GCM, ALGO_XCHACHA20_POLY1305
from app.crypto.kdf import Argon2Params, default_params, derive_master_key, generate_salt
from app.files.decrypt import decrypt_file
from app.files.encrypt import encrypt_file

_ALGO_NAMES = {ALGO_XCHACHA20_POLY1305: "xchacha20-poly1305", ALGO_AES_256_GCM: "aes-256-gcm"}
MiB = 1024 * 1024


@dataclass(frozen=True, slots=True)
class RunResult:
    seconds: float
    peak_rss_mb: float


class _PeakRssSampler:
    """Polls this process's RSS on a background thread for the duration of a
    `with` block and reports the maximum observed value.
    """

    def __init__(self, interval: float = 0.02) -> None:
        self._interval = interval
        self._stop = threading.Event()
        self._process = psutil.Process(os.getpid())
        self._peak_bytes = 0
        self._thread: threading.Thread | None = None

    def __enter__(self) -> _PeakRssSampler:
        self._peak_bytes = self._process.memory_info().rss
        self._stop.clear()
        self._thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _sample_loop(self) -> None:
        while not self._stop.is_set():
            rss = self._process.memory_info().rss
            self._peak_bytes = max(self._peak_bytes, rss)
            self._stop.wait(self._interval)

    @property
    def peak_mb(self) -> float:
        return self._peak_bytes / MiB


def _time_and_measure(fn: Callable[[], None]) -> RunResult:
    with _PeakRssSampler() as sampler:
        start = time.perf_counter()
        fn()
        elapsed = time.perf_counter() - start
    return RunResult(seconds=elapsed, peak_rss_mb=sampler.peak_mb)


def _median(results: list[RunResult]) -> RunResult:
    return RunResult(
        seconds=statistics.median(r.seconds for r in results),
        peak_rss_mb=statistics.median(r.peak_rss_mb for r in results),
    )


def _throughput_mb_s(size_bytes: int, seconds: float) -> float:
    return (size_bytes / MiB) / seconds if seconds > 0 else float("inf")


def run_benchmark(
    size_bytes: int,
    aead_id: int,
    chunk_size: int,
    *,
    runs: int = 3,
    argon2_params: Argon2Params | None = None,
) -> dict[str, float | str]:
    """Encrypt+decrypt `size_bytes` of random data `runs` times; report medians."""
    params = argon2_params or default_params()

    with tempfile.TemporaryDirectory(prefix="thex_bench_") as tmp:
        tmp_path = Path(tmp)
        src = tmp_path / "input.bin"
        src.write_bytes(os.urandom(size_bytes))
        enc = tmp_path / "output.thex"
        dec = tmp_path / "roundtrip.bin"
        password = "benchmark-password"

        kdf_start = time.perf_counter()
        derive_master_key(password, generate_salt(), params)
        argon2_seconds = time.perf_counter() - kdf_start

        encrypt_results = [
            _time_and_measure(
                lambda: encrypt_file(
                    src, enc, password, aead_id=aead_id, chunk_size=chunk_size, argon2_params=params
                )
            )
            for _ in range(runs)
        ]
        decrypt_results = [
            _time_and_measure(lambda: decrypt_file(enc, dec, password)) for _ in range(runs)
        ]

        enc_med = _median(encrypt_results)
        dec_med = _median(decrypt_results)

        return {
            "size_mb": size_bytes / MiB,
            "aead": _ALGO_NAMES[aead_id],
            "chunk_size_kib": chunk_size / 1024,
            "argon2_seconds": argon2_seconds,
            "encrypt_seconds": enc_med.seconds,
            "decrypt_seconds": dec_med.seconds,
            "encrypt_mb_s": _throughput_mb_s(size_bytes, enc_med.seconds),
            "decrypt_mb_s": _throughput_mb_s(size_bytes, dec_med.seconds),
            "encrypt_peak_rss_mb": enc_med.peak_rss_mb,
            "decrypt_peak_rss_mb": dec_med.peak_rss_mb,
        }


def _format_size_row(size_label: str, r: dict[str, float | str]) -> str:
    return (
        f"| {size_label} | {r['aead']} | {r['encrypt_seconds']:.3f} | {r['decrypt_seconds']:.3f} "
        f"| {r['encrypt_mb_s']:.1f} | {r['decrypt_mb_s']:.1f} | {r['encrypt_peak_rss_mb']:.1f} |"
    )


def _format_chunk_row(r: dict[str, float | str]) -> str:
    return (
        f"| {r['chunk_size_kib']:.0f} KiB "
        f"| {r['encrypt_seconds']:.3f} | {r['decrypt_seconds']:.3f} "
        f"| {r['encrypt_mb_s']:.1f} | {r['decrypt_mb_s']:.1f} |"
    )


def print_machine_info(runs: int) -> None:
    params = default_params()
    print("## Benchmark environment\n")
    print(f"- CPU: {platform.processor() or platform.machine()}")
    print(f"- Cores: {os.cpu_count()}")
    print(f"- OS: {platform.system()} {platform.release()}")
    print(f"- Python: {platform.python_version()}")
    print(f"- Runs per configuration: {runs} (median reported)")
    print(
        "- Argon2id: memory_cost_kib="
        f"{params.memory_cost_kib} time_cost={params.time_cost} parallelism={params.parallelism} "
        "(a fixed per-call cost included in every Encrypt/Decrypt time below - "
        "see the note after the table)\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="THEncrypterX performance benchmarks")
    parser.add_argument(
        "--quick", action="store_true", help="Small sizes, fewer runs - a fast sanity check."
    )
    parser.add_argument("--runs", type=int, default=3, help="Runs per configuration.")
    parser.add_argument("--no-sweep", action="store_true", help="Skip the chunk-size sweep table.")
    args = parser.parse_args()

    if args.quick:
        sizes_mb = [1, 10]
        algos = [ALGO_XCHACHA20_POLY1305]
        sweep = False
    else:
        sizes_mb = [10, 100, 500, 1024]
        algos = [ALGO_XCHACHA20_POLY1305, ALGO_AES_256_GCM]
        sweep = not args.no_sweep

    print_machine_info(args.runs)

    print("## Throughput and memory by file size\n")
    print(
        "| File size | AEAD | Encrypt (s) | Decrypt (s) "
        "| Encrypt (MB/s) | Decrypt (MB/s) | Peak RSS (MB) |"
    )
    print("|---:|---|---:|---:|---:|---:|---:|")
    argon2_seconds_seen = []
    for size_mb in sizes_mb:
        for aead_id in algos:
            result = run_benchmark(
                size_bytes=size_mb * MiB, aead_id=aead_id, chunk_size=1024 * 1024, runs=args.runs
            )
            argon2_seconds_seen.append(result["argon2_seconds"])
            print(_format_size_row(f"{size_mb} MB", result))

    median_argon2 = statistics.median(argon2_seconds_seen)
    print(
        f"\nArgon2id key derivation: ~{median_argon2:.3f}s per call, independent of file "
        "size, and *included* in every Encrypt/Decrypt time above (each real "
        "encrypt_file()/decrypt_file() call derives its own key). This is why "
        "small files show lower apparent throughput - the fixed KDF cost is a "
        "larger fraction of the total time - while it becomes negligible at "
        "larger sizes.\n"
    )

    if sweep:
        print("## Chunk-size sweep (500 MB, xchacha20-poly1305)\n")
        print("| Chunk size | Encrypt (s) | Decrypt (s) | Encrypt (MB/s) | Decrypt (MB/s) |")
        print("|---:|---:|---:|---:|---:|")
        for chunk_kib in (64, 256, 1024, 4096, 16384):
            result = run_benchmark(
                size_bytes=500 * MiB,
                aead_id=ALGO_XCHACHA20_POLY1305,
                chunk_size=chunk_kib * 1024,
                runs=args.runs,
            )
            print(_format_chunk_row(result))


if __name__ == "__main__":
    main()
