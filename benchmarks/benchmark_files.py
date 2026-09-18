"""Manual, full-sweep performance benchmark (Build Guide Section 20/11.3).

Run manually - this is not part of the pytest suite. It intentionally spends
real wall-clock time against real files on disk and is meant to be read, not
asserted on:

    python benchmarks/benchmark_files.py --quick     # fast sanity check
    python benchmarks/benchmark_files.py             # full run, several minutes

Prints Markdown tables meant to be pasted directly into README.md. Only
measured numbers belong there - see Build Guide Section 20: "Only put
measured numbers in the resume."

For a quicker, interactive check without pasting into README.md, use
`thencrypterx benchmark` instead - it wraps the same measurement core
(app/benchmark.py) that this script uses.
"""

from __future__ import annotations

import argparse
import statistics

from app.benchmark import (
    MiB,
    format_chunk_row,
    format_size_row,
    machine_info_lines,
    run_benchmark,
)
from app.crypto.cipher import ALGO_AES_256_GCM, ALGO_XCHACHA20_POLY1305


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

    for line in machine_info_lines(args.runs):
        print(line)

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
            print(format_size_row(f"{size_mb} MB", result))

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
            print(format_chunk_row(result))


if __name__ == "__main__":
    main()
