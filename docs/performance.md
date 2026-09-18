# Performance

All numbers below are measured, not estimated - reproduce them yourself
with `python benchmarks/benchmark_files.py` (see
[`CONTRIBUTING.md`](../CONTRIBUTING.md#running-benchmarks)) before relying on
them for a different machine or workload. Do not extrapolate these to
hardware without AES-NI / ARM crypto extensions, or to very different chunk
sizes, without re-measuring.

Machine used for every measurement below: Apple Silicon, 8 cores, macOS,
Python 3.13.7.

## Throughput by file size and algorithm

Median of 3 runs; production Argon2id parameters (256 MiB memory,
time_cost 3, parallelism 4, ~0.15s per call) - included in every number
below, since every real encrypt/decrypt call derives its own key.

| File size | AEAD | Encrypt (MB/s) | Decrypt (MB/s) |
|---:|---|---:|---:|
| 10 MB | xchacha20-poly1305 | 29.7 | 29.3 |
| 10 MB | aes-256-gcm | 63.1 | 63.7 |
| 100 MB | xchacha20-poly1305 | 45.8 | 47.8 |
| 100 MB | aes-256-gcm | 399.6 | 396.1 |
| 500 MB | xchacha20-poly1305 | 49.3 | 49.1 |
| 500 MB | aes-256-gcm | 645.9 | 548.2 |
| 1024 MB | xchacha20-poly1305 | 48.7 | 49.0 |
| 1024 MB | aes-256-gcm | 487.2 | 354.3 |

AES-256-GCM is roughly 10x faster here because OpenSSL's implementation
uses the CPU's dedicated AES hardware instructions (AES-NI on x86, the
ARMv8 crypto extensions on Apple Silicon); libsodium's XChaCha20 runs in
optimized software with no equivalent hardware path on either architecture.
A chunk-size sweep from 64 KiB to 16 MiB at 500 MB showed flat throughput
for XChaCha20-Poly1305, confirming this gap is the cipher itself, not
per-chunk overhead.

XChaCha20-Poly1305 stays the CLI/library default anyway - see
[`docs/threat-model.md`](threat-model.md#why-xchacha20-poly1305-is-the-default-despite-being-much-slower-here)
for why nonce safety was weighted above raw throughput.

## Memory

Peak memory stayed in the 275-780 MB range across all file sizes from
10 MB to 1024 MB - it does not scale with file size, which is what
streaming, chunked processing is meant to prove. A naive whole-file-in-
memory implementation would need >1 GB of RAM for the 1 GB case; this
needed roughly a quarter of that, dominated by Argon2id's own 256 MiB
working set rather than file data. The exact figures are somewhat inflated
by test-harness memory used to generate the random input file - see
`benchmarks/benchmark_files.py`'s docstring.

## Parallel workers (`--workers`)

Measured on a 200 MB file, XChaCha20-Poly1305, same 8-core machine:

| Workers | Encrypt (MB/s) | Decrypt (MB/s) |
|---:|---:|---:|
| 1 | 45.9 | 44.8 |
| 2 | 78.6 | 80.3 |
| 4 | 142.5 | 169.9 |
| 8 | 189.2 | 137.3 |

Encrypt scales close to linearly through 8 workers (~4.1x). Decrypt peaks
at 4 workers (~3.8x) and *regresses* at 8: on an 8-core machine, 8 worker
threads plus the main thread doing sequential reads/writes oversubscribes
the available cores, and thread-scheduling/GIL-reacquisition overhead
starts to outweigh the parallel gain. This is why the CLI's `--workers`
default is your CPU core count rather than an arbitrarily high number -
matching cores is the sweet spot the data shows, not a guess.

Parallel workers pipeline chunk-level AEAD calls only - not the Argon2id
key derivation itself (a fixed cost per operation, ~0.15s at production
parameters), and not disk I/O beyond what the OS already buffers.

## What is not yet benchmarked

- Files below 10 MB or above 1 GB
- Non-Apple-Silicon hardware (no AES-NI comparison point has been run on
  x86 for this project; the ~10x XChaCha20/AES-GCM gap should hold
  directionally on any hardware with AES-NI, but has not been measured
  there)
- `--workers` combined with AES-256-GCM (only measured with the default
  XChaCha20-Poly1305)
- Cold-start vs. warm-cache disk I/O effects on very large files

These are reasonable follow-ups before adding resumable/large-file support
(see [`docs/ROADMAP.md`](ROADMAP.md), Phase 8).
