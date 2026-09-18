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

Measured on a 200 MB file, XChaCha20-Poly1305, same 8-core machine, median
of 3 runs, now including CPU utilization (roadmap Phase 10 - `thencrypterx
benchmark` and `benchmarks/benchmark_files.py` both report this via
`app.benchmark`'s `psutil.Process.cpu_percent`, which can read above 100%
once more than one core is in use):

| Workers | Encrypt (MB/s) | Decrypt (MB/s) | Encrypt CPU% | Decrypt CPU% | Peak RSS (MB) |
|---:|---:|---:|---:|---:|---:|
| 1 | 48.7 | 49.9 | 108% | 109% | 477 |
| 2 | 95.2 | 95.4 | 215% | 214% | 487 |
| 4 | 170.4 | 172.9 | 403% | 405% | 500 |
| 8 | 220.3 | 221.4 | 691% | 695% | 521 |

CPU% is the clearest evidence yet that `--workers` is genuinely
parallelizing, not just reporting faster numbers: it climbs in lockstep
with throughput, reaching ~690% (using close to all 8 cores at once) at
`workers=8`. Throughput itself scales sub-linearly past 2 workers (~4.5x
at 8 workers, not 8x) while CPU usage keeps climbing near-linearly (~6.4x)
- the gap between those two curves *is* the parallelization overhead
(thread scheduling, GIL reacquisition around each AEAD call, chunk
read/write staying on the main thread): more cores get used, but each
additional core buys less throughput than the last one did. Peak memory
grows only modestly with worker count (477 MB to 521 MB, +9%) since each
worker briefly holds one chunk in flight - nowhere near proportional to
the 8x jump in worker count.

These numbers replace an earlier single-run measurement that didn't track
CPU% and showed decrypt *regressing* at 8 workers - not reproduced here
with median-of-3 and full precision; take the general shape (throughput
scales sub-linearly, more so past 4 workers on this 8-core machine) as the
finding, not the exact prior numbers.

Parallel workers pipeline chunk-level AEAD calls only - not the Argon2id
key derivation itself (a fixed cost per operation, ~0.15s at production
parameters), and not disk I/O beyond what the OS already buffers.

## Large files (4 GB, roadmap Phase 8)

Single run (not median-of-3, unlike the table above - a 4 GB file takes
minutes per run, so this is a spot-check, not the same statistical rigor),
production Argon2id parameters, same 8-core Apple Silicon machine, default
1 MiB chunks, `workers=1`:

| AEAD | Encrypt (MB/s) | Decrypt (MB/s) | Encrypt peak RSS (MB) | Decrypt peak RSS (MB) |
|---|---:|---:|---:|---:|
| xchacha20-poly1305 | 50.0 | 49.8 | 279.8 | 278.3 |
| aes-256-gcm | 205.7 | 179.2 | 273.8 | 275.7 |

Two real findings, reported as measured rather than smoothed over:

- **Peak memory stays flat at 4 GB just like it did at 1 GB** (~275-280 MB,
  the same range the 10 MB-1024 MB table above shows) - the clearest
  confirmation that streaming chunked I/O genuinely doesn't scale memory
  with file size, at the size where a naive whole-file-in-memory
  implementation would need 4+ GB of RAM to do the same job.
- **AES-256-GCM's throughput dropped substantially at this size** (205/179
  MB/s here vs. 487/354 MB/s at 1024 MB) while XChaCha20-Poly1305's stayed
  essentially flat (50 MB/s vs. 48.7 MB/s). This was not re-run to smooth
  out - it's one real data point, not confirmed against a second run, so
  treat the *direction* (AES-GCM's advantage narrows a lot at multi-GB
  sizes on this machine) as more trustworthy than the exact numbers.
  Plausible causes not yet isolated: sustained-write thermal/power
  throttling over a 20-80 second run (this machine is a laptop), or disk
  I/O becoming the bottleneck once AES-GCM's CPU cost drops low enough for
  I/O to dominate instead. Re-running with median-of-3 at this size and
  watching CPU frequency/I/O wait during the run would confirm which.

## What is not yet benchmarked

- Files above 4 GB
- Non-Apple-Silicon hardware (no AES-NI comparison point has been run on
  x86 for this project; the ~10x XChaCha20/AES-GCM gap should hold
  directionally on any hardware with AES-NI, but has not been measured
  there)
- `--workers` combined with AES-256-GCM (only measured with the default
  XChaCha20-Poly1305)
- Cold-start vs. warm-cache disk I/O effects on very large files
- Median-of-3 confirmation of the AES-256-GCM throughput drop noted above
- CPU% for the file-size and chunk-size sweep tables above - those predate
  CPU tracking being added; only the "Parallel workers" table below has
  been re-measured with it so far

True resumable encryption/decryption (continuing an interrupted operation
on a huge file without restarting from scratch) is intentionally not
implemented - see "What large-file support means today" in
[`docs/architecture.md`](architecture.md#large-file-handling) for what is
and isn't guaranteed, and [`docs/ROADMAP.md`](ROADMAP.md) Phase 7 for why
that's deliberately deferred rather than half-built.
