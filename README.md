# THEncrypterX

A file encryption tool with authenticated encryption, a password-derived key
(Argon2id), and a versioned binary container format (`.thex`). Ships as a
CLI (`typer`) and a desktop GUI (PySide6).

```bash
thencrypterx encrypt document.pdf
thencrypterx decrypt document.pdf.thex
thencrypterx inspect document.pdf.thex
```

## Status

Feature-complete against the [build guide](THEncrypterX_Build_Guide.md)'s v1
scope. 263 tests passing, CI green on Linux/macOS/Windows × Python 3.12/3.13.

## Features

- **Authenticated encryption**: XChaCha20-Poly1305 (default) or AES-256-GCM,
  chosen per file and recorded in its header
- **Password-based key derivation**: Argon2id with a random salt per file;
  parameters are versioned and stored alongside the ciphertext
- **Domain-separated subkeys**: metadata and file content are encrypted
  under independent keys derived via HKDF
- **Streaming, bounded-memory processing**: files are read and encrypted in
  fixed-size chunks; memory use does not scale with file size
- **Parallel chunk workers**: `--workers N` seals/opens up to N chunks
  concurrently on a thread pool - both AEAD backends release the GIL during
  their C-level work, so this is real multi-core speedup, not just
  scheduling overhead (measured ~4x throughput at 8 workers on an 8-core
  machine; see Benchmarks). File order is preserved regardless of which
  chunk's computation finishes first, and any worker count can decrypt a
  file produced with any other
- **Tamper detection**: every chunk's position (index + final-flag) is
  cryptographically bound to its content, catching reordering, duplication,
  and truncation - not just content modification
- **Encrypted metadata**: original filename, size, and modification time are
  hidden inside the container, never shown before authentication succeeds
- **Atomic writes**: output is only created/replaced if the whole operation
  succeeds; a crash, exception, or cancellation never leaves a partial file
- **CLI**: `encrypt` / `decrypt` / `inspect` / `shred`, with password
  sourcing via environment variable, file, or a no-echo prompt - never a
  plain command-line flag
- **GUI**: drag-and-drop, a responsive window (encryption runs on a
  background thread), live progress, and a working Cancel button
- **Best-effort secure deletion** (`shred`), honestly documented as
  best-effort - see the threat model

## Security model

Full details, including exactly what is and is not protected: **[docs/threat-model.md](docs/threat-model.md)**.

In short: Argon2id derives a master key from the password and a random
per-file salt; HKDF splits it into independent metadata/data subkeys; AEAD
(XChaCha20-Poly1305 by default) provides confidentiality and integrity;
every chunk's index and final-flag are bound into its authenticated data, so
tampering with content, order, or completeness is all detected the same way.
The container format is fully specified in
**[docs/file-format.md](docs/file-format.md)**, and the module layout in
**[docs/architecture.md](docs/architecture.md)**.

## Installation

```bash
git clone https://github.com/Emonemon74/THEncrypterX.git
cd THEncrypterX
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
```

`requirements.txt` covers the CLI only; `requirements-dev.txt` adds the GUI
(PySide6) and everything needed to run the tests.

## Usage

### CLI

```bash
# Encrypt (prompts for a password, twice, with no echo)
thencrypterx encrypt document.pdf
thencrypterx encrypt document.pdf -o secret.thex --aead aes256gcm --chunk-size 4194304

# --workers defaults to your CPU count - pass --workers 1 for the original
# single-threaded behaviour
thencrypterx encrypt large-video.mp4 --workers 8

# Decrypt (default output name comes from the encrypted metadata)
thencrypterx decrypt document.pdf.thex
thencrypterx decrypt document.pdf.thex -o restored.pdf

# Inspect a container's header - no password needed, nothing inside is read
thencrypterx inspect document.pdf.thex

# Best-effort overwrite + delete
thencrypterx shred document.pdf --yes
```

Password sourcing, in priority order: `THEX_PASSWORD` environment variable →
`--password-file <path>` → interactive no-echo prompt. There is no
`--password` flag on purpose - it would leak into shell history.

Exit codes: `0` success, `1` unexpected error, `2` wrong password, `3`
corrupt/unsupported container, `4` cancelled.

### GUI

```bash
python main.py
```

![THEncrypterX GUI](docs/images/gui_screenshot.png)

Drag a file in (or click "Select File"), type a password, click Encrypt or
Decrypt. Large files run on a background thread - the window stays
responsive, and Cancel actually stops the job.

### Library

```python
from app.files.encrypt import encrypt_file
from app.files.decrypt import decrypt_file

encrypt_file("document.pdf", "document.pdf.thex", "a password")
metadata = decrypt_file("document.pdf.thex", "restored.pdf", "a password")
print(metadata.original_name, metadata.original_size)
```

## File format

`.thex` is a versioned binary container: a plaintext header (magic bytes,
format version, algorithm ids, KDF parameters, salt), an encrypted metadata
section, N encrypted chunks, and a footer. Full byte-offset spec, associated-
data definitions, and a frozen known-answer test vector:
**[docs/file-format.md](docs/file-format.md)**.

## Testing

```bash
pytest                    # full suite, ~1-5s
pytest tests/test_security.py -v   # the 22-case tamper matrix
```

Test suite breakdown (263 tests total):

| Category | File(s) | What it proves |
|---|---|---|
| Crypto primitives | `test_kdf.py`, `test_keys.py`, `test_cipher.py` | Argon2id, HKDF, AEAD wrapper correctness and failure modes |
| Wire format | `test_header.py`, `test_container.py` | Byte-exact pack/parse, strict validation, fuzz-safety against malformed headers |
| Metadata | `test_metadata.py` | Serialization, path-traversal-safe filename sanitization |
| File I/O | `test_files_stream.py`, `test_files_encrypt.py`, `test_files_decrypt.py` | Chunking, atomic writes, full encrypt/decrypt round trips |
| Security matrix | `test_security.py` | 22 documented attack scenarios, each with an expected typed failure |
| Property-based | `test_properties.py` | Round-trip and "any single-bit flip is caught" across hundreds of generated inputs (Hypothesis) |
| Known-answer vector | `test_kat.py` | A frozen container that must always decode identically - a compatibility guardrail |
| CLI / core / GUI | `test_cli.py`, `test_core_*.py`, `test_gui_main_window.py` | Argument handling and exit codes, job/progress/cancellation wiring, the PySide6 window (headless, `pytest-qt`) |

CI runs the same suite plus `ruff` and `mypy` on every push, across
Linux/macOS/Windows and Python 3.12/3.13.

## Benchmarks

Measured with `benchmarks/benchmark_files.py` (median of 3 runs; production
Argon2id parameters - 256 MiB memory, time_cost 3, parallelism 4, ~0.15s per
call, included in every Encrypt/Decrypt time below since every real call
derives its own key):

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

Machine: Apple Silicon, 8 cores, macOS, Python 3.13.7. A chunk-size sweep
(64 KiB-16 MiB) at 500 MB showed flat throughput for XChaCha20-Poly1305,
confirming the gap to AES-256-GCM is the cipher itself (OpenSSL's hardware
AES instructions vs. software ChaCha20), not per-chunk overhead. See
`docs/threat-model.md` for why XChaCha20-Poly1305 remains the default
despite being ~10x slower here.

Peak memory stayed in the 275-780 MB range across all file sizes from 10 MB
to 1024 MB - it does not scale with file size, which is the actual claim
streaming is meant to prove (a naive whole-file-in-memory implementation
would need >1 GB of RAM for the 1 GB file; this needed roughly a quarter of
that, dominated by Argon2id's own 256 MiB working set rather than file
data). The exact figures are somewhat inflated by test-harness memory from
generating the random input file; see the script's docstring.

### Parallel workers (`--workers`)

Measured on a 200 MB file, XChaCha20-Poly1305, same 8-core machine:

| Workers | Encrypt (MB/s) | Decrypt (MB/s) |
|---:|---:|---:|
| 1 | 45.9 | 44.8 |
| 2 | 78.6 | 80.3 |
| 4 | 142.5 | 169.9 |
| 8 | 189.2 | 137.3 |

Encrypt scales close to linearly through 8 workers (~4.1x). Decrypt peaks at
4 workers (~3.8x) and *regresses* at 8 - on an 8-core machine, 8 worker
threads plus the main thread doing sequential reads/writes oversubscribes
the available cores, and thread-scheduling and GIL-reacquisition overhead
starts to outweigh the parallel gain. This is why the CLI's `--workers`
default is your CPU core count, not an arbitrarily high number - matching
cores is the sweet spot the data actually shows, not a guess.

## Limitations and roadmap

- File size is not hidden (no padding to fixed buckets)
- Secure deletion is best-effort only - not guaranteed on SSDs, CoW
  filesystems, or where backups/snapshots exist (see threat model)
- No password-strength checking
- Parallel workers (`--workers`) only pipeline chunk-level AEAD calls, not
  the Argon2id key derivation itself (a fixed cost per operation) or disk
  I/O beyond the OS's own buffering
- No post-quantum primitives
- No multi-recipient / key-sharing support

## License

MIT - see [LICENSE](LICENSE).
