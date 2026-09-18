# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `docs/ROADMAP.md` - a prioritized improvement roadmap for post-v1.0 work
  (security engineering, distribution, advanced file handling)
- `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`
- `docs/cryptography.md`, `docs/security.md`, `docs/performance.md`,
  `docs/development.md`
- `thencrypterx verify` CLI command and `app.files.verify.verify_file`:
  authenticates a container's header, metadata, and every chunk without
  writing any plaintext anywhere. Reuses `decrypt.py`'s chunk-
  authentication loops against a discard sink, so it's the same
  authentication path as `decrypt`, not a separate reimplementation.
  22 new tests (`tests/test_verify.py` plus CLI coverage in
  `tests/test_cli.py`)
- `tests/test_fuzz_parser.py`: Hypothesis-based fuzzing of every `.thex`
  parser entry point (header, footer, metadata, chunk framing) with
  arbitrary unstructured bytes, plus a whole-file fuzz through `verify`,
  and a targeted regression test confirming extreme length fields
  (near u32/u64 max) fail fast without over-allocating. 10 new tests,
  318 total
- `thencrypterx benchmark` CLI command: measures real encrypt/decrypt
  throughput on this machine across algorithms and worker counts, without
  needing to run the standalone `benchmarks/benchmark_files.py` script.
  The shared measurement core moved to `app/benchmark.py` so both the CLI
  command and the standalone Markdown-sweep script use the same code.
- Desktop GUI: algorithm selector, chunk-size selector, and worker-count
  selector for encryption; live throughput/ETA display during a job; a
  confirmation prompt when closing the window while a job is running
  (cancels the job and lets its own cleanup run, rather than abandoning a
  background thread and any partial temp file).

### Security
- Fixed a denial-of-service bug found by the existing bit-flip property
  test: `Argon2Params` (`app/crypto/kdf.py`) had no upper bound on
  `memory_cost_kib`/`time_cost`/`parallelism`, and those fields are read
  straight from the (not-yet-authenticated) file header. A single flipped
  bit could turn `memory_cost_kib` into a huge value, and Argon2id's C
  implementation won't return control to Python until it finishes trying to
  allocate/hash that much "memory cost" - not even a timeout can interrupt
  it mid-call. `decrypt`/`verify` on a corrupted or malicious `.thex` file
  could hang for a very long time instead of failing parsing fast. Fixed by
  capping all three params to generous-but-finite ceilings, enforced in
  `Argon2Params.__post_init__` so every caller (header parsing, the GUI, the
  library API) is covered. See `docs/threat-model.md`.

### Fixed
- Closed a TOCTOU race in `decrypt_file(..., output_path=None)`: the
  auto-derived output path's "refuse to overwrite" check could be beaten by
  something else creating that path mid-decryption, which the old
  `os.replace`-based publish would then have silently clobbered.
  `atomic_writer` gained a `must_not_exist=True` mode (publishes via
  `os.link`, which atomically fails if the destination exists) to close the
  window at the filesystem level.

## [1.0.0] - tagged `v1.0`

Initial feature-complete release, built end-to-end against
`THEncrypterX_Build_Guide.md`.

### Added
- Argon2id password-based key derivation, versioned parameters stored in
  the container header
- HKDF-SHA256 domain separation into independent metadata/data subkeys
- AEAD file encryption: XChaCha20-Poly1305 (default) and AES-256-GCM,
  selectable per file
- Versioned `.thex` binary container format (`THX1`): plaintext header,
  encrypted metadata section, streamed encrypted chunks, footer
- Streaming, bounded-memory encryption/decryption - memory does not scale
  with file size
- Per-chunk tamper detection: index and final-flag cryptographically bound
  to content, catching reordering, duplication, and truncation
- Encrypted metadata (original filename, size, modification time), hidden
  until authentication succeeds
- Atomic writes - a crash, exception, or cancellation never leaves a
  partial output file
- CLI (`typer`): `encrypt`, `decrypt`, `inspect`, `shred`, with password
  sourcing via env var, file, or no-echo prompt (no `--password` flag, by
  design)
- Desktop GUI (PySide6): drag-and-drop, background-thread encryption/
  decryption, live progress, working Cancel
- Best-effort secure deletion (`shred`), documented as best-effort
- 284 tests: crypto primitives, wire-format fuzzing-safety, a 22-case
  security/tamper matrix, Hypothesis property tests, a frozen known-answer
  test vector, CLI/core/GUI integration tests
- CI (GitHub Actions): full suite + `ruff` + `mypy` on Linux/macOS/Windows
  x Python 3.12/3.13
- `docs/threat-model.md`, `docs/file-format.md`, `docs/architecture.md`
- Benchmark harness (`benchmarks/benchmark_files.py`) for throughput,
  memory, and chunk-size trade-offs

### Added (post-tag, same release cycle)
- Parallel chunk workers (`--workers N`): concurrent chunk-level AEAD on a
  thread pool, ~4x measured encrypt throughput at 8 workers on an 8-core
  machine; CLI defaults to CPU count, library functions default to 1
  (backward-compatible)

### Security
- `tests/test_security.py`'s 22-case matrix is the primary evidence for
  every claim in the threat model
- `tests/test_properties.py` (Hypothesis) checks round-trip correctness and
  that any single-bit corruption of a valid container produces a typed
  failure, never a crash or silent wrong success, across many generated
  inputs
