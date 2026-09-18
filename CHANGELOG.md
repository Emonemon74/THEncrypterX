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
