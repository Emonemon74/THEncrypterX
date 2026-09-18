# Development

The full local setup, test, lint, and PR workflow lives in
[`CONTRIBUTING.md`](../CONTRIBUTING.md) at the repo root - that's the
canonical reference; this page only adds the parts specific to
understanding the codebase while developing it, rather than repeating the
day-to-day commands.

For what each module is responsible for, see
[`docs/architecture.md`](architecture.md#module-responsibilities).

## Where things live

```text
app/
├── crypto/     # Argon2id, HKDF, AEAD - no file or CLI/GUI concerns
├── format/     # .thex wire format: header, container framing, constants
├── metadata/   # FileMetadata: serialize/deserialize, filename sanitization
├── files/      # Orchestration: encrypt/decrypt/shred, streaming, atomic I/O
├── core/       # Errors, Progress/CancellationToken, Job classes (CLI+GUI share these)
├── cli.py      # typer CLI
└── gui/        # PySide6 desktop app

tests/          # mirrors app/ roughly 1:1, plus test_security.py, test_properties.py, test_kat.py
benchmarks/     # benchmark_files.py - throughput/memory/chunk-size measurements
scripts/        # generate_kat.py - regenerates the frozen known-answer test vector
packaging/      # PyInstaller spec for the standalone desktop-GUI build
docs/           # architecture, cryptography/threat-model, file-format, performance, this file
web/            # standalone client-side web demo - separate Node/TS project,
                # its own format (.thexweb), not part of the Python package
                # (see web/README.md - this doc covers app/ only)
```

`app/core/*` is the layer both the CLI and the GUI build on - if you're
adding a new operation (not just a flag on an existing one), it likely
belongs there first as a `Job` class, with `app/cli.py` and
`app/gui/workers.py` each becoming thin adapters over it. This is why
`app/gui/main_window.py` never imports `app.files` or `app.crypto`
directly (see [`docs/architecture.md`](architecture.md#threading-model-gui-only)).

## Design invariants worth knowing before changing code

These aren't enforced by a linter - they're conventions this codebase
depends on, and changing them without updating the tests that check for
them is how a security regression slips in silently:

- **The header is associated data, never just a preamble.** Every field in
  it (algorithm ids, KDF params, chunk size, salt) is bound into both the
  metadata AEAD and every chunk's AEAD via `app/format/header.py`. Adding a
  new header field means deciding whether it should be authenticated the
  same way - almost always yes.
- **Chunk index and `is_final` are part of a chunk's associated data**, not
  just sequential reads. This is what makes reordering/duplication/
  truncation detectable, not just content tampering. See
  `app/format/container.py` and `docs/threat-model.md`.
- **Fail closed.** Any parse or verification step that can't be trusted
  should raise a typed `ThexError` subtype (`app/core/errors.py`) rather
  than returning a partial or best-guess result. `tests/test_security.py`
  exists to catch violations of this.
- **Writes are atomic.** `app/files/stream.py::atomic_writer` writes to a
  temp file, `fsync`s, then `os.replace`s - any exception unlinks the temp
  file instead of leaving a partial `.thex`/output file. Don't introduce a
  second write path that bypasses this.
- **Format changes are versioned, not silent.** A wire-format change bumps
  the format version in `app/format/constants.py` and requires a
  deliberate KAT regeneration (`scripts/generate_kat.py`) - never edit
  `tests/vectors/` by hand or regenerate it just to make a failing test
  pass without understanding why the format moved.

## Before opening a PR

See [`CONTRIBUTING.md`](../CONTRIBUTING.md#pull-request-expectations) for
the checklist (tests, `ruff`, `mypy`, and which docs to update alongside a
security- or format-relevant change).
