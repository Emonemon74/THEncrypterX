# Architecture

## Layers

```text
                       ┌──────────────────────┐
                       │   app/cli.py          │   app/gui/main_window.py
                       │   (typer)             │   (PySide6)
                       └──────────┬───────────┘   app/gui/workers.py (QThread)
                                  │                        │
                                  ▼                        ▼
                       ┌──────────────────────────────────────┐
                       │            app/core/                  │
                       │  service.py: EncryptJob / DecryptJob  │
                       │             / InspectJob              │
                       │  progress.py: Progress,               │
                       │               CancellationToken       │
                       │  errors.py: typed exception hierarchy │
                       └──────────┬─────────────────────────────┘
             ┌────────────────────┼────────────────────┐
             ▼                    ▼                    ▼
      ┌─────────────┐      ┌──────────────┐     ┌──────────────┐
      │ app/crypto/ │      │ app/format/  │     │ app/files/   │
      │  kdf.py     │      │  header.py   │     │  stream.py   │
      │  keys.py    │      │  container.py│     │  encrypt.py  │
      │  cipher.py  │      │  constants.py│     │  decrypt.py  │
      │             │      │  _io.py      │     │  shred.py    │
      │ Argon2id    │      │              │     │              │
      │ HKDF subkeys│      │ THX1 header  │     │ chunk loop   │
      │ AEAD wrap   │      │ sealed       │     │ bounded RAM  │
      │             │      │ sections     │     │ atomic write │
      └─────────────┘      └──────┬───────┘     └──────┬───────┘
                                  │                    │
                       ┌──────────┴───────┐            │
                       │ app/metadata/    │            │
                       │  metadata.py     │            │
                       └──────────────────┘            │
                                  │                    │
                                  └──────────┬─────────┘
                                             ▼
                                      ┌──────────────┐
                                      │ .thex file   │
                                      │ container    │
                                      └──────────────┘
```

**Dependency rule, enforced by convention (not tooling):** `crypto/`, `format/`,
`files/`, and `metadata/` never import from `core/`, `cli.py`, or `gui/`. Only
`core/service.py` orchestrates across `crypto/`, `format/`, `files/`, and
`metadata/`; `cli.py` and `gui/` both sit on top of `core/` (though `cli.py`
currently calls `app.files` directly too, since it runs synchronously either
way and doesn't need cancellation - `core/service.py` exists for the layer
that does, `gui/workers.py`).

## Module responsibilities

| Module | Responsibility | Depends on |
|---|---|---|
| `app/crypto/kdf.py` | Argon2id: password + salt → master key (versioned, bounded params); HKDF-Extract-and-Expand for key-file mode | `argon2-cffi`, `cryptography` |
| `app/crypto/keys.py` | HKDF: master key → `meta_key` / `data_key` subkeys (domain separation) | `cryptography` |
| `app/crypto/cipher.py` | AEAD `seal`/`open_`: XChaCha20-Poly1305 (PyNaCl) and AES-256-GCM (`cryptography`) behind one interface | PyNaCl, `cryptography` |
| `app/format/constants.py` | Magic bytes, field widths, size caps - single source of truth for the wire format | - |
| `app/format/_io.py` | `read_exact`: read-or-raise-`FormatError`, shared by header and container parsing | `app.core.errors` |
| `app/format/header.py` | `Header`: pack/parse the fixed `.thex` header; the header is its own associated data | `app.crypto.cipher`, `app.crypto.kdf` |
| `app/format/container.py` | Sealed-section framing (shared by metadata and every chunk), chunk associated-data, footer | `app.crypto.cipher` |
| `app/metadata/metadata.py` | `FileMetadata`: strict serialize/deserialize, filename sanitization (path-traversal defense) | `app.core.errors` |
| `app/files/stream.py` | `iter_chunks` (bounded-memory read-ahead), `atomic_writer` (temp file + fsync + `os.replace`) | - |
| `app/files/encrypt.py` | Orchestrates header + metadata + chunk loop → `.thex`, streaming | everything above |
| `app/files/decrypt.py` | Reverse of `encrypt.py`, fail-closed at every step, optional metadata-derived output name | everything above |
| `app/files/verify.py` | `verify_file`: reuses `decrypt.py`'s chunk-authentication loops against a discard sink - authenticates everything, writes nothing | `app.files.decrypt` |
| `app/files/keyfile.py` | `generate_key_file`/`read_key_file`: the separate `.thexkey` format for key-file mode | `app.crypto.kdf`, `app.files.stream` |
| `app/files/shred.py` | Best-effort overwrite-then-delete | - |
| `app/core/errors.py` | Typed exception hierarchy (`ThexError` and subtypes) shared by every layer | - |
| `app/core/progress.py` | `Progress` value object, thread-safe `CancellationToken` | `app.core.errors` |
| `app/core/service.py` | `EncryptJob`/`DecryptJob`/`VerifyJob`/`InspectJob`: bridge `app.files` callbacks to `Progress`/cancellation | `app.core.progress`, `app.files.*` |
| `app/benchmark.py` | Shared measurement core for `thencrypterx benchmark` and `benchmarks/benchmark_files.py` | `app.files.encrypt`/`decrypt` |
| `app/cli.py` | `typer` CLI: `encrypt`/`decrypt`/`verify`/`inspect`/`keygen`/`benchmark`/`shred`, password/key-file sourcing, exit codes | `app.files.*` |
| `app/gui/main_window.py` | PySide6 window: file/output selection, password field, buttons, progress bar | `app.gui.workers` |
| `app/gui/workers.py` | `EncryptWorker`/`DecryptWorker`: run one job per `QThread`, report back via Qt signals | `app.core.service` |

## Data flow: encrypting a file

Key-file mode (`--key-file`) branches only at the first step: a random key
file's bytes take HKDF-Extract-and-Expand instead of Argon2id (no memory-hard
stretching - see `docs/threat-model.md`), producing the same `master_key`
shape everything below consumes unchanged.

```text
password ──Argon2id(random salt, versioned params)──► master_key (32B)
                                                            │
                                          HKDF-SHA256 (domain-separated)
                                                            │
                            ┌───────────────────────────────┼───────────────────────────────┐
                            ▼                                                               ▼
                       meta_key (32B)                                                  data_key (32B)
                            │                                                               │
        AEAD(meta_key, random nonce, serialize(FileMetadata))              per-chunk AEAD(data_key, nonce_i,
                            │                                               chunk_i; AD binds index + is_final)
                            ▼                                                               ▼
                 [ nonce | len | ciphertext+tag ]                          [ nonce | len | ciphertext+tag ] × N
                            │                                                               │
                            └──────────────────────────┬────────────────────────────────────┘
                                                        ▼
                      header (magic, version, algo ids, KDF params, salt)
                          + metadata section + chunk sections + footer
                                                        ▼
                                              atomic write → .thex
```

Header bytes (through the salt) are the associated data for the metadata AEAD
call *and* every chunk's AEAD call - tampering with any header field breaks
authentication everywhere downstream. See `docs/file-format.md` for the exact
byte layout and `docs/threat-model.md` for what each defense catches.

## Parallel chunk workers (`workers > 1`)

```text
main thread                          ThreadPoolExecutor (workers=N)
    │
    │  read chunk i, submit seal(i) ────► worker: seal(chunk_i)  (GIL released - runs on its own core)
    │  read chunk i+1, submit seal(i+1) ─► worker: seal(chunk_i+1) (concurrent with the above)
    │  ...
    │  pop oldest future, write it     ◄── FIFO window, size = workers * 2
    │  (blocks here only if the oldest isn't done yet)
```

`app/files/encrypt.py::_encrypt_chunks_parallel` and
`app/files/decrypt.py::_decrypt_chunks_parallel` submit each chunk's
`seal()`/`open_()` call to a `ThreadPoolExecutor` instead of calling it
inline. This works because both AEAD backends (PyNaCl/libsodium,
`cryptography`/OpenSSL) release the GIL for the duration of their C-level
work, so multiple chunks genuinely compute on different cores at once -
confirmed by measurement (README §Benchmarks: ~4x throughput at 8 workers
on an 8-core machine), not just assumed from "the docs say AEAD releases
the GIL."

Reading/writing stays on the calling thread and in strict file order - a
frame's length is only known after reading its length prefix, so I/O can't
be parallelized the same way, and chunks must land in the file in index
order regardless of which one's *computation* finishes first (the pool
makes no ordering guarantee). A fixed-size FIFO window (`workers * 2`
in-flight chunks) reconciles the two: work is submitted in order, but only
drained - written, or checked for a raised `AuthenticationError` - from the
front of the window, once that specific chunk is done, however long its
neighbors take. This bounds memory the same way `iter_chunks`'s read-ahead
does, just widened to fit the pool. The container produced is ordinary and
worker-count-agnostic: a file encrypted with `workers=8` decrypts correctly
with `workers=1` and vice versa, since nothing about the on-disk format
depends on how many threads produced or consume it.

## Threading model (GUI only)

```text
GUI thread (Qt event loop)              Worker thread (QThread.run())
    │                                        │
    │  EncryptWorker(...); worker.start() ──►│  EncryptJob.run(on_progress, cancel_token)
    │                                        │      read → seal → write, chunk by chunk
    │  ◄── progress(float) [queued signal] ──┤      on_progress() checks cancel_token first
    │  ◄── finished_ok / failed / cancelled ─┤
    │      (queued signal)                   │
    │  update UI, re-enable buttons          │  run() returns
```

Signals crossing threads are queued onto the receiving thread's event loop by
Qt automatically (`Qt.AutoConnection`) - no manual locking anywhere in
`app/gui/`. Cancellation is cooperative: `CancellationToken.cancel()` (called
from the GUI thread) just sets a `threading.Event`; the worker notices it the
next time a chunk's progress callback runs and lets `CancelledError`
propagate, which `atomic_writer`'s existing exception handling turns into "no
partial output" without any GUI-specific cleanup code.

## Why this layering

- **`crypto/`, `format/`, `metadata/` know nothing about files, threads, or
  UI.** They can be tested (and were, first - Sections 7-9 of the build
  guide) as pure functions on bytes, long before there was a CLI or GUI to
  drive them.
- **`files/` knows about disk, but not about threads or UI.** `encrypt_file`/
  `decrypt_file` are ordinary blocking functions; whether they run on the
  main thread (CLI) or a `QThread` (GUI) is a concern of the caller, not of
  the function.
- **`core/` is the only place that knows both "job" and "progress/
  cancellation" exist.** Adding a second GUI (say, a web frontend) later
  would reuse `core/service.py` unchanged and only need a new
  `gui_web/workers.py`-equivalent adapter.
