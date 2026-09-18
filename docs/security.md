# Security Engineering Notes

This page covers the *engineering practices* around secrets, error
handling, and file safety - how the code behaves, not what the cryptography
guarantees. For the attacker model and what is/isn't protected, see
[`docs/threat-model.md`](threat-model.md). To report a vulnerability, see
[`SECURITY.md`](../SECURITY.md).

## Secret handling

- **No `--password` CLI flag, by design.** A command-line argument is
  visible in shell history, in `ps` output to any other user on the same
  machine, and often in logs. Passwords are sourced, in priority order, from
  the `THEX_PASSWORD` environment variable, a `--password-file`, or a
  no-echo interactive prompt (`app/cli.py::_resolve_password`).
- **Passwords and keys are never logged or printed.** `app/cli.py`'s error
  paths print exception messages (`{exc}`) and fixed status strings, never
  the password, a derived key, or file plaintext. The GUI's error dialogs
  (`app/gui/main_window.py`) follow the same rule.
- **Exceptions don't leak secrets by construction**, not just by convention
  - the typed exception hierarchy (`app/core/errors.py`) carries only
  operation-level context (which step failed, why), never key material,
  because key material is never passed into an exception in the first
  place.
- **Key zeroization is partial, and documented as such.** `app/crypto/keys.py::zeroize()`
  overwrites a `bytearray` in place, for the one place a mutable buffer is
  used. Most of the codebase handles keys as plain Python `bytes`, which are
  immutable and cannot be reliably wiped - this is a known limitation of
  memory-managed languages, not something this project claims to solve. See
  [`docs/threat-model.md`](threat-model.md#what-is-explicitly-not-protected).

## File handling

- **Path traversal**: `FileMetadata` deserialization always sanitizes the
  stored original filename down to a bare basename before it's used to open
  a file, discarding any directory component (`app/metadata/metadata.py`,
  tested in `tests/test_metadata.py::test_sanitize_filename_*` and
  `test_deserialize_rejects_path_like_name_via_validation`). A crafted
  `.thex` file cannot cause decryption to write outside the requested
  output directory.
- **Atomic writes**: every encrypt/decrypt writes to a temporary file,
  `fsync`s it, then `os.replace`s it into place (`app/files/stream.py::atomic_writer`).
  Any exception - including a mid-operation cancel - unlinks the temp file
  instead of leaving a partial or corrupt output file where the real one
  should be.
- **Malformed input never over-allocates or hangs.** Every length field
  read from an untrusted `.thex` file (chunk length, metadata length,
  declared chunk count) is validated against a known-safe bound *before* it
  is used to size a read or allocation (`app/format/header.py`,
  `app/format/container.py`; see `tests/test_header.py::test_random_garbage_never_crashes`
  and the Hypothesis-based fuzzing in `tests/test_properties.py`).
- **Fixed by this review: a TOCTOU race on the auto-derived decrypt output
  path.** `decrypt_file(..., output_path=None)` takes the output filename
  from authenticated metadata and was checking `resolved_output.exists()`
  once, before decryption started - on a large file, something else could
  create that path in the window between the check and the eventual write,
  and the old `os.replace`-based publish would have silently clobbered it
  anyway, defeating the documented "refuses to overwrite" guarantee.
  `atomic_writer` now takes `must_not_exist=True` for this path
  (`app/files/stream.py`), which publishes via `os.link` instead of
  `os.replace` - `os.link` atomically fails with `FileExistsError` if the
  destination exists, closing the race at the filesystem level rather than
  with a separate check. Covered by
  `tests/test_files_stream.py::test_must_not_exist_raises_and_leaves_no_tmp_file_on_race`.
  An explicit `-o`/`output_path` is unaffected and still always overwrites,
  matching `encrypt_file`'s existing semantics.
- **Reviewed, found not to be an issue: symlinked output paths.**
  `os.replace`/`os.link`'s destination argument replaces the directory
  entry itself rather than following it, on both POSIX and Windows - so a
  destination that is a symlink gets replaced as a symlink, it does not
  cause the write to land at whatever the symlink points to.
- **Not yet reviewed**: behavior under disk-space exhaustion mid-write
  (temp file write fails partway - the exception path should still clean up
  the temp file via the existing `except BaseException` handler, but this
  hasn't been exercised by a dedicated test that simulates `ENOSPC`).
  Tracked in [`docs/ROADMAP.md`](ROADMAP.md) (Phase 14).

## Memory

- Chunked, streaming processing means plaintext and ciphertext are held in
  bounded-size buffers (one chunk at a time), not the whole file at once -
  see [`docs/performance.md`](performance.md#memory) for measured peak
  memory across file sizes.
- Argon2id's own working set (256 MiB by default) dominates peak memory
  usage for small-to-medium files; it is not itself a leak, it's the
  deliberate memory-hardness the KDF is chosen for.
- No independent side-channel hardening (timing, power, cache) is added on
  top of the underlying libraries - `cryptography`, PyNaCl, and
  `argon2-cffi` are relied on for their own constant-time implementations.
  See [`docs/threat-model.md`](threat-model.md#attacker-model).

## The security regression suite

`tests/test_security.py`'s 22-case matrix is the primary automated evidence
for every claim in `docs/threat-model.md`'s "What is protected, and how"
table - each row there names the specific test(s) that back it. Any change
to `app/crypto/`, `app/format/`, or `app/files/` should be checked against
this matrix before merging; a change that requires *weakening* one of these
cases to pass is very likely a security regression, not a test that needs
updating.

`tests/test_properties.py` adds broader, generated-input evidence on top of
the hand-picked matrix: for many random plaintexts and passwords, round-trip
correctness holds, and any single-bit corruption anywhere in a valid
container produces a typed failure - never a crash, never a silent wrong
success.

`tests/test_fuzz_parser.py` goes further, fuzzing every parser entry point
(header, footer, metadata, chunk framing) with arbitrary, unstructured
bytes rather than mutations of an otherwise-valid container - plus a
whole-file fuzz through `verify_file`, the closest thing to what handing an
attacker-controlled file to this project actually looks like. It also has
a targeted regression test for extreme length fields (near the u32/u64 max)
never triggering an oversized allocation, since `read_exact`'s `stream.read(n)`
only ever returns bytes actually present regardless of what `n` claims.
Coverage-guided fuzzing (Atheris/libFuzzer) was considered and deliberately
not added - see the module docstring for why Hypothesis was judged
sufficient for a format this small and already this strictly validated
field-by-field.

## Known gaps (tracked, not silently ignored)

See [`docs/threat-model.md`](threat-model.md#what-is-explicitly-not-protected)
for the full list (file size not hidden, best-effort-only secure deletion,
no password-strength check, no post-quantum primitives, no multi-recipient
support).
