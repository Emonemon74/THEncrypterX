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
- **Not yet reviewed**: symlink handling on the output path (if the target
  path is a symlink, THEncrypterX currently does not special-case it -
  `os.replace` follows normal OS symlink semantics), and behavior under
  disk-space exhaustion mid-write. Both are tracked in
  [`docs/ROADMAP.md`](ROADMAP.md) (Phase 14) as review items, not yet
  confirmed safe or unsafe by a dedicated test.

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

## Known gaps (tracked, not silently ignored)

See [`docs/threat-model.md`](threat-model.md#what-is-explicitly-not-protected)
for the full list (file size not hidden, best-effort-only secure deletion,
no password-strength check, no post-quantum primitives, no multi-recipient
support). Fuzz testing of the `.thex` parser beyond Hypothesis-generated
mutations of valid containers (i.e., true unstructured-input fuzzing with a
dedicated harness) is a roadmap item - see
[`docs/ROADMAP.md`](ROADMAP.md), Phase 5.
