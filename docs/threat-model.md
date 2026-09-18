# Threat Model

This document states what THEncrypterX defends against, what it explicitly
does not, and why - following the project's own rule (Build Guide Section
29): every claim here maps to a design decision, an implementation, and a
test. The primary evidence is `tests/test_security.py`'s 22-case matrix;
this document explains *why* those 22 cases are the right ones to test, not
just that they pass.

## Attacker model

The attacker we defend against: **someone who obtains a `.thex` file but does
not know the password.** This covers the realistic cases a file-encryption
tool exists for - a stolen laptop, a leaked backup, a misconfigured public
bucket, a compromised cloud storage account.

We explicitly do **not** defend against an attacker who:

- controls the machine while you are actively using it (a keylogger, a
  compromised OS, malware reading process memory while the password is
  typed or held in RAM),
- can observe side channels (timing, power, cache) on the machine running
  THEncrypterX - we rely on the underlying libraries' (`cryptography`,
  PyNaCl, `argon2-cffi`) own constant-time implementations of AEAD and
  Argon2id and do not add any independent side-channel hardening,
  or
- has unlimited compute to brute-force a weak, short, guessable password.
  Argon2id (below) raises the cost of each guess; it does not make a weak
  password strong.

## What is protected, and how

| Property | Mechanism | Test evidence |
|---|---|---|
| File contents are unreadable without the password | AEAD (XChaCha20-Poly1305 or AES-256-GCM) under a key derived from the password | `test_01_correct_password_succeeds`, round-trip tests throughout |
| A wrong password is rejected, not silently misdecrypted | Metadata AEAD tag must verify before anything is trusted | `test_02_wrong_password_fails` |
| Tampering with any chunk's bytes is detected | Per-chunk AEAD tag | `test_03_modified_chunk_ciphertext_fails` |
| Tampering with a chunk's nonce is detected | The nonce is itself part of what the AEAD tag protects the pairing of | `test_04_modified_chunk_nonce_fails` |
| Tampering with the header (algorithm ids, KDF params, chunk size, salt) is detected, even if the header stays structurally valid | The whole header is the associated data for the metadata AEAD and every chunk AEAD | `test_05_modified_header_field_fails`, `test_15/16` |
| Removing, reordering, or duplicating chunks is detected | Each chunk's associated data binds its own index and `is_final` flag - a chunk's real position must match what it was sealed against | `test_06/07/12`, `tests/test_files_decrypt.py` structural-tamper tests |
| Truncating the file (at the end, or mid-chunk) is detected | A length-prefixed frame that runs past EOF fails to read; the true final chunk is the only one authenticated with `is_final=1`; the footer's declared chunk count is sanity-checked against the bytes actually present before the chunk loop even starts | `test_08_truncated_container_fails`, `test_18_truncated_mid_chunk_fails` |
| The original filename, size, and modification time are hidden | Encrypted as their own AEAD section under a key domain-separated from the data key | `test_09_tampered_metadata_fails`; see the residual leak noted below |
| A crafted filename cannot escape the output directory | `FileMetadata` always sanitizes to a bare basename, discarding any path component before it is ever used to open a file | `tests/test_metadata.py::test_sanitize_filename_*`, `test_deserialize_rejects_path_like_name_via_validation` |
| Splicing in a chunk from a different, unrelated `.thex` file fails | Each file has its own random salt, hence its own unrelated `data_key` | `test_13_spliced_chunk_from_different_file_fails` |
| Two files encrypted with the same password don't share any derivable state | Random salt per file | `test_22_two_files_same_password_are_independent` |
| A crash or exception during encrypt/decrypt never leaves a corrupted or partial file | Write to a temp file, `fsync`, then atomic `os.replace`; any exception unlinks the temp file instead | `tests/test_files_stream.py`, exercised throughout `test_files_encrypt.py`/`test_files_decrypt.py` |
| A malformed or malicious header can never trigger an oversized allocation or a hang | Every length field is validated against a known-safe value or an explicit cap *before* it is used to size a read | `tests/test_header.py::test_random_garbage_never_crashes`, `tests/test_properties.py` |
| A user-initiated cancel leaves no partial output | Cancellation raises inside the same exception path as any other failure, so the atomic writer's cleanup applies unchanged | `tests/test_core_service.py`, `tests/test_gui_main_window.py::test_cancel_stops_the_job_and_leaves_no_output` |

## Password → key: Argon2id

The password is never used as a key directly. Argon2id (memory-hard,
resistant to GPU/ASIC parallelization in a way plain-slow KDFs like PBKDF2
are not) derives a 32-byte master key from `password + random 16-byte salt`.
Default cost: 256 MiB memory, 3 iterations, 4 lanes - deliberately expensive
per guess. All three parameters, plus the salt, are stored in the header so
decryption reproduces the exact computation regardless of what today's
defaults happen to be (`app/crypto/kdf.py`, `docs/file-format.md` §3).

**What this does not do:** turn a weak password into a strong one. Argon2id
raises the cost per guess from nanoseconds to a fraction of a second; it
does not make `password123` safe. There is currently no password-strength
check in the CLI or GUI - a reasonable roadmap item.

## Key separation: HKDF subkeys

The master key is never used to encrypt anything directly. HKDF-SHA256
expands it into two independent subkeys - `meta_key` for the metadata
section, `data_key` for every chunk (`app/crypto/keys.py`). This is domain
separation: a bug in one path (say, a nonce collision in metadata handling)
cannot weaken the other, because the keys are cryptographically unrelated.

## Nonce strategy, and why it differs by algorithm

- **XChaCha20-Poly1305 (default, `aead_id=1`):** every nonce - metadata's and
  every chunk's - is `os.urandom(24)`. The 192-bit nonce space is large
  enough that random collisions are negligible even across an extremely
  large number of chunks, so no counter or per-file state is needed.
- **AES-256-GCM (alternate profile, `aead_id=2`):** its 96-bit nonce is *not*
  safe to pick at random across many messages under one key. The metadata
  section is a single message, so a random nonce there is still fine; the
  chunk stream (many messages under `data_key`) instead uses
  `nonce_i = per-file random 4-byte prefix || uint64_LE(chunk index)`,
  guaranteeing uniqueness by construction rather than by chance
  (`app/files/encrypt.py::_data_chunk_nonce`, `docs/file-format.md` §7).

## Why XChaCha20-Poly1305 is the default despite being much slower here

Benchmarking (`benchmarks/benchmark_files.py`, Build Guide Section 20) on
this project's development machine showed AES-256-GCM roughly **10x faster**
than XChaCha20-Poly1305 at realistic file sizes (≈490-650 MB/s vs ≈49 MB/s at
500 MB-1 GB). The cause: OpenSSL's AES-GCM uses the CPU's dedicated AES
hardware instructions (AES-NI on x86, the ARMv8 crypto extensions on Apple
Silicon); libsodium's XChaCha20 runs in optimized software with no
equivalent hardware path on either architecture. A chunk-size sweep from 64
KiB to 16 MiB showed flat throughput for XChaCha20, confirming this is the
cipher's genuine cost and not per-chunk overhead.

**The default stays XChaCha20-Poly1305 anyway.** The reason is the nonce
argument above, not performance: a 192-bit random nonce cannot practically
collide, which removes an entire class of implementation mistakes (a
mismanaged counter, a reused prefix) that a 96-bit-nonce cipher structurally
invites. For most files at typical human-scale sizes, a few seconds versus a
few hundred milliseconds is not a meaningful difference; for a use case that
is genuinely throughput-sensitive on very large files, `--aead aes256gcm` (CLI)
is available and uses the counter-nonce construction described above to stay
safe. This is a deliberate "safe by default, fast by choice" trade-off,
made with real numbers rather than assumed.

## What is explicitly NOT protected

- **The `.thex` file's own size** is observable to anyone who can see the
  file, and is not padded to hide it - an approximate size of the original
  content leaks. Padding to a fixed set of size buckets is a roadmap item,
  not implemented in v1.
- **File existence and access patterns.** Someone who can see your
  filesystem knows a `.thex` file exists, when it was created/modified at
  the filesystem level (distinct from the encrypted, authenticated
  `mtime_ns` inside it), and roughly how often it is accessed.
- **Secure deletion is best-effort, not guaranteed.** `app/files/shred.py`
  overwrites a file with random bytes before deleting it, but this
  provides **no** guarantee on: SSDs (wear-leveling relocates data
  invisibly to software), copy-on-write filesystems (APFS, Btrfs, ZFS -
  "overwriting" a file may just write a new block and leave the old one
  intact until garbage collection), journaling filesystems, or any system
  with existing snapshots or backups. If data must be provably
  unrecoverable, the correct tools are full-disk encryption with key
  destruction, or physical media destruction - not file-level overwrite.
- **Metadata beyond name/size/mtime.** Original file permissions, owner,
  extended attributes, and full path are never collected or stored at all
  (not "hidden" - simply absent from the format), which is a deliberate
  minimization rather than a limitation to fix.
- **Protection while the password is being typed or held in memory.** Key
  material is handled as plain Python `bytes` in most of the codebase;
  `app/crypto/keys.zeroize()` exists for the one place a `bytearray` is used,
  but Python's memory model means a fully airtight guarantee that no copy of
  a key or password ever lingers in process memory or gets paged to disk is
  not something this project claims. This is a known, common limitation of
  memory-managed-language crypto tools, not specific to THEncrypterX.
- **Post-quantum security.** All primitives here (Argon2id, XChaCha20/
  AES-256-GCM, HKDF-SHA256) are classical. A sufficiently capable quantum
  computer would not break these symmetric primitives via Grover's algorithm
  as catastrophically as it would break asymmetric ones, but this is not a
  design goal of v1 - noted as future work in the README roadmap.
- **Multi-user or key-sharing scenarios.** There is no concept of multiple
  recipients, key escrow, or revocation. One password, one file, one owner.

## Fuzz/property testing as ongoing evidence

Beyond the hand-picked matrix, `tests/test_properties.py` uses Hypothesis to
generate many random plaintexts, passwords, and single-bit corruptions and
checks two properties hold for all of them: round-trip correctness, and that
*any* single-bit flip anywhere in a valid `.thex` file causes a typed failure
(never a crash, never a silent wrong success). This is broader evidence than
any fixed list of hand-picked cases can provide on its own.

That property test is what caught a real denial-of-service bug: the header's
Argon2 `memory_cost_kib`/`time_cost` fields are read straight from the file,
and the header isn't authenticated until *after* the KDF runs (the KDF
derives the key needed to check the metadata MAC), so nothing bounded them.
A single flipped bit could turn `memory_cost_kib` into a huge value, and
Argon2id's C implementation doesn't return control to Python until it
finishes trying to allocate/hash that much "memory cost" - not even a
signal-based watchdog can interrupt it mid-call. `decrypt`/`verify` on a
corrupted or malicious file would hang for a very long time instead of
failing parsing fast. Fixed by capping `memory_cost_kib`, `time_cost`, and
`parallelism` in `Argon2Params.__post_init__` (`app/crypto/kdf.py`) to
generous-but-finite ceilings, so a corrupted header is rejected during
parsing before the KDF ever runs.
