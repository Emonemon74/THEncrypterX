# THEncrypterX — Secure File Encryption System (Build Guide v2)

## 0. About This Document

This is the working build specification for THEncrypterX. It supersedes the
original slide-deck proposal. Where this guide and the proposal disagree, this
guide wins, and Section 1.2 records exactly what changed and why so the
deviation is defensible during grading or an interview.

Read Section 29 (Philosophy) and Section 28 (First Milestone) before writing any
code. Build in the order given in Section 26.

---

## 1. Project Goal

THEncrypterX is a production-oriented tool for securely encrypting and
decrypting files. It ships as both a command-line tool (primary, testable
backend) and a desktop GUI (secondary, for demonstration).

The tool must provide:

- Confidentiality and integrity of file contents via authenticated encryption
- A password-based key with a slow, salted KDF (Argon2id)
- A versioned, self-describing binary container format (`.thex`)
- Protection of file metadata (original name, extension, size, timestamps)
- Streaming/chunked processing so memory stays flat regardless of file size
- Detection of tampering, truncation, chunk reordering, and chunk removal
- Measured performance numbers (not adjectives)
- An honest, documented threat model

> **Hard rule:** Do not implement cryptographic primitives from scratch. Use
> vetted libraries. Every security-relevant decision is documented in
> `docs/threat-model.md` with a matching test.

### 1.1 Non-Goals (explicitly out of scope)

- Inventing or combining ciphers ("cascade" encryption). One modern AEAD only.
- Hidden volumes / true plausible deniability. Not attempted.
- Guaranteed unrecoverable deletion. See Section 14 — we document what we can
  and cannot promise instead of claiming magic.
- Network features, key servers, multi-user key sharing, cloud sync.
- Post-quantum cryptography. Noted as future work only.

### 1.2 Deviations From the Original Proposal (record these for grading)

| Proposal said | This build does | Why |
|---|---|---|
| Multi-layer AES-256 + XChaCha20 + Serpent cascade | Single AEAD: XChaCha20-Poly1305 (AES-256-GCM as an alternate profile) | Cascading adds complexity and near-zero security benefit over one correctly-used AEAD; Serpent has poor maintained library support. Layering is where student crypto projects introduce bugs. |
| Backend in Go, GUI in Dear ImGui | Python 3.12+, GUI in PySide6 | `cryptography` and `argon2-cffi` are audited, batteries-included, and remove the need to touch primitives. cgo + Dear ImGui cross-compilation is a time sink with no learning payoff for this project. The GIL is not a bottleneck here (Section 3.1). |
| HKDF-SHA3 for key management | HKDF-SHA-256 used **only** to split the Argon2id output into named subkeys | "HKDF-SHA3" is not a standard construction. HKDF is defined over HMAC. We use it for domain separation (one subkey for metadata, one for chunk data), not as the main KDF. If a single key is enough (v1), HKDF can be skipped — decide in Phase 1 and document it. |
| Reed-Solomon error correction | Not in v1. Optional add-on in Appendix B. | It protects against random bit-rot, not attackers, and interacts awkwardly with authentication. Ship the secure core first; add it only if there is time and a clear story. |
| "Secure deletion makes data unrecoverable" | "Best-effort overwrite; guarantees documented per-filesystem" | Overwrite-in-place is not honored by SSDs, CoW/journaling filesystems, or snapshots. Claiming otherwise is wrong. |

---

## 2. Learning Objectives

By completing this project you should be able to demonstrate and explain:

- Python application architecture and packaging
- Cryptography fundamentals: encryption vs hashing, keys vs passwords
- AEAD (authenticated encryption with associated data)
- Password-based key derivation, salts, nonces, and why nonce reuse is fatal
- Domain separation / subkey derivation with HKDF
- Designing an unambiguous, versioned binary file format
- Streaming and chunking large files with bounded memory
- Metadata protection and information-leak analysis
- Integrity and tamper detection (per-chunk and whole-file)
- Desktop GUI development with a responsive UI over background workers
- Unit, integration, negative, and property/fuzz testing
- Benchmark methodology and honest reporting
- Secure handling of temporary files and secrets in memory
- Git/GitHub workflow and CI/CD

---

## 3. Technology Stack

### Core (required, pin these)

| Package | Version (floor) | Purpose |
|---|---|---|
| Python | 3.12+ | language |
| `cryptography` | 43.0+ | AEAD (XChaCha20-Poly1305, AES-GCM), HKDF, constant-time compare |
| `argon2-cffi` | 23.1+ | Argon2id password hashing / key derivation |
| `pytest` | 8.0+ | test runner |
| `hypothesis` | 6.100+ | property / fuzz-style testing |

### GUI (required for full Definition of Done)

| Package | Version (floor) | Purpose |
|---|---|---|
| `PySide6` | 6.7+ | desktop GUI + QThread workers |

### CLI + quality (recommended)

| Package | Purpose |
|---|---|
| `typer` | CLI framework |
| `rich` | CLI output / progress |
| `ruff` | lint + format |
| `mypy` | static type checking |
| `psutil` | peak-memory measurement in benchmarks |
| GitHub Actions | CI |

Everything is pure-Python or has prebuilt wheels for Linux/macOS/Windows. No
compiler required.

### 3.1 Is Python fast enough? (know this answer cold)

Yes, for this workload. The `cryptography` library performs AEAD in a native
OpenSSL backend and **releases the GIL** during encryption/decryption of each
chunk. Throughput is bound by OpenSSL's AES-NI / SIMD ChaCha implementation, not
by the interpreter. Expect **hundreds of MB/s to low GB/s** single-threaded on a
modern laptop.

Python overhead per chunk is ~microseconds (a function call, a `memoryview`,
a `file.write`). With a 1–4 MiB chunk size that overhead is well under 1% of
wall time. This is why chunk size matters (Section 11.3) and why we benchmark it.

If a reviewer pushes: the honest ceiling is that multi-threaded scaling across
cores needs multiple worker threads doing AEAD in parallel, which the GIL
release makes possible but v1 does not implement (single worker thread). That is
a legitimate roadmap item, not a flaw.

---

## 4. High-Level Architecture

```text
                       ┌──────────────────────┐
                       │      PySide6 GUI      │
                       │  file picker / DnD    │
                       │  password input       │
                       │  progress / errors    │
                       └──────────┬───────────┘
                                  │ (calls, never blocks UI thread)
                                  ▼
                       ┌──────────────────────┐
                       │   core/service.py    │
                       │  EncryptJob /        │
                       │  DecryptJob /        │
                       │  InspectJob          │
                       │  progress callbacks  │
                       │  cancellation token  │
                       └──────────┬───────────┘
             ┌────────────────────┼────────────────────┐
             ▼                    ▼                    ▼
      ┌─────────────┐      ┌──────────────┐     ┌──────────────┐
      │ crypto/     │      │ format/      │     │ files/       │
      │  kdf.py     │      │  header.py   │     │  stream.py   │
      │  keys.py    │      │  container.py│     │  encrypt.py  │
      │  cipher.py  │      │              │     │  decrypt.py  │
      │             │      │              │     │              │
      │ Argon2id    │      │ THX1 header  │     │ chunk loop   │
      │ HKDF subkeys│      │ parse/emit   │     │ bounded RAM  │
      │ AEAD wrap   │      │ strict       │     │ atomic write │
      └─────────────┘      └──────────────┘     └──────┬───────┘
                                  │                    │
             ┌────────────────────┘                    │
             ▼                                         ▼
      ┌──────────────┐                          ┌──────────────┐
      │ metadata/    │                          │  .thex file  │
      │ metadata.py  │  serialize + encrypt     │  container   │
      └──────────────┘                          └──────────────┘

CLI (cli.py) calls core/service.py directly — no GUI dependency.
```

**Dependency rule:** `crypto`, `format`, `files`, `metadata` never import
`gui`. `core/service.py` is the only orchestration layer. `cli.py` and `gui/`
both sit on top of `core`.

---

## 5. Design Principles

1. **One AEAD, used correctly, beats many ciphers used nervously.**
2. **The password is never a key.** Argon2id stands between them, always.
3. **Never reuse a nonce under the same key.** Enforced structurally
   (Section 11.2), not by hoping.
4. **Every byte written to `.thex` is either authenticated or is input to a KDF.**
   No unauthenticated plaintext-influenced bytes.
5. **Fail closed.** Any authentication failure, parse error, or truncation
   aborts and removes partial output. Never produce a half-decrypted file.
6. **Version everything.** Header has a format version and algorithm IDs so v2
   can change primitives without guessing.
7. **Claims require evidence.** Every line in the README security section maps
   to a test in `tests/test_security.py`.

Baseline data flow:

```text
password ──► Argon2id(salt, params) ──► master_key (32 bytes)
                                             │
                        HKDF-SHA256(master_key, info=...)
                                             │
                     ┌───────────────────────┼───────────────────────┐
                     ▼                       ▼                       ▼
              meta_key (32B)          data_key (32B)         (reserved for v2)
                     │                       │
        AEAD(meta_key, nonce_m, meta)   per-chunk AEAD(data_key, nonce_i, chunk_i)
```

---

## 6. Repository Layout

```text
THEncrypterX/
├── app/
│   ├── __init__.py
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── kdf.py           # Argon2id: generate_salt, derive_master_key
│   │   ├── keys.py          # HKDF subkey derivation, key zeroization helpers
│   │   └── cipher.py        # AEAD wrapper: seal / open, algorithm registry
│   ├── format/
│   │   ├── __init__.py
│   │   ├── constants.py     # magic, versions, algorithm IDs, field sizes
│   │   ├── header.py        # Header dataclass, pack() / parse()
│   │   └── container.py     # writer/reader that ties header+meta+chunks
│   ├── files/
│   │   ├── __init__.py
│   │   ├── stream.py        # chunk iterator, atomic temp-file writer
│   │   ├── encrypt.py       # file -> .thex
│   │   └── decrypt.py       # .thex -> file
│   ├── metadata/
│   │   ├── __init__.py
│   │   └── metadata.py      # FileMetadata dataclass, serialize/deserialize
│   ├── core/
│   │   ├── __init__.py
│   │   ├── service.py       # EncryptJob / DecryptJob / InspectJob
│   │   ├── progress.py      # Progress + CancellationToken
│   │   └── errors.py        # typed exception hierarchy
│   ├── cli.py               # typer app
│   └── gui/
│       ├── __init__.py
│       ├── main_window.py
│       └── workers.py       # QThread wrappers around core jobs
├── tests/
│   ├── test_kdf.py
│   ├── test_keys.py
│   ├── test_cipher.py
│   ├── test_header.py
│   ├── test_container.py
│   ├── test_metadata.py
│   ├── test_files_roundtrip.py
│   ├── test_security.py       # the tamper/negative matrix
│   ├── test_properties.py     # hypothesis
│   └── vectors/
│       └── kat_v1.json        # known-answer test vector(s)
├── benchmarks/
│   └── benchmark_files.py
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   └── file-format.md         # byte-offset table + test vector (Section 9)
├── main.py                    # launches GUI
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── README.md
├── LICENSE
├── .gitignore
└── .github/workflows/ci.yml
```

---

## 7. Phase 1 — Cryptographic Core

### 7.1 `crypto/kdf.py` — password → master key

```python
def generate_salt() -> bytes: ...            # 16 bytes from os.urandom
def derive_master_key(password: str, salt: bytes, params: Argon2Params) -> bytes:
    ...                                       # returns 32 bytes
```

**Argon2id parameters (v1 defaults, stored in the header):**

| Parameter | v1 value | Notes |
|---|---|---|
| type | Argon2id | not `i`, not `d` |
| version | 0x13 (19) | |
| memory_cost | 262144 KiB (256 MiB) | tune down for CI to 64 MiB via env |
| time_cost | 3 | iterations |
| parallelism | 4 | lanes |
| salt length | 16 bytes | random per file |
| output length | 32 bytes | master key |

Requirements:

- New random salt for **every** encryption operation.
- Salt is stored in the header; it is not secret.
- Password is never written to disk, never logged, never put in an exception
  message. Accept it as `str`, encode UTF-8, and drop the reference after use.
- KDF parameters are explicit fields in the header and are versioned. Decryption
  reads them from the file, never assumes defaults.
- Provide a way to override `memory_cost` for tests/CI (env var
  `THEX_ARGON2_MEMORY_KIB`) — but the *written* file always records the value
  actually used.

### 7.2 `crypto/keys.py` — subkey derivation

```python
def derive_subkeys(master_key: bytes) -> Subkeys:
    # HKDF-SHA256, no salt (master_key is already high-entropy),
    # expand with distinct info labels:
    #   b"THEncrypterX v1 metadata key"
    #   b"THEncrypterX v1 data key"
    ...

def zeroize(buf: bytearray) -> None:
    # best-effort overwrite of key material; document that CPython
    # may have kept copies (immutable bytes) — prefer bytearray for keys.
```

Decision to record in `docs/threat-model.md`: we use HKDF for **domain
separation** so that a bug in metadata handling cannot affect chunk decryption
and vice versa. If you choose to skip HKDF in v1, use `master_key` directly for
both and say so — but subkeys are cheap and cleaner.

### 7.3 `crypto/cipher.py` — AEAD wrapper

```python
ALGO_XCHACHA20_POLY1305 = 1
ALGO_AES_256_GCM        = 2

def seal(algo: int, key: bytes, nonce: bytes, plaintext: bytes,
         associated_data: bytes) -> bytes:
    # returns ciphertext || tag  (tag appended by the primitive)

def open_(algo: int, key: bytes, nonce: bytes, ciphertext: bytes,
          associated_data: bytes) -> bytes:
    # raises AuthenticationError on any failure; never returns partial data
```

Nonce sizes: XChaCha20-Poly1305 = 24 bytes, AES-256-GCM = 12 bytes. The wrapper
knows the size per algorithm; callers ask for `cipher.nonce_size(algo)`.

**v1 default algorithm: `ALGO_XCHACHA20_POLY1305`** (24-byte nonce makes random
nonces safe; see Section 11.2).

### 7.4 Tests for Phase 1 (`test_kdf.py`, `test_keys.py`, `test_cipher.py`)

The crypto layer must prove:

- Same password + same salt + same params → same master key (determinism).
- Different salt → different master key.
- `derive_subkeys` returns two **distinct** 32-byte keys, stable across calls.
- Correct key + nonce + AD → `open_(seal(x)) == x`.
- Wrong key → `AuthenticationError`.
- Flip any single bit of ciphertext → `AuthenticationError`.
- Flip any single bit of the nonce → `AuthenticationError`.
- Change one byte of associated data → `AuthenticationError`.
- Two `seal` calls with fresh nonces on the same plaintext → different outputs.
- `open_` never returns bytes when it raises (no partial plaintext leak).

---

## 8. Phase 2 — The `.thex` Container Format

See Section 9 for the exact byte layout. Design rules:

- Fixed 4-byte magic `THX1` (0x54 0x48 0x58 0x31).
- Explicit little-endian for all integers. State it once, apply everywhere.
- Every variable-length field is length-prefixed (`uint32` unless noted).
- The header up to and including the salt is **associated data** for the
  metadata AEAD and for every chunk AEAD. Tampering with algorithm IDs, KDF
  params, or the salt therefore breaks authentication.
- Parser is strict: unknown magic, unknown version, impossible lengths,
  trailing garbage, or a truncated field → `FormatError`, no exceptions
  swallowed.
- `inspect` can print everything in the header **without** the password (it is
  all plaintext); it must **not** be able to print metadata (that needs the key).

---

## 9. `docs/file-format.md` — Canonical Byte Layout (v1)

> This section is the spec. Copy it verbatim into `docs/file-format.md` and keep
> it in sync. A reviewer who reads only this file should be able to write a
> decoder.

### 9.1 Overall structure

```text
[ Fixed Header ]
[ KDF params block ]
[ Salt ]
[ Metadata nonce ][ Metadata length (u32) ][ Encrypted metadata + tag ]
[ Chunk 0 ]
[ Chunk 1 ]
...
[ Chunk N-1 ]
[ Footer ]
```

### 9.2 Fixed Header

| Offset | Size | Field | Value / notes |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `THX1` |
| 4 | 2 | format_version | u16 LE, = `1` |
| 6 | 1 | kdf_id | `1` = Argon2id |
| 7 | 1 | aead_id | `1` = XChaCha20-Poly1305, `2` = AES-256-GCM |
| 8 | 1 | kdf_params_len | u8, length of the KDF params block that follows |
| 9 | 1 | salt_len | u8, = `16` |
| 10 | 4 | chunk_size | u32 LE, plaintext bytes per chunk (e.g. 1048576) |
| 14 | 2 | reserved | u16, must be `0` |

Header fixed part = 16 bytes.

### 9.3 KDF params block (Argon2id, kdf_id = 1)

Immediately follows the fixed header. Length = `kdf_params_len` (= 13 for v1).

| Offset (rel) | Size | Field |
|---:|---:|---|
| 0 | 4 | memory_cost_kib (u32 LE) |
| 4 | 4 | time_cost (u32 LE) |
| 8 | 1 | parallelism (u8) |
| 9 | 1 | argon2_version (u8, = 0x13) |
| 10 | 1 | argon2_type (u8, = 2 for id) |
| 11 | 2 | reserved (u16, = 0) |

### 9.4 Salt

`salt_len` (16) bytes, raw, from `os.urandom(16)`.

### 9.5 Associated data definition

```text
AD_HEADER = bytes from offset 0 through the end of the salt (inclusive)
```

`AD_HEADER` is passed as `associated_data` to:
- the metadata AEAD, and
- every chunk AEAD (concatenated with the per-chunk AD, Section 9.7).

### 9.6 Metadata section

| Size | Field |
|---:|---|
| `nonce_size(aead_id)` | metadata_nonce (random) |
| 4 | metadata_ct_len (u32 LE) — length of ciphertext+tag |
| metadata_ct_len | metadata_ciphertext_and_tag |

Plaintext of the metadata section = the serialized `FileMetadata` (Section 12).
`associated_data = AD_HEADER`.

### 9.7 Chunk `i` (0-indexed)

| Size | Field |
|---:|---|
| `nonce_size(aead_id)` | chunk_nonce (see Section 11.2) |
| 4 | chunk_ct_len (u32 LE) — ciphertext+tag length |
| chunk_ct_len | chunk_ciphertext_and_tag |

Per-chunk associated data:

```text
AD_CHUNK_i = AD_HEADER
           || b"CHUNK"
           || uint64_LE(i)                 # chunk index — detects reordering
           || uint8(is_final)              # 1 for the last chunk, else 0
```

`is_final` in the AD lets the decryptor detect truncation: if it reaches a
chunk marked final it must then see the footer; if it hits EOF without a
final-marked chunk, the file was truncated → `FormatError`.

Last chunk may have a plaintext length in `[0, chunk_size]`. Empty input file =
exactly one chunk with 0 plaintext bytes and `is_final = 1`.

### 9.8 Footer

| Size | Field |
|---:|---|
| 4 | magic_end — ASCII `THXE` |
| 8 | total_chunks (u64 LE) |

The footer is **not** encrypted but `total_chunks` is cross-checked against the
number of chunks actually authenticated. Mismatch → `FormatError`. (The footer
is a convenience/sanity check; security against chunk removal comes from the
`is_final` flag in chunk AD, not from the footer.)

### 9.9 Known-Answer Test Vector (store in `tests/vectors/kat_v1.json`)

Generate this once from the finished implementation and freeze it. Any future
change that breaks it is a format-compatibility break and must bump
`format_version`.

```json
{
  "description": "THEncrypterX v1 KAT",
  "password": "correct horse battery staple",
  "argon2": { "memory_cost_kib": 65536, "time_cost": 2, "parallelism": 1 },
  "salt_hex": "000102030405060708090a0b0c0d0e0f",
  "aead_id": 1,
  "chunk_size": 16,
  "metadata_nonce_hex": "<24 bytes hex>",
  "chunk_nonces_hex": ["<24 bytes hex>", "..."],
  "plaintext_hex": "68656c6c6f2c20776f726c6421",
  "expected_thex_hex": "<full container hex>"
}
```

For the KAT, nonces are supplied (not random) so the output is reproducible.
Production code always uses random nonces; only the test-vector generator accepts
injected nonces.

---

## 10. Phase 3 — File Encryption (streaming)

`files/encrypt.py` flow:

```text
open input (rb)
stat input  -> size, mtime  (for metadata)
build header + KDF params + random salt
derive master_key (Argon2id)  -> subkeys (meta_key, data_key)
serialize + encrypt metadata  -> write metadata section
i = 0
loop:
    buf = input.read(chunk_size)
    is_final = (len(buf) < chunk_size) or (next read would be empty)
    nonce = chunk nonce for i
    ct = seal(aead_id, data_key, nonce, buf, AD_CHUNK_i)
    write [nonce][u32 len(ct)][ct]
    i += 1
    if is_final: break
write footer (THXE, total_chunks = i)
fsync, atomic rename temp -> output
zeroize keys
```

**Determining `is_final` without a second read:** read `chunk_size + 1`? No —
simpler: do a read-ahead of one buffer. Keep `pending = input.read(chunk_size)`;
each iteration, read the *next* buffer; `is_final = (next buffer is empty)`;
encrypt `pending`; set `pending = next`. Handles the empty-file case cleanly
(first `pending` is `b""`, next is `b""`, so chunk 0 is final with 0 bytes).

- Never read the whole file into memory.
- Write to `output.thex.tmp`, `fsync`, then atomic `os.replace` to final name.
  On any error, delete the temp file.
- Report progress as `bytes_processed / total_size` through the progress
  callback; check the cancellation token between chunks.

---

## 11. Phase 3.1 — Chunking Details

### 11.1 Chunk framing

Defined in Section 9.7. Index and final-flag are authenticated via AD, not
stored in plaintext beyond what the framing needs.

### 11.2 Nonce strategy (this is the part that must be right)

**v1 (XChaCha20-Poly1305, 24-byte nonce): random nonce per chunk.**
24 bytes = 192 bits. Random nonces have negligible collision probability even
across trillions of chunks, so a fresh `os.urandom(24)` per chunk is safe and
simple. Each chunk stores its own nonce.

**If `aead_id = 2` (AES-256-GCM, 12-byte nonce): counter-based nonce.**
12-byte random nonces are *not* safe past ~2^32 chunks. Instead derive a
per-file random 4-byte prefix (store it once) and set
`nonce_i = prefix (4B) || uint64_LE(i)`. Never store per-chunk nonces in this
mode; recompute from `i`. Document this branch explicitly.

Rule enforced in code: the same `(key, nonce)` pair is never produced twice.
For v1 random-nonce mode, add a debug assertion in tests that all chunk nonces
in a file are unique.

### 11.3 Chunk size

Default 1 MiB (1048576). Benchmarked in Phase 11 across
64 KiB / 256 KiB / 1 MiB / 4 MiB / 16 MiB. Trade-off:

- Smaller chunks → more per-chunk overhead (nonce + tag + Python loop), more
  authentication boundaries, higher relative size overhead.
- Larger chunks → more RAM per worker, coarser progress/cancellation.

Overhead per chunk = `nonce_size + 16 (tag) + 4 (len prefix)`. At 1 MiB chunk
that is ~44 bytes / 1 MiB ≈ 0.004%.

### 11.4 What each defense catches

| Attack | Caught by |
|---|---|
| Modify chunk contents | AEAD tag fails |
| Reorder chunks | chunk index `i` in AD → wrong `i` fails auth |
| Duplicate a chunk | index mismatch on the duplicate |
| Delete a middle chunk | subsequent chunk's `i` won't match position |
| Delete trailing chunk(s) | no chunk with `is_final=1` before EOF |
| Truncate mid-chunk | length prefix overruns EOF → `FormatError` |
| Swap in chunks from another file | different `data_key` (different salt) → auth fails |
| Tamper header/salt/params | `AD_HEADER` change → metadata + all chunks fail |

---

## 12. Phase 4 — Metadata Protection

`metadata/metadata.py`:

```python
@dataclass
class FileMetadata:
    original_name: str        # basename only, never a full path
    original_size: int        # u64
    mtime_ns: int             # u64, original modification time
    created_with: str = "THEncrypterX/1.0"
    # v1 does NOT store full paths, owner, permissions, xattrs.

def serialize(m: FileMetadata) -> bytes:      # deterministic: length-prefixed fields or canonical JSON (UTF-8, sorted keys, no whitespace)
def deserialize(b: bytes) -> FileMetadata:    # strict; reject extra/missing fields
```

- Metadata is encrypted with `meta_key` and `AD_HEADER` (Section 9.6).
- The container does **not** expose the original filename or exact size in
  plaintext. (Approximate size is still observable from the `.thex` file length;
  document this residual leak in the threat model — padding to hide it is a
  roadmap item, not v1.)
- On decryption, metadata is shown/used **only after** its tag verifies.
- Output filename on decrypt: use `original_name` from the authenticated
  metadata; if a file with that name exists, refuse or add a suffix (never
  overwrite silently). Sanitize: strip any directory separators and `..`.

---

## 13. Phase 5 — Decryption

`files/decrypt.py`:

```text
open .thex (rb)
read + validate fixed header (magic, version, ids, lengths)
read KDF params block, salt
compute AD_HEADER
derive master_key from password + salt + params  -> subkeys
read metadata nonce + len + ct; open_ -> FileMetadata   (fail -> WrongPasswordError)
open output.tmp (wb)
i = 0
loop:
    if next 4 bytes are magic_end "THXE": break   (peek)
    read nonce, u32 len, ct
    pt = open_(aead_id, data_key, nonce, ct, AD_CHUNK_i)   # i and is_final from position
    ...but is_final is in the AD, which we must supply -> we try is_final=0 first,
       and for the last chunk we know only after: so instead:
    read footer first? No. Use: try open with is_final=0; if that is the last
    data before THXE, it must have been sealed with is_final=1.
```

**Cleaner decrypt loop (recommended):** the footer's `total_chunks` is
plaintext, so read the footer first is not possible without seeking. Instead:

1. Seek to end, read the 12-byte footer, validate `THXE`, get `total_chunks`.
2. Seek back to first chunk.
3. For `i` in `0 .. total_chunks-1`: `is_final = (i == total_chunks - 1)`;
   read frame; `open_` with `AD_CHUNK_i`. Any failure → abort.
4. After the loop the read cursor must be exactly at the footer offset;
   otherwise `FormatError` (trailing data).

This makes `is_final` unambiguous and still authenticates it (a forged footer
with a smaller `total_chunks` would make the decryptor stop early, but then step
4 fails because there is leftover data before the footer; a larger count runs
past into the footer bytes and fails the length/parse).

### 13.1 Failure handling

Every one of these aborts, deletes `output.tmp`, and raises a typed error:

| Condition | Exception |
|---|---|
| bad magic / trailing garbage / bad lengths | `FormatError` |
| `format_version` unknown | `UnsupportedVersionError` |
| `aead_id` / `kdf_id` unknown | `UnsupportedAlgorithmError` |
| metadata tag fails | `WrongPasswordError` (indistinguishable from real wrong password — intentional) |
| any chunk tag fails | `IntegrityError` |
| EOF before final chunk / footer | `TruncatedFileError` (subtype of `FormatError`) |
| `total_chunks` mismatch | `FormatError` |

Never write a partial plaintext file that a user could mistake for the real
thing.

---

## 14. Phase 6 — Temporary Files & "Secure Deletion"

- Encrypt/decrypt write to a temp file **in the same directory** as the target
  (so `os.replace` is atomic on the same filesystem), named `*.tmp`, mode 0600.
- On success: `fsync` then `os.replace`. On any exception: `os.unlink` the temp.
- Never write plaintext to a system temp dir unless the output itself is there.
- Passwords: never logged, never in exception text, never in `repr`. Scrub the
  `bytearray` after key derivation.
- No plaintext or key material in `--verbose` / debug output.

### Secure deletion — what we actually claim

Provide `thencrypterx shred <file>` that overwrites the file with random bytes,
`fsync`s, and unlinks. Then document, in `docs/threat-model.md` and `--help`:

> Overwriting **does not** reliably destroy data on SSDs (wear leveling),
> copy-on-write or log-structured filesystems (APFS, Btrfs, ZFS), journaling
> filesystems, or where snapshots/backups exist. On a traditional magnetic disk
> with a simple filesystem it is best-effort. For guaranteed erasure use
> full-disk encryption and destroy the key, or physical destruction.

Claiming more than this is the single most common lie in encryption projects.
Do not make it.

---

## 15. Phase 7 — Desktop GUI (PySide6)

```text
┌─────────────────────────────────────────┐
│              THEncrypterX               │
├─────────────────────────────────────────┤
│     ┌───────────────────────────────┐   │
│     │      Drop file here           │   │
│     │      or  [ Select File ]      │   │
│     └───────────────────────────────┘   │
│     Selected: (none)                    │
│                                         │
│     Password  [********************]  👁 │
│     Confirm   [********************]     │  (encrypt mode only)
│                                         │
│     Output    [ ... ]  [ Choose ]       │
│                                         │
│     [ Encrypt ]        [ Decrypt ]      │
│                                         │
│     ██████████████░░░░░░  62%           │
│     Status: Encrypting chunk 118/190…   │
│     [ Cancel ]                          │
└─────────────────────────────────────────┘
```

Requirements: file picker + drag-and-drop, password field with show/hide,
confirm-password on encrypt, output path chooser, Encrypt/Decrypt buttons,
progress bar, status line, inline error box, Cancel button.

Error messages are user-facing and safe: "Wrong password or corrupted file."
never a stack trace, never the path of a temp file.

---

## 16. Phase 7.1 — Background Processing

```text
GUI thread                    Worker (QThread / QRunnable)
   │  start job  ───────────────►  core.EncryptJob.run(progress_cb, cancel_token)
   │                                   │  read / seal / write loop
   │  ◄──── progress signal ───────────┤  emit every N chunks or 100 ms
   │  ◄──── finished / error signal ───┘
   │  update bar / show result
```

- The UI thread never does file IO or crypto.
- Progress via Qt signals (thread-safe). Do not touch widgets from the worker.
- Cancellation: cooperative — worker checks `cancel_token.cancelled` between
  chunks, cleans up temp file, emits `cancelled`.
- Exactly one job at a time in v1; disable buttons while running.

---

## 17. Phase 8 — CLI

Built on `typer`. The CLI is the reference interface and what the tests drive.

```bash
thencrypterx encrypt <infile> [-o out.thex] [--aead xchacha20|aes256gcm] [--chunk-size 1048576]
thencrypterx decrypt <infile.thex> [-o outfile]
thencrypterx inspect <infile.thex>      # prints header/KDF params/chunk count; NO password, NO metadata
thencrypterx shred <file>               # best-effort overwrite + delete (see Section 14)
```

- Password: prompt with no echo (`typer.prompt(hide_input=True)`), or read from
  `THEX_PASSWORD` env / `--password-file` for scripting/tests. Never a
  `--password` flag (shell history leak).
- Exit codes: `0` ok, `2` wrong password, `3` corrupt/format, `4` cancelled,
  `1` unexpected.
- `inspect` output is stable and greppable (used by tests).

---

## 18. Phase 9 — Testing

### Unit (`test_*.py` per module)

KDF determinism, subkey distinctness, AEAD round-trip + failures, header
pack/parse exact bytes, container assembly, metadata serialize round-trip,
chunk iterator edge cases (empty, exactly one chunk, exact multiple of chunk
size, one byte over).

### Integration (`test_files_roundtrip.py`)

```text
for size in [0, 1, 15, 16, 17, 1 MiB - 1, 1 MiB, 1 MiB + 1, 5 MiB]:
    random file -> encrypt -> decrypt -> assert bytes identical
    assert recovered metadata.original_name / size / mtime_ns correct
for aead in [xchacha20, aes256gcm]:
    round-trip a 3 MiB file
```

### Negative / security matrix (`test_security.py`) — see Section 19

### Property / fuzz (`test_properties.py`, hypothesis)

```python
@given(data=st.binary(max_size=200_000), pw=st.text(min_size=1, max_size=64))
def test_roundtrip(data, pw):
    assert decrypt(encrypt(data, pw), pw) == data

@given(data=st.binary(min_size=1, max_size=50_000), pw=st.text(min_size=1))
def test_any_single_byte_flip_is_caught(data, pw):
    blob = bytearray(encrypt(data, pw))
    i = draw_index(len(blob))
    blob[i] ^= 0x01
    with pytest.raises((IntegrityError, FormatError, WrongPasswordError)):
        decrypt(bytes(blob), pw)
```

Also fuzz the header parser directly with random bytes — it must only ever
raise `FormatError`, never crash, hang, or `MemoryError` (guard length fields
against absurd values before allocating).

### KAT (`tests/vectors/kat_v1.json`)

Decrypt the frozen vector and assert exact plaintext; regenerate the container
with injected nonces and assert exact bytes equal `expected_thex_hex`.

### CI (`.github/workflows/ci.yml`)

Matrix: `{ubuntu, macos, windows} × {py3.12, py3.13}`. Steps: install,
`ruff check .`, `ruff format --check .`, `mypy app`, `pytest -q`
(with `THEX_ARGON2_MEMORY_KIB=65536` to keep CI fast). GUI import test only
(don't spin a window in CI).

---

## 19. Phase 10 — Security Test Matrix

| # | Test | Setup | Expected |
|---:|---|---|---|
| 1 | Correct password | valid `.thex` | decrypt succeeds, bytes match |
| 2 | Wrong password | valid `.thex` | `WrongPasswordError`, no output file |
| 3 | Flip 1 byte in a chunk ciphertext | | `IntegrityError` |
| 4 | Flip 1 byte in a chunk nonce | | `IntegrityError` |
| 5 | Flip 1 byte in metadata ciphertext | | `WrongPasswordError` |
| 6 | Flip 1 byte in the salt | | `WrongPasswordError` (key changes) |
| 7 | Flip `aead_id` in header | | `UnsupportedAlgorithmError` or `IntegrityError` |
| 8 | Change `memory_cost` in KDF params | | `WrongPasswordError` |
| 9 | Remove the last chunk | | `TruncatedFileError` |
| 10 | Remove a middle chunk | | `IntegrityError` (index mismatch) |
| 11 | Swap chunk 2 and chunk 5 | | `IntegrityError` |
| 12 | Duplicate chunk 3 | | `IntegrityError` / `FormatError` |
| 13 | Truncate file mid-chunk | | `FormatError` |
| 14 | Append trailing bytes after footer | | `FormatError` |
| 15 | Corrupt footer `total_chunks` | | `FormatError` |
| 16 | Bad magic | | `FormatError` |
| 17 | `format_version = 999` | | `UnsupportedVersionError` |
| 18 | Empty input file | encrypt 0 bytes | round-trips, 1 final chunk |
| 19 | 5 MiB file | | round-trips, peak RSS < ~3× chunk_size + overhead |
| 20 | Chunk from a *different* `.thex` spliced in | | `IntegrityError` |
| 21 | Header length field says 4 GiB | fuzz | `FormatError`, no huge allocation |
| 22 | Password with unicode / emoji / 200 chars | | round-trips |

`docs/threat-model.md` must state, for each: what an attacker can and cannot do,
and what is explicitly *not* protected (file existence, approximate size, timing
of access, the machine being compromised while the password is typed).

---

## 20. Phase 11 — Performance Benchmarking

`benchmarks/benchmark_files.py` — generates random files, runs encrypt/decrypt,
records with `time.perf_counter` and `psutil` peak RSS.

Sizes: 10 MB, 100 MB, 500 MB, 1 GB, (5 GB if disk allows).
Also sweep chunk size {64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB} at 500 MB.
Also compare `xchacha20` vs `aes256gcm` (AES-NI usually wins on x86).

| File size | AEAD | Chunk | Encrypt (s) | Decrypt (s) | Throughput (MB/s) | Peak RSS (MB) |
|---:|---|---:|---:|---:|---:|---:|
| 100 MB | xchacha20 | 1 MiB | measure | measure | measure | measure |
| 1 GB | xchacha20 | 1 MiB | measure | measure | measure | measure |
| 1 GB | aes256gcm | 1 MiB | measure | measure | measure | measure |

Report: median of 3 runs, machine specs (CPU, RAM, disk type, OS, Python
version), and note that Argon2id time (fixed cost, ~0.1–0.5 s) is excluded from
throughput and reported separately.

**Only measured numbers go in the README and resume.** No "blazing fast."

---

## 21. Phase 12 — Code Quality

```bash
ruff check .
ruff format --check .
mypy app          # strict-ish: disallow untyped defs in app/crypto and app/format
pytest -q
```

- Full type hints on `crypto/`, `format/`, `files/`, `core/`.
- No duplicated crypto logic — one `seal`/`open_`, one KDF path.
- No secrets in logs, no hard-coded keys/passwords, no `except: pass`.
- Small functions; the chunk loop is the only place that touches raw offsets.
- `pyproject.toml` drives ruff/mypy/pytest config.

---

## 22. Phase 13 — Git Workflow

Conventional commits, one logical change each:

```text
chore: project skeleton, pyproject, ci
feat(crypto): argon2id key derivation with versioned params
feat(crypto): hkdf subkey derivation
feat(crypto): aead seal/open wrapper (xchacha20-poly1305)
test(crypto): kdf + aead negative tests
feat(format): THX1 header pack/parse
docs: file-format.md byte layout + KAT
feat(format): container reader/writer
feat(files): streaming chunked encryption
feat(files): streaming decryption with fail-closed handling
feat(metadata): encrypted file metadata
test(security): tamper/truncation/reorder matrix
feat(cli): encrypt/decrypt/inspect/shred
feat(gui): pyside6 window
feat(gui): qthread worker + progress + cancel
perf: benchmark harness + results
ci: matrix build, ruff, mypy, pytest
docs: readme, threat-model, architecture
```

`.gitignore`: `.venv/`, `__pycache__/`, `*.pyc`, `*.thex`, `benchmarks/data/`,
`*.tmp`, real files, `.env`.

---

## 23. Phase 14 — README

Sections, in order:

1. **Overview** — one paragraph, honest.
2. **Status** — what works, what doesn't yet.
3. **Features** — only implemented ones.
4. **Security model** — KDF, AEAD, nonce strategy, subkeys, metadata,
   fail-closed behavior; link to `docs/threat-model.md`.
5. **What it does NOT protect** — file size/existence, compromised host,
   keyloggers, deletion guarantees.
6. **Install** — exact commands, venv, `pip install -r requirements.txt`.
7. **Usage** — CLI examples, then GUI.
8. **File format** — link to `docs/file-format.md`.
9. **Testing** — `pytest`, categories, how to run the security matrix.
10. **Benchmarks** — measured table + machine specs.
11. **Architecture** — the diagram, module responsibilities.
12. **Limitations & roadmap** — parallel chunk workers, size-hiding padding,
    Reed-Solomon (Appendix B), keyfiles, post-quantum KEM, Argon2 auto-tuning.
13. **License.**

---

## 24. Resume Version (fill in real numbers only when Section 27 is done)

**THEncrypterX — Secure File Encryption System** · Python, PySide6, cryptography

- Built a file-encryption tool with a versioned binary container format
  (`.thex`): Argon2id password KDF, HKDF subkey separation, and
  XChaCha20-Poly1305 authenticated encryption with per-chunk nonces and
  authenticated chunk indices for tamper, truncation, and reordering detection.
- Implemented streaming/chunked processing that encrypts multi-GB files at
  \<MEASURED\> MB/s with peak memory held under \<MEASURED\> MB regardless of
  file size; benchmarked chunk-size and cipher trade-offs.
- Wrote a 22-case security test matrix and property/fuzz tests (Hypothesis)
  covering wrong-password, bit-flip, splice, and truncation attacks; documented
  a full threat model and byte-level format spec.
- Shipped a PySide6 GUI with drag-and-drop and cancellable background workers,
  a `typer` CLI, and CI across Linux/macOS/Windows (ruff, mypy, pytest).

Do not claim anything not in Section 27's checklist.

---

## 25. Interview Preparation

**Crypto:** encryption vs hashing; why a password isn't a key; Argon2id vs
bcrypt/PBKDF2 and what memory-hardness buys; salt vs nonce; what AEAD
guarantees; why nonce reuse breaks ChaCha20/GCM catastrophically; why 24-byte
(XChaCha) nonces can be random but 12-byte (GCM) shouldn't be; what HKDF is for
(expansion + domain separation, not slowing down); why "roll your own crypto" is
a red flag.

**System design:** why stream instead of read-all; how chunk framing works; how
each tamper class is caught (Section 11.4); why the header is associated data;
what happens on a crash mid-write (atomic temp + replace, no partial output);
how you'd parallelize (multiple workers, GIL released during AEAD); how you'd
hide file size (padding buckets).

**Security:** your threat model; what you do NOT protect; timing/side channels
(you rely on the library's constant-time AEAD and `hmac.compare_digest`);
metadata leakage and residual size leak; why "secure delete" is mostly a myth on
modern storage.

**Performance:** your measured throughput and the machine; why chunk size
matters; Argon2 parameter choice and how you'd auto-tune; memory profile.

---

## 26. Build Order (follow exactly)

```text
 1. Project skeleton, pyproject, .gitignore, CI stub
 2. crypto/kdf.py        + tests   (Argon2id, versioned params)
 3. crypto/keys.py       + tests   (HKDF subkeys, zeroize)
 4. crypto/cipher.py     + tests   (AEAD seal/open, both algos)      ◄── FIRST MILESTONE (Section 28)
 5. format/constants.py, format/header.py + tests (exact bytes)
 6. docs/file-format.md  (write the spec BEFORE the container code)
 7. format/container.py  + tests
 8. metadata/metadata.py + tests
 9. files/stream.py      + tests   (chunk iterator, atomic writer)
10. files/encrypt.py     + integration round-trip test
11. files/decrypt.py     + fail-closed handling
12. tests/test_security.py  (the full matrix)
13. tests/test_properties.py (hypothesis) + tests/vectors/kat_v1.json
14. cli.py               (encrypt/decrypt/inspect/shred)
15. core/service.py, core/progress.py, core/errors.py  (refactor jobs out)
16. gui/main_window.py
17. gui/workers.py       (QThread, progress, cancel)
18. benchmarks/benchmark_files.py + run + record results
19. CI matrix, ruff, mypy green
20. README, threat-model.md, architecture.md
21. GitHub polish (topics, description, screenshots, release tag v1.0)
22. Resume bullets from real numbers
```

Steps 15–17 refactor: it's fine that the CLI (step 14) first calls
`files/encrypt.py` directly; introduce `core/service.py` when the GUI needs the
same jobs with progress + cancellation.

---

## 27. Definition of Done

- [ ] Encrypt → decrypt returns byte-identical output for sizes 0 B … 5 GB
- [ ] Password never written to disk, logs, or exception text
- [ ] Random 16-byte salt per file; Argon2id params versioned in the header
- [ ] HKDF subkeys (meta/data) derived and used distinctly
- [ ] XChaCha20-Poly1305 default; AES-256-GCM alternate profile both round-trip
- [ ] Every chunk authenticated with index + final-flag in associated data
- [ ] Header/salt/params are associated data for metadata and all chunks
- [ ] Nonce strategy correct per algorithm; test asserts no nonce reuse
- [ ] `.thex` format has magic, version, algorithm IDs, explicit endianness
- [ ] `docs/file-format.md` byte table matches the code; KAT vector frozen
- [ ] Strict parser: fuzzed header only ever raises `FormatError`
- [ ] Metadata (name/size/mtime) encrypted; never shown before auth
- [ ] Streaming: peak RSS stays flat as file size grows (benchmarked)
- [ ] Wrong password, bit-flip, splice, reorder, truncation all fail closed
- [ ] No partial/corrupt output file is ever left behind
- [ ] Atomic write (temp + fsync + os.replace)
- [ ] `shred` implemented; deletion limitations documented honestly
- [ ] CLI: encrypt/decrypt/inspect/shred with correct exit codes
- [ ] GUI: responsive, drag-and-drop, progress, working Cancel
- [ ] Unit + integration + 22-case security matrix + hypothesis tests pass
- [ ] Benchmarks measured; table + machine specs in README
- [ ] CI green on Linux/macOS/Windows; ruff + mypy clean
- [ ] README, threat-model.md, architecture.md complete
- [ ] Resume bullets contain only implemented features and measured numbers

---

## 28. First Milestone (do not skip, do not expand)

Build only steps 2–4 of the build order:

```text
password ──Argon2id(random salt)──► master_key (32B)
                 │
          HKDF ──► data_key (32B)
                 │
   XChaCha20-Poly1305 seal/open on an in-memory bytes blob
```

Prove, with tests:

```text
✓ encrypt(x) then decrypt → x
✓ wrong password            → AuthenticationError
✓ flip 1 bit of ciphertext  → AuthenticationError
✓ flip 1 bit of nonce       → AuthenticationError
✓ change associated data    → AuthenticationError
✓ two encryptions of x      → different ciphertext (fresh nonce)
✓ derive_subkeys is deterministic and meta_key != data_key
```

No files, no container, no CLI, no GUI until this is green and committed.

---

## 29. Project Philosophy

The goal is not to make THEncrypterX *sound* secure. The goal is for it to be
**measurably secure, testable, and honestly documented.**

Every security claim follows the chain:

```text
Claim  ─►  Design decision  ─►  Implementation  ─►  Test  ─►  Evidence in docs
```

If a claim has no test, delete the claim. If a feature adds cipher names but no
defensible security property, don't build it. A small tool that does authenticated
encryption correctly, streams large files, detects every tamper case in a written
matrix, and states plainly what it does not protect — that is a strong portfolio
project. A pile of algorithm names is not.

---

## Appendix A — Typed Error Hierarchy (`core/errors.py`)

```text
ThexError (base)
├── FormatError
│   └── TruncatedFileError
├── UnsupportedVersionError
├── UnsupportedAlgorithmError
├── WrongPasswordError        # raised for metadata auth failure (ambiguous on purpose)
├── IntegrityError            # chunk auth failure on an otherwise well-formed file
└── CancelledError
```

CLI maps these to exit codes (Section 17). GUI maps these to one-line safe
messages. Library callers catch the types.

## Appendix B — Optional: Reed-Solomon Resilience (post-v1)

Only after Section 27 is fully checked. Purpose: survive random bit-rot on
long-term storage (not an attacker defense).

- Apply RS **to the ciphertext of each chunk**, after AEAD, so corruption
  within the RS correction budget is repaired before the tag is checked.
- Store parity shards in the chunk frame with their own length prefix; include
  shard layout in the header (new `format_version` = 2).
- Library: `reedsolomon` / `pyfinite` or `klauspost`-style params (e.g. 10 data
  + 3 parity per chunk).
- Test: corrupt up to the budget → still decrypts; corrupt past the budget →
  `IntegrityError` (never silent bad data).
- Document the storage overhead (parity/data ratio) in the README.

If you add this, it becomes a strong extra resume line: *"optional Reed-Solomon
forward error correction applied post-encryption, versioned into the container
format, with tests proving correction up to the parity budget and fail-closed
beyond it."*
