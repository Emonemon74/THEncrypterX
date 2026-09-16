# The `.thex` File Format — v1

This is the canonical spec. A reader who implements only what's written here
should produce byte-identical output to `app/format/header.py`. If code and
this document ever disagree, that's a bug — fix the code or fix the doc, but
never let them drift apart silently.

All integers are **little-endian**. All lengths are exact; there is no
padding between fields.

## 1. Overall layout

```text
[ Fixed Header  (16 bytes)              ]
[ Argon2id params block (13 bytes)      ]
[ Salt (16 bytes)                       ]
[ Metadata nonce ][ len (u32) ][ Encrypted metadata + tag ]
[ Chunk 0 ]
[ Chunk 1 ]
...
[ Chunk N-1 ]
[ Footer (12 bytes) ]
```

## 2. Fixed header (16 bytes, offsets 0–15)

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `THX1` (`0x54 0x48 0x58 0x31`) |
| 4 | 2 | `format_version` | u16, currently `1` |
| 6 | 1 | `kdf_id` | u8, `1` = Argon2id (only value defined) |
| 7 | 1 | `aead_id` | u8, `1` = XChaCha20-Poly1305, `2` = AES-256-GCM |
| 8 | 1 | `kdf_params_len` | u8, length of the block in §3. Always `13` for `kdf_id=1` |
| 9 | 1 | `salt_len` | u8, always `16` |
| 10 | 4 | `chunk_size` | u32, plaintext bytes per chunk (e.g. `1048576` for 1 MiB) |
| 14 | 2 | `reserved` | u16, must be `0`; a parser rejects any other value |

Python struct format: `"<4sHBBBBIH"` (16 bytes).

## 3. Argon2id params block (13 bytes, immediately after the fixed header)

| Offset (relative) | Size | Field |
|---:|---:|---|
| 0 | 4 | `memory_cost_kib` (u32) |
| 4 | 4 | `time_cost` (u32) |
| 8 | 1 | `parallelism` (u8) |
| 9 | 1 | `argon2_version` (u8, `0x13` = 19) |
| 10 | 1 | `argon2_type` (u8, `2` = Argon2**id**; `0`/`1` are rejected) |
| 11 | 2 | `reserved` (u16, must be `0`) |

Python struct format: `"<IIBBBH"` (13 bytes).

Only Argon2id parameters travel in the header today. If a second KDF is ever
added, `kdf_id` gets a new value and `kdf_params_len` changes to match — old
readers correctly refuse the file via `UnsupportedAlgorithmError` instead of
misparsing it.

## 4. Salt (16 bytes)

Raw random bytes from `os.urandom(16)`. Not secret.

## 5. Associated data (`AD_HEADER`)

```text
AD_HEADER = bytes[0 .. end of salt]   # fixed header || argon2 params || salt
```

`AD_HEADER` is the `associated_data` argument to the metadata AEAD call and to
**every** chunk's AEAD call. Consequence: flipping a single bit anywhere in
the header — the version, either algorithm id, the chunk size, any KDF
parameter, or the salt — makes every chunk and the metadata fail to
authenticate. There is no way to tamper with the header without the whole
file becoming undecryptable.

`Header.associated_data` in code is simply `Header.pack()` — the header is its
own associated data.

## 6. Metadata section

| Size | Field |
|---:|---|
| `nonce_size(aead_id)` | `metadata_nonce` (random) |
| 4 | `metadata_ct_len` (u32) — length of ciphertext + tag |
| `metadata_ct_len` | `metadata_ciphertext_and_tag` |

- Key: `meta_key` (from `derive_subkeys`).
- Associated data: `AD_HEADER`.
- Plaintext: the serialized `FileMetadata` (original filename, size, mtime —
  see the metadata module once built).
- A failure here raises `WrongPasswordError` (indistinguishable from an
  actually-wrong password, by design).

## 7. Chunk `i` (0-indexed)

| Size | Field |
|---:|---|
| `nonce_size(aead_id)` | `chunk_nonce` |
| 4 | `chunk_ct_len` (u32) |
| `chunk_ct_len` | `chunk_ciphertext_and_tag` |

**Nonce, by algorithm:**
- `aead_id = 1` (XChaCha20-Poly1305, 24-byte nonce): a fresh `os.urandom(24)`
  per chunk, stored inline as shown above. Safe because the nonce space is
  large enough that random collisions are negligible even across an
  enormous number of chunks.
- `aead_id = 2` (AES-256-GCM, 12-byte nonce): **not** safe to pick at random
  past ~2³² messages. Instead, a 4-byte random prefix is generated once per
  file (stored once, in the first chunk's nonce field, or as a dedicated
  field — see the chunking module for the exact placement) and
  `nonce_i = prefix || uint64_LE(i)` is derived, never stored per-chunk.

**Associated data per chunk:**

```text
AD_CHUNK_i = AD_HEADER || b"CHUNK" || uint64_LE(i) || uint8(is_final)
```

`i` is the chunk's position; `is_final` is `1` for the last chunk, else `0`.
Binding the index into the AD is what turns "any AEAD" into "an
order-and-completeness-authenticated stream": swap two chunks, drop one, or
duplicate one, and the index embedded in the AD no longer matches the
chunk's real position, so authentication fails.

An empty input file is exactly one chunk: `i = 0`, `is_final = 1`, zero bytes
of plaintext.

## 8. Footer (12 bytes)

| Size | Field |
|---:|---|
| 4 | `magic_end` — ASCII `THXE` |
| 8 | `total_chunks` (u64) |

Not encrypted. It is a sanity cross-check, not the primary defense against
truncation — that comes from `is_final` in the chunk AD (§7). The decryptor
reads the footer **first** (it knows the file's end from the filesystem), then
authenticates exactly `total_chunks` chunks starting after the salt, and
finally checks that its read cursor lands exactly on the footer offset with no
leftover bytes.

## 9. What each attack breaks

| Attacker action | What catches it |
|---|---|
| Flip a bit in a chunk's ciphertext | that chunk's AEAD tag |
| Flip a bit in a chunk's nonce | that chunk's AEAD tag |
| Flip a bit in the header/salt | `AD_HEADER` changes → metadata **and every chunk** fail |
| Reorder two chunks | the chunk's real position no longer matches `i` in its AD |
| Duplicate a chunk | the duplicate's `i` doesn't match its new position |
| Delete a middle chunk | every following chunk's `i` is now wrong |
| Delete the last chunk(s) | no chunk carries `is_final=1` before EOF/footer |
| Truncate mid-chunk | the length-prefixed read runs past EOF |
| Forge the footer's `total_chunks` | cursor position check fails (leftover or missing bytes) |
| Splice in a chunk from a different `.thex` | different file → different salt → different `data_key` → tag fails |

## 10. Known-answer test vector

A frozen vector lives at `tests/vectors/kat_v1.json`, generated once from this
implementation with fixed (non-random) nonces supplied only for
reproducibility. Any code change that fails to reproduce it is a
format-breaking change and must bump `format_version`.
