# Cryptography

This page explains *what* each primitive is and why it was chosen, primitive
by primitive. For the attacker model, what each mechanism actually protects
against, and what it explicitly does not, see
[`docs/threat-model.md`](threat-model.md) - that document is the deeper,
test-backed reference; this one is the shorter "what and why" companion to
it. For the exact byte layout, see [`docs/file-format.md`](file-format.md).

## Overview: password to ciphertext

```text
Password
   |
 Argon2id  (+ random 16-byte salt, per file)
   |
Master Key (32 bytes)
   |
  HKDF-SHA256
   |
   +------------------+
   |                  |
Meta Key          Data Key
   |                  |
   v                  v
Metadata AEAD     Chunk AEAD (one seal per chunk)
   |                  |
   v                  v
Encrypted         Encrypted
metadata          chunks
   |                  |
   +--------+---------+
            |
            v
      .thex container
```

## Why passwords never become keys directly

A human password is low-entropy compared to a cryptographic key - it must
go through a key-derivation function (KDF) before it's usable as one.
Directly hashing a password with something fast (SHA-256, MD5) would let an
attacker who steals the container try billions of guesses per second on
commodity hardware.

### Argon2id

THEncrypterX uses Argon2id (`app/crypto/kdf.py`) - the Argon2 variant
recommended by [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) for most
use cases, combining Argon2i's resistance to side-channel attacks with
Argon2d's resistance to GPU/ASIC cracking.

- **Salt**: a fresh random 16 bytes per file (`os.urandom(16)`), so two
  files encrypted with the same password derive completely unrelated master
  keys, and pre-computed rainbow tables are useless.
- **Cost parameters**: memory (256 MiB by default), time (3 iterations),
  parallelism (4 lanes) - all deliberately expensive per guess, and all
  three plus the salt are stored in the header (versioned, see
  `docs/file-format.md` §3) so decryption reproduces the exact computation
  even if the project's own defaults change later.
- **Output**: a 32-byte master key.

Argon2id raises the cost of each password guess from nanoseconds to a
fraction of a second. It does not turn a weak password into a strong one -
see [`docs/threat-model.md`](threat-model.md#password--key-argon2id).

## HKDF: one master key, two independent purposes

The master key from Argon2id is never used to encrypt anything directly.
HKDF-SHA256 (`app/crypto/keys.py`, [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869))
expands it into two subkeys with different "info" labels:

- `meta_key` - encrypts the metadata section (filename, size, mtime)
- `data_key` - encrypts every chunk of file content

This is **domain separation**: the two keys are cryptographically
independent, so a mistake confined to one path (say, a nonce-handling bug
in the metadata code) cannot leak information about, or weaken, the other.

## AEAD: confidentiality and authentication together

An AEAD (Authenticated Encryption with Associated Data) cipher provides
both secrecy and tamper detection in one primitive, and lets you bind
additional data (here: the header, and each chunk's index/final-flag) into
the authentication check without encrypting that data itself. THEncrypterX
supports two:

### XChaCha20-Poly1305 (default, `aead_id=1`)

Implemented via PyNaCl (libsodium), since PyCA's `cryptography` package
does not ship XChaCha20 - only the standard (96-bit-nonce) ChaCha20-
Poly1305. XChaCha20's extended 192-bit nonce is the reason it's the
default: it's large enough that a randomly chosen nonce cannot practically
collide, even across a very large number of chunks, which removes an
entire class of implementation mistakes (a mismanaged counter, a reused
prefix) that a shorter-nonce cipher structurally invites. Every nonce -
metadata's and every chunk's - is simply `os.urandom(24)`.

This nonce-safety property, not performance, is why XChaCha20-Poly1305 is
the default even though it benchmarks roughly 10x slower than AES-256-GCM
on typical hardware - see
[`docs/performance.md`](performance.md) for the numbers and
[`docs/threat-model.md`](threat-model.md#why-xchacha20-poly1305-is-the-default-despite-being-much-slower-here)
for the full reasoning.

### AES-256-GCM (alternate, `aead_id=2`, `--aead aes256gcm`)

Implemented via `cryptography` (OpenSSL), which uses the CPU's dedicated
AES hardware instructions (AES-NI on x86, ARMv8 crypto extensions on Apple
Silicon) - this is where the throughput advantage comes from. Its 96-bit
nonce is *not* safe to choose at random across many messages under one
key, so the two AEAD calls in this format use different strategies:

- **Metadata** (a single message under `meta_key`): a random 96-bit nonce
  is fine here, since it's only ever used once per file.
- **Chunks** (many messages under `data_key`): `nonce_i = per-file random
  4-byte prefix || uint64_LE(chunk index)`, which guarantees uniqueness by
  construction rather than by chance (`app/files/encrypt.py::_data_chunk_nonce`).

Choose it with `--aead aes256gcm` when throughput matters more than
avoiding a counter-based nonce construction - the construction used here is
still safe, just structurally less forgiving of a future implementation
mistake than XChaCha20's random nonces.

## What's authenticated, not just encrypted

Every AEAD call in this format binds in associated data (AD) that isn't
itself encrypted but must match exactly for the tag to verify:

- The metadata AEAD's AD is the full plaintext header - so tampering with
  algorithm ids, KDF parameters, chunk size, or salt is detected even
  though the header itself isn't secret.
- Each chunk's AD includes its own index and an `is_final` flag - so a
  chunk moved, duplicated, or dropped fails to verify even if its
  ciphertext and tag are individually valid and untouched.

See [`docs/file-format.md`](file-format.md#5-associated-data-ad_header) for
the exact byte layout of each AD, and
[`docs/threat-model.md`](threat-model.md#what-is-protected-and-how) for the
full table of what this buys you, with test references.
