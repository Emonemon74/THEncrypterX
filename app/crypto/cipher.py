"""AEAD wrapper: one small, uniform surface over two vetted primitives.

AEAD = Authenticated Encryption with Associated Data. A single call gives us:
  - confidentiality: the plaintext is hidden,
  - integrity + authenticity: any change to the ciphertext, the nonce, or the
    associated data makes decryption fail instead of returning garbage.

Primitives (never hand-rolled):
  id 1  XChaCha20-Poly1305  (libsodium via PyNaCl) - 24-byte nonce, v1 default.
        The 192-bit nonce is large enough that random per-message nonces have
        negligible collision risk, so callers don't need a stateful counter.
  id 2  AES-256-GCM  (OpenSSL via `cryptography`) - 12-byte nonce. Fast where
        AES-NI is present. 96-bit nonces are NOT safe to pick at random past
        ~2^32 messages, so the file layer uses a counter-based nonce for this
        profile (see docs/file-format.md).

`seal` returns `ciphertext || tag` (tag appended). `open_` takes that same
blob and returns plaintext, or raises AuthenticationError.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_ABYTES,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)
from nacl.exceptions import CryptoError

from app.core.errors import AuthenticationError

ALGO_XCHACHA20_POLY1305 = 1
ALGO_AES_256_GCM = 2

_KEY_LEN = 32
_TAG_LEN = 16

_NONCE_LEN = {
    ALGO_XCHACHA20_POLY1305: crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,  # 24
    ALGO_AES_256_GCM: 12,
}

# Sanity: our assumptions about libsodium's constants must hold.
assert crypto_aead_xchacha20poly1305_ietf_KEYBYTES == _KEY_LEN
assert crypto_aead_xchacha20poly1305_ietf_ABYTES == _TAG_LEN


def is_supported(algo: int) -> bool:
    return algo in _NONCE_LEN


def nonce_size(algo: int) -> int:
    try:
        return _NONCE_LEN[algo]
    except KeyError:
        raise ValueError(f"unknown AEAD id {algo}") from None


def key_size(algo: int) -> int:
    _check(algo)
    return _KEY_LEN


def tag_size(algo: int) -> int:
    _check(algo)
    return _TAG_LEN


def _check(algo: int) -> None:
    if algo not in _NONCE_LEN:
        raise ValueError(f"unknown AEAD id {algo}")


def _validate(algo: int, key: bytes, nonce: bytes) -> None:
    _check(algo)
    if len(key) != _KEY_LEN:
        raise ValueError(f"key must be {_KEY_LEN} bytes, got {len(key)}")
    if len(nonce) != _NONCE_LEN[algo]:
        raise ValueError(
            f"nonce must be {_NONCE_LEN[algo]} bytes for algo {algo}, got {len(nonce)}"
        )


def seal(algo: int, key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """Encrypt and authenticate. Returns ciphertext || 16-byte tag."""
    _validate(algo, key, nonce)
    if algo == ALGO_XCHACHA20_POLY1305:
        return crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, associated_data, nonce, key)
    return AESGCM(key).encrypt(nonce, plaintext, associated_data)


def open_(algo: int, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    """Verify and decrypt. Raises AuthenticationError on any mismatch.

    Never returns partial plaintext: the primitive checks the tag before
    releasing any bytes to us.
    """
    _validate(algo, key, nonce)
    if len(ciphertext) < _TAG_LEN:
        raise AuthenticationError("ciphertext shorter than the authentication tag")
    try:
        if algo == ALGO_XCHACHA20_POLY1305:
            return crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext, associated_data, nonce, key
            )
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except (CryptoError, InvalidTag) as exc:
        raise AuthenticationError("AEAD authentication failed") from exc
