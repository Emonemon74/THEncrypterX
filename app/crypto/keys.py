"""Subkey derivation and key hygiene.

Argon2id gives us a single 32-byte *master key*. We never encrypt with it
directly. Instead we use HKDF-Expand (RFC 5869) to derive independent subkeys,
one per purpose:

    master_key ──HKDF-Expand(info=b"...metadata key")──► meta_key
              └─HKDF-Expand(info=b"...data key")──────► data_key

This is "domain separation": a mistake in metadata handling (e.g. a nonce
reused there) cannot weaken chunk encryption, because the two operations use
mathematically unrelated keys.

We only need HKDF-*Expand*, not the full extract-then-expand, because the
master key is already uniformly random (Argon2id output). HKDF-Extract exists
to condition non-uniform input; we don't have that problem here.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

SUBKEY_LEN = 32

# Versioned, purpose-specific labels. Changing any of these bytes changes the
# derived key, so they are effectively part of the format version.
_INFO_META = b"THEncrypterX v1 metadata key"
_INFO_DATA = b"THEncrypterX v1 data key"


@dataclass(frozen=True, slots=True)
class Subkeys:
    """The set of purpose-specific keys derived from one master key."""

    meta_key: bytes
    data_key: bytes


def _expand(master_key: bytes, info: bytes) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=SUBKEY_LEN, info=info).derive(master_key)


def derive_subkeys(master_key: bytes) -> Subkeys:
    """Derive the metadata and data subkeys from a 32-byte master key."""
    if len(master_key) != SUBKEY_LEN:
        raise ValueError(f"master_key must be {SUBKEY_LEN} bytes, got {len(master_key)}")
    return Subkeys(
        meta_key=_expand(master_key, _INFO_META),
        data_key=_expand(master_key, _INFO_DATA),
    )


def zeroize(buf: bytearray) -> None:
    """Best-effort wipe of key material held in a mutable buffer.

    Note: this only helps for keys kept in a ``bytearray``. Python ``bytes``
    are immutable and the interpreter may have made copies we cannot reach.
    For real secret hygiene, hold keys in ``bytearray`` and wipe them in a
    ``finally`` block. We document this limitation in docs/threat-model.md
    rather than pretend it is airtight.
    """
    for i in range(len(buf)):
        buf[i] = 0
