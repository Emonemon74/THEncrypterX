"""The .thex fixed header: pack to bytes, parse from a stream.

The header (fixed part + KDF params + salt) is never encrypted - a reader
must be able to see the algorithm and KDF parameters before it has a
password. It is, however, the *associated data* for the metadata AEAD and
every chunk AEAD (see docs/file-format.md), so tampering with any header
byte breaks authentication everywhere else in the file.

Parsing is strict: every field is validated *before* it is used to size a
read, so a corrupt or malicious header can only ever raise FormatError -
never a crash, a hang, or a runaway allocation.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO

from app.core.errors import FormatError, UnsupportedAlgorithmError, UnsupportedVersionError
from app.crypto.cipher import is_supported
from app.crypto.kdf import SALT_LEN, Argon2Params
from app.format._io import read_exact as _read_exact
from app.format.constants import (
    ARGON2ID_PARAMS_LEN,
    FIXED_HEADER_LEN,
    FORMAT_VERSION,
    KDF_ID_ARGON2ID,
    MAGIC,
    MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
)

# Little-endian, explicit widths. See constants.py for the byte accounting.
_FIXED_STRUCT = struct.Struct("<4sHBBBBIH")
_ARGON2_PARAMS_STRUCT = struct.Struct("<IIBBBH")

assert _FIXED_STRUCT.size == FIXED_HEADER_LEN
assert _ARGON2_PARAMS_STRUCT.size == ARGON2ID_PARAMS_LEN


@dataclass(frozen=True, slots=True)
class Header:
    """A fully-validated .thex header."""

    aead_id: int
    chunk_size: int
    argon2_params: Argon2Params
    salt: bytes
    format_version: int = FORMAT_VERSION
    kdf_id: int = KDF_ID_ARGON2ID

    def __post_init__(self) -> None:
        if len(self.salt) != SALT_LEN:
            raise ValueError(f"salt must be {SALT_LEN} bytes, got {len(self.salt)}")
        if not is_supported(self.aead_id):
            raise ValueError(f"unsupported aead_id {self.aead_id}")
        if self.kdf_id != KDF_ID_ARGON2ID:
            raise ValueError(f"unsupported kdf_id {self.kdf_id}")
        if not (MIN_CHUNK_SIZE <= self.chunk_size <= MAX_CHUNK_SIZE):
            raise ValueError(f"chunk_size {self.chunk_size} out of range")

    def pack(self) -> bytes:
        """Serialize to the exact on-disk byte layout."""
        fixed = _FIXED_STRUCT.pack(
            MAGIC,
            self.format_version,
            self.kdf_id,
            self.aead_id,
            ARGON2ID_PARAMS_LEN,
            len(self.salt),
            self.chunk_size,
            0,  # reserved
        )
        params = _ARGON2_PARAMS_STRUCT.pack(
            self.argon2_params.memory_cost_kib,
            self.argon2_params.time_cost,
            self.argon2_params.parallelism,
            self.argon2_params.argon2_version,
            self.argon2_params.argon2_type,
            0,  # reserved
        )
        return fixed + params + self.salt

    @property
    def associated_data(self) -> bytes:
        """AD_HEADER: the whole header (through the salt) as defined in the spec."""
        return self.pack()

    @classmethod
    def read_from(cls, stream: BinaryIO) -> Header:
        """Parse a header from a readable binary stream.

        Raises FormatError / UnsupportedVersionError / UnsupportedAlgorithmError.
        Never raises anything else for malformed input.
        """
        fixed = _read_exact(stream, FIXED_HEADER_LEN)
        (
            magic,
            version,
            kdf_id,
            aead_id,
            kdf_params_len,
            salt_len,
            chunk_size,
            reserved,
        ) = _FIXED_STRUCT.unpack(fixed)

        if magic != MAGIC:
            raise FormatError(f"bad magic bytes: {magic!r}")
        if reserved != 0:
            raise FormatError("reserved header field must be zero")
        if version != FORMAT_VERSION:
            raise UnsupportedVersionError(f"unsupported format_version {version}")
        if kdf_id != KDF_ID_ARGON2ID:
            raise UnsupportedAlgorithmError(f"unsupported kdf_id {kdf_id}")
        if not is_supported(aead_id):
            raise UnsupportedAlgorithmError(f"unsupported aead_id {aead_id}")
        if kdf_params_len != ARGON2ID_PARAMS_LEN:
            raise FormatError(f"unexpected kdf_params_len {kdf_params_len}")
        if salt_len != SALT_LEN:
            raise FormatError(f"unexpected salt_len {salt_len}")
        if not (MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE):
            raise FormatError(f"chunk_size {chunk_size} out of range")

        params_bytes = _read_exact(stream, kdf_params_len)
        (
            memory_cost_kib,
            time_cost,
            parallelism,
            argon2_version,
            argon2_type,
            params_reserved,
        ) = _ARGON2_PARAMS_STRUCT.unpack(params_bytes)
        if params_reserved != 0:
            raise FormatError("reserved KDF-params field must be zero")

        try:
            params = Argon2Params(
                memory_cost_kib=memory_cost_kib,
                time_cost=time_cost,
                parallelism=parallelism,
                argon2_version=argon2_version,
                argon2_type=argon2_type,
            )
        except ValueError as exc:
            raise FormatError(f"invalid KDF params: {exc}") from exc

        salt = _read_exact(stream, salt_len)

        try:
            return cls(
                aead_id=aead_id,
                chunk_size=chunk_size,
                argon2_params=params,
                salt=salt,
                format_version=version,
                kdf_id=kdf_id,
            )
        except ValueError as exc:
            raise FormatError(str(exc)) from exc
