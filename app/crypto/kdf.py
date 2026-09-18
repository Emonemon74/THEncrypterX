"""Password-based key derivation using Argon2id.

The password is *never* used directly as an encryption key. It is low-entropy
and guessable. Argon2id stretches ``password + random salt`` through a
deliberately expensive, memory-hard computation to produce a 32-byte master
key. "Memory-hard" means an attacker cannot cheaply parallelise guessing on
GPUs/ASICs, because each guess needs a large block of RAM.

All parameters are explicit and are written into the ``.thex`` header, so
decryption reproduces the exact same computation regardless of what the
current defaults happen to be.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw

# Argon2 "type" byte as stored in the .thex header (see docs/file-format.md).
ARGON2_TYPE_ID = 2

SALT_LEN = 16
KEY_LEN = 32

# Environment override for the memory cost, used only to keep CI / tests fast.
# The value actually used is always recorded in the header, so a file encrypted
# with a low memory cost still decrypts correctly anywhere.
_ENV_MEMORY_KIB = "THEX_ARGON2_MEMORY_KIB"

# Upper bounds on Argon2 params read back out of a .thex header - untrusted
# input, since the header isn't authenticated until *after* the KDF has
# already run (the KDF derives the key needed to check the metadata MAC).
# Without a ceiling, a single flipped bit in memory_cost_kib or time_cost
# turns "decrypt/verify a corrupted file" into an effectively unbounded
# Argon2id computation - the C call won't return control to Python (so it
# can't even be interrupted) until it finishes trying to allocate/hash that
# much "memory cost". These are generous relative to any real interactive
# use (RFC 9106 tops out its recommendations in the low GiB / low tens of
# iterations), not a recommendation for what to actually configure.
MAX_MEMORY_COST_KIB = 4 * 1024 * 1024  # 4 GiB
MAX_TIME_COST = 64
MAX_PARALLELISM = 64


@dataclass(frozen=True, slots=True)
class Argon2Params:
    """Concrete Argon2id parameters. Immutable so they cannot drift mid-run."""

    memory_cost_kib: int = 262_144  # 256 MiB
    time_cost: int = 3  # iterations
    parallelism: int = 4  # lanes
    argon2_version: int = ARGON2_VERSION  # 0x13 (19)
    argon2_type: int = ARGON2_TYPE_ID  # 2 == Argon2id

    def __post_init__(self) -> None:
        if self.memory_cost_kib < 8 * self.parallelism:
            raise ValueError("memory_cost_kib too small for the given parallelism")
        if self.memory_cost_kib > MAX_MEMORY_COST_KIB:
            raise ValueError(f"memory_cost_kib exceeds the maximum ({MAX_MEMORY_COST_KIB})")
        if self.time_cost < 1:
            raise ValueError("time_cost must be >= 1")
        if self.time_cost > MAX_TIME_COST:
            raise ValueError(f"time_cost exceeds the maximum ({MAX_TIME_COST})")
        if self.parallelism < 1:
            raise ValueError("parallelism must be >= 1")
        if self.parallelism > MAX_PARALLELISM:
            raise ValueError(f"parallelism exceeds the maximum ({MAX_PARALLELISM})")
        if self.argon2_type != ARGON2_TYPE_ID:
            raise ValueError("only Argon2id (type=2) is supported")


def default_params() -> Argon2Params:
    """Return the default parameters, honouring the CI/test memory override."""
    override = os.environ.get(_ENV_MEMORY_KIB)
    if override:
        return Argon2Params(memory_cost_kib=int(override))
    return Argon2Params()


def generate_salt() -> bytes:
    """Return a fresh random 16-byte salt. Not secret; stored in the header."""
    return os.urandom(SALT_LEN)


def derive_master_key(password: str, salt: bytes, params: Argon2Params) -> bytes:
    """Derive the 32-byte master key from a password and salt.

    Deterministic: the same (password, salt, params) always yields the same
    key. That is what lets decryption work.
    """
    if not password:
        raise ValueError("password must not be empty")
    if len(salt) != SALT_LEN:
        raise ValueError(f"salt must be exactly {SALT_LEN} bytes, got {len(salt)}")

    secret = password.encode("utf-8")
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
        version=params.argon2_version,
    )
