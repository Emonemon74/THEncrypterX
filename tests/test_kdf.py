"""Tests for app.crypto.kdf.

These run with a low Argon2 memory cost (set in conftest.py) so the suite is
fast. We are testing the *wiring*, not Argon2 itself.
"""

from __future__ import annotations

import pytest

from app.crypto.kdf import (
    KEY_LEN,
    MAX_MEMORY_COST_KIB,
    MAX_PARALLELISM,
    MAX_TIME_COST,
    SALT_LEN,
    Argon2Params,
    derive_master_key,
    generate_salt,
)

CHEAP = Argon2Params(memory_cost_kib=8, time_cost=1, parallelism=1)


def test_generate_salt_length_and_randomness() -> None:
    a = generate_salt()
    b = generate_salt()
    assert len(a) == SALT_LEN
    assert a != b  # astronomically unlikely to collide


def test_derive_key_length() -> None:
    key = derive_master_key("password", generate_salt(), CHEAP)
    assert isinstance(key, bytes)
    assert len(key) == KEY_LEN


def test_derive_key_is_deterministic() -> None:
    salt = generate_salt()
    k1 = derive_master_key("correct horse", salt, CHEAP)
    k2 = derive_master_key("correct horse", salt, CHEAP)
    assert k1 == k2


def test_different_salt_changes_key() -> None:
    k1 = derive_master_key("pw", generate_salt(), CHEAP)
    k2 = derive_master_key("pw", generate_salt(), CHEAP)
    assert k1 != k2


def test_different_password_changes_key() -> None:
    salt = generate_salt()
    assert derive_master_key("pw-a", salt, CHEAP) != derive_master_key("pw-b", salt, CHEAP)


def test_different_params_change_key() -> None:
    salt = generate_salt()
    k1 = derive_master_key("pw", salt, Argon2Params(memory_cost_kib=8, time_cost=1, parallelism=1))
    k2 = derive_master_key("pw", salt, Argon2Params(memory_cost_kib=8, time_cost=2, parallelism=1))
    assert k1 != k2


def test_empty_password_rejected() -> None:
    with pytest.raises(ValueError, match="password"):
        derive_master_key("", generate_salt(), CHEAP)


def test_wrong_salt_length_rejected() -> None:
    with pytest.raises(ValueError, match="salt"):
        derive_master_key("pw", b"tooshort", CHEAP)


def test_unicode_password_supported() -> None:
    salt = generate_salt()
    key = derive_master_key("pÀsswörd_🔐_ñ" * 10, salt, CHEAP)
    assert len(key) == KEY_LEN


@pytest.mark.parametrize(
    "kwargs",
    [
        {"time_cost": 0},
        {"parallelism": 0},
        {"memory_cost_kib": 1},
        {"argon2_type": 1},
        {"memory_cost_kib": MAX_MEMORY_COST_KIB + 1},
        {"time_cost": MAX_TIME_COST + 1},
        {"parallelism": MAX_PARALLELISM + 1},
    ],
)
def test_invalid_params_rejected(kwargs: dict[str, int]) -> None:
    base = {"memory_cost_kib": 8, "time_cost": 1, "parallelism": 1}
    base.update(kwargs)
    with pytest.raises(ValueError):
        Argon2Params(**base)


def test_max_params_are_still_constructible() -> None:
    """The ceilings are a safety cap, not accidentally excluding the max
    values themselves."""
    Argon2Params(
        memory_cost_kib=MAX_MEMORY_COST_KIB, time_cost=MAX_TIME_COST, parallelism=MAX_PARALLELISM
    )


def test_oversized_params_from_a_corrupted_header_are_rejected_instantly() -> None:
    """Regression test for a real hang: Header.read_from() parses
    memory_cost_kib/time_cost straight out of an untrusted file, and the
    header isn't authenticated until *after* the KDF runs (the KDF derives
    the key needed to check the metadata MAC). Before MAX_MEMORY_COST_KIB
    existed, a single flipped bit turning memory_cost_kib into a huge value
    made `decrypt`/`verify` on a corrupted file hang for a very long time (a
    real DoS: the C call blocks signal delivery too, so not even a
    watchdog/timeout can interrupt it) instead of failing parsing fast.
    """
    with pytest.raises(ValueError, match="memory_cost_kib exceeds the maximum"):
        Argon2Params(memory_cost_kib=2_000_000_000, time_cost=1, parallelism=1)
