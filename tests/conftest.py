"""Shared pytest configuration.

Force a cheap Argon2 memory cost for the whole test session so key derivation
is fast. Individual tests can still pass explicit Argon2Params.
"""

from __future__ import annotations

import os

os.environ.setdefault("THEX_ARGON2_MEMORY_KIB", "8192")
