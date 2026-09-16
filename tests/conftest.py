"""Shared pytest configuration.

Force a cheap Argon2 memory cost for the whole test session so key derivation
is fast. Individual tests can still pass explicit Argon2Params.

Force the Qt "offscreen" platform plugin so GUI tests (pytest-qt) run without
a real display - required in CI and convenient locally. Must be set before
any PySide6 import, hence doing it here rather than in a fixture.
"""

from __future__ import annotations

import os

os.environ.setdefault("THEX_ARGON2_MEMORY_KIB", "8192")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
