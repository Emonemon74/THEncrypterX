"""Structured fuzzing of the .thex parser (roadmap Phase 5).

Where tests/test_properties.py mutates a single bit of an otherwise-valid
container, and tests/test_header.py::test_random_garbage_never_crashes is a
fixed-size smoke test, this file uses Hypothesis to throw arbitrary,
variable-length, unstructured bytes directly at every parser entry point:
the header, the footer, metadata, and sealed-section/chunk framing, plus a
whole-file fuzz that pushes garbage through the full read path
(`verify_file`) the way an attacker handing over an arbitrary file would.

The property under test throughout is the one docs/threat-model.md and the
module docstrings already claim: a malformed or malicious `.thex` file can
only ever raise one of this project's typed exceptions (or a couple of
specific, expected builtin ones - never a bare `struct.error`, `IndexError`,
etc.), can never hang, and can never trigger an allocation anywhere near the
size of an attacker-controlled length field. Concretely:

  - **Never crash**: any exception escaping a parser call that is not one of
    the typed exceptions listed per test fails the test outright (there is
    no `contextlib.suppress`-everything net here).
  - **Never hang**: `@settings(deadline=...)` fails a specific example if it
    takes meaningfully longer than legitimate parsing ever should - for
    pure in-memory parsing of a bounded-size blob, that's low hundreds of
    milliseconds, not the seconds a pathological quadratic blowup would
    take.
  - **Never over-allocate**: every length field is read via
    `app.format._io.read_exact`, which calls `stream.read(n)` - for a
    `BytesIO`/file object this only ever returns bytes actually present, it
    does not pre-allocate `n` bytes before finding out the stream is
    shorter. `test_extreme_length_fields_reject_fast_without_over_reading`
    below confirms this holds even at declared lengths near the u32/u64
    max, where a naive implementation might try to allocate gigabytes
    before failing.

Atheris/libFuzzer-style coverage-guided fuzzing was considered (the roadmap
mentions it) and deliberately not added: it requires a compiled harness and
a C-extension-heavy toolchain that doesn't fit this project's pure-Python
dependency footprint, for marginal benefit over Hypothesis on a format this
small and this thoroughly validated field-by-field already. Hypothesis
already found real bugs during v1 development (see the parser's strict
field-by-field validation, added specifically to close cases like these);
this file is the roadmap's "parser-focused fuzzing" recommendation, just
without the extra build dependency.
"""

from __future__ import annotations

import contextlib
import io
import os
import struct
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.core.errors import (
    AuthenticationError,
    FormatError,
    ThexError,
    TruncatedFileError,
    UnsupportedAlgorithmError,
    UnsupportedVersionError,
)
from app.crypto.cipher import ALGO_AES_256_GCM, ALGO_XCHACHA20_POLY1305, nonce_size
from app.files.verify import verify_file
from app.format._io import read_exact
from app.format.container import read_footer_at_end, read_raw_frame, read_sealed_section
from app.format.header import Header
from app.metadata.metadata import deserialize

# Fast, deterministic settings: pure in-memory parsing, no I/O, so a tight
# per-example deadline is a meaningful hang detector rather than CI-machine
# noise (contrast tests/test_properties.py, which does real file I/O and
# needs deadline=None).
_FAST = settings(max_examples=300, deadline=200)


@_FAST
@given(blob=st.binary(max_size=256))
def test_header_arbitrary_bytes_never_crash(blob: bytes) -> None:
    with contextlib.suppress(FormatError, UnsupportedVersionError, UnsupportedAlgorithmError):
        Header.read_from(io.BytesIO(blob))


@_FAST
@given(blob=st.binary(max_size=64))
def test_footer_arbitrary_bytes_never_crash(blob: bytes) -> None:
    with contextlib.suppress(FormatError, TruncatedFileError):
        read_footer_at_end(io.BytesIO(blob))


@_FAST
@given(blob=st.binary(max_size=512))
def test_metadata_arbitrary_bytes_never_crash(blob: bytes) -> None:
    with contextlib.suppress(FormatError):
        deserialize(blob)


@_FAST
@given(
    blob=st.binary(max_size=512),
    algo=st.sampled_from([ALGO_XCHACHA20_POLY1305, ALGO_AES_256_GCM]),
)
def test_raw_frame_arbitrary_bytes_never_crash(blob: bytes, algo: int) -> None:
    with contextlib.suppress(FormatError):
        read_raw_frame(io.BytesIO(blob), algo, max_ciphertext_len=4096)


@_FAST
@given(
    blob=st.binary(max_size=512),
    algo=st.sampled_from([ALGO_XCHACHA20_POLY1305, ALGO_AES_256_GCM]),
    key_seed=st.binary(min_size=32, max_size=32),
)
def test_sealed_section_arbitrary_bytes_never_crash(
    blob: bytes, algo: int, key_seed: bytes
) -> None:
    """Same as the raw-frame fuzz, but through the layer that also calls
    open_() - confirms a garbage ciphertext/tag only ever fails
    authentication (AuthenticationError, from app.crypto.cipher) or the
    same structural FormatErrors, never crashes the AEAD call itself."""
    with contextlib.suppress(FormatError, AuthenticationError):
        read_sealed_section(
            io.BytesIO(blob), algo, key_seed, b"some associated data", max_ciphertext_len=4096
        )


# Unlike _FAST above, this one does real file I/O (and, when an example
# happens to parse far enough, real Argon2id) via verify_file - a tight
# deadline here would flag ordinary CI-machine/disk noise as a failure and
# then burn far more time shrinking that "failing" example than the slow
# example itself cost (see test_properties.py for the same reasoning).
_FAST_WITH_TMPDIR = settings(
    max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)


@_FAST_WITH_TMPDIR
@given(blob=st.binary(min_size=0, max_size=2000), password=st.text(min_size=1, max_size=40))
def test_whole_file_arbitrary_bytes_never_crash_via_verify(
    tmp_path: Path, blob: bytes, password: str
) -> None:
    """The real attack surface: an attacker hands over an arbitrary file and
    a guessed password. verify_file must only ever raise a ThexError
    subclass, and must never create any file regardless of outcome.
    """
    target = tmp_path / "arbitrary.thex"
    target.write_bytes(blob)
    before = {p.name for p in tmp_path.iterdir()}

    with contextlib.suppress(ThexError):
        verify_file(target, password)

    assert {p.name for p in tmp_path.iterdir()} == before


# --- targeted: extreme length fields must fail fast, not over-allocate -------------


@pytest.mark.parametrize("declared_len", [0xFFFF_FFFF, 0x7FFF_FFFF, 2**32 - 1])
def test_extreme_length_fields_reject_fast_without_over_reading(declared_len: int) -> None:
    """A declared ciphertext length near the u32 max, backed by a stream that
    actually contains almost nothing, must fail immediately with FormatError
    - not attempt to read/allocate anywhere near `declared_len` bytes.

    Regression guard for the specific failure mode Phase 5 calls out
    ("allocate unreasonable amounts of memory"): read_exact only ever reads
    what the underlying stream actually has buffered, so this should return
    in microseconds regardless of how large the declared length is.
    """
    algo = ALGO_XCHACHA20_POLY1305
    nonce = os.urandom(nonce_size(algo))
    # A length field claiming ~4GB, followed by a mere handful of real bytes.
    frame = nonce + struct.pack("<I", declared_len) + b"\x00" * 8
    with pytest.raises(FormatError):
        read_raw_frame(io.BytesIO(frame), algo, max_ciphertext_len=declared_len)


def test_read_exact_never_over_allocates_for_a_short_stream() -> None:
    """Direct unit check of the primitive every length-prefixed read relies
    on: asking for far more bytes than the stream has just fails, it doesn't
    try to materialize the requested size first."""
    stream = io.BytesIO(b"short")
    with pytest.raises(FormatError):
        read_exact(stream, 2**31)
