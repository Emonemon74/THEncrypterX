"""Typed exception hierarchy for THEncrypterX.

Every failure mode has a specific type so that:
  - the CLI can map it to a stable exit code,
  - the GUI can show a safe one-line message,
  - library callers can catch exactly what they mean to handle.

See docs/threat-model.md for how each maps to an attacker capability.
"""

from __future__ import annotations


class ThexError(Exception):
    """Base class for all THEncrypterX errors."""


class FormatError(ThexError):
    """The container is malformed: bad magic, bad lengths, trailing garbage."""


class TruncatedFileError(FormatError):
    """The container ends before a chunk marked final / before the footer."""


class UnsupportedVersionError(ThexError):
    """The container's format_version is newer/unknown to this build."""


class UnsupportedAlgorithmError(ThexError):
    """The container names a KDF or AEAD id this build does not implement."""


class AuthenticationError(ThexError):
    """An AEAD tag failed to verify (low-level crypto layer)."""


class WrongPasswordError(ThexError):
    """Metadata failed to authenticate.

    Raised for a genuinely wrong password *and* for tampering with the salt,
    KDF params, or metadata ciphertext. The two are deliberately
    indistinguishable to an attacker.
    """


class IntegrityError(ThexError):
    """A file chunk failed to authenticate on an otherwise well-formed file."""


class CancelledError(ThexError):
    """The operation was cancelled by the caller before completion."""
