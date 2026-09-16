"""Constants for the .thex container format. Single source of truth.

Changing any of these is a format-breaking change and must come with a
`format_version` bump plus an update to docs/file-format.md.
"""

from __future__ import annotations

MAGIC = b"THX1"
MAGIC_END = b"THXE"

FORMAT_VERSION = 1

KDF_ID_ARGON2ID = 1

# Fixed-header layout: magic(4) + version(u16) + kdf_id(u8) + aead_id(u8)
# + kdf_params_len(u8) + salt_len(u8) + chunk_size(u32) + reserved(u16) = 16
FIXED_HEADER_LEN = 16

# Argon2id params block: memory_cost_kib(u32) + time_cost(u32) + parallelism(u8)
# + argon2_version(u8) + argon2_type(u8) + reserved(u16) = 13
ARGON2ID_PARAMS_LEN = 13

# Sanity caps so a malicious/corrupt header can never trigger a huge
# allocation before we've validated it. Not security boundaries by
# themselves - just guards against resource-exhaustion from a bad file.
MAX_CHUNK_SIZE = 64 * 1024 * 1024  # 64 MiB
MIN_CHUNK_SIZE = 1

# Footer: magic_end(4) + total_chunks(u64) = 12
FOOTER_LEN = 12

# Section length-prefix field width (u32) and a generous cap for the
# metadata section specifically - a filename/size/timestamp fits in a few
# hundred bytes; this just bounds how much a corrupt length field could make
# us try to read/allocate before failing.
SECTION_LEN_FIELD_SIZE = 4
MAX_METADATA_CT_LEN = 64 * 1024  # 64 KiB
