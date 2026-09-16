"""Generate the frozen v1 known-answer test vector (KAT).

Run manually: `python scripts/generate_kat.py`. Only re-run this when the
.thex format deliberately changes in a way expected to change this fixed
input's output - which should come with a format_version bump. If running
this script ever produces bytes that differ from the committed
tests/vectors/kat_v1.json without an intentional format change, that is a
compatibility break to investigate, not to silently regenerate away.

`build_container` is imported directly by tests/test_kat.py so the
"reconstruct it" logic used to verify the vector is the exact same code that
generated it - not a second, possibly-drifting implementation.

All nonces here are fixed, not random, purely so this vector is
byte-for-byte reproducible. Production encryption (app.files.encrypt) always
uses random nonces - see docs/file-format.md.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from app.crypto.cipher import ALGO_XCHACHA20_POLY1305
from app.crypto.kdf import Argon2Params, derive_master_key
from app.crypto.keys import derive_subkeys
from app.format.container import chunk_associated_data, write_footer, write_sealed_section
from app.format.header import Header
from app.metadata.metadata import FileMetadata, serialize

PASSWORD = "correct horse battery staple"
# Deliberately cheap - this vector is about format correctness, not about
# validating production Argon2id cost (that's covered in tests/test_kdf.py).
ARGON2_PARAMS = Argon2Params(memory_cost_kib=8, time_cost=1, parallelism=1)
SALT = bytes(range(16))
AEAD_ID = ALGO_XCHACHA20_POLY1305
CHUNK_SIZE = 16
PLAINTEXT = b"hello, world!"  # 13 bytes: fits in a single final chunk
METADATA_NAME = "kat.txt"
METADATA_NONCE = bytes((0xA0 + i) & 0xFF for i in range(24))
CHUNK0_NONCE = bytes((0xB0 + i) & 0xFF for i in range(24))


def build_container(
    *,
    password: str,
    argon2_params: Argon2Params,
    salt: bytes,
    aead_id: int,
    chunk_size: int,
    plaintext: bytes,
    metadata_name: str,
    metadata_nonce: bytes,
    chunk_nonce: bytes,
) -> bytes:
    """Build a single-chunk .thex container from fully explicit inputs."""
    header = Header(aead_id=aead_id, chunk_size=chunk_size, argon2_params=argon2_params, salt=salt)
    ad_header = header.associated_data

    master_key = derive_master_key(password, salt, argon2_params)
    subkeys = derive_subkeys(master_key)
    metadata = FileMetadata(original_name=metadata_name, original_size=len(plaintext), mtime_ns=0)

    buf = io.BytesIO()
    buf.write(header.pack())
    write_sealed_section(
        buf, aead_id, subkeys.meta_key, metadata_nonce, serialize(metadata), ad_header
    )
    chunk_ad = chunk_associated_data(ad_header, 0, is_final=True)
    write_sealed_section(buf, aead_id, subkeys.data_key, chunk_nonce, plaintext, chunk_ad)
    write_footer(buf, total_chunks=1)
    return buf.getvalue()


def main() -> None:
    container = build_container(
        password=PASSWORD,
        argon2_params=ARGON2_PARAMS,
        salt=SALT,
        aead_id=AEAD_ID,
        chunk_size=CHUNK_SIZE,
        plaintext=PLAINTEXT,
        metadata_name=METADATA_NAME,
        metadata_nonce=METADATA_NONCE,
        chunk_nonce=CHUNK0_NONCE,
    )
    vector = {
        "description": "THEncrypterX v1 known-answer test vector - see docs/file-format.md sec 10",
        "password": PASSWORD,
        "argon2": {
            "memory_cost_kib": ARGON2_PARAMS.memory_cost_kib,
            "time_cost": ARGON2_PARAMS.time_cost,
            "parallelism": ARGON2_PARAMS.parallelism,
        },
        "salt_hex": SALT.hex(),
        "aead_id": AEAD_ID,
        "chunk_size": CHUNK_SIZE,
        "metadata_original_name": METADATA_NAME,
        "metadata_nonce_hex": METADATA_NONCE.hex(),
        "chunk_nonces_hex": [CHUNK0_NONCE.hex()],
        "plaintext_hex": PLAINTEXT.hex(),
        "expected_thex_hex": container.hex(),
    }

    out_path = Path(__file__).resolve().parent.parent / "tests" / "vectors" / "kat_v1.json"
    out_path.write_text(json.dumps(vector, indent=2) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
