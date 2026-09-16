"""Known-answer test (KAT).

tests/vectors/kat_v1.json must always decode to its recorded plaintext, and
rebuilding it from its recorded inputs must reproduce the exact frozen
bytes. Any code change that breaks either of these is a format-compatibility
break and requires a format_version bump - see docs/file-format.md section
10 and scripts/generate_kat.py.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.crypto.kdf import Argon2Params
from app.files.decrypt import decrypt_file
from scripts.generate_kat import build_container

VECTOR_PATH = Path(__file__).parent / "vectors" / "kat_v1.json"


def _load_vector() -> dict:
    return json.loads(VECTOR_PATH.read_text())


def test_vector_file_exists() -> None:
    assert VECTOR_PATH.exists(), "run `python scripts/generate_kat.py` to (re)create it"


def test_reconstruction_matches_frozen_bytes() -> None:
    v = _load_vector()
    container = build_container(
        password=v["password"],
        argon2_params=Argon2Params(**v["argon2"]),
        salt=bytes.fromhex(v["salt_hex"]),
        aead_id=v["aead_id"],
        chunk_size=v["chunk_size"],
        plaintext=bytes.fromhex(v["plaintext_hex"]),
        metadata_name=v["metadata_original_name"],
        metadata_nonce=bytes.fromhex(v["metadata_nonce_hex"]),
        chunk_nonce=bytes.fromhex(v["chunk_nonces_hex"][0]),
    )
    assert container.hex() == v["expected_thex_hex"]


def test_decrypts_to_frozen_plaintext(tmp_path: Path) -> None:
    v = _load_vector()
    thex_path = tmp_path / "kat.thex"
    thex_path.write_bytes(bytes.fromhex(v["expected_thex_hex"]))
    dec_path = tmp_path / "kat_out.bin"

    metadata = decrypt_file(thex_path, dec_path, v["password"])

    assert dec_path.read_bytes() == bytes.fromhex(v["plaintext_hex"])
    assert metadata.original_name == v["metadata_original_name"]
