"""File and bytes hashing utilities (SHA-256)."""

from __future__ import annotations

import hashlib
from pathlib import Path

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB


def hash_bytes(data: bytes) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def hash_file(path: str | Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Stream ``path`` through SHA-256 and return the hex digest.

    Streams in fixed-size chunks so multi-gigabyte disk images / memory
    dumps can be hashed without loading the whole file into memory.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_hex_pair(left_hex: str, right_hex: str) -> str:
    """Hash two hex-encoded digests together (used by the Merkle tree)."""
    return hash_bytes(bytes.fromhex(left_hex) + bytes.fromhex(right_hex))
