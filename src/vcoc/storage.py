
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import CustodyEvent, Evidence

NONCE_SIZE = 12
KEY_SIZE = 32


def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)


def save_key(key: bytes, path: str | Path) -> None:
    Path(path).write_bytes(key)


def load_key(path: str | Path) -> bytes:
    key = Path(path).read_bytes()
    if len(key) != KEY_SIZE:
        raise ValueError(f"expected a {KEY_SIZE}-byte AES-256 key, got {len(key)} bytes")
    return key


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt(key: bytes, blob: bytes, associated_data: bytes | None = None) -> bytes:
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    blob BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS custody_events (
    idx INTEGER PRIMARY KEY,
    blob BLOB NOT NULL
);
"""


class EncryptedStore:

    def __init__(self, db_path: str | Path, key: bytes):
        self.db_path = str(db_path)
        self.key = key
        self.conn = sqlite3.connect(self.db_path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "EncryptedStore":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


    def put_evidence(self, evidence: Evidence) -> None:
        aad = evidence.evidence_id.encode("utf-8")
        payload = json.dumps(evidence.__dict__).encode("utf-8")
        blob = encrypt(self.key, payload, aad)
        self.conn.execute(
            "INSERT OR REPLACE INTO evidence (evidence_id, blob) VALUES (?, ?)",
            (evidence.evidence_id, blob),
        )
        self.conn.commit()

    def get_evidence(self, evidence_id: str) -> Evidence:
        row = self.conn.execute(
            "SELECT blob FROM evidence WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"no evidence with id {evidence_id!r}")
        plaintext = decrypt(self.key, row[0], evidence_id.encode("utf-8"))
        return Evidence(**json.loads(plaintext))

    def list_evidence(self) -> list[Evidence]:
        rows = self.conn.execute("SELECT evidence_id, blob FROM evidence ORDER BY evidence_id").fetchall()
        result = []
        for evidence_id, blob in rows:
            plaintext = decrypt(self.key, blob, evidence_id.encode("utf-8"))
            result.append(Evidence(**json.loads(plaintext)))
        return result


    def put_event(self, event: CustodyEvent) -> None:
        aad = str(event.index).encode("utf-8")
        blob = encrypt(self.key, json.dumps(event.to_dict()).encode("utf-8"), aad)
        self.conn.execute(
            "INSERT OR REPLACE INTO custody_events (idx, blob) VALUES (?, ?)",
            (event.index, blob),
        )
        self.conn.commit()

    def list_events(self) -> list[CustodyEvent]:
        rows = self.conn.execute("SELECT idx, blob FROM custody_events ORDER BY idx").fetchall()
        result = []
        for idx, blob in rows:
            plaintext = decrypt(self.key, blob, str(idx).encode("utf-8"))
            result.append(CustodyEvent.from_dict(json.loads(plaintext)))
        return result
