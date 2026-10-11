"""Checkpoints: a signed commitment to the custody log at one moment.

A checkpoint is {"body": {...}, "signature": hex}. The body holds the log's size, an RFC 6962 Merkle root over the entries'
entry_hash values, the chain head, and the evidence Merkle root. The custodian signs the canonical JSON of the body with
SHA-256. Anyone holding the public key and the log can check the log against it (verifier.py does, with its own copy of
the rules); witnesses cosign checkpoints that extend the last one they saw, using a consistency proof.
"""

from __future__ import annotations

import hashlib
import json

from ecdsa import SigningKey, VerifyingKey

from .ecdsa_signer import sign_message
from .hash_chain import HashChain, utc_now_iso
from .merkle import MERKLE_FORMAT, MerkleTree

CHECKPOINT_VERSION = 1


def log_id(verifying_key: VerifyingKey) -> str:
    """Names a log by its signing key: SHA-256 of the public key bytes."""
    return hashlib.sha256(verifying_key.to_string()).hexdigest()


def body_bytes(body: dict) -> bytes:
    """The exact bytes that are signed: canonical JSON (sorted keys, no spaces)."""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_checkpoint(
    chain: HashChain, signing_key: SigningKey, evidence_root: str | None = None, timestamp: str | None = None
) -> dict:
    if not chain.entries:
        raise ValueError("there are no custody events to checkpoint")
    hashes = [e.entry_hash for e in chain.entries]
    body = {
        "v": CHECKPOINT_VERSION,
        "log_id": log_id(signing_key.verifying_key),
        "size": len(hashes),
        "root": MerkleTree(hashes).root,
        "head_hash": hashes[-1],
        "evidence_root": evidence_root,
        "merkle_format": MERKLE_FORMAT,
        "timestamp": timestamp or utc_now_iso(),
    }
    return {"body": body, "signature": sign_message(signing_key, body_bytes(body))}


def consistency_proof_since(entry_hashes: list[str], old_size: int) -> dict:
    """The proof that the log's first `old_size` entries are a prefix of its current `len(entry_hashes)` entries."""
    proof = MerkleTree(entry_hashes).consistency_proof(old_size)  # ValueError for a size outside 1..len
    return {"v": CHECKPOINT_VERSION, "from_size": old_size, "to_size": len(entry_hashes), "proof": proof}
