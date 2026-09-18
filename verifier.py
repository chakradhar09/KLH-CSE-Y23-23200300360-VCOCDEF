#!/usr/bin/env python3
"""Standalone chain-of-custody verifier.

Deliberately decoupled from ``cli.py``: it re-implements hash and signature
recomputation from first principles (stdlib ``hashlib`` + ``ecdsa`` only,
no import of ``vcoc.hash_chain``), so a bug or backdoor in the logging tool
cannot cause this verifier to falsely certify a tampered log as authentic.
It reads only the same public artifacts an outside auditor would have: the
JSON log file, the public key, and (optionally) an evidence index + Merkle
proof file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from ecdsa import BadSignatureError, VerifyingKey
from ecdsa.util import sigdecode_string

GENESIS_HASH = "0" * 64


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_hex_pair(left_hex: str, right_hex: str) -> str:
    return sha256_hex(bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def canonical_payload(entry: dict) -> str:
    return "|".join(
        [
            str(entry["index"]),
            entry["evidence_id"],
            entry["actor"],
            entry["action"],
            entry["timestamp"],
            entry["prev_hash"],
        ]
    )


def verify_chain(entries: list[dict], verifying_key: VerifyingKey) -> tuple[bool, int | None, str]:
    expected_prev = GENESIS_HASH
    for entry in entries:
        if entry["prev_hash"] != expected_prev:
            return False, entry["index"], "prev_hash does not match preceding entry"

        recomputed_hash = sha256_hex(canonical_payload(entry).encode("utf-8"))
        if recomputed_hash != entry["entry_hash"]:
            return False, entry["index"], "entry_hash does not match recomputed payload hash"

        try:
            ok = verifying_key.verify(
                bytes.fromhex(entry["signature"]),
                entry["entry_hash"].encode("utf-8"),
                sigdecode=sigdecode_string,
            )
        except (BadSignatureError, ValueError):
            ok = False
        if not ok:
            return False, entry["index"], "signature verification failed"

        expected_prev = entry["entry_hash"]

    return True, None, "chain verified"


def verify_merkle_proof(leaf: str, proof: list[dict], root: str) -> bool:
    computed = leaf
    for step in proof:
        if step["is_left"]:
            computed = hash_hex_pair(step["sibling"], computed)
        else:
            computed = hash_hex_pair(computed, step["sibling"])
    return computed == root


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="verifier.py", description="Standalone chain-of-custody verifier")
    parser.add_argument("--log", required=True, help="Path to custody_log.json")
    parser.add_argument("--public-key", required=True, help="Path to the signer's PEM public key")
    parser.add_argument("--merkle-proof", default=None, help="Optional Merkle proof JSON to also verify")
    args = parser.parse_args(argv)

    entries = json.loads(Path(args.log).read_text(encoding="utf-8"))
    verifying_key = VerifyingKey.from_pem(Path(args.public_key).read_bytes())

    ok, break_index, reason = verify_chain(entries, verifying_key)
    if ok:
        print(f"OK: chain of {len(entries)} entries verified independently ({reason}).")
    else:
        print(f"TAMPER DETECTED at entry #{break_index}: {reason}")

    exit_code = 0 if ok else 1

    if args.merkle_proof:
        proof_data = json.loads(Path(args.merkle_proof).read_text(encoding="utf-8"))
        merkle_ok = verify_merkle_proof(proof_data["leaf"], proof_data["proof"], proof_data["root"])
        evidence_id = proof_data.get("evidence_id", "<unknown>")
        if merkle_ok:
            print(f"OK: Merkle inclusion proof for {evidence_id} verified against root {proof_data['root']}.")
        else:
            print(f"TAMPER DETECTED: Merkle inclusion proof for {evidence_id} does NOT match the claimed root.")
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
