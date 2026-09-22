#!/usr/bin/env python3
"""Standalone chain-of-custody verifier.

Deliberately decoupled from ``cli.py``: it re-implements hash and signature
recomputation from first principles (stdlib ``hashlib`` + ``ecdsa`` only,
no import of ``vcoc.hash_chain`` or ``vcoc.merkle``), so a bug or backdoor in
the logging tool cannot cause this verifier to falsely certify a tampered
log as authentic. It reads only the same public artifacts an outside
auditor would have: the JSON custody log, the public key, and (optionally)
the evidence index and a Merkle proof file. ``evidence_index.json`` is read
directly (not through ``vcoc``) -- it is a plain public data file, the same
kind of artifact ``custody_log.json`` already is, not logging-tool logic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
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


def verify_nested_proof(leaf: str, proof: dict, root: str) -> bool:
    """Recompute both hops of a nested (file -> subtree root -> main root)
    proof, independently of ``vcoc.merkle.verify_nested_proof`` -- this
    module re-implements every check from scratch by design (see module
    docstring), so a bug in the logging tool's proof format can't silently
    propagate into a false "verified" result here.

    ``proof`` is the dict shape ``vcoc.merkle.nested_proof_to_dict`` produces:
    ``{"local_proof": [...], "subtree_root": str, "folder_proof": [...]}``.
    A record not part of a folder batch has an empty ``folder_proof`` and
    ``subtree_root == root`` -- the single-tree case is this format's literal
    degenerate case, not a separate one.
    """
    if not verify_merkle_proof(leaf, proof["local_proof"], proof["subtree_root"]):
        return False
    if not proof["folder_proof"]:
        return proof["subtree_root"] == root
    return verify_merkle_proof(proof["subtree_root"], proof["folder_proof"], root)


def merkle_root(leaves: list[str]) -> str:
    """Recompute a Merkle root from ordered leaf hashes, from scratch."""
    if not leaves:
        raise ValueError("cannot compute a Merkle root over zero leaves")
    level = list(leaves)
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(hash_hex_pair(left, right))
        level = next_level
    return level[0]


@dataclass
class EvidenceCheckResult:
    """Per-evidence-record verification outcome."""

    evidence_id: str
    original_filename: str
    recorded_sha256: str
    source_path: str
    rehash_status: str  # "match" | "MISMATCH" | "not found" | "no source_path recorded"
    logged_status: str  # "logged" | "NOT LOGGED"

    @property
    def ok(self) -> bool:
        return self.rehash_status in ("match", "not found", "no source_path recorded") and self.logged_status == "logged"


def verify_evidence_index(
    index: dict, custody_entries: list[dict], folder_index: dict | None = None
) -> tuple[list[EvidenceCheckResult], str | None]:
    """Independently re-check every evidence record in ``evidence_index.json``.

    For each record: re-hash the file at ``source_path`` if it still exists
    on disk (a missing/moved file is reported, not treated as tamper -- the
    file may simply have been archived elsewhere since collection), and
    confirm at least one custody_log.json entry references the evidence_id.
    Also recomputes the main Merkle root, grouping any folder-batch records
    (``rec["folder_id"]`` set) under their precomputed subtree root from
    ``folder_index`` -- the same grouping ``cli.py``'s ``_build_main_tree``
    performs, recomputed here independently so the two can never silently
    drift apart (folder-batch registration, evidence-index.json schema).

    Returns (per-evidence results, recomputed root or None if index empty).
    """
    folder_index = folder_index or {}
    logged_ids = {entry["evidence_id"] for entry in custody_entries}

    results = []
    for evidence_id, rec in sorted(index.items()):
        source_path = rec.get("source_path", "")
        if not source_path:
            rehash_status = "no source_path recorded"
        elif not Path(source_path).exists():
            rehash_status = "not found"
        else:
            current = sha256_hex(Path(source_path).read_bytes())
            rehash_status = "match" if current == rec["sha256"] else "MISMATCH"

        logged_status = "logged" if evidence_id in logged_ids else "NOT LOGGED"

        results.append(
            EvidenceCheckResult(
                evidence_id=evidence_id,
                original_filename=rec.get("original_filename", ""),
                recorded_sha256=rec["sha256"],
                source_path=source_path,
                rehash_status=rehash_status,
                logged_status=logged_status,
            )
        )

    if not index:
        return results, None
    grouped_ids = sorted({rec.get("folder_id") or eid for eid, rec in index.items()})
    leaves = [
        folder_index[gid]["root"] if gid in folder_index else index[gid]["sha256"]
        for gid in grouped_ids
    ]
    return results, merkle_root(leaves)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="verifier.py", description="Standalone chain-of-custody verifier")
    parser.add_argument("--log", required=True, help="Path to custody_log.json")
    parser.add_argument("--public-key", required=True, help="Path to the signer's PEM public key")
    parser.add_argument("--merkle-proof", default=None, help="Optional Merkle proof JSON to also verify")
    parser.add_argument(
        "--evidence-index",
        default=None,
        help="Optional path to evidence_index.json to independently re-verify every registered evidence file",
    )
    parser.add_argument(
        "--folder-index",
        default=None,
        help="Optional path to folder_index.json, used with --evidence-index to group folder batches",
    )
    args = parser.parse_args(argv)

    entries = json.loads(Path(args.log).read_text(encoding="utf-8"))
    verifying_key = VerifyingKey.from_pem(Path(args.public_key).read_bytes())
    exit_code = 0

    print("== Chain verification ==")
    chain_ok, break_index, reason = verify_chain(entries, verifying_key)
    if chain_ok:
        print(f"OK: chain of {len(entries)} entries verified independently ({reason}).")
    else:
        print(f"TAMPER DETECTED at entry #{break_index}: {reason}")
        exit_code = 1

    if args.merkle_proof:
        print("\n== Merkle inclusion proof ==")
        proof_data = json.loads(Path(args.merkle_proof).read_text(encoding="utf-8"))
        merkle_ok = verify_nested_proof(proof_data["leaf"], proof_data["proof"], proof_data["root"])
        evidence_id = proof_data.get("evidence_id", "<unknown>")
        if merkle_ok:
            print(f"OK: Merkle inclusion proof for {evidence_id} verified against root {proof_data['root']}.")
        else:
            print(f"TAMPER DETECTED: Merkle inclusion proof for {evidence_id} does NOT match the claimed root.")
            exit_code = 1

    if args.evidence_index:
        print("\n== Evidence verification ==")
        index = json.loads(Path(args.evidence_index).read_text(encoding="utf-8"))
        folder_index = (
            json.loads(Path(args.folder_index).read_text(encoding="utf-8"))
            if args.folder_index and Path(args.folder_index).exists()
            else {}
        )
        results, root = verify_evidence_index(index, entries, folder_index=folder_index)
        if not results:
            print("No evidence registered.")
        for r in results:
            print(f"{r.evidence_id}  ({r.original_filename})")
            print(f"  re-hash: {r.rehash_status}")
            print(f"  custody log: {r.logged_status}")
            if not r.ok:
                exit_code = 1
        if root is not None:
            print(f"\nRecomputed Merkle root over {len(results)} evidence file(s): {root}")

    print()
    print("OK: all requested verifications passed." if exit_code == 0 else "TAMPER DETECTED: see above.")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
