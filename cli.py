#!/usr/bin/env python3
"""CLI for the Verifiable Chain-of-Custody tool.

Commands:
    init-keys        Generate an ECDSA keypair for signing custody events.
    add-evidence      Hash a file, register it as evidence, add it as a Merkle leaf.
    log-event        Append a signed custody event to the hash chain.
    verify-chain      Recompute and verify the entire hash chain + signatures.
    merkle-root       Print the current Merkle root over registered evidence.
    merkle-proof      Generate an inclusion proof for one evidence file.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from vcoc.ecdsa_signer import generate_keypair, load_signing_key, save_keypair
from vcoc.hash_chain import HashChain, utc_now_iso
from vcoc.hashing import hash_file
from vcoc.merkle import MerkleTree, proof_to_dict
from vcoc.models import Evidence

DEFAULT_LOG = "custody_log.json"
DEFAULT_EVIDENCE_INDEX = "evidence_index.json"
DEFAULT_PRIVATE_KEY = "private_key.pem"
DEFAULT_PUBLIC_KEY = "public_key.pem"


def cmd_init_keys(args: argparse.Namespace) -> None:
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, args.private_key, args.public_key)
    print(f"Wrote private key -> {args.private_key}")
    print(f"Wrote public key  -> {args.public_key}")


def _load_evidence_index(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _save_evidence_index(path: str, index: dict) -> None:
    Path(path).write_text(json.dumps(index, indent=2), encoding="utf-8")


def cmd_add_evidence(args: argparse.Namespace) -> None:
    digest = hash_file(args.file)
    size_bytes = Path(args.file).stat().st_size
    evidence = Evidence(
        evidence_id=args.evidence_id,
        original_filename=Path(args.file).name,
        sha256=digest,
        size_bytes=size_bytes,
        added_at=utc_now_iso(),
    )
    index = _load_evidence_index(args.evidence_index)
    index[evidence.evidence_id] = evidence.__dict__
    _save_evidence_index(args.evidence_index, index)
    print(f"Registered evidence {evidence.evidence_id}: sha256={digest}")


def cmd_log_event(args: argparse.Namespace) -> None:
    signing_key = load_signing_key(args.private_key)
    chain = HashChain.load(args.log) if Path(args.log).exists() else HashChain()
    entry = chain.add_event(
        evidence_id=args.evidence_id,
        actor=args.actor,
        action=args.action,
        signing_key=signing_key,
    )
    chain.save(args.log)
    print(f"Logged event #{entry.index}: {entry.action} on {entry.evidence_id} by {entry.actor}")
    print(f"entry_hash={entry.entry_hash}")


def cmd_verify_chain(args: argparse.Namespace) -> None:
    from vcoc.ecdsa_signer import load_verifying_key

    chain = HashChain.load(args.log)
    verifying_key = load_verifying_key(args.public_key)
    ok, break_index, reason = chain.verify(verifying_key)
    if ok:
        print(f"OK: chain of {len(chain.entries)} entries verified ({reason}).")
    else:
        print(f"TAMPER DETECTED at entry #{break_index}: {reason}")
        sys.exit(1)


def cmd_merkle_root(args: argparse.Namespace) -> None:
    index = _load_evidence_index(args.evidence_index)
    if not index:
        print("No evidence registered yet.")
        sys.exit(1)
    leaves = [rec["sha256"] for _, rec in sorted(index.items())]
    tree = MerkleTree(leaves)
    print(f"Merkle root over {len(leaves)} evidence file(s): {tree.root}")


def cmd_merkle_proof(args: argparse.Namespace) -> None:
    index = _load_evidence_index(args.evidence_index)
    if args.evidence_id not in index:
        print(f"Unknown evidence id: {args.evidence_id}")
        sys.exit(1)
    ordered_ids = sorted(index.keys())
    leaves = [index[eid]["sha256"] for eid in ordered_ids]
    tree = MerkleTree(leaves)
    leaf_index = ordered_ids.index(args.evidence_id)
    proof = tree.get_proof(leaf_index)
    output = {
        "evidence_id": args.evidence_id,
        "leaf": leaves[leaf_index],
        "root": tree.root,
        "proof": proof_to_dict(proof),
    }
    if args.out:
        Path(args.out).write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"Wrote proof -> {args.out}")
    else:
        print(json.dumps(output, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cli.py", description="Verifiable Chain-of-Custody CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-keys", help="Generate an ECDSA keypair")
    p.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY)
    p.add_argument("--public-key", default=DEFAULT_PUBLIC_KEY)
    p.set_defaults(func=cmd_init_keys)

    p = sub.add_parser("add-evidence", help="Register a file as evidence")
    p.add_argument("--file", required=True)
    p.add_argument("--evidence-id", required=True)
    p.add_argument("--evidence-index", default=DEFAULT_EVIDENCE_INDEX)
    p.set_defaults(func=cmd_add_evidence)

    p = sub.add_parser("log-event", help="Append a custody event")
    p.add_argument("--evidence-id", required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--action", required=True)
    p.add_argument("--log", default=DEFAULT_LOG)
    p.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY)
    p.set_defaults(func=cmd_log_event)

    p = sub.add_parser("verify-chain", help="Verify the custody hash chain")
    p.add_argument("--log", default=DEFAULT_LOG)
    p.add_argument("--public-key", default=DEFAULT_PUBLIC_KEY)
    p.set_defaults(func=cmd_verify_chain)

    p = sub.add_parser("merkle-root", help="Print the Merkle root over registered evidence")
    p.add_argument("--evidence-index", default=DEFAULT_EVIDENCE_INDEX)
    p.set_defaults(func=cmd_merkle_root)

    p = sub.add_parser("merkle-proof", help="Generate a Merkle inclusion proof")
    p.add_argument("--evidence-id", required=True)
    p.add_argument("--evidence-index", default=DEFAULT_EVIDENCE_INDEX)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_merkle_proof)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
