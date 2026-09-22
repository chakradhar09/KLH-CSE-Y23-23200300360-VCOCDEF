#!/usr/bin/env python3
"""CLI for the Verifiable Chain-of-Custody tool.

Commands:
    init-keys        Generate an ECDSA keypair for signing custody events.
    add-evidence      Hash a file, register it as evidence, add it as a Merkle leaf.
    check-evidence    Rehash a file and compare it against its recorded evidence hash.
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
from vcoc.merkle import MerkleTree, build_nested_proof, nested_proof_to_dict, proof_to_dict
from vcoc.models import Evidence

DEFAULT_LOG = "custody_log.json"
DEFAULT_EVIDENCE_INDEX = "evidence_index.json"
DEFAULT_FOLDER_INDEX = "folder_index.json"
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


def _load_folder_index(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _save_folder_index(path: str, index: dict) -> None:
    Path(path).write_text(json.dumps(index, indent=2), encoding="utf-8")


def cmd_add_evidence(args: argparse.Namespace) -> None:
    if Path(args.file).is_dir():
        _add_evidence_folder(args)
    else:
        _add_evidence_file(args)


def _add_evidence_file(args: argparse.Namespace, folder_id: str | None = None) -> Evidence:
    digest = hash_file(args.file)
    size_bytes = Path(args.file).stat().st_size
    evidence = Evidence(
        evidence_id=args.evidence_id,
        original_filename=Path(args.file).name,
        sha256=digest,
        size_bytes=size_bytes,
        added_at=utc_now_iso(),
        source_path=str(Path(args.file).resolve()),
        folder_id=folder_id,
    )
    index = _load_evidence_index(args.evidence_index)
    index[evidence.evidence_id] = evidence.__dict__
    _save_evidence_index(args.evidence_index, index)
    print(f"Registered evidence {evidence.evidence_id}: sha256={digest}")
    return evidence


def _add_evidence_folder(args: argparse.Namespace) -> None:
    folder_path = Path(args.file)
    folder_id = args.evidence_id

    all_entries = sorted(
        (p for p in folder_path.rglob("*") if not p.is_dir()),
        key=lambda p: p.relative_to(folder_path).as_posix(),
    )
    files: list[Path] = []
    skipped = 0
    for entry in all_entries:
        if entry.is_symlink() or not entry.is_file():
            skipped += 1
            continue
        files.append(entry)

    if not files:
        print(f"No files found under {folder_path} (skipped {skipped} symlink/special entries).")
        sys.exit(1)

    total_size = sum(f.stat().st_size for f in files)
    print(f"Found {len(files)} file(s) ({total_size} bytes) under {folder_path}")
    if skipped:
        print(f"Skipped {skipped} symlink/special entries.")

    index = _load_evidence_index(args.evidence_index)
    member_ids: list[str] = []
    leaves: list[str] = []
    for i, f in enumerate(files, 1):
        rel = f.relative_to(folder_path).as_posix()
        print(f"[{i}/{len(files)}] hashing {rel}")
        try:
            digest = hash_file(f)
            size_bytes = f.stat().st_size
        except OSError as exc:
            print(f"  skipped ({exc})")
            continue
        evidence_id = f"{folder_id}/{rel}"
        evidence = Evidence(
            evidence_id=evidence_id,
            original_filename=f.name,
            sha256=digest,
            size_bytes=size_bytes,
            added_at=utc_now_iso(),
            source_path=str(f.resolve()),
            folder_id=folder_id,
        )
        index[evidence_id] = evidence.__dict__
        member_ids.append(evidence_id)
        leaves.append(digest)

    _save_evidence_index(args.evidence_index, index)

    if not leaves:
        print("No files were successfully hashed; folder not registered.")
        sys.exit(1)

    subtree = MerkleTree(leaves)
    folder_index = _load_folder_index(args.folder_index)
    folder_index[folder_id] = {"root": subtree.root, "member_ids": member_ids}
    _save_folder_index(args.folder_index, folder_index)
    print(f"Registered folder {folder_id}: {len(member_ids)} file(s), subtree root={subtree.root}")

    if args.private_key:
        signing_key = load_signing_key(args.private_key)
        chain = HashChain.load(args.log) if Path(args.log).exists() else HashChain()
        entry = chain.add_event(
            evidence_id=folder_id,
            actor=getattr(args, "actor", None) or "unknown",
            action="batch-register",
            signing_key=signing_key,
        )
        chain.save(args.log)
        print(f"Logged batch-register event #{entry.index} for {folder_id}")


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


def cmd_check_evidence(args: argparse.Namespace) -> None:
    index = _load_evidence_index(args.evidence_index)
    if args.evidence_id not in index:
        print(f"Unknown evidence id: {args.evidence_id}")
        sys.exit(1)
    rec = index[args.evidence_id]
    file_path = getattr(args, "file", None) or rec.get("source_path")
    if not file_path:
        print(f"MISSING: no source_path recorded for {args.evidence_id} and no --file given.")
        sys.exit(1)
    if not Path(file_path).exists():
        print(f"MISSING: {args.evidence_id}'s recorded path does not exist: {file_path}")
        sys.exit(1)

    recorded = rec["sha256"]
    current = hash_file(file_path)
    if current == recorded:
        print(f"OK: {file_path} matches recorded sha256 for {args.evidence_id}.")
    else:
        print(f"TAMPER DETECTED: {file_path} does NOT match recorded sha256 for {args.evidence_id}.")
        print(f"  recorded: {recorded}")
        print(f"  current:  {current}")
        sys.exit(1)


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


def _build_main_tree(evidence_index: dict, folder_index: dict) -> tuple[MerkleTree, list[str]]:
    """Group evidence_index records by folder_id (or their own id if solo),
    substituting each folder's precomputed subtree root for its leaf.

    Returns (main_tree, ordered_group_ids) where ordered_group_ids[i] is the
    evidence_id or folder_id backing main_tree's leaf at index i.
    """
    grouped_ids = sorted({rec.get("folder_id") or eid for eid, rec in evidence_index.items()})
    leaves = []
    for gid in grouped_ids:
        if gid in folder_index:
            leaves.append(folder_index[gid]["root"])
        else:
            leaves.append(evidence_index[gid]["sha256"])
    return MerkleTree(leaves), grouped_ids


def cmd_merkle_root(args: argparse.Namespace) -> None:
    index = _load_evidence_index(args.evidence_index)
    if not index:
        print("No evidence registered yet.")
        sys.exit(1)
    folder_index = _load_folder_index(args.folder_index)
    tree, grouped_ids = _build_main_tree(index, folder_index)
    print(f"Merkle root over {len(grouped_ids)} evidence file(s)/folder(s): {tree.root}")


def cmd_merkle_proof(args: argparse.Namespace) -> None:
    index = _load_evidence_index(args.evidence_index)
    if args.evidence_id not in index:
        print(f"Unknown evidence id: {args.evidence_id}")
        sys.exit(1)
    folder_index = _load_folder_index(args.folder_index)
    main_tree, grouped_ids = _build_main_tree(index, folder_index)

    rec = index[args.evidence_id]
    folder_id = rec.get("folder_id")
    if folder_id:
        member_ids = folder_index[folder_id]["member_ids"]
        folder_leaves = [index[eid]["sha256"] for eid in member_ids]
        folder_tree = MerkleTree(folder_leaves)
        local_index = member_ids.index(args.evidence_id)
        main_index = grouped_ids.index(folder_id)
        leaf = folder_leaves[local_index]
        proof = build_nested_proof(folder_tree, local_index, main_tree, main_index)
    else:
        main_index = grouped_ids.index(args.evidence_id)
        leaf = rec["sha256"]
        proof = build_nested_proof(main_tree, main_index, None, None)

    output = {
        "evidence_id": args.evidence_id,
        "leaf": leaf,
        "root": main_tree.root,
        "proof": nested_proof_to_dict(proof),
    }
    if args.out:
        Path(args.out).write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"Wrote proof -> {args.out}")
    else:
        print(json.dumps(output, indent=2))


def cmd_shell(args: argparse.Namespace) -> None:
    from vcoc.interactive.app import run_shell

    run_shell()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cli.py", description="Verifiable Chain-of-Custody CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-keys", help="Generate an ECDSA keypair")
    p.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY)
    p.add_argument("--public-key", default=DEFAULT_PUBLIC_KEY)
    p.set_defaults(func=cmd_init_keys)

    p = sub.add_parser("add-evidence", help="Register a file (or folder) as evidence")
    p.add_argument("--file", required=True, help="File path, or a folder to register recursively")
    p.add_argument("--evidence-id", required=True, help="Evidence id, or folder/batch id when --file is a directory")
    p.add_argument("--evidence-index", default=DEFAULT_EVIDENCE_INDEX)
    p.add_argument("--folder-index", default=DEFAULT_FOLDER_INDEX, help="Used only when --file is a directory")
    p.add_argument("--log", default=DEFAULT_LOG, help="Folder mode only: log a batch-register custody event here")
    p.add_argument(
        "--private-key",
        default=None,
        help="Folder mode only: sign a batch-register custody event with this key (omit to skip logging)",
    )
    p.add_argument("--actor", default=None, help="Folder mode only: actor recorded on the batch-register event")
    p.set_defaults(func=cmd_add_evidence)

    p = sub.add_parser("log-event", help="Append a custody event")
    p.add_argument("--evidence-id", required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--action", required=True)
    p.add_argument("--log", default=DEFAULT_LOG)
    p.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY)
    p.set_defaults(func=cmd_log_event)

    p = sub.add_parser("check-evidence", help="Check a file against its recorded evidence hash")
    p.add_argument(
        "--file",
        default=None,
        help="Override path to check; defaults to the evidence's recorded source_path",
    )
    p.add_argument("--evidence-id", required=True)
    p.add_argument("--evidence-index", default=DEFAULT_EVIDENCE_INDEX)
    p.set_defaults(func=cmd_check_evidence)

    p = sub.add_parser("verify-chain", help="Verify the custody hash chain")
    p.add_argument("--log", default=DEFAULT_LOG)
    p.add_argument("--public-key", default=DEFAULT_PUBLIC_KEY)
    p.set_defaults(func=cmd_verify_chain)

    p = sub.add_parser("merkle-root", help="Print the Merkle root over registered evidence")
    p.add_argument("--evidence-index", default=DEFAULT_EVIDENCE_INDEX)
    p.add_argument("--folder-index", default=DEFAULT_FOLDER_INDEX)
    p.set_defaults(func=cmd_merkle_root)

    p = sub.add_parser("merkle-proof", help="Generate a Merkle inclusion proof")
    p.add_argument("--evidence-id", required=True)
    p.add_argument("--evidence-index", default=DEFAULT_EVIDENCE_INDEX)
    p.add_argument("--folder-index", default=DEFAULT_FOLDER_INDEX)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_merkle_proof)

    p = sub.add_parser("shell", help="Launch the interactive shell")
    p.set_defaults(func=cmd_shell)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
