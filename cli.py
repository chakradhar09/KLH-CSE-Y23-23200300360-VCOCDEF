#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from vcoc import db
from vcoc.ecdsa_signer import generate_keypair, load_signing_key, save_keypair
from vcoc.hash_chain import HashChain, utc_now_iso
from vcoc import hashing
from vcoc.hashing import hash_file
from vcoc.merkle import MerkleRootBuilder, MerkleTree, NestedProof, merkle_proof_stream, nested_proof_to_dict
from vcoc.models import Evidence
from vcoc.visualize import build_chain_view, format_entry_detail_lines

DEFAULT_DB = "vcoc.db"
DEFAULT_PRIVATE_KEY = "private_key.pem"
DEFAULT_PUBLIC_KEY = "public_key.pem"


def cmd_init_keys(args: argparse.Namespace) -> None:
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, args.private_key, args.public_key)
    print(f"Wrote private key -> {args.private_key}")
    print(f"Wrote public key  -> {args.public_key}")


def _load_evidence_index(db_path: str) -> dict:
    if not Path(db_path).exists():
        return {}
    with contextlib.closing(db.connect(db_path)) as conn:
        return db.load_evidence_index(conn)


def _load_folder_index(db_path: str) -> dict:
    if not Path(db_path).exists():
        return {}
    with contextlib.closing(db.connect(db_path)) as conn:
        return db.load_folder_index(conn)


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
    with contextlib.closing(db.connect(args.db)) as conn:
        db.put_evidence(conn, evidence)
    print(f"Registered evidence {evidence.evidence_id}: sha256={digest}")
    return evidence


def _is_reparse_point(entry: os.DirEntry) -> bool:
    # Windows junctions / mount points are not symlinks but make Path.resolve() leave the tree.
    # ponytail: any reparse point (OneDrive placeholders too) just costs a per-file resolve(), never a wrong path.
    return sys.platform == "win32" and getattr(entry.stat(follow_symlinks=False), "st_reparse_tag", 0) != 0


WALK_BATCH_SIZE = 5000


def _walk_folder(root: Path) -> tuple[sqlite3.Connection, int, int, int, set[str]]:
    """One os.scandir pass: (walk, count, total_size, skipped, unplain).

    `walk` is a private temporary database (on disk, deleted when closed; the caller closes it) holding table
    walk(rel PRIMARY KEY, size): the sort by rel_posix is done by SQLite, so memory does not grow with the file count
    (the sorted Python list cost ~0.4 KB per file: 279 MiB at 416,000 files). Read it back with `_iter_walk`.

    Same selection as the old rglob walk: symlinked directories are neither entered nor counted, other symlinks and
    non-regular files count as skipped, junctions are entered. `unplain` holds the directory prefixes ("a/b/") and
    file paths of everything that is a junction/reparse point: a file under one of them may not resolve to
    root.resolve() + its relative path. Only these small tuples are kept per file (no absolute path, name or flag).
    """
    walk = sqlite3.connect("")  # "" = a private temp database; SQLite spills it to disk, only a small cache stays in RAM
    walk.execute("CREATE TABLE walk(rel TEXT PRIMARY KEY, size INTEGER) WITHOUT ROWID")
    found: list[tuple[str, int | None]] = []
    count = total_size = skipped = 0
    unplain: set[str] = set()
    stack = [(str(root), "")]
    while stack:
        directory, prefix = stack.pop()
        try:
            it = os.scandir(directory)
        except PermissionError:
            continue
        with it:
            for entry in it:
                if entry.is_dir():
                    if not entry.is_symlink():
                        stack.append((entry.path, f"{prefix}{entry.name}/"))
                        if _is_reparse_point(entry):
                            unplain.add(f"{prefix}{entry.name}/")
                    continue
                if entry.is_symlink() or not entry.is_file():
                    skipped += 1
                    continue
                try:
                    size = entry.stat().st_size
                except OSError:
                    size = None  # surfaces below as a per-file "skipped (...)" like any unreadable file
                found.append((f"{prefix}{entry.name}", size))
                count += 1
                total_size += size or 0
                if _is_reparse_point(entry):
                    unplain.add(f"{prefix}{entry.name}")
                if len(found) >= WALK_BATCH_SIZE:
                    walk.executemany("INSERT INTO walk VALUES (?, ?)", found)
                    found = []
    walk.executemany("INSERT INTO walk VALUES (?, ?)", found)
    return walk, count, total_size, skipped, unplain


def _iter_walk(walk: sqlite3.Connection):
    """(rel_posix, size or None) in rel_posix order. BINARY collation on UTF-8 equals Python's code point order."""
    return walk.execute("SELECT rel, size FROM walk ORDER BY rel")


INGEST_BATCH_SIZE = 1000


def _add_evidence_folder(args: argparse.Namespace) -> None:
    folder_path = Path(args.file)
    folder_id = args.evidence_id

    walk, file_count, total_size, skipped, unplain = _walk_folder(folder_path)
    try:
        _ingest_walked_folder(args, folder_id, folder_path, walk, file_count, total_size, skipped, unplain)
    finally:
        walk.close()


def _ingest_walked_folder(args, folder_id, folder_path, walk, file_count, total_size, skipped, unplain) -> None:
    root_resolved = folder_path.resolve()

    if not file_count:
        print(f"No files found under {folder_path} (skipped {skipped} symlink/special entries).")
        sys.exit(1)

    # Optional hook, read like `actor`: progress(i, n, rel, size, done_bytes, total_bytes), at each file start and after
    # every chunk; done_bytes counts the whole folder. With a hook there are no per-file lines on stdout (the hook is the
    # progress channel). A hook that raises aborts the ingest and nothing is committed: the rows written so far sit in ONE
    # open transaction (do not raise an OSError from the hook: it would be taken for an unreadable file and skipped).
    progress = getattr(args, "progress", None)
    base = 0
    print(f"Found {file_count} file(s) ({total_size} bytes) under {folder_path}")
    if skipped:
        print(f"Skipped {skipped} symlink/special entries.")

    # Streaming: one batch of Evidence, an O(log n) Merkle builder, and member_ids built by SQLite at the end.
    # Opt-in process pool (--jobs / VCOC_HASH_JOBS): digests come back in walk order, so everything below is unchanged.
    jobs = getattr(args, "jobs", None) or hashing.default_jobs()
    pre = None
    if jobs > 1 and file_count >= hashing.PARALLEL_MIN_FILES:
        pre = hashing.hash_files(
            ((os.path.join(args.file, rel.replace("/", os.sep)), size) for rel, size in _iter_walk(walk)), jobs
        )
    batch: list[Evidence] = []
    builder = MerkleRootBuilder()
    conn = None  # opened at the first flush, so a run that fails before then does not even create the database
    try:
        for i, (rel, size_bytes) in enumerate(_iter_walk(walk), 1):
            full = os.path.join(args.file, rel.replace("/", os.sep))
            if progress is None:
                print(f"[{i}/{file_count}] hashing {rel}")
                on_chunk = None
            else:
                progress(i, file_count, rel, size_bytes or 0, base, total_size)
                on_chunk = lambda done, i=i, rel=rel, size=size_bytes or 0, b=base: progress(  # noqa: E731
                    i, file_count, rel, size, b + done, total_size
                )
            try:
                result = next(pre) if pre is not None else None
                if isinstance(result, OSError):
                    raise result
                digest = result or (hash_file(full, on_chunk=on_chunk) if on_chunk else hash_file(full))
                base += size_bytes or 0
                if size_bytes is None:
                    size_bytes = os.stat(full).st_size
            except OSError as exc:
                print(f"  skipped ({exc})")
                continue
            plain = not unplain or not any(rel.startswith(u) for u in unplain)
            batch.append(
                Evidence(
                    evidence_id=f"{folder_id}/{rel}",
                    original_filename=rel.rpartition("/")[2],
                    sha256=digest,
                    size_bytes=size_bytes,
                    added_at=utc_now_iso(),
                    source_path=str(root_resolved / rel) if plain and len(full) < 240 else str(Path(full).resolve()),
                    folder_id=folder_id,
                )
            )
            builder.add(digest)
            if len(batch) >= INGEST_BATCH_SIZE:
                if conn is None:
                    conn = db.connect(args.db)
                    db.begin_folder(conn)
                db.add_folder_members(conn, batch)
                batch = []

        if not builder.count:
            print("No files were successfully hashed; folder not registered.")
            sys.exit(1)

        if conn is None:
            conn = db.connect(args.db)
            db.begin_folder(conn)
        db.add_folder_members(conn, batch)
        root = builder.root()
        db.finish_folder(conn, folder_id, root)
    except BaseException:
        if conn is not None:
            conn.close()  # discards the open transaction: a cancel or crash leaves nothing behind
        raise
    finally:
        if pre is not None:
            pre.close()  # stops the workers (also when the progress hook raised)
    print(f"Registered folder {folder_id}: {builder.count} file(s), subtree root={root}")

    with contextlib.closing(conn):
        if args.private_key:
            signing_key = load_signing_key(args.private_key)
            chain = HashChain.load_db(conn)
            entry = chain.add_event(
                evidence_id=folder_id,
                actor=getattr(args, "actor", None) or "unknown",
                action="batch-register",
                signing_key=signing_key,
            )
            chain.save_db(conn)
            print(f"Logged batch-register event #{entry.index} for {folder_id}")


def cmd_log_event(args: argparse.Namespace) -> None:
    signing_key = load_signing_key(args.private_key)
    with contextlib.closing(db.connect(args.db)) as conn:
        _log_event(args, conn, signing_key)


def _log_event(args: argparse.Namespace, conn, signing_key) -> None:
    chain = HashChain.load_db(conn)
    evidence_ids = args.evidence_id
    if len(evidence_ids) == 1:
        entry = chain.add_event(
            evidence_id=evidence_ids[0],
            actor=args.actor,
            action=args.action,
            signing_key=signing_key,
        )
        described = entry.evidence_id
    else:
        entry = chain.add_event(
            evidence_ids=evidence_ids,
            actor=args.actor,
            action=args.action,
            signing_key=signing_key,
            case_number=getattr(args, "case_number", None),
            tag=getattr(args, "tag", None),
            notes=getattr(args, "notes", None),
        )
        described = ",".join(entry.evidence_ids)
    chain.save_db(conn)
    print(f"Logged event #{entry.index}: {entry.action} on {described} by {entry.actor}")
    print(f"entry_hash={entry.entry_hash}")


def cmd_check_evidence(args: argparse.Namespace) -> None:
    rec = None
    if Path(args.db).exists():
        with contextlib.closing(db.connect(args.db)) as conn:
            rec = db.get_evidence(conn, args.evidence_id)
    if rec is None:
        print(f"Unknown evidence id: {args.evidence_id}")
        sys.exit(1)
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

    if not Path(args.db).exists():
        print(f"No custody log found: {args.db} does not exist.")
        sys.exit(1)
    with contextlib.closing(db.connect(args.db)) as conn:
        chain = HashChain.load_db(conn)
    verifying_key = load_verifying_key(args.public_key)
    per_entry = chain.verify_each(verifying_key)
    first_bad = next((v for v in per_entry if not v.ok), None)
    ok = first_bad is None
    if ok:
        print(f"OK: chain of {len(chain.entries)} entries verified (chain verified).")
    else:
        # verify_each lists reasons in the same order verify() checks them, and the first failing entry has no upstream reason
        print(f"TAMPER DETECTED at entry #{first_bad.index}: {first_bad.reason.split('; ')[0]}")

    if chain.entries:
        chain_view = build_chain_view([e.to_dict() for e in chain.entries])
        print()
        for entry, verification in zip(chain_view, per_entry):
            for line in format_entry_detail_lines(entry, verification=verification):
                print(f"  {line}")
            print()

    if not ok:
        sys.exit(1)


def cmd_export(args: argparse.Namespace) -> None:
    if not Path(args.db).exists():
        print(f"Nothing to export: {args.db} does not exist.")
        sys.exit(1)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(db.connect(args.db)) as conn:
        chain = HashChain.load_db(conn)
        (out_dir / "custody_log.json").write_text(chain.to_json(), encoding="utf-8")
        (out_dir / "evidence_index.json").write_text(json.dumps(db.load_evidence_index(conn), indent=2), encoding="utf-8")
        (out_dir / "folder_index.json").write_text(json.dumps(db.load_folder_index(conn), indent=2), encoding="utf-8")
        groups = db.group_leaves(conn, counts=False)
    # The anchor: two short values that pin the whole store as of now. Keep a copy OUTSIDE the database (a ticket, an
    # email, a printout): a store rewritten later, or a log cut short, no longer matches the copy.
    anchor = {
        "exported_at": utc_now_iso(),
        "chain_entries": len(chain.entries),
        "chain_head_hash": chain.last_hash,
        "merkle_leaves": len(groups),
        "merkle_root": MerkleTree([leaf for _, leaf, _ in groups]).root if groups else None,
    }
    (out_dir / "anchor.json").write_text(json.dumps(anchor, indent=2), encoding="utf-8")
    print(f"Exported custody_log.json, evidence_index.json, folder_index.json, anchor.json -> {out_dir}")
    print("Anchor (keep a copy outside this database):")
    print(f"  chain head hash ({anchor['chain_entries']} entries): {anchor['chain_head_hash']}")
    print(f"  merkle root ({anchor['merkle_leaves']} leaves)    : {anchor['merkle_root'] or '(no evidence)'}")


def _build_main_tree(evidence_index: dict, folder_index: dict) -> tuple[MerkleTree, list[str]]:
    grouped_ids = sorted({rec.get("folder_id") or eid for eid, rec in evidence_index.items()})
    leaves = []
    for gid in grouped_ids:
        if gid in folder_index:
            leaves.append(folder_index[gid]["root"])
        else:
            leaves.append(evidence_index[gid]["sha256"])
    return MerkleTree(leaves), grouped_ids


def cmd_merkle_root(args: argparse.Namespace) -> None:
    if not Path(args.db).exists():
        groups = []
    else:
        with contextlib.closing(db.connect(args.db)) as conn:
            groups = db.group_leaves(conn)
    if not groups:
        print("No evidence registered yet.")
        sys.exit(1)
    tree = MerkleTree([leaf for _, leaf, _ in groups])
    print(f"Merkle root over {len(groups)} evidence file(s)/folder(s): {tree.root}")

    print()
    for gid, leaf, member_count in groups:
        if member_count:  # a folder: its leaf is the folder's own Merkle root
            print(f"  {gid}  {leaf}  ({member_count} files)")
        else:
            print(f"  {gid}  {leaf}")


def cmd_merkle_proof(args: argparse.Namespace) -> None:
    rec = None
    if Path(args.db).exists():
        with contextlib.closing(db.connect(args.db)) as conn:
            rec = db.get_evidence(conn, args.evidence_id)
            if rec is not None:
                # Streamed: the folder's members and the groups are read once each and never held as lists or trees.
                folder_id = rec.get("folder_id")
                if folder_id:
                    _, leaf, local_proof, subtree_root = merkle_proof_stream(
                        db.iter_member_leaves(conn, folder_id), args.evidence_id
                    )
                    _, _, folder_proof, root = merkle_proof_stream(db.iter_group_leaves(conn), folder_id)
                else:
                    _, _, local_proof, root = merkle_proof_stream(db.iter_group_leaves(conn), args.evidence_id)
                    leaf, subtree_root, folder_proof = rec["sha256"], root, []
    if rec is None:
        print(f"Unknown evidence id: {args.evidence_id}")
        sys.exit(1)

    proof = NestedProof(local_proof=local_proof, subtree_root=subtree_root, folder_proof=folder_proof)
    output = {
        "evidence_id": args.evidence_id,
        "leaf": leaf,
        "root": root,
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
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument(
        "--private-key",
        default=None,
        help="Folder mode only: sign a batch-register custody event with this key (omit to skip logging)",
    )
    p.add_argument("--actor", default=None, help="Folder mode only: actor recorded on the batch-register event")
    p.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="Folder mode only: hash with this many worker processes (default 1, or $VCOC_HASH_JOBS)",
    )
    p.set_defaults(func=cmd_add_evidence)

    p = sub.add_parser("log-event", help="Append a custody event")
    p.add_argument(
        "--evidence-id",
        required=True,
        action="append",
        help="Repeatable: one custody event can cover multiple evidence ids",
    )
    p.add_argument("--actor", required=True)
    p.add_argument("--action", required=True)
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY)
    p.add_argument("--case-number", default=None, help="Multi-evidence events only")
    p.add_argument("--tag", default=None, help="Multi-evidence events only")
    p.add_argument("--notes", default=None, help="Multi-evidence events only")
    p.set_defaults(func=cmd_log_event)

    p = sub.add_parser("check-evidence", help="Check a file against its recorded evidence hash")
    p.add_argument(
        "--file",
        default=None,
        help="Override path to check; defaults to the evidence's recorded source_path",
    )
    p.add_argument("--evidence-id", required=True)
    p.add_argument("--db", default=DEFAULT_DB)
    p.set_defaults(func=cmd_check_evidence)

    p = sub.add_parser("verify-chain", help="Verify the custody hash chain")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--public-key", default=DEFAULT_PUBLIC_KEY)
    p.set_defaults(func=cmd_verify_chain)

    p = sub.add_parser("merkle-root", help="Print the Merkle root over registered evidence")
    p.add_argument("--db", default=DEFAULT_DB)
    p.set_defaults(func=cmd_merkle_root)

    p = sub.add_parser("merkle-proof", help="Generate a Merkle inclusion proof")
    p.add_argument("--evidence-id", required=True)
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_merkle_proof)

    p = sub.add_parser("export", help="Export the DB to the JSON files verifier.py reads")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--out-dir", default=".")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("shell", help="Launch the interactive shell")
    p.set_defaults(func=cmd_shell)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
