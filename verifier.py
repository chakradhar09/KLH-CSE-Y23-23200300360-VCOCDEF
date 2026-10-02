#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import sys
import time
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from ecdsa import BadSignatureError, VerifyingKey
from ecdsa.util import sigdecode_string

GENESIS_HASH = "0" * 64
_SMALL_READ = 64 * 1024


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_stream(fh, chunk_size: int, on_chunk: Callable[[int], None] | None) -> str:
    # Same hybrid read as vcoc.hashing.hash_file (kept local: this file imports nothing from vcoc):
    # one small unbuffered read, then a single reused chunk_size buffer only for bigger files.
    digest = hashlib.sha256()
    done = 0
    head = fh.read(_SMALL_READ)
    more = len(head) == _SMALL_READ
    if not more:
        probe = fh.read(1)  # confirm EOF: a short read is not guaranteed to be the end
        head, more = head + probe, bool(probe)
    digest.update(head)
    done = len(head)
    if done and on_chunk is not None:
        on_chunk(done)
    if more:
        buf = bytearray(chunk_size)
        view = memoryview(buf)
        while n := fh.readinto(buf):
            digest.update(view[:n])
            done += n
            if on_chunk is not None:
                on_chunk(done)
    return digest.hexdigest()


def sha256_file_hex(
    path: str | Path, chunk_size: int = 1024 * 1024, on_chunk: Callable[[int], None] | None = None
) -> str:
    with open(path, "rb", buffering=0) as fh:
        return _hash_stream(fh, chunk_size, on_chunk)


def hash_hex_pair(left_hex: str, right_hex: str) -> str:
    return sha256_hex(bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def canonical_payload(entry: dict) -> str:
    evidence_ids = entry.get("evidence_ids")
    if evidence_ids is None:
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
    return json.dumps(
        {
            "index": entry["index"],
            "evidence_ids": evidence_ids,
            "actor": entry["actor"],
            "action": entry["action"],
            "timestamp": entry["timestamp"],
            "prev_hash": entry["prev_hash"],
            "case_number": entry.get("case_number") or "",
            "tag": entry.get("tag") or "",
            "notes": entry.get("notes") or "",
        },
        sort_keys=True,
    )


def _verify_entry_signature(entry: dict, verifying_key: VerifyingKey) -> bool:
    try:
        return verifying_key.verify(
            bytes.fromhex(entry["signature"]),
            entry["entry_hash"].encode("utf-8"),
            sigdecode=sigdecode_string,
        )
    except (BadSignatureError, ValueError):
        return False


def verify_chain(entries: list[dict], verifying_key: VerifyingKey) -> tuple[bool, int | None, str]:
    expected_prev = GENESIS_HASH
    for entry in entries:
        if entry["prev_hash"] != expected_prev:
            return False, entry["index"], "prev_hash does not match preceding entry"

        recomputed_hash = sha256_hex(canonical_payload(entry).encode("utf-8"))
        if recomputed_hash != entry["entry_hash"]:
            return False, entry["index"], "entry_hash does not match recomputed payload hash"

        if not _verify_entry_signature(entry, verifying_key):
            return False, entry["index"], "signature verification failed"

        expected_prev = entry["entry_hash"]

    return True, None, "chain verified"


@dataclass(frozen=True)
class EntryVerification:

    index: int
    ok: bool
    reason: str


def verify_each(entries: list[dict], verifying_key: VerifyingKey) -> list[EntryVerification]:
    results: list[EntryVerification] = []
    expected_prev = GENESIS_HASH
    upstream_broken = False
    for entry in entries:
        reasons = []
        if entry["prev_hash"] != expected_prev:
            reasons.append("prev_hash does not match preceding entry")

        recomputed_hash = sha256_hex(canonical_payload(entry).encode("utf-8"))
        if recomputed_hash != entry["entry_hash"]:
            reasons.append("entry_hash does not match recomputed payload hash")

        if not _verify_entry_signature(entry, verifying_key):
            reasons.append("signature verification failed")

        if upstream_broken:
            reasons.append("upstream entry failed verification")

        ok = not reasons
        results.append(EntryVerification(index=entry["index"], ok=ok, reason="; ".join(reasons) or "ok"))

        if not ok:
            upstream_broken = True
        expected_prev = entry["entry_hash"]

    return results


def verify_merkle_proof(leaf: str, proof: list[dict], root: str) -> bool:
    computed = leaf
    for step in proof:
        if step["is_left"]:
            computed = hash_hex_pair(step["sibling"], computed)
        else:
            computed = hash_hex_pair(computed, step["sibling"])
    return computed == root


def verify_nested_proof(leaf: str, proof: dict, root: str) -> bool:
    if not verify_merkle_proof(leaf, proof["local_proof"], proof["subtree_root"]):
        return False
    if not proof["folder_proof"]:
        return proof["subtree_root"] == root
    return verify_merkle_proof(proof["subtree_root"], proof["folder_proof"], root)


def merkle_root(leaves: list[str]) -> str:
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

    evidence_id: str
    original_filename: str
    recorded_sha256: str
    source_path: str
    rehash_status: str
    logged_status: str

    @property
    def ok(self) -> bool:
        return self.rehash_status in ("match", "not found", "no source_path recorded") and self.logged_status.startswith("logged")


def _is_missing(exc: OSError) -> bool:
    """The errors Path.exists() reads as "no such file" (same list as pathlib); anything else is a real problem."""
    return exc.errno in (errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP) or getattr(exc, "winerror", None) in (
        21,
        123,
        1921,
    )


def evidence_rehash_status(
    position: int,
    total_records: int,
    evidence_id: str,
    source_path: str,
    recorded_sha256: str,
    progress: Callable[[int, int, str, int, int], None] | None = None,
) -> str:
    """Re-hash one evidence record from disk: "match", "MISMATCH", "not found" or "no source_path recorded".

    `progress(position, total_records, evidence_id, done_bytes, total_bytes)` is called only when a file is hashed.
    """
    if not source_path:
        return "no source_path recorded"
    # One open() answers "does it exist", "how big is it" (fstat on the handle) and "what is its hash": a separate
    # exists() and stat() cost ~100 us each per file on Windows, as much as the hashing itself.
    try:
        fh = open(source_path, "rb", buffering=0)
    except OSError as exc:
        if _is_missing(exc):
            return "not found"
        raise
    with fh:
        on_chunk = None
        if progress is not None:
            total = os.fstat(fh.fileno()).st_size
            progress(position, total_records, evidence_id, 0, total)
            on_chunk = lambda done: progress(position, total_records, evidence_id, done, total)
        return "match" if _hash_stream(fh, 1024 * 1024, on_chunk) == recorded_sha256 else "MISMATCH"


# Opt-in parallel re-hash (--jobs / VCOC_HASH_JOBS, default 1). This is its own copy of vcoc.hashing's batching: this file
# imports nothing from vcoc. Statuses come back in input order; a file of BIG_FILE bytes or more is hashed in the caller
# so it keeps byte-level progress; below PARALLEL_MIN_FILES a pool's start-up costs more than it saves.
PARALLEL_MIN_FILES = 2000
BATCH_FILES = 500
BATCH_BYTES = 64 * 1024 * 1024
BIG_FILE = 256 * 1024 * 1024


def default_jobs() -> int:
    try:
        return max(1, int(os.environ.get("VCOC_HASH_JOBS", "1")))
    except ValueError:
        return 1


def _rehash_batch(items: list[tuple[str, str]]) -> list:
    out: list = []
    for path, recorded_sha256 in items:
        try:
            out.append(evidence_rehash_status(0, 0, "", path, recorded_sha256))
        except OSError as exc:  # an error that is not "missing": raised again by the caller, as in a sequential run
            out.append(exc)
    return out


def _rehash_units(entries: Iterable[tuple[str, str, int | None]]) -> Iterator[list | None]:
    batch: list[tuple[str, str]] = []
    nbytes = 0
    for path, recorded_sha256, size in entries:
        size = size or 0
        if size >= BIG_FILE:
            if batch:
                yield batch
                batch, nbytes = [], 0
            yield None
            continue
        batch.append((path, recorded_sha256))
        nbytes += size
        if len(batch) >= BATCH_FILES or nbytes >= BATCH_BYTES:
            yield batch
            batch, nbytes = [], 0
    if batch:
        yield batch


def _rehash_parallel(entries: Iterable[tuple[str, str, int | None]], jobs: int) -> Iterator:
    """One status per entry in input order: a status string, an OSError, or None (a big file: hash it yourself)."""
    units = _rehash_units(entries)
    pool = ProcessPoolExecutor(max_workers=jobs)
    window: deque = deque()
    try:
        while True:
            while len(window) < 2 * jobs and (unit := next(units, False)) is not False:
                window.append(None if unit is None else pool.submit(_rehash_batch, unit))
            if not window:
                return
            first = window.popleft()
            if first is None:
                yield None
            else:
                yield from first.result()
    finally:
        pool.shutdown(wait=True, cancel_futures=True)


def verify_evidence_index(
    index: dict,
    custody_entries: list[dict],
    folder_index: dict | None = None,
    progress: Callable[[int, int, str, int, int], None] | None = None,
    jobs: int = 1,
) -> tuple[list[EvidenceCheckResult], str | None]:
    # progress(i, n, evidence_id, done_bytes, total_bytes): once per hashed file at done=0, then after every chunk.
    # Records that are not re-hashed (no path / not found) never call it. Exceptions from it propagate to the caller.
    # jobs > 1 re-hashes in a process pool: progress then fires per file (start and end), not per chunk.
    folder_index = folder_index or {}
    logged_ids = set()
    for entry in custody_entries:
        if entry.get("evidence_ids") is not None:
            logged_ids.update(entry["evidence_ids"])
        else:
            logged_ids.add(entry["evidence_id"])

    results = []
    ordered = sorted(index.items())
    pre = None
    if jobs > 1 and sum(1 for _, r in ordered if r.get("source_path")) >= PARALLEL_MIN_FILES:
        pre = _rehash_parallel(
            ((r["source_path"], r["sha256"], r.get("size_bytes")) for _, r in ordered if r.get("source_path")), jobs
        )
    try:
        return _verify_records(ordered, index, logged_ids, folder_index, progress, pre, results)
    finally:
        if pre is not None:
            pre.close()


def _verify_records(ordered, index, logged_ids, folder_index, progress, pre, results):
    for position, (evidence_id, rec) in enumerate(ordered, 1):
        source_path = rec.get("source_path", "")
        rehash_status = next(pre) if pre is not None and source_path else None
        if isinstance(rehash_status, OSError):
            raise rehash_status
        if rehash_status is None:
            rehash_status = evidence_rehash_status(
                position, len(index), evidence_id, source_path, rec["sha256"], progress
            )
        elif progress is not None and rehash_status != "not found":
            size = rec.get("size_bytes") or 0
            progress(position, len(index), evidence_id, 0, size)
            if size:  # like the sequential run: an empty file reports only its start
                progress(position, len(index), evidence_id, size, size)

        # A folder's batch-register event logs the FOLDER id (it commits to the folder's Merkle root), so its members
        # count as logged through it. The folder must exist in folder_index: a bare folder_id claim is not enough.
        # ponytail: member_ids membership is not re-checked (the grouped Merkle root already pins the folder's contents)
        folder_id = rec.get("folder_id")
        if evidence_id in logged_ids:
            logged_status = "logged"
        elif folder_id and folder_id in logged_ids and folder_id in folder_index:
            logged_status = f"logged (via folder {folder_id})"
        else:
            logged_status = "NOT LOGGED"

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


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _stderr_progress(
    stream=None, interval: float = 0.5, summary_interval: float = 5.0, big_file_bytes: int = 64 * 2**20
) -> Callable[[int, int, str, int, int], None]:
    stream = stream or sys.stderr
    tty = stream.isatty()
    last = [0.0]
    last_line: list[float | None] = [None]

    def report(i: int, n: int, evidence_id: str, done: int, total: int) -> None:
        if not tty:
            # Piped/logged: no \r noise, and not one line per file either (832,300 lines on a real run). A line for the
            # first file, the last file, every file of 64 MiB or more (a long step worth naming), and one more every
            # `summary_interval` seconds, so a log shows steady progress without growing with the file count.
            if done == 0:
                now = time.monotonic()
                if last_line[0] is None or i == n or total >= big_file_bytes or now - last_line[0] >= summary_interval:
                    last_line[0] = now
                    print(f"[{i}/{n}] re-hashing {evidence_id} ({_fmt_bytes(total)})", file=stream, flush=True)
            return
        now = time.monotonic()
        finished = done >= total
        if done and not finished and now - last[0] < interval:
            return
        last[0] = now
        pct = 100 * done // total if total else 100
        line = f"[{i}/{n}] {evidence_id}  {_fmt_bytes(done)} / {_fmt_bytes(total)} ({pct}%)"
        print(f"\r{line.ljust(70)}", end="\n" if finished else "", file=stream, flush=True)

    return report


def load_anchor(path: str) -> dict:
    """Read an anchor.json written by `cli.py export`; exit 1 with a message if it is missing or malformed."""
    try:
        anchor = json.loads(Path(path).read_text(encoding="utf-8"))
        ok = (
            isinstance(anchor, dict)
            and isinstance(anchor.get("chain_entries"), int)
            and anchor["chain_entries"] >= 0
            and isinstance(anchor.get("chain_head_hash"), str)
            and isinstance(anchor.get("merkle_root"), (str, type(None)))
        )
    except (OSError, ValueError) as exc:
        print(f"Cannot read the anchor file {path}: {exc}")
        sys.exit(1)
    if not ok:
        print(f"The anchor file {path} is not a valid anchor.json (needs chain_entries, chain_head_hash, merkle_root).")
        sys.exit(1)
    return anchor


def anchor_chain_problem(anchor: dict, entries: list[dict]) -> str | None:
    """None if the log still starts with the anchored entries (it may have grown since), else what is wrong.

    The entry at the anchored position pins every entry before it, because each entry_hash covers its prev_hash."""
    n = anchor["chain_entries"]
    if len(entries) < n:
        return f"the log has {len(entries)} entries but the anchor was taken at {n}: entries were removed"
    head = entries[n - 1].get("entry_hash") if n else GENESIS_HASH
    if head != anchor["chain_head_hash"]:
        return f"entry #{n - 1} does not match the anchor (hash {head}, anchored {anchor['chain_head_hash']})"
    return None


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="verifier.py", description="Standalone chain-of-custody verifier")
    parser.add_argument("--log", required=True, help="Path to custody_log.json")
    parser.add_argument(
        "--anchor",
        default=None,
        help="Optional anchor.json from `cli.py export`, kept outside the database: checks the log still starts with "
        "the anchored entries and (with --evidence-index) that the Merkle root is unchanged",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="Re-hash evidence with this many worker processes (default 1, or $VCOC_HASH_JOBS)",
    )
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

    anchor = load_anchor(args.anchor) if args.anchor else None
    entries = json.loads(Path(args.log).read_text(encoding="utf-8"))
    verifying_key = VerifyingKey.from_pem(Path(args.public_key).read_bytes())
    exit_code = 0
    evidence_root = None

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
        results, root = verify_evidence_index(
            index, entries, folder_index=folder_index, progress=_stderr_progress(), jobs=args.jobs or default_jobs()
        )
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
        evidence_root = root

    if anchor is not None:
        print("\n== Anchor ==")
        problem = anchor_chain_problem(anchor, entries)
        if problem:
            print(f"TAMPER DETECTED: {problem}.")
            exit_code = 1
        else:
            added = len(entries) - anchor["chain_entries"]
            note = f" ({added} {'entry' if added == 1 else 'entries'} added since the anchor)" if added else ""
            print(f"OK: custody log matches the anchor ({anchor['chain_entries']} entries, head {anchor['chain_head_hash']}){note}.")
        if not args.evidence_index:
            print("Merkle root not checked (pass --evidence-index to compare it with the anchor).")
        elif evidence_root != anchor["merkle_root"]:
            print(
                "TAMPER DETECTED: Merkle root does not match the anchor "
                f"(recomputed {evidence_root}, anchored {anchor['merkle_root']}). Evidence was added, removed or changed "
                "since the anchor was taken: if that was intended, export a new anchor."
            )
            exit_code = 1
        else:
            print(f"OK: Merkle root matches the anchor ({evidence_root}).")

    print()
    print("OK: all requested verifications passed." if exit_code == 0 else "TAMPER DETECTED: see above.")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
