#!/usr/bin/env python3
"""Storage-overhead experiment: plaintext vs. AES-256-GCM-at-rest size.

For each record count N in --sizes, this script:
  1. Builds N synthetic Evidence records and N synthetic CustodyEvent
     records (via a real HashChain, so entries are genuinely hash-linked
     and signed).
  2. Serializes them as plain JSON (the "plaintext" baseline) and measures
     the byte size.
  3. Writes them into an EncryptedStore (SQLite + AES-256-GCM) and measures
     the resulting .db file size.
  4. Reports absolute and per-record overhead.

This is the experiment behind the "storage overhead" result in the paper
(PRC-2 Plan, Section 4, item 4), scoped to the SQLite + AES-GCM extension
selected for this cycle.

Usage:
    python scripts/storage_overhead.py [--sizes 10 100 1000] [--out results.json] [--chart chart.png]
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vcoc.ecdsa_signer import generate_keypair
from vcoc.hash_chain import HashChain, utc_now_iso
from vcoc.models import Evidence
from vcoc.storage import EncryptedStore, generate_key

DEFAULT_SIZES = [10, 100, 1000]


def build_records(count: int, signing_key) -> tuple[list[Evidence], HashChain]:
    evidence_records = [
        Evidence(
            evidence_id=f"EV{i:06d}",
            original_filename=f"synthetic_evidence_{i:06d}.bin",
            sha256=f"{i:064x}"[-64:],
            size_bytes=65536,
            added_at=utc_now_iso(),
        )
        for i in range(count)
    ]
    chain = HashChain()
    for i in range(count):
        chain.add_event(
            evidence_id=f"EV{i:06d}",
            actor="J. Doe",
            action="collected" if i == 0 else "reviewed",
            signing_key=signing_key,
        )
    return evidence_records, chain


def plaintext_json_size(evidence_records: list[Evidence], chain: HashChain) -> int:
    payload = {
        "evidence": [e.__dict__ for e in evidence_records],
        "custody_events": [e.to_dict() for e in chain.entries],
    }
    return len(json.dumps(payload).encode("utf-8"))


def encrypted_db_size(evidence_records: list[Evidence], chain: HashChain, db_path: Path) -> int:
    key = generate_key()
    store = EncryptedStore(db_path, key)
    for e in evidence_records:
        store.put_evidence(e)
    for event in chain.entries:
        store.put_event(event)
    store.close()
    return db_path.stat().st_size


def run_trial(count: int, signing_key) -> dict:
    evidence_records, chain = build_records(count, signing_key)
    plaintext_size = plaintext_json_size(evidence_records, chain)

    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "custody.db"
        encrypted_size = encrypted_db_size(evidence_records, chain, db_path)

    overhead_bytes = encrypted_size - plaintext_size
    overhead_pct = (overhead_bytes / plaintext_size * 100) if plaintext_size else 0.0

    return {
        "record_count": count,
        "plaintext_json_bytes": plaintext_size,
        "encrypted_sqlite_bytes": encrypted_size,
        "overhead_bytes": overhead_bytes,
        "overhead_percent": overhead_pct,
        "plaintext_bytes_per_record": plaintext_size / count,
        "encrypted_bytes_per_record": encrypted_size / count,
    }


def make_chart(results: list[dict], out_path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    counts = [r["record_count"] for r in results]
    plaintext = [r["plaintext_json_bytes"] / 1024 for r in results]
    encrypted = [r["encrypted_sqlite_bytes"] / 1024 for r in results]

    fig, ax = plt.subplots(figsize=(7, 4.5))
    width = 0.35
    x = range(len(counts))
    ax.bar([i - width / 2 for i in x], plaintext, width, label="Plaintext JSON")
    ax.bar([i + width / 2 for i in x], encrypted, width, label="Encrypted SQLite (AES-256-GCM)")
    ax.set_xticks(list(x))
    ax.set_xticklabels([str(c) for c in counts])
    ax.set_xlabel("Number of evidence + custody records")
    ax.set_ylabel("Storage size (KB)")
    ax.set_title("Storage Size: Plaintext vs. Encrypted-at-Rest")
    ax.legend()
    ax.grid(True, alpha=0.3, axis="y")

    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Storage-overhead experiment")
    parser.add_argument("--sizes", type=int, nargs="+", default=DEFAULT_SIZES,
                         help="Record counts to test (default: 10 100 1000)")
    parser.add_argument("--out", default=None, help="Write JSON results to this path")
    parser.add_argument("--chart", default=None, help="Write a PNG chart to this path")
    args = parser.parse_args(argv)

    signing_key, _ = generate_keypair()

    results = []
    for count in args.sizes:
        print(f"Running trial: {count} evidence + custody records ...")
        result = run_trial(count, signing_key)
        results.append(result)
        print(
            f"  plaintext={result['plaintext_json_bytes']}B "
            f"encrypted={result['encrypted_sqlite_bytes']}B "
            f"overhead={result['overhead_percent']:.1f}%"
        )

    print()
    print(f"{'Records':>8} {'Plaintext (B)':>14} {'Encrypted (B)':>14} {'Overhead':>10}")
    for r in results:
        print(
            f"{r['record_count']:>8} {r['plaintext_json_bytes']:>14} "
            f"{r['encrypted_sqlite_bytes']:>14} {r['overhead_percent']:>9.1f}%"
        )

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nWrote results -> {args.out}")

    if args.chart:
        make_chart(results, Path(args.chart))
        print(f"Wrote chart -> {args.chart}")


if __name__ == "__main__":
    main()
