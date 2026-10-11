#!/usr/bin/env python3
"""Extended tamper scenarios: each is checked by the chain alone and again with an anchor kept outside the database."""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ecdsa import SigningKey

from vcoc.ecdsa_signer import generate_keypair, sign_message
from vcoc.hash_chain import HashChain
from verifier import anchor_chain_problem, canonical_payload, merkle_root, sha256_hex, verify_chain


def clean_chain(key: SigningKey, n: int = 6, multi_at: int = 2) -> list[dict]:
    chain = HashChain()
    for i in range(n):
        if i == multi_at:
            chain.add_event(
                "J. Doe", "transferred", key, evidence_ids=["EV002", "EV003"], case_number="C-1", tag="disk", notes="n"
            )
        else:
            chain.add_event("J. Doe", "collected" if i == 0 else "reviewed", key, evidence_id=f"EV{i:03d}")
    return [e.to_dict() for e in chain.entries]


def anchor_of(entries: list[dict]) -> dict:
    return {"chain_entries": len(entries), "chain_head_hash": entries[-1]["entry_hash"], "merkle_root": None}


def relink_from(entries: list[dict], start: int, key: SigningKey | None) -> None:
    """Recompute prev_hash and entry_hash from `start` on, as an attacker rewriting history would; re-sign only with a key."""
    for i in range(start, len(entries)):
        entries[i]["prev_hash"] = entries[i - 1]["entry_hash"] if i else "0" * 64
        entries[i]["entry_hash"] = sha256_hex(canonical_payload(entries[i]).encode("utf-8"))
        if key is not None:
            entries[i]["signature"] = sign_message(key, entries[i]["entry_hash"].encode("utf-8"))


def truncate_tail(e, key):
    return e[:-2]


def delete_middle(e, key):
    del e[3]
    return e


def swap_adjacent(e, key):
    e[1], e[2] = e[2], e[1]
    return e


def edit_multi_evidence_id(e, key):
    e[2]["evidence_ids"] = ["EV002", "EV999"]
    return e


def rewrite_suffix_no_key(e, key):
    e[3]["actor"] = "Mallory"
    relink_from(e, 3, None)
    return e


def rewrite_suffix_stolen_key(e, key):
    e[3]["actor"] = "Mallory"
    relink_from(e, 3, key)
    return e


SCENARIOS = [
    ("truncate_last_two", "Delete the newest two entries", truncate_tail),
    ("delete_middle_entry", "Remove entry 3 and leave a gap", delete_middle),
    ("swap_adjacent_entries", "Swap entries 1 and 2", swap_adjacent),
    ("edit_multi_evidence_id", "Change one evidence id inside a multi-evidence entry", edit_multi_evidence_id),
    ("rewrite_suffix_no_key", "Edit entry 3, recompute every later hash, no signing key", rewrite_suffix_no_key),
    ("rewrite_suffix_stolen_key", "Edit entry 3, re-sign every later entry with the stolen key", rewrite_suffix_stolen_key),
]


def run(key: SigningKey, vk) -> list[dict]:
    clean = clean_chain(key)
    anchor = anchor_of(clean)
    rows = []
    for name, desc, mutate in SCENARIOS:
        tampered = mutate(copy.deepcopy(clean), key)
        ok, idx, reason = verify_chain(tampered, vk)
        problem = anchor_chain_problem(anchor, tampered)
        rows.append({
            "scenario": name,
            "description": desc,
            "chain_only_detected": not ok,
            "chain_only_break_index": idx,
            "chain_only_reason": reason,
            "with_anchor_detected": (not ok) or problem is not None,
            "anchor_reason": problem,
        })

    leaves = [sha256_hex(f"file{i}".encode()) for i in range(8)]
    root = merkle_root(leaves)
    changed = list(leaves)
    changed[5] = sha256_hex(b"altered")
    moved = merkle_root(changed) != root
    rows.append({
        "scenario": "merkle_leaf_changed",
        "description": "Change one evidence digest, compare the recomputed root with the anchored root",
        "chain_only_detected": False,
        "chain_only_break_index": None,
        "chain_only_reason": "not a custody-log property",
        "with_anchor_detected": moved,
        "anchor_reason": "Merkle root does not match the anchor" if moved else None,
    })
    return rows


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Extended tamper scenarios, with and without an anchor")
    parser.add_argument("--out", default=None, help="Write JSON results to this path")
    args = parser.parse_args(argv)

    key, vk = generate_keypair()
    clean_ok, _, _ = verify_chain(clean_chain(key), vk)
    rows = run(key, vk)
    for r in rows:
        print(
            f"{r['scenario']:<28} chain-only: {'DETECTED' if r['chain_only_detected'] else 'missed  '} "
            f"(#{r['chain_only_break_index']})   with anchor: {'DETECTED' if r['with_anchor_detected'] else 'missed'}"
        )
    print(f"\nClean chain verified: {clean_ok}")
    print(
        f"Chain only: {sum(r['chain_only_detected'] for r in rows)}/{len(rows)} detected; "
        f"with anchor: {sum(r['with_anchor_detected'] for r in rows)}/{len(rows)}"
    )
    if args.out:
        Path(args.out).write_text(json.dumps({"clean_chain_verified": clean_ok, "scenarios": rows}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
