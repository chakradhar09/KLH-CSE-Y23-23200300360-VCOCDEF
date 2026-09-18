#!/usr/bin/env python3
"""Tamper-simulation harness.

Builds a small custody chain, verifies it is clean, then applies a series
of deliberate single-point corruptions (one at a time, from a freshly
rebuilt clean chain each time) and confirms the independent verifier
(``verifier.py``) flags every one of them at the correct entry index. This
is the experiment behind the "tamper detection" result in the paper.

Usage:
    python scripts/tamper_simulation.py [--out results.json]
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from verifier import verify_chain as independent_verify_chain  # noqa: E402
from ecdsa import VerifyingKey  # noqa: E402


def build_clean_chain(signing_key, num_entries: int = 5) -> HashChain:
    chain = HashChain()
    for i in range(num_entries):
        chain.add_event(
            evidence_id=f"EV{i:03d}",
            actor="J. Doe",
            action="collected" if i == 0 else "reviewed",
            signing_key=signing_key,
        )
    return chain


SCENARIOS = [
    {
        "name": "flip_actor_field",
        "description": "Change the actor name on entry 2 (payload tamper, hash not recomputed).",
        "target_index": 2,
        "mutate": lambda e: e.__setitem__("actor", "Mallory"),
    },
    {
        "name": "flip_action_field",
        "description": "Change the action on entry 1 (payload tamper, hash not recomputed).",
        "target_index": 1,
        "mutate": lambda e: e.__setitem__("action", "destroyed"),
    },
    {
        "name": "corrupt_signature",
        "description": "Flip one hex character in entry 3's signature.",
        "target_index": 3,
        "mutate": lambda e: e.__setitem__(
            "signature", ("0" if e["signature"][0] != "0" else "1") + e["signature"][1:]
        ),
    },
    {
        "name": "break_prev_hash_link",
        "description": "Corrupt entry 4's prev_hash so it no longer chains to entry 3.",
        "target_index": 4,
        "mutate": lambda e: e.__setitem__("prev_hash", "f" * 64),
    },
]


def run_scenario(scenario: dict, verifying_key: VerifyingKey, num_entries: int, signing_key) -> dict:
    chain = build_clean_chain(signing_key, num_entries)
    entries = [e.to_dict() for e in chain.entries]

    tampered = copy.deepcopy(entries)
    scenario["mutate"](tampered[scenario["target_index"]])

    ok, break_index, reason = independent_verify_chain(tampered, verifying_key)
    detected = (not ok) and (break_index == scenario["target_index"])
    return {
        "scenario": scenario["name"],
        "description": scenario["description"],
        "target_index": scenario["target_index"],
        "detected": detected,
        "reported_break_index": break_index,
        "reason": reason,
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run tamper-detection scenarios")
    parser.add_argument("--out", default=None, help="Write JSON results to this path")
    parser.add_argument("--entries", type=int, default=5, help="Number of clean entries per scenario")
    args = parser.parse_args(argv)

    signing_key, verifying_key = generate_keypair()

    with tempfile.TemporaryDirectory() as tmp:
        save_keypair(signing_key, Path(tmp) / "priv.pem", Path(tmp) / "pub.pem")

        clean_chain = build_clean_chain(signing_key, args.entries)
        clean_ok, _, clean_reason = independent_verify_chain(
            [e.to_dict() for e in clean_chain.entries], verifying_key
        )

        results = {
            "baseline_clean_chain_verified": clean_ok,
            "baseline_reason": clean_reason,
            "scenarios": [],
        }

        all_detected = True
        for scenario in SCENARIOS:
            result = run_scenario(scenario, verifying_key, args.entries, signing_key)
            results["scenarios"].append(result)
            all_detected = all_detected and result["detected"]
            status = "DETECTED" if result["detected"] else "MISSED"
            print(f"[{status}] {scenario['name']}: {result['reason']} (entry #{result['reported_break_index']})")

        results["all_tamper_scenarios_detected"] = all_detected

    print()
    print(f"Clean chain verified: {clean_ok}")
    print(f"All {len(SCENARIOS)} tamper scenarios detected: {all_detected}")

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Wrote results -> {args.out}")

    sys.exit(0 if (clean_ok and all_detected) else 1)


if __name__ == "__main__":
    main()
