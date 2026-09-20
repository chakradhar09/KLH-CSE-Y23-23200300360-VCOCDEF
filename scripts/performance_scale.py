#!/usr/bin/env python3
"""Performance/scale experiment: hashing + Merkle tree build/verify time
vs. number of evidence files.

For each evidence-set size N in --sizes, this script:
  1. Generates N synthetic evidence files of --file-size-kb each.
  2. Hashes all N files (SHA-256) and times it.
  3. Builds a Merkle tree over the N digests and times it.
  4. Generates and verifies an inclusion proof for one leaf and times it.

This is the experiment behind the "performance/scale" result in the paper
(PRC-2 Plan, Section 4, item 3).

Usage:
    python scripts/performance_scale.py [--sizes 10 100 1000] [--out results.json] [--chart chart.png]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vcoc.hashing import hash_file
from vcoc.merkle import MerkleTree, verify_proof

DEFAULT_SIZES = [10, 100, 1000]
DEFAULT_FILE_SIZE_KB = 64


def generate_synthetic_files(directory: Path, count: int, file_size_kb: int) -> list[Path]:
    """Create `count` synthetic evidence files of `file_size_kb` KB each.

    Content is pseudo-random per file (not all-zero) so files don't hash
    identically, mirroring the entropy real evidence artifacts would have.
    """
    paths = []
    for i in range(count):
        path = directory / f"synthetic_evidence_{i:06d}.bin"
        path.write_bytes(os.urandom(file_size_kb * 1024))
        paths.append(path)
    return paths


def run_trial(count: int, file_size_kb: int) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        gen_start = time.perf_counter()
        files = generate_synthetic_files(tmp_path, count, file_size_kb)
        gen_time = time.perf_counter() - gen_start

        hash_start = time.perf_counter()
        digests = [hash_file(f) for f in files]
        hash_time = time.perf_counter() - hash_start

        build_start = time.perf_counter()
        tree = MerkleTree(digests)
        build_time = time.perf_counter() - build_start

        proof_index = count // 2
        proof_gen_start = time.perf_counter()
        proof = tree.get_proof(proof_index)
        proof_gen_time = time.perf_counter() - proof_gen_start

        verify_start = time.perf_counter()
        ok = verify_proof(digests[proof_index], proof, tree.root)
        verify_time = time.perf_counter() - verify_start

        return {
            "evidence_count": count,
            "file_size_kb": file_size_kb,
            "synthetic_data_generation_seconds": gen_time,
            "hashing_seconds": hash_time,
            "hashing_seconds_per_file": hash_time / count,
            "merkle_build_seconds": build_time,
            "merkle_proof_generation_seconds": proof_gen_time,
            "merkle_proof_verification_seconds": verify_time,
            "proof_verified": ok,
            "proof_size_steps": len(proof),
        }


def make_chart(results: list[dict], out_path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    counts = [r["evidence_count"] for r in results]
    hash_times = [r["hashing_seconds"] for r in results]
    build_times = [r["merkle_build_seconds"] for r in results]
    verify_times = [r["merkle_proof_verification_seconds"] for r in results]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

    ax1.plot(counts, hash_times, marker="o", label="Hashing (SHA-256, all files)")
    ax1.plot(counts, build_times, marker="s", label="Merkle tree build")
    ax1.set_xlabel("Number of evidence files")
    ax1.set_ylabel("Time (seconds, log scale)")
    ax1.set_title("Hashing & Merkle Build Time vs. Evidence Count")
    ax1.set_xscale("log")
    ax1.set_yscale("log")
    ax1.legend()
    ax1.grid(True, alpha=0.3, which="both")

    ax2.plot(counts, verify_times, marker="^", color="darkgreen", label="Merkle proof verification")
    ax2.set_xlabel("Number of evidence files")
    ax2.set_ylabel("Time (seconds)")
    ax2.set_title("Merkle Proof Verification Time vs. Evidence Count\n(O(log n) expected)")
    ax2.set_xscale("log")
    ax2.ticklabel_format(axis="y", style="scientific", scilimits=(0, 0))
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Performance/scale experiment")
    parser.add_argument("--sizes", type=int, nargs="+", default=DEFAULT_SIZES,
                         help="Evidence-set sizes to test (default: 10 100 1000)")
    parser.add_argument("--file-size-kb", type=int, default=DEFAULT_FILE_SIZE_KB,
                         help="Size of each synthetic evidence file in KB (default: 64)")
    parser.add_argument("--out", default=None, help="Write JSON results to this path")
    parser.add_argument("--chart", default=None, help="Write a PNG chart to this path")
    args = parser.parse_args(argv)

    results = []
    for count in args.sizes:
        print(f"Running trial: {count} evidence files x {args.file_size_kb} KB ...")
        result = run_trial(count, args.file_size_kb)
        results.append(result)
        print(
            f"  hash={result['hashing_seconds']:.4f}s "
            f"build={result['merkle_build_seconds']:.6f}s "
            f"proof_gen={result['merkle_proof_generation_seconds']:.6f}s "
            f"verify={result['merkle_proof_verification_seconds']:.6f}s "
            f"verified={result['proof_verified']}"
        )

    print()
    print(f"{'Files':>8} {'Hash (s)':>10} {'Build (s)':>12} {'ProofGen (s)':>14} {'Verify (s)':>12}")
    for r in results:
        print(
            f"{r['evidence_count']:>8} {r['hashing_seconds']:>10.4f} "
            f"{r['merkle_build_seconds']:>12.6f} {r['merkle_proof_generation_seconds']:>14.6f} "
            f"{r['merkle_proof_verification_seconds']:>12.6f}"
        )

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nWrote results -> {args.out}")

    if args.chart:
        make_chart(results, Path(args.chart))
        print(f"Wrote chart -> {args.chart}")


if __name__ == "__main__":
    main()
