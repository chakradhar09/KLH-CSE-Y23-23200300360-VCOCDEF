#!/usr/bin/env python3
"""Redraw the paper's figures from the JSON written by performance_scale.py, storage_overhead.py and the --verify-db runs."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = Path(__file__).resolve().parent.parent / "Doc" / "experiment_results"


def median_runs(runs: list[list[dict]]) -> list[dict]:
    """Per evidence count, the median of every numeric field across repeated runs."""
    import statistics

    def med(i: int, k: str, v):
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return v
        return statistics.median(r[i][k] for r in runs)

    return [{k: med(i, k, v) for k, v in runs[0][i].items()} for i in range(len(runs[0]))]


def load(name: str):
    return json.loads((R / name).read_text(encoding="utf-8"))


def scale_charts(rows: list[dict], out_a: Path, out_b: Path) -> None:
    """Two single-panel charts (column width in a two-column layout), like the paper's Fig. 1a and 1b."""
    n = [r["evidence_count"] for r in rows]
    fig, ax = plt.subplots(figsize=(4.2, 2.8))
    ax.loglog(n, [r["hashing_seconds"] for r in rows], "o-", label="Hashing (SHA-256, all files)")
    ax.loglog(n, [r["merkle_build_seconds"] for r in rows], "s-", label="Merkle tree build")
    ax.set_xlabel("Number of evidence files")
    ax.set_ylabel("Time (s, log scale)")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(out_a, dpi=200)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(4.2, 2.8))
    ax.semilogx(n, [r["merkle_proof_verification_mean_seconds"] * 1e6 for r in rows], "^-", color="darkgreen")
    ax.set_xlabel("Number of evidence files")
    ax.set_ylabel("Proof verification (µs)")
    ax.grid(True, which="both", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_b, dpi=200)
    plt.close(fig)


def rehash_chart(out: Path) -> None:
    rows = [load(f"rehash5_jobs{j}.json")[0] for j in (1, 2, 4, 8)]
    jobs = [1, 2, 4, 8]
    wall = [r["wall_seconds"] for r in rows]
    fig, ax = plt.subplots(figsize=(4.2, 2.8))
    bars = ax.bar([str(j) for j in jobs], wall, color="#2b6cb0")
    for b, w in zip(bars, wall):
        ax.text(b.get_x() + b.get_width() / 2, w, f"{w:.2f}s\n{wall[0] / w:.1f}x", ha="center", va="bottom", fontsize=8)
    ax.set_xlabel("Worker processes")
    ax.set_ylabel("Re-hash wall time (s)")
    ax.set_ylim(0, max(wall) * 1.3)
    ax.set_title("Re-hashing 10,000 files (625 MiB)", fontsize=9)
    fig.tight_layout()
    fig.savefig(out, dpi=200)


def storage_chart(out: Path) -> None:
    rows = load("storage_overhead_v3.json")
    rows = rows["results"] if isinstance(rows, dict) else rows
    keys = list(rows[0])
    count_k = next(k for k in keys if "count" in k or "record" in k)
    plain_k = next(k for k in keys if "plain" in k and "bytes" in k)
    enc_k = next(k for k in keys if "enc" in k and "bytes" in k)
    x = range(len(rows))
    fig, ax = plt.subplots(figsize=(4.2, 2.8))
    ax.bar([i - 0.2 for i in x], [r[plain_k] / 1024 for r in rows], 0.4, label="Plaintext JSON", color="#2b6cb0")
    ax.bar([i + 0.2 for i in x], [r[enc_k] / 1024 for r in rows], 0.4, label="AES-256-GCM SQLite", color="#dd6b20")
    ax.set_xticks(list(x), [str(r[count_k]) for r in rows])
    ax.set_xlabel("Records")
    ax.set_ylabel("Size (KB)")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(out, dpi=200)


if __name__ == "__main__":
    out = R / "figures"
    out.mkdir(exist_ok=True)
    scale = median_runs([load(f"performance_scale_v5_run{i}.json") for i in (1, 2, 3)])
    (R / "performance_scale_v5_median.json").write_text(json.dumps(scale, indent=2), encoding="utf-8")
    scale_charts(scale, out / "fig_scale_a.png", out / "fig_scale_b.png")
    rehash_chart(out / "fig_rehash.png")
    try:
        storage_chart(out / "fig_storage.png")
    except Exception as exc:  # the JSON layout is only checked here, by running it
        print("storage chart skipped:", exc)
    print("wrote", sorted(p.name for p in out.iterdir()))
