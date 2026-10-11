#!/usr/bin/env python3
"""Attack scenarios and costs for witness-cosigned checkpoints.

Every scenario drives the real code: `witness.main` for what a witness will cosign and `verifier.main` for what a verifier
accepts, on files in a temporary folder. The attacker in most scenarios holds the custodian's signing key (the case the hash
chain alone cannot see). Scenarios the design does not stop are reported as limits, not left out.

    python scripts/witness_scenarios.py [--out report.json] [--sizes 1000 10000 100000]
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

import verifier  # noqa: E402
import witness  # noqa: E402
from vcoc import checkpoint as checkpoint_module  # noqa: E402
from vcoc.ecdsa_signer import generate_keypair, save_keypair  # noqa: E402
from vcoc.hash_chain import HashChain, utc_now_iso  # noqa: E402
from vcoc.merkle import MerkleTree, verify_consistency  # noqa: E402

EVIDENCE_ITEMS = 6
HONEST_SIZE, CHECKPOINT_SIZE = 8, 6  # the log has 8 entries; the witnessed checkpoint covers the first 6


def _quiet(func, argv: list[str]) -> tuple[int, str]:
    """Run a main() that prints and may sys.exit: (exit code, what it printed)."""
    out, code = io.StringIO(), 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            func(argv)
        except SystemExit as exc:
            code = exc.code or 0
    return code, out.getvalue()


def _line(output: str, *starts: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in lines:
        if line.startswith(starts):
            return line
    return lines[-1] if lines else ""


class Env:
    """One custodian, two witnesses, and a small evidence set, in a folder."""

    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.key, _ = generate_keypair()
        save_keypair(self.key, self.dir / "c.pem", self.dir / "c.pub")
        self.witness_keys = {}
        for name in ("w1", "w2"):
            key, _ = generate_keypair()
            save_keypair(key, self.dir / f"{name}.pem", self.dir / f"{name}.pub")
            self.witness_keys[name] = key
        (self.dir / "evidence").mkdir(exist_ok=True)
        self.index = {}
        for i in range(EVIDENCE_ITEMS):
            path = self.dir / "evidence" / f"EV{i}.bin"
            data = f"evidence item {i}".encode()
            path.write_bytes(data)
            self.index[f"EV{i}"] = {
                "original_filename": path.name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "source_path": str(path),
                "size_bytes": len(data),
            }
        self.evidence_root = verifier.merkle_root([self.index[k]["sha256"] for k in sorted(self.index)])

    def build(self, count: int, rewrite_at: int | None = None) -> HashChain:
        """A deterministic custody log signed with the (stolen) custodian key; the entry at `rewrite_at` has another actor."""
        chain = HashChain()
        for i in range(count):
            chain.add_event(
                actor="Mallory" if i == rewrite_at else "J. Doe",
                action="reviewed",
                signing_key=self.key,
                evidence_id=f"EV{i % EVIDENCE_ITEMS}",
                timestamp=f"2026-01-01T00:00:{i:02d}+00:00",
            )
        return chain

    def checkpoint(self, chain: HashChain, name: str, since: int | None = None) -> tuple[Path, Path | None]:
        path = self.dir / name
        checkpoint = checkpoint_module.build_checkpoint(chain, self.key, evidence_root=self.evidence_root)
        path.write_text(json.dumps(checkpoint), encoding="utf-8")
        if since is None:
            return path, None
        proof = self.dir / f"{Path(name).stem}_proof.json"
        proof.write_text(json.dumps(checkpoint_module.consistency_proof_since([e.entry_hash for e in chain.entries], since)), encoding="utf-8")
        return path, proof

    def cosign(self, who: str, checkpoint: Path, out: Path, proof: Path | None = None) -> tuple[int, str]:
        argv = [
            "cosign", "--checkpoint", str(checkpoint), "--state", str(self.dir / f"{who}_state.json"),
            "--key", str(self.dir / f"{who}.pem"), "--log-key", str(self.dir / "c.pub"), "--out", str(out),
        ]  # fmt: skip
        return _quiet(witness.main, argv + (["--proof", str(proof)] if proof else []))

    def verify(self, entries, checkpoint: Path, quorum: int = 2, index: dict | None = None) -> tuple[int, str]:
        entries = [e.to_dict() for e in entries.entries] if isinstance(entries, HashChain) else entries
        log = self.dir / "log_under_test.json"
        log.write_text(json.dumps(entries), encoding="utf-8")
        argv = ["--log", str(log), "--public-key", str(self.dir / "c.pub"), "--checkpoint", str(checkpoint)]
        for name in ("w1", "w2"):
            argv += ["--witness-key", str(self.dir / f"{name}.pub")]
        argv += ["--quorum", str(quorum)]
        if index is not None:
            path = self.dir / "index_under_test.json"
            path.write_text(json.dumps(index), encoding="utf-8")
            argv += ["--evidence-index", str(path)]
        return _quiet(verifier.main, argv)

    def witnessed(self, chain: HashChain, name: str, both: bool = True) -> Path:
        """Checkpoint `chain`, cosigned by witness 1 (and 2). Raises if a witness refuses."""
        checkpoint, _ = self.checkpoint(chain, name)
        first = self.dir / f"{Path(name).stem}_w1.json"
        code, out = self.cosign("w1", checkpoint, first)
        assert code == 0, out
        if not both:
            return first
        final = self.dir / f"{Path(name).stem}_w1w2.json"
        code, out = self.cosign("w2", first, final)
        assert code == 0, out
        return final


def _row(name: str, attack: str, stopped: bool, by: str | None, detail: str) -> dict:
    return {"name": name, "attack": attack, "stopped": stopped, "stopped_by": by, "detail": detail, "limit": not stopped and name != "honest_log"}


def _by_verifier(name: str, attack: str, result: tuple[int, str]) -> dict:
    code, out = result
    if code != 0:
        return _row(name, attack, True, "verifier", _line(out, "TAMPER DETECTED:", "NOT WITNESSED:", "TAMPER DETECTED"))
    return _row(name, attack, False, None, "the verifier accepted it: " + _line(out, "OK: checkpoint cosigned"))


def _by_witness(name: str, attack: str, result: tuple[int, str]) -> dict:
    code, out = result
    if code != 0:
        return _row(name, attack, True, "witness", _line(out, "REFUSED:"))
    return _row(name, attack, False, None, "the witness cosigned it")


def run_scenarios() -> list[dict]:
    rows: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(Path(tmp) / "lab")
        honest = env.build(HONEST_SIZE)
        c6 = env.witnessed(env.build(CHECKPOINT_SIZE), "c6.json")  # intake: both witnesses cosign the first 6 entries
        c6_one = env.dir / "c6_w1.json"
        entries = [e.to_dict() for e in honest.entries]

        code, out = env.verify(honest, c6, index=env.index)
        rows.append(_row(
            "honest_log", "No attack: the honest 8-entry log, its witnessed checkpoint of the first 6 entries, and the evidence index.",
            code != 0, "verifier" if code else None, _line(out, "OK: checkpoint cosigned", "TAMPER", "NOT WITNESSED"),
        ))  # fmt: skip

        rows.append(_by_verifier(
            "stolen_key_rewrite", "Holds the signing key. Rewrites entry 2 and re-signs every later entry, so the chain itself is valid.",
            env.verify(env.build(HONEST_SIZE, rewrite_at=2), c6),
        ))  # fmt: skip
        rows.append(_by_verifier(
            "truncate_below_checkpoint", "Deletes the newest 4 entries, leaving 4: fewer than the witnessed checkpoint covers.",
            env.verify(entries[:4], c6),
        ))  # fmt: skip
        rows.append(_by_verifier(
            "delete_entries_after_checkpoint", "Deletes the 2 entries added after the witnessed checkpoint (back to exactly 6).",
            env.verify(entries[:CHECKPOINT_SIZE], c6),
        ))  # fmt: skip
        rows.append(_by_verifier(
            "rewrite_entries_after_checkpoint", "Holds the key. Rewrites entry 6, which was added after the witnessed checkpoint.",
            env.verify(env.build(HONEST_SIZE, rewrite_at=6), c6),
        ))  # fmt: skip

        fork, _ = env.checkpoint(env.build(CHECKPOINT_SIZE, rewrite_at=3), "fork.json")
        rows.append(_by_witness(
            "fork_shown_to_witness", "Holds the key. Asks a witness to cosign a different history of the same size 6 (entry 3 rewritten).",
            env.cosign("w1", fork, env.dir / "fork_out.json"),
        ))  # fmt: skip
        small, _ = env.checkpoint(env.build(4), "small.json")
        rows.append(_by_witness(
            "rollback_shown_to_witness", "Holds the key. Asks a witness to cosign a checkpoint of only 4 entries, after it has cosigned 6.",
            env.cosign("w1", small, env.dir / "small_out.json"),
        ))  # fmt: skip
        grown, proof = env.checkpoint(env.build(10, rewrite_at=2), "grown.json", since=CHECKPOINT_SIZE)
        rows.append(_by_witness(
            "rewrite_then_grow", "Holds the key. Rewrites entry 2, adds entries up to 10, and supplies a consistency proof from size 6.",
            env.cosign("w1", grown, env.dir / "grown_out.json", proof),
        ))  # fmt: skip

        rewritten = env.build(HONEST_SIZE, rewrite_at=2)
        forged, _ = env.checkpoint(rewritten, "forged.json")
        document = json.loads(forged.read_text(encoding="utf-8"))
        document["cosignatures"] = [
            {"witness_id": verifier.checkpoint_log_id(env.witness_keys[w].verifying_key), "witnessed_at": utc_now_iso(), "signature": "00" * 64}
            for w in ("w1", "w2")
        ]
        forged.write_text(json.dumps(document), encoding="utf-8")
        rows.append(_by_verifier(
            "forged_cosignatures", "Holds the signing key but no witness key. Signs a checkpoint of the rewritten log and attaches made-up cosignatures.",
            env.verify(rewritten, forged),
        ))  # fmt: skip
        rows.append(_by_verifier(
            "one_witness_of_two_required", "A checkpoint that only one of the two required witnesses cosigned.",
            env.verify(honest, c6_one),
        ))  # fmt: skip
        trimmed = {k: v for k, v in env.index.items() if k != "EV5"}
        rows.append(_by_verifier(
            "evidence_removed_from_index", "Removes one evidence record from the index (the custody log is untouched).",
            env.verify(honest, c6, index=trimmed),
        ))  # fmt: skip

        stolen, _ = env.checkpoint(rewritten, "stolen.json")
        document = json.loads(stolen.read_text(encoding="utf-8"))
        document["cosignatures"] = [witness.make_cosignature(env.witness_keys[w], document["body"], utc_now_iso()) for w in ("w1", "w2")]
        stolen.write_text(json.dumps(document), encoding="utf-8")
        row = _by_verifier(
            "witness_keys_also_stolen", "Holds the custodian key and every witness key (a whole quorum). Signs and cosigns the rewritten history itself.",
            env.verify(rewritten, stolen),
        )  # fmt: skip
        rows.append(row)

        rows.append(_before_first_witnessing(Path(tmp) / "late"))
    return rows


def _before_first_witnessing(directory: Path) -> dict:
    """The attacker rewrites history before any witness has seen the log (trust on first use)."""
    env = Env(directory)
    forged_chain = env.build(CHECKPOINT_SIZE, rewrite_at=2)
    forged = env.witnessed(forged_chain, "forged_first.json")
    code, out = env.verify(forged_chain, forged)
    honest_checkpoint, _ = env.checkpoint(env.build(CHECKPOINT_SIZE), "honest_later.json")
    refused_code, refused = env.cosign("w1", honest_checkpoint, env.dir / "honest_later_out.json")
    detail = (
        f"the forged history was cosigned and verified ({_line(out, 'OK: checkpoint cosigned')}); "
        f"the honest custodian's own checkpoint was then refused: {_line(refused, 'REFUSED:')}"
    )
    assert code == 0 and refused_code != 0, (out, refused)
    return _row(
        "rewrite_before_first_witnessing",
        "Holds the key and rewrites entry 2 before any witness has cosigned this log, then gets the rewritten history cosigned.",
        False,
        None,
        detail,
    )


# --- costs -------------------------------------------------------------------------------------------------------------


def _mean_seconds(func, repeats: int) -> float:
    start = time.perf_counter()
    for _ in range(repeats):
        func()
    return (time.perf_counter() - start) / repeats


def measure(n: int) -> dict:
    """What checkpoints and proofs cost for a custody log of `n` entries (entry hashes stand in for real entries: the tree
    and the checkpoint only ever see the hashes)."""
    hashes = [hashlib.sha256(f"entry-{i}".encode()).hexdigest() for i in range(n)]
    half = max(1, n // 2)
    chain = SimpleNamespace(entries=[SimpleNamespace(entry_hash=h) for h in hashes])
    half_chain = SimpleNamespace(entries=chain.entries[:half])
    key, _ = generate_keypair()

    start = time.perf_counter()
    tree = MerkleTree(hashes)
    tree_build = time.perf_counter() - start
    proof = tree.consistency_proof(half)
    old_root = tree.root_at(half)
    start = time.perf_counter()
    verifier.merkle_root(hashes)
    verifier_rebuild = time.perf_counter() - start

    checkpoint = checkpoint_module.build_checkpoint(chain, key)
    cosigned = {**checkpoint, "cosignatures": [witness.make_cosignature(key, checkpoint["body"], utc_now_iso()) for _ in range(2)]}
    proof_document = checkpoint_module.consistency_proof_since(hashes, half)

    latencies = {"first": [], "growth": []}
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        save_keypair(key, directory / "c.pem", directory / "c.pub")
        save_keypair(generate_keypair()[0], directory / "w.pem", directory / "w.pub")
        (directory / "half.json").write_text(json.dumps(checkpoint_module.build_checkpoint(half_chain, key)), encoding="utf-8")
        (directory / "full.json").write_text(json.dumps(checkpoint), encoding="utf-8")
        (directory / "proof.json").write_text(json.dumps(proof_document), encoding="utf-8")
        for run in range(3):  # a fresh witness state each time: first sight, then growth with the proof
            state = directory / f"state{run}.json"
            common = ["--state", str(state), "--key", str(directory / "w.pem"), "--out", str(directory / "out.json")]
            start = time.perf_counter()
            assert _quiet(witness.main, ["cosign", "--checkpoint", str(directory / "half.json"), "--log-key", str(directory / "c.pub"), *common])[0] == 0
            latencies["first"].append(time.perf_counter() - start)
            start = time.perf_counter()
            assert _quiet(witness.main, ["cosign", "--checkpoint", str(directory / "full.json"), "--proof", str(directory / "proof.json"), *common])[0] == 0
            latencies["growth"].append(time.perf_counter() - start)

    return {
        "entries": n,
        "checkpoint_bytes": len(json.dumps(checkpoint)),
        "cosigned_bytes_two_witnesses": len(json.dumps(cosigned)),
        "proof_steps": len(proof),
        "proof_bytes": len(json.dumps(proof_document)),
        "tree_build_ms": tree_build * 1000,
        "proof_generation_us": _mean_seconds(lambda: tree.consistency_proof(half), 200) * 1e6,
        "proof_verification_us": _mean_seconds(lambda: verify_consistency(half, n, old_root, tree.root, proof), 2000) * 1e6,
        "verifier_rebuild_ms": verifier_rebuild * 1000,
        "cosign_first_sight_ms": statistics.median(latencies["first"]) * 1000,
        "cosign_growth_ms": statistics.median(latencies["growth"]) * 1000,
    }


# --- report ------------------------------------------------------------------------------------------------------------


def print_report(rows: list[dict], metrics: list[dict]) -> None:
    print("Scenarios (the attacker holds the custodian's signing key unless stated)")
    print(f"{'scenario':<34}{'result':<24}detail")
    for row in rows:
        result = "(control: accepted)" if row["name"] == "honest_log" else f"stopped by {row['stopped_by']}" if row["stopped"] else "NOT stopped (limit)"
        print(f"{row['name']:<34}{result:<24}{row['detail']}")
    if metrics:
        print("\nCosts per custody-log size (proof from half the size; times are medians or means of repeated calls)")
        header = ("entries", "ckpt B", "cosigned B", "steps", "proof B", "build ms", "gen us", "verify us", "rebuild ms", "cosign1 ms", "cosignG ms")
        print("".join(f"{h:>12}" for h in header))
        for m in metrics:
            values = (m["entries"], m["checkpoint_bytes"], m["cosigned_bytes_two_witnesses"], m["proof_steps"], m["proof_bytes"],
                      f"{m['tree_build_ms']:.1f}", f"{m['proof_generation_us']:.1f}", f"{m['proof_verification_us']:.1f}",
                      f"{m['verifier_rebuild_ms']:.1f}", f"{m['cosign_first_sight_ms']:.1f}", f"{m['cosign_growth_ms']:.1f}")  # fmt: skip
            print("".join(f"{v:>12}" for v in values))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Witness-cosigned checkpoints: attack scenarios and costs")
    parser.add_argument("--out", default=None, help="Write the JSON report to this path")
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000, 10000, 100000], help="Custody-log sizes to measure")
    args = parser.parse_args(argv)

    rows = run_scenarios()
    metrics = [measure(n) for n in args.sizes]
    print_report(rows, metrics)
    if args.out:
        report = {
            "scenarios": rows,
            "metrics": metrics,
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
                "cpus": os.cpu_count(),
                "note": "Run in a fresh process. On the development laptop any process slows by 2-3.5x after ~3 s of sustained CPU work.",
            },
        }
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
