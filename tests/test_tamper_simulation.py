import json
import subprocess
import sys
from pathlib import Path

from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain
from vcoc.merkle import MerkleTree, build_nested_proof, nested_proof_to_dict

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_tamper_simulation_script_detects_all_scenarios(tmp_path):
    out_path = tmp_path / "results.json"
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "tamper_simulation.py"), "--out", str(out_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["baseline_clean_chain_verified"] is True
    assert data["all_tamper_scenarios_detected"] is True
    assert len(data["scenarios"]) == 4
    for scenario in data["scenarios"]:
        assert scenario["detected"] is True
        assert scenario["reported_break_index"] == scenario["target_index"]


def test_standalone_verifier_cli_accepts_clean_chain(tmp_path):
    signing_key, _ = generate_keypair()
    priv_path, pub_path = tmp_path / "priv.pem", tmp_path / "pub.pem"
    save_keypair(signing_key, priv_path, pub_path)

    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(evidence_id="EV001", actor="A. Smith", action="reviewed", signing_key=signing_key)
    log_path = tmp_path / "log.json"
    chain.save(log_path)

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "verifier.py"), "--log", str(log_path), "--public-key", str(pub_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "OK" in result.stdout


def test_standalone_verifier_cli_rejects_tampered_chain(tmp_path):
    signing_key, _ = generate_keypair()
    priv_path, pub_path = tmp_path / "priv.pem", tmp_path / "pub.pem"
    save_keypair(signing_key, priv_path, pub_path)

    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(evidence_id="EV001", actor="A. Smith", action="reviewed", signing_key=signing_key)

    raw = json.loads(chain.to_json())
    raw[1]["actor"] = "Mallory"
    log_path = tmp_path / "log.json"
    log_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "verifier.py"), "--log", str(log_path), "--public-key", str(pub_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    assert "TAMPER DETECTED" in result.stdout
    assert "#1" in result.stdout


def test_standalone_verifier_cli_checks_merkle_proof(tmp_path):
    signing_key, _ = generate_keypair()
    priv_path, pub_path = tmp_path / "priv.pem", tmp_path / "pub.pem"
    save_keypair(signing_key, priv_path, pub_path)

    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    log_path = tmp_path / "log.json"
    chain.save(log_path)

    leaves = ["a" * 64, "b" * 64, "c" * 64]
    tree = MerkleTree(leaves)
    # No folder batch involved: build_nested_proof(..., folder_tree=None) is
    # the degenerate single-tree case (subtree_root == root, folder_proof == []),
    # exercising the real nested-proof format end to end through verifier.py.
    proof = build_nested_proof(tree, 1, None, None)
    proof_path = tmp_path / "proof.json"
    proof_path.write_text(
        json.dumps(
            {"evidence_id": "EV_B", "leaf": leaves[1], "root": tree.root, "proof": nested_proof_to_dict(proof)},
            indent=2,
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "verifier.py"),
            "--log",
            str(log_path),
            "--public-key",
            str(pub_path),
            "--merkle-proof",
            str(proof_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "Merkle inclusion proof" in result.stdout
