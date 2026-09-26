import json
import subprocess
import sys
from pathlib import Path

from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain
from vcoc.merkle import MerkleTree, build_nested_proof, nested_proof_to_dict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verifier as verifier_module

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


def test_verifier_canonical_payload_matches_models_for_legacy_entry():
    """verifier.py's independent canonical_payload() must agree with
    CustodyEvent.canonical_payload() for a legacy single-evidence_id entry --
    verifier.py deliberately reimplements this from scratch (no import of
    vcoc), so the two must be kept in lockstep by hand.
    """
    from vcoc.models import CustodyEvent

    event = CustodyEvent(
        index=0,
        evidence_id="EV001",
        actor="J. Doe",
        action="collected",
        timestamp="2026-09-22T00:00:00+00:00",
        prev_hash="0" * 64,
    )
    assert verifier_module.canonical_payload(event.to_dict()) == event.canonical_payload()


def test_verifier_canonical_payload_matches_models_for_new_shape_entry():
    from vcoc.models import CustodyEvent

    event = CustodyEvent(
        index=0,
        evidence_id="",
        evidence_ids=["EV001", "EV002"],
        actor="J. Doe",
        action="seized",
        timestamp="2026-09-22T00:00:00+00:00",
        prev_hash="0" * 64,
        case_number="C-001",
        tag="disk+memory",
        notes="seized together",
    )
    assert verifier_module.canonical_payload(event.to_dict()) == event.canonical_payload()


def test_verifier_verify_chain_agrees_with_hashchain_on_mixed_shape_chain(tmp_path):
    """Cross-check: build a mixed-shape (legacy + new-shape) chain via
    HashChain, save it, and confirm verifier.py's independent verify_chain
    accepts it -- proving the two implementations compute identical hashes
    for every entry shape, not just the legacy one.
    """
    signing_key, verifying_key = generate_keypair()
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(
        evidence_ids=["EV002", "EV003"],
        actor="J. Doe",
        action="seized",
        signing_key=signing_key,
        case_number="C-001",
        tag="disk+memory",
    )
    chain.add_event(evidence_id="EV004", actor="A. Smith", action="reviewed", signing_key=signing_key)

    entries = json.loads(chain.to_json())
    ok, break_index, reason = verifier_module.verify_chain(entries, verifying_key)
    assert ok, f"verifier.py disagreed with HashChain: break_index={break_index}, reason={reason}"
    assert break_index is None


def test_verifier_verify_each_agrees_with_hashchain_verify_each():
    """Cross-check: verifier.py's independent verify_each() agrees with
    HashChain.verify_each() on both clean and tampered chains -- Task 27's
    interactive Chain tab uses verifier.py's version, so it must not
    silently diverge from the logging tool's own implementation."""
    signing_key, verifying_key = generate_keypair()
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(evidence_id="EV002", actor="A. Smith", action="reviewed", signing_key=signing_key)
    chain.add_event(evidence_id="EV003", actor="A. Smith", action="transferred", signing_key=signing_key)
    chain.entries[1].actor = "Mallory"

    entries = json.loads(chain.to_json())
    hashchain_results = chain.verify_each(verifying_key)
    verifier_results = verifier_module.verify_each(entries, verifying_key)

    assert len(hashchain_results) == len(verifier_results)
    for hc, vf in zip(hashchain_results, verifier_results):
        assert hc.index == vf.index
        assert hc.ok == vf.ok


def test_standalone_verifier_cli_verifies_multi_evidence_entry(tmp_path):
    """Real end-to-end: python verifier.py against a log containing a
    new-shape (multi-evidence) entry -- no KeyError, no false tamper report.
    """
    signing_key, _ = generate_keypair()
    priv_path, pub_path = tmp_path / "priv.pem", tmp_path / "pub.pem"
    save_keypair(signing_key, priv_path, pub_path)

    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(
        evidence_ids=["EV002", "EV003"],
        actor="J. Doe",
        action="seized",
        signing_key=signing_key,
        case_number="C-001",
    )
    log_path = tmp_path / "log.json"
    chain.save(log_path)

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "verifier.py"), "--log", str(log_path), "--public-key", str(pub_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout
