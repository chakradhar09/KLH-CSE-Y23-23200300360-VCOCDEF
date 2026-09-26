"""Tests for verifier.py's evidence-index verification (re-hash, custody-log
cross-check, Merkle root) -- the standalone verifier's independent checks."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli as cli_module
from vcoc.merkle import verify_nested_proof
from verifier import (
    EvidenceCheckResult,
    merkle_root,
    sha256_hex,
    verify_evidence_index,
    verify_merkle_proof,
    verify_nested_proof as verifier_verify_nested_proof,
)


def test_verify_evidence_index_match_and_logged(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")
    digest = sha256_hex(b"hello")
    index = {
        "EV001": {
            "original_filename": "a.bin",
            "sha256": digest,
            "source_path": str(f),
        }
    }
    entries = [{"evidence_id": "EV001", "index": 0}]

    results, root = verify_evidence_index(index, entries)
    assert len(results) == 1
    r = results[0]
    assert r.rehash_status == "match"
    assert r.logged_status == "logged"
    assert r.ok
    assert root == digest  # single-leaf tree: root == the leaf itself


def test_verify_evidence_index_logged_via_multi_evidence_event(tmp_path):
    """An evidence record covered only by a new-shape (evidence_ids) custody
    entry must be recognized as logged, not flagged NOT LOGGED."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")
    digest = sha256_hex(b"hello")
    index = {
        "EV001": {
            "original_filename": "a.bin",
            "sha256": digest,
            "source_path": str(f),
        }
    }
    entries = [{"evidence_ids": ["EV001", "EV002"], "index": 0}]

    results, _ = verify_evidence_index(index, entries)
    assert results[0].logged_status == "logged"


def test_verify_evidence_index_mismatch_detected(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")
    index = {
        "EV001": {
            "original_filename": "a.bin",
            "sha256": sha256_hex(b"different"),
            "source_path": str(f),
        }
    }
    results, _ = verify_evidence_index(index, [])
    assert results[0].rehash_status == "MISMATCH"
    assert not results[0].ok


def test_verify_evidence_index_not_logged_flagged():
    index = {
        "EV001": {"original_filename": "a.bin", "sha256": "a" * 64, "source_path": ""},
    }
    results, _ = verify_evidence_index(index, [])
    assert results[0].logged_status == "NOT LOGGED"
    assert results[0].rehash_status == "no source_path recorded"
    assert not results[0].ok  # not logged fails ok even though rehash is benign


def test_verify_evidence_index_missing_file_not_treated_as_tamper():
    index = {
        "EV001": {
            "original_filename": "a.bin",
            "sha256": "a" * 64,
            "source_path": "/nonexistent/path/a.bin",
        }
    }
    entries = [{"evidence_id": "EV001"}]
    results, _ = verify_evidence_index(index, entries)
    assert results[0].rehash_status == "not found"
    assert results[0].ok  # not found + logged is not itself tamper


def test_verify_evidence_index_empty_index_no_root():
    results, root = verify_evidence_index({}, [])
    assert results == []
    assert root is None


def test_merkle_root_matches_two_leaf_hash_pairing():
    leaves = [sha256_hex(b"a"), sha256_hex(b"b")]
    root = merkle_root(leaves)
    expected = sha256_hex(bytes.fromhex(leaves[0]) + bytes.fromhex(leaves[1]))
    assert root == expected


def test_merkle_root_rejects_empty():
    import pytest

    with pytest.raises(ValueError):
        merkle_root([])


def test_verifier_own_nested_proof_verifies_degenerate_case():
    """verifier.py's own verify_nested_proof, independent of vcoc.merkle,
    must accept the same degenerate (no-folder) proof shape cli.py emits."""
    from vcoc.merkle import build_nested_proof, MerkleTree, nested_proof_to_dict

    tree = MerkleTree([sha256_hex(b"a"), sha256_hex(b"b"), sha256_hex(b"c")])
    proof = build_nested_proof(tree, 1, None, None)
    proof_dict = nested_proof_to_dict(proof)

    assert verifier_verify_nested_proof(tree.leaves[1], proof_dict, tree.root)


def test_verifier_own_nested_proof_verifies_two_hop_case():
    from vcoc.merkle import build_nested_proof, MerkleTree, nested_proof_to_dict

    folder_tree = MerkleTree([sha256_hex(b"x"), sha256_hex(b"y")])
    main_tree = MerkleTree([folder_tree.root, sha256_hex(b"z")])
    proof = build_nested_proof(folder_tree, 0, main_tree, 0)
    proof_dict = nested_proof_to_dict(proof)

    assert verifier_verify_nested_proof(folder_tree.leaves[0], proof_dict, main_tree.root)


def test_verifier_own_nested_proof_rejects_tampered_leaf():
    from vcoc.merkle import build_nested_proof, MerkleTree, nested_proof_to_dict

    tree = MerkleTree([sha256_hex(b"a"), sha256_hex(b"b"), sha256_hex(b"c")])
    proof = build_nested_proof(tree, 1, None, None)
    proof_dict = nested_proof_to_dict(proof)

    assert not verifier_verify_nested_proof(sha256_hex(b"not-the-real-leaf"), proof_dict, tree.root)


def test_verify_evidence_index_groups_folder_batch_into_single_root(tmp_path):
    """A folder-registered evidence set must recompute the same grouped root
    verifier.py and cli.py's _build_main_tree independently agree on."""
    monkey_cwd = tmp_path
    import os

    old_cwd = os.getcwd()
    os.chdir(monkey_cwd)
    try:
        folder = monkey_cwd / "batchdir"
        folder.mkdir()
        (folder / "a.txt").write_bytes(b"a-content")
        (folder / "b.txt").write_bytes(b"b-content")
        (monkey_cwd / "solo.bin").write_bytes(b"solo-content")

        import argparse

        cli_module.cmd_add_evidence(
            argparse.Namespace(
                file=str(folder),
                evidence_id="BATCH1",
                evidence_index="evidence_index.json",
                folder_index="folder_index.json",
                log="custody_log.json",
                private_key=None,
                actor=None,
            )
        )
        cli_module.cmd_add_evidence(
            argparse.Namespace(
                file=str(monkey_cwd / "solo.bin"),
                evidence_id="SOLO1",
                evidence_index="evidence_index.json",
                folder_index="folder_index.json",
                log="custody_log.json",
                private_key=None,
                actor=None,
            )
        )

        evidence_index = cli_module._load_evidence_index("evidence_index.json")
        folder_index = cli_module._load_folder_index("folder_index.json")
        cli_tree, _ = cli_module._build_main_tree(evidence_index, folder_index)

        _, verifier_root = verify_evidence_index(evidence_index, [], folder_index=folder_index)
    finally:
        os.chdir(old_cwd)

    assert verifier_root == cli_tree.root
