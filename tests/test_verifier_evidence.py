"""Tests for verifier.py's evidence-index verification (re-hash, custody-log
cross-check, Merkle root) -- the standalone verifier's independent checks."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier import EvidenceCheckResult, merkle_root, sha256_hex, verify_evidence_index


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
