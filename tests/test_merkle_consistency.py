"""Consistency proofs: a short proof that the tree of the first m leaves is a prefix of the tree of n leaves (RFC 6962
section 2.1.2 to generate, RFC 9162 section 2.1.4 to verify). The reference below is written from the RFC text, not from
the module under test; vcoc.merkle and the standalone verifier.py must both agree with it."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import verifier
from vcoc.merkle import MerkleTree, verify_consistency


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _mth(leaves: list[bytes]) -> bytes:
    """RFC 6962 section 2.1: the Merkle tree hash."""
    n = len(leaves)
    if n == 1:
        return _h(b"\x00" + leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return _h(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:]))


def _subproof(m: int, leaves: list[bytes], complete: bool) -> list[bytes]:
    """RFC 6962 section 2.1.2: SUBPROOF(m, D[n], b)."""
    n = len(leaves)
    if m == n:
        return [] if complete else [_mth(leaves)]
    k = 1
    while k * 2 < n:
        k *= 2
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [_mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [_mth(leaves[:k])]


def _digests(n: int) -> list[str]:
    return [_h(f"entry-{i}".encode()).hex() for i in range(n)]


def _reference(m: int, digests: list[str]) -> list[str]:
    return [x.hex() for x in _subproof(m, [bytes.fromhex(d) for d in digests], True)]


def _both(m, n, root_m, root_n, proof) -> tuple[bool, bool]:
    return (
        verify_consistency(m, n, root_m, root_n, proof),
        verifier.verify_consistency(m, n, root_m, root_n, proof),
    )


SIZES = range(1, 65)


@pytest.mark.parametrize("n", SIZES)
def test_the_proof_and_the_prefix_roots_match_the_rfc_reference_for_every_prefix(n):
    digests = _digests(n)
    tree = MerkleTree(digests)

    for m in range(1, n + 1):
        assert tree.consistency_proof(m) == _reference(m, digests), (m, n)
        assert tree.root_at(m) == _mth([bytes.fromhex(d) for d in digests[:m]]).hex(), (m, n)
    assert tree.root_at(n) == tree.root


@pytest.mark.parametrize("n", SIZES)
def test_every_proof_verifies_in_the_library_and_in_the_verifier(n):
    tree = MerkleTree(_digests(n))

    for m in range(1, n + 1):
        proof = tree.consistency_proof(m)
        assert _both(m, n, tree.root_at(m), tree.root, proof) == (True, True), (m, n)


@pytest.mark.parametrize("m, n, steps", [(1, 1, 0), (8, 8, 0), (1, 2, 1), (3, 7, 4), (6, 8, 3)])
def test_proof_lengths_are_the_ones_the_rfc_gives(m, n, steps):
    assert len(MerkleTree(_digests(n)).consistency_proof(m)) == steps


@pytest.mark.parametrize("n", [2, 3, 5, 8, 11, 16, 20])
def test_anything_but_the_genuine_proof_and_roots_fails(n):
    digests = _digests(n)
    tree = MerkleTree(digests)
    wrong = _h(b"not a root").hex()

    for m in range(1, n):
        proof, root_m = tree.consistency_proof(m), tree.root_at(m)
        assert _both(m, n, wrong, tree.root, proof) == (False, False), ("old root", m, n)
        assert _both(m, n, root_m, wrong, proof) == (False, False), ("new root", m, n)
        assert _both(m, n, root_m, tree.root, proof[:-1]) == (False, False), ("truncated", m, n)
        assert _both(m, n, root_m, tree.root, proof + [wrong]) == (False, False), ("extended", m, n)
        assert _both(m, n, root_m, tree.root, []) == (False, False), ("missing", m, n)
        assert _both(n, m, tree.root, root_m, proof) == (False, False), ("sizes swapped", m, n)
        for i in range(len(proof)):
            mutated = proof[:i] + [wrong] + proof[i + 1 :]
            assert _both(m, n, root_m, tree.root, mutated) == (False, False), ("mutated", i, m, n)
        # Not asserted: a wrong `new_size`. A root does not encode its tree size (a proof for 3 leaves also verifies as one
        # for 4), so the size has to be authenticated by something else. In a checkpoint it is: the custodian signs
        # (size, root) together and the verifier rebuilds the root over the first `size` entries (tests/test_checkpoint.py).


def test_a_proof_for_a_different_log_does_not_verify():
    mine, other = MerkleTree(_digests(10)), MerkleTree([_h(f"other-{i}".encode()).hex() for i in range(10)])

    proof = other.consistency_proof(4)

    assert _both(4, 10, mine.root_at(4), mine.root, proof) == (False, False)


def test_a_rewritten_history_cannot_be_proved_consistent_with_the_old_root():
    old = MerkleTree(_digests(6))
    rewritten = _digests(10)
    rewritten[2] = _h(b"forged").hex()  # entry 2 changed, then the log grew
    new = MerkleTree(rewritten)

    proof = new.consistency_proof(6)

    assert _both(6, 10, old.root, new.root, proof) == (False, False)


def test_the_same_size_needs_an_empty_proof_and_equal_roots():
    tree = MerkleTree(_digests(7))

    assert _both(7, 7, tree.root, tree.root, []) == (True, True)
    assert _both(7, 7, tree.root, tree.root, [tree.root]) == (False, False)
    assert _both(7, 7, tree.root, _h(b"x").hex(), []) == (False, False)


@pytest.mark.parametrize("m", [0, -1, 9])
def test_impossible_sizes_are_rejected(m):
    tree = MerkleTree(_digests(8))

    with pytest.raises(ValueError):
        tree.consistency_proof(m)
    assert _both(m, 8, tree.root, tree.root, []) == (False, False)


def test_root_at_rejects_sizes_outside_the_tree():
    tree = MerkleTree(_digests(5))

    for size in (0, 6):
        with pytest.raises(ValueError):
            tree.root_at(size)


def test_garbage_in_a_proof_is_a_failed_check_not_a_crash():
    tree = MerkleTree(_digests(9))
    proof = tree.consistency_proof(4)

    assert _both(4, 9, tree.root_at(4), tree.root, ["zz"] + proof[1:]) == (False, False)
    assert _both(4, 9, tree.root_at(4), tree.root, [""] + proof[1:]) == (False, False)
