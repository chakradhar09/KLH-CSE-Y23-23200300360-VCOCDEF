"""The Merkle tree follows RFC 6962: prefixed leaf and node hashes, and a lone node moves up instead of being paired with
itself. Checked against the spec written out independently, in vcoc.merkle and in the standalone verifier.py."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import verifier
from vcoc.merkle import (
    MERKLE_FORMAT,
    MerkleRootBuilder,
    MerkleTree,
    ProofStep,
    leaf_hash,
    merkle_proof_stream,
    node_hash,
    proof_to_dict,
    verify_proof,
)


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _mth(leaves: list[bytes]) -> bytes:
    """RFC 6962 section 2.1 as written there: split at the largest power of two smaller than n."""
    n = len(leaves)
    if n == 1:
        return _h(b"\x00" + leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return _h(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:]))


def _digests(n: int) -> list[str]:
    return [_h(f"file-{i}".encode()).hex() for i in range(n)]


@pytest.mark.parametrize("n", range(1, 41))
def test_every_implementation_gives_the_rfc_6962_root(n):
    leaves = _digests(n)
    expected = _mth([bytes.fromhex(x) for x in leaves]).hex()

    builder = MerkleRootBuilder()
    for leaf in leaves:
        builder.add(leaf)

    assert MerkleTree(leaves).root == expected
    assert builder.root() == expected
    assert verifier.merkle_root(leaves) == expected
    assert merkle_proof_stream(((i, leaf) for i, leaf in enumerate(leaves)), 0)[3] == expected


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 16, 17, 33])
def test_every_proof_verifies_in_the_library_and_in_the_verifier(n):
    leaves = _digests(n)
    tree = MerkleTree(leaves)
    for index, leaf in enumerate(leaves):
        proof = tree.get_proof(index)
        assert verify_proof(leaf, proof, tree.root)
        assert verifier.verify_merkle_proof(leaf, proof_to_dict(proof), tree.root)
        streamed = merkle_proof_stream(((i, x) for i, x in enumerate(leaves)), index)
        assert (streamed[0], streamed[1], streamed[2], streamed[3]) == (index, leaf, proof, tree.root)


@pytest.mark.parametrize("n, index, steps", [(3, 2, 1), (5, 4, 1), (7, 6, 2), (6, 5, 2), (4, 3, 2), (1, 0, 0)])
def test_a_lone_last_leaf_has_no_proof_step_at_the_level_where_it_moves_up(n, index, steps):
    assert len(MerkleTree(_digests(n)).get_proof(index)) == steps


@pytest.mark.parametrize("n", range(1, 13))
def test_repeating_the_last_leaf_changes_the_root(n):
    """Before the fix [a, b, c] and [a, b, c, c] had the same root (the Bitcoin CVE-2012-2459 shape)."""
    leaves = _digests(n)
    longer = leaves + [leaves[-1]]

    assert MerkleTree(leaves).root != MerkleTree(longer).root
    assert verifier.merkle_root(leaves) != verifier.merkle_root(longer)


def test_a_node_cannot_be_passed_off_as_a_leaf():
    """Before the fix a 64-byte file holding two leaf digests hashed to the node above them, and verified as a leaf."""
    leaves = _digests(4)
    tree = MerkleTree(leaves)
    fake_file = bytes.fromhex(leaves[0]) + bytes.fromhex(leaves[1])
    fake_digest = hashlib.sha256(fake_file).hexdigest()
    shortened_proof = [ProofStep(sibling=tree.levels[1][1], is_left=False)]  # the path from that node up to the root

    assert not verify_proof(fake_digest, shortened_proof, tree.root)
    assert not verifier.verify_merkle_proof(fake_digest, proof_to_dict(shortened_proof), tree.root)
    assert leaf_hash(fake_digest) != tree.levels[1][0]


def test_leaf_and_node_hashes_are_in_different_domains():
    a, b = _digests(2)

    assert leaf_hash(a) == _h(b"\x00" + bytes.fromhex(a)).hex()
    assert node_hash(a, b) == _h(b"\x01" + bytes.fromhex(a) + bytes.fromhex(b)).hex()
    assert node_hash(a, b) != leaf_hash(a + b)
    assert node_hash(a, b) != node_hash(b, a)


def test_the_verifier_and_the_library_agree_on_the_primitives_and_the_format():
    a, b = _digests(2)

    assert verifier.leaf_hash(a) == leaf_hash(a)
    assert verifier.node_hash(a, b) == node_hash(a, b)
    assert verifier.MERKLE_FORMAT == MERKLE_FORMAT == 2
