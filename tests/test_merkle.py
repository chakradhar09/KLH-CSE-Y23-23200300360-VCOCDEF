import pytest

from vcoc.hashing import hash_bytes
from vcoc.merkle import MerkleTree, proof_from_dict, proof_to_dict, verify_proof


def leaves(n: int) -> list[str]:
    return [hash_bytes(f"leaf-{i}".encode()) for i in range(n)]


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 8, 13])
def test_every_leaf_has_a_valid_proof(n):
    tree = MerkleTree(leaves(n))
    for i in range(n):
        proof = tree.get_proof(i)
        assert verify_proof(tree.leaves[i], proof, tree.root)


def test_tampered_leaf_fails_proof():
    tree = MerkleTree(leaves(5))
    proof = tree.get_proof(2)
    fake_leaf = hash_bytes(b"not-the-real-leaf")
    assert not verify_proof(fake_leaf, proof, tree.root)


def test_tampered_root_fails_proof():
    tree = MerkleTree(leaves(5))
    proof = tree.get_proof(2)
    fake_root = hash_bytes(b"not-the-real-root")
    assert not verify_proof(tree.leaves[2], proof, fake_root)


def test_proof_index_out_of_range_raises():
    tree = MerkleTree(leaves(3))
    with pytest.raises(IndexError):
        tree.get_proof(10)


def test_empty_tree_raises():
    with pytest.raises(ValueError):
        MerkleTree([])


def test_proof_serialization_round_trip():
    tree = MerkleTree(leaves(6))
    proof = tree.get_proof(4)
    round_tripped = proof_from_dict(proof_to_dict(proof))
    assert verify_proof(tree.leaves[4], round_tripped, tree.root)
