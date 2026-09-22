"""Merkle tree construction and inclusion-proof generation/verification.

Odd levels are handled by duplicating the last node (Bitcoin-style), which
keeps the implementation simple and deterministic. Leaves are pre-hashed
(hex-encoded SHA-256 digests) by the caller (see ``hashing.hash_file``).
"""

from __future__ import annotations

from dataclasses import dataclass

from .hashing import hash_hex_pair


@dataclass(frozen=True)
class ProofStep:
    """One step of a Merkle inclusion proof: a sibling hash and its side."""

    sibling: str
    is_left: bool  # True if the sibling belongs on the left of the pair


class MerkleTree:
    """A Merkle tree over an ordered list of leaf hashes."""

    def __init__(self, leaves: list[str]):
        if not leaves:
            raise ValueError("Merkle tree requires at least one leaf")
        self.leaves: list[str] = list(leaves)
        self.levels: list[list[str]] = self._build_levels(self.leaves)

    @staticmethod
    def _build_levels(leaves: list[str]) -> list[list[str]]:
        levels = [leaves]
        current = leaves
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                next_level.append(hash_hex_pair(left, right))
            levels.append(next_level)
            current = next_level
        return levels

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def get_proof(self, leaf_index: int) -> list[ProofStep]:
        """Build an inclusion proof for the leaf at ``leaf_index``."""
        if not (0 <= leaf_index < len(self.leaves)):
            raise IndexError(f"leaf_index {leaf_index} out of range")

        proof: list[ProofStep] = []
        index = leaf_index
        for level in self.levels[:-1]:
            is_right_node = index % 2 == 1
            sibling_index = index - 1 if is_right_node else index + 1
            if sibling_index >= len(level):
                sibling_index = index  # odd level: duplicated last node
            sibling = level[sibling_index]
            proof.append(ProofStep(sibling=sibling, is_left=is_right_node))
            index //= 2
        return proof


def verify_proof(leaf: str, proof: list[ProofStep], root: str) -> bool:
    """Recompute the root from ``leaf`` and ``proof`` and compare to ``root``."""
    computed = leaf
    for step in proof:
        if step.is_left:
            computed = hash_hex_pair(step.sibling, computed)
        else:
            computed = hash_hex_pair(computed, step.sibling)
    return computed == root


def proof_to_dict(proof: list[ProofStep]) -> list[dict]:
    return [{"sibling": s.sibling, "is_left": s.is_left} for s in proof]


def proof_from_dict(data: list[dict]) -> list[ProofStep]:
    return [ProofStep(sibling=d["sibling"], is_left=bool(d["is_left"])) for d in data]


@dataclass(frozen=True)
class NestedProof:
    """A two-hop inclusion proof: file leaf -> subtree root -> main root.

    For evidence that isn't part of a folder batch, ``subtree_root`` equals
    the main root and ``folder_proof`` is empty -- the single-tree case is a
    literal degenerate nested proof, not a separate format.
    """

    local_proof: list[ProofStep]
    subtree_root: str
    folder_proof: list[ProofStep]


def build_nested_proof(
    local_tree: MerkleTree,
    local_index: int,
    folder_tree: MerkleTree | None,
    folder_index: int | None,
) -> NestedProof:
    """Build a proof for ``local_tree``'s leaf, optionally nested under ``folder_tree``.

    Pass ``folder_tree=None`` when the leaf isn't part of a folder batch --
    ``local_tree`` is then the main tree itself.
    """
    local_proof = local_tree.get_proof(local_index)
    if folder_tree is None:
        return NestedProof(local_proof=local_proof, subtree_root=local_tree.root, folder_proof=[])
    folder_proof = folder_tree.get_proof(folder_index)
    return NestedProof(local_proof=local_proof, subtree_root=local_tree.root, folder_proof=folder_proof)


def verify_nested_proof(leaf: str, proof: NestedProof, root: str) -> bool:
    """Recompute both hops from ``leaf`` and ``proof`` and compare to ``root``."""
    if not verify_proof(leaf, proof.local_proof, proof.subtree_root):
        return False
    if not proof.folder_proof:
        return proof.subtree_root == root
    return verify_proof(proof.subtree_root, proof.folder_proof, root)


def nested_proof_to_dict(proof: NestedProof) -> dict:
    return {
        "local_proof": proof_to_dict(proof.local_proof),
        "subtree_root": proof.subtree_root,
        "folder_proof": proof_to_dict(proof.folder_proof),
    }


def nested_proof_from_dict(data: dict) -> NestedProof:
    return NestedProof(
        local_proof=proof_from_dict(data["local_proof"]),
        subtree_root=data["subtree_root"],
        folder_proof=proof_from_dict(data["folder_proof"]),
    )
