
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .hashing import hash_hex_pair


@dataclass(frozen=True)
class ProofStep:

    sibling: str
    is_left: bool


class MerkleTree:

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
        if not (0 <= leaf_index < len(self.leaves)):
            raise IndexError(f"leaf_index {leaf_index} out of range")

        proof: list[ProofStep] = []
        index = leaf_index
        for level in self.levels[:-1]:
            is_right_node = index % 2 == 1
            sibling_index = index - 1 if is_right_node else index + 1
            if sibling_index >= len(level):
                sibling_index = index
            sibling = level[sibling_index]
            proof.append(ProofStep(sibling=sibling, is_left=is_right_node))
            index //= 2
        return proof


class MerkleRootBuilder:
    """Root of the same tree as MerkleTree (odd last node paired with itself), fed one leaf at a time.

    Keeps one pending node per tree level, so memory is O(log n) instead of every level of the tree.
    """

    def __init__(self) -> None:
        self.pending: list[str | None] = []
        self.count = 0

    def add(self, leaf: str) -> None:
        self.count += 1
        node, level = leaf, 0
        while level < len(self.pending) and self.pending[level] is not None:
            node = hash_hex_pair(self.pending[level], node)
            self.pending[level] = None
            level += 1
        if level == len(self.pending):
            self.pending.append(None)
        self.pending[level] = node

    def root(self) -> str:
        if not self.count:
            raise ValueError("Merkle tree requires at least one leaf")
        top = max(k for k, p in enumerate(self.pending) if p is not None)
        carry: str | None = None  # the last (odd) node of the level being folded
        for level in range(top + 1):
            left = self.pending[level]
            if carry is None:
                if left is None:
                    continue
                if level == top:
                    return left  # a complete subtree that is the whole tree
                carry = hash_hex_pair(left, left)
            else:
                carry = hash_hex_pair(left if left is not None else carry, carry)
        return carry


def merkle_proof_stream(items, target_key):
    """(index, leaf, proof, root) of the first leaf whose key is `target_key`, from an iterable of (key, leaf_hex).

    Same tree, same proof steps and same root as MerkleTree(...).get_proof(index), but the leaves are only streamed
    through: memory is the current level as raw 32-byte values (about 32 bytes per two leaves) instead of every level as
    hex strings (~113 bytes per node), so a 416,000-leaf folder needs ~7 MB instead of ~95 MB.
    Raises KeyError if no leaf has that key and ValueError if there are no leaves.
    """
    sha = hashlib.sha256
    level = bytearray()  # the nodes of level 1: one hash per pair of leaves
    index = leaf_hex = sibling = None
    previous = None  # the left leaf of the pair being read
    want_next = False  # the target is a left leaf: its sibling is the next leaf (or itself, if it is the last)
    n = 0
    for key, hex_leaf in items:
        raw = bytes.fromhex(hex_leaf)
        if index is None and key == target_key:
            index, leaf_hex = n, hex_leaf
            if n % 2:
                sibling = previous
            else:
                want_next = True
        elif want_next:
            sibling, want_next = raw, False
        if n % 2:
            level += sha(previous + raw).digest()
        else:
            previous = raw
        n += 1
    if n == 0:
        raise ValueError("Merkle tree requires at least one leaf")
    if index is None:
        raise KeyError(target_key)
    if want_next:  # the target is the last leaf and has no right neighbour
        sibling = previous
    if n % 2:  # an odd last leaf is paired with itself
        level += sha(previous + previous).digest()
    if n == 1:
        return 0, leaf_hex, [], leaf_hex

    proof = [ProofStep(sibling=sibling.hex(), is_left=index % 2 == 1)]
    position = index >> 1
    while len(level) > 32:
        nodes = len(level) // 32
        is_right = position % 2 == 1
        sibling_at = position - 1 if is_right else position + 1
        if sibling_at >= nodes:
            sibling_at = position
        proof.append(ProofStep(sibling=level[sibling_at * 32 : sibling_at * 32 + 32].hex(), is_left=is_right))
        upper = bytearray()
        for i in range(0, nodes, 2):
            left = level[i * 32 : i * 32 + 32]
            right = level[(i + 1) * 32 : (i + 1) * 32 + 32] if i + 1 < nodes else left
            upper += sha(left + right).digest()
        level, position = upper, position >> 1
    return index, leaf_hex, proof, level.hex()


def verify_proof(leaf: str, proof: list[ProofStep], root: str) -> bool:
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

    local_proof: list[ProofStep]
    subtree_root: str
    folder_proof: list[ProofStep]


def build_nested_proof(
    local_tree: MerkleTree,
    local_index: int,
    folder_tree: MerkleTree | None,
    folder_index: int | None,
) -> NestedProof:
    local_proof = local_tree.get_proof(local_index)
    if folder_tree is None:
        return NestedProof(local_proof=local_proof, subtree_root=local_tree.root, folder_proof=[])
    folder_proof = folder_tree.get_proof(folder_index)
    return NestedProof(local_proof=local_proof, subtree_root=local_tree.root, folder_proof=folder_proof)


def verify_nested_proof(leaf: str, proof: NestedProof, root: str) -> bool:
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
