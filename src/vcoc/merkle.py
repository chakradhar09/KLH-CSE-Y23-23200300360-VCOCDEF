
from __future__ import annotations

import hashlib
from dataclasses import dataclass

# The tree is the one of RFC 6962 (Certificate Transparency). A leaf is hashed as SHA-256(0x00 || digest) and an inner node as
# SHA-256(0x01 || left || right), so a node can never be passed off as a leaf (a 64-byte file holding two child digests
# used to hash to the node above them). A lone node at the end of a level moves up unchanged instead of being paired with
# itself, so [a, b, c] and [a, b, c, c] no longer share a root. verifier.py keeps its own copy of these rules.
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
MERKLE_FORMAT = 2  # written into anchors and proof files; roots made under the old rules (no format field) are never compared


def leaf_hash(leaf_hex: str) -> str:
    return hashlib.sha256(LEAF_PREFIX + bytes.fromhex(leaf_hex)).hexdigest()


def node_hash(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256(NODE_PREFIX + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()


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
        current = [leaf_hash(leaf) for leaf in leaves]
        levels = [current]
        while len(current) > 1:
            next_level = [node_hash(current[i], current[i + 1]) for i in range(0, len(current) - 1, 2)]
            if len(current) % 2:
                next_level.append(current[-1])  # the lone last node moves up as it is
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
            if sibling_index < len(level):  # a lone node has no sibling at this level: no step
                proof.append(ProofStep(sibling=level[sibling_index], is_left=is_right_node))
            index //= 2
        return proof

    def _node(self, lo: int, hi: int) -> str:
        """The stored node over leaves [lo, hi). Valid for a complete aligned block, or a range that ends at the last leaf."""
        height = (hi - lo - 1).bit_length()
        return self.levels[height][lo >> height]

    def root_at(self, size: int) -> str:
        """The root this tree had when it held only its first `size` leaves."""
        if not (1 <= size <= len(self.leaves)):
            raise ValueError(f"size {size} is outside 1..{len(self.leaves)}")
        carry: str | None = None
        end = size
        while end:  # the prefix is complete blocks, one per set bit of `size`; fold them from the smallest (right) up
            block = end & -end
            node = self._node(end - block, end)
            carry = node if carry is None else node_hash(node, carry)
            end -= block
        return carry

    def consistency_proof(self, old_size: int) -> list[str]:
        """Hashes that show the tree over the first `old_size` leaves is a prefix of this tree (RFC 6962 section 2.1.2)."""
        if not (1 <= old_size <= len(self.leaves)):
            raise ValueError(f"old_size {old_size} is outside 1..{len(self.leaves)}")

        def sub(m: int, lo: int, hi: int, complete: bool) -> list[str]:
            if m == hi - lo:
                return [] if complete else [self._node(lo, hi)]
            k = 1 << ((hi - lo - 1).bit_length() - 1)  # the largest power of two below the size
            if m <= k:
                return sub(m, lo, lo + k, complete) + [self._node(lo + k, hi)]
            return sub(m - k, lo + k, hi, False) + [self._node(lo, lo + k)]

        return sub(old_size, 0, len(self.leaves), True)


class MerkleRootBuilder:
    """Root of the same tree as MerkleTree, fed one leaf at a time.

    Keeps one pending node per tree level, so memory is O(log n) instead of every level of the tree.
    """

    def __init__(self) -> None:
        self.pending: list[str | None] = []
        self.count = 0

    def add(self, leaf: str) -> None:
        self.count += 1
        node, level = leaf_hash(leaf), 0
        while level < len(self.pending) and self.pending[level] is not None:
            node = node_hash(self.pending[level], node)
            self.pending[level] = None
            level += 1
        if level == len(self.pending):
            self.pending.append(None)
        self.pending[level] = node

    def root(self) -> str:
        if not self.count:
            raise ValueError("Merkle tree requires at least one leaf")
        carry: str | None = None  # the subtrees still open, folded from the smallest (newest) up to the largest
        for left in self.pending:
            if left is not None:
                carry = left if carry is None else node_hash(left, carry)
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
    previous = None  # the (hashed) left leaf of the pair being read
    want_next = False  # the target is a left leaf: its sibling is the next leaf, if there is one
    n = 0
    for key, hex_leaf in items:
        raw = sha(LEAF_PREFIX + bytes.fromhex(hex_leaf)).digest()
        if index is None and key == target_key:
            index, leaf_hex = n, hex_leaf
            if n % 2:
                sibling = previous
            else:
                want_next = True
        elif want_next:
            sibling, want_next = raw, False
        if n % 2:
            level += sha(NODE_PREFIX + previous + raw).digest()
        else:
            previous = raw
        n += 1
    if n == 0:
        raise ValueError("Merkle tree requires at least one leaf")
    if index is None:
        raise KeyError(target_key)
    if n % 2:  # an odd last leaf moves up unchanged
        level += previous
    if n == 1:
        return 0, leaf_hex, [], level.hex()

    proof = []
    if sibling is not None:  # a target that is the lone last leaf has none
        proof.append(ProofStep(sibling=sibling.hex(), is_left=index % 2 == 1))
    position = index >> 1
    while len(level) > 32:
        nodes = len(level) // 32
        is_right = position % 2 == 1
        sibling_at = position - 1 if is_right else position + 1
        if sibling_at < nodes:
            proof.append(ProofStep(sibling=level[sibling_at * 32 : sibling_at * 32 + 32].hex(), is_left=is_right))
        upper = bytearray()
        for i in range(0, nodes - 1, 2):
            upper += sha(NODE_PREFIX + level[i * 32 : i * 32 + 64]).digest()
        if nodes % 2:
            upper += level[(nodes - 1) * 32 : nodes * 32]
        level, position = upper, position >> 1
    return index, leaf_hex, proof, level.hex()


def verify_proof(leaf: str, proof: list[ProofStep], root: str) -> bool:
    computed = leaf_hash(leaf)
    for step in proof:
        if step.is_left:
            computed = node_hash(step.sibling, computed)
        else:
            computed = node_hash(computed, step.sibling)
    return computed == root


def verify_consistency(old_size: int, new_size: int, old_root: str, new_root: str, proof: list[str]) -> bool:
    """True if `proof` shows the tree with `old_root` over `old_size` leaves is a prefix of the tree with `new_root` over
    `new_size` leaves (RFC 9162 section 2.1.4.2). Never raises on a malformed proof: that is just a failed check."""
    if not (1 <= old_size <= new_size):
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if not proof:
        return False
    path = list(proof)
    if old_size & (old_size - 1) == 0:  # an exact power of two: the old root is itself a node of the new tree
        path.insert(0, old_root)
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    try:
        fr = sr = path[0]
        for c in path[1:]:
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                fr, sr = node_hash(c, fr), node_hash(c, sr)
                if not fn & 1:
                    while not fn & 1 and fn != 0:
                        fn >>= 1
                        sn >>= 1
            else:
                sr = node_hash(sr, c)
            fn >>= 1
            sn >>= 1
    except ValueError:  # not hex
        return False
    return fr == old_root and sr == new_root and sn == 0


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
