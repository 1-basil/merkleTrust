"""core/merkle.py — Merkle tree with inclusion proofs (RFC 6962 hashing).

Hashing rules (Certificate Transparency, RFC 6962 §2.1):

    leaf hash  = SHA-256(0x00 || leaf_data)
    node hash  = SHA-256(0x01 || left_hash || right_hash)
    empty tree = SHA-256("")

Why the prefixes matter: without them an internal node (64 bytes of child
hashes) could be presented as a leaf, enabling second-preimage forgeries.
Why no duplication: the common "duplicate the last node when the level is odd"
rule gives [a, b, c] and [a, b, c, c] the same root (the CVE-2012-2459 class of
bug). Here a lone node is promoted to the next level unchanged, which yields
exactly the RFC 6962 Merkle Tree Hash for any number of leaves.

Leaves are supplied as *leaf data* — either raw bytes or a hex string (decoded
to bytes) — and are hashed with the 0x00 prefix internally.

Pure functions only: no DB, no network, no state.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")

LeafData = bytes | str


def _as_bytes(leaf: LeafData) -> bytes:
    return bytes.fromhex(leaf) if isinstance(leaf, str) else bytes(leaf)


def leaf_hash(leaf: LeafData) -> str:
    """Hex SHA-256(0x00 || leaf_data)."""
    return hashlib.sha256(LEAF_PREFIX + _as_bytes(leaf)).hexdigest()


def node_hash(left: str, right: str) -> str:
    """Hex SHA-256(0x01 || left || right) for hex child hashes."""
    return hashlib.sha256(NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def build_tree(leaves: Sequence[LeafData]) -> list[list[str]]:
    """Return all levels: levels[0] are leaf hashes, levels[-1] == [root]."""
    if not leaves:
        return [[EMPTY_ROOT]]
    level = [leaf_hash(x) for x in leaves]
    levels = [level]
    while len(level) > 1:
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])  # promote the lone node unchanged
        level = nxt
        levels.append(level)
    return levels


def root(tree_or_leaves: Sequence[Any]) -> str:
    """Root from tree levels (output of build_tree) or directly from leaf data."""
    if not tree_or_leaves:
        return EMPTY_ROOT
    if isinstance(tree_or_leaves[0], list):
        return tree_or_leaves[-1][0]
    return build_tree(tree_or_leaves)[-1][0]


def proof(tree_levels: list[list[str]], index: int) -> list[dict[str, str]]:
    """Inclusion proof (audit path) for leaf `index`.

    Each step is {"sibling": <hex hash>, "position": "left"|"right"} giving the
    side on which the sibling sits. Levels where the node is promoted contribute
    no step.
    """
    leaf_count = len(tree_levels[0]) if tree_levels else 0
    if not 0 <= index < leaf_count or tree_levels == [[EMPTY_ROOT]]:
        raise IndexError(f"leaf index {index} out of range (tree has {leaf_count} leaves)")
    path = []
    idx = index
    for level in tree_levels[:-1]:
        sibling = idx ^ 1
        if sibling < len(level):
            path.append({"sibling": level[sibling], "position": "left" if idx % 2 else "right"})
        idx //= 2
    return path


def verify_proof_from_hash(leaf_hash_hex: str, audit_path: Any, expected_root: str) -> bool:
    """Verify an audit path starting from an already-computed leaf hash.

    Never raises: malformed proofs simply fail verification.
    """
    if not isinstance(audit_path, list) or not isinstance(expected_root, str) or not _HEX64.match(expected_root):
        return False
    if not isinstance(leaf_hash_hex, str) or not _HEX64.match(leaf_hash_hex):
        return False
    current = leaf_hash_hex
    for step in audit_path:
        if not isinstance(step, dict):
            return False
        sibling, position = step.get("sibling"), step.get("position")
        if not isinstance(sibling, str) or not _HEX64.match(sibling) or position not in ("left", "right"):
            return False
        current = node_hash(sibling, current) if position == "left" else node_hash(current, sibling)
    return current.lower() == expected_root.lower()


def verify_proof(leaf: LeafData, audit_path: Any, expected_root: str) -> bool:
    """Verify that `leaf` (leaf data) is included in the tree with `expected_root`."""
    try:
        h = leaf_hash(leaf)
    except (ValueError, TypeError):
        return False
    return verify_proof_from_hash(h, audit_path, expected_root)


def compare_trees(tree_or_leaves_a: list[Any], tree_or_leaves_b: list[Any]) -> list[int]:
    """Indices at which two leaf lists (or trees' leaf levels) differ."""
    a = tree_or_leaves_a[0] if tree_or_leaves_a and isinstance(tree_or_leaves_a[0], list) else tree_or_leaves_a
    b = tree_or_leaves_b[0] if tree_or_leaves_b and isinstance(tree_or_leaves_b[0], list) else tree_or_leaves_b
    return [i for i in range(max(len(a), len(b)))
            if (a[i] if i < len(a) else None) != (b[i] if i < len(b) else None)]
