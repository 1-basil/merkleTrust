"""core/merkle.py — Pure Merkle tree library.

Published for use across engines (e.g. Ajay, Ashwini, Basil).
Pure functions only: no DB, no network, no state.
"""

import hashlib
from typing import Any


def _hash_pair(left: str, right: str) -> str:
    """Hash two hex-encoded hashes together: SHA256(left_bytes + right_bytes)."""
    left_bytes = bytes.fromhex(left) if isinstance(left, str) else left
    right_bytes = bytes.fromhex(right) if isinstance(right, str) else right
    return hashlib.sha256(left_bytes + right_bytes).hexdigest()


def build_tree(leaves: list[str]) -> list[list[str]]:
    """Build a Merkle tree from a list of leaf hex hashes.

    Returns layers of the tree from leaves up to the root level.
    layers[0] is the leaves, layers[-1][0] is the Merkle root.
    """
    if not leaves:
        empty_root = hashlib.sha256(b"").hexdigest()
        return [[empty_root]]

    current_layer = list(leaves)
    layers = [current_layer]

    while len(current_layer) > 1:
        next_layer = []
        for i in range(0, len(current_layer), 2):
            left = current_layer[i]
            # If odd number of leaves, duplicate the last element
            right = current_layer[i + 1] if i + 1 < len(current_layer) else left
            next_layer.append(_hash_pair(left, right))
        current_layer = next_layer
        layers.append(current_layer)

    return layers


def root(tree_layers: list[list[str]] | list[str]) -> str:
    """Return the hex Merkle root from tree layers or leaf list."""
    if not tree_layers:
        return hashlib.sha256(b"").hexdigest()
    if isinstance(tree_layers[0], list):
        return tree_layers[-1][0]
    # If passed a list of leaf hashes directly
    tree = build_tree(tree_layers)
    return tree[-1][0]


def proof(tree_layers: list[list[str]], index: int) -> list[dict[str, str]]:
    """Generate an audit inclusion proof for leaf at `index`.

    Returns a list of dicts: [{"sibling": "<hex>", "position": "left"|"right"}]
    """
    if not tree_layers or not tree_layers[0]:
        return []

    leaf_count = len(tree_layers[0])
    if index < 0 or index >= leaf_count:
        raise IndexError(f"Leaf index {index} out of range (0..{leaf_count - 1})")

    audit_path = []
    idx = index

    for layer in tree_layers[:-1]:
        is_right = idx % 2 == 1
        sibling_idx = idx - 1 if is_right else idx + 1

        if sibling_idx < len(layer):
            sibling_hash = layer[sibling_idx]
        else:
            sibling_hash = layer[idx]  # Duplicated when odd

        audit_path.append({
            "sibling": sibling_hash,
            "position": "left" if is_right else "right",
        })
        idx //= 2

    return audit_path


def verify_proof(leaf: str, audit_path: list[dict[str, str]], expected_root: str) -> bool:
    """Verify an inclusion proof against expected Merkle root."""
    current = leaf
    for step in audit_path:
        sibling = step["sibling"]
        pos = step.get("position", "right")
        if pos == "left":
            current = _hash_pair(sibling, current)
        else:
            current = _hash_pair(current, sibling)
    return current.lower() == expected_root.lower()


def compare_trees(tree_or_leaves_a: list[Any], tree_or_leaves_b: list[Any]) -> list[int]:
    """Compare two Merkle trees (or leaf hash lists) and return changed leaf indices."""
    leaves_a = tree_or_leaves_a[0] if (tree_or_leaves_a and isinstance(tree_or_leaves_a[0], list)) else tree_or_leaves_a
    leaves_b = tree_or_leaves_b[0] if (tree_or_leaves_b and isinstance(tree_or_leaves_b[0], list)) else tree_or_leaves_b

    max_len = max(len(leaves_a), len(leaves_b))
    changed_indices = []

    for i in range(max_len):
        h_a = leaves_a[i] if i < len(leaves_a) else None
        h_b = leaves_b[i] if i < len(leaves_b) else None
        if h_a != h_b:
            changed_indices.append(i)

    return changed_indices
