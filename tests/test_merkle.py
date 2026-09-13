"""tests/test_merkle.py — Unit tests for Merkle tree library."""

import hashlib
import pytest
from core.merkle import build_tree, root, proof, verify_proof, compare_trees


def test_build_tree_and_root():
    leaves = [hashlib.sha256(f"leaf_{i}".encode()).hexdigest() for i in range(4)]
    tree = build_tree(leaves)

    assert len(tree) == 3  # 4 leaves -> 2 nodes -> 1 root
    assert len(tree[0]) == 4
    assert len(tree[1]) == 2
    assert len(tree[2]) == 1

    r = root(tree)
    assert r == tree[-1][0]
    assert len(r) == 64


def test_inclusion_proof_and_verification():
    leaves = [hashlib.sha256(f"chunk_{i}".encode()).hexdigest() for i in range(8)]
    tree = build_tree(leaves)
    tree_root = root(tree)

    for i in range(len(leaves)):
        p = proof(tree, i)
        assert verify_proof(leaves[i], p, tree_root) is True

    # Tampered leaf should fail verification
    fake_leaf = hashlib.sha256(b"tampered_content").hexdigest()
    assert verify_proof(fake_leaf, proof(tree, 0), tree_root) is False


def test_compare_trees():
    leaves_a = [hashlib.sha256(f"chunk_{i}".encode()).hexdigest() for i in range(5)]
    leaves_b = list(leaves_a)

    # No changes
    assert compare_trees(leaves_a, leaves_b) == []

    # Modify chunk 2 and chunk 4
    leaves_b[2] = hashlib.sha256(b"modified_2").hexdigest()
    leaves_b[4] = hashlib.sha256(b"modified_4").hexdigest()

    changed = compare_trees(leaves_a, leaves_b)
    assert changed == [2, 4]
