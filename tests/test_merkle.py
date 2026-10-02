"""Unit and security tests for the Merkle tree library (RFC 6962 hashing)."""

import hashlib

import pytest

from core.merkle import (EMPTY_ROOT, build_tree, compare_trees, leaf_hash, node_hash, proof, root,
                         verify_proof, verify_proof_from_hash)


def _leaves(n, tag="leaf"):
    return [f"{tag}-{i}".encode() for i in range(n)]


def _rfc6962_mth(data):
    """Reference Merkle Tree Hash, written directly from RFC 6962 §2.1."""
    if not data:
        return hashlib.sha256(b"").hexdigest()
    if len(data) == 1:
        return hashlib.sha256(b"\x00" + data[0]).hexdigest()
    k = 1
    while k * 2 < len(data):
        k *= 2
    left, right = _rfc6962_mth(data[:k]), _rfc6962_mth(data[k:])
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


@pytest.mark.parametrize("n", list(range(0, 34)) + [100, 257])
def test_root_matches_rfc6962_reference(n):
    data = _leaves(n)
    assert root(data) == _rfc6962_mth(data)


def test_known_values():
    assert root([]) == EMPTY_ROOT
    assert leaf_hash(b"") == hashlib.sha256(b"\x00").hexdigest()
    a, b = leaf_hash(b"a"), leaf_hash(b"b")
    assert root([b"a", b"b"]) == hashlib.sha256(b"\x01" + bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()


def test_deterministic_and_order_sensitive():
    data = _leaves(7)
    assert root(data) == root(list(data))
    assert root(data) != root(list(reversed(data)))


def test_hex_leaf_data_is_decoded():
    h = hashlib.sha256(b"x").hexdigest()
    assert root([h]) == root([bytes.fromhex(h)])


def test_no_duplicate_last_leaf_collision():
    """Bitcoin-style duplication makes [a,b,c] == [a,b,c,c]; RFC 6962 hashing must not."""
    a, b, c = b"a", b"b", b"c"
    assert root([a, b, c]) != root([a, b, c, c])


def test_internal_node_cannot_pose_as_leaf():
    """Second-preimage resistance: the concatenated children of a node are not a valid leaf."""
    data = _leaves(4)
    tree = build_tree(data)
    forged_leaf = bytes.fromhex(tree[1][0]) + bytes.fromhex(tree[1][1])
    assert root([forged_leaf]) != root(data)
    assert not verify_proof(forged_leaf, [], root(data))


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13, 31, 64])
def test_every_proof_verifies(n):
    data = _leaves(n)
    tree = build_tree(data)
    r = root(tree)
    for i, leaf in enumerate(data):
        assert verify_proof(leaf, proof(tree, i), r)


def test_proof_length_is_logarithmic():
    tree = build_tree(_leaves(1024))
    assert all(len(proof(tree, i)) == 10 for i in (0, 511, 1023))


def _setup(n=9, i=4):
    data = _leaves(n)
    tree = build_tree(data)
    return data, tree, root(tree), proof(tree, i), i


def test_modified_leaf_fails():
    data, _, r, p, i = _setup()
    assert not verify_proof(data[i] + b"!", p, r)


def test_modified_sibling_fails():
    data, _, r, p, i = _setup()
    bad = [dict(s) for s in p]
    bad[1]["sibling"] = hashlib.sha256(b"evil").hexdigest()
    assert not verify_proof(data[i], bad, r)


def test_wrong_root_fails():
    data, _, _, p, i = _setup()
    assert not verify_proof(data[i], p, root(_leaves(9, "other")))


def test_swapped_position_fails():
    data, _, r, p, i = _setup()
    bad = [dict(s) for s in p]
    bad[0]["position"] = "left" if bad[0]["position"] == "right" else "right"
    assert not verify_proof(data[i], bad, r)


def test_truncated_or_extended_proof_fails():
    data, _, r, p, i = _setup()
    assert not verify_proof(data[i], p[:-1], r)
    assert not verify_proof(data[i], p + [{"sibling": "0" * 64, "position": "right"}], r)


def test_proof_for_other_leaf_fails():
    data, tree, r, _, _ = _setup()
    assert not verify_proof(data[3], proof(tree, 4), r)


@pytest.mark.parametrize("bad_proof", [None, "x", [None], [{"sibling": "zz", "position": "left"}],
                                       [{"sibling": "0" * 64, "position": "up"}], [{"position": "left"}]])
def test_malformed_proofs_fail_without_raising(bad_proof):
    data, _, r, _, i = _setup()
    assert verify_proof(data[i], bad_proof, r) is False


def test_malformed_root_or_leaf_fails():
    data, _, r, p, i = _setup()
    assert verify_proof(data[i], p, "not-a-root") is False
    assert verify_proof("zz-not-hex", p, r) is False
    assert verify_proof_from_hash("abc", p, r) is False


def test_proof_index_out_of_range():
    tree = build_tree(_leaves(3))
    with pytest.raises(IndexError):
        proof(tree, 3)
    with pytest.raises(IndexError):
        proof(build_tree([]), 0)


def test_node_hash_is_not_plain_concatenation():
    a, b = "00" * 32, "11" * 32
    assert node_hash(a, b) != hashlib.sha256(bytes.fromhex(a + b)).hexdigest()


def test_compare_trees():
    a = [hashlib.sha256(f"c{i}".encode()).hexdigest() for i in range(5)]
    b = list(a)
    assert compare_trees(a, b) == []
    b[2] = b[4] = "f" * 64
    assert compare_trees(a, b) == [2, 4]
    assert compare_trees(a, b + ["e" * 64]) == [2, 4, 5]
