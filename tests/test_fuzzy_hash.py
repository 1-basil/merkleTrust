"""tests/test_fuzzy_hash.py — Unit tests for Context Triggered Piecewise Hashing (CTPH)."""

import os
import tempfile
import pytest
from core.fuzzy_hash import (
    fuzzy_hash_bytes,
    fuzzy_hash_file,
    compare_fuzzy_hashes,
    detect_near_duplicate,
)


def test_fuzzy_hash_empty_bytes():
    h = fuzzy_hash_bytes(b"")
    assert h.startswith("3::")


def test_fuzzy_hash_identical():
    data = b"This is a sample payload testing MerkleTrust fuzzy hashing CTPH algorithm." * 50
    h1 = fuzzy_hash_bytes(data)
    h2 = fuzzy_hash_bytes(data)
    assert h1 == h2
    assert compare_fuzzy_hashes(h1, h2) == 100


def test_fuzzy_hash_near_duplicate():
    base = b"Base application code with multiple methods and procedures executing logic. " * 80
    # Inject a 30-byte patch/tamper
    tampered = base[:300] + b"INJECTED_C2_PAYLOAD_HERE_FOR_TESTING" + base[337:]

    h_base = fuzzy_hash_bytes(base)
    h_tampered = fuzzy_hash_bytes(tampered)

    sim = compare_fuzzy_hashes(h_base, h_tampered)
    # High similarity (> 70%) but not 100%
    assert 70 <= sim <= 99

    res = detect_near_duplicate(h_tampered, h_base, threshold=70)
    assert res["is_near_duplicate"] is True
    assert res["classification"] == "NEAR_DUPLICATE"
    assert res["similarity"] == sim


def test_fuzzy_hash_unrelated():
    data1 = b"AAAAAAAAAAAAAAAA" * 100
    data2 = b"zzzzzzzzzzzzzzzz" * 100

    h1 = fuzzy_hash_bytes(data1)
    h2 = fuzzy_hash_bytes(data2)

    sim = compare_fuzzy_hashes(h1, h2)
    assert sim < 40


def test_fuzzy_hash_file():
    content = b"File content for testing CTPH streaming and file hashing." * 60
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(content)
        path = tf.name

    try:
        h = fuzzy_hash_file(path)
        expected = fuzzy_hash_bytes(content)
        assert h == expected
    finally:
        os.remove(path)
