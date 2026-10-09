"""tests/test_fuzzy_hash.py — Context Triggered Piecewise Hashing (ssdeep algorithm)."""

import os
import random
import tempfile
from pathlib import Path

import pytest

from core.fuzzy_hash import compare_fuzzy_hashes, detect_near_duplicate, fuzzy_hash_bytes, fuzzy_hash_file

ROOT = Path(__file__).resolve().parent.parent

# Reference values produced by the independent ssdeep port `ppdeep` (version 20260221).
# Our implementation was also checked against it on 939 inputs (0..300 bytes, random sizes up to
# 200 KB, every APK in evaluation/dataset and every file in samples/) with no differences.
VECTORS = [
    (bytes(range(256)) * 40,
     "192:znnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnb:n"),
    (b"The quick brown fox jumps over the lazy dog. " * 200,
     "12:Fg6666666666666666666666666666666666666666666666666666666666666p:FV"),
]
FILE_VECTORS = [
    ("samples/clean_photo.jpg", "3:nStlVlilllIylA38lSY8n:DvlS8MR"),
    ("evaluation/dataset/baseline_demo.apk",
     "48:JgvIEFwuF3WLPO9LpcdVeGwDgY7inDriz8S4r4ysaZE8++892Vww+JWioyDZ2UaF:"
     "OwQ3WbOgaz7yrizbCKN6opou+Q2sQuz0"),
]


@pytest.mark.parametrize("data,expected", VECTORS)
def test_matches_ssdeep_reference_vectors(data, expected):
    assert fuzzy_hash_bytes(data) == expected


@pytest.mark.parametrize("path,expected", FILE_VECTORS)
def test_matches_ssdeep_reference_files(path, expected):
    assert fuzzy_hash_file(str(ROOT / path)) == expected


def test_empty_input():
    assert fuzzy_hash_bytes(b"") == "3::"


def test_identical_inputs_score_100():
    data = random.Random(7).randbytes(20000)
    h = fuzzy_hash_bytes(data)
    assert h == fuzzy_hash_bytes(data)
    assert compare_fuzzy_hashes(h, h) == 100


def test_small_patch_is_a_near_duplicate():
    base = random.Random(1).randbytes(40000)
    patched = base[:20000] + b"INJECTED_C2_PAYLOAD_HERE_FOR_TESTING" + base[20036:]
    sim = compare_fuzzy_hashes(fuzzy_hash_bytes(base), fuzzy_hash_bytes(patched))
    assert 70 <= sim < 100
    res = detect_near_duplicate(fuzzy_hash_bytes(patched), fuzzy_hash_bytes(base))
    assert res["classification"] == "NEAR_DUPLICATE" and res["is_near_duplicate"] and res["similarity"] == sim


def test_unrelated_inputs_score_0():
    r = random.Random(3)
    assert compare_fuzzy_hashes(fuzzy_hash_bytes(r.randbytes(30000)), fuzzy_hash_bytes(r.randbytes(30000))) == 0


def test_incompatible_block_sizes_score_0():
    assert compare_fuzzy_hashes("3:abcdefgh:abcd", "12:abcdefgh:abcd") == 0


def test_malformed_hashes_score_0():
    assert compare_fuzzy_hashes("not-a-hash", "3:abc:def") == 0
    assert compare_fuzzy_hashes(None, "3:abc:def") == 0


def test_identical_is_not_reported_as_near_duplicate():
    h = fuzzy_hash_bytes(random.Random(5).randbytes(8000))
    res = detect_near_duplicate(h, h)
    assert res["classification"] == "IDENTICAL" and not res["is_near_duplicate"]


def test_file_and_bytes_agree():
    content = random.Random(9).randbytes(5000)
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(content)
        path = tf.name
    try:
        assert fuzzy_hash_file(path) == fuzzy_hash_bytes(content)
    finally:
        os.remove(path)
