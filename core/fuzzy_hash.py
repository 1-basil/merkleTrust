"""core/fuzzy_hash.py — Context Triggered Piecewise Hashing (CTPH, the ssdeep algorithm).

Pure-Python implementation of ssdeep's hash and comparison, based on:
  - J. Kornblum, "Identifying almost identical files using context triggered piecewise hashing,"
    Digital Investigation, vol. 3, pp. 91–97, Sep. 2006.
  - M. Fleming and O. Olukoya, "A temporal analysis and evaluation of fuzzy hashing algorithms
    for Android malware analysis," Forensic Sci. Int.: Digit. Investig., vol. 49, 2024.

Hash (follows ssdeep 2.13+; output matches the independent `ppdeep` implementation, see
tests/test_fuzzy_hash.py):
  - a 7-byte rolling hash decides where a piece ends ("context triggered");
  - each piece is summarised by one Base64 character of a 6-bit FNV-style hash;
  - two digests are kept, at block size b and 2b, and b is halved until the first digest
    has at least 32 characters.

Comparison follows ssdeep's rules: block sizes must be equal or differ by a factor of two,
runs of more than three identical characters are collapsed, the digests must share a 7-character
substring, and the score is derived from a weighted edit distance (insert/delete 1, replace 2).

In MerkleTrust it answers "how much of this program code is still the trusted code?": a DEX
file that changed but is still highly similar to the trusted one is a near-copy, the typical
shape of a repackaged app.
"""

from __future__ import annotations

import os
from typing import Any

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ROLLING_WINDOW = 7
MIN_BLOCK_SIZE = 3
SPAMSUM_LENGTH = 64
HASH_INIT = 0x27

# ssdeep's 6-bit piece hash: low 6 bits of FNV-1 (prime 0x01000193) as a lookup table,
# exactly as in ssdeep 2.13 (fuzzy.c, sum_table).
_F_TABLE = (
    0x00, 0x13, 0x26, 0x39, 0x0c, 0x1f, 0x32, 0x05, 0x18, 0x2b, 0x3e, 0x11, 0x24, 0x37, 0x0a, 0x1d,
    0x30, 0x03, 0x16, 0x29, 0x3c, 0x0f, 0x22, 0x35, 0x08, 0x1b, 0x2e, 0x01, 0x14, 0x27, 0x3a, 0x0d,
    0x20, 0x33, 0x06, 0x19, 0x2c, 0x3f, 0x12, 0x25, 0x38, 0x0b, 0x1e, 0x31, 0x04, 0x17, 0x2a, 0x3d,
    0x10, 0x23, 0x36, 0x09, 0x1c, 0x2f, 0x02, 0x15, 0x28, 0x3b, 0x0e, 0x21, 0x34, 0x07, 0x1a, 0x2d,
)
# _SUM[byte][h] -> next 6-bit hash
_SUM = [[_F_TABLE[h] ^ (b & 0x3F) for h in range(64)] for b in range(256)]


def _digests(data: bytes, bs: int) -> tuple[str, str, int]:
    """One pass at block size `bs` (and 2*bs).

    Returns both digests and the length of the first digest *before* its trailing character,
    which is what ssdeep uses to decide whether to retry with a smaller block size.
    """
    # The window's oldest byte is simply data[i - 7], so no separate window buffer is needed.
    old = bytes(ROLLING_WINDOW) + data
    h1 = h2 = h3 = 0
    sum1 = sum2 = HASH_INIT
    d1: list[str] = []
    d2: list[str] = []
    last1 = last2 = ""
    roll = 0
    bs1, bs2 = bs - 1, bs * 2
    table = _SUM
    for b, o in zip(data, old):
        sum1 = table[b][sum1]
        sum2 = table[b][sum2]
        h2 += 7 * b - h1
        h1 += b - o
        h3 = ((h3 << 5) & 0xFFFFFFFF) ^ b
        roll = (h1 + h2 + h3) & 0xFFFFFFFF
        if roll % bs == bs1:
            last1 = B64[sum1]
            if len(d1) < SPAMSUM_LENGTH - 1:
                d1.append(last1)
                sum1, last1 = HASH_INIT, ""
            if roll % bs2 == bs2 - 1:
                last2 = B64[sum2]
                if len(d2) < SPAMSUM_LENGTH // 2 - 1:
                    d2.append(last2)
                    sum2, last2 = HASH_INIT, ""
    pieces = len(d1)
    # The trailing piece: its running hash, or the last overflow character.
    if roll != 0:
        d1.append(B64[sum1])
        d2.append(B64[sum2])
    else:
        d1.append(last1)
        d2.append(last2)
    return "".join(d1), "".join(d2), pieces


def fuzzy_hash_bytes(data: bytes) -> str:
    """ssdeep hash of `data`, formatted '<blocksize>:<digest>:<digest at 2x blocksize>'."""
    bs = MIN_BLOCK_SIZE
    while bs * SPAMSUM_LENGTH < len(data):
        bs *= 2
    while True:
        d1, d2, pieces = _digests(data, bs)
        if bs > MIN_BLOCK_SIZE and pieces < SPAMSUM_LENGTH // 2:
            bs //= 2
            continue
        return f"{bs}:{d1}:{d2}"


def fuzzy_hash_file(path: str) -> str:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")
    with open(path, "rb") as fh:
        return fuzzy_hash_bytes(fh.read())


# ------------------------------------------------------------- comparison --

def _strip_runs(s: str) -> str:
    """Collapse runs of more than three identical characters (they carry little information)."""
    out = s[:3]
    for i in range(3, len(s)):
        if not (s[i] == s[i - 1] == s[i - 2] == s[i - 3]):
            out += s[i]
    return out


def _edit_distance(a: str, b: str) -> int:
    """ssdeep's weighted edit distance: insert 1, delete 1, replace 2."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (0 if ca == cb else 2))
        prev = cur
    return prev[-1]


def _has_common_substring(a: str, b: str) -> bool:
    if len(a) < ROLLING_WINDOW or len(b) < ROLLING_WINDOW:
        return False
    grams = {a[i:i + ROLLING_WINDOW] for i in range(len(a) - ROLLING_WINDOW + 1)}
    return any(b[i:i + ROLLING_WINDOW] in grams for i in range(len(b) - ROLLING_WINDOW + 1))


def _score(a: str, b: str, block_size: int) -> int:
    if not _has_common_substring(a, b):
        return 0
    score = _edit_distance(a, b) * SPAMSUM_LENGTH // (len(a) + len(b))
    score = 100 * score // SPAMSUM_LENGTH
    if score >= 100:
        return 0
    score = 100 - score
    # Small block sizes would exaggerate the match, so ssdeep caps the score there.
    if block_size < (99 + ROLLING_WINDOW) // ROLLING_WINDOW * MIN_BLOCK_SIZE:
        score = min(score, block_size // MIN_BLOCK_SIZE * min(len(a), len(b)))
    return score


def compare_fuzzy_hashes(hash1: str, hash2: str) -> int:
    """Similarity 0..100 of two ssdeep hashes (0 = unrelated, 100 = same pieces)."""
    try:
        bs1, a1, b1 = hash1.strip().split(":")
        bs2, a2, b2 = hash2.strip().split(":")
        bs1, bs2 = int(bs1), int(bs2)
    except (AttributeError, ValueError):
        return 0
    if bs1 != bs2 and bs1 != 2 * bs2 and bs2 != 2 * bs1:
        return 0
    a1, b1, a2, b2 = map(_strip_runs, (a1, b1, a2, b2))
    if bs1 == bs2 and a1 == a2:
        return 100
    if bs1 == bs2:
        return max(_score(a1, a2, bs1), _score(b1, b2, bs1 * 2))
    if bs1 == 2 * bs2:
        return _score(a1, b2, bs1)
    return _score(b1, a2, bs2)


def detect_near_duplicate(target_hash: str, reference_hash: str, threshold: int = 70) -> dict[str, Any]:
    """Classify how close `target_hash` is to `reference_hash`.

    classification: IDENTICAL (100) | NEAR_DUPLICATE (>= threshold) | DIVERGENT (>= 30) | UNRELATED
    """
    sim = compare_fuzzy_hashes(target_hash, reference_hash)
    cls = ("IDENTICAL" if sim >= 100 else "NEAR_DUPLICATE" if sim >= threshold
           else "DIVERGENT" if sim >= 30 else "UNRELATED")
    return {"similarity": sim, "is_near_duplicate": threshold <= sim < 100, "threshold": threshold,
            "classification": cls, "target_hash": target_hash, "reference_hash": reference_hash}
