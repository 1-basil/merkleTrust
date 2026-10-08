"""core/fuzzy_hash.py — Context Triggered Piecewise Hashing (CTPH / ssdeep).

Implements pure-Python fuzzy hashing based on:
  - J. Kornblum, "Identifying almost identical files using context triggered piecewise hashing,"
    Digital Investigation, vol. 3, pp. 91–97, Sep. 2006.
  - M. Fleming and O. Olukoya, "A temporal analysis and evaluation of fuzzy hashing algorithms
    for Android malware analysis," Forensic Sci. Int.: Digit. Investig., vol. 49, 2024.

Used for:
  1. Near-duplicate repackaged malware detection (identifying modified APKs / DEX files
     that share significant code with a known clean baseline or known malware family).
  2. Bytecode similarity scoring (quantifying how much of the application changed).
"""

from __future__ import annotations

import os
from typing import Any

# Standard ssdeep Base64-like alphabet (64 characters)
B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
WINDOW_SIZE = 7
FNV_PRIME = 0x01000193
FNV_INIT = 0x2802
MIN_BLOCK_SIZE = 3
MAX_DIGEST_LEN = 64
MAX_SECOND_DIGEST_LEN = 32


def _compute_ctph(data: bytes, bs1: int, bs2: int) -> tuple[str, str]:
    """Single-pass computation of dual piecewise digests for block sizes bs1 and bs2."""
    window = [0] * WINDOW_SIZE
    w_idx = 0
    h1 = 0
    h2 = 0
    h3 = 0
    fnv1 = FNV_INIT
    fnv2 = FNV_INIT
    s1: list[str] = []
    s2: list[str] = []

    for b in data:
        old_b = window[w_idx]
        window[w_idx] = b
        w_idx = (w_idx + 1) % WINDOW_SIZE

        h1 += b - old_b
        h2 += h1 - (WINDOW_SIZE * old_b)
        h3 = ((h3 << 5) & 0xFFFFFFFF) ^ b
        rolling = (h1 + h2 + h3) & 0xFFFFFFFF

        fnv1 = ((fnv1 * FNV_PRIME) ^ b) & 0xFFFFFFFF
        fnv2 = ((fnv2 * FNV_PRIME) ^ b) & 0xFFFFFFFF

        if (rolling % bs1) == (bs1 - 1):
            if len(s1) < MAX_DIGEST_LEN:
                # Avoid more than 3 consecutive repeats
                char = B64_CHARS[fnv1 & 63]
                if len(s1) < 3 or not (s1[-1] == s1[-2] == s1[-3] == char):
                    s1.append(char)
            fnv1 = FNV_INIT

        if (rolling % bs2) == (bs2 - 1):
            if len(s2) < MAX_SECOND_DIGEST_LEN:
                char = B64_CHARS[fnv2 & 63]
                if len(s2) < 3 or not (s2[-1] == s2[-2] == s2[-3] == char):
                    s2.append(char)
            fnv2 = FNV_INIT

    if fnv1 != FNV_INIT and len(s1) < MAX_DIGEST_LEN:
        s1.append(B64_CHARS[fnv1 & 63])
    if fnv2 != FNV_INIT and len(s2) < MAX_SECOND_DIGEST_LEN:
        s2.append(B64_CHARS[fnv2 & 63])

    return "".join(s1), "".join(s2)


def fuzzy_hash_bytes(data: bytes) -> str:
    """Compute CTPH (ssdeep format) hash for arbitrary byte payload: <blocksize>:<h1>:<h2."""
    n = len(data)
    if n == 0:
        return f"{MIN_BLOCK_SIZE}::"

    bs = MIN_BLOCK_SIZE
    while bs * MAX_DIGEST_LEN < n:
        bs *= 2

    s1, s2 = _compute_ctph(data, bs, bs * 2)
    while len(s1) < 32 and bs > MIN_BLOCK_SIZE:
        bs //= 2
        s1, s2 = _compute_ctph(data, bs, bs * 2)

    return f"{bs}:{s1}:{s2}"


def fuzzy_hash_file(path: str) -> str:
    """Read file into memory (or stream) and compute CTPH hash."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")
    with open(path, "rb") as fh:
        return fuzzy_hash_bytes(fh.read())


def _levenshtein(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1] * (len(s2) + 1)
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr[j + 1] = min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost)
        prev = curr
    return prev[len(s2)]


def _has_common_substring(s1: str, s2: str, min_len: int = 4) -> bool:
    """Check if strings share a common contiguous substring of at least min_len."""
    if len(s1) < min_len or len(s2) < min_len:
        return s1 == s2 and len(s1) >= min_len
    for i in range(len(s1) - min_len + 1):
        if s1[i : i + min_len] in s2:
            return True
    return False


def _score_strings(s1: str, s2: str) -> int:
    """Calculates normalized similarity percentage [0..100] between two digests."""
    if not s1 or not s2:
        return 0
    # ssdeep rule: must share at least a minimal sequence of context to have non-zero similarity
    if not _has_common_substring(s1, s2, min_len=4):
        return 0
    dist = _levenshtein(s1, s2)
    max_len = max(len(s1), len(s2))
    if dist >= max_len:
        return 0
    score = int((1.0 - (dist / max_len)) * 100)
    return max(0, min(100, score))


def compare_fuzzy_hashes(hash1: str, hash2: str) -> int:
    """Compare two CTPH signatures and return similarity score [0..100].

    Follows ssdeep comparison rules:
      - Block sizes must be equal, or one must be exactly 2x the other.
      - Returns 0 if block sizes are incompatible.
    """
    if not hash1 or not hash2:
        return 0
    if hash1 == hash2:
        return 100

    try:
        parts1 = hash1.strip().split(":")
        parts2 = hash2.strip().split(":")
        if len(parts1) != 3 or len(parts2) != 3:
            return 0
        bs1, s1a, s1b = int(parts1[0]), parts1[1], parts1[2]
        bs2, s2a, s2b = int(parts2[0]), parts2[1], parts2[2]
    except Exception:
        return 0

    if bs1 == bs2:
        score_a = _score_strings(s1a, s2a)
        score_b = _score_strings(s1b, s2b)
        return max(score_a, score_b)
    elif bs1 * 2 == bs2:
        return _score_strings(s1b, s2a)
    elif bs1 == bs2 * 2:
        return _score_strings(s1a, s2b)

    return 0


def detect_near_duplicate(target_hash: str, reference_hash: str, threshold: int = 70) -> dict[str, Any]:
    """Determine if target is a near-duplicate of reference build.

    Returns dict with:
      - similarity: 0..100
      - is_near_duplicate: bool
      - classification: "IDENTICAL" | "NEAR_DUPLICATE" | "DIVERGENT" | "UNRELATED"
    """
    sim = compare_fuzzy_hashes(target_hash, reference_hash)
    if sim >= 100:
        cls = "IDENTICAL"
    elif sim >= threshold:
        cls = "NEAR_DUPLICATE"
    elif sim >= 30:
        cls = "DIVERGENT"
    else:
        cls = "UNRELATED"

    return {
        "similarity": sim,
        "is_near_duplicate": sim >= threshold,
        "threshold": threshold,
        "classification": cls,
        "target_hash": target_hash,
        "reference_hash": reference_hash,
    }
