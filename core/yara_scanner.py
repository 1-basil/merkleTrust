"""core/yara_scanner.py — YARA-style signature rules for APK threat detection.

A small rules engine in the spirit of YARA: each rule is a set of regular expressions plus a
minimum number that must match. It does not read YARA rule files. The built-in rules look for
ransom notes, crypto-mining pools (stratum, XMRig, Coinhive), unencrypted downloads of code
(.apk/.dex/.jar over http) and the native libraries of well-known commercial packers
(Qihoo 360 Jiagu, Bangcle/SecNeo). Pure Python, no C dependencies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RuleMatch:
    rule_name: str
    category: str
    severity: str
    description: str
    matched_strings: list[str] = field(default_factory=list)
    file_path: str = ""


@dataclass
class YaraRule:
    name: str
    category: str
    severity: str
    description: str
    patterns: list[re.Pattern]
    condition_min_matches: int = 1

    def match(self, data: bytes, file_path: str = "", lowered: bytes | None = None) -> RuleMatch | None:
        matched: list[str] = []
        for pat in self.patterns:
            m = _search(pat, data, lowered)
            if m:
                matched.append(m.group(0).decode("ascii", errors="replace"))
        if len(matched) >= self.condition_min_matches:
            return RuleMatch(
                rule_name=self.name,
                category=self.category,
                severity=self.severity,
                description=self.description,
                matched_strings=matched,
                file_path=file_path,
            )
        return None


# --------------------------------------------------------------- fast search --
# Running every regex over every byte costs about 0.8 s per MB. Instead, each pattern's longest
# piece of fixed text (which every match must contain) is located with bytes.find, a fast C
# substring search, and the full regex only runs in a window around each hit. Matches longer
# than WINDOW bytes on either side of that text are not found.

WINDOW = 512
_META = set(b"()[]{}|?*+^$.")
_anchor_cache: dict[tuple[bytes, int], bytes | None] = {}


def _anchor(pat: re.Pattern) -> bytes | None:
    """Longest literal run that every match of `pat` must contain (None if there is none)."""
    key = (pat.pattern, pat.flags)
    if key in _anchor_cache:
        return _anchor_cache[key]
    src, runs, cur, depth, i = pat.pattern, [], bytearray(), 0, 0
    top_level_alternation = False
    while i < len(src):
        c = src[i]
        lit = None
        if c == 0x5C and i + 1 < len(src):  # backslash
            nxt = src[i + 1]
            lit = nxt if chr(nxt) in r".+*?()[]{}|^$\/-:" else None
            i += 2
        else:
            if c in _META:
                if c == ord("(") or c == ord("["):
                    depth += 1
                elif c == ord(")") or c == ord("]"):
                    depth -= 1
                elif c == ord("|") and depth == 0:
                    top_level_alternation = True
                if c in b"?*{" and cur:
                    cur.pop()  # the previous character was optional
                runs.append(bytes(cur))
                cur = bytearray()
                i += 1
                continue
            lit = c
            i += 1
        if lit is None or depth > 0:
            runs.append(bytes(cur))
            cur = bytearray()
        else:
            cur.append(lit)
    runs.append(bytes(cur))
    best = max(runs, key=len) if runs and not top_level_alternation else b""
    anchor = (best.lower() if pat.flags & re.IGNORECASE else best) or None
    _anchor_cache[key] = anchor
    return anchor


def _search(pat: re.Pattern, data: bytes, lowered: bytes | None) -> re.Match | None:
    anchor = _anchor(pat)
    if anchor is None:
        return pat.search(data)
    hay = (lowered if lowered is not None else data.lower()) if pat.flags & re.IGNORECASE else data
    pos = hay.find(anchor)
    while pos != -1:
        m = pat.search(data, max(0, pos - WINDOW), min(len(data), pos + len(anchor) + WINDOW))
        if m:
            return m
        pos = hay.find(anchor, pos + 1)
    return None


# Built-in rules (generic patterns, not tied to a threat feed)
BUILTIN_RULES: list[YaraRule] = [
    YaraRule(
        name="Android_Ransomware_Indicators",
        category="ransomware",
        severity="high",
        description="Ransomware payment demand or file encryption extortion strings",
        patterns=[
            re.compile(rb"all your files (have been|are) encrypted", re.IGNORECASE),
            re.compile(rb"pay (the )?ransom", re.IGNORECASE),
            re.compile(rb"your personal files are encrypted", re.IGNORECASE),
            re.compile(rb"to decrypt your files, send", re.IGNORECASE),
            re.compile(rb"bitcoin address to pay", re.IGNORECASE),
        ],
        condition_min_matches=1,
    ),
    YaraRule(
        name="Android_Cryptominer_Pool",
        category="cryptominer",
        severity="high",
        description="Mining pool protocols and cryptocurrency miner strings",
        patterns=[
            re.compile(rb"stratum\+tcp://", re.IGNORECASE),
            re.compile(rb"stratum\+ssl://", re.IGNORECASE),
            re.compile(rb"\bxmrig\b", re.IGNORECASE),
            re.compile(rb"\bcoinhive\b", re.IGNORECASE),
            re.compile(rb"\bpool\.supportxmr\.com\b", re.IGNORECASE),
            re.compile(rb"\bxmr\.crypto-pool\.fr\b", re.IGNORECASE),
        ],
        condition_min_matches=1,
    ),
    YaraRule(
        name="Android_Suspicious_Downloader",
        category="dropper",
        severity="high",
        description="Direct unencrypted dynamic payload download URL patterns",
        patterns=[
            re.compile(rb"http://[a-zA-Z0-9.\-_/]+\.apk\b", re.IGNORECASE),
            re.compile(rb"http://[a-zA-Z0-9.\-_/]+\.dex\b", re.IGNORECASE),
            re.compile(rb"http://[a-zA-Z0-9.\-_/]+\.jar\b", re.IGNORECASE),
        ],
        condition_min_matches=1,
    ),
    YaraRule(
        name="Android_Root_Hider_Evasion",
        category="evasion",
        severity="medium",
        description="Device rooting evasion and root-cloaking strings",
        patterns=[
            re.compile(rb"/sbin/su\b"),
            re.compile(rb"/system/xbin/which\s+su\b"),
            re.compile(rb"\bmagisk\.version\b", re.IGNORECASE),
            re.compile(rb"eu\.chainfire\.supersu", re.IGNORECASE),
        ],
        condition_min_matches=2,
    ),
    YaraRule(
        name="Android_Commercial_Packer",
        category="packer",
        severity="high",
        description="Known binary packer or code protection wrapper signatures",
        patterns=[
            re.compile(rb"\bUPX!\b"),
            re.compile(rb"libsecexe\.so", re.IGNORECASE),
            re.compile(rb"libsecmain\.so", re.IGNORECASE),
            re.compile(rb"libDexHelper\.so", re.IGNORECASE),
            re.compile(rb"libjiagu\.so", re.IGNORECASE),
        ],
        condition_min_matches=1,
    ),
]


def scan_files(files: list[tuple[str, bytes]], rules: list[YaraRule] | None = None) -> list[RuleMatch]:
    """Scan a list of (path, bytes) files against all active YARA rules."""
    active_rules = rules or BUILTIN_RULES
    matches: list[RuleMatch] = []
    for file_path, data in files:
        lowered = data.lower()  # one case-folded copy shared by all case-insensitive patterns
        for rule in active_rules:
            m = rule.match(data, file_path=file_path, lowered=lowered)
            if m:
                matches.append(m)
    return matches
