"""core/yara_scanner.py — Lightweight YARA-compatible rules engine for APK threat detection.

Provides built-in threat signatures for ransomware, cryptominers, packers, dynamic downloaders,
and root hiders, executable in pure Python with zero mandatory external C dependencies.
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

    def match(self, data: bytes, file_path: str = "") -> RuleMatch | None:
        matched: list[str] = []
        for pat in self.patterns:
            m = pat.search(data)
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


# Built-in curated threat rules
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
        for rule in active_rules:
            m = rule.match(data, file_path=file_path)
            if m:
                matches.append(m)
    return matches
