"""core/threat_intel.py — Threat intelligence: known C2 servers and known malware files.

Indicators come from a real, dated feed: abuse.ch ThreatFox (https://threatfox.abuse.ch),
downloaded with `python -m scripts.update_threat_feed`. Every match names the feed, the
ThreatFox record id, the malware family and when the indicator was first seen, so a verdict can
be traced back to its source. No indicators are built into this module.

Two kinds of check:
  1. Feed matches (high confidence): a URL, domain, IP or IP:port found in the app's code, or the
     SHA-256 of the uploaded file, appears in the feed.
  2. Heuristics (medium confidence, always labelled as such): dynamic-DNS / tunnelling services
     that are often used for short-lived C2, and malware-like host names on top-level domains
     with high abuse rates. These never claim a host is known-bad.

ThreatFox data is free to use under abuse.ch's fair-use terms; commercial use may require their
commercial API (https://threatfox.abuse.ch/faq/).
"""

from __future__ import annotations

import csv
import ipaddress
import logging
import re
import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger("merkletrust.threat_intel")

FEED_FILE = "threatfox_recent.csv"
FEED_SOURCE = "abuse.ch ThreatFox"

# Dynamic DNS and tunnelling services that let an attacker move a C2 server at will.
DYNDNS_SUFFIXES = (".duckdns.org", ".no-ip.biz", ".no-ip.org", ".ddns.net", ".zapto.org", ".hopto.org",
                   ".ngrok.io", ".ngrok-free.app", ".loca.lt")
# Top-level domains that abuse reports (e.g. Interisle, Spamhaus) repeatedly list among the most abused.
HIGH_ABUSE_TLDS = (".top", ".xyz", ".buzz", ".monster", ".click", ".cfd")
# Whole words in a host name that are typical of malware infrastructure.
MALWARE_WORDS = {"c2", "cnc", "gate", "panel", "stealer", "rat", "bot", "drop", "payload", "loader"}

_LABEL_SPLIT = re.compile(r"[.\-_]")


@dataclass(frozen=True)
class Indicator:
    value: str          # normalised: lower-case domain/URL, "ip", "ip:port" or sha256 hex
    kind: str           # domain | ip | ip_port | url | sha256
    family: str         # e.g. "CraxsRAT"
    malware_id: str     # ThreatFox malware id, e.g. "apk.craxs_rat" (prefix = platform)
    threat_type: str    # ThreatFox threat_type, e.g. botnet_cc, payload_delivery, payload
    confidence: int | None
    first_seen: str
    record_id: str
    tags: str


def _host(target: str) -> str:
    t = target.strip().lower()
    if "://" not in t:
        t = "//" + t
    try:
        return (urllib.parse.urlsplit(t).hostname or "").strip(".")
    except ValueError:
        return ""


def _port(target: str) -> int | None:
    t = target.strip()
    try:
        return urllib.parse.urlsplit(t if "://" in t else "//" + t).port
    except ValueError:
        return None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def load_threatfox_csv(path: Path) -> tuple[list[Indicator], dict[str, Any]]:
    """Parse a ThreatFox CSV export. Returns (indicators, metadata)."""
    updated = None
    rows: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#"):
                m = re.search(r"Last updated:\s*([0-9-]+ [0-9:]+ UTC)", line)
                if m:
                    updated = m.group(1)
                continue
            if line.strip():
                rows.append(line)
    out: list[Indicator] = []
    for rec in csv.reader(rows, skipinitialspace=True):
        if len(rec) < 10:
            continue
        first_seen, record_id, value, ioc_type, threat_type, malware_id, _alias, family, _last, conf = rec[:10]
        tags = rec[12] if len(rec) > 12 else ""
        kind = {"domain": "domain", "url": "url", "ip:port": "ip_port", "sha256_hash": "sha256"}.get(ioc_type)
        if kind is None:
            continue
        v = value.strip().lower()
        if kind == "url":
            v = v.rstrip("/")
        out.append(Indicator(v, kind, family or "Unknown malware", malware_id, threat_type,
                             int(conf) if conf.isdigit() else None,
                             first_seen, record_id, tags if tags != "None" else ""))
    return out, {"source": FEED_SOURCE, "updated": updated, "file": str(path), "indicators": len(out)}


class ThreatIntelEngine:
    def __init__(self, indicators: list[Indicator] | None = None, meta: dict[str, Any] | None = None):
        self.meta = meta or {"source": None, "updated": None, "indicators": 0}
        self._by: dict[str, dict[str, Indicator]] = {"domain": {}, "url": {}, "ip_port": {}, "ip": {}, "sha256": {}}
        for ind in indicators or []:
            self._by[ind.kind].setdefault(ind.value, ind)
            if ind.kind == "ip_port":
                self._by["ip"].setdefault(ind.value.rsplit(":", 1)[0], ind)

    @property
    def loaded(self) -> bool:
        return bool(self.meta.get("indicators"))

    def status(self) -> dict[str, Any]:
        return {"source": self.meta.get("source"), "updated": self.meta.get("updated"),
                "indicators": self.meta.get("indicators", 0), "loaded": self.loaded}

    def _feed_match(self, ind: Indicator, matched: str) -> dict[str, Any]:
        c2 = ind.threat_type == "botnet_cc"
        return {
            "indicator": matched, "type": f"feed_{ind.kind}", "basis": "feed",
            "threat_family": ind.family, "threat_type": ind.threat_type, "malware_id": ind.malware_id,
            "android": ind.malware_id.startswith("apk."),
            "severity": "critical", "confidence": ind.confidence,
            "source": self.meta.get("source"), "record_id": ind.record_id, "first_seen": ind.first_seen,
            "description": (f"{'C2 server' if c2 else 'Malware host'} of {ind.family}"
                            f"{' (Android malware)' if ind.malware_id.startswith('apk.') else ''} listed in "
                            f"{self.meta.get('source')} (record #{ind.record_id}, first seen {ind.first_seen}"
                            + (f", confidence {ind.confidence}%" if ind.confidence is not None else "") + ")."),
        }

    def lookup_target(self, target: str) -> dict[str, Any] | None:
        """Check one URL, domain, IP or IP:port."""
        if not target:
            return None
        host = _host(target)
        if not host:
            return None
        url = target.strip().lower().rstrip("/")
        if url in self._by["url"]:
            return self._feed_match(self._by["url"][url], url)
        if _is_ip(host):
            port = _port(target)
            if port is not None and f"{host}:{port}" in self._by["ip_port"]:
                return self._feed_match(self._by["ip_port"][f"{host}:{port}"], f"{host}:{port}")
            if host in self._by["ip"]:
                return self._feed_match(self._by["ip"][host], host)
            return None
        # The host or any parent domain (sub.bad.example matches a listed bad.example).
        labels = host.split(".")
        for i in range(len(labels) - 1):
            cand = ".".join(labels[i:])
            if cand in self._by["domain"]:
                return self._feed_match(self._by["domain"][cand], host)
        for suffix in DYNDNS_SUFFIXES:
            if host.endswith(suffix):
                return {"indicator": host, "type": "heuristic_dynamic_dns", "basis": "heuristic",
                        "threat_family": "Dynamic DNS / tunnel service", "severity": "medium", "confidence": None,
                        "description": f"Uses {suffix.lstrip('.')}, a dynamic DNS or tunnelling service often used to "
                                       "move C2 servers. This is a warning sign, not proof of malware."}
        words = set(_LABEL_SPLIT.split(host))
        if host.endswith(HIGH_ABUSE_TLDS) and words & MALWARE_WORDS:
            return {"indicator": host, "type": "heuristic_domain_pattern", "basis": "heuristic",
                    "threat_family": "Malware-like host name", "severity": "medium", "confidence": None,
                    "description": f"Host name contains '{sorted(words & MALWARE_WORDS)[0]}' on a top-level domain with "
                                   "a high abuse rate. This is a warning sign, not proof of malware."}
        return None

    def lookup_hash(self, sha256: str) -> dict[str, Any] | None:
        ind = self._by["sha256"].get((sha256 or "").lower())
        return self._feed_match(ind, ind.value) if ind else None

    def scan_iocs(self, urls: list[str], ips: list[str]) -> list[dict[str, Any]]:
        matches, seen = [], set()
        for target in list(urls or []) + list(ips or []):
            res = self.lookup_target(target)
            if res and res["indicator"] not in seen:
                seen.add(res["indicator"])
                matches.append(res)
        return matches


# ------------------------------------------------------------- default feed --

_lock = threading.Lock()
_cache: dict[str, Any] = {"key": None, "engine": ThreatIntelEngine()}


def feed_path() -> Path:
    from core.config import get_settings
    s = get_settings()
    return Path(s.threat_feed_path) if s.threat_feed_path else Path(s.data_dir) / "threat_feeds" / FEED_FILE


def default_engine() -> ThreatIntelEngine:
    """The engine for the configured feed file, reloaded whenever the file changes."""
    path = feed_path()
    try:
        st = path.stat()
        key = (str(path), st.st_mtime_ns, st.st_size)
    except OSError:
        key = (str(path), None, None)
    with _lock:
        if _cache["key"] != key:
            if key[1] is None:
                _cache["engine"] = ThreatIntelEngine()
            else:
                try:
                    _cache["engine"] = ThreatIntelEngine(*load_threatfox_csv(path))
                    log.info("threat feed loaded: %s indicators (updated %s)",
                             _cache["engine"].meta["indicators"], _cache["engine"].meta["updated"])
                except (OSError, csv.Error, ValueError) as exc:
                    log.warning("threat feed %s could not be read: %s", path, exc)
                    _cache["engine"] = ThreatIntelEngine()
            _cache["key"] = key
        return _cache["engine"]


def check_target(target: str) -> dict[str, Any] | None:
    return default_engine().lookup_target(target)


def scan_iocs(urls: list[str], ips: list[str]) -> list[dict[str, Any]]:
    return default_engine().scan_iocs(urls, ips)


def check_file_hash(sha256: str) -> dict[str, Any] | None:
    return default_engine().lookup_hash(sha256)


def feed_status() -> dict[str, Any]:
    return default_engine().status()
