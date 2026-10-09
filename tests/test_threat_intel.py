"""tests/test_threat_intel.py — Threat intelligence engine (ThreatFox feed + labelled heuristics).

The feed below is TEST DATA in ThreatFox's real CSV format. It uses only reserved values:
documentation IP ranges (RFC 5737) and reserved .example / .test domains (RFC 2606), so it cannot
be mistaken for real indicators.
"""

import os
import time

import pytest

from core import threat_intel
from core.threat_intel import ThreatIntelEngine, load_threatfox_csv

FEED = """################################################################
# ThreatFox IOCs: recent additions - CSV format                #
# Last updated: 2026-10-08 07:40:22 UTC                        #
################################################################
#
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"
"2026-10-08 06:26:07", "1001", "198.51.100.23:9443", "ip:port", "botnet_cc", "apk.test_rat", "None", "TestRAT", "", "75", "False", "None", "c2,TestRAT", "0", "tester"
"2026-10-08 06:00:00", "1002", "c2-panel.example", "domain", "botnet_cc", "apk.test_bank", "None", "TestBanker", "", "100", "False", "None", "apk", "0", "tester"
"2026-10-08 05:00:00", "1003", "https://drop.example/stage2.apk", "url", "payload_delivery", "apk.test_loader", "None", "TestLoader", "", "90", "False", "None", "apk", "0", "tester"
"2026-10-08 04:00:00", "1004", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256_hash", "payload", "apk.test_loader", "None", "TestLoader", "", "80", "False", "None", "apk", "0", "tester"
"2026-10-08 03:00:00", "1005", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "md5_hash", "payload", "win.other", "None", "Other", "", "80", "False", "None", "None", "0", "tester"
"""


@pytest.fixture
def feed_file(tmp_path):
    p = tmp_path / "threatfox_recent.csv"
    p.write_text(FEED, encoding="utf-8")
    return p


@pytest.fixture
def engine(feed_file):
    return ThreatIntelEngine(*load_threatfox_csv(feed_file))


def test_parses_threatfox_csv_and_metadata(feed_file):
    indicators, meta = load_threatfox_csv(feed_file)
    assert meta["updated"] == "2026-10-08 07:40:22 UTC" and meta["source"] == "abuse.ch ThreatFox"
    assert len(indicators) == 4  # the md5 row is not used
    assert {i.kind for i in indicators} == {"ip_port", "domain", "url", "sha256"}


def test_ip_port_and_bare_ip_match_with_provenance(engine):
    m = engine.lookup_target("http://198.51.100.23:9443/gate")
    assert m["basis"] == "feed" and m["record_id"] == "1001" and m["threat_family"] == "TestRAT"
    assert "record #1001" in m["description"] and "C2 server" in m["description"]
    assert engine.lookup_target("198.51.100.23")["record_id"] == "1001"


def test_domain_and_subdomain_match(engine):
    assert engine.lookup_target("https://c2-panel.example/api")["record_id"] == "1002"
    assert engine.lookup_target("cdn.c2-panel.example")["record_id"] == "1002"


def test_url_match(engine):
    m = engine.lookup_target("https://drop.example/stage2.apk")
    assert m["record_id"] == "1003" and "Malware host" in m["description"]


def test_known_malware_file_hash(engine):
    assert engine.lookup_hash("A" * 64)["record_id"] == "1004"
    assert engine.lookup_hash("c" * 64) is None


def test_clean_targets_do_not_match(engine):
    assert engine.lookup_target("https://api.github.com/repos") is None
    assert engine.lookup_target("8.8.8.8") is None
    assert engine.lookup_target("ratings.xyz") is None  # 'rat' inside a word is not a malware word


def test_heuristics_are_labelled_as_heuristics(engine):
    m = engine.lookup_target("controller.duckdns.org")
    assert m["basis"] == "heuristic" and m["severity"] == "medium" and "not proof" in m["description"]
    m = engine.lookup_target("stealer-gate.top")
    assert m["basis"] == "heuristic" and m["type"] == "heuristic_domain_pattern"


def test_no_feed_means_no_feed_matches(tmp_path, monkeypatch):
    from core.config import get_settings
    monkeypatch.setattr(get_settings(), "threat_feed_path", tmp_path / "missing.csv")
    assert threat_intel.feed_status()["loaded"] is False
    assert threat_intel.check_target("c2-panel.example") is None


def test_default_engine_reloads_when_the_file_changes(tmp_path, monkeypatch):
    from core.config import get_settings
    path = tmp_path / "feed.csv"
    path.write_text(FEED.split('"2026-10-08 06:00:00"')[0], encoding="utf-8")
    monkeypatch.setattr(get_settings(), "threat_feed_path", path)
    assert threat_intel.feed_status()["indicators"] == 1
    path.write_text(FEED, encoding="utf-8")
    os.utime(path, (time.time() + 5, time.time() + 5))
    assert threat_intel.feed_status()["indicators"] == 4
    assert threat_intel.check_file_hash("a" * 64)["threat_family"] == "TestLoader"


def test_batch_scan_deduplicates(engine):
    matches = engine.scan_iocs(["https://c2-panel.example/a", "https://c2-panel.example/b", "https://google.com"],
                               ["198.51.100.23", "8.8.8.8"])
    assert [m["record_id"] for m in matches] == ["1002", "1001"]
