"""tests/test_threat_intel.py — Unit tests for Threat Intelligence & C2 indicator engine."""

import pytest
from core.threat_intel import ThreatIntelEngine, check_target, scan_iocs


def test_threat_intel_exact_domain_match():
    res = check_target("teabot-c2.net")
    assert res is not None
    assert res["type"] == "exact_domain_match"
    assert "TeaBot" in res["threat_family"]
    assert res["severity"] == "critical"


def test_threat_intel_exact_ip_match():
    res = check_target("198.51.100.23")
    assert res is not None
    assert res["type"] == "exact_ip_match"
    assert res["severity"] == "critical"


def test_threat_intel_url_extraction():
    res = check_target("https://flubot-gate.top/api/v1/collect")
    assert res is not None
    assert "FluBot" in res["threat_family"]


def test_threat_intel_dynamic_dns_abuse():
    res = check_target("trojan-controller.duckdns.org")
    assert res is not None
    assert res["type"] == "dynamic_dns_abuse"
    assert res["severity"] == "high"


def test_threat_intel_clean_domain():
    res = check_target("https://api.github.com/repos")
    assert res is None


def test_scan_iocs_batch():
    urls = ["https://teabot-c2.net/gate", "https://google.com/search", "http://badbazaar-sync.com/ping"]
    ips = ["198.51.100.23", "8.8.8.8"]

    matches = scan_iocs(urls, ips)
    assert len(matches) == 3
    indicators = [m["indicator"] for m in matches]
    assert "teabot-c2.net" in indicators
    assert "badbazaar-sync.com" in indicators
    assert "198.51.100.23" in indicators
