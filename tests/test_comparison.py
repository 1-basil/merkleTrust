"""Pure integrity-comparison rules on synthetic snapshots (cases that would need re-signing)."""

import hashlib

import pytest

from core.comparison import build_profile, compare_with_baseline
from core.file_manifest import categorize

pytestmark = pytest.mark.unit


def _f(path, content):
    return {"path": path, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
            "category": categorize(path)}


PROFILE = {"version_code": 5, "version_name": "2.0", "permissions": [], "components": [], "application": {},
           "certificate": {"subject": "CN=Dev"}, "dangerous_apis": [], "network_urls": []}


def snap(files, cert="c" * 64, apk="a" * 64, sig="verified", profile=None):
    return {"files": files, "profile": profile or PROFILE, "apk_sha256": apk, "certificate_sha256": cert,
            "chunk_hashes": [], "chunk_size": 65536, "signature_status": sig}


BASE = [_f("classes.dex", b"code"), _f("META-INF/CERT.SF", b"sf1"), _f("META-INF/CERT.EC", b"sig1")]


def test_resigned_with_same_certificate_is_clean():
    cur = [_f("classes.dex", b"code"), _f("META-INF/CERT.SF", b"sf2"), _f("META-INF/CERT.EC", b"sig2")]
    r = compare_with_baseline(snap(BASE), snap(cur, apk="b" * 64))
    assert r["status"] == "CLEAN"
    assert r["byte_identical"] is False
    assert r["counts"]["signature_files_changed"] == 2
    assert any("same certificate" in x for x in r["reasons"])


def test_invalid_signature_is_modified_even_if_files_match():
    r = compare_with_baseline(snap(BASE), snap(BASE, sig="invalid"))
    assert r["status"] == "MODIFIED"


def test_certificate_change_wins_over_modification():
    cur = [_f("classes.dex", b"evil"), *BASE[1:]]
    r = compare_with_baseline(snap(BASE), snap(cur, cert="d" * 64))
    assert r["status"] == "CERTIFICATE_CHANGED"
    assert r["counts"]["modified"] == 1


def test_unsigned_upload_is_certificate_changed():
    r = compare_with_baseline(snap(BASE), snap(BASE, cert="", sig="unsigned"))
    assert r["status"] == "CERTIFICATE_CHANGED"
    assert "no verifiable signing certificate" in r["reasons"][0]


def test_version_downgrade_flagged():
    older = {**PROFILE, "version_code": 3}
    r = compare_with_baseline(snap(BASE), snap(BASE, profile=older))
    assert r["version"]["downgrade"] is True
    assert any("downgrade" in x for x in r["reasons"])


def test_profile_excludes_time_dependent_fields():
    p = build_profile({"certificate": {"sha256": "x", "expired": False, "not_yet_valid": False}})
    assert p["certificate"] == {"sha256": "x"}
