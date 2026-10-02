"""Tests for DEX parsing and sensitive-API detection on real d8-compiled bytecode."""

import random
import zipfile

import pytest

from core.dex import DexError, analyze_dex_files, extract_iocs, parse_dex

pytestmark = pytest.mark.unit


def _dex(path):
    return zipfile.ZipFile(path).read("classes.dex")


def test_parses_real_dex(fixture_apk):
    d = parse_dex(_dex(fixture_apk("signed_v1v2_ec.apk")))
    assert d["checksum_valid"] and d["signature_valid"]
    assert d["file_size_header"] == d["file_size_actual"]
    classes = [c for c, _ in d["classes"]]
    assert "Lcom/merkletrust/demo/MainActivity;" in classes
    assert ("Landroid/app/Activity;", "onCreate") in d["method_refs"]


def test_benign_app_has_no_dangerous_apis(fixture_apk):
    r = analyze_dex_files([("classes.dex", _dex(fixture_apk("signed_v1v2_ec.apk")))])
    assert r["dangerous_apis"] == []
    assert r["iocs"]["urls"] == ["https://api.merkletrust-demo.com/v1/health"]


def test_dangerous_apis_found_by_method_reference(fixture_apk):
    r = analyze_dex_files([("classes.dex", _dex(fixture_apk("suspicious_v2_ec.apk")))])
    apis = {a["api"]: a for a in r["dangerous_apis"]}
    assert {"RuntimeExec", "DexClassLoader", "SmsManager_sendTextMessage"} <= set(apis)
    assert all(a["match"] == "method_ref" for a in apis.values())
    assert apis["RuntimeExec"]["class"] == "java.lang.Runtime"
    assert "http://198.51.100.7:8080/c2/beacon" in r["iocs"]["urls"]


def test_patched_dex_fails_header_checks(fixture_apk):
    data = bytearray(_dex(fixture_apk("signed_v1v2_ec.apk")))
    data[-10] ^= 0xFF
    d = parse_dex(bytes(data))
    assert d["checksum_valid"] is False
    assert d["signature_valid"] is False


def test_non_dex_uses_labelled_string_fallback():
    blob = b"junk Ldalvik/system/DexClassLoader; more junk"
    with pytest.raises(DexError):
        parse_dex(blob)
    r = analyze_dex_files([("classes.dex", blob)])
    assert r["dex_files"][0]["parsed"] is False
    assert r["dangerous_apis"][0]["api"] == "DexClassLoader"
    assert r["dangerous_apis"][0]["match"] == "string"


def test_ioc_filtering():
    iocs = extract_iocs(["connect 8.8.8.8 and 10.0.0.1 and 127.0.0.1", "evil-c2.xyz",
                         "https://schemas.android.com/apk/res/android", "admin@evil-c2.xyz",
                         "Lcom/example/Foo;"])
    assert iocs["ips"] == ["8.8.8.8"]
    assert iocs["domains"] == ["evil-c2.xyz"]
    assert iocs["urls"] == []
    assert iocs["emails"] == ["admin@evil-c2.xyz"]


def test_truncated_and_fuzzed_dex_only_raise_dex_error(fixture_apk):
    data = _dex(fixture_apk("suspicious_v2_ec.apk"))
    for cut in range(0, len(data), 61):
        try:
            parse_dex(data[:cut])
        except DexError:
            pass
    rng = random.Random(7)
    for _ in range(300):
        mutated = bytearray(data)
        for _ in range(rng.randint(1, 6)):
            mutated[rng.randrange(0x38, 0x70)] = rng.randrange(256)
        try:
            parse_dex(bytes(mutated))
        except DexError:
            pass
