"""Tests for the binary AndroidManifest.xml parser, using real aapt2-compiled manifests."""

import random
import zipfile

import pytest

from core.axml import AxmlError, parse_manifest, parse_manifest_xml


def _manifest(path):
    return zipfile.ZipFile(path).read("AndroidManifest.xml")


def test_parses_real_binary_manifest(fixture_apk):
    m = parse_manifest(_manifest(fixture_apk("signed_v1v2_ec.apk")))
    assert m["format"] == "binary"
    assert m["package_name"] == "com.merkletrust.demo"
    assert m["version_code"] == 3
    assert m["version_name"] == "1.2.0"
    assert m["min_sdk"] == 24
    assert m["target_sdk"] == 34
    assert m["permissions"] == ["android.permission.INTERNET"]
    assert m["application"]["allowBackup"] is False
    assert "com.merkletrust.demo.MainActivity" in m["components"]["activities"]
    service = next(c for c in m["component_details"] if c["name"].endswith("SyncService"))
    assert service["type"] == "service"
    assert service["exported"] is False
    assert service["exported_effective"] is False


def test_security_relevant_flags(fixture_apk):
    m = parse_manifest(_manifest(fixture_apk("suspicious_v2_ec.apk")))
    assert m["application"]["debuggable"] is True
    assert m["application"]["usesCleartextTraffic"] is True
    assert "android.permission.SEND_SMS" in m["permissions"]
    receiver = next(c for c in m["component_details"] if c["name"].endswith("BootReceiver"))
    assert receiver["has_intent_filter"] is True
    assert receiver["exported_effective"] is True
    assert receiver["permission"] is None


def test_attribute_names_resolved_by_resource_id(fixture_apk):
    """Obfuscators blank attribute-name strings; the resource-ID map must still work."""
    data = _manifest(fixture_apk("signed_v1v2_ec.apk"))
    for encoded in ("versionCode".encode("utf-16-le"), b"versionCode"):
        if encoded in data:
            data = data.replace(encoded, b"x" * len(encoded))
            break
    else:
        pytest.skip("attribute string not found in pool")
    assert parse_manifest(data)["version_code"] == 3


def test_text_manifest_fallback_is_labelled(fixture_apk):
    m = parse_manifest(b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                       b'package="a.b" android:versionCode="5"><uses-permission android:name="p.Q"/></manifest>')
    assert m["format"] == "text"
    assert m["package_name"] == "a.b"
    assert m["version_code"] == 5
    assert m["permissions"] == ["p.Q"]


@pytest.mark.parametrize("data", [b"", b"\x03\x00\x08\x00", b"\x03\x00\x08\x00\xff\xff\xff\x7f" + b"\x00" * 30,
                                  b"\x89PNG garbage", "<html/>".encode()])
def test_invalid_input_raises_axml_error(data):
    with pytest.raises(AxmlError):
        parse_manifest(data)


def test_compat_wrapper_never_raises():
    assert parse_manifest_xml(b"junk")["format"] == "invalid"


def test_truncation_and_fuzzing_only_raise_axml_error(fixture_apk):
    data = _manifest(fixture_apk("suspicious_v2_ec.apk"))
    rng = random.Random(1337)
    for cut in range(8, len(data), 37):
        try:
            parse_manifest(data[:cut])
        except AxmlError:
            pass
    for _ in range(400):
        mutated = bytearray(data)
        for _ in range(rng.randint(1, 8)):
            mutated[rng.randrange(8, len(mutated))] = rng.randrange(256)
        try:
            parse_manifest(bytes(mutated))
        except AxmlError:
            pass
