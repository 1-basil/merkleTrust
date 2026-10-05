"""APK signature verification tests (v1 JAR, v2, v3) on real apksigner output,
including the attacks the verifier must catch."""

from pathlib import Path
import zipfile

import pytest

from core.apk_archive import ApkArchive
from core.apk_signature import locate_signing_block, verify_apk
from scripts.apk_mutations import flip_byte, local_header_offset, rewrite_zip

pytestmark = [pytest.mark.unit, pytest.mark.security]


def _verify(path):
    with ApkArchive(str(path)) as apk:
        return verify_apk(apk)


@pytest.mark.parametrize("name,schemes,key_alg", [
    ("signed_v1v2_ec.apk", ["v1", "v2"], "EC"),
    ("signed_v1only_ec.apk", ["v1"], "EC"),
    ("signed_v2v3_rsa.apk", ["v2", "v3"], "RSA"),
    ("suspicious_v2_ec.apk", ["v2"], "EC"),
])
def test_genuine_signatures_verify(fixture_apk, name, schemes, key_alg):
    r = _verify(fixture_apk(name))
    assert r["status"] == "verified", r["errors"]
    assert r["schemes_present"] == schemes
    assert r["certificate_verified"] is True
    assert r["certificate"]["public_key"]["algorithm"] == key_alg
    assert len(r["certificate"]["sha256"]) == 64


def test_certificate_details(fixture_apk):
    cert = _verify(fixture_apk("signed_v1v2_ec.apk"))["certificate"]
    assert cert["subject"] == "CN=MerkleTrust Demo Release,O=MerkleTrust,C=IN"
    assert cert["self_signed"] is True
    assert cert["public_key"]["curve"] == "secp256r1"
    assert cert["valid_from"] < cert["valid_to"]
    assert cert["expired"] is False


def test_v1_only_rejected_by_policy_for_modern_target_sdk(fixture_apk):
    """Matches apksigner: targetSdk >= 30 requires v2+, even if the v1 signature is valid."""
    with ApkArchive(fixture_apk("signed_v1only_ec.apk")) as apk:
        r = verify_apk(apk, target_sdk=34)
    assert r["schemes"]["v1"]["verified"] is True
    assert r["status"] == "invalid"
    assert r["errors"][0].startswith("policy:")
    with ApkArchive(fixture_apk("signed_v1only_ec.apk")) as apk:
        assert verify_apk(apk, target_sdk=29)["status"] == "verified"


def test_unsigned(fixture_apk):
    r = _verify(fixture_apk("unsigned.apk"))
    assert r["status"] == "unsigned"
    assert r["certificate"] == {}


def test_resigned_apk_verifies_with_a_different_certificate(fixture_apk):
    """Re-signing is cryptographically valid — only a baseline can reveal it."""
    original = _verify(fixture_apk("signed_v1v2_ec.apk"))["certificate"]["sha256"]
    resigned = _verify(fixture_apk("signed_v2v3_rsa.apk"))["certificate"]["sha256"]
    assert original != resigned


def test_v1_modified_file_detected(tmp_path, fixture_apk):
    out = rewrite_zip(fixture_apk("signed_v1only_ec.apk"), tmp_path / "m.apk",
                      modify={"assets/config.json": b'{"endpoint": "https://evil.example"}'})
    r = _verify(out)
    assert r["status"] == "invalid"
    assert r["schemes"]["v1"]["mismatched_entries"] == ["assets/config.json"]


def test_v1_injected_file_detected(tmp_path, fixture_apk):
    out = rewrite_zip(fixture_apk("signed_v1only_ec.apk"), tmp_path / "i.apk",
                      add={"assets/payload.bin": b"\x00evil"})
    r = _verify(out)
    assert r["status"] == "invalid"
    assert r["schemes"]["v1"]["unsigned_entries"] == ["assets/payload.bin"]


def test_v1_deleted_file_detected(tmp_path, fixture_apk):
    out = rewrite_zip(fixture_apk("signed_v1only_ec.apk"), tmp_path / "d.apk", remove={"assets/config.json"})
    r = _verify(out)
    assert r["status"] == "invalid"
    assert r["schemes"]["v1"]["missing_entries"] == ["assets/config.json"]


def test_v1_tampered_signature_file(tmp_path, fixture_apk):
    src = fixture_apk("signed_v1only_ec.apk")
    sf_name = next(n for n in zipfile.ZipFile(src).namelist() if n.endswith(".SF"))
    sf = zipfile.ZipFile(src).read(sf_name)
    out = rewrite_zip(src, tmp_path / "s.apk", modify={sf_name: sf + b"X-Injected: 1\r\n"})
    r = _verify(out)
    assert r["status"] == "invalid"
    assert any("INVALID" in e or "messageDigest" in e for e in r["errors"])


def test_v2_signature_stripping_detected(tmp_path, fixture_apk):
    """Removing the v2 block to fall back to (weaker) v1 must be detected."""
    out = rewrite_zip(fixture_apk("signed_v1v2_ec.apk"), tmp_path / "strip.apk")
    r = _verify(out)
    assert r["schemes"]["v1"]["verified"] is True
    assert r["schemes"]["v2"]["present"] is False
    assert r["status"] == "invalid"
    assert any("stripping" in e for e in r["errors"])


def test_v2_content_modification_detected(tmp_path, fixture_apk):
    src = fixture_apk("suspicious_v2_ec.apk")
    # Byte 10 of a local file header is the modification time: not CRC-protected,
    # invisible to zipfile, but covered by the v2 content digest.
    out = flip_byte(src, tmp_path / "t.apk", local_header_offset(src, "classes.dex") + 10)
    r = _verify(out)
    assert r["status"] == "invalid"
    assert any("content digest mismatch" in e for e in r["errors"])
    assert r["certificate_verified"] is False
    assert r["certificate"]["subject"].startswith("CN=MerkleTrust Demo Release")  # claimed, not verified


def test_v2_forged_signed_data_detected(tmp_path, fixture_apk):
    src = fixture_apk("suspicious_v2_ec.apk")
    data = Path(src).read_bytes()
    loc = locate_signing_block(data)
    # Flip a byte early inside the v2 signed-data (inside the digests list).
    out = flip_byte(src, tmp_path / "f.apk", loc["block_offset"] + 8 + 12 + 4 + 4 + 4 + 4 + 4 + 4 + 8)
    r = _verify(out)
    assert r["status"] == "invalid"
    assert r["errors"] == ["v2: signature over signed data is INVALID"]


def test_truncated_apk_does_not_crash(tmp_path, fixture_apk):
    data = Path(fixture_apk("signed_v1v2_ec.apk")).read_bytes()
    p = tmp_path / "trunc.apk"
    p.write_bytes(data[: len(data) // 2])
    try:
        _verify(p)
    except Exception as exc:  # the archive layer must reject it cleanly
        assert type(exc).__name__ == "ApkValidationError"
