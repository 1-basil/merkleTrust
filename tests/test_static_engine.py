"""Static engine on real APKs (regression for the binary-manifest crash) and on invalid input."""

from pathlib import Path
import pytest

from core.contracts import EngineError, JobContext
from core.static import classify_permission, run as run_static


def _run(path, tmp_path):
    ctx = JobContext(apk_path=str(path), workspace=str(tmp_path), prior={}, config={})
    return run_static("job-static", ctx)


def _ids(report):
    return {f["id"] for f in report["findings"]}


def test_real_benign_apk(fixture_apk, tmp_path):
    r = _run(fixture_apk("signed_v1v2_ec.apk"), tmp_path)
    assert r["status"] == "ok"
    assert r["manifest_format"] == "binary"
    assert r["package_name"] == "com.merkletrust.demo"
    assert r["version_code"] == 3
    assert r["signature"]["status"] == "verified"
    assert r["certificate"]["subject"].startswith("CN=MerkleTrust Demo Release")
    assert r["native_libs"][0]["path"] == "lib/arm64-v8a/libdemo.so"
    assert r["dex"]["files"][0]["checksum_valid"] is True
    assert r["dangerous_apis"] == []
    assert not _ids(r) & {"STATIC_DCL", "STATIC_CMD_EXEC", "STATIC_SIGNATURE_INVALID", "STATIC_UNSIGNED"}


def test_real_suspicious_apk(fixture_apk, tmp_path):
    r = _run(fixture_apk("suspicious_v2_ec.apk"), tmp_path)
    assert {"STATIC_DCL", "STATIC_CMD_EXEC", "STATIC_SMS_SEND", "STATIC_DANGEROUS_PERM"} <= _ids(r)
    assert r["application"]["debuggable"] is True


def test_unsigned_apk_flagged(fixture_apk, tmp_path):
    r = _run(fixture_apk("unsigned.apk"), tmp_path)
    assert r["signature"]["status"] == "unsigned"
    assert "STATIC_UNSIGNED" in _ids(r)


def test_prepended_data_flagged(fixture_apk, tmp_path):
    p = tmp_path / "janus.apk"
    p.write_bytes(b"dex\n035\x00" + b"\x00" * 100 + Path(fixture_apk("signed_v1v2_ec.apk")).read_bytes())
    r = _run(p, tmp_path)
    assert "STATIC_ARCHIVE_PREFIX" in _ids(r)
    assert r["signature"]["status"] == "invalid"


@pytest.mark.parametrize("content", [b"not a zip", b"PK\x03\x04truncated"])
def test_invalid_file_raises_engine_error(tmp_path, content):
    p = tmp_path / "bad.apk"
    p.write_bytes(content)
    with pytest.raises(EngineError, match="Invalid APK"):
        _run(p, tmp_path)


def test_permission_classification():
    assert classify_permission("android.permission.SEND_SMS")["is_dangerous"] is True
    assert classify_permission("android.permission.INTERNET") == {
        "name": "android.permission.INTERNET", "protection_level": "normal", "is_dangerous": False}
