"""Static engine on real APKs (regression for the binary-manifest crash) and on invalid input."""

from pathlib import Path
import pytest

from core.contracts import EngineError, JobContext
from core.static import classify_permission, run as run_static

pytestmark = pytest.mark.unit


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


# ------------------------------------------------- call sites and context-aware rules --

def _units(*u):
    import struct
    return b"".join(struct.pack("<H", x) for x in u)


def test_bytecode_walker_finds_invokes_and_skips_payloads():
    from core.dex import _invoked
    # invoke-virtual {..}, meth@7 ; packed-switch payload containing the bytes 0x0009 ; invoke-static meth@9
    code = _units(0x206E, 7, 0x0000) + _units(0x0100, 1, 0, 0, 0x0009, 0x0009) + _units(0x1071, 9, 0x0000)
    assert _invoked(code, {7, 9}) == {7, 9}
    # The same index only inside a payload is not a call.
    assert _invoked(_units(0x0E) + _units(0x0100, 1, 0, 0, 0x0005, 0x0005), {5}) == set()
    # A const/16 whose literal equals the index is not a call either.
    assert _invoked(_units(0x0013, 0x0005, 0x000E), {5}) == set()


def test_real_apk_attributes_calls_to_classes(fixture_apk):
    from core.static import analyze_apk
    report = analyze_apk(fixture_apk("suspicious_v2_ec.apk"))
    called = [a for a in report["dangerous_apis"] if a.get("callers")]
    assert called and all(isinstance(c, str) and "." in c for a in called for c in a["callers"])


def _minimal(component_details=(), apis=()):
    manifest = {"format": "binary", "application": {}, "component_details": list(component_details),
                "target_sdk": 34, "min_sdk": 26, "permissions": ["android.permission.INTERNET",
                                                                 "android.permission.READ_PHONE_STATE",
                                                                 "android.permission.READ_CONTACTS"]}
    signature = {"status": "verified", "errors": [], "certificate": {}}
    dex = {"dex_files": [], "dangerous_apis": list(apis), "sensitive_classes": [],
           "iocs": {"ips": [], "urls": [], "domains": [], "emails": []}}
    return manifest, signature, dex


def _api(api, callers):
    return {"api": api, "class": "x", "method": "m", "source": "classes.dex", "match": "method_ref", "callers": callers}


def test_widget_receivers_are_not_unprotected_exports():
    from core.static import static_findings
    widget = {"name": "a.Widget", "type": "receiver", "exported_effective": True, "permission": None,
              "intent_actions": ["android.appwidget.action.APPWIDGET_UPDATE"]}
    other = dict(widget, name="a.Open", intent_actions=["a.CUSTOM"])
    ids = lambda comps: [f["id"] for f in static_findings(*_minimal(comps)[:1], [], *_minimal()[1:], [])]
    assert "STATIC_EXPORTED_UNPROTECTED" not in ids([widget])
    assert "STATIC_EXPORTED_UNPROTECTED" in ids([widget, other])


def test_library_only_calls_count_a_quarter_and_never_make_a_malware_pattern():
    from core.static import static_findings
    m, s, d = _minimal(apis=[_api("RuntimeExec", ["org.acra.collector.MemoryInfoCollector"]),
                             _api("TelephonyManager_getDeviceId", ["androidx.core.telephony.TelephonyManagerCompat"])])
    found = {f["id"]: f for f in static_findings(m, [], s, d, [])}
    assert found["STATIC_CMD_EXEC"]["points"] == 15 // 4 and "well-known libraries" in found["STATIC_CMD_EXEC"]["evidence"]
    assert "PATTERN_SPYWARE" not in found

    m, s, d = _minimal(apis=[_api("RuntimeExec", ["org.acra.X", "com.evil.app.Shell"]),
                             _api("TelephonyManager_getDeviceId", ["com.evil.app.Collector"])])
    found = {f["id"]: f for f in static_findings(m, [], s, d, [])}
    assert found["STATIC_CMD_EXEC"]["points"] == 15 and "com.evil.app.Shell" in found["STATIC_CMD_EXEC"]["evidence"]
    assert "PATTERN_SPYWARE" in found
