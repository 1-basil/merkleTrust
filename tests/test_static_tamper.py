"""tests/test_static_tamper.py — Tests for Ashwini's Static & Tamper Engines."""

import os
import json
import zipfile
import tempfile
import hashlib
import pytest

from core.contracts import JobContext
from core.static import run as run_static, classify_permission
from core.tamper import run as run_tamper
from core.merkle import build_tree, root


def create_sample_apk(path: str, package_name: str = "com.test.secureapp", is_tampered: bool = False):
    """Generate a synthetic APK zip for testing."""
    manifest_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}"
    android:versionCode="100"
    android:versionName="1.0.0">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.SEND_SMS"/>
    {"<uses-permission android:name='android.permission.READ_CONTACTS'/>" if is_tampered else ""}
    <application android:name=".App" android:label="TestApp">
        <activity android:name=".MainActivity" android:exported="true"/>
        <service android:name=".SyncService" android:exported="false"/>
        {"<service android:name='.PayloadService' android:exported='true'/>" if is_tampered else ""}
    </application>
</manifest>"""

    # Create dummy DEX
    dex_strings = b"dex\n035\x00" + b"\x00" * 48
    if is_tampered:
        dex_strings += b"Lcom/evil/Payload; Ldalvik/system/DexClassLoader; https://c2.malicious-c2.xyz/beacon 198.51.100.99"
    else:
        dex_strings += b"Lcom/test/secureapp/MainActivity; https://api.test.com/v1/health"

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
        zf.writestr("classes.dex", dex_strings)
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 100)
        zf.writestr("META-INF/CERT.RSA", b"CERTIFICATE_BYTES_SAMPLE" if not is_tampered else b"TAMPERED_CERTIFICATE_BYTES")


def test_permission_classification():
    p1 = classify_permission("android.permission.SEND_SMS")
    assert p1["is_dangerous"] is True
    assert p1["protection_level"] == "dangerous"

    p2 = classify_permission("android.permission.INTERNET")
    assert p2["is_dangerous"] is False
    assert p2["protection_level"] == "normal"


def test_static_engine_run():
    with tempfile.TemporaryDirectory() as tmpdir:
        apk_path = os.path.join(tmpdir, "test.apk")
        create_sample_apk(apk_path, "com.test.secureapp", is_tampered=False)

        ws = os.path.join(tmpdir, "job1_ws")
        os.makedirs(ws, exist_ok=True)

        ctx = JobContext(apk_path=apk_path, workspace=ws, prior={}, config={})
        res = run_static("job_static_1", ctx)

        assert res["job_id"] == "job_static_1"
        assert res["engine"] == "static"
        assert res["status"] == "ok"
        assert res["package_name"] == "com.test.secureapp"
        assert len(res["permissions"]) >= 2
        assert "com.test.secureapp.MainActivity" in res["components"]["activities"]
        assert "com.test.secureapp.SyncService" in res["components"]["services"]
        assert len(res["native_libs"]) == 1
        assert res["native_libs"][0]["arch"] == "arm64-v8a"
        assert os.path.exists(ctx.out("static.json"))


def test_tamper_engine_baseline_and_comparison():
    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. Clean APK as baseline
        apk_clean = os.path.join(tmpdir, "clean.apk")
        create_sample_apk(apk_clean, "com.test.app", is_tampered=False)

        ws1 = os.path.join(tmpdir, "job1")
        os.makedirs(ws1, exist_ok=True)

        base_db = os.path.join(tmpdir, "baselines.json")
        ctx1 = JobContext(apk_path=apk_clean, workspace=ws1, prior={}, config={"baseline_storage_path": base_db})
        static1 = run_static("job1", ctx1)

        # Build mock integrity
        with open(apk_clean, "rb") as fh:
            apk1_bytes = fh.read()
        chunk_size = 65536
        chunks1 = [
            {"index": 0, "offset": 0, "length": len(apk1_bytes), "hash": hashlib.sha256(apk1_bytes).hexdigest()}
        ]
        file_map1 = [
            {"path": "classes.dex", "offset": 0, "length": len(apk1_bytes), "sha256": hashlib.sha256(b"dex").hexdigest()},
            {"path": "AndroidManifest.xml", "offset": 0, "length": 500, "sha256": "abc"},
        ]
        integrity1 = {
            "job_id": "job1",
            "merkle_root": chunks1[0]["hash"],
            "chunks": chunks1,
            "file_map": file_map1,
        }

        ctx1.prior = {"integrity": integrity1, "static": static1}
        tamper1 = run_tamper("job1", ctx1)

        assert tamper1["role"] == "baseline"
        assert tamper1["baseline_found"] is False
        assert tamper1["changed_chunks"] == []
        assert tamper1["suspicious_targets"] == []

        # 2. Tampered APK compared against baseline
        apk_tampered = os.path.join(tmpdir, "tampered.apk")
        create_sample_apk(apk_tampered, "com.test.app", is_tampered=True)

        ws2 = os.path.join(tmpdir, "job2")
        os.makedirs(ws2, exist_ok=True)

        ctx2 = JobContext(apk_path=apk_tampered, workspace=ws2, prior={}, config={"baseline_storage_path": base_db})
        static2 = run_static("job2", ctx2)

        with open(apk_tampered, "rb") as fh:
            apk2_bytes = fh.read()
        chunks2 = [
            {"index": 0, "offset": 0, "length": len(apk2_bytes), "hash": hashlib.sha256(apk2_bytes).hexdigest()}
        ]
        file_map2 = [
            {"path": "classes.dex", "offset": 0, "length": len(apk2_bytes), "sha256": hashlib.sha256(b"tampered_dex").hexdigest()},
            {"path": "AndroidManifest.xml", "offset": 0, "length": 600, "sha256": "def"},
        ]
        integrity2 = {
            "job_id": "job2",
            "merkle_root": chunks2[0]["hash"],
            "chunks": chunks2,
            "file_map": file_map2,
        }

        ctx2.prior = {"integrity": integrity2, "static": static2}
        tamper2 = run_tamper("job2", ctx2)

        assert tamper2["role"] == "comparison"
        assert tamper2["baseline_found"] is True
        assert tamper2["baseline_job_id"] == "job1"
        assert len(tamper2["changed_chunks"]) == 1
        assert any(f["path"] == "classes.dex" for f in tamper2["changed_files"])
        assert "android.permission.READ_CONTACTS" in tamper2["manifest_diff"]["permissions_added"]
        assert "com.test.app.PayloadService" in tamper2["manifest_diff"]["components_added"]
        assert len(tamper2["suspicious_targets"]) > 0
        assert os.path.exists(ctx2.out("tamper.json"))
