"""scripts/build_fixtures.py — Regenerate the real, signed APK test fixtures.

    python -m scripts.build_fixtures

Writes small genuine APKs into tests/fixtures/apks/. They are committed so the
test suite runs on machines without the Android SDK. Signing keys are created in
a temporary directory and destroyed afterwards — only public certificates end up
inside the APKs.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from scripts.apk_builder import AppSpec, Toolchain, build_signed, build_unsigned, create_keystore

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "apks"

FAKE_ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57


def benign_spec() -> AppSpec:
    return AppSpec(
        package="com.merkletrust.demo",
        version_code=3,
        version_name="1.2.0",
        permissions=["android.permission.INTERNET"],
        application_attrs={"allowBackup": "false"},
        components_xml='        <service android:name=".SyncService" android:exported="false"/>',
        java_sources={
            "com/merkletrust/demo/SyncService.java": """package com.merkletrust.demo;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
public class SyncService extends Service {
    @Override public IBinder onBind(Intent intent) { return null; }
}
""",
        },
        main_activity_body='        android.util.Log.i("Demo", "https://api.merkletrust-demo.com/v1/health");',
        extra_files={"assets/config.json": b'{"endpoint": "https://api.merkletrust-demo.com"}',
                     "lib/arm64-v8a/libdemo.so": FAKE_ELF},
    )


def suspicious_spec() -> AppSpec:
    return AppSpec(
        package="com.merkletrust.suspicious",
        version_code=1,
        version_name="0.9",
        min_sdk=24,
        target_sdk=34,
        permissions=["android.permission.INTERNET", "android.permission.SEND_SMS",
                     "android.permission.READ_CONTACTS", "android.permission.RECEIVE_BOOT_COMPLETED"],
        application_attrs={"debuggable": "true", "usesCleartextTraffic": "true", "allowBackup": "true"},
        components_xml="""        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter>
        </receiver>""",
        java_sources={
            "com/merkletrust/suspicious/BootReceiver.java": """package com.merkletrust.suspicious;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.telephony.SmsManager;
import dalvik.system.DexClassLoader;
public class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context ctx, Intent intent) {
        try {
            Runtime.getRuntime().exec("id");
            new DexClassLoader("/data/local/tmp/p.dex", ctx.getCacheDir().getPath(), null, getClass().getClassLoader());
            SmsManager.getDefault().sendTextMessage("+10000000000", null, "hi", null, null);
        } catch (Exception e) { }
        android.util.Log.i("x", "http://198.51.100.7:8080/c2/beacon");
    }
}
""",
        },
    )


def main() -> None:
    tools = Toolchain.discover()
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mt_keys_") as keydir:
        key_a = create_keystore(Path(keydir), "release", "EC",
                                "CN=MerkleTrust Demo Release, O=MerkleTrust, C=IN", tools)
        key_b = create_keystore(Path(keydir), "other", "RSA",
                                "CN=Unknown Re-signer, O=Elsewhere, C=US", tools)
        outputs = {
            "signed_v1v2_ec.apk": (benign_spec(), key_a, ("v1", "v2")),
            "signed_v1only_ec.apk": (benign_spec(), key_a, ("v1",)),
            "signed_v2v3_rsa.apk": (benign_spec(), key_b, ("v2", "v3")),
            "suspicious_v2_ec.apk": (suspicious_spec(), key_a, ("v2",)),
        }
        for name, (spec, key, schemes) in outputs.items():
            build_signed(spec, FIXTURE_DIR / name, key, schemes, tools)
            print(f"built {name}")
        build_unsigned(benign_spec(), FIXTURE_DIR / "unsigned.apk", tools)
        print("built unsigned.apk")


if __name__ == "__main__":
    main()
