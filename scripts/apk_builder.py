"""scripts/apk_builder.py — Build real, properly signed Android APKs from source.

Uses the official Android toolchain so that test fixtures and evaluation samples
are genuine APKs (compiled binary manifest, resources.arsc, real DEX bytecode,
real v1/v2/v3 signatures) rather than hand-made ZIP files:

    aapt2 compile/link  ->  javac  ->  d8  ->  zipalign  ->  apksigner

Signing keys are generated into a temporary directory with keytool and are
never written into the repository.

Requirements: Android SDK (build-tools + a platform), a JDK (java, javac, keytool).
The SDK is located through ANDROID_HOME / ANDROID_SDK_ROOT or the default
per-user install location.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


class ToolchainUnavailable(RuntimeError):
    """Raised when the Android SDK or JDK required to build APKs is missing."""


@dataclass(frozen=True)
class Toolchain:
    aapt2: Path
    zipalign: Path | None
    d8_jar: Path
    apksigner_jar: Path
    android_jar: Path
    java: str
    javac: str
    keytool: str

    @classmethod
    def discover(cls) -> "Toolchain":
        sdk_candidates = [
            os.environ.get("ANDROID_HOME"),
            os.environ.get("ANDROID_SDK_ROOT"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"),
            os.path.expanduser("~/Library/Android/sdk"),
            os.path.expanduser("~/Android/Sdk"),
        ]
        sdk = next((Path(p) for p in sdk_candidates if p and Path(p, "build-tools").is_dir()), None)
        if sdk is None:
            raise ToolchainUnavailable("Android SDK not found (set ANDROID_HOME)")

        build_tools = sorted((sdk / "build-tools").iterdir(), key=lambda p: _version_key(p.name), reverse=True)
        platforms = sorted((sdk / "platforms").iterdir(), key=lambda p: _version_key(p.name), reverse=True)
        bt = next((b for b in build_tools if (b / "lib" / "d8.jar").exists()), None)
        plat = next((p for p in platforms if (p / "android.jar").exists()), None)
        if bt is None or plat is None:
            raise ToolchainUnavailable("Android build-tools or platform android.jar missing")

        exe = ".exe" if os.name == "nt" else ""
        java, javac, keytool = shutil.which("java"), shutil.which("javac"), shutil.which("keytool")
        if not (java and javac and keytool):
            raise ToolchainUnavailable("JDK (java, javac, keytool) not found on PATH")

        zipalign = bt / f"zipalign{exe}"
        return cls(
            aapt2=bt / f"aapt2{exe}",
            zipalign=zipalign if zipalign.exists() else None,
            d8_jar=bt / "lib" / "d8.jar",
            apksigner_jar=bt / "lib" / "apksigner.jar",
            android_jar=plat / "android.jar",
            java=java,
            javac=javac,
            keytool=keytool,
        )


def _version_key(name: str) -> tuple:
    parts = name.replace("android-", "").split(".")
    return tuple(int(p) if p.isdigit() else 0 for p in parts)


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(map(str, cmd))}\n{proc.stdout}\n{proc.stderr}")


@dataclass
class Keystore:
    path: Path
    alias: str
    password: str
    key_algorithm: str


def create_keystore(directory: Path, alias: str, key_algorithm: str = "EC",
                    dname: str = "CN=MerkleTrust Test, O=MerkleTrust, C=IN",
                    tools: Toolchain | None = None) -> Keystore:
    """Generate a throwaway PKCS#12 keystore (EC P-256 or RSA-2048)."""
    tools = tools or Toolchain.discover()
    path = Path(directory) / f"{alias}.p12"
    password = "throwaway-test-only"
    alg_args = (["-keyalg", "EC", "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA"]
                if key_algorithm == "EC" else ["-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA256withRSA"])
    _run([tools.keytool, "-genkeypair", "-keystore", str(path), "-storetype", "PKCS12",
          "-alias", alias, *alg_args, "-dname", dname, "-validity", "10000",
          "-storepass", password, "-keypass", password])
    return Keystore(path=path, alias=alias, password=password, key_algorithm=key_algorithm)


@dataclass
class AppSpec:
    """Declarative description of a small Android application."""
    package: str = "com.merkletrust.demo"
    version_code: int = 1
    version_name: str = "1.0"
    min_sdk: int = 24
    target_sdk: int = 34
    label: str = "MerkleTrust Demo"
    permissions: list[str] = field(default_factory=list)
    application_attrs: dict[str, str] = field(default_factory=dict)
    # Extra raw XML inside <application> (activities, services, receivers, providers).
    components_xml: str = ""
    # {relative/path/Foo.java: source}. A MainActivity is always generated.
    java_sources: dict[str, str] = field(default_factory=dict)
    main_activity_body: str = ""
    # Extra entries added to the APK before signing: {zip_path: bytes}.
    extra_files: dict[str, bytes] = field(default_factory=dict)
    strings: dict[str, str] = field(default_factory=lambda: {"greeting": "Hello from MerkleTrust"})

    def manifest_xml(self) -> str:
        perms = "\n".join(f'    <uses-permission android:name="{p}"/>' for p in self.permissions)
        app_attrs = " ".join(f'android:{k}="{v}"' for k, v in self.application_attrs.items())
        pkg_path = self.package
        return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{pkg_path}" android:versionCode="{self.version_code}" android:versionName="{self.version_name}">
    <uses-sdk android:minSdkVersion="{self.min_sdk}" android:targetSdkVersion="{self.target_sdk}"/>
{perms}
    <application android:label="@string/app_name" {app_attrs}>
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
{self.components_xml}
    </application>
</manifest>
"""

    def strings_xml(self) -> str:
        items = {"app_name": self.label, **self.strings}
        body = "\n".join(f'    <string name="{k}">{v}</string>' for k, v in items.items())
        return f'<?xml version="1.0" encoding="utf-8"?>\n<resources>\n{body}\n</resources>\n'

    def all_java_sources(self) -> dict[str, str]:
        pkg_dir = self.package.replace(".", "/")
        main = f"""package {self.package};

import android.app.Activity;
import android.os.Bundle;

public class MainActivity extends Activity {{
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
{self.main_activity_body}
    }}
}}
"""
        return {f"{pkg_dir}/MainActivity.java": main, **self.java_sources}


def build_unsigned(spec: AppSpec, out_path: Path, tools: Toolchain | None = None) -> Path:
    """Compile resources + code and produce an unsigned, aligned APK."""
    tools = tools or Toolchain.discover()
    out_path = Path(out_path)
    with tempfile.TemporaryDirectory(prefix="mt_build_") as tmp:
        tmp = Path(tmp)
        (tmp / "res" / "values").mkdir(parents=True)
        (tmp / "res" / "values" / "strings.xml").write_text(spec.strings_xml(), encoding="utf-8")
        (tmp / "AndroidManifest.xml").write_text(spec.manifest_xml(), encoding="utf-8")

        _run([str(tools.aapt2), "compile", "--dir", str(tmp / "res"), "-o", str(tmp / "res.zip")])
        base = tmp / "base.apk"
        _run([str(tools.aapt2), "link", "-o", str(base), "-I", str(tools.android_jar),
              "--manifest", str(tmp / "AndroidManifest.xml"), str(tmp / "res.zip")])

        src_root = tmp / "src"
        for rel, code in spec.all_java_sources().items():
            p = src_root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(code, encoding="utf-8")
        classes = tmp / "classes"
        classes.mkdir()
        java_files = [str(p) for p in src_root.rglob("*.java")]
        _run([tools.javac, "--release", "11", "-nowarn", "-cp", str(tools.android_jar),
              "-d", str(classes), *java_files])
        dex_out = tmp / "dex"
        dex_out.mkdir()
        class_files = [str(p) for p in classes.rglob("*.class")]
        _run([tools.java, "-cp", str(tools.d8_jar), "com.android.tools.r8.D8",
              "--lib", str(tools.android_jar), "--min-api", str(spec.min_sdk),
              "--output", str(dex_out), *class_files])

        with zipfile.ZipFile(base, "a", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(dex_out / "classes.dex", "classes.dex")
            for name, data in spec.extra_files.items():
                zf.writestr(name, data)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        if tools.zipalign:
            _run([str(tools.zipalign), "-f", "4", str(base), str(out_path)])
        else:
            shutil.copyfile(base, out_path)
    return out_path


def sign(unsigned: Path, out_path: Path, keystore: Keystore, schemes: tuple[str, ...] = ("v1", "v2"),
         min_sdk: int = 24, tools: Toolchain | None = None) -> Path:
    """Sign an APK with apksigner using the requested signature schemes."""
    tools = tools or Toolchain.discover()
    flags = []
    for scheme in ("v1", "v2", "v3"):
        flags += [f"--{scheme}-signing-enabled", "true" if scheme in schemes else "false"]
    _run([tools.java, "-jar", str(tools.apksigner_jar), "sign",
          "--ks", str(keystore.path), "--ks-key-alias", keystore.alias,
          "--ks-pass", f"pass:{keystore.password}", "--key-pass", f"pass:{keystore.password}",
          "--min-sdk-version", str(min_sdk), *flags,
          "--out", str(out_path), str(unsigned)])
    idsig = Path(str(out_path) + ".idsig")
    if idsig.exists():
        idsig.unlink()
    return Path(out_path)


def build_signed(spec: AppSpec, out_path: Path, keystore: Keystore,
                 schemes: tuple[str, ...] = ("v1", "v2"), tools: Toolchain | None = None) -> Path:
    tools = tools or Toolchain.discover()
    with tempfile.TemporaryDirectory(prefix="mt_sign_") as tmp:
        unsigned = build_unsigned(spec, Path(tmp) / "unsigned.apk", tools)
        return sign(unsigned, Path(out_path), keystore, schemes, spec.min_sdk, tools)
