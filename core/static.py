"""core/static.py — ASHWINI.

Static Analysis Engine for Android APKs.

Extracts, from a validated archive (core.apk_archive):
  * manifest model — package, versions, SDK levels, permissions, application
    flags (debuggable, allowBackup, cleartext), components and export state
    (core.axml, binary AXML);
  * signing certificate and signature verification for v1/v2/v3
    (core.apk_signature);
  * DEX consistency, sensitive API references, sensitive base classes and
    network indicators (core.dex);
  * native libraries with SHA-256.

Outputs static.json. Risk interpretation of these facts lives in the scoring
engine; findings here describe what was observed.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from core.apk_archive import ApkArchive, ApkValidationError
from core.apk_signature import verify_apk
from core.axml import AxmlError, parse_manifest
from core.contracts import EngineError, JobContext, emit
from core.dex import analyze_dex_files

# Known Android dangerous permissions (Android runtime permissions)
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR": "dangerous",
    "android.permission.WRITE_CALENDAR": "dangerous",
    "android.permission.CAMERA": "dangerous",
    "android.permission.READ_CONTACTS": "dangerous",
    "android.permission.WRITE_CONTACTS": "dangerous",
    "android.permission.GET_ACCOUNTS": "dangerous",
    "android.permission.ACCESS_FINE_LOCATION": "dangerous",
    "android.permission.ACCESS_COARSE_LOCATION": "dangerous",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "dangerous",
    "android.permission.RECORD_AUDIO": "dangerous",
    "android.permission.READ_PHONE_STATE": "dangerous",
    "android.permission.READ_PHONE_NUMBERS": "dangerous",
    "android.permission.CALL_PHONE": "dangerous",
    "android.permission.ANSWER_PHONE_CALLS": "dangerous",
    "android.permission.READ_CALL_LOG": "dangerous",
    "android.permission.WRITE_CALL_LOG": "dangerous",
    "android.permission.ADD_VOICEMAIL": "dangerous",
    "android.permission.USE_SIP": "dangerous",
    "android.permission.PROCESS_OUTGOING_CALLS": "dangerous",
    "android.permission.BODY_SENSORS": "dangerous",
    "android.permission.BODY_SENSORS_BACKGROUND": "dangerous",
    "android.permission.SEND_SMS": "dangerous",
    "android.permission.RECEIVE_SMS": "dangerous",
    "android.permission.READ_SMS": "dangerous",
    "android.permission.RECEIVE_WAP_PUSH": "dangerous",
    "android.permission.RECEIVE_MMS": "dangerous",
    "android.permission.READ_EXTERNAL_STORAGE": "dangerous",
    "android.permission.WRITE_EXTERNAL_STORAGE": "dangerous",
    "android.permission.ACCESS_MEDIA_LOCATION": "dangerous",
    "android.permission.POST_NOTIFICATIONS": "dangerous",
    "android.permission.NEARBY_WIFI_DEVICES": "dangerous",
    "android.permission.BLUETOOTH_SCAN": "dangerous",
    "android.permission.BLUETOOTH_CONNECT": "dangerous",
    "android.permission.BLUETOOTH_ADVERTISE": "dangerous",
    "android.permission.SYSTEM_ALERT_WINDOW": "signature/dangerous",
    "android.permission.WRITE_SETTINGS": "signature/dangerous",
    "android.permission.REQUEST_INSTALL_PACKAGES": "signature/dangerous",
}

SIGNATURE_PERMISSIONS = {
    "android.permission.INSTALL_PACKAGES": "signature",
    "android.permission.DELETE_PACKAGES": "signature",
    "android.permission.BATTERY_STATS": "signature",
    "android.permission.REBOOT": "signature",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "signature",
    "android.permission.BIND_DEVICE_ADMIN": "signature",
}


def classify_permission(name: str) -> dict[str, Any]:
    """Return protection level and dangerous boolean flag for an Android permission."""
    if name in DANGEROUS_PERMISSIONS:
        return {"name": name, "protection_level": "dangerous", "is_dangerous": True}
    if name in SIGNATURE_PERMISSIONS:
        return {"name": name, "protection_level": "signature", "is_dangerous": False}
    return {"name": name, "protection_level": "normal", "is_dangerous": False}



def _run_decompiler(cmd: list[str], timeout_s: int) -> bool:
    """Run an optional external decompiler (apktool / jadx). Opt-in via config."""
    if not shutil.which(cmd[0]) and not os.path.isfile(cmd[0]):
        return False
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout_s).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _finding(fid: str, severity: str, title: str, evidence: str) -> dict[str, str]:
    return {"id": fid, "severity": severity, "title": title, "evidence": evidence}


def _signature_summary(sig: dict[str, Any]) -> dict[str, Any]:
    """Compact, JSON-friendly view of the verification result."""
    schemes = {}
    for name, s in sig["schemes"].items():
        schemes[name] = {
            "present": s.get("present", False),
            "verified": s.get("verified", False),
            "algorithms": s.get("algorithms", []),
            "errors": s.get("errors", []),
        }
        for key in ("mismatched_entries", "missing_entries", "unsigned_entries", "apk_signed_claims"):
            if s.get(key):
                schemes[name][key] = s[key]
    return {"status": sig["status"], "schemes_present": sig["schemes_present"],
            "certificate_verified": sig["certificate_verified"], "schemes": schemes, "errors": sig["errors"]}


def analyze_apk(apk_path: str, limits: dict | None = None) -> dict[str, Any]:
    """Pure analysis function (no workspace, no job). Raises ApkValidationError."""
    findings: list[dict[str, str]] = []
    with ApkArchive(apk_path, limits=limits) as apk:
        for warning in apk.report.warnings:
            findings.append(_finding("STATIC_ARCHIVE_PREFIX", "high",
                                     "Unexpected data before the APK contents", warning))

        try:
            manifest = parse_manifest(apk.read("AndroidManifest.xml", max_bytes=8 * 1024 * 1024))
        except AxmlError as exc:
            raise ApkValidationError(f"AndroidManifest.xml could not be parsed: {exc}") from None
        if manifest["format"] != "binary":
            findings.append(_finding("STATIC_TEXT_MANIFEST", "medium",
                                     "Manifest is not compiled binary XML",
                                     "Android only installs APKs with a compiled manifest; this archive "
                                     "was not produced by the Android build tools."))

        signature = verify_apk(apk, target_sdk=manifest["target_sdk"])
        dex_files = [(n, apk.read(n)) for n in apk.names()
                     if n.endswith(".dex") and "/" not in n]
        dex = analyze_dex_files(dex_files)

        native_libs = []
        for entry in apk.files():
            if entry.name.startswith("lib/") and entry.name.endswith(".so"):
                parts = entry.name.split("/")
                native_libs.append({"path": entry.name, "arch": parts[1] if len(parts) > 2 else "unknown",
                                    "sha256": hashlib.sha256(apk.read(entry.name)).hexdigest()})

    classified = [classify_permission(p) for p in manifest["permissions"]]
    dangerous = [p["name"] for p in classified if p["is_dangerous"]]
    if dangerous:
        findings.append(_finding("STATIC_DANGEROUS_PERM", "high" if len(dangerous) > 3 else "medium",
                                 f"App requests {len(dangerous)} dangerous permission(s)",
                                 f"Permissions: {', '.join(dangerous)}"))
    min_sdk = manifest["min_sdk"]
    if min_sdk is not None and min_sdk < 24:
        findings.append(_finding("STATIC_LOW_MIN_SDK", "low", "Low minSdkVersion allows outdated Android runtime",
                                 f"minSdkVersion: {min_sdk} (recommended >= 24)"))

    status = signature["status"]
    if status == "invalid":
        findings.append(_finding("STATIC_SIGNATURE_INVALID", "critical", "APK signature verification failed",
                                 "; ".join(signature["errors"][:5])))
    elif status == "unsigned":
        findings.append(_finding("STATIC_UNSIGNED", "high", "APK is not signed",
                                 "No v1, v2 or v3 signature found; Android will refuse to install it."))
    elif status == "unverifiable":
        findings.append(_finding("STATIC_SIGNATURE_UNVERIFIABLE", "low",
                                 "APK signature uses an algorithm this tool cannot verify",
                                 "; ".join(signature["errors"][:3])))

    cert = signature["certificate"]
    if cert.get("self_signed"):
        findings.append(_finding("STATIC_SELF_SIGNED_CERT", "medium", "Application certificate is self-signed",
                                 f"Issuer: {cert.get('issuer', '')}"))

    for f in dex["dex_files"]:
        if f.get("parsed") and not (f["checksum_valid"] and f["signature_valid"]):
            findings.append(_finding("STATIC_DEX_HEADER_MISMATCH", "high",
                                     "DEX header checksum does not match its contents",
                                     f"{f['path']}: adler32 valid={f['checksum_valid']}, "
                                     f"sha1 valid={f['signature_valid']} (bytes changed after compilation)"))

    for api in dex["dangerous_apis"]:
        api_name = api["api"]
        if api_name in ("DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader"):
            findings.append(_finding("STATIC_DCL", "high", "Dynamic Code Loading (DCL) capability",
                                     f"API: {api_name} in {api['source']}"))
        elif api_name in ("RuntimeExec", "ProcessBuilder"):
            findings.append(_finding("STATIC_CMD_EXEC", "high", "Arbitrary command execution capability",
                                     f"API: {api['class']}->{api['method']}"))
        elif api_name == "SmsManager_sendTextMessage":
            findings.append(_finding("STATIC_SMS_SEND", "high", "Programmatic SMS transmission API detected",
                                     f"API: {api['class']}->{api['method']}"))
        elif api_name == "TelephonyManager_getDeviceId":
            findings.append(_finding("STATIC_DEVICE_HARVEST", "medium",
                                     "Hardware/Subscriber identifier access detected",
                                     f"API: {api['class']}->{api['method']}"))
    if dex["iocs"]["ips"]:
        findings.append(_finding("STATIC_HARDCODED_IP", "medium",
                                 f"Hardcoded external IP address(es) detected ({len(dex['iocs']['ips'])})",
                                 f"IPs: {', '.join(dex['iocs']['ips'][:5])}"))

    return {
        "findings": findings,
        "manifest_format": manifest["format"],
        "package_name": manifest["package_name"] or "unknown.package",
        "version_name": manifest["version_name"],
        "version_code": manifest["version_code"],
        "min_sdk": manifest["min_sdk"],
        "target_sdk": manifest["target_sdk"],
        "permissions": classified,
        "declared_permissions": manifest["declared_permissions"],
        "application": manifest["application"],
        "components": manifest["components"],
        "component_details": manifest["component_details"],
        "certificate": cert,
        "signature": _signature_summary(signature),
        "native_libs": native_libs,
        "dex": {"files": dex["dex_files"], "class_count": dex["class_count"],
                "sensitive_classes": dex["sensitive_classes"]},
        "iocs": dex["iocs"],
        "dangerous_apis": dex["dangerous_apis"],
    }


def run(job_id: str, ctx: JobContext) -> dict:
    """Execute static analysis on the target APK."""
    if not ctx.apk_path or not os.path.isfile(ctx.apk_path):
        raise EngineError("APK file not found")
    try:
        result = analyze_apk(ctx.apk_path, ctx.config.get("apk_limits"))
    except ApkValidationError as exc:
        raise EngineError(f"Invalid APK: {exc}") from None

    static_dir = ctx.subdir("static")
    artifacts = {}
    if ctx.config.get("run_decompilers"):
        timeout_s = int(ctx.config.get("decompiler_timeout_s", 120))
        out = os.path.join(static_dir, "apktool")
        if _run_decompiler([ctx.config.get("apktool", "apktool"), "d", "-f", "-o", out, ctx.apk_path], timeout_s):
            artifacts["apktool_dir"] = "static/apktool"
        out = os.path.join(static_dir, "jadx")
        if _run_decompiler([ctx.config.get("jadx", "jadx"), "-d", out, ctx.apk_path], timeout_s):
            artifacts["jadx_dir"] = "static/jadx"

    report = {"job_id": job_id, "engine": "static", "status": "ok", **result, "artifacts": artifacts}
    return emit(ctx, "static.json", report)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m core.static <path_to_apk>")
        sys.exit(1)
    apk = sys.argv[1]
    ctx = JobContext(apk_path=apk, workspace=tempfile.mkdtemp(prefix="mt_static_"), prior={}, config={})
    print(json.dumps(run(hashlib.sha1(apk.encode()).hexdigest()[:12], ctx), indent=2))
