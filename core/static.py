"""core/static.py — ASHWINI.

Static Analysis Engine for Android APKs.
Extracts package metadata, permissions, components, certificates, native libraries,
DEX classes, dangerous APIs, IOCs, and generates security findings.
Outputs: static.json and scratch files in <workspace>/static/
"""

import os
import sys
import json
import zipfile
import hashlib
import tempfile
import subprocess
import shutil
from typing import Any

from core.contracts import JobContext, emit, EngineError
from core.axml import parse_manifest_xml
from core.dex_cert_scanner import scan_dex_content, parse_apk_certificates

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


def _run_apktool(apk_path: str, out_dir: str, apktool_cmd: str) -> bool:
    """Run apktool if installed to decompile resources and smali."""
    if not apktool_cmd or not shutil.which(apktool_cmd) and not os.path.isfile(apktool_cmd):
        return False
    try:
        cmd = [apktool_cmd, "d", "-f", "-o", out_dir, apk_path]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.returncode == 0
    except Exception:
        return False


def _run_jadx(apk_path: str, out_dir: str, jadx_cmd: str) -> bool:
    """Run jadx if installed to decompile Java sources."""
    if not jadx_cmd or not shutil.which(jadx_cmd) and not os.path.isfile(jadx_cmd):
        return False
    try:
        cmd = [jadx_cmd, "-d", out_dir, apk_path]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.returncode == 0
    except Exception:
        return False


def run(job_id: str, ctx: JobContext) -> dict:
    """Execute static analysis on the target APK."""
    if not ctx.apk_path or not os.path.exists(ctx.apk_path):
        raise EngineError(f"APK file not found at: {ctx.apk_path}")

    static_dir = ctx.subdir("static")
    apktool_dir = os.path.join(static_dir, "apktool")
    jadx_dir = os.path.join(static_dir, "jadx")
    os.makedirs(apktool_dir, exist_ok=True)
    os.makedirs(jadx_dir, exist_ok=True)

    findings: list[dict[str, Any]] = []

    # 1. Open APK as ZIP
    try:
        apk_zip = zipfile.ZipFile(ctx.apk_path, "r")
    except zipfile.BadZipFile as e:
        raise EngineError(f"Invalid APK (not a valid ZIP archive): {e}")

    try:
        namelist = apk_zip.namelist()

        # 2. Parse AndroidManifest.xml
        manifest_data = {}
        if "AndroidManifest.xml" in namelist:
            axml_bytes = apk_zip.read("AndroidManifest.xml")
            manifest_data = parse_manifest_xml(axml_bytes)
        else:
            findings.append({
                "id": "STATIC_NO_MANIFEST",
                "severity": "critical",
                "title": "Missing AndroidManifest.xml",
                "evidence": "APK archive contains no AndroidManifest.xml",
            })

        package_name = manifest_data.get("package_name") or "unknown.package"
        version_name = manifest_data.get("version_name") or "1.0"
        version_code = int(manifest_data.get("version_code") or 1)
        min_sdk = int(manifest_data.get("min_sdk") or 1)
        target_sdk = int(manifest_data.get("target_sdk") or 1)

        # 3. Classify Permissions
        raw_perms = manifest_data.get("permissions", [])
        classified_perms = [classify_permission(p) for p in raw_perms]
        dangerous_perm_names = [p["name"] for p in classified_perms if p["is_dangerous"]]

        if dangerous_perm_names:
            findings.append({
                "id": "STATIC_DANGEROUS_PERM",
                "severity": "high" if len(dangerous_perm_names) > 3 else "medium",
                "title": f"App requests {len(dangerous_perm_names)} dangerous permission(s)",
                "evidence": f"Permissions: {', '.join(dangerous_perm_names)}",
            })

        # Check SDK levels
        if min_sdk < 24:
            findings.append({
                "id": "STATIC_LOW_MIN_SDK",
                "severity": "low",
                "title": "Low minSdkVersion allows outdated Android runtime",
                "evidence": f"minSdkVersion: {min_sdk} (recommended >= 24)",
            })

        # 4. Extract Components
        components = manifest_data.get("components", {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        })

        # 5. Extract Native Libraries
        native_libs: list[dict[str, str]] = []
        for name in namelist:
            if name.startswith("lib/") and name.endswith(".so"):
                parts = name.split("/")
                arch = parts[1] if len(parts) > 2 else "unknown"
                so_data = apk_zip.read(name)
                so_sha = hashlib.sha256(so_data).hexdigest()
                native_libs.append({
                    "path": name,
                    "arch": arch,
                    "sha256": so_sha,
                })

        # 6. Extract Certificate
        cert_info = parse_apk_certificates(apk_zip, ctx.apk_path)
        if cert_info.get("self_signed"):
            findings.append({
                "id": "STATIC_SELF_SIGNED_CERT",
                "severity": "medium",
                "title": "Application certificate is self-signed",
                "evidence": f"Issuer: {cert_info.get('issuer', '')}",
            })

        # 7. Scan DEX files for dangerous APIs, IOCs, and class definitions
        dex_files: list[tuple[str, bytes]] = []
        for name in namelist:
            if name.endswith(".dex"):
                dex_files.append((name, apk_zip.read(name)))

        dex_scan = scan_dex_content(dex_files)
        dangerous_apis = dex_scan["dangerous_apis"]
        iocs = dex_scan["iocs"]

        for api in dangerous_apis:
            api_name = api.get("api", "")
            if api_name in ("DexClassLoader", "PathClassLoader"):
                findings.append({
                    "id": "STATIC_DCL",
                    "severity": "high",
                    "title": "Dynamic Code Loading (DCL) capability",
                    "evidence": f"API: {api_name} in {api.get('source', '')}",
                })
            elif api_name in ("RuntimeExec", "ProcessBuilder"):
                findings.append({
                    "id": "STATIC_CMD_EXEC",
                    "severity": "high",
                    "title": "Arbitrary command execution capability",
                    "evidence": f"API: {api.get('class', '')}->{api.get('method', '')}",
                })
            elif api_name == "SmsManager_sendTextMessage":
                findings.append({
                    "id": "STATIC_SMS_SEND",
                    "severity": "high",
                    "title": "Programmatic SMS transmission API detected",
                    "evidence": f"API: {api.get('class', '')}->{api.get('method', '')}",
                })
            elif api_name == "TelephonyManager_getDeviceId":
                findings.append({
                    "id": "STATIC_DEVICE_HARVEST",
                    "severity": "medium",
                    "title": "Hardware/Subscriber identifier access detected",
                    "evidence": f"API: {api.get('class', '')}->{api.get('method', '')}",
                })

        if iocs.get("ips"):
            findings.append({
                "id": "STATIC_HARDCODED_IP",
                "severity": "medium",
                "title": f"Hardcoded external IP address(es) detected ({len(iocs['ips'])})",
                "evidence": f"IPs: {', '.join(iocs['ips'][:5])}",
            })

        # 8. Attempt optional decompilation tools if configured
        apktool_cmd = ctx.config.get("apktool", "apktool")
        jadx_cmd = ctx.config.get("jadx", "jadx")
        _run_apktool(ctx.apk_path, apktool_dir, apktool_cmd)
        _run_jadx(ctx.apk_path, jadx_dir, jadx_cmd)

    finally:
        apk_zip.close()

    # 9. Build final report conforming strictly to schemas/static.json
    status = "ok" if findings else "ok"

    report = {
        "job_id": job_id,
        "engine": "static",
        "status": status,
        "findings": findings,
        "package_name": package_name,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "permissions": classified_perms,
        "components": components,
        "certificate": cert_info,
        "native_libs": native_libs,
        "iocs": {
            "urls": iocs.get("urls", []),
            "ips": iocs.get("ips", []),
            "domains": iocs.get("domains", []),
            "emails": iocs.get("emails", []),
        },
        "dangerous_apis": dangerous_apis,
        "artifacts": {
            "apktool_dir": "static/apktool",
            "jadx_dir": "static/jadx",
        },
    }

    return emit(ctx, "static.json", report)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m core.static <path_to_apk> [prior.json]")
        sys.exit(1)

    apk = sys.argv[1]
    prior = json.load(open(sys.argv[2], encoding="utf-8")) if len(sys.argv) > 2 else {}
    ws = tempfile.mkdtemp(prefix="mt_static_")
    ctx = JobContext(apk_path=apk, workspace=ws, prior=prior, config={})
    job_id = hashlib.sha1(apk.encode()).hexdigest()[:12]
    res = run(job_id, ctx)
    print(json.dumps(res, indent=2))
    print(f"\nwrote: {ctx.out('static.json')}")
