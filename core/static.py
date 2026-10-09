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
from core.findings import finding
from core.config import get_settings
from core.fuzzy_hash import fuzzy_hash_bytes
from core.threat_intel import check_file_hash, feed_status, scan_iocs

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


SMS_AND_CALL_PERMISSIONS = {
    "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG", "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
}
API_FINDINGS = {
    "DexClassLoader": "STATIC_DCL", "InMemoryDexClassLoader": "STATIC_DCL", "PathClassLoader": "STATIC_DCL",
    "RuntimeExec": "STATIC_CMD_EXEC", "ProcessBuilder": "STATIC_CMD_EXEC",
    "SmsManager_sendTextMessage": "STATIC_SMS_SEND",
    "TelephonyManager_getDeviceId": "STATIC_DEVICE_HARVEST",
    "DevicePolicyManager": "STATIC_DEVICE_ADMIN",
    "WebView_addJavascriptInterface": "STATIC_WEBVIEW_JS_BRIDGE",
    "HideComponent": "STATIC_HIDE_ICON",
    "ReflectionInvoke": "STATIC_REFLECTION",
}
SENSITIVE_CLASS_FINDINGS = {"accessibility_service": "STATIC_ACCESSIBILITY",
                            "device_admin_receiver": "STATIC_DEVICE_ADMIN"}


SENSITIVE_DATA_PERMISSIONS = {
    "android.permission.READ_CONTACTS", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.RECORD_AUDIO",
    "android.permission.READ_SMS", "android.permission.READ_CALL_LOG", "android.permission.CAMERA",
    "android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS",
}


def behaviour_patterns(manifest: dict[str, Any], dex: dict[str, Any],
                       capabilities: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Recognise capability combinations typical of malware families (see core/findings.py).

    Only method-reference evidence counts here: a class name merely appearing as text
    is too weak to accuse an app of a malware pattern.
    """
    def has(fid: str) -> bool:
        return any(i.get("match") != "string" for i in capabilities.get(fid, []))

    perms = set(manifest["permissions"])
    network = "android.permission.INTERNET" in perms
    out = []
    if has("STATIC_DCL") and network:
        out.append(finding("PATTERN_DROPPER", "Dynamic code loading + INTERNET permission"))

    triggered = "android.permission.RECEIVE_BOOT_COMPLETED" in perms or any(
        c["type"] == "receiver" and c["exported_effective"] and not c.get("permission")
        for c in manifest["component_details"])
    if has("STATIC_SMS_SEND") and "android.permission.SEND_SMS" in perms and triggered:
        out.append(finding("PATTERN_SMS_FRAUD", "SmsManager send API + SEND_SMS + boot/exported receiver"))

    sensitive = sorted(perms & SENSITIVE_DATA_PERMISSIONS)
    collects = has("STATIC_DEVICE_HARVEST") or len(sensitive) >= 2
    concealment = [name for name, present in (
        ("command execution", has("STATIC_CMD_EXEC")), ("hard-coded IP address", bool(dex["iocs"]["ips"])),
        ("icon hiding", has("STATIC_HIDE_ICON")), ("accessibility control", has("STATIC_ACCESSIBILITY")))
        if present]
    if collects and network and concealment:
        out.append(finding("PATTERN_SPYWARE", f"data: {', '.join(sensitive) or 'device identifiers'}; "
                                              f"network: INTERNET; indicator: {', '.join(concealment)}"))
    return out


def static_findings(manifest: dict[str, Any], classified: list[dict[str, Any]], signature: dict[str, Any],
                    dex: dict[str, Any], archive_warnings: list[str]) -> list[dict[str, Any]]:
    """Turn observed facts into catalogue findings (see core/findings.py)."""
    out: list[dict[str, Any]] = []
    for warning in archive_warnings:
        out.append(finding("STATIC_ARCHIVE_PREFIX", warning))
    if manifest["format"] != "binary":
        out.append(finding("STATIC_TEXT_MANIFEST", "AndroidManifest.xml is plain-text XML."))

    # Signature and certificate
    status = signature["status"]
    if status == "invalid":
        out.append(finding("STATIC_SIGNATURE_INVALID", "; ".join(signature["errors"][:5])))
    elif status == "unsigned":
        out.append(finding("STATIC_UNSIGNED", "No v1 (JAR), v2 or v3 signature found."))
    elif status == "unverifiable":
        out.append(finding("STATIC_SIGNATURE_UNVERIFIABLE", "; ".join(signature["errors"][:3])))
    cert = signature["certificate"]
    if cert.get("debug_certificate"):
        out.append(finding("STATIC_DEBUG_CERT", f"Certificate subject: {cert.get('subject')}"))

    # Manifest security settings
    app = manifest["application"]
    if app.get("debuggable"):
        out.append(finding("STATIC_DEBUGGABLE", 'android:debuggable="true" in <application>'))
    if app.get("testOnly"):
        out.append(finding("STATIC_TEST_ONLY", 'android:testOnly="true" in <application>'))
    if app.get("usesCleartextTraffic"):
        out.append(finding("STATIC_CLEARTEXT_TRAFFIC", 'android:usesCleartextTraffic="true" in <application>'))
    if app.get("allowBackup") is True:
        out.append(finding("STATIC_ALLOW_BACKUP", 'android:allowBackup="true" in <application>'))
    exposed = [c for c in manifest["component_details"]
               if c["type"] != "activity" and c["exported_effective"] and not c.get("permission")]
    if exposed:
        out.append(finding("STATIC_EXPORTED_UNPROTECTED",
                           ", ".join(f"{c['type']} {c['name']}" for c in exposed),
                           points=min(16, 8 * len(exposed))))
    dangerous = [p["name"] for p in classified if p["is_dangerous"]]
    if dangerous:
        sensitive = bool(set(dangerous) & SMS_AND_CALL_PERMISSIONS)
        out.append(finding("STATIC_DANGEROUS_PERM", ", ".join(dangerous),
                           severity="high" if len(dangerous) > 3 or sensitive else "medium",
                           points=min(15, 3 * len(dangerous) + (5 if sensitive else 0)),
                           title=f"The app asks for access to sensitive data ({len(dangerous)} permission"
                                 f"{'s' if len(dangerous) != 1 else ''})"))
    target, minimum = manifest["target_sdk"], manifest["min_sdk"]
    if target is not None and target < 28:
        out.append(finding("STATIC_LOW_TARGET_SDK", f"targetSdkVersion = {target}"))
    if minimum is not None and minimum < 24:
        out.append(finding("STATIC_LOW_MIN_SDK", f"minSdkVersion = {minimum}"))

    # Code
    for f in dex["dex_files"]:
        if f.get("parsed") and not (f["checksum_valid"] and f["signature_valid"]):
            out.append(finding("STATIC_DEX_HEADER_MISMATCH",
                               f"{f['path']}: Adler-32 valid = {f['checksum_valid']}, "
                               f"SHA-1 valid = {f['signature_valid']}"))
    grouped: dict[str, list[dict[str, Any]]] = {}
    for api in dex["dangerous_apis"]:
        fid = API_FINDINGS.get(api["api"])
        if fid:
            grouped.setdefault(fid, []).append(api)
    for cls in dex["sensitive_classes"]:
        fid = SENSITIVE_CLASS_FINDINGS.get(cls["kind"])
        if fid:
            grouped.setdefault(fid, []).append({"class": cls["class"], "method": "(subclass)", "match": "method_ref",
                                                "source": cls["source"]})
    for fid, items in grouped.items():
        weak = all(i.get("match") == "string" for i in items)
        evidence = "; ".join(f"{i['class']}.{i['method']} in {i['source']}" for i in items)
        if weak:
            evidence += " (weak evidence: name found as text, not as a method call)"
        base = finding(fid, evidence)
        out.append(finding(fid, evidence, points=base["points"] // 2 if weak else None))

    out.extend(behaviour_patterns(manifest, dex, grouped))

    # Network indicators
    if dex["iocs"]["ips"]:
        out.append(finding("STATIC_HARDCODED_IP", ", ".join(dex["iocs"]["ips"][:10])))
    http_urls = [u for u in dex["iocs"]["urls"] if u.lower().startswith("http://")]
    if http_urls:
        out.append(finding("STATIC_HTTP_URLS", ", ".join(http_urls[:10])))
    return out


def analyze_apk(apk_path: str, limits: dict | None = None) -> dict[str, Any]:
    """Pure analysis function (no workspace, no job). Raises ApkValidationError."""
    with ApkArchive(apk_path, limits=limits) as apk:
        try:
            manifest = parse_manifest(apk.read("AndroidManifest.xml", max_bytes=8 * 1024 * 1024))
        except AxmlError as exc:
            raise ApkValidationError(f"AndroidManifest.xml could not be parsed: {exc}") from None
        signature = verify_apk(apk, target_sdk=manifest["target_sdk"])
        dex_files = [(n, apk.read(n)) for n in apk.names()
                     if n.endswith(".dex") and "/" not in n]
        dex = analyze_dex_files(dex_files)

        from core.native_analyzer import analyze_native_library
        from core.yara_scanner import scan_files

        native_libs = []
        native_findings = []
        for entry in apk.files():
            if entry.name.startswith("lib/") and entry.name.endswith(".so"):
                parts = entry.name.split("/")
                raw_so = apk.read(entry.name)
                so_info = analyze_native_library(entry.name, raw_so)
                arch = parts[1] if len(parts) > 2 else "unknown"
                native_libs.append({
                    "path": entry.name,
                    "arch": arch,
                    "sha256": hashlib.sha256(raw_so).hexdigest(),
                    "elf_architecture": so_info["elf_header"].get("architecture"),
                    "bitness": so_info["elf_header"].get("bitness"),
                    "capabilities": so_info["capabilities"],
                })
                caps = so_info["capabilities"]
                if caps.get("root_detection"):
                    native_findings.append(finding("STATIC_NATIVE_ROOT_DETECT",
                                                   f"{entry.name}: {', '.join(caps['root_detection'][:3])}"))
                if caps.get("anti_debugging"):
                    native_findings.append(finding("STATIC_NATIVE_PTRACE",
                                                   f"{entry.name}: {', '.join(caps['anti_debugging'][:3])}"))
                if caps.get("command_execution"):
                    native_findings.append(finding("STATIC_NATIVE_EXEC",
                                                   f"{entry.name}: {', '.join(caps['command_execution'][:3])}"))
                if caps.get("packer_signatures"):
                    native_findings.append(finding("STATIC_NATIVE_PACKER",
                                                   f"{entry.name}: {', '.join(caps['packer_signatures'][:3])}"))

        archive_warnings = list(apk.report.warnings)

        # YARA threat scanning across code and bundled assets
        scan_candidates = [(n, apk.read(n)) for n in apk.names()
                           if n.endswith(".dex") or n.startswith("lib/") or n.startswith("assets/")]
        yara_matches = scan_files(scan_candidates)
        yara_findings = []
        for ym in yara_matches:
            yara_findings.append(finding("STATIC_YARA_MATCH",
                                         f"[{ym.rule_name}] matched in {ym.file_path}: {', '.join(ym.matched_strings[:3])}"))

        # Context Triggered Piecewise Hashing (CTPH / ssdeep fuzzy hashing)
        # ssdeep is pure Python here (~0.7 s per MB), so very large DEX files are skipped, never guessed.
        fuzzy_limit = get_settings().fuzzy_max_dex_mb * 1024 * 1024
        dex_fuzzy_hashes = {n: fuzzy_hash_bytes(raw) for n, raw in dex_files if len(raw) <= fuzzy_limit}
        fuzzy_skipped = [n for n, raw in dex_files if len(raw) > fuzzy_limit]

        # Threat intelligence: addresses in the code, and the file itself, against the ThreatFox feed.
        iocs = dex.get("iocs") or {}
        threat_matches = scan_iocs(iocs.get("urls", []), iocs.get("ips", []))
        threat_findings = []
        for tm in threat_matches:
            fid = "STATIC_THREAT_INTEL_C2" if tm["basis"] == "feed" else "STATIC_THREAT_INTEL_SUSPICIOUS"
            threat_findings.append(finding(fid, f"{tm['indicator']}: {tm['description']}"))
        with open(apk_path, "rb") as fh:
            known_file = check_file_hash(hashlib.file_digest(fh, "sha256").hexdigest())
        if known_file:
            threat_findings.append(finding("STATIC_KNOWN_MALWARE_FILE", known_file["description"]))

    classified = [classify_permission(p) for p in manifest["permissions"]]
    cert = signature["certificate"]
    findings = static_findings(manifest, classified, signature, dex, archive_warnings)

    if len(dex_files) > 1:
        findings.append(finding("STATIC_MULTIDEX",
                                f"Package contains {len(dex_files)} DEX files: {', '.join(n for n, _ in dex_files)}"))
    findings.extend(native_findings)
    findings.extend(yara_findings)
    findings.extend(threat_findings)

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
                "sensitive_classes": dex["sensitive_classes"],
                "multidex": len(dex_files) > 1,
                "dex_count": len(dex_files)},
        "dex_fuzzy_hashes": dex_fuzzy_hashes,
        "dex_fuzzy_skipped": fuzzy_skipped,
        "threat_intel": {
            "matches": threat_matches,
            "c2_detected": any(tm["severity"] == "critical" for tm in threat_matches),
            "match_count": len(threat_matches),
            "known_malware_file": known_file,
            "feed": feed_status(),  # which feed (and version) this verdict was based on
        },
        "iocs": dex["iocs"],
        "dangerous_apis": dex["dangerous_apis"],
        "yara_matches": [{"rule": ym.rule_name, "file": ym.file_path, "strings": ym.matched_strings}
                         for ym in yara_matches],
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
