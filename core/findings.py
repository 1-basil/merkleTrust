"""core/findings.py — The catalogue of everything MerkleTrust can report.

Every finding produced by any engine is defined here exactly once, so each one
carries a plain-language title, a technical title, a severity, an explanation,
a recommendation and its contribution to the risk score.

Risk points and groups
----------------------
``points`` is the finding's contribution to the 0–100 risk indicator.
``group`` prevents double counting: when several findings describe the same
underlying fact (e.g. "debuggable" seen by the static engine *and* reported as
newly enabled by the tamper engine), only the highest-scoring finding in the
group counts. Operational findings (analysis could not run) have 0 points: a
failure to analyse is reported as such, never converted into "risk".

The points are expert-assigned heuristics, not a calibrated probability of
malware. They are documented, visible per finding, and covered by tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class FindingType:
    severity: str
    category: str          # integrity | signature | manifest | code | network | archive | runtime | analysis
    title: str             # plain language, for non-specialists
    technical: str         # precise technical statement
    explanation: str
    recommendation: str
    points: int
    group: str


def _t(severity, category, title, technical, explanation, recommendation, points, group=None):
    return severity, category, title, technical, explanation, recommendation, points, group


_CATALOG_SPEC: dict[str, tuple] = {
    # ------------------------------------------------------- integrity --
    "TAMPER_NO_BASELINE": _t(
        "info", "integrity", "No trusted version to compare against",
        "No approved baseline exists for this package",
        "Without an approved reference build, MerkleTrust cannot tell whether this app was changed.",
        "Ask an administrator to enrol and approve the official build of this app as a baseline.", 0),
    "TAMPER_BASELINE_INVALID": _t(
        "critical", "integrity", "The stored trusted record has been altered",
        "Baseline failed verification (signature / Merkle root / profile hash)",
        "The baseline in the database no longer matches what was approved and signed, so it cannot be trusted. "
        "This indicates tampering with the stored records.",
        "Investigate database access, restore the baseline from a trusted backup, and re-approve it.", 30),
    "TAMPER_INTEGRITY_VERIFIED": _t(
        "info", "integrity", "Matches the trusted version",
        "All content files match the approved baseline; signature valid",
        "Every application file has exactly the same SHA-256 hash as in the approved baseline.",
        "No action needed.", 0),
    "TAMPER_SIGNED_UPDATE": _t(
        "info", "integrity", "Changed by the original developer",
        "Content differs from the baseline but is validly signed by the baseline's certificate",
        "The files differ from the trusted version, but the app is correctly signed with the same developer key, "
        "which normally means a new release from the original developer. Its new capabilities are assessed "
        "separately below.",
        "If this is an expected release, review it and enrol it as the new baseline.", 0),
    "TAMPER_CERT_CHANGED": _t(
        "critical", "integrity", "Signed by a different developer key",
        "Signing certificate differs from the trusted baseline",
        "The app was signed with a different certificate than the approved version. Only the original developer "
        "holds the original key, so this usually means the app was repackaged and re-signed by someone else. "
        "It is not proof of malice on its own (developers occasionally rotate keys), but it must be explained.",
        "Do not install. Confirm with the developer whether the signing key was rotated.", 40, "signer"),
    "TAMPER_DEX_MODIFIED": _t(
        "critical", "integrity", "The app's program code was changed",
        "DEX bytecode differs from the trusted baseline",
        "The compiled code (classes*.dex) is different from the approved version, so the app may behave differently.",
        "Treat as untrusted unless this is a new release; if so, enrol it as a new baseline after review.", 35,
        "code_tamper"),
    "TAMPER_NATIVE_MODIFIED": _t(
        "high", "integrity", "Native code libraries were changed",
        "Native shared libraries (.so) differ from the trusted baseline",
        "Native libraries run with the app's full privileges and are a common place to hide malicious code.",
        "Treat as untrusted unless this is a reviewed new release.", 25, "native_tamper"),
    "TAMPER_MANIFEST_MODIFIED": _t(
        "high", "integrity", "The app's configuration was changed",
        "AndroidManifest.xml differs from the trusted baseline",
        "The manifest declares permissions, components and security settings; changing it can grant new powers.",
        "Review the configuration differences listed below.", 10, "manifest_tamper"),
    "TAMPER_PERMISSIONS_ADDED": _t(
        "high", "integrity", "The app asks for new permissions",
        "Permissions added compared to the trusted baseline",
        "New permissions give the app access to data or functions the trusted version did not have.",
        "Check whether each new permission is justified by a documented new feature.", 15, "manifest_tamper"),
    "TAMPER_COMPONENTS_ADDED": _t(
        "medium", "integrity", "New hidden app parts were added",
        "Components (activities/services/receivers/providers) added vs baseline",
        "Extra components can run code in the background or respond to system events.",
        "Verify the new components belong to a legitimate update.", 8, "components_tamper"),
    "TAMPER_NEWLY_EXPORTED": _t(
        "medium", "integrity", "Parts of the app are newly open to other apps",
        "Components newly exported compared to the baseline",
        "Exported components can be started by any other app on the device.",
        "Confirm the export is intended and protected by a permission.", 10, "components_tamper"),
    "TAMPER_DEBUGGABLE_ENABLED": _t(
        "high", "integrity", "Debugging was switched on",
        "android:debuggable changed to true compared to the baseline",
        "A debuggable app lets anyone with USB access inspect and modify it while running.",
        "Release builds must not be debuggable.", 15, "debuggable"),
    "TAMPER_DANGEROUS_API_ADDED": _t(
        "high", "integrity", "New sensitive capabilities appeared",
        "Sensitive API references not present in the baseline",
        "The code now uses sensitive functions (e.g. running commands, loading code) that the trusted version did not.",
        "Find out why these capabilities were added.", 15, "new_capabilities"),
    "TAMPER_VERSION_DOWNGRADE": _t(
        "high", "integrity", "This is an older version than the trusted one",
        "versionCode lower than the trusted baseline",
        "Installing an older version can reintroduce vulnerabilities fixed in the trusted release.",
        "Use the current trusted version.", 20, "downgrade"),
    "TAMPER_FILES_CHANGED": _t(
        "medium", "integrity", "Other app files were changed",
        "Resource/asset files differ from the trusted baseline",
        "Resources and assets can contain configuration, web content or hidden payloads.",
        "Review the list of changed files.", 10, "files_tamper"),
    "TAMPER_MISSING_INPUT": _t(
        "info", "analysis", "Comparison could not run",
        "Tamper analysis skipped because earlier stages failed",
        "The app could not be compared with its baseline because it could not be analysed.",
        "See the analysis errors.", 0),

    # ------------------------------------------------------- signature --
    "STATIC_SIGNATURE_INVALID": _t(
        "critical", "signature", "The app's digital signature is broken",
        "APK signature verification failed (v1/v2/v3)",
        "The app's own signature does not match its contents: something was modified after the developer signed it, "
        "or the signature was stripped or forged. Android would refuse to install it.",
        "Do not install. Obtain the app from the official source.", 35, "signer"),
    "STATIC_UNSIGNED": _t(
        "high", "signature", "The app is not signed",
        "No v1/v2/v3 APK signature present",
        "Every installable Android app must be signed by its developer. An unsigned file cannot be attributed to anyone.",
        "Do not install.", 30, "signer"),
    "STATIC_SIGNATURE_UNVERIFIABLE": _t(
        "low", "signature", "The signature uses an algorithm this tool cannot check",
        "Only verity/DSA signature algorithms present",
        "The signature might be valid, but MerkleTrust cannot verify this algorithm.",
        "Verify with Google's apksigner.", 5, "signer"),
    "STATIC_DEBUG_CERT": _t(
        "medium", "signature", "Signed with a developer test key",
        "Signed with the Android Debug certificate",
        "Debug certificates are generated automatically on developer machines and are never used for official releases.",
        "Do not distribute or install debug-signed builds.", 10),

    # -------------------------------------------------------- archive --
    "STATIC_ARCHIVE_PREFIX": _t(
        "critical", "archive", "Hidden data was found at the start of the file",
        "Bytes precede the first ZIP local file header",
        "Extra data in front of an APK is the technique used by the 'Janus' attack (CVE-2017-13156) to smuggle code "
        "past signature checks on old Android versions.",
        "Do not install.", 30),
    "STATIC_TEXT_MANIFEST": _t(
        "medium", "archive", "This is not a real Android build",
        "AndroidManifest.xml is plain text, not compiled binary XML",
        "Android only installs apps whose manifest was compiled by the Android build tools.",
        "Obtain a genuine build of the app.", 10),
    "STATIC_DEX_HEADER_MISMATCH": _t(
        "high", "code", "The program code was patched after it was built",
        "DEX header checksum / SHA-1 does not match the file body",
        "The DEX header stores a checksum of the code. A mismatch means bytes were changed by hand after compilation.",
        "Treat the app as tampered.", 20, "code_tamper"),

    # -------------------------------------------------------- manifest --
    "STATIC_DEBUGGABLE": _t(
        "high", "manifest", "Debugging is switched on",
        "android:debuggable=\"true\"",
        "Anyone with USB access can attach a debugger and read or change the app's memory and data.",
        "Release builds must set debuggable to false.", 15, "debuggable"),
    "STATIC_TEST_ONLY": _t(
        "medium", "manifest", "Marked as a test build",
        "android:testOnly=\"true\"",
        "Test-only builds are not meant for distribution.",
        "Use the production build.", 8),
    "STATIC_CLEARTEXT_TRAFFIC": _t(
        "medium", "network", "Unencrypted internet traffic is allowed",
        "android:usesCleartextTraffic=\"true\"",
        "Data sent over plain HTTP can be read or altered by anyone on the same network.",
        "Use HTTPS only and disable cleartext traffic.", 8, "cleartext"),
    "STATIC_ALLOW_BACKUP": _t(
        "low", "manifest", "App data can be copied off the device",
        "android:allowBackup=\"true\"",
        "Backups may let app data be extracted via adb or cloud backup.",
        "Disable backup or exclude sensitive data.", 3),
    "STATIC_EXPORTED_UNPROTECTED": _t(
        "medium", "manifest", "Parts of the app can be started by any other app",
        "Exported components without a permission",
        "Other apps can trigger these components, which can lead to data leaks or unintended actions.",
        "Set exported=\"false\" or protect them with a permission.", 8),
    "STATIC_DANGEROUS_PERM": _t(
        "medium", "manifest", "The app asks for access to sensitive data",
        "Dangerous (runtime) permissions requested",
        "These permissions give access to personal data or costly functions (SMS, contacts, location, camera...).",
        "Check that each permission is needed for the app's purpose.", 5),
    "STATIC_LOW_TARGET_SDK": _t(
        "low", "manifest", "Built for an old Android version",
        "targetSdkVersion below 28",
        "Apps targeting old Android versions opt out of newer platform security protections.",
        "Target a recent Android API level.", 3),
    "STATIC_LOW_MIN_SDK": _t(
        "info", "manifest", "Runs on very old Android versions",
        "minSdkVersion below 24",
        "Old Android versions lack security fixes; this is a compatibility choice rather than a flaw of the app.",
        "No action needed unless the app handles sensitive data.", 0),

    # ------------------------------------------------------------ code --
    "STATIC_DCL": _t(
        "high", "code", "Can download and run extra code",
        "Dynamic code loading (DexClassLoader / InMemoryDexClassLoader / PathClassLoader)",
        "The app can load code that was not part of the reviewed package, so its behaviour can change after install.",
        "Find out what code is loaded and from where.", 20, "dynamic_code"),
    "STATIC_CMD_EXEC": _t(
        "high", "code", "Can run system commands",
        "Runtime.exec / ProcessBuilder.start referenced",
        "Running shell commands is rarely needed by normal apps and is common in rooting tools and malware.",
        "Review why the app executes commands.", 15, "command_execution"),
    "STATIC_SMS_SEND": _t(
        "high", "code", "Can send text messages by itself",
        "SmsManager.sendTextMessage referenced",
        "Sending SMS silently is a classic way to charge premium-rate messages or exfiltrate data.",
        "Confirm the app has a legitimate messaging feature.", 20, "sms"),
    "STATIC_DEVICE_HARVEST": _t(
        "medium", "code", "Reads phone identifiers",
        "TelephonyManager device/subscriber identifier APIs referenced",
        "IMEI, IMSI and phone number uniquely identify the device and user.",
        "Confirm the identifiers are necessary.", 8, "device_identifiers"),
    "STATIC_DEVICE_ADMIN": _t(
        "high", "code", "Can lock or wipe the device",
        "DevicePolicyManager lockNow/resetPassword/wipeData or DeviceAdminReceiver",
        "Device-administrator powers are abused by ransomware to lock users out.",
        "Only device-management apps should need this.", 15, "device_admin"),
    "STATIC_ACCESSIBILITY": _t(
        "medium", "code", "Can read and control the screen",
        "Declares an AccessibilityService",
        "Accessibility services can read everything on screen and perform taps; banking trojans abuse them.",
        "Only assistive apps should need this.", 12),
    "STATIC_HIDE_ICON": _t(
        "medium", "code", "Can hide itself",
        "PackageManager.setComponentEnabledSetting referenced",
        "Disabling components is often used to remove the app's launcher icon so users cannot find it.",
        "Check whether the app hides its icon.", 8, "hide_icon"),
    "STATIC_WEBVIEW_JS_BRIDGE": _t(
        "low", "code", "Web pages can call into the app",
        "WebView.addJavascriptInterface referenced",
        "If untrusted web content is loaded, JavaScript can call the exposed Java methods.",
        "Ensure only trusted content is loaded.", 4),
    "STATIC_REFLECTION": _t(
        "info", "code", "Uses reflection",
        "java.lang.reflect.Method.invoke referenced",
        "Reflection is common in normal apps and libraries but can also be used to hide which functions are called.",
        "No action needed on its own.", 0),
    "STATIC_HARDCODED_IP": _t(
        "medium", "network", "Contacts hard-coded internet addresses",
        "Public IPv4 address literals in code",
        "Legitimate apps normally use domain names; fixed IP addresses are common in command-and-control code.",
        "Check what these addresses are.", 8, "network_ioc"),
    "STATIC_HTTP_URLS": _t(
        "low", "network", "Uses unencrypted web addresses",
        "http:// URL literals in code",
        "Traffic to http:// addresses is not encrypted.",
        "Use https:// endpoints.", 4, "cleartext"),

    # ------------------------------------------------ behaviour patterns --
    # Combinations of capabilities that characterise well-known Android malware
    # families. Each adds to (does not replace) the individual capability findings.
    "PATTERN_DROPPER": _t(
        "high", "code", "Can download and run code from the internet",
        "Dynamic code loading in an app with network access (dropper pattern)",
        "Loading executable code at runtime in an app that can reach the internet is how 'dropper' malware "
        "installs its real payload after passing review: what was checked is not what will run.",
        "Find out what code is loaded and where it comes from before trusting the app.", 25, "pattern_dropper"),
    "PATTERN_SMS_FRAUD": _t(
        "critical", "code", "Can send paid text messages without the user",
        "SMS sending + SEND_SMS permission + triggered by the system (boot or exported receiver)",
        "Sending SMS automatically when the phone starts or when a broadcast arrives, without the user pressing "
        "anything, is the pattern of premium-rate SMS fraud.",
        "Do not install unless the app is a messaging app you trust.", 30, "pattern_sms_fraud"),
    "PATTERN_SPYWARE": _t(
        "high", "code", "Collects personal data and can secretly send it away",
        "Sensitive data access + network access + concealment/exfiltration indicator",
        "The app can read personal data (identifiers, contacts, location, microphone, call logs), can reach "
        "the internet, and shows a sign of hiding or exfiltration (command execution, hard-coded IP address, "
        "hiding its icon, accessibility control) — the profile of spyware.",
        "Do not install unless every permission is clearly justified by the app's purpose.", 25,
        "pattern_spyware"),

    # -------------------------------------------------------- runtime --
    # Behaviour observed while the app ran in the emulator (core/dynamic.py).
    # Each shares its group with the static finding for the same capability, so
    # "can do X" (static) and "did X" (runtime) are never counted twice.
    "RUNTIME_PRIV_ESC": _t(
        "critical", "runtime", "Tried to take full control of the device (root)",
        "App process attempted to execute su (superuser)",
        "While it ran, the app tried to start the superuser program. Normal apps never need root; rooting tools "
        "and malware use it to disable Android's protections and act outside the app sandbox.",
        "Do not install.", 30, "privilege_escalation"),
    "RUNTIME_CMD_EXEC": _t(
        "high", "runtime", "Ran system commands while running",
        "App process started a child process (shell command)",
        "The app was seen starting other programs on the device, not just referencing the ability to do so.",
        "Find out which commands are run and why.", 15, "command_execution"),
    "RUNTIME_CODE_LOADED": _t(
        "high", "runtime", "Loaded code that was not part of the app",
        "Executable code (DEX/JAR/native library) written to app storage or loaded at runtime",
        "The app wrote or loaded program code at runtime. Code obtained this way was never part of the reviewed "
        "package, so the app's behaviour can change after installation.",
        "Find out where the code comes from before trusting the app.", 20, "dynamic_code"),
    "RUNTIME_SMS_SENT": _t(
        "critical", "runtime", "Sent a text message by itself",
        "Outgoing SMS recorded during the automated run (no user interaction)",
        "During the test nobody touched the app, yet it sent a text message. This is how premium-rate SMS fraud "
        "charges the victim.",
        "Do not install.", 30, "pattern_sms_fraud"),
    "RUNTIME_HIDES_ICON": _t(
        "medium", "runtime", "Hid itself from the home screen",
        "Launcher activity disabled at runtime",
        "After it started, the app removed its own icon from the launcher, so the user can no longer find or "
        "easily uninstall it.",
        "Treat as stalkerware or malware unless this is clearly intended.", 12, "hide_icon"),
    "RUNTIME_CLEARTEXT": _t(
        "medium", "runtime", "Sent unencrypted internet traffic",
        "Plain-text HTTP connection observed",
        "The app was seen talking to a server over unencrypted HTTP; anyone on the network can read or alter it.",
        "Use HTTPS only.", 8, "cleartext"),
    "RUNTIME_NETWORK": _t(
        "info", "runtime", "Internet servers contacted while running",
        "Outgoing connections observed from the app",
        "These are the servers the app connected to during the test. Contacting servers is normal; the list helps "
        "a reviewer check that they belong to the app's developer.",
        "Check that the servers are expected for this app.", 0),

    # ------------------------------------------------------- analysis --
    "INTEGRITY_COMPUTED": _t("info", "analysis", "File fingerprints computed", "Per-file SHA-256 manifest and Merkle root computed",
                             "Every file was hashed and committed to a Merkle root.", "No action needed.", 0),
    "REPO_SEALED": _t("info", "analysis", "Result recorded in the audit log", "Report committed to the signed ledger",
                      "The analysis result was hashed, signed and appended to the tamper-evident log.", "No action needed.", 0),
}

CATALOG: dict[str, FindingType] = {}
for _id, (_sev, _cat, _title, _tech, _expl, _rec, _pts, _grp) in _CATALOG_SPEC.items():
    CATALOG[_id] = FindingType(_sev, _cat, _title, _tech, _expl, _rec, _pts, _grp or _id)

# Dynamic-engine (emulator) findings are operational status messages, not app risk.
DYNAMIC_OPERATIONAL_PREFIX = "DYN_"


def finding(fid: str, evidence: str, *, severity: str | None = None, points: int | None = None,
            title: str | None = None) -> dict[str, Any]:
    """Build a complete finding dict from the catalogue."""
    t = CATALOG[fid]
    sev = severity or t.severity
    if sev not in SEVERITIES:
        raise ValueError(f"invalid severity {sev}")
    return {
        "id": fid, "severity": sev, "category": t.category,
        "title": title or t.title, "technical": t.technical,
        "explanation": t.explanation, "evidence": evidence, "recommendation": t.recommendation,
        "points": t.points if points is None else points, "group": t.group,
    }


def normalize(f: dict[str, Any], source: str) -> dict[str, Any]:
    """Make any engine's finding complete. Unknown IDs get conservative, clearly-labelled defaults."""
    fid = f.get("id", "UNKNOWN")
    if fid in CATALOG:
        full = finding(fid, f.get("evidence", ""), severity=f.get("severity"), points=f.get("points"),
                       title=f.get("title") if "explanation" in f else None)
    elif fid.startswith(DYNAMIC_OPERATIONAL_PREFIX):
        full = {"id": fid, "severity": "info", "category": "analysis",
                "title": f.get("title", "Dynamic analysis status"), "technical": f.get("title", ""),
                "explanation": "Status of the optional emulator-based analysis. It describes whether the analysis "
                               "could run, not how risky the app is.",
                "evidence": f.get("evidence", ""), "recommendation": "No action needed.",
                "points": 0, "group": fid, "reported_severity": f.get("severity")}
    else:
        sev = f.get("severity") if f.get("severity") in SEVERITIES else "info"
        full = {"id": fid, "severity": sev, "category": "other", "title": f.get("title", fid),
                "technical": f.get("title", fid), "explanation": f.get("explanation", "Reported by the "
                f"{source} engine."), "evidence": f.get("evidence", ""),
                "recommendation": f.get("recommendation", "Review the evidence."),
                "points": {"info": 0, "low": 2, "medium": 5, "high": 10, "critical": 20}[sev], "group": fid}
    full["source"] = source
    return full
