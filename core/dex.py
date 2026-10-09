"""core/dex.py — Dalvik Executable (DEX) analysis.

Parses the DEX header and ID tables (strings, types, method references, class
definitions) to answer three questions precisely:

1. Is the DEX internally consistent? The header carries an Adler-32 checksum and
   a SHA-1 signature of the file body. Crude byte patching that does not
   recompute them is detected here.
2. Which sensitive Android/Java APIs does the code *reference*? Matching on
   ``method_id`` entries (class + method name) is far more precise than
   searching for substrings anywhere in the file.
3. Which network indicators (URLs, IPs, e-mails, hostnames) appear as string
   constants?

If a file cannot be parsed as DEX (e.g. synthetic test data), a string scan is
used as a fallback and results are marked ``"match": "string"`` so consumers
know the evidence is weaker.

Reference: https://source.android.com/docs/core/runtime/dex-format
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import struct
import zlib
from typing import Any

HEADER_SIZE = 0x70
MAX_ITEMS = 2_000_000

# (class descriptor, method names or None for any, api id, category, title)
SENSITIVE_APIS: list[tuple[str, tuple[str, ...] | None, str, str, str]] = [
    ("Ldalvik/system/DexClassLoader;", ("<init>",), "DexClassLoader", "dynamic_code_loading",
     "Loads executable code from files at runtime"),
    ("Ldalvik/system/InMemoryDexClassLoader;", ("<init>",), "InMemoryDexClassLoader", "dynamic_code_loading",
     "Loads executable code from memory at runtime"),
    ("Ldalvik/system/PathClassLoader;", ("<init>",), "PathClassLoader", "dynamic_code_loading",
     "Creates a class loader for code outside the app"),
    ("Ljava/lang/Runtime;", ("exec",), "RuntimeExec", "command_execution",
     "Executes operating-system commands"),
    ("Ljava/lang/ProcessBuilder;", ("start",), "ProcessBuilder", "command_execution",
     "Starts operating-system processes"),
    ("Ljava/lang/reflect/Method;", ("invoke",), "ReflectionInvoke", "reflection",
     "Calls methods by name at runtime (can hide behaviour)"),
    ("Landroid/telephony/SmsManager;", ("sendTextMessage", "sendMultipartTextMessage", "sendDataMessage"),
     "SmsManager_sendTextMessage", "sms", "Sends SMS messages programmatically"),
    ("Landroid/telephony/TelephonyManager;",
     ("getDeviceId", "getImei", "getSubscriberId", "getLine1Number", "getSimSerialNumber", "getMeid"),
     "TelephonyManager_getDeviceId", "device_identifiers", "Reads phone/subscriber identifiers"),
    ("Landroid/location/LocationManager;", ("getLastKnownLocation", "requestLocationUpdates"),
     "LocationManager", "location", "Reads device location"),
    ("Landroid/app/admin/DevicePolicyManager;", ("lockNow", "resetPassword", "wipeData"),
     "DevicePolicyManager", "device_admin", "Uses device-administrator powers (lock/wipe)"),
    ("Landroid/webkit/WebView;", ("addJavascriptInterface",), "WebView_addJavascriptInterface", "webview",
     "Exposes Java objects to JavaScript in a WebView"),
    ("Landroid/media/MediaRecorder;", ("setAudioSource",), "MediaRecorder_audio", "audio_capture",
     "Records audio"),
    ("Landroid/content/pm/PackageManager;", ("setComponentEnabledSetting",), "HideComponent", "stealth",
     "Enables/disables app components (often used to hide the launcher icon)"),
    ("Ljava/lang/System;", ("loadLibrary", "load"), "NativeLoad", "native_code",
     "Loads native (C/C++) code"),
    ("Ljavax/crypto/Cipher;", ("getInstance",), "Cipher_getInstance", "cryptography",
     "Uses encryption APIs"),
]

SENSITIVE_SUPERCLASSES = {
    "Landroid/accessibilityservice/AccessibilityService;": "accessibility_service",
    "Landroid/app/admin/DeviceAdminReceiver;": "device_admin_receiver",
    "Landroid/service/notification/NotificationListenerService;": "notification_listener",
    "Landroid/inputmethodservice/InputMethodService;": "input_method",
}

URL_RE = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE)
# Four dotted numbers that are not part of a longer dotted number: "1.3.6.1.5.5.7.3.1" is an ASN.1
# object identifier (common in crypto libraries), not the IP address 1.3.6.1.
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
HOST_RE = re.compile(r"^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                     r"(?:com|org|net|io|co|xyz|info|biz|ru|cn|top|cc|me|dev|tk|onion|su|pw)$", re.IGNORECASE)
BENIGN_HOST_SUFFIXES = ("android.com", "google.com", "googleapis.com", "w3.org", "apache.org",
                        "example.com", "schema.org", "schemas.android.com", "gstatic.com",
                        # XML namespace names (e.g. XMP image metadata): identifiers, never contacted
                        "ns.adobe.com", "purl.org")


class DexError(ValueError):
    """Raised when bytes are not a parseable DEX file."""


def _mutf8(raw: bytes) -> str:
    return raw.replace(b"\xc0\x80", b"\x00").decode("utf-8", errors="replace")


def _uleb128(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80 or shift >= 28:
            return result, pos
        shift += 7


def parse_dex(data: bytes) -> dict[str, Any]:
    """Parse a DEX file. Raises DexError for non-DEX or structurally invalid input."""
    if len(data) < HEADER_SIZE or not data.startswith(b"dex\n"):
        raise DexError("missing DEX magic")
    version = data[4:7].decode("ascii", errors="replace")
    (checksum,) = struct.unpack_from("<I", data, 0x08)
    signature = data[0x0C:0x20]
    file_size, header_size, endian = struct.unpack_from("<III", data, 0x20)
    if endian != 0x12345678:
        raise DexError("unsupported endianness tag")

    def table(off: int) -> tuple[int, int]:
        size, start = struct.unpack_from("<II", data, off)
        if size > MAX_ITEMS or (size and start >= len(data)):
            raise DexError(f"table at header offset 0x{off:x} out of range")
        return size, start

    n_str, off_str = table(0x38)
    n_type, off_type = table(0x40)
    n_meth, off_meth = table(0x58)
    n_cls, off_cls = table(0x60)

    try:
        strings = []
        for i in range(n_str):
            (sdata,) = struct.unpack_from("<I", data, off_str + i * 4)
            _, p = _uleb128(data, sdata)
            end = data.index(b"\x00", p)
            strings.append(_mutf8(data[p:end]))
        types = [strings[struct.unpack_from("<I", data, off_type + i * 4)[0]] for i in range(n_type)]
        methods = []
        for i in range(n_meth):
            cls_idx, _proto, name_idx = struct.unpack_from("<HHI", data, off_meth + i * 8)
            methods.append((types[cls_idx], strings[name_idx]))
        classes = []
        for i in range(n_cls):
            cls_idx, _flags, super_idx = struct.unpack_from("<III", data, off_cls + i * 32)
            classes.append((types[cls_idx], types[super_idx] if super_idx != 0xFFFFFFFF else None))
    except (struct.error, IndexError, ValueError) as exc:
        raise DexError(f"corrupt ID tables ({type(exc).__name__})") from None

    return {
        "version": version,
        "file_size_header": file_size,
        "file_size_actual": len(data),
        "checksum_valid": checksum == (zlib.adler32(data[12:]) & 0xFFFFFFFF),
        "signature_valid": signature == hashlib.sha1(data[32:]).digest(),
        "strings": strings,
        "method_refs": methods,
        "classes": classes,
    }


def _string_fallback(data: bytes, min_len: int = 4) -> list[str]:
    return [m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)]


def _detect_apis(method_refs: list[tuple[str, str]], source: str) -> list[dict[str, Any]]:
    refs = set(method_refs)
    by_class: dict[str, set[str]] = {}
    for cls, name in refs:
        by_class.setdefault(cls, set()).add(name)
    found = []
    for cls, names, api, category, title in SENSITIVE_APIS:
        hit = by_class.get(cls, set()) & set(names) if names else by_class.get(cls, set())
        if hit:
            found.append({
                "api": api, "category": category, "title": title,
                "class": cls[1:-1].replace("/", "."), "method": ", ".join(sorted(hit)),
                "source": source, "match": "method_ref",
            })
    return found


def _detect_apis_by_string(strings: list[str], source: str) -> list[dict[str, Any]]:
    blob = "\n".join(strings)
    found = []
    for cls, names, api, category, title in SENSITIVE_APIS:
        simple = cls.rsplit("/", 1)[-1].rstrip(";")
        method_names = [n for n in (names or ()) if n != "<init>"]
        # Constructor-only APIs match on the class name; others also need a method name.
        if simple in blob and (not method_names or any(n in blob for n in method_names)):
            found.append({
                "api": api, "category": category, "title": title,
                "class": cls[1:-1].replace("/", "."), "method": ", ".join(names or ()),
                "source": source, "match": "string",
            })
    return found


def extract_iocs(strings: list[str]) -> dict[str, list[str]]:
    urls, ips, emails, hosts = set(), set(), set(), set()
    for s in strings:
        if len(s) > 2048:
            continue
        for url in URL_RE.findall(s):
            host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
            if not host.endswith(BENIGN_HOST_SUFFIXES):
                urls.add(url)
                if HOST_RE.match(host):
                    hosts.add(host)
        for ip in IPV4_RE.findall(s):
            try:
                obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if obj.is_global:
                ips.add(ip)
        for email in EMAIL_RE.findall(s):
            if not email.lower().endswith(BENIGN_HOST_SUFFIXES):
                emails.add(email)
        if HOST_RE.match(s) and not s.lower().endswith(BENIGN_HOST_SUFFIXES):
            hosts.add(s.lower())
    return {"urls": sorted(urls), "ips": sorted(ips), "domains": sorted(hosts), "emails": sorted(emails)}


def analyze_dex_files(dex_files: list[tuple[str, bytes]]) -> dict[str, Any]:
    """Analyse every DEX file of an APK and merge the results."""
    per_file = []
    all_strings: list[str] = []
    apis: dict[str, dict[str, Any]] = {}
    sensitive_classes = []
    class_count = 0

    for name, data in dex_files:
        entry: dict[str, Any] = {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        try:
            parsed = parse_dex(data)
            entry.update(parsed=True, version=parsed["version"],
                         checksum_valid=parsed["checksum_valid"], signature_valid=parsed["signature_valid"],
                         size_matches_header=parsed["file_size_header"] == parsed["file_size_actual"],
                         class_count=len(parsed["classes"]), method_ref_count=len(parsed["method_refs"]))
            strings = parsed["strings"]
            found = _detect_apis(parsed["method_refs"], name)
            class_count += len(parsed["classes"])
            for cls, sup in parsed["classes"]:
                if sup in SENSITIVE_SUPERCLASSES:
                    sensitive_classes.append({"class": cls[1:-1].replace("/", "."),
                                              "kind": SENSITIVE_SUPERCLASSES[sup], "source": name})
        except DexError as exc:
            entry.update(parsed=False, error=str(exc))
            strings = _string_fallback(data)
            found = _detect_apis_by_string(strings, name)
        per_file.append(entry)
        all_strings.extend(strings)
        for f in found:
            # Prefer the stronger (method_ref) evidence when an API appears in several files.
            if f["api"] not in apis or (apis[f["api"]]["match"] == "string" and f["match"] == "method_ref"):
                apis[f["api"]] = f

    return {
        "dex_files": per_file,
        "class_count": class_count,
        "dangerous_apis": sorted(apis.values(), key=lambda a: a["api"]),
        "sensitive_classes": sensitive_classes,
        "iocs": extract_iocs(all_strings),
    }
