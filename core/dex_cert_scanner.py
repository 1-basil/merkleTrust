"""core/dex_cert_scanner.py — DEX file analysis and APK certificate extraction.

Extracts class definitions, dangerous APIs, IOCs (URLs, IPs, domains, emails)
from Dalvik Executable (DEX) bytecode and parses X.509 certificates (v1, v2).
"""

import os
import re
import struct
import hashlib
import zipfile
import ipaddress
from datetime import datetime, timezone
from typing import Any

# Dangerous API signatures
DANGEROUS_API_PATTERNS = [
    {
        "api": "DexClassLoader",
        "pattern": re.compile(r"DexClassLoader"),
        "class": "dalvik.system.DexClassLoader",
        "method": "loadClass/init",
        "severity": "critical",
        "title": "Dynamic DEX code loading detected",
    },
    {
        "api": "PathClassLoader",
        "pattern": re.compile(r"PathClassLoader"),
        "class": "dalvik.system.PathClassLoader",
        "method": "loadClass/init",
        "severity": "high",
        "title": "PathClassLoader dynamic code loading detected",
    },
    {
        "api": "RuntimeExec",
        "pattern": re.compile(r"Runtime;->exec|Runtime\.exec"),
        "class": "java.lang.Runtime",
        "method": "exec",
        "severity": "high",
        "title": "Command execution via Runtime.exec detected",
    },
    {
        "api": "ProcessBuilder",
        "pattern": re.compile(r"ProcessBuilder"),
        "class": "java.lang.ProcessBuilder",
        "method": "start",
        "severity": "high",
        "title": "Process execution via ProcessBuilder detected",
    },
    {
        "api": "ReflectionInvoke",
        "pattern": re.compile(r"Method;->invoke|Method\.invoke"),
        "class": "java.lang.reflect.Method",
        "method": "invoke",
        "severity": "medium",
        "title": "Reflection method invocation detected",
    },
    {
        "api": "TelephonyManager_getDeviceId",
        "pattern": re.compile(r"TelephonyManager;->(getDeviceId|getImei|getSubscriberId|getLine1Number|getSimSerialNumber)"),
        "class": "android.telephony.TelephonyManager",
        "method": "getDeviceId/IMEI/IMSI",
        "severity": "high",
        "title": "Hardware/Subscriber identifier harvesting detected",
    },
    {
        "api": "SmsManager_sendTextMessage",
        "pattern": re.compile(r"SmsManager;->(sendTextMessage|sendMultipartTextMessage)"),
        "class": "android.telephony.SmsManager",
        "method": "sendTextMessage",
        "severity": "high",
        "title": "SMS sending capability detected",
    },
    {
        "api": "Cipher_getInstance",
        "pattern": re.compile(r"Cipher;->getInstance|Cipher\.getInstance"),
        "class": "javax.crypto.Cipher",
        "method": "getInstance",
        "severity": "low",
        "title": "Cryptographic cipher usage detected",
    },
    {
        "api": "LocationManager",
        "pattern": re.compile(r"LocationManager;->(getLastKnownLocation|requestLocationUpdates)"),
        "class": "android.location.LocationManager",
        "method": "requestLocationUpdates",
        "severity": "medium",
        "title": "Device geolocation tracking API detected",
    },
]

# Non-backtracking linear regexes
URL_REGEX = re.compile(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;%=]+", re.IGNORECASE)
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b")
DOMAIN_REGEX = re.compile(r"\b[a-zA-Z0-9\-]{2,63}\.(?:com|org|net|io|co|xyz|info|biz|ru|cn|top|cc|me|app|dev)\b", re.IGNORECASE)
CLASS_DESC_REGEX = re.compile(r"L[a-zA-Z0-9_$/]+;")


def extract_strings_from_raw_bytes(data: bytes, min_len: int = 4) -> list[str]:
    """Fallback ASCII string extraction from binary blob."""
    result = []
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                try:
                    result.append(current.decode("ascii"))
                except Exception:
                    pass
            current.clear()
    if len(current) >= min_len:
        try:
            result.append(current.decode("ascii"))
        except Exception:
            pass
    return result


def parse_dex_strings_and_classes(dex_bytes: bytes) -> tuple[list[str], list[str]]:
    """Parse DEX header and extract all string items and class descriptor strings."""
    if len(dex_bytes) < 0x70:
        raw_strs = extract_strings_from_raw_bytes(dex_bytes)
        classes = [s for s in raw_strs if s.startswith("L") and s.endswith(";")]
        return raw_strs, classes

    magic = dex_bytes[:8]
    if not magic.startswith(b"dex\n"):
        raw_strs = extract_strings_from_raw_bytes(dex_bytes)
        classes = [s for s in raw_strs if s.startswith("L") and s.endswith(";")]
        return raw_strs, classes

    strings = []
    classes = []

    try:
        string_ids_size, string_ids_off = struct.unpack("<II", dex_bytes[0x38:0x40])
        type_ids_size, type_ids_off = struct.unpack("<II", dex_bytes[0x40:0x48])
        class_defs_size, class_defs_off = struct.unpack("<II", dex_bytes[0x60:0x68])

        if string_ids_size > 0 and string_ids_off + string_ids_size * 4 <= len(dex_bytes):
            string_offsets = []
            for i in range(min(string_ids_size, 50000)):
                pos = string_ids_off + i * 4
                string_offsets.append(struct.unpack("<I", dex_bytes[pos:pos + 4])[0])

            for off in string_offsets:
                if off >= len(dex_bytes):
                    continue
                idx = off
                utf16_size = 0
                shift = 0
                while idx < len(dex_bytes) and shift < 32:
                    b = dex_bytes[idx]
                    idx += 1
                    utf16_size |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7

                null_pos = dex_bytes.find(b"\x00", idx)
                if null_pos != -1 and null_pos - idx < 4096:
                    raw_str = dex_bytes[idx:null_pos]
                    try:
                        s = raw_str.decode("utf-8", errors="replace")
                        strings.append(s)
                    except Exception:
                        pass

        # Extract classes from Type IDs / Class Defs
        if type_ids_size > 0 and type_ids_off + type_ids_size * 4 <= len(dex_bytes):
            type_str_indices = []
            for i in range(min(type_ids_size, 20000)):
                pos = type_ids_off + i * 4
                type_str_indices.append(struct.unpack("<I", dex_bytes[pos:pos + 4])[0])

            if class_defs_size > 0 and class_defs_off + class_defs_size * 32 <= len(dex_bytes):
                for i in range(min(class_defs_size, 10000)):
                    pos = class_defs_off + i * 32
                    class_idx = struct.unpack("<I", dex_bytes[pos:pos + 4])[0]
                    if class_idx < len(type_str_indices):
                        str_idx = type_str_indices[class_idx]
                        if str_idx < len(strings):
                            classes.append(strings[str_idx])

    except Exception:
        pass

    if not strings:
        strings = extract_strings_from_raw_bytes(dex_bytes)
        classes = [s for s in strings if s.startswith("L") and s.endswith(";")]

    return strings, classes


def scan_dex_content(dex_files: list[tuple[str, bytes]]) -> dict[str, Any]:
    """Scan all DEX files in APK for dangerous APIs, IOCs, and classes."""
    all_strings: list[str] = []
    all_classes: list[str] = []
    dangerous_apis: list[dict[str, str]] = []
    seen_apis = set()

    for dex_name, dex_bytes in dex_files:
        strings, classes = parse_dex_strings_and_classes(dex_bytes)
        all_strings.extend(strings)
        all_classes.extend(classes)

        joined_strings = "\n".join(strings)
        for d in DANGEROUS_API_PATTERNS:
            if d["pattern"].search(joined_strings):
                key = (d["api"], d["class"], d["method"])
                if key not in seen_apis:
                    seen_apis.add(key)
                    dangerous_apis.append({
                        "api": d["api"],
                        "class": d["class"],
                        "method": d["method"],
                        "source": dex_name,
                    })

    # IOC extraction
    urls: set[str] = set()
    ips: set[str] = set()
    domains: set[str] = set()
    emails: set[str] = set()

    for s in all_strings:
        if len(s) > 2000:
            continue

        # URLs
        for match in URL_REGEX.findall(s):
            if "schemas.android.com" not in match and "w3.org" not in match and "apache.org" not in match:
                urls.add(match)

        # IPs
        for match in IPV4_REGEX.findall(s):
            try:
                ip_obj = ipaddress.ip_address(match)
                if not (ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_unspecified or ip_obj.is_multicast or match.startswith("0.")):
                    ips.add(match)
            except ValueError:
                pass

        # Emails
        for match in EMAIL_REGEX.findall(s):
            if "android.com" not in match and "example.com" not in match:
                emails.add(match)

        # Domains
        for match in DOMAIN_REGEX.findall(s):
            if match not in ("android.com", "google.com", "schema.org", "w3.org", "apache.org", "example.com"):
                domains.add(match)

    return {
        "classes": sorted(set(all_classes)),
        "dangerous_apis": dangerous_apis,
        "iocs": {
            "urls": sorted(urls),
            "ips": sorted(ips),
            "domains": sorted(domains),
            "emails": sorted(emails),
        },
    }


def parse_apk_certificates(apk_zip: zipfile.ZipFile, apk_path: str) -> dict[str, Any]:
    """Extract and parse X.509 certificate(s) from APK using cryptography."""
    cert_info = {
        "sha256": "",
        "issuer": "",
        "subject": "",
        "valid_from": "",
        "valid_to": "",
        "self_signed": False,
        "schemes": [],
    }

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError:
        return cert_info

    schemes = []
    found_cert = None

    # 1. Check v1 signatures in META-INF/ (*.RSA, *.DSA, *.EC)
    for name in apk_zip.namelist():
        if name.startswith("META-INF/") and (name.endswith(".RSA") or name.endswith(".DSA") or name.endswith(".EC")):
            schemes.append("v1")
            try:
                data = apk_zip.read(name)
                # Try loading as PKCS7
                try:
                    certs = pkcs7.load_der_pkcs7_certificates(data)
                    if certs:
                        found_cert = certs[0]
                except Exception:
                    try:
                        found_cert = x509.load_der_x509_certificate(data, default_backend())
                    except Exception:
                        pass
            except Exception:
                pass

    # 2. Check APK Signing Block (v2 / v3)
    if apk_path and os.path.isfile(apk_path):
        try:
            with open(apk_path, "rb") as f:
                f.seek(0, 2)
                file_size = f.tell()
                if file_size > 1024:
                    f.seek(max(0, file_size - 65536))
                    tail = f.read()
                    eocd_pos = tail.rfind(b"\x50\x4b\x05\x06")
                    if eocd_pos != -1:
                        eocd_abs = max(0, file_size - 65536) + eocd_pos
                        f.seek(eocd_abs + 16)
                        cd_offset = struct.unpack("<I", f.read(4))[0]
                        if cd_offset >= 24:
                            f.seek(cd_offset - 24)
                            sig_block_footer = f.read(24)
                            if len(sig_block_footer) == 24 and sig_block_footer[8:] == b"APK Sig Block 42":
                                sig_block_size = struct.unpack("<Q", sig_block_footer[:8])[0]
                                sig_block_start = cd_offset - (sig_block_size + 8)
                                if sig_block_start >= 0:
                                    f.seek(sig_block_start)
                                    sig_data = f.read(sig_block_size)
                                    if b"\x1a\x87\x09\x71" in sig_data:
                                        schemes.append("v2")
                                    if b"\xc0\x68\x53\xf0" in sig_data:
                                        schemes.append("v3")
        except Exception:
            pass

    if found_cert:
        try:
            der_bytes = found_cert.public_bytes(x509.Encoding.DER)
            cert_info["sha256"] = hashlib.sha256(der_bytes).hexdigest()
            cert_info["issuer"] = found_cert.issuer.rfc4514_string()
            cert_info["subject"] = found_cert.subject.rfc4514_string()
            cert_info["valid_from"] = found_cert.not_valid_before_utc.isoformat()
            cert_info["valid_to"] = found_cert.not_valid_after_utc.isoformat()
            cert_info["self_signed"] = bool(found_cert.issuer == found_cert.subject)
            cert_info["schemes"] = sorted(set(schemes)) if schemes else ["v1"]
        except Exception:
            pass
    else:
        cert_info["schemes"] = sorted(set(schemes)) if schemes else []

    return cert_info
