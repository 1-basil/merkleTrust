"""core/native_analyzer.py — ELF header parser and native .so security inspection.

Extracts architecture, binary properties, and security capabilities directly from
native libraries (.so files) inside an Android APK without requiring external binutils.
"""

from __future__ import annotations

import re
import struct
from typing import Any

ELF_MAGIC = b"\x7fELF"

# ELF Machine architectures commonly found in Android NDK builds
ARCH_NAMES = {
    0x03: "x86",
    0x28: "armeabi-v7a (ARM)",
    0x3E: "x86_64",
    0xB7: "arm64-v8a (AArch64)",
    0x08: "mips",
    0xF3: "riscv64",
}

# Suspicious string patterns in native libraries
PATTERNS_ROOT = [
    re.compile(rb"/system/bin/su\b"),
    re.compile(rb"/system/xbin/su\b"),
    re.compile(rb"/sbin/su\b"),
    re.compile(rb"/data/local/su\b"),
    re.compile(rb"/system/app/Superuser\.apk\b"),
    re.compile(rb"\bmagisk\b", re.IGNORECASE),
    re.compile(rb"\bdaemonsu\b"),
]

PATTERNS_ANTIDEBUG = [
    re.compile(rb"\bptrace\b"),
    re.compile(rb"/proc/self/status\b"),
    re.compile(rb"/proc/self/wchan\b"),
    re.compile(rb"\bTracerPid\b"),
    re.compile(rb"/sys/class/android_usb\b"),
]

PATTERNS_EXEC = [
    re.compile(rb"\bsystem\b"),
    re.compile(rb"\bexecve\b"),
    re.compile(rb"\bpopen\b"),
    re.compile(rb"/bin/sh\b"),
    re.compile(rb"/system/bin/sh\b"),
]

PACKER_INDICATORS = [
    re.compile(rb"UPX!"),
    re.compile(rb"libsecexe\.so", re.IGNORECASE),
    re.compile(rb"libsecmain\.so", re.IGNORECASE),
    re.compile(rb"libDexHelper\.so", re.IGNORECASE),
    re.compile(rb"libprotectClass\.so", re.IGNORECASE),
    re.compile(rb"libjiagu\.so", re.IGNORECASE),
    re.compile(rb"libshell\.so", re.IGNORECASE),
]


def parse_elf_header(data: bytes) -> dict[str, Any]:
    """Parse ELF header bytes and return binary characteristics."""
    if len(data) < 52 or not data.startswith(ELF_MAGIC):
        return {"valid_elf": False, "error": "Not a valid ELF binary"}

    ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]   # 1 = Little-endian, 2 = Big-endian
    endian = "<" if ei_data == 1 else ">"

    bitness = 32 if ei_class == 1 else 64 if ei_class == 2 else 0
    e_machine = struct.unpack(f"{endian}H", data[18:20])[0]

    return {
        "valid_elf": True,
        "bitness": bitness,
        "endianness": "little" if ei_data == 1 else "big" if ei_data == 2 else "unknown",
        "machine_id": e_machine,
        "architecture": ARCH_NAMES.get(e_machine, f"machine_0x{e_machine:x}"),
    }


def analyze_native_library(name: str, data: bytes) -> dict[str, Any]:
    """Inspect one .so file for ELF metadata and security-sensitive capabilities."""
    header = parse_elf_header(data)
    capabilities: dict[str, list[str]] = {
        "root_detection": [],
        "anti_debugging": [],
        "command_execution": [],
        "packer_signatures": [],
    }

    # Match suspicious patterns against the binary bytes
    for pat in PATTERNS_ROOT:
        m = pat.search(data)
        if m:
            capabilities["root_detection"].append(m.group(0).decode("ascii", errors="replace"))

    for pat in PATTERNS_ANTIDEBUG:
        m = pat.search(data)
        if m:
            capabilities["anti_debugging"].append(m.group(0).decode("ascii", errors="replace"))

    for pat in PATTERNS_EXEC:
        m = pat.search(data)
        if m:
            capabilities["command_execution"].append(m.group(0).decode("ascii", errors="replace"))

    for pat in PACKER_INDICATORS:
        m = pat.search(data)
        if m:
            capabilities["packer_signatures"].append(m.group(0).decode("ascii", errors="replace"))

    # Also check library name against known packer names
    lib_basename = name.split("/")[-1].lower()
    if any(p in lib_basename for p in ("secexe", "secmain", "dexhelper", "jiagu", "protectclass")):
        capabilities["packer_signatures"].append(lib_basename)

    return {
        "path": name,
        "size": len(data),
        "elf_header": header,
        "capabilities": capabilities,
    }
