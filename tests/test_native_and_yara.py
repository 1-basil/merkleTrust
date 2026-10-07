"""tests/test_native_and_yara.py — Test native library inspection, multi-DEX, and YARA threat rules."""

from __future__ import annotations

import struct
import pytest

from core.native_analyzer import parse_elf_header, analyze_native_library
from core.yara_scanner import BUILTIN_RULES, YaraRule, scan_files

pytestmark = pytest.mark.unit


def _make_dummy_elf(bitness: int = 64, machine: int = 0xB7, extra_strings: list[bytes] | None = None) -> bytes:
    """Construct minimal synthetic ELF binary bytes for testing."""
    magic = b"\x7fELF"
    ei_class = 2 if bitness == 64 else 1  # 2 = 64-bit
    ei_data = 1   # Little-endian
    ei_version = 1
    pad = b"\x00" * 9
    e_type = struct.pack("<H", 3)  # ET_DYN (shared object)
    e_machine = struct.pack("<H", machine)
    e_version = struct.pack("<I", 1)
    e_entry = struct.pack("<Q" if bitness == 64 else "<I", 0x1000)
    e_phoff = struct.pack("<Q" if bitness == 64 else "<I", 64)
    e_shoff = struct.pack("<Q" if bitness == 64 else "<I", 0)
    e_flags = struct.pack("<I", 0)
    e_ehsize = struct.pack("<H", 64)
    header = (magic + bytes([ei_class, ei_data, ei_version]) + pad +
              e_type + e_machine + e_version + e_entry + e_phoff + e_shoff + e_flags + e_ehsize)
    body = b"".join(extra_strings or [])
    return header.ljust(64, b"\x00") + body


def test_elf_header_parsing():
    elf_arm64 = _make_dummy_elf(bitness=64, machine=0xB7)
    parsed = parse_elf_header(elf_arm64)
    assert parsed["valid_elf"] is True
    assert parsed["bitness"] == 64
    assert parsed["endianness"] == "little"
    assert "arm64" in parsed["architecture"].lower()

    elf_x86 = _make_dummy_elf(bitness=32, machine=0x03)
    parsed_x86 = parse_elf_header(elf_x86)
    assert parsed_x86["bitness"] == 32
    assert parsed_x86["architecture"] == "x86"


def test_native_library_security_capabilities():
    suspicious_bytes = [
        b"Checking /system/bin/su for root\x00",
        b"Calling ptrace to detect debugger\x00",
        b"execve(/bin/sh) command\x00",
    ]
    elf = _make_dummy_elf(bitness=64, machine=0xB7, extra_strings=suspicious_bytes)
    res = analyze_native_library("lib/arm64-v8a/libroot.so", elf)
    caps = res["capabilities"]
    assert len(caps["root_detection"]) > 0
    assert len(caps["anti_debugging"]) > 0
    assert len(caps["command_execution"]) > 0


def test_yara_scanner_ransomware_detection():
    data = b"Attention: All your files have been encrypted! Pay the ransom immediately."
    matches = scan_files([("assets/notice.txt", data)])
    assert any(m.rule_name == "Android_Ransomware_Indicators" for m in matches)


def test_yara_scanner_cryptominer_detection():
    data = b"Connecting to stratum+tcp://pool.supportxmr.com:3333 with xmrig..."
    matches = scan_files([("classes.dex", data)])
    assert any(m.rule_name == "Android_Cryptominer_Pool" for m in matches)


def test_yara_scanner_downloader_detection():
    data = b"Downloading payload from http://malicious-c2.org/stage2.apk now."
    matches = scan_files([("classes2.dex", data)])
    assert any(m.rule_name == "Android_Suspicious_Downloader" for m in matches)
