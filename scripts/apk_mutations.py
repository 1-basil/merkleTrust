"""scripts/apk_mutations.py — Controlled tampering operations on real APKs.

Shared by the test suite and the evaluation runner so that "what an attacker
did" is defined once. All functions write a new file and never modify the input.
"""

from __future__ import annotations

import zipfile
from pathlib import Path


def rewrite_zip(src: str | Path, dst: str | Path, modify: dict[str, bytes] | None = None,
                add: dict[str, bytes] | None = None, remove: set[str] | None = None) -> Path:
    """Re-create the archive entry by entry, optionally changing its contents.

    Rewriting with zipfile drops the APK Signing Block (v2/v3), exactly as a
    naive repackaging tool would. v1 signature files are kept unless removed.
    """
    modify, add, remove = modify or {}, add or {}, remove or set()
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
        for info in zin.infolist():
            if info.filename in remove:
                continue
            data = modify.get(info.filename, zin.read(info.filename))
            zout.writestr(info, data, compress_type=info.compress_type)
        for name, data in add.items():
            zout.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED)
    return Path(dst)


def flip_byte(src: str | Path, dst: str | Path, offset: int) -> Path:
    """Copy the file and XOR one byte at `offset` (negative offsets count from the end)."""
    data = bytearray(Path(src).read_bytes())
    data[offset] ^= 0xFF
    Path(dst).write_bytes(bytes(data))
    return Path(dst)


def local_header_offset(apk: str | Path, name: str) -> int:
    with zipfile.ZipFile(apk) as zf:
        return zf.getinfo(name).header_offset
