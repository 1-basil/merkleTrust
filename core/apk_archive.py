"""core/apk_archive.py — Hardened, read-only access to an APK (ZIP) archive.

Every engine that reads APK contents goes through this module so that untrusted
archives are validated once, consistently:

* file size, entry count and total uncompressed size are bounded;
* compression ratio is bounded (zip-bomb defence) and reads are size-capped even
  if the central directory lies about sizes;
* entry names are checked for absolute paths, ``..`` traversal, backslashes,
  drive letters and NUL bytes (we never extract to disk, but names flow into
  reports, the UI and baseline manifests);
* duplicate entry names are rejected — they make "the content of classes.dex"
  ambiguous (cf. Android "Master Key" bug, CVE-2013-4787);
* bytes before the first local file header are reported (cf. "Janus",
  CVE-2017-13156, where a DEX is prepended to a signed APK).
"""

from __future__ import annotations

import os
import posixpath
import re
import zipfile
from dataclasses import dataclass, field
from typing import Iterator

# Defaults are deliberately generous for real apps but finite.
DEFAULT_LIMITS = {
    "max_file_bytes": 200 * 1024 * 1024,           # 200 MB on disk
    "max_entries": 20_000,
    "max_total_uncompressed": 1024 * 1024 * 1024,   # 1 GB
    "max_entry_uncompressed": 256 * 1024 * 1024,    # 256 MB
    "max_compression_ratio": 200,                   # only applied to entries > 1 MB
}

_DRIVE_RE = re.compile(r"^[A-Za-z]:")


class ApkValidationError(Exception):
    """The file is not a structurally acceptable APK. Message is safe to show users."""


@dataclass(frozen=True)
class EntryInfo:
    name: str
    compressed_size: int
    uncompressed_size: int
    crc32: int
    header_offset: int
    compress_type: int
    is_dir: bool


@dataclass
class ArchiveReport:
    entry_count: int
    total_uncompressed: int
    prefix_bytes: int
    warnings: list[str] = field(default_factory=list)


def unsafe_name_reason(name: str) -> str | None:
    """Return why an entry name is unsafe, or None if acceptable."""
    if not name:
        return "empty entry name"
    if "\x00" in name:
        return "NUL byte in entry name"
    if "\\" in name:
        return "backslash in entry name"
    if name.startswith("/") or _DRIVE_RE.match(name):
        return "absolute path in entry name"
    if ".." in name.split("/"):
        return "parent-directory traversal ('..') in entry name"
    if posixpath.normpath(name).startswith("../"):
        return "path escapes archive root"
    return None


class ApkArchive:
    """Validated read-only view of an APK. Use as a context manager."""

    def __init__(self, path: str, limits: dict | None = None, require_manifest: bool = True):
        self.path = path
        self.limits = {**DEFAULT_LIMITS, **(limits or {})}
        self._fh = None
        self._zip: zipfile.ZipFile | None = None
        self._entries: dict[str, EntryInfo] = {}
        self.report: ArchiveReport
        self._open(require_manifest)

    # ------------------------------------------------------------ opening --
    def _open(self, require_manifest: bool) -> None:
        if not os.path.isfile(self.path):
            raise ApkValidationError("File not found")
        size = os.path.getsize(self.path)
        if size == 0:
            raise ApkValidationError("File is empty")
        if size > self.limits["max_file_bytes"]:
            raise ApkValidationError(f"File exceeds maximum size of {self.limits['max_file_bytes']} bytes")

        self._fh = open(self.path, "rb")
        try:
            self._zip = zipfile.ZipFile(self._fh, "r")
        except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError) as exc:
            self.close()
            raise ApkValidationError(f"Not a valid ZIP/APK archive ({type(exc).__name__})") from None

        try:
            self.report = self._validate(require_manifest)
        except ApkValidationError:
            self.close()
            raise

    def _validate(self, require_manifest: bool) -> ArchiveReport:
        infos = self._zip.infolist()
        if len(infos) > self.limits["max_entries"]:
            raise ApkValidationError(f"Archive has too many entries ({len(infos)})")

        warnings: list[str] = []
        total = 0
        for info in infos:
            # zipfile silently normalises names (truncates at NUL, maps os.sep to '/'),
            # so validate the raw central-directory name as well.
            for candidate in (info.orig_filename, info.filename):
                reason = unsafe_name_reason(candidate)
                if reason:
                    raise ApkValidationError(f"Unsafe entry name {candidate!r}: {reason}")
            if info.filename in self._entries:
                raise ApkValidationError(f"Duplicate entry name {info.filename!r} (ambiguous archive)")
            if info.file_size > self.limits["max_entry_uncompressed"]:
                raise ApkValidationError(f"Entry {info.filename!r} is too large when uncompressed")
            if (info.file_size > 1024 * 1024 and info.compress_size > 0
                    and info.file_size / info.compress_size > self.limits["max_compression_ratio"]):
                raise ApkValidationError(f"Entry {info.filename!r} has a suspicious compression ratio (possible zip bomb)")
            if info.flag_bits & 0x1:
                raise ApkValidationError(f"Entry {info.filename!r} is encrypted")
            total += info.file_size
            self._entries[info.filename] = EntryInfo(
                name=info.filename,
                compressed_size=info.compress_size,
                uncompressed_size=info.file_size,
                crc32=info.CRC,
                header_offset=info.header_offset,
                compress_type=info.compress_type,
                is_dir=info.is_dir(),
            )
        if total > self.limits["max_total_uncompressed"]:
            raise ApkValidationError("Archive total uncompressed size exceeds limit (possible zip bomb)")

        if require_manifest and "AndroidManifest.xml" not in self._entries:
            raise ApkValidationError("Archive does not contain AndroidManifest.xml — not an Android application")

        # Bytes before the first local file header (Janus-style prepended data).
        first_offset = min((e.header_offset for e in self._entries.values()), default=0)
        prefix = first_offset
        self._fh.seek(0)
        if self._fh.read(4) != b"PK\x03\x04":
            prefix = max(prefix, 1)
        if prefix:
            warnings.append(f"{prefix} byte(s) of data precede the first ZIP entry")

        return ArchiveReport(entry_count=len(infos), total_uncompressed=total,
                             prefix_bytes=prefix, warnings=warnings)

    # ------------------------------------------------------------- access --
    def names(self) -> list[str]:
        return list(self._entries)

    def entries(self) -> list[EntryInfo]:
        return list(self._entries.values())

    def files(self) -> Iterator[EntryInfo]:
        """Iterate non-directory entries in archive order."""
        return (e for e in self._entries.values() if not e.is_dir)

    def has(self, name: str) -> bool:
        return name in self._entries

    def info(self, name: str) -> EntryInfo:
        return self._entries[name]

    def read(self, name: str, max_bytes: int | None = None) -> bytes:
        """Read an entry, enforcing a hard cap independent of declared sizes.

        Raises ApkValidationError if the entry is corrupt (bad CRC / bad data)
        or larger than allowed.
        """
        if name not in self._entries:
            raise KeyError(name)
        cap = max_bytes if max_bytes is not None else self.limits["max_entry_uncompressed"]
        try:
            with self._zip.open(name) as fh:
                data = fh.read(cap + 1)
        except (zipfile.BadZipFile, EOFError, OSError, ValueError, NotImplementedError) as exc:
            raise ApkValidationError(f"Entry {name!r} is corrupt or unreadable ({type(exc).__name__})") from None
        except Exception as exc:  # zlib.error and other decompressor failures
            raise ApkValidationError(f"Entry {name!r} could not be decompressed ({type(exc).__name__})") from None
        if len(data) > cap:
            raise ApkValidationError(f"Entry {name!r} exceeds read limit")
        return data

    # ------------------------------------------------------------ cleanup --
    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "ApkArchive":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
