"""core/detector.py — Content-type detection by magic bytes.

The upload's filename and declared MIME type are not trusted; the category that
decides which analysers run is taken from the file's own leading bytes.

    detect_content_type(path) -> (mime_type, file_category)

file_category is one of "apk" | "image" | "video" | "audio" | "web" | "doc",
or "unknown" when nothing matches. Unknown files are sent down the APK pipeline
by the orchestrator, which rejects them exactly as before ("Invalid APK").

Any ZIP is reported as category "apk": the APK engine is the only analyser for
ZIP containers, and its hardened archive validation decides whether the file is
really an installable app.
"""

from __future__ import annotations

import os
import re
import zipfile

SNIFF_BYTES = 4096

ZIP_MAGIC = b"PK\x03\x04"
APK_MIME = "application/vnd.android.package-archive"

# Brands of the ISO base media file format that carry audio only.
_AUDIO_BRANDS = {b"M4A ", b"M4B ", b"M4P ", b"F4A ", b"F4B "}
_HTML_START = re.compile(rb"^\s*(<!--.*?-->\s*)*<(!doctype\s+html|html|head|body)[\s>]", re.IGNORECASE | re.DOTALL)
_HTML_ANYWHERE = re.compile(rb"<(html|head|body|script|form|iframe)[\s>]", re.IGNORECASE)
_JS_HINT = re.compile(rb"\b(function|var|let|const|=>|document\.|window\.|import\s|export\s)")

# Extensions accepted for text formats that have no magic number. They only
# refine the decision between "web" and "unknown"; binary formats ignore them.
_JS_EXTENSIONS = {".js", ".mjs", ".cjs"}
_HTML_EXTENSIONS = {".html", ".htm", ".xhtml"}


def _zip_type(path: str) -> tuple[str, str]:
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
        return APK_MIME, "apk"   # damaged archive: the APK engine reports why
    if "AndroidManifest.xml" in names or any(re.match(r"classes\d*\.dex$", n) for n in names):
        return APK_MIME, "apk"
    if "base/manifest/AndroidManifest.xml" in names:
        return "application/vnd.android.aab", "apk"
    if "META-INF/MANIFEST.MF" in names:
        return "application/java-archive", "apk"
    return "application/zip", "apk"


def _is_text(head: bytes) -> bool:
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A multi-byte character cut off at the end of the sniff window is still text.
        return exc.start >= len(head) - 3
    return True


def sniff(head: bytes, extension: str = "") -> tuple[str, str]:
    """Classify the leading bytes of a file. `extension` (lower case, with dot) only
    breaks ties for text formats without a signature."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "image"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", "image"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif", "image"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp", "image"
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "audio/wav", "audio"
    if head[4:8] == b"ftyp":
        return ("audio/mp4", "audio") if head[8:12] in _AUDIO_BRANDS else ("video/mp4", "video")
    if head.startswith(b"\x1a\x45\xdf\xa3"):
        if b"webm" in head[:64]:
            return "video/webm", "video"
        return "video/x-matroska", "video"
    if head.startswith(b"ID3") or (len(head) >= 2 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0
                                   and (head[1] >> 1) & 0x03 != 0):
        return "audio/mpeg", "audio"
    if head.startswith(b"%PDF-"):
        return "application/pdf", "doc"
    if not _is_text(head):
        return "application/octet-stream", "unknown"
    text = head.lstrip(b"\xef\xbb\xbf")
    if _HTML_START.match(text) or (extension in _HTML_EXTENSIONS and _HTML_ANYWHERE.search(text)):
        return "text/html", "web"
    if extension in _JS_EXTENSIONS and (_JS_HINT.search(text) or not text.strip()):
        return "application/javascript", "web"
    return "text/plain", "unknown"


def detect_content_type(file_path: str) -> tuple[str, str]:
    """(mime_type, file_category) from the file's magic bytes."""
    with open(file_path, "rb") as fh:
        head = fh.read(SNIFF_BYTES)
    if head.startswith(ZIP_MAGIC):
        return _zip_type(file_path)
    return sniff(head, os.path.splitext(file_path)[1].lower())
