"""api/uploads.py — Safe handling of uploaded files (APKs, and media/web/PDF content for scans).

Nothing about an upload is trusted: not the filename, not the declared MIME
type, not the declared size.

  * the body is streamed to a private temporary file in 1 MiB chunks and
    aborted as soon as it exceeds the size limit (memory use stays constant);
  * an APK must then pass the hardened archive validation (core.apk_archive:
    ZIP structure, manifest present, zip-bomb, path and duplicate-entry checks);
    any other accepted type must have magic bytes (core.detector) that agree
    with its extension — a renamed executable is refused, not analysed;
  * the client filename is reduced to a short, safe display string and never
    used to build a filesystem path — stored files are named by their SHA-256;
  * quarantined files are written atomically and made read-only;
  * temporary files are always removed.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from fastapi import UploadFile

from api.errors import ApiError
from core.apk_archive import ApkArchive, ApkValidationError
from core.detector import detect_content_type

CHUNK = 1024 * 1024
_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._ -]+")

# Non-APK content accepted for scans: extension -> file categories its magic bytes may show.
CONTENT_EXTENSIONS = {
    ".png": {"image"}, ".jpg": {"image"}, ".jpeg": {"image"}, ".gif": {"image"}, ".webp": {"image"},
    ".mp4": {"video", "audio"}, ".m4a": {"audio"}, ".mkv": {"video"}, ".webm": {"video"},
    ".mp3": {"audio"}, ".wav": {"audio"},
    ".html": {"web"}, ".htm": {"web"}, ".js": {"web"},
    ".pdf": {"doc"},
}


@dataclass
class ReceivedApk:
    path: Path              # temporary file (deleted when the context exits)
    sha256: str
    size: int
    display_name: str
    suffix: str = ".apk"
    mime_type: str = "application/vnd.android.package-archive"
    file_category: str = "apk"


def safe_display_name(raw: str | None) -> str:
    """A harmless label derived from the client filename (never used as a path)."""
    name = unicodedata.normalize("NFKC", raw or "")
    name = name.replace("\\", "/").rsplit("/", 1)[-1]          # drop any directory part
    name = _SAFE_CHARS.sub("_", name).strip(" .") or "upload.apk"
    return name[:100]


@contextmanager
def receive_apk(upload: UploadFile, max_bytes: int, tmp_dir: Path, *,
                allow_content: bool = False) -> Iterator[ReceivedApk]:
    """Stream, size-limit, hash and validate an upload. Yields a temporary file.

    With allow_content, images, audio/video, web pages and PDFs are accepted too
    (scans); baselines stay APK-only.
    """
    display = safe_display_name(upload.filename)
    suffix = os.path.splitext(display.lower())[1]
    if suffix != ".apk" and not (allow_content and suffix in CONTENT_EXTENSIONS):
        if allow_content:
            raise ApiError(415, "Unsupported file type. Upload an .apk, image, audio/video, web page or PDF.")
        raise ApiError(415, "Only .apk files can be uploaded.")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix="upload_", suffix=suffix, dir=tmp_dir)
    tmp = Path(tmp_name)
    try:
        digest, size = hashlib.sha256(), 0
        with os.fdopen(fd, "wb") as out:
            while chunk := upload.file.read(CHUNK):
                size += len(chunk)
                if size > max_bytes:
                    raise ApiError(413, f"The file is larger than the {max_bytes // (1024 * 1024)} MB limit.")
                digest.update(chunk)
                out.write(chunk)
        if size == 0:
            raise ApiError(422, "The uploaded file is empty.")
        if suffix != ".apk":
            mime_type, category = detect_content_type(str(tmp))
            if category not in CONTENT_EXTENSIONS[suffix]:
                raise ApiError(422, f"The file's contents do not match its {suffix} extension.",
                               code="invalid_content")
            yield ReceivedApk(tmp, digest.hexdigest(), size, display, suffix, mime_type, category)
            return
        try:
            with ApkArchive(str(tmp), limits={"max_file_bytes": max_bytes}):
                pass
        except ApkValidationError as exc:
            raise ApiError(422, f"This is not a valid Android app: {exc}", code="invalid_apk") from None
        yield ReceivedApk(tmp, digest.hexdigest(), size, display)
    finally:
        tmp.unlink(missing_ok=True)


def quarantine(received: ReceivedApk, quarantine_dir: Path) -> Path:
    """Store the validated file under its SHA-256 name (atomic, read-only, idempotent)."""
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    target = quarantine_dir / f"{received.sha256}{received.suffix}"
    if not target.exists():
        fd, staging = tempfile.mkstemp(prefix=".staging_", dir=quarantine_dir)
        with os.fdopen(fd, "wb") as out, open(received.path, "rb") as src:
            while chunk := src.read(CHUNK):
                out.write(chunk)
        os.replace(staging, target)
        os.chmod(target, 0o444)
    return target
