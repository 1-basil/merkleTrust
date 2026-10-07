"""core/analyzers/image.py — PNG, JPEG, GIF and WebP structural analysis.

Every format here has an unambiguous end: PNG's IEND chunk, JPEG's EOI marker,
GIF's 0x3B trailer, WebP's RIFF length. Decoders stop there, so bytes after it
are invisible to anyone viewing the picture — the polyglot / appended-payload
technique (IMG_POLYGLOT_PAYLOAD). The parsers walk the real structure rather
than searching for the end marker, because the marker bytes can legitimately
occur inside compressed data and embedded EXIF thumbnails.

Also checked: PNG chunk CRCs and out-of-bounds lengths (IMG_CORRUPT_CHUNK) and
EXIF metadata that leaks location or camera identity (IMG_PRIVACY_EXIF_*).
"""

from __future__ import annotations

import struct
import zlib
from typing import Any

from core.analyzers._common import MAX_EVIDENCE_ITEMS, build_report, trailing_finding
from core.contracts import JobContext
from core.detector import sniff
from core.findings import finding

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


# --------------------------------------------------------------- EXIF ----

_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
_MAX_IFD_ENTRIES = 512

TAG_MAKE, TAG_MODEL = 0x010F, 0x0110
TAG_EXIF_IFD, TAG_GPS_IFD = 0x8769, 0x8825
SERIAL_TAGS = {0xA431: "BodySerialNumber", 0xA435: "LensSerialNumber", 0xC62F: "CameraSerialNumber"}


def _read_ifd(tiff: bytes, offset: int, e: str) -> dict[int, Any]:
    """{tag: decoded value} for one IFD. Malformed entries are skipped, never raised."""
    if offset + 2 > len(tiff):
        return {}
    count = min(struct.unpack_from(e + "H", tiff, offset)[0], _MAX_IFD_ENTRIES)
    out: dict[int, Any] = {}
    for i in range(count):
        p = offset + 2 + 12 * i
        if p + 12 > len(tiff):
            break
        tag, typ, n = struct.unpack_from(e + "HHI", tiff, p)
        size = _TYPE_SIZES.get(typ)
        if size is None or n > 1 << 16:
            continue
        total = size * n
        if total <= 4:
            raw = tiff[p + 8:p + 8 + total]
        else:
            vo = struct.unpack_from(e + "I", tiff, p + 8)[0]
            if vo + total > len(tiff):
                continue
            raw = tiff[vo:vo + total]
        if typ == 2:
            out[tag] = raw.split(b"\x00", 1)[0].decode("latin-1", "replace").strip()
        elif typ in (3, 4, 9):
            fmt = {3: "H", 4: "I", 9: "i"}[typ]
            vals = struct.unpack(e + fmt * n, raw)
            out[tag] = vals[0] if n == 1 else list(vals)
        elif typ in (5, 10):
            fmt = "II" if typ == 5 else "ii"
            pairs = struct.unpack(e + fmt * n, raw)
            out[tag] = [pairs[j] / pairs[j + 1] if pairs[j + 1] else 0.0 for j in range(0, len(pairs), 2)]
        else:
            out[tag] = raw
    return out


def parse_exif(tiff: bytes) -> dict[str, Any]:
    """Privacy-relevant EXIF fields from a TIFF-structured blob ({} if not EXIF)."""
    if tiff.startswith(b"Exif\x00\x00"):
        tiff = tiff[6:]
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return {}
    e = "<" if tiff[:2] == b"II" else ">"
    if struct.unpack_from(e + "H", tiff, 2)[0] != 42:
        return {}
    ifd0 = _read_ifd(tiff, struct.unpack_from(e + "I", tiff, 4)[0], e)
    exif_ifd = _read_ifd(tiff, ifd0[TAG_EXIF_IFD], e) if isinstance(ifd0.get(TAG_EXIF_IFD), int) else {}
    gps_ifd = _read_ifd(tiff, ifd0[TAG_GPS_IFD], e) if isinstance(ifd0.get(TAG_GPS_IFD), int) else {}

    result: dict[str, Any] = {"make": ifd0.get(TAG_MAKE), "model": ifd0.get(TAG_MODEL),
                              "has_gps_ifd": TAG_GPS_IFD in ifd0, "gps": None, "serials": {}}
    lat, lon = gps_ifd.get(2), gps_ifd.get(4)
    if isinstance(lat, list) and isinstance(lon, list) and len(lat) == 3 and len(lon) == 3:
        def deg(v, ref, neg):
            d = v[0] + v[1] / 60 + v[2] / 3600
            return -d if str(ref).upper().startswith(neg) else d
        result["gps"] = (deg(lat, gps_ifd.get(1, "N"), "S"), deg(lon, gps_ifd.get(3, "E"), "W"))
    for tag, name in SERIAL_TAGS.items():
        value = exif_ifd.get(tag, ifd0.get(tag))
        if isinstance(value, str) and value:
            result["serials"][name] = value
    return result


def _mask(serial: str) -> str:
    return "*" * max(0, len(serial) - 4) + serial[-4:]


def exif_findings(exif: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    if exif.get("gps"):
        lat, lon = exif["gps"]
        # Rounded to ~1 km: the report must flag the leak, not repeat it precisely.
        findings.append(finding("IMG_PRIVACY_EXIF_GPS",
                                f"GPS coordinates embedded (approximately {lat:.2f}, {lon:.2f})"))
    if exif.get("serials"):
        findings.append(finding("IMG_PRIVACY_EXIF_SERIAL", "; ".join(
            f"{k} {_mask(v)}" for k, v in sorted(exif["serials"].items()))))
    return findings


def _exif_details(exif: dict[str, Any]) -> dict[str, Any]:
    return {"present": bool(exif), "make": exif.get("make"), "model": exif.get("model"),
            "gps_present": bool(exif.get("gps")), "serial_tags": sorted(exif.get("serials", {}))}


# --------------------------------------------------------------- PNG ----

def analyze_png(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings, problems, chunks = [], [], []
    exif: dict[str, Any] = {}
    pos, end_of_image = len(PNG_SIGNATURE), None
    while pos + 8 <= len(data):
        length, ctype = struct.unpack_from(">I4s", data, pos)
        name = ctype.decode("latin-1")
        end = pos + 12 + length
        if not ctype.isalpha():
            problems.append(f"invalid chunk type {ctype.hex()} at offset {pos}")
            break
        if end > len(data):
            problems.append(f"chunk {name} at offset {pos} declares {length} bytes, past the end of the file")
            break
        body = data[pos + 8:pos + 8 + length]
        (crc,) = struct.unpack_from(">I", data, pos + 8 + length)
        if zlib.crc32(ctype + body) & 0xFFFFFFFF != crc:
            problems.append(f"CRC mismatch in chunk {name} at offset {pos}")
        chunks.append(name)
        if ctype == b"eXIf":
            exif = parse_exif(body)
        pos = end
        if ctype == b"IEND":
            end_of_image = end
            break
    if end_of_image is None and not problems:
        problems.append("no IEND chunk: the image is truncated")
    if problems:
        findings.append(finding("IMG_CORRUPT_CHUNK", "; ".join(problems[:MAX_EVIDENCE_ITEMS])))
    if end_of_image is not None:
        f = trailing_finding("IMG_POLYGLOT_PAYLOAD", data, end_of_image, "the PNG IEND chunk")
        if f:
            findings.append(f)
    findings += exif_findings(exif)
    return findings, {"format": "png", "chunk_count": len(chunks), "chunk_types": sorted(set(chunks)),
                      "end_offset": end_of_image, "exif": _exif_details(exif)}


# -------------------------------------------------------------- JPEG ----

def _jpeg_end(data: bytes, start: int) -> tuple[int | None, list[str], bytes | None, bool]:
    """Walk one JPEG from its SOI at `start`. Returns (offset after EOI or None,
    problems, EXIF blob, has MPF multi-picture segment)."""
    pos, problems, exif, mpf = start + 2, [], None, False
    n = len(data)
    while pos < n:
        if data[pos] != 0xFF:
            problems.append(f"expected a marker at offset {pos}, found {data[pos]:#04x}")
            return None, problems, exif, mpf
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break
        marker = data[pos]
        pos += 1
        if marker == 0xD9:
            return pos, problems, exif, mpf
        if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
            continue
        if pos + 2 > n:
            break
        (seglen,) = struct.unpack_from(">H", data, pos)
        if seglen < 2 or pos + seglen > n:
            problems.append(f"segment {marker:#04x} at offset {pos - 2} runs past the end of the file")
            return None, problems, exif, mpf
        seg = data[pos + 2:pos + seglen]
        if marker == 0xE1 and seg.startswith(b"Exif\x00\x00") and exif is None:
            exif = seg[6:]
        elif marker == 0xE2 and seg.startswith(b"MPF\x00"):
            mpf = True
        pos += seglen
        if marker == 0xDA:   # entropy-coded scan data follows: find the next real marker
            while True:
                i = data.find(b"\xff", pos)
                if i < 0 or i + 1 >= n:
                    pos = n
                    break
                nxt = data[i + 1]
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                    pos = i + 1
                    continue
                pos = i
                break
    problems.append("no end-of-image (EOI) marker: the image is truncated")
    return None, problems, exif, mpf


def analyze_jpeg(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings = []
    end, problems, exif_blob, mpf = _jpeg_end(data, 0)
    images = 1
    # Multi-Picture Format (phones: depth maps, previews) stores extra JPEGs after
    # the primary image's EOI. They are part of the format, not appended payload.
    while mpf and end is not None and data[end:end + 3] == b"\xff\xd8\xff":
        nxt, more, _, _ = _jpeg_end(data, end)
        if nxt is None:
            problems += more
            break
        end, images = nxt, images + 1
    if problems:
        findings.append(finding("IMG_CORRUPT_CHUNK", "; ".join(problems[:MAX_EVIDENCE_ITEMS])))
    if end is not None:
        f = trailing_finding("IMG_POLYGLOT_PAYLOAD", data, end, "the JPEG end-of-image marker")
        if f:
            findings.append(f)
    exif = parse_exif(exif_blob) if exif_blob else {}
    findings += exif_findings(exif)
    return findings, {"format": "jpeg", "end_offset": end, "embedded_images": images, "mpf": mpf,
                      "exif": _exif_details(exif)}


# --------------------------------------------------------------- GIF ----

def _skip_sub_blocks(data: bytes, pos: int) -> int | None:
    while pos < len(data):
        size = data[pos]
        pos += 1
        if size == 0:
            return pos
        pos += size
    return None


def analyze_gif(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings, problems, frames = [], [], 0
    end = None
    if len(data) < 13:
        problems.append("file too short for a GIF header")
    else:
        flags = data[10]
        pos = 13 + (3 * (2 << (flags & 7)) if flags & 0x80 else 0)
        while pos < len(data):
            block = data[pos]
            if block == 0x3B:
                end = pos + 1
                break
            if block == 0x21:
                nxt = _skip_sub_blocks(data, pos + 2)
            elif block == 0x2C:
                if pos + 10 > len(data):
                    nxt = None
                else:
                    lflags = data[pos + 9]
                    p = pos + 10 + (3 * (2 << (lflags & 7)) if lflags & 0x80 else 0) + 1   # + LZW min code size
                    nxt = _skip_sub_blocks(data, p)
                    frames += 1
            else:
                problems.append(f"unknown block {block:#04x} at offset {pos}")
                break
            if nxt is None:
                problems.append(f"block at offset {pos} runs past the end of the file")
                break
            pos = nxt
        else:
            problems.append("no trailer (0x3B): the image is truncated")
    if problems:
        findings.append(finding("IMG_CORRUPT_CHUNK", "; ".join(problems[:MAX_EVIDENCE_ITEMS])))
    if end is not None:
        f = trailing_finding("IMG_POLYGLOT_PAYLOAD", data, end, "the GIF trailer")
        if f:
            findings.append(f)
    return findings, {"format": "gif", "frames": frames, "end_offset": end}


# -------------------------------------------------------------- WebP ----

def analyze_webp(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings, problems, chunks = [], [], []
    exif: dict[str, Any] = {}
    if len(data) < 12:
        return [finding("IMG_CORRUPT_CHUNK", "file too short for a RIFF/WebP header")], {"format": "webp"}
    (riff_size,) = struct.unpack_from("<I", data, 4)
    end = 8 + riff_size
    if end > len(data):
        problems.append(f"RIFF header declares {riff_size} bytes but only {len(data) - 8} are present")
        end = len(data)
    pos = 12
    while pos + 8 <= end:
        fourcc, size = data[pos:pos + 4], struct.unpack_from("<I", data, pos + 4)[0]
        if pos + 8 + size > end:
            problems.append(f"chunk {fourcc!r} at offset {pos} runs past the RIFF end")
            break
        chunks.append(fourcc.decode("latin-1"))
        if fourcc == b"EXIF":
            exif = parse_exif(data[pos + 8:pos + 8 + size])
        pos += 8 + size + (size & 1)
    if problems:
        findings.append(finding("IMG_CORRUPT_CHUNK", "; ".join(problems[:MAX_EVIDENCE_ITEMS])))
    f = trailing_finding("IMG_POLYGLOT_PAYLOAD", data, end, "the declared RIFF length")
    if f:
        findings.append(f)
    findings += exif_findings(exif)
    return findings, {"format": "webp", "riff_size": riff_size, "chunk_types": sorted(set(chunks)),
                      "end_offset": end, "exif": _exif_details(exif)}


ANALYZERS = {"image/png": analyze_png, "image/jpeg": analyze_jpeg, "image/gif": analyze_gif,
             "image/webp": analyze_webp}


def analyze(data: bytes, mime_type: str | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    mime = mime_type if mime_type in ANALYZERS else sniff(data[:4096])[0]
    if mime not in ANALYZERS:
        return [], {"format": "unsupported", "mime_type": mime}
    return ANALYZERS[mime](data)


def run(job_id: str, ctx: JobContext) -> dict:
    with open(ctx.target_path, "rb") as fh:
        data = fh.read()
    findings, details = analyze(data, ctx.mime_type)
    status = "ok" if details.get("format") != "unsupported" else "partial"
    return build_report(ctx, job_id, "image", findings, details, status)
