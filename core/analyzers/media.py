"""core/analyzers/media.py — Audio and video container analysis.

Containers declare their own extent: ISO-BMFF (MP4) boxes and Matroska
elements carry sizes, a RIFF/WAV header states the total length, and MPEG audio
is a chain of fixed-length frames. Walking that structure from the start shows
exactly where the media ends; anything after it, or any structure no player
understands, is reported:

  MEDIA_CONTAINER_ANOMALY  unknown/orphan box or element, truncation, data past
                           the final atom, a known payload inside a free box
  AUDIO_TRAILING_PAYLOAD   bytes past the declared RIFF length or the last MPEG frame
"""

from __future__ import annotations

import io
import struct
import wave
from typing import Any

from core.analyzers._common import (EMBEDDED_SIGNATURES, MAX_EVIDENCE_ITEMS, build_report, describe_trailing,
                                    is_padding, trailing_finding)
from core.contracts import JobContext
from core.detector import sniff
from core.findings import finding

# ----------------------------------------------------------- ISO BMFF ----

MP4_TOP_LEVEL = {b"ftyp", b"styp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta", b"moof",
                 b"mfra", b"sidx", b"ssix", b"prft", b"emsg", b"pdin", b"udta", b"jumb", b"junk", b"pnot",
                 b"PICT", b"mvex"}
_FILLER_BOXES = {b"free", b"skip", b"wide", b"junk"}


def _box_type_ok(t: bytes) -> bool:
    return all(0x20 <= b < 0x7F or b == 0xA9 for b in t)


def _anomaly(severity: str, points: int, problems: list[str]) -> dict[str, Any]:
    return finding("MEDIA_CONTAINER_ANOMALY", "; ".join(problems[:MAX_EVIDENCE_ITEMS]),
                   severity=severity, points=points)


def _trailing_anomaly(data: bytes, offset: int, marker: str) -> dict[str, Any] | None:
    """Trailing bytes inside a video container: high, or critical with a known signature."""
    f = trailing_finding("MEDIA_CONTAINER_ANOMALY", data, offset, marker)
    if f and f["severity"] == "medium":
        f["severity"], f["points"] = "high", 20
    return f


def analyze_mp4(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings, boxes, unknown, structural, hidden = [], [], [], [], []
    n, pos, trailing_at = len(data), 0, None
    while pos < n:
        if n - pos < 8:
            trailing_at = pos
            break
        size, btype = struct.unpack_from(">I4s", data, pos)
        hdr = 8
        if size == 1:
            if n - pos < 16:
                trailing_at = pos
                break
            (size,) = struct.unpack_from(">Q", data, pos + 8)
            hdr = 16
        elif size == 0:
            size = n - pos
        if not _box_type_ok(btype) or size < hdr:
            trailing_at = pos   # not a box: whatever is here is not part of the media
            break
        name = btype.decode("latin-1")
        if pos + size > n:
            structural.append(f"box '{name}' at offset {pos} declares {size} bytes, past the end of the file")
            boxes.append({"type": name, "offset": pos, "size": n - pos})
            break
        boxes.append({"type": name, "offset": pos, "size": size})
        if btype not in MP4_TOP_LEVEL:
            unknown.append(f"unrecognised top-level box '{name}' ({size} bytes) at offset {pos}")
        elif btype in _FILLER_BOXES:
            body = data[pos + hdr:pos + min(size, hdr + 64)].lstrip(b"\x00")
            kind = next((k for sig, k in EMBEDDED_SIGNATURES if body[:len(sig)].lower() == sig.lower()), None)
            if kind:
                hidden.append(f"filler box '{name}' at offset {pos} contains a {kind} signature")
        pos += size
    types = [b["type"] for b in boxes]
    if types and types[0] not in ("ftyp", "styp"):
        structural.append(f"first box is '{types[0]}', not 'ftyp'")
    if types and "moov" not in types and "moof" not in types:
        structural.append("no 'moov' (movie metadata) box")

    if trailing_at is not None:
        f = _trailing_anomaly(data, trailing_at, "the final MP4 atom")
        if f:
            findings.append(f)
    if hidden:
        findings.append(_anomaly("critical", 30, hidden))
    if unknown:
        findings.append(_anomaly("medium", 10, unknown))
    if structural:
        findings.append(_anomaly("low", 3, structural))
    return findings, {"format": "mp4", "boxes": boxes[:200], "box_count": len(boxes),
                      "end_offset": trailing_at if trailing_at is not None else pos}


# ------------------------------------------------------------ Matroska ----

EBML_ID, SEGMENT_ID = 0x1A45DFA3, 0x18538067
MKV_TOP_LEVEL = {EBML_ID, SEGMENT_ID, 0xEC, 0xBF}   # EBML header, Segment, Void, CRC-32


def _vint(data: bytes, pos: int, keep_marker: bool) -> tuple[int, int, bool] | None:
    """(value, length, is_unknown_size) of an EBML variable-length integer."""
    if pos >= len(data) or data[pos] == 0:
        return None
    length = 9 - data[pos].bit_length()
    if pos + length > len(data):
        return None
    value = int.from_bytes(data[pos:pos + length], "big")
    if keep_marker:
        return value, length, False
    value &= (1 << (7 * length)) - 1
    return value, length, value == (1 << (7 * length)) - 1


def analyze_mkv(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings, elements, unknown, structural = [], [], [], []
    n, pos, trailing_at = len(data), 0, None
    while pos < n:
        eid = _vint(data, pos, keep_marker=True)
        esize = _vint(data, pos + eid[1], keep_marker=False) if eid and eid[1] <= 4 else None
        if eid is None or esize is None:
            trailing_at = pos
            break
        start = pos + eid[1] + esize[1]
        size = n - start if esize[2] else esize[0]
        if eid[0] not in MKV_TOP_LEVEL:
            if elements:          # after real elements, an unknown ID is most likely appended data
                trailing_at = pos
                break
            unknown.append(f"unrecognised top-level element {eid[0]:#x} at offset {pos}")
        if start + size > n:
            structural.append(f"element {eid[0]:#x} at offset {pos} declares {size} bytes, past the end of the file")
            elements.append({"id": hex(eid[0]), "offset": pos, "size": n - start})
            pos = n
            break
        elements.append({"id": hex(eid[0]), "offset": pos, "size": size})
        pos = start + size
    if not any(e["id"] == hex(SEGMENT_ID) for e in elements):
        structural.append("no Segment element")
    if trailing_at is not None:
        f = _trailing_anomaly(data, trailing_at, "the final Matroska element")
        if f:
            findings.append(f)
    if unknown:
        findings.append(_anomaly("medium", 10, unknown))
    if structural:
        findings.append(_anomaly("low", 3, structural))
    return findings, {"format": "matroska", "elements": elements[:200],
                      "end_offset": trailing_at if trailing_at is not None else pos}


# ------------------------------------------------------------ RIFF/WAV ----

def analyze_wav(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings, structural, chunks = [], [], []
    (riff_size,) = struct.unpack_from("<I", data, 4)
    declared_end = 8 + riff_size
    end = min(declared_end, len(data))
    if declared_end > len(data):
        structural.append(f"RIFF header declares {riff_size} bytes but only {len(data) - 8} are present")
    pos = 12
    while pos + 8 <= end:
        cid, size = data[pos:pos + 4], struct.unpack_from("<I", data, pos + 4)[0]
        name = cid.decode("latin-1")
        if pos + 8 + size > end:
            structural.append(f"chunk '{name}' at offset {pos} runs past the RIFF end")
            chunks.append(name)
            break
        chunks.append(name)
        pos += 8 + size + (size & 1)
    for required in ("fmt ", "data"):
        if required not in chunks:
            structural.append(f"missing '{required.strip()}' chunk")

    params: dict[str, Any] = {}
    try:
        with wave.open(io.BytesIO(data[:end])) as w:
            params = {"channels": w.getnchannels(), "sample_rate": w.getframerate(),
                      "sample_width": w.getsampwidth(), "frames": w.getnframes()}
    except (wave.Error, EOFError, struct.error):
        pass   # compressed or unusual WAV codecs: structure is still checked above

    tail_start = declared_end + (riff_size & 1)   # RIFF pads odd sizes with one byte
    if declared_end <= len(data):
        f = trailing_finding("AUDIO_TRAILING_PAYLOAD", data, min(tail_start, len(data)),
                             "the declared RIFF length")
        if f:
            findings.append(f)
    if structural:
        findings.append(_anomaly("low", 3, structural))
    return findings, {"format": "wav", "riff_size": riff_size, "chunks": chunks, "end_offset": declared_end,
                      "audio": params}


# ---------------------------------------------------------- MPEG audio ----

_BITRATES = {
    (3, 3): [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
    (3, 2): [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
    (3, 1): [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
    (2, 3): [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],
    (2, 2): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
    (2, 1): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
}
_SAMPLE_RATES = {3: [44100, 48000, 32000], 2: [22050, 24000, 16000], 0: [11025, 12000, 8000]}
MIN_FRAMES_FOR_VERDICT = 4


def _mpeg_frame_length(data: bytes, pos: int) -> int | None:
    if pos + 4 > len(data) or data[pos] != 0xFF or data[pos + 1] & 0xE0 != 0xE0:
        return None
    version, layer = (data[pos + 1] >> 3) & 3, (data[pos + 1] >> 1) & 3
    br_idx, sr_idx, pad = data[pos + 2] >> 4, (data[pos + 2] >> 2) & 3, (data[pos + 2] >> 1) & 1
    if version == 1 or layer == 0 or br_idx in (0, 15) or sr_idx == 3:
        return None
    bitrate = _BITRATES[(3 if version == 3 else 2, layer)][br_idx] * 1000
    sr = _SAMPLE_RATES[version][sr_idx]
    if layer == 3:                                   # Layer I
        return (12 * bitrate // sr + pad) * 4
    if layer == 1 and version != 3:                  # Layer III, MPEG-2/2.5
        return 72 * bitrate // sr + pad
    return 144 * bitrate // sr + pad


def analyze_mp3(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings, n = [], len(data)
    pos, id3v2 = 0, 0
    if data.startswith(b"ID3") and n >= 10:
        size = (data[6] & 0x7F) << 21 | (data[7] & 0x7F) << 14 | (data[8] & 0x7F) << 7 | (data[9] & 0x7F)
        id3v2 = 10 + size + (10 if data[5] & 0x10 else 0)
        pos = id3v2
    while pos < n and data[pos] == 0:   # padding after the tag
        pos += 1
    first_frame, frames = pos, 0
    while (length := _mpeg_frame_length(data, pos)) is not None and length > 4 and pos + length <= n:
        pos += length
        frames += 1

    # Legitimate trailers, removed from the end before judging what is left.
    end = n
    trailers = []
    if end - 128 >= pos and data[end - 128:end - 125] == b"TAG":
        end -= 128
        trailers.append("ID3v1")
    if end - 32 >= pos and data[end - 32:end - 24] == b"APETAGEX":
        (ape_size,) = struct.unpack_from("<I", data, end - 20)
        end = max(pos, end - ape_size - (32 if data[end - 32 + 23] & 0x80 else 0))
        trailers.append("APEv2")
    if end - 15 >= pos and data[end - 9:end] in (b"LYRICS200", b"LYRICSEND"):
        trailers.append("Lyrics3")
        end = pos   # Lyrics3 length is unreliable to parse; accept the block

    leftover = data[pos:end]
    cut_frame = _mpeg_frame_length(data, pos)
    truncated = cut_frame is not None and pos + cut_frame > end   # last frame cut short, not appended data
    if frames >= MIN_FRAMES_FOR_VERDICT and leftover and not truncated and not is_padding(leftover, limit=1024):
        text, kind = describe_trailing(data[:end], pos)
        evidence = f"{text} (after the last of {frames} MPEG audio frames)"
        findings.append(finding("AUDIO_TRAILING_PAYLOAD", evidence,
                                **({"severity": "critical", "points": 30} if kind else {})))
    status_note = None if frames >= MIN_FRAMES_FOR_VERDICT else "too few MPEG frames to judge trailing data"
    return findings, {"format": "mp3", "id3v2_size": id3v2, "first_frame_offset": first_frame, "frames": frames,
                      "end_offset": pos, "trailers": trailers, "note": status_note}


ANALYZERS = {"video/mp4": analyze_mp4, "audio/mp4": analyze_mp4, "video/x-matroska": analyze_mkv,
             "video/webm": analyze_mkv, "audio/wav": analyze_wav, "audio/mpeg": analyze_mp3}


def analyze(data: bytes, mime_type: str | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    mime = mime_type if mime_type in ANALYZERS else sniff(data[:4096])[0]
    if mime not in ANALYZERS or len(data) < 12:
        return [], {"format": "unsupported", "mime_type": mime}
    return ANALYZERS[mime](data)


def run(job_id: str, ctx: JobContext) -> dict:
    with open(ctx.target_path, "rb") as fh:
        data = fh.read()
    findings, details = analyze(data, ctx.mime_type)
    status = "partial" if details.get("format") == "unsupported" or details.get("note") else "ok"
    return build_report(ctx, job_id, "media", findings, details, status)
