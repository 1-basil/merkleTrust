"""core/analyzers/document.py — PDF active-content and appended-data analysis.

PDF name objects may hide their spelling with #xx escapes (/J#61vaScript), and
PDF 1.5 object streams compress whole dictionaries; both are undone before
searching, with a hard cap on decompressed bytes so a compression bomb cannot
exhaust memory.

  DOC_PDF_ACTIVE_CONTENT  /JavaScript, /JS or /Launch
  DOC_PDF_AUTO_ACTION     /OpenAction or /AA
  DOC_PDF_EMBEDDED_FILE   /EmbeddedFile
  DOC_TRAILING_PAYLOAD    bytes after the final %%EOF
"""

from __future__ import annotations

import re
import zlib
from typing import Any

from core.analyzers._common import build_report, trailing_finding
from core.contracts import JobContext
from core.findings import finding

MAX_INFLATED_BYTES = 16 * 1024 * 1024
MAX_STREAMS = 2000

_NAME_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
_STREAM = re.compile(rb"(?<!end)stream\r?\n")
_KEYS = {
    "JavaScript": re.compile(rb"/JavaScript\b"),
    "JS": re.compile(rb"/JS\b"),
    "Launch": re.compile(rb"/Launch\b"),
    "OpenAction": re.compile(rb"/OpenAction\b"),
    "AA": re.compile(rb"/AA\b"),
    "EmbeddedFile": re.compile(rb"/EmbeddedFiles?\b"),
}


def _unescape_names(data: bytes) -> bytes:
    return _NAME_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), data)


def _object_streams(data: bytes) -> tuple[list[bytes], bool]:
    """Decompressed object streams (where PDF 1.5+ hides dictionaries); True if the cap was hit."""
    out, total, capped = [], 0, False
    seen = 0
    for m in _STREAM.finditer(data):
        head = data[max(0, m.start() - 1024):m.start()]
        head = head[max(0, head.rfind(b" obj")):]          # this object's dictionary only
        if not re.search(rb"/Type\s*/ObjStm", head):
            continue
        seen += 1
        if seen > MAX_STREAMS:
            break
        end = data.find(b"endstream", m.end())
        if end < 0:
            continue
        d = zlib.decompressobj()
        try:
            chunk = d.decompress(data[m.end():end], MAX_INFLATED_BYTES - total)
        except zlib.error:
            continue
        total += len(chunk)
        out.append(chunk)
        if d.unconsumed_tail or total >= MAX_INFLATED_BYTES:
            capped = True
            break
    return out, capped


def analyze_pdf(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    streams, capped = _object_streams(data)
    corpus = [_unescape_names(data)] + [_unescape_names(s) for s in streams]
    counts = {k: sum(len(p.findall(c)) for c in corpus) for k, p in _KEYS.items()}
    obfuscated = bool(_NAME_ESCAPE.search(re.sub(rb"stream.*?endstream", b"", data, flags=re.DOTALL)))

    findings = []
    active = [k for k in ("JavaScript", "JS", "Launch") if counts[k]]
    if active:
        evidence = ", ".join(f"/{k} x{counts[k]}" for k in active)
        if obfuscated:
            evidence += " (PDF names are hex-escaped, a common obfuscation)"
        findings.append(finding("DOC_PDF_ACTIVE_CONTENT", evidence,
                                **({"severity": "critical", "points": 30} if counts["Launch"] else {})))
    auto = [k for k in ("OpenAction", "AA") if counts[k]]
    if auto:
        findings.append(finding("DOC_PDF_AUTO_ACTION", ", ".join(f"/{k} x{counts[k]}" for k in auto)))
    if counts["EmbeddedFile"]:
        findings.append(finding("DOC_PDF_EMBEDDED_FILE", f"/EmbeddedFile x{counts['EmbeddedFile']}"))

    eof = data.rfind(b"%%EOF")
    end = None
    if eof >= 0:
        end = eof + 5
        f = trailing_finding("DOC_TRAILING_PAYLOAD", data, end, "the final %%EOF marker")
        if f:
            findings.append(f)
    version = data[5:8].decode("latin-1", "replace")
    return findings, {"format": "pdf", "version": version, "keywords": counts, "object_streams": len(streams),
                      "inflate_capped": capped, "eof_offset": end, "incremental_updates": data.count(b"%%EOF")}


def run(job_id: str, ctx: JobContext) -> dict:
    with open(ctx.target_path, "rb") as fh:
        data = fh.read()
    findings, details = analyze_pdf(data)
    status = "partial" if details["eof_offset"] is None or details["inflate_capped"] else "ok"
    return build_report(ctx, job_id, "document", findings, details, status)
