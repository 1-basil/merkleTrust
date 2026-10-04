"""Shared helpers for the content analysers."""

from __future__ import annotations

from typing import Any

from core.contracts import JobContext, emit
from core.findings import finding

# Signatures that make appended bytes far more than padding: archives,
# executables, documents and markup that another program will happily open.
EMBEDDED_SIGNATURES = [
    (b"PK\x03\x04", "ZIP archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b\x08", "gzip stream"),
    (b"MZ", "Windows executable"),
    (b"\x7fELF", "ELF executable"),
    (b"dex\n", "Android DEX bytecode"),
    (b"%PDF-", "PDF document"),
    (b"<script", "HTML script"),
    (b"<html", "HTML document"),
    (b"<?php", "PHP script"),
    (b"#!/", "shell script"),
]

MAX_EVIDENCE_ITEMS = 10


def describe_trailing(data: bytes, offset: int) -> tuple[str, str | None]:
    """Human-readable description of the bytes from `offset` to the end, and the
    kind of embedded content they start with (if recognisable)."""
    tail = data[offset:]
    head = tail[:64].lstrip(b"\x00\r\n\t ")
    kind = next((name for sig, name in EMBEDDED_SIGNATURES if head[:len(sig)].lower() == sig.lower()), None)
    text = f"{len(tail)} byte(s) after offset {offset}"
    if kind:
        text += f"; they start with a {kind} signature"
    else:
        text += f"; first bytes {tail[:16].hex()}"
    return text, kind


def is_padding(tail: bytes, limit: int = 16) -> bool:
    """A few zero / whitespace bytes after the end marker are common encoder padding."""
    return len(tail) <= limit and not tail.strip(b"\x00\r\n\t ")


def trailing_finding(fid: str, data: bytes, offset: int, marker: str) -> dict[str, Any] | None:
    """Finding for bytes past a container's end, escalated when they carry a known payload."""
    tail = data[offset:]
    if not tail or is_padding(tail):
        return None
    text, kind = describe_trailing(data, offset)
    evidence = f"{text} (after {marker})"
    if kind:
        return finding(fid, evidence, severity="critical", points=30)
    return finding(fid, evidence)


def build_report(ctx: JobContext, job_id: str, analyzer: str, findings: list[dict[str, Any]],
                 details: dict[str, Any], status: str = "ok") -> dict[str, Any]:
    """Assemble and emit content.json — the common report shape of every content analyser."""
    risky = [f for f in findings if f["severity"] != "info"]
    findings = findings + [finding("CONTENT_ANALYZED",
                                   f"{analyzer} analyser: {len(risky)} issue(s) found in {ctx.mime_type}")]
    report = {
        "job_id": job_id,
        "engine": "content",
        "status": status,
        "findings": findings,
        "analyzer": analyzer,
        "mime_type": ctx.mime_type,
        "file_category": ctx.file_category,
        "details": details,
    }
    return emit(ctx, "content.json", report)
