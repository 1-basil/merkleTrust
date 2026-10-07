"""core/integrity.py — AJAY.

Cryptographic Integrity Engine for MerkleTrust.

Authoritative mechanism — per-file SHA-256:
  every file inside the APK is hashed; the sorted (path, sha256) manifest is
  committed to a Merkle root (core.file_manifest). Comparing manifests tells
  exactly which files were modified, added or deleted.

Supplementary forensics — fixed-size chunks:
  the raw APK bytes are split into 64 KB chunks, each hashed, and committed to a
  second Merkle tree. Chunk diffs show *where in the file* bytes changed, but one
  inserted byte shifts every later chunk, so they are never used as the verdict.

Also records each ZIP entry's byte span (file_map) for chunk-to-file localisation.

Non-APK content (images, audio/video, web pages, PDFs — ctx.file_category other
than "apk") has no inner files: the chunk tree over the raw bytes is its
commitment, and the manifest holds the single file.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from typing import Any

from core.apk_archive import ApkArchive, ApkValidationError
from core.contracts import EngineError, JobContext, emit
from core.file_manifest import build_file_manifest, manifest_root
from core.merkle import build_tree, root

DEFAULT_CHUNK_SIZE = 65536


def compute_chunks(data: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> list[dict[str, Any]]:
    """Slice binary data into chunk_size blocks and SHA-256 each one."""
    if not data:
        return [{"index": 0, "offset": 0, "length": 0, "hash": hashlib.sha256(b"").hexdigest()}]
    return [{"index": i, "offset": off, "length": len(data[off:off + chunk_size]),
             "hash": hashlib.sha256(data[off:off + chunk_size]).hexdigest()}
            for i, off in enumerate(range(0, len(data), chunk_size))]


def extract_file_map(apk_path: str) -> list[dict[str, Any]]:
    """Each ZIP entry's byte span (local header + data) and the SHA-256 of its content.

    Uses the hardened archive reader, so oversized, malformed or zip-bomb archives
    yield an empty map instead of exhausting memory.
    """
    file_map = []
    try:
        with ApkArchive(apk_path, require_manifest=False) as apk, open(apk_path, "rb") as fh:
            for entry in apk.files():
                fh.seek(entry.header_offset)
                hdr = fh.read(30)
                if len(hdr) == 30 and hdr.startswith(b"PK\x03\x04"):
                    fn_len = int.from_bytes(hdr[26:28], "little")
                    extra_len = int.from_bytes(hdr[28:30], "little")
                    span = 30 + fn_len + extra_len + entry.compressed_size
                else:
                    span = entry.compressed_size
                try:
                    digest = hashlib.sha256(apk.read(entry.name)).hexdigest()
                except ApkValidationError:
                    digest = ""
                file_map.append({"path": entry.name, "offset": entry.header_offset,
                                 "length": span, "sha256": digest})
    except (ApkValidationError, OSError):
        return []
    return file_map


def compute_integrity(apk_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE,
                      limits: dict | None = None) -> dict[str, Any]:
    """Pure integrity computation. Raises ApkValidationError for invalid APKs."""
    with ApkArchive(apk_path, limits=limits) as apk:
        files = build_file_manifest(apk)
    with open(apk_path, "rb") as fh:
        data = fh.read()
    chunks = compute_chunks(data, chunk_size)
    chunk_tree = build_tree([c["hash"] for c in chunks])
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "file_size": len(data),
        "file_count": len(files),
        "files": files,
        "merkle_root": manifest_root(files),
        "chunk_size": chunk_size,
        "chunk_count": len(chunks),
        "chunks": chunks,
        "chunk_merkle_root": root(chunk_tree),
        "tree_depth": len(chunk_tree),
        "file_map": extract_file_map(apk_path),
    }


def compute_content_integrity(path: str, chunk_size: int = DEFAULT_CHUNK_SIZE, *,
                              mime_type: str = "application/octet-stream",
                              file_category: str = "other") -> dict[str, Any]:
    """Integrity for a single non-archive file (image, media, web page, document).

    The chunk tree is the primary commitment here: there are no inner files, so
    the "manifest" is one entry binding the file name to its SHA-256, keeping the
    integrity.json schema (and every reader of merkle_root) unchanged.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    sha256 = hashlib.sha256(data).hexdigest()
    files = [{"path": os.path.basename(path) or "content", "sha256": sha256, "size": len(data),
              "category": file_category}]
    chunks = compute_chunks(data, chunk_size)
    chunk_tree = build_tree([c["hash"] for c in chunks])
    return {
        "sha256": sha256,
        "file_size": len(data),
        "file_count": 1,
        "files": files,
        "merkle_root": manifest_root(files),
        "chunk_size": chunk_size,
        "chunk_count": len(chunks),
        "chunks": chunks,
        "chunk_merkle_root": root(chunk_tree),
        "tree_depth": len(chunk_tree),
        "file_map": [{"path": files[0]["path"], "offset": 0, "length": len(data), "sha256": sha256}],
        "mime_type": mime_type,
        "file_category": file_category,
    }


def _run_content(job_id: str, ctx: JobContext, chunk_size: int) -> dict:
    try:
        result = compute_content_integrity(ctx.target_path, chunk_size, mime_type=ctx.mime_type,
                                           file_category=ctx.file_category)
    except OSError as exc:
        raise EngineError(f"Cannot read file: {exc.strerror or exc}") from None
    findings = [{
        "id": "INTEGRITY_COMPUTED",
        "severity": "info",
        "title": "Content fingerprint and Merkle commitment computed",
        "evidence": f"{result['chunk_count']} chunk(s) of {chunk_size} bytes hashed with SHA-256; "
                    f"chunk root {result['chunk_merkle_root'][:16]}...",
    }]
    report = {"job_id": job_id, "engine": "integrity", "status": "ok", "findings": findings, **result}
    return emit(ctx, "integrity.json", report)


def run(job_id: str, ctx: JobContext) -> dict:
    chunk_size = int(ctx.config.get("chunk_size", DEFAULT_CHUNK_SIZE))
    if ctx.file_category != "apk":
        return _run_content(job_id, ctx, chunk_size)
    try:
        result = compute_integrity(ctx.apk_path, chunk_size, ctx.config.get("apk_limits"))
    except ApkValidationError as exc:
        raise EngineError(f"Invalid APK: {exc}") from None
    findings = [{
        "id": "INTEGRITY_COMPUTED",
        "severity": "info",
        "title": "File manifest and Merkle commitment computed",
        "evidence": f"{result['file_count']} files hashed with SHA-256; manifest root {result['merkle_root'][:16]}...",
    }]
    report = {"job_id": job_id, "engine": "integrity", "status": "ok", "findings": findings, **result}
    return emit(ctx, "integrity.json", report)


if __name__ == "__main__":
    ctx = JobContext(apk_path=sys.argv[1], workspace=tempfile.mkdtemp(prefix="mt_"), prior={},
                     config={"chunk_size": DEFAULT_CHUNK_SIZE})
    print(json.dumps(run("local-test", ctx), indent=2))
