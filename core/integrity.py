"""core/integrity.py — AJAY.

Cryptographic Integrity Engine for MerkleTrust.
- Reads APK in fixed-size blocks (chunk_size, default 64KB) and computes SHA-256 for each.
- Builds Merkle tree using core.merkle over chunk hashes to produce merkle_root and tree_depth.
- Reads APK as ZIP central directory to extract byte offset, length, and sha256 of each entry into file_map.
- Emits integrity.json and returns the report dict.
"""

import sys
import os
import json
import hashlib
import tempfile
from typing import Any

from core.contracts import JobContext, emit, EngineError
from core.apk_archive import ApkArchive, ApkValidationError
from core.merkle import build_tree, root


def compute_chunks(data: bytes, chunk_size: int = 65536) -> list[dict[str, Any]]:
    """Slice binary data into chunks of chunk_size and compute SHA-256 hashes."""
    chunks = []
    total_len = len(data)
    if total_len == 0:
        empty_hash = hashlib.sha256(b"").hexdigest()
        return [{"index": 0, "offset": 0, "length": 0, "hash": empty_hash}]

    offset = 0
    idx = 0
    while offset < total_len:
        end = min(offset + chunk_size, total_len)
        chunk_data = data[offset:end]
        h = hashlib.sha256(chunk_data).hexdigest()
        chunks.append({
            "index": idx,
            "offset": offset,
            "length": len(chunk_data),
            "hash": h,
        })
        offset = end
        idx += 1
    return chunks


def extract_file_map(apk_path: str) -> list[dict[str, Any]]:
    """Record each ZIP entry's byte span (local header + data) and SHA-256 of its content.

    Uses the hardened archive reader, so oversized, malformed or zip-bomb archives
    yield an empty map instead of exhausting memory.
    """
    file_map = []
    try:
        with ApkArchive(apk_path, require_manifest=False) as apk, open(apk_path, "rb") as fh:
            for entry in apk.files():
                fh.seek(entry.header_offset)
                hdr = fh.read(30)
                if len(hdr) == 30 and hdr.startswith(b"PK"):
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


def run(job_id: str, ctx: JobContext) -> dict:
    chunk_size = ctx.config.get("chunk_size", 65536)
    findings = []

    if not os.path.isfile(ctx.apk_path):
        raise EngineError(f"APK file not found: {ctx.apk_path}")

    with open(ctx.apk_path, "rb") as fh:
        data = fh.read()
    file_sha = hashlib.sha256(data).hexdigest()

    # 1. Chunking
    chunks = compute_chunks(data, chunk_size=chunk_size)
    chunk_hashes = [c["hash"] for c in chunks]

    # 2. Merkle Tree
    tree_layers = build_tree(chunk_hashes)
    merkle_root = root(tree_layers)
    tree_depth = len(tree_layers)

    # 3. File Map
    file_map = extract_file_map(ctx.apk_path)
    if not file_map:
        findings.append({
            "id": "INTEGRITY_ZIP_WARNING",
            "severity": "medium",
            "title": "Could not parse APK ZIP central directory",
            "evidence": "File may not be a standard ZIP/APK or has corrupted headers.",
        })
    else:
        findings.append({
            "id": "INTEGRITY_VERIFIED",
            "severity": "info",
            "title": "APK chunking and Merkle root computed successfully",
            "evidence": f"Total {len(chunks)} chunks, root: {merkle_root[:16]}..., mapped {len(file_map)} files",
        })

    report = {
        "job_id": job_id,
        "engine": "integrity",
        "status": "ok",
        "findings": findings,
        "sha256": file_sha,
        "file_size": len(data),
        "chunk_size": chunk_size,
        "chunk_count": len(chunks),
        "chunks": chunks,
        "merkle_root": merkle_root,
        "tree_depth": tree_depth,
        "file_map": file_map,
    }
    return emit(ctx, "integrity.json", report)


if __name__ == "__main__":
    apk = sys.argv[1]
    prior = json.load(open(sys.argv[2], encoding="utf-8")) if len(sys.argv) > 2 else {}
    ctx = JobContext(apk_path=apk, workspace=tempfile.mkdtemp(prefix="mt_"),
                     prior=prior, config={"chunk_size": 65536})
    print(json.dumps(run("local-test", ctx), indent=2))
    print("\nwrote:", ctx.out("integrity.json"))
