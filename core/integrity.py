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
import zipfile
import tempfile
from typing import Any

from core.contracts import JobContext, emit, EngineError
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
    """Parse APK ZIP central directory and local headers to record byte spans and hashes."""
    file_map = []
    if not os.path.exists(apk_path):
        return file_map

    try:
        with open(apk_path, "rb") as fh:
            with zipfile.ZipFile(fh, "r") as zf:
                for zinfo in zf.infolist():
                    header_offset = zinfo.header_offset
                    fh.seek(header_offset)
                    hdr = fh.read(30)
                    if len(hdr) == 30 and hdr.startswith(b"PK\x03\x04"):
                        fn_len = int.from_bytes(hdr[26:28], "little")
                        extra_len = int.from_bytes(hdr[28:30], "little")
                        total_entry_len = 30 + fn_len + extra_len + zinfo.compress_size
                    else:
                        total_entry_len = zinfo.compress_size

                    # Calculate sha256 of uncompressed payload
                    try:
                        content = zf.read(zinfo.filename)
                        c_sha = hashlib.sha256(content).hexdigest()
                    except Exception:
                        c_sha = ""

                    file_map.append({
                        "path": zinfo.filename,
                        "offset": header_offset,
                        "length": total_entry_len,
                        "sha256": c_sha,
                    })
    except (zipfile.BadZipFile, OSError):
        pass

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
