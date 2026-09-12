"""core/integrity.py — AJAY.

Stub that runs today. Replace the TODO block with real work.

TODO for Ajay:
  1. read the APK in chunk_size blocks, sha256 each -> chunks[]
  2. build a merkle tree over those chunk hashes -> merkle_root, tree_depth
  3. open the APK as a zipfile, read the central directory,
     record each entry's byte offset + length -> file_map[]
     (zipfile.ZipInfo.header_offset is the start; add the local header size)
  4. put the tree helpers in core/merkle.py as pure functions:
       build_tree(leaves) -> nodes
       root(nodes) -> str
       proof(nodes, index) -> [{"sibling","position"}]
       verify_proof(leaf, proof, root) -> bool
       compare_trees(a, b) -> [changed leaf indices]
     Ashwini imports ONLY these. No DB, no state.
"""

import sys
import json
import hashlib
import tempfile

from core.contracts import JobContext, emit


def run(job_id: str, ctx: JobContext) -> dict:
    chunk_size = ctx.config.get("chunk_size", 65536)

    with open(ctx.apk_path, "rb") as fh:
        data = fh.read()
    file_sha = hashlib.sha256(data).hexdigest()

    # TODO(ajay): real chunking + merkle tree + file_map
    report = {
        "job_id": job_id,
        "engine": "integrity",
        "status": "partial",
        "findings": [
            {
                "id": "INTEGRITY_STUB",
                "severity": "info",
                "title": "Integrity engine not implemented yet",
                "evidence": f"sha256 {file_sha[:16]}...",
            }
        ],
        "sha256": file_sha,
        "file_size": len(data),
        "chunk_size": chunk_size,
        "chunk_count": 0,
        "chunks": [],
        "merkle_root": "",
        "tree_depth": 0,
        "file_map": [],
    }
    return emit(ctx, "integrity.json", report)


if __name__ == "__main__":
    apk = sys.argv[1]
    prior = json.load(open(sys.argv[2], encoding="utf-8")) if len(sys.argv) > 2 else {}
    ctx = JobContext(apk_path=apk, workspace=tempfile.mkdtemp(prefix="mt_"),
                     prior=prior, config={"chunk_size": 65536})
    print(json.dumps(run("local-test", ctx), indent=2))
    print("\nwrote:", ctx.out("integrity.json"))
