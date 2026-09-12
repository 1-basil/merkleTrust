"""core/repository.py — AJAY.

Last stage. Turns the merged report into a signed, chained, provable entry.

TODO for Ajay:
  1. canonicalise the merged report: json.dumps(sort_keys=True, separators=(",",":"))
  2. report_sha = sha256(canonical)
  3. prev = last entry_hash in the repository (genesis = 64 zeros)
     entry_hash = sha256(prev + report_sha + timestamp)
  4. sign entry_hash with an ECDSA P-256 key (`cryptography` lib), store base64
  5. append entry_hash as a leaf to the repository-wide merkle tree
     (reuse core/merkle.py), recompute repo_merkle_root, emit inclusion_proof
  6. simulated chain: every N entries seal a "block" whose header is
     sha256(prev_block_hash + batch_merkle_root). Keep "simulated": true.
  7. write verify_chain() and verify_entry() — the demo is: flip one byte in a
     stored report, re-run verify, show exactly which entry breaks.
"""

import sys
import json
import hashlib
import tempfile
from datetime import datetime, timezone

from core.contracts import JobContext, emit

GENESIS = "0" * 64


def run(job_id: str, ctx: JobContext) -> dict:
    canonical = json.dumps(ctx.prior, sort_keys=True, separators=(",", ":"))
    report_sha = hashlib.sha256(canonical.encode()).hexdigest()

    # TODO(ajay): real chain lookup, ECDSA signing, merkle proof, sim block
    return emit(ctx, "repo_entry.json", {
        "job_id": job_id,
        "engine": "repository",
        "status": "partial",
        "findings": [{
            "id": "REPO_STUB",
            "severity": "info",
            "title": "Repository not implemented yet",
            "evidence": f"report sha256 {report_sha[:16]}...",
        }],
        "entry_index": 0,
        "canonical_report_sha256": report_sha,
        "prev_entry_hash": GENESIS,
        "entry_hash": "",
        "signature": "",
        "pubkey_id": "mt-signer-1",
        "repo_merkle_root": "",
        "inclusion_proof": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sim_block": {"height": 0, "block_hash": "", "tx_id": "", "simulated": True},
    })


if __name__ == "__main__":
    prior = json.load(open(sys.argv[1], encoding="utf-8")) if len(sys.argv) > 1 else {}
    ctx = JobContext(apk_path="", workspace=tempfile.mkdtemp(prefix="mt_"), prior=prior, config={})
    print(json.dumps(run("local-test", ctx), indent=2))
