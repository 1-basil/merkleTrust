"""core/repository.py — AJAY.

Report sealing stage. After scoring, the complete set of engine reports is
canonicalised and hashed (report_sha256) and recorded in the audit chain
(core.audit — Cryptographically Linked Blockchain Simulation) as an
ANALYSIS_COMPLETED block. If integrity failed, an INTEGRITY_ALERT block is
recorded as well.

Later, anyone can prove the stored report is the one that was sealed:
recompute the hash of the stored reports (excluding this stage's own output)
and compare it with the payload of the signed, chain-linked block — see
`verify_job_report`.
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core import audit
from core.contracts import JobContext, emit
from core.crypto import get_keyring, hash_payload
from db.database import session_scope

SEALED_ENGINES = ("integrity", "static", "tamper", "dynamic", "score")
ALERT_STATUSES = {"MODIFIED", "CERTIFICATE_CHANGED", "BASELINE_INVALID"}


def report_hash(reports: dict[str, Any]) -> str:
    """Canonical SHA-256 of the sealed engine reports (the repository stage itself excluded)."""
    return hash_payload({k: v for k, v in reports.items() if k in SEALED_ENGINES})


def seal(db: Session, job_id: str, reports: dict[str, Any], actor: str = "pipeline") -> dict[str, Any]:
    static = reports.get("static") or {}
    integrity = reports.get("integrity") or {}
    score = reports.get("score") or {}
    tamper = reports.get("tamper") or {}
    integrity_status = (score.get("integrity") or {}).get("status", "UNKNOWN")
    payload = {
        "job_id": job_id,
        "apk_sha256": integrity.get("sha256"),
        "package_name": static.get("package_name"),
        "version_name": static.get("version_name"),
        "certificate_sha256": (static.get("certificate") or {}).get("sha256"),
        "files_merkle_root": integrity.get("merkle_root"),
        "baseline_id": tamper.get("baseline_id"),
        "integrity_status": integrity_status,
        "risk_level": (score.get("risk") or {}).get("level"),
        "risk_score": (score.get("risk") or {}).get("score"),
        "verdict": (score.get("verdict") or {}).get("code"),
        "engines": sorted(k for k in reports if k in SEALED_ENGINES),
        "report_sha256": report_hash(reports),
    }
    block = audit.append_event(db, "ANALYSIS_COMPLETED", actor, payload, subject=job_id)
    alert = None
    if integrity_status in ALERT_STATUSES:
        alert = audit.append_event(db, "INTEGRITY_ALERT", actor, {
            "job_id": job_id, "package_name": payload["package_name"], "integrity_status": integrity_status,
            "baseline_id": payload["baseline_id"], "reasons": (score.get("integrity") or {}).get("reasons", []),
            "analysis_block": block.block_index}, subject=job_id)
    return {"block": block, "alert": alert, "payload": payload}


def verify_job_report(db: Session, job_id: str, reports: dict[str, Any]) -> dict[str, Any]:
    """Prove that `reports` is exactly what was sealed for `job_id` in an intact chain."""
    blocks = audit.events_for_subject(db, job_id, ("ANALYSIS_COMPLETED",))
    if not blocks:
        return {"valid": False, "checks": {"sealed": False}, "reasons": ["No sealed record exists for this job."]}
    block = blocks[-1]
    chain = audit.verify_chain(audit.all_blocks(db), get_keyring())
    block_check = next(r for r in chain["blocks"] if r["index"] == block.block_index)
    sealed = json.loads(block.payload_json)
    computed = report_hash(reports)
    checks = {
        "sealed": True,
        "report_hash_matches": computed == sealed.get("report_sha256"),
        "block_valid": block_check["valid"],
        "chain_valid": chain["valid"],
    }
    reasons = []
    if not checks["report_hash_matches"]:
        reasons.append("The stored report was changed after it was sealed (its hash no longer matches).")
    reasons += block_check["reasons"]
    if checks["block_valid"] and not checks["chain_valid"]:
        reasons.append(f"The audit chain is broken elsewhere: {chain['summary']}")
    return {
        "valid": all(checks.values()),
        "checks": checks,
        "reasons": reasons,
        "block_index": block.block_index,
        "block_hash": block.block_hash,
        "key_id": block.key_id,
        "sealed_report_sha256": sealed.get("report_sha256"),
        "computed_report_sha256": computed,
        "proof": audit.block_inclusion_proof(db, block.block_index),
    }


def _seal_with_retry(job_id: str, reports: dict[str, Any], attempts: int = 5) -> dict[str, Any]:
    """Seal in a short, dedicated transaction.

    Concurrent jobs may race for the same block index; the PRIMARY KEY and
    UNIQUE(previous_hash) constraints reject the loser, which then retries on
    top of the new head. The chain therefore never forks.
    """
    for attempt in range(1, attempts + 1):
        try:
            with session_scope() as db:
                sealed = seal(db, job_id, reports)
                block, alert = sealed["block"], sealed["alert"]
                return {
                    "report_sha256": sealed["payload"]["report_sha256"],
                    "block_index": block.block_index,
                    "block_hash": block.block_hash,
                    "previous_hash": block.previous_hash,
                    "payload_hash": block.payload_hash,
                    "key_id": block.key_id,
                    "signature": json.loads(block.signature_json),
                    "timestamp": block.timestamp,
                    "alert_block_index": alert.block_index if alert else None,
                }
        except IntegrityError:
            if attempt == attempts:
                raise
            time.sleep(0.05 * attempt)
    raise AssertionError("unreachable")


def run(job_id: str, ctx: JobContext) -> dict:
    """Seal the job's reports into the audit chain."""
    sealed = _seal_with_retry(job_id, ctx.prior)
    report = {
        "job_id": job_id,
        "engine": "repository",
        "status": "ok",
        "findings": [{
            "id": "REPO_SEALED", "severity": "info",
            "title": "Result recorded in the audit log",
            "evidence": f"Block #{sealed['block_index']}, signed with {sealed['key_id']}",
        }],
        **sealed,
        "simulation_notice": "Cryptographically Linked Blockchain Simulation: a single-node, append-only "
                             "hash chain — not a distributed blockchain.",
    }
    return emit(ctx, "repo_entry.json", report)


if __name__ == "__main__":
    prior = json.load(open(sys.argv[1], encoding="utf-8")) if len(sys.argv) > 1 else {}
    ctx = JobContext(apk_path="", workspace=tempfile.mkdtemp(prefix="mt_"), prior=prior, config={})
    print(json.dumps(run("local-test", ctx), indent=2))
