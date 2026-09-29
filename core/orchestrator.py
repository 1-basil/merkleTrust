"""core/orchestrator.py — BASIL.

The Master Orchestrator and Integration Pipeline.
Runs the complete 6-stage pipeline:
  1. integrity (Ajay)
  2. static (Ashwini)
  3. tamper (Ashwini)
  4. dynamic (Bhavish)
  5. score (Basil)
  6. repository (Ajay)

Supports standalone CLI execution or automated background processing with database tracking.
"""

import os
import sys
import json
import uuid
import time
import hashlib
import traceback
from datetime import datetime, timezone
from typing import Any

from core.contracts import JobContext, EngineError
from core import integrity, static, tamper, dynamic, scoring, repository

CONFIG = {
    "chunk_size": 65536,
    "apktool": "apktool",
    "jadx": "jadx",
    "emulator_avd": "mt_api30_root",
    "dynamic_timeout_s": 90,
}

STAGES = [
    ("integrity", integrity.run),
    ("static", static.run),
    ("tamper", tamper.run),
    ("dynamic", dynamic.run),
    ("score", scoring.run),
    ("repository", repository.run),
]


def run_job(apk_path: str, job_id: str | None = None, root: str = "jobs", db_session: Any = None) -> dict:
    """Execute complete analysis pipeline on an APK."""
    job_id = job_id or str(uuid.uuid4())
    workspace = os.path.join(root, job_id)
    os.makedirs(workspace, exist_ok=True)

    with open(apk_path, "rb") as fh:
        sha = hashlib.sha256(fh.read()).hexdigest()
    print(f"job {job_id}\nsha256 {sha}\nworkspace {workspace}\n")

    # Update DB job status if DB session is active
    if db_session:
        try:
            from db.models import Job, EngineStatus
            job_record = db_session.query(Job).filter_by(id=job_id).first()
            if job_record:
                job_record.status = "running"
                db_session.commit()
        except Exception as e:
            print(f"[Orchestrator DB warning]: {e}")

    prior: dict = {}
    status: dict = {}

    for name, fn in STAGES:
        start_t = time.time()
        ctx = JobContext(apk_path=apk_path, workspace=workspace, prior=dict(prior), db=db_session, config=CONFIG)

        if db_session:
            try:
                from db.models import EngineStatus
                es = db_session.query(EngineStatus).filter_by(job_id=job_id, engine_name=name).first()
                if not es:
                    es = EngineStatus(job_id=job_id, engine_name=name, status="running")
                    db_session.add(es)
                else:
                    es.status = "running"
                db_session.commit()
            except Exception:
                pass

        try:
            report = fn(job_id, ctx)
            prior[name] = report
            status[name] = report.get("status", "ok")
            duration_ms = int((time.time() - start_t) * 1000)
            print(f"  {name:<11} {status[name]} ({duration_ms}ms)")

            if db_session:
                try:
                    from db.models import EngineStatus, TrustScore, RepositoryEntry
                    es = db_session.query(EngineStatus).filter_by(job_id=job_id, engine_name=name).first()
                    if es:
                        es.status = status[name]
                        es.duration_ms = duration_ms
                        db_session.commit()

                    if name == "score":
                        ts = db_session.query(TrustScore).filter_by(job_id=job_id).first()
                        if not ts:
                            ts = TrustScore(
                                job_id=job_id,
                                score=report.get("score", 0),
                                verdict=report.get("verdict", "unknown"),
                                rules_fired_json=json.dumps(report.get("rules_fired", [])),
                                inputs_json=json.dumps(report.get("inputs", {})),
                            )
                            db_session.add(ts)
                        else:
                            ts.score = report.get("score", 0)
                            ts.verdict = report.get("verdict", "unknown")
                            ts.rules_fired_json = json.dumps(report.get("rules_fired", []))
                            ts.inputs_json = json.dumps(report.get("inputs", {}))
                        db_session.commit()

                    elif name == "repository":
                        re = db_session.query(RepositoryEntry).filter_by(job_id=job_id).first()
                        if not re:
                            re = RepositoryEntry(
                                entry_index=report.get("entry_index", 0),
                                job_id=job_id,
                                canonical_report_sha256=report.get("canonical_report_sha256", ""),
                                prev_entry_hash=report.get("prev_entry_hash", ""),
                                entry_hash=report.get("entry_hash", ""),
                                signature=report.get("signature", ""),
                                pubkey_id=report.get("pubkey_id", "mt-signer-1"),
                                repo_merkle_root=report.get("repo_merkle_root", ""),
                                inclusion_proof_json=json.dumps(report.get("inclusion_proof", [])),
                                timestamp=report.get("timestamp", ""),
                                sim_block_json=json.dumps(report.get("sim_block", {})),
                            )
                            db_session.add(re)
                        db_session.commit()
                except Exception as e:
                    print(f"[Orchestrator DB record error for {name}]: {e}")

        except EngineError as exc:
            status[name] = "failed"
            duration_ms = int((time.time() - start_t) * 1000)
            print(f"  {name:<11} failed: {exc}")
            if db_session:
                try:
                    from db.models import EngineStatus
                    es = db_session.query(EngineStatus).filter_by(job_id=job_id, engine_name=name).first()
                    if es:
                        es.status = "failed"
                        es.duration_ms = duration_ms
                        es.error_message = str(exc)
                        db_session.commit()
                except Exception:
                    pass
        except Exception as exc:
            status[name] = "failed"
            duration_ms = int((time.time() - start_t) * 1000)
            print(f"  {name:<11} crashed")
            traceback.print_exc()
            if db_session:
                try:
                    from db.models import EngineStatus
                    es = db_session.query(EngineStatus).filter_by(job_id=job_id, engine_name=name).first()
                    if es:
                        es.status = "failed"
                        es.duration_ms = duration_ms
                        es.error_message = str(exc)
                        db_session.commit()
                except Exception:
                    pass

    with open(os.path.join(workspace, "merged.json"), "w", encoding="utf-8") as fh:
        json.dump({"job_id": job_id, "sha256": sha, "status": status, "reports": prior},
                  fh, indent=2, sort_keys=True)

    if db_session:
        try:
            from db.models import Job
            job_record = db_session.query(Job).filter_by(id=job_id).first()
            if job_record:
                job_record.status = "failed" if all(s == "failed" for s in status.values()) else "done"
                job_record.completed_at = datetime.now(timezone.utc)
                db_session.commit()
        except Exception as e:
            print(f"[Orchestrator DB completion warning]: {e}")

    score = prior.get("score", {})
    print(f"\nverdict: {score.get('verdict', 'n/a')}  score: {score.get('score', 'n/a')}")
    return prior


if __name__ == "__main__":
    run_job(sys.argv[1])
