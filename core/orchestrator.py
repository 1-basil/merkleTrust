"""core/orchestrator.py — BASIL.

Runs the analysis pipeline for one APK:

  1. integrity   per-file SHA-256 manifest + Merkle root (and chunk forensics)
  2. static      manifest, signature/certificate, DEX analysis
  3. tamper      comparison with the approved trusted baseline
  4. dynamic     optional emulator run (degrades gracefully without one)
  5. score       integrity status, risk score, verdict
  6. repository  seal the reports into the audit chain

An engine failure is recorded and the pipeline continues; the scoring stage
turns missing core results into ANALYSIS_FAILED rather than a false "safe".

When a Job row exists (jobs created through the API), its status and each
engine's status/duration are persisted. Database errors while tracking are
logged and rolled back; they never abort the analysis.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from core import dynamic, integrity, repository, scoring, static, tamper
from core.config import get_settings
from core.contracts import EngineError, JobContext
from db.database import init_db

log = logging.getLogger("merkletrust.pipeline")

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


class _Tracker:
    """Persists job/engine progress when the job exists in the database."""

    def __init__(self, db, job_id: str):
        from db.models import Job
        self.db, self.job_id = db, job_id
        self.job = db.get(Job, job_id) if db is not None else None

    @property
    def active(self) -> bool:
        return self.job is not None

    def _commit(self, what: str) -> None:
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            log.exception("could not persist %s for job %s", what, self.job_id)

    def job_started(self) -> None:
        if self.active:
            self.job.status, self.job.started_at = "running", datetime.now(timezone.utc)
            self._commit("job start")

    def engine(self, name: str, status: str, duration_ms: int = 0, error: str | None = None) -> None:
        if not self.active:
            return
        from db.models import EngineStatus
        es = self.db.query(EngineStatus).filter_by(job_id=self.job_id, engine_name=name).first()
        if es is None:
            es = EngineStatus(job_id=self.job_id, engine_name=name)
            self.db.add(es)
        es.status, es.duration_ms, es.error_message = status, duration_ms, error
        self._commit(f"engine {name}")

    def score(self, report: dict[str, Any]) -> None:
        if not self.active:
            return
        from db.models import TrustScore
        ts = self.db.query(TrustScore).filter_by(job_id=self.job_id).first()
        if ts is None:
            ts = TrustScore(job_id=self.job_id)
            self.db.add(ts)
        ts.score = report["risk"]["score"]
        ts.risk_level = report["risk"]["level"]
        ts.integrity_status = report["integrity"]["status"]
        ts.verdict = report["verdict"]["code"]
        ts.rules_fired_json = json.dumps(report["risk"]["contributions"])
        ts.inputs_json = json.dumps(report.get("inputs", {}))
        self._commit("score")

    def package(self, name: str | None) -> None:
        if self.active and name:
            self.job.package_name = name
            self._commit("package name")

    def job_finished(self, ok: bool, error: str | None) -> None:
        if self.active:
            self.job.status = "done" if ok else "failed"
            self.job.error_message = error
            self.job.completed_at = datetime.now(timezone.utc)
            self._commit("job completion")


def run_job(apk_path: str, job_id: str | None = None, root: str | None = None, db_session: Any = None) -> dict:
    """Execute the complete analysis pipeline on an APK and return all engine reports."""
    job_id = job_id or str(uuid.uuid4())
    init_db()
    workspace = os.path.join(root or str(get_settings().jobs_dir), job_id)
    os.makedirs(workspace, exist_ok=True)
    with open(apk_path, "rb") as fh:
        apk_sha256 = hashlib.sha256(fh.read()).hexdigest()
    log.info("job %s started (sha256 %s)", job_id, apk_sha256)

    tracker = _Tracker(db_session, job_id)
    tracker.job_started()
    prior: dict[str, dict] = {}
    status: dict[str, str] = {}
    errors: dict[str, str] = {}

    for name, fn in STAGES:
        tracker.engine(name, "running")
        start = time.perf_counter()
        ctx = JobContext(apk_path=apk_path, workspace=workspace, prior=dict(prior), db=db_session, config=CONFIG)
        try:
            report = fn(job_id, ctx)
            prior[name] = report
            status[name] = report.get("status", "ok")
        except EngineError as exc:
            status[name], errors[name] = "failed", str(exc)
            log.warning("job %s: engine %s failed: %s", job_id, name, exc)
        except Exception as exc:  # an engine bug must not take the whole pipeline down
            status[name], errors[name] = "failed", f"internal error ({type(exc).__name__})"
            log.exception("job %s: engine %s crashed", job_id, name)
        duration_ms = int((time.perf_counter() - start) * 1000)
        tracker.engine(name, status[name], duration_ms, errors.get(name))
        if name == "static" and name in prior:
            tracker.package(prior[name].get("package_name"))
        if name == "score" and name in prior:
            tracker.score(prior[name])
        log.info("job %s: %s %s (%d ms)", job_id, name, status[name], duration_ms)

    with open(os.path.join(workspace, "merged.json"), "w", encoding="utf-8") as fh:
        json.dump({"job_id": job_id, "sha256": apk_sha256, "status": status, "errors": errors, "reports": prior},
                  fh, indent=2, sort_keys=True)

    score = prior.get("score") or {}
    complete = bool(score.get("analysis_complete"))
    error_text = "; ".join(f"{k}: {v}" for k, v in errors.items()) or None
    tracker.job_finished(complete, error_text if not complete else None)
    if score:
        log.info("job %s finished: verdict %s, integrity %s, risk %s (%s)", job_id, score["verdict"]["code"],
                 score["integrity"]["status"], score["risk"]["level"], score["risk"]["score"])
    return prior


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    reports = run_job(sys.argv[1])
    print(json.dumps(reports.get("score", {}).get("verdict", {}), indent=2))
