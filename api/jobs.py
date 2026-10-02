"""api/jobs.py — Background analysis job runner.

    upload -> validate -> create job (queued) -> worker runs the pipeline
           -> results persisted -> client polls GET /api/v1/scans/{id}

A bounded thread pool keeps the API responsive while APKs are analysed and
limits how many analyses run at once; when too many jobs are waiting, new
uploads are refused with HTTP 503 instead of overloading the server. Jobs left
"queued"/"running" by a server restart are marked failed at startup, so no job
stays pending forever. In tests (job_execution="inline") jobs run synchronously.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from sqlalchemy import update

from core.config import Settings
from core.orchestrator import run_job
from db.database import SessionLocal, get_engine
from db.models import Job

log = logging.getLogger("merkletrust.jobs")


class QueueFull(RuntimeError):
    pass


class JobRunner:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._executor: ThreadPoolExecutor | None = None
        self._pending = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        if self.settings.job_execution == "thread" and self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=self.settings.job_workers,
                                                thread_name_prefix="analysis")

    def shutdown(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=True, cancel_futures=True)
            self._executor = None

    @staticmethod
    def recover_interrupted() -> int:
        """Mark jobs that were in flight when the server stopped as failed."""
        get_engine()
        with SessionLocal() as db:
            result = db.execute(update(Job).where(Job.status.in_(("queued", "running"))).values(
                status="failed", error_message="Interrupted by a server restart; please resubmit.",
                completed_at=datetime.now(timezone.utc)))
            db.commit()
            if result.rowcount:
                log.warning("marked %d interrupted job(s) as failed", result.rowcount)
            return result.rowcount

    def submit(self, job_id: str, apk_path: str) -> None:
        if self.settings.job_execution == "inline":
            self._run(job_id, apk_path)
            return
        with self._lock:
            if self._pending >= self.settings.max_queued_jobs:
                raise QueueFull()
            self._pending += 1
        self.start()
        self._executor.submit(self._run_and_release, job_id, apk_path)

    def _run_and_release(self, job_id: str, apk_path: str) -> None:
        try:
            self._run(job_id, apk_path)
        finally:
            with self._lock:
                self._pending -= 1

    def _run(self, job_id: str, apk_path: str) -> None:
        get_engine()
        db = SessionLocal()
        try:
            run_job(apk_path, job_id=job_id, root=str(self.settings.jobs_dir), db_session=db)
        except Exception:
            log.exception("job %s aborted", job_id)
            db.rollback()
            job = db.get(Job, job_id)
            if job is not None and job.status not in ("done", "failed"):
                job.status, job.error_message = "failed", "Internal error while analysing the file."
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()
