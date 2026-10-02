"""Scans: upload an APK for analysis, follow its progress, read and verify results."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.deps import CurrentUser, current_user, get_db, rate_limited, settings_dep
from api.errors import ApiError
from api.jobs import QueueFull
from api.uploads import quarantine, receive_apk
from core import audit
from core.baselines import BaselineService
from core.config import Settings
from core.file_manifest import file_proof, verify_file_proof
from core.repository import verify_job_report
from core.orchestrator import STAGES
from db.models import ApkFile, EngineStatus, Job, TrustScore

router = APIRouter(prefix="/scans", tags=["scans"])


def _job_or_404(db: Session, scan_id: str) -> Job:
    try:
        uuid.UUID(scan_id)
    except ValueError:
        raise ApiError(404, "Scan not found.") from None
    job = db.get(Job, scan_id)
    if job is None:
        raise ApiError(404, "Scan not found.")
    return job


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def summarize(job: Job) -> dict[str, Any]:
    ts: TrustScore | None = job.trust_score
    return {
        "id": job.id,
        "status": job.status,
        "filename": job.filename,
        "submitted_by": job.submitted_by,
        "package_name": job.package_name,
        "apk_sha256": job.apk_sha256,
        "created_at": _iso(job.created_at),
        "completed_at": _iso(job.completed_at),
        "error": job.error_message,
        "engines": {e.engine_name: {"status": e.status, "duration_ms": e.duration_ms} for e in job.engine_statuses},
        "result": None if ts is None else {
            "verdict": ts.verdict, "integrity_status": ts.integrity_status,
            "risk_level": ts.risk_level, "risk_score": ts.score,
        },
    }


def _load_reports(job: Job, settings: Settings) -> dict[str, Any]:
    if job.status not in ("done", "failed"):
        raise ApiError(409, "The analysis has not finished yet.", code="not_ready")
    path = Path(settings.jobs_dir) / job.id / "merged.json"
    if not path.is_file():
        raise ApiError(404, "No report is available for this scan.")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


@router.post("", status_code=202)
def create_scan(request: Request, file: UploadFile = File(...), user: CurrentUser = Depends(current_user),
                db: Session = Depends(get_db), settings: Settings = Depends(settings_dep),
                _rl: None = Depends(rate_limited("upload", lambda s: s.upload_rate_per_minute, by="user"))):
    """Upload an APK. Returns immediately with a scan id; poll GET /scans/{id}."""
    with receive_apk(file, settings.max_upload_mb * 1024 * 1024, Path(settings.data_dir) / "tmp") as received:
        stored = quarantine(received, Path(settings.quarantine_dir))
    if db.get(ApkFile, received.sha256) is None:
        db.add(ApkFile(sha256=received.sha256, filename=received.display_name, file_size=received.size,
                       quarantine_path=str(stored)))
    job_id = str(uuid.uuid4())
    db.add(Job(id=job_id, apk_sha256=received.sha256, status="queued", filename=received.display_name,
               submitted_by=user.username, workspace=str(Path(settings.jobs_dir) / job_id)))
    for name, _ in STAGES:
        db.add(EngineStatus(job_id=job_id, engine_name=name, status="pending"))
    db.commit()
    audit.record_event("APK_UPLOADED", user.username, {"scan_id": job_id, "apk_sha256": received.sha256,
                                                        "size": received.size, "filename": received.display_name},
                       subject=job_id)
    try:
        request.app.state.job_runner.submit(job_id, str(stored))
    except QueueFull:
        job = db.get(Job, job_id)
        job.status, job.error_message = "failed", "Server busy: too many analyses waiting."
        db.commit()
        raise ApiError(503, "The server is busy analysing other apps. Please try again shortly.") from None
    db.expire_all()
    return summarize(db.get(Job, job_id))


@router.get("")
def list_scans(limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0),
               package: str | None = Query(None, max_length=255),
               _user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    stmt = select(Job).order_by(Job.created_at.desc())
    count = select(func.count()).select_from(Job)
    if package:
        stmt, count = stmt.where(Job.package_name == package), count.where(Job.package_name == package)
    jobs = db.scalars(stmt.offset(offset).limit(limit)).all()
    return {"total": db.scalar(count), "limit": limit, "offset": offset, "items": [summarize(j) for j in jobs]}


@router.get("/{scan_id}")
def get_scan(scan_id: str, _user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    return summarize(_job_or_404(db, scan_id))


@router.get("/{scan_id}/report")
def get_report(scan_id: str, _user: CurrentUser = Depends(current_user), db: Session = Depends(get_db),
               settings: Settings = Depends(settings_dep)):
    job = _job_or_404(db, scan_id)
    return {"scan": summarize(job), **_load_reports(job, settings)}


@router.post("/{scan_id}/verify")
def verify_scan(scan_id: str, user: CurrentUser = Depends(current_user), db: Session = Depends(get_db),
                settings: Settings = Depends(settings_dep)):
    """Prove the stored report is exactly the one sealed in the audit chain (records the check)."""
    job = _job_or_404(db, scan_id)
    reports = _load_reports(job, settings).get("reports", {})
    result = verify_job_report(db, job.id, reports)
    db.rollback()
    audit.record_event("REPORT_VERIFIED", user.username, {"scan_id": job.id, "valid": result["valid"],
                                                           "checks": result["checks"]}, subject=job.id)
    return {"scan_id": job.id, **result}


@router.get("/{scan_id}/files/proof")
def file_proof_against_baseline(scan_id: str, path: str = Query(..., min_length=1, max_length=512),
                                _user: CurrentUser = Depends(current_user), db: Session = Depends(get_db),
                                settings: Settings = Depends(settings_dep)):
    """Merkle proof for one file: is this scan's version of the file committed in the baseline root?"""
    job = _job_or_404(db, scan_id)
    reports = _load_reports(job, settings).get("reports", {})
    baseline_id = (reports.get("tamper") or {}).get("baseline_id")
    if not baseline_id:
        raise ApiError(409, "This scan was not compared with a trusted baseline.", code="no_baseline")
    baseline = BaselineService(db).get(baseline_id)
    baseline_files = json.loads(baseline.files_json)
    current = next((f for f in (reports.get("integrity") or {}).get("files", []) if f["path"] == path), None)
    in_baseline = any(f["path"] == path for f in baseline_files)
    if current is None and not in_baseline:
        raise ApiError(404, "No such file in this app or its baseline.")
    proof = file_proof(baseline_files, path) if in_baseline else None
    current_valid = bool(current and proof and
                         verify_file_proof(path, current["sha256"], proof["proof"], baseline.merkle_root))
    return {
        "path": path,
        "baseline_id": baseline.id,
        "trusted_root": baseline.merkle_root,
        "baseline_sha256": proof["sha256"] if proof else None,
        "current_sha256": current["sha256"] if current else None,
        "proof": proof["proof"] if proof else [],
        "leaf_index": proof["leaf_index"] if proof else None,
        "current_file_verified": current_valid,
        "explanation": ("This file is exactly as in the trusted version." if current_valid else
                        "This file was added after the trusted version." if not in_baseline else
                        "This file was removed from the app." if current is None else
                        "This file differs from the trusted version: its fingerprint does not lead to the "
                        "trusted root."),
    }
