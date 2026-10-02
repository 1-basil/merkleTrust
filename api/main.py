"""api/main.py — BASIL.

MerkleTrust Central REST API and Job Dispatcher.
Implements the frozen API surface:
  POST /api/upload              -> Upload APK, quarantine, trigger pipeline
  GET  /api/jobs/{id}           -> Per-engine status
  GET  /api/jobs/{id}/report    -> Merged report (all 6 JSONs)
  GET  /api/jobs/{id}/verify    -> Signature check + inclusion proof result
  GET  /api/repository          -> Ledger entries (paginated)
  GET  /api/repository/{idx}/proof -> Inclusion proof for one entry
  POST /api/tamper-demo         -> Tamper demonstration endpoint
  GET  /                        -> Web dashboard UI
"""

import os
import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, UploadFile, File, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from core.config import get_settings
from db.database import get_db, init_db, SessionLocal
from db.models import Job, ApkFile, EngineStatus, TrustScore
from core.orchestrator import run_job
from core import audit
from core.repository import verify_job_report
from core.merkle import verify_proof

# Ensure required directories exist
_DATA_DIR = os.path.abspath(get_settings().data_dir)
QUARANTINE_DIR = os.path.join(_DATA_DIR, "quarantine")
JOBS_DIR = os.path.join(_DATA_DIR, "jobs")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(REPO_ROOT, "frontend")
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(JOBS_DIR, exist_ok=True)
os.makedirs(FRONTEND_DIR, exist_ok=True)

# Initialize database tables on startup
init_db()

app = FastAPI(
    title="MerkleTrust API",
    description="Cryptographic APK Integrity Verification & Tamper Detection Engine",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _background_run_job(apk_path: str, job_id: str):
    """Run orchestrator in background with its own DB session."""
    db = SessionLocal()
    try:
        run_job(apk_path=apk_path, job_id=job_id, root=JOBS_DIR, db_session=db)
    except Exception as e:
        print(f"[Background Job Error for {job_id}]: {e}")
    finally:
        db.close()


@app.post("/api/upload")
async def upload_apk(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Accept APK upload, validate, quarantine by SHA-256, create Job, and queue pipeline."""
    if not file.filename.endswith(".apk") and not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .apk and .zip files are supported.")

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    sha256 = hashlib.sha256(content).hexdigest()
    quarantine_path = os.path.join(QUARANTINE_DIR, f"{sha256}.apk")

    # Save to quarantine
    with open(quarantine_path, "wb") as fh:
        fh.write(content)

    # Register ApkFile if new
    apk_record = db.query(ApkFile).filter_by(sha256=sha256).first()
    if not apk_record:
        apk_record = ApkFile(
            sha256=sha256,
            filename=file.filename,
            file_size=len(content),
            quarantine_path=quarantine_path,
        )
        db.add(apk_record)
        db.commit()

    # Create Job record
    job_id = str(uuid.uuid4())
    job = Job(
        id=job_id,
        apk_sha256=sha256,
        status="pending",
        workspace=os.path.join(JOBS_DIR, job_id),
    )
    db.add(job)

    # Pre-populate engine statuses
    for engine_name in ("integrity", "static", "tamper", "dynamic", "score", "repository"):
        db.add(EngineStatus(job_id=job_id, engine_name=engine_name, status="pending"))
    db.commit()

    # Queue execution
    background_tasks.add_task(_background_run_job, quarantine_path, job_id)

    return {
        "job_id": job_id,
        "sha256": sha256,
        "filename": file.filename,
        "file_size": len(content),
        "status": "pending",
        "message": "APK successfully quarantined. Analysis pipeline queued.",
    }


@app.post("/api/upload-sample")
async def upload_sample_endpoint(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Trigger analysis directly using the repository's test_sample.apk."""
    sample_path = os.path.join(REPO_ROOT, "test_sample.apk")
    if not os.path.exists(sample_path):
        raise HTTPException(status_code=404, detail="test_sample.apk not found in repository root")

    with open(sample_path, "rb") as fh:
        content = fh.read()

    sha256 = hashlib.sha256(content).hexdigest()
    quarantine_path = os.path.join(QUARANTINE_DIR, f"{sha256}.apk")

    with open(quarantine_path, "wb") as fh:
        fh.write(content)

    apk_record = db.query(ApkFile).filter_by(sha256=sha256).first()
    if not apk_record:
        apk_record = ApkFile(
            sha256=sha256,
            filename="test_sample.apk",
            file_size=len(content),
            quarantine_path=quarantine_path,
        )
        db.add(apk_record)
        db.commit()

    job_id = str(uuid.uuid4())
    job = Job(
        id=job_id,
        apk_sha256=sha256,
        status="pending",
        workspace=os.path.join(JOBS_DIR, job_id),
    )
    db.add(job)

    for engine_name in ("integrity", "static", "tamper", "dynamic", "score", "repository"):
        db.add(EngineStatus(job_id=job_id, engine_name=engine_name, status="pending"))
    db.commit()

    background_tasks.add_task(_background_run_job, quarantine_path, job_id)

    return {
        "job_id": job_id,
        "sha256": sha256,
        "filename": "test_sample.apk",
        "file_size": len(content),
        "status": "pending",
        "message": "Sample APK successfully quarantined. Analysis pipeline queued.",
    }


@app.get("/api/jobs/{job_id}")
def get_job_status(job_id: str, db: Session = Depends(get_db)):
    """Return per-engine status: pending/running/ok/partial/failed."""
    job = db.query(Job).filter_by(id=job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    statuses = {es.engine_name: es.status for es in job.engine_statuses}
    durations = {es.engine_name: es.duration_ms for es in job.engine_statuses}

    score_data = None
    if job.trust_score:
        score_data = {
            "risk_score": job.trust_score.score,
            "risk_level": job.trust_score.risk_level,
            "integrity_status": job.trust_score.integrity_status,
            "verdict": job.trust_score.verdict,
            "risk_contributions": json.loads(job.trust_score.rules_fired_json or "[]"),
        }

    return {
        "job_id": job.id,
        "apk_sha256": job.apk_sha256,
        "status": job.status,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "engine_status": statuses,
        "durations_ms": durations,
        "trust_score": score_data,
    }


@app.get("/api/jobs/{job_id}/report")
def get_job_report(job_id: str, db: Session = Depends(get_db)):
    """Return merged report containing all six JSONs."""
    merged_path = os.path.join(JOBS_DIR, job_id, "merged.json")
    if os.path.exists(merged_path):
        with open(merged_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    job = db.query(Job).filter_by(id=job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # If merged.json is not yet written, return current progress
    return {
        "job_id": job.id,
        "status": job.status,
        "reports": {},
        "message": f"Job is currently {job.status}. Merged report will be available upon completion.",
    }


@app.get("/api/jobs/{job_id}/verify")
def verify_job_integrity(job_id: str, db: Session = Depends(get_db)):
    """Prove the stored report is exactly what was sealed in the (intact) audit chain."""
    merged_path = os.path.join(JOBS_DIR, job_id, "merged.json")
    if not os.path.exists(merged_path):
        raise HTTPException(status_code=404, detail="No completed report for this job")
    with open(merged_path, "r", encoding="utf-8") as fh:
        reports = json.load(fh).get("reports", {})
    return {"job_id": job_id, **verify_job_report(db, job_id, reports)}


@app.get("/api/repository")
def get_repository(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Audit chain blocks (Cryptographically Linked Blockchain Simulation), newest first."""
    blocks = audit.all_blocks(db)
    verification = audit.verify_chain(blocks)
    by_index = {r["index"]: r for r in verification["blocks"]}
    newest_first = list(reversed(blocks))[(page - 1) * limit: page * limit]
    return {
        "page": page,
        "limit": limit,
        "total_blocks": len(blocks),
        "chain": {k: verification[k] for k in ("valid", "length", "first_invalid_index", "head",
                                                "merkle_root", "summary")},
        "blocks": [audit.block_to_dict(b, by_index[b.block_index]) for b in newest_first],
    }


@app.get("/api/repository/{block_index}/proof")
def get_block_proof(block_index: int, db: Session = Depends(get_db)):
    """Merkle inclusion proof that a block belongs to the current chain."""
    try:
        p = audit.block_inclusion_proof(db, block_index)
    except IndexError:
        raise HTTPException(status_code=404, detail=f"Block {block_index} not found") from None
    return {**p, "verified": verify_proof(p["block_hash"], p["proof"], p["merkle_root"])}


@app.post("/api/tamper-demo")
def tamper_demo(block_index: Optional[int] = Query(None), db: Session = Depends(get_db)):
    """Non-destructive demonstration: alter a *copy* of one block and verify the copied chain."""
    blocks = audit.all_blocks(db)
    if not blocks:
        raise HTTPException(status_code=400, detail="The audit chain is empty. Run an analysis first.")
    target = len(blocks) // 2 if block_index is None else block_index
    if not 0 <= target < len(blocks):
        raise HTTPException(status_code=404, detail=f"Block {target} not found")
    copies = audit.detached_copies(blocks)
    payload = json.loads(copies[target].payload_json)
    payload["tampered"] = True
    copies[target].payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    result = audit.verify_chain(copies)
    return {
        "demonstration": "Blockchain Simulation tamper check (performed on a copy; stored chain unchanged)",
        "target_block_index": target,
        "chain_intact": result["valid"],
        "break_detected_at_index": result["first_invalid_index"],
        "summary": result["summary"],
    }


# Serve Frontend Web App
@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as fh:
            return fh.read()
    return "<h1>MerkleTrust API is running. Build frontend/index.html to view dashboard.</h1>"


if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
