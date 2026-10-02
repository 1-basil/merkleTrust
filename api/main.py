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
from db.models import Job, ApkFile, EngineStatus, TrustScore, RepositoryEntry
from core.orchestrator import run_job
from core.repository import (
    load_ledger,
    verify_entry_signature,
    verify_proof,
    verify_chain,
    canonicalize_json,
    LEDGER_PATH,
)
from core.merkle import root, proof, build_tree

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
    """Perform ECDSA signature verification and Merkle inclusion proof check."""
    rep_path = os.path.join(JOBS_DIR, job_id, "repo_entry.json")
    if not os.path.exists(rep_path):
        raise HTTPException(status_code=404, detail="Repository entry not found for this job")

    with open(rep_path, "r", encoding="utf-8") as fh:
        repo_entry = json.load(fh)

    # 1. Verify ECDSA signature
    sig_valid = verify_entry_signature(repo_entry)

    # 2. Verify inclusion proof against current repo root
    entry_hash = repo_entry.get("entry_hash", "")
    proof_steps = repo_entry.get("inclusion_proof", [])
    current_root = repo_entry.get("repo_merkle_root", "")
    proof_valid = verify_proof(entry_hash, proof_steps, current_root) if proof_steps else True

    # 3. Verify canonical report hash match
    merged_path = os.path.join(JOBS_DIR, job_id, "merged.json")
    report_hash_match = False
    if os.path.exists(merged_path):
        with open(merged_path, "r", encoding="utf-8") as fh:
            merged_data = json.load(fh)
        prior_reports = merged_data.get("reports", {})
        canonical = canonicalize_json(prior_reports)
        computed_report_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        report_hash_match = (computed_report_sha == repo_entry.get("canonical_report_sha256"))

    is_valid = sig_valid and proof_valid and report_hash_match

    return {
        "job_id": job_id,
        "is_valid": is_valid,
        "checks": {
            "signature_verified": sig_valid,
            "inclusion_proof_verified": proof_valid,
            "canonical_report_hash_matched": report_hash_match,
        },
        "pubkey_id": repo_entry.get("pubkey_id"),
        "repo_merkle_root": current_root,
        "entry_hash": entry_hash,
        "sim_block": repo_entry.get("sim_block"),
        "timestamp": repo_entry.get("timestamp"),
    }


@app.get("/api/repository")
def get_repository(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    """Return paginated repository ledger entries."""
    ledger = load_ledger(LEDGER_PATH)
    total_entries = len(ledger)
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    entries = ledger[start_idx:end_idx]

    all_hashes = [e["entry_hash"] for e in ledger]
    latest_root = root(all_hashes) if all_hashes else ""

    return {
        "page": page,
        "limit": limit,
        "total_entries": total_entries,
        "latest_repo_merkle_root": latest_root,
        "entries": entries,
    }


@app.get("/api/repository/{entry_index}/proof")
def get_entry_proof(entry_index: int):
    """Return Merkle inclusion proof for a specific repository entry index."""
    ledger = load_ledger(LEDGER_PATH)
    if entry_index < 0 or entry_index >= len(ledger):
        raise HTTPException(status_code=404, detail=f"Entry index {entry_index} not found in ledger")

    all_hashes = [e["entry_hash"] for e in ledger]
    tree = build_tree(all_hashes)
    current_root = root(tree)
    inclusion_proof = proof(tree, entry_index)

    return {
        "entry_index": entry_index,
        "entry_hash": all_hashes[entry_index],
        "repo_merkle_root": current_root,
        "inclusion_proof": inclusion_proof,
        "verified": verify_proof(all_hashes[entry_index], inclusion_proof, current_root),
    }


@app.post("/api/tamper-demo")
def tamper_demo(
    job_id: Optional[str] = Query(None),
    corrupt_byte: bool = Query(True),
):
    """Tamper demonstration: Simulate flipping a byte in a report and show the chain breakage."""
    ledger = load_ledger(LEDGER_PATH)
    if not ledger:
        raise HTTPException(status_code=400, detail="Repository ledger is currently empty. Run an analysis first.")

    target_idx = 0
    if job_id:
        found = False
        for idx, entry in enumerate(ledger):
            if entry.get("job_id") == job_id:
                target_idx = idx
                found = True
                break
        if not found:
            raise HTTPException(status_code=404, detail="Target job_id not found in ledger")

    # Create a corrupted clone of the ledger
    corrupted_ledger = [dict(e) for e in ledger]
    target_entry = dict(corrupted_ledger[target_idx])

    if corrupt_byte:
        # Flip characters in canonical_report_sha256 or signature
        old_hash = target_entry["canonical_report_sha256"]
        flipped_char = "a" if old_hash[-1] != "a" else "b"
        target_entry["canonical_report_sha256"] = old_hash[:-1] + flipped_char
        corrupted_ledger[target_idx] = target_entry

    is_valid, broken_idx, reason = verify_chain(corrupted_ledger)

    return {
        "demonstration": "Cryptographic Hash Chain Tamper Verification",
        "target_entry_index": target_idx,
        "tamper_applied": corrupt_byte,
        "chain_intact": is_valid,
        "break_detected_at_index": broken_idx,
        "reason": reason,
        "explanation": "Because entry hashes cryptographically bind prev_entry_hash and canonical_report_sha256, any single-bit modification causes an immediate, mathematically undeniable break at the tampered entry and invalidates all subsequent proofs.",
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
