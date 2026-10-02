"""Dashboard summary and service health."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from api.deps import CurrentUser, current_user, get_db, settings_dep
from api.routers.scans import summarize
from core import audit
from core.config import Settings
from core.crypto import get_keyring
from db.models import Job, TrustScore, TrustedBaseline

router = APIRouter(tags=["dashboard"])

CHANGED = ("MODIFIED", "CERTIFICATE_CHANGED", "BASELINE_INVALID")


@router.get("/dashboard/summary")
def summary(_user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    # Latest finished scan of each app decides how that app is counted.
    latest = (select(Job.package_name, func.max(Job.created_at).label("ts"))
              .where(Job.status == "done", Job.package_name.is_not(None))
              .group_by(Job.package_name).subquery())
    rows = db.execute(select(TrustScore.verdict, TrustScore.integrity_status, TrustScore.risk_level)
                      .join(Job, Job.id == TrustScore.job_id)
                      .join(latest, (Job.package_name == latest.c.package_name) & (Job.created_at == latest.c.ts))
                      ).all()
    apps = {
        "analyzed": len(rows),
        "clean": sum(1 for v, _, _ in rows if v == "CLEAN"),
        "modified": sum(1 for _, i, _ in rows if i in CHANGED),
        "high_risk": sum(1 for _, _, r in rows if r in ("HIGH", "CRITICAL")),
        "not_verified": sum(1 for _, i, _ in rows if i == "NO_BASELINE"),
    }
    scans = dict(db.execute(select(Job.status, func.count()).group_by(Job.status)).all())
    baselines = dict(db.execute(select(TrustedBaseline.status, func.count())
                                .group_by(TrustedBaseline.status)).all())
    blocks = audit.all_blocks(db)
    chain = audit.verify_chain(blocks, get_keyring())
    recent_jobs = db.scalars(select(Job).order_by(Job.created_at.desc()).limit(6)).all()
    return {
        "applications": apps,
        "scans": {"total": sum(scans.values()), **{k: scans.get(k, 0) for k in ("queued", "running", "done",
                                                                                  "failed")}},
        "baselines": {k: baselines.get(k, 0) for k in ("approved", "pending", "rejected", "revoked")},
        "audit_chain": {"length": chain["length"], "valid": chain["valid"], "summary": chain["summary"]},
        "recent_events": [{"index": b.block_index, "timestamp": b.timestamp, "event_type": b.event_type,
                           "event_label": audit.EVENTS.get(b.event_type, b.event_type), "actor": b.actor,
                           "subject": b.subject} for b in reversed(blocks[-10:])],
        "recent_scans": [summarize(j) for j in recent_jobs],
    }


@router.get("/health")
def health(db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)):
    """Liveness/readiness without authentication. Exposes no sensitive detail."""
    db.execute(text("SELECT 1"))
    return {"status": "ok", "demo_enabled": settings.demo_enabled, "max_upload_mb": settings.max_upload_mb}
