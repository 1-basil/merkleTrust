"""Trusted baselines: enrol (admin), approve / reject / revoke (admin), list, inspect, verify."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, File, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.deps import CurrentUser, current_user, get_db, require_admin, settings_dep
from api.errors import ApiError
from api.uploads import receive_apk
from core.baselines import BaselineError, BaselineNotFound, BaselineService, to_dict
from core.config import Settings
from core.file_manifest import file_proof, verify_file_proof

router = APIRouter(prefix="/baselines", tags=["baselines"])


class ApproveRequest(BaseModel):
    note: str | None = Field(default=None, max_length=500)


class ReasonRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


def _commit(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "Another change happened at the same moment. Please retry.") from None


def _get(svc: BaselineService, baseline_id: int):
    try:
        return svc.get(baseline_id)
    except BaselineNotFound:
        raise ApiError(404, "Baseline not found.") from None


def _change(fn, *args):
    try:
        return fn(*args)
    except BaselineNotFound:
        raise ApiError(404, "Baseline not found.") from None
    except BaselineError as exc:
        raise ApiError(409, str(exc), code="invalid_state") from None


@router.get("")
def list_baselines(package: str | None = Query(None, max_length=255),
                   status: str | None = Query(None, pattern="^(pending|approved|rejected|revoked)$"),
                   _user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    svc = BaselineService(db)
    return {"items": [to_dict(b) for b in svc.list(package, status)]}


@router.post("", status_code=201)
def enroll(file: UploadFile = File(...), admin: CurrentUser = Depends(require_admin),
           db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)):
    """Upload the official build of an app. It stays *pending* until an administrator approves it."""
    svc = BaselineService(db)
    with receive_apk(file, settings.max_upload_mb * 1024 * 1024, Path(settings.data_dir) / "tmp") as received:
        try:
            baseline, review = svc.enroll(str(received.path), admin.username)
        except BaselineError as exc:
            db.rollback()
            raise ApiError(422, str(exc), code="baseline_rejected") from None
    _commit(db)
    return {"baseline": to_dict(baseline), "review_against_active": review}


@router.get("/{baseline_id}")
def get_baseline(baseline_id: int, include_files: bool = False,
                 _user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    return to_dict(_get(BaselineService(db), baseline_id), include_files=include_files)


@router.post("/{baseline_id}/approve")
def approve(baseline_id: int, body: ApproveRequest, admin: CurrentUser = Depends(require_admin),
            db: Session = Depends(get_db)):
    b = _change(BaselineService(db).approve, baseline_id, admin.username, body.note)
    _commit(db)
    return to_dict(b)


@router.post("/{baseline_id}/reject")
def reject(baseline_id: int, body: ReasonRequest, admin: CurrentUser = Depends(require_admin),
           db: Session = Depends(get_db)):
    b = _change(BaselineService(db).reject, baseline_id, admin.username, body.reason)
    _commit(db)
    return to_dict(b)


@router.post("/{baseline_id}/revoke")
def revoke(baseline_id: int, body: ReasonRequest, admin: CurrentUser = Depends(require_admin),
           db: Session = Depends(get_db)):
    b = _change(BaselineService(db).revoke, baseline_id, admin.username, body.reason)
    _commit(db)
    return to_dict(b)


@router.get("/{baseline_id}/verify")
def verify(baseline_id: int, _user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    svc = BaselineService(db)
    _get(svc, baseline_id)
    return {"baseline_id": baseline_id, **svc.verify(baseline_id)}


@router.get("/{baseline_id}/files/proof")
def baseline_file_proof(baseline_id: int, path: str = Query(..., min_length=1, max_length=512),
                        _user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    b = _get(BaselineService(db), baseline_id)
    try:
        p = file_proof(json.loads(b.files_json), path)
    except KeyError:
        raise ApiError(404, "This file is not part of the baseline.") from None
    return {**p, "baseline_id": b.id, "verified": verify_file_proof(path, p["sha256"], p["proof"], b.merkle_root)}
