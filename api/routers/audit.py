"""Audit trail — Cryptographically Linked Blockchain Simulation.

Read and verify the chain; administrators can run the tamper demonstration
(disabled in production) and restore the chain afterwards.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import CurrentUser, current_user, get_db, rate_limited, require_admin, settings_dep
from api.errors import ApiError
from core import audit
from core.config import Settings
from core.crypto import get_keyring, public_key_pem

router = APIRouter(prefix="/audit", tags=["audit"])

NOTICE = ("Cryptographically Linked Blockchain Simulation: a single-node, append-only chain of signed, "
          "hash-linked blocks stored in the application database. It demonstrates tamper evidence; it is not a "
          "distributed blockchain (no network, consensus or mining).")


def _verification(db: Session, expected_head: dict | None = None) -> dict:
    return audit.verify_chain(audit.all_blocks(db), get_keyring(), expected_head)


@router.get("/blocks")
def list_blocks(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                event_type: str | None = Query(None, max_length=48),
                _user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    """Blocks, newest first, each with its verification result."""
    blocks = audit.all_blocks(db)
    result = audit.verify_chain(blocks, get_keyring())
    status = {r["index"]: r for r in result["blocks"]}
    chosen = [b for b in reversed(blocks) if event_type is None or b.event_type == event_type]
    return {
        "notice": NOTICE,
        "total": len(chosen),
        "chain": {k: result[k] for k in ("valid", "length", "first_invalid_index", "head", "merkle_root",
                                         "summary")},
        "items": [audit.block_to_dict(b, status[b.block_index]) for b in chosen[offset:offset + limit]],
    }


@router.get("/blocks/{index}")
def get_block(index: int, _user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    blocks = audit.all_blocks(db)
    position = next((i for i, b in enumerate(blocks) if b.block_index == index), None)
    if position is None:
        raise ApiError(404, "Block not found.")
    result = audit.verify_chain(blocks, get_keyring())
    return audit.block_to_dict(blocks[position], result["blocks"][position])


@router.get("/blocks/{index}/proof")
def block_proof(index: int, _user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    try:
        return audit.block_inclusion_proof(db, index)
    except IndexError:
        raise ApiError(404, "Block not found.") from None


class VerifyRequest(BaseModel):
    expected_head: dict | None = Field(default=None, description="A previously saved signed head['head']")


@router.post("/verify")
def verify_chain(body: VerifyRequest | None = None, user: CurrentUser = Depends(current_user),
                 db: Session = Depends(get_db)):
    """Verify every block (and optionally compare with a saved head). The check itself is recorded."""
    result = _verification(db, body.expected_head if body else None)
    db.rollback()
    if result["valid"]:
        audit.record_event("CHAIN_VERIFIED", user.username, {"valid": True, "length": result["length"],
                                                              "head": result["head"]})
    # A broken chain is not extended: appending to a tampered chain would hide the evidence.
    return {"notice": NOTICE, **result}


@router.get("/head")
def signed_head(_user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    """Signed statement of the current head — save it to detect later deletion of blocks."""
    return audit.signed_head(db) or {}


@router.get("/keys")
def trusted_keys(_user: CurrentUser = Depends(current_user)):
    """Public keys accepted for signatures, for independent verification."""
    ring = get_keyring()
    return {"algorithm": "ECDSA-P256-SHA256",
            "keys": [{"key_id": k, "public_key_pem": public_key_pem(ring.get(k))} for k in ring.key_ids()]}


class TamperRequest(BaseModel):
    block_index: int = Field(ge=1)
    mode: Literal["edit_payload", "rewrite_block"] = "edit_payload"


def _demo_enabled(settings: Settings = Depends(settings_dep)) -> None:
    if not settings.demo_enabled:
        raise ApiError(403, "The tamper demonstration is disabled on this server.")


@router.post("/demo/tamper", dependencies=[Depends(_demo_enabled),
                                           Depends(rate_limited("demo", lambda s: 30))])
def demo_tamper(body: TamperRequest, admin: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)):
    """DEMO: alter a stored block as an attacker with database access would; then verify to see the failure."""
    if not _verification(db)["valid"]:
        raise ApiError(409, "The chain is already broken; restore it first.", code="invalid_state")
    if db.get(audit.AuditBlock, body.block_index) is None:
        raise ApiError(404, "Block not found.")
    # Record the demonstration first, so the tampered block is never the head and
    # restore_tampered() returns the chain to an exactly valid state.
    with audit.APPEND_LOCK:
        audit.append_event(db, "AUDIT_TAMPER_DEMO", admin.username,
                           {"block_index": body.block_index, "mode": body.mode})
        audit.simulate_tamper(db, body.block_index, body.mode)
        db.commit()
    return {"tampered_block": body.block_index, "mode": body.mode, **_verification(db)}


@router.post("/demo/restore", dependencies=[Depends(_demo_enabled)])
def demo_restore(admin: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)):
    restored = audit.restore_tampered(db)
    db.commit()
    result = _verification(db)
    if restored and result["valid"]:
        audit.record_event("AUDIT_RESTORED", admin.username, {"restored_blocks": restored})
        result = _verification(db)
    return {"restored_blocks": restored, **result}
