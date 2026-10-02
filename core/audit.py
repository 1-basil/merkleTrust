"""core/audit.py — Tamper-evident audit trail: a Cryptographically Linked
Blockchain Simulation.

WHAT THIS IS: an append-only chain of blocks stored in the application
database. Each block records one security event and is

    payload_hash  = SHA-256(canonical JSON of the event payload)
    header        = {chain, index, timestamp, event_type, actor, subject,
                     payload_hash, previous_hash}
    block_hash    = SHA-256(canonical JSON of header)
    signature     = ECDSA P-256 over the header (core.crypto)

Because each header contains the previous block's hash, changing any block
changes its hash, and the next block's previous_hash no longer matches — the
chain verification pinpoints the first broken block. Without the signing key an
attacker cannot recompute valid signatures for a rewritten chain.

WHAT THIS IS NOT: a real blockchain. There is a single node, no network, no
consensus, no mining and no decentralisation. Someone with database access can
still delete the newest blocks (truncation); keep a copy of the signed chain
head (see `signed_head`) and pass it to `verify_chain(expected_head=...)` to
detect that.

All appends happen in the caller's transaction, so an event is recorded if and
only if the state change it describes is committed.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.crypto import KeyRing, Signer, get_keyring, get_signer, hash_payload, sha256_hex, canonical_json
from core.merkle import build_tree, proof as merkle_proof, root as merkle_root
from db.models import AuditBlock, AuditTamperBackup

log = logging.getLogger("merkletrust.audit")

CHAIN_ID = "merkletrust.audit.v1"
GENESIS_PREVIOUS = "0" * 64

# Event types recorded in the chain.
EVENTS = {
    "GENESIS": "Audit chain created",
    "APK_UPLOADED": "APK uploaded",
    "ANALYSIS_COMPLETED": "APK analysed",
    "INTEGRITY_ALERT": "Integrity problem detected",
    "BASELINE_ENROLLED": "Baseline enrolled",
    "BASELINE_APPROVED": "Baseline approved and signed",
    "BASELINE_REJECTED": "Baseline rejected",
    "BASELINE_REVOKED": "Baseline revoked",
    "REPORT_VERIFIED": "Report verification performed",
    "CHAIN_VERIFIED": "Audit chain verification performed",
    "USER_LOGIN": "User signed in",
    "LOGIN_FAILED": "Failed sign-in attempt",
    "AUDIT_TAMPER_DEMO": "Tamper demonstration applied",
    "AUDIT_RESTORED": "Tamper demonstration reverted",
}


class AuditError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def block_header(b: AuditBlock) -> dict[str, Any]:
    return {"chain": CHAIN_ID, "index": b.block_index, "timestamp": b.timestamp, "event_type": b.event_type,
            "actor": b.actor, "subject": b.subject, "payload_hash": b.payload_hash,
            "previous_hash": b.previous_hash}


def compute_block_hash(header: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(header))


def head(db: Session) -> AuditBlock | None:
    return db.scalars(select(AuditBlock).order_by(AuditBlock.block_index.desc()).limit(1)).first()


# Serialises "read head -> append -> commit" for writers in this process (API
# requests, background analysis jobs). Without it, concurrent writers repeatedly
# collide on the same block position. Across processes, the PRIMARY KEY and
# UNIQUE(previous_hash) constraints still guarantee the chain cannot fork; the
# losing writer retries.
APPEND_LOCK = threading.RLock()
APPEND_ATTEMPTS = 10


def _new_block(db: Session, index: int, previous_hash: str, event_type: str, actor: str,
               payload: dict[str, Any], subject: str | None, signer: Signer) -> AuditBlock:
    block = AuditBlock(
        block_index=index,
        timestamp=_now(),
        event_type=event_type,
        actor=actor,
        subject=None if subject is None else str(subject),
        payload_json=canonical_json(payload).decode("ascii"),
        payload_hash=hash_payload(payload),
        previous_hash=previous_hash,
    )
    header = block_header(block)
    block.block_hash = compute_block_hash(header)
    envelope = signer.sign(header)
    block.signature_json = json.dumps(envelope, sort_keys=True)
    block.key_id = envelope["key_id"]
    db.add(block)
    db.flush()  # PK / UNIQUE(previous_hash) reject a concurrent append for the same position
    log.info("audit block %s appended: %s (%s)", block.block_index, event_type, subject)
    return block


def append_event(db: Session, event_type: str, actor: str, payload: dict[str, Any],
                 subject: str | None = None, signer: Signer | None = None) -> AuditBlock:
    """Append a signed, hash-linked block in the caller's transaction.

    The head is read exactly once; if the chain is empty, the genesis block is
    created at index 0 first. (Re-reading the head for the genesis block would let
    a concurrent writer slip in between and produce a second genesis block.)
    """
    if event_type not in EVENTS:
        raise AuditError(f"unknown audit event type {event_type!r}")
    signer = signer or get_signer()
    last = head(db)
    if last is None:
        if event_type == "GENESIS":
            return _new_block(db, 0, GENESIS_PREVIOUS, event_type, actor, payload, subject, signer)
        last = _new_block(db, 0, GENESIS_PREVIOUS, "GENESIS", "system",
                          {"chain": CHAIN_ID, "note": "Blockchain simulation started"}, None, signer)
    return _new_block(db, last.block_index + 1, last.block_hash, event_type, actor, payload, subject, signer)


def with_append_retry(fn, attempts: int = APPEND_ATTEMPTS):
    """Run `fn()` (which opens, appends and commits its own transaction) under the
    process-wide append lock, retrying if another process took the same position."""
    from sqlalchemy.exc import IntegrityError, OperationalError

    for attempt in range(1, attempts + 1):
        try:
            with APPEND_LOCK:
                return fn()
        except (IntegrityError, OperationalError) as exc:
            if attempt == attempts:
                log.error("audit append failed after %d attempts: %s", attempts, type(exc).__name__)
                raise
            time.sleep(min(0.5, 0.02 * 2 ** attempt))
    raise AssertionError("unreachable")


def record_event(event_type: str, actor: str, payload: dict[str, Any], subject: str | None = None) -> int:
    """Append an event in its own short, committed transaction. Returns the new block index."""
    from db.database import session_scope

    def write() -> int:
        with session_scope() as db:
            return append_event(db, event_type, actor, payload, subject).block_index
    return with_append_retry(write)


def all_blocks(db: Session) -> list[AuditBlock]:
    return list(db.scalars(select(AuditBlock).order_by(AuditBlock.block_index)))


def block_to_dict(b: AuditBlock, verification: dict[str, Any] | None = None) -> dict[str, Any]:
    data = {
        "index": b.block_index, "timestamp": b.timestamp, "event_type": b.event_type,
        "event_label": EVENTS.get(b.event_type, b.event_type), "actor": b.actor, "subject": b.subject,
        "payload": json.loads(b.payload_json), "payload_hash": b.payload_hash,
        "previous_hash": b.previous_hash, "block_hash": b.block_hash,
        "signature": json.loads(b.signature_json), "key_id": b.key_id,
    }
    if verification is not None:
        data["verification"] = verification
    return data


def verify_block(b: AuditBlock, previous: AuditBlock | None, expected_index: int,
                 keyring: KeyRing) -> dict[str, Any]:
    """Check one block. Returns {"valid", "checks", "reasons"} with plain-language reasons."""
    checks, reasons = {}, []

    checks["index"] = b.block_index == expected_index
    if not checks["index"]:
        reasons.append(f"Expected block #{expected_index} here but found #{b.block_index} (blocks missing or reordered).")

    expected_prev = GENESIS_PREVIOUS if previous is None else previous.block_hash
    checks["link"] = b.previous_hash == expected_prev
    if not checks["link"]:
        reasons.append("Its 'previous hash' does not match the hash of the block before it — "
                       "the earlier block was changed or replaced.")

    try:
        payload = json.loads(b.payload_json)
        checks["payload"] = hash_payload(payload) == b.payload_hash
    except (ValueError, TypeError):
        checks["payload"] = False
    if not checks["payload"]:
        reasons.append("Its recorded event data was changed after the block was written.")

    header = block_header(b)
    checks["hash"] = compute_block_hash(header) == b.block_hash
    if not checks["hash"]:
        reasons.append("Its block hash does not match its contents.")

    try:
        result = keyring.verify(header, json.loads(b.signature_json))
        checks["signature"] = result.valid
        if not result.valid:
            reasons.append(f"Its digital signature is not valid ({result.reason}).")
    except (ValueError, TypeError):
        checks["signature"] = False
        reasons.append("Its digital signature record is unreadable.")

    return {"valid": all(checks.values()), "checks": checks, "reasons": reasons}


def verify_chain(blocks: list[AuditBlock], keyring: KeyRing | None = None,
                 expected_head: dict[str, Any] | None = None) -> dict[str, Any]:
    """Verify the whole chain in order and explain the first break."""
    keyring = keyring or get_keyring()
    results = []
    previous = None
    for i, b in enumerate(blocks):
        r = verify_block(b, previous, i, keyring)
        results.append({"index": b.block_index, "event_type": b.event_type, **r})
        previous = b

    first_bad = next((r["index"] for r in results if not r["valid"]), None)
    truncated = False
    if expected_head is not None:
        idx, h = expected_head.get("index"), expected_head.get("block_hash")
        truncated = not (isinstance(idx, int) and 0 <= idx < len(blocks) and blocks[idx].block_hash == h)

    valid = first_bad is None and not truncated
    if valid:
        summary = f"All {len(blocks)} blocks verified: every link, hash and signature is intact."
    elif first_bad is not None:
        bad = next(r for r in results if r["index"] == first_bad)
        summary = f"Integrity failure at block #{first_bad}: " + " ".join(bad["reasons"])
    else:
        summary = ("The chain is shorter than, or different from, a previously recorded head: "
                   "blocks were deleted or replaced.")
    hashes = [b.block_hash for b in blocks]
    return {
        "valid": valid,
        "length": len(blocks),
        "first_invalid_index": first_bad,
        "truncation_detected": truncated,
        "head": {"index": blocks[-1].block_index, "block_hash": blocks[-1].block_hash} if blocks else None,
        "merkle_root": merkle_root(hashes) if hashes else None,
        "summary": summary,
        "blocks": results,
    }


def detached_copies(blocks: list[AuditBlock]) -> list[AuditBlock]:
    """Independent in-memory copies (changes are never written to the database)."""
    cols = [c.name for c in AuditBlock.__table__.columns]
    return [AuditBlock(**{c: getattr(b, c) for c in cols}) for b in blocks]


def signed_head(db: Session, signer: Signer | None = None) -> dict[str, Any] | None:
    """A signed statement of the current chain head, to be stored externally (anti-truncation)."""
    last = head(db)
    if last is None:
        return None
    statement = {"chain": CHAIN_ID, "index": last.block_index, "block_hash": last.block_hash, "issued_at": _now()}
    return {"head": statement, "signature": (signer or get_signer()).sign(statement)}


def block_inclusion_proof(db: Session, index: int) -> dict[str, Any]:
    """Merkle proof that block `index` is part of the current chain's Merkle root."""
    blocks = all_blocks(db)
    if not 0 <= index < len(blocks):
        raise IndexError(index)
    tree = build_tree([b.block_hash for b in blocks])
    return {"index": index, "block_hash": blocks[index].block_hash, "proof": merkle_proof(tree, index),
            "merkle_root": merkle_root(tree)}


def events_for_subject(db: Session, subject: str, event_types: tuple[str, ...] | None = None) -> list[AuditBlock]:
    stmt = select(AuditBlock).where(AuditBlock.subject == str(subject)).order_by(AuditBlock.block_index)
    if event_types:
        stmt = stmt.where(AuditBlock.event_type.in_(event_types))
    return list(db.scalars(stmt))


# ------------------------------------------------- demonstration only --

TAMPER_MODES = ("edit_payload", "rewrite_block")


def simulate_tamper(db: Session, index: int, mode: str = "edit_payload") -> AuditBlock:
    """DEMO: modify a stored block the way an attacker with database access would.

    edit_payload  — change the event data only (block hash left as recorded)
    rewrite_block — change the data AND recompute payload/block hashes consistently;
                    the signature and the next block's link still expose it.
    The original row is saved so `restore_tampered` can undo the demonstration.
    """
    if mode not in TAMPER_MODES:
        raise AuditError(f"mode must be one of {TAMPER_MODES}")
    b = db.get(AuditBlock, index)
    if b is None:
        raise AuditError(f"block #{index} does not exist")
    if db.get(AuditTamperBackup, index) is None:
        db.add(AuditTamperBackup(block_index=index, original_json=json.dumps(block_to_dict(b))))
    payload = json.loads(b.payload_json)
    payload["tampered"] = "This value was inserted by the tamper demonstration"
    b.payload_json = canonical_json(payload).decode("ascii")
    if mode == "rewrite_block":
        b.payload_hash = hash_payload(payload)
        b.block_hash = compute_block_hash(block_header(b))
    db.flush()
    log.warning("DEMO: audit block %s tampered (%s)", index, mode)
    return b


def restore_tampered(db: Session) -> list[int]:
    """DEMO: put back every block altered by simulate_tamper."""
    restored = []
    for backup in db.scalars(select(AuditTamperBackup)).all():
        b = db.get(AuditBlock, backup.block_index)
        original = json.loads(backup.original_json)
        if b is not None:
            b.payload_json = canonical_json(original["payload"]).decode("ascii")
            b.payload_hash = original["payload_hash"]
            b.block_hash = original["block_hash"]
            restored.append(b.block_index)
        db.delete(backup)
    db.flush()
    return sorted(restored)
