"""Cryptographically Linked Blockchain Simulation (audit chain): construction,
verification, tamper detection, restore, truncation, forks, report sealing."""

import contextlib
import io
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy.exc import IntegrityError

from core import audit
from core.baselines import BaselineService, verify_baseline
from core.crypto import Signer, get_keyring
from core.merkle import verify_proof
from core.orchestrator import run_job
from core.repository import report_hash, verify_job_report
from db.models import AuditBlock


def _chain(db, n=4):
    for i in range(n):
        audit.append_event(db, "APK_UPLOADED", f"user{i}", {"n": i, "sha256": f"{i:064x}"}, subject=f"job-{i}")
    db.commit()
    return audit.all_blocks(db)


def _verify(db, **kw):
    return audit.verify_chain(audit.all_blocks(db), get_keyring(), **kw)


def test_genesis_and_linking(db):
    blocks = _chain(db, 3)
    assert [b.block_index for b in blocks] == [0, 1, 2, 3]
    assert blocks[0].event_type == "GENESIS" and blocks[0].previous_hash == "0" * 64
    for prev, cur in zip(blocks, blocks[1:]):
        assert cur.previous_hash == prev.block_hash
    r = _verify(db)
    assert r["valid"] and r["length"] == 4 and r["first_invalid_index"] is None
    assert all(b["checks"] == {"index": True, "link": True, "payload": True, "hash": True, "signature": True}
               for b in r["blocks"])


def test_block_hash_depends_on_previous_hash(db):
    b = _chain(db, 1)[1]
    header = audit.block_header(b)
    assert audit.compute_block_hash({**header, "previous_hash": "1" * 64}) != b.block_hash


def test_unknown_event_rejected(db):
    with pytest.raises(audit.AuditError):
        audit.append_event(db, "MADE_UP", "x", {})


def test_edit_payload_detected_at_that_block(db):
    _chain(db)
    audit.simulate_tamper(db, 2, "edit_payload")
    r = _verify(db)
    assert not r["valid"] and r["first_invalid_index"] == 2
    bad = r["blocks"][2]
    assert bad["checks"]["payload"] is False
    assert "changed after the block was written" in r["summary"]


def test_rewritten_block_breaks_signature_and_next_link(db):
    _chain(db)
    audit.simulate_tamper(db, 2, "rewrite_block")
    r = _verify(db)
    assert r["first_invalid_index"] == 2
    assert r["blocks"][2]["checks"]["payload"] is True       # attacker made it self-consistent...
    assert r["blocks"][2]["checks"]["hash"] is True
    assert r["blocks"][2]["checks"]["signature"] is False    # ...but cannot re-sign it
    assert r["blocks"][3]["checks"]["link"] is False         # and block 3 no longer links to it


def test_restore_makes_chain_valid_again(db):
    _chain(db)
    audit.simulate_tamper(db, 1, "rewrite_block")
    audit.simulate_tamper(db, 3, "edit_payload")
    assert not _verify(db)["valid"]
    assert audit.restore_tampered(db) == [1, 3]
    db.commit()
    assert _verify(db)["valid"]


def test_broken_previous_hash(db):
    _chain(db)
    db.get(AuditBlock, 3).previous_hash = "e" * 64
    db.flush()
    r = _verify(db)
    assert r["first_invalid_index"] == 3 and r["blocks"][3]["checks"]["link"] is False


def test_deleted_middle_block_detected(db):
    _chain(db)
    db.delete(db.get(AuditBlock, 2))
    db.flush()
    r = _verify(db)
    assert r["first_invalid_index"] == 3
    assert r["blocks"][2]["checks"]["index"] is False


def test_truncation_detected_with_saved_head(db):
    _chain(db)
    saved = audit.signed_head(db)
    assert get_keyring().verify(saved["head"], saved["signature"]).valid
    db.delete(db.get(AuditBlock, 4))
    db.flush()
    assert _verify(db)["valid"]                               # links alone cannot see truncation
    r = _verify(db, expected_head=saved["head"])
    assert not r["valid"] and r["truncation_detected"]


def test_block_signed_by_untrusted_key_detected(db):
    _chain(db, 1)
    rogue = Signer(ec.generate_private_key(ec.SECP256R1()))
    audit.append_event(db, "APK_UPLOADED", "mallory", {"x": 1}, signer=rogue)
    r = _verify(db)
    assert r["first_invalid_index"] == 2 and r["blocks"][2]["checks"]["signature"] is False


def test_fork_is_impossible(db):
    blocks = _chain(db, 2)
    twin = audit.detached_copies([blocks[2]])[0]
    twin.block_index, twin.block_hash = 99, "f" * 64      # second child of block 1
    db.add(twin)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_inclusion_proof(db):
    _chain(db, 5)
    p = audit.block_inclusion_proof(db, 3)
    assert verify_proof(p["block_hash"], p["proof"], p["merkle_root"])
    audit.simulate_tamper(db, 3, "rewrite_block")
    assert not verify_proof(db.get(AuditBlock, 3).block_hash, p["proof"], p["merkle_root"])


def test_detached_copies_never_touch_database(db):
    blocks = _chain(db, 2)
    copies = audit.detached_copies(blocks)
    copies[1].payload_json = "{}"
    assert not audit.verify_chain(copies, get_keyring())["valid"]
    db.expire_all()
    assert _verify(db)["valid"]


# ------------------------------------------------------- report sealing --

@pytest.fixture
def sealed_job(db, fixture_apk, tmp_path):
    with contextlib.redirect_stdout(io.StringIO()):
        reports = run_job(fixture_apk("signed_v1v2_ec.apk"), job_id="job-seal", root=str(tmp_path), db_session=db)
    return reports


def test_report_sealed_and_verifiable(db, sealed_job):
    rep = sealed_job["repository"]
    assert rep["report_sha256"] == report_hash(sealed_job)
    r = verify_job_report(db, "job-seal", sealed_job)
    assert r["valid"], r["reasons"]
    assert verify_proof(r["proof"]["block_hash"], r["proof"]["proof"], r["proof"]["merkle_root"])


def test_modified_report_detected(db, sealed_job):
    forged = json.loads(json.dumps(sealed_job))
    forged["score"]["verdict"]["code"] = "CLEAN"
    forged["score"]["risk"]["score"] = 0
    r = verify_job_report(db, "job-seal", forged)
    assert not r["valid"] and r["checks"]["report_hash_matches"] is False


def test_broken_chain_invalidates_report_verification(db, sealed_job):
    audit.simulate_tamper(db, 0, "rewrite_block")
    r = verify_job_report(db, "job-seal", sealed_job)
    assert r["checks"]["report_hash_matches"] is True
    assert r["checks"]["chain_valid"] is False and not r["valid"]


def test_unsealed_job(db):
    assert verify_job_report(db, "nope", {})["checks"] == {"sealed": False}


def test_integrity_alert_recorded(db, fixture_apk, tmp_path):
    svc = BaselineService(db)
    b, _ = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    svc.approve(b.id, "admin")
    db.commit()
    with contextlib.redirect_stdout(io.StringIO()):
        run_job(fixture_apk("signed_v2v3_rsa.apk"), job_id="job-alert", root=str(tmp_path), db_session=db)
    events = [e.event_type for e in audit.events_for_subject(db, "job-alert")]
    assert events == ["ANALYSIS_COMPLETED", "INTEGRITY_ALERT"]
    alert = json.loads(audit.events_for_subject(db, "job-alert")[1].payload_json)
    assert alert["integrity_status"] == "CERTIFICATE_CHANGED"


# ------------------------------------------------ baseline audit trail --

def test_baseline_lifecycle_is_audited(db, fixture_apk):
    svc = BaselineService(db)
    b, _ = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "alice")
    svc.approve(b.id, "bob", "ok")
    svc.revoke(b.id, "carol", "key leaked")
    db.commit()
    events = audit.events_for_subject(db, f"baseline:{b.id}")
    assert [(e.event_type, e.actor) for e in events] == [
        ("BASELINE_ENROLLED", "alice"), ("BASELINE_APPROVED", "bob"), ("BASELINE_REVOKED", "carol")]
    assert _verify(db)["valid"]


def test_undoing_a_revocation_in_the_database_is_detected(db, fixture_apk):
    svc = BaselineService(db)
    b, _ = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    svc.approve(b.id, "admin")
    svc.revoke(b.id, "admin", "compromised")
    b.status = "approved"                  # attacker flips the column back
    db.commit()
    r = verify_baseline(b, get_keyring(), db)
    assert r["checks"]["signature"] is True           # the approval signature itself is still valid...
    assert r["checks"]["status_matches_audit"] is False  # ...but the audit trail says revoked
    assert not r["valid"]
