"""Integration tests for the trusted-baseline database path:
enrol -> approve (sign) -> retrieve -> verify, plus versioning and tampering of stored rows."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from core.baselines import BaselineError, BaselineNotFound, BaselineService, verify_baseline
from core.crypto import KeyRing, Signer
from db.models import TrustedBaseline

pytestmark = [pytest.mark.integration, pytest.mark.security]


@pytest.fixture
def svc(db):
    return BaselineService(db)


def test_enrol_creates_pending_baseline_that_is_not_used(svc, fixture_apk):
    b, review = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    assert b.status == "pending"
    assert b.baseline_version == 1
    assert b.package_name == "com.merkletrust.demo"
    assert b.app_version_code == 3
    assert b.file_count > 5 and len(b.merkle_root) == 64
    assert b.signature_json is None
    assert review is None
    assert svc.get_active("com.merkletrust.demo") is None  # pending is never trusted


def test_approve_signs_and_activates(svc, db, fixture_apk):
    b, _ = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "alice")
    svc.approve(b.id, "bob", "release 1.2.0")
    db.commit()
    db.expire_all()  # force reload from the database
    active = svc.get_active("com.merkletrust.demo")
    assert active.id == b.id
    assert active.status == "approved" and active.approved_by == "bob"
    assert active.signing_key_id.startswith("mt-")
    result = svc.verify(b.id)
    assert result["valid"], result
    assert result["checks"] == {"status_matches_audit": True, "approved": True, "merkle_root": True,
                                "profile": True, "signature": True}


def test_invalid_apks_cannot_be_enrolled(svc, fixture_apk, tmp_path):
    with pytest.raises(BaselineError, match="signature is unsigned"):
        svc.enroll(fixture_apk("unsigned.apk"), "admin")
    junk = tmp_path / "junk.apk"
    junk.write_bytes(b"not an apk")
    with pytest.raises(BaselineError, match="Not a valid APK"):
        svc.enroll(str(junk), "admin")
    assert svc.list() == []


def test_duplicate_enrolment_rejected(svc, fixture_apk):
    svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    with pytest.raises(BaselineError, match="already baseline"):
        svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")


def test_versioning_and_review_of_new_version(svc, fixture_apk):
    v1, _ = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    svc.approve(v1.id, "admin")
    v2, review = svc.enroll(fixture_apk("update_v1v2_ec.apk"), "admin")
    assert v2.baseline_version == 2
    assert review["compared_with_baseline_id"] == v1.id
    assert review["status"] == "MODIFIED"
    assert review["certificate"]["changed"] is False
    assert "android.permission.CAMERA" in review["manifest_diff"]["permissions_added"]
    assert svc.get_active("com.merkletrust.demo").id == v1.id   # still v1 until approved
    svc.approve(v2.id, "admin")
    assert svc.get_active("com.merkletrust.demo").id == v2.id


def test_review_warns_about_certificate_change(svc, fixture_apk):
    """Baseline-poisoning defence: the approver sees that the signer changed."""
    v1, _ = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    svc.approve(v1.id, "admin")
    _, review = svc.enroll(fixture_apk("signed_v2v3_rsa.apk"), "admin")
    assert review["status"] == "CERTIFICATE_CHANGED"


def test_state_machine(svc, fixture_apk):
    b, _ = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    with pytest.raises(BaselineError):
        svc.revoke(b.id, "admin", "x")                  # cannot revoke pending
    svc.approve(b.id, "admin")
    with pytest.raises(BaselineError):
        svc.approve(b.id, "admin")                      # cannot approve twice
    with pytest.raises(BaselineError):
        svc.reject(b.id, "admin", "x")                  # cannot reject approved
    svc.revoke(b.id, "admin", "key compromised")
    assert b.status == "revoked" and "key compromised" in b.status_reason
    assert svc.get_active("com.merkletrust.demo") is None
    assert verify_baseline(b)["checks"]["approved"] is False
    with pytest.raises(BaselineNotFound):
        svc.get(9999)


def test_reject(svc, fixture_apk):
    b, _ = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    svc.reject(b.id, "bob", "wrong build")
    assert b.status == "rejected"
    assert svc.get_active("com.merkletrust.demo") is None


def _approved(svc, db, fixture_apk):
    b, _ = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    svc.approve(b.id, "admin")
    db.commit()
    return b


def test_tampered_file_list_detected(svc, db, fixture_apk):
    b = _approved(svc, db, fixture_apk)
    files = json.loads(b.files_json)
    dex = next(f for f in files if f["path"] == "classes.dex")
    dex["sha256"] = "0" * 64           # attacker "blesses" a patched DEX in the DB
    b.files_json = json.dumps(files)
    db.commit()
    r = svc.verify(b.id)
    assert not r["valid"] and r["checks"]["merkle_root"] is False


def test_tampered_root_and_files_detected_by_signature(svc, db, fixture_apk):
    from core.file_manifest import manifest_root
    b = _approved(svc, db, fixture_apk)
    files = json.loads(b.files_json)
    files[0]["sha256"] = "1" * 64
    b.files_json = json.dumps(files)
    b.merkle_root = manifest_root(files)  # consistent forgery of list + root
    db.commit()
    r = svc.verify(b.id)
    assert r["checks"]["merkle_root"] is True
    assert r["checks"]["signature"] is False and not r["valid"]


def test_tampered_certificate_or_profile_detected(svc, db, fixture_apk):
    b = _approved(svc, db, fixture_apk)
    b.certificate_sha256 = "f" * 64   # accept an attacker's certificate
    db.commit()
    assert svc.verify(b.id)["checks"]["signature"] is False

    b2, _ = svc.enroll(fixture_apk("update_v1v2_ec.apk"), "admin")
    svc.approve(b2.id, "admin")
    profile = json.loads(b2.profile_json)
    profile["permissions"].append("android.permission.SEND_SMS")
    b2.profile_json = json.dumps(profile)
    db.commit()
    assert svc.verify(b2.id)["checks"]["profile"] is False


def test_unknown_signing_key_detected(db, fixture_apk):
    rogue = Signer(ec.generate_private_key(ec.SECP256R1()))
    svc_rogue = BaselineService(db, signer=rogue)
    b, _ = svc_rogue.enroll(fixture_apk("signed_v1v2_ec.apk"), "mallory")
    svc_rogue.approve(b.id, "mallory")
    trusted_only = KeyRing([Signer(ec.generate_private_key(ec.SECP256R1())).public_key])
    r = verify_baseline(b, trusted_only)
    assert not r["valid"] and "untrusted" in r["reasons"][0]


def test_constraints_enforced(db):
    db.add(TrustedBaseline(package_name="x", baseline_version=1, status="bogus", apk_sha256="0" * 64, apk_size=1,
                           certificate_sha256="0" * 64, file_count=0, merkle_root="0" * 64, files_json="[]",
                           profile_json="{}", profile_sha256="0" * 64, chunk_size=1, chunk_hashes_json="[]",
                           created_by="t"))
    with pytest.raises(Exception):
        db.commit()
    db.rollback()
