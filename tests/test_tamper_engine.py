"""Tamper engine: real APKs compared against an approved baseline in an isolated database."""

import json
import zipfile

import pytest

from core import integrity, static, tamper
from core.baselines import BaselineService
from core.contracts import JobContext
from scripts.apk_mutations import rewrite_zip

pytestmark = [pytest.mark.integration, pytest.mark.security]

PKG = "com.merkletrust.demo"


def analyse(apk_path, db, tmp_path):
    ctx = JobContext(apk_path=str(apk_path), workspace=str(tmp_path), prior={}, db=db, config={})
    ctx.prior["integrity"] = integrity.run("job", ctx)
    ctx.prior["static"] = static.run("job", ctx)
    return tamper.run("job", ctx)


@pytest.fixture
def baseline(db, fixture_apk):
    svc = BaselineService(db)
    b, _ = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    svc.approve(b.id, "admin")
    db.commit()
    return b


def ids(report):
    return {f["id"] for f in report["findings"]}


def test_no_baseline(db, fixture_apk, tmp_path):
    r = analyse(fixture_apk("signed_v1v2_ec.apk"), db, tmp_path)
    assert r["integrity"]["status"] == "NO_BASELINE"
    assert r["role"] == "no_baseline"
    assert "TAMPER_NO_BASELINE" in ids(r)
    assert BaselineService(db).list() == []  # nothing auto-enrolled


def test_pending_baseline_is_not_used(db, fixture_apk, tmp_path):
    BaselineService(db).enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    db.commit()
    assert analyse(fixture_apk("signed_v1v2_ec.apk"), db, tmp_path)["integrity"]["status"] == "NO_BASELINE"


def test_identical_apk_is_clean(db, baseline, fixture_apk, tmp_path):
    r = analyse(fixture_apk("signed_v1v2_ec.apk"), db, tmp_path)
    i = r["integrity"]
    assert i["status"] == "CLEAN"
    assert i["byte_identical"] is True
    assert i["merkle"]["match"] is True
    assert i["counts"]["modified"] == i["counts"]["added"] == i["counts"]["deleted"] == 0
    assert r["baseline_verification"]["valid"] is True
    assert "TAMPER_INTEGRITY_VERIFIED" in ids(r)


def test_resigned_by_other_key_is_certificate_changed(db, baseline, fixture_apk, tmp_path):
    """Same code, different signer — the classic repackaging signature."""
    r = analyse(fixture_apk("signed_v2v3_rsa.apk"), db, tmp_path)
    i = r["integrity"]
    assert i["status"] == "CERTIFICATE_CHANGED"
    assert i["certificate"]["changed"] is True
    assert i["certificate"]["current_subject"].startswith("CN=Unknown Re-signer")
    assert i["counts"]["modified"] == 0        # content identical...
    assert i["counts"]["signature_files_changed"] > 0
    assert r["certificate_changed"] is True
    assert "TAMPER_CERT_CHANGED" in ids(r)


def test_modified_dex_detected_with_merkle_proof(db, baseline, fixture_apk, tmp_path):
    src = fixture_apk("signed_v1v2_ec.apk")
    dex = zipfile.ZipFile(src).read("classes.dex")
    out = rewrite_zip(src, tmp_path / "patched.apk", modify={"classes.dex": dex + b"\x00injected"})
    r = analyse(out, db, tmp_path)
    i = r["integrity"]
    assert i["status"] == "MODIFIED"
    assert [c["path"] for c in i["files"]["modified"]] == ["classes.dex"]
    assert i["signature_status"] == "invalid"
    assert "TAMPER_DEX_MODIFIED" in ids(r)
    proof = next(p for p in r["proofs"] if p["path"] == "classes.dex")
    assert proof["baseline_hash_valid"] is True       # trusted hash is in the signed root
    assert proof["current_hash_valid"] is False       # uploaded hash is not
    assert proof["root"] == baseline.merkle_root


def test_added_and_deleted_files(db, baseline, fixture_apk, tmp_path):
    out = rewrite_zip(fixture_apk("signed_v1v2_ec.apk"), tmp_path / "x.apk",
                      add={"assets/payload.bin": b"evil"}, remove={"assets/config.json"})
    i = analyse(out, db, tmp_path)["integrity"]
    assert i["status"] == "MODIFIED"
    assert [c["path"] for c in i["files"]["added"]] == ["assets/payload.bin"]
    assert [c["path"] for c in i["files"]["deleted"]] == ["assets/config.json"]


def test_manifest_modification(db, baseline, fixture_apk, tmp_path):
    src = fixture_apk("signed_v1v2_ec.apk")
    m = bytearray(zipfile.ZipFile(src).read("AndroidManifest.xml"))
    m[-1] ^= 0x01
    out = rewrite_zip(src, tmp_path / "m.apk", modify={"AndroidManifest.xml": bytes(m)})
    r = analyse(out, db, tmp_path)
    assert r["integrity"]["status"] == "MODIFIED"
    assert "TAMPER_MANIFEST_MODIFIED" in ids(r)


def test_legitimate_update_reports_profile_changes(db, baseline, fixture_apk, tmp_path):
    r = analyse(fixture_apk("update_v1v2_ec.apk"), db, tmp_path)
    i = r["integrity"]
    assert i["status"] == "MODIFIED"
    assert i["certificate"]["changed"] is False
    assert i["version"]["changed"] is True and i["version"]["downgrade"] is False
    assert i["manifest_diff"]["permissions_added"] == ["android.permission.CAMERA"]
    assert i["manifest_diff"]["components_added"] == ["com.merkletrust.demo.UploadService"]
    assert {"TAMPER_PERMISSIONS_ADDED", "TAMPER_COMPONENTS_ADDED"} <= ids(r)


def test_tampered_baseline_is_not_trusted(db, baseline, fixture_apk, tmp_path):
    files = json.loads(baseline.files_json)
    next(f for f in files if f["path"] == "classes.dex")["sha256"] = "a" * 64
    baseline.files_json = json.dumps(files)
    db.commit()
    r = analyse(fixture_apk("signed_v1v2_ec.apk"), db, tmp_path)
    assert r["integrity"]["status"] == "BASELINE_INVALID"
    assert "TAMPER_BASELINE_INVALID" in ids(r)


def test_missing_inputs_degrade_gracefully(tmp_path):
    ctx = JobContext(apk_path="", workspace=str(tmp_path), prior={}, config={})
    r = tamper.run("job", ctx)
    assert r["status"] == "partial"
    assert r["integrity"]["status"] == "UNKNOWN"
