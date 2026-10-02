"""End-to-end pipeline (orchestrator) with an explicitly approved baseline."""

from core.baselines import BaselineService
from core.orchestrator import run_job


def test_pipeline_against_approved_baseline(db, fixture_apk, tmp_path):
    svc = BaselineService(db)
    b, _ = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    svc.approve(b.id, "admin")
    db.commit()

    clean = run_job(fixture_apk("signed_v1v2_ec.apk"), root=str(tmp_path), db_session=db)
    assert clean["static"]["signature"]["status"] == "verified"
    assert clean["tamper"]["integrity"]["status"] == "CLEAN"

    resigned = run_job(fixture_apk("signed_v2v3_rsa.apk"), root=str(tmp_path), db_session=db)
    assert resigned["tamper"]["integrity"]["status"] == "CERTIFICATE_CHANGED"
    assert set(resigned) == {"integrity", "static", "tamper", "dynamic", "score", "repository"}


def test_pipeline_without_baseline_never_auto_trusts(db, fixture_apk, tmp_path):
    first = run_job(fixture_apk("signed_v1v2_ec.apk"), root=str(tmp_path), db_session=db)
    second = run_job(fixture_apk("signed_v2v3_rsa.apk"), root=str(tmp_path), db_session=db)
    assert first["tamper"]["integrity"]["status"] == "NO_BASELINE"
    assert second["tamper"]["integrity"]["status"] == "NO_BASELINE"
    assert BaselineService(db).list() == []
