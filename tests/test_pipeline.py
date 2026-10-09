"""End-to-end pipeline (orchestrator) with an explicitly approved baseline."""

import pytest

from core.baselines import BaselineService
from core.orchestrator import run_job

pytestmark = pytest.mark.integration


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


DATASET = __import__("pathlib").Path(__file__).resolve().parent.parent / "evaluation" / "dataset"


def test_pipeline_measures_code_similarity_to_the_trusted_version(db, tmp_path):
    """The DEX fuzzy hashes are stored in the signed baseline and compared on every later scan."""
    svc = BaselineService(db)
    b, _ = svc.enroll(str(DATASET / "baseline_demo.apk"), "admin")
    svc.approve(b.id, "admin")
    db.commit()

    same = run_job(str(DATASET / "demo_official_copy.apk"), root=str(tmp_path), db_session=db)
    fz = same["tamper"]["fuzzy_comparison"]
    assert fz["compared"] and [d["classification"] for d in fz["dex"]] == ["IDENTICAL"]

    modified = run_job(str(DATASET / "demo_dex_mod.apk"), root=str(tmp_path), db_session=db)
    dex = modified["tamper"]["fuzzy_comparison"]["dex"]
    assert dex[0]["file"] == "classes.dex" and 0 <= dex[0]["similarity"] < 100


def test_pipeline_flags_an_address_from_the_threat_feed(db, tmp_path, monkeypatch):
    """N04 calls http://203.0.113.9/x (a documentation address); a test feed lists it as a C2 server."""
    from core.config import get_settings
    feed = tmp_path / "feed.csv"
    feed.write_text('# "first_seen_utc","ioc_id","ioc_value","ioc_type"\n'
                    '"2026-10-08 06:26:07", "42", "203.0.113.9:80", "ip:port", "botnet_cc", "apk.test_rat", "None", '
                    '"TestRAT", "", "75", "False", "None", "c2", "0", "tester"\n', encoding="utf-8")
    monkeypatch.setattr(get_settings(), "threat_feed_path", feed)
    result = run_job(str(DATASET / "notes_code_mod.apk"), root=str(tmp_path), db_session=db)
    match = [f for f in result["static"]["findings"] if f["id"] == "STATIC_THREAT_INTEL_C2"]
    assert match and "record #42" in match[0]["evidence"]
    assert result["static"]["threat_intel"]["c2_detected"] is True
