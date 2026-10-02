"""Findings catalogue, risk scoring (no double counting) and verdict logic."""

import contextlib
import io
import re
import zipfile
from pathlib import Path

import pytest

from core import scoring
from core.baselines import BaselineService
from core.contracts import JobContext
from core.findings import CATALOG, SEVERITIES, finding, normalize
from core.orchestrator import run_job
from core.scoring import decide_verdict, risk_level, score_findings
from scripts.apk_mutations import rewrite_zip

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------ catalogue --

def test_catalogue_entries_are_complete():
    for fid, t in CATALOG.items():
        assert t.severity in SEVERITIES, fid
        assert t.title and t.technical and t.explanation and t.recommendation, fid
        assert t.points >= 0 and t.group, fid


def test_every_emitted_finding_id_is_catalogued():
    emitted = set()
    for src in ("core/static.py", "core/tamper.py"):
        emitted |= set(re.findall(r'"((?:STATIC|TAMPER)_[A-Z_]+)"', (ROOT / src).read_text(encoding="utf-8")))
    assert emitted, "pattern found no finding ids"
    assert emitted <= set(CATALOG), emitted - set(CATALOG)


def test_finding_has_all_presentation_fields():
    f = finding("STATIC_DEBUGGABLE", "android:debuggable=true")
    assert set(f) >= {"id", "severity", "title", "technical", "explanation", "evidence", "recommendation", "points"}


def test_dynamic_operational_findings_never_add_risk():
    f = normalize({"id": "DYN_002", "severity": "critical", "title": "APK file not found", "evidence": "x"}, "dynamic")
    assert f["points"] == 0 and f["severity"] == "info" and f["reported_severity"] == "critical"


def test_unknown_findings_get_labelled_fallback():
    f = normalize({"id": "X_NEW", "severity": "high", "title": "Something", "evidence": "e"}, "plugin")
    assert f["points"] == 10 and f["category"] == "other" and f["source"] == "plugin"


# --------------------------------------------------------------- scoring --

def _f(fid, **kw):
    return {**finding(fid, "evidence", **kw), "source": "test"}


def test_same_group_counted_once():
    r = score_findings([_f("STATIC_DEBUGGABLE"), _f("TAMPER_DEBUGGABLE_ENABLED")])
    assert r["score"] == 15
    assert len(r["contributions"]) == 1
    assert r["suppressed_duplicates"][0]["counted_as"] == r["contributions"][0]["finding_id"]


def test_signer_group_takes_maximum():
    r = score_findings([_f("STATIC_UNSIGNED"), _f("TAMPER_CERT_CHANGED"), _f("STATIC_SIGNATURE_INVALID")])
    assert r["score"] == 40
    assert [c["finding_id"] for c in r["contributions"]] == ["TAMPER_CERT_CHANGED"]


def test_independent_findings_add_up_and_cap_at_100():
    ids = ["STATIC_DCL", "STATIC_SMS_SEND", "STATIC_CMD_EXEC", "TAMPER_CERT_CHANGED", "TAMPER_DEX_MODIFIED"]
    r = score_findings([_f(i) for i in ids])
    assert r["raw_points"] == 20 + 20 + 15 + 40 + 35
    assert r["score"] == 100 and r["level"] == "CRITICAL"


def test_info_findings_score_zero():
    r = score_findings([_f("TAMPER_INTEGRITY_VERIFIED"), _f("STATIC_REFLECTION")])
    assert r == {**r, "score": 0, "level": "LOW", "contributions": []}


@pytest.mark.parametrize("score,level", [(0, "LOW"), (19, "LOW"), (20, "MEDIUM"), (44, "MEDIUM"),
                                         (45, "HIGH"), (69, "HIGH"), (70, "CRITICAL"), (100, "CRITICAL")])
def test_level_thresholds(score, level):
    assert risk_level(score, []) == level


def test_critical_finding_raises_level_to_high():
    assert risk_level(30, [_f("TAMPER_CERT_CHANGED")]) == "HIGH"


@pytest.mark.parametrize("complete,integrity,level,expected", [
    (False, "CLEAN", "LOW", "ANALYSIS_FAILED"),
    (True, "CLEAN", "CRITICAL", "HIGH_RISK"),
    (True, "NO_BASELINE", "HIGH", "HIGH_RISK"),
    (True, "MODIFIED", "MEDIUM", "CHANGES_DETECTED"),
    (True, "CERTIFICATE_CHANGED", "LOW", "CHANGES_DETECTED"),
    (True, "BASELINE_INVALID", "LOW", "CHANGES_DETECTED"),
    (True, "NO_BASELINE", "LOW", "NO_BASELINE"),
    (True, "CLEAN", "MEDIUM", "REVIEW"),
    (True, "CLEAN", "LOW", "CLEAN"),
])
def test_verdict_precedence(complete, integrity, level, expected):
    assert decide_verdict(complete, integrity, level) == expected


def test_failed_analysis_is_never_safe(tmp_path):
    ctx = JobContext(apk_path="", workspace=str(tmp_path), prior={"dynamic": {"status": "partial", "findings": []}})
    r = scoring.run("job", ctx)
    assert r["analysis_complete"] is False
    assert r["risk"]["score"] is None and r["risk"]["level"] == "UNKNOWN"
    assert r["verdict"]["code"] == "ANALYSIS_FAILED"
    assert r["missing_engines"] == ["integrity", "static"]


# ----------------------------------------------------- real scenarios --

@pytest.fixture
def scan(db, fixture_apk, tmp_path):
    svc = BaselineService(db)
    b, _ = svc.enroll(fixture_apk("signed_v1v2_ec.apk"), "admin")
    svc.approve(b.id, "admin")
    db.commit()

    def _scan(path):
        with contextlib.redirect_stdout(io.StringIO()):
            return run_job(str(path), root=str(tmp_path), db_session=db)["score"]
    return _scan


def _contrib_ids(score):
    return [c["finding_id"] for c in score["risk"]["contributions"]]


def test_scenario_clean(scan, fixture_apk):
    s = scan(fixture_apk("signed_v1v2_ec.apk"))
    assert s["verdict"]["code"] == "CLEAN"
    assert s["risk"]["score"] == 0 and s["integrity"]["status"] == "CLEAN"


def test_scenario_resigned(scan, fixture_apk):
    s = scan(fixture_apk("signed_v2v3_rsa.apk"))
    assert s["verdict"]["code"] == "HIGH_RISK"
    assert s["integrity"]["status"] == "CERTIFICATE_CHANGED"
    assert _contrib_ids(s) == ["TAMPER_CERT_CHANGED"]


def test_scenario_modified_code_no_double_count(scan, fixture_apk, tmp_path):
    src = fixture_apk("signed_v1v2_ec.apk")
    dex = zipfile.ZipFile(src).read("classes.dex")
    s = scan(rewrite_zip(src, tmp_path / "m.apk", modify={"classes.dex": dex + b"\x00x"}))
    assert set(_contrib_ids(s)) == {"STATIC_SIGNATURE_INVALID", "TAMPER_DEX_MODIFIED"}
    assert {"finding_id": "STATIC_DEX_HEADER_MISMATCH"}.items() <= s["risk"]["suppressed_duplicates"][0].items()
    assert s["risk"]["score"] == 70


def test_scenario_legitimate_update_is_not_high_risk(scan, fixture_apk):
    s = scan(fixture_apk("update_v1v2_ec.apk"))
    assert s["integrity"]["status"] == "MODIFIED"
    assert s["verdict"]["code"] == "CHANGES_DETECTED"
    assert s["risk"]["level"] == "MEDIUM"
    assert "TAMPER_DEX_MODIFIED" not in _contrib_ids(s)
    assert "TAMPER_SIGNED_UPDATE" in {f["id"] for f in s["all_findings"]}


def test_scenario_suspicious_app(scan, fixture_apk):
    s = scan(fixture_apk("suspicious_v2_ec.apk"))
    assert s["verdict"]["code"] == "HIGH_RISK" and s["integrity"]["status"] == "NO_BASELINE"
    assert {"STATIC_DCL", "STATIC_SMS_SEND", "STATIC_CMD_EXEC", "STATIC_DEBUGGABLE"} <= set(_contrib_ids(s))


def test_benign_app_without_baseline_has_no_findings(db, fixture_apk, tmp_path):
    with contextlib.redirect_stdout(io.StringIO()):
        s = run_job(fixture_apk("signed_v2v3_rsa.apk"), root=str(tmp_path), db_session=db)["score"]
    assert s["verdict"]["code"] == "NO_BASELINE"
    assert s["risk"]["score"] == 0        # self-signed certificates are normal on Android: no penalty
    assert all(f["points"] == 0 for f in s["all_findings"])


def test_every_reported_finding_is_explained(scan, fixture_apk):
    s = scan(fixture_apk("suspicious_v2_ec.apk"))
    for f in s["all_findings"]:
        assert f["title"] and f["explanation"] and f["recommendation"] and "evidence" in f, f["id"]
