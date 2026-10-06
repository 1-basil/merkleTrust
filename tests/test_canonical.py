"""Canonical form of engine reports: the input to every ledger digest.

These rules are frozen once ledger entries exist. If one of these tests starts
failing, the cause is almost always a new volatile field in an engine report.
"""

import json
from pathlib import Path

import pytest

from core.repository import canonicalise, report_digest

FIXTURE_APK = Path(__file__).parent / "fixtures" / "apks" / "signed_v1v2_ec.apk"


def _reversed_keys(obj):
    if isinstance(obj, dict):
        return {k: _reversed_keys(obj[k]) for k in reversed(list(obj))}
    if isinstance(obj, list):
        return [_reversed_keys(v) for v in obj]
    return obj


def test_key_order_does_not_change_the_digest():
    report = {"static": {"package_name": "com.x", "permissions": [{"name": "A", "dangerous": False}]},
              "score": {"risk": {"score": 3, "level": "LOW"}}}
    assert report_digest(report) == report_digest(_reversed_keys(report))
    assert report_digest(report) == report_digest(json.loads(json.dumps(report)))


def test_a_single_nested_value_change_changes_the_digest():
    report = {"score": {"risk": {"score": 3, "contributions": [{"points": 8, "title": "x"}]}}}
    changed = json.loads(json.dumps(report))
    changed["score"]["risk"]["contributions"][0]["points"] = 9
    assert report_digest(report) != report_digest(changed)


def test_volatile_keys_are_stripped_at_any_depth():
    base = {"static": {"package_name": "com.x"}, "dynamic": {"duration_s": 4, "job_id": "a"}}
    other = {"static": {"package_name": "com.x"}, "dynamic": {"duration_s": 99, "job_id": "b"}}
    assert report_digest(base) == report_digest(other)
    assert b"duration_s" not in canonicalise(base) and b"job_id" not in canonicalise(base)


def test_score_inputs_are_stripped_but_the_score_itself_is_not():
    a = {"score": {"verdict": {"code": "CLEAN"}, "inputs": {"static_sha256": "1" * 64}}}
    b = {"score": {"verdict": {"code": "CLEAN"}, "inputs": {"static_sha256": "2" * 64}}}
    c = {"score": {"verdict": {"code": "HIGH_RISK"}, "inputs": {"static_sha256": "1" * 64}}}
    assert report_digest(a) == report_digest(b)
    assert report_digest(a) != report_digest(c)


def test_workspace_paths_are_stripped():
    ws = "C:\\jobs\\abc"
    a = {"dynamic": {"artifacts": {"pcap": f"{ws}\\capture.pcap", "logcat": "dynamic/logcat.txt"}}}
    b = {"dynamic": {"artifacts": {"pcap": "C:\\jobs\\zzz\\capture.pcap", "logcat": "dynamic/logcat.txt"}}}
    assert report_digest(a, ws) != report_digest(b, ws)  # b's pcap sits in another job's folder
    assert report_digest(a, ws) == report_digest({"dynamic": {"artifacts": {"logcat": "dynamic/logcat.txt"}}}, ws)
    stripped = json.loads(canonicalise(a, ws))
    assert "pcap" not in stripped["dynamic"]["artifacts"]
    assert stripped["dynamic"]["artifacts"]["logcat"] == "dynamic/logcat.txt"


def test_floats_are_rejected():
    with pytest.raises(ValueError, match="floats are not allowed"):
        canonicalise({"static": {"ratio": 0.5}})


def test_output_is_compact_sorted_ascii():
    out = canonicalise({"b": 1, "a": "é"})
    assert out == b'{"a":"\\u00e9","b":1}'


def test_orchestrator_twice_on_the_same_apk_gives_the_same_digest(tmp_path, monkeypatch):
    """The test that matters: two full pipeline runs, one APK, one digest."""
    from core.orchestrator import run_job

    # The ledger path is relative to the working directory: keep it out of the repo.
    monkeypatch.chdir(tmp_path)
    digests = []
    for _ in range(2):
        prior = run_job(str(FIXTURE_APK), root=str(tmp_path / "jobs"))
        engine_reports = {k: v for k, v in prior.items() if k != "repository"}
        digests.append(report_digest(engine_reports, str(tmp_path / "jobs")))
    assert digests[0] == digests[1], "a volatile field differs between runs; find it with canonicalise()"
