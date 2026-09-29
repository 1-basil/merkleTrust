"""tests/test_differential_tamper.py — Week 4 Multi-APK Differential Analysis Verification."""

import os
import tempfile
import pytest

from core.orchestrator import run_job
from scripts.create_test_apks import (
    create_clean_baseline,
    create_tampered_repackaged,
)


def test_baseline_and_tampered_differential_pipeline():
    clean_apk = create_clean_baseline()
    tampered_apk = create_tampered_repackaged()

    workspace_root = tempfile.mkdtemp(prefix="mt_diff_test_")
    baseline_store = tempfile.mktemp(suffix="_baselines.json")
    ledger_store = tempfile.mktemp(suffix="_ledger.json")

    # Set temporary config paths in test context
    from core import orchestrator
    orchestrator.CONFIG["baseline_storage_path"] = baseline_store
    orchestrator.CONFIG["repository_ledger_path"] = ledger_store

    # 1. First Run: Clean Baseline APK
    report1 = run_job(clean_apk, root=workspace_root)
    tamper1 = report1["tamper"]
    score1 = report1["score"]

    assert tamper1["role"] == "baseline"
    assert tamper1["baseline_found"] is False
    assert len(tamper1["changed_chunks"]) == 0
    assert len(tamper1["changed_files"]) == 0
    assert tamper1["certificate_changed"] is False
    assert score1["score"] >= 70  # Baseline trusted

    # 2. Second Run: Tampered APK with modified classes.dex & altered cert
    report2 = run_job(tampered_apk, root=workspace_root)
    tamper2 = report2["tamper"]
    score2 = report2["score"]

    assert tamper2["role"] == "comparison"
    assert tamper2["baseline_found"] is True

    # Mathematical chunk diff verification
    assert len(tamper2["changed_chunks"]) > 0

    # Physical file localization verification
    modified_paths = [f["path"] for f in tamper2["changed_files"] if f.get("change_type") == "modified"]
    assert "classes.dex" in modified_paths

    # Certificate tampering detection
    assert tamper2["certificate_changed"] is True

    # Rule scoring penalty verification
    rule_ids = [r["rule_id"] for r in score2["rules_fired"]]
    assert "R_CERT_CHANGED" in rule_ids
    assert "R_FILES_MODIFIED" in rule_ids

    # Score dropped significantly
    assert score2["score"] < score1["score"]

    # Clean up test artifacts
    if os.path.exists(baseline_store):
        os.remove(baseline_store)
    if os.path.exists(ledger_store):
        os.remove(ledger_store)
