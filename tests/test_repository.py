"""tests/test_repository.py — Tests for Ajay's Merkle Repository & Blockchain Simulation."""

import os
import tempfile
import json
import pytest

from core.repository import (
    canonicalize_json,
    verify_entry_signature,
    verify_chain,
    run,
    load_ledger,
    save_ledger,
    GENESIS,
)
from core.contracts import JobContext
from core.merkle import verify_proof


def test_canonicalize_json():
    # Order of keys must be deterministic and whitespace stripped
    obj1 = {"b": 2, "a": 1, "c": [3, 2, 1]}
    obj2 = {"a": 1, "c": [3, 2, 1], "b": 2}
    assert canonicalize_json(obj1) == '{"a":1,"b":2,"c":[3,2,1]}'
    assert canonicalize_json(obj1) == canonicalize_json(obj2)


def test_repository_run_and_chaining():
    tmp_ledger = tempfile.mktemp(suffix=".json")
    workspace1 = tempfile.mkdtemp(prefix="mt_repo_test_1_")
    workspace2 = tempfile.mkdtemp(prefix="mt_repo_test_2_")

    ctx1 = JobContext(
        apk_path="",
        workspace=workspace1,
        prior={"static": {"package_name": "app1"}},
        config={"repository_ledger_path": tmp_ledger},
    )
    entry1 = run("job-1", ctx1)

    assert entry1["engine"] == "repository"
    assert entry1["status"] == "ok"
    assert entry1["entry_index"] == 0
    assert entry1["prev_entry_hash"] == GENESIS
    assert len(entry1["signature"]) > 0
    assert verify_entry_signature(entry1)

    # Second entry in chain
    ctx2 = JobContext(
        apk_path="",
        workspace=workspace2,
        prior={"static": {"package_name": "app2"}},
        config={"repository_ledger_path": tmp_ledger},
    )
    entry2 = run("job-2", ctx2)

    assert entry2["entry_index"] == 1
    assert entry2["prev_entry_hash"] == entry1["entry_hash"]
    assert verify_entry_signature(entry2)

    # Verify entire chain
    ledger = load_ledger(tmp_ledger)
    assert len(ledger) == 2
    is_valid, broken_idx, reason = verify_chain(ledger)
    assert is_valid is True
    assert broken_idx == -1

    # Tamper test: Corrupt entry 0's canonical report sha
    corrupted_ledger = json.loads(json.dumps(ledger))
    corrupted_ledger[0]["canonical_report_sha256"] = "f" * 64

    is_valid_tampered, broken_idx_tampered, _ = verify_chain(corrupted_ledger)
    assert is_valid_tampered is False
    assert broken_idx_tampered == 0  # Specifically caught at entry 0!

    if os.path.exists(tmp_ledger):
        os.remove(tmp_ledger)
