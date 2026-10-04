"""The append-only hash chain: append, verify, and the ways it must fail."""

import json

import pytest

from core import repository as repo


def _append(path, n):
    return [repo.append_entry({"static": {"package_name": f"com.app{i}"}}, str(path), job_id=f"job-{i}")
            for i in range(n)]


def test_empty_or_missing_ledger_is_valid(tmp_path):
    assert repo.verify_chain(str(tmp_path / "none.jsonl")) == {"valid": True, "length": 0,
                                                              "broken_at": None, "reason": None}


def test_first_entry_links_to_genesis_and_chain_verifies(tmp_path):
    path = tmp_path / "chain.jsonl"
    entries = _append(path, 3)
    assert entries[0]["prev_entry_hash"] == repo.GENESIS
    assert entries[1]["prev_entry_hash"] == entries[0]["entry_hash"]
    assert [e["entry_index"] for e in entries] == [0, 1, 2]
    assert repo.verify_chain(str(path)) == {"valid": True, "length": 3, "broken_at": None, "reason": None}


def test_entry_shape_keeps_the_reserved_fields_empty(tmp_path):
    entry = _append(tmp_path / "chain.jsonl", 1)[0]
    assert set(entry) == {"entry_index", "job_id", "canonical_report_sha256", "prev_entry_hash", "entry_hash",
                          "timestamp", "signature", "pubkey_id", "repo_merkle_root", "inclusion_proof"}
    assert entry["signature"] == "" and entry["inclusion_proof"] == []


def test_a_changed_report_digest_breaks_exactly_that_entry(tmp_path):
    path = tmp_path / "chain.jsonl"
    _append(path, 4)
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[2])
    digest = entry["canonical_report_sha256"]
    entry["canonical_report_sha256"] = ("1" if digest[0] != "1" else "2") + digest[1:]
    lines[2] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = repo.verify_chain(str(path))
    assert result["valid"] is False and result["broken_at"] == 2
    assert "altered" in result["reason"]


def test_removing_an_entry_is_detected(tmp_path):
    path = tmp_path / "chain.jsonl"
    _append(path, 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    result = repo.verify_chain(str(path))
    assert result["valid"] is False and result["broken_at"] == 1


def test_an_interrupted_write_is_detected_not_silently_extended(tmp_path):
    path = tmp_path / "chain.jsonl"
    _append(path, 2)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write('{"entry_index":2,"job_id":"half')  # no newline: a crash mid-write
    result = repo.verify_chain(str(path))
    assert result["valid"] is False and result["broken_at"] == 2
    assert "incomplete" in result["reason"]
    with pytest.raises(RuntimeError, match="incomplete line"):
        repo.append_entry({}, str(path), job_id="next")


def test_lock_file_is_removed_after_each_append(tmp_path):
    path = tmp_path / "chain.jsonl"
    _append(path, 2)
    assert not (tmp_path / "chain.jsonl.lock").exists()


def test_a_stale_lock_times_out_with_an_actionable_message(tmp_path, monkeypatch):
    path = tmp_path / "chain.jsonl"
    (tmp_path / "chain.jsonl.lock").write_text("999999")
    monkeypatch.setattr(repo, "LEDGER_LOCK_TIMEOUT_S", 0.2)
    with pytest.raises(TimeoutError, match="stale"):
        repo.append_entry({}, str(path), job_id="x")
