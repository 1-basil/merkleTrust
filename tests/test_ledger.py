"""The append-only hash chain: append, verify, and the ways it must fail."""

import hashlib
import json
import os

import pytest

from core import repository as repo


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _append(path, n, payload_size=0):
    entries = []
    for i in range(n):
        report = {"static": {"package_name": f"com.app{i}", "blob": "x" * payload_size}}
        entries.append(repo.append_entry(report, str(path), job_id=f"job-{i}", sealed_sha256=_sha(f"sealed-{i}")))
    return entries


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
    assert set(entry) == {"entry_index", "job_id", "sealed_sha256", "canonical_report_sha256",
                          "prev_entry_hash", "entry_hash", "timestamp", "signature", "pubkey_id",
                          "repo_merkle_root", "inclusion_proof"}
    assert entry["signature"] == "" and entry["inclusion_proof"] == []


def test_the_chain_commits_to_the_sealed_hash(tmp_path):
    path = tmp_path / "chain.jsonl"
    _append(path, 4)
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[2])
    sealed = entry["sealed_sha256"]
    entry["sealed_sha256"] = ("1" if sealed[0] != "1" else "2") + sealed[1:]
    lines[2] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = repo.verify_chain(str(path))
    assert result["valid"] is False and result["broken_at"] == 2
    assert "altered" in result["reason"]


def test_the_canonical_digest_is_not_part_of_the_chain(tmp_path):
    """Documented choice: canonical_report_sha256 is an informational dedup key, not sealed."""
    path = tmp_path / "chain.jsonl"
    _append(path, 2)
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["canonical_report_sha256"] = "f" * 64
    lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert repo.verify_chain(str(path))["valid"] is True


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
        repo.append_entry({}, str(path), job_id="next", sealed_sha256=_sha("n"))


def test_last_line_is_found_across_read_block_boundaries(tmp_path):
    """Entries far bigger than the 4 KiB read block: the backwards scan must still find the tail."""
    path = tmp_path / "chain.jsonl"
    entries = _append(path, 5, payload_size=20_000)
    assert repo.verify_chain(str(path))["valid"] is True
    last, truncated = repo._last_line(str(path))
    assert truncated is False and json.loads(last)["entry_hash"] == entries[-1]["entry_hash"]


def test_a_stale_lock_clears_itself_after_its_ttl(tmp_path, monkeypatch):
    path = tmp_path / "chain.jsonl"
    lock = tmp_path / "chain.jsonl.lock"
    lock.write_text("999999")
    old = os.path.getmtime(lock) - repo.LEDGER_LOCK_TTL_S - 5
    os.utime(lock, (old, old))
    entry = repo.append_entry({}, str(path), job_id="x", sealed_sha256=_sha("x"))
    assert entry["entry_index"] == 0
    assert not lock.exists()


def test_a_fresh_lock_still_blocks_and_times_out(tmp_path, monkeypatch):
    path = tmp_path / "chain.jsonl"
    (tmp_path / "chain.jsonl.lock").write_text("999999")
    monkeypatch.setattr(repo, "LEDGER_LOCK_TIMEOUT_S", 0.2)
    with pytest.raises(TimeoutError, match="locked by another writer"):
        repo.append_entry({}, str(path), job_id="x", sealed_sha256=_sha("x"))


def test_lock_file_is_removed_after_each_append(tmp_path):
    path = tmp_path / "chain.jsonl"
    _append(path, 2)
    assert not (tmp_path / "chain.jsonl.lock").exists()


def test_verify_entry_accepts_the_sealed_file_and_rejects_an_edited_one(tmp_path):
    sealed = tmp_path / "sealed_reports.json"
    content = b'{"static": {"package_name": "com.x"}}'
    sealed.write_bytes(content)
    entry = {"sealed_sha256": hashlib.sha256(content).hexdigest()}
    assert repo.verify_entry(entry, str(sealed)) == {"valid": True, "reason": None}
    sealed.write_bytes(content.replace(b"com.x", b"com.y"))
    result = repo.verify_entry(entry, str(sealed))
    assert result["valid"] is False and "no longer matches" in result["reason"]
    sealed.unlink()
    assert repo.verify_entry(entry, str(sealed))["valid"] is False
