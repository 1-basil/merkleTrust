"""Hardening tests filling coverage gaps: concurrency, rate limiting, logging, CLIs,
non-ASCII paths, determinism, background jobs, malformed signature structures."""

import json
import logging
import struct
import threading
import zipfile
from pathlib import Path

import pytest

from core import audit
from core.apk_archive import ApkArchive
from core.apk_signature import locate_signing_block, verify_apk
from core.crypto import get_keyring

pytestmark = pytest.mark.integration


# ------------------------------------------------------------ concurrency --

@pytest.mark.security
def test_concurrent_audit_appends_never_fork_the_chain(db):
    """Many writers at once: every event recorded exactly once, chain stays linear and valid."""
    errors = []

    def writer(n):
        try:
            for i in range(10):
                audit.record_event("APK_UPLOADED", f"worker{n}", {"worker": n, "i": i})
        except Exception as exc:  # surfaced below
            errors.append(repr(exc))

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    db.expire_all()
    blocks = audit.all_blocks(db)
    extra = [(b.event_type, b.actor) for b in blocks if not b.actor.startswith("worker") and b.event_type != "GENESIS"]
    assert extra == [], f"blocks written by something else: {extra}"
    from collections import Counter
    seen = Counter((b.event_type, b.actor, b.payload_json) for b in blocks)
    dupes = [(k, n, [b.block_index for b in blocks if (b.event_type, b.actor, b.payload_json) == k])
             for k, n in seen.items() if n > 1]
    assert dupes == [], f"duplicated events: {dupes}"
    assert len(blocks) == 1 + 8 * 10                           # genesis + every event, none lost
    assert [b.block_index for b in blocks] == list(range(len(blocks)))
    assert audit.verify_chain(blocks, get_keyring())["valid"]
    payloads = {(json.loads(b.payload_json).get("worker"), json.loads(b.payload_json).get("i")) for b in blocks[1:]}
    assert len(payloads) == 80


@pytest.mark.security
def test_stale_empty_chain_read_cannot_create_a_second_genesis(db, monkeypatch):
    """Regression: if a writer saw an empty chain but another writer committed first,
    the old code re-read the head and appended a SECOND genesis block mid-chain.
    Now the stale writer targets index 0 and is rejected by the database instead."""
    from sqlalchemy.exc import IntegrityError
    audit.record_event("APK_UPLOADED", "first", {"n": 1})          # genesis + block 1 exist
    real_head = audit.head
    calls = {"n": 0}

    def stale_head(session):
        calls["n"] += 1
        return None if calls["n"] == 1 else real_head(session)      # first read is stale
    monkeypatch.setattr(audit, "head", stale_head)
    with pytest.raises(IntegrityError):
        audit.append_event(db, "APK_UPLOADED", "late", {"n": 2})
    db.rollback()
    monkeypatch.setattr(audit, "head", real_head)
    assert [b.event_type for b in audit.all_blocks(db)].count("GENESIS") == 1


# ----------------------------------------------------------- rate limiter --

def test_rate_limiter_window(monkeypatch):
    from api import ratelimit
    clock = [1000.0]
    monkeypatch.setattr(ratelimit.time, "monotonic", lambda: clock[0])
    rl = ratelimit.RateLimiter()
    assert rl.hit("k", 2) is None and rl.hit("k", 2) is None
    retry = rl.hit("k", 2)
    assert retry is not None and 0 < retry <= 60
    assert rl.hit("other", 2) is None                          # buckets are independent
    clock[0] += 61
    assert rl.hit("k", 2) is None                              # window slid past


# ---------------------------------------------------------------- logging --

def test_json_log_lines_carry_request_id_and_fields():
    from core.logging_setup import JsonFormatter, request_id_var
    token = request_id_var.set("abc123")
    try:
        try:
            raise ValueError("boom")
        except ValueError:
            record = logging.getLogger("t").makeRecord("t", logging.ERROR, __file__, 1, "failed %s", ("x",),
                                                       exc_info=__import__("sys").exc_info(),
                                                       extra={"path": "/api/v1/x", "status": 500})
        line = json.loads(JsonFormatter().format(record))
    finally:
        request_id_var.reset(token)
    assert line["msg"] == "failed x" and line["level"] == "ERROR"
    assert line["request_id"] == "abc123" and line["path"] == "/api/v1/x" and line["status"] == 500
    assert "ValueError: boom" in line["exc"]


# ------------------------------------------------------------------- CLIs --

def test_user_cli(db, monkeypatch, capsys):
    from scripts import manage_users
    monkeypatch.setenv("MERKLETRUST_NEW_USER_PASSWORD", "cli-password-12345")
    assert manage_users.main(["create", "carol", "--role", "analyst"]) == 0
    assert manage_users.main(["create", "carol", "--role", "analyst"]) == 1      # duplicate
    assert manage_users.main(["disable", "carol"]) == 0
    capsys.readouterr()
    assert manage_users.main(["list"]) == 0
    listing = capsys.readouterr().out
    assert "carol" in listing and "disabled" in listing
    monkeypatch.setenv("MERKLETRUST_NEW_USER_PASSWORD", "short")
    assert manage_users.main(["create", "dave", "--role", "admin"]) == 1        # weak password


def test_baseline_cli(db, fixture_apk, capsys):
    from scripts import baseline_cli
    assert baseline_cli.main(["enroll", fixture_apk("signed_v1v2_ec.apk"), "--by", "alice"]) == 0
    assert baseline_cli.main(["approve", "1", "--by", "bob", "--note", "ok"]) == 0
    capsys.readouterr()
    assert baseline_cli.main(["verify", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert baseline_cli.main(["enroll", fixture_apk("unsigned.apk"), "--by", "alice"]) == 1
    assert baseline_cli.main(["revoke", "99", "--by", "x", "--reason", "nope"]) == 1


# ------------------------------------------------- unicode / determinism --

def test_non_ascii_paths_are_hashed_and_provable(tmp_path, fixture_apk):
    from core.file_manifest import build_file_manifest, file_proof, manifest_root, verify_file_proof
    from scripts.apk_mutations import rewrite_zip
    out = rewrite_zip(fixture_apk("signed_v1v2_ec.apk"), tmp_path / "u.apk",
                      add={"assets/données/ünïcødé 文件.txt": "héllo".encode()})
    with ApkArchive(str(out)) as apk:
        files = build_file_manifest(apk)
    path = "assets/données/ünïcødé 文件.txt"
    p = file_proof(files, path)
    assert verify_file_proof(path, p["sha256"], p["proof"], manifest_root(files))
    assert not verify_file_proof("assets/donnees/unicode 文件.txt", p["sha256"], p["proof"], manifest_root(files))


def test_analysis_is_deterministic(fixture_apk):
    from core.comparison import build_profile, profile_hash
    from core.integrity import compute_integrity
    from core.static import analyze_apk
    apk = fixture_apk("suspicious_v2_ec.apk")
    a, b = compute_integrity(apk), compute_integrity(apk)
    assert a["merkle_root"] == b["merkle_root"] and a["chunk_merkle_root"] == b["chunk_merkle_root"]
    assert profile_hash(build_profile(analyze_apk(apk))) == profile_hash(build_profile(analyze_apk(apk)))


# -------------------------------------------------------- background jobs --

def test_thread_job_runner_completes_jobs(db, fixture_apk, tmp_path):
    import hashlib
    from api.jobs import JobRunner
    from core.config import get_settings
    from db.models import ApkFile, Job
    data = Path(fixture_apk("signed_v1v2_ec.apk")).read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    db.add(ApkFile(sha256=sha, filename="a.apk", file_size=len(data), quarantine_path="x"))
    db.add(Job(id="33333333-3333-3333-3333-333333333333", apk_sha256=sha, status="queued", workspace="w"))
    db.commit()
    runner = JobRunner(get_settings().model_copy(update={"job_execution": "thread", "job_workers": 2,
                                                         "data_dir": tmp_path}))
    runner.submit("33333333-3333-3333-3333-333333333333", fixture_apk("signed_v1v2_ec.apk"))
    runner.shutdown()                          # waits for running work
    db.expire_all()
    job = db.get(Job, "33333333-3333-3333-3333-333333333333")
    assert job.status == "done" and job.package_name == "com.merkletrust.demo"


# ---------------------------------------------- malformed signature data --

def _patch(src, dst, offset, new_bytes):
    data = bytearray(Path(src).read_bytes())
    data[offset:offset + len(new_bytes)] = new_bytes
    Path(dst).write_bytes(bytes(data))
    return dst


@pytest.mark.security
def test_corrupt_signing_block_size_is_invalid_not_unsigned(tmp_path, fixture_apk):
    src = fixture_apk("suspicious_v2_ec.apk")
    loc = locate_signing_block(Path(src).read_bytes())
    out = _patch(src, tmp_path / "c.apk", loc["block_offset"], struct.pack("<Q", 12345))  # header size != footer
    with ApkArchive(str(out)) as apk:
        r = verify_apk(apk)
    assert r["status"] == "invalid"
    assert any("sizes differ" in e for e in r["errors"])


@pytest.mark.security
def test_unsupported_signature_algorithm_is_unverifiable(tmp_path, fixture_apk):
    """An algorithm we cannot check must be reported as such, never as verified."""
    src = fixture_apk("suspicious_v2_ec.apk")
    data = Path(src).read_bytes()
    loc = locate_signing_block(data)
    block = data[loc["block_offset"]:loc["cd_offset"]]
    ecdsa = struct.pack("<I", 0x0201)
    first = block.find(ecdsa)                      # in the signed digests list
    second = block.find(ecdsa, first + 4)          # in the (unsigned) signatures list
    assert first != -1 and second != -1
    out = _patch(src, tmp_path / "v.apk", loc["block_offset"] + second, struct.pack("<I", 0x0423))  # verity ECDSA
    with ApkArchive(str(out)) as apk:
        r = verify_apk(apk)
    assert r["status"] != "verified"
    assert r["schemes"]["v2"]["verified"] is False


@pytest.mark.security
def test_der_parser_rejects_garbage_without_crashing():
    import random
    from core import der
    rng = random.Random(3)
    for _ in range(500):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64)))
        try:
            der.parse_pkcs7_signer_infos(blob)
        except (der.DerError, IndexError, ValueError):
            pass
