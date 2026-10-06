"""core/repository.py — AJAY.

Report sealing stage. After scoring, the complete set of engine reports is
canonicalised and hashed (report_sha256) and recorded in the audit chain
(core.audit — Cryptographically Linked Blockchain Simulation) as an
ANALYSIS_COMPLETED block. If integrity failed, an INTEGRITY_ALERT block is
recorded as well.

Later, anyone can prove the stored report is the one that was sealed:
recompute the hash of the stored reports (excluding this stage's own output)
and compare it with the payload of the signed, chain-linked block — see
`verify_job_report`.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from sqlalchemy.orm import Session

from core import audit
from core.config import get_settings
from core.contracts import JobContext, emit
from core.crypto import get_keyring, hash_payload
from db.database import session_scope

SEALED_ENGINES = ("integrity", "static", "tamper", "dynamic", "content", "score")
ALERT_STATUSES = {"MODIFIED", "CERTIFICATE_CHANGED", "BASELINE_INVALID"}


def report_hash(reports: dict[str, Any]) -> str:
    """Canonical SHA-256 of the sealed engine reports (the repository stage itself excluded)."""
    return hash_payload({k: v for k, v in reports.items() if k in SEALED_ENGINES})


def seal(db: Session, job_id: str, reports: dict[str, Any], actor: str = "pipeline") -> dict[str, Any]:
    static = reports.get("static") or {}
    integrity = reports.get("integrity") or {}
    score = reports.get("score") or {}
    tamper = reports.get("tamper") or {}
    integrity_status = (score.get("integrity") or {}).get("status", "UNKNOWN")
    payload = {
        "job_id": job_id,
        "apk_sha256": integrity.get("sha256"),
        "package_name": static.get("package_name"),
        "version_name": static.get("version_name"),
        "certificate_sha256": (static.get("certificate") or {}).get("sha256"),
        "files_merkle_root": integrity.get("merkle_root"),
        "baseline_id": tamper.get("baseline_id"),
        "integrity_status": integrity_status,
        "risk_level": (score.get("risk") or {}).get("level"),
        "risk_score": (score.get("risk") or {}).get("score"),
        "verdict": (score.get("verdict") or {}).get("code"),
        "engines": sorted(k for k in reports if k in SEALED_ENGINES),
        "report_sha256": report_hash(reports),
    }
    if integrity.get("file_category"):   # non-APK content: record what was sealed and its chunk commitment
        payload.update({"file_category": integrity["file_category"], "mime_type": integrity.get("mime_type"),
                        "chunk_merkle_root": integrity.get("chunk_merkle_root")})
    block = audit.append_event(db, "ANALYSIS_COMPLETED", actor, payload, subject=job_id)
    alert = None
    if integrity_status in ALERT_STATUSES:
        alert = audit.append_event(db, "INTEGRITY_ALERT", actor, {
            "job_id": job_id, "package_name": payload["package_name"], "integrity_status": integrity_status,
            "baseline_id": payload["baseline_id"], "reasons": (score.get("integrity") or {}).get("reasons", []),
            "analysis_block": block.block_index}, subject=job_id)
    return {"block": block, "alert": alert, "payload": payload}


def verify_job_report(db: Session, job_id: str, reports: dict[str, Any]) -> dict[str, Any]:
    """Prove that `reports` is exactly what was sealed for `job_id` in an intact chain."""
    blocks = audit.events_for_subject(db, job_id, ("ANALYSIS_COMPLETED",))
    if not blocks:
        return {"valid": False, "checks": {"sealed": False}, "reasons": ["No sealed record exists for this job."]}
    block = blocks[-1]
    chain = audit.verify_chain(audit.all_blocks(db), get_keyring())
    block_check = next(r for r in chain["blocks"] if r["index"] == block.block_index)
    sealed = json.loads(block.payload_json)
    computed = report_hash(reports)
    checks = {
        "sealed": True,
        "report_hash_matches": computed == sealed.get("report_sha256"),
        "block_valid": block_check["valid"],
        "chain_valid": chain["valid"],
    }
    reasons = []
    if not checks["report_hash_matches"]:
        reasons.append("The stored report was changed after it was sealed (its hash no longer matches).")
    reasons += block_check["reasons"]
    if checks["block_valid"] and not checks["chain_valid"]:
        reasons.append(f"The audit chain is broken elsewhere: {chain['summary']}")
    return {
        "valid": all(checks.values()),
        "checks": checks,
        "reasons": reasons,
        "block_index": block.block_index,
        "block_hash": block.block_hash,
        "key_id": block.key_id,
        "sealed_report_sha256": sealed.get("report_sha256"),
        "computed_report_sha256": computed,
        "proof": audit.block_inclusion_proof(db, block.block_index),
    }


def _seal_with_retry(job_id: str, reports: dict[str, Any]) -> dict[str, Any]:
    """Seal in a short, dedicated transaction under the audit append lock.

    Across processes, concurrent jobs may still race for the same block index; the
    PRIMARY KEY and UNIQUE(previous_hash) constraints reject the loser, which then
    retries on top of the new head. The chain therefore never forks.
    """
    def write() -> dict[str, Any]:
        with session_scope() as db:
            sealed = seal(db, job_id, reports)
            block, alert = sealed["block"], sealed["alert"]
            return {
                "report_sha256": sealed["payload"]["report_sha256"],
                "block_index": block.block_index,
                "block_hash": block.block_hash,
                "previous_hash": block.previous_hash,
                "payload_hash": block.payload_hash,
                "key_id": block.key_id,
                "signature": json.loads(block.signature_json),
                "timestamp": block.timestamp,
                "alert_block_index": alert.block_index if alert else None,
            }
    return audit.with_append_retry(write)


# ---------------------------------------------------------------- ledger ----
#
# Append-only hash chain in ledger/chain.jsonl. The canonical form and the link
# rule are frozen: once entries exist, changing either breaks every stored entry.

GENESIS = "0" * 64


def default_ledger_path() -> str:
    """Under the data directory, so tests (which isolate it) never write the real ledger."""
    return str(get_settings().data_dir / "ledger" / "chain.jsonl")
LEDGER_LOCK_TIMEOUT_S = 10.0
LEDGER_LOCK_TTL_S = 30.0          # a lockfile older than this belongs to a dead writer
SEALED_FILE = "sealed_reports.json"  # the exact bytes the chain commits to, written by run()

# Stripped from every engine report before hashing. Each differs between runs of
# the same APK without the content changing:
#   job_id                       generated per run
#   timestamp, created_at,       wall-clock times (the baseline's created_at and
#   approved_at, updated_at,     approved_at sit inside the tamper report)
#   generated_at, started_at,
#   finished_at, completed_at,
#   issued_at, tampered_at
#   duration_s, duration_ms,     how long a stage took
#   elapsed_ms
VOLATILE_KEYS = frozenset({
    "job_id",
    "timestamp", "created_at", "approved_at", "updated_at", "generated_at",
    "started_at", "finished_at", "completed_at", "issued_at", "tampered_at",
    "duration_s", "duration_ms", "elapsed_ms",
    "ts", "timings_s",  # live dynamic runs: capture-window offsets and per-stage timings
})


def _in_workspace(value: Any, workspace: str | None) -> bool:
    return bool(workspace) and isinstance(value, str) and value.startswith(workspace)


def _clean(obj: Any, workspace: str | None) -> Any:
    if isinstance(obj, dict):
        return {k: _clean(v, workspace) for k, v in obj.items()
                if k not in VOLATILE_KEYS and not _in_workspace(v, workspace)}
    if isinstance(obj, list):
        return [_clean(v, workspace) for v in obj if not _in_workspace(v, workspace)]
    return obj


def canonicalise(report: dict, workspace: str | None = None) -> bytes:
    """Deterministic bytes for an engine-report dict; the input to every ledger digest.

    Removed before hashing:
      * every key in VOLATILE_KEYS, at any depth;
      * every string value starting with `workspace` (absolute job paths);
      * ``score.inputs``: the score report's provenance hashes are SHA-256 over the raw
        engine reports, which contain job_id, so they change between runs. The engine
        reports themselves are still hashed, so provenance is still covered.

    Floats are kept and serialised by Python's shortest round-trip repr, which is
    deterministic for a given interpreter. The canonical digest is only a secondary
    reproducibility key: it never gates the ledger, which seals the stored bytes.
    """
    body = _clean(report, workspace)
    score = body.get("score")
    if isinstance(score, dict):
        score.pop("inputs", None)
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def report_digest(report: dict, workspace: str | None = None) -> str:
    return hashlib.sha256(canonicalise(report, workspace)).hexdigest()


def entry_hash(prev: str, sealed_sha256: str, timestamp: str) -> str:
    return hashlib.sha256((prev + sealed_sha256 + timestamp).encode()).hexdigest()


def sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


@contextmanager
def _ledger_lock(ledger_path: str) -> Iterator[None]:
    """Exclusive writer lock from an O_EXCL lockfile (fcntl does not exist on Windows).

    A lockfile older than LEDGER_LOCK_TTL_S belongs to a writer that died; it is removed
    so the ledger heals itself instead of needing a manual delete.
    """
    os.makedirs(os.path.dirname(os.path.abspath(ledger_path)), exist_ok=True)
    lock_path = ledger_path + ".lock"
    deadline = time.monotonic() + LEDGER_LOCK_TIMEOUT_S
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(lock_path) > LEDGER_LOCK_TTL_S:
                    os.remove(lock_path)
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() > deadline:
                raise TimeoutError(f"ledger is locked by another writer ({lock_path})")
            time.sleep(0.05)
    try:
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        yield
    finally:
        try:
            os.remove(lock_path)
        except FileNotFoundError:
            pass


def _last_line(ledger_path: str) -> tuple[str | None, bool]:
    """The final line of the ledger and whether the file ends mid-line.

    Reads backwards from the end in blocks, so appending costs the same whether the
    chain has ten entries or a million.
    """
    if not os.path.exists(ledger_path):
        return None, False
    with open(ledger_path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        if end == 0:
            return None, False
        fh.seek(end - 1)
        truncated = fh.read(1) != b"\n"
        body_end = end if truncated else end - 1
        pos = body_end
        while pos > 0:
            step = min(4096, pos)
            fh.seek(pos - step)
            chunk = fh.read(step)
            idx = chunk.rfind(b"\n")
            if idx != -1:
                start = pos - step + idx + 1
                fh.seek(start)
                return fh.read(body_end - start).decode("utf-8"), truncated
            pos -= step
        fh.seek(0)
        return fh.read(body_end).decode("utf-8"), truncated


def _read_all(ledger_path: str) -> tuple[list[str], bool]:
    """Every line, and whether the file ends mid-line. Used for verification only."""
    if not os.path.exists(ledger_path):
        return [], False
    with open(ledger_path, "r", encoding="utf-8", newline="") as fh:
        text = fh.read()
    if not text:
        return [], False
    truncated = not text.endswith("\n")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines, truncated


def read_chain(ledger_path: str) -> list[dict]:
    lines, _ = _read_all(ledger_path)
    return [json.loads(line) for line in lines]


def append_entry(report: dict, ledger_path: str, job_id: str, sealed_sha256: str,
                 workspace: str | None = None) -> dict:
    """Append one entry sealing `sealed_sha256` and return it.

    `report` is only canonicalised into the secondary reproducibility digest; the chain
    itself commits to `sealed_sha256`, the hash of the bytes written to disk.
    """
    canonical_sha = report_digest(report, workspace)
    with _ledger_lock(ledger_path):
        last, truncated = _last_line(ledger_path)
        if truncated:
            raise RuntimeError("the ledger ends with an incomplete line (a previous write was interrupted); "
                               "run verify_chain and repair the file before appending")
        previous = json.loads(last) if last is not None else None
        prev = previous["entry_hash"] if previous else GENESIS
        index = previous["entry_index"] + 1 if previous else 0
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = {
            "entry_index": index,
            "job_id": job_id,
            "sealed_sha256": sealed_sha256,
            "canonical_report_sha256": canonical_sha,
            "prev_entry_hash": prev,
            "entry_hash": entry_hash(prev, sealed_sha256, timestamp),
            "timestamp": timestamp,
            "signature": "", "pubkey_id": "", "repo_merkle_root": "", "inclusion_proof": [],
        }
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        with open(ledger_path, "a", encoding="utf-8", newline="") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
    return entry


def verify_entry(entry: dict, sealed_path: str) -> dict:
    """Check that the sealed file on disk is exactly the bytes this entry committed to."""
    if not os.path.exists(sealed_path):
        return {"valid": False, "reason": "the sealed report file is missing"}
    if sha256_file(sealed_path) != entry.get("sealed_sha256"):
        return {"valid": False, "reason": "the sealed report file no longer matches the hash in the ledger"}
    return {"valid": True, "reason": None}


def verify_chain(ledger_path: str) -> dict:
    """Recompute every link from genesis; stop at the first entry that does not check out."""
    lines, truncated = _read_all(ledger_path)
    length = len(lines)

    def broken(index: int, reason: str) -> dict:
        return {"valid": False, "length": length, "broken_at": index, "reason": reason}

    prev = GENESIS
    for i, line in enumerate(lines):
        if truncated and i == length - 1:
            return broken(i, "the last line is incomplete: a write was interrupted")
        try:
            entry = json.loads(line)
        except ValueError:
            return broken(i, "the line is not valid JSON")
        if not isinstance(entry, dict):
            return broken(i, "the line is not a ledger entry")
        if entry.get("entry_index") != i:
            return broken(i, f"entry_index is {entry.get('entry_index')!r} but the position is {i} "
                             "(entries were removed, duplicated or reordered)")
        if entry.get("prev_entry_hash") != prev:
            return broken(i, "prev_entry_hash does not match the hash of the previous entry")
        expected = entry_hash(prev, str(entry.get("sealed_sha256", "")), str(entry.get("timestamp", "")))
        if entry.get("entry_hash") != expected:
            return broken(i, "entry_hash does not match the entry's own fields: the entry was altered")
        prev = entry["entry_hash"]
    return {"valid": True, "length": length, "broken_at": None, "reason": None}


def run(job_id: str, ctx: JobContext) -> dict:
    """Seal the reports: ledger first (the authority), then the audit-chain database (a cache)."""
    sealed_bytes = json.dumps(ctx.prior, sort_keys=True, indent=2, ensure_ascii=True).encode("utf-8")
    sealed_path = ctx.out(SEALED_FILE)
    with open(sealed_path, "wb") as fh:
        fh.write(sealed_bytes)
    sealed_sha256 = hashlib.sha256(sealed_bytes).hexdigest()

    ledger_entry = append_entry(ctx.prior, ctx.config.get("ledger_path") or default_ledger_path(),
                                job_id, sealed_sha256, ctx.workspace)
    sealed = _seal_with_retry(job_id, ctx.prior)
    report = {
        "job_id": job_id,
        "engine": "repository",
        "status": "ok",
        "findings": [{
            "id": "REPO_SEALED", "severity": "info",
            "title": "Result recorded in the audit log",
            "evidence": f"Block #{sealed['block_index']}, signed with {sealed['key_id']}; "
                        f"ledger entry #{ledger_entry['entry_index']}",
        }],
        **sealed,
        "ledger": ledger_entry,
        "sealed_file": SEALED_FILE,
        "simulation_notice": "Cryptographically Linked Blockchain Simulation: a single-node, append-only "
                             "hash chain — not a distributed blockchain.",
    }
    return emit(ctx, "repo_entry.json", report)


if __name__ == "__main__":
    prior = json.load(open(sys.argv[1], encoding="utf-8")) if len(sys.argv) > 1 else {}
    ctx = JobContext(apk_path="", workspace=tempfile.mkdtemp(prefix="mt_"), prior=prior, config={})
    print(json.dumps(run("local-test", ctx), indent=2))
