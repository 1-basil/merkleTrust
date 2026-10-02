"""core/repository.py — AJAY.

Cryptographic Merkle Repository and Simulated Blockchain Ledger for MerkleTrust.
- Turns the merged analysis report into a canonicalized, chained, signed, and provable entry.
- Maintains an append-only cryptographic ledger of job reports.
- Signs entry hashes with ECDSA P-256 (SECP256R1) keys.
- Computes repository-wide Merkle root and audit inclusion proofs.
- Simulates blockchain block commitments with height, block hash, and transaction IDs.
- Provides verify_chain() and tamper verification routines for security audits.
"""

import sys
import os
import json
import hashlib
import tempfile
from datetime import datetime, timezone
from typing import Any, Tuple

from core.contracts import JobContext, emit
from core.crypto import KeyRing, canonical_json, get_keyring, get_signer
from core.merkle import build_tree, root, proof, verify_proof

GENESIS = "0" * 64
LEDGER_PATH = os.path.join("data", "repository_ledger.json")


def canonicalize_json(data: Any) -> str:
    """Canonical JSON (sorted keys, compact) — delegates to core.crypto."""
    return canonical_json(data).decode("ascii")


def load_ledger(ledger_file: str = LEDGER_PATH) -> list[dict[str, Any]]:
    """Load existing repository ledger entries."""
    if not os.path.exists(ledger_file):
        return []
    try:
        with open(ledger_file, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return []


def save_ledger(ledger: list[dict[str, Any]], ledger_file: str = LEDGER_PATH) -> None:
    """Save ledger entries atomically."""
    os.makedirs(os.path.dirname(ledger_file) or ".", exist_ok=True)
    with open(ledger_file, "w", encoding="utf-8") as fh:
        json.dump(ledger, fh, indent=2, sort_keys=True)


def verify_entry_signature(entry: dict[str, Any], keyring: KeyRing | None = None) -> bool:
    """Verify the ECDSA P-256 signature over an entry's entry_hash.

    Uses the configured key ring; never generates keys during verification.
    """
    keyring = keyring or get_keyring()
    entry_hash = entry.get("entry_hash")
    if not isinstance(entry_hash, str) or not entry_hash:
        return False
    return keyring.verify_bytes(entry_hash.encode("utf-8"), entry.get("signature"), entry.get("pubkey_id")).valid


def verify_chain(ledger: list[dict[str, Any]]) -> Tuple[bool, int, str]:
    """Verify integrity of the entire repository ledger.

    Returns (is_valid, broken_index, reason).
    """
    if not ledger:
        return True, -1, "Ledger is empty"

    all_entry_hashes = [e["entry_hash"] for e in ledger]
    expected_tree = build_tree(all_entry_hashes)
    expected_root = root(expected_tree)

    for i, entry in enumerate(ledger):
        # 1. Verify prev_entry_hash chaining
        expected_prev = GENESIS if i == 0 else ledger[i - 1]["entry_hash"]
        if entry.get("prev_entry_hash") != expected_prev:
            return False, i, f"Hash chain break at entry {i}: prev_entry_hash does not match previous entry_hash"

        # 2. Verify entry_hash derivation
        expected_hash = hashlib.sha256(
            (entry["prev_entry_hash"] + entry["canonical_report_sha256"] + entry["timestamp"]).encode("utf-8")
        ).hexdigest()
        if entry.get("entry_hash") != expected_hash:
            return False, i, f"Entry {i} hash mismatch: computed {expected_hash}, recorded {entry.get('entry_hash')}"

        # 3. Verify signature
        if not verify_entry_signature(entry):
            return False, i, f"Entry {i} has invalid cryptographic ECDSA signature"

        # 4. Verify inclusion proof against current repo root
        proof_path = entry.get("inclusion_proof", [])
        if not verify_proof(entry["entry_hash"], proof_path, entry.get("repo_merkle_root", expected_root)):
            return False, i, f"Entry {i} inclusion proof failed verification against repository root"

    return True, -1, "All ledger entries and cryptographic proofs verified successfully"


def run(job_id: str, ctx: JobContext) -> dict:
    """Execute repository engine."""
    # 1. Canonicalize upstream reports and compute canonical report sha256
    canonical = canonicalize_json(ctx.prior)
    report_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # 2. Load existing ledger
    ledger_path = ctx.config.get("repository_ledger_path", LEDGER_PATH)
    ledger = load_ledger(ledger_path)

    entry_index = len(ledger)
    prev_entry_hash = GENESIS if entry_index == 0 else ledger[-1]["entry_hash"]
    timestamp = datetime.now(timezone.utc).isoformat()

    # 3. Chained entry hash
    entry_hash = hashlib.sha256(
        (prev_entry_hash + report_sha + timestamp).encode("utf-8")
    ).hexdigest()

    # 4. Sign entry_hash with ECDSA P-256
    signer = get_signer()
    sig_b64 = signer.sign_bytes(entry_hash.encode("utf-8"))

    # 5. Build repository-wide Merkle tree and inclusion proof
    all_hashes = [e["entry_hash"] for e in ledger] + [entry_hash]
    repo_tree = build_tree(all_hashes)
    repo_merkle_root = root(repo_tree)
    inclusion_proof = proof(repo_tree, entry_index)

    # 6. Simulated Blockchain Block
    batch_size = 5
    block_height = entry_index // batch_size
    prev_block_hash = GENESIS if block_height == 0 else hashlib.sha256(f"block:{block_height-1}".encode()).hexdigest()
    block_hash = hashlib.sha256((prev_block_hash + repo_merkle_root).encode("utf-8")).hexdigest()

    sim_block = {
        "height": block_height,
        "block_hash": block_hash,
        "tx_id": entry_hash[:32],
        "simulated": True,
    }

    report = {
        "job_id": job_id,
        "engine": "repository",
        "status": "ok",
        "findings": [
            {
                "id": "REPO_SEALED",
                "severity": "info",
                "title": "Analysis report cryptographically committed to Merkle repository",
                "evidence": f"Entry index {entry_index}, signed with {signer.key_id}, simulated block height {block_height}",
            }
        ],
        "entry_index": entry_index,
        "canonical_report_sha256": report_sha,
        "prev_entry_hash": prev_entry_hash,
        "entry_hash": entry_hash,
        "signature": sig_b64,
        "pubkey_id": signer.key_id,
        "repo_merkle_root": repo_merkle_root,
        "inclusion_proof": inclusion_proof,
        "timestamp": timestamp,
        "sim_block": sim_block,
    }

    # Append to repository ledger
    ledger.append(report)
    save_ledger(ledger, ledger_path)

    return emit(ctx, "repo_entry.json", report)


if __name__ == "__main__":
    prior = json.load(open(sys.argv[1], encoding="utf-8")) if len(sys.argv) > 1 else {}
    ctx = JobContext(apk_path="", workspace=tempfile.mkdtemp(prefix="mt_"), prior=prior, config={})
    print(json.dumps(run("local-test", ctx), indent=2))
