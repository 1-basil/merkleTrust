"""tests/test_offline_verifier.py — Test offline verification and bundle validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from core.crypto import Signer, public_key_pem
from core.offline_verifier import create_verification_bundle, verify_bundle
from scripts.verify_offline import main as offline_cli_main

pytestmark = pytest.mark.unit


@pytest.fixture
def sample_bundle(tmp_path):
    signer = Signer(ec.generate_private_key(ec.SECP256R1()))
    pubkey = public_key_pem(signer.public_key)

    from core.file_manifest import file_leaf, manifest_root, file_proof
    from core.repository import report_hash

    files = [
        {"path": "AndroidManifest.xml", "sha256": "a" * 64, "size": 100, "category": "manifest"},
        {"path": "classes.dex", "sha256": "b" * 64, "size": 200, "category": "code"},
    ]
    root = manifest_root(files)
    proof_entry = file_proof(files, "AndroidManifest.xml")

    reports = {
        "integrity": {"sha256": "c" * 64, "files": files, "merkle_root": root},
        "static": {"package_name": "com.test.app", "version_name": "1.0"},
        "tamper": {"status": "MATCH"},
        "score": {"verdict": {"code": "TRUSTED"}, "risk": {"score": 5, "level": "low"}},
    }
    rep_hash = report_hash(reports)

    sealed_payload = {
        "job_id": "job-123",
        "apk_sha256": "c" * 64,
        "files_merkle_root": root,
        "report_sha256": rep_hash,
    }

    from core.audit import CHAIN_ID
    from core.crypto import hash_payload

    payload_hash = hash_payload(sealed_payload)
    header = {
        "chain": CHAIN_ID,
        "index": 1,
        "timestamp": "2026-10-07T12:00:00Z",
        "event_type": "ANALYSIS_COMPLETED",
        "actor": "pipeline",
        "subject": "job-123",
        "payload_hash": payload_hash,
        "previous_hash": "0" * 64,
    }
    block_hash = hash_payload(header)
    sig = signer.sign(header)

    block_record = {
        "block_index": 1,
        "block_hash": block_hash,
        "previous_hash": "0" * 64,
        "timestamp": "2026-10-07T12:00:00Z",
        "event_type": "ANALYSIS_COMPLETED",
        "actor": "pipeline",
        "subject": "job-123",
        "payload_hash": payload_hash,
        "key_id": signer.key_id,
        "signature": sig,
        "payload": sealed_payload,
    }

    job_summary = {
        "id": "job-123",
        "filename": "test.apk",
        "apk_sha256": "c" * 64,
    }

    bundle = create_verification_bundle(job_summary, reports, block_record, pubkey)
    return bundle, signer


def test_offline_verification_valid_bundle(sample_bundle):
    bundle, _ = sample_bundle
    res = verify_bundle(bundle)
    assert res.valid is True
    assert "passed offline" in res.summary


def test_offline_verification_tampered_merkle_root(sample_bundle):
    bundle, _ = sample_bundle
    bundle["merkle_root"] = "f" * 64
    res = verify_bundle(bundle)
    assert res.valid is False
    assert any("Merkle root mismatch" in e for e in res.errors)


def test_offline_verification_tampered_report(sample_bundle):
    bundle, _ = sample_bundle
    bundle["reports"]["static"]["version_name"] = "2.0-TAMPERED"
    res = verify_bundle(bundle)
    assert res.valid is False
    assert any("Report hash mismatch" in e for e in res.errors)


def test_offline_verification_tampered_signature(sample_bundle):
    bundle, _ = sample_bundle
    sig = bundle["audit_block"]["signature"]
    # Tamper with the signature string
    sig["signature"] = "AA" + sig["signature"][2:]
    res = verify_bundle(bundle)
    assert res.valid is False
    assert any("Signature verification failed" in e for e in res.errors)


def test_offline_cli_main(sample_bundle, tmp_path):
    bundle, _ = sample_bundle
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    # Run CLI in JSON mode
    exit_code = offline_cli_main(["--bundle", str(bundle_path), "--json"])
    assert exit_code == 0

    # Tamper bundle file
    bundle["merkle_root"] = "e" * 64
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    exit_code = offline_cli_main(["--bundle", str(bundle_path), "--json"])
    assert exit_code == 1
