"""tests/test_attestation.py — Test in-toto Statement v1 and SLSA Provenance v1.0 with DSSE."""

from __future__ import annotations

import base64
import json
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from core.attestation import (
    create_intoto_statement,
    create_slsa_predicate,
    dsse_pae,
    sign_dsse,
    verify_dsse,
    STATEMENT_TYPE_V1,
    SLSA_PREDICATE_V1,
)
from core.crypto import KeyRing, Signer

pytestmark = pytest.mark.unit


def test_dsse_pae_encoding():
    pae = dsse_pae("test-type", b"hello world")
    assert pae == b"DSSEv1 9 test-type 11 hello world"


def test_slsa_predicate_and_intoto_generation():
    job = {
        "id": "job-test-456",
        "filename": "release.apk",
        "apk_sha256": "1234abcd" * 8,
        "created_at": "2026-10-07T10:00:00Z",
        "completed_at": "2026-10-07T10:01:00Z",
    }
    reports = {
        "integrity": {"merkle_root": "5678" * 16},
        "static": {"package_name": "org.example.app", "version_name": "1.2.3"},
        "score": {"verdict": {"code": "TRUSTED"}, "risk": {"score": 0, "level": "low"}},
    }
    pred = create_slsa_predicate(job, reports)
    assert pred["buildDefinition"]["externalParameters"]["packageName"] == "org.example.app"
    assert pred["buildDefinition"]["internalParameters"]["verdict"] == "TRUSTED"
    assert pred["runDetails"]["metadata"]["invocationId"] == "job-test-456"

    statement = create_intoto_statement("release.apk", job["apk_sha256"], pred)
    assert statement["_type"] == STATEMENT_TYPE_V1
    assert statement["predicateType"] == SLSA_PREDICATE_V1
    assert statement["subject"][0]["digest"]["sha256"] == job["apk_sha256"]


def test_dsse_signing_and_verification():
    signer = Signer(ec.generate_private_key(ec.SECP256R1()))
    ring = KeyRing([signer.public_key])

    statement = {
        "_type": STATEMENT_TYPE_V1,
        "subject": [{"name": "app.apk", "digest": {"sha256": "abc" * 20}}],
        "predicateType": SLSA_PREDICATE_V1,
        "predicate": {"status": "ok"},
    }

    envelope = sign_dsse(statement, signer)
    assert envelope["payloadType"] == "application/vnd.in-toto+json"
    assert len(envelope["signatures"]) == 1
    assert envelope["signatures"][0]["keyid"] == signer.key_id

    # Verify intact envelope
    valid, recovered, msg = verify_dsse(envelope, ring)
    assert valid is True
    assert recovered["_type"] == STATEMENT_TYPE_V1
    assert recovered["predicate"]["status"] == "ok"

    # Verify tampered payload fails
    tampered_stmt = dict(statement)
    tampered_stmt["predicate"] = {"status": "TAMPERED"}
    tampered_payload_b64 = base64.b64encode(json.dumps(tampered_stmt).encode()).decode()
    envelope_tampered = dict(envelope)
    envelope_tampered["payload"] = tampered_payload_b64
    valid2, _, msg2 = verify_dsse(envelope_tampered, ring)
    assert valid2 is False
