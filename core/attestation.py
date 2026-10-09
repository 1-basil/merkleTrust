"""core/attestation.py — in-toto v1 Statement and SLSA Provenance v1.0 with DSSE envelope.

Produces and verifies cryptographically signed supply-chain attestations compliant with:
  * in-toto Attestation Framework v1.0 (https://in-toto.io/)
  * SLSA Provenance v1.0 Specification (https://slsa.dev/provenance/v1)
  * Dead Simple Signing Envelope (DSSE) (https://github.com/secure-systems-lab/dsse)
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any

from core.crypto import KeyRing, Signer, canonical_json


STATEMENT_TYPE_V1 = "https://in-toto.io/Statement/v1"
SLSA_PREDICATE_V1 = "https://slsa.dev/provenance/v1"
DSSE_PAYLOAD_TYPE_INTOTO = "application/vnd.in-toto+json"
BUILDER_ID = "https://merkletrust.dev/verifier/v1"
BUILD_TYPE = "https://merkletrust.dev/attestation/v1"


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Pre-Authentication Encoding (PAE) according to DSSE specification.

    PAE(type, payload) = "DSSEv1" + " " + len(type) + " " + type + " " + len(payload) + " " + payload
    """
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (len(type_bytes), type_bytes, len(payload), payload)


def create_slsa_predicate(job_summary: dict[str, Any], reports: dict[str, Any]) -> dict[str, Any]:
    """Build a SLSA Provenance v1.0 predicate reflecting the verification results."""
    integrity = reports.get("integrity") or {}
    static = reports.get("static") or {}
    tamper = reports.get("tamper") or {}
    score = reports.get("score") or {}

    verdict_info = score.get("verdict") or {}
    risk_info = score.get("risk") or {}
    integrity_info = score.get("integrity") or {}

    now_iso = datetime.now(timezone.utc).isoformat()

    return {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "packageName": static.get("package_name") or job_summary.get("package_name"),
                "versionName": static.get("version_name"),
                "versionCode": static.get("version_code"),
                "filename": job_summary.get("filename"),
            },
            "internalParameters": {
                "verdict": verdict_info.get("code", "UNKNOWN"),
                "verdictTitle": verdict_info.get("title", ""),
                "integrityStatus": integrity_info.get("status", "UNKNOWN"),
                "riskLevel": risk_info.get("level", "unknown"),
                "riskScore": risk_info.get("score", 0),
                "merkleRoot": integrity.get("merkle_root"),
                "baselineId": tamper.get("baseline_id"),
                "certificateSha256": (static.get("certificate") or {}).get("sha256"),
            },
        },
        "runDetails": {
            "builder": {
                "id": BUILDER_ID,
                "version": {"merkletrust": "1.0.0"},
            },
            "metadata": {
                "invocationId": job_summary.get("id"),
                "startedOn": job_summary.get("created_at") or now_iso,
                "finishedOn": job_summary.get("completed_at") or now_iso,
            },
            "byproducts": [
                {
                    "name": "merkletrust-findings",
                    "content": [
                        {"id": f.get("id"), "severity": f.get("severity"), "title": f.get("title")}
                        for f in score.get("findings", [])
                    ],
                }
            ],
        },
    }


def create_intoto_statement(subject_name: str, subject_sha256: str,
                            predicate: dict[str, Any], predicate_type: str = SLSA_PREDICATE_V1) -> dict[str, Any]:
    """Build an in-toto Statement v1 document."""
    return {
        "_type": STATEMENT_TYPE_V1,
        "subject": [
            {
                "name": subject_name,
                "digest": {
                    "sha256": subject_sha256,
                },
            }
        ],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def sign_dsse(statement: dict[str, Any], signer: Signer,
              payload_type: str = DSSE_PAYLOAD_TYPE_INTOTO) -> dict[str, Any]:
    """Wrap and sign an in-toto statement in a DSSE envelope."""
    payload_bytes = canonical_json(statement)
    pae_data = dsse_pae(payload_type, payload_bytes)
    sig_b64 = signer.sign_bytes(pae_data)

    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [
            {
                "keyid": signer.key_id,
                "sig": sig_b64,
            }
        ],
    }


def verify_dsse(envelope: dict[str, Any], keyring: KeyRing) -> tuple[bool, dict[str, Any] | None, str]:
    """Verify a DSSE envelope and return (valid, statement_dict, reason)."""
    if not isinstance(envelope, dict):
        return False, None, "Envelope is not a dictionary"

    payload_type = envelope.get("payloadType")
    payload_b64 = envelope.get("payload")
    signatures = envelope.get("signatures") or []

    if not payload_type or not payload_b64 or not signatures:
        return False, None, "Envelope missing payloadType, payload, or signatures"

    try:
        payload_bytes = base64.b64decode(payload_b64, validate=True)
        statement = json.loads(payload_bytes)
    except Exception as exc:
        return False, None, f"Failed to decode statement payload: {exc}"

    pae_data = dsse_pae(payload_type, payload_bytes)

    # Check that at least one signature verifies against the keyring
    verified_any = False
    reasons = []
    for sig_entry in signatures:
        key_id = sig_entry.get("keyid")
        sig_str = sig_entry.get("sig")
        res = keyring.verify_bytes(pae_data, sig_str, key_id)
        if res.valid:
            verified_any = True
            break
        else:
            reasons.append(f"Key {key_id}: {res.reason}")

    if not verified_any:
        return False, None, "No valid signature found in DSSE envelope: " + "; ".join(reasons)

    if statement.get("_type") != STATEMENT_TYPE_V1:
        return False, None, f"Invalid in-toto statement _type: {statement.get('_type')}"

    return True, statement, "DSSE envelope and in-toto statement valid"
