"""core/offline_verifier.py — Zero-trust offline verification engine.

Verifies MerkleTrust verification bundles, audit blocks, Merkle tree proofs,
and target APK/media artifacts completely offline without any network or database connection.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from core.crypto import KeyRing, canonical_json, hash_payload, key_id_for, sha256_hex
from core.file_manifest import file_leaf, manifest_root, verify_file_proof
from core.repository import SEALED_ENGINES, report_hash

CHAIN_ID = "merkletrust.audit.v1"


@dataclass
class CheckStep:
    name: str
    passed: bool
    details: str


@dataclass
class OfflineVerificationResult:
    valid: bool
    summary: str
    steps: list[CheckStep] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "summary": self.summary,
            "steps": [{"name": s.name, "passed": s.passed, "details": s.details} for s in self.steps],
            "errors": self.errors,
        }


def create_verification_bundle(job_summary: dict[str, Any], reports: dict[str, Any],
                               block_record: dict[str, Any], public_key_pem: str) -> dict[str, Any]:
    """Package a self-contained verification bundle for offline verification."""
    integrity = reports.get("integrity") or {}
    files = integrity.get("files") or []
    merkle_root = integrity.get("merkle_root") or ""
    
    # Generate proofs for key files if available
    sample_proofs: dict[str, Any] = {}
    if files:
        from core.file_manifest import file_proof
        for key_path in ("AndroidManifest.xml", "classes.dex", "META-INF/MANIFEST.MF"):
            if any(f["path"] == key_path for f in files):
                try:
                    p = file_proof(files, key_path)
                    sample_proofs[key_path] = p["proof"]
                except KeyError:
                    pass

    sealed_payload = block_record.get("payload") or {}
    if isinstance(sealed_payload, str):
        sealed_payload = json.loads(sealed_payload)

    return {
        "version": "merkletrust.bundle.v1",
        "scan_id": job_summary.get("id"),
        "filename": job_summary.get("filename"),
        "sha256": job_summary.get("apk_sha256"),
        "public_key_pem": public_key_pem,
        "key_id": block_record.get("key_id"),
        "merkle_root": merkle_root,
        "manifest": files,
        "file_proofs": sample_proofs,
        "sealed_payload": sealed_payload,
        "sealed_report_sha256": report_hash(reports),
        "audit_block": {
            "block_index": block_record.get("block_index"),
            "block_hash": block_record.get("block_hash"),
            "previous_hash": block_record.get("previous_hash"),
            "timestamp": block_record.get("timestamp"),
            "event_type": block_record.get("event_type", "ANALYSIS_COMPLETED"),
            "actor": block_record.get("actor", "pipeline"),
            "subject": block_record.get("subject", job_summary.get("id")),
            "payload_hash": block_record.get("payload_hash"),
            "key_id": block_record.get("key_id"),
            "signature": block_record.get("signature"),
        },
        "reports": {k: v for k, v in reports.items() if k in SEALED_ENGINES},
    }


def verify_bundle(bundle: dict[str, Any], target_file_path: Path | str | None = None,
                  trusted_pubkey_pem: str | None = None) -> OfflineVerificationResult:
    """Verify an entire verification bundle and optionally cross-check with the physical artifact."""
    steps: list[CheckStep] = []
    errors: list[str] = []

    # 1. Target artifact verification (if file provided)
    if target_file_path is not None:
        p = Path(target_file_path)
        if not p.is_file():
            errors.append(f"Target artifact does not exist: {p}")
            steps.append(CheckStep("Artifact File Present", False, f"File not found: {p}"))
        else:
            file_bytes = p.read_bytes()
            computed_sha = hashlib.sha256(file_bytes).hexdigest()
            expected_sha = bundle.get("sha256")
            if expected_sha and computed_sha != expected_sha:
                errors.append(f"Artifact SHA-256 mismatch: computed {computed_sha}, expected {expected_sha}")
                steps.append(CheckStep("Artifact SHA-256", False, f"Hash mismatch: {computed_sha} != {expected_sha}"))
            else:
                steps.append(CheckStep("Artifact SHA-256", True, f"Artifact SHA-256 verified ({computed_sha[:16]}...)"))

            # Check individual files inside ZIP / APK if manifest exists
            manifest = bundle.get("manifest") or []
            if manifest and zipfile.is_zipfile(p):
                zip_errors = []
                try:
                    with zipfile.ZipFile(p, "r") as zf:
                        zip_names = set(zf.namelist())
                        for item in manifest:
                            name = item["path"]
                            expected_f_sha = item["sha256"]
                            if name not in zip_names:
                                zip_errors.append(f"File missing from archive: {name}")
                                continue
                            actual_f_sha = hashlib.sha256(zf.read(name)).hexdigest()
                            if actual_f_sha != expected_f_sha:
                                zip_errors.append(f"Content hash mismatch for {name}: {actual_f_sha} != {expected_f_sha}")
                    if zip_errors:
                        errors.extend(zip_errors[:5])
                        steps.append(CheckStep("Archive Manifest Content", False, f"{len(zip_errors)} file(s) mismatched"))
                    else:
                        steps.append(CheckStep("Archive Manifest Content", True,
                                               f"All {len(manifest)} files match their manifest SHA-256"))
                except Exception as exc:
                    errors.append(f"Error inspecting zip archive: {exc}")
                    steps.append(CheckStep("Archive Manifest Content", False, str(exc)))

    # 2. RFC 6962 Merkle tree manifest verification
    manifest = bundle.get("manifest") or []
    expected_root = bundle.get("merkle_root")
    if manifest and expected_root:
        recomputed_root = manifest_root(manifest)
        if recomputed_root == expected_root:
            steps.append(CheckStep("Merkle Root Verification", True,
                                   f"RFC 6962 tree root verified ({recomputed_root[:16]}...)"))
        else:
            errors.append(f"Merkle root mismatch: recomputed {recomputed_root}, expected {expected_root}")
            steps.append(CheckStep("Merkle Root Verification", False,
                                   f"Root mismatch: {recomputed_root} != {expected_root}"))

    # Verify individual file proofs
    file_proofs = bundle.get("file_proofs") or {}
    if file_proofs and expected_root:
        manifest_map = {f["path"]: f["sha256"] for f in manifest}
        proof_errors = []
        for path, proof_path in file_proofs.items():
            f_sha = manifest_map.get(path)
            if not f_sha:
                proof_errors.append(f"File {path} not found in manifest")
                continue
            if not verify_file_proof(path, f_sha, proof_path, expected_root):
                proof_errors.append(f"Merkle inclusion proof invalid for {path}")
        if proof_errors:
            errors.extend(proof_errors)
            steps.append(CheckStep("Merkle Inclusion Proofs", False, "; ".join(proof_errors)))
        else:
            steps.append(CheckStep("Merkle Inclusion Proofs", True,
                                   f"Verified {len(file_proofs)} file inclusion proof(s)"))

    # 3. Canonical report sealing verification
    reports = bundle.get("reports")
    sealed_report_sha = bundle.get("sealed_report_sha256")
    if reports and sealed_report_sha:
        recomputed_report_sha = report_hash(reports)
        if recomputed_report_sha == sealed_report_sha:
            steps.append(CheckStep("Canonical Report Hash", True,
                                   f"Canonical report hash matches sealed record ({recomputed_report_sha[:16]}...)"))
        else:
            errors.append(f"Report hash mismatch: recomputed {recomputed_report_sha}, sealed {sealed_report_sha}")
            steps.append(CheckStep("Canonical Report Hash", False,
                                   f"Report hash mismatch: {recomputed_report_sha} != {sealed_report_sha}"))

    # 4. Audit block header & payload hash verification
    block = bundle.get("audit_block") or {}
    sealed_payload = bundle.get("sealed_payload") or {}
    if block and sealed_payload:
        computed_payload_hash = hash_payload(sealed_payload)
        expected_payload_hash = block.get("payload_hash")
        if computed_payload_hash == expected_payload_hash:
            steps.append(CheckStep("Audit Payload Commitment", True,
                                   f"Payload SHA-256 matches header ({computed_payload_hash[:16]}...)"))
        else:
            errors.append(f"Payload hash mismatch: computed {computed_payload_hash}, block {expected_payload_hash}")
            steps.append(CheckStep("Audit Payload Commitment", False,
                                   f"Mismatch: {computed_payload_hash} != {expected_payload_hash}"))

        header = {
            "chain": CHAIN_ID,
            "index": block.get("block_index"),
            "timestamp": block.get("timestamp"),
            "event_type": block.get("event_type"),
            "actor": block.get("actor"),
            "subject": block.get("subject"),
            "payload_hash": block.get("payload_hash"),
            "previous_hash": block.get("previous_hash"),
        }
        recomputed_block_hash = hash_payload(header)
        expected_block_hash = block.get("block_hash")
        if recomputed_block_hash == expected_block_hash:
            steps.append(CheckStep("Block Header Hash", True,
                                   f"Block hash matches canonical header ({recomputed_block_hash[:16]}...)"))
        else:
            errors.append(f"Block hash mismatch: recomputed {recomputed_block_hash}, recorded {expected_block_hash}")
            steps.append(CheckStep("Block Header Hash", False,
                                   f"Mismatch: {recomputed_block_hash} != {expected_block_hash}"))

        # 5. Cryptographic signature verification
        pubkey_pem = trusted_pubkey_pem or bundle.get("public_key_pem")
        sig_envelope = block.get("signature")
        if pubkey_pem and sig_envelope:
            try:
                public_key = serialization.load_pem_public_key(pubkey_pem.encode("ascii")
                                                               if isinstance(pubkey_pem, str) else pubkey_pem)
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    errors.append("Public key is not an EllipticCurvePublicKey")
                    steps.append(CheckStep("Public Key Format", False, "Key is not EC P-256"))
                else:
                    derived_kid = key_id_for(public_key)
                    expected_kid = block.get("key_id") or sig_envelope.get("key_id")
                    if expected_kid and derived_kid != expected_kid:
                        errors.append(f"Key ID mismatch: derived {derived_kid}, block has {expected_kid}")
                        steps.append(CheckStep("Key Identity", False, f"Key ID mismatch ({derived_kid} != {expected_kid})"))
                    else:
                        steps.append(CheckStep("Key Identity", True, f"Key ID matches public key: {derived_kid}"))

                    ring = KeyRing([public_key])
                    sig_res = ring.verify(header, sig_envelope)
                    if sig_res.valid:
                        steps.append(CheckStep("ECDSA P-256 Block Signature", True,
                                               f"Cryptographic signature verified with key {derived_kid}"))
                    else:
                        errors.append(f"Signature verification failed: {sig_res.reason}")
                        steps.append(CheckStep("ECDSA P-256 Block Signature", False, sig_res.reason))
            except Exception as exc:
                errors.append(f"Error parsing public key or verifying signature: {exc}")
                steps.append(CheckStep("ECDSA P-256 Block Signature", False, str(exc)))
        else:
            errors.append("Public key or signature envelope missing from bundle")
            steps.append(CheckStep("ECDSA P-256 Block Signature", False, "Public key or signature missing"))

    valid = len(errors) == 0 and len(steps) > 0
    summary = "All cryptographic integrity and authenticity checks passed offline." if valid else \
        f"Verification failed with {len(errors)} error(s)."
    return OfflineVerificationResult(valid=valid, summary=summary, steps=steps, errors=errors)
