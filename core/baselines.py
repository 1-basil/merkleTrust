"""core/baselines.py — Trusted baseline enrolment, approval and verification.

A baseline is the reference against which every later upload of the same
package is compared. Nothing becomes trusted automatically:

    enrol (admin uploads APK)  ->  status "pending"
        the APK is validated and analysed, its per-file manifest and Merkle root
        are computed, and it is compared with the currently active baseline so
        the approver sees what would change (e.g. a different signing certificate)
    approve (admin)            ->  status "approved", ECDSA-signed
    reject (admin)             ->  status "rejected"
    revoke (admin)             ->  status "revoked" (no longer used)

The *active* baseline of a package is its approved baseline with the highest
baseline_version. Before any comparison the baseline row is re-verified:
signature over the canonical payload, Merkle root recomputed from the stored
file list, and the stored profile re-hashed. A modified database row is
therefore detected instead of silently trusted.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.apk_archive import ApkValidationError
from core.comparison import build_profile, compare_with_baseline, profile_hash
from core.crypto import KeyRing, Signer, get_keyring, get_signer, hash_payload
from core.file_manifest import manifest_root
from core.integrity import DEFAULT_CHUNK_SIZE, compute_integrity
from core.static import analyze_apk
from db.models import TrustedBaseline

log = logging.getLogger("merkletrust.baselines")

PAYLOAD_TYPE = "merkletrust.baseline.v1"


class BaselineError(ValueError):
    """Request cannot be fulfilled (invalid APK, wrong state...). Message is user-safe."""


class BaselineNotFound(LookupError):
    pass


def _utc_naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _ts(dt: datetime | None) -> str | None:
    """Stable timestamp encoding (SQLite drops tzinfo; values are always UTC)."""
    dt = _utc_naive(dt)
    return dt.isoformat(timespec="microseconds") + "Z" if dt else None


def signed_payload(b: TrustedBaseline) -> dict[str, Any]:
    """The exact data an approval signature commits to."""
    return {
        "type": PAYLOAD_TYPE,
        "baseline_id": b.id,
        "package_name": b.package_name,
        "baseline_version": b.baseline_version,
        "app_version_name": b.app_version_name,
        "app_version_code": b.app_version_code,
        "apk_sha256": b.apk_sha256,
        "apk_size": b.apk_size,
        "certificate_sha256": b.certificate_sha256,
        "file_count": b.file_count,
        "merkle_root": b.merkle_root,
        "profile_sha256": b.profile_sha256,
        "chunk_size": b.chunk_size,
        "chunk_hashes_sha256": hash_payload(json.loads(b.chunk_hashes_json)),
        "created_by": b.created_by,
        "created_at": _ts(b.created_at),
        "approved_by": b.approved_by,
        "approved_at": _ts(b.approved_at),
        "approval_note": b.approval_note,
    }


def baseline_snapshot(b: TrustedBaseline) -> dict[str, Any]:
    """Comparison input built from a stored baseline."""
    return {
        "files": json.loads(b.files_json),
        "profile": json.loads(b.profile_json),
        "apk_sha256": b.apk_sha256,
        "certificate_sha256": b.certificate_sha256,
        "merkle_root": b.merkle_root,
        "chunk_hashes": json.loads(b.chunk_hashes_json),
        "chunk_size": b.chunk_size,
    }


def snapshot_from_reports(integrity: dict[str, Any], static: dict[str, Any]) -> dict[str, Any]:
    """Comparison input built from an analysis job's engine reports."""
    return {
        "files": integrity["files"],
        "profile": build_profile(static),
        "apk_sha256": integrity["sha256"],
        "certificate_sha256": (static.get("certificate") or {}).get("sha256", ""),
        "merkle_root": integrity["merkle_root"],
        "chunk_hashes": [c["hash"] for c in integrity.get("chunks", [])],
        "chunk_size": integrity.get("chunk_size", 0),
        "signature_status": (static.get("signature") or {}).get("status", "unknown"),
    }


def verify_baseline(b: TrustedBaseline, keyring: KeyRing | None = None) -> dict[str, Any]:
    """Re-verify a stored baseline. Returns {"valid": bool, "checks": {...}, "reasons": [...]}."""
    keyring = keyring or get_keyring()
    checks: dict[str, bool] = {}
    reasons: list[str] = []

    checks["approved"] = b.status == "approved"
    if not checks["approved"]:
        reasons.append(f"baseline status is '{b.status}', not 'approved'")

    try:
        files = json.loads(b.files_json)
        recomputed = manifest_root(files)
        checks["merkle_root"] = recomputed == b.merkle_root and len(files) == b.file_count
    except (ValueError, KeyError, TypeError):
        checks["merkle_root"] = False
    if not checks["merkle_root"]:
        reasons.append("stored file list does not reproduce the recorded Merkle root")

    try:
        checks["profile"] = profile_hash(json.loads(b.profile_json)) == b.profile_sha256
    except (ValueError, TypeError):
        checks["profile"] = False
    if not checks["profile"]:
        reasons.append("stored app profile does not match its recorded hash")

    try:
        envelope = json.loads(b.signature_json) if b.signature_json else None
        result = keyring.verify(signed_payload(b), envelope)
    except (ValueError, TypeError) as exc:
        result = None
        reasons.append(f"signature record unreadable ({exc})")
    checks["signature"] = result is not None and result.valid
    if result is not None and not result.valid:
        reasons.append(f"approval signature invalid: {result.reason}")

    valid = all(checks.values())
    if not valid:
        log.warning("baseline %s failed verification: %s", b.id, "; ".join(reasons))
    return {"valid": valid, "checks": checks, "reasons": reasons,
            "key_id": envelope.get("key_id") if isinstance(envelope, dict) else None}


def to_dict(b: TrustedBaseline, include_files: bool = False) -> dict[str, Any]:
    profile = json.loads(b.profile_json)
    data = {
        "id": b.id,
        "package_name": b.package_name,
        "baseline_version": b.baseline_version,
        "status": b.status,
        "app_version_name": b.app_version_name,
        "app_version_code": b.app_version_code,
        "apk_sha256": b.apk_sha256,
        "apk_size": b.apk_size,
        "certificate_sha256": b.certificate_sha256,
        "certificate": profile.get("certificate", {}),
        "file_count": b.file_count,
        "merkle_root": b.merkle_root,
        "created_by": b.created_by,
        "created_at": _ts(b.created_at),
        "approved_by": b.approved_by,
        "approved_at": _ts(b.approved_at),
        "approval_note": b.approval_note,
        "status_reason": b.status_reason,
        "signing_key_id": b.signing_key_id,
        "signature": json.loads(b.signature_json) if b.signature_json else None,
    }
    if include_files:
        data["files"] = json.loads(b.files_json)
        data["profile"] = profile
    return data


class BaselineService:
    """All baseline state changes go through here. Callers own the transaction."""

    def __init__(self, db: Session, signer: Signer | None = None, keyring: KeyRing | None = None,
                 apk_limits: dict | None = None):
        self.db = db
        self._signer = signer
        self._keyring = keyring
        self.apk_limits = apk_limits

    @property
    def signer(self) -> Signer:
        return self._signer or get_signer()

    @property
    def keyring(self) -> KeyRing:
        return self._keyring or get_keyring()

    # ------------------------------------------------------------ queries --
    def get(self, baseline_id: int) -> TrustedBaseline:
        b = self.db.get(TrustedBaseline, baseline_id)
        if b is None:
            raise BaselineNotFound(f"baseline {baseline_id} not found")
        return b

    def list(self, package_name: str | None = None, status: str | None = None) -> list[TrustedBaseline]:
        stmt = select(TrustedBaseline).order_by(TrustedBaseline.package_name, TrustedBaseline.baseline_version.desc())
        if package_name:
            stmt = stmt.where(TrustedBaseline.package_name == package_name)
        if status:
            stmt = stmt.where(TrustedBaseline.status == status)
        return list(self.db.scalars(stmt))

    def get_active(self, package_name: str) -> TrustedBaseline | None:
        stmt = (select(TrustedBaseline)
                .where(TrustedBaseline.package_name == package_name, TrustedBaseline.status == "approved")
                .order_by(TrustedBaseline.baseline_version.desc()).limit(1))
        return self.db.scalars(stmt).first()

    # ---------------------------------------------------------- lifecycle --
    def enroll(self, apk_path: str, created_by: str) -> tuple[TrustedBaseline, dict[str, Any] | None]:
        """Analyse an APK and store it as a *pending* baseline.

        Returns (baseline, review) where review is the comparison with the
        currently active baseline of the same package (None if there is none).
        """
        try:
            static = analyze_apk(apk_path, self.apk_limits)
            integrity = compute_integrity(apk_path, DEFAULT_CHUNK_SIZE, self.apk_limits)
        except ApkValidationError as exc:
            raise BaselineError(f"Not a valid APK: {exc}") from None

        sig_status = static["signature"]["status"]
        if sig_status != "verified":
            raise BaselineError(f"Only APKs with a valid signature can become a baseline (signature is {sig_status}).")
        package = static["package_name"]
        if not package or package == "unknown.package":
            raise BaselineError("The APK does not declare a package name.")

        duplicate = self.db.scalars(select(TrustedBaseline).where(
            TrustedBaseline.package_name == package, TrustedBaseline.apk_sha256 == integrity["sha256"],
            TrustedBaseline.status.in_(("pending", "approved")))).first()
        if duplicate:
            raise BaselineError(f"This exact APK is already baseline #{duplicate.id} ({duplicate.status}).")

        profile = build_profile(static)
        next_version = (self.db.scalar(select(func.max(TrustedBaseline.baseline_version))
                                       .where(TrustedBaseline.package_name == package)) or 0) + 1
        b = TrustedBaseline(
            package_name=package,
            baseline_version=next_version,
            status="pending",
            app_version_name=static["version_name"],
            app_version_code=static["version_code"],
            apk_sha256=integrity["sha256"],
            apk_size=integrity["file_size"],
            certificate_sha256=static["certificate"]["sha256"],
            file_count=integrity["file_count"],
            merkle_root=integrity["merkle_root"],
            files_json=json.dumps(integrity["files"], sort_keys=True),
            profile_json=json.dumps(profile, sort_keys=True),
            profile_sha256=profile_hash(profile),
            chunk_size=integrity["chunk_size"],
            chunk_hashes_json=json.dumps([c["hash"] for c in integrity["chunks"]]),
            created_by=created_by,
            created_at=_utc_naive(datetime.now(timezone.utc)),
        )
        self.db.add(b)
        self.db.flush()

        review = None
        active = self.get_active(package)
        if active is not None:
            current = baseline_snapshot(b)
            current["signature_status"] = sig_status
            review = compare_with_baseline(baseline_snapshot(active), current)
            review["compared_with_baseline_id"] = active.id
        log.info("baseline %s enrolled for %s (v%s) by %s", b.id, package, next_version, created_by)
        return b, review

    def approve(self, baseline_id: int, approved_by: str, note: str | None = None) -> TrustedBaseline:
        b = self.get(baseline_id)
        if b.status != "pending":
            raise BaselineError(f"Only pending baselines can be approved (baseline is {b.status}).")
        b.approved_by = approved_by
        b.approved_at = _utc_naive(datetime.now(timezone.utc))
        b.approval_note = note
        envelope = self.signer.sign(signed_payload(b))
        b.signature_json = json.dumps(envelope, sort_keys=True)
        b.signing_key_id = envelope["key_id"]
        b.status = "approved"
        self.db.flush()
        log.info("baseline %s approved by %s, signed with %s", b.id, approved_by, envelope["key_id"])
        return b

    def reject(self, baseline_id: int, rejected_by: str, reason: str) -> TrustedBaseline:
        b = self.get(baseline_id)
        if b.status != "pending":
            raise BaselineError(f"Only pending baselines can be rejected (baseline is {b.status}).")
        b.status, b.status_reason = "rejected", f"Rejected by {rejected_by}: {reason}"
        self.db.flush()
        return b

    def revoke(self, baseline_id: int, revoked_by: str, reason: str) -> TrustedBaseline:
        b = self.get(baseline_id)
        if b.status != "approved":
            raise BaselineError(f"Only approved baselines can be revoked (baseline is {b.status}).")
        b.status, b.status_reason = "revoked", f"Revoked by {revoked_by}: {reason}"
        self.db.flush()
        return b

    def verify(self, baseline_id: int) -> dict[str, Any]:
        return verify_baseline(self.get(baseline_id), self.keyring)
