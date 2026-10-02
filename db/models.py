"""db/models.py — SQLAlchemy database models for MerkleTrust.

Owner: Basil.
Models represent tables for all four engines:
- Basil: Job, ApkFile, EngineStatus, TrustScore
- Ajay: AuditBlock (blockchain simulation), ChunkHash
- Ashwini: TrustedBaseline, StaticReportModel, TamperReportModel
- Bhavish: DynamicReportModel
"""

from datetime import datetime, timezone
from sqlalchemy import (
    CheckConstraint,
    Column,
    Index,
    UniqueConstraint,
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    Float,
)
from sqlalchemy.orm import relationship

from db.database import Base


class ApkFile(Base):
    """Quarantined APK files uploaded to the platform."""
    __tablename__ = "apk_files"

    sha256 = Column(String(64), primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False)
    quarantine_path = Column(String(512), nullable=False)
    uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    jobs = relationship("Job", back_populates="apk_file")


class Job(Base):
    """Analysis job orchestrator records."""
    __tablename__ = "jobs"

    id = Column(String(64), primary_key=True, index=True)
    apk_sha256 = Column(String(64), ForeignKey("apk_files.sha256"), nullable=False)
    status = Column(String(32), default="pending", index=True)  # pending, running, done, failed
    workspace = Column(String(512), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    apk_file = relationship("ApkFile", back_populates="jobs")
    engine_statuses = relationship("EngineStatus", back_populates="job", cascade="all, delete-orphan")
    trust_score = relationship("TrustScore", back_populates="job", uselist=False, cascade="all, delete-orphan")


class EngineStatus(Base):
    """Execution status for each engine stage within a job."""
    __tablename__ = "engine_status"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(64), ForeignKey("jobs.id"), nullable=False, index=True)
    engine_name = Column(String(32), nullable=False)  # integrity, static, tamper, dynamic, score, repository
    status = Column(String(32), default="pending")    # pending, running, ok, partial, failed
    duration_ms = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    job = relationship("Job", back_populates="engine_statuses")


class TrustScore(Base):
    """Risk score, integrity status and verdict from the scoring engine."""
    __tablename__ = "trust_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(64), ForeignKey("jobs.id"), unique=True, nullable=False)
    score = Column(Integer, nullable=True)  # risk indicator 0-100 (higher = riskier); NULL if not analysable
    risk_level = Column(String(16), nullable=False, default="UNKNOWN")  # LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN
    integrity_status = Column(String(32), nullable=False, default="UNKNOWN")
    verdict = Column(String(32), nullable=False)  # CLEAN|REVIEW|NO_BASELINE|CHANGES_DETECTED|HIGH_RISK|ANALYSIS_FAILED
    rules_fired_json = Column(Text, nullable=False, default="[]")  # risk contributions
    inputs_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    job = relationship("Job", back_populates="trust_score")


class AuditBlock(Base):
    """One block of the Cryptographically Linked Blockchain Simulation (audit trail).

    block_hash = SHA-256(canonical header), where the header contains the
    previous block's hash, so changing any block breaks every later link.
    The header is also ECDSA-signed. previous_hash is UNIQUE: two blocks can
    never claim the same predecessor (no forks). This is a single-node,
    append-only simulation — there is no network, consensus or mining.
    """
    __tablename__ = "audit_blocks"
    __table_args__ = (CheckConstraint("block_index >= 0", name="ck_block_index"),)

    block_index = Column(Integer, primary_key=True, autoincrement=False)
    timestamp = Column(String(40), nullable=False)            # exact ISO-8601 string that was hashed
    event_type = Column(String(48), nullable=False, index=True)
    actor = Column(String(128), nullable=False)
    subject = Column(String(128), nullable=True, index=True)  # job id, baseline id...
    payload_json = Column(Text, nullable=False)
    payload_hash = Column(String(64), nullable=False)
    previous_hash = Column(String(64), nullable=False, unique=True)
    block_hash = Column(String(64), nullable=False, unique=True)
    signature_json = Column(Text, nullable=False)
    key_id = Column(String(32), nullable=False)


class AuditTamperBackup(Base):
    """Demo support only: original copy of a block deliberately altered by the
    tamper demonstration, so the valid chain can be restored afterwards."""
    __tablename__ = "audit_tamper_backups"

    block_index = Column(Integer, primary_key=True, autoincrement=False)
    original_json = Column(Text, nullable=False)
    tampered_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class ChunkHash(Base):
    """64KB chunk hashes from Ajay's integrity engine."""
    __tablename__ = "chunk_hashes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(64), nullable=False, index=True)
    chunk_index = Column(Integer, nullable=False)
    offset = Column(Integer, nullable=False)
    length = Column(Integer, nullable=False)
    hash = Column(String(64), nullable=False)


class TrustedBaseline(Base):
    """An explicitly enrolled reference build of an application.

    Lifecycle: pending -> approved (signed) | rejected; approved -> revoked.
    Only approved baselines are used for comparison. Approval signs a canonical
    payload committing to the file-manifest Merkle root and the app profile hash,
    so later edits to this row are detectable (see core.baselines.verify_baseline).
    """
    __tablename__ = "trusted_baselines"
    __table_args__ = (
        UniqueConstraint("package_name", "baseline_version", name="uq_baseline_package_version"),
        CheckConstraint("status IN ('pending','approved','rejected','revoked')", name="ck_baseline_status"),
        Index("ix_baseline_package_status", "package_name", "status"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    package_name = Column(String(255), nullable=False)
    baseline_version = Column(Integer, nullable=False)          # 1, 2, 3... per package
    status = Column(String(16), nullable=False, default="pending")

    app_version_name = Column(String(128), nullable=True)
    app_version_code = Column(Integer, nullable=True)
    apk_sha256 = Column(String(64), nullable=False)
    apk_size = Column(Integer, nullable=False)
    certificate_sha256 = Column(String(64), nullable=False, index=True)

    file_count = Column(Integer, nullable=False)
    merkle_root = Column(String(64), nullable=False)
    files_json = Column(Text, nullable=False)                   # [{path, sha256, size, category}]
    profile_json = Column(Text, nullable=False)                 # permissions, components, certificate...
    profile_sha256 = Column(String(64), nullable=False)
    chunk_size = Column(Integer, nullable=False)
    chunk_hashes_json = Column(Text, nullable=False)            # supplementary forensics

    created_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    approved_by = Column(String(128), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approval_note = Column(Text, nullable=True)
    status_reason = Column(Text, nullable=True)                 # why rejected / revoked

    signature_json = Column(Text, nullable=True)                # {"alg","key_id","signature"}
    signing_key_id = Column(String(32), nullable=True)


class StaticReportModel(Base):
    """Static analysis findings from Ashwini's static engine."""
    __tablename__ = "static_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(64), nullable=False, unique=True, index=True)
    package_name = Column(String(255), nullable=True)
    version_name = Column(String(64), nullable=True)
    version_code = Column(Integer, nullable=True)
    min_sdk = Column(Integer, nullable=True)
    target_sdk = Column(Integer, nullable=True)
    report_json = Column(Text, nullable=False)


class TamperReportModel(Base):
    """Tamper analysis report from Ashwini's tamper engine."""
    __tablename__ = "tamper_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(64), nullable=False, unique=True, index=True)
    role = Column(String(32), nullable=False)  # baseline or comparison
    baseline_job_id = Column(String(64), nullable=True)
    certificate_changed = Column(Boolean, default=False)
    report_json = Column(Text, nullable=False)


class DynamicReportModel(Base):
    """Dynamic analysis report from Bhavish's dynamic engine."""
    __tablename__ = "dynamic_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(64), nullable=False, unique=True, index=True)
    installed = Column(Boolean, default=False)
    launched = Column(Boolean, default=False)
    duration_s = Column(Integer, default=0)
    report_json = Column(Text, nullable=False)
