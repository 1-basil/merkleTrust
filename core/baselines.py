"""core/baselines.py — Baseline Storage & Lookup for MerkleTrust.

Handles baseline persistence and retrieval across database (SQLAlchemy)
and local fallback storage (JSON/SQLite).
"""

import os
import json
from typing import Any


class BaselineStore:
    """Manages baseline APK profiles for tamper detection."""

    def __init__(self, db_session: Any = None, storage_path: str = "data/baselines.json"):
        self.db = db_session
        self.storage_path = storage_path
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        if not self.db:
            dirname = os.path.dirname(self.storage_path)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            if not os.path.exists(self.storage_path):
                try:
                    with open(self.storage_path, "w", encoding="utf-8") as f:
                        json.dump({}, f)
                except Exception:
                    pass

    def get_baseline(self, package_name: str, cert_sha256: str = "") -> dict[str, Any] | None:
        """Find baseline profile for a package name (and optionally certificate)."""
        if not package_name:
            return None

        # 1. If SQLAlchemy DB session is available, try querying DB
        if self.db:
            try:
                # Query baselines table if mapped
                from sqlalchemy import text
                stmt = text("SELECT job_id, package_name, cert_sha256, merkle_root, chunk_hashes, file_map, static_data FROM baselines WHERE package_name = :pkg ORDER BY id DESC LIMIT 1")
                row = self.db.execute(stmt, {"pkg": package_name}).fetchone()
                if row:
                    return {
                        "job_id": row[0],
                        "package_name": row[1],
                        "cert_sha256": row[2],
                        "merkle_root": row[3],
                        "chunk_hashes": json.loads(row[4]) if isinstance(row[4], str) else row[4],
                        "file_map": json.loads(row[5]) if isinstance(row[5], str) else row[5],
                        "static_data": json.loads(row[6]) if isinstance(row[6], str) else row[6],
                    }
            except Exception:
                pass  # Fall back to file storage

        # 2. Local file-based baseline store
        try:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return data.get(package_name)
        except Exception:
            pass

        return None

    def save_baseline(
        self,
        job_id: str,
        package_name: str,
        cert_sha256: str,
        merkle_root: str,
        chunks: list[dict],
        file_map: list[dict],
        static_report: dict,
    ) -> None:
        """Persist a new baseline profile for a package."""
        if not package_name:
            return

        baseline_record = {
            "job_id": job_id,
            "package_name": package_name,
            "cert_sha256": cert_sha256,
            "merkle_root": merkle_root,
            "chunks": chunks,
            "file_map": file_map,
            "static_data": static_report,
        }

        # 1. Save to DB if session available
        if self.db:
            try:
                from sqlalchemy import text
                stmt = text(
                    """
                    INSERT INTO baselines (job_id, package_name, cert_sha256, merkle_root, chunk_hashes, file_map, static_data)
                    VALUES (:job_id, :pkg, :cert, :root, :chunks, :fmap, :sdata)
                    """
                )
                self.db.execute(stmt, {
                    "job_id": job_id,
                    "pkg": package_name,
                    "cert": cert_sha256,
                    "root": merkle_root,
                    "chunks": json.dumps(chunks),
                    "fmap": json.dumps(file_map),
                    "sdata": json.dumps(static_report),
                })
                self.db.commit()
            except Exception:
                pass

        # 2. Save to local fallback file
        try:
            current = {}
            if os.path.exists(self.storage_path):
                try:
                    with open(self.storage_path, "r", encoding="utf-8") as f:
                        current = json.load(f)
                except Exception:
                    current = {}

            current[package_name] = baseline_record
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(current, f, indent=2)
        except Exception:
            pass
