"""tests/test_api.py — Integration tests for MerkleTrust FastAPI REST API."""

import pytest
from fastapi.testclient import TestClient

from api.main import app
from db.database import init_db

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()


def test_get_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "MerkleTrust" in response.text


def test_get_repository():
    response = client.get("/api/repository")
    assert response.status_code == 200
    data = response.json()
    assert "total_blocks" in data
    assert "blocks" in data and "chain" in data


def test_upload_sample_and_job_lifecycle():
    # 1. Trigger upload
    upload_res = client.post("/api/upload-sample")
    assert upload_res.status_code == 200
    upload_data = upload_res.json()
    job_id = upload_data["job_id"]
    assert job_id is not None
    assert upload_data["status"] == "pending"

    # 2. Query status
    status_res = client.get(f"/api/jobs/{job_id}")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["job_id"] == job_id
    assert "engine_status" in status_data

    # 3. Query report endpoint
    report_res = client.get(f"/api/jobs/{job_id}/report")
    assert report_res.status_code == 200


def test_tamper_demo_endpoint():
    res = client.post("/api/tamper-demo")
    if res.status_code == 200:
        data = res.json()
        assert data["chain_intact"] is False
        assert data["break_detected_at_index"] == data["target_block_index"]
        # the demonstration works on a copy: the stored chain is still intact
        assert client.get("/api/repository").json()["chain"]["valid"] is True
    else:
        assert res.status_code == 400


def test_job_report_verification_end_to_end():
    """Regression: /verify used to report every job invalid. Valid now — until the report is edited."""
    import json
    import os
    from api.main import JOBS_DIR

    job_id = client.post("/api/upload-sample").json()["job_id"]
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "done"
    ok = client.get(f"/api/jobs/{job_id}/verify").json()
    assert ok["valid"] is True, ok["reasons"]

    merged = os.path.join(JOBS_DIR, job_id, "merged.json")
    data = json.load(open(merged, encoding="utf-8"))
    data["reports"]["score"]["verdict"]["code"] = "CLEAN"
    json.dump(data, open(merged, "w", encoding="utf-8"))
    bad = client.get(f"/api/jobs/{job_id}/verify").json()
    assert bad["valid"] is False and bad["checks"]["report_hash_matches"] is False
