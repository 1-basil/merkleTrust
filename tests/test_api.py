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
    assert "total_entries" in data
    assert "entries" in data


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
    res = client.post("/api/tamper-demo?corrupt_byte=true")
    # If ledger has entries, it returns 200 with break detected
    if res.status_code == 200:
        data = res.json()
        assert data["tamper_applied"] is True
        assert data["chain_intact"] is False
        assert data["break_detected_at_index"] >= 0
    else:
        assert res.status_code == 400
