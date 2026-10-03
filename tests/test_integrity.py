"""tests/test_integrity.py — Tests for Ajay's Integrity Engine."""

import os
import tempfile
import hashlib
import pytest

from core.integrity import compute_chunks, extract_file_map, run
from core.contracts import JobContext

pytestmark = pytest.mark.unit


def test_compute_chunks():
    # 130KB data with 64KB chunk size -> 3 chunks
    data = b"A" * 65536 + b"B" * 65536 + b"C" * 1000
    chunks = compute_chunks(data, chunk_size=65536)

    assert len(chunks) == 3
    assert chunks[0]["index"] == 0
    assert chunks[0]["offset"] == 0
    assert chunks[0]["length"] == 65536
    assert chunks[0]["hash"] == hashlib.sha256(b"A" * 65536).hexdigest()

    assert chunks[1]["index"] == 1
    assert chunks[1]["offset"] == 65536
    assert chunks[1]["length"] == 65536
    assert chunks[1]["hash"] == hashlib.sha256(b"B" * 65536).hexdigest()

    assert chunks[2]["index"] == 2
    assert chunks[2]["offset"] == 131072
    assert chunks[2]["length"] == 1000
    assert chunks[2]["hash"] == hashlib.sha256(b"C" * 1000).hexdigest()


def test_extract_file_map(fixture_apk):
    sample_path = fixture_apk("signed_v1v2_ec.apk")

    file_map = extract_file_map(sample_path)
    assert len(file_map) > 0

    paths = [f["path"] for f in file_map]
    assert "AndroidManifest.xml" in paths
    assert "classes.dex" in paths

    for f in file_map:
        assert "offset" in f
        assert "length" in f
        assert f["length"] > 0
        assert "sha256" in f
        assert len(f["sha256"]) == 64


def test_integrity_run(fixture_apk):
    sample_path = fixture_apk("signed_v1v2_ec.apk")

    workspace = tempfile.mkdtemp(prefix="mt_test_integ_")
    ctx = JobContext(apk_path=sample_path, workspace=workspace, prior={}, config={"chunk_size": 65536})

    report = run("job-test-integrity", ctx)

    assert report["engine"] == "integrity"
    assert report["status"] == "ok"
    assert report["file_size"] > 0
    assert len(report["chunks"]) > 0
    assert len(report["merkle_root"]) == 64
    assert len(report["file_map"]) > 0
    assert os.path.exists(ctx.out("integrity.json"))
