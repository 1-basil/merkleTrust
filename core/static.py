"""core/static.py — Ashwini. Stub that returns fake data but runs today."""

import sys
import json
import tempfile
import hashlib

from core.contracts import JobContext, emit


def run(job_id: str, ctx: JobContext) -> dict:
    with open(ctx.apk_path, "rb") as fh:
        size = len(fh.read())

    report = {
        "job_id": job_id,
        "engine": "static",
        "status": "partial",
        "findings": [
            {
                "id": "STATIC_STUB",
                "severity": "info",
                "title": "Static engine not implemented yet",
                "evidence": f"apk size {size} bytes",
            }
        ],
        "package_name": "com.example.stub",
        "version_name": "0.0.0",
        "version_code": 0,
        "min_sdk": 0,
        "target_sdk": 0,
        "permissions": [],
        "components": {"activities": [], "services": [], "receivers": [], "providers": []},
        "certificate": {"sha256": "", "issuer": "", "subject": "", "self_signed": False, "schemes": []},
        "native_libs": [],
        "iocs": {"urls": [], "ips": [], "domains": []},
        "dangerous_apis": [],
        "artifacts": {"apktool_dir": "static/apktool", "jadx_dir": "static/jadx"},
    }
    return emit(ctx, "static.json", report)


if __name__ == "__main__":
    apk = sys.argv[1]
    prior = json.load(open(sys.argv[2], encoding="utf-8")) if len(sys.argv) > 2 else {}
    ws = tempfile.mkdtemp(prefix="mt_")
    ctx = JobContext(apk_path=apk, workspace=ws, prior=prior, config={"chunk_size": 65536})
    job_id = hashlib.sha1(apk.encode()).hexdigest()[:12]
    print(json.dumps(run(job_id, ctx), indent=2))
    print("\nwrote:", ctx.out("static.json"))
