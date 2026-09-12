"""core/orchestrator.py — BASIL.

The integration test. Runs the whole pipeline on one APK with whatever
engines exist. Works today with stubs, works unchanged when they are real.

    python -m core.orchestrator path\\to\\app.apk
"""

import os
import sys
import json
import uuid
import hashlib
import traceback

from core.contracts import JobContext, EngineError
from core import integrity, static, tamper, dynamic, scoring, repository

CONFIG = {
    "chunk_size": 65536,
    "apktool": "apktool",
    "jadx": "jadx",
    "emulator_avd": "mt_api30_root",
    "dynamic_timeout_s": 90,
}

STAGES = [
    ("integrity", integrity.run),
    ("static", static.run),
    ("tamper", tamper.run),
    ("dynamic", dynamic.run),
    ("score", scoring.run),
    ("repository", repository.run),
]


def run_job(apk_path: str, root: str = "jobs") -> dict:
    job_id = str(uuid.uuid4())
    workspace = os.path.join(root, job_id)
    os.makedirs(workspace, exist_ok=True)

    with open(apk_path, "rb") as fh:
        sha = hashlib.sha256(fh.read()).hexdigest()
    print(f"job {job_id}\nsha256 {sha}\nworkspace {workspace}\n")

    prior: dict = {}
    status: dict = {}

    for name, fn in STAGES:
        ctx = JobContext(apk_path=apk_path, workspace=workspace, prior=dict(prior), config=CONFIG)
        try:
            report = fn(job_id, ctx)
            prior[name] = report
            status[name] = report.get("status", "ok")
            print(f"  {name:<11} {status[name]}")
        except EngineError as exc:
            status[name] = "failed"
            print(f"  {name:<11} failed: {exc}")
        except Exception:
            status[name] = "failed"
            print(f"  {name:<11} crashed")
            traceback.print_exc()

    with open(os.path.join(workspace, "merged.json"), "w", encoding="utf-8") as fh:
        json.dump({"job_id": job_id, "sha256": sha, "status": status, "reports": prior},
                  fh, indent=2, sort_keys=True)

    score = prior.get("score", {})
    print(f"\nverdict: {score.get('verdict', 'n/a')}  score: {score.get('score', 'n/a')}")
    return prior


if __name__ == "__main__":
    run_job(sys.argv[1])
