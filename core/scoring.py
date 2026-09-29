"""core/scoring.py — BASIL.

Trust Score Engine for MerkleTrust.
Reads findings from all engines plus named critical fields to compute an aggregate
trust score (0–100) and security verdict (trusted | suspicious | malicious).
Records hashes of all engine inputs for cryptographic provenance.
"""

import sys
import json
import hashlib
import tempfile
from typing import Any

from core.contracts import JobContext, emit

SEVERITY_WEIGHT = {
    "info": 0,
    "low": -3,
    "medium": -8,
    "high": -18,
    "critical": -35,
}


def run(job_id: str, ctx: JobContext) -> dict:
    score = 100
    rules: list[dict[str, Any]] = []

    # 1. Evaluate findings from all upstream engines
    for engine, report in ctx.prior.items():
        for f in report.get("findings", []):
            severity = f.get("severity", "info")
            w = SEVERITY_WEIGHT.get(severity, 0)
            if w != 0:
                score += w
                rules.append({
                    "rule_id": f.get("id", "UNKNOWN"),
                    "weight": w,
                    "source": engine,
                    "reason": f.get("title", ""),
                })

    # 2. Named field rules
    tamper = ctx.prior.get("tamper", {})
    if tamper.get("certificate_changed"):
        score -= 40
        rules.append({
            "rule_id": "R_CERT_CHANGED",
            "weight": -40,
            "source": "tamper",
            "reason": "Signing certificate differs from trusted baseline",
        })

    changed_files = tamper.get("changed_files", [])
    if changed_files:
        dex_changed = any("classes" in f.get("path", "") for f in changed_files)
        penalty = -25 if dex_changed else -15
        score += penalty
        rules.append({
            "rule_id": "R_FILES_MODIFIED",
            "weight": penalty,
            "source": "tamper",
            "reason": f"Detected {len(changed_files)} tampered file(s) against baseline" + (" (DEX modified)" if dex_changed else ""),
        })

    static = ctx.prior.get("static", {})
    cert_info = static.get("certificate", {})
    if cert_info.get("self_signed"):
        score -= 10
        rules.append({
            "rule_id": "R_SELF_SIGNED_CERT",
            "weight": -10,
            "source": "static",
            "reason": "Application is signed with a self-signed certificate",
        })

    # 3. Provenance hashes of upstream inputs
    inputs = {}
    for eng in ("integrity", "static", "tamper", "dynamic"):
        rep = ctx.prior.get(eng, {})
        canonical = json.dumps(rep, sort_keys=True, separators=(",", ":"))
        inputs[f"{eng}_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    score = max(0, min(100, score))
    verdict = "trusted" if score >= 70 else "suspicious" if score >= 40 else "malicious"

    report = {
        "job_id": job_id,
        "engine": "score",
        "status": "ok",
        "findings": [],
        "score": score,
        "verdict": verdict,
        "rules_fired": rules,
        "inputs": inputs,
    }

    return emit(ctx, "score.json", report)


if __name__ == "__main__":
    prior = json.load(open(sys.argv[1], encoding="utf-8")) if len(sys.argv) > 1 else {}
    ctx = JobContext(apk_path="", workspace=tempfile.mkdtemp(prefix="mt_"), prior=prior, config={})
    print(json.dumps(run("local-test", ctx), indent=2))
