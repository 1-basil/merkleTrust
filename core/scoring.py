"""core/scoring.py — BASIL.

Reads every findings[] plus a few named fields. Never looks inside an engine.
"""

import sys
import json
import tempfile

from core.contracts import JobContext, emit

SEVERITY_WEIGHT = {"info": 0, "low": -3, "medium": -8, "high": -18, "critical": -35}


def run(job_id: str, ctx: JobContext) -> dict:
    score = 100
    rules = []

    for engine, report in ctx.prior.items():
        for f in report.get("findings", []):
            w = SEVERITY_WEIGHT.get(f.get("severity", "info"), 0)
            if w:
                score += w
                rules.append({
                    "rule_id": f.get("id", "UNKNOWN"),
                    "weight": w,
                    "source": engine,
                    "reason": f.get("title", ""),
                })

    tamper = ctx.prior.get("tamper", {})
    if tamper.get("certificate_changed"):
        score -= 40
        rules.append({"rule_id": "R_CERT_CHANGED", "weight": -40, "source": "tamper",
                      "reason": "Signing certificate differs from trusted baseline"})

    score = max(0, min(100, score))
    verdict = "trusted" if score >= 70 else "suspicious" if score >= 40 else "malicious"

    return emit(ctx, "score.json", {
        "job_id": job_id,
        "engine": "score",
        "status": "ok",
        "findings": [],
        "score": score,
        "verdict": verdict,
        "rules_fired": rules,
    })


if __name__ == "__main__":
    prior = json.load(open(sys.argv[1], encoding="utf-8")) if len(sys.argv) > 1 else {}
    ctx = JobContext(apk_path="", workspace=tempfile.mkdtemp(prefix="mt_"), prior=prior, config={})
    print(json.dumps(run("local-test", ctx), indent=2))
