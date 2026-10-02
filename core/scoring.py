"""core/scoring.py — BASIL.

Turns the engine reports into three separate answers:

1. **Integrity** — "Is this the same app as the trusted baseline?"
   Taken verbatim from the tamper engine:
   NO_BASELINE | BASELINE_INVALID | CLEAN | MODIFIED | CERTIFICATE_CHANGED | UNKNOWN.

2. **Risk** — "Does this app have suspicious or dangerous characteristics?"
   A 0–100 indicator built from catalogued findings (core/findings.py):
     * each finding contributes its documented points;
     * findings sharing a ``group`` describe the same fact — only the highest
       counts, the others are listed as "already counted" (no double counting);
     * the total is capped at 100.
   Level: LOW < 20 <= MEDIUM < 45 <= HIGH < 70 <= CRITICAL. A critical-severity
   finding raises the level to at least HIGH.
   This is a transparent heuristic indicator, NOT a probability of malware.

3. **Verdict** — one headline for non-specialists, derived from 1 and 2 with
   a fixed precedence (analysis failed > high risk > changes > no baseline >
   review > clean).

If the core analysis (integrity/static) failed, risk is UNKNOWN and the verdict
is ANALYSIS_FAILED — an unanalysable file is never reported as safe.
"""

from __future__ import annotations

import json
import sys
import tempfile
from typing import Any

from core.contracts import JobContext, emit
from core.crypto import hash_payload
from core.findings import normalize

LEVELS = [(70, "CRITICAL"), (45, "HIGH"), (20, "MEDIUM"), (0, "LOW")]
LEVEL_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
REQUIRED_ENGINES = ("integrity", "static")
INTEGRITY_CHANGED = {"MODIFIED", "CERTIFICATE_CHANGED", "BASELINE_INVALID"}

VERDICTS = {
    "ANALYSIS_FAILED": ("Could not be analysed",
                        "The file could not be analysed, so no safety statement can be made."),
    "HIGH_RISK": ("High risk",
                  "The app shows serious security concerns. Do not install it until they are explained."),
    "CHANGES_DETECTED": ("Changes detected",
                         "This app is not identical to the trusted version."),
    "NO_BASELINE": ("Not verified",
                    "There is no trusted version of this app to compare with, so changes cannot be ruled out."),
    "REVIEW": ("Review recommended",
               "The app matches its trusted version but has some security concerns worth reviewing."),
    "CLEAN": ("Clean",
              "The app matches its trusted version and no significant security concerns were found."),
}


def risk_level(score: int, findings: list[dict[str, Any]]) -> str:
    level = next(name for threshold, name in LEVELS if score >= threshold)
    if any(f["severity"] == "critical" and f["points"] > 0 for f in findings):
        level = max(level, "HIGH", key=LEVEL_ORDER.index)
    return level


def score_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Group-deduplicated risk score with a line-by-line explanation."""
    best: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f["points"] <= 0:
            continue
        cur = best.get(f["group"])
        if cur is None or f["points"] > cur["points"]:
            best[f["group"]] = f
    counted = sorted(best.values(), key=lambda f: -f["points"])
    counted_ids = {id(f) for f in counted}
    suppressed = [{"finding_id": f["id"], "source": f["source"], "points": f["points"],
                   "counted_as": best[f["group"]]["id"]}
                  for f in findings if f["points"] > 0 and id(f) not in counted_ids]
    raw = sum(f["points"] for f in counted)
    score = min(100, raw)
    return {
        "score": score,
        "raw_points": raw,
        "level": risk_level(score, findings),
        "contributions": [{"finding_id": f["id"], "title": f["title"], "severity": f["severity"],
                           "points": f["points"], "source": f["source"], "group": f["group"]} for f in counted],
        "suppressed_duplicates": suppressed,
    }


def decide_verdict(analysis_complete: bool, integrity_status: str, level: str) -> str:
    if not analysis_complete:
        return "ANALYSIS_FAILED"
    if level in ("HIGH", "CRITICAL"):
        return "HIGH_RISK"
    if integrity_status in INTEGRITY_CHANGED:
        return "CHANGES_DETECTED"
    if integrity_status in ("NO_BASELINE", "UNKNOWN"):
        return "NO_BASELINE"
    if level == "MEDIUM":
        return "REVIEW"
    return "CLEAN"


def run(job_id: str, ctx: JobContext) -> dict:
    prior = ctx.prior
    missing = [e for e in REQUIRED_ENGINES if e not in prior]
    analysis_complete = not missing

    findings = [normalize(f, engine) for engine, report in prior.items()
                for f in report.get("findings", [])]
    integrity = (prior.get("tamper") or {}).get("integrity") or {}
    integrity_status = integrity.get("status", "UNKNOWN")

    if analysis_complete:
        risk = score_findings(findings)
    else:
        risk = {"score": None, "raw_points": None, "level": "UNKNOWN", "contributions": [],
                "suppressed_duplicates": []}
    verdict = decide_verdict(analysis_complete, integrity_status, risk["level"])
    headline, summary = VERDICTS[verdict]

    dynamic = prior.get("dynamic") or {}
    notes = []
    if missing:
        notes.append(f"Analysis stage(s) failed: {', '.join(missing)}.")
    if dynamic.get("status") != "ok":
        notes.append("Emulator-based (dynamic) analysis did not run; results are from static analysis only.")

    report = {
        "job_id": job_id,
        "engine": "score",
        "status": "ok" if analysis_complete else "partial",
        "findings": [],
        "analysis_complete": analysis_complete,
        "missing_engines": missing,
        "integrity": {"status": integrity_status, "reasons": integrity.get("reasons", [])},
        "risk": risk,
        "verdict": {"code": verdict, "headline": headline, "summary": summary},
        "all_findings": sorted(findings, key=lambda f: (-["info", "low", "medium", "high", "critical"]
                                                       .index(f["severity"]), -f["points"])),
        "notes": notes,
        "disclaimer": "The risk score is a heuristic indicator of security concerns, not a probability of malware.",
        # Provenance: hashes of the exact engine reports this assessment was derived from.
        "inputs": {f"{e}_sha256": hash_payload(prior[e]) for e in ("integrity", "static", "tamper", "dynamic")
                   if e in prior},
    }
    return emit(ctx, "score.json", report)


if __name__ == "__main__":
    prior = json.load(open(sys.argv[1], encoding="utf-8")) if len(sys.argv) > 1 else {}
    ctx = JobContext(apk_path="", workspace=tempfile.mkdtemp(prefix="mt_"), prior=prior, config={})
    print(json.dumps(run("local-test", ctx), indent=2))
