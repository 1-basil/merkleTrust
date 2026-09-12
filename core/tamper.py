"""core/tamper.py — ASHWINI.

Runs after integrity + static. Does NOT touch the APK file.

TODO for Ashwini:
  1. key = (static.package_name, static.certificate.sha256)
  2. look that key up in your `baselines` table
  3. no baseline -> insert this job as the baseline, return role="baseline"
     with every changed_* list empty and suspicious_targets empty
  4. baseline found -> compare merkle roots; if equal, nothing changed.
     else use merkle.compare_trees() to get changed chunk indices,
     then intersect each chunk's [offset, offset+length) with
     integrity.file_map to name the changed files
  5. diff the baseline's static.json against this one:
     permissions added/removed, components added/removed, cert changed
  6. build suspicious_targets — this is the ONLY thing Bhavish reads
"""

import sys
import json
import tempfile

from core.contracts import JobContext, emit


def run(job_id: str, ctx: JobContext) -> dict:
    integrity = ctx.prior.get("integrity", {})
    static = ctx.prior.get("static", {})

    findings = []
    if not integrity or not static:
        findings.append({
            "id": "TAMPER_MISSING_INPUT",
            "severity": "medium",
            "title": "Ran without integrity or static report",
            "evidence": f"prior keys: {sorted(ctx.prior)}",
        })

    # TODO(ashwini): baseline lookup + merkle diff + manifest diff
    report = {
        "job_id": job_id,
        "engine": "tamper",
        "status": "partial",
        "findings": findings or [{
            "id": "TAMPER_STUB",
            "severity": "info",
            "title": "Tamper detection not implemented yet",
            "evidence": f"package {static.get('package_name', '?')}",
        }],
        "role": "baseline",
        "baseline_found": False,
        "baseline_job_id": None,
        "changed_chunks": [],
        "changed_files": [],
        "manifest_diff": {
            "permissions_added": [],
            "permissions_removed": [],
            "components_added": [],
            "components_removed": [],
        },
        "certificate_changed": False,
        "suspicious_targets": [],
    }
    return emit(ctx, "tamper.json", report)


if __name__ == "__main__":
    apk = sys.argv[1]
    prior = json.load(open(sys.argv[2], encoding="utf-8")) if len(sys.argv) > 2 else {}
    ctx = JobContext(apk_path=apk, workspace=tempfile.mkdtemp(prefix="mt_"),
                     prior=prior, config={})
    print(json.dumps(run("local-test", ctx), indent=2))
