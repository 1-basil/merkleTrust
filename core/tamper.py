"""core/tamper.py — ASHWINI.

Tamper Detection Engine: compares the analysed APK with the package's active,
*explicitly approved* trusted baseline.

  1. Look up the active approved baseline for the package (never auto-create one).
  2. Re-verify the baseline record (ECDSA approval signature, Merkle root
     recomputed from the stored file list, profile hash) — a tampered baseline
     is reported, not used.
  3. Compare per-file SHA-256 manifests, signing certificate, version and the
     manifest profile (core.comparison).
  4. For changed files, attach Merkle proofs: the baseline hash proves into the
     signed baseline root; the current hash does not.
  5. Emit suspicious_targets for the dynamic engine.

Integrity status: NO_BASELINE | BASELINE_INVALID | CLEAN | MODIFIED | CERTIFICATE_CHANGED
"""

from __future__ import annotations

import json
import sys
import tempfile
from contextlib import nullcontext
from typing import Any

from core.baselines import (BaselineService, baseline_snapshot, snapshot_from_reports, to_dict,
                            verify_baseline)
from core.comparison import compare_with_baseline
from core.contracts import JobContext, emit
from core.file_manifest import file_proof, verify_file_proof
from core.findings import finding
from db.database import session_scope

MAX_PROOFS = 25


def _empty_report(job_id: str, findings: list, status: str, role: str, **extra) -> dict[str, Any]:
    return {
        "job_id": job_id, "engine": "tamper", "status": "ok", "findings": findings,
        "role": role, "baseline_found": False, "baseline_id": None, "baseline": None,
        "baseline_verification": None,
        "integrity": {"status": status, "reasons": extra.pop("reasons", [])},
        "changed_files": [], "changed_chunks": [],
        "manifest_diff": {"permissions_added": [], "permissions_removed": [],
                          "components_added": [], "components_removed": []},
        "certificate_changed": False, "proofs": [], "suspicious_targets": [], **extra,
    }


def _proofs(baseline_files: list[dict], comparison: dict[str, Any], root: str) -> list[dict[str, Any]]:
    out = []
    for change in comparison["files"]["modified"] + comparison["files"]["deleted"]:
        if len(out) >= MAX_PROOFS:
            break
        p = file_proof(baseline_files, change["path"])
        entry = {"path": change["path"], "baseline_sha256": p["sha256"], "leaf_index": p["leaf_index"],
                 "proof": p["proof"], "root": root,
                 "baseline_hash_valid": verify_file_proof(change["path"], p["sha256"], p["proof"], root)}
        if change.get("current_sha256"):
            entry["current_sha256"] = change["current_sha256"]
            entry["current_hash_valid"] = verify_file_proof(change["path"], change["current_sha256"],
                                                            p["proof"], root)
        out.append(entry)
    return out


def _findings(cmp: dict[str, Any], baseline: dict[str, Any]) -> list[dict[str, str]]:
    f: list[dict[str, str]] = []
    files = cmp["files"]
    changed = files["modified"] + files["added"] + files["deleted"]
    by_cat = {}
    for c in changed:
        by_cat.setdefault(c["category"], []).append(c)

    if cmp["certificate"]["changed"]:
        f.append(finding("TAMPER_CERT_CHANGED", f"Baseline {cmp['certificate']['baseline_sha256'][:16]}… "
                          f"({cmp['certificate']['baseline_subject']}), current "
                          f"{(cmp['certificate']['current_sha256'] or 'none')[:16]}… "
                          f"({cmp['certificate']['current_subject']})"))
    # A change re-signed with the baseline's own key and a valid signature is the
    # developer's new release: report it, but do not treat "content changed" as risk.
    # Risk then comes only from what the update adds (permissions, APIs, flags...).
    authentic = not cmp["certificate"]["changed"] and cmp["signature_status"] == "verified"
    if authentic and changed:
        f.append(finding("TAMPER_SIGNED_UPDATE",
                         f"{len(changed)} file(s) changed ({', '.join(sorted(by_cat))}); version "
                         f"{cmp['version']['baseline']['name']} → {cmp['version']['current']['name']}"))
        by_cat = {}
    if "code" in by_cat:
        f.append(finding("TAMPER_DEX_MODIFIED", ", ".join(f"{c['path']} ({c['change_type']})" for c in by_cat["code"])))
    if "native" in by_cat:
        f.append(finding("TAMPER_NATIVE_MODIFIED", ", ".join(f"{c['path']} ({c['change_type']})" for c in by_cat["native"])))
    if "manifest" in by_cat:
        f.append(finding("TAMPER_MANIFEST_MODIFIED", "The app's declared configuration changed"))
    other = [c for cat, items in by_cat.items() if cat not in ("code", "native", "manifest") for c in items]
    if other:
        f.append(finding("TAMPER_FILES_CHANGED", ", ".join(f"{c['path']} ({c['change_type']})" for c in other[:10])))

    md = cmp["manifest_diff"]
    if md["permissions_added"]:
        f.append(finding("TAMPER_PERMISSIONS_ADDED", ", ".join(md["permissions_added"])))
    if md["components_added"]:
        f.append(finding("TAMPER_COMPONENTS_ADDED", ", ".join(md["components_added"])))
    if md["newly_exported_components"]:
        f.append(finding("TAMPER_NEWLY_EXPORTED", ", ".join(md["newly_exported_components"])))
    for flag in md["flags_changed"]:
        if flag["flag"] == "debuggable" and flag["current"]:
            f.append(finding("TAMPER_DEBUGGABLE_ENABLED", "android:debuggable is now true"))
    if md["dangerous_apis_added"]:
        f.append(finding("TAMPER_DANGEROUS_API_ADDED", ", ".join(md["dangerous_apis_added"])))
    if cmp["version"]["downgrade"]:
        f.append(finding("TAMPER_VERSION_DOWNGRADE", f"{cmp['version']['baseline']['code']} → {cmp['version']['current']['code']}"))
    if cmp["status"] == "CLEAN":
        f.append(finding("TAMPER_INTEGRITY_VERIFIED", f"Baseline #{baseline['id']} v{baseline['baseline_version']} "
                          f"({cmp['counts']['unchanged']} files identical)"))
    return f


def _suspicious_targets(cmp: dict[str, Any], static: dict[str, Any]) -> list[dict[str, str]]:
    targets, seen = [], set()

    def add(kind: str, value: str, reason: str) -> None:
        if value and value not in seen:
            seen.add(value)
            targets.append({"type": kind, "value": value, "reason": reason})

    code_changed = any(c["category"] == "code" for c in cmp["files"]["modified"] + cmp["files"]["added"])
    if code_changed:
        for api in static.get("dangerous_apis", []):
            add("class", api.get("class", ""), f"Sensitive API {api.get('api')} in modified code")
    for comp in cmp["manifest_diff"]["components_added"]:
        add("service" if "service" in comp.lower() else "class", comp, "Component added vs baseline")
    for url in cmp["manifest_diff"]["network_urls_added"]:
        add("url", url, "Network endpoint not present in baseline")
    return targets


def compare_reports(job_id: str, integrity: dict[str, Any], static: dict[str, Any], db) -> dict[str, Any]:
    package = static.get("package_name") or "unknown.package"
    service = BaselineService(db)
    row = service.get_active(package)
    if row is None:
        return _empty_report(job_id, [finding("TAMPER_NO_BASELINE", f"Package {package} has no approved baseline, so changes cannot be determined. "
            f"An administrator can enrol a trusted build.")], "NO_BASELINE", "no_baseline",
            reasons=["No approved baseline exists for this package."])

    baseline = to_dict(row)
    verification = verify_baseline(row, service.keyring)
    if not verification["valid"]:
        return _empty_report(job_id, [finding("TAMPER_BASELINE_INVALID", "; ".join(verification["reasons"]))], "BASELINE_INVALID", "comparison",
            baseline_found=True, baseline_id=row.id, baseline=baseline, baseline_verification=verification,
            reasons=["The stored baseline could not be verified, so it was not used."])

    base_snap = baseline_snapshot(row)
    cmp = compare_with_baseline(base_snap, snapshot_from_reports(integrity, static))
    files = cmp["files"]
    changed_files = files["modified"] + files["added"] + files["deleted"] + files["signature_files_changed"]
    return {
        "job_id": job_id, "engine": "tamper", "status": "ok",
        "findings": _findings(cmp, baseline),
        "role": "comparison",
        "baseline_found": True,
        "baseline_id": row.id,
        "baseline": baseline,
        "baseline_verification": verification,
        "integrity": cmp,
        "changed_files": changed_files,
        "changed_chunks": cmp["chunks"].get("changed_indices", []),
        "manifest_diff": cmp["manifest_diff"],
        "certificate_changed": cmp["certificate"]["changed"],
        "proofs": _proofs(base_snap["files"], cmp, row.merkle_root),
        "suspicious_targets": _suspicious_targets(cmp, static),
    }


def run(job_id: str, ctx: JobContext) -> dict:
    """Execute tamper analysis against the active trusted baseline."""
    integrity, static = ctx.prior.get("integrity"), ctx.prior.get("static")
    if not integrity or not static:
        report = _empty_report(job_id, [finding("TAMPER_MISSING_INPUT", f"Available reports: {sorted(ctx.prior)}")], "UNKNOWN", "skipped")
        report["status"] = "partial"
        return emit(ctx, "tamper.json", report)

    scope = nullcontext(ctx.db) if ctx.db is not None else session_scope()
    with scope as db:
        report = compare_reports(job_id, integrity, static, db)
    return emit(ctx, "tamper.json", report)


if __name__ == "__main__":
    prior = json.load(open(sys.argv[1], encoding="utf-8")) if len(sys.argv) > 1 else {}
    ctx = JobContext(apk_path="", workspace=tempfile.mkdtemp(prefix="mt_tamper_"), prior=prior, config={})
    print(json.dumps(run("local-tamper-test", ctx), indent=2))
