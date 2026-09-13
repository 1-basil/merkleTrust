"""core/tamper.py — ASHWINI.

Tamper Detection Engine for MerkleTrust.
Runs after integrity + static.
Compares Merkle trees, chunk hashes, and static profiles against baseline.
Localizes changed byte chunks to specific files and outputs suspicious_targets
for Bhavish's dynamic analysis engine.
"""

import sys
import json
import tempfile
from typing import Any

from core.contracts import JobContext, emit
from core.merkle import compare_trees
from core.baselines import BaselineStore


def _extract_all_components(components_dict: dict[str, list[str]]) -> set[str]:
    """Flatten all activities, services, receivers, and providers into a set."""
    comps = set()
    for cat in ("activities", "services", "receivers", "providers"):
        for item in components_dict.get(cat, []):
            if isinstance(item, str):
                comps.add(item)
            elif isinstance(item, dict) and "name" in item:
                comps.add(item["name"])
    return comps


def run(job_id: str, ctx: JobContext) -> dict:
    """Execute tamper analysis and baseline comparison."""
    integrity = ctx.prior.get("integrity", {})
    static = ctx.prior.get("static", {})

    findings: list[dict[str, Any]] = []

    if not integrity or not static:
        findings.append({
            "id": "TAMPER_MISSING_INPUT",
            "severity": "medium",
            "title": "Ran with incomplete prior engine reports",
            "evidence": f"Prior keys available: {sorted(ctx.prior.keys())}",
        })

    package_name = static.get("package_name") or "unknown.package"
    curr_cert_info = static.get("certificate", {})
    curr_cert_sha = curr_cert_info.get("sha256", "")
    merkle_root = integrity.get("merkle_root", "")
    chunks = integrity.get("chunks", [])
    file_map = integrity.get("file_map", [])

    # Initialize baseline store
    baseline_path = ctx.config.get("baseline_storage_path", "data/baselines.json")
    baseline_store = BaselineStore(db_session=ctx.db, storage_path=baseline_path)
    baseline = baseline_store.get_baseline(package_name, curr_cert_sha)

    # 1. No baseline found -> Register as baseline
    if not baseline:
        baseline_store.save_baseline(
            job_id=job_id,
            package_name=package_name,
            cert_sha256=curr_cert_sha,
            merkle_root=merkle_root,
            chunks=chunks,
            file_map=file_map,
            static_report=static,
        )

        findings.append({
            "id": "TAMPER_BASELINE_SAVED",
            "severity": "info",
            "title": "Initial build established as trusted baseline",
            "evidence": f"Package {package_name} recorded with Merkle root {merkle_root[:16]}...",
        })

        report = {
            "job_id": job_id,
            "engine": "tamper",
            "status": "ok",
            "findings": findings,
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

    # 2. Baseline found -> Perform comparison
    baseline_job_id = baseline.get("job_id")
    base_chunks = baseline.get("chunks", [])
    base_file_map = baseline.get("file_map", [])
    base_static = baseline.get("static_data", {})
    base_cert_sha = baseline.get("cert_sha256") or base_static.get("certificate", {}).get("sha256", "")

    # Compare chunk hashes
    curr_chunk_hashes = [c.get("hash", "") for c in chunks]
    base_chunk_hashes = [c.get("hash", "") for c in base_chunks]

    changed_chunk_indices = compare_trees(base_chunk_hashes, curr_chunk_hashes)
    changed_chunks: list[dict[str, Any]] = []

    for idx in changed_chunk_indices:
        old_h = base_chunk_hashes[idx] if idx < len(base_chunk_hashes) else "none"
        new_h = curr_chunk_hashes[idx] if idx < len(curr_chunk_hashes) else "none"
        changed_chunks.append({
            "index": idx,
            "old_hash": old_h,
            "new_hash": new_h,
        })

    # Map changed chunks to files using integrity.file_map
    changed_files_map: dict[str, dict[str, Any]] = {}

    # Check modified files via byte-range intersection
    for c_info in changed_chunks:
        idx = c_info["index"]
        if idx < len(chunks):
            chunk = chunks[idx]
            c_start = chunk.get("offset", 0)
            c_end = c_start + chunk.get("length", 0)

            for f_entry in file_map:
                f_path = f_entry.get("path", "")
                f_start = f_entry.get("offset", 0)
                f_end = f_start + f_entry.get("length", 0)

                # Overlap test: max(start1, start2) < min(end1, end2)
                if max(c_start, f_start) < min(c_end, f_end):
                    if f_path not in changed_files_map:
                        changed_files_map[f_path] = {
                            "path": f_path,
                            "change_type": "modified",
                            "chunks": [],
                        }
                    if idx not in changed_files_map[f_path]["chunks"]:
                        changed_files_map[f_path]["chunks"].append(idx)

    # Check added and removed files
    curr_paths = {f.get("path") for f in file_map if f.get("path")}
    base_paths = {f.get("path") for f in base_file_map if f.get("path")}

    for added_p in (curr_paths - base_paths):
        if added_p not in changed_files_map:
            changed_files_map[added_p] = {
                "path": added_p,
                "change_type": "added",
                "chunks": [],
            }

    for rem_p in (base_paths - curr_paths):
        if rem_p not in changed_files_map:
            changed_files_map[rem_p] = {
                "path": rem_p,
                "change_type": "removed",
                "chunks": [],
            }

    changed_files = list(changed_files_map.values())

    # Diff permissions
    curr_perms = {
        p["name"] if isinstance(p, dict) else p
        for p in static.get("permissions", [])
    }
    base_perms = {
        p["name"] if isinstance(p, dict) else p
        for p in base_static.get("permissions", [])
    }
    permissions_added = sorted(curr_perms - base_perms)
    permissions_removed = sorted(base_perms - curr_perms)

    # Diff components
    curr_comps = _extract_all_components(static.get("components", {}))
    base_comps = _extract_all_components(base_static.get("components", {}))
    components_added = sorted(curr_comps - base_comps)
    components_removed = sorted(base_comps - curr_comps)

    # Certificate changed check
    certificate_changed = bool(base_cert_sha and curr_cert_sha and base_cert_sha != curr_cert_sha)

    # Build suspicious_targets for Bhavish's Dynamic engine
    suspicious_targets: list[dict[str, str]] = []
    seen_targets = set()

    # 1. New or modified classes/APIs in changed DEX files
    dex_changed = any(f["path"].endswith(".dex") for f in changed_files)
    if dex_changed:
        for api in static.get("dangerous_apis", []):
            cls_name = api.get("class", "")
            if cls_name and cls_name not in seen_targets:
                seen_targets.add(cls_name)
                suspicious_targets.append({
                    "type": "class",
                    "value": cls_name,
                    "reason": f"Dangerous API {api.get('api')} in modified DEX",
                })

    # 2. Components added (services, receivers, activities)
    for comp in components_added:
        c_type = "service" if "Service" in comp or "service" in comp.lower() else "class"
        if comp not in seen_targets:
            seen_targets.add(comp)
            suspicious_targets.append({
                "type": c_type,
                "value": comp,
                "reason": "Component added vs baseline",
            })

    # 3. New URLs / IOCs not present in baseline
    curr_urls = set(static.get("iocs", {}).get("urls", []))
    base_urls = set(base_static.get("iocs", {}).get("urls", []))
    for url in sorted(curr_urls - base_urls):
        if url not in seen_targets:
            seen_targets.add(url)
            suspicious_targets.append({
                "type": "url",
                "value": url,
                "reason": "New network IOC detected vs baseline",
            })

    # Generate security findings
    if certificate_changed:
        findings.append({
            "id": "TAMPER_CERT_CHANGED",
            "severity": "critical",
            "title": "Signing certificate differs from trusted baseline",
            "evidence": f"Baseline cert: {base_cert_sha[:16]}..., Current cert: {curr_cert_sha[:16]}...",
        })

    if dex_changed:
        dex_paths = [f["path"] for f in changed_files if f["path"].endswith(".dex")]
        findings.append({
            "id": "TAMPER_DEX_MODIFIED",
            "severity": "critical",
            "title": "Executable Dalvik bytecode modified vs baseline",
            "evidence": f"Modified DEX: {', '.join(dex_paths)} ({len(changed_chunks)} chunks changed)",
        })

    so_changed = [f["path"] for f in changed_files if f["path"].endswith(".so")]
    if so_changed:
        findings.append({
            "id": "TAMPER_NATIVE_MODIFIED",
            "severity": "high",
            "title": "Native shared libraries modified vs baseline",
            "evidence": f"Modified native libs: {', '.join(so_changed)}",
        })

    if permissions_added:
        findings.append({
            "id": "TAMPER_PERMISSIONS_ADDED",
            "severity": "high",
            "title": f"Privilege escalation: {len(permissions_added)} new permission(s) added",
            "evidence": f"Added permissions: {', '.join(permissions_added)}",
        })

    if components_added:
        findings.append({
            "id": "TAMPER_COMPONENTS_ADDED",
            "severity": "medium",
            "title": f"New application components added ({len(components_added)})",
            "evidence": f"Added components: {', '.join(components_added)}",
        })

    if not changed_chunks and not certificate_changed and not permissions_added and not components_added:
        findings.append({
            "id": "TAMPER_INTEGRITY_VERIFIED",
            "severity": "info",
            "title": "Application strictly matches trusted baseline",
            "evidence": f"Matches baseline job {baseline_job_id}",
        })

    report = {
        "job_id": job_id,
        "engine": "tamper",
        "status": "ok",
        "findings": findings,
        "role": "comparison",
        "baseline_found": True,
        "baseline_job_id": baseline_job_id,
        "changed_chunks": changed_chunks,
        "changed_files": changed_files,
        "manifest_diff": {
            "permissions_added": permissions_added,
            "permissions_removed": permissions_removed,
            "components_added": components_added,
            "components_removed": components_removed,
        },
        "certificate_changed": certificate_changed,
        "suspicious_targets": suspicious_targets,
    }

    return emit(ctx, "tamper.json", report)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m core.tamper <path_to_apk> [prior.json]")
        sys.exit(1)

    apk = sys.argv[1]
    prior = json.load(open(sys.argv[2], encoding="utf-8")) if len(sys.argv) > 2 else {}
    ws = tempfile.mkdtemp(prefix="mt_tamper_")
    ctx = JobContext(apk_path=apk, workspace=ws, prior=prior, config={})
    job_id = "local-tamper-test"
    res = run(job_id, ctx)
    print(json.dumps(res, indent=2))
    print(f"\nwrote: {ctx.out('tamper.json')}")
