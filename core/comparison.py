"""core/comparison.py — Compare an analysed APK against a trusted baseline.

This answers the *integrity* question only — "is this the same application as
the approved baseline?" — and deliberately says nothing about whether the app is
dangerous (that is risk scoring).

Integrity status (most severe wins):

    CERTIFICATE_CHANGED  signed by a different certificate than the baseline
    MODIFIED             same signer, but files differ or the signature does not verify
    CLEAN                every content file matches and the signature verifies

Signature files (META-INF) are reported separately: an APK re-signed with the
*same* certificate changes only those files and is still CLEAN.
"""

from __future__ import annotations

from typing import Any

from core.crypto import hash_payload
from core.file_manifest import compare_manifests, manifest_root

# Certificate fields that change with the clock are excluded from the hashed profile.
_TIME_DEPENDENT_CERT_FIELDS = {"expired", "not_yet_valid"}
APP_FLAGS = ("debuggable", "allowBackup", "usesCleartextTraffic", "testOnly")


def build_profile(static: dict[str, Any]) -> dict[str, Any]:
    """The security-relevant, time-independent description of an app stored with a baseline."""
    cert = {k: v for k, v in (static.get("certificate") or {}).items() if k not in _TIME_DEPENDENT_CERT_FIELDS}
    return {
        "package_name": static.get("package_name"),
        "version_name": static.get("version_name"),
        "version_code": static.get("version_code"),
        "min_sdk": static.get("min_sdk"),
        "target_sdk": static.get("target_sdk"),
        "permissions": sorted(p["name"] if isinstance(p, dict) else p for p in static.get("permissions", [])),
        "components": sorted(
            ({"name": c["name"], "type": c["type"], "exported": bool(c.get("exported_effective")),
              "permission": c.get("permission")} for c in static.get("component_details", [])),
            key=lambda c: (c["type"], c["name"])),
        "application": {k: static.get("application", {}).get(k) for k in APP_FLAGS},
        "certificate": cert,
        "signature_schemes": (static.get("signature") or {}).get("schemes_present", []),
        "dangerous_apis": sorted(a["api"] for a in static.get("dangerous_apis", [])),
        "network_urls": sorted((static.get("iocs") or {}).get("urls", [])),
    }


def profile_hash(profile: dict[str, Any]) -> str:
    return hash_payload(profile)


def _manifest_diff(base: dict[str, Any], cur: dict[str, Any]) -> dict[str, Any]:
    bp, cp = set(base.get("permissions", [])), set(cur.get("permissions", []))
    bc = {c["name"]: c for c in base.get("components", [])}
    cc = {c["name"]: c for c in cur.get("components", [])}
    newly_exported = sorted(n for n, c in cc.items() if c["exported"] and not (bc.get(n) or {}).get("exported"))
    flags = []
    for flag in APP_FLAGS:
        b, c = (base.get("application") or {}).get(flag), (cur.get("application") or {}).get(flag)
        if b != c:
            flags.append({"flag": flag, "baseline": b, "current": c})
    return {
        "permissions_added": sorted(cp - bp),
        "permissions_removed": sorted(bp - cp),
        "components_added": sorted(cc.keys() - bc.keys()),
        "components_removed": sorted(bc.keys() - cc.keys()),
        "newly_exported_components": newly_exported,
        "flags_changed": flags,
        "dangerous_apis_added": sorted(set(cur.get("dangerous_apis", [])) - set(base.get("dangerous_apis", []))),
        "network_urls_added": sorted(set(cur.get("network_urls", [])) - set(base.get("network_urls", []))),
    }


def _chunk_diff(base_hashes: list[str], cur_hashes: list[str], base_size: int, cur_size: int) -> dict[str, Any]:
    if base_size != cur_size:
        return {"comparable": False, "reason": "different chunk sizes"}
    changed = [i for i in range(max(len(base_hashes), len(cur_hashes)))
               if (base_hashes[i] if i < len(base_hashes) else None) != (cur_hashes[i] if i < len(cur_hashes) else None)]
    return {"comparable": True, "chunk_size": cur_size, "baseline_chunks": len(base_hashes),
            "current_chunks": len(cur_hashes), "changed_count": len(changed), "changed_indices": changed[:256]}


def compare_with_baseline(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare snapshots. Both dicts carry: files, profile, apk_sha256, certificate_sha256,
    chunk_hashes, chunk_size; `current` also carries signature_status."""
    files = compare_manifests(baseline["files"], current["files"])
    counts = {k: len(v) for k, v in files.items()}
    base_profile, cur_profile = baseline["profile"], current["profile"]

    base_cert, cur_cert = baseline.get("certificate_sha256") or "", current.get("certificate_sha256") or ""
    cert_changed = base_cert != cur_cert
    sig_status = current.get("signature_status", "unknown")
    content_changed = bool(files["modified"] or files["added"] or files["deleted"])

    bv, cv = base_profile.get("version_code"), cur_profile.get("version_code")
    version = {
        "baseline": {"name": base_profile.get("version_name"), "code": bv},
        "current": {"name": cur_profile.get("version_name"), "code": cv},
        "changed": (bv, base_profile.get("version_name")) != (cv, cur_profile.get("version_name")),
        "downgrade": isinstance(bv, int) and isinstance(cv, int) and cv < bv,
    }

    base_root = baseline.get("merkle_root") or manifest_root(baseline["files"])
    cur_root = current.get("merkle_root") or manifest_root(current["files"])

    reasons = []
    if cert_changed:
        reasons.append("The app is signed by a different certificate than the trusted baseline."
                       if cur_cert else "The app carries no verifiable signing certificate.")
    if counts["modified"]:
        reasons.append(f"{counts['modified']} file(s) have different contents.")
    if counts["added"]:
        reasons.append(f"{counts['added']} file(s) were added.")
    if counts["deleted"]:
        reasons.append(f"{counts['deleted']} file(s) were removed.")
    if sig_status != "verified":
        reasons.append(f"The app's own signature is {sig_status}.")
    if version["downgrade"]:
        reasons.append(f"Version code went down from {bv} to {cv} (possible downgrade).")

    if cert_changed:
        status = "CERTIFICATE_CHANGED"
    elif content_changed or sig_status != "verified":
        status = "MODIFIED"
    else:
        status = "CLEAN"
    if status == "CLEAN":
        reasons.append("All application files match the trusted baseline and the signature is valid.")
        if counts["signature_files_changed"]:
            reasons.append("Only signature files differ (re-signed with the same certificate).")

    return {
        "status": status,
        "byte_identical": baseline.get("apk_sha256") == current.get("apk_sha256"),
        "reasons": reasons,
        "counts": counts,
        "files": files,
        "certificate": {
            "changed": cert_changed,
            "baseline_sha256": base_cert, "current_sha256": cur_cert,
            "baseline_subject": (base_profile.get("certificate") or {}).get("subject"),
            "current_subject": (cur_profile.get("certificate") or {}).get("subject"),
        },
        "signature_status": sig_status,
        "version": version,
        "manifest_diff": _manifest_diff(base_profile, cur_profile),
        "merkle": {"baseline_root": base_root, "current_root": cur_root, "match": base_root == cur_root},
        "chunks": _chunk_diff(baseline.get("chunk_hashes", []), current.get("chunk_hashes", []),
                              baseline.get("chunk_size", 0), current.get("chunk_size", 0)),
    }
