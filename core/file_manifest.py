"""core/file_manifest.py — Per-file SHA-256 manifest, Merkle commitment and comparison.

This is the authoritative integrity mechanism. Each file inside the APK is
hashed individually; the sorted list of (path, SHA-256) pairs is committed to a
single Merkle root. Each leaf binds the *path* to the *content hash*:

    leaf_data = b"merkletrust.file.v1" || 0x00 || utf8(path) || 0x00 || sha256(content)

so moving content to another path, or swapping two files, changes the root.

Comparing two manifests yields exactly which files were modified, added,
deleted or unchanged — independent of where they sit inside the ZIP (unlike
fixed-offset chunking, where one inserted byte shifts everything after it).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from core.apk_archive import ApkArchive
from core.merkle import build_tree, leaf_hash, proof, root, verify_proof

LEAF_DOMAIN = b"merkletrust.file.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_FILE = re.compile(r"^META-INF/([^/]+\.(SF|RSA|DSA|EC)|MANIFEST\.MF)$", re.IGNORECASE)

# Order matters: first match wins.
_CATEGORIES = [
    ("manifest", re.compile(r"^AndroidManifest\.xml$")),
    ("signature", _SIGNATURE_FILE),
    ("code", re.compile(r"^classes\d*\.dex$")),
    ("native", re.compile(r"^lib/.+\.so$")),
    ("resources", re.compile(r"^(resources\.arsc|res/.*)$")),
    ("assets", re.compile(r"^assets/.*$")),
]

CATEGORY_LABELS = {
    "manifest": "App configuration (AndroidManifest.xml)",
    "signature": "Signature files",
    "code": "Application code (DEX)",
    "native": "Native libraries",
    "resources": "Resources",
    "assets": "Bundled assets",
    "other": "Other files",
}


def categorize(path: str) -> str:
    for name, pattern in _CATEGORIES:
        if pattern.match(path):
            return name
    return "other"


def build_file_manifest(apk: ApkArchive) -> list[dict[str, Any]]:
    """[{path, sha256, size, category}] for every file, sorted by path."""
    files = []
    for entry in apk.files():
        data = apk.read(entry.name)
        files.append({"path": entry.name, "sha256": hashlib.sha256(data).hexdigest(),
                      "size": len(data), "category": categorize(entry.name)})
    files.sort(key=lambda f: f["path"])
    return files


def file_leaf(path: str, sha256: str) -> bytes:
    if not _SHA256.match(sha256 or ""):
        raise ValueError("sha256 must be 64 lowercase hex characters")
    return LEAF_DOMAIN + b"\x00" + path.encode("utf-8") + b"\x00" + bytes.fromhex(sha256)


def _sorted(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(files, key=lambda f: f["path"])


def manifest_root(files: list[dict[str, Any]]) -> str:
    """Merkle root committing to the whole file manifest (order-independent input)."""
    return root([file_leaf(f["path"], f["sha256"]) for f in _sorted(files)])


def file_proof(files: list[dict[str, Any]], path: str) -> dict[str, Any]:
    """Inclusion proof that `path` with its recorded hash is part of the manifest root."""
    ordered = _sorted(files)
    index = next((i for i, f in enumerate(ordered) if f["path"] == path), None)
    if index is None:
        raise KeyError(path)
    tree = build_tree([file_leaf(f["path"], f["sha256"]) for f in ordered])
    return {"path": path, "sha256": ordered[index]["sha256"], "leaf_index": index,
            "leaf_hash": leaf_hash(file_leaf(path, ordered[index]["sha256"])),
            "proof": proof(tree, index), "root": root(tree)}


def verify_file_proof(path: str, sha256: str, audit_path: Any, expected_root: str) -> bool:
    """True iff (path, sha256) is committed under expected_root. Never raises."""
    try:
        leaf = file_leaf(path, sha256)
    except (ValueError, AttributeError, TypeError):
        return False
    return verify_proof(leaf, audit_path, expected_root)


def compare_manifests(baseline: list[dict[str, Any]], current: list[dict[str, Any]]) -> dict[str, Any]:
    """Classify every path as modified / added / deleted / unchanged.

    Signature files (META-INF/*.SF|RSA|EC|DSA, MANIFEST.MF) change whenever an APK
    is re-signed, so they are reported separately from content changes.
    """
    base = {f["path"]: f for f in baseline}
    cur = {f["path"]: f for f in current}
    result: dict[str, list] = {"modified": [], "added": [], "deleted": [], "unchanged": [],
                               "signature_files_changed": []}
    for path in sorted(base.keys() | cur.keys()):
        b, c = base.get(path), cur.get(path)
        category = categorize(path)
        if b and c and b["sha256"] == c["sha256"]:
            result["unchanged"].append(path)
            continue
        if b and c:
            change = {"path": path, "category": category, "change_type": "modified",
                      "baseline_sha256": b["sha256"], "current_sha256": c["sha256"],
                      "baseline_size": b.get("size"), "current_size": c.get("size")}
        elif c:
            change = {"path": path, "category": category, "change_type": "added",
                      "baseline_sha256": None, "current_sha256": c["sha256"], "current_size": c.get("size")}
        else:
            change = {"path": path, "category": category, "change_type": "deleted",
                      "baseline_sha256": b["sha256"], "current_sha256": None, "baseline_size": b.get("size")}
        if category == "signature":
            result["signature_files_changed"].append(change)
        else:
            result[change["change_type"]].append(change)
    return result
