"""Per-file SHA-256 manifest, Merkle commitment, per-file proofs and comparison."""

import hashlib

from core.apk_archive import ApkArchive
from core.file_manifest import (build_file_manifest, categorize, compare_manifests, file_proof, manifest_root,
                                verify_file_proof)


def _f(path, content):
    return {"path": path, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
            "category": categorize(path)}


BASE = [_f("AndroidManifest.xml", b"m"), _f("classes.dex", b"code"), _f("res/a.xml", b"r"),
        _f("META-INF/CERT.SF", b"sf"), _f("lib/arm64-v8a/libx.so", b"so")]


def test_manifest_of_real_apk(fixture_apk):
    with ApkArchive(fixture_apk("signed_v1v2_ec.apk")) as apk:
        files = build_file_manifest(apk)
        dex = apk.read("classes.dex")
    paths = [f["path"] for f in files]
    assert paths == sorted(paths)
    entry = next(f for f in files if f["path"] == "classes.dex")
    assert entry["sha256"] == hashlib.sha256(dex).hexdigest()
    assert entry["category"] == "code"
    assert {f["category"] for f in files} >= {"manifest", "code", "resources", "signature", "native", "assets"}


def test_categories():
    assert categorize("classes2.dex") == "code"
    assert categorize("META-INF/MANIFEST.MF") == "signature"
    assert categorize("META-INF/services/x") == "other"
    assert categorize("res/raw/a.bin") == "resources"


def test_root_is_order_independent_and_content_sensitive():
    assert manifest_root(BASE) == manifest_root(list(reversed(BASE)))
    changed = [dict(f) for f in BASE]
    changed[1] = _f("classes.dex", b"code!")
    assert manifest_root(changed) != manifest_root(BASE)


def test_root_binds_paths():
    """Swapping contents between two paths must change the root."""
    a, b = _f("assets/a", b"one"), _f("assets/b", b"two")
    swapped = [{**a, "sha256": b["sha256"]}, {**b, "sha256": a["sha256"]}]
    assert manifest_root([a, b]) != manifest_root(swapped)


def test_file_proof_valid_and_invalid():
    r = manifest_root(BASE)
    p = file_proof(BASE, "classes.dex")
    assert p["root"] == r
    assert verify_file_proof("classes.dex", p["sha256"], p["proof"], r)
    modified = hashlib.sha256(b"patched").hexdigest()
    assert not verify_file_proof("classes.dex", modified, p["proof"], r)          # modified content
    assert not verify_file_proof("classes2.dex", p["sha256"], p["proof"], r)      # wrong path
    assert not verify_file_proof("classes.dex", p["sha256"], p["proof"], "0" * 64)  # wrong root
    assert not verify_file_proof("classes.dex", "not-a-hash", p["proof"], r)


def test_compare_detects_every_change_type():
    current = [_f("AndroidManifest.xml", b"m"), _f("classes.dex", b"evil code"), _f("res/a.xml", b"r"),
               _f("META-INF/CERT.SF", b"other sf"), _f("assets/payload.bin", b"x")]
    d = compare_manifests(BASE, current)
    assert [c["path"] for c in d["modified"]] == ["classes.dex"]
    assert [c["path"] for c in d["added"]] == ["assets/payload.bin"]
    assert [c["path"] for c in d["deleted"]] == ["lib/arm64-v8a/libx.so"]
    assert [c["path"] for c in d["signature_files_changed"]] == ["META-INF/CERT.SF"]
    assert d["unchanged"] == ["AndroidManifest.xml", "res/a.xml"]
    assert d["modified"][0]["baseline_sha256"] != d["modified"][0]["current_sha256"]


def test_compare_identical():
    d = compare_manifests(BASE, list(BASE))
    assert not (d["modified"] or d["added"] or d["deleted"] or d["signature_files_changed"])
    assert len(d["unchanged"]) == len(BASE)
