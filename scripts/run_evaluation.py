"""scripts/run_evaluation.py — Controlled evaluation of MerkleTrust against ground truth.

    python -m scripts.run_evaluation

Everything runs through the real REST API (upload validation, job pipeline,
database, audit chain) in an isolated temporary data directory:

  1. an administrator enrols and approves the three official builds as baselines;
  2. an analyst uploads every case of evaluation/dataset/manifest.json;
  3. cryptographic tampering is performed directly on stored data, as an attacker
     with database / file-system access would, and verification is re-run.

Results are compared with the ground truth recorded in the dataset manifest and
written to evaluation/results/evaluation.{json,md}. Nothing is tuned here: the
runner only measures.
"""

from __future__ import annotations

import os
import sys
import tempfile

# Isolate all state BEFORE importing the application.
_DATA = tempfile.mkdtemp(prefix="mt_eval_")
os.environ.update(MERKLETRUST_ENV="test", MERKLETRUST_DATA_DIR=os.path.join(_DATA, "data"),
                  MERKLETRUST_DEV_KEY_DIR=os.path.join(_DATA, "keys"), MERKLETRUST_JOB_EXECUTION="inline",
                  MERKLETRUST_LOG_LEVEL="WARNING", MERKLETRUST_LOG_JSON="false",
                  MERKLETRUST_UPLOAD_RATE_PER_MINUTE="1000", MERKLETRUST_LOGIN_RATE_PER_MINUTE="1000")
for _v in ("MERKLETRUST_DATABASE_URL", "MERKLETRUST_SIGNING_KEY_PATH", "MERKLETRUST_TRUSTED_KEYS_DIR"):
    os.environ.pop(_v, None)

import json  # noqa: E402
import platform  # noqa: E402
import statistics  # noqa: E402
import time  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from scripts.eval_metrics import confusion  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "evaluation" / "dataset"
RESULTS = ROOT / "evaluation" / "results"
PASSWORD = "evaluation-only-password"


# --------------------------------------------------------------- evaluation --

def run() -> dict:
    from api.main import create_app
    from api.security import create_user
    from core import audit
    from core.crypto import Signer
    from core.config import get_settings
    from db.database import SessionLocal
    from db.models import AuditBlock, TrustedBaseline

    manifest = json.loads((DATASET / "manifest.json").read_text(encoding="utf-8"))
    client = TestClient(create_app())
    client.__enter__()
    with SessionLocal() as db:
        create_user(db, "admin", PASSWORD, "admin")
        create_user(db, "analyst", PASSWORD, "analyst")
        db.commit()

    def login(user):
        r = client.post("/api/v1/auth/login", json={"username": user, "password": PASSWORD})
        r.raise_for_status()
        return {"Authorization": f"Bearer {r.json()['access_token']}"}
    admin, analyst = login("admin"), login("analyst")

    def upload(url, headers, path):
        t0 = time.perf_counter()
        r = client.post(url, headers=headers, files={"file": (path.name, path.read_bytes())})
        return r, (time.perf_counter() - t0) * 1000

    # 1. baselines
    baseline_ids, timings = {}, {"enroll_ms": [], "approve_ms": []}
    for name, file in manifest["baselines"].items():
        r, ms = upload("/api/v1/baselines", admin, DATASET / file)
        r.raise_for_status()
        timings["enroll_ms"].append(ms)
        bid = r.json()["baseline"]["id"]
        t0 = time.perf_counter()
        client.post(f"/api/v1/baselines/{bid}/approve", headers=admin, json={"note": "evaluation"}).raise_for_status()
        timings["approve_ms"].append((time.perf_counter() - t0) * 1000)
        baseline_ids[name] = bid

    # 2. cases
    cases = []
    for case in manifest["cases"]:
        r, ms = upload("/api/v1/scans", analyst, DATASET / case["file"])
        if r.status_code != 202:
            cases.append({**case, "error": f"HTTP {r.status_code}: {r.text[:200]}", "processing_ms": ms})
            continue
        scan = r.json()
        report = client.get(f"/api/v1/scans/{scan['id']}/report", headers=analyst).json()
        rep = report["reports"]
        score, tamper, static = rep["score"], rep.get("tamper", {}), rep["static"]
        files = (tamper.get("integrity") or {}).get("files") or {}
        observed_files = {k: sorted(c["path"] for c in files.get(k, [])) for k in ("modified", "added", "deleted")}
        cert_changed = bool(tamper.get("certificate_changed"))
        sig = static["signature"]["status"]
        integrity = score["integrity"]["status"]
        cases.append({
            **case,
            "scan_id": scan["id"],
            "processing_ms": round(ms, 1),
            "engine_ms": {k: v["duration_ms"] for k, v in report["scan"]["engines"].items()},
            "observed": {
                "integrity": integrity, "verdict": score["verdict"]["code"], "risk_level": score["risk"]["level"],
                "risk_score": score["risk"]["score"], "signature": sig, "certificate_changed": cert_changed,
                "files": observed_files,
                "contributions": [f"{c['finding_id']}+{c['points']}" for c in score["risk"]["contributions"]],
            },
            "predicted": {
                "changed": integrity not in ("CLEAN", "NO_BASELINE"),
                "unauthorized": cert_changed or sig != "verified" or integrity == "BASELINE_INVALID",
                "risky": score["risk"]["level"] in ("HIGH", "CRITICAL"),
            },
        })

    # 3. cryptographic verification under tampering
    crypto = []

    def record(cid, description, tampered, detected, detail=""):
        crypto.append({"id": cid, "description": description, "tampered": tampered, "detected": detected,
                       "detail": detail})

    def chain_valid(expected_head=None):
        body = {"expected_head": expected_head} if expected_head else None
        return client.post("/api/v1/audit/verify", headers=admin, json=body).json()

    # controls (nothing tampered): every report, every baseline, the chain
    for c in cases:
        if "scan_id" in c:
            v = client.post(f"/api/v1/scans/{c['scan_id']}/verify", headers=analyst).json()
            record(f"C-report-{c['id']}", f"Untouched report of {c['id']}", False, not v["valid"])
    for name, bid in baseline_ids.items():
        v = client.get(f"/api/v1/baselines/{bid}/verify", headers=analyst).json()
        record(f"C-baseline-{name}", f"Untouched baseline {name}", False, not v["valid"])
    v = chain_valid()
    record("C-chain", "Untouched audit chain", False, not v["valid"], f"{v['length']} blocks")

    # ledger tampering via the demonstration endpoint (restored after each)
    middle = chain_valid()["length"] // 2
    for cid, mode, desc in (("K01", "edit_payload", "Audit block event data edited"),
                            ("K02", "rewrite_block", "Audit block edited and its hash recomputed")):
        client.post("/api/v1/audit/demo/tamper", headers=admin, json={"block_index": middle, "mode": mode}).raise_for_status()
        v = chain_valid()
        record(cid, desc, True, not v["valid"], v["summary"][:160])
        client.post("/api/v1/audit/demo/restore", headers=admin).raise_for_status()

    # report tampering on disk
    target = next(c for c in cases if c["id"] == "D05")
    merged = Path(get_settings().jobs_dir) / target["scan_id"] / "merged.json"
    original = merged.read_text(encoding="utf-8")
    for cid, desc, mutate in (
        ("K03", "Stored report: verdict changed to CLEAN", lambda d: d["reports"]["score"]["verdict"].update(code="CLEAN")),
        ("K04", "Stored report: one file fingerprint altered",
         lambda d: d["reports"]["integrity"]["files"][0].update(sha256="0" * 64)),
    ):
        data = json.loads(original)
        mutate(data)
        merged.write_text(json.dumps(data), encoding="utf-8")
        v = client.post(f"/api/v1/scans/{target['scan_id']}/verify", headers=analyst).json()
        record(cid, desc, True, not v["valid"], "; ".join(v["reasons"])[:160])
        merged.write_text(original, encoding="utf-8")

    # baseline tampering in the database (restored after each)
    bid = baseline_ids["demo"]

    def tamper_baseline(cid, desc, mutate):
        with SessionLocal() as db:
            b = db.get(TrustedBaseline, bid)
            saved = {c.name: getattr(b, c.name) for c in TrustedBaseline.__table__.columns}
            mutate(b, db)
            db.commit()
        v = client.get(f"/api/v1/baselines/{bid}/verify", headers=analyst).json()
        record(cid, desc, True, not v["valid"], "; ".join(v["reasons"])[:160])
        with SessionLocal() as db:
            b = db.get(TrustedBaseline, bid)
            for k, val in saved.items():
                setattr(b, k, val)
            db.commit()

    def edit_file_hash(b, _db):
        files = json.loads(b.files_json)
        files[0]["sha256"] = "1" * 64
        b.files_json = json.dumps(files)

    def forge_list_and_root(b, _db):
        from core.file_manifest import manifest_root
        files = json.loads(b.files_json)
        files[0]["sha256"] = "2" * 64
        b.files_json, b.merkle_root = json.dumps(files), manifest_root(files)

    def rogue_signature(b, _db):
        from core.baselines import signed_payload
        rogue = Signer(ec.generate_private_key(ec.SECP256R1()))
        env = rogue.sign(signed_payload(b))
        env["key_id"] = json.loads(b.signature_json)["key_id"]   # claim the trusted key's id
        b.signature_json = json.dumps(env)

    def accept_attacker_cert(b, _db):
        b.certificate_sha256 = "f" * 64

    tamper_baseline("K05", "Baseline: one stored file fingerprint altered", edit_file_hash)
    tamper_baseline("K06", "Baseline: file list and Merkle root forged consistently", forge_list_and_root)
    tamper_baseline("K07", "Baseline: re-signed with a rogue key claiming the trusted key id", rogue_signature)
    tamper_baseline("K08", "Baseline: certificate fingerprint swapped for an attacker's", accept_attacker_cert)

    # revocation rolled back in the database
    nb = baseline_ids["notes"]
    client.post(f"/api/v1/baselines/{nb}/revoke", headers=admin, json={"reason": "evaluation"}).raise_for_status()
    with SessionLocal() as db:
        db.get(TrustedBaseline, nb).status = "approved"
        db.commit()
    v = client.get(f"/api/v1/baselines/{nb}/verify", headers=analyst).json()
    record("K09", "Baseline: revocation undone by editing the status column", True, not v["valid"],
           "; ".join(v["reasons"])[:160])

    # block appended with an untrusted key, then removed
    with SessionLocal() as db:
        rogue_block = audit.append_event(db, "APK_UPLOADED", "mallory", {"forged": True},
                                         signer=Signer(ec.generate_private_key(ec.SECP256R1())))
        rogue_index = rogue_block.block_index
        db.commit()
    v = chain_valid()
    record("K10", "Audit block appended with an untrusted signing key", True, not v["valid"], v["summary"][:160])
    with SessionLocal() as db:
        db.delete(db.get(AuditBlock, rogue_index))
        db.commit()

    # truncation against a saved signed head
    saved_head = client.get("/api/v1/audit/head", headers=admin).json()["head"]
    with SessionLocal() as db:
        last = audit.head(db)
        db.delete(last)
        db.commit()
    v = chain_valid(expected_head=saved_head)
    record("K11", "Newest audit block deleted (checked against a saved signed head)", True, not v["valid"],
           v["summary"][:160])

    client.__exit__(None, None, None)
    return {"cases": cases, "crypto": crypto, "baseline_timings": timings}


def summarise(raw: dict) -> dict:
    cases = [c for c in raw["cases"] if "observed" in c]
    dev = [c for c in cases if c.get("set", "development") == "development"]
    held = [c for c in cases if c.get("set") == "held_out"]
    with_baseline = [c for c in dev if c["baseline"]]
    tasks = {
        "change_detection": {
            "question": "Does the app differ from its trusted version?",
            "scope": "cases with a baseline",
            **confusion([(c["truth"]["changed"], c["predicted"]["changed"]) for c in with_baseline])},
        "unauthorized_modification": {
            "question": "Was the app changed by someone other than the key holder (re-signed, unsigned or broken signature)?",
            "scope": "cases with a baseline",
            **confusion([(c["truth"]["unauthorized"], c["predicted"]["unauthorized"]) for c in with_baseline])},
        "install_warning": {
            "question": "Should the user be warned not to install it (risk HIGH/CRITICAL)?",
            "scope": "development cases (D, N, W, R)",
            **confusion([(c["truth"]["risky"], c["predicted"]["risky"]) for c in dev])},
        "behavioural_risk_development": {
            "question": "Same, apps without a baseline (risk from the app's own behaviour only)",
            "scope": "development R* cases",
            **confusion([(c["truth"]["risky"], c["predicted"]["risky"]) for c in dev if not c["baseline"]])},
        "behavioural_risk_held_out": {
            "question": "Same, on samples written after the risk rules were finalised",
            "scope": "held-out H* cases",
            **confusion([(c["truth"]["risky"], c["predicted"]["risky"]) for c in held])},
        "crypto_tamper_detection": {
            "question": "Is tampering with stored reports, baselines or the audit chain detected (and untouched data accepted)?",
            "scope": "tampering cases + untouched controls",
            **confusion([(k["tampered"], k["detected"]) for k in raw["crypto"]])},
    }
    exact = [c["observed"]["integrity"] == c["truth"]["integrity"] for c in cases]
    localisation = []
    for c in with_baseline:
        exp = c["truth"].get("files")
        req = c["truth"].get("required")
        obs = c["observed"]["files"]
        if exp is not None:
            ok = all(sorted(exp.get(k, [])) == obs[k] for k in ("modified", "added", "deleted"))
        elif req is not None:
            ok = all(set(req.get(k, [])) <= set(obs[k]) for k in ("modified", "added", "deleted"))
        else:
            continue
        localisation.append(ok)
    times = [c["processing_ms"] for c in cases]
    return {
        "tasks": tasks,
        "integrity_status_exact": {"n": len(exact), "correct": sum(exact),
                                   "accuracy": round(sum(exact) / len(exact), 4)},
        "file_localisation": {"n": len(localisation), "correct": sum(localisation),
                              "accuracy": round(sum(localisation) / len(localisation), 4) if localisation else None},
        "processing_ms": {"median": round(statistics.median(times), 1), "max": round(max(times), 1),
                          "min": round(min(times), 1)},
        "errors": [c["id"] for c in raw["cases"] if "error" in c],
    }


def _fmt(v):
    return "—" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))


def markdown(raw: dict, summary: dict, env: dict) -> str:
    out = ["# MerkleTrust — Evaluation results", "",
           f"Generated {env['generated_at']} on {env['platform']} (Python {env['python']}, {env['cpus']} CPUs).",
           "Produced by `python -m scripts.run_evaluation` from `evaluation/dataset/` (real APKs built with the "
           "Android toolchain; see `scripts/build_eval_dataset.py`). Ground truth was fixed when the dataset was "
           "built; this report only measures. Methodology, the held-out protocol and the changes made after the "
           "initial run are described in `evaluation/README.md`.", "",
           "## Detection metrics", "",
           "| Question | Scope | n | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 | FPR | FNR |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for t in summary["tasks"].values():
        out.append(f"| {t['question']} | {t['scope']} | {t['n']} | {t['tp']} | {t['fp']} | {t['tn']} | {t['fn']} | "
                   f"{_fmt(t['accuracy'])} | {_fmt(t['precision'])} | {_fmt(t['recall'])} | {_fmt(t['f1'])} | "
                   f"{_fmt(t['false_positive_rate'])} | {_fmt(t['false_negative_rate'])} |")
    e, loc, pm = summary["integrity_status_exact"], summary["file_localisation"], summary["processing_ms"]
    out += ["", f"* Exact integrity status (5 classes): **{e['correct']}/{e['n']}** ({_fmt(e['accuracy'])})",
            f"* Changed files reported exactly as expected: **{loc['correct']}/{loc['n']}** ({_fmt(loc['accuracy'])})",
            f"* Upload-to-result time per APK (API, inline analysis): median {pm['median']} ms, "
            f"min {pm['min']} ms, max {pm['max']} ms",
            f"* Cases that failed to process: {', '.join(summary['errors']) or 'none'}", "",
            "## Per-case results", "",
            "| ID | Case | Expected | Observed integrity | Verdict | Risk | Signature | Changed files | ms | Match |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for c in raw["cases"]:
        if "observed" not in c:
            out.append(f"| {c['id']} | {c['description']} | {c['truth']['integrity']} | ERROR | | | | | | ✗ |")
            continue
        o = c["observed"]
        changed = "; ".join(f"{k}: {', '.join(v)}" for k, v in o["files"].items() if v) or "none"
        match = (o["integrity"] == c["truth"]["integrity"] and c["predicted"]["risky"] == c["truth"]["risky"]
                 and (not c["baseline"] or (c["predicted"]["changed"] == c["truth"]["changed"]
                                            and c["predicted"]["unauthorized"] == c["truth"]["unauthorized"])))
        out.append(f"| {c['id']} | {c['description']} | {c['truth']['integrity']} | {o['integrity']} | {o['verdict']} | "
                   f"{o['risk_level']} ({o['risk_score']}) | {o['signature']} | {changed} | {c['processing_ms']} | "
                   f"{'✓' if match else '✗'} |")
    out += ["", "## Cryptographic tampering", "", "| ID | Scenario | Tampered | Detected | Detail |", "|---|---|---|---|---|"]
    for k in raw["crypto"]:
        if k["id"].startswith("C-report"):
            continue
        out.append(f"| {k['id']} | {k['description']} | {'yes' if k['tampered'] else 'no'} | "
                   f"{'yes' if k['detected'] else 'no'} | {k['detail']} |")
    controls = [k for k in raw["crypto"] if k["id"].startswith("C-report")]
    out += [f"", f"Plus {len(controls)} untouched sealed reports, each verified: "
            f"{sum(not k['detected'] for k in controls)}/{len(controls)} accepted as valid.", "",
            "## Limitations", "",
            "* The dataset is small and constructed by the project team; it demonstrates that each detection "
            "mechanism works on realistic APKs, not how the system performs on real-world malware in the wild.",
            "* Risk weights and thresholds were designed by the same team that labelled the samples, so the risk "
            "metrics are a consistency check of the design, not an independent accuracy estimate.",
            "* All attacks follow the stated threat model (the attacker does not hold the developer key, the "
            "server, or the audit signing key).", ""]
    return "\n".join(out)


def main() -> int:
    raw = run()
    summary = summarise(raw)
    env = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "platform": f"{platform.system()} {platform.release()}", "python": platform.python_version(),
           "cpus": os.cpu_count()}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "evaluation.json").write_text(json.dumps({"environment": env, "summary": summary, **raw},
                                                        indent=2, default=str), encoding="utf-8")
    (RESULTS / "evaluation.md").write_text(markdown(raw, summary, env), encoding="utf-8")
    for name, t in summary["tasks"].items():
        print(f"{name:28} n={t['n']:3} acc={_fmt(t['accuracy'])} P={_fmt(t['precision'])} "
              f"R={_fmt(t['recall'])} F1={_fmt(t['f1'])} FPR={_fmt(t['false_positive_rate'])} "
              f"FNR={_fmt(t['false_negative_rate'])}")
    print("exact integrity status:", summary["integrity_status_exact"])
    print("file localisation:", summary["file_localisation"])
    print("errors:", summary["errors"] or "none")
    print(f"\nwritten to {RESULTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
