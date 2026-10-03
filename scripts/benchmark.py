"""scripts/benchmark.py — Performance measurements.

    python -m scripts.benchmark [--repeat 5]

Measures, in an isolated temporary data directory:
  * end-to-end upload -> analysis -> result through the REST API, per APK size;
  * the stages inside it: archive validation + per-file hashing, static analysis
    (manifest, DEX, signature verification), baseline comparison;
  * database operations: baseline enrolment, approval (sign + commit);
  * cryptographic primitives: ECDSA P-256 sign / verify, Merkle tree build,
    inclusion-proof generation / verification, audit-chain verification.

Small / medium / large APKs are real signed builds (Android SDK) of the demo app
with 0 MB, 5 MB and 50 MB of incompressible assets. Results (median and p95 of
the repetitions) go to evaluation/results/benchmark.{json,md}.
"""

from __future__ import annotations

import os
import sys
import tempfile

_DATA = tempfile.mkdtemp(prefix="mt_bench_")
os.environ.update(MERKLETRUST_ENV="test", MERKLETRUST_DATA_DIR=os.path.join(_DATA, "data"),
                  MERKLETRUST_DEV_KEY_DIR=os.path.join(_DATA, "keys"), MERKLETRUST_JOB_EXECUTION="inline",
                  MERKLETRUST_LOG_LEVEL="WARNING", MERKLETRUST_LOG_JSON="false",
                  MERKLETRUST_UPLOAD_RATE_PER_MINUTE="10000", MERKLETRUST_LOGIN_RATE_PER_MINUTE="10000")
for _v in ("MERKLETRUST_DATABASE_URL", "MERKLETRUST_SIGNING_KEY_PATH"):
    os.environ.pop(_v, None)

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import platform  # noqa: E402
import statistics  # noqa: E402
import time  # noqa: E402
from dataclasses import replace  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "evaluation" / "results"
PASSWORD = "benchmark-only-password"


def stats(samples_ms: list[float]) -> dict:
    s = sorted(samples_ms)
    p95 = s[min(len(s) - 1, max(0, round(0.95 * len(s)) - 1))]
    return {"n": len(s), "median_ms": round(statistics.median(s), 3), "p95_ms": round(p95, 3),
            "min_ms": round(s[0], 3), "max_ms": round(s[-1], 3)}


def timed(fn, repeat: int) -> tuple[dict, object]:
    samples, result = [], None
    for _ in range(repeat):
        t0 = time.perf_counter()
        result = fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return stats(samples), result


def build_apks(workdir: Path) -> dict[str, Path]:
    """Signed demo app with 0 / 5 / 50 MB of random (incompressible) assets."""
    from scripts.apk_builder import Toolchain, build_signed, create_keystore
    from scripts.build_fixtures import benign_spec
    tools = Toolchain.discover()
    key = create_keystore(workdir, "bench", "EC", tools=tools)
    out = {}
    for label, mb in (("small", 0), ("medium", 5), ("large", 50)):
        spec = benign_spec()
        if mb:
            spec = replace(spec, extra_files={**spec.extra_files, "assets/blob.bin": os.urandom(mb * 1024 * 1024)})
        out[label] = build_signed(spec, workdir / f"{label}.apk", key, ("v1", "v2"), tools)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args(argv)

    from cryptography.hazmat.primitives.asymmetric import ec
    from fastapi.testclient import TestClient

    from api.main import create_app
    from api.security import create_user
    from core import audit
    from core.apk_archive import ApkArchive
    from core.baselines import BaselineService, baseline_snapshot, snapshot_from_reports
    from core.comparison import compare_with_baseline
    from core.crypto import KeyRing, Signer, get_keyring
    from core.integrity import compute_integrity
    from core.apk_signature import verify_apk
    from core.merkle import build_tree, proof, root, verify_proof
    from core.static import analyze_apk
    from db.database import SessionLocal

    results: dict = {"apk": {}, "crypto": {}, "database": {}}
    with tempfile.TemporaryDirectory(prefix="mt_bench_apks_") as tmp:
        apks = build_apks(Path(tmp))
        client = TestClient(create_app())
        client.__enter__()
        with SessionLocal() as db:
            create_user(db, "bench", PASSWORD, "admin")
            db.commit()
        token = client.post("/api/v1/auth/login", json={"username": "bench", "password": PASSWORD}).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        for label, path in apks.items():
            data = path.read_bytes()
            entry: dict = {"size_bytes": len(data)}
            with ApkArchive(str(path)) as a:
                entry["files"] = sum(1 for _ in a.files())
            entry["sha256_whole_file"], _ = timed(lambda: hashlib.sha256(data).hexdigest(), args.repeat)
            entry["integrity_per_file_hashing_and_merkle"], integ = timed(lambda: compute_integrity(str(path)), args.repeat)

            def sig():
                with ApkArchive(str(path)) as a:
                    return verify_apk(a, target_sdk=34)
            entry["apk_signature_verification"], _ = timed(sig, args.repeat)
            entry["static_analysis_total"], static = timed(lambda: analyze_apk(str(path)), args.repeat)

            with SessionLocal() as db:
                svc = BaselineService(db)
                t0 = time.perf_counter()
                b, _ = svc.enroll(str(path), "bench")
                db.commit()
                enroll_ms = (time.perf_counter() - t0) * 1000
                t0 = time.perf_counter()
                svc.approve(b.id, "bench")
                db.commit()
                approve_ms = (time.perf_counter() - t0) * 1000
                results["database"].setdefault("baseline_enroll_ms", {})[label] = round(enroll_ms, 1)
                results["database"].setdefault("baseline_approve_sign_commit_ms", {})[label] = round(approve_ms, 1)
                snap = baseline_snapshot(b)
            entry["baseline_comparison"], _ = timed(
                lambda: compare_with_baseline(snap, snapshot_from_reports(integ, static)), args.repeat)

            def end_to_end():
                r = client.post("/api/v1/scans", headers=headers, files={"file": (path.name, data)})
                assert r.status_code == 202, r.text
                return r.json()
            entry["api_upload_to_result"], scan = timed(end_to_end, args.repeat)
            entry["engine_ms_last_run"] = {k: v["duration_ms"] for k, v in scan["engines"].items()}
            assert scan["result"]["integrity_status"] == "CLEAN", scan["result"]
            results["apk"][label] = entry
            print(f"{label:6} {len(data) / 1e6:6.2f} MB  end-to-end median "
                  f"{entry['api_upload_to_result']['median_ms']:.0f} ms", flush=True)

        # cryptographic primitives
        signer = Signer(ec.generate_private_key(ec.SECP256R1()))
        ring = KeyRing([signer.public_key])
        payload = {"type": "bench", "merkle_root": "ab" * 32, "files": 1234}
        n = 200
        results["crypto"]["ecdsa_p256_sign"], env = timed(lambda: signer.sign(payload), n)
        results["crypto"]["ecdsa_p256_verify"], _ = timed(lambda: ring.verify(payload, env), n)
        for leaves in (100, 1_000, 10_000, 100_000):
            data_leaves = [hashlib.sha256(str(i).encode()).digest() for i in range(leaves)]
            reps = 5 if leaves <= 10_000 else 2
            build, tree = timed(lambda: build_tree(data_leaves), reps)
            r = root(tree)
            gen, p = timed(lambda: proof(tree, leaves // 2), 200)
            ver, ok = timed(lambda: verify_proof(data_leaves[leaves // 2], p, r), 200)
            assert ok
            results["crypto"][f"merkle_{leaves}_leaves"] = {"build": build, "proof_generate": gen,
                                                           "proof_verify": ver, "proof_steps": len(p)}
        with SessionLocal() as db:
            for _ in range(500):
                audit.append_event(db, "APK_UPLOADED", "bench", {"i": _})
            db.commit()
            blocks = audit.all_blocks(db)
        results["crypto"][f"audit_chain_verify_{len(blocks)}_blocks"], v = timed(
            lambda: audit.verify_chain(blocks, get_keyring()), 3)
        assert v["valid"]
        client.__exit__(None, None, None)

    env = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "platform": f"{platform.system()} {platform.release()}", "machine": platform.machine(),
           "processor": platform.processor(), "python": platform.python_version(), "cpus": os.cpu_count(),
           "repeat": args.repeat}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "benchmark.json").write_text(json.dumps({"environment": env, **results}, indent=2), encoding="utf-8")
    (RESULTS / "benchmark.md").write_text(markdown(env, results), encoding="utf-8")
    print(f"written to {RESULTS}")
    return 0


def markdown(env: dict, r: dict) -> str:
    def m(x):
        return f"{x['median_ms']:.2f} ms ({x['min_ms']:.2f}–{x['p95_ms']:.2f})"
    out = ["# MerkleTrust — Performance", "",
           f"Generated {env['generated_at']} on {env['platform']} ({env['machine']}, {env['cpus']} CPUs), "
           f"Python {env['python']}. Cells show **median (min–p95)** of {env['repeat']} runs unless stated. "
           "Single process, SQLite (WAL, synchronous=FULL), no emulator. Produced by `python -m scripts.benchmark`.",
           "", "The machine was in normal interactive use while measuring, so medians include background noise; "
           "the minimum is the best estimate of the intrinsic cost.", "",
           "## Per APK size", "",
           "| Measurement | " + " | ".join(f"{k} ({v['size_bytes'] / 1e6:.2f} MB, {v['files']} files)" for k, v in r["apk"].items()) + " |",
           "|---|" + "---|" * len(r["apk"])]
    rows = [("Upload → analysis → result (REST API)", "api_upload_to_result"),
            ("SHA-256 of the whole file", "sha256_whole_file"),
            ("Per-file SHA-256 manifest + Merkle root (+ chunk forensics)", "integrity_per_file_hashing_and_merkle"),
            ("APK signature verification (v1/v2/v3)", "apk_signature_verification"),
            ("Static analysis (manifest, DEX, signature, findings)", "static_analysis_total"),
            ("Comparison with baseline", "baseline_comparison")]
    for title, key in rows:
        out.append(f"| {title} | " + " | ".join(m(v[key]) for v in r["apk"].values()) + " |")
    db = r["database"]
    out.append("| Baseline enrolment (analyse + insert + commit), single run | " +
               " | ".join(f"{db['baseline_enroll_ms'][k]:.1f} ms" for k in r["apk"]) + " |")
    out.append("| Baseline approval (ECDSA sign + audit block + commit), single run | " +
               " | ".join(f"{db['baseline_approve_sign_commit_ms'][k]:.1f} ms" for k in r["apk"]) + " |")
    out += ["", "## Cryptographic operations", "", "| Operation | Time |", "|---|---|",
            f"| ECDSA P-256 sign (canonical JSON payload, 200 runs) | {m(r['crypto']['ecdsa_p256_sign'])} |",
            f"| ECDSA P-256 verify (200 runs) | {m(r['crypto']['ecdsa_p256_verify'])} |"]
    for key, v in r["crypto"].items():
        if key.startswith("merkle_"):
            n = key.split("_")[1]
            out.append(f"| Merkle tree build, {n} leaves | {m(v['build'])} |")
            out.append(f"| Inclusion proof generate / verify, {n} leaves ({v['proof_steps']} steps) | "
                       f"{m(v['proof_generate'])} / {m(v['proof_verify'])} |")
        if key.startswith("audit_chain_verify"):
            out.append(f"| Full audit-chain verification, {key.split('_')[3]} blocks (hash + link + ECDSA per block) | {m(v)} |")
    out += ["", "Times include Python interpreter overhead; they are indicative of this prototype on this machine, "
            "not a performance guarantee.", ""]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
