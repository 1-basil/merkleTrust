"""scripts/run_realworld_evaluation.py — MerkleTrust on real, published Android apps.

    python -m scripts.run_realworld_evaluation [--work DIR]

The synthetic dataset (evaluation/dataset/) was built by the team. This evaluation uses real
open-source apps as published on F-Droid, and repackages them the way an attacker would:

  1. downloads three apps from f-droid.org and refuses any file whose SHA-256 differs from the
     value pinned below (taken from F-Droid's signed repository index, index-v2.json);
  2. builds attack variants of each app with zip operations and Google's apksigner — no app
     code is ever run, installed or emulated; the apps are only read as bytes;
  3. enrols each official app as a trusted baseline and scans every variant through the real
     REST API in an isolated temporary data directory;
  4. compares the results with ground truth that is fixed below, before any scan runs.

Safety: APKs are Android packages; Windows/Linux/macOS cannot execute them, and this script
never starts an emulator. The "attack" payloads are harmless: a text marker file, and a DEX
string changed to a documentation-only address (RFC 5737) or to one current C2 address from the
ThreatFox feed — inert text inside a file that is never run.

Needs: internet (first run), the Android SDK build-tools and a JDK (for apksigner/keytool).
Writes evaluation/results/realworld.{json,md}. Downloads and variants go to --work
(default: data/realworld, ignored by git).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Pinned from https://f-droid.org/repo/index-v2.json (8 October 2026).
APPS = [
    {"package": "net.gsantner.markor", "name": "Markor (notes editor)", "version": "2.16.1",
     "file": "net.gsantner.markor_163.apk",
     "sha256": "3f9f260dc3e32a1281cb8803eea6f926eef897579f68a5d35f922523974b84b9",
     "signer": "9c70033237dc46fe5052e420c665708de8b3105b89842843818981826b7eec9c"},
    {"package": "org.fossify.notes", "name": "Fossify Notes", "version": "1.7.0",
     "file": "org.fossify.notes_13.apk",
     "sha256": "5a56e0e39cc488e1f3b947d3801006d3b7450ec73c67f03195c64c5fd3b6bced",
     "signer": "affdb124d3f4720c2f98dbca9eacba0514fba4306e20a2786c861c3c0d6ff292"},
    {"package": "de.danoeh.antennapod", "name": "AntennaPod (podcast player)", "version": "3.12.2",
     "file": "de.danoeh.antennapod_3120295.apk",
     "sha256": "3f43a4337a693cdb49141afe06cb596e88c796009ed77bff51e9444ce2d1ebfc",
     "signer": "179430565a4a04bfe7827483243099bd10870410800cd7c4c7b48d8d3226df55"},
]
FDROID = "https://f-droid.org/repo/"
PAYLOAD_NAME = "assets/merkletrust_eval_payload.bin"
PAYLOAD = b"MerkleTrust evaluation marker. Harmless text standing in for an injected payload.\n" * 64
DOC_ADDRESS = "203.0.113.9:8080"   # RFC 5737 documentation range: cannot be a real server
FUZZY_LIMIT_MB = 16                # large enough to fuzzy-hash these apps' DEX files

# Ground truth per attack, fixed before any scan (dex/file names are filled per app).
VARIANTS = {
    "official_copy": {"what": "Byte-identical copy of the F-Droid download",
                      "changed": False, "unauthorized": False},
    "payload_resigned": {"what": "Extra file added (harmless marker), re-signed with an attacker key",
                         "changed": True, "unauthorized": True},
    "code_endpoint_swap": {"what": "One URL in the program code replaced (documentation address), re-signed",
                           "changed": True, "unauthorized": True},
    "code_c2_swap": {"what": "One URL in the program code replaced by a current ThreatFox C2 address, re-signed",
                     "changed": True, "unauthorized": True, "threat_feed_match": True},
    "signature_stripped": {"what": "All signatures removed (zip rebuilt, not re-signed)",
                           "changed": True, "unauthorized": True},
}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def download(app: dict, folder: Path) -> Path:
    import urllib.request
    dst = folder / app["file"]
    if not dst.exists():
        print(f"downloading {app['file']}")
        req = urllib.request.Request(FDROID + app["file"], headers={"User-Agent": "MerkleTrust evaluation"})
        with urllib.request.urlopen(req, timeout=300) as resp, open(dst.with_suffix(".part"), "wb") as out:  # noqa: S310
            shutil.copyfileobj(resp, out)
        dst.with_suffix(".part").replace(dst)
    got = sha256_file(dst)
    if got != app["sha256"]:
        dst.unlink()
        raise SystemExit(f"{app['file']}: SHA-256 {got} does not match the pinned F-Droid value; file deleted")
    return dst


# ---------------------------------------------------------------- DEX editing --

def _fix_dex_header(dex: bytearray) -> None:
    """Recompute the DEX header's SHA-1 signature (bytes 12..32) and Adler-32 checksum (8..12)."""
    dex[12:32] = hashlib.sha1(bytes(dex[32:])).digest()
    dex[8:12] = (zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF).to_bytes(4, "little")


def find_url_string(dex: bytes, min_len: int) -> tuple[int, str] | None:
    """An ASCII http(s) URL stored as a DEX string (length prefix, bytes, NUL), at least min_len long."""
    import re
    for m in re.finditer(rb"(?<=[\x00])([\x14-\x7f])(https?://[\x21-\x7e]{10,120})\x00", dex):
        if m.group(1)[0] == len(m.group(2)) and len(m.group(2)) >= min_len:
            return m.start(2), m.group(2).decode()
    return None


def swap_url(dex: bytes, host: str) -> tuple[bytes, str, str]:
    """Replace one URL string with http://<host>/... of exactly the same length (a valid DEX)."""
    stem = f"http://{host}/"
    hit = find_url_string(dex, len(stem) + 4)
    if hit is None:
        raise ValueError("no suitable URL string in this DEX")
    pos, old = hit
    new = (stem + "x" * len(old))[:len(old)]
    out = bytearray(dex)
    out[pos:pos + len(old)] = new.encode()
    _fix_dex_header(out)
    return bytes(out), old, new


def c2_address_from_feed(feed: Path) -> dict | None:
    """One current Android C2 ip:port from the downloaded ThreatFox feed (None without a feed)."""
    from core.threat_intel import load_threatfox_csv
    if not feed.exists():
        return None
    indicators, meta = load_threatfox_csv(feed)
    for ind in indicators:
        if ind.kind == "ip_port" and ind.threat_type == "botnet_cc" and ind.malware_id.startswith("apk."):
            return {"address": ind.value, "family": ind.family, "record_id": ind.record_id,
                    "first_seen": ind.first_seen, "feed_updated": meta["updated"]}
    return None


# ------------------------------------------------------------------ variants --

def build_variants(app: dict, official: Path, out: Path, keystore, c2: dict | None) -> dict[str, dict]:
    import zipfile
    from scripts.apk_builder import sign
    from scripts.apk_mutations import rewrite_zip

    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(official) as z:
        names = z.namelist()
        # Only the v1 signature files directly inside META-INF/. (The first run also removed
        # META-INF/versions/9/OSGI-INF/MANIFEST.MF, a library file — and MerkleTrust reported it as deleted.)
        sig_files = {n for n in names if n.count("/") == 1 and n.startswith("META-INF/") and
                     n.upper().endswith((".SF", ".RSA", ".EC", ".DSA", "/MANIFEST.MF"))}
        dexes = sorted(((n, z.getinfo(n).file_size) for n in names if n.endswith(".dex")), key=lambda x: -x[1])
        target_dex = next(n for n, size in dexes if size <= FUZZY_LIMIT_MB * 1024 * 1024)
        dex_bytes = z.read(target_dex)

    stem = app["package"]
    built: dict[str, dict] = {}

    def resign(unsigned: Path, dst: Path) -> Path:
        return sign(unsigned, dst, keystore, schemes=("v1", "v2"))

    p = out / f"{stem}__official_copy.apk"
    shutil.copyfile(official, p)
    built["official_copy"] = {"file": p, "expect_files": {}}

    tmp = out / f"{stem}__tmp_unsigned.apk"
    rewrite_zip(official, tmp, add={PAYLOAD_NAME: PAYLOAD}, remove=sig_files)
    p = resign(tmp, out / f"{stem}__payload_resigned.apk")
    built["payload_resigned"] = {"file": p, "expect_files": {"added": [PAYLOAD_NAME]}}

    new_dex, old_url, new_url = swap_url(dex_bytes, DOC_ADDRESS)
    rewrite_zip(official, tmp, modify={target_dex: new_dex}, remove=sig_files)
    p = resign(tmp, out / f"{stem}__code_endpoint_swap.apk")
    built["code_endpoint_swap"] = {"file": p, "expect_files": {"modified": [target_dex]},
                                   "detail": f"{target_dex}: {old_url!r} -> {new_url!r}"}

    if c2:
        new_dex, old_url, new_url = swap_url(dex_bytes, c2["address"])
        rewrite_zip(official, tmp, modify={target_dex: new_dex}, remove=sig_files)
        p = resign(tmp, out / f"{stem}__code_c2_swap.apk")
        built["code_c2_swap"] = {"file": p, "expect_files": {"modified": [target_dex]},
                                 "detail": f"{target_dex}: {old_url!r} -> {new_url!r} "
                                           f"(ThreatFox #{c2['record_id']}, {c2['family']})"}

    p = out / f"{stem}__signature_stripped.apk"
    rewrite_zip(official, p, remove=sig_files)
    built["signature_stripped"] = {"file": p, "expect_files": {}}
    tmp.unlink(missing_ok=True)
    return built


# --------------------------------------------------------------------- main --

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--work", type=Path, default=ROOT / "data" / "realworld")
    args = parser.parse_args(argv)
    downloads, variants_dir = args.work / "downloads", args.work / "variants"
    downloads.mkdir(parents=True, exist_ok=True)

    # The feed the user downloaded (scripts/update_threat_feed.py), read before isolating state.
    user_feed = ROOT / "data" / "threat_feeds" / "threatfox_recent.csv"

    data = tempfile.mkdtemp(prefix="mt_realworld_")
    os.environ.update(MERKLETRUST_ENV="test", MERKLETRUST_DATA_DIR=os.path.join(data, "data"),
                      MERKLETRUST_DEV_KEY_DIR=os.path.join(data, "keys"), MERKLETRUST_JOB_EXECUTION="inline",
                      MERKLETRUST_LOG_LEVEL="WARNING", MERKLETRUST_LOG_JSON="false",
                      MERKLETRUST_UPLOAD_RATE_PER_MINUTE="1000", MERKLETRUST_LOGIN_RATE_PER_MINUTE="1000",
                      MERKLETRUST_MAX_UPLOAD_MB="200", MERKLETRUST_FUZZY_MAX_DEX_MB=str(FUZZY_LIMIT_MB))
    for v in ("MERKLETRUST_DATABASE_URL", "MERKLETRUST_SIGNING_KEY_PATH", "MERKLETRUST_TRUSTED_KEYS_DIR"):
        os.environ.pop(v, None)
    if user_feed.exists():
        feed_dir = Path(data, "data", "threat_feeds")
        feed_dir.mkdir(parents=True)
        shutil.copyfile(user_feed, feed_dir / "threatfox_recent.csv")

    from scripts.apk_builder import create_keystore
    c2 = c2_address_from_feed(user_feed)
    keystore = create_keystore(Path(data), "attacker", "RSA", dname="CN=Not The Developer, O=Attacker, C=XX")

    builds = {}
    for app in APPS:
        official = download(app, downloads)
        builds[app["package"]] = (official, build_variants(app, official, variants_dir, keystore, c2))

    import json
    import time
    from datetime import datetime, timezone
    from fastapi.testclient import TestClient
    from api.main import create_app
    from api.security import create_user
    from db.database import SessionLocal

    client = TestClient(create_app())
    client.__enter__()
    with SessionLocal() as db:
        create_user(db, "admin", "evaluation-only-password", "admin")
        db.commit()
    auth = {"Authorization": "Bearer " + client.post("/api/v1/auth/login", json={
        "username": "admin", "password": "evaluation-only-password"}).json()["access_token"]}

    def post_file(url: str, path: Path):
        t0 = time.perf_counter()
        r = client.post(url, headers=auth, files={"file": (path.name, path.read_bytes())})
        return r, (time.perf_counter() - t0) * 1000

    results = []
    for app in APPS:
        official, variants = builds[app["package"]]
        r, enrol_ms = post_file("/api/v1/baselines", official)
        r.raise_for_status()
        base = r.json()["baseline"]
        client.post(f"/api/v1/baselines/{base['id']}/approve", headers=auth, json={"note": "F-Droid release"}).raise_for_status()
        signer_ok = base["certificate_sha256"] == app["signer"]
        for key, v in variants.items():
            truth = VARIANTS[key]
            r, ms = post_file("/api/v1/scans", v["file"])
            if r.status_code != 202:
                results.append({"app": app["package"], "variant": key, "error": f"HTTP {r.status_code}: {r.text[:200]}"})
                continue
            rep = client.get(f"/api/v1/scans/{r.json()['id']}/report", headers=auth).json()["reports"]
            score, tamper, static = rep["score"], rep.get("tamper") or {}, rep["static"]
            files = (tamper.get("integrity") or {}).get("files") or {}
            observed_files = {k: sorted(c["path"] for c in files.get(k, [])) for k in ("modified", "added", "deleted")}
            observed_files = {k: v2 for k, v2 in observed_files.items() if v2}
            integrity = score["integrity"]["status"]
            sig = static["signature"]["status"]
            fuzzy = [d for d in (tamper.get("fuzzy_comparison") or {}).get("dex", []) if d["file"] in
                     (v["expect_files"].get("modified") or [])]
            feed_hits = [m for m in static.get("threat_intel", {}).get("matches", []) if m.get("basis") == "feed"]
            obs = {
                "integrity": integrity, "verdict": score["verdict"]["code"], "risk": score["risk"]["level"],
                "risk_score": score["risk"]["score"], "signature": sig,
                "certificate_changed": bool(tamper.get("certificate_changed")), "files": observed_files,
                "dex_similarity": [{"file": d["file"], "similarity": d["similarity"], "class": d["classification"]}
                                   for d in fuzzy],
                "near_duplicate_finding": any(f["id"] == "TAMPER_FUZZY_NEAR_DUPLICATE" for f in tamper.get("findings", [])),
                "threat_feed_matches": [f"{m['indicator']} (#{m['record_id']} {m['threat_family']})" for m in feed_hits],
            }
            checks = {
                "changed": (integrity not in ("CLEAN", "NO_BASELINE")) == truth["changed"],
                "unauthorized": (obs["certificate_changed"] or sig != "verified") == truth["unauthorized"],
                "files_exact": observed_files == v["expect_files"],
            }
            if truth.get("threat_feed_match"):
                checks["threat_feed_match"] = bool(feed_hits)
            results.append({"app": app["package"], "variant": key, "what": truth["what"], "detail": v.get("detail"),
                            "size_mb": round(v["file"].stat().st_size / 1e6, 1), "ms": round(ms),
                            "observed": obs, "checks": checks, "correct": all(checks.values())})
        results.append({"app": app["package"], "variant": "_baseline", "enrol_ms": round(enrol_ms),
                        "signer_matches_fdroid": signer_ok, "baseline_sha256": base["apk_sha256"]})
    client.__exit__(None, None, None)

    env = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "python": sys.version.split()[0],
           "fuzzy_limit_mb": FUZZY_LIMIT_MB, "c2_indicator": c2}
    out = ROOT / "evaluation" / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "realworld.json").write_text(json.dumps({"environment": env, "apps": APPS, "results": results},
                                                   indent=2), encoding="utf-8")
    (out / "realworld.md").write_text(markdown(env, results), encoding="utf-8")
    scored = [r for r in results if "correct" in r]
    print(f"{sum(r['correct'] for r in scored)}/{len(scored)} variants handled as expected; "
          f"written to {out / 'realworld.md'}")
    return 0


def markdown(env: dict, results: list[dict]) -> str:
    rows = [r for r in results if "correct" in r or "error" in r]
    base = {r["app"]: r for r in results if r.get("variant") == "_baseline"}
    lines = [
        "# MerkleTrust — Real-world apps (F-Droid)", "",
        f"Generated {env['generated']} by `python -m scripts.run_realworld_evaluation` (Python {env['python']}).",
        "Three open-source apps were downloaded from f-droid.org and verified against the SHA-256 pinned from F-Droid's",
        "repository index. Each official app was enrolled as the trusted baseline; attack variants were built with zip",
        "operations and apksigner only (no app was installed or run). Ground truth is fixed in the script before scanning.",
        f"DEX files up to {env['fuzzy_limit_mb']} MB were fuzzy-hashed for this run (the default limit is 4 MB).", "",
        "| App | Official signer matches F-Droid | Enrol time |", "|---|---|---|",
    ]
    for app, b in base.items():
        lines.append(f"| `{app}` | {'yes' if b['signer_matches_fdroid'] else '**no**'} | {b['enrol_ms']} ms |")
    if env.get("c2_indicator"):
        c = env["c2_indicator"]
        lines += ["", f"C2 address used in `code_c2_swap`: `{c['address']}` — {c['family']}, ThreatFox record "
                      f"#{c['record_id']}, first seen {c['first_seen']} (feed updated {c['feed_updated']})."]
    lines += ["", "| App | Variant | Integrity | Signed by someone else? | Changed files | Code similarity (ssdeep) | "
                  "Threat feed | Risk | Time | As expected |", "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if "error" in r:
            lines.append(f"| `{r['app']}` | {r['variant']} | ERROR {r['error']} | | | | | | | ✗ |")
            continue
        o = r["observed"]
        files = "; ".join(f"{k}: {', '.join(v)}" for k, v in o["files"].items()) or "none"
        sim = ", ".join(f"{d['file']} {d['similarity']}% ({d['class']})" for d in o["dex_similarity"]) or "—"
        feed = "; ".join(o["threat_feed_matches"]) or "—"
        lines.append(f"| `{r['app']}` | {r['variant']} | {o['integrity']} | "
                     f"{'yes' if o['certificate_changed'] or o['signature'] != 'verified' else 'no'} ({o['signature']}) | "
                     f"{files} | {sim} | {feed} | {o['risk']} ({o['risk_score']}) | {r['ms']} ms | "
                     f"{'✓' if r['correct'] else '✗ ' + ', '.join(k for k, ok in r['checks'].items() if not ok)} |")
    scored = [r for r in rows if "correct" in r]
    lines += ["", f"**{sum(r['correct'] for r in scored)}/{len(scored)} variants handled as expected.**", "",
              "Variant details:", ""]
    lines += [f"* `{r['app']}` {r['variant']}: {r['what']}" + (f" — {r['detail']}" if r.get("detail") else "")
              for r in scored]
    official = [r for r in scored if r["variant"] == "official_copy"]
    lines += ["", "## Risk scores of the untouched official apps", "",
              "Integrity answers (is it the original?) were correct for every variant. The *risk* score, however, is",
              "high for genuine apps: " + ", ".join(f"`{r['app']}` {r['observed']['risk']} ({r['observed']['risk_score']})"
                                                     for r in official) + ".",
              "These are false positives of the behavioural heuristics, which were designed on small synthetic apps.",
              "On 9 October two rule changes were made using these three apps as the DEVELOPMENT set (call-site",
              "analysis, so APIs called only from well-known libraries count a quarter; widget receivers no longer",
              "count as unprotected exports). Their effect was measured on eight other F-Droid apps never used for",
              "design (results/benign_risk_before.json / _after.json). Before that, two extraction defects were fixed,",
              "because they were objectively wrong rather than a matter of judgement: ASN.1 object identifiers (e.g. 1.3.6.1.5.5.7.3.1)",
              "reported as IP addresses, and the XMP namespace http://ns.adobe.com/xap/1.0/ reported as a web address.",
              "A standalone four-part OID such as 2.5.29.37 still looks like an IP and is still reported.",
              "The first run, before those fixes and before a bug in this script was corrected, is kept in",
              "realworld_initial.md: the script removed a library file (META-INF/versions/9/OSGI-INF/MANIFEST.MF)",
              "together with the signature files, and MerkleTrust correctly reported it as deleted.", "",
              f"Scan times include ssdeep over DEX files of up to {env['fuzzy_limit_mb']} MB (pure Python, about",
              "0.7 s per MB); with the default 4 MB limit the largest DEX files are skipped and scans are faster.", "",
              "Limitations: three apps and synthetic attacks on them (not malware found in the wild); the C2 address",
              "is inserted by us to show that a feed match is reported, not discovered in a real sample."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
