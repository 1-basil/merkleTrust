"""scripts/seed_demo.py — Put a running MerkleTrust server into a realistic demo state.

    python -m scripts.seed_demo http://127.0.0.1:8000 \
        --admin admin --analyst analyst          # passwords are prompted for

Uses only the public REST API, exactly as a user would:
  1. the administrator enrols and approves the official build (signed_v1v2_ec.apk);
  2. the analyst scans five variants: the identical app, a legitimate update, a copy
     re-signed with another key, a patched copy (modified DEX + injected file) and a
     suspicious app without a baseline.
Prints "<name>=<scan id>" pairs (input for tests/e2e/ui_smoke.mjs).
Passwords may also come from MERKLETRUST_ADMIN_PASSWORD / MERKLETRUST_ANALYST_PASSWORD.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import httpx

from scripts.apk_mutations import rewrite_zip

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "apks"


def _login(client: httpx.Client, username: str, env: str) -> dict[str, str]:
    password = os.environ.get(env) or getpass.getpass(f"Password for {username}: ")
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _post_file(client: httpx.Client, url: str, headers: dict, path: Path, name: str | None = None) -> dict:
    r = client.post(url, headers=headers, files={"file": (name or path.name, path.read_bytes())})
    if r.status_code >= 400:
        raise SystemExit(f"{url} failed: {r.status_code} {r.text}")
    return r.json()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("base_url")
    parser.add_argument("--admin", default="admin")
    parser.add_argument("--analyst", default="analyst")
    args = parser.parse_args(argv)

    client = httpx.Client(base_url=args.base_url, timeout=120)
    admin = _login(client, args.admin, "MERKLETRUST_ADMIN_PASSWORD")
    analyst = _login(client, args.analyst, "MERKLETRUST_ANALYST_PASSWORD")

    official = FIXTURES / "signed_v1v2_ec.apk"
    enrolled = _post_file(client, "/api/v1/baselines", admin, official, "demo-1.2.0-official.apk")
    bid = enrolled["baseline"]["id"]
    client.post(f"/api/v1/baselines/{bid}/approve", headers=admin,
                json={"note": "Official release 1.2.0"}).raise_for_status()

    with tempfile.TemporaryDirectory() as tmp:
        dex = zipfile.ZipFile(official).read("classes.dex")
        patched = rewrite_zip(official, Path(tmp) / "demo-patched.apk",
                              modify={"classes.dex": dex + b"\0payload"}, add={"assets/payload.bin": b"evil"})
        variants = {"clean": official, "update": FIXTURES / "update_v1v2_ec.apk",
                    "resigned": FIXTURES / "signed_v2v3_rsa.apk", "patched": patched,
                    "suspicious": FIXTURES / "suspicious_v2_ec.apk"}
        ids = {name: _post_file(client, "/api/v1/scans", analyst, path)["id"] for name, path in variants.items()}

    for _ in range(240):
        items = client.get("/api/v1/scans", headers=analyst, params={"limit": 100}).json()["items"]
        if all(i["status"] in ("done", "failed") for i in items if i["id"] in ids.values()):
            break
        time.sleep(0.5)
    print(" ".join(f"{k}={v}" for k, v in ids.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
