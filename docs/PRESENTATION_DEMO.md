# MerkleTrust — presentation status and demo script

Rewritten after consolidating the two frontends into one React SPA at
`frontend/`. Everything below was run and verified on this machine before
writing it down — nothing here is aspirational.

---

## 1. What is complete

### Core pipeline (all six stages are real, not stubs)

| Stage | Owner (per README) | What it actually does |
|---|---|---|
| Integrity | Ajay | Per-file SHA-256 manifest + Merkle root over the real ZIP central directory; 64 KB chunk forensics kept as a supplementary signal. |
| Static | Ashwini | Real binary AndroidManifest.xml (AXML) parsing, permissions, components, DEX scan for dangerous APIs/IOCs, X.509 certificate extraction (v1 and v2/v3), APK signature verification. |
| Tamper | Ashwini | DB-backed trusted baselines with explicit admin enroll → approve → ECDSA signature (no auto-baselining). Localizes a change to the exact file changed, not just "something changed." |
| Dynamic | Bhavish | Installs and launches the real APK on a rooted Android emulator, captures logcat, a pure-Python PCAP-equivalent network capture, kernel kprobe exec tracing, and optional Frida instrumentation. **Off by default** — see §2. |
| Scoring | Basil | Three separate answers: integrity status (CLEAN/MODIFIED/…), a risk score built from a findings catalogue with no double-counting, and a plain-language verdict. |
| Repository/Ledger | Basil | Seals every job into **two** places: a signed, hash-linked audit-chain database, and an **append-only JSON-lines hash chain** (`data/ledger/chain.jsonl`) that commits to the exact bytes written to disk. |

### Beyond the original brief (added by the team since)

- **REST API** (`api/`): auth with roles, rate limiting, CORS allow-list, CSP and
  security headers, structured logging, Alembic migrations.
- **One frontend** (`frontend/`): a React SPA built with Vite. The earlier plain-JS
  dashboard and the newer React app were two separate directories for a while;
  they're now consolidated into this one. FastAPI serves its production build
  (`frontend/dist`, built with `npm run build`) — it will not serve anything
  until that build exists.
- **Supply-chain attestation**: in-toto Statement v1 + SLSA Provenance v1.0 in a
  signed DSSE envelope (`core/attestation.py`).
- **Offline verifier** (`core/offline_verifier.py`): verifies a self-contained
  bundle — signature, hash chain, Merkle proof — with no network or database.
- **YARA scanning and native-library analysis** (`core/yara_scanner.py`,
  `core/native_analyzer.py`).

### Tests

- Full suite: **448 passing** (`python -m pytest`), with `frontend/dist` built first.
- Security-marked subset: **90 passing** (`python -m pytest -m security`).
- Browser UI smoke test (headless Chrome, every real route, desktop + phone):
  **no problems** — rewritten for the React app's actual markup and routes.
- Frontend production build: succeeds (`cd frontend && npm run build`).
- All of the above run clean on this machine as of this writing.

### Verified on the real reference APK (not a synthetic sample)

- Baselined the real APK (via `scripts/baseline_cli.py` — see §3, baseline
  enrollment is CLI/API only, not exposed in the UI), then built a
  byte-flipped copy: the system localized the change to exactly `classes.dex`
  out of 741 files, flagged `MODIFIED`/`CRITICAL`, and the tampered copy's
  broken signature also made **Android itself** refuse to install it — two
  independent layers catching the same tamper.
- Live dynamic analysis on a real rooted emulator (with `MERKLETRUST_DYNAMIC_ENABLED=true`):
  app installs, launches, Frida attaches, real network connections captured.
- The ledger's tamper demo (`scripts/tamper_demo.py`): flips one character of
  a stored entry, shows exactly which entry breaks and why, restores the file
  byte-for-byte.

### What is deliberately not implemented

- The repository-wide Merkle tree and the simulated-blockchain batching from
  the original brief were superseded by the hash-linked ledger design, which
  is stronger (every entry individually verifiable, not just whole batches).
- Packet capture is a pure-Python PCAP-equivalent parser, not a dropped-in
  tcpdump binary.

---

## 2. Known gaps (say these before someone asks)

- **Dynamic analysis is off by default**, and a scan with it off returns in
  a second or two — that speed is correct behaviour, not a shortcut. It
  needs `MERKLETRUST_DYNAMIC_ENABLED=true` (set before starting the server)
  and a booted emulator; with those, a real scan with it on takes ~20–30
  seconds for the observation window alone, not the single-digit seconds
  you'll see with it off.
- **Baseline enrollment and approval are CLI/API only** (`scripts/baseline_cli.py`
  or `POST /api/v1/baselines`). The Baselines page in the UI is read-only by
  design — it says so on the page. If you're demoing baseline enrollment live,
  do it from a terminal, not by looking for a button in the browser.
- **The ledger's canonical-reproducibility digest is not authenticated by the
  chain.** The chain commits to the exact bytes stored (`sealed_sha256`), which
  is what makes it unbreakable by volatile fields. A secondary digest
  (`canonical_report_sha256`) is kept for deduplication only, and altering it
  alone would go undetected. This is a documented, deliberate trade-off.
- **If the ledger write succeeds but the database write then fails**, the
  database (a cache) is briefly missing an entry the ledger (the authority)
  has. Rebuilding the database from the ledger after that isn't implemented.
- **Frida hooks fire on dangerous-API calls only.** A clean app that never
  calls `DexClassLoader`/`Runtime.exec`/`Cipher` shows zero hooks during the
  observation window — correct, not a bug.
- **The new frontend's Chain page doesn't expose the tamper/restore demo as a
  button** (the old one did). Use `scripts/tamper_demo.py` for that — it's
  the safer, dependency-free option anyway (see Step 3a below).

---

## 3. Demo script

Total time: ~10 minutes for the safe path, ~15 with the live emulator section.
**Run step 0 well before you're called up** — it's the only slow, failure-prone
step. **Also build the frontend before you start** — the server serves
nothing at `/` until you do.

### Step 0 (do this *before* your slot, not during it)

Build the frontend once:

```powershell
cd C:\pbl_cns\frontend
npm ci
npm run build
```

If you want the live emulator section, boot it now so it's ready:

```powershell
& "$env:LOCALAPPDATA\Android\Sdk\emulator\emulator.exe" -avd Pixel_6 -no-snapshot -no-boot-anim
```

Wait for `adb devices` to show it, then push and start frida-server (already
downloaded to the scratch temp dir from earlier sessions; re-download from
`https://github.com/frida/frida/releases` if that's gone):

```powershell
adb root
adb push frida-server /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server && (nohup /data/local/tmp/frida-server >/dev/null 2>&1 &)"
```

If this step is flaky or you're short on time, **skip the live emulator
section** (3b below) and just show the dynamic engine's JSON output from a
prior run — the result is identical, just not live. Also set the enable flag
now if you want dynamic analysis live, since it's read once at server start:

```powershell
$env:MERKLETRUST_DYNAMIC_ENABLED = "true"
```

### Step 1 — start the server (30 seconds)

```powershell
cd C:\pbl_cns
uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in a browser — this is the (one, consolidated)
frontend. Sign in with an admin account; create one first if you haven't:

```powershell
$env:MERKLETRUST_NEW_USER_PASSWORD = "demo-password-123"
python -m scripts.manage_users create demo --role admin
```

### Step 2 — the core story: integrity, tamper, scoring (4 minutes)

1. **Upload the reference APK** (`booking-hotelcom-hotelbooking-….apk`) from
   the "Upload & Scan" page. Walk through the result page: trust score,
   Merkle root, certificate status, security findings. Say out loud that this
   is a real commercial APK, not a synthetic test file.
2. **Enroll it as a trusted baseline — from a terminal, not the UI**:
   ```powershell
   python -m scripts.baseline_cli enroll booking-hotelcom-hotelbooking-32-63214345-8c8a2f82fdf0275d1e93fd8d7c6db081.apk --by demo
   python -m scripts.baseline_cli approve 1 --by demo --note "Reference build for the demo"
   ```
   Narrate: *"this is deliberately a two-step admin action, and deliberately
   not a UI button — the old design auto-trusted the first APK it ever saw,
   which is a poisoning vulnerability we removed."* Then show the Baselines
   page in the browser — it now lists this as approved.
3. **Upload the same APK again** through the UI. Verdict: `CLEAN`. It
   matches its own baseline.
4. **Build a tampered copy and upload it.** Either use a pre-built one, or
   build it live:
   ```powershell
   python -c "
   import zipfile
   from scripts.apk_mutations import rewrite_zip
   src = 'booking-hotelcom-hotelbooking-32-63214345-8c8a2f82fdf0275d1e93fd8d7c6db081.apk'
   data = zipfile.ZipFile(src).read('classes.dex')
   mutated = bytearray(data); mutated[len(mutated)//2] ^= 0xFF
   rewrite_zip(src, 'tampered_demo.apk', modify={'classes.dex': bytes(mutated)})
   "
   ```
   Upload `tampered_demo.apk` through the UI. Point out on the result page:
   - Verdict flips to `High risk` / `Differs from the trusted master copy`.
   - The security findings list shows the app's digital signature is broken
     and its program code was changed — **exactly** `classes.dex`, none of
     the app's other files.
   - The signature check independently reports invalid — **because the
     mutation also breaks the real Android signing block**, so Android
     itself would refuse to install this file. Two layers catching the same
     tamper is the strongest point to make here.
   - Click **"Verify now"** in the Integrity & Authenticity card — this
     cryptographically re-checks the signed, sealed record against what's
     stored right now, live.

### Step 3a — the ledger (3 minutes, the mathematically provable part)

```powershell
python -m scripts.tamper_demo
```

This is self-contained and has no dependencies — if nothing else works on
presentation day, this will. Narrate each of its four printed steps as it
runs:
1. Chain verifies valid.
2. One character of one entry is changed on disk.
3. Verification immediately names the exact broken entry and why.
4. The file is restored byte-for-byte and re-verified.

The key sentence: *"the chain seals the exact bytes we stored, not a
recomputed summary — so there's no volatile field anywhere that can ever
make a genuine entry look broken."*

### Step 3b — live dynamic analysis (optional, 3 minutes, only if Step 0 worked)

If you set `MERKLETRUST_DYNAMIC_ENABLED=true` before starting the server in
Step 1, uploads already run it — no extra step needed. Narrate while it runs
(~20–30 seconds, visibly longer than the dynamic-off uploads in Step 2):
*"it's actually installing and launching this app on a real emulator right
now, capturing its real network traffic and system calls."* Show the result:
network connections captured, Frida attached. If it shows zero Frida hooks,
that's correct — this APK doesn't call the specific APIs the hooks watch for.

**Fallback if the emulator isn't ready:** mention dynamic analysis is real
but takes an emulator boot, which you've skipped for time, and show a
`dynamic.json` from a prior run instead.

### Step 4 — if there's time: the extras

- `GET /api/v1/scans/{id}/attestation` — a signed SLSA/in-toto attestation.
- `GET /api/v1/scans/{id}/bundle` — a bundle `scripts/verify_offline.py` can
  check with zero network access.

### If something breaks live

- **`/` shows nothing or a blank page**: the frontend hasn't been built —
  run Step 0's `npm run build` in `frontend/`.
- **Server won't start**: check nothing else is on port 8000
  (`Get-NetTCPConnection -LocalPort 8000`).
- **Upload fails**: the body-size limit is 100 MB by default; the reference
  APK is ~2.1 MB, so this shouldn't trigger.
- **Dynamic analysis hangs**: it's timeboxed and will report `partial` with a
  clear finding, not hang forever — just wait it out, or skip to the next
  step while narrating that the timeout is itself the intended safety
  behaviour.
- **Anything else**: fall back to `python -m scripts.tamper_demo` (step 3a).
  It has zero dependencies, zero network calls, and makes the single most
  defensible claim in the project.
