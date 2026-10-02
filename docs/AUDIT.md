# MerkleTrust — Repository Audit (Baseline: commit `6f10447`)

Date: 2026-10-02. Scope: the whole repository (backend, engines, crypto, DB, API,
frontend, tests, evaluation, docs, Git). Every finding below was **reproduced** on
the audited commit unless marked *(code review)*.

Legend: ✅ implemented correctly · 🟡 partially implemented · ❌ broken · ⬜ missing

---

## 1. Component status

| Component | Status | Summary |
|---|---|---|
| ZIP / APK opening | 🟡 | `zipfile` used directly; no size, entry-count, compression-ratio or path checks. |
| AXML (binary manifest) parser | ❌ | Crashes on **every real binary manifest** (`struct.error: unpack requires a buffer of 26 bytes`). Only plain-text XML (synthetic test APKs) parses. Res_value layout is also decoded incorrectly. |
| DEX analysis | 🟡 | Parses string table; class extraction OK. Dangerous-API detection is substring matching over all strings (no method-reference context). |
| Certificate extraction | 🟡 | v1 (`META-INF/*.RSA/EC/DSA`) PKCS#7 only. v2/v3 detected by magic-byte search, certificate **not extracted** — v2-only APKs (most modern apps) yield an empty certificate. |
| APK signature verification | ⬜ | APK signatures are never verified (neither v1 digests nor v2 block). |
| Per-file SHA-256 | 🟡 | `integrity.file_map` computes per-file hashes, but tamper detection **ignores them** and uses 64 KB chunk overlap instead. |
| Chunk-based Merkle integrity | 🟡 | Works mechanically, but fixed-offset chunks mean one inserted byte marks every later chunk/file as "modified". |
| Merkle tree library | 🟡 | Root/proof/verify correct for the happy path. **No leaf/node domain separation** and odd-node duplication ⇒ `[a,b,c]` and `[a,b,c,c]` have the same root (CVE-2012-2459 class). |
| Trusted baseline | ❌ | First APK seen for a package silently becomes the baseline (baseline poisoning). DB path uses columns that don't exist (`chunk_hashes`, `file_map`, `static_data`) — the exception is swallowed; the `baselines` table has **0 rows**. Falls back to `data/baselines.json`, keyed by package only; the `cert_sha256` lookup argument is ignored. No approval, no signature, no versioning. |
| Certificate comparison | 🟡 | Compares fingerprints, but also sets `certificate_changed=True` whenever **any** `META-INF/` file changes — which happens for any content modification of a v1-signed APK (MANIFEST.MF digests change). |
| ECDSA P-256 signing | 🟡 | Correct primitive (`cryptography`, SHA-256). Key auto-generated unencrypted into `data/keys/`; verification **generates a new key** if the public key is missing (silent false "invalid"). Signature covers only `entry_hash`; `repo_merkle_root`, `inclusion_proof`, `sim_block`, `job_id` are unauthenticated. No key ID/versioning beyond a constant string. |
| Hash-chained ledger | 🟡 | `prev_entry_hash` chaining and `verify_chain()` work. Ledger stored in a JSON file **and** partially in the DB — two diverging sources of truth (22 JSON entries vs 10 DB rows locally). Non-atomic writes; concurrent jobs race on read-modify-write. |
| Blockchain simulation | ❌ | `prev_block_hash = SHA256("block:{h-1}")` — a constant, **not** the previous block's hash. Blocks are not actually linked. Five entries per "block" each produce a different `block_hash` at the same height. |
| Report verification endpoint | ❌ | `/api/jobs/{id}/verify` hashes `merged.json` (which includes the repository report itself) and compares with the hash taken *before* that report existed ⇒ `canonical_report_hash_matched` is **always False** ⇒ `is_valid` is always False. Reproduced on 3 jobs. |
| Risk scoring | ❌ | Double counting (cert change: −35 finding + −40 rule; DEX change: −35 + −25; self-signed: −8 + −10). Penalises self-signed certs, which is normal on Android. Failed engines contribute nothing ⇒ **a non-APK file scored "trusted" 84/100**. Integrity and risk are merged into one verdict. |
| Orchestrator / job processing | 🟡 | Sequential stages, per-stage status. `print()` logging, bare `except: pass` around DB writes, `traceback.print_exc()`. Job marked `done` unless *every* engine failed. |
| Dynamic engine (emulator) | 🟡 | Requires a running AVD; degrades to `partial` without one. Not required by the project brief; keep as an optional stage. |
| REST API | ❌ (security) | No auth, `allow_origins=["*"]` **with** `allow_credentials=True`, no upload size limit (whole file read into memory), extension-only validation, client filename stored unsanitised, `/api/tamper-demo` and `/api/upload-sample` are unauthenticated state-changing endpoints. A 9-byte non-ZIP named `../../evil.apk` was accepted (HTTP 200), scored "trusted", and sealed into the ledger. |
| Database | 🟡 | SQLAlchemy models exist; `create_all` only (no migrations); several models unused (`ChunkHash`, `StaticReportModel`, `TamperReportModel`, `DynamicReportModel`); no FK on `baselines`. |
| Frontend | 🟡 | Single page, functional. Several `innerHTML` interpolations of APK-derived strings (XSS sink). Technical jargon throughout; no audit history, baseline or chain-visualisation pages. |
| Tests | 🟡 | 16 pass, but: they only use text-XML synthetic APKs (hiding the AXML crash), write into the real `data/` directory, and the API test does not wait for the job to finish. No security tests. |
| Evaluation | ❌ | Committed `data/evaluation_summary.json` shows the **clean baseline classified "malicious", score 0** (polluted shared baseline store). No ground truth, no metrics. |
| Documentation | 🟡 | Claims PostgreSQL support (untested), "zero-trust", "runtime defense framework", "mathematically undeniable"; describes linked blocks that are not linked. |
| Git hygiene | 🟡 | Private keys were **never committed** (`git log --all` on `*.pem`, `data/keys/`). But 2 `.pyc` files are tracked, and `data/baselines.json` (test junk) and `data/evaluation_summary.json` (wrong results) are tracked. |

## 2. What is already good and will be preserved

- The engine contract (`core/contracts.py`): `run(job_id, ctx) -> dict`, JSON output per engine.
- Correct choice of primitives: SHA-256, ECDSA P-256 via `cryptography`.
- Canonical JSON (`sort_keys`, compact separators) for hashing.
- The Merkle proof format (`sibling` + `position`) and the tests for it.
- The DEX string-table parser and the IOC extraction (private/loopback IPs filtered).
- The permission classification table.
- The dynamic engine and Frida script generator (optional stage, teammate's work).
- `.gitignore` already excludes keys, `.env`, DBs, job workspaces.

## 3. Environment facts relevant to the plan

- Python 3.14, FastAPI 0.141, SQLAlchemy 2.0, cryptography 50, Alembic installed.
- Android SDK present (build-tools 35/36: `aapt2`, `d8`, `apksigner`, `zipalign`; platforms 35/36) and a JDK (`keytool`).
  ⇒ The evaluation can use **real, properly signed APKs** built from source, not only synthetic ZIPs. Tests must still run without the SDK (committed small fixtures).

## 4. Implementation plan (logical parts, each ends in a Git checkpoint)

| # | Part | Key outcomes |
|---|---|---|
| 0 | **Audit** | This document. |
| 1 | **APK parsing correctness** | Fixed AXML parser (real binary manifests), hardened ZIP reader (limits, path checks, zip-bomb guard), DEX analysis with method-reference context, certificate extraction for v1 **and** v2/v3, v1 signature verification, real signed APK test fixtures (no keys committed). |
| 2 | **Cryptographic core** | RFC 6962-style Merkle tree (0x00 leaf / 0x01 node prefixes, no duplication) with proofs; ECDSA P-256 signer/verifier over canonical JSON with key ID; keys from env/config path, never auto-written into the repo; explicit failure reasons. |
| 3 | **Trusted baseline + file integrity** | DB-backed baselines with explicit admin enrollment → approval → ECDSA signature; versioning; per-file SHA-256 manifest as the authoritative integrity check (modified/added/deleted/unchanged); Merkle root over the file manifest with per-file proofs; certificate comparison distinct from "malicious". Chunk analysis kept as supplementary forensics. |
| 4 | **Findings & risk scoring** | Integrity verdict (CLEAN / MODIFIED / CERTIFICATE CHANGED / NO BASELINE) separate from risk level (LOW–CRITICAL). Every finding has title, severity, explanation, evidence, recommendation. No double counting; failed analysis ⇒ "could not be analysed", never "trusted". |
| 5 | **Blockchain simulation & audit trail** | DB-backed, signed, genuinely hash-linked blocks for every security event; chain verification pinpointing the broken block; tamper/restore demo; honest naming ("Cryptographically Linked Blockchain Simulation"). |
| 6 | **Backend hardening** | Auth (admin / analyst roles), secure upload pipeline, job processing, structured logging, consistent error model, CORS allow-list, security headers, rate limiting, Alembic migrations, env-based config. |
| 7 | **Frontend** | Dashboard, Scan, Result (plain-language with Technical Details), File Changes, Findings, Certificate, Verification, Audit History, Baselines, Blockchain Simulation. No XSS sinks. |
| 8 | **Test suite** | Unit, integration and security tests listed in the brief; isolated temp data dirs. |
| 9 | **Evaluation & performance** | 12-case controlled dataset (real signed APKs where SDK available), ground truth, confusion-matrix metrics, timing by APK size; reproducible script. |
| 10 | **Documentation & threat model** | Architecture, threat model (threat → attack → detection → defence), API, DB, demo script, viva Q&A — all matched to the code. |
| 11 | **Final hardening & review** | Full run, secret scan, git review, final report. |
