> **Historical planning document** — written at the start of the project and kept for the record.
> The system as built is described in [../ARCHITECTURE.md](../ARCHITECTURE.md); where this plan differs
> (e.g. chunk-based integrity, automatic baselines, trust score, PostgreSQL/React), the architecture document is authoritative.

# MerkleTrust — 4-Person Work Split & Integration Contract

Assumed stack: Python 3.11 + FastAPI + PostgreSQL (SQLAlchemy) + React frontend. One Git repo, one branch per person.

---

## 0. The rule that makes integration painless

**Engines are NOT services. They are plain Python functions.**

Nobody builds an API. Nobody builds a UI. There is exactly **one** HTTP API and **one** frontend, both owned by Basil. Every other person writes a module that satisfies this signature:

```python
# core/<your_engine>.py
def run(job_id: str, ctx: JobContext) -> dict:
    """
    Reads:   ctx.apk_path, ctx.workspace, ctx.prior (dict of earlier engine outputs)
    Writes:  <workspace>/<engine>.json   (must match the frozen schema)
             your own DB tables only
    Returns: the same dict it wrote to JSON
    Raises:  EngineError(msg) on failure — orchestrator handles status
    """
```

```python
@dataclass
class JobContext:
    apk_path: str          # quarantine/<sha256>.apk
    workspace: str         # jobs/<job_id>/
    prior: dict            # {"integrity": {...}, "static": {...}, ...}
    db: Session
    config: dict
```

Consequences: no HTTP between engines, no port clashes, no CORS, no auth between teammates, no "your service is down so I can't test". Integration day is `pip install -e .` and calling four functions in order.

---

## 1. Ownership table

| Person | Owns | Output file | DB tables it writes |
|---|---|---|---|
| **Basil** | Ingestion, DB schema, job orchestrator, Trust Score engine, REST API, React frontend | `score.json` | `jobs`, `apk_files`, `engine_status`, `trust_scores` |
| **Ajay** | Integrity Engine + all cryptography: chunking, Merkle tree, file map, Merkle Repository (canonical JSON, ECDSA, hash chain, inclusion proofs, blockchain simulation) | `integrity.json`, `repo_entry.json` | `chunk_hashes`, `merkle_roots`, `repository_entries`, `hash_chain`, `sim_blocks` |
| **Ashwini** | Static Analysis Engine + Tamper Detection + baseline management | `static.json`, `tamper.json` | `static_reports`, `permissions`, `certificates`, `iocs`, `dangerous_apis`, `baselines`, `tamper_reports` |
| **Bhavish** | Dynamic Analysis Engine: emulator, install, logcat, pcap, process monitor, Frida hooks | `dynamic.json` | `dynamic_reports`, `network_events`, `runtime_events`, `hook_events` |

**Hard boundaries**
- Only Basil edits `db/models.py`, `api/`, and `frontend/`. Others open an issue: "I need table X with columns Y" — Basil adds it within a day.
- Nobody imports another person's module. You only read `ctx.prior["<engine>"]`, which is a plain dict.
- One exception: Ajay publishes `core/merkle.py` as a **pure library** (`build_tree`, `root`, `proof`, `verify_proof`, `compare_trees`). Ashwini imports only these functions — no state, no DB.

---

## 2. Execution order (Basil's orchestrator)

```
ingestion
   ├── integrity      (Ajay)   ┐ run in parallel
   └── static         (Ashwini)┘
        ↓
      tamper          (Ashwini)   needs integrity + static
        ↓
      dynamic         (Bhavish)   needs tamper.suspicious_targets
        ↓
      trust_score     (Basil)
        ↓
      repository      (Ajay)
```

---

## 3. Frozen contracts

These are frozen on **Day 1**. Committed to `schemas/` as JSON Schema + a filled sample in `schemas/samples/`. Any change = PR + message in the group. No silent renames.

### `integrity.json` — Ajay
```json
{
  "job_id": "uuid",
  "sha256": "hex",
  "file_size": 12345678,
  "chunk_size": 65536,
  "chunk_count": 189,
  "chunks": [{"index": 0, "offset": 0, "length": 65536, "hash": "hex"}],
  "merkle_root": "hex",
  "tree_depth": 8,
  "file_map": [{"path": "classes.dex", "offset": 4096, "length": 2200000, "sha256": "hex"}]
}
```
`file_map` is the bridge between bytes and meaning: Ajay reads the ZIP central directory and records where each APK entry physically sits. Ashwini intersects changed chunk ranges with this to say *which file* changed.

### `static.json` — Ashwini
```json
{
  "job_id": "uuid",
  "package_name": "com.example.app",
  "version_name": "1.2.3", "version_code": 123,
  "min_sdk": 24, "target_sdk": 34,
  "permissions": [{"name": "android.permission.SEND_SMS", "protection_level": "dangerous", "is_dangerous": true}],
  "components": {"activities": [], "services": [], "receivers": [], "providers": []},
  "certificate": {"sha256": "hex", "issuer": "", "subject": "", "valid_from": "", "valid_to": "",
                  "self_signed": true, "schemes": ["v1","v2"]},
  "native_libs": [{"path": "lib/arm64-v8a/libfoo.so", "arch": "arm64-v8a", "sha256": "hex"}],
  "iocs": {"urls": [], "ips": [], "domains": [], "emails": []},
  "dangerous_apis": [{"api": "DexClassLoader", "class": "Lcom/x/Y;", "method": "load", "source": "smali/..."}],
  "findings": [{"id": "STATIC_001", "severity": "high", "title": "", "evidence": ""}],
  "artifacts": {"apktool_dir": "static/apktool", "jadx_dir": "static/jadx"}
}
```

### `tamper.json` — Ashwini
```json
{
  "job_id": "uuid",
  "role": "baseline" | "comparison",
  "baseline_found": true,
  "baseline_job_id": "uuid|null",
  "changed_chunks": [{"index": 42, "old_hash": "hex", "new_hash": "hex"}],
  "changed_files": [{"path": "classes.dex", "change_type": "modified|added|removed", "chunks": [42,43]}],
  "manifest_diff": {"permissions_added": [], "permissions_removed": [],
                    "components_added": [], "components_removed": []},
  "certificate_changed": true,
  "suspicious_targets": [
    {"type": "class",   "value": "Lcom/evil/Payload;", "reason": "new class in modified dex"},
    {"type": "service", "value": "com.evil.BgService", "reason": "component added vs baseline"},
    {"type": "url",     "value": "http://c2.example", "reason": "new IOC"}
  ],
  "findings": [{"id": "TAMPER_001", "severity": "critical", "title": "", "evidence": ""}]
}
```
`suspicious_targets` is the **only** thing Bhavish reads from Ashwini. If `role == "baseline"`, it is an empty list and Bhavish runs a generic hook set.

### `dynamic.json` — Bhavish
```json
{
  "job_id": "uuid",
  "emulator": {"avd": "mt_api30_root", "api_level": 30, "rooted": true},
  "installed": true, "launched": true, "duration_s": 90,
  "network": [{"ts": 0.0, "proto": "tcp", "dst_ip": "", "dst_port": 443, "host": "", "sni": "", "bytes": 0}],
  "dns": [{"ts": 0.0, "query": "", "answers": []}],
  "file_ops": [{"ts": 0.0, "op": "write", "path": ""}],
  "process_events": [{"ts": 0.0, "event": "fork", "detail": ""}],
  "hooks": [{"ts": 0.0, "target": "Lcom/evil/Payload;", "api": "", "args_sample": ""}],
  "runtime_permissions": [],
  "findings": [{"id": "DYN_001", "severity": "high", "title": "", "evidence": ""}],
  "artifacts": {"pcap": "dynamic/capture.pcap", "logcat": "dynamic/logcat.txt", "screenshots": []}
}
```

### `score.json` — Basil
```json
{
  "job_id": "uuid",
  "score": 37,
  "verdict": "trusted|suspicious|malicious",
  "rules_fired": [{"rule_id": "R_CERT_CHANGED", "weight": -30, "source": "tamper", "reason": ""}],
  "inputs": {"integrity_sha256": "hex", "static_sha256": "hex", "tamper_sha256": "hex", "dynamic_sha256": "hex"}
}
```
The scoring rule engine consumes only the `findings[]` arrays plus a handful of named fields. That means **everyone must populate `findings[]` with a stable `id` and `severity`** — that is how your work reaches the score without Basil reading your internals.

### `repo_entry.json` — Ajay
```json
{
  "entry_index": 17,
  "job_id": "uuid",
  "canonical_report_sha256": "hex",
  "prev_entry_hash": "hex",
  "entry_hash": "hex",
  "signature": "base64",
  "pubkey_id": "mt-signer-1",
  "repo_merkle_root": "hex",
  "inclusion_proof": [{"sibling": "hex", "position": "left|right"}],
  "timestamp": "ISO8601",
  "sim_block": {"height": 5, "block_hash": "hex", "tx_id": "hex", "simulated": true}
}
```
Blockchain is simulated: a local append-only chain of blocks where each block header hashes the previous header plus the batch Merkle root. Keep `"simulated": true` in the payload — it is honest and it still demonstrates the maths. Ajay also writes the tamper demo script: flip one byte in a stored report, re-run `verify_chain()`, show the break point.

---

## 4. Workspace layout (fixed, everyone obeys)

```
jobs/<job_id>/
  integrity.json
  static.json          static/apktool/   static/jadx/
  tamper.json
  dynamic.json         dynamic/capture.pcap   dynamic/logcat.txt
  score.json
  repo_entry.json
quarantine/<sha256>.apk
```

Never write outside your own subfolder. Never hardcode a path — use `ctx.workspace`.

---

## 5. Who passes what to whom (one line each)

- Basil → everyone: `JobContext` (apk path, workspace, prior reports).
- Ajay → Ashwini: `integrity.json` (`chunks[]` + `file_map[]`), and the `merkle.compare_trees()` function.
- Ashwini → Bhavish: `tamper.json` → `suspicious_targets[]`.
- Everyone → Basil: `findings[]` + their JSON file.
- Basil → Ajay: `score.json` + the merged report to be canonicalised and signed.
- Ajay → Basil: `repo_entry.json` + `merkle.verify_proof()` for the `/verify` endpoint.

That is six arrows. Nothing else crosses.

---

## 6. API surface (Basil only)

| Method | Path | Returns |
|---|---|---|
| POST | `/api/upload` | `{job_id}` |
| GET | `/api/jobs/{id}` | per-engine status: `pending/running/done/failed` |
| GET | `/api/jobs/{id}/report` | merged report (all six JSONs) |
| GET | `/api/jobs/{id}/verify` | signature check + inclusion proof result |
| GET | `/api/repository` | ledger entries, paginated |
| GET | `/api/repository/{index}/proof` | inclusion proof for one entry |

---

## 7. Timeline

**Week 1 — contracts and stubs (everyone, together)**
- Freeze the six schemas. Commit a realistic filled sample for each to `schemas/samples/`.
- Each person's `run()` exists and simply returns their sample fixture.
- Basil: DB migrations + orchestrator + upload endpoint + frontend skeleton reading fixtures.
- **End of week 1 the whole pipeline runs end-to-end on fake data.** Everything after this is swapping fakes for real, one module at a time, with zero integration risk.

**Weeks 2–3 — real implementations**
- Ajay: chunking + Merkle tree + file map → then repository, ECDSA, hash chain, proofs, simulated chain.
- Ashwini: apktool/jadx wrappers → manifest, cert, resources, native libs → IOC + dangerous APIs → then tamper diff.
- Bhavish: AVD setup script (commit it — everyone needs to reproduce), install + launch + logcat + pcap → Frida hooks driven by `suspicious_targets`.
- Basil: scoring rules, report merge, real frontend views.

**Week 4 — real wiring**
- Run on three APKs: a clean one, a self-repackaged version of it (change one string + re-sign, make it yourselves), and a known-bad sample.
- Clean APK first run → baseline. Repackaged APK → must localise the exact changed chunk and file.

**Week 5 — demo polish**
- Verification UI, tamper-the-ledger demo, slides, report.

---

## 8. Five rules that prevent merge hell

1. Schema change → PR to `schemas/` + group message. Never rename a field in place.
2. Your engine must run standalone: `python -m core.<engine> --apk sample.apk --workspace /tmp/x`.
3. Your engine never crashes the pipeline. Catch everything, return partial output with `"status": "partial"` and a finding.
4. Only Basil touches `db/models.py`, `api/`, `frontend/`.
5. Commit your sample fixture before you commit your implementation. Others develop against it.
