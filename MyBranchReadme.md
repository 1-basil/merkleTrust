# MyBranchReadme — Bhavish (Dynamic Analysis Engine)

## 1. Project Context

**MerkleTrust** is a zero-trust Android APK integrity verification and runtime defense framework.
The project is a multi-person implementation with a shared architecture where each person owns a specific engine.
All engines are plain Python functions — not services — called by Basil's orchestrator.

---

## 2. Bhavish's Exact Responsibility

**Owner:** Dynamic Analysis Engine

As defined in `MerkleTrust_Work_Split.md`, this includes:

- Android emulator / AVD boot and management
- APK installation into the emulator
- APK launch (via monkey or `am start`)
- Logcat collection
- Packet capture / PCAP
- Process monitoring
- Runtime event monitoring
- Frida hooks — targeted by `suspicious_targets` from the Tamper Engine
- Generic Frida hook set for baseline runs (no suspicious targets)

---

## 3. Dynamic Engine Scope

### Engine Interface

```python
# core/dynamic.py
def run(job_id: str, ctx: JobContext) -> dict:
```

### Inputs

| Source | Field | Purpose |
|---|---|---|
| `ctx.apk_path` | APK file on disk | Install into emulator |
| `ctx.prior["static"]["package_name"]` | Package name | What to launch |
| `ctx.prior["static"]["components"]` | Activities, services, etc. | Activities to poke |
| `ctx.prior["tamper"]["suspicious_targets"]` | List of targets | Drive targeted Frida hooks |
| `ctx.config["emulator_avd"]` | AVD name | Which emulator to boot |
| `ctx.config["dynamic_timeout_s"]` | Timeout seconds | Timebox for the entire run |

### Outputs

- `<workspace>/dynamic.json` — frozen contract schema
- `<workspace>/dynamic/capture.pcap` — network capture artifact
- `<workspace>/dynamic/logcat.txt` — logcat artifact
- `<workspace>/dynamic/screenshots/` — optional screenshots

---

## 4. Files Bhavish Owns

| File | Status | Notes |
|---|---|---|
| `core/dynamic.py` | **EXISTS** — stub | Correct interface, frozen schema match verified |
| `schemas/samples/dynamic_sample.json` | **NEW** | Realistic filled sample (worksplit.md Week 1 rule 5) |
| `schemas/samples/prior.json` | **NEW** | Upstream engine fixture for standalone testing |

Bhavish does **NOT** own or edit:
- `core/contracts.py` (Basil)
- `core/orchestrator.py` (Basil)
- `core/integrity.py` (Ajay)
- `core/static.py` (Ashwini)
- `core/tamper.py` (Ashwini)
- `core/scoring.py` (Basil)
- `core/repository.py` (Basil/Ajay)
- `db/models.py` (Basil)
- `api/` (Basil)
- `frontend/` (Basil)

---

## 5. `dynamic.json` Frozen Schema

From `MerkleTrust_Work_Split.md` §3:

```json
{
  "job_id": "uuid",
  "engine": "dynamic",
  "status": "ok|partial",
  "findings": [{"id": "DYN_001", "severity": "high", "title": "", "evidence": ""}],
  "emulator": {"avd": "mt_api30_root", "api_level": 30, "rooted": true},
  "installed": true,
  "launched": true,
  "duration_s": 90,
  "network": [{"ts": 0.0, "proto": "tcp", "dst_ip": "", "dst_port": 443, "host": "", "sni": "", "bytes": 0}],
  "dns": [{"ts": 0.0, "query": "", "answers": []}],
  "file_ops": [{"ts": 0.0, "op": "write", "path": ""}],
  "process_events": [{"ts": 0.0, "event": "fork", "detail": ""}],
  "hooks": [{"ts": 0.0, "target": "Lcom/evil/Payload;", "api": "", "args_sample": ""}],
  "runtime_permissions": [],
  "artifacts": {"pcap": "dynamic/capture.pcap", "logcat": "dynamic/logcat.txt", "screenshots": []}
}
```

**Common required keys** (all engines):
- `job_id` — the job_id passed in
- `engine` — `"dynamic"`
- `status` — `"ok"` or `"partial"` (never `"failed"` — raise `EngineError` instead)
- `findings[]` — list of `{"id", "severity", "title", "evidence"}` where `severity ∈ {info, low, medium, high, critical}`

> **Note:** The existing stub in `core/dynamic.py` is missing `"engine"` and `"screenshots"` in artifacts.
> These will be fixed when Phase 1 begins.

---

## 6. Database Tables Owned by Bhavish

| Table | Purpose |
|---|---|
| `dynamic_reports` | Per-job dynamic analysis summary |
| `network_events` | Network connections observed during runtime |
| `runtime_events` | Process events, file ops, permissions |
| `hook_events` | Frida hook observations |

**Important:** Only Basil edits `db/models.py`. If these tables do not yet exist, Bhavish must request them from Basil with exact column specifications. See §10 below.

---

## 7. Inputs Received from Other Engines

| Engine | Key in `ctx.prior` | Fields Bhavish reads |
|---|---|---|
| Static (Ashwini) | `ctx.prior["static"]` | `package_name`, `components.activities` |
| Tamper (Ashwini) | `ctx.prior["tamper"]` | `suspicious_targets[]`, `role` |

**Critical contract:** `suspicious_targets` is a list of:
```json
{"type": "class|service|url", "value": "string", "reason": "string"}
```

- If `role == "baseline"`, `suspicious_targets` is `[]` → use generic hook set.
- If `suspicious_targets` is non-empty → generate targeted Frida hooks.

Bhavish does **NOT** import any other engine's Python module. All data comes through `ctx.prior` dicts.

---

## 8. Execution Order

```
ingestion
   ├── integrity      (Ajay)   ┐ run in parallel
   └── static         (Ashwini)┘
        ↓
      tamper           (Ashwini)   needs integrity + static
        ↓
      dynamic          (Bhavish)   needs tamper.suspicious_targets  ← THIS ENGINE
        ↓
      trust_score      (Basil)
        ↓
      repository       (Ajay)
```

Dynamic runs **after** tamper, **before** trust_score.

---

## 9. Implementation Phases

| Phase | Description | Status |
|---|---|---|
| **0** | Understand repository, read `worksplit.md`, inspect existing code | ✅ **COMPLETE** |
| **1** | Contract/stub — fix `core/dynamic.py` to match frozen schema, standalone runner, sample fixtures | ✅ **COMPLETE** |
| **2** | Android emulator / AVD — reproducible AVD setup | 🔲 Next |
| **3** | APK installation and launch | 🔲 |
| **4** | Runtime collection — logcat, PCAP, DNS, file ops, process events, permissions | 🔲 |
| **5** | Frida integration — targeted + generic hooks | 🔲 |
| **6** | Findings — stable IDs, severity, consumable by Trust Score | 🔲 |
| **7** | Database integration — write to Bhavish's tables only | 🔲 |
| **8** | Integration testing — realistic APKs, baseline + tamper scenarios | 🔲 |

---

## 10. Dependencies / Inputs Required from Teammates

### From Basil (DB owner)

- [ ] **Create database tables** for Bhavish's engine. Required tables and suggested columns:
  - `dynamic_reports`: `id`, `job_id` (FK→jobs), `status`, `emulator_avd`, `api_level`, `rooted`, `installed`, `launched`, `duration_s`, `report_json`, `created_at`
  - `network_events`: `id`, `job_id`, `ts`, `proto`, `dst_ip`, `dst_port`, `host`, `sni`, `bytes_transferred`
  - `runtime_events`: `id`, `job_id`, `ts`, `event_type`, `detail`, `source` (logcat/procmon)
  - `hook_events`: `id`, `job_id`, `ts`, `target`, `api`, `args_sample`
- [ ] **Confirm DB connection** — how `ctx.db` (SQLAlchemy Session) is provided

### From Ashwini (Tamper Engine owner)

- [ ] **Provide a realistic `tamper.json` fixture** with populated `suspicious_targets[]` (for testing targeted hook generation)
- [ ] **Provide a baseline `tamper.json` fixture** with `role: "baseline"` and empty `suspicious_targets` (for testing generic hook fallback)
- [ ] **Provide a realistic `static.json` fixture** with real `package_name` and `components.activities`

### From the Team (shared decisions)

- [ ] **Agree on emulator API level** — the contract says `api_level: 30` (Android 11). Confirm this is the team standard.
- [ ] **Agree on AVD name** — the contract says `mt_api30_root`. Confirm this.
- [ ] **PCAP capture mechanism** — confirm whether `tcpdump` inside the emulator, the `-tcpdump` emulator flag, or another tool is the project-approved approach.
- [ ] **Provide test APKs**:
  - A clean APK for baseline runs
  - A repackaged APK (changed string + re-signed) for tamper-driven runs
  - A known-bad sample for validating detection
- [ ] **Frida version** — agree on Frida version and frida-server binary for the target API level
- [ ] **Android SDK location** — confirm how `adb`, `emulator`, and `avdmanager` paths are communicated (via `ctx.config`?)

### Environment Requirements

- [ ] Android SDK with platform-tools (`adb`) and emulator binary
- [ ] An AVD image for API 30 (rooted)
- [ ] Python 3.11+
- [ ] `frida` and `frida-tools` pip packages
- [ ] `frida-server` binary matching the target architecture (x86_64 for emulator)
- [ ] `tcpdump` or equivalent for PCAP (available inside the emulator or host-side capture)
- [ ] `scapy` or `dpkt` for PCAP parsing (to be confirmed)

---

## 11. Required Test APKs / Test Data

| Artifact | Source | Purpose |
|---|---|---|
| Clean test APK | Team-provided | Baseline run, generic hooks |
| Repackaged APK | Team-built (changed string + re-sign) | Tamper-driven suspicious targets |
| Known-bad sample | Team-provided | Validate dynamic detection |
| `prior.json` fixture | To be created at `schemas/samples/prior.json` | Standalone testing without real upstream engines |

---

## 12. Environment Requirements

```
Python         3.11+
Android SDK    platform-tools (adb), emulator, avdmanager
System Image   system-images;android-30;google_apis;x86_64 (or x86_64 rooted)
Frida          frida + frida-tools (pip), frida-server (on-device)
PCAP           tcpdump (emulator) or emulator -tcpdump flag
```

---

## 13. Commands to Run/Test the Dynamic Engine

### Standalone (stub mode, today)

As required by worksplit.md rule 2:
```bash
python -m core.dynamic --apk sample.apk --workspace /tmp/x
```

With prior fixture for testing against upstream engine data:
```bash
python -m core.dynamic --apk sample.apk --workspace /tmp/x --prior schemas/samples/prior.json
```

Minimal (auto-creates temp workspace):
```bash
python -m core.dynamic --apk sample.apk
```

### Via orchestrator (full pipeline)

```bash
python -m core.orchestrator path/to/sample.apk
```

---

## 14. Current Implementation Status

### Phase 0 — COMPLETE ✅

Repository inspected, worksplit.md read, all contracts understood.

### Phase 1 — COMPLETE ✅

**Changes made:**
1. Fixed `core/dynamic.py` — added `"screenshots": []` to `artifacts` to match frozen schema exactly
2. Updated standalone runner to use `--apk` / `--workspace` flags (worksplit.md rule 2)
3. Created `schemas/samples/dynamic_sample.json` — realistic filled sample (worksplit.md Week 1 rule 5)
4. Created `schemas/samples/prior.json` — upstream engine fixture for standalone testing (contracts.py line 253)

**Verified:**
- Standalone execution: `python -m core.dynamic --apk test.apk --prior schemas/samples/prior.json` ✅
- Output `dynamic.json` matches frozen schema exactly — all 19 fields present ✅
- Prior fixture correctly read: `package_name` and `suspicious_targets` populated in output ✅
- Engine returns `status: "partial"` with informational finding (correct for stub) ✅

**What does NOT exist yet:**
- `db/` directory — not created (Basil's responsibility)
- No real test APKs in the repository
- No `quarantine/` directory

---

## 15. Known Limitations / Blockers

| Blocker | Owner | Status |
|---|---|---|
| No test APK in the repository | Team | 🔴 Blocks all runtime testing |
| No `schemas/samples/prior.json` fixture | Team (conventions say commit samples) | 🔴 Blocks convenient standalone testing |
| No `db/models.py` or migrations | Basil | 🟡 Blocks Phase 7 only |
| No Ashwini fixture with real `suspicious_targets` | Ashwini | 🟡 Blocks Phase 5 targeted-hook testing |
| Android SDK / emulator not confirmed on dev machines | Team | 🟡 Blocks Phase 2+ |
| Frida version not agreed | Team | 🟡 Blocks Phase 5 |
| PCAP capture mechanism not decided | Team | 🟡 Blocks Phase 4 network capture |

---

## 16. Integration Checklist

- [ ] `core/dynamic.py` → `run()` returns dict matching frozen `dynamic.json` schema exactly
- [ ] `run()` writes `<workspace>/dynamic.json` via `emit()`
- [ ] `run()` includes all common keys: `job_id`, `engine`, `status`, `findings[]`
- [ ] `findings[]` uses stable `DYN_xxx` IDs with valid severity values
- [ ] Engine degrades gracefully: returns `status: "partial"` on partial failure, never crashes pipeline
- [ ] Engine raises `EngineError` only on total unrecoverable failure
- [ ] Engine handles missing `ctx.prior["tamper"]` gracefully (empty targets → generic hooks)
- [ ] Engine handles missing `ctx.prior["static"]` gracefully
- [ ] Standalone runner works: `python -m core.dynamic <apk> [prior.json]`
- [ ] Engine respects `ctx.config["dynamic_timeout_s"]` — never hangs
- [ ] All file writes go inside `ctx.workspace` and `ctx.subdir("dynamic")`
- [ ] No hardcoded paths
- [ ] No imports of other engine modules
- [ ] Database writes use ONLY Bhavish's four tables
- [ ] Output verified against frozen schema by automated test
