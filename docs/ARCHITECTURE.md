# MerkleTrust System Architecture & Technical Specifications

MerkleTrust is a zero-trust Android application integrity verification, runtime defense, and cryptographic audit framework. It combines multi-layer Merkle tree chunking, binary static reverse engineering, differential tamper localization, dynamic sandboxing, and an append-only simulated blockchain ledger.

---

## 1. High-Level Architectural Flow

```
                      ┌───────────────────────┐
                      │    Uploaded APK       │
                      └──────────┬────────────┘
                                 │
                     ┌───────────┴───────────┐
                     ▼                       ▼
            ┌─────────────────┐     ┌─────────────────┐
            │ Integrity Engine│     │ Static Analysis │
            │ (64KB Chunking &│     │ (AXML, DEX,     │
            │  Merkle Root)   │     │  Certs, APIs)   │
            └────────┬────────┘     └────────┬────────┘
                     │                       │
                     └───────────┬───────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │ Tamper Detection Engine │
                    │ (Chunk-to-File Mapping, │
                    │  Baseline Differential) │
                    └────────────┬────────────┘
                                 │ suspicious_targets[]
                                 ▼
                    ┌─────────────────────────┐
                    │ Dynamic Analysis Engine │
                    │ (AVD, Frida Hooking,    │
                    │  Logcat & Network pcap) │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │  Trust Scoring Engine   │
                    │ (Penalty Rules Matrix,  │
                    │  Verdict Classification)│
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Merkle Repository Ledger│
                    │ (Canonical JSON, ECDSA, │
                    │  Hash Chain, Proofs)    │
                    └─────────────────────────┘
```

---

## 2. Engine Specifications

### 2.1 Cryptographic Integrity Engine (`core/integrity.py`)
- **64KB Binary Chunking**: Slices the raw APK byte stream into fixed $64\text{ KB}$ ($65,536\text{ bytes}$) blocks. Each block is hashed using SHA-256.
- **Merkle Tree Construction (`core/merkle.py`)**:
  - Takes leaf hashes $L_0, L_1, \dots, L_{n-1}$. If count is odd, duplicates the last leaf.
  - Pairwise hash: $\text{Node} = \text{SHA256}(\text{Left} \mathbin{\Vert} \text{Right})$.
  - Recursively builds tree layers until reaching the single Merkle Root.
  - **Audit Proof Complexity**: $O(\log N)$ proof size with sibling position tags (`left` or `right`).
- **ZIP Central Directory File Map**:
  - Inspects the APK archive structure (ZIP format).
  - Determines the physical byte range $[offset, offset + length)$ for every packed file (such as `classes.dex`, `AndroidManifest.xml`, native `.so` binaries) by reading local file headers and central directory entries.

### 2.2 Static Analysis Engine (`core/static.py`)
- **Pure Python AXML Parser (`core/axml.py`)**: Parses binary Android XML without external dependencies to extract `package_name`, version codes, SDK constraints, requested permissions, and components.
- **DEX Bytecode Scanner (`core/dex_cert_scanner.py`)**: Inspects Dalvik bytecode for security-sensitive API invocations:
  - Dynamic Code Loading (`dalvik.system.DexClassLoader`, `PathClassLoader`)
  - Operating System Command Execution (`java.lang.Runtime.exec`, `ProcessBuilder`)
  - Java Reflection (`java.lang.reflect.Method.invoke`)
  - Telephony and Hardware Identifiers (`getDeviceId`, `getSubscriberId`)
  - SMS Transmission (`android.telephony.SmsManager`)
  - Hardcoded Network IOCs (IPv4 addresses, external domains, URLs)
- **Certificate Analyzer**: Extracts X.509 certificates from APK v1 signatures (`META-INF/*.RSA`) and v2/v3 signing blocks.

### 2.3 Tamper Detection Engine (`core/tamper.py`)
- **Baseline Profile Lookup (`core/baselines.py`)**: Queries existing records for `(package_name, cert_sha256)`.
  - If not found: Registers the build as the initial trusted baseline (`role: "baseline"`).
  - If found: Initiates comparison analysis (`role: "comparison"`).
- **Chunk-to-File Localization Geometry**:
  - Compares baseline leaf hashes with current leaf hashes using `compare_trees()`.
  - For each changed chunk $[C_{start}, C_{end})$, tests overlap against file entry spans $[F_{start}, F_{end})$:
    $$\max(C_{start}, F_{start}) < \min(C_{end}, F_{end})$$
  - Pinpoints the exact files modified (e.g. `classes.dex` altered).
- **Target Export**: Dispatches `suspicious_targets` (classes, newly added services, network IOCs) to the dynamic engine.

### 2.4 Dynamic Analysis Engine (`core/dynamic.py`)
- **Automated AVD Setup (`scripts/setup_avd.ps1`)**: Configures rooted API 30 emulator.
- **Lifecycle Management**: Timeboxed ADB installation, launch intent execution (`am start` / `monkey`), and logcat monitoring.
- **Frida Hook Generator (`generate_frida_script`)**: Generates targeted JavaScript hooks for modified classes and default security sensors (`DexClassLoader`, `Runtime.exec`, `Cipher`).

### 2.5 Trust Scoring Engine (`core/scoring.py`)
- **Baseline Score**: Starts at 100.
- **Severity Deduction Weights**:
  - `critical`: $-35$
  - `high`: $-18$
  - `medium`: $-8$
  - `low`: $-3$
- **Named Security Penalties**:
  - Certificate mismatch against baseline: $-40$ (`R_CERT_CHANGED`)
  - Modified code chunks in DEX files: $-25$ (`R_FILES_MODIFIED`)
  - Modified non-code files: $-15$
  - Self-signed certificate: $-10$ (`R_SELF_SIGNED_CERT`)
- **Verdict Thresholds**:
  - $\text{Score} \ge 70$: `trusted`
  - $40 \le \text{Score} < 70$: `suspicious`
  - $\text{Score} < 40$: `malicious`

### 2.6 Merkle Repository & Blockchain Simulation (`core/repository.py`)
- **Canonical Serialization**: Formats merged report deterministically (`json.dumps(sort_keys=True, separators=(",", ":"))`).
- **Cryptographic Chaining**:
  $$\text{entry\_hash} = \text{SHA256}(\text{prev\_entry\_hash} \mathbin{\Vert} \text{report\_sha256} \mathbin{\Vert} \text{timestamp})$$
- **Digital Signatures**: Signs `entry_hash` with ECDSA P-256 (`SECP256R1`) private key.
- **Repository Merkle Tree**: Appends `entry_hash` as a new leaf, updates repository root, and emits inclusion proofs.
- **Simulated Blockchain Blocks**: Batches entries into blocks with `height`, `block_hash`, and transaction identifiers.
- **Tamper Verification (`verify_chain`)**: Validates the entire chain history; any single-bit corruption immediately breaks the hash chain and is flagged with the exact offending index.

---

## 3. Database Schema

Managed via SQLAlchemy (`db/models.py`) with support for SQLite and PostgreSQL:

| Table | Description |
|---|---|
| `jobs` | Master execution jobs with state (`pending`, `running`, `done`, `failed`) |
| `apk_files` | Quarantined APK metadata indexed by SHA-256 |
| `engine_status` | Per-stage execution state, runtime duration in milliseconds, and error messages |
| `trust_scores` | Computed numerical score, verdict, rules fired, and input report hashes |
| `repository_entries` | Cryptographic ledger entries with signatures, chained hashes, and inclusion proofs |
| `baselines` | Trusted baseline profiles for packages |
| `chunk_hashes` | 64KB chunk hashes from integrity engine |
| `static_reports` | Manifest and bytecode analysis findings |
| `tamper_reports` | Changed chunks and localized file diffs |
| `dynamic_reports` | Emulation and process execution telemetry |

---

## 4. REST API Specification

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/upload` | Quarantines APK by SHA-256, initializes database records, and dispatches background pipeline |
| `POST` | `/api/upload-sample` | Directly runs analysis on built-in `test_sample.apk` |
| `GET` | `/api/jobs/{id}` | Returns per-engine status (`pending`, `running`, `ok`, `partial`, `failed`) and durations |
| `GET` | `/api/jobs/{id}/report` | Retrieves complete merged report containing all six engine JSONs |
| `GET` | `/api/jobs/{id}/verify` | Cryptographically re-verifies ECDSA signature, canonical hash, and inclusion proof |
| `GET` | `/api/repository` | Returns paginated repository ledger entries and current repository Merkle root |
| `GET` | `/api/repository/{index}/proof` | Returns audit inclusion proof for a specific ledger entry |
| `POST` | `/api/tamper-demo` | Simulates a byte-flip attack and executes `verify_chain()` to prove tamper detection |
