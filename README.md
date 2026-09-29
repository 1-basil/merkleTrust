# MerkleTrust — Android APK Integrity & Tamper Verification

MerkleTrust is a zero-trust Android application integrity verification and runtime defense framework. It evaluates APK security through cryptographic Merkle tree chunking, comprehensive static analysis, byte-level tamper detection against verified baselines, dynamic sandbox emulation, and blockchain-inspired cryptographic ledger anchoring.

---

## Architecture & Work Split

The system operates as a unified multi-engine pipeline orchestrated via a standardized Python contract (`core/contracts.py`), backed by a PostgreSQL / SQLite database, a FastAPI REST API, and a modern web dashboard.

| Owner | Component / Engines | Output Artifacts | Primary Responsibilities |
|---|---|---|---|
| **Ajay** | **Integrity Engine & Merkle Repository** | `integrity.json`, `repo_entry.json` | 64KB APK chunking, Merkle root & depth, ZIP central directory `file_map`, ECDSA P-256 digital signing, cryptographic hash chain, inclusion proofs, simulated blockchain blocks, ledger verification. |
| **Ashwini** | **Static Analysis & Tamper Detection** | `static.json`, `tamper.json` | AXML binary manifest parsing, permissions, components, DEX scanning, dangerous APIs, IOCs, baseline profile store, chunk-to-file localization, `suspicious_targets` for dynamic instrumentation. |
| **Bhavish** | **Dynamic Analysis Engine** | `dynamic.json` | AVD orchestration script (`setup_avd.ps1`), ADB install and launch lifecycle, logcat and pcap capture, and Frida hook dispatching. |
| **Basil** | **Orchestrator, Scoring, DB, REST API & Web UI** | `score.json`, Database, Web UI | Master pipeline runner, multi-rule trust scoring engine, SQLAlchemy models (`db/models.py`), FastAPI REST API (`api/main.py`), and interactive web dashboard (`frontend/`). |

---

## Features & Implementation Overview

### 1. Integrity Engine (`core/integrity.py` — Ajay)
- **64KB Chunk Slicing**: Chunks APK binary into 64KB blocks and hashes each chunk with SHA-256.
- **Merkle Tree Computation**: Builds multi-layer Merkle tree (`core/merkle.py`) to derive root hash and tree depth.
- **ZIP Central Directory Parser**: Reads local and central directory headers to map byte spans `[offset, offset + length)` and SHA-256 for all internal APK files (`AndroidManifest.xml`, `classes.dex`, native libraries, etc.).

### 2. Merkle Repository & Blockchain Simulation (`core/repository.py` — Ajay)
- **Canonical Serialization**: Deterministic JSON formatting (`sort_keys=True, separators=(",",":")`).
- **Cryptographic Hash Chain**: Links `entry_hash = SHA256(prev_entry_hash + canonical_report_sha256 + timestamp)`.
- **ECDSA P-256 Signatures**: Digitally signs entries using SECP256R1 elliptic curve cryptography.
- **Inclusion Proofs**: Generates Merkle audit paths to verify entry inclusion in the repository root.
- **Simulated Blockchain Ledger**: Batches entries into blocks with height, block hash, and transaction IDs.
- **Tamper Detection**: Exposes any bit flip across the chain via `verify_chain()`.

### 3. Static Analysis Engine (`core/static.py` — Ashwini)
- **AXML Manifest Parser (`core/axml.py`)**: Pure Python binary XML parser extracting package name, SDK levels, permissions, and components.
- **DEX & Bytecode Scanner (`core/dex_cert_scanner.py`)**: Scans Dalvik bytecode for reflection, dynamic class loading (`DexClassLoader`), command execution (`Runtime.exec`), SMS APIs, and network IOCs.
- **Certificate Analyzer**: Extracts X.509 certificates and reports fingerprints, issuers, validity, and self-signed status.

### 4. Tamper Detection Engine (`core/tamper.py` — Ashwini)
- **Baseline Profile Management (`core/baselines.py`)**: Automatic registration and lookup of trusted builds.
- **Chunk-to-File Localization**: Intersects changed byte ranges with `file_map` to pinpoint modified APK files.
- **Dynamic Targeting**: Exports `suspicious_targets` for Frida dynamic instrumentation.

### 5. Dynamic Analysis Engine (`core/dynamic.py` — Bhavish)
- **AVD Orchestration**: Automated emulator setup script (`scripts/setup_avd.ps1`).
- **ADB Lifecycle**: Timeboxed installation, monkey/activity launch, logcat recording, and graceful failure handling.

### 6. Trust Scoring Engine (`core/scoring.py` — Basil)
- **Aggregate Security Score**: Evaluates upstream engine findings and applies weighted penalties.
- **Verdict Classification**: Categorizes packages as `trusted` (>= 70), `suspicious` (40–69), or `malicious` (< 40).
- **Provenance Hashes**: Hashes input reports (`integrity_sha256`, `static_sha256`, etc.) for auditability.

### 7. Database Layer (`db/` — Basil)
- SQLAlchemy database models for all 4 team members: `jobs`, `apk_files`, `engine_status`, `trust_scores`, `repository_entries`, `chunk_hashes`, `baselines`, `static_reports`, `tamper_reports`, `dynamic_reports`.
- SQLite default (`data/merkletrust.db`) with full PostgreSQL support via `DATABASE_URL`.

### 8. FastAPI REST API (`api/main.py` — Basil)
- `POST /api/upload`: Upload and quarantine APK, queue background analysis.
- `POST /api/upload-sample`: Trigger analysis directly using `test_sample.apk`.
- `GET /api/jobs/{id}`: Query per-engine status and job summary.
- `GET /api/jobs/{id}/report`: Retrieve complete 6-stage merged report.
- `GET /api/jobs/{id}/verify`: Verify digital signature and Merkle inclusion proof.
- `GET /api/repository`: Paginated repository ledger explorer.
- `GET /api/repository/{index}/proof`: Merkle inclusion proof for a specific entry.
- `POST /api/tamper-demo`: Interactive tamper simulation and chain breakage test.

### 9. Web Dashboard (`frontend/` — Basil)
- Modern dark-mode UI with glassmorphism, responsive grid, and live polling.
- Drag-and-drop APK upload zone.
- Visual 6-stage pipeline progress stepper.
- Circular trust score gauge and security rule breakdown.
- 64KB Merkle chunk matrix with changed chunks highlighted.
- ZIP file map table and searchable findings list.
- Interactive cryptographic ledger and tamper demonstration lab.

---

## How to Run & Verify

### 1. Run Automated Test Suite
```powershell
pytest -v
```
Runs 15 automated unit and integration tests covering Merkle operations, static/tamper engines, integrity chunking, repository signatures/proofs, and FastAPI REST endpoints.

### 2. Run Master CLI Orchestrator
```powershell
python -m core.orchestrator test_sample.apk
```
Executes all 6 engines in sequence and outputs `jobs/<job_id>/merged.json`.

### 3. Run the FastAPI Web App & Dashboard
```powershell
uvicorn api.main:app --reload --port 8000
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser to access the full interactive MerkleTrust Web Dashboard!
Interactive API documentation is available at **[http://localhost:8000/docs](http://localhost:8000/docs)**.
