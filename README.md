# MerkleTrust

**Is this Android app the same as its trusted version? What exactly changed? Is it
dangerous? And can every answer be proven later?**

MerkleTrust is an academic prototype (Cryptography and Network Security, final-year
project) that verifies uploaded APKs against administrator-approved trusted baselines,
pinpoints changed files, explains security risk, and records every result in a signed,
hash-linked audit chain.

| | |
|---|---|
| **Integrity** | Per-file SHA-256 manifest committed to an RFC 6962 Merkle tree; modified / added / deleted files; per-file Merkle proofs against the signed baseline root |
| **Authenticity** | Own implementation of APK Signature Scheme v1/v2/v3 verification (agrees with Google's `apksigner` on 13/13 cases); signer compared by certificate fingerprint |
| **Trusted baselines** | Explicit enrol → approve workflow, ECDSA P-256-signed, versioned, re-verified before every use |
| **Risk** | Explained findings (title, explanation, evidence, recommendation, points), kept separate from integrity; no double counting |
| **Runtime behaviour** | Optional emulator stage: installs and runs the app, triggers its boot/broadcast receivers, and records child processes (e.g. `su`), connections named from a packet capture, files written, SMS sent and icon hiding; off by default |
| **Audit** | *Cryptographically Linked Blockchain Simulation*: signed, hash-linked blocks for every security event (single node — not a distributed blockchain) |
| **Platform** | FastAPI REST API with roles, secure uploads and job queue; SQLite + Alembic; plain-language web dashboard |

## Quick start

```bash
pip install -r requirements.txt                     # Python 3.12+
python -m pytest                                    # 357 tests
python -m scripts.manage_users create admin --role admin
uvicorn api.main:app --port 8000                    # open http://127.0.0.1:8000
```

Upload `evaluation/dataset/baseline_demo.apk` as a trusted version (admin → *Trusted
versions*), approve it, then scan `evaluation/dataset/demo_repackaged.apk`. The full
walk-through is in [docs/DEMO.md](docs/DEMO.md).

To also watch the app run, create and boot the analysis emulator
(`scripts/setup_avd.ps1`, then `emulator -avd mt_api30_root`) and set
`MERKLETRUST_DYNAMIC_ENABLED=true`; see [docs/ARCHITECTURE.md §2.1](docs/ARCHITECTURE.md#21-dynamic-analysis-emulator).

Configuration is by environment variables (`MERKLETRUST_*`, see
[.env.example](.env.example)). For anything beyond a demo, create a signing key outside
the repository with `python -m scripts.generate_signing_key --out <path> --encrypt` and
set `MERKLETRUST_SIGNING_KEY_PATH`.

## Results at a glance

On 35 real APKs built with the Android toolchain ([evaluation/](evaluation/README.md)):

* changes and unauthorised modifications detected 20/20 with no false positives;
  changed files localised exactly 20/20;
* 11/11 tampering attacks on stored reports, baselines and the audit chain detected,
  36/36 untouched records accepted;
* behavioural risk on a held-out set written after the rules: 5/7 correct (one false
  positive, one false negative — the limits of static analysis, documented); with the
  optional emulator stage 6/7, as it catches the app running `su` (finished after these
  results were known — see [evaluation/README.md](evaluation/README.md));
* about 0.1 s from upload to result for a small APK, about 1.1 s for 52 MB.

## Documentation

| Document | Contents |
|---|---|
| [docs/REPORT.md](docs/REPORT.md) | Project report: problem, objectives, design, cryptography, methodology, results, limitations |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, pipeline, cryptographic formats, database, API, frontend |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Attackers, assumptions, threat → attack → detection → defence, residual risks |
| [docs/TESTING.md](docs/TESTING.md) | Test strategy, requirement traceability, coverage, defects found |
| [evaluation/README.md](evaluation/README.md) | Dataset, metrics, disclosure of changes after the first run |
| [docs/DEMO.md](docs/DEMO.md) | Live demonstration script |
| [docs/VIVA_QUESTION_BANK.md](docs/VIVA_QUESTION_BANK.md) | Likely questions with answers tied to the code |
| [docs/AUDIT.md](docs/AUDIT.md) | The initial repository audit that started this rework |

## What this prototype is not

* Not a distributed blockchain — the audit chain is a single-node simulation of hash
  chaining with signatures.
* Not a malware detector with measured real-world accuracy — the risk score is an
  explained heuristic indicator.
* Not production-hardened key management — keys are files; use an HSM/KMS in deployment.

## Team

Ajay, Ashwini, Basil and Bhavish. The original work split and per-engine plans are kept
for the record in [docs/team/](docs/team/).
