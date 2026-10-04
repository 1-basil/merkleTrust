# MerkleTrust: Cryptographic Integrity Verification, Tamper-Evident Auditing and Threat Detection for Android Applications

*Final-year project report — Cryptography and Network Security.*

---

## 1. Abstract

Android apps are routinely repackaged: an attacker downloads a legitimate APK,
modifies its code or configuration, re-signs it with their own key and redistributes
it. MerkleTrust verifies whether an uploaded APK is the same application as an
administrator-approved **trusted baseline**, identifies exactly which files changed,
assesses security risk from the app's manifest and bytecode, and records every result in
a **signed, hash-linked audit chain** (a *Cryptographically Linked Blockchain
Simulation*) so that reports, baselines and history can later be proven unaltered. The
system combines per-file SHA-256 manifests committed to RFC 6962 Merkle trees, ECDSA
P-256 signatures over canonical JSON, a from-scratch implementation of APK Signature
Scheme v1/v2/v3 verification (13/13 verdicts identical to Google's `apksigner`), and a
risk model in which every point of the score is explained. On a controlled dataset of 35
real APKs built with the Android toolchain it detects every integrity change and every
unauthorised modification (20/20, no false positives), localises changed files exactly
(20/20), and detects all 11 cryptographic tampering attacks on stored data with no false
alarms on 36 untouched controls. Its heuristic behavioural-risk component reaches 0.71
accuracy on a small held-out set, with one false positive and one false negative that
illustrate the limits of static analysis.

## 2. Problem statement

Given an APK file, a security reviewer needs to answer, with evidence:

1. Is it *the same application* as the version the organisation trusts?
2. If not, *what exactly* changed — which files, permissions, components, signer?
3. Does it contain *dangerous characteristics*, independently of whether it changed?
4. Can the answers, the trusted reference and the history of decisions be *proven* not
   to have been altered afterwards — including by someone with database access?

A single SHA-256 of the whole APK answers only "byte-identical or not": it cannot say
what changed, it flags harmless re-signing by the developer, and it says nothing about
risk. Android's own signature check answers "was this signed by *someone*" — repackaged
apps are validly signed, just by the wrong key.

## 3. Motivation

Repackaged apps are a well-documented malware distribution technique: trojanised copies
of popular apps carry injected code and are re-signed by the attacker. Organisations that
distribute or approve apps (enterprise app stores, MDM, security teams, examiners) need
an auditable, explainable way to tell genuine builds from modified ones, and a record of
those decisions that cannot be silently rewritten.

## 4. Objectives

* O1 — Explicit, signed, versioned trusted baselines (no "first upload is trusted").
* O2 — Per-file integrity verification with exact change localisation.
* O3 — Correct APK signature and certificate verification, distinguishing "different
  signer" from "malicious".
* O4 — Explained security risk, separate from integrity.
* O5 — Cryptographic proof: ECDSA signatures, Merkle proofs, a tamper-evident audit chain.
* O6 — A secure, production-quality API and a dashboard usable by non-specialists.
* O7 — Rigorous testing and a reproducible evaluation with honest metrics.

## 5. System architecture

A FastAPI REST API (`api/`) accepts uploads, authenticates users and queues analysis
jobs; a six-stage pipeline (`core/`) — integrity, static, tamper, dynamic, score,
repository — produces reports that are sealed into the audit chain; SQLite (via
SQLAlchemy and Alembic) stores baselines, jobs and the chain; a dependency-free web
dashboard (`frontend/`) presents results. Details, diagrams and the full API table:
[ARCHITECTURE.md](ARCHITECTURE.md).

## 6. Threat model

Five attacker types are considered: app tamperers/repackagers, malicious-app authors,
hostile uploaders, insiders with database/file access, and network attackers. The
attacker is assumed **not** to hold the developer's signing key, the MerkleTrust
signing key, or administrator credentials. 26 threats are mapped to their detection,
defence, implementing code and evidence, and residual risks are stated:
[THREAT_MODEL.md](THREAT_MODEL.md).

## 7. Security requirements

| ID | Requirement | Met by |
|---|---|---|
| SR1 | Only explicitly approved builds are trusted | Baseline enrol → approve workflow; admin role |
| SR2 | Any change to an app's files is detected and localised | Per-file SHA-256 manifest comparison |
| SR3 | A different signer is detected regardless of certificate *name* | Certificate fingerprint comparison |
| SR4 | Stored baselines, reports and audit history are tamper-evident | ECDSA signatures, sealed report hashes, hash chain, audit cross-checks |
| SR5 | Untrusted input cannot crash, exhaust or exploit the server | Hardened archive reader, size limits, typed parsers, bounded queue |
| SR6 | Only authorised users act; secrets are not stored in clear | Bearer sessions, roles, scrypt, hashed tokens, rate limiting |
| SR7 | Results are explainable and do not overclaim | Findings catalogue, score breakdown, "simulation" labelling |

## 8. APK analysis

An APK is a ZIP archive. `core/apk_archive.py` validates it before anything else
(limits, unsafe raw names, duplicates, zip bombs, data prepended before the archive). The
binary `AndroidManifest.xml` is parsed by a pure-Python AXML parser (`core/axml.py`) that
resolves attribute names via resource IDs, extracting package, versions, SDK levels,
permissions, application flags and components with their effective export state. DEX
files are parsed (`core/dex.py`) to verify the header Adler-32 checksum and SHA-1, and to
list method references, so that sensitive APIs (`DexClassLoader.<init>`,
`Runtime.exec`, `SmsManager.sendTextMessage`, …) are detected where the code *calls*
them rather than wherever a substring appears. Signing certificates are extracted and the
APK signature is verified for all three schemes (`core/apk_signature.py`, with a minimal
DER reader in `core/der.py` because the `cryptography` package cannot verify PKCS#7).

## 9. Baseline mechanism

An administrator uploads the official build; it is analysed and stored as *pending*,
together with a review against the currently active baseline (warning, for example, that
the signer changed — the main defence against baseline poisoning). Approval signs a
canonical payload binding the package, versions, APK hash, certificate fingerprint, file
count, Merkle root, profile hash and chunk hashes. Baselines are versioned per package;
the newest approved one is active; they can be rejected or revoked. Before every use the
record is re-verified, and its status is cross-checked against the audit chain so that a
revocation cannot be undone by editing the database.

## 10. Hashing

SHA-256 is used throughout. Integrity is decided **per file**: each entry's content is
hashed, the sorted `(path, hash)` manifest is committed to a Merkle root, and comparison
classifies files as modified, added, deleted or unchanged; signature files are reported
separately. The earlier design's fixed 64 KB chunking is kept only as supplementary
forensics: inserting one byte shifts every later chunk, so chunks cannot localise changes
reliably. Reports and payloads are hashed in canonical JSON so that the same content
always yields the same digest.

## 11. ECDSA

ECDSA over NIST P-256 with SHA-256 signs baseline approvals, audit blocks and signed chain
heads. What is signed is always canonical JSON. Signatures are normalised to low-S and
high-S signatures are rejected (no malleable twins). The key id is derived from the public
key, so a signature cannot be relabelled as coming from another key; verification never
creates keys and reports a reason on failure. Keys come from configuration (optionally
password-encrypted, never in the repository); retired keys remain verifiable; production
refuses to start without an explicit key. Measured: 0.04 ms per signature and 0.08 ms per
verification.

## 12. Merkle tree

The tree follows RFC 6962: leaves are hashed as `SHA-256(0x00‖data)` and internal nodes as
`SHA-256(0x01‖left‖right)`, and a node without a sibling is promoted rather than
duplicated. Domain separation prevents an internal node from being presented as a leaf
(second-preimage forgery), and avoiding duplication prevents `[a,b,c]` and `[a,b,c,c]`
from sharing a root. Roots are tested against a reference implementation written directly
from the RFC. File leaves bind the *path* to the content hash, so swapping two files'
contents changes the root. Inclusion proofs let a single file (e.g. `classes.dex`) be
checked against the signed baseline root: the trusted hash verifies, a modified hash does
not. A 100 000-leaf tree builds in about 0.3 s; a 17-step proof verifies in about 0.03 ms.

## 13. Blockchain simulation

Every security event is a block whose hash covers the previous block's hash and the hash
of its event data, and whose header is ECDSA-signed. Verification checks position, link,
data, hash and signature of every block and explains the first break in plain language.
Editing a block breaks its payload hash; recomputing its hash breaks its signature and the
next block's link; appending with a foreign key fails signature checks; deleting the
newest blocks is detected against a previously saved signed head; a fork is prevented by a
uniqueness constraint. This is deliberately named a **Cryptographically Linked Blockchain
Simulation**: it is a single-node chain with no network, consensus, mining or
decentralisation, and the documentation and UI say so.

## 14. Risk analysis

Integrity and risk are separate outputs. Risk is computed from a catalogue of 54 finding
types, each with a plain-language title, explanation, evidence and recommendation, and
documented points. Findings describing the same fact share a group and are counted once;
self-signed certificates are not penalised (normal on Android); operational messages
(e.g. "no emulator") carry no points; a failed analysis yields "could not be analysed",
never "safe". Behaviour-pattern rules recognise dangerous *combinations* (dropper,
premium-SMS fraud, spyware). A change re-signed by the baseline's own key is treated as a
legitimate update and judged only on what it adds. The score is a transparent heuristic
indicator, not a probability of malware.

## 15. Backend architecture

FastAPI application factory with versioned routers; bearer-token authentication with
admin/analyst roles; uploads streamed with a size cap, validated as APKs and stored
read-only under their SHA-256; analysis in a bounded worker pool with back-pressure (HTTP
503) and recovery of interrupted jobs; a uniform JSON error format without stack traces;
structured JSON logs with request ids; CSP and other security headers; a closed-by-default
CORS allow-list without credentials; rate limiting on sign-in and upload. See
[ARCHITECTURE.md §7](ARCHITECTURE.md#7-api-design).

## 16. Database design

Nine tables: users, auth_sessions, apk_files, jobs, engine_status, trust_scores,
trusted_baselines, audit_blocks, audit_tamper_backups — with foreign keys, uniqueness and
check constraints, and indexes on lookup columns. Schema changes are managed by Alembic.
SQLite runs in WAL mode with `synchronous=FULL`; profiling showed the default rollback
journal dominated request time, and the change made a small-APK scan about ten times
faster without weakening durability. ER diagram: [ARCHITECTURE.md §6](ARCHITECTURE.md#6-database-design).

## 17. API design

27 endpoints under `/api/v1` covering authentication, scans (upload, status, report,
verification, per-file Merkle proof), baselines (enrol, approve, reject, revoke, verify,
proof), the audit chain (blocks, verification, signed head, public keys, admin-only
tamper/restore demonstration) and the dashboard. Every state change is authorised and
audited. Table: [ARCHITECTURE.md §7](ARCHITECTURE.md#7-api-design).

## 18. Frontend

A dependency-free single-page dashboard. The result page leads with a plain-language
verdict and answers two questions — "Is this the same app as the trusted version?" and
"Does it have security concerns?" — before tabs for file changes (with per-file proof
checks), findings (each with explanation, evidence and recommendation), certificate
comparison, cryptographic verification and raw reports. The Blockchain Simulation page
draws the linked blocks, highlights a tampered block and the broken link, and lets an
administrator run and undo the tamper demonstration. All data is rendered as text (no HTML
injection) under a strict Content Security Policy; status is never conveyed by colour
alone; the layout works at phone width.

## 19. Experimental methodology

A dataset of 35 APKs was built from source with `aapt2`, `javac`, `d8`, `zipalign` and
`apksigner`: three official baselines; attack cases following the threat model (content
modified and re-signed with an attacker key — one of which copies the developer's
certificate subject — or left with a broken signature; signature stripping; prepended
data); negatives (byte-identical copies, same-key re-signs, legitimate updates); five
risk samples; and seven held-out risk samples written after the risk rules were final.
Ground truth was recorded when the dataset was built. The evaluation runner drives the
real REST API in an isolated environment, then performs 11 tampering attacks directly on
stored reports, baselines and the audit chain, plus 36 untouched controls. Full method and
disclosure: [../evaluation/README.md](../evaluation/README.md).

## 20. Results

| Question | n | Accuracy | Precision | Recall | FPR | FNR |
|---|---|---|---|---|---|---|
| Change detection | 20 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| Unauthorised modification | 20 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| Install warning (development set) | 25 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| Behavioural risk, held-out set | 7 | 0.714 | 0.750 | 0.750 | 0.333 | 0.250 |
| Cryptographic tamper detection | 47 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |

Exact integrity status 32/32; exact changed-file localisation 20/20; median
upload-to-result time 84 ms per dataset APK. Performance on a machine in interactive use
(median, 9 runs): about 0.11 s end-to-end for a 9 KB APK and about 1.1 s for a 52 MB APK;
full verification of a 562-block audit chain about 95 ms. The test suite has 357
automated tests at 91.9 % line coverage, plus a headless-browser end-to-end test, an
`apksigner` cross-check and a concurrency stress test. Details:
[../evaluation/results/evaluation.md](../evaluation/results/evaluation.md),
[../evaluation/results/benchmark.md](../evaluation/results/benchmark.md),
[TESTING.md](TESTING.md).

**Emulator.** With the optional dynamic engine (`results/dynamic.md`), the held-out
behavioural result becomes 4 TP / 1 FP / 2 TN / 0 FN: the booster's `su -c setenforce 0`
was recorded by a kernel exec trace when the engine delivered its boot broadcast, and
SMS fraud was confirmed at runtime for R03 and H02. The engine was finished after the
held-out results were known, so this row is not an independent test (§22).

**Interpretation.** The integrity and cryptographic results test deterministic mechanisms;
correct implementations should be exact, and the evaluation confirms that on realistic
APKs and attacks. The first evaluation run exposed two mislabelled samples and a real
weakness in risk scoring (capabilities scored in isolation); behaviour-pattern rules were
added and, because they were written after seeing results, a held-out set was built to
measure them honestly. Its two errors are kept: a benign app loading its own plugins is
indistinguishable, statically, from a dropper (false positive), and a booster running
`su` to disable SELinux is missed because there is no rule for privilege-escalation
commands (false negative).

## 21. Security analysis

Testing and evaluation found and fixed real defects, among them: the original manifest
parser crashed on every real APK; a non-APK upload was scored "trusted"; the original
"blockchain" blocks were not linked; the original report verification could never pass;
APK-derived strings could inject code into the generated Frida script; under contention
the audit chain could lose events or gain a second genesis block; and a race created the
development key twice. Each fix has a regression test that fails on the old code. Security
properties rest on standard primitives (SHA-256, ECDSA P-256 via the `cryptography`
library), on verification of everything stored before it is trusted, and on keeping
untrusted input as data (no HTML, no code, no paths). Residual risks — a stolen signing
key, an insider who also holds the key, tail truncation without a saved head, a dishonest
approver, and the limits of static analysis — are listed in
[THREAT_MODEL.md §4](THREAT_MODEL.md#4-residual-risks-stated-honestly).

## 22. Limitations

* The audit chain is a single-node simulation; it is tamper-*evident*, not tamper-proof
  against someone who holds the signing key.
* The signing key is a file in the prototype (HSM/KMS recommended for deployment).
* Static analysis cannot determine intent or see code downloaded at runtime; the risk
  model is heuristic and its weights were set by the authors.
* The evaluation dataset is small and constructed; it validates mechanisms, not
  real-world malware detection rates.
* v3 key-rotation lineage is reported but not validated; verity-only and DSA signatures
  are reported as unverifiable.
* SQLite and an in-process rate limiter suit a single server, not a cluster.
* The dynamic (emulator) engine is optional, off by default, needs a rooted x86_64
  emulator for its full observations, and sees only behaviour that an unattended 20 s
  run triggers (no UI exploration; emulator-aware apps can stay quiet). It was evaluated
  on a real emulator only after the held-out results were known.

## 23. Future work

* Anchor signed chain heads in an external transparency log or a real blockchain to
  remove the single-node trust assumption.
* HSM/KMS-backed signing and two-person baseline approval.
* Validate v3 rotation lineage and v4 (incremental) signatures.
* Grow the evaluation with third-party malware corpora and benign app stores to measure
  real-world risk detection, and calibrate risk weights on that data.
* Static rules for privilege escalation and obfuscation; UI exploration and longer runs
  for the dynamic engine; a fresh held-out set to measure it independently.
* PostgreSQL and a shared rate-limit store for multi-instance deployment.
