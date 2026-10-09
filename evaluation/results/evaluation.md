# MerkleTrust — Evaluation results

Generated 2026-10-09T01:57:13+00:00 on Windows 11 (Python 3.14.7, 22 CPUs).
Produced by `python -m scripts.run_evaluation` from `evaluation/dataset/` (real APKs built with the Android toolchain; see `scripts/build_eval_dataset.py`). Ground truth was fixed when the dataset was built; this report only measures. Methodology, the held-out protocol and the changes made after the initial run are described in `evaluation/README.md`.

## Detection metrics

| Question | Scope | n | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 | FPR | FNR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Does the app differ from its trusted version? | cases with a baseline | 20 | 15 | 0 | 5 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| Was the app changed by someone other than the key holder (re-signed, unsigned or broken signature)? | cases with a baseline | 20 | 13 | 0 | 7 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| Should the user be warned not to install it (risk HIGH/CRITICAL)? | development cases (D, N, W, R) | 25 | 17 | 0 | 8 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| Same, apps without a baseline (risk from the app's own behaviour only) | development R* cases | 5 | 4 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| Same, on samples written after the risk rules were finalised | held-out H* cases | 7 | 3 | 1 | 2 | 1 | 0.714 | 0.750 | 0.750 | 0.750 | 0.333 | 0.250 |
| Is tampering with stored reports, baselines or the audit chain detected (and untouched data accepted)? | tampering cases + untouched controls | 47 | 11 | 0 | 36 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |

* Exact integrity status (5 classes): **32/32** (1.000)
* Changed files reported exactly as expected: **20/20** (1.000)
* Upload-to-result time per APK (API, inline analysis): median 80.5 ms, min 59.6 ms, max 157.0 ms
* Cases that failed to process: none

## Per-case results

| ID | Case | Expected | Observed integrity | Verdict | Risk | Signature | Changed files | ms | Match |
|---|---|---|---|---|---|---|---|---|---|
| D01 | Byte-identical copy of the official build | CLEAN | CLEAN | CLEAN | LOW (0) | verified | none | 79.1 | ✓ |
| D02 | Rebuilt and re-signed by the developer with the same key (v2+v3) | CLEAN | CLEAN | CLEAN | LOW (0) | verified | none | 73.4 | ✓ |
| D03 | Legitimate next release by the developer (+CAMERA, +1 service) | MODIFIED | MODIFIED | CHANGES_DETECTED | MEDIUM (26) | verified | modified: AndroidManifest.xml, classes.dex | 85.0 | ✓ |
| D04 | Manifest modified (debuggable, backup) and re-signed | CERTIFICATE_CHANGED | CERTIFICATE_CHANGED | HIGH_RISK | HIGH (68) | verified | modified: AndroidManifest.xml | 79.9 | ✓ |
| D05 | Program code (DEX) modified to run commands and re-signed | CERTIFICATE_CHANGED | CERTIFICATE_CHANGED | HIGH_RISK | CRITICAL (100) | verified | modified: classes.dex | 92.2 | ✓ |
| D06 | Unchanged content re-signed with a look-alike certificate (same subject name) | CERTIFICATE_CHANGED | CERTIFICATE_CHANGED | HIGH_RISK | HIGH (40) | verified | none | 84.4 | ✓ |
| D07 | File injected (assets/payload.bin) and re-signed | CERTIFICATE_CHANGED | CERTIFICATE_CHANGED | HIGH_RISK | HIGH (50) | verified | added: assets/payload.bin | 157.0 | ✓ |
| D08 | File deleted (assets/config.json) and re-signed | CERTIFICATE_CHANGED | CERTIFICATE_CHANGED | HIGH_RISK | HIGH (50) | verified | deleted: assets/config.json | 93.9 | ✓ |
| D09 | Repackaged: injected loader + SMS code, new permission, extra native library | CERTIFICATE_CHANGED | CERTIFICATE_CHANGED | HIGH_RISK | CRITICAL (100) | verified | modified: AndroidManifest.xml, classes.dex; added: lib/x86_64/libpayload.so | 98.1 | ✓ |
| D10 | Permissions added (SEND_SMS, READ_CONTACTS) and re-signed | CERTIFICATE_CHANGED | CERTIFICATE_CHANGED | HIGH_RISK | HIGH (66) | verified | modified: AndroidManifest.xml | 76.6 | ✓ |
| D11 | Asset modified after signing (signature now invalid) | MODIFIED | MODIFIED | HIGH_RISK | HIGH (45) | invalid | modified: assets/config.json | 59.6 | ✓ |
| D12 | v2 signature block stripped (downgrade to v1) | MODIFIED | MODIFIED | HIGH_RISK | HIGH (35) | invalid | none | 61.2 | ✓ |
| D13 | DEX data prepended to the signed APK (Janus-style) | MODIFIED | MODIFIED | HIGH_RISK | HIGH (65) | invalid | none | 80.5 | ✓ |
| N01 | Byte-identical copy of the official build | CLEAN | CLEAN | CLEAN | LOW (0) | verified | none | 74.1 | ✓ |
| N02 | Re-signed by the developer, v2 only | CLEAN | CLEAN | CLEAN | LOW (0) | verified | none | 86.2 | ✓ |
| N03 | Re-signed with an attacker key (RSA) | CERTIFICATE_CHANGED | CERTIFICATE_CHANGED | HIGH_RISK | HIGH (40) | verified | none | 87.2 | ✓ |
| N04 | Code modified (new network endpoint) and re-signed | CERTIFICATE_CHANGED | CERTIFICATE_CHANGED | HIGH_RISK | CRITICAL (79) | verified | modified: classes.dex | 60.1 | ✓ |
| W01 | Byte-identical copy of the official build | CLEAN | CLEAN | CLEAN | LOW (3) | verified | none | 88.1 | ✓ |
| W02 | Legitimate data-only update by the developer | MODIFIED | MODIFIED | CHANGES_DETECTED | LOW (3) | verified | modified: AndroidManifest.xml, assets/cities.json | 72.4 | ✓ |
| W03 | Location tracking permissions added and re-signed | CERTIFICATE_CHANGED | CERTIFICATE_CHANGED | HIGH_RISK | HIGH (64) | verified | modified: AndroidManifest.xml | 75.8 | ✓ |
| R01 | Debuggable app with command execution, code loading and SMS sending | NO_BASELINE | NO_BASELINE | HIGH_RISK | CRITICAL (100) | verified | none | 80.7 | ✓ |
| R02 | Dropper: downloads and loads extra code | NO_BASELINE | NO_BASELINE | HIGH_RISK | HIGH (64) | verified | none | 76.2 | ✓ |
| R03 | Premium-SMS fraud on boot | NO_BASELINE | NO_BASELINE | HIGH_RISK | HIGH (66) | verified | none | 99.1 | ✓ |
| R04 | Spyware: identifiers, contacts, location, audio, command execution | NO_BASELINE | NO_BASELINE | HIGH_RISK | HIGH (68) | verified | none | 99.4 | ✓ |
| R05 | Benign app with debuggable/cleartext/backup enabled (should be review, not high risk) | NO_BASELINE | NO_BASELINE | NO_BASELINE | MEDIUM (26) | verified | none | 80.5 | ✓ |
| H01 | Dropper using InMemoryDexClassLoader + HTTPS download | NO_BASELINE | NO_BASELINE | HIGH_RISK | HIGH (45) | verified | none | 85.4 | ✓ |
| H02 | SMS fraud triggered by incoming SMS (multipart send) | NO_BASELINE | NO_BASELINE | HIGH_RISK | HIGH (69) | verified | none | 78.0 | ✓ |
| H03 | Stalkerware: call log, location, phone number, hides its icon | NO_BASELINE | NO_BASELINE | HIGH_RISK | HIGH (55) | verified | none | 91.1 | ✓ |
| H04 | Runs 'su' to disable SELinux on boot | NO_BASELINE | NO_BASELINE | NO_BASELINE | MEDIUM (23) | verified | none | 75.4 | ✗ |
| H05 | Benign drawing app loading its own plugins (legitimate code loading) | NO_BASELINE | NO_BASELINE | HIGH_RISK | HIGH (45) | verified | none | 79.6 | ✗ |
| H06 | Benign user-initiated SMS reminders | NO_BASELINE | NO_BASELINE | NO_BASELINE | MEDIUM (28) | verified | none | 68.7 | ✓ |
| H07 | Benign fitness tracker with location | NO_BASELINE | NO_BASELINE | NO_BASELINE | LOW (3) | verified | none | 100.1 | ✓ |

## Cryptographic tampering

| ID | Scenario | Tampered | Detected | Detail |
|---|---|---|---|---|
| C-baseline-demo | Untouched baseline demo | no | no |  |
| C-baseline-notes | Untouched baseline notes | no | no |  |
| C-baseline-weather | Untouched baseline weather | no | no |  |
| C-chain | Untouched audit chain | no | no | 120 blocks |
| K01 | Audit block event data edited | yes | yes | Integrity failure at block #60: Its recorded event data was changed after the block was written. |
| K02 | Audit block edited and its hash recomputed | yes | yes | Integrity failure at block #60: Its digital signature is not valid (signature does not match the signed data). |
| K03 | Stored report: verdict changed to CLEAN | yes | yes | The stored report was changed after it was sealed (its hash no longer matches). |
| K04 | Stored report: one file fingerprint altered | yes | yes | The stored report was changed after it was sealed (its hash no longer matches). |
| K05 | Baseline: one stored file fingerprint altered | yes | yes | stored file list does not reproduce the recorded Merkle root |
| K06 | Baseline: file list and Merkle root forged consistently | yes | yes | approval signature invalid: signature does not match the signed data |
| K07 | Baseline: re-signed with a rogue key claiming the trusted key id | yes | yes | approval signature invalid: signature does not match the signed data |
| K08 | Baseline: certificate fingerprint swapped for an attacker's | yes | yes | approval signature invalid: signature does not match the signed data |
| K09 | Baseline: revocation undone by editing the status column | yes | yes | status 'approved' contradicts the audit trail (last recorded: revoked) |
| K10 | Audit block appended with an untrusted signing key | yes | yes | Integrity failure at block #129: Its digital signature is not valid (unknown or untrusted signing key 'mt-18f656fa2088c7a1'). |
| K11 | Newest audit block deleted (checked against a saved signed head) | yes | yes | The chain is shorter than, or different from, a previously recorded head: blocks were deleted or replaced. |

Plus 32 untouched sealed reports, each verified: 32/32 accepted as valid.

## Limitations

* The dataset is small and constructed by the project team; it demonstrates that each detection mechanism works on realistic APKs, not how the system performs on real-world malware in the wild.
* Risk weights and thresholds were designed by the same team that labelled the samples, so the risk metrics are a consistency check of the design, not an independent accuracy estimate.
* All attacks follow the stated threat model (the attacker does not hold the developer key, the server, or the audit signing key).
