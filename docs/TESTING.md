# MerkleTrust — Testing

## How to run

```bash
pip install -r requirements.txt
python -m pytest                     # full suite (~30 s)
python -m pytest -m security         # attack / abuse scenarios only
python -m pytest -m "unit"           # fast single-module tests
python -m scripts.coverage_report    # line coverage (standard library only; slow, ~15 min)
python -m scripts.crosscheck_apksigner   # differential check vs Google's apksigner (needs Android SDK)
python -m scripts.stress_audit_chain     # concurrent audit-chain writers under CPU load
node tests/e2e/ui_smoke.mjs <url> <shots-dir> "<ids>"   # browser end-to-end (needs Chrome, Node 22+)
```

Markers (`pytest.ini`, `--strict-markers`): `unit`, `integration`, `api`, `security`.
Tests never touch the developer's `data/` directory or real keys: `tests/conftest.py`
points the data directory, database and signing key at temporary locations before
any application module is imported, and the `db` fixture gives each test a fresh,
migrated SQLite database.

## Test data

`tests/fixtures/apks/` holds **real** APKs produced by the official Android
toolchain (`aapt2` → `javac` → `d8` → `zipalign` → `apksigner`) via
`python -m scripts.build_fixtures`. The signing keys are generated into a temporary
directory and destroyed; only public certificates are inside the APKs.

| Fixture | What it is |
|---|---|
| `signed_v1v2_ec.apk` | Benign app 1.2.0, v1+v2 signed with key A (EC P-256) — the "official build" |
| `signed_v1only_ec.apk` | Same app, v1 (JAR) signature only, key A |
| `signed_v2v3_rsa.apk` | Same code re-signed with a different key B (RSA-2048), v2+v3 |
| `update_v1v2_ec.apk` | Legitimate next release 1.3.0 (key A): +CAMERA permission, +1 service |
| `suspicious_v2_ec.apk` | Debuggable, cleartext, exported boot receiver; calls `Runtime.exec`, `DexClassLoader`, `SmsManager.sendTextMessage` |
| `unsigned.apk` | Benign app, never signed |

Attack variants (modified/added/deleted files, stripped signatures, flipped bytes,
forged signature data, prepended data, zip bombs, hostile names) are derived from
these at test time with `scripts/apk_mutations.py`, so "what the attacker did" is
explicit in each test.

## Traceability: brief requirement → tests

### Unit tests

| Requirement | Tests |
|---|---|
| APK parser | `test_apk_archive.py` (14 tests: valid APK, limits, names, duplicates, bombs, CRC, prefix) |
| AXML parser | `test_axml.py::test_parses_real_binary_manifest`, `::test_security_relevant_flags`, `::test_attribute_names_resolved_by_resource_id`, `::test_truncation_and_fuzzing_only_raise_axml_error` |
| DEX analysis | `test_dex.py::test_parses_real_dex`, `::test_dangerous_apis_found_by_method_reference`, `::test_patched_dex_fails_header_checks`, `::test_truncated_and_fuzzed_dex_only_raise_dex_error` |
| Certificate analysis | `test_apk_signature.py::test_certificate_details`, `::test_genuine_signatures_verify`, `::test_resigned_apk_verifies_with_a_different_certificate` |
| Hashing | `test_file_manifest.py::test_manifest_of_real_apk`, `::test_root_binds_paths`; `test_crypto.py::test_canonical_json_*`, `::test_hash_payload_changes_with_any_field`; `test_integrity.py::test_compute_chunks` |
| ECDSA | `test_crypto.py::test_sign_and_verify`, `::test_signatures_are_low_s_and_high_s_is_rejected`, `::test_non_p256_keys_rejected`, `::test_rotated_key_still_verifies_old_signatures` |
| Merkle tree | `test_merkle.py::test_root_matches_rfc6962_reference` (36 sizes), `::test_no_duplicate_last_leaf_collision`, `::test_internal_node_cannot_pose_as_leaf` |
| Merkle proofs | `test_merkle.py::test_every_proof_verifies`, `::test_proof_length_is_logarithmic`; `test_file_manifest.py::test_file_proof_valid_and_invalid` |
| Blockchain simulation | `test_audit_chain.py::test_genesis_and_linking`, `::test_block_hash_depends_on_previous_hash`, `::test_inclusion_proof` |
| Universal content | `test_universal_integrity.py::test_detects_by_magic_bytes`, `::test_non_apk_integrity_builds_chunk_merkle_tree`, `::test_png_polyglot_payload_detected`, `::test_risky_html_findings`, `::test_mp4_trailing_payload_detected`, `::test_wav_trailing_payload_detected`, `::test_pdf_javascript_inside_compressed_object_stream`, `::test_pipeline_seals_non_apk_content` |
| Dynamic engine | `test_dynamic_engine.py::test_disabled_by_default`, `::test_physical_device_is_refused`, `::test_full_run_observes_malicious_behaviour`, `::test_hostile_names_never_reach_the_device_shell`, `::test_runtime_findings_are_not_double_counted_with_static`, `::test_pcap_reader_never_raises_on_garbage` (simulated emulator); real emulator: `scripts/run_dynamic_evaluation.py` |

### Integration tests

| Requirement | Tests |
|---|---|
| Upload | `test_api.py::test_upload_runs_analysis`, `::test_bad_uploads_rejected` |
| Baseline creation | `test_baselines.py::test_enrol_creates_pending_baseline_that_is_not_used`, `::test_approve_signs_and_activates`; `test_api.py::test_full_flow_through_the_api` |
| Baseline retrieval | `test_baselines.py::test_versioning_and_review_of_new_version`; `test_api.py::test_baseline_routes` |
| Comparison | `test_tamper_engine.py` (10 tests); `test_comparison.py` (6 tests) |
| Analysis | `test_pipeline.py::*`; `test_static_engine.py::test_real_benign_apk`, `::test_real_suspicious_apk` |
| Report generation | `test_scoring.py::test_scenario_*`, `::test_every_reported_finding_is_explained` |
| Signature verification | `test_audit_chain.py::test_report_sealed_and_verifiable`; `test_api.py::test_full_flow_through_the_api` (POST `/scans/{id}/verify`) |
| Audit ledger | `test_audit_chain.py::test_baseline_lifecycle_is_audited`, `::test_integrity_alert_recorded`; `test_api.py::test_logins_are_audited`; `test_hardening.py::test_concurrent_audit_appends_never_fork_the_chain` |

### Security tests

| Attack | Tests |
|---|---|
| Malformed APK | `test_apk_archive.py::test_not_a_zip`, `::test_corrupt_entry_detected_on_read`; `test_static_engine.py::test_invalid_file_raises_engine_error`; `test_api.py::test_bad_uploads_rejected` |
| Oversized upload / zip bomb | `test_api.py::test_oversized_upload_rejected`; `test_apk_archive.py::test_zip_bomb_ratio_rejected`, `::test_total_uncompressed_limit` |
| Path traversal | `test_apk_archive.py::test_unsafe_entry_names_rejected` (6 variants); `test_api.py::test_filename_cannot_escape_quarantine`, `::test_unknown_scan_ids` |
| Invalid signature | `test_apk_signature.py::test_v2_forged_signed_data_detected`, `::test_v1_tampered_signature_file`; `test_crypto.py::test_flipped_signature_bit_fails` |
| Wrong public key | `test_crypto.py::test_wrong_public_key_fails`, `::test_relabelled_key_id_fails`; `test_baselines.py::test_unknown_signing_key_detected`; `test_audit_chain.py::test_block_signed_by_untrusted_key_detected` |
| Modified report | `test_audit_chain.py::test_modified_report_detected`; `test_api.py::test_tampered_report_fails_verification` |
| Modified baseline | `test_baselines.py::test_tampered_file_list_detected`, `::test_tampered_root_and_files_detected_by_signature`, `::test_tampered_certificate_or_profile_detected`; `test_tamper_engine.py::test_tampered_baseline_is_not_trusted`; `test_audit_chain.py::test_undoing_a_revocation_in_the_database_is_detected` |
| Modified Merkle proof | `test_merkle.py::test_modified_sibling_fails`, `::test_swapped_position_fails`, `::test_truncated_or_extended_proof_fails`, `::test_malformed_proofs_fail_without_raising`, `::test_wrong_root_fails` |
| Modified ledger block | `test_audit_chain.py::test_edit_payload_detected_at_that_block`, `::test_rewritten_block_breaks_signature_and_next_link`, `::test_deleted_middle_block_detected`, `::test_truncation_detected_with_saved_head` |
| Broken previous hash | `test_audit_chain.py::test_broken_previous_hash`, `::test_fork_is_impossible` |
| Certificate replacement | `test_tamper_engine.py::test_resigned_by_other_key_is_certificate_changed`; `test_scoring.py::test_scenario_resigned`; `test_baselines.py::test_review_warns_about_certificate_change` |
| DEX modification | `test_tamper_engine.py::test_modified_dex_detected_with_merkle_proof`; `test_dex.py::test_patched_dex_fails_header_checks`; `test_apk_signature.py::test_v2_content_modification_detected` |
| Manifest modification | `test_tamper_engine.py::test_manifest_modification`, `::test_legitimate_update_reports_profile_changes` |

Additional security tests beyond the brief: signature stripping, v1 file
injection/deletion, Janus-style prepended data, duplicate ZIP entries, obfuscated
manifests, fuzzing (AXML, DEX, DER), authentication/authorization matrix, session
expiry and revocation, rate limiting, CORS, security headers, error-message leakage,
XSS sinks in the frontend, code injection into the generated Frida script,
concurrent ledger writers.

## Independent verification

* **Signature verification vs Google `apksigner`** (`scripts/crosscheck_apksigner.py`):
  13/13 genuine and tampered cases give the same verdict.
* **Merkle tree vs RFC 6962**: roots match a reference implementation written
  directly from the RFC for 0–33, 100 and 257 leaves.
* **Browser end-to-end** (`tests/e2e/ui_smoke.mjs`): every page at desktop and phone
  width in real Chrome; fails on console errors, CSP violations or horizontal overflow.

## Defects found by these tests (and fixed)

| Found by | Defect |
|---|---|
| Real binary manifest (aapt2) | The original AXML parser crashed on every real APK |
| apksigner cross-check | v1-only APKs targeting API ≥ 30 must be rejected (install policy) |
| `test_unsafe_entry_names_rejected` | `zipfile` silently normalises names; raw names were not validated |
| `test_unknown_signing_key_detected` | `verify_baseline` dropped failure reasons (`__bool__` truthiness bug) |
| Foreign-key enforcement in tests | Orchestrator inserted rows for non-existent jobs, poisoning the session |
| `test_frida_script_is_not_injectable` | APK-derived strings were pasted into generated JavaScript (code injection) |
| `test_concurrent_audit_appends_never_fork_the_chain` | Race creating the development signing key under concurrent first use |
| `test_corrupt_signing_block_size_is_invalid_not_unsigned` | A corrupt signing block was reported as "unsigned" instead of "invalid" |
| Browser smoke test | A failed sign-in triggered the "session expired" redirect and erased its error |
| Audit-chain stress test (8 writers under CPU load) | Under contention, writers exhausted their retries and **events were lost** (194–200 of 201 recorded) |
| Same stress test + `test_stale_empty_chain_read_cannot_create_a_second_genesis` | A writer that saw an empty chain re-read the head and could append a **second genesis block** mid-chain |

## Known limitations of the test suite

* Line coverage is measured (not branch coverage) with `scripts/coverage_report.py`:
  **91.9 %** of the lines in `core/`, `api/` and `db/` (4 831 of 5 259). The least-covered module is the optional dynamic engine
  (85.9 %), whose uncovered lines are mostly the standalone command-line entry point and Frida process handling.
* The dynamic engine's unit tests use a simulated emulator (captured adb, kernel-trace and
  packet-capture formats); the real emulator is exercised by `scripts/run_dynamic_evaluation.py`
  and the browser test with dynamic analysis enabled, which are run manually (not in CI).
* PostgreSQL is not tested; SQLite is the tested database.
* The CI workflow (`.github/workflows/tests.yml`, Python 3.12/3.13 on Linux) has
  been written but can only be confirmed once it runs on GitHub; local runs use
  Python 3.14 on Windows.
