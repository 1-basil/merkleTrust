# MerkleTrust — Viva Question Bank

Answers are written to match the code; file references let you show the evidence.

## A. Problem and design

**Q1. What problem does MerkleTrust solve, and why not just hash the whole APK?**
It decides whether an uploaded APK is the same app as an approved trusted version, shows
exactly what changed, assesses risk, and makes every answer provable later. A whole-file
hash only says "identical or not": it cannot localise changes, and it flags a harmless
re-sign by the developer (the signature bytes are random each time) as a change. We hash
every file inside the APK and commit the sorted list to a Merkle root
(`core/file_manifest.py`).

**Q2. Android already verifies signatures. Why is that not enough?**
Android checks that the APK was signed by *some* key and has not changed since *that*
signing. A repackaged app re-signed by the attacker passes. What matters is *which* key —
we compare the certificate fingerprint with the trusted baseline (evaluation cases D04–D10,
N03, W03). We also verify the signature ourselves: v1, v2 and v3, with stripping detection
and the API-30 policy rule, matching `apksigner` on 13/13 cases.

**Q3. Why did you replace "the first upload becomes the baseline"?**
Baseline poisoning: if an attacker's build is uploaded first, it becomes "trusted" and the
genuine app later looks modified. Baselines are now enrolled and approved explicitly by an
administrator, only APKs with a valid signature can be enrolled, and the approver sees a
review against the active baseline that flags a signer change (`core/baselines.py`).

**Q4. What is the difference between integrity and risk?**
Integrity: "is this the same app as the trusted version?" (CLEAN / MODIFIED /
CERTIFICATE_CHANGED / NO_BASELINE / BASELINE_INVALID). Risk: "does it have dangerous
characteristics?" (LOW … CRITICAL). A legitimate update is MODIFIED but can be low risk; a
brand-new malicious app has no baseline but is HIGH risk. Mixing them gives wrong answers
in both directions.

**Q5. Why per-file hashing instead of 64 KB chunks?**
Chunks are positional: inserting one byte shifts every later chunk, so the whole tail looks
changed and the affected file cannot be identified. Per-file hashes are position-independent
and name the file. Chunk hashes are kept only as supplementary forensics.

## B. Cryptography

**Q6. Explain your Merkle tree.**
RFC 6962 hashing: leaf = SHA-256(0x00 ‖ data), node = SHA-256(0x01 ‖ left ‖ right), a node
without a sibling is promoted unchanged. A leaf is `"merkletrust.file.v1" ‖ 0x00 ‖ path ‖
0x00 ‖ SHA-256(content)`, sorted by path. The root commits to every file; an inclusion proof
for one file has ⌈log₂ n⌉ sibling hashes (`core/merkle.py`).

**Q7. Why the 0x00 / 0x01 prefixes, and why not duplicate the last leaf?**
Without domain separation, the 64 bytes of an internal node could be presented as a leaf,
giving a second preimage. Duplicating the odd leaf (Bitcoin-style) makes [a, b, c] and
[a, b, c, c] share a root (the CVE-2012-2459 class of bug). Both are tested
(`test_internal_node_cannot_pose_as_leaf`, `test_no_duplicate_last_leaf_collision`).

**Q8. Why does the leaf include the file path?**
So that swapping the contents of two files, or moving a payload to another name, changes
the root (`test_root_binds_paths`).

**Q9. Why ECDSA P-256 rather than RSA?**
Equivalent ~128-bit security with 32-byte keys and 64-byte signatures, fast signing (about
0.04 ms here), and it is one of the algorithms Android itself uses for APK signatures. RSA
is supported where Android uses it (we *verify* RSA-signed APKs).

**Q10. What exactly do you sign, and why canonical JSON?**
A JSON payload encoded with sorted keys, no whitespace, ASCII escaping, and NaN/Infinity
rejected — so the same data always produces the same bytes. Otherwise a verifier
re-serialising the data could get different bytes and a valid signature would fail.
(`core/crypto.py::canonical_json`)

**Q11. What is ECDSA signature malleability and how do you handle it?**
For a valid signature (r, s), (r, n − s) is also valid. We normalise to low-S when signing
and reject high-S signatures when verifying, so each message has one accepted signature
(`test_signatures_are_low_s_and_high_s_is_rejected`).

**Q12. Where is the private key, and what if it is stolen?**
In a PEM file outside the repository, path from configuration, optionally password-encrypted;
in development it is auto-created under `~/.merkletrust`; production refuses to start without
an explicit key. If stolen, the attacker can forge baselines and blocks — the main residual
risk. A deployment should use an HSM or cloud KMS; retired keys can still verify old
signatures (`MERKLETRUST_TRUSTED_KEYS_DIR`).

**Q13. How do you verify v2 APK signatures without Android?**
Locate the APK Signing Block before the central directory, parse each signer, verify the
signature over `signed data` with the signer's public key, check the key matches the first
certificate, then recompute the content digest: 1 MiB chunks of (entries | central directory
| EOCD with the CD offset replaced), each hashed with a 0xa5 prefix, then a 0x5a top-level
hash — and compare (`core/apk_signature.py`).

## C. Blockchain simulation and audit

**Q14. Is this a blockchain?**
No — it is a *Cryptographically Linked Blockchain Simulation*: one server, one append-only
table, no network, consensus, mining or decentralisation. It demonstrates the
tamper-evidence of hash chaining plus signatures, and we say so in the UI and docs.

**Q15. What happens if someone edits block 4 in the database?**
If they edit only the data, its payload hash no longer matches. If they also recompute the
block hash, the ECDSA signature fails (they lack the key) and block 5's `previous_hash`
no longer matches. Verification reports the first broken block and why
(`core/audit.py::verify_chain`; live in the demo).

**Q16. Can someone delete the latest blocks?**
Hash links cannot reveal missing *newest* blocks. We issue a signed chain head
(`GET /api/v1/audit/head`); verifying against a saved head detects truncation
(`test_truncation_detected_with_saved_head`). Saving heads outside the server is needed.

**Q17. What stops two blocks claiming the same parent?**
`UNIQUE(previous_hash)` in the database, plus an in-process lock and retry for concurrent
writers. A stress test with 8 writers under CPU load records 201/201 events with no
duplicates — it found and fixed lost events and a duplicate genesis block.

**Q18. How do you prove a stored report has not been changed?**
At the end of each analysis the canonical SHA-256 of all engine reports is written into a
signed ANALYSIS_COMPLETED block. Verification recomputes the hash from the stored report and
checks the block and the chain (`core/repository.py::verify_job_report`).

**Q19. Could an insider undo a baseline revocation by editing the status column?**
The approval signature does not cover the status, so the signature alone would not notice.
That is why every lifecycle change is also an audit event, and `verify_baseline` checks that
the status matches the last recorded event (`test_undoing_a_revocation_in_the_database_is_detected`).

## D. Analysis and risk

**Q20. How is the risk score calculated?**
Each finding type in `core/findings.py` has points and a group. The score is the sum of the
highest finding per group (no double counting), capped at 100; level thresholds 20 / 45 / 70;
a critical finding forces at least HIGH. Every point is listed in the UI with its reason.
It is a heuristic indicator, not a probability of malware.

**Q21. Do you penalise self-signed certificates?**
No. Almost all Android apps are self-signed; penalising it was a false positive in the
original design. What matters is whether the certificate matches the baseline.

**Q22. Why do some findings say "already counted"?**
When two findings describe the same fact — e.g. a patched DEX also fails its header checksum
— only the higher-scoring one counts, and the UI says so.

**Q23. What are the behaviour-pattern rules and were they tuned on your test data?**
Dropper (code loading + network), SMS fraud (SMS sending + permission + automatic trigger),
spyware (sensitive data + network + concealment indicator). They were added after the first
evaluation run, which we disclose; to measure them fairly we wrote seven held-out samples
afterwards and did not tune on them. Held-out accuracy is 0.71, with one false positive
(benign plugin loading) and one false negative (`su` privilege escalation).

**Q24. Why are your integrity results 100 %? Isn't that suspicious?**
They test deterministic mechanisms: a changed file has a different SHA-256, a different key
has a different fingerprint, a forged signature fails ECDSA. A correct implementation
should be exact; the evaluation shows ours is, on realistic APKs, including a look-alike
certificate. The heuristic part (risk) is where errors appear, and we report them.

**Q25. What can static analysis not do?**
It cannot know intent (a plugin loader looks like a dropper), cannot see code downloaded at
runtime, and can be evaded by obfuscation and reflection. The optional dynamic engine and
human review address part of that.

**Q25a. What does the emulator (dynamic) engine add, and how does it see a failed `su`?**
It installs the app in a rooted Android 11 emulator, starts it, sends its receivers the
broadcasts the system would send (e.g. `BOOT_COMPLETED`) and watches for 20 s: programs
executed, sockets (named from a packet capture), files written, SMS sent, icon hiding.
An unprivileged app's `su` is refused by the kernel before it becomes a process, so `ps`
and logcat never see it; a kprobe on `execve` plus fork events in a private ftrace
instance records every exec *attempt* by the app's process tree. That caught held-out
H04 (`su -c setenforce 0`). Honest caveats: it was finished after the held-out results
were known, it only sees what an unattended run triggers, and "nothing observed" is not
"safe" (`core/dynamic.py`, `evaluation/results/dynamic.md`).

## E. Engineering

**Q26. How do you handle malicious uploads?**
The body size is enforced while streaming; the file must pass archive validation (size and
compression-ratio limits, raw entry names checked for traversal, NUL and backslash,
duplicate entries rejected, manifest required); the client filename is only a display
label; files are stored read-only under their SHA-256 (`api/uploads.py`,
`core/apk_archive.py`).

**Q27. How are users authenticated?**
scrypt password hashes; on sign-in a random 256-bit token whose SHA-256 alone is stored;
sessions expire and can be revoked; sent as a bearer header (no cookies, so no CSRF);
admin/analyst roles; sign-in is rate-limited and audited (`api/security.py`, `api/deps.py`).

**Q28. How do you prevent XSS from data inside APKs?**
The dashboard builds DOM nodes with `textContent` only — a test fails if any HTML-injection
API appears — and a CSP with `script-src 'self'` and no inline scripts.

**Q29. How did you test it?**
478 automated tests (unit, integration, API, security) at 90.5 % line coverage; real signed
APK fixtures; regression tests that fail on the old code for every fixed bug; headless
Chrome end-to-end tests of both web front ends (the React one runs in CI); fuzzy hashes
cross-checked against an independent ssdeep implementation; a differential check against `apksigner`; a concurrency stress
test; and the evaluation (`docs/TESTING.md`).

**Q30. What would you do next?**
Anchor signed heads externally, move the key to an HSM/KMS, two-person approval, evaluate on
third-party malware corpora, and add privilege-escalation and obfuscation rules
(`docs/REPORT.md` §23).
