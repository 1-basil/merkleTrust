# MerkleTrust — Live Demonstration Script (≈ 12 minutes)

All APKs used here are already in the repository (`evaluation/dataset/`), so the demo
needs no Android SDK and no internet.

| File | Role in the story |
|---|---|
| `baseline_demo.apk` | The developer's official build 1.2.0 |
| `demo_official_copy.apk` | A byte-identical copy that a user downloaded |
| `demo_repackaged.apk` | The same app repackaged by an attacker: injected code-loading and SMS code, an extra permission, an extra native library, re-signed with the attacker's key |

## 0. Before the viva (pre-flight)

```bash
pip install -r requirements.txt
python -m pytest -q                                    # expect: all passed
# fresh demo data directory (any empty folder)
#   PowerShell: $env:MERKLETRUST_DATA_DIR = "demo-data"
#   bash:       export MERKLETRUST_DATA_DIR=demo-data
python -m scripts.generate_signing_key --out ~/.merkletrust/keys/demo.pem   # optional; otherwise a dev key is created
python -m scripts.manage_users create admin --role admin
python -m scripts.manage_users create analyst --role analyst
uvicorn api.main:app --port 8000
```

Open http://127.0.0.1:8000 and sign in as **admin**. Keep `evaluation/dataset/` open in a
file browser. Rehearse once; to reset, stop the server and delete the demo data folder.

Optional automated rehearsal of every screen: `python -m scripts.seed_demo
http://127.0.0.1:8000` against a *separate* fresh data folder, then `node
tests/e2e/ui_smoke.mjs …` (see the script header).

## 1–2. Upload a clean APK — and see that nothing is trusted by default

1. **Scan an app** → drop `demo_official_copy.apk`.
   *Say:* "Every file inside the APK is fingerprinted with SHA-256, its signature is
   verified, its code and configuration are inspected, and the result is recorded."
2. Result: **NOT VERIFIED — No trusted version to compare with**, risk **LOW 0**.
   *Say:* "The app is validly signed — but by whom? Android only checks that *someone*
   signed it. Without an approved reference we refuse to call it 'clean'. Many systems
   trust the first upload; that would let an attacker poison the baseline."

## 3. Create and verify the trusted baseline

3. **Trusted versions** → **Upload official APK** → `baseline_demo.apk` → it appears as
   *Awaiting approval*. Click **Approve** (note: "Official release 1.2.0").
   Then **Details** → "Record verified".
   *Say:* "Approval signs a canonical record with ECDSA P-256: package, version, the
   certificate fingerprint, the Merkle root over every file's hash. Before every use the
   record is re-verified — if anyone edits it in the database, it is rejected."
   Re-upload `demo_official_copy.apk` → **CLEAN**, "Matches the trusted version".

## 4–5. Modify the APK and upload it

4. *Say:* "An attacker took the official app, injected a code loader and SMS-sending
   code, added a permission and a native library, and re-signed it with their own key —
   they don't have the developer's key." (The file is `demo_repackaged.apk`; it was built
   with the real Android toolchain.)
5. **Scan an app** → `demo_repackaged.apk`.

## 6–8. What changed, the certificate, and why it is risky

6. Result: **HIGH RISK**; "Is this the same app?" → **Signed by a different developer
   key**. Tab **File changes**: `AndroidManifest.xml` and `classes.dex` **modified**,
   `lib/x86_64/libpayload.so` **added**; resources unchanged.
   *Say:* "Per-file hashing tells us exactly *which* files changed, not just that the
   bytes differ."
7. Tab **Certificate**: trusted vs this app side by side — different fingerprint and key
   type. *Say:* "A self-signed certificate is normal on Android. What matters is that it
   is not the trusted developer's. Our dataset even includes an attacker certificate that
   copies the developer's *name* — we compare fingerprints, never names."
8. Tab **Overview** → risk breakdown: each line with its points (signed by a different
   developer key, program code changed, can download and run code, …). Tab **Security
   findings**: each finding has an explanation, evidence and what to do.
   *Say:* "Integrity and risk are separate questions. The score is an explained
   indicator, not a malware probability — and nothing is counted twice."

## 9–10. Cryptographic verification and a Merkle proof

9. Tab **Verification**: trusted record ✓, developer signature (this app's own signature
   is valid — it is the attacker's), Merkle root ✗ "Integrity record has changed", audit
   record ✓. Click **Verify this report now** → **Verified**.
   *Say:* "The report's canonical SHA-256 is sealed in a signed audit block. If anyone
   edits the stored report, this check fails."
10. Tab **File changes** → **Check proof** on `classes.dex` → **INVALID**: "its
    fingerprint does not lead to the trusted root". Open *Merkle proof*: trusted root,
    both fingerprints, number of proof steps.
    *Say:* "A Merkle proof needs only log₂(n) hashes. The trusted fingerprint of
    classes.dex proves into the signed root; the uploaded one cannot." (Optionally show
    the clean scan: **VALID**.)

## 11. The audit entry

11. **Audit history**: Baseline enrolled / approved, APK uploaded, APK analysed,
    **Integrity problem detected**, Report verification performed — each with actor,
    time, and a valid record.

## 12–14. Tamper with the Blockchain Simulation

12. **Blockchain Simulation**. Point at the notice: single-node, append-only, *not* a
    distributed blockchain. Click a block: index, previous hash, block hash, signature.
    Admin panel → enter the number of the **Baseline enrolled** block (block **4** if you
    signed in once and followed the steps above; check the event name on the card), mode
    **Edit data and recompute the block hash** → **Tamper with block**.
    *Say:* "This is an attacker with database access rewriting history — and they even
    recompute the block's hash."
13. Click **Verify chain**.
14. Red banner **BLOCKCHAIN SIMULATION INTEGRITY FAILURE** — the altered block and the
    broken link to the next block are red; block detail: "Its digital signature is not
    valid", and the next block "does not match the hash of the block before it".
    *Say:* "Without our private key they cannot re-sign it, and block 4 still points to
    the old fingerprint. Changing anything breaks the chain from that point."

## 15–16. Restore and verify again

15. **Restore valid chain**.
16. **Verify chain** → **Chain intact**, all blocks valid.

## Fallbacks

* Browser problem: every step has an API equivalent at http://127.0.0.1:8000/api/docs.
* If the server will not start because of an old database: point
  `MERKLETRUST_DATA_DIR` at a new folder.
* If time is short: steps 1–3, 5–6, 10, 12–16 carry the story.

## Questions to expect at this point

See [VIVA_QUESTION_BANK.md](VIVA_QUESTION_BANK.md).
