# MerkleTrust — Viva & Defense Question Bank

Comprehensive preparation guide for external examiners, project evaluators, and academic defense.

---

### Q1: What problem does MerkleTrust solve? Why not just hash the whole APK with SHA-256?
**Answer:**
A whole-file SHA-256 hash is an all-or-nothing check. If a single bit in an APK changes:
1. Whole-file SHA-256 tells you *that* something changed, but gives **zero information about what changed, where it changed, or whether it was malicious**.
2. MerkleTrust divides the APK into $64\text{ KB}$ binary chunks, builds a **Merkle tree**, and maps each chunk to the APK's internal archive entries (`classes.dex`, `AndroidManifest.xml`, native libraries) using the ZIP Central Directory.
3. This allows MerkleTrust to:
   - Identify the exact physical files modified.
   - Detect certificate replacements while ignoring harmless metadata shifts.
   - Provide $O(\log N)$ cryptographic inclusion proofs so any client can verify any chunk or report without transferring or re-reading the entire APK.

---

### Q2: What is a Merkle tree and what are its mathematical properties?
**Answer:**
A Merkle tree is a binary tree where:
- Every leaf node is a cryptographic hash of a data block ($H(B_i)$).
- Every non-leaf node is the cryptographic hash of its concatenated children:
  $$\text{Parent} = \text{SHA256}(\text{Child}_{\text{left}} \mathbin{\Vert} \text{Child}_{\text{right}})$$
- The top node is the **Merkle Root**.

**Key Properties:**
- **Tamper Evidence**: Any alteration to any leaf node alters the hashes up the path, inevitably altering the Merkle Root.
- **Logarithmic Audit Proofs**: To prove a specific chunk is part of a file with $N$ chunks requires only $\log_2(N)$ sibling hashes (an **audit path** or **inclusion proof**), rather than all $N$ chunks.

---

### Q3: How does Chunk-to-File Localization work?
**Answer:**
1. The **Integrity Engine** parses the APK ZIP Central Directory and local headers to record the physical byte span $[F_{\text{start}}, F_{\text{end}})$ and SHA-256 for every entry.
2. The APK is sliced into $64\text{ KB}$ chunks with spans $[C_{\text{start}}, C_{\text{end}})$.
3. When comparing against a trusted baseline, the **Tamper Engine** identifies the changed chunk indices $i$.
4. It performs a 1D bounding box intersection check:
   $$\max(C_{\text{start}}, F_{\text{start}}) < \min(C_{\text{end}}, F_{\text{end}})$$
5. Any file whose byte span overlaps with a changed chunk is flagged as modified. If the file is `classes.dex`, it triggers code tampering alerts and extracts new classes for dynamic analysis.

---

### Q4: Why is Canonical JSON necessary before signing or hashing?
**Answer:**
In standard JSON, key order and whitespace are non-deterministic. For example:
```json
{"score": 90, "verdict": "trusted"}
```
and
```json
{
  "verdict": "trusted",
  "score": 90
}
```
represent identical semantic data, but produce completely different SHA-256 hashes and invalid digital signatures!
Canonical JSON enforces:
- Alphabetically sorted keys (`sort_keys=True`).
- Minimal delimiters without whitespace (`separators=(',', ':')`).
- UTF-8 encoding.
This guarantees that any participant computing the hash of the report gets the identical bit-for-bit digest.

---

### Q5: Why use ECDSA P-256 instead of RSA?
**Answer:**
- **Key & Signature Size**: An ECDSA P-256 private key is only 256 bits, and a signature is 64–72 bytes in DER format (or 64 bytes raw $r \mathbin{\Vert} s$), compared to a 2048-bit or 4096-bit RSA signature (256–512 bytes).
- **Security Level**: ECDSA P-256 (`SECP256R1`) provides approximately 128 bits of symmetric security equivalence—matching standard AES-128—with a tiny computational and bandwidth footprint.
- **Suitability for Embedded/Mobile & Blockchain**: ECDSA is the cryptographic standard used in Bitcoin, Ethereum, and Android APK v2/v3 signatures.

---

### Q6: How is the Blockchain Ledger simulated and how does it prevent tampering?
**Answer:**
1. **Hash Chaining**: Each ledger entry contains:
   $$\text{entry\_hash} = \text{SHA256}(\text{prev\_entry\_hash} \mathbin{\Vert} \text{canonical\_report\_sha256} \mathbin{\Vert} \text{timestamp})$$
   where the first entry points to a 64-zero Genesis hash.
2. **Digital Notarization**: Every `entry_hash` is digitally signed with an ECDSA private key (`mt-signer-1`).
3. **Batch Merkle Blocks**: Every $N$ entries are batched into a simulated block whose header contains $\text{SHA256}(\text{prev\_block\_hash} \mathbin{\Vert} \text{batch\_merkle\_root})$.
4. **Tamper Detection**: If an attacker attempts to modify an old report:
   - The canonical SHA changes.
   - The `entry_hash` breaks.
   - The ECDSA signature becomes invalid.
   - All subsequent `prev_entry_hash` pointers in the chain sever.
   - `verify_chain()` instantly pinpoints the exact entry index where tampering occurred.

---

### Q7: How do the four teammates' engines communicate without creating coupling?
**Answer:**
By adhering to **Engine Independence Contract** (`core/contracts.py`):
1. **Engines are plain Python functions**, not independent HTTP microservices:
   ```python
   def run(job_id: str, ctx: JobContext) -> dict
   ```
2. No engine imports another engine's private code.
3. Engines only communicate through `ctx.prior`, which contains plain Python dictionaries loaded from frozen JSON contracts (`integrity.json`, `static.json`, etc.).
4. If an upstream engine fails or is incomplete (e.g. emulator absent), downstream engines degrade gracefully with `status: "partial"` and continue without crashing the master pipeline.

---

### Q8: How is the Trust Score calculated?
**Answer:**
- Every application starts with a perfect score of **100**.
- The scoring engine inspects the standardized `findings[]` emitted by all upstream engines and applies severity deductions:
  - Critical finding: $-35$
  - High finding: $-18$
  - Medium finding: $-8$
  - Low finding: $-3$
- Named rule deductions:
  - `R_CERT_CHANGED`: $-40$ (tampered signing identity)
  - `R_FILES_MODIFIED`: $-25$ for modified DEX, $-15$ for other files
  - `R_SELF_SIGNED_CERT`: $-10$
- Final score is bounded to $[0, 100]$:
  - $\text{Score} \ge 70 \implies \text{trusted}$
  - $40 \le \text{Score} < 70 \implies \text{suspicious}$
  - $\text{Score} < 40 \implies \text{malicious}$
