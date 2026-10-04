# MerkleTrust — Evaluation

This folder holds a controlled, reproducible evaluation of MerkleTrust:

| Path | Content |
|---|---|
| `dataset/` | 35 real APKs (3 official baselines + 32 cases) and `manifest.json` with the ground truth |
| `results/evaluation.md` / `.json` | Detection results of the current system |
| `results/evaluation_initial.md` / `.json` | The first run, before the changes described below (kept unedited) |
| `results/benchmark.md` / `.json` | Performance measurements |

## Reproduce

```bash
python -m scripts.run_evaluation      # ~1 min; no Android SDK needed (dataset is committed)
python -m scripts.benchmark           # builds 0/5/50 MB APKs, needs the Android SDK + JDK
python -m scripts.build_eval_dataset  # regenerate the dataset (Android SDK + JDK); new signatures each time
```

The runner works only through the real REST API (upload validation, job pipeline,
database, audit chain) in a fresh temporary data directory, then compares what the
API reports with `dataset/manifest.json`. It contains no tuning.

## Dataset

All APKs are genuine builds produced by `aapt2 → javac → d8 → zipalign → apksigner`
(`scripts/build_eval_dataset.py`). Three signing keys are used:

* **A** — the developer's key (EC P-256). Official builds and legitimate releases.
* **B** — an attacker key whose certificate **copies the developer's subject name**
  (`CN=MerkleTrust Demo Release`), so a look-alike certificate must be caught by fingerprint.
* **C** — another attacker key (RSA-2048).

Threat model for the cases: the attacker can modify and repackage an app but does not
hold key A, so a modified app is either re-signed with B/C or left with a broken
signature (see `docs/THREAT_MODEL.md`).

| Group | Cases | What they are |
|---|---|---|
| Demo app (baseline 1.2.0) | D01–D13 | byte-identical copy; same-key re-sign; legitimate update; manifest, DEX, certificate, added-file, deleted-file, repackaging and permission attacks (re-signed); broken signature; stripped v2 signature; Janus-style prepended data |
| Notes app (baseline 4.1) | N01–N04 | copy; same-key re-sign; certificate replacement; code modification |
| Weather app (baseline 2.3) | W01–W03 | copy; legitimate data-only update; added location-tracking permissions |
| Risk samples (no baseline) | R01–R05 | combined suspicious app, dropper, premium-SMS fraud, spyware, and a *benign* app with sloppy release settings |
| Held-out risk samples | H01–H07 | written after the risk rules were final (see below): 4 malicious, 3 benign |

Ground truth per case (in `manifest.json`): expected integrity status, whether the app
changed, whether the change was unauthorised, whether the user should be warned not to
install it, and — where it is known exactly — which files were modified/added/deleted.

## Questions measured

| Question | Positive means |
|---|---|
| Change detection | integrity status is not CLEAN (app differs from its trusted version) |
| Unauthorised modification | certificate changed, or app signature not valid, or baseline invalid |
| Install warning | risk level HIGH or CRITICAL |
| Cryptographic tamper detection | verification of a report / baseline / audit chain fails |

Plus: exact integrity status (5 classes) and exact localisation of changed files.
Untouched reports, baselines and the untouched chain are verified too, as negatives,
so false positives are measured.

## Results (current system)

From `results/evaluation.md`:

| Question | n | Accuracy | Precision | Recall | FPR | FNR |
|---|---|---|---|---|---|---|
| Change detection | 20 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| Unauthorised modification | 20 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| Install warning (development set) | 25 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| **Behavioural risk — held-out set** | **7** | **0.714** | **0.750** | **0.750** | **0.333** | **0.250** |
| Cryptographic tamper detection | 47 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |

Exact integrity status 32/32; exact changed-file localisation 20/20.

**How to read this.** The integrity and cryptographic results test deterministic
mechanisms (hash comparison, signature verification, hash chaining): with correct
implementation they are expected to be exact, and the evaluation confirms that on
realistic APKs and attacks. The behavioural-risk results are heuristic, and the
held-out row is the honest estimate of how they generalise.

## What changed after the first run (full disclosure)

The first run (`results/evaluation_initial.md`) gave perfect integrity and cryptographic
results but missed 3 of 4 malicious samples on behavioural risk (recall 0.25,
install-warning recall 0.82). Investigation found two separate causes:

1. **Two samples were built wrongly.** In R02 the C2 URL was an unused local
   variable, which the compiler removed, so the APK did not contain the indicator it
   was labelled with. In R04 the hard-coded IP was in a reserved documentation range
   (203.0.113.0/24), which the detector deliberately ignores. Both samples were
   corrected (the URL is now used; the IP is a routable address).
2. **A real weakness: scoring added capabilities independently.** A dropper, an SMS
   fraud app or spyware is dangerous because of a *combination* of capabilities. Three
   behaviour-pattern rules were added (`PATTERN_DROPPER`, `PATTERN_SMS_FRAUD`,
   `PATTERN_SPYWARE` in `core/findings.py` / `core/static.py`), each describing a
   recognised malware-family pattern.

Because those rules were written after seeing the development results, the development
set can no longer measure them fairly. Seven **held-out** samples were therefore
written *after* the rules were final, using different APIs (InMemoryDexClassLoader,
multipart SMS triggered by incoming SMS, icon hiding, `su`), with labels fixed by
intent before the run, and including benign apps that legitimately use the same
capabilities. The rules were **not** changed after the held-out run.

Held-out errors, kept as they are:

* **H05 — false positive.** A benign drawing app that loads its own plugin code is
  flagged as a dropper. Static analysis sees *what* code can do, not *why*; legitimate
  and malicious dynamic code loading look the same.
* **H04 — false negative.** A "booster" that runs `su` to disable SELinux on boot is
  only MEDIUM: there is no rule for privilege-escalation commands.

## Emulator (dynamic) evaluation

`python -m scripts.run_dynamic_evaluation` (needs the running `mt_api30_root` emulator)
runs the 12 cases without a baseline through the real pipeline with the dynamic engine
enabled, and computes the risk level twice from the same reports: without and with the
emulator's findings. Full table: `results/dynamic.md` (Android API 30, rooted, 20 s
observation window, about 20 s per app).

| Cases | n | Static only: TP / FP / TN / FN | With emulator: TP / FP / TN / FN |
|---|---|---|---|
| Development R* | 5 | 4 / 0 / 1 / 0 | 4 / 0 / 1 / 0 |
| Held-out H* | 7 | 3 / 1 / 2 / 1 | 4 / 1 / 2 / 0 |

* **H04 is now detected.** When the engine sent the booster its `BOOT_COMPLETED`
  broadcast, the kernel exec trace recorded the app running `su -c setenforce 0`
  (`RUNTIME_PRIV_ESC`), raising it from MEDIUM (23) to HIGH (53). The attempt fails
  (the app is not allowed to use `su`), so it never appears as a process in `ps` or in
  logcat; only the execve kprobe sees it.
* **SMS fraud confirmed at runtime** for R03 (boot receiver → `90901`) and H02 (incoming
  SMS receiver → `7726`), and command execution plus an SMS for R01, read from the
  device's SMS sent box and the exec trace.
* **No benign app got worse**: H05's false positive is a *static* finding and stays;
  runtime observation adds evidence, it never removes points.
* **"Nothing suspicious" is not "safe".** R02, R04, H01 and H03 keep their malicious code
  in classes the app never calls during an unattended run (no UI interaction, and the
  dropper's download server does not exist), so there was nothing to observe; their
  static verdicts stand.

**Disclosure.** The dynamic engine was completed *after* the held-out results above were
known, and H04 was the motivating miss, so the held-out row is not an independent test of
the engine. It shows what runtime evidence adds on samples whose behaviour is documented
in their source. A fair measurement needs new samples written after this engine.

## Performance (summary)

From `results/benchmark.md` (median of 9 runs on a machine in interactive use):
end-to-end upload-to-result through the API takes about 0.1 s for a small APK and
about 1.1 s for a 52 MB APK; ECDSA P-256 signing/verification take well under a
millisecond; a Merkle tree over 100 000 leaves builds in about 0.3 s and proofs verify in
microseconds.

Profiling during the benchmark showed that SQLite's default rollback journal (creating
and deleting a journal file on every commit) dominated request time on Windows. Switching
to WAL mode with `synchronous=FULL` (no durability trade-off) reduced a small-APK scan
from about 1.2 s to about 0.1 s.

## Limitations

* Small dataset built by the project team. It shows that each mechanism works on
  realistic APKs and attacks; it does not measure performance on real-world malware.
* The risk heuristics and the development labels come from the same team; only the
  held-out row is an (imperfect) independent check, and it has just 7 samples.
* The main evaluation is static analysis only; the optional emulator engine is
  evaluated separately on the 12 behaviour cases (above), after the held-out results
  were known.
* Timings are from one Windows machine under normal interactive load.
