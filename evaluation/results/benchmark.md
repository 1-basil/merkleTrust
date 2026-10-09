# MerkleTrust — Performance

Generated 2026-10-09T02:02:31+00:00 on Windows 11 (AMD64, 22 CPUs), Python 3.14.7. Cells show **median (min–p95)** of 5 runs unless stated. Single process, SQLite (WAL, synchronous=FULL), no emulator. Produced by `python -m scripts.benchmark`.

The machine was in normal interactive use while measuring, so medians include background noise; the minimum is the best estimate of the intrinsic cost.

## Per APK size

| Measurement | small (0.01 MB, 8 files) | medium (5.26 MB, 9 files) | large (52.45 MB, 9 files) |
|---|---|---|---|
| Upload → analysis → result (REST API) | 70.10 ms (66.02–147.36) | 205.99 ms (188.03–214.69) | 1366.59 ms (1326.05–1379.61) |
| SHA-256 of the whole file | 0.01 ms (0.01–0.03) | 2.87 ms (2.85–4.17) | 30.89 ms (26.38–34.63) |
| Per-file SHA-256 manifest + Merkle root (+ chunk forensics) | 1.89 ms (1.68–2.41) | 30.16 ms (28.47–31.61) | 281.56 ms (278.51–286.18) |
| APK signature verification (v1/v2/v3) | 1.54 ms (1.37–2.73) | 15.47 ms (14.46–16.82) | 140.05 ms (134.92–143.73) |
| Static analysis (manifest, DEX, signature, findings) | 2.70 ms (2.57–9.82) | 76.52 ms (69.60–80.17) | 745.64 ms (699.60–800.65) |
| Comparison with baseline | 0.03 ms (0.03–0.08) | 0.08 ms (0.07–0.13) | 0.10 ms (0.10–0.18) |
| Baseline enrolment (analyse + insert + commit), single run | 12.1 ms | 106.4 ms | 1092.5 ms |
| Baseline approval (ECDSA sign + audit block + commit), single run | 5.0 ms | 3.8 ms | 17.1 ms |

## Cryptographic operations

| Operation | Time |
|---|---|
| ECDSA P-256 sign (canonical JSON payload, 200 runs) | 0.04 ms (0.03–0.06) |
| ECDSA P-256 verify (200 runs) | 0.06 ms (0.06–0.09) |
| Merkle tree build, 100 leaves | 0.14 ms (0.14–0.16) |
| Inclusion proof generate / verify, 100 leaves (7 steps) | 0.00 ms (0.00–0.00) / 0.01 ms (0.01–0.01) |
| Merkle tree build, 1000 leaves | 1.46 ms (1.44–1.89) |
| Inclusion proof generate / verify, 1000 leaves (10 steps) | 0.00 ms (0.00–0.00) / 0.01 ms (0.01–0.01) |
| Merkle tree build, 10000 leaves | 16.43 ms (14.61–24.11) |
| Inclusion proof generate / verify, 10000 leaves (14 steps) | 0.00 ms (0.00–0.00) / 0.02 ms (0.02–0.03) |
| Merkle tree build, 100000 leaves | 168.65 ms (161.92–175.38) |
| Inclusion proof generate / verify, 100000 leaves (17 steps) | 0.00 ms (0.00–0.00) / 0.02 ms (0.02–0.03) |
| Full audit-chain verification, 538 blocks (hash + link + ECDSA per block) | 54.49 ms (52.93–63.11) |

Times include Python interpreter overhead; they are indicative of this prototype on this machine, not a performance guarantee.
