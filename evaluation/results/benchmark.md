# MerkleTrust — Performance

Generated 2026-10-08T09:44:47+00:00 on Windows 11 (AMD64, 22 CPUs), Python 3.14.7. Cells show **median (min–p95)** of 5 runs unless stated. Single process, SQLite (WAL, synchronous=FULL), no emulator. Produced by `python -m scripts.benchmark`.

The machine was in normal interactive use while measuring, so medians include background noise; the minimum is the best estimate of the intrinsic cost.

## Per APK size

| Measurement | small (0.01 MB, 8 files) | medium (5.26 MB, 9 files) | large (52.45 MB, 9 files) |
|---|---|---|---|
| Upload → analysis → result (REST API) | 190.78 ms (171.41–1080.00) | 497.10 ms (452.14–810.13) | 2970.81 ms (2718.16–3865.56) |
| SHA-256 of the whole file | 0.01 ms (0.01–0.04) | 5.39 ms (4.32–5.58) | 62.86 ms (55.18–70.90) |
| Per-file SHA-256 manifest + Merkle root (+ chunk forensics) | 4.22 ms (3.06–10.54) | 72.89 ms (59.03–120.08) | 642.85 ms (565.77–740.96) |
| APK signature verification (v1/v2/v3) | 4.48 ms (3.45–13.13) | 38.99 ms (35.81–44.62) | 471.89 ms (299.34–634.18) |
| Static analysis (manifest, DEX, signature, findings) | 8.03 ms (5.35–18.44) | 191.81 ms (157.72–202.22) | 1696.26 ms (1478.07–2278.70) |
| Comparison with baseline | 0.05 ms (0.04–0.12) | 0.14 ms (0.07–0.24) | 0.43 ms (0.36–0.61) |
| Baseline enrolment (analyse + insert + commit), single run | 24.4 ms | 268.5 ms | 2301.6 ms |
| Baseline approval (ECDSA sign + audit block + commit), single run | 4.6 ms | 5.5 ms | 10.2 ms |

## Cryptographic operations

| Operation | Time |
|---|---|
| ECDSA P-256 sign (canonical JSON payload, 200 runs) | 0.13 ms (0.10–0.21) |
| ECDSA P-256 verify (200 runs) | 0.29 ms (0.18–0.50) |
| Merkle tree build, 100 leaves | 0.58 ms (0.57–0.65) |
| Inclusion proof generate / verify, 100 leaves (7 steps) | 0.00 ms (0.00–0.01) / 0.04 ms (0.02–0.05) |
| Merkle tree build, 1000 leaves | 6.05 ms (5.70–6.89) |
| Inclusion proof generate / verify, 1000 leaves (10 steps) | 0.01 ms (0.00–0.01) / 0.06 ms (0.04–0.09) |
| Merkle tree build, 10000 leaves | 76.38 ms (66.64–96.08) |
| Inclusion proof generate / verify, 10000 leaves (14 steps) | 0.00 ms (0.00–0.01) / 0.08 ms (0.04–0.10) |
| Merkle tree build, 100000 leaves | 950.92 ms (719.98–1181.86) |
| Inclusion proof generate / verify, 100000 leaves (17 steps) | 0.00 ms (0.00–0.00) / 0.09 ms (0.04–0.09) |
| Full audit-chain verification, 538 blocks (hash + link + ECDSA per block) | 225.56 ms (205.93–226.23) |

Times include Python interpreter overhead; they are indicative of this prototype on this machine, not a performance guarantee.
