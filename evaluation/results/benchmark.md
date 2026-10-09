# MerkleTrust — Performance

Generated 2026-10-09T01:38:31+00:00 on Windows 11 (AMD64, 22 CPUs), Python 3.14.7. Cells show **median (min–p95)** of 5 runs unless stated. Single process, SQLite (WAL, synchronous=FULL), no emulator. Produced by `python -m scripts.benchmark`.

The machine was in normal interactive use while measuring, so medians include background noise; the minimum is the best estimate of the intrinsic cost.

## Per APK size

| Measurement | small (0.01 MB, 8 files) | medium (5.26 MB, 9 files) | large (52.45 MB, 9 files) |
|---|---|---|---|
| Upload → analysis → result (REST API) | 66.93 ms (61.70–122.83) | 204.17 ms (189.17–227.25) | 1413.51 ms (1382.66–1447.39) |
| SHA-256 of the whole file | 0.01 ms (0.01–0.04) | 2.84 ms (2.71–4.07) | 30.67 ms (26.58–35.03) |
| Per-file SHA-256 manifest + Merkle root (+ chunk forensics) | 1.47 ms (1.02–2.93) | 28.00 ms (25.17–31.47) | 296.85 ms (290.10–301.98) |
| APK signature verification (v1/v2/v3) | 1.19 ms (1.16–2.94) | 16.71 ms (15.21–18.52) | 156.79 ms (142.68–160.25) |
| Static analysis (manifest, DEX, signature, findings) | 3.58 ms (2.67–7.30) | 80.93 ms (70.39–85.63) | 761.67 ms (709.43–773.16) |
| Comparison with baseline | 0.03 ms (0.02–0.07) | 0.07 ms (0.06–0.13) | 0.10 ms (0.10–0.15) |
| Baseline enrolment (analyse + insert + commit), single run | 12.2 ms | 110.4 ms | 1163.3 ms |
| Baseline approval (ECDSA sign + audit block + commit), single run | 2.8 ms | 3.9 ms | 4.5 ms |

## Cryptographic operations

| Operation | Time |
|---|---|
| ECDSA P-256 sign (canonical JSON payload, 200 runs) | 0.03 ms (0.03–0.04) |
| ECDSA P-256 verify (200 runs) | 0.07 ms (0.07–0.11) |
| Merkle tree build, 100 leaves | 0.15 ms (0.15–0.17) |
| Inclusion proof generate / verify, 100 leaves (7 steps) | 0.00 ms (0.00–0.00) / 0.01 ms (0.01–0.01) |
| Merkle tree build, 1000 leaves | 1.59 ms (1.52–1.60) |
| Inclusion proof generate / verify, 1000 leaves (10 steps) | 0.00 ms (0.00–0.00) / 0.01 ms (0.01–0.01) |
| Merkle tree build, 10000 leaves | 16.48 ms (16.28–19.59) |
| Inclusion proof generate / verify, 10000 leaves (14 steps) | 0.00 ms (0.00–0.00) / 0.02 ms (0.02–0.02) |
| Merkle tree build, 100000 leaves | 188.13 ms (184.60–191.67) |
| Inclusion proof generate / verify, 100000 leaves (17 steps) | 0.01 ms (0.01–0.01) / 0.02 ms (0.02–0.03) |
| Full audit-chain verification, 538 blocks (hash + link + ECDSA per block) | 57.40 ms (51.76–60.00) |

Times include Python interpreter overhead; they are indicative of this prototype on this machine, not a performance guarantee.
