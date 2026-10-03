# MerkleTrust — Performance

Generated 2026-10-02T23:52:00+00:00 on Windows 11 (AMD64, 22 CPUs), Python 3.14.7. Cells show **median (min–p95)** of 9 runs unless stated. Single process, SQLite (WAL, synchronous=FULL), no emulator. Produced by `python -m scripts.benchmark`.

The machine was in normal interactive use while measuring, so medians include background noise; the minimum is the best estimate of the intrinsic cost.

## Per APK size

| Measurement | small (0.01 MB, 8 files) | medium (5.26 MB, 9 files) | large (52.45 MB, 9 files) |
|---|---|---|---|
| Upload → analysis → result (REST API) | 111.38 ms (66.49–336.23) | 689.66 ms (235.78–1105.50) | 1131.32 ms (1043.23–1195.65) |
| SHA-256 of the whole file | 0.01 ms (0.01–0.03) | 4.11 ms (2.78–5.89) | 135.62 ms (54.30–193.36) |
| Per-file SHA-256 manifest + Merkle root (+ chunk forensics) | 1.19 ms (0.72–2.11) | 44.23 ms (35.44–114.56) | 1053.35 ms (367.12–2102.97) |
| APK signature verification (v1/v2/v3) | 1.78 ms (1.08–3.96) | 24.43 ms (21.59–30.89) | 248.34 ms (211.32–296.66) |
| Static analysis (manifest, DEX, signature, findings) | 8.52 ms (1.50–12.25) | 27.93 ms (21.66–128.38) | 249.66 ms (238.36–297.49) |
| Comparison with baseline | 0.02 ms (0.02–0.07) | 0.08 ms (0.08–0.17) | 0.17 ms (0.13–0.19) |
| Baseline enrolment (analyse + insert + commit), single run | 14.0 ms | 212.0 ms | 682.5 ms |
| Baseline approval (ECDSA sign + audit block + commit), single run | 5.1 ms | 4.5 ms | 4.5 ms |

## Cryptographic operations

| Operation | Time |
|---|---|
| ECDSA P-256 sign (canonical JSON payload, 200 runs) | 0.04 ms (0.04–0.09) |
| ECDSA P-256 verify (200 runs) | 0.08 ms (0.08–0.19) |
| Merkle tree build, 100 leaves | 0.19 ms (0.18–0.21) |
| Inclusion proof generate / verify, 100 leaves (7 steps) | 0.00 ms (0.00–0.00) / 0.01 ms (0.01–0.02) |
| Merkle tree build, 1000 leaves | 2.78 ms (1.88–3.48) |
| Inclusion proof generate / verify, 1000 leaves (10 steps) | 0.00 ms (0.00–0.01) / 0.03 ms (0.02–0.08) |
| Merkle tree build, 10000 leaves | 25.12 ms (22.97–29.72) |
| Inclusion proof generate / verify, 10000 leaves (14 steps) | 0.01 ms (0.00–0.01) / 0.04 ms (0.02–0.06) |
| Merkle tree build, 100000 leaves | 299.91 ms (294.00–305.81) |
| Inclusion proof generate / verify, 100000 leaves (17 steps) | 0.00 ms (0.00–0.00) / 0.03 ms (0.03–0.04) |
| Full audit-chain verification, 562 blocks (hash + link + ECDSA per block) | 95.37 ms (88.70–119.22) |

Times include Python interpreter overhead; they are indicative of this prototype on this machine, not a performance guarantee.
