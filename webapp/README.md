# MerkleTrust web app (React)

A dark-mode dashboard for the MerkleTrust API: universal file scanner, results with
trust score and cryptographic proof, scan history, audit ledger explorer and baselines.

Stack: React 18, Vite, Tailwind CSS 4, lucide-react, react-router. No state library.

## Run

```bash
# 1. backend (from the repository root)
python -m uvicorn api.main:app --port 8000

# 2. a user account (first time only; prompts for a password)
python -m scripts.manage_users create alice --role admin

# 3. this app
cd webapp
npm install
npm run dev          # http://localhost:5173
```

The dev server proxies `/api` to `http://localhost:8000`, so the backend needs no CORS
setup. Point it elsewhere with `VITE_API_TARGET=http://host:8000 npm run dev`.
`npm run build` writes a static bundle to `dist/`. To serve that bundle from a different
origin, set `VITE_API_BASE` at build time and add that origin to `MERKLETRUST_CORS_ORIGINS`.

## Pages

| Route | Purpose |
|---|---|
| `/scan` | Drag-and-drop upload. The file type is sniffed from the file's magic bytes; analysis steps are shown live |
| `/results/:jobId` | Trust score gauge, verdict, file info; Merkle root and ECDSA seal with a "Verify now" check; findings filterable by severity |
| `/history` | Searchable list of all scans |
| `/chain` | Audit ledger timeline (previous hash → block hash) and "Verify Whole Chain" |
| `/baselines` | Trusted master copies of Android apps |

## How the numbers map to the backend

* **Trust score = 100 − risk score.** The backend reports a 0–100 *risk* score (heuristic,
  group-deduplicated points from `core/findings.py`).
* **Colour** is the worse of the score band (green ≥ 80, yellow 50–79, red < 50) and the
  verdict (HIGH_RISK / CHANGES_DETECTED / ANALYSIS_FAILED are red; REVIEW / NO_BASELINE
  are yellow), so a tampered or high-risk file is never shown in green.
* API used: `POST /auth/login`, `GET /health`, `POST /scans`, `GET /scans`,
  `GET /scans/{id}`, `GET /scans/{id}/report`, `POST /scans/{id}/verify`,
  `GET /audit/blocks`, `POST /audit/verify`, `GET /baselines` (all under `/api/v1`).
