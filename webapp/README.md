# MerkleTrust web app (React)

The main dashboard for the MerkleTrust API: scan any file, see what changed, explore the
Merkle tree and the blockchain, and manage trusted apps. Built for live demos, with
plain-language wording, interactive visualisations and a projector mode.

Stack: React 18, Vite, Tailwind CSS 4, lucide-react, react-router. No state library.

## Run it for a demo (one server)

```bash
cd webapp && npm install && npm run build && cd ..      # once, and after UI changes
python -m scripts.manage_users create admin --role admin
python -m uvicorn api.main:app --port 8000
# open http://127.0.0.1:8000/app
```

FastAPI serves the built bundle from `webapp/dist` under `/app`. The classic dashboard
stays at `/`.

## Develop

```bash
python -m uvicorn api.main:app --port 8000     # backend, from the repository root
cd webapp && npm run dev                       # http://localhost:5173
```

The dev server proxies `/api` to `http://localhost:8000`. Point it elsewhere with
`VITE_API_TARGET=http://host:8000 npm run dev`.

## Pages

| Route | Purpose |
|---|---|
| `/` | Home: live numbers, how it works in three steps, a tick-off **demo guide**, latest scans |
| `/scan` | Drag-and-drop upload; file type sniffed from magic bytes; live analysis steps |
| `/results/:id` | Trust score and verdict, with tabs: **Summary** (is it the original? is it safe? where the risk points come from) · **What changed** (modified/added/deleted files, each with a Merkle proof recomputed in the browser) · **Problems found** · **Proof & seal** (re-verify the signed report; download the verification bundle and in-toto attestation) |
| `/history` | Searchable list of all scans |
| `/merkle` | **Merkle Tree Lab**: edit or tamper with items and watch the change ripple to the root; click an item to see its inclusion proof. Drop a real file to rebuild its chunk tree in the browser. It matches the server's root exactly for a scanned file |
| `/chain` | **Blockchain**: visual chain where matching colours show matching hashes; animated "Verify the whole chain"; **Play the attacker** (admins, demo mode) tampers with a block, then restore |
| `/baselines` | **Trusted Apps**: admins upload the official APK and approve, reject or revoke it |

The screen icon in the top bar turns on **projector mode** (all text scaled up).

## Notes for reviewers

* `src/lib/merkle.js` is a browser port of `core/merkle.py` (RFC 6962: `0x00` leaf and
  `0x01` node prefixes, lone nodes promoted). It also builds the file leaves
  (`core/file_manifest.py`) and chunk leaves (`core/integrity.py`). It has been
  checked against the Python implementation and uses a pure-JS SHA-256 when WebCrypto
  is unavailable (plain-http LAN address).
* **Trust score = 100 − risk score.** The colour is the worse of the score band and the
  verdict, so a tampered file is never shown in green.
* The session token lives in `sessionStorage` and is sent only as a Bearer header.
