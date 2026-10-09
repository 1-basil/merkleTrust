# MerkleTrust — Live Demonstration Script (≈ 12 minutes)

Everything used here is in the repository (`evaluation/dataset/`, `samples/`), so the demo
needs no Android SDK. Internet is only needed to download the threat feed beforehand.
The web app also has this script built in: **Home → Demo guide**.

| File | Role in the story |
|---|---|
| `evaluation/dataset/baseline_demo.apk` | The developer's official build 1.2.0 |
| `evaluation/dataset/demo_official_copy.apk` | A byte-identical copy that a user downloaded |
| `evaluation/dataset/demo_repackaged.apk` | The same app repackaged by an attacker: injected code-loading and SMS code, an extra permission, an extra native library, re-signed with the attacker's key |
| `samples/tampered_photo.jpg` / `samples/clean_photo.jpg` | A photo with data hidden after the end of the image, and the original |

## 0. Before the presentation

```powershell
python -m pytest -q                                              # expect: all passed
powershell -ExecutionPolicy Bypass -File scripts\start_demo.ps1 -Fresh
```

`start_demo.ps1` builds the web app (first run), downloads today's abuse.ch ThreatFox feed,
creates the `admin` account (you choose the password) and starts the server. Open
**http://127.0.0.1:8000/app** and sign in as **admin**. Turn on **projector mode** (screen
icon, top right) for a large room. Keep the two folders above open in a file browser.
Rehearse once; `-Fresh` resets everything.

Manual alternative: `cd webapp; npm install; npm run build; cd ..`, then
`python -m scripts.update_threat_feed`, `python -m scripts.manage_users create admin --role admin`
and `python -m uvicorn api.main:app --port 8000`.

## 1. Home — the idea in one sentence

Show the hero and the live numbers. Point at the line under the numbers: *"Threat
intelligence: abuse.ch ThreatFox, N known malicious servers and files, updated …"*.
*Say:* "MerkleTrust answers three questions about any file: is it the original, is it
safe, and can we prove both later?"

## 2. Scan an app with nothing to compare it to

**Scan** → drop `demo_official_copy.apk`. Watch the four steps (fingerprint, look inside,
score, seal). Result: **Not Verified**.
*Say:* "The app is validly signed — but by whom? Android only checks that *someone*
signed it. We never trust a file just because it looks fine, and we never trust the first
upload: an attacker who uploads first would otherwise become the 'original'."

## 3. Add the official app as trusted

**Trusted Apps** → drop `baseline_demo.apk` → **Approve & sign** → **Check this record**
(all five checks green).
*Say:* "Approval digitally signs a record of the app: name, version, developer key, the
Merkle root over every file and the fuzzy fingerprint of its code. That record is
re-checked before every use, so editing it in the database is detected."
Scan `demo_official_copy.apk` again → **Verified Original**.

## 4. Scan the hacked copy

**Scan** → `demo_repackaged.apk` → **Security Risks Found**, trust score 0.

* **Summary** — "Is it the original? No, signed by someone else." Risk points, each with a reason.
* **What changed** — 2 modified, 1 added. Press **Prove it** on `classes.dex`:
  *"Not genuine: its fingerprint does not lead to the trusted root."*
  *Say:* "This Merkle proof is recomputed in this browser, not on our server: you don't
  have to trust us." The code-similarity bar (ssdeep fuzzy hash) shows a low score here:
  the demo app's code is only about 3 KB, and fuzzy hashing needs larger files to be
  meaningful. Say so if asked — it is stated on the page too.
* **Certificate** — trusted key vs this upload, side by side.
  *Say:* "We compare key fingerprints, never names. Our dataset includes an attacker
  certificate that copies the developer's name; it is still caught."
* **Problems found** — the line on top shows which threat feed (and which version) the app
  was checked against. Each finding has an explanation, evidence and what to do.
* **Proof & seal** → **Check it again now** → *Verified*. Download the verification bundle:
  "anyone can check this offline with `python -m scripts.verify_offline --bundle bundle.json`."

## 5. Not just apps: a photo with hidden data

Scan `samples/tampered_photo.jpg` → **Problems found**: data hidden after the end of the
image. Scan `samples/clean_photo.jpg` → no problems.

## 6. How the fingerprint works — Merkle Tree Lab

**Merkle Tree** → **Tamper with an item**: the changed path turns red up to the root, the
proof panel shows the item no longer reaches the trusted root.
*Say:* "Only 3 hashes are needed to check one item out of 8; about 10 for 1,000 files."
Optional: drop `samples/clean_photo.jpg` into *Fingerprint a real file* — once it has been
scanned, the browser shows **Matches the server, computed independently**.

## 7. Try to rewrite history — Blockchain

1. **Save checkpoint** (a signed statement of the newest block, kept in this browser).
2. Click a block in the middle of the chain → **Play the attacker** → *Change it and cover
   the tracks* → **Tamper with block #N**. The block turns red and its link to the next
   block breaks.
3. **Verify the whole chain** → the check walks the chain and stops at the broken block.
   *Say:* "They recomputed the hash, but they cannot forge the signature without our private
   key, and the next block still points to the old fingerprint."
4. **Restore the chain** → **Verify the whole chain** → *Verified: all N blocks*.

*Say:* "This is a single-server, signed hash chain — tamper-evident, not a distributed
blockchain. The checkpoint also catches deleted blocks, not only edited ones."

## Fallbacks

* Browser problem: every step has an API equivalent at http://127.0.0.1:8000/api/docs.
* Offline on the day: the last downloaded threat feed is used; if there is none, the
  report says so instead of claiming a check that did not run.
* If the server will not start because of an old database: run `start_demo.ps1 -Fresh`.
* If time is short: steps 3, 4 and 7 carry the story.
* The classic dashboard (http://127.0.0.1:8000/) still offers every function.

## Questions to expect

See [VIVA_QUESTION_BANK.md](VIVA_QUESTION_BANK.md).
