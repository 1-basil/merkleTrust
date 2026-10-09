// tests/e2e/webapp_smoke.mjs — End-to-end check of the React web app (webapp/) in headless Chrome.
//
//   node tests/e2e/webapp_smoke.mjs <base-url> [screenshot-dir]
//
// Needs: a running server with the built app (cd webapp && npm run build), a FRESH data folder,
// and an admin account whose password is in MERKLETRUST_E2E_PASSWORD:
//   MERKLETRUST_DATA_DIR=e2e-data MERKLETRUST_NEW_USER_PASSWORD=... python -m scripts.manage_users create admin --role admin
//   MERKLETRUST_DATA_DIR=e2e-data python -m uvicorn api.main:app --port 8765
//   MERKLETRUST_E2E_PASSWORD=... node tests/e2e/webapp_smoke.mjs http://127.0.0.1:8765 shots
//
// It seeds data through the API (trusted app, approval, four scans), then visits every page at
// desktop and phone width, opens every report tab, proves a file, re-verifies a report, runs the
// Merkle Tree Lab tamper, saves a chain checkpoint, tampers with a block, verifies, restores, and
// checks a trusted-app record. It fails on any console error, uncaught exception or horizontal
// overflow. Uses the Chrome DevTools Protocol directly (Node 22+, no npm packages).
// Set CHROME to the browser path if it is not in the default Windows location.

import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const [BASE, OUT] = process.argv.slice(2);
const PASSWORD = process.env.MERKLETRUST_E2E_PASSWORD;
if (!BASE || !PASSWORD) {
  console.error('usage: MERKLETRUST_E2E_PASSWORD=... node tests/e2e/webapp_smoke.mjs <base-url> [screenshot-dir]');
  process.exit(2);
}
if (OUT) mkdirSync(OUT, { recursive: true });
const ROOT = resolve(new URL('.', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'), '..', '..');
const API = `${BASE}/api/v1`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const problems = [];

// ------------------------------------------------------------------ seed data --
const token = (await (await fetch(`${API}/auth/login`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: PASSWORD }),
})).json()).access_token;
if (!token) throw new Error('login failed');
const auth = { Authorization: `Bearer ${token}` };
const upload = async (path, rel) => {
  const form = new FormData();
  form.append('file', new Blob([readFileSync(join(ROOT, rel))]), rel.split('/').pop());
  const res = await fetch(`${API}${path}`, { method: 'POST', headers: auth, body: form });
  if (!res.ok) throw new Error(`upload ${rel}: ${res.status} ${await res.text()}`);
  return res.json();
};
const scan = async (rel) => {
  const job = await upload('/scans', rel);
  for (let i = 0; i < 120; i++) {
    const s = await (await fetch(`${API}/scans/${job.id}`, { headers: auth })).json();
    if (s.status === 'done' || s.status === 'failed') return s;
    await sleep(500);
  }
  throw new Error(`scan of ${rel} did not finish`);
};
// Reuse the trusted app if an earlier run already enrolled it.
const existing = (await (await fetch(`${API}/baselines`, { headers: auth })).json()).items
  .find((b) => b.package_name === 'com.merkletrust.demo' && b.status === 'approved');
if (!existing) {
  const { baseline } = await upload('/baselines', 'evaluation/dataset/baseline_demo.apk');
  await fetch(`${API}/baselines/${baseline.id}/approve`, { method: 'POST', headers: { ...auth, 'Content-Type': 'application/json' }, body: '{}' });
}
const repack = await scan('evaluation/dataset/demo_repackaged.apk');
await scan('evaluation/dataset/demo_official_copy.apk');
const photo = await scan('samples/tampered_photo.jpg');
await scan('samples/clean_page.html');
if (repack.result?.verdict !== 'HIGH_RISK') problems.push(`seed: repackaged app verdict ${repack.result?.verdict}`);

// ---------------------------------------------------------------- browser --
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PORT = 9335;
const chrome = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${PORT}`, '--no-first-run', '--disable-gpu',
  `--user-data-dir=${mkdtempSync(join(tmpdir(), 'mtchrome-'))}`, 'about:blank'], { stdio: 'ignore' });
let targets;
for (let i = 0; i < 50; i++) {
  try { targets = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json(); if (targets.length) break; } catch { /* starting */ }
  await sleep(200);
}
const ws = new WebSocket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let id = 0;
const pending = new Map();
let label = 'setup';
ws.addEventListener('message', (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); return; }
  if (msg.method === 'Runtime.consoleAPICalled' && ['error', 'warning'].includes(msg.params.type)) {
    problems.push(`${label} console: ${msg.params.args.map((a) => a.value ?? a.description).join(' ')}`);
  }
  if (msg.method === 'Runtime.exceptionThrown') problems.push(`${label} exception: ${msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text}`);
  if (msg.method === 'Log.entryAdded' && ['error', 'warning'].includes(msg.params.entry.level)) problems.push(`${label} log: ${msg.params.entry.text}`);
});
const send = (method, params = {}) => new Promise((ok, fail) => {
  const mid = ++id;
  pending.set(mid, (m) => (m.error ? fail(new Error(`${method}: ${m.error.message}`)) : ok(m.result)));
  ws.send(JSON.stringify({ id: mid, method, params }));
});
const evaluate = async (expr) => {
  const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(`${label}: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
  return r.result.value;
};
const has = (t) => `!!document.body && document.body.textContent.includes(${JSON.stringify(t)})`;
const waitFor = async (expr, ms = 15000) => {
  for (const end = Date.now() + ms; Date.now() < end;) { if (await evaluate(expr)) return; await sleep(150); }
  throw new Error(`${label}: timed out waiting for ${expr}`);
};
const click = (sel, text) => evaluate(`(() => { const el = [...document.querySelectorAll(${JSON.stringify(sel)})]
  .find((e) => e.textContent.includes(${JSON.stringify(text)}) && !e.disabled); if (!el) throw new Error('no ' + ${JSON.stringify(text)}); el.click(); return true; })()`);
const shot = async (name) => {
  await sleep(400);
  if (await evaluate('document.documentElement.scrollWidth > window.innerWidth + 1')) problems.push(`${name}: horizontal overflow`);
  if (!OUT) return;
  const { data } = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
  writeFileSync(join(OUT, `${name}.png`), Buffer.from(data, 'base64'));
};
const go = async (name, path, ready) => { label = name; await send('Page.navigate', { url: `${BASE}${path}` }); await waitFor(ready); };

await send('Runtime.enable'); await send('Log.enable'); await send('Page.enable');

for (const [vp, metrics] of [['desktop', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false }],
  ['phone', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true }]]) {
  await send('Emulation.setDeviceMetricsOverride', metrics);
  await evaluate("(() => { try { sessionStorage.clear(); } catch { /* about:blank */ } return true; })()");
  await go(`${vp}-login`, '/app/login', has('Sign in'));
  await shot(`${vp}-login`);
  await evaluate(`sessionStorage.setItem('merkletrust.session', JSON.stringify({ token: ${JSON.stringify(token)}, user: { username: 'admin', role: 'admin' } })), true`);

  await go(`${vp}-home`, '/app/', has('Demo guide'));
  await shot(`${vp}-home`);
  await go(`${vp}-scan`, '/app/scan', has('Drag & drop'));
  await shot(`${vp}-scan`);
  await go(`${vp}-history`, '/app/history', has('demo_repackaged'));
  await shot(`${vp}-history`);

  await go(`${vp}-report`, `/app/results/${repack.id}`, has('Is it the original?'));
  await shot(`${vp}-report-summary`);
  await click('[role=tab]', 'What changed');
  await waitFor(has('Changed files'));
  await click('button', 'Prove it');
  await waitFor(`${has('Not genuine')} || ${has('Proven')}`);
  await shot(`${vp}-report-changes`);
  await click('[role=tab]', 'Problems found');
  await shot(`${vp}-report-findings`);
  await click('[role=tab]', 'Certificate');
  await waitFor(has('Signed with a different key'));
  await shot(`${vp}-report-certificate`);
  await click('[role=tab]', 'Runtime');
  await waitFor(has('emulator'));
  await click('[role=tab]', 'Proof & seal');
  await click('button', 'Check it again now');
  await waitFor(has('Verified: the stored report'));
  await shot(`${vp}-report-proof`);

  await go(`${vp}-photo`, `/app/results/${photo.id}`, has('Is it the original?'));
  await click('[role=tab]', 'Problems found');
  await shot(`${vp}-photo-findings`);

  await go(`${vp}-merkle`, '/app/merkle', 'document.querySelectorAll("svg[role=img] g").length > 5');
  await click('button', 'Tamper with an item');
  await waitFor(has('Tampering detected'));
  await shot(`${vp}-merkle`);

  await go(`${vp}-baselines`, '/app/baselines', has('Check this record'));
  await click('button', 'Check this record');
  await waitFor(has('Approval signature is valid'));
  await shot(`${vp}-baselines`);

  await go(`${vp}-chain`, '/app/chain', has('Chain intact'));
  await click('button', 'checkpoint');
  await waitFor(has('Checkpoint saved at block'));
  if (vp === 'desktop') {
    // Pick a block in the middle of the visible chain (the first block can't be tampered with in the demo).
    const target = await evaluate(`(() => { const tiles = [...document.querySelectorAll('[data-index]')];
      const t = tiles[Math.floor(tiles.length / 2)]; t.click(); return t.dataset.index; })()`);
    await click('button', `Tamper with block #${target}`);
    await waitFor(has('Chain broken at block'));
    await click('button', 'Verify the whole chain');
    await sleep(2500);
    await shot(`${vp}-chain-broken`);
    await click('button', 'Restore the chain');
    await waitFor(has('Chain intact'));
    await click('button', 'Verify the whole chain');
    await waitFor(has('Verified: all'));
  }
  await shot(`${vp}-chain`);
}

chrome.kill();
if (problems.length) {
  console.error(`FAILED (${problems.length}):\n${problems.join('\n')}`);
  process.exit(1);
}
console.log('web app smoke test passed');
process.exit(0);
