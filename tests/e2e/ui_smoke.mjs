// tests/e2e/ui_smoke.mjs — End-to-end check of the web dashboard in headless Chrome.
//
//   node tests/e2e/ui_smoke.mjs <base-url> <screenshot-dir> "<name>=<scan-id> ..."
//
// Uses the Chrome DevTools Protocol directly (Node 22+ built-in WebSocket; no npm
// packages). Signs in as admin/admin-password-123 (create it with scripts/manage_users),
// visits every page at desktop and phone width, exercises the Merkle proof check,
// report verification and the tamper -> verify -> restore demo, and fails on any
// console error, uncaught exception, CSP violation or horizontal overflow.
// Scan ids come from: python -m scripts.seed_demo <base-url>
// Set CHROME to the browser path if it is not in the default Windows location.
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [BASE, OUT, IDS_RAW] = process.argv.slice(2);
const IDS = Object.fromEntries(IDS_RAW.split(' ').map((x) => x.split('=')));
mkdirSync(OUT, { recursive: true });
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PORT = 9333;
const problems = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
    problems.push(`${label} console ${msg.params.type}: ${msg.params.args.map((a) => a.value ?? a.description).join(' ')}`);
  }
  if (msg.method === 'Runtime.exceptionThrown') problems.push(`${label} exception: ${msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text}`);
  if (msg.method === 'Log.entryAdded' && ['error', 'warning'].includes(msg.params.entry.level)) {
    const t = msg.params.entry.text;
    if (!/favicon/.test(t) && !/401 \(Unauthorized\)/.test(t)) problems.push(`${label} log ${msg.params.entry.level}: ${t}`);
  }
});
const send = (method, params = {}) => new Promise((resolve, reject) => {
  const mid = ++id;
  pending.set(mid, (m) => (m.error ? reject(new Error(`${method}: ${m.error.message}`)) : resolve(m.result)));
  ws.send(JSON.stringify({ id: mid, method, params }));
});
const evaluate = async (expr) => {
  const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(`eval failed: ${expr.slice(0, 80)} -> ${r.exceptionDetails.text}`);
  return r.result.value;
};
const waitFor = async (selectorOrExpr, ms = 15000, isExpr = false) => {
  const expr = isExpr ? selectorOrExpr : `!!document.querySelector(${JSON.stringify(selectorOrExpr)})`;
  for (const end = Date.now() + ms; Date.now() < end;) { if (await evaluate(expr)) return; await sleep(150); }
  throw new Error(`${label}: timed out waiting for ${selectorOrExpr}`);
};
const clickText = (sel, text) => evaluate(`(() => { const el = [...document.querySelectorAll(${JSON.stringify(sel)})]
  .find(e => e.textContent.includes(${JSON.stringify(text)})); if (!el) throw new Error('no element'); el.click(); return true; })()`);
const setValue = (sel, value) => evaluate(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); el.value = ${JSON.stringify(value)};
  el.dispatchEvent(new Event('input', {bubbles:true})); el.dispatchEvent(new Event('change', {bubbles:true})); return true; })()`);
const shot = async (name) => {
  await sleep(350);
  const { data } = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
  writeFileSync(join(OUT, `${name}.png`), Buffer.from(data, 'base64'));
  if (await evaluate('document.documentElement.scrollWidth > window.innerWidth + 1')) problems.push(`${name}: horizontal page overflow`);
};
const go = async (name, hash, waitSel, action) => {
  label = name;
  await send('Page.navigate', { url: `${BASE}/${hash}` });
  await waitFor(waitSel);
  if (action) await action();
  await shot(name);
};

await send('Runtime.enable'); await send('Log.enable'); await send('Page.enable');

for (const [vp, metrics] of [['desktop', { width: 1366, height: 900, deviceScaleFactor: 1, mobile: false }],
  ['phone', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true }]]) {
  await send('Emulation.setDeviceMetricsOverride', metrics);
  label = `${vp}-login`;
  await send('Page.navigate', { url: `${BASE}/#/login` });
  await evaluate('sessionStorage.clear()');
  await send('Page.reload');
  await waitFor('#username');
  await shot(`${vp}-login`);
  await setValue('#username', 'admin'); await setValue('#password', 'wrong-password');
  await clickText('button', 'Sign in');
  await waitFor("document.querySelector('.form-error')?.textContent.length > 0", 8000, true);
  await setValue('#password', 'admin-password-123');
  await clickText('button', 'Sign in');
  await waitFor('.stats');

  await go(`${vp}-dashboard`, '#/dashboard', '.stats');
  await go(`${vp}-scans`, '#/scans', 'table');
  await go(`${vp}-scan`, '#/scan', '.dropzone');
  for (const key of ['clean', 'resigned', 'patched', 'suspicious', 'update']) await go(`${vp}-result-${key}`, `#/scans/${IDS[key]}`, '.hero');
  if (vp === 'desktop') {
    const tabs = ['File changes', 'Security findings', 'Certificate', 'Verification', 'Technical details'];
    for (const [i, tab] of tabs.entries()) {
      await go(`desktop-patched-tab${i + 1}`, `#/scans/${IDS.patched}`, '.hero', async () => {
        await clickText('button.tab', tab);
        if (tab === 'File changes') { await clickText('button', 'Check proof'); await waitFor('.proof-result .alert'); }
        if (tab === 'Verification') { await clickText('button', 'Verify this report now'); await waitFor("[...document.querySelectorAll('.alert')].some(a => a.textContent.includes('Verified'))", 8000, true); }
      });
    }
    await go('desktop-resigned-cert', `#/scans/${IDS.resigned}`, '.hero', () => clickText('button.tab', 'Certificate'));
  }
  await go(`${vp}-baselines`, '#/baselines', 'table');
  await go(`${vp}-audit`, '#/audit', 'table');
  await go(`${vp}-chain`, '#/chain', '.block');
  if (vp === 'desktop') {
    await go('desktop-chain-tampered', '#/chain', '.block', async () => {
      await setValue('input.narrow', '3');
      await setValue("select[aria-label='Tamper mode']", 'rewrite_block');
      await clickText('button', 'Tamper with block');
      await waitFor("document.querySelector('.alert.big')?.textContent.includes('INTEGRITY FAILURE')", 8000, true);
    });
    await go('desktop-chain-restored', '#/chain', '.block', async () => {
      await clickText('button', 'Restore valid chain');
      await waitFor("document.querySelector('.alert.big')?.textContent.includes('Chain intact')", 8000, true);
      await clickText('button', 'Verify chain');
      await waitFor("[...document.querySelectorAll('.toast')].some(t => t.textContent.includes('chain intact'))", 8000, true);
    });
  }
  await evaluate('sessionStorage.clear()');
}

ws.close();
chrome.kill();
console.log(problems.length ? problems.join('\n') : 'NO PROBLEMS');
process.exit(problems.length ? 1 : 0);
