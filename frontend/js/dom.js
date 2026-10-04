// dom.js — safe DOM building, plain-language vocabulary, icons, formatting.
//
// SECURITY: every piece of data (APK names, paths, certificate subjects, audit
// payloads...) is attacker-influenced. It is only ever inserted with
// textContent / setAttribute via h(); innerHTML is never used with data.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key === 'text') el.textContent = value;
    else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2), value);
    else if (key === 'dataset') Object.assign(el.dataset, value);
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function mount(target, ...children) {
  target.replaceChildren();
  append(target, children);
}

// ------------------------------------------------------------- icons --
const ICONS = {
  check: 'M20 6 9 17l-5-5',
  alert: 'M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  stop: 'M7.9 2h8.2L22 7.9v8.2L16.1 22H7.9L2 16.1V7.9zM12 8v4m0 4h.01',
  help: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zm-2.1-13a2.5 2.5 0 0 1 4.6 1c0 1.7-2.5 2.5-2.5 2.5m0 4h.01',
  x: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zm3-13-6 6m0-6 6 6',
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  upload: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4m14-7-5-5-5 5m5-5v12',
  file: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zm0 0v6h6',
  link: 'M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7',
  key: 'M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4',
  blocks: 'M3 7h6v6H3zm12 0h6v6h-6zM9 10h6M6 13v4h12v-4',
  clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zm0-16v6l4 2',
  grid: 'M3 3h7v7H3zm11 0h7v7h-7zM3 14h7v7H3zm11 0h7v7h-7z',
  list: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4m7 14 5-5-5-5m5 5H9',
  download: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4m4-5 5 5 5-5m-5 5V3',
};

export function icon(name, cls = 'icon') {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', cls);
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(NS, 'path');
  path.setAttribute('d', ICONS[name] || ICONS.help);
  svg.append(path);
  return svg;
}

// ------------------------------------------------- plain vocabulary --
// tone -> one of the reserved status colours (good / warning / serious / critical / neutral).
export const VERDICT = {
  CLEAN: { label: 'Clean', tone: 'good', icon: 'check' },
  REVIEW: { label: 'Review recommended', tone: 'warning', icon: 'alert' },
  CHANGES_DETECTED: { label: 'Changes detected', tone: 'serious', icon: 'alert' },
  HIGH_RISK: { label: 'High risk', tone: 'critical', icon: 'stop' },
  NO_BASELINE: { label: 'Not verified', tone: 'neutral', icon: 'help' },
  ANALYSIS_FAILED: { label: 'Could not be analysed', tone: 'neutral', icon: 'x' },
};

export const INTEGRITY = {
  CLEAN: { label: 'Matches the trusted version', tone: 'good', icon: 'check' },
  MODIFIED: { label: 'Application files have changed', tone: 'serious', icon: 'alert' },
  CERTIFICATE_CHANGED: { label: 'Signed by a different developer key', tone: 'critical', icon: 'stop' },
  BASELINE_INVALID: { label: 'Integrity record has changed', tone: 'critical', icon: 'stop' },
  NO_BASELINE: { label: 'No trusted version to compare with', tone: 'neutral', icon: 'help' },
  UNKNOWN: { label: 'Could not be checked', tone: 'neutral', icon: 'help' },
};

export const RISK = {
  LOW: { label: 'Low risk', tone: 'good', icon: 'check' },
  MEDIUM: { label: 'Medium risk', tone: 'warning', icon: 'alert' },
  HIGH: { label: 'High risk', tone: 'serious', icon: 'alert' },
  CRITICAL: { label: 'Critical risk', tone: 'critical', icon: 'stop' },
  UNKNOWN: { label: 'Unknown', tone: 'neutral', icon: 'help' },
};

export const SEVERITY = {
  critical: { label: 'Critical', tone: 'critical', icon: 'stop' },
  high: { label: 'High', tone: 'serious', icon: 'alert' },
  medium: { label: 'Medium', tone: 'warning', icon: 'alert' },
  low: { label: 'Low', tone: 'info', icon: 'help' },
  info: { label: 'Info', tone: 'neutral', icon: 'help' },
};

export const SIGNATURE = {
  verified: { label: 'Developer signature is valid', tone: 'good', icon: 'check' },
  invalid: { label: 'Security proof could not be verified', tone: 'critical', icon: 'stop' },
  unsigned: { label: 'The app is not signed', tone: 'critical', icon: 'stop' },
  unverifiable: { label: 'Signature could not be checked by this tool', tone: 'neutral', icon: 'help' },
};

export const ENGINE_LABELS = {
  integrity: 'Fingerprinting every file',
  static: 'Reading the app and its signature',
  tamper: 'Comparing with the trusted version',
  dynamic: 'Running in an emulator (optional)',
  content: 'Checking the file structure',
  score: 'Assessing security risk',
  repository: 'Recording the result in the audit log',
};

export const CATEGORY_LABELS = {
  manifest: 'App configuration', code: 'Program code', native: 'Native library', resources: 'Resources',
  assets: 'Bundled asset', signature: 'Signature file', other: 'Other file',
};

export function badge(info, text) {
  const meta = info || { label: text || 'Unknown', tone: 'neutral', icon: 'help' };
  return h('span', { class: `badge tone-${meta.tone}` }, icon(meta.icon, 'icon icon-sm'), text || meta.label);
}

// --------------------------------------------------------- formatting --
export function shortHash(hex, n = 12) {
  if (!hex) return '—';
  return hex.length > n ? `${hex.slice(0, n)}…` : hex;
}

export function hashEl(hex, n = 16) {
  return h('code', { class: 'hash', title: hex || '' }, shortHash(hex, n));
}

export function bytes(n) {
  if (n === null || n === undefined) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function when(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function timeEl(iso) {
  return h('time', { datetime: iso || '', title: iso ? new Date(iso).toLocaleString() : '' }, when(iso));
}

export function card(title, ...children) {
  return h('section', { class: 'card' }, title ? h('h2', { class: 'card-title' }, title) : null, ...children);
}

export function empty(text) {
  return h('p', { class: 'empty' }, text);
}

export function technical(summary, ...children) {
  return h('details', { class: 'technical' }, h('summary', {}, summary || 'Technical details'), ...children);
}

export function kv(rows) {
  return h('dl', { class: 'kv' }, rows.filter(Boolean).map(([k, v]) => [h('dt', {}, k), h('dd', {}, v ?? '—')]));
}

export function spinner(text = 'Loading…') {
  return h('div', { class: 'loading', role: 'status' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), text);
}

export function errorBox(err) {
  return h('div', { class: 'alert tone-critical', role: 'alert' }, icon('stop'),
    h('div', {}, h('strong', {}, 'Something went wrong. '), err?.message || String(err),
      err?.requestId ? h('div', { class: 'muted small' }, `Reference: ${err.requestId}`) : null));
}

export function table(columns, rows, { onRowClick, caption } = {}) {
  return h('div', { class: 'table-wrap' },
    h('table', {},
      caption ? h('caption', { class: 'sr-only' }, caption) : null,
      h('thead', {}, h('tr', {}, columns.map((c) => h('th', { scope: 'col', class: c.class }, c.label)))),
      h('tbody', {}, rows.map((row) => {
        const tr = h('tr', onRowClick ? { class: 'clickable', tabindex: '0' } : {},
          columns.map((c) => h('td', { class: c.class }, c.render(row))));
        if (onRowClick) {
          tr.addEventListener('click', () => onRowClick(row));
          tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') onRowClick(row); });
        }
        return tr;
      }))));
}

export function toast(message, tone = 'neutral') {
  const region = document.getElementById('toasts');
  const el = h('div', { class: `toast tone-${tone}`, role: 'status' }, message);
  region.append(el);
  setTimeout(() => el.remove(), 4500);
}
