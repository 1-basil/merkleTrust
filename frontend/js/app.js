// app.js — router and application shell.
import { logout, session, setUnauthorizedHandler } from './api.js';
import { h, icon, mount } from './dom.js';
import { renderLogin } from './pages/login.js';
import { renderDashboard } from './pages/dashboard.js';
import { renderScan } from './pages/scan.js';
import { renderScans } from './pages/scans.js';
import { renderResult } from './pages/result.js';
import { renderBaselines } from './pages/baselines.js';
import { renderAudit } from './pages/audit.js';
import { renderChain } from './pages/chain.js';

const NAV = [
  { path: '/dashboard', label: 'Dashboard', icon: 'grid' },
  { path: '/scan', label: 'Scan an app', icon: 'upload' },
  { path: '/scans', label: 'Scan history', icon: 'list' },
  { path: '/baselines', label: 'Trusted versions', icon: 'shield' },
  { path: '/audit', label: 'Audit history', icon: 'clock' },
  { path: '/chain', label: 'Blockchain', icon: 'blocks' },
];

const ROUTES = [
  [/^\/dashboard$/, renderDashboard],
  [/^\/scan$/, renderScan],
  [/^\/scans$/, renderScans],
  [/^\/scans\/([0-9a-f-]{36})$/, renderResult],
  [/^\/baselines$/, renderBaselines],
  [/^\/audit$/, renderAudit],
  [/^\/chain$/, renderChain],
];

const root = document.getElementById('app');
let renderToken = 0;

export function navigate(path) {
  if (location.hash !== `#${path}`) location.hash = path;
  else route();
}

export function currentUser() {
  return session.get()?.user || null;
}

function shell(active) {
  const user = currentUser();
  const main = h('main', { id: 'main', class: 'container', tabindex: '-1' });
  const nav = h('nav', { class: 'nav', 'aria-label': 'Main' },
    NAV.map((item) => h('a', {
      href: `#${item.path}`,
      class: active.startsWith(item.path) && (item.path !== '/scan' || active === '/scan') ? 'active' : '',
      'aria-current': active === item.path ? 'page' : null,
    }, icon(item.icon, 'icon icon-sm'), item.label)));
  const header = h('header', { class: 'topbar' },
    h('div', { class: 'topbar-inner' },
      h('a', { class: 'brand', href: '#/dashboard' }, icon('shield', 'icon brand-icon'), h('span', {}, 'MerkleTrust')),
      h('button', { class: 'btn ghost nav-toggle', type: 'button', 'aria-label': 'Menu',
        onclick: () => nav.classList.toggle('open') }, icon('list')),
      nav,
      h('div', { class: 'user' },
        h('span', { class: 'user-name' }, user?.username || ''),
        h('span', { class: `role role-${user?.role}` }, user?.role === 'admin' ? 'Administrator' : 'Analyst'),
        h('button', { class: 'btn ghost', type: 'button', title: 'Sign out',
          onclick: async () => { await logout(); navigate('/login'); } }, icon('logout'), h('span', { class: 'sr-only' }, 'Sign out')))));
  mount(root, h('a', { class: 'skip', href: '#main' }, 'Skip to content'), header, main);
  return main;
}

async function route() {
  const token = ++renderToken;
  const path = (location.hash || '#/dashboard').slice(1);
  if (path === '/login' || !session.get()?.token) {
    mount(root, renderLogin(() => navigate('/dashboard')));
    if (path !== '/login') history.replaceState(null, '', '#/login');
    return;
  }
  const match = ROUTES.map(([re, fn]) => [path.match(re), fn]).find(([m]) => m);
  if (!match) return navigate('/dashboard');
  const [m, render] = match;
  const main = shell(path);
  document.title = `${NAV.find((n) => path.startsWith(n.path))?.label || 'Scan result'} · MerkleTrust`;
  try {
    await render(main, { params: m.slice(1), isCurrent: () => token === renderToken, user: currentUser() });
  } catch (err) {
    if (token === renderToken) mount(main, h('div', { class: 'alert tone-critical' }, icon('stop'), err.message));
  }
  if (token === renderToken) main.focus({ preventScroll: true });
}

setUnauthorizedHandler(() => { session.clear(); navigate('/login'); });
window.addEventListener('hashchange', route);
route();
