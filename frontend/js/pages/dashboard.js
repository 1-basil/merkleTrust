import { get } from '../api.js';
import { navigate } from '../app.js';
import { INTEGRITY, VERDICT, badge, card, empty, errorBox, h, icon, mount, spinner, table, timeEl } from '../dom.js';

const TILES = [
  { key: 'analyzed', label: 'Apps analysed', tone: 'neutral', icon: 'grid', hint: 'Distinct apps with a finished scan' },
  { key: 'clean', label: 'Clean', tone: 'good', icon: 'check', hint: 'Match their trusted version, no significant concerns' },
  { key: 'modified', label: 'Changes detected', tone: 'serious', icon: 'alert', hint: 'Differ from their trusted version' },
  { key: 'high_risk', label: 'High risk', tone: 'critical', icon: 'stop', hint: 'High or critical security risk' },
  { key: 'not_verified', label: 'Not verified', tone: 'neutral', icon: 'help', hint: 'No trusted version to compare with' },
];

function tile(t, value) {
  return h('div', { class: `stat tone-${t.tone}`, title: t.hint },
    h('div', { class: 'stat-label' }, icon(t.icon, 'icon icon-sm'), t.label),
    h('div', { class: 'stat-value' }, String(value ?? 0)));
}

// Share of apps by their latest verdict: one thin stacked bar, status colours with
// icon + label in the legend, values on hover. The tiles above are its table view.
function verdictShare(scans) {
  const latest = new Map();
  for (const s of scans) if (s.status === 'done' && s.package_name && !latest.has(s.package_name)) latest.set(s.package_name, s);
  const counts = {};
  for (const s of latest.values()) counts[s.result?.verdict || 'ANALYSIS_FAILED'] = (counts[s.result?.verdict || 'ANALYSIS_FAILED'] || 0) + 1;
  const total = latest.size;
  if (!total) return null;
  const order = ['CLEAN', 'REVIEW', 'NO_BASELINE', 'CHANGES_DETECTED', 'HIGH_RISK', 'ANALYSIS_FAILED'].filter((k) => counts[k]);
  return h('div', { class: 'share' },
    h('p', { class: 'share-caption' }, `Latest result of each app (${total})`),
    h('div', { class: 'share-bar', role: 'img', 'aria-label': order.map((k) => `${VERDICT[k].label}: ${counts[k]}`).join(', ') },
      order.map((k) => h('span', { class: `share-seg tone-${VERDICT[k].tone}`, style: `flex-grow:${counts[k]}`,
        title: `${VERDICT[k].label}: ${counts[k]} of ${total} recent apps` }))),
    h('ul', { class: 'legend' }, order.map((k) => h('li', {}, badge(VERDICT[k]), h('span', { class: 'legend-value' }, String(counts[k]))))));
}

export async function renderDashboard(main, { isCurrent }) {
  mount(main, h('h1', {}, 'Dashboard'), spinner());
  let data;
  let recent;
  try {
    [data, recent] = await Promise.all([get('/dashboard/summary'), get('/scans', { limit: 100 })]);
  } catch (err) {
    if (isCurrent()) mount(main, h('h1', {}, 'Dashboard'), errorBox(err));
    return;
  }
  if (!isCurrent()) return;

  const chain = data.audit_chain;
  const scanTable = data.recent_scans.length ? table([
    { label: 'App', render: (s) => h('div', {}, h('div', { class: 'strong' }, s.package_name || s.filename || 'Unknown app'),
      h('div', { class: 'muted small' }, s.filename || '')) },
    { label: 'Result', render: (s) => s.result ? badge(VERDICT[s.result.verdict]) : badge(null, s.status === 'failed' ? 'Failed' : 'In progress') },
    { label: 'Same as trusted version?', class: 'hide-sm', render: (s) => s.result ? badge(INTEGRITY[s.result.integrity_status]) : '—' },
    { label: 'When', render: (s) => timeEl(s.created_at) },
  ], data.recent_scans, { onRowClick: (s) => navigate(`/scans/${s.id}`), caption: 'Recent scans' })
    : empty('No apps scanned yet.');

  mount(main,
    h('div', { class: 'page-head' },
      h('div', {}, h('h1', {}, 'Dashboard'), h('p', { class: 'muted' }, 'Overview of analysed apps, trusted versions and the audit log.')),
      h('a', { class: 'btn primary', href: '#/scan' }, icon('upload'), 'Scan an app')),
    h('div', { class: 'stats' }, TILES.map((t) => tile(t, data.applications[t.key]))),
    verdictShare(recent.items),
    h('div', { class: 'grid-2' },
      card('Recent scans', scanTable),
      h('div', { class: 'stack' },
        card('Audit log',
          h('div', { class: `alert tone-${chain.valid ? 'good' : 'critical'}` }, icon(chain.valid ? 'check' : 'stop'),
            h('div', {}, h('strong', {}, chain.valid ? 'Audit history is intact' : 'Audit history has been tampered with'),
              h('div', { class: 'small' }, `${chain.length} linked, signed records`))),
          h('a', { class: 'btn ghost', href: '#/chain' }, icon('blocks'), 'Open the Blockchain Simulation')),
        card('Trusted versions',
          h('p', {}, h('strong', {}, String(data.baselines.approved)), ' approved · ',
            h('strong', {}, String(data.baselines.pending)), ' awaiting approval'),
          h('a', { class: 'btn ghost', href: '#/baselines' }, icon('shield'), 'Manage trusted versions')),
        card('Recent security events',
          data.recent_events.length ? h('ul', { class: 'events' }, data.recent_events.map((e) =>
            h('li', {}, h('span', { class: 'event-label' }, e.event_label), h('span', { class: 'muted small' }, ` by ${e.actor} · `),
              timeEl(e.timestamp)))) : empty('No events yet.'),
          h('a', { class: 'btn ghost', href: '#/audit' }, icon('clock'), 'Full audit history')))));
}
