import { get } from '../api.js';
import { badge, empty, errorBox, h, icon, mount, spinner, table, technical, timeEl } from '../dom.js';

const EVENT_TYPES = ['', 'APK_UPLOADED', 'ANALYSIS_COMPLETED', 'INTEGRITY_ALERT', 'BASELINE_ENROLLED', 'BASELINE_APPROVED',
  'BASELINE_REJECTED', 'BASELINE_REVOKED', 'REPORT_VERIFIED', 'CHAIN_VERIFIED', 'USER_LOGIN', 'LOGIN_FAILED',
  'AUDIT_TAMPER_DEMO', 'AUDIT_RESTORED'];
const ALERTS = new Set(['INTEGRITY_ALERT', 'LOGIN_FAILED', 'BASELINE_REVOKED', 'AUDIT_TAMPER_DEMO']);

function describe(e) {
  const p = e.payload || {};
  switch (e.event_type) {
    case 'ANALYSIS_COMPLETED': return `${p.package_name || 'App'} analysed: ${p.verdict || '—'} (integrity ${p.integrity_status}, risk ${p.risk_level})`;
    case 'INTEGRITY_ALERT': return `${p.package_name || 'App'}: ${p.integrity_status}`;
    case 'APK_UPLOADED': return `${p.filename || 'APK'} uploaded`;
    case 'BASELINE_ENROLLED': case 'BASELINE_APPROVED': case 'BASELINE_REJECTED': case 'BASELINE_REVOKED':
      return `${p.package_name || ''} trusted version #${p.baseline_version ?? p.baseline_id}${p.reason ? ` — ${p.reason}` : ''}`;
    case 'LOGIN_FAILED': return `Failed sign-in for "${p.username}"`;
    case 'REPORT_VERIFIED': return `Report verification: ${p.valid ? 'valid' : 'FAILED'}`;
    case 'CHAIN_VERIFIED': return `Audit chain verified (${p.length} blocks)`;
    case 'AUDIT_TAMPER_DEMO': return `Demonstration: block #${p.block_index} altered (${p.mode})`;
    case 'AUDIT_RESTORED': return `Demonstration reverted (blocks ${(p.restored_blocks || []).join(', ')})`;
    default: return '';
  }
}

export async function renderAudit(main, { isCurrent }) {
  const filter = h('select', { id: 'event-filter' }, EVENT_TYPES.map((t) => h('option', { value: t }, t ? t.replaceAll('_', ' ').toLowerCase() : 'All events')));
  const body = h('div', {});
  const load = async () => {
    mount(body, spinner());
    let data;
    try { data = await get('/audit/blocks', { limit: 200, event_type: filter.value || undefined }); } catch (err) { mount(body, errorBox(err)); return; }
    if (!isCurrent()) return;
    mount(body,
      h('div', { class: `alert tone-${data.chain.valid ? 'good' : 'critical'}` }, icon(data.chain.valid ? 'check' : 'stop'),
        h('div', {}, h('strong', {}, data.chain.valid ? 'This history is intact. ' : 'This history has been tampered with. '), data.chain.summary)),
      data.items.length ? table([
        { label: 'When', render: (e) => timeEl(e.timestamp) },
        { label: 'Event', render: (e) => h('div', {}, ALERTS.has(e.event_type) ? badge({ label: e.event_label, tone: 'serious', icon: 'alert' }) : h('span', { class: 'strong' }, e.event_label),
          h('div', { class: 'small' }, describe(e))) },
        { label: 'By', render: (e) => e.actor },
        { label: 'Record', class: 'hide-sm', render: (e) => h('a', { href: '#/chain', title: 'Open in the Blockchain Simulation' }, `Block #${e.index}`) },
        { label: 'Verified', render: (e) => (e.verification.valid ? badge({ label: 'Valid', tone: 'good', icon: 'check' }) : badge({ label: 'Invalid', tone: 'critical', icon: 'stop' })) },
      ], data.items, { caption: 'Audit history' }) : empty('No events.'),
      technical('How this history is protected', h('p', { class: 'small' },
        'Each event is stored as a block whose fingerprint includes the previous block’s fingerprint, and every block is digitally ' +
        'signed (ECDSA P-256). Changing or deleting an earlier event breaks the chain from that point, which verification reports.')));
  };
  filter.addEventListener('change', load);
  mount(main,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Audit history'),
      h('p', { class: 'muted' }, 'Every security-relevant action, in order, newest first.')),
    h('label', { class: 'inline-field' }, 'Show ', filter)),
    h('section', { class: 'card' }, body));
  await load();
}
