import { get } from '../api.js';
import { navigate } from '../app.js';
import { INTEGRITY, RISK, VERDICT, badge, empty, errorBox, h, icon, mount, spinner, table, timeEl } from '../dom.js';

const PAGE = 25;

export async function renderScans(main, { isCurrent }) {
  let offset = 0;
  const body = h('div', {});
  const load = async () => {
    mount(body, spinner());
    let data;
    try { data = await get('/scans', { limit: PAGE, offset }); } catch (err) { mount(body, errorBox(err)); return; }
    if (!isCurrent()) return;
    if (!data.items.length) { mount(body, empty('No scans yet. Upload an app to get started.')); return; }
    mount(body,
      table([
        { label: 'App', render: (s) => h('div', {}, h('div', { class: 'strong' }, s.package_name || s.filename || 'Unknown app'),
          h('div', { class: 'muted small' }, s.filename || '')) },
        { label: 'Result', render: (s) => s.result ? badge(VERDICT[s.result.verdict]) : badge(null, s.status === 'failed' ? 'Failed' : 'In progress') },
        { label: 'Same as trusted version?', class: 'hide-sm', render: (s) => s.result ? badge(INTEGRITY[s.result.integrity_status]) : '—' },
        { label: 'Risk', class: 'hide-sm', render: (s) => s.result ? h('span', {}, badge(RISK[s.result.risk_level]),
          s.result.risk_score !== null ? h('span', { class: 'muted small' }, ` ${s.result.risk_score}/100`) : null) : '—' },
        { label: 'By', class: 'hide-sm', render: (s) => s.submitted_by || '—' },
        { label: 'When', render: (s) => timeEl(s.created_at) },
      ], data.items, { onRowClick: (s) => navigate(`/scans/${s.id}`), caption: 'Scan history' }),
      h('div', { class: 'pager' },
        h('button', { class: 'btn ghost', disabled: offset === 0, onclick: () => { offset = Math.max(0, offset - PAGE); load(); } }, 'Previous'),
        h('span', { class: 'muted small' }, `${offset + 1}–${Math.min(offset + PAGE, data.total)} of ${data.total}`),
        h('button', { class: 'btn ghost', disabled: offset + PAGE >= data.total, onclick: () => { offset += PAGE; load(); } }, 'Next')));
  };
  mount(main, h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Scan history'),
    h('p', { class: 'muted' }, 'Every app that was uploaded for analysis.')),
  h('a', { class: 'btn primary', href: '#/scan' }, icon('upload'), 'Scan an app')), h('section', { class: 'card' }, body));
  await load();
}
