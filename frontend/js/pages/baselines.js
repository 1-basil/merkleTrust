import { get, post, upload } from '../api.js';
import { INTEGRITY, badge, card, empty, errorBox, h, hashEl, icon, kv, mount, spinner, table, technical, timeEl, toast } from '../dom.js';

const STATUS = {
  approved: { label: 'Approved', tone: 'good', icon: 'check' },
  pending: { label: 'Awaiting approval', tone: 'warning', icon: 'clock' },
  rejected: { label: 'Rejected', tone: 'neutral', icon: 'x' },
  revoked: { label: 'Revoked', tone: 'critical', icon: 'stop' },
};

// Small modal asking for a reason / note. Resolves to the text or null.
function ask(title, label, { required = true, confirm = 'Confirm' } = {}) {
  return new Promise((resolve) => {
    const input = h('textarea', { rows: 3, maxlength: 500, required });
    const error = h('p', { class: 'form-error' });
    const dialog = h('dialog', { class: 'modal' },
      h('form', { method: 'dialog' },
        h('h2', {}, title), h('label', {}, label, input), error,
        h('div', { class: 'actions' },
          h('button', { class: 'btn ghost', value: 'cancel', type: 'submit' }, 'Cancel'),
          h('button', { class: 'btn primary', value: 'ok', type: 'submit' }, confirm))));
    dialog.addEventListener('close', () => {
      const ok = dialog.returnValue === 'ok';
      dialog.remove();
      resolve(ok ? input.value.trim() : null);
    });
    dialog.querySelector('form').addEventListener('submit', (e) => {
      if (e.submitter?.value === 'ok' && required && input.value.trim().length < 3) {
        e.preventDefault();
        error.textContent = 'Please give a short reason (at least 3 characters).';
      }
    });
    document.body.append(dialog);
    dialog.showModal();
  });
}

function review(result) {
  if (!result.review_against_active) {
    return h('div', { class: 'alert tone-neutral' }, icon('help'), 'This is the first trusted version of this app.');
  }
  const rv = result.review_against_active;
  return h('div', {},
    h('div', { class: `alert tone-${rv.status === 'CERTIFICATE_CHANGED' ? 'critical' : rv.status === 'CLEAN' ? 'good' : 'warning'}` },
      icon(rv.status === 'CERTIFICATE_CHANGED' ? 'stop' : 'alert'),
      h('div', {}, h('strong', {}, `Compared with the current trusted version: ${INTEGRITY[rv.status]?.label || rv.status}. `),
        rv.status === 'CERTIFICATE_CHANGED' ? 'Approve only if the developer has confirmed a signing-key change — otherwise this could be a poisoned baseline.' : '')),
    h('ul', { class: 'reasons' }, rv.reasons.map((x) => h('li', {}, x))),
    technical('Differences', kv([
      ['Files modified / added / deleted', `${rv.counts.modified} / ${rv.counts.added} / ${rv.counts.deleted}`],
      ['Permissions added', rv.manifest_diff.permissions_added.join(', ') || 'none'],
      ['Components added', rv.manifest_diff.components_added.join(', ') || 'none'],
      ['Version', `${rv.version.baseline.name} → ${rv.version.current.name}`]])));
}

export async function renderBaselines(main, { isCurrent, user }) {
  const isAdmin = user?.role === 'admin';
  const list = h('div', {});
  const detail = h('div', {});

  const act = async (fn, okMessage) => {
    try { await fn(); toast(okMessage, 'good'); await load(); } catch (err) { toast(err.message, 'critical'); }
  };

  const show = async (b) => {
    mount(detail, spinner());
    try {
      const v = await get(`/baselines/${b.id}/verify`);
      mount(detail, card(`${b.package_name} — trusted version #${b.baseline_version}`,
        h('div', { class: `alert tone-${v.valid ? 'good' : 'critical'}` }, icon(v.valid ? 'check' : 'stop'),
          h('div', {}, h('strong', {}, v.valid ? 'Record verified. ' : 'Integrity record has changed. '),
            v.valid ? 'Approval signature, Merkle root, stored profile and audit history all agree.' : v.reasons.join('; '))),
        kv([['Status', badge(STATUS[b.status])], ['App version', `${b.app_version_name || '—'} (code ${b.app_version_code ?? '—'})`],
          ['Files', String(b.file_count)], ['Merkle root', hashEl(b.merkle_root, 24)],
          ['Certificate', b.certificate?.subject], ['Certificate fingerprint', hashEl(b.certificate_sha256, 24)],
          ['Enrolled', h('span', {}, `${b.created_by}, `, timeEl(b.created_at))],
          ['Approved', b.approved_by ? h('span', {}, `${b.approved_by}, `, timeEl(b.approved_at)) : '—'],
          ['Note', b.approval_note || b.status_reason || '—'], ['Signing key', b.signing_key_id || '—']]),
        technical('Verification checks', kv(Object.entries(v.checks).map(([k, val]) => [k, val ? 'passed' : 'FAILED'])))));
    } catch (err) { mount(detail, errorBox(err)); }
  };

  const load = async () => {
    mount(list, spinner());
    let data;
    try { data = await get('/baselines'); } catch (err) { mount(list, errorBox(err)); return; }
    if (!isCurrent()) return;
    mount(list, data.items.length ? table([
      { label: 'App', render: (b) => h('div', {}, h('div', { class: 'strong' }, b.package_name), h('div', { class: 'muted small' }, `Trusted version #${b.baseline_version} · app ${b.app_version_name || '—'}`)) },
      { label: 'Status', render: (b) => badge(STATUS[b.status]) },
      { label: 'Signed by', class: 'hide-sm', render: (b) => b.certificate?.subject || '—' },
      { label: 'Updated', class: 'hide-sm', render: (b) => timeEl(b.approved_at || b.created_at) },
      { label: '', render: (b) => h('div', { class: 'row-actions' },
        h('button', { class: 'btn ghost small', type: 'button', onclick: (e) => { e.stopPropagation(); show(b); } }, 'Details'),
        isAdmin && b.status === 'pending' ? [
          h('button', { class: 'btn primary small', type: 'button', onclick: async (e) => {
            e.stopPropagation();
            const note = await ask('Approve trusted version', 'Approval note (optional)', { required: false, confirm: 'Approve and sign' });
            if (note !== null) act(() => post(`/baselines/${b.id}/approve`, { note: note || null }), 'Approved and digitally signed.');
          } }, 'Approve'),
          h('button', { class: 'btn ghost small', type: 'button', onclick: async (e) => {
            e.stopPropagation();
            const reason = await ask('Reject trusted version', 'Reason');
            if (reason) act(() => post(`/baselines/${b.id}/reject`, { reason }), 'Rejected.');
          } }, 'Reject')] : null,
        isAdmin && b.status === 'approved' ? h('button', { class: 'btn danger small', type: 'button', onclick: async (e) => {
          e.stopPropagation();
          const reason = await ask('Revoke trusted version', 'Reason (e.g. signing key compromised)', { confirm: 'Revoke' });
          if (reason) act(() => post(`/baselines/${b.id}/revoke`, { reason }), 'Revoked.');
        } }, 'Revoke') : null) },
    ], data.items, { onRowClick: show, caption: 'Trusted versions' }) : empty('No trusted versions yet.'));
  };

  let enrolCard = null;
  if (isAdmin) {
    const input = h('input', { type: 'file', accept: '.apk', id: 'baseline-input', class: 'sr-only' });
    const out = h('div', {});
    input.addEventListener('change', async () => {
      const file = input.files[0];
      if (!file) return;
      mount(out, spinner(`Analysing ${file.name}…`));
      try {
        const res = await upload('/baselines', file);
        const b = res.baseline;
        mount(out, h('div', { class: 'subsection' },
          h('h3', {}, `Enrolled ${b.package_name} as trusted version #${b.baseline_version} — awaiting approval`),
          review(res),
          h('p', { class: 'muted small' }, 'Approve it from the list below once you have checked it is the official build.')));
        await load();
      } catch (err) { mount(out, errorBox(err)); }
      input.value = '';
    });
    enrolCard = card('Add a trusted version',
      h('p', {}, 'Upload the official build of an app. It is analysed and fingerprinted, then waits for an administrator to approve it. ' +
        'Approval digitally signs the record; only approved versions are used for comparison.'),
      input, h('label', { for: 'baseline-input', class: 'btn primary' }, icon('upload'), 'Upload official APK'), out);
  }

  mount(main,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Trusted versions'),
      h('p', { class: 'muted' }, 'Approved reference builds that every later scan of the same app is compared with.'))),
    enrolCard,
    h('section', { class: 'card' }, list),
    detail);
  await load();
}
