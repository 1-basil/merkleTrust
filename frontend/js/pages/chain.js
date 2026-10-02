import { get, post } from '../api.js';
import { errorBox, h, hashEl, icon, kv, mount, spinner, technical, timeEl, toast } from '../dom.js';

const SHOW = 40;
const CHECK_TEXT = {
  index: 'Position in the chain is correct',
  link: 'Points to the previous block’s fingerprint',
  payload: 'Event data unchanged',
  hash: 'Block fingerprint matches its contents',
  signature: 'Digital signature valid',
};

export async function renderChain(main, { isCurrent, user }) {
  const isAdmin = user?.role === 'admin';
  const banner = h('div', {});
  const strip = h('div', { class: 'chain-strip', role: 'list', 'aria-label': 'Blocks, oldest to newest' });
  const detail = h('div', { class: 'card block-detail' }, h('p', { class: 'muted' }, 'Select a block to inspect it.'));
  let blocks = [];
  let selected = null;

  const showBlock = (b) => {
    selected = b.index;
    strip.querySelectorAll('.block').forEach((el) => {
      const isSel = Number(el.dataset.index) === b.index;
      el.classList.toggle('selected', isSel);
      if (isSel) el.scrollIntoView({ block: 'nearest', inline: 'center' });
    });
    const v = b.verification;
    mount(detail,
      h('h2', { class: 'card-title' }, `Block #${b.index} — ${b.event_label}`),
      h('div', { class: `alert tone-${v.valid ? 'good' : 'critical'}` }, icon(v.valid ? 'check' : 'stop'),
        h('div', {}, h('strong', {}, v.valid ? 'This block is valid.' : 'This block failed verification.'),
          v.reasons.map((r) => h('div', { class: 'small' }, r)))),
      h('ul', { class: 'checks compact' }, Object.entries(v.checks).map(([k, ok]) =>
        h('li', { class: `check ${ok ? 'ok' : 'bad'}` }, icon(ok ? 'check' : 'stop'), CHECK_TEXT[k] || k))),
      kv([['Time', timeEl(b.timestamp)], ['Event', b.event_type], ['By', b.actor], ['Subject', b.subject || '—'],
        ['Previous hash', hashEl(b.previous_hash, 32)], ['Block hash', hashEl(b.block_hash, 32)],
        ['Event data hash', hashEl(b.payload_hash, 32)], ['Signed with', b.key_id]]),
      technical('Event data', h('pre', { class: 'json' }, JSON.stringify(b.payload, null, 2))),
      technical('Signature', h('pre', { class: 'json' }, JSON.stringify(b.signature, null, 2))));
  };

  const draw = (data) => {
    blocks = data.items.slice().reverse();  // oldest -> newest
    const c = data.chain;
    mount(banner, h('div', { class: `alert big tone-${c.valid ? 'good' : 'critical'}`, role: 'status' }, icon(c.valid ? 'check' : 'stop', 'icon icon-lg'),
      h('div', {}, h('strong', {}, c.valid ? 'Chain intact' : 'BLOCKCHAIN SIMULATION INTEGRITY FAILURE'),
        h('div', {}, c.summary),
        !c.valid && c.first_invalid_index !== null ? h('div', { class: 'small' },
          `Block #${c.first_invalid_index} was altered. Because each block includes the previous block’s fingerprint, `
          + 'the change is visible at that block and breaks the link from the next one.') : null)));
    const items = [];
    blocks.forEach((b, i) => {
      if (i > 0) {
        const linkOk = b.verification.checks.link;
        items.push(h('div', { class: `chain-link ${linkOk ? '' : 'broken'}`, 'aria-hidden': 'true' }, icon('link', 'icon icon-sm')));
      }
      const valid = b.verification.valid;
      const el = h('button', { type: 'button', role: 'listitem', class: `block ${valid ? '' : 'invalid'}`, dataset: { index: b.index },
        onclick: () => showBlock(b), 'aria-label': `Block ${b.index}, ${b.event_label}, ${valid ? 'valid' : 'invalid'}` },
      h('div', { class: 'block-head' }, h('span', { class: 'block-index' }, `#${b.index}`), icon(valid ? 'check' : 'stop', 'icon icon-sm')),
      h('div', { class: 'block-event' }, b.event_label),
      h('div', { class: 'block-hash' }, h('span', { class: 'muted' }, 'prev '), (b.previous_hash || '').slice(0, 8)),
      h('div', { class: 'block-hash' }, h('span', { class: 'muted' }, 'hash '), (b.block_hash || '').slice(0, 8)),
      h('div', { class: 'block-time muted' }, timeEl(b.timestamp)));
      items.push(el);
    });
    mount(strip, items);
    const target = blocks.find((b) => b.index === selected) || blocks.find((b) => !b.verification.valid) || blocks[blocks.length - 1];
    if (target) requestAnimationFrame(() => showBlock(target));
  };

  const load = async () => {
    try {
      const data = await get('/audit/blocks', { limit: SHOW });
      if (isCurrent()) draw(data);
    } catch (err) { mount(banner, errorBox(err)); }
  };

  const verifyBtn = h('button', { class: 'btn primary', type: 'button', onclick: async () => {
    verifyBtn.disabled = true;
    try {
      const r = await post('/audit/verify');
      toast(r.valid ? 'Verification complete: chain intact.' : 'Verification failed: the chain was tampered with.', r.valid ? 'good' : 'critical');
      await load();
    } catch (err) { toast(err.message, 'critical'); }
    verifyBtn.disabled = false;
  } }, icon('shield'), 'Verify chain');

  let demo = null;
  if (isAdmin) {
    const blockSel = h('input', { type: 'number', min: 1, value: 1, class: 'narrow', 'aria-label': 'Block number' });
    const modeSel = h('select', { 'aria-label': 'Tamper mode' },
      h('option', { value: 'edit_payload' }, 'Edit the event data'),
      h('option', { value: 'rewrite_block' }, 'Edit data and recompute the block hash'));
    demo = h('section', { class: 'card demo' },
      h('h2', { class: 'card-title' }, 'Tamper demonstration (administrators)'),
      h('p', { class: 'small' }, 'Simulates an attacker who edits a stored audit record directly in the database. ' +
        'Even if the attacker recomputes the block hash, they cannot produce a valid signature, and the next block still points to the old fingerprint.'),
      h('div', { class: 'demo-controls' },
        h('label', { class: 'inline-field' }, 'Block ', blockSel), modeSel,
        h('button', { class: 'btn danger', type: 'button', onclick: async () => {
          try {
            const r = await post('/audit/demo/tamper', { block_index: Number(blockSel.value), mode: modeSel.value });
            selected = r.tampered_block;
            toast(`Block #${r.tampered_block} altered. Now press “Verify chain”.`, 'serious');
            await load();
          } catch (err) { toast(err.message, 'critical'); }
        } }, icon('alert'), 'Tamper with block'),
        h('button', { class: 'btn ghost', type: 'button', onclick: async () => {
          try {
            const r = await post('/audit/demo/restore');
            toast(r.restored_blocks.length ? `Restored block(s) ${r.restored_blocks.join(', ')}.` : 'Nothing to restore.', 'good');
            await load();
          } catch (err) { toast(err.message, 'critical'); }
        } }, 'Restore valid chain')));
  }

  mount(main,
    h('div', { class: 'page-head' }, h('div', {},
      h('h1', {}, 'Blockchain Simulation'),
      h('p', { class: 'muted' }, 'A cryptographically linked chain of signed audit records.')), verifyBtn),
    h('div', { class: 'notice' }, icon('help'), h('p', {},
      h('strong', {}, 'Cryptographically Linked Blockchain Simulation. '),
      'This is a single-server, append-only chain stored in the application database. It demonstrates how hash-linking and digital ' +
      'signatures make tampering evident. It is not a distributed blockchain: there is no network, consensus or mining.')),
    banner,
    h('section', { class: 'card' }, h('h2', { class: 'card-title' }, `Latest blocks (oldest → newest)`), strip),
    detail,
    demo);
  mount(banner, spinner());
  await load();
}
