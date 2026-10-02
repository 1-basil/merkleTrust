import { get, post } from '../api.js';
import {
  CATEGORY_LABELS, INTEGRITY, RISK, SEVERITY, SIGNATURE, VERDICT, badge, bytes, card, empty, errorBox, h, hashEl,
  icon, kv, mount, spinner, table, technical,
} from '../dom.js';

export async function renderResult(main, { params, isCurrent }) {
  const [id] = params;
  mount(main, spinner('Loading the result…'));
  let data;
  try {
    let scan = await get(`/scans/${id}`);
    while (isCurrent() && (scan.status === 'queued' || scan.status === 'running')) {
      mount(main, spinner('The analysis is still running…'));
      await new Promise((r) => setTimeout(r, 1000));
      scan = await get(`/scans/${id}`);
    }
    if (!isCurrent()) return;
    data = await get(`/scans/${id}/report`);
  } catch (err) {
    if (isCurrent()) mount(main, errorBox(err));
    return;
  }
  if (!isCurrent()) return;
  const r = data.reports || {};
  const score = r.score;
  const panel = h('div', { class: 'tab-panel', role: 'tabpanel', tabindex: '0' });

  const tabs = [
    ['Overview', () => overview(r, data)],
    ['File changes', () => fileChanges(r, id)],
    ['Security findings', () => findings(score)],
    ['Certificate', () => certificate(r)],
    ['Verification', () => verification(r, id)],
    ['Technical details', () => technicalTab(data)],
  ];
  const tabButtons = tabs.map(([label, render], i) => h('button', {
    type: 'button', role: 'tab', class: 'tab', 'aria-selected': i === 0 ? 'true' : 'false',
    onclick: (e) => {
      tabButtons.forEach((b) => b.setAttribute('aria-selected', 'false'));
      e.currentTarget.setAttribute('aria-selected', 'true');
      mount(panel, render());
    },
  }, label));

  mount(main, hero(data, r), h('div', { class: 'tabs', role: 'tablist' }, tabButtons), panel);
  mount(panel, tabs[0][1]());
}

// ------------------------------------------------------------ hero --
function hero(data, r) {
  const score = r.score;
  const st = r.static || {};
  const scan = data.scan;
  if (!score) {
    return h('section', { class: 'hero tone-neutral' }, h('div', { class: 'hero-main' },
      h('div', { class: 'hero-status' }, icon('x', 'icon icon-xl'), h('div', {}, h('div', { class: 'hero-label' }, 'Could not be analysed'),
        h('p', {}, scan.error || 'The analysis did not complete.')))));
  }
  const v = VERDICT[score.verdict.code] || VERDICT.ANALYSIS_FAILED;
  const integ = INTEGRITY[score.integrity.status] || INTEGRITY.UNKNOWN;
  const risk = RISK[score.risk.level] || RISK.UNKNOWN;
  const pct = score.risk.score ?? 0;
  return h('section', { class: `hero tone-${v.tone}` },
    h('div', { class: 'hero-main' },
      h('div', { class: 'hero-status' }, icon(v.icon, 'icon icon-xl'),
        h('div', {}, h('div', { class: 'hero-label' }, v.label.toUpperCase()), h('p', { class: 'hero-summary' }, score.verdict.summary))),
      h('div', { class: 'hero-app' },
        h('div', { class: 'strong' }, st.package_name || scan.filename || 'Unknown app'),
        h('div', { class: 'muted small' }, [st.version_name && `Version ${st.version_name}`, scan.filename, `scanned ${new Date(scan.created_at).toLocaleString()}`]
          .filter(Boolean).join(' · ')))),
    h('div', { class: 'hero-questions' },
      h('div', { class: 'question' },
        h('div', { class: 'q' }, 'Is this the same app as the trusted version?'),
        badge(integ),
        score.integrity.reasons?.length ? h('p', { class: 'small' }, score.integrity.reasons[0]) : null),
      h('div', { class: 'question' },
        h('div', { class: 'q' }, 'Does it have security concerns?'),
        badge(risk),
        score.risk.score === null ? null : h('div', { class: 'meter', role: 'meter', 'aria-valuemin': '0', 'aria-valuemax': '100',
          'aria-valuenow': String(pct), 'aria-label': `Risk score ${pct} of 100` },
        h('span', { class: `meter-fill tone-${risk.tone}`, style: `width:${Math.max(2, pct)}%` })),
        score.risk.score === null ? null : h('p', { class: 'small' }, `Risk score ${pct}/100 · `,
          h('span', { class: 'muted' }, 'an indicator of concerns, not a probability of malware')))));
}

// --------------------------------------------------------- overview --
function overview(r, data) {
  const score = r.score;
  if (!score) return card('Why the analysis failed', h('p', {}, data.scan.error || 'Unknown error'));
  const contributions = score.risk.contributions || [];
  return h('div', { class: 'grid-2' },
    card('What we found',
      h('ul', { class: 'reasons' }, (score.integrity.reasons || []).map((t) => h('li', {}, t))),
      score.notes?.length ? h('ul', { class: 'notes muted small' }, score.notes.map((n) => h('li', {}, n))) : null),
    card(`Risk score: ${score.risk.score ?? '—'}/100`,
      contributions.length ? table([
        { label: 'Reason', render: (c) => h('div', {}, c.title, h('div', { class: 'muted small' }, c.finding_id)) },
        { label: 'Points', class: 'num', render: (c) => `+${c.points}` },
      ], contributions, { caption: 'Risk score breakdown' }) : empty('No risk factors were found.'),
      score.risk.suppressed_duplicates?.length ? technical('Not counted twice',
        h('ul', { class: 'small' }, score.risk.suppressed_duplicates.map((d) =>
          h('li', {}, `${d.finding_id} (+${d.points}) is the same fact as ${d.counted_as}, which is already counted.`)))) : null,
      h('p', { class: 'muted small' }, score.disclaimer)));
}

// ----------------------------------------------------- file changes --
function fileChanges(r, scanId) {
  const t = r.tamper || {};
  const integ = t.integrity || {};
  if (!t.baseline_found || !integ.files) {
    return card('File changes', h('div', { class: 'alert tone-neutral' }, icon('help'),
      h('div', {}, h('strong', {}, 'There is no trusted version to compare with. '),
        'An administrator can approve the official build of this app as a trusted version; later scans will then show exactly which files changed.')),
    filesTable((r.integrity?.files || []).map((f) => ({ path: f.path, category: f.category, size: f.size })), 'All files in this app'));
  }
  const files = integ.files;
  const c = integ.counts;
  const counts = [['Modified', c.modified, 'serious'], ['Added', c.added, 'serious'], ['Deleted', c.deleted, 'serious'], ['Unchanged', c.unchanged, 'good']];
  const proofRow = (f) => {
    const out = h('div', { class: 'proof-result' });
    const btn = h('button', { class: 'btn ghost small', type: 'button', onclick: async () => {
      btn.disabled = true;
      try {
        const p = await get(`/scans/${scanId}/files/proof`, { path: f.path });
        mount(out, h('div', { class: `alert tone-${p.current_file_verified ? 'good' : 'critical'}` },
          icon(p.current_file_verified ? 'check' : 'stop'),
          h('div', {}, h('strong', {}, p.current_file_verified ? 'VALID — ' : 'INVALID — '), p.explanation,
            technical('Merkle proof',
              kv([['Trusted root', hashEl(p.trusted_root, 24)], ['Trusted fingerprint', hashEl(p.baseline_sha256, 24)],
                ['This app’s fingerprint', hashEl(p.current_sha256, 24)], ['Proof steps', String(p.proof.length)]])))));
      } catch (err) { mount(out, errorBox(err)); }
      btn.disabled = false;
    } }, icon('link', 'icon icon-sm'), 'Check proof');
    return h('div', {}, btn, out);
  };
  const changeTable = (rows, title, withProof) => rows.length ? h('div', { class: 'subsection' }, h('h3', {}, title),
    table([
      { label: 'File', render: (f) => h('code', { class: 'path' }, f.path) },
      { label: 'Type', class: 'hide-sm', render: (f) => CATEGORY_LABELS[f.category] || f.category },
      { label: 'Size', class: 'hide-sm num', render: (f) => bytes(f.current_size ?? f.baseline_size) },
      withProof ? { label: 'Merkle proof', render: proofRow } : null,
    ].filter(Boolean), rows)) : null;

  return h('div', {},
    card('Compared with the trusted version',
      h('p', {}, `Trusted version #${t.baseline.baseline_version} (${t.baseline.app_version_name || 'unknown version'}), approved by ${t.baseline.approved_by}.`),
      h('div', { class: 'stats compact' }, counts.map(([label, n, tone]) => h('div', { class: `stat tone-${n ? tone : 'neutral'}` },
        h('div', { class: 'stat-label' }, label), h('div', { class: 'stat-value' }, String(n))))),
      c.modified + c.added + c.deleted === 0 ? h('div', { class: 'alert tone-good' }, icon('check'), 'Every application file is identical to the trusted version.') : null,
      changeTable(files.modified, 'Modified files', true),
      changeTable(files.added, 'Added files', true),
      changeTable(files.deleted, 'Deleted files', true),
      files.signature_files_changed.length ? technical(`Signature files that differ (${files.signature_files_changed.length})`,
        h('p', { class: 'small muted' }, 'These change whenever an app is signed again; they are reported separately from content changes.'),
        h('ul', { class: 'small' }, files.signature_files_changed.map((f) => h('li', {}, h('code', {}, f.path))))) : null,
      technical(`Unchanged files (${files.unchanged.length})`, h('ul', { class: 'small cols' }, files.unchanged.map((p) => h('li', {}, h('code', {}, p))))),
      integ.chunks?.comparable ? technical('Byte-level forensics (supplementary)',
        h('p', { class: 'small' }, `${integ.chunks.changed_count} of ${integ.chunks.current_chunks} raw 64 KB blocks differ. `
          + 'Block positions shift when bytes are inserted, so this is shown for forensics only; the per-file comparison above is authoritative.')) : null));
}

function filesTable(rows, title) {
  return h('div', { class: 'subsection' }, h('h3', {}, title), table([
    { label: 'File', render: (f) => h('code', { class: 'path' }, f.path) },
    { label: 'Type', class: 'hide-sm', render: (f) => CATEGORY_LABELS[f.category] || f.category },
    { label: 'Size', class: 'num', render: (f) => bytes(f.size) },
  ], rows));
}

// --------------------------------------------------------- findings --
function findings(score) {
  const all = (score?.all_findings || []).filter((f) => f.category !== 'analysis' || f.points > 0);
  if (!all.length) return card('Security findings', empty('No security findings.'));
  // Findings that describe the same fact as a higher-scoring one are not counted twice.
  const duplicates = new Map((score.risk?.suppressed_duplicates || []).map((d) => [`${d.source}:${d.finding_id}`, d.counted_as]));
  return h('div', { class: 'findings' }, all.map((f) => {
    const sev = SEVERITY[f.severity] || SEVERITY.info;
    const countedAs = duplicates.get(`${f.source}:${f.id}`);
    const points = !f.points ? null : countedAs ? `already counted (${countedAs})` : `+${f.points} risk`;
    return h('article', { class: `finding tone-${sev.tone}` },
      h('header', {}, badge(sev), h('h3', {}, f.title), points ? h('span', { class: 'points' }, points) : null),
      h('p', {}, f.explanation),
      f.evidence ? h('div', { class: 'evidence' }, h('span', { class: 'muted small' }, 'Evidence'), h('code', {}, f.evidence)) : null,
      h('p', { class: 'recommendation' }, h('strong', {}, 'What to do: '), f.recommendation),
      technical('Technical details', kv([['Technical description', f.technical], ['Finding ID', h('code', {}, f.id)],
        ['Reported by', `${f.source} engine`], ['Risk points', String(f.points)]])));
  }));
}

// ------------------------------------------------------ certificate --
function certificate(r) {
  const current = r.static?.certificate || {};
  const t = r.tamper || {};
  const base = t.baseline?.certificate;
  const sig = r.static?.signature || {};
  const changed = t.certificate_changed;
  const certRows = (c) => kv([
    ['Issued to', c.subject], ['Issued by', c.issuer],
    ['Fingerprint (SHA-256)', hashEl(c.sha256, 24)],
    ['Valid', c.valid_from ? `${new Date(c.valid_from).toLocaleDateString()} – ${new Date(c.valid_to).toLocaleDateString()}` : null],
    ['Key', c.public_key ? `${c.public_key.algorithm} ${c.public_key.size || ''}${c.public_key.curve ? ` (${c.public_key.curve})` : ''}` : null],
    ['Signature algorithm', c.signature_algorithm],
  ]);
  return h('div', {},
    card('Developer signing certificate',
      base ? h('div', { class: `alert tone-${changed ? 'critical' : 'good'}` }, icon(changed ? 'stop' : 'check'),
        h('div', {}, h('strong', {}, changed ? 'Signed with a different key than the trusted version. ' : 'Same developer key as the trusted version. '),
          changed ? 'Only the original developer holds the original key, so this usually means someone else repackaged the app.' : ''))
        : h('div', { class: 'alert tone-neutral' }, icon('help'), 'No trusted version to compare the certificate with.'),
      h('div', { class: base ? 'grid-2' : '' },
        base ? h('div', {}, h('h3', {}, 'Trusted version'), certRows(base)) : null,
        h('div', {}, h('h3', {}, 'This app'), current.sha256 ? certRows(current) : empty('No certificate found.'),
          !sig.certificate_verified && current.sha256 ? h('p', { class: 'small muted' }, 'Shown as claimed by the app; its signature did not verify.') : null)),
      h('p', { class: 'muted small' }, 'Android app certificates are normally self-signed; that alone is not a security problem. ' +
        'What matters is whether the key matches the trusted version.')),
    card('App signature', badge(SIGNATURE[sig.status]),
      table([
        { label: 'Scheme', render: (s) => s.name },
        { label: 'Present', render: (s) => (s.present ? 'Yes' : 'No') },
        { label: 'Verified', render: (s) => (!s.present ? '—' : s.verified ? badge({ label: 'Valid', tone: 'good', icon: 'check' }) : badge({ label: 'Failed', tone: 'critical', icon: 'stop' })) },
      ], ['v1', 'v2', 'v3'].map((name) => ({ name: { v1: 'v1 (JAR signing)', v2: 'v2 (APK Signature Scheme)', v3: 'v3 (key rotation)' }[name], ...(sig.schemes?.[name] || {}) }))),
      sig.errors?.length ? technical('Why verification failed', h('ul', { class: 'small' }, sig.errors.map((e) => h('li', {}, e)))) : null));
}

// ----------------------------------------------------- verification --
function verification(r, scanId) {
  const t = r.tamper || {};
  const repo = r.repository || {};
  const integ = t.integrity || {};
  const sig = r.static?.signature || {};
  const out = h('div', {});
  const check = (ok, title, text, details) => h('li', { class: `check ${ok === null ? 'na' : ok ? 'ok' : 'bad'}` },
    icon(ok === null ? 'help' : ok ? 'check' : 'stop'), h('div', {}, h('strong', {}, title), h('div', { class: 'small' }, text), details));

  const bv = t.baseline_verification;
  return h('div', {},
    card('Cryptographic proof',
      h('ul', { class: 'checks' },
        check(bv ? bv.valid : null, 'Trusted version record',
          bv ? (bv.valid ? 'The trusted version is approved, signed, and its stored data is unaltered.' : `Integrity record has changed: ${bv.reasons.join('; ')}`)
            : 'No trusted version exists for this app.',
          bv ? technical('Checks', kv(Object.entries(bv.checks).map(([k, v]) => [k, v ? 'passed' : 'FAILED']).concat([['Signing key', bv.key_id]]))) : null),
        check(sig.status === 'verified', 'Developer signature', SIGNATURE[sig.status]?.label || 'Unknown',
          technical('Schemes', h('p', { class: 'small' }, `Present: ${(sig.schemes_present || []).join(', ') || 'none'}`))),
        check(integ.merkle ? integ.merkle.match : null, 'File fingerprints (Merkle root)',
          integ.merkle ? (integ.merkle.match ? 'All file fingerprints combine to the trusted Merkle root.' : 'Integrity record has changed: the files no longer combine to the trusted Merkle root.')
            : 'Nothing to compare with.',
          integ.merkle ? technical('Roots', kv([['Trusted root', hashEl(integ.merkle.baseline_root, 24)], ['This app', hashEl(integ.merkle.current_root, 24)]])) : null),
        check(repo.block_index !== undefined ? true : null, 'Audit record',
          repo.block_index !== undefined ? `Sealed in block #${repo.block_index} of the audit log, signed with ${repo.key_id}.` : 'Not recorded.',
          repo.block_index !== undefined ? technical('Seal', kv([['Report fingerprint', hashEl(repo.report_sha256, 24)], ['Block hash', hashEl(repo.block_hash, 24)],
            ['Previous block', hashEl(repo.previous_hash, 24)]])) : null)),
      h('button', { class: 'btn primary', type: 'button', onclick: async (e) => {
        const btn = e.currentTarget;
        btn.disabled = true;
        mount(out, spinner('Verifying…'));
        try {
          const v = await post(`/scans/${scanId}/verify`);
          mount(out, h('div', { class: `alert tone-${v.valid ? 'good' : 'critical'}` }, icon(v.valid ? 'check' : 'stop'),
            h('div', {}, h('strong', {}, v.valid ? 'Verified. ' : 'Verification failed. '),
              v.valid ? 'This report is exactly the one that was signed and recorded, and the audit log is intact.' : v.reasons.join(' '),
              technical('Checks performed', kv(Object.entries(v.checks).map(([k, val]) => [k, val ? 'passed' : 'FAILED']))))));
        } catch (err) { mount(out, errorBox(err)); }
        btn.disabled = false;
      } }, icon('shield'), 'Verify this report now'),
      out));
}

// --------------------------------------------------------- technical --
function technicalTab(data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  return card('Engine reports',
    h('p', { class: 'muted small' }, 'Full machine-readable output of every analysis stage.'),
    h('a', { class: 'btn ghost', href: url, download: `merkletrust-${data.job_id}.json` }, icon('download'), 'Download JSON'),
    Object.entries(data.reports || {}).map(([name, rep]) => technical(`${name}.json`, h('pre', { class: 'json' }, JSON.stringify(rep, null, 2)))),
    data.errors && Object.keys(data.errors).length ? technical('Stage errors', h('pre', { class: 'json' }, JSON.stringify(data.errors, null, 2))) : null);
}
