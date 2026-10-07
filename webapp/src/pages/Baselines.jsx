import { useEffect, useMemo, useState } from 'react';
import { CheckCircle2, Clock, Database, Info, ShieldX, Smartphone, XCircle } from 'lucide-react';
import { Card, CopyHash, Empty, ErrorBox, PageHeader, Spinner, ToneBadge, cx } from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { dateTime, shortHash } from '../lib/format.js';

const STATUS = {
  approved: ['good', 'Approved', CheckCircle2],
  pending: ['warn', 'Awaiting approval', Clock],
  rejected: ['neutral', 'Rejected', XCircle],
  revoked: ['bad', 'Revoked', ShieldX],
};
const FILTERS = ['all', 'approved', 'pending', 'rejected', 'revoked'];

function BaselineCard({ b }) {
  const [tone, label, Icon] = STATUS[b.status] || ['neutral', b.status, Info];
  return (
    <Card className="p-5">
      <div className="flex flex-wrap items-start gap-3">
        <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-emerald-500/10 ring-1 ring-emerald-500/20">
          <Smartphone className="size-5 text-emerald-300" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="truncate font-mono text-sm text-zinc-100" title={b.package_name}>{b.package_name}</p>
          <p className="mt-0.5 text-xs text-zinc-500">
            App version {b.app_version_name || '—'} ({b.app_version_code ?? '—'}) · master copy v{b.baseline_version} · {b.file_count} files
          </p>
        </div>
        <ToneBadge tone={tone} icon={Icon}>{label}</ToneBadge>
      </div>
      <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-2">
        <div className="min-w-0">
          <dt className="mb-1 text-zinc-500">Merkle root (fingerprint of every file)</dt>
          <dd><CopyHash value={b.merkle_root} display={shortHash(b.merkle_root, 12)} /></dd>
        </div>
        <div className="min-w-0">
          <dt className="mb-1 text-zinc-500">Developer certificate (SHA-256)</dt>
          <dd><CopyHash value={b.certificate_sha256} display={shortHash(b.certificate_sha256, 12)} /></dd>
        </div>
        <div>
          <dt className="text-zinc-500">Enrolled</dt>
          <dd className="text-zinc-300">{dateTime(b.created_at)} by {b.created_by}</dd>
        </div>
        <div>
          <dt className="text-zinc-500">{b.status === 'approved' ? 'Approved & signed' : 'Decision'}</dt>
          <dd className="text-zinc-300">
            {b.approved_at ? `${dateTime(b.approved_at)} by ${b.approved_by}` : '—'}
            {b.status_reason && <span className="block text-zinc-500">{b.status_reason}</span>}
          </dd>
        </div>
      </dl>
    </Card>
  );
}

export default function Baselines() {
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    api.get('/baselines').then((d) => setItems(d.items)).catch(setError);
  }, []);

  const counts = useMemo(() => Object.fromEntries(FILTERS.map((f) => [f, (items || []).filter((b) => f === 'all' || b.status === f).length])), [items]);
  const shown = (items || []).filter((b) => filter === 'all' || b.status === filter);

  return (
    <div className="animate-fade-in">
      <PageHeader
        title="Baselines"
        description="Trusted master copies of Android apps. An administrator enrols the official build and signs its approval; every later upload of the same app is compared against it file by file."
      />
      <Card className="mb-6 flex items-start gap-3 p-4 text-sm text-zinc-400">
        <Info className="mt-0.5 size-4 shrink-0 text-sky-400" aria-hidden="true" />
        <p>
          Baselines apply to Android apps only. Images, media, web pages and PDFs are judged on their own structure and
          fingerprint. Enrolling and approving a master copy requires an administrator account (API{' '}
          <code className="text-zinc-300">POST /api/v1/baselines</code> or <code className="text-zinc-300">scripts/baseline_cli.py</code>).
        </p>
      </Card>
      <div className="mb-4 flex flex-wrap gap-2">
        {FILTERS.map((f) => (
          <button key={f} type="button" onClick={() => setFilter(f)} aria-pressed={filter === f}
            className={cx('rounded-full px-3 py-1 text-xs font-medium capitalize ring-1 ring-inset transition',
              filter === f ? 'bg-white/10 text-zinc-100 ring-white/20' : 'text-zinc-400 ring-white/10 hover:text-zinc-200')}>
            {f} <span className="opacity-60">{counts[f]}</span>
          </button>
        ))}
      </div>
      <ErrorBox error={error} />
      {!items && !error && <Spinner label="Loading baselines…" />}
      {items && shown.length === 0 && (
        <Card><Empty icon={Database} title={items.length ? 'No baselines with this status' : 'No baselines yet'}>
          {items.length ? 'Choose another filter.' : 'Without a master copy, apps are reported as “Not Verified”.'}
        </Empty></Card>
      )}
      <div className="grid gap-4 lg:grid-cols-2">{shown.map((b) => <BaselineCard key={b.id} b={b} />)}</div>
    </div>
  );
}
