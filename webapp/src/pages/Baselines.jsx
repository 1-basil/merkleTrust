import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CheckCircle2, Clock, Info, ShieldCheck, ShieldX, Smartphone, Stamp, UploadCloud, XCircle } from 'lucide-react';
import {
  Button, Card, CardHeader, Empty, ErrorBox, Explain, HashChip, PageHeader, ProgressBar, Spinner, ToneBadge, cx,
} from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { useAuth } from '../lib/auth.jsx';
import { dateTime } from '../lib/format.js';

const STATUS = {
  approved: ['good', 'Trusted', CheckCircle2],
  pending: ['warn', 'Waiting for approval', Clock],
  rejected: ['neutral', 'Rejected', XCircle],
  revoked: ['bad', 'Revoked', ShieldX],
};
const FILTERS = ['all', 'approved', 'pending', 'rejected', 'revoked'];
const FILTER_LABEL = { all: 'All', approved: 'Trusted', pending: 'Waiting', rejected: 'Rejected', revoked: 'Revoked' };

function Actions({ b, onChanged }) {
  const [mode, setMode] = useState(null); // 'reject' | 'revoke'
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const send = async (action, body) => {
    setBusy(true);
    setError(null);
    try {
      await api.post(`/baselines/${b.id}/${action}`, body);
      setMode(null);
      setText('');
      await onChanged();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mt-4 border-t border-white/[0.06] pt-4">
      {!mode && (
        <div className="flex flex-wrap gap-2">
          {b.status === 'pending' && (
            <>
              <Button size="sm" loading={busy} onClick={() => send('approve', { note: 'Approved in the web app' })}>
                <Stamp className="size-3.5" aria-hidden="true" />Approve & sign
              </Button>
              <Button size="sm" variant="secondary" onClick={() => setMode('reject')}>Reject</Button>
            </>
          )}
          {b.status === 'approved' && (
            <Button size="sm" variant="ghost" onClick={() => setMode('revoke')}><ShieldX className="size-3.5" aria-hidden="true" />Revoke trust</Button>
          )}
        </div>
      )}
      {mode && (
        <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); send(mode, { reason: text }); }}>
          <input autoFocus value={text} onChange={(e) => setText(e.target.value)} minLength={3} required
            placeholder={mode === 'reject' ? 'Why reject it?' : 'Why revoke it?'}
            className="min-w-0 flex-1 rounded-lg border border-white/10 bg-black/30 px-3 py-1.5 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-emerald-500/60 focus:outline-none" />
          <Button size="sm" variant="danger" type="submit" loading={busy}>{mode === 'reject' ? 'Reject' : 'Revoke'}</Button>
          <Button size="sm" variant="ghost" onClick={() => setMode(null)}>Cancel</Button>
        </form>
      )}
      <ErrorBox error={error} className="mt-3" />
    </div>
  );
}

function BaselineCard({ b, isAdmin, onChanged }) {
  const [tone, label, Icon] = STATUS[b.status] || ['neutral', b.status, Info];
  return (
    <Card className={cx('p-5 transition', b.status === 'pending' && 'border-amber-500/30')}>
      <div className="flex flex-wrap items-start gap-3">
        <span className="grid size-11 shrink-0 place-items-center rounded-2xl bg-gradient-to-br from-emerald-400/20 to-sky-400/10 ring-1 ring-emerald-400/25">
          <Smartphone className="size-5 text-emerald-200" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="truncate font-mono text-sm font-medium text-zinc-100" title={b.package_name}>{b.package_name}</p>
          <p className="mt-0.5 text-xs text-zinc-500">
            Version {b.app_version_name || '—'} · {b.file_count} files · record v{b.baseline_version}
          </p>
        </div>
        <ToneBadge tone={tone} icon={Icon}>{label}</ToneBadge>
      </div>
      <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-2">
        <div className="min-w-0">
          <dt className="mb-1 text-zinc-500">App fingerprint (Merkle root)</dt>
          <dd><HashChip value={b.merkle_root} n={18} /></dd>
        </div>
        <div className="min-w-0">
          <dt className="mb-1 text-zinc-500">Developer’s key (certificate)</dt>
          <dd><HashChip value={b.certificate_sha256} n={18} /></dd>
        </div>
        <div>
          <dt className="text-zinc-500">Added</dt>
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
      {isAdmin && (b.status === 'pending' || b.status === 'approved') && <Actions b={b} onChanged={onChanged} />}
    </Card>
  );
}

function Enrol({ onDone }) {
  const inputRef = useRef(null);
  const [progress, setProgress] = useState(null);
  const [error, setError] = useState(null);
  const [note, setNote] = useState(null);

  const upload = async (file) => {
    if (!file) return;
    setError(null);
    setNote(null);
    setProgress(0);
    try {
      const r = await api.upload('/baselines', file, setProgress);
      setNote(`${r.baseline.package_name} added. Review it below and press “Approve & sign”.`);
      await onDone();
    } catch (err) {
      setError(err);
    } finally {
      setProgress(null);
      if (inputRef.current) inputRef.current.value = '';
    }
  };

  return (
    <Card>
      <CardHeader icon={UploadCloud} title="Add an official app"
        subtitle="Upload the developer’s genuine APK. After you approve it, every later upload of that app is compared with it file by file." />
      <div className="p-5">
        <label htmlFor="baseline-file"
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => { e.preventDefault(); upload(e.dataTransfer.files[0]); }}
          className="flex cursor-pointer items-center gap-3 rounded-xl border-2 border-dashed border-white/10 px-4 py-4 text-sm transition hover:border-emerald-400/40 hover:bg-white/[0.02]">
          <input ref={inputRef} id="baseline-file" type="file" accept=".apk" className="sr-only" onChange={(e) => upload(e.target.files[0])} />
          <UploadCloud className="size-5 text-emerald-300" aria-hidden="true" />
          <span className="text-zinc-300">Drop the official <strong>.apk</strong> here, or click to choose it</span>
          <span className="ml-auto hidden text-xs text-zinc-500 sm:inline">e.g. evaluation/dataset/baseline_demo.apk</span>
        </label>
        {progress !== null && <div className="mt-3"><ProgressBar value={progress} /></div>}
        {note && <p className="mt-3 flex items-center gap-2 text-sm text-emerald-200"><CheckCircle2 className="size-4" aria-hidden="true" />{note}</p>}
        <ErrorBox error={error} className="mt-3" />
      </div>
    </Card>
  );
}

export default function Baselines() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');

  const load = useCallback(async () => {
    try {
      const d = await api.get('/baselines');
      setItems(d.items);
      setError(null);
    } catch (err) {
      setError(err);
    }
  }, []);
  useEffect(() => { load(); }, [load]);

  const counts = useMemo(() => Object.fromEntries(FILTERS.map((f) => [f, (items || []).filter((b) => f === 'all' || b.status === f).length])), [items]);
  const shown = (items || []).filter((b) => filter === 'all' || b.status === filter);

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        eyebrow="Android apps"
        title="Trusted Apps"
        description="The official, approved versions of apps. A scanned app is only called “Verified Original” if it matches one of these exactly."
      />
      {isAdmin ? <Enrol onDone={load} /> : (
        <Card className="flex items-start gap-3 p-4 text-sm text-zinc-400">
          <Info className="mt-0.5 size-4 shrink-0 text-sky-400" aria-hidden="true" />
          Only administrators can add or approve trusted apps.
        </Card>
      )}
      <Explain title="Why must a person approve it?">
        <p>Many systems trust whatever version they see first. An attacker who uploads a hacked app first would then “become” the original.
          MerkleTrust never does that: a person has to approve the official version.</p>
        <p>Approval <strong className="text-zinc-100">digitally signs</strong> a record of the app: its name, version, developer key and the fingerprint of
          every file. That record is re-checked before every use, so if someone edits it in the database it is rejected.</p>
      </Explain>
      <div className="flex flex-wrap gap-2">
        {FILTERS.map((f) => (
          <button key={f} type="button" onClick={() => setFilter(f)} aria-pressed={filter === f}
            className={cx('rounded-full px-3.5 py-1.5 text-sm font-medium ring-1 ring-inset transition',
              filter === f ? 'bg-white/10 text-zinc-100 ring-white/20' : 'text-zinc-400 ring-white/10 hover:text-zinc-200')}>
            {FILTER_LABEL[f]} <span className="opacity-60">{counts[f]}</span>
          </button>
        ))}
      </div>
      <ErrorBox error={error} />
      {!items && !error && <Spinner label="Loading trusted apps…" />}
      {items && shown.length === 0 && (
        <Card><Empty icon={ShieldCheck} title={items.length ? 'Nothing with this status' : 'No trusted apps yet'}>
          {items.length ? 'Choose another filter.' : 'Without a trusted original, apps are reported as “Not Verified”.'}
        </Empty></Card>
      )}
      <div className="grid gap-4 lg:grid-cols-2">{shown.map((b) => <BaselineCard key={b.id} b={b} isAdmin={isAdmin} onChanged={load} />)}</div>
    </div>
  );
}
