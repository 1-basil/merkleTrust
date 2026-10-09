import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Blocks, Bookmark, CheckCircle2, ChevronLeft, ExternalLink, FileCheck2, FileUp, KeyRound, Link2, Link2Off, LogIn, RotateCcw,
  ShieldAlert, ShieldCheck, ShieldX, Skull, Sparkles, Stamp, User, XCircle,
} from 'lucide-react';
import {
  Banner, Button, Card, CardHeader, ErrorBox, Explain, HashChip, PageHeader, Spinner, cx,
} from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { useAuth } from '../lib/auth.jsx';
import { dateTime } from '../lib/format.js';

const PAGE = 40;
const CHECKPOINT_KEY = 'merkletrust.chain-checkpoint';

function readCheckpoint() {
  try { return JSON.parse(localStorage.getItem(CHECKPOINT_KEY)); } catch { return null; }
}

// Plain-language names; the backend's labels predate non-APK files.
const EVENTS = {
  GENESIS: ['Chain started', Sparkles],
  APK_UPLOADED: ['File uploaded', FileUp],
  ANALYSIS_COMPLETED: ['Scan finished & sealed', FileCheck2],
  INTEGRITY_ALERT: ['Tampering detected', ShieldAlert],
  BASELINE_ENROLLED: ['Trusted app added', Stamp],
  BASELINE_APPROVED: ['Trusted app approved', Stamp],
  BASELINE_REJECTED: ['Trusted app rejected', XCircle],
  BASELINE_REVOKED: ['Trusted app revoked', XCircle],
  REPORT_VERIFIED: ['Report re-checked', ShieldCheck],
  CHAIN_VERIFIED: ['Chain checked', ShieldCheck],
  USER_LOGIN: ['User signed in', LogIn],
  LOGIN_FAILED: ['Failed sign-in', ShieldAlert],
  AUDIT_TAMPER_DEMO: ['Attack demo started', Skull],
  AUDIT_RESTORED: ['Chain restored', RotateCcw],
};
const eventOf = (b) => EVENTS[b.event_type] || [b.event_label || b.event_type, Blocks];

const CHECK_TEXT = {
  index: 'In the right position in the chain',
  link: 'Points to the previous block’s fingerprint',
  payload: 'Its data has not been edited',
  hash: 'Its fingerprint matches its contents',
  signature: 'Digital signature is valid',
};

// ------------------------------------------------------------ chain strip --

function BlockTile({ block, selected, scanState, onClick }) {
  const valid = block.verification?.valid !== false;
  const [label, Icon] = eventOf(block);
  const scanned = scanState === 'ok' || scanState === 'bad';
  return (
    <button type="button" onClick={onClick} data-index={block.index}
      aria-label={`Block ${block.index}: ${label}, ${valid ? 'valid' : 'broken'}`} aria-pressed={selected}
      className={cx('relative w-44 shrink-0 rounded-2xl border p-3 text-left transition duration-300',
        selected ? '-translate-y-1 shadow-xl' : 'hover:-translate-y-0.5',
        !valid ? 'animate-shake border-red-500/60 bg-red-500/[0.12] shadow-red-500/20'
          : scanState === 'active' ? 'border-sky-400/70 bg-sky-400/[0.10] shadow-sky-400/20'
            : scanState === 'ok' ? 'border-emerald-500/40 bg-emerald-500/[0.07]'
              : selected ? 'border-emerald-400/50 bg-zinc-900/90 shadow-emerald-500/10' : 'border-white/[0.09] bg-zinc-900/70')}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-bold tabular-nums text-zinc-400">#{block.index}</span>
        {!valid ? <ShieldX className="size-4 text-red-400" aria-hidden="true" />
          : scanned ? <CheckCircle2 className="size-4 text-emerald-400" aria-hidden="true" />
            : <Icon className="size-4 text-zinc-500" aria-hidden="true" />}
      </div>
      <p className={cx('mt-1.5 line-clamp-2 min-h-10 text-sm font-medium leading-snug', valid ? 'text-zinc-100' : 'text-red-200')}>{label}</p>
      <div className="mt-2 space-y-1">
        <HashChip value={block.previous_hash} n={6} label="prev" className="w-full" />
        <HashChip value={block.block_hash} n={6} label="this" className="w-full" />
      </div>
    </button>
  );
}

function Connector({ ok }) {
  return (
    <div className="flex shrink-0 items-center self-center" aria-hidden="true">
      <span className={cx('h-0.5 w-4', ok ? 'bg-gradient-to-r from-emerald-500/30 to-emerald-400/70' : 'bg-red-500/70')} />
      <span className={cx('grid size-7 place-items-center rounded-full ring-1',
        ok ? 'bg-emerald-500/10 ring-emerald-500/40' : 'animate-pulse bg-red-500/20 ring-red-500/60')}>
        {ok ? <Link2 className="size-3.5 text-emerald-300" /> : <Link2Off className="size-3.5 text-red-300" />}
      </span>
      <span className={cx('h-0.5 w-4', ok ? 'bg-gradient-to-r from-emerald-400/70 to-emerald-500/30' : 'bg-red-500/70')} />
    </div>
  );
}

// ----------------------------------------------------------- block detail --

function BlockDetail({ block }) {
  const [showData, setShowData] = useState(false);
  if (!block) return null;
  const v = block.verification || { valid: true, checks: {}, reasons: [] };
  const [label, Icon] = eventOf(block);
  const scanId = block.payload?.scan_id || block.payload?.job_id;
  return (
    <Card className={cx('animate-fade-in', !v.valid && 'border-red-500/40')}>
      <CardHeader icon={Icon} title={`Block #${block.index} — ${label}`}
        subtitle={`${dateTime(block.timestamp)} · by ${block.actor}`}
        action={scanId && (
          <Link to={`/results/${scanId}`} className="inline-flex items-center gap-1 text-sm text-emerald-300 hover:underline">
            Open the scan <ExternalLink className="size-3.5" aria-hidden="true" />
          </Link>
        )} />
      <div className="grid gap-6 p-5 lg:grid-cols-2">
        <div>
          <p className="mb-2 text-xs font-medium uppercase tracking-wider text-zinc-500">Checks</p>
          <ul className="space-y-2">
            {Object.entries(v.checks || {}).map(([k, ok]) => (
              <li key={k} className={cx('flex items-center gap-2 text-sm', ok ? 'text-zinc-200' : 'text-red-300')}>
                {ok ? <CheckCircle2 className="size-4 text-emerald-400" aria-hidden="true" /> : <XCircle className="size-4 text-red-400" aria-hidden="true" />}
                {CHECK_TEXT[k] || k}
              </li>
            ))}
          </ul>
          {!v.valid && v.reasons?.length > 0 && (
            <div className="mt-3 space-y-1 rounded-xl bg-red-500/10 p-3 text-sm text-red-200 ring-1 ring-red-500/30">
              {v.reasons.map((r) => <p key={r}>{r}</p>)}
            </div>
          )}
        </div>
        <dl className="space-y-3 text-sm">
          <div>
            <dt className="mb-1 text-xs text-zinc-500">Fingerprint of the previous block</dt>
            <dd><HashChip value={block.previous_hash} n={32} /></dd>
          </div>
          <div>
            <dt className="mb-1 text-xs text-zinc-500">This block’s fingerprint</dt>
            <dd><HashChip value={block.block_hash} n={32} /></dd>
          </div>
          <div className="flex items-center gap-2 text-xs text-zinc-500">
            <KeyRound className="size-3.5" aria-hidden="true" />Signed with key <span className="font-mono text-zinc-300">{block.key_id}</span>
          </div>
          <button type="button" onClick={() => setShowData((x) => !x)} className="text-xs text-sky-300 hover:underline">
            {showData ? 'Hide' : 'Show'} the recorded data
          </button>
          {showData && (
            <pre className="scroll-thin max-h-56 overflow-auto rounded-xl bg-black/40 p-3 font-mono text-[11px] leading-relaxed text-zinc-300 ring-1 ring-white/[0.06]">
              {JSON.stringify(block.payload, null, 2)}
            </pre>
          )}
        </dl>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------- attacker panel --

const MODES = [
  { id: 'edit_payload', title: 'Change the record', text: 'Quietly edit what the block says, as someone with database access could.' },
  { id: 'rewrite_block', title: 'Change it and cover the tracks', text: 'Edit the record and recompute its fingerprint so it looks consistent.' },
];

function AttackerPanel({ block, chainValid, onDone }) {
  const [mode, setMode] = useState('rewrite_block');
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [last, setLast] = useState(null);

  const run = async (kind) => {
    setBusy(kind);
    setError(null);
    try {
      if (kind === 'tamper') {
        const r = await api.post('/audit/demo/tamper', { block_index: block.index, mode });
        setLast({ index: r.tampered_block, mode });
        await onDone(r.tampered_block);
      } else {
        await api.post('/audit/demo/restore');
        setLast(null);
        await onDone(null);
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(null);
    }
  };

  const canTamper = block && block.index >= 1 && chainValid;
  return (
    <Card className="overflow-hidden border-red-500/25">
      <div className="bg-gradient-to-r from-red-500/[0.12] via-red-500/[0.04] to-transparent">
        <CardHeader icon={Skull} title="Play the attacker"
          subtitle="Try to secretly rewrite history. Pick a block in the chain above, choose how sneaky to be, and see if you get caught." />
      </div>
      <div className="space-y-4 p-5">
        <div className="grid gap-3 sm:grid-cols-2">
          {MODES.map((m) => (
            <button key={m.id} type="button" onClick={() => setMode(m.id)} aria-pressed={mode === m.id}
              className={cx('rounded-xl p-4 text-left ring-1 transition',
                mode === m.id ? 'bg-red-500/10 ring-red-400/50' : 'bg-white/[0.02] ring-white/10 hover:ring-white/20')}>
              <p className={cx('text-sm font-semibold', mode === m.id ? 'text-red-200' : 'text-zinc-200')}>{m.title}</p>
              <p className="mt-1 text-xs leading-relaxed text-zinc-400">{m.text}</p>
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="danger" onClick={() => run('tamper')} loading={busy === 'tamper'} disabled={!canTamper || busy}>
            <Skull className="size-4" aria-hidden="true" />
            {block ? `Tamper with block #${block.index}` : 'Select a block first'}
          </Button>
          <Button variant="secondary" onClick={() => run('restore')} loading={busy === 'restore'} disabled={busy}>
            <RotateCcw className="size-4" aria-hidden="true" />Restore the chain
          </Button>
          {block?.index === 0 && <span className="text-xs text-zinc-500">The first block can’t be tampered with in the demo. Pick another.</span>}
          {!chainValid && <span className="text-xs text-amber-300">The chain is already broken. Restore it to try again.</span>}
        </div>
        <ErrorBox error={error} />
        {last && (
          <div className="animate-fade-in rounded-xl bg-black/25 p-4 text-sm leading-relaxed text-zinc-300 ring-1 ring-white/[0.06]">
            <p className="mb-1 font-semibold text-zinc-100">Why you got caught</p>
            {last.mode === 'edit_payload'
              ? <p>You changed block #{last.index}’s data, but its fingerprint was computed from the old data, so they no longer match.</p>
              : <p>You even recomputed block #{last.index}’s fingerprint. But it needs a digital signature that only the server’s private key can make, and block #{last.index + 1} still points to the <em>old</em> fingerprint, so the link breaks.</p>}
          </div>
        )}
      </div>
    </Card>
  );
}

// ------------------------------------------------------------------- page --

export default function Chain() {
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [items, setItems] = useState([]); // oldest -> newest
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [scanPos, setScanPos] = useState(null); // animated verification cursor
  const [result, setResult] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [demoEnabled, setDemoEnabled] = useState(false);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [checkpoint, setCheckpoint] = useState(readCheckpoint);
  const stripRef = useRef(null);

  // A signed statement of the newest block, kept outside the server, reveals blocks deleted later.
  const saveCheckpoint = async () => {
    try {
      const h = await api.get('/audit/head');
      if (!h?.head) return;
      try { localStorage.setItem(CHECKPOINT_KEY, JSON.stringify(h)); } catch { /* storage unavailable */ }
      setCheckpoint(h);
    } catch (err) {
      setError(err);
    }
  };

  const load = useCallback(async (focus) => {
    try {
      const d = await api.get('/audit/blocks', { limit: PAGE, offset: 0 });
      const list = d.items.slice().reverse();
      setData(d);
      setItems(list);
      setError(null);
      const target = (focus !== undefined && focus !== null && list.find((b) => b.index === focus))
        || list.find((b) => b.verification?.valid === false);
      setSelected((cur) => (target ? target.index : cur ?? list[list.length - 1]?.index ?? null));
      return list;
    } catch (err) {
      setError(err);
      return [];
    }
  }, []);

  useEffect(() => {
    load();
    api.get('/health').then((h) => setDemoEnabled(Boolean(h.demo_enabled))).catch(() => {});
  }, [load]);

  // Keep the selected block in view.
  useEffect(() => {
    const el = stripRef.current?.querySelector(`[data-index="${selected}"]`);
    el?.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
  }, [selected, items]);

  const loadOlder = async () => {
    setLoadingOlder(true);
    try {
      const d = await api.get('/audit/blocks', { limit: PAGE, offset: items.length });
      setItems((cur) => [...d.items.slice().reverse(), ...cur]);
    } catch (err) {
      setError(err);
    } finally {
      setLoadingOlder(false);
    }
  };

  // Verify on the server, then replay the check block by block so the audience can follow it.
  const verify = async () => {
    setVerifying(true);
    setResult(null);
    try {
      const r = await api.post('/audit/verify', checkpoint?.head ? { expected_head: checkpoint.head } : undefined);
      const firstBad = r.valid ? null : r.first_invalid_index;
      const stopAt = firstBad === null ? items.length : Math.max(0, items.findIndex((b) => b.index === firstBad));
      const stride = Math.max(1, Math.ceil(items.length / 45));
      for (let i = 0; i <= Math.min(stopAt, items.length - 1); i += stride) {
        setScanPos(i);
        const el = stripRef.current?.querySelector(`[data-index="${items[i].index}"]`);
        el?.scrollIntoView({ block: 'nearest', inline: 'center' });
        await new Promise((res) => setTimeout(res, 45));
      }
      setScanPos(firstBad === null ? items.length : stopAt);
      setResult(r);
      await load(firstBad);
    } catch (err) {
      setError(err);
    } finally {
      setVerifying(false);
      setTimeout(() => setScanPos(null), 2500);
    }
  };

  const chain = data?.chain;
  const total = data?.total || 0;
  const selectedBlock = items.find((b) => b.index === selected);
  const isAdmin = user?.role === 'admin';
  const broken = chain && !chain.valid;

  const scanStateOf = (i, b) => {
    if (scanPos === null) return null;
    if (b.verification?.valid === false) return 'bad';
    if (i < scanPos) return 'ok';
    if (i === scanPos) return 'active';
    return null;
  };

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        eyebrow="Tamper-proof history"
        title="Blockchain"
        description="Everything that happens is saved as a block. Each block holds the fingerprint of the block before it, like links in a chain. Change any old block and the chain visibly breaks."
        action={(
          <Button size="lg" onClick={verify} loading={verifying} disabled={!items.length}>
            <ShieldCheck className="size-5" aria-hidden="true" />Verify the whole chain
          </Button>
        )}
      />

      {result?.truncation_detected && (
        <Banner tone="bad" icon={ShieldX} pulse title="Blocks were deleted or replaced">
          The chain no longer contains the block saved in your checkpoint (block #{checkpoint?.head?.index}). Someone removed or rewrote history after it was saved.
        </Banner>
      )}

      {chain && (broken ? (
        <Banner tone="bad" icon={ShieldX} pulse title={`Chain broken at block #${chain.first_invalid_index}`}>
          Someone changed history. Block #{chain.first_invalid_index} no longer matches its fingerprint or signature, so every block after it
          can no longer be trusted. Click the red block to see exactly what failed.
        </Banner>
      ) : (
        <Banner tone="good" icon={ShieldCheck} title={result?.valid ? `Verified: all ${result.length} blocks checked, nothing was changed` : 'Chain intact'}>
          {result?.valid && chain.length > result.length
            ? `The check itself was then recorded as a new block, so the chain now has ${chain.length} blocks, each signed and linked to the one before it.`
            : `${chain.length} blocks, each signed and linked to the one before it, all the way back to the first.`}
        </Banner>
      ))}

      <ErrorBox error={error} />

      {!data && !error && <Spinner label="Loading the chain…" />}

      {items.length > 0 && (
        <Card className="p-4">
          <div className="mb-3 flex flex-wrap items-center gap-3 px-1">
            <p className="text-sm font-medium text-zinc-200">The chain <span className="text-zinc-500">· oldest → newest</span></p>
            <p className="text-xs text-zinc-500">Matching colours = matching fingerprints. Each “prev” should match the “this” of the block before.</p>
          </div>
          <div ref={stripRef} className="scroll-thin flex items-stretch overflow-x-auto px-1 pb-3 pt-2">
            {items.length < total && (
              <button type="button" onClick={loadOlder} disabled={loadingOlder}
                className="mr-3 flex w-24 shrink-0 flex-col items-center justify-center gap-1 rounded-2xl border border-dashed border-white/15 text-xs text-zinc-400 hover:text-zinc-100">
                <ChevronLeft className="size-4" aria-hidden="true" />{loadingOlder ? 'Loading…' : 'Older blocks'}
              </button>
            )}
            {items.map((b, i) => (
              <div key={b.index} className="flex shrink-0">
                {i > 0 && <Connector ok={b.verification?.checks?.link !== false} />}
                <BlockTile block={b} selected={b.index === selected} scanState={scanStateOf(i, b)} onClick={() => setSelected(b.index)} />
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card className="flex flex-wrap items-center gap-3 p-4">
        <Bookmark className="size-4 text-sky-300" aria-hidden="true" />
        <p className="min-w-0 flex-1 basis-60 text-sm text-zinc-300">
          {checkpoint?.head
            ? <>Checkpoint saved at block #{checkpoint.head.index} ({dateTime(checkpoint.head.issued_at)}). Every check now also confirms that no blocks up to there were deleted.</>
            : <>Save a signed checkpoint of the newest block in this browser. Later checks will then also catch deleted blocks, not only edited ones.</>}
        </p>
        <Button variant="secondary" size="sm" onClick={saveCheckpoint}>{checkpoint?.head ? 'Update checkpoint' : 'Save checkpoint'}</Button>
      </Card>

      <BlockDetail block={selectedBlock} />

      {isAdmin && demoEnabled && <AttackerPanel block={selectedBlock} chainValid={chain?.valid !== false} onDone={load} />}
      {isAdmin && !demoEnabled && data && (
        <p className="text-center text-xs text-zinc-500">The “Play the attacker” demo is switched off on this server.</p>
      )}

      <Explain title="Why can’t anyone secretly edit this?">
        <p><strong className="text-zinc-100">Fingerprints:</strong> each block’s fingerprint (SHA-256) is computed from everything inside it. Edit one character and the fingerprint changes.</p>
        <p><strong className="text-zinc-100">Links:</strong> every block stores the previous block’s fingerprint. Changing an old block breaks the link to the next one.</p>
        <p><strong className="text-zinc-100">Signatures:</strong> every block is signed with the server’s private key (ECDSA). An attacker can recompute a hash, but cannot forge a signature.</p>
        <p className="text-xs text-zinc-500">{data?.notice}</p>
      </Explain>
    </div>
  );
}
