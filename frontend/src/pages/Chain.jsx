import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Blocks, CheckCircle2, ExternalLink, Link2, ShieldCheck, User, XCircle } from 'lucide-react';
import { Button, Card, CopyHash, Empty, ErrorBox, PageHeader, Spinner, ToneBadge, cx } from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { dateTime, shortHash } from '../lib/format.js';

const PAGE = 25;

// The backend's labels predate non-APK content; these read correctly for any file.
const LABELS = {
  APK_UPLOADED: 'File uploaded',
  ANALYSIS_COMPLETED: 'File analysed & sealed',
  INTEGRITY_ALERT: 'Integrity problem detected',
};

const EVENT_TONE = {
  GENESIS: 'good', ANALYSIS_COMPLETED: 'good', BASELINE_APPROVED: 'good', CHAIN_VERIFIED: 'good', REPORT_VERIFIED: 'good',
  INTEGRITY_ALERT: 'bad', LOGIN_FAILED: 'warn', AUDIT_TAMPER_DEMO: 'bad', BASELINE_REVOKED: 'warn', BASELINE_REJECTED: 'warn',
};

function BlockCard({ block, last }) {
  const valid = block.verification?.valid !== false;
  const scanId = block.payload?.scan_id || block.payload?.job_id;
  return (
    <li className="relative pl-10 sm:pl-12">
      {!last && <span className="absolute left-[15px] top-10 h-[calc(100%-1.5rem)] w-px bg-gradient-to-b from-white/15 to-white/[0.03] sm:left-[19px]" aria-hidden="true" />}
      <span className={cx('absolute left-0 top-3 grid size-8 place-items-center rounded-full ring-1 sm:size-10',
        valid ? 'bg-zinc-900 ring-white/15' : 'bg-red-500/15 ring-red-500/50')}>
        <span className="text-[11px] font-semibold tabular-nums text-zinc-300">#{block.index}</span>
      </span>
      <Card className={cx('mb-4 p-4 transition hover:border-white/[0.12]', !valid && 'border-red-500/40')}>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold text-zinc-100">Block #{block.index}</span>
          <ToneBadge tone={EVENT_TONE[block.event_type] || 'neutral'}>{block.event_type}</ToneBadge>
          <span className="text-sm text-zinc-400">{LABELS[block.event_type] || block.event_label}</span>
          <span className="ml-auto flex items-center gap-1 text-xs">
            {valid
              ? <><CheckCircle2 className="size-3.5 text-emerald-400" aria-hidden="true" /><span className="text-emerald-300">Verified</span></>
              : <><XCircle className="size-3.5 text-red-400" aria-hidden="true" /><span className="text-red-300">Broken</span></>}
          </span>
        </div>
        <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
          <span>{dateTime(block.timestamp)}</span>
          <span className="flex items-center gap-1"><User className="size-3" aria-hidden="true" />{block.actor}</span>
          {scanId && (
            <Link to={`/results/${scanId}`} className="flex items-center gap-1 text-emerald-400 hover:underline">
              View scan <ExternalLink className="size-3" aria-hidden="true" />
            </Link>
          )}
        </div>
        <div className="mt-3 grid items-center gap-2 rounded-xl bg-black/25 p-3 ring-1 ring-white/[0.05] md:grid-cols-[1fr_auto_1fr]">
          <div className="min-w-0">
            <p className="mb-1 text-[11px] uppercase tracking-wide text-zinc-500">Previous block hash</p>
            <CopyHash value={block.previous_hash} display={shortHash(block.previous_hash, 12)} className="w-full" />
          </div>
          <ArrowRight className="mx-auto size-4 rotate-90 text-zinc-600 md:rotate-0" aria-hidden="true" />
          <div className="min-w-0">
            <p className="mb-1 text-[11px] uppercase tracking-wide text-zinc-500">This block’s hash</p>
            <CopyHash value={block.block_hash} display={shortHash(block.block_hash, 12)} className="w-full" />
          </div>
        </div>
        {!valid && block.verification?.reasons?.length > 0 && (
          <p className="mt-2 text-xs text-red-300">{block.verification.reasons.join(' ')}</p>
        )}
      </Card>
    </li>
  );
}

export default function Chain() {
  const [data, setData] = useState(null);
  const [items, setItems] = useState([]);
  const [error, setError] = useState(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState(null);

  const load = useCallback(async () => {
    try {
      const d = await api.get('/audit/blocks', { limit: PAGE, offset: 0 });
      setData(d);
      setItems(d.items);
      setError(null);
    } catch (err) {
      setError(err);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const more = async () => {
    setLoadingMore(true);
    try {
      const d = await api.get('/audit/blocks', { limit: PAGE, offset: items.length });
      setItems((cur) => [...cur, ...d.items]);
    } catch (err) {
      setError(err);
    } finally {
      setLoadingMore(false);
    }
  };

  const verify = async () => {
    setVerifying(true);
    setResult(null);
    try {
      const r = await api.post('/audit/verify');
      setResult(r);
      await load(); // a successful check is itself recorded as a new block
    } catch (err) {
      setError(err);
    } finally {
      setVerifying(false);
    }
  };

  const chain = data?.chain;
  return (
    <div className="animate-fade-in">
      <PageHeader
        title="Audit Ledger"
        description="Every upload, analysis and approval is written as a signed block that contains the fingerprint of the block before it. Changing any old record breaks every link after it — so tampering is always visible."
        action={<Button onClick={verify} loading={verifying}><ShieldCheck className="size-4" aria-hidden="true" />Verify Whole Chain</Button>}
      />

      {result && (
        <div role="status" className={cx('mb-6 flex items-start gap-3 rounded-2xl border px-5 py-4 animate-fade-in',
          result.valid ? 'border-emerald-500/30 bg-emerald-500/[0.08]' : 'border-red-500/30 bg-red-500/[0.08]')}>
          {result.valid
            ? <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-emerald-400" aria-hidden="true" />
            : <XCircle className="mt-0.5 size-5 shrink-0 text-red-400" aria-hidden="true" />}
          <div>
            <p className={cx('font-medium', result.valid ? 'text-emerald-200' : 'text-red-200')}>
              {result.valid
                ? `Chain Valid: all ${result.length} blocks mathematically verified against genesis.`
                : 'Chain Broken: the history has been altered.'}
            </p>
            <p className="mt-0.5 text-sm text-zinc-400">{result.summary}</p>
          </div>
        </div>
      )}

      <ErrorBox error={error} className="mb-6" />

      {chain && (
        <div className="mb-6 grid gap-4 sm:grid-cols-3">
          <Card className="p-4">
            <p className="text-xs text-zinc-500">Blocks in the chain</p>
            <p className="mt-1 text-2xl font-semibold tabular-nums text-zinc-50">{chain.length}</p>
          </Card>
          <Card className="p-4">
            <p className="text-xs text-zinc-500">Current status</p>
            <p className={cx('mt-1 flex items-center gap-1.5 text-lg font-semibold', chain.valid ? 'text-emerald-300' : 'text-red-300')}>
              {chain.valid ? <CheckCircle2 className="size-5" aria-hidden="true" /> : <XCircle className="size-5" aria-hidden="true" />}
              {chain.valid ? 'Intact' : `Broken at #${chain.first_invalid_index}`}
            </p>
          </Card>
          <Card className="min-w-0 p-4">
            <p className="text-xs text-zinc-500">Latest block hash</p>
            <div className="mt-2"><CopyHash value={chain.head?.block_hash} display={shortHash(chain.head?.block_hash, 10)} /></div>
          </Card>
        </div>
      )}

      {!data && !error && <Spinner label="Loading ledger…" />}
      {data && items.length === 0 && <Card><Empty icon={Blocks} title="The ledger is empty" /></Card>}
      {items.length > 0 && (
        <>
          <p className="mb-3 flex items-center gap-2 text-xs text-zinc-500"><Link2 className="size-3.5" aria-hidden="true" />Newest first</p>
          <ol>{items.map((b, i) => <BlockCard key={b.index} block={b} last={i === items.length - 1} />)}</ol>
          {items.length < (data?.total || 0) && (
            <div className="text-center">
              <Button variant="secondary" onClick={more} loading={loadingMore}>Load older blocks</Button>
            </div>
          )}
        </>
      )}
      {data?.notice && <p className="mt-8 text-center text-xs text-zinc-600">{data.notice}</p>}
    </div>
  );
}
