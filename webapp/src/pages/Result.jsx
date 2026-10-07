import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  ArrowLeft, BadgeCheck, CheckCircle2, ChevronDown, FileSearch, Fingerprint, KeyRound, Link2, ListFilter,
  ShieldAlert, ShieldCheck, ShieldQuestion, ShieldX, XCircle,
} from 'lucide-react';
import ScanSteps from '../components/ScanSteps.jsx';
import TrustGauge from '../components/TrustGauge.jsx';
import {
  Button, Card, CardHeader, CopyHash, Empty, ErrorBox, FileTypeBadge, InfoTip, SeverityBadge, Spinner, ToneBadge, cx,
} from '../components/ui.jsx';
import { api } from '../lib/api.js';
import {
  SEVERITIES, SEVERITY_STYLE, TONES, bytes, dateTime, overallTone, shortHash, trustLabel, trustScore, verdictLabel,
} from '../lib/format.js';

const TONE_ICON = { good: ShieldCheck, warn: ShieldAlert, bad: ShieldX, neutral: ShieldQuestion };

const BASELINE_TEXT = {
  CLEAN: ['good', 'Matches the trusted master copy'],
  MODIFIED: ['bad', 'Differs from the trusted master copy'],
  CERTIFICATE_CHANGED: ['bad', 'Signed by a different developer key'],
  BASELINE_INVALID: ['bad', 'Stored master copy failed verification'],
  NO_BASELINE: ['warn', 'No trusted master copy to compare with'],
  NOT_APPLICABLE: ['neutral', 'Not applicable (no master copy for this file type)'],
  UNKNOWN: ['neutral', 'Comparison did not run'],
};

const APP_SIGNATURE_TEXT = {
  verified: ['good', 'Developer signature valid'],
  invalid: ['bad', 'Developer signature broken'],
  unsigned: ['bad', 'Not signed by any developer'],
  unverifiable: ['warn', 'Signature algorithm cannot be checked'],
};

function useScan(jobId) {
  const [scan, setScan] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let alive = true;
    setScan(null);
    setReport(null);
    setError(null);
    (async () => {
      try {
        for (let i = 0; i < 900 && alive; i += 1) {
          const s = await api.get(`/scans/${jobId}`);
          if (!alive) return;
          setScan(s);
          if (s.status === 'done' || s.status === 'failed') break;
          await new Promise((r) => setTimeout(r, 1000));
        }
        const r = await api.get(`/scans/${jobId}/report`);
        if (alive) setReport(r);
      } catch (err) {
        if (alive) setError(err);
      }
    })();
    return () => { alive = false; };
  }, [jobId]);

  return { scan, report, error };
}

// --------------------------------------------------------------- summary --

function SummaryCard({ scan, report }) {
  const r = report.reports || {};
  const score = r.score || {};
  const trust = trustScore(score.risk?.score);
  const verdict = score.verdict?.code;
  const integrityStatus = score.integrity?.status;
  const tone = overallTone(trust, verdict);
  const t = TONES[tone];
  const Icon = TONE_ICON[tone];
  const category = report.file_category || 'apk';

  return (
    <Card className={cx('overflow-hidden shadow-2xl', t.glow)}>
      <div className="grid gap-6 p-6 md:grid-cols-[auto_1fr] md:items-center">
        <div className="mx-auto"><TrustGauge value={trust} tone={tone} label={trustLabel(trust)} /></div>
        <div className="min-w-0 space-y-4">
          <div>
            <ToneBadge tone={tone} icon={Icon}>{verdictLabel(verdict, integrityStatus)}</ToneBadge>
            <h1 className="mt-3 text-xl font-semibold tracking-tight text-zinc-50 sm:text-2xl">
              {score.verdict?.headline || 'Analysis finished'}
            </h1>
            <p className="mt-1 text-sm leading-relaxed text-zinc-400">{score.verdict?.summary}</p>
          </div>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-4">
            <div className="col-span-2 min-w-0 sm:col-span-4">
              <dt className="text-xs text-zinc-500">File</dt>
              <dd className="truncate font-medium text-zinc-100" title={scan.filename}>{scan.filename}</dd>
            </div>
            <div>
              <dt className="text-xs text-zinc-500">Type</dt>
              <dd className="mt-0.5"><FileTypeBadge category={category} /></dd>
            </div>
            <div>
              <dt className="text-xs text-zinc-500">Size</dt>
              <dd className="text-zinc-200">{bytes(r.integrity?.file_size)}</dd>
            </div>
            <div>
              <dt className="text-xs text-zinc-500">Scanned</dt>
              <dd className="text-zinc-200">{dateTime(scan.completed_at || scan.created_at)}</dd>
            </div>
            <div>
              <dt className="flex items-center gap-1 text-xs text-zinc-500">
                Risk points <InfoTip text="The trust score is 100 minus the risk points the findings below add up to (capped at 100)." />
              </dt>
              <dd className="text-zinc-200">{score.risk?.score ?? '—'}</dd>
            </div>
            {scan.package_name && (
              <div className="col-span-2 min-w-0">
                <dt className="text-xs text-zinc-500">App package</dt>
                <dd className="truncate font-mono text-xs text-zinc-300">{scan.package_name}</dd>
              </div>
            )}
          </dl>
        </div>
      </div>
      {(score.notes?.length > 0 || Object.keys(report.errors || {}).length > 0) && (
        <div className="space-y-1 border-t border-white/[0.06] bg-black/20 px-6 py-3 text-xs text-zinc-400">
          {score.notes?.map((n) => <p key={n}>• {n}</p>)}
          {Object.entries(report.errors || {}).map(([k, v]) => <p key={k} className="text-amber-300">• {k}: {v}</p>)}
        </div>
      )}
    </Card>
  );
}

// ------------------------------------------------------------- integrity --

function Row({ label, tip, children }) {
  return (
    <div className="grid gap-1.5 py-3 sm:grid-cols-[200px_1fr] sm:items-center sm:gap-4">
      <dt className="flex items-center gap-1.5 text-xs font-medium text-zinc-400">{label}{tip && <InfoTip text={tip} />}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}

function StatusLine({ map, status }) {
  const [tone, text] = map[status] || ['neutral', status || 'Not available'];
  const Icon = { good: CheckCircle2, bad: XCircle, warn: ShieldAlert, neutral: ShieldQuestion }[tone];
  return <span className={cx('inline-flex items-center gap-1.5 text-sm', TONES[tone].text)}><Icon className="size-4" aria-hidden="true" />{text}</span>;
}

function IntegrityCard({ jobId, report }) {
  const r = report.reports || {};
  const integ = r.integrity || {};
  const repo = r.repository;
  const isApk = (report.file_category || 'apk') === 'apk';
  const [check, setCheck] = useState(null);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState(null);

  const verify = useCallback(async () => {
    setChecking(true);
    setCheckError(null);
    try {
      setCheck(await api.post(`/scans/${jobId}/verify`));
    } catch (err) {
      setCheckError(err);
    } finally {
      setChecking(false);
    }
  }, [jobId]);

  const primaryRoot = isApk ? integ.merkle_root : integ.chunk_merkle_root;

  return (
    <Card>
      <CardHeader icon={Fingerprint} title="Integrity & Authenticity"
        subtitle="The cryptographic proof that this exact file was analysed and that the result has not been changed since." />
      <dl className="divide-y divide-white/[0.05] px-5">
        <Row label="Merkle root (file fingerprint)"
          tip={isApk
            ? 'A unique fingerprint built from the SHA-256 of every file inside the app. If even one file changes, this fingerprint changes completely.'
            : 'A unique fingerprint representing every chunk of this file. If even a single byte changes, this fingerprint changes completely.'}>
          <CopyHash value={primaryRoot} display={shortHash(primaryRoot, 16)} />
        </Row>
        {isApk && (
          <Row label="Chunk fingerprint" tip="The same idea applied to the raw bytes in 64 KB pieces. Used to locate where a change happened.">
            <CopyHash value={integ.chunk_merkle_root} display={shortHash(integ.chunk_merkle_root, 16)} />
          </Row>
        )}
        <Row label="SHA-256 of the whole file" tip="A standard fingerprint of the complete file. Anyone can recompute it with common tools (e.g. sha256sum) to confirm they have the same file.">
          <CopyHash value={integ.sha256} display={shortHash(integ.sha256, 16)} />
        </Row>
        <Row label="How it was fingerprinted">
          <span className="text-sm text-zinc-300">
            {isApk ? `${integ.file_count ?? '—'} files inside the app, and ` : ''}
            {integ.chunk_count ?? '—'} chunk{integ.chunk_count === 1 ? '' : 's'} of {bytes(integ.chunk_size)} in a Merkle tree {integ.tree_depth ?? '—'} levels deep
          </span>
        </Row>
        {isApk && (
          <>
            <Row label="Trusted master copy" tip="Compared with the administrator-approved original of this app (a baseline).">
              <StatusLine map={BASELINE_TEXT} status={r.tamper?.integrity?.status} />
            </Row>
            <Row label="App signature" tip="Android apps are signed by their developer. A broken signature means the app was changed after signing.">
              <StatusLine map={APP_SIGNATURE_TEXT} status={r.static?.signature?.status} />
            </Row>
          </>
        )}
      </dl>

      <div className="m-5 mt-2 rounded-xl border p-4 transition-colors
        data-[ok=true]:border-emerald-500/25 data-[ok=true]:bg-emerald-500/[0.06] data-[ok=false]:border-red-500/25 data-[ok=false]:bg-red-500/[0.06]"
        data-ok={Boolean(repo)}>
        {repo ? (
          <div className="flex flex-wrap items-start gap-3">
            <span className="grid size-10 shrink-0 place-items-center rounded-full bg-emerald-500/15 ring-1 ring-emerald-500/40">
              <BadgeCheck className="size-5 text-emerald-300" aria-hidden="true" />
            </span>
            <div className="min-w-0 flex-1 space-y-1">
              <p className="text-sm font-semibold text-emerald-200">Digitally signed & recorded</p>
              <p className="text-sm text-zinc-300">
                Signed with an ECDSA P-256 private key. Proof of non-repudiation recorded in{' '}
                <Link to="/chain" className="text-emerald-300 underline-offset-2 hover:underline">audit block #{repo.block_index}</Link>.
              </p>
              <div className="flex flex-wrap gap-x-4 gap-y-1 pt-1 text-xs text-zinc-500">
                <span className="flex items-center gap-1"><KeyRound className="size-3.5" aria-hidden="true" /> Key {repo.key_id}</span>
                <span className="flex items-center gap-1"><Link2 className="size-3.5" aria-hidden="true" /> Block {shortHash(repo.block_hash)}</span>
                <span>{dateTime(repo.timestamp)}</span>
              </div>
            </div>
            <Button variant="secondary" onClick={verify} loading={checking}>
              <ShieldCheck className="size-4" aria-hidden="true" /> Verify now
            </Button>
          </div>
        ) : (
          <p className="flex items-center gap-2 text-sm text-red-200">
            <XCircle className="size-4" aria-hidden="true" /> This result was not sealed in the audit ledger.
          </p>
        )}
        {check && (
          <div className={cx('mt-3 rounded-lg px-3 py-2 text-sm animate-fade-in', check.valid ? 'bg-emerald-500/10 text-emerald-200' : 'bg-red-500/10 text-red-200')}>
            {check.valid
              ? '✅ Verified: the stored report matches its sealed fingerprint, the signature is valid and the ledger is intact.'
              : `❌ Verification failed: ${(check.reasons || []).join(' ') || 'the report does not match its sealed record.'}`}
          </div>
        )}
        <ErrorBox error={checkError} className="mt-3" />
      </div>
    </Card>
  );
}

// -------------------------------------------------------------- findings --

function Finding({ f }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="px-5 py-4">
      <button type="button" onClick={() => setOpen((v) => !v)} aria-expanded={open}
        className="flex w-full items-start gap-3 text-left">
        <SeverityBadge severity={f.severity} />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-zinc-100">{f.title}</p>
          <p className="mt-1 text-sm leading-relaxed text-zinc-400">{f.explanation}</p>
        </div>
        <ChevronDown className={cx('mt-0.5 size-4 shrink-0 text-zinc-500 transition', open && 'rotate-180')} aria-hidden="true" />
      </button>
      {open && (
        <div className="mt-3 space-y-3 pl-0 text-sm animate-fade-in sm:pl-[72px]">
          {f.evidence && (
            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">What was found</p>
              <p className="mt-1 break-words rounded-lg bg-black/30 px-3 py-2 font-mono text-xs leading-relaxed text-zinc-300">{f.evidence}</p>
            </div>
          )}
          {f.recommendation && (
            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">What to do</p>
              <p className="mt-1 text-zinc-300">{f.recommendation}</p>
            </div>
          )}
          <p className="text-xs text-zinc-500">
            {f.technical} · reported by the {f.source} check{f.points > 0 ? ` · ${f.points} risk points` : ''}
          </p>
        </div>
      )}
    </li>
  );
}

function FindingsCard({ findings }) {
  const counts = useMemo(() => Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length])), [findings]);
  const hasIssues = findings.some((f) => f.severity !== 'info');
  const [filter, setFilter] = useState('issues');
  const shown = findings.filter((f) => (filter === 'all' ? true : filter === 'issues' ? f.severity !== 'info' : f.severity === filter));

  const chip = (key, label, count, style) => (
    <button key={key} type="button" onClick={() => setFilter(key)} aria-pressed={filter === key}
      className={cx('inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ring-1 ring-inset transition',
        filter === key ? style || 'bg-white/10 text-zinc-100 ring-white/20' : 'text-zinc-400 ring-white/10 hover:text-zinc-200')}>
      {label}<span className="tabular-nums opacity-70">{count}</span>
    </button>
  );

  return (
    <Card>
      <CardHeader icon={FileSearch} title="Security Findings"
        subtitle="Everything the analysis noticed, explained in plain English. Click a finding for the evidence and what to do." />
      <div className="flex flex-wrap items-center gap-2 border-b border-white/[0.06] px-5 py-3">
        <ListFilter className="size-4 text-zinc-500" aria-hidden="true" />
        {chip('issues', 'Issues', findings.length - counts.info)}
        {SEVERITIES.map((s) => counts[s] > 0 && chip(s, s[0].toUpperCase() + s.slice(1), counts[s], SEVERITY_STYLE[s]))}
        {chip('all', 'All', findings.length)}
      </div>
      {shown.length === 0 ? (
        <Empty icon={hasIssues ? ListFilter : ShieldCheck} title={hasIssues ? 'Nothing at this level' : 'No security issues found'}>
          {hasIssues ? 'Choose another filter above.' : 'Only informational notes were recorded. Select “All” to see them.'}
        </Empty>
      ) : (
        <ul className="divide-y divide-white/[0.05]">
          {shown.map((f, i) => <Finding key={`${f.id}-${f.source}-${i}`} f={f} />)}
        </ul>
      )}
    </Card>
  );
}

// ------------------------------------------------------------------ page --

export default function Result() {
  const { jobId } = useParams();
  const { scan, report, error } = useScan(jobId);

  const back = (
    <Link to="/history" className="mb-4 inline-flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-100">
      <ArrowLeft className="size-4" aria-hidden="true" /> Scan history
    </Link>
  );

  if (error) return <div>{back}<ErrorBox error={error} /></div>;
  if (!scan) return <Spinner label="Loading scan…" />;
  if (!report) {
    return (
      <div className="mx-auto max-w-xl animate-fade-in">
        {back}
        <Card className="p-6">
          <p className="mb-1 text-sm font-medium text-zinc-100">Analysing {scan.filename}</p>
          <p className="mb-4 text-xs text-zinc-500">This page updates automatically.</p>
          <ScanSteps scan={scan} />
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div>{back}<SummaryCard scan={scan} report={report} /></div>
      <IntegrityCard jobId={jobId} report={report} />
      <FindingsCard findings={report.reports?.score?.all_findings || []} />
    </div>
  );
}
