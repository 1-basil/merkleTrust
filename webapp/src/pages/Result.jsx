import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  ArrowDown, ArrowLeft, BadgeCheck, CheckCircle2, ChevronDown, Download, FileDiff, FileSearch, Fingerprint, Gauge,
  KeyRound, LayoutDashboard, Link2, ListFilter, Network, ShieldAlert, ShieldCheck, ShieldQuestion, ShieldX, XCircle,
} from 'lucide-react';
import ScanSteps from '../components/ScanSteps.jsx';
import TrustGauge from '../components/TrustGauge.jsx';
import {
  Banner, Button, Card, CardHeader, CopyHash, Empty, ErrorBox, Explain, FileTypeBadge, HashChip, InfoTip, SeverityBadge,
  Spinner, Tabs, ToneBadge, cx,
} from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { fileLeaf, foldProof, leafHash } from '../lib/merkle.js';
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
          {r.static?.threat_intel?.matches?.length > 0 && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3.5">
              <div className="flex items-center gap-2 text-xs font-semibold text-red-300">
                <ShieldAlert className="size-4 shrink-0 text-red-400" />
                <span>Threat Intelligence: {r.static.threat_intel.matches.length} C2 indicator match(es) detected</span>
              </div>
              <ul className="mt-1.5 space-y-1 text-xs text-red-200/80">
                {r.static.threat_intel.matches.map((m, idx) => (
                  <li key={idx} className="truncate">• <strong className="text-red-100">{m.threat_family}</strong> ({m.indicator})</li>
                ))}
              </ul>
            </div>
          )}
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
      <CardHeader icon={Fingerprint} title="Proof & seal"
        subtitle="Proof that this exact file was checked, and that nobody has changed the result since." />
      <dl className="divide-y divide-white/[0.05] px-5">
        <Row label="File fingerprint (Merkle root)"
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
            {r.static?.fuzzy_hash && (
              <Row label="Fuzzy hash (CTPH / ssdeep)" tip="Context Triggered Piecewise Hashing (Kornblum 2006). Enables near-duplicate detection across modified/repackaged builds.">
                <CopyHash value={r.static.fuzzy_hash} display={shortHash(r.static.fuzzy_hash, 24)} />
              </Row>
            )}
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
                Signed with the server’s private key (ECDSA P-256), so it can’t be forged or denied, and recorded in{' '}
                <Link to="/chain" className="text-emerald-300 underline-offset-2 hover:underline">blockchain block #{repo.block_index}</Link>.
              </p>
              <div className="flex flex-wrap gap-x-4 gap-y-1 pt-1 text-xs text-zinc-500">
                <span className="flex items-center gap-1"><KeyRound className="size-3.5" aria-hidden="true" /> Key {repo.key_id}</span>
                <span className="flex items-center gap-1"><Link2 className="size-3.5" aria-hidden="true" /> Block {shortHash(repo.block_hash)}</span>
                <span>{dateTime(repo.timestamp)}</span>
              </div>
            </div>
            <Button variant="secondary" onClick={verify} loading={checking}>
              <ShieldCheck className="size-4" aria-hidden="true" /> Check it again now
            </Button>
          </div>
        ) : (
          <p className="flex items-center gap-2 text-sm text-red-200">
            <XCircle className="size-4" aria-hidden="true" /> This result was not sealed in the blockchain.
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

// ----------------------------------------------------------- risk & answers --

const INTEGRITY_ANSWER = {
  CLEAN: ['good', 'Yes, it matches the trusted original'],
  MODIFIED: ['bad', 'No, files were changed'],
  CERTIFICATE_CHANGED: ['bad', 'No, signed by someone else'],
  BASELINE_INVALID: ['bad', 'Unknown, the trusted record failed its check'],
  NO_BASELINE: ['warn', 'Unknown, no trusted original to compare with'],
  NOT_APPLICABLE: ['neutral', 'Checked on its own (no original needed)'],
};
const RISK_ANSWER = {
  LOW: ['good', 'Low risk'], MEDIUM: ['warn', 'Some concerns'], HIGH: ['bad', 'High risk'], CRITICAL: ['bad', 'Critical risk'],
};

function Answers({ report }) {
  const score = report.reports?.score || {};
  const [iTone, iText] = INTEGRITY_ANSWER[score.integrity?.status] || ['neutral', score.integrity?.status || 'Not available'];
  const [rTone, rText] = RISK_ANSWER[score.risk?.level] || ['neutral', score.risk?.level || 'Not scored'];
  const contributions = score.risk?.contributions || [];
  const max = Math.max(1, ...contributions.map((c) => c.points));
  const Q = ({ q, tone, text, reason }) => (
    <Card className="p-5">
      <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">{q}</p>
      <p className={cx('mt-2 text-lg font-semibold', TONES[tone].text)}>{text}</p>
      {reason && <p className="mt-1 text-sm leading-relaxed text-zinc-400">{reason}</p>}
    </Card>
  );
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="grid content-start gap-4">
        <Q q="Is it the original?" tone={iTone} text={iText} reason={score.integrity?.reasons?.[0]} />
        <Q q="Is it safe?" tone={rTone} text={rText}
          reason={score.risk?.score === null || score.risk?.score === undefined ? null : `${score.risk.score} risk points. This is an explained warning level, not a malware probability.`} />
      </div>
      <Card>
        <CardHeader icon={Gauge} title="Where the risk points come from" subtitle="Each problem adds points. The same fact is never counted twice." />
        {contributions.length === 0 ? (
          <Empty icon={ShieldCheck} title="No risk points">Nothing concerning was found.</Empty>
        ) : (
          <ul className="space-y-3 p-5">
            {contributions.map((c) => (
              <li key={`${c.finding_id}-${c.title}`}>
                <div className="flex items-baseline justify-between gap-3 text-sm">
                  <span className="text-zinc-200">{c.title}</span>
                  <span className="shrink-0 font-semibold tabular-nums text-red-300">+{c.points}</span>
                </div>
                <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
                  <div className="h-full rounded-full bg-gradient-to-r from-amber-400 to-red-500" style={{ width: `${(c.points / max) * 100}%` }} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

// ------------------------------------------------------------- what changed --

const CHANGE_STYLE = {
  modified: ['Modified', 'text-red-200 bg-red-500/15 ring-red-500/40'],
  added: ['Added', 'text-amber-200 bg-amber-500/15 ring-amber-500/40'],
  deleted: ['Deleted', 'text-zinc-200 bg-zinc-500/20 ring-zinc-500/40'],
};

function FileProof({ jobId, path }) {
  const [state, setState] = useState({ loading: true });
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const p = await api.get(`/scans/${jobId}/files/proof`, { path });
        let trail = null;
        if (p.current_sha256 && p.baseline_sha256) {
          // Recompute the proof here in the browser instead of trusting the server's verdict.
          trail = await foldProof(await leafHash(fileLeaf(path, p.current_sha256)), p.proof);
        }
        if (alive) setState({ p, trail, valid: Boolean(trail && trail[trail.length - 1] === p.trusted_root) });
      } catch (err) {
        if (alive) setState({ error: err });
      }
    })();
    return () => { alive = false; };
  }, [jobId, path]);

  if (state.loading) return <p className="py-2 text-xs text-zinc-500">Building the proof…</p>;
  if (state.error) return <ErrorBox error={state.error} className="mt-2" />;
  const { p, trail, valid } = state;
  return (
    <div className="mt-3 animate-fade-in rounded-xl bg-black/30 p-4 ring-1 ring-white/[0.06]">
      {trail ? (
        <div className="space-y-2 text-xs">
          <div className="grid gap-2 sm:grid-cols-2">
            <div><p className="mb-1 text-zinc-500">Trusted fingerprint of this file</p><HashChip value={p.baseline_sha256} n={16} /></div>
            <div><p className="mb-1 text-zinc-500">This upload’s fingerprint</p><HashChip value={p.current_sha256} n={16} /></div>
          </div>
          <p className="flex items-center gap-1.5 pt-1 text-zinc-500">
            <ArrowDown className="size-3.5" aria-hidden="true" />
            Combined with {p.proof.length} neighbour hash{p.proof.length === 1 ? '' : 'es'} from the trusted tree, computed in your browser
          </p>
          <div className="grid gap-2 sm:grid-cols-2">
            <div><p className="mb-1 text-zinc-500">Root we arrive at</p><HashChip value={trail[trail.length - 1]} n={16} /></div>
            <div><p className="mb-1 text-zinc-500">Trusted root (signed)</p><HashChip value={p.trusted_root} n={16} /></div>
          </div>
        </div>
      ) : null}
      <p className={cx('flex items-start gap-2 text-sm font-medium', trail && 'mt-3', valid ? 'text-emerald-200' : 'text-red-200')}>
        {valid ? <CheckCircle2 className="mt-0.5 size-4 shrink-0" aria-hidden="true" /> : <XCircle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />}
        {valid ? 'Proven: ' : 'Not genuine: '}{p.explanation}
      </p>
    </div>
  );
}

function ChangedFile({ jobId, f, kind }) {
  const [open, setOpen] = useState(false);
  const [label, style] = CHANGE_STYLE[kind];
  return (
    <li className="px-5 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <span className={cx('rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset', style)}>{label}</span>
        <code className="min-w-0 flex-1 truncate font-mono text-sm text-zinc-100" title={f.path}>{f.path}</code>
        <span className="text-xs text-zinc-500">{bytes(f.current_size ?? f.baseline_size)}</span>
        <Button variant="secondary" size="sm" onClick={() => setOpen((v) => !v)}>
          <Network className="size-3.5" aria-hidden="true" />{open ? 'Hide proof' : 'Prove it'}
        </Button>
      </div>
      {open && <FileProof jobId={jobId} path={f.path} />}
    </li>
  );
}

function ChangesTab({ jobId, report }) {
  const r = report.reports || {};
  const isApk = (report.file_category || 'apk') === 'apk';
  const t = r.tamper || {};
  const integ = t.integrity || {};

  if (!isApk) {
    return (
      <div className="space-y-4">
        <Banner tone="neutral" icon={Fingerprint} title="This file is judged on its own">
          Photos, videos, web pages and PDFs have no “official original” to compare with. Instead the file is fingerprinted piece by
          piece ({r.integrity?.chunk_count ?? '?'} piece{r.integrity?.chunk_count === 1 ? '' : 's'}) and checked for hidden data and unsafe content.
          See <strong className="text-zinc-100">Problems found</strong> for what was found.
        </Banner>
        <Card className="p-5">
          <p className="text-sm text-zinc-300">Don’t trust us? Rebuild the same fingerprint yourself.</p>
          <p className="mt-1 text-xs text-zinc-500">Open the Merkle Tree Lab and drop this same file in. Your browser will compute the root below independently.</p>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <HashChip value={r.integrity?.chunk_merkle_root} n={24} />
            <Link to="/merkle"><Button variant="secondary" size="sm"><Network className="size-3.5" aria-hidden="true" />Open the Merkle Tree Lab</Button></Link>
          </div>
        </Card>
      </div>
    );
  }

  if (!t.baseline_found || !integ.files) {
    return (
      <Banner tone="warn" icon={ShieldQuestion} title="No trusted original to compare with">
        An administrator can add the official version of this app under <Link to="/baselines" className="text-emerald-300 hover:underline">Trusted Apps</Link>.
        Every later scan will then show exactly which files were changed, added or removed.
      </Banner>
    );
  }

  const c = integ.counts || {};
  const files = integ.files;
  const total = (c.modified || 0) + (c.added || 0) + (c.deleted || 0);
  const tile = (label, n, tone) => (
    <div className={cx('rounded-xl p-4 ring-1', n ? TONES[tone].bg + ' ' + TONES[tone].ring : 'bg-white/[0.02] ring-white/[0.06]')}>
      <p className="text-xs text-zinc-500">{label}</p>
      <p className={cx('text-2xl font-bold tabular-nums', n ? TONES[tone].text : 'text-zinc-400')}>{n ?? 0}</p>
    </div>
  );
  return (
    <div className="space-y-6">
      {total === 0 && !t.certificate_changed ? (
        <Banner tone="good" icon={ShieldCheck} title="Identical to the trusted original">
          Every file matches trusted version #{t.baseline?.baseline_version} ({t.baseline?.app_version_name || 'unknown version'}), approved by {t.baseline?.approved_by}.
        </Banner>
      ) : (
        <Banner tone="bad" icon={ShieldX} title={`${total} file${total === 1 ? '' : 's'} differ from the trusted original`}>
          Compared with trusted version #{t.baseline?.baseline_version} ({t.baseline?.app_version_name || 'unknown version'}).
          {t.certificate_changed && ' It is also signed with a different developer key, so someone other than the developer rebuilt it.'}
        </Banner>
      )}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {tile('Modified', c.modified, 'bad')}
        {tile('Added', c.added, 'warn')}
        {tile('Deleted', c.deleted, 'bad')}
        {tile('Unchanged', c.unchanged, 'good')}
      </div>
      {integ.merkle && (
        <Card className="p-5">
          <p className="mb-3 text-sm font-medium text-zinc-200">App fingerprints (Merkle roots over every file)</p>
          <div className="grid items-center gap-3 sm:grid-cols-[1fr_auto_1fr]">
            <div><p className="mb-1 text-xs text-zinc-500">Trusted original</p><HashChip value={integ.merkle.baseline_root} n={20} /></div>
            <span className={cx('mx-auto text-xl font-bold', integ.merkle.match ? 'text-emerald-300' : 'text-red-300')}>{integ.merkle.match ? '=' : '≠'}</span>
            <div><p className="mb-1 text-xs text-zinc-500">This upload</p><HashChip value={integ.merkle.current_root} n={20} /></div>
          </div>
        </Card>
      )}
      {t.fuzzy_comparison && t.fuzzy_comparison.similarity !== null && (
        <Card className="p-5">
          <CardHeader icon={Fingerprint} title="Near-duplicate analysis (Fuzzy Hashing / CTPH)"
            subtitle="Measures bytecode similarity to detect repackaged malware and modified variants." />
          <div className="mt-3 grid gap-3 sm:grid-cols-3">
            <div className="rounded-xl bg-white/[0.03] p-4 ring-1 ring-white/[0.06]">
              <p className="text-xs text-zinc-500">Bytecode similarity</p>
              <p className={cx('mt-1 text-2xl font-bold tabular-nums',
                t.fuzzy_comparison.similarity >= 80 ? 'text-amber-300' : 'text-emerald-300')}>
                {t.fuzzy_comparison.similarity}%
              </p>
            </div>
            <div className="rounded-xl bg-white/[0.03] p-4 ring-1 ring-white/[0.06]">
              <p className="text-xs text-zinc-500">Classification</p>
              <p className="mt-1 text-base font-semibold text-zinc-100">{t.fuzzy_comparison.classification}</p>
            </div>
            <div className="rounded-xl bg-white/[0.03] p-4 ring-1 ring-white/[0.06]">
              <p className="text-xs text-zinc-500">Assessment</p>
              <p className="mt-1 text-xs leading-relaxed text-zinc-300">
                {t.fuzzy_comparison.is_near_duplicate
                  ? 'High similarity indicates a repackaged or trojanized build with modified bytecode.'
                  : 'Codebase has diverged significantly from baseline.'}
              </p>
            </div>
          </div>
        </Card>
      )}
      {total > 0 && (
        <Card>
          <CardHeader icon={FileDiff} title="Changed files"
            subtitle="Press “Prove it” to check a file against the signed trusted root. The math runs in your browser." />
          <ul className="divide-y divide-white/[0.05]">
            {files.modified.map((f) => <ChangedFile key={`m${f.path}`} jobId={jobId} f={f} kind="modified" />)}
            {files.added.map((f) => <ChangedFile key={`a${f.path}`} jobId={jobId} f={f} kind="added" />)}
            {files.deleted.map((f) => <ChangedFile key={`d${f.path}`} jobId={jobId} f={f} kind="deleted" />)}
          </ul>
        </Card>
      )}
      {files.unchanged?.length > 0 && (
        <Card>
          <CardHeader icon={CheckCircle2} title={`Unchanged files (${files.unchanged.length})`} subtitle="Pick any one and prove it is genuine." />
          <ul className="scroll-thin max-h-72 divide-y divide-white/[0.05] overflow-y-auto">
            {files.unchanged.slice(0, 200).map((path) => (
              <ChangedUnchanged key={path} jobId={jobId} path={path} />
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

function ChangedUnchanged({ jobId, path }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="px-5 py-2.5">
      <div className="flex items-center gap-3">
        <code className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-300" title={path}>{path}</code>
        <button type="button" onClick={() => setOpen((v) => !v)} className="text-xs text-emerald-300 hover:underline">{open ? 'Hide' : 'Prove it'}</button>
      </div>
      {open && <FileProof jobId={jobId} path={path} />}
    </li>
  );
}

// ---------------------------------------------------------------- downloads --

function Downloads({ jobId, report }) {
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const save = (name, obj) => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const get = async (kind, path, name) => {
    setBusy(kind);
    setError(null);
    try { save(name, await api.get(path)); } catch (err) { setError(err); } finally { setBusy(null); }
  };
  return (
    <Card>
      <CardHeader icon={Download} title="Take the proof with you"
        subtitle="Download signed evidence that anyone can check offline, without access to this server." />
      <div className="flex flex-wrap gap-3 p-5">
        <Button variant="secondary" loading={busy === 'bundle'} onClick={() => get('bundle', `/scans/${jobId}/bundle`, `merkletrust-proof-${jobId}.json`)}>
          <ShieldCheck className="size-4" aria-hidden="true" />Verification bundle
        </Button>
        <Button variant="secondary" loading={busy === 'att'} onClick={() => get('att', `/scans/${jobId}/attestation`, `merkletrust-attestation-${jobId}.json`)}>
          <BadgeCheck className="size-4" aria-hidden="true" />Signed attestation (in-toto)
        </Button>
        <Button variant="ghost" onClick={() => save(`merkletrust-report-${jobId}.json`, report)}>
          <Download className="size-4" aria-hidden="true" />Full report
        </Button>
      </div>
      {error && <div className="px-5 pb-5"><ErrorBox error={error} /></div>}
      <p className="border-t border-white/[0.06] px-5 py-3 text-xs text-zinc-500">
        Check a bundle offline with <code className="text-zinc-300">python -m scripts.verify_offline --bundle bundle.json</code>.
      </p>
    </Card>
  );
}

// ------------------------------------------------------------------ page --

export default function Result() {
  const { jobId } = useParams();
  const { scan, report, error } = useScan(jobId);
  const [tab, setTab] = useState('summary');

  const back = (
    <Link to="/history" className="mb-4 inline-flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-100">
      <ArrowLeft className="size-4" aria-hidden="true" /> All scans
    </Link>
  );

  if (error) return <div>{back}<ErrorBox error={error} /></div>;
  if (!scan) return <Spinner label="Loading scan…" />;
  if (!report) {
    return (
      <div className="mx-auto max-w-xl animate-fade-in">
        {back}
        <Card className="p-6">
          <p className="mb-1 text-sm font-medium text-zinc-100">Checking {scan.filename}</p>
          <p className="mb-4 text-xs text-zinc-500">This page updates automatically.</p>
          <ScanSteps scan={scan} />
        </Card>
      </div>
    );
  }

  const findings = report.reports?.score?.all_findings || [];
  const issues = findings.filter((f) => f.severity !== 'info').length;
  const counts = report.reports?.tamper?.integrity?.counts;
  const changed = counts ? (counts.modified || 0) + (counts.added || 0) + (counts.deleted || 0) : null;
  const tabs = [
    { id: 'summary', label: 'Summary', icon: LayoutDashboard },
    { id: 'changes', label: 'What changed', icon: FileDiff, count: changed || null, tone: 'bad' },
    { id: 'findings', label: 'Problems found', icon: FileSearch, count: issues || null, tone: 'warn' },
    { id: 'proof', label: 'Proof & seal', icon: ShieldCheck },
  ];

  return (
    <div className="animate-fade-in space-y-6">
      <div>{back}<SummaryCard scan={scan} report={report} /></div>
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      <div key={tab} className="animate-fade-in space-y-6">
        {tab === 'summary' && <Answers report={report} />}
        {tab === 'changes' && <ChangesTab jobId={jobId} report={report} />}
        {tab === 'findings' && <FindingsCard findings={findings} />}
        {tab === 'proof' && (
          <>
            <IntegrityCard jobId={jobId} report={report} />
            <Downloads jobId={jobId} report={report} />
            <Explain title="What does “sealed” mean?">
              <p>When the scan finished, the server computed a fingerprint of the whole report and signed it with its private key.
                That signed fingerprint was added as a block to the <Link to="/chain" className="text-emerald-300 hover:underline">blockchain</Link>.</p>
              <p>“Check it again now” recomputes the report’s fingerprint and confirms that it still matches the sealed one. If anyone edited
                the stored report, even by one character, this check fails.</p>
            </Explain>
          </>
        )}
      </div>
    </div>
  );
}
