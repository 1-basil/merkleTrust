import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowRight, Blocks, CheckCircle2, ChevronRight, Circle, FileSearch, Fingerprint, Link2, Network, PlayCircle,
  ScanLine, ShieldAlert, ShieldCheck, Stamp, Upload,
} from 'lucide-react';
import { Button, Card, CardHeader, ErrorBox, FileTypeBadge, Stat, ToneBadge, cx } from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { useAuth } from '../lib/auth.jsx';
import { categoryFromName, dateTime, overallTone, trustScore, verdictLabel } from '../lib/format.js';

const FLOW = [
  { icon: Fingerprint, title: 'Fingerprint', text: 'Every file gets a unique fingerprint built with a Merkle tree. Change one byte and it changes completely.', to: '/merkle', cta: 'Try the Merkle tree' },
  { icon: FileSearch, title: 'Compare & inspect', text: 'Apps are compared with their trusted original, file by file. Photos, pages and PDFs are checked for hidden data.', to: '/scan', cta: 'Scan a file' },
  { icon: Link2, title: 'Seal forever', text: 'Every result is signed and added to a blockchain-style record that nobody can quietly edit.', to: '/chain', cta: 'See the blockchain' },
];

// A rehearsable demo, in the order that tells the story best.
const STEPS = [
  { title: 'Scan an app with nothing to compare it to', detail: 'Upload evaluation/dataset/demo_official_copy.apk. It is reported as “Not Verified”: we never trust a file just because it looks fine.', to: '/scan' },
  { title: 'Add the official app as trusted', detail: 'In Trusted Apps, upload evaluation/dataset/baseline_demo.apk and approve it (admin).', to: '/baselines' },
  { title: 'Scan a hacked copy', detail: 'Upload evaluation/dataset/demo_repackaged.apk. You get “Tampering Detected”. Open “What changed” and prove classes.dex was altered.', to: '/scan' },
  { title: 'Catch hidden data in a photo', detail: 'Upload samples/tampered_photo.jpg and compare it with samples/clean_photo.jpg.', to: '/scan' },
  { title: 'Show how the fingerprint works', detail: 'In the Merkle Tree Lab, press “Tamper with an item” and watch the change ripple up to the root.', to: '/merkle' },
  { title: 'Try to rewrite history and get caught', detail: 'On the Blockchain page, select a block, “Play the attacker”, then “Verify the whole chain”. Finish with “Restore the chain”.', to: '/chain' },
];
const DONE_KEY = 'merkletrust.demo-steps';

function readDone() {
  try { return JSON.parse(localStorage.getItem(DONE_KEY)) || []; } catch { return []; }
}

function DemoGuide() {
  const [done, setDone] = useState(readDone);
  const toggle = (i) => {
    const next = done.includes(i) ? done.filter((x) => x !== i) : [...done, i];
    setDone(next);
    try { localStorage.setItem(DONE_KEY, JSON.stringify(next)); } catch { /* storage unavailable */ }
  };
  return (
    <Card>
      <CardHeader icon={PlayCircle} title="Demo guide"
        subtitle="A 5-minute walkthrough that shows every feature. Tick the steps off as you go."
        action={done.length > 0 && <Button variant="ghost" size="sm" onClick={() => { setDone([]); try { localStorage.removeItem(DONE_KEY); } catch { /* ignore */ } }}>Reset</Button>} />
      <ol className="divide-y divide-white/[0.05]">
        {STEPS.map((s, i) => {
          const isDone = done.includes(i);
          return (
            <li key={s.title} className="flex items-start gap-3 px-5 py-3.5">
              <button type="button" onClick={() => toggle(i)} aria-pressed={isDone} aria-label={`Mark step ${i + 1} ${isDone ? 'not done' : 'done'}`}
                className="mt-0.5 shrink-0">
                {isDone ? <CheckCircle2 className="size-5 text-emerald-400" aria-hidden="true" /> : <Circle className="size-5 text-zinc-600 hover:text-zinc-400" aria-hidden="true" />}
              </button>
              <div className="min-w-0 flex-1">
                <p className={cx('text-sm font-medium', isDone ? 'text-zinc-500 line-through' : 'text-zinc-100')}>{i + 1}. {s.title}</p>
                <p className="mt-0.5 text-xs leading-relaxed text-zinc-500">{s.detail}</p>
              </div>
              <Link to={s.to} className="inline-flex shrink-0 items-center gap-0.5 rounded-lg px-2 py-1 text-xs font-medium text-emerald-300 hover:bg-emerald-500/10">
                Go <ChevronRight className="size-3.5" aria-hidden="true" />
              </Link>
            </li>
          );
        })}
      </ol>
    </Card>
  );
}

function RecentScans({ scans }) {
  return (
    <Card>
      <CardHeader icon={ScanLine} title="Latest scans" action={<Link to="/history" className="text-xs text-emerald-300 hover:underline">See all</Link>} />
      {scans.length === 0 ? (
        <p className="px-5 py-8 text-center text-sm text-zinc-500">No scans yet. <Link to="/scan" className="text-emerald-300 hover:underline">Scan your first file</Link>.</p>
      ) : (
        <ul className="divide-y divide-white/[0.05]">
          {scans.map((s) => {
            const r = s.result;
            const tone = r ? overallTone(trustScore(r.risk_score), r.verdict) : 'neutral';
            return (
              <li key={s.id}>
                <Link to={`/results/${s.id}`} className="flex items-center gap-3 px-5 py-3 transition hover:bg-white/[0.02]">
                  <FileTypeBadge category={categoryFromName(s.filename)} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm text-zinc-100">{s.filename}</p>
                    <p className="text-xs text-zinc-500">{dateTime(s.created_at)}</p>
                  </div>
                  {r ? <ToneBadge tone={tone}>{verdictLabel(r.verdict, r.integrity_status)}</ToneBadge>
                    : <span className="text-xs text-zinc-500">{s.status}</span>}
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

export default function Home() {
  const { user } = useAuth();
  const [sum, setSum] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.get('/dashboard/summary').then(setSum).catch(setError);
  }, []);

  const caught = sum ? sum.applications.modified + sum.applications.high_risk : null;
  const chainOk = sum?.audit_chain.valid;

  return (
    <div className="animate-fade-in space-y-10">
      {/* Hero */}
      <section className="relative overflow-hidden rounded-3xl border border-white/[0.08] bg-gradient-to-br from-emerald-500/[0.10] via-zinc-900/60 to-sky-500/[0.08] px-6 py-10 sm:px-10 sm:py-14">
        <div className="pointer-events-none absolute -right-16 -top-16 size-72 rounded-full bg-emerald-400/10 blur-3xl" aria-hidden="true" />
        <div className="pointer-events-none absolute -bottom-24 right-40 size-72 rounded-full bg-sky-400/10 blur-3xl" aria-hidden="true" />
        <div className="relative grid items-center gap-10 lg:grid-cols-[1.4fr_1fr]">
          <div>
            <p className="mb-4 inline-flex items-center gap-2 rounded-full bg-white/[0.06] px-3 py-1 text-xs font-medium text-zinc-300 ring-1 ring-white/10">
              <span className="size-1.5 rounded-full bg-emerald-400" />Welcome back, {user?.username}
            </p>
            <h1 className="text-4xl font-bold leading-[1.1] tracking-tight text-zinc-50 sm:text-5xl">
              Prove any file is <span className="text-gradient">genuine</span>, and that nobody changed it.
            </h1>
            <p className="mt-4 max-w-xl text-base leading-relaxed text-zinc-400">
              MerkleTrust checks Android apps, images, videos, web pages and PDFs for tampering, explains what it finds in plain
              words, and seals every result so it can be proven later.
            </p>
            <div className="mt-7 flex flex-wrap gap-3">
              <Link to="/scan"><Button size="lg"><Upload className="size-5" aria-hidden="true" />Scan a file</Button></Link>
              <Link to="/merkle"><Button size="lg" variant="secondary"><Network className="size-5" aria-hidden="true" />See how it works</Button></Link>
            </div>
          </div>
          <HeroArt />
        </div>
      </section>

      <ErrorBox error={error} />

      {/* Live numbers */}
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat icon={ScanLine} label="Files scanned" value={sum?.scans.total ?? '—'} tone="neutral" hint="All file types" />
        <Stat icon={ShieldAlert} label="Tampered or risky apps" value={caught ?? '—'} tone={caught ? 'bad' : 'good'}
          hint={caught ? 'Caught and explained' : 'None found so far'} />
        <Stat icon={Stamp} label="Trusted apps" value={sum?.baselines.approved ?? '—'} tone="good"
          hint={sum?.baselines.pending ? `${sum.baselines.pending} waiting for approval` : 'Approved originals'} />
        <Stat icon={Blocks} label="Blockchain" value={sum ? `${sum.audit_chain.length} blocks` : '—'}
          tone={sum ? (chainOk ? 'good' : 'bad') : 'neutral'} hint={sum ? (chainOk ? 'Intact: nothing was edited' : 'Broken: tampering detected') : ''} />
      </section>

      {/* How it works */}
      <section>
        <h2 className="mb-4 text-xl font-semibold tracking-tight text-zinc-50">How it works, in three steps</h2>
        <div className="grid gap-4 md:grid-cols-3">
          {FLOW.map(({ icon: Icon, title, text, to, cta }, i) => (
            <Link key={title} to={to} className="group">
              <Card className="relative h-full p-6 transition group-hover:-translate-y-1 group-hover:border-emerald-400/30">
                <div className="mb-4 flex items-center gap-3">
                  <span className="grid size-11 place-items-center rounded-2xl bg-gradient-to-br from-emerald-400/25 to-sky-400/15 ring-1 ring-emerald-400/30">
                    <Icon className="size-5 text-emerald-200" aria-hidden="true" />
                  </span>
                  <span className="text-4xl font-bold text-white/[0.06]">0{i + 1}</span>
                </div>
                <h3 className="text-lg font-semibold text-zinc-50">{title}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-zinc-400">{text}</p>
                <p className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-emerald-300">
                  {cta}<ArrowRight className="size-4 transition group-hover:translate-x-1" aria-hidden="true" />
                </p>
              </Card>
            </Link>
          ))}
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-[1.25fr_1fr]">
        <DemoGuide />
        <RecentScans scans={sum?.recent_scans || []} />
      </section>
    </div>
  );
}

// A small animated Merkle tree + chain motif for the hero.
function HeroArt() {
  const node = (x, y, c, delay) => (
    <g style={{ animation: `pop .45s ${delay * 0.5}s both cubic-bezier(.2,1.4,.4,1)`, transformOrigin: `${x}px ${y}px` }}>
      <rect x={x - 26} y={y - 13} width={52} height={26} rx={8} fill="#111114" stroke={c} strokeWidth={1.5} />
      <circle cx={x - 13} cy={y} r={4} fill={c} />
      <rect x={x - 5} y={y - 2} width={22} height={4} rx={2} fill="rgba(255,255,255,0.25)" />
    </g>
  );
  const edge = (x1, y1, x2, y2) => <path d={`M${x1} ${y1 - 13} C ${x1} ${(y1 + y2) / 2}, ${x2} ${(y1 + y2) / 2}, ${x2} ${y2 + 13}`} stroke="rgba(52,211,153,.45)" strokeWidth={1.5} fill="none" strokeDasharray="4 4" className="animate-dash" />;
  return (
    <div className="hidden animate-float lg:block" aria-hidden="true">
      <svg viewBox="0 0 320 230" className="w-full drop-shadow-[0_0_30px_rgba(16,185,129,0.15)]">
        {edge(70, 120, 115, 50)}{edge(160, 120, 115, 50)}{edge(160, 120, 205, 50)}{edge(250, 120, 205, 50)}
        {edge(40, 190, 70, 120)}{edge(100, 190, 70, 120)}{edge(220, 190, 250, 120)}{edge(280, 190, 250, 120)}
        {edge(160, 190, 160, 120)}
        {edge(115, 50, 160, 0 + 13)}{edge(205, 50, 160, 13)}
        {node(160, 0 + 13, '#34d399', 0.9)}
        {node(115, 50, '#2dd4bf', 0.7)}{node(205, 50, '#38bdf8', 0.75)}
        {node(70, 120, '#a78bfa', 0.45)}{node(160, 120, '#f472b6', 0.5)}{node(250, 120, '#fbbf24', 0.55)}
        {[40, 100, 160, 220, 280].map((x, i) => node(x, 190, ['#f87171', '#fb923c', '#facc15', '#4ade80', '#22d3ee'][i], 0.1 + i * 0.05))}
      </svg>
      <p className="mt-2 text-center text-xs text-zinc-500"><ShieldCheck className="mr-1 inline size-3.5 text-emerald-400" />Many fingerprints → one root</p>
    </div>
  );
}
