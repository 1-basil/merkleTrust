import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronRight, History as HistoryIcon, Loader2, Search, Upload } from 'lucide-react';
import { Button, Card, Empty, ErrorBox, FileTypeBadge, PageHeader, Spinner, ToneBadge, cx } from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { TONES, categoryFromName, dateTime, overallTone, trustScore, verdictLabel } from '../lib/format.js';

const PAGE = 100;

function Score({ scan }) {
  if (scan.status !== 'done' && scan.status !== 'failed') {
    return <span className="inline-flex items-center gap-1.5 text-xs text-zinc-400"><Loader2 className="size-3.5 animate-spin" aria-hidden="true" />{scan.status}</span>;
  }
  const trust = trustScore(scan.result?.risk_score);
  const tone = overallTone(trust, scan.result?.verdict);
  return (
    <span className="inline-flex items-center gap-2">
      <span className="h-1.5 w-12 overflow-hidden rounded-full bg-white/[0.06]">
        <span className="block h-full rounded-full" style={{ width: `${trust ?? 0}%`, background: TONES[tone].stroke }} />
      </span>
      <span className={cx('text-sm tabular-nums', TONES[tone].text)}>{trust ?? '—'}</span>
    </span>
  );
}

function Verdict({ scan }) {
  if (scan.status !== 'done' && scan.status !== 'failed') return <span className="text-xs text-zinc-500">In progress</span>;
  const r = scan.result;
  if (!r) return <ToneBadge tone="bad">Could Not Analyse</ToneBadge>;
  return <ToneBadge tone={overallTone(trustScore(r.risk_score), r.verdict)}>{verdictLabel(r.verdict, r.integrity_status)}</ToneBadge>;
}

export default function History() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loaded, setLoaded] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState(null);
  const [query, setQuery] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const d = await api.get('/scans', { limit: PAGE, offset: 0 });
        setItems(d.items);
        setTotal(d.total);
      } catch (err) {
        setError(err);
      } finally {
        setLoaded(true);
      }
    })();
  }, []);

  const more = async () => {
    setLoadingMore(true);
    try {
      const d = await api.get('/scans', { limit: PAGE, offset: items.length });
      setItems((cur) => [...cur, ...d.items]);
    } catch (err) {
      setError(err);
    } finally {
      setLoadingMore(false);
    }
  };

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((s) => [s.filename, s.package_name, s.apk_sha256, s.submitted_by, s.result?.verdict]
      .some((v) => v && String(v).toLowerCase().includes(q)));
  }, [items, query]);

  return (
    <div className="animate-fade-in">
      <PageHeader
        title="Scan History"
        description="Every file analysed so far. Open a report to see its trust score, fingerprint and findings."
        action={<Link to="/scan"><Button><Upload className="size-4" aria-hidden="true" />New scan</Button></Link>}
      />
      <Card>
        <div className="flex flex-wrap items-center gap-3 border-b border-white/[0.06] px-4 py-3">
          <label className="relative min-w-0 flex-1">
            <span className="sr-only">Search scans</span>
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-zinc-500" aria-hidden="true" />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search by file name, app, SHA-256 or user…"
              className="w-full rounded-lg border border-white/10 bg-black/30 py-2 pl-9 pr-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-emerald-500/60 focus:outline-none" />
          </label>
          <span className="text-xs text-zinc-500">{shown.length} of {total}</span>
        </div>
        <ErrorBox error={error} className="m-4" />
        {!loaded && <Spinner label="Loading scans…" />}
        {loaded && !error && shown.length === 0 && (
          <Empty icon={HistoryIcon} title={items.length ? 'No scans match your search' : 'No scans yet'}>
            {items.length ? 'Try a different search.' : 'Upload a file to run your first scan.'}
          </Empty>
        )}
        {shown.length > 0 && (
          <>
            {/* Desktop table */}
            <div className="hidden overflow-x-auto md:block">
              <table className="w-full text-left text-sm">
                <thead className="text-xs text-zinc-500">
                  <tr className="border-b border-white/[0.06]">
                    <th className="px-4 py-2.5 font-medium">File name</th>
                    <th className="px-4 py-2.5 font-medium">Type</th>
                    <th className="px-4 py-2.5 font-medium">Trust score</th>
                    <th className="px-4 py-2.5 font-medium">Verdict</th>
                    <th className="px-4 py-2.5 font-medium">Date</th>
                    <th className="px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.05]">
                  {shown.map((s) => (
                    <tr key={s.id} className="transition hover:bg-white/[0.02]">
                      <td className="max-w-[260px] px-4 py-3">
                        <p className="truncate font-medium text-zinc-100" title={s.filename}>{s.filename}</p>
                        {s.package_name && <p className="truncate font-mono text-xs text-zinc-500">{s.package_name}</p>}
                      </td>
                      <td className="px-4 py-3"><FileTypeBadge category={categoryFromName(s.filename)} /></td>
                      <td className="px-4 py-3"><Score scan={s} /></td>
                      <td className="px-4 py-3"><Verdict scan={s} /></td>
                      <td className="whitespace-nowrap px-4 py-3 text-zinc-400">{dateTime(s.created_at)}</td>
                      <td className="px-4 py-3 text-right">
                        <Link to={`/results/${s.id}`} className="inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-xs font-medium text-emerald-300 ring-1 ring-emerald-500/30 hover:bg-emerald-500/10">
                          View Report <ChevronRight className="size-3.5" aria-hidden="true" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {/* Mobile cards */}
            <ul className="divide-y divide-white/[0.05] md:hidden">
              {shown.map((s) => (
                <li key={s.id}>
                  <Link to={`/results/${s.id}`} className="flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02]">
                    <div className="min-w-0 flex-1 space-y-1.5">
                      <p className="truncate text-sm font-medium text-zinc-100">{s.filename}</p>
                      <div className="flex flex-wrap items-center gap-2">
                        <FileTypeBadge category={categoryFromName(s.filename)} />
                        <Verdict scan={s} />
                      </div>
                      <div className="flex items-center gap-3 text-xs text-zinc-500"><Score scan={s} />{dateTime(s.created_at)}</div>
                    </div>
                    <ChevronRight className="size-4 shrink-0 text-zinc-600" aria-hidden="true" />
                  </Link>
                </li>
              ))}
            </ul>
          </>
        )}
        {items.length < total && (
          <div className="border-t border-white/[0.06] p-4 text-center">
            <Button variant="secondary" onClick={more} loading={loadingMore}>Load more</Button>
          </div>
        )}
      </Card>
    </div>
  );
}
