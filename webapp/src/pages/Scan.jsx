import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, FileUp, Fingerprint, Link2, ScanSearch, ShieldCheck, UploadCloud, X } from 'lucide-react';
import ScanSteps from '../components/ScanSteps.jsx';
import { Button, Card, CardHeader, ErrorBox, FileTypeBadge, PageHeader, ProgressBar, cx } from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { ACCEPT, bytes, detectFile } from '../lib/format.js';

const SUPPORTED = [
  ['Android apps', 'APK'],
  ['Images', 'PNG · JPG · GIF · WebP'],
  ['Video', 'MP4 · MKV · WebM'],
  ['Audio', 'MP3 · WAV · M4A'],
  ['Web pages', 'HTML · JS'],
  ['Documents', 'PDF'],
];

const HOW = [
  { icon: Fingerprint, title: 'Fingerprint', text: 'The file is split into 64 KB pieces. Each piece gets a SHA-256 fingerprint, and all of them combine into one Merkle root — change one byte and it changes completely.' },
  { icon: ScanSearch, title: 'Inspect', text: 'Apps are checked against their trusted master copy and their signature. Images, media, pages and PDFs are checked for hidden attachments, unsafe scripts and leaked metadata.' },
  { icon: Link2, title: 'Seal', text: 'The result is signed with the server’s private key and chained to every earlier result, so nobody can quietly edit history.' },
];

export default function Scan() {
  const navigate = useNavigate();
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [detected, setDetected] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [phase, setPhase] = useState('idle'); // idle | uploading | analysing
  const [progress, setProgress] = useState(0);
  const [scan, setScan] = useState(null);
  const [error, setError] = useState(null);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; };
  }, []);

  const choose = async (f) => {
    if (!f || phase !== 'idle') return;
    setError(null);
    setFile(f);
    setDetected(null);
    setDetected(await detectFile(f));
  };

  const reset = () => {
    setFile(null);
    setDetected(null);
    setError(null);
    if (inputRef.current) inputRef.current.value = '';
  };

  const analyse = async () => {
    alive.current = true;
    setError(null);
    setPhase('uploading');
    setProgress(0);
    try {
      const created = await api.upload('/scans', file, setProgress);
      if (!alive.current) return;
      setScan(created);
      setPhase('analysing');
      for (let i = 0; i < 900 && alive.current; i += 1) {
        const s = await api.get(`/scans/${created.id}`);
        if (!alive.current) return;
        setScan(s);
        if (s.status === 'done' || s.status === 'failed') {
          setTimeout(() => alive.current && navigate(`/results/${s.id}`), 700);
          return;
        }
        await new Promise((r) => setTimeout(r, 800));
      }
    } catch (err) {
      if (!alive.current) return;
      setError(err);
      setPhase('idle');
      setScan(null);
    }
  };

  const busy = phase !== 'idle';
  const blocked = detected && (!detected.supported || detected.mismatch);

  return (
    <div className="animate-fade-in">
      <PageHeader
        title="Universal File Scanner"
        description="Drop any app, image, video, audio file, web page or PDF. MerkleTrust fingerprints it, checks it for tampering and hidden threats, and records a signed result you can verify later."
      />
      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        <Card className="overflow-hidden">
          {!busy && (
            <label
              htmlFor="file-input"
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => { e.preventDefault(); setDragging(false); choose(e.dataTransfer.files[0]); }}
              className={cx('m-4 flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed px-6 py-14 text-center transition-all duration-200',
                dragging ? 'scale-[1.01] border-emerald-400 bg-emerald-500/[0.07]' : 'border-white/10 hover:border-white/20 hover:bg-white/[0.02]')}
            >
              <input ref={inputRef} id="file-input" type="file" accept={ACCEPT} className="sr-only"
                onChange={(e) => choose(e.target.files[0])} />
              <span className={cx('grid size-14 place-items-center rounded-2xl ring-1 transition',
                dragging ? 'bg-emerald-500/20 ring-emerald-400/50' : 'bg-white/[0.04] ring-white/10')}>
                <UploadCloud className={cx('size-7 transition', dragging ? 'text-emerald-300 -translate-y-0.5' : 'text-zinc-400')} aria-hidden="true" />
              </span>
              <div>
                <p className="text-base font-medium text-zinc-100">{dragging ? 'Release to add the file' : 'Drag & drop a file here'}</p>
                <p className="mt-1 text-sm text-zinc-500">or <span className="text-emerald-400 underline-offset-2 hover:underline">browse your computer</span></p>
              </div>
            </label>
          )}

          {file && (
            <div className="border-t border-white/[0.06] px-5 py-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-white/[0.04] ring-1 ring-white/10">
                  <FileUp className="size-5 text-zinc-300" aria-hidden="true" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium text-zinc-100">{file.name}</p>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-zinc-500">
                    {bytes(file.size)}
                    {detected && <FileTypeBadge category={detected.category} format={detected.format} />}
                  </div>
                </div>
                {!busy && (
                  <button type="button" onClick={reset} aria-label="Remove file"
                    className="rounded-lg p-2 text-zinc-500 hover:bg-white/[0.06] hover:text-zinc-200">
                    <X className="size-4" aria-hidden="true" />
                  </button>
                )}
              </div>
              {detected && !detected.supported && (
                <p className="mt-3 flex items-start gap-2 text-xs text-amber-300">
                  <AlertTriangle className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
                  This file type isn’t supported yet. Choose one of the formats listed on the right.
                </p>
              )}
              {detected?.mismatch && (
                <p className="mt-3 flex items-start gap-2 text-xs text-amber-300">
                  <AlertTriangle className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
                  The file’s contents look like {detected.format}, which doesn’t match its extension. The server will refuse it — renamed files are a common disguise.
                </p>
              )}
              {phase === 'idle' && (
                <Button className="mt-4 w-full sm:w-auto" onClick={analyse} disabled={!detected || blocked}>
                  <ShieldCheck className="size-4" aria-hidden="true" /> Analyze File
                </Button>
              )}
              {phase === 'uploading' && (
                <div className="mt-4 space-y-2">
                  <div className="flex justify-between text-xs text-zinc-400">
                    <span>Uploading securely…</span><span>{Math.round(progress * 100)}%</span>
                  </div>
                  <ProgressBar value={progress} />
                </div>
              )}
            </div>
          )}

          {phase === 'analysing' && (
            <div className="border-t border-white/[0.06] px-5 py-5">
              <p className="mb-3 text-sm font-medium text-zinc-200">Analysing your file</p>
              <ScanSteps scan={scan} />
            </div>
          )}
          {error && <div className="px-5 pb-5"><ErrorBox error={error} /></div>}
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader title="Supported files" subtitle="The type is detected from the file’s contents, not just its name." />
            <ul className="divide-y divide-white/[0.05] px-5 py-2 text-sm">
              {SUPPORTED.map(([k, v]) => (
                <li key={k} className="flex justify-between gap-3 py-2">
                  <span className="text-zinc-300">{k}</span><span className="text-right text-xs text-zinc-500">{v}</span>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-3">
        {HOW.map(({ icon: Icon, title, text }) => (
          <Card key={title} className="p-5">
            <Icon className="mb-3 size-5 text-emerald-400" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-zinc-100">{title}</h3>
            <p className="mt-1.5 text-sm leading-relaxed text-zinc-400">{text}</p>
          </Card>
        ))}
      </div>
    </div>
  );
}
