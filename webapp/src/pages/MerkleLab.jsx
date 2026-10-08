import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowDown, CheckCircle2, FileUp, Fingerprint, Lock, Plus, RotateCcw, Server, Skull, Trash2, UploadCloud, XCircle,
} from 'lucide-react';
import MerkleTreeView, { TreeLegend } from '../components/MerkleTreeView.jsx';
import { Banner, Button, Card, CardHeader, Explain, HashChip, PageHeader, cx } from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { bytes } from '../lib/format.js';
import {
  CHUNK_SIZE, buildTree, chunkHashes, foldProof, fromHex, leafHash, proofFor, rootOf, sha256, utf8,
} from '../lib/merkle.js';

// ------------------------------------------------------------------ presets --

const PRESETS = {
  app: {
    label: 'App files',
    items: ['AndroidManifest.xml', 'classes.dex (app code)', 'res/icon.png', 'res/layout/main.xml',
      'lib/libapp.so', 'assets/config.json', 'resources.arsc', 'META-INF/CERT.RSA'],
    tamper: (s) => (s.includes('code') ? `${s} + hidden SMS sender` : `${s} (modified)`),
  },
  bank: {
    label: 'Bank payments',
    items: ['Alice → Bob: ₹500', 'Bob → Carol: ₹120', 'Carol → Dan: ₹75', 'Dan → Eve: ₹300',
      'Eve → Alice: ₹40', 'Bob → Dan: ₹220'],
    tamper: (s) => s.replace(/₹[\d,]+/, '₹50,000'),
  },
  marks: {
    label: 'Exam marks',
    items: ['Ajay: 78', 'Ashwini: 91', 'Basil: 84', 'Bhavish: 88', 'Riya: 67'],
    tamper: (s) => s.replace(/\d+/, '100'),
  },
};

const shapeKey = (levels) => levels.map((l) => l.length).join(',');

// --------------------------------------------------------------- text lab --

function TreeLab() {
  const [preset, setPreset] = useState('app');
  const [items, setItems] = useState(PRESETS.app.items);
  const [trusted, setTrusted] = useState({ items: PRESETS.app.items, levels: null });
  const [levels, setLevels] = useState(null);
  const [selected, setSelected] = useState(1);
  const [proof, setProof] = useState(null);

  // Rebuild the current tree on every edit.
  useEffect(() => {
    let alive = true;
    buildTree(items.map(utf8)).then((l) => alive && setLevels(l));
    return () => { alive = false; };
  }, [items]);

  // The trusted tree is rebuilt only when a new version is trusted.
  useEffect(() => {
    if (trusted.levels) return;
    buildTree(trusted.items.map(utf8)).then((l) => setTrusted((t) => (t.items === trusted.items ? { ...t, levels: l } : t)));
  }, [trusted]);

  const changedItems = useMemo(() => items.map((s, i) => s !== trusted.items[i]), [items, trusted.items]);
  const sameShape = levels && trusted.levels && shapeKey(levels) === shapeKey(trusted.levels);
  const tampered = levels && trusted.levels && rootOf(levels) !== rootOf(trusted.levels);
  const changedCount = changedItems.filter(Boolean).length + Math.abs(items.length - trusted.items.length);

  // Proof of the selected item against the *trusted* root — exactly how the server checks a file.
  useEffect(() => {
    let alive = true;
    if (!trusted.levels || !levels || selected === null || selected >= Math.min(items.length, trusted.items.length)) {
      setProof(null);
      return undefined;
    }
    (async () => {
      const { steps, path } = proofFor(trusted.levels, selected);
      const leaf = await leafHash(utf8(items[selected]));
      const trail = await foldProof(leaf, steps);
      if (alive) setProof({ steps, path, trail, valid: trail[trail.length - 1] === rootOf(trusted.levels) });
    })();
    return () => { alive = false; };
  }, [trusted.levels, levels, items, selected, trusted.items.length]);

  const marks = useMemo(() => {
    const m = {};
    if (levels && trusted.levels) {
      levels.forEach((lvl, k) => lvl.forEach((h, i) => {
        if (!sameShape || trusted.levels[k]?.[i] !== h) m[`${k}:${i}`] = 'changed';
      }));
    }
    if (proof && sameShape) {
      proof.steps.forEach((s) => { if (!m[s.node]) m[s.node] = 'sibling'; });
      proof.path.forEach((key) => { if (!m[key]) m[key] = 'path'; });
    }
    return m;
  }, [levels, trusted.levels, sameShape, proof]);

  const loadPreset = (key) => {
    setPreset(key);
    setItems(PRESETS[key].items);
    setTrusted({ items: PRESETS[key].items, levels: null });
    setSelected(1);
  };
  const tamper = () => {
    const pool = items.map((_, i) => i).filter((i) => !changedItems[i]);
    const i = selected !== null && !changedItems[selected] ? selected : pool[Math.floor(Math.random() * pool.length)];
    if (i === undefined) return;
    const next = PRESETS[preset].tamper(items[i]);
    setItems(items.map((s, j) => (j === i ? (next === s ? `${s}!` : next) : s)));
    setSelected(i);
  };
  const edit = (i, v) => setItems(items.map((s, j) => (j === i ? v : s)));
  const trustCurrent = () => setTrusted({ items, levels: null });

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-2">
        <span className="mr-1 text-sm text-zinc-500">Example data:</span>
        {Object.entries(PRESETS).map(([k, p]) => (
          <button key={k} type="button" onClick={() => loadPreset(k)} aria-pressed={preset === k}
            className={cx('rounded-full px-3.5 py-1.5 text-sm font-medium ring-1 ring-inset transition',
              preset === k ? 'bg-emerald-500/15 text-emerald-200 ring-emerald-400/40' : 'text-zinc-400 ring-white/10 hover:text-zinc-100')}>
            {p.label}
          </button>
        ))}
        <div className="ml-auto flex flex-wrap gap-2">
          <Button variant="danger" onClick={tamper}><Skull className="size-4" aria-hidden="true" />Tamper with an item</Button>
          <Button variant="secondary" onClick={() => setItems(trusted.items)} disabled={!tampered && items === trusted.items}>
            <RotateCcw className="size-4" aria-hidden="true" />Undo changes
          </Button>
        </div>
      </div>

      {/* Root comparison */}
      <Card className={cx('p-5 transition-colors', tampered ? 'border-red-500/40' : 'border-emerald-500/25')}>
        <div className="grid items-center gap-4 md:grid-cols-[1fr_auto_1fr_auto]">
          <div className="min-w-0">
            <p className="mb-1.5 flex items-center gap-1.5 text-xs font-medium uppercase tracking-wider text-zinc-500">
              <Lock className="size-3.5" aria-hidden="true" />Trusted fingerprint (saved earlier)
            </p>
            <HashChip value={trusted.levels && rootOf(trusted.levels)} n={20} className="text-sm" />
          </div>
          <span className={cx('mx-auto grid size-10 place-items-center rounded-full text-lg font-bold ring-1',
            tampered ? 'bg-red-500/15 text-red-300 ring-red-500/40' : 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40')}>
            {tampered ? '≠' : '='}
          </span>
          <div className="min-w-0">
            <p className="mb-1.5 text-xs font-medium uppercase tracking-wider text-zinc-500">Fingerprint right now</p>
            <HashChip value={levels && rootOf(levels)} n={20} className="text-sm" />
          </div>
          {tampered ? (
            <span key="bad" className="inline-flex animate-shake items-center gap-2 rounded-full bg-red-500/15 px-3 py-1.5 text-sm font-semibold text-red-200 ring-1 ring-red-500/40">
              <XCircle className="size-4" aria-hidden="true" />Tampering detected
            </span>
          ) : (
            <span key="ok" className="inline-flex animate-pop items-center gap-2 rounded-full bg-emerald-500/15 px-3 py-1.5 text-sm font-semibold text-emerald-200 ring-1 ring-emerald-500/40">
              <CheckCircle2 className="size-4" aria-hidden="true" />Untouched
            </span>
          )}
        </div>
        {tampered && (
          <p className="mt-3 text-sm text-red-200/90 animate-fade-in">
            {changedCount === 1 ? 'One item was changed' : `${changedCount} items were changed`} — and the root fingerprint changed
            completely. The red boxes show the change rippling up to the top.
          </p>
        )}
      </Card>

      <Card className="p-4 sm:p-6">
        {levels ? (
          <MerkleTreeView levels={levels} labels={items} marks={marks} selected={selected} onSelect={setSelected} />
        ) : <div className="h-64" />}
        <div className="mt-4 border-t border-white/[0.06] pt-4"><TreeLegend /></div>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="The data" subtitle="Edit any item and watch the tree. Click an item to see its proof." />
          <ol className="space-y-2 p-4">
            {items.map((s, i) => (
              <li key={i} className="flex items-center gap-2">
                <button type="button" onClick={() => setSelected(i)} aria-label={`Select item ${i + 1}`}
                  className={cx('grid size-8 shrink-0 place-items-center rounded-lg text-xs font-semibold tabular-nums ring-1 transition',
                    selected === i ? 'bg-emerald-500/20 text-emerald-200 ring-emerald-400/50' : 'bg-white/[0.04] text-zinc-400 ring-white/10 hover:text-zinc-100')}>
                  {i + 1}
                </button>
                <input value={s} onChange={(e) => edit(i, e.target.value)} onFocus={() => setSelected(i)}
                  aria-label={`Item ${i + 1}`}
                  className={cx('min-w-0 flex-1 rounded-lg border bg-black/30 px-3 py-2 text-sm text-zinc-100 focus:outline-none',
                    changedItems[i] ? 'border-red-500/50 text-red-100' : 'border-white/10 focus:border-emerald-500/60')} />
                <button type="button" onClick={() => { setItems(items.filter((_, j) => j !== i)); setSelected(null); }}
                  disabled={items.length <= 2} aria-label={`Remove item ${i + 1}`}
                  className="rounded-lg p-2 text-zinc-500 hover:bg-white/[0.06] hover:text-zinc-200 disabled:opacity-30">
                  <Trash2 className="size-4" aria-hidden="true" />
                </button>
              </li>
            ))}
          </ol>
          <div className="flex flex-wrap gap-2 border-t border-white/[0.06] px-4 py-3">
            <Button variant="ghost" size="sm" onClick={() => setItems([...items, `New item ${items.length + 1}`])} disabled={items.length >= 12}>
              <Plus className="size-3.5" aria-hidden="true" />Add item
            </Button>
            <Button variant="ghost" size="sm" onClick={trustCurrent} disabled={!tampered}>
              <Lock className="size-3.5" aria-hidden="true" />Trust this version instead
            </Button>
          </div>
        </Card>

        <Card>
          <CardHeader title={selected !== null ? `Proof for item ${selected + 1}` : 'Proof'}
            subtitle="Can we prove one item belongs to the trusted tree — without looking at all the others?" />
          <div className="p-5">
            {!proof && <p className="text-sm text-zinc-500">Click an item (that existed in the trusted version) to build its proof.</p>}
            {proof && (
              <ol className="space-y-2 text-sm">
                <li className="rounded-xl bg-black/25 p-3 ring-1 ring-white/[0.06]">
                  <p className="text-xs text-zinc-500">Start: fingerprint of “{items[selected]}”</p>
                  <HashChip value={proof.trail[0]} n={16} className="mt-1" />
                </li>
                {proof.steps.map((s, i) => (
                  <li key={i} className="animate-fade-in" style={{ animationDelay: `${i * 90}ms` }}>
                    <ArrowDown className="mx-auto mb-2 size-4 text-zinc-600" aria-hidden="true" />
                    <div className="rounded-xl bg-black/25 p-3 ring-1 ring-white/[0.06]">
                      <p className="flex flex-wrap items-center gap-1.5 text-xs text-zinc-500">
                        Combine with the {s.position === 'left' ? 'left' : 'right'} neighbour
                        <HashChip value={s.sibling} n={7} className="ring-amber-400/40" />
                      </p>
                      <HashChip value={proof.trail[i + 1]} n={16} className="mt-1" />
                    </div>
                  </li>
                ))}
                <li>
                  <ArrowDown className="mx-auto mb-2 size-4 text-zinc-600" aria-hidden="true" />
                  <div className={cx('rounded-xl p-3 ring-1', proof.valid ? 'bg-emerald-500/10 ring-emerald-500/30' : 'bg-red-500/10 ring-red-500/30')}>
                    <p className={cx('flex items-center gap-2 font-semibold', proof.valid ? 'text-emerald-200' : 'text-red-200')}>
                      {proof.valid ? <CheckCircle2 className="size-4" aria-hidden="true" /> : <XCircle className="size-4" aria-hidden="true" />}
                      {proof.valid ? 'Matches the trusted root — proven genuine' : 'Does not reach the trusted root — this item was changed'}
                    </p>
                  </div>
                </li>
              </ol>
            )}
            {proof && (
              <p className="mt-4 text-xs leading-relaxed text-zinc-400">
                Only <strong className="text-amber-300">{proof.steps.length} neighbour hashes</strong> were needed for {trusted.items.length} items.
                For an app with 1,000 files it would be about 10 — that’s why checking stays fast at any size.
              </p>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}

// --------------------------------------------------------------- file lab --

const SIZES = [
  [CHUNK_SIZE, '64 KB — same as the server'],
  [4096, '4 KB — bigger tree'],
  [1024, '1 KB — biggest tree'],
];
const MAX_FILE = 100 * 1024 * 1024;
const GRID_MAX = 600;

function FileLab() {
  const [file, setFile] = useState(null);
  const [data, setData] = useState(null); // Uint8Array, possibly tampered
  const [size, setSize] = useState(CHUNK_SIZE);
  const [original, setOriginal] = useState(null); // { chunks, root, sha }
  const [current, setCurrent] = useState(null); // { chunks, levels, root }
  const [server, setServer] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [flipped, setFlipped] = useState([]);
  const inputRef = useRef(null);

  const hashAll = async (bytesIn, chunkSize) => {
    const chunks = await chunkHashes(bytesIn, chunkSize);
    const levels = await buildTree(chunks.map(fromHex));
    return { chunks, levels, root: rootOf(levels) };
  };

  const open = async (f) => {
    if (!f) return;
    if (f.size > MAX_FILE) { setError(`Please choose a file under ${bytes(MAX_FILE)}.`); return; }
    setError(null);
    setBusy(true);
    setServer(null);
    setFlipped([]);
    try {
      const b = new Uint8Array(await f.arrayBuffer());
      const sha = await sha256(b);
      const res = await hashAll(b, size);
      setFile(f);
      setData(b);
      setOriginal({ ...res, sha });
      setCurrent(res);
      lookupServer(sha);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  };

  // Was this exact file scanned already? Then compare our root with the one the server sealed.
  const lookupServer = async (sha) => {
    try {
      const list = await api.get('/scans', { limit: 100 });
      const hit = list.items.find((s) => s.apk_sha256 === sha && s.status === 'done');
      if (!hit) { setServer({ found: false }); return; }
      const rep = await api.get(`/scans/${hit.id}/report`);
      setServer({ found: true, scan: hit, root: rep.reports?.integrity?.chunk_merkle_root });
    } catch {
      setServer(null);
    }
  };

  useEffect(() => {
    if (!data) return;
    let alive = true;
    (async () => {
      setBusy(true);
      const pristine = new Uint8Array(data);
      flipped.forEach((off) => { pristine[off] ^= 0xff; }); // undo flips for the original
      const orig = await hashAll(pristine, size);
      const cur = flipped.length ? await hashAll(data, size) : orig;
      if (!alive) return;
      setOriginal((o) => ({ ...orig, sha: o.sha }));
      setCurrent(cur);
      setBusy(false);
    })();
    return () => { alive = false; };
  }, [size]); // eslint-disable-line react-hooks/exhaustive-deps

  const flip = async () => {
    const off = Math.floor(Math.random() * data.length);
    const next = new Uint8Array(data);
    next[off] ^= 0xff;
    setData(next);
    setFlipped([...flipped, off]);
    setCurrent(await hashAll(next, size));
  };
  const undo = () => {
    const next = new Uint8Array(data);
    flipped.forEach((off) => { next[off] ^= 0xff; });
    setData(next);
    setFlipped([]);
    setCurrent({ chunks: original.chunks, levels: original.levels, root: original.root });
  };

  const changed = current && original ? current.chunks.map((h, i) => h !== original.chunks[i]) : [];
  const tampered = current && original && current.root !== original.root;
  const marks = useMemo(() => {
    const m = {};
    if (current && original && tampered) {
      current.levels.forEach((lvl, k) => lvl.forEach((h, i) => { if (original.levels[k]?.[i] !== h) m[`${k}:${i}`] = 'changed'; }));
    }
    return m;
  }, [current, original, tampered]);

  return (
    <Card>
      <CardHeader icon={Fingerprint} title="Fingerprint a real file — right here in your browser"
        subtitle="Your file never leaves this page. It is cut into pieces, each piece is hashed, and the hashes are built into a Merkle tree — exactly like the server does." />
      <div className="space-y-5 p-5">
        <div className="flex flex-wrap items-center gap-3">
          <label htmlFor="lab-file"
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => { e.preventDefault(); open(e.dataTransfer.files[0]); }}
            className="flex flex-1 cursor-pointer items-center gap-3 rounded-xl border-2 border-dashed border-white/10 px-4 py-3 text-sm transition hover:border-emerald-400/40 hover:bg-white/[0.02]">
            <input ref={inputRef} id="lab-file" type="file" className="sr-only" onChange={(e) => open(e.target.files[0])} />
            <UploadCloud className="size-5 text-emerald-300" aria-hidden="true" />
            <span className="min-w-0 truncate text-zinc-300">{file ? file.name : 'Drop any file here, or click to choose one'}</span>
            {file && <span className="ml-auto shrink-0 text-xs text-zinc-500">{bytes(file.size)}</span>}
          </label>
          <label className="flex items-center gap-2 text-sm text-zinc-400">
            Piece size
            <select value={size} onChange={(e) => setSize(Number(e.target.value))}
              className="rounded-lg border border-white/10 bg-zinc-900 px-2 py-2 text-sm text-zinc-100">
              {SIZES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </label>
        </div>
        {error && <p className="text-sm text-red-300">{error}</p>}
        {busy && !current && <p className="text-sm text-zinc-400">Hashing…</p>}

        {current && original && (
          <>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="rounded-xl bg-black/25 p-3 ring-1 ring-white/[0.06]">
                <p className="text-xs text-zinc-500">Pieces</p>
                <p className="text-xl font-semibold tabular-nums text-zinc-50">{current.chunks.length.toLocaleString()}</p>
              </div>
              <div className="rounded-xl bg-black/25 p-3 ring-1 ring-white/[0.06]">
                <p className="text-xs text-zinc-500">Tree levels</p>
                <p className="text-xl font-semibold tabular-nums text-zinc-50">{current.levels.length}</p>
              </div>
              <div className="min-w-0 rounded-xl bg-black/25 p-3 ring-1 ring-white/[0.06]">
                <p className="mb-1 text-xs text-zinc-500">Root fingerprint</p>
                <HashChip value={current.root} n={16} />
              </div>
            </div>

            {server?.found && size === CHUNK_SIZE && !tampered && (
              <Banner tone={server.root === current.root ? 'good' : 'bad'} icon={Server}
                title={server.root === current.root ? 'Matches the server, computed independently' : 'Does not match the server'}>
                This exact file was scanned as{' '}
                <Link to={`/results/${server.scan.id}`} className="text-emerald-300 underline-offset-2 hover:underline">{server.scan.filename}</Link>.
                Your browser computed the same root fingerprint the server sealed in its signed report, so you don’t have to take the server’s word for it.
              </Banner>
            )}
            {server && !server.found && size === CHUNK_SIZE && (
              <p className="text-xs text-zinc-500">
                Tip: <Link to="/scan" className="text-emerald-300 hover:underline">scan this file</Link> too, then come back. Your browser
                will show the same root fingerprint the server computed.
              </p>
            )}

            <div>
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <p className="text-sm font-medium text-zinc-200">Every piece of the file</p>
                <span className="text-xs text-zinc-500">
                  {current.chunks.length > GRID_MAX ? `(first ${GRID_MAX} shown)` : ''}
                </span>
                <div className="ml-auto flex gap-2">
                  <Button variant="danger" size="sm" onClick={flip} disabled={busy}><Skull className="size-3.5" aria-hidden="true" />Change one byte</Button>
                  <Button variant="secondary" size="sm" onClick={undo} disabled={!flipped.length}><RotateCcw className="size-3.5" aria-hidden="true" />Undo</Button>
                </div>
              </div>
              <div className="scroll-thin flex max-h-48 flex-wrap gap-1 overflow-y-auto rounded-xl bg-black/25 p-3 ring-1 ring-white/[0.06]">
                {current.chunks.slice(0, GRID_MAX).map((h, i) => (
                  <span key={i} title={`Piece ${i + 1}: ${h}`}
                    className={cx('size-3.5 rounded-[3px] transition', changed[i] ? 'animate-flash bg-red-500' : '')}
                    style={changed[i] ? undefined : { background: `hsl(${parseInt(h.slice(0, 4), 16) % 360} 55% 45% / .75)` }} />
                ))}
              </div>
              {tampered && (
                <Banner tone="bad" icon={XCircle} className="mt-3"
                  title={`Changed ${flipped.length} byte${flipped.length === 1 ? '' : 's'} out of ${data.length.toLocaleString()} — the root fingerprint is completely different`}>
                  The red square{changed.filter(Boolean).length === 1 ? ' shows the piece' : 's show the pieces'} that changed. This is how MerkleTrust spots
                  tampering — and pinpoints <em>where</em> it happened.
                </Banner>
              )}
            </div>

            {current.chunks.length <= 16 && current.chunks.length > 1 && (
              <div className="rounded-xl bg-black/20 p-3 ring-1 ring-white/[0.06]">
                <MerkleTreeView levels={current.levels} marks={marks}
                  labels={current.chunks.map((_, i) => `Piece ${i + 1}`)} leafTitle="Piece" />
              </div>
            )}
            {current.chunks.length === 1 && (
              <p className="text-xs text-zinc-500">This file fits in a single piece. Choose a smaller piece size to see a full tree.</p>
            )}
          </>
        )}
        {!file && (
          <p className="flex items-center gap-2 text-xs text-zinc-500">
            <FileUp className="size-3.5" aria-hidden="true" />
            Try <code className="text-zinc-300">samples/clean_photo.jpg</code> from the project folder.
          </p>
        )}
      </div>
    </Card>
  );
}

// ------------------------------------------------------------------- page --

export default function MerkleLab() {
  return (
    <div className="animate-fade-in space-y-8">
      <PageHeader
        eyebrow="Interactive demo"
        title="Merkle Tree Lab"
        description="A Merkle tree turns lots of data into one short fingerprint, the root. Change anything, even one letter, and the root changes. That is how MerkleTrust catches tampering."
      />
      <Explain title="Explain it simply">
        <p><strong className="text-zinc-100">1. Fingerprint every item.</strong> Each item gets a SHA-256 hash: a 64-character code that changes completely if the item changes at all.</p>
        <p><strong className="text-zinc-100">2. Pair them up.</strong> Two neighbouring hashes are joined and hashed again, level by level, until one hash is left: the root.</p>
        <p><strong className="text-zinc-100">3. Compare roots.</strong> If the root matches the trusted one, nothing changed. If it doesn’t, following the red boxes down shows exactly which item was altered.</p>
        <p className="text-xs text-zinc-500">This page uses the same RFC 6962 rules as the server, so the hashes here match the server’s exactly.</p>
      </Explain>
      <TreeLab />
      <FileLab />
    </div>
  );
}
