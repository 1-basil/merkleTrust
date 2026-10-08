import { hashHue } from '../lib/merkle.js';

// SVG drawing of a Merkle tree, root at the top and leaves at the bottom.
// `marks` maps "level:index" to 'changed' | 'path' | 'sibling' for highlighting.

const NODE_W = 92;
const NODE_H = 36;
const ROW = 92;
const PAD_TOP = 34;

const STYLE = {
  plain: { fill: '#16161b', stroke: 'rgba(255,255,255,0.16)', text: '#d4d4d8' },
  changed: { fill: 'rgba(239,68,68,0.18)', stroke: '#f87171', text: '#fecaca', glow: '#ef4444' },
  path: { fill: 'rgba(16,185,129,0.16)', stroke: '#34d399', text: '#a7f3d0', glow: '#10b981' },
  sibling: { fill: 'rgba(245,158,11,0.16)', stroke: '#fbbf24', text: '#fde68a', glow: '#f59e0b' },
};

function layout(levels, slot) {
  const pos = [];
  pos[0] = levels[0].map((_, i) => slot * (i + 0.5));
  for (let k = 1; k < levels.length; k += 1) {
    const below = pos[k - 1];
    pos[k] = levels[k].map((_, j) => {
      const a = below[2 * j];
      const b = below[2 * j + 1];
      return b === undefined ? a : (a + b) / 2; // a promoted node sits above its only child
    });
  }
  return pos;
}

const clip = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export default function MerkleTreeView({ levels, labels = [], marks = {}, selected, onSelect, leafTitle = 'Item' }) {
  if (!levels?.length) return null;
  const n = levels[0].length;
  const slot = n > 8 ? 104 : 124;
  const width = Math.max(slot * n, 320);
  const depth = levels.length;
  const height = PAD_TOP + (depth - 1) * ROW + NODE_H + 40;
  const pos = layout(levels, slot);
  const yOf = (k) => PAD_TOP + (depth - 1 - k) * ROW;
  const markOf = (k, i) => marks[`${k}:${i}`];

  const edges = [];
  for (let k = 1; k < depth; k += 1) {
    levels[k].forEach((_, j) => {
      [2 * j, 2 * j + 1].forEach((c) => {
        if (c >= levels[k - 1].length) return;
        const child = markOf(k - 1, c);
        const parent = markOf(k, j);
        const tone = child === 'changed' && parent === 'changed' ? 'changed'
          : (child === 'path' || child === 'sibling') && parent === 'path' ? 'path' : null;
        const [cx, cy, px, py] = [pos[k - 1][c], yOf(k - 1), pos[k][j], yOf(k) + NODE_H];
        const mid = (cy + py) / 2;
        edges.push(
          <path key={`e${k}-${j}-${c}`}
            d={`M ${cx} ${cy} C ${cx} ${mid}, ${px} ${mid}, ${px} ${py}`}
            fill="none"
            stroke={tone ? STYLE[tone].stroke : 'rgba(255,255,255,0.14)'}
            strokeWidth={tone ? 2.25 : 1.5}
            strokeDasharray={tone === 'path' ? '5 4' : undefined}
            className={tone === 'path' ? 'animate-dash' : undefined}
            style={{ transition: 'stroke 400ms' }}
          />,
        );
      });
    });
  }

  const nodes = [];
  levels.forEach((level, k) => {
    level.forEach((hash, i) => {
      const isRoot = k === depth - 1;
      const isLeaf = k === 0;
      const st = STYLE[markOf(k, i)] || STYLE.plain;
      const x = pos[k][i] - NODE_W / 2;
      const y = yOf(k);
      const hue = hashHue(hash);
      const clickable = isLeaf && onSelect;
      nodes.push(
        <g key={`n${k}-${i}`} transform={`translate(${x} ${y})`}
          onClick={clickable ? () => onSelect(i) : undefined}
          onKeyDown={clickable ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(i); } } : undefined}
          role={clickable ? 'button' : undefined} tabIndex={clickable ? 0 : undefined}
          aria-label={clickable ? `${leafTitle} ${i + 1}: ${labels[i] ?? ''}` : undefined}
          style={{ cursor: clickable ? 'pointer' : 'default', outline: 'none' }}>
          {isLeaf && selected === i && (
            <rect x={-5} y={-5} width={NODE_W + 10} height={NODE_H + 10} rx={14} fill="none" stroke="#34d399" strokeWidth={2} opacity={0.9} />
          )}
          <rect width={NODE_W} height={NODE_H} rx={10} fill={st.fill} stroke={st.stroke} strokeWidth={isRoot ? 2 : 1.5}
            style={{ transition: 'fill 400ms, stroke 400ms', filter: st.glow ? `drop-shadow(0 0 7px ${st.glow})` : undefined }} />
          <circle cx={14} cy={NODE_H / 2} r={5} fill={`hsl(${hue} 80% 60%)`} style={{ transition: 'fill 400ms' }} />
          <text x={25} y={NODE_H / 2 + 4} fontSize={12} fontFamily="ui-monospace, Consolas, monospace" fill={st.text}>
            {hash.slice(0, 7)}
          </text>
          {isRoot && (
            <text x={NODE_W / 2} y={-10} textAnchor="middle" fontSize={11} fontWeight={700} letterSpacing="0.14em" fill="#6ee7b7">
              ROOT FINGERPRINT
            </text>
          )}
          {isLeaf && (
            <text x={NODE_W / 2} y={NODE_H + 18} textAnchor="middle" fontSize={11}
              fill={markOf(k, i) === 'changed' ? '#fca5a5' : '#a1a1aa'}>
              {clip(labels[i] ?? `${leafTitle} ${i + 1}`, 15)}
            </text>
          )}
        </g>,
      );
    });
  });

  return (
    <div className="scroll-thin overflow-x-auto">
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" style={{ minWidth: Math.min(width, 640) }} className="mx-auto block max-h-[440px]"
        role="img" aria-label={`Merkle tree with ${n} items and ${depth} levels`}>
        {edges}
        {nodes}
      </svg>
    </div>
  );
}

export function TreeLegend() {
  const item = (color, text) => (
    <span className="inline-flex items-center gap-1.5">
      <span className="size-3 rounded-[4px] ring-1" style={{ background: `${color}33`, borderColor: color, boxShadow: `inset 0 0 0 1.5px ${color}` }} />
      {text}
    </span>
  );
  return (
    <div className="flex flex-wrap gap-x-5 gap-y-2 text-xs text-zinc-400">
      {item('#f87171', 'Changed by tampering')}
      {item('#34d399', 'Path from the item up to the root')}
      {item('#fbbf24', 'Hashes needed for the proof')}
      <span className="inline-flex items-center gap-1.5"><span className="size-3 rounded-full bg-gradient-to-r from-pink-400 via-amber-300 to-sky-400" />Same colour = same hash</span>
    </div>
  );
}
