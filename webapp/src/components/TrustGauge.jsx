import { TONES } from '../lib/format.js';

// Circular trust-score gauge. `value` is 0–100 or null (not scored).
export default function TrustGauge({ value, tone, label, size = 168 }) {
  const stroke = 12;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const pct = value === null || value === undefined ? 0 : value / 100;
  const color = TONES[tone]?.stroke || TONES.neutral.stroke;
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90" aria-hidden="true">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={stroke} />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - pct)}
          style={{ transition: 'stroke-dashoffset 900ms cubic-bezier(.2,.8,.2,1)', filter: `drop-shadow(0 0 10px ${color}55)` }}
        />
      </svg>
      <div className="absolute text-center" role="img" aria-label={`Trust score ${value ?? 'not available'} out of 100, ${label}`}>
        <div className="text-4xl font-semibold tabular-nums tracking-tight text-zinc-50">
          {value ?? '—'}<span className="text-base font-normal text-zinc-500"> / 100</span>
        </div>
        <div className="mt-0.5 text-xs font-medium" style={{ color }}>{label}</div>
      </div>
    </div>
  );
}
