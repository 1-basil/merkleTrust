import { useState } from 'react';
import { AlertTriangle, Check, ChevronDown, Copy, Info, Lightbulb, Loader2 } from 'lucide-react';
import { FILE_TYPES, SEVERITY_STYLE, TONES } from '../lib/format.js';
import { hashHue } from '../lib/merkle.js';

export function cx(...parts) {
  return parts.filter(Boolean).join(' ');
}

export function Card({ className, children, ...rest }) {
  return (
    <section
      className={cx('rounded-2xl border border-white/[0.08] bg-zinc-900/55 shadow-xl shadow-black/30 backdrop-blur-md',
        className)}
      {...rest}
    >
      {children}
    </section>
  );
}

export function CardHeader({ icon: Icon, title, subtitle, action }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-white/[0.06] px-5 py-4">
      <div className="flex min-w-0 items-start gap-3">
        {Icon && (
          <span className="mt-0.5 grid size-8 shrink-0 place-items-center rounded-lg bg-white/[0.04] ring-1 ring-white/10">
            <Icon className="size-4 text-zinc-300" aria-hidden="true" />
          </span>
        )}
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-zinc-100">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs leading-relaxed text-zinc-400">{subtitle}</p>}
        </div>
      </div>
      {action}
    </div>
  );
}

export function PageHeader({ eyebrow, title, description, action }) {
  return (
    <div className="mb-7 flex flex-wrap items-end justify-between gap-4">
      <div>
        {eyebrow && <p className="mb-2 text-xs font-semibold uppercase tracking-[0.18em] text-emerald-400/90">{eyebrow}</p>}
        <h1 className="text-3xl font-bold tracking-tight text-zinc-50 sm:text-4xl">{title}</h1>
        {description && <p className="mt-2 max-w-2xl text-[15px] leading-relaxed text-zinc-400">{description}</p>}
      </div>
      {action}
    </div>
  );
}

export function Button({ variant = 'primary', size = 'md', className, children, loading, ...rest }) {
  const styles = {
    primary: 'bg-gradient-to-b from-emerald-400 to-emerald-500 text-zinc-950 shadow-lg shadow-emerald-500/20 hover:from-emerald-300 hover:to-emerald-400 disabled:from-emerald-500/40 disabled:to-emerald-500/40 disabled:shadow-none',
    secondary: 'bg-white/[0.06] text-zinc-100 ring-1 ring-white/10 hover:bg-white/[0.1] disabled:opacity-50',
    ghost: 'text-zinc-300 hover:bg-white/[0.06] hover:text-zinc-100 disabled:opacity-50',
    danger: 'bg-gradient-to-b from-red-500 to-red-600 text-white shadow-lg shadow-red-500/20 hover:from-red-400 hover:to-red-500 disabled:opacity-40 disabled:shadow-none',
  };
  const sizes = { sm: 'px-2.5 py-1.5 text-xs', md: 'px-3.5 py-2 text-sm', lg: 'px-5 py-3 text-base' };
  return (
    <button
      type="button"
      className={cx('inline-flex items-center justify-center gap-2 rounded-xl font-semibold transition active:scale-[.98]',
        'disabled:cursor-not-allowed', sizes[size], styles[variant], className)}
      disabled={loading || rest.disabled}
      {...rest}
    >
      {loading && <Loader2 className="size-4 animate-spin" aria-hidden="true" />}
      {children}
    </button>
  );
}

export function Badge({ className, children }) {
  return (
    <span className={cx('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset',
      className)}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }) {
  return <Badge className={cx('capitalize', SEVERITY_STYLE[severity] || SEVERITY_STYLE.info)}>{severity}</Badge>;
}

export function ToneBadge({ tone, children, icon: Icon }) {
  const t = TONES[tone] || TONES.neutral;
  return (
    <Badge className={cx(t.text, t.bg, t.ring)}>
      {Icon && <Icon className="size-3.5" aria-hidden="true" />}
      {children}
    </Badge>
  );
}

export function FileTypeBadge({ category, format }) {
  const t = FILE_TYPES[category] || FILE_TYPES.unknown;
  const Icon = t.icon;
  return (
    <Badge className={t.tint}>
      <Icon className="size-3.5" aria-hidden="true" />
      {t.label}
      {format && <span className="opacity-70">· {format}</span>}
    </Badge>
  );
}

export function Tooltip({ text, children }) {
  return (
    <span className="group relative inline-flex">
      {children}
      <span
        role="tooltip"
        className="pointer-events-none absolute bottom-full left-1/2 z-20 mb-2 w-64 -translate-x-1/2 rounded-lg border border-white/10
          bg-zinc-800 px-3 py-2 text-xs leading-relaxed text-zinc-200 opacity-0 shadow-xl transition group-hover:opacity-100
          group-focus-within:opacity-100"
      >
        {text}
      </span>
    </span>
  );
}

export function InfoTip({ text }) {
  return (
    <Tooltip text={text}>
      <button type="button" className="rounded text-zinc-500 hover:text-zinc-300" aria-label={text}>
        <Info className="size-3.5" aria-hidden="true" />
      </button>
    </Tooltip>
  );
}

export function CopyHash({ value, display, className }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="font-mono text-xs text-zinc-500">—</span>;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard blocked */ }
  };
  return (
    <button
      type="button"
      onClick={copy}
      title={value}
      className={cx('group inline-flex max-w-full items-center gap-2 rounded-md bg-black/30 px-2 py-1 font-mono text-xs text-zinc-300',
        'ring-1 ring-white/10 transition hover:text-zinc-100 hover:ring-white/20', className)}
    >
      <span className="truncate">{display || value}</span>
      {copied
        ? <Check className="size-3.5 shrink-0 text-emerald-400" aria-label="Copied" />
        : <Copy className="size-3.5 shrink-0 opacity-60 group-hover:opacity-100" aria-hidden="true" />}
    </button>
  );
}

export function Spinner({ label = 'Loading…' }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-sm text-zinc-400" role="status">
      <Loader2 className="size-4 animate-spin" aria-hidden="true" /> {label}
    </div>
  );
}

export function ErrorBox({ error, className }) {
  if (!error) return null;
  return (
    <div role="alert" className={cx('flex items-start gap-2 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200', className)}>
      <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{error.message || String(error)}</span>
    </div>
  );
}

export function Empty({ icon: Icon, title, children }) {
  return (
    <div className="flex flex-col items-center gap-2 px-6 py-14 text-center">
      {Icon && <Icon className="size-8 text-zinc-600" aria-hidden="true" />}
      <p className="text-sm font-medium text-zinc-300">{title}</p>
      {children && <p className="max-w-sm text-sm text-zinc-500">{children}</p>}
    </div>
  );
}

export function ProgressBar({ value, tone = 'good' }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06]" role="progressbar"
      aria-valuenow={Math.round(value * 100)} aria-valuemin={0} aria-valuemax={100}>
      <div className="h-full rounded-full transition-all duration-300"
        style={{ width: `${Math.round(value * 100)}%`, background: TONES[tone].stroke }} />
    </div>
  );
}

// A hash shown with a colour swatch derived from its first bytes: equal hashes get
// equal colours, so a matching (or broken) link is visible without reading hex.
export function HashChip({ value, n = 8, className, label }) {
  if (!value) return <span className="font-mono text-xs text-zinc-600">—</span>;
  const hue = hashHue(value);
  return (
    <span title={value} className={cx('inline-flex max-w-full items-center gap-1.5 rounded-md bg-black/35 px-1.5 py-0.5 font-mono text-[11px] text-zinc-300 ring-1 ring-white/10', className)}>
      <span className="size-2.5 shrink-0 rounded-sm" style={{ background: `hsl(${hue} 80% 60%)`, boxShadow: `0 0 8px hsl(${hue} 80% 60% / .6)` }} aria-hidden="true" />
      {label && <span className="text-zinc-500">{label}</span>}
      <span className="truncate">{value.slice(0, n)}</span>
    </span>
  );
}

export function Tabs({ tabs, value, onChange }) {
  return (
    <div role="tablist" className="scroll-thin mb-6 flex gap-1 overflow-x-auto rounded-2xl border border-white/[0.08] bg-zinc-900/50 p-1 backdrop-blur">
      {tabs.map(({ id, label, icon: Icon, count, tone }) => (
        <button key={id} type="button" role="tab" aria-selected={value === id} onClick={() => onChange(id)}
          className={cx('flex shrink-0 items-center gap-2 rounded-xl px-4 py-2 text-sm font-medium transition',
            value === id ? 'bg-white/[0.09] text-zinc-50 shadow-inner shadow-white/5' : 'text-zinc-400 hover:text-zinc-100')}>
          {Icon && <Icon className="size-4" aria-hidden="true" />}
          {label}
          {count !== undefined && count !== null && (
            <span className={cx('rounded-full px-1.5 text-[11px] tabular-nums', tone ? `${TONES[tone].bg} ${TONES[tone].text}` : 'bg-white/10 text-zinc-300')}>{count}</span>
          )}
        </button>
      ))}
    </div>
  );
}

export function Stat({ icon: Icon, label, value, tone = 'neutral', hint, className }) {
  const t = TONES[tone] || TONES.neutral;
  return (
    <Card className={cx('relative overflow-hidden p-5', className)}>
      <div className="flex items-start justify-between gap-3">
        <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">{label}</p>
        {Icon && (
          <span className={cx('grid size-9 place-items-center rounded-xl ring-1', t.bg, t.ring)}>
            <Icon className={cx('size-4', t.text)} aria-hidden="true" />
          </span>
        )}
      </div>
      <p className="mt-2 text-3xl font-bold tabular-nums tracking-tight text-zinc-50">{value}</p>
      {hint && <p className={cx('mt-1 text-xs', tone === 'neutral' ? 'text-zinc-500' : t.text)}>{hint}</p>}
    </Card>
  );
}

// "How does this work?" — a plain-language explanation the presenter can open on demand.
export function Explain({ title = 'How does this work?', children, defaultOpen = false, className }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={cx('rounded-2xl border border-sky-400/20 bg-sky-400/[0.05]', className)}>
      <button type="button" onClick={() => setOpen((v) => !v)} aria-expanded={open}
        className="flex w-full items-center gap-2 px-4 py-3 text-left text-sm font-medium text-sky-200">
        <Lightbulb className="size-4 shrink-0 text-sky-300" aria-hidden="true" />
        {title}
        <ChevronDown className={cx('ml-auto size-4 transition', open && 'rotate-180')} aria-hidden="true" />
      </button>
      {open && <div className="animate-fade-in space-y-2 px-4 pb-4 text-sm leading-relaxed text-zinc-300">{children}</div>}
    </div>
  );
}

const BANNER_STYLE = {
  good: 'border-emerald-500/30 bg-emerald-500/[0.08]',
  warn: 'border-amber-500/30 bg-amber-500/[0.08]',
  bad: 'border-red-500/40 bg-red-500/[0.10]',
  neutral: 'border-white/10 bg-white/[0.03]',
};

export function Banner({ tone = 'good', icon: Icon, title, children, className, pulse }) {
  const t = TONES[tone] || TONES.neutral;
  return (
    <div role="status" className={cx('relative flex items-start gap-4 overflow-hidden rounded-2xl border p-5 animate-fade-in',
      BANNER_STYLE[tone], className)}>
      {Icon && (
        <span className={cx('relative grid size-12 shrink-0 place-items-center rounded-2xl ring-1', t.bg, t.ring)}>
          {pulse && <span className={cx('absolute inset-0 animate-ping rounded-2xl opacity-30', t.bg)} />}
          <Icon className={cx('size-6', t.text)} aria-hidden="true" />
        </span>
      )}
      <div className="min-w-0">
        <p className={cx('text-lg font-semibold', t.text)}>{title}</p>
        {children && <div className="mt-0.5 text-sm leading-relaxed text-zinc-300">{children}</div>}
      </div>
    </div>
  );
}
