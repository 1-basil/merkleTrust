import { useState } from 'react';
import { AlertTriangle, Check, Copy, Info, Loader2 } from 'lucide-react';
import { FILE_TYPES, SEVERITY_STYLE, TONES } from '../lib/format.js';

export function cx(...parts) {
  return parts.filter(Boolean).join(' ');
}

export function Card({ className, children, ...rest }) {
  return (
    <section
      className={cx('rounded-2xl border border-white/[0.07] bg-zinc-900/60 shadow-xl shadow-black/20 backdrop-blur',
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

export function PageHeader({ title, description, action }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-50 sm:text-3xl">{title}</h1>
        {description && <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-zinc-400">{description}</p>}
      </div>
      {action}
    </div>
  );
}

export function Button({ variant = 'primary', className, children, loading, ...rest }) {
  const styles = {
    primary: 'bg-emerald-500 text-zinc-950 hover:bg-emerald-400 disabled:bg-emerald-500/40',
    secondary: 'bg-white/[0.06] text-zinc-100 ring-1 ring-white/10 hover:bg-white/[0.1] disabled:opacity-50',
    ghost: 'text-zinc-300 hover:bg-white/[0.06] hover:text-zinc-100',
  };
  return (
    <button
      type="button"
      className={cx('inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition',
        'disabled:cursor-not-allowed', styles[variant], className)}
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
