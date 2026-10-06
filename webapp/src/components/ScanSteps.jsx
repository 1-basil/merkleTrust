import { AlertTriangle, CheckCircle2, Circle, Loader2 } from 'lucide-react';
import { cx } from './ui.jsx';

// The four user-facing steps, each backed by one or more pipeline engines.
const STEPS = [
  { label: 'Calculating cryptographic Merkle root', hint: 'Fingerprinting every byte of the file', engines: ['integrity'] },
  { label: 'Inspecting file structure & code', hint: 'Looking for hidden data, tampering and risky code',
    engines: ['static', 'tamper', 'dynamic', 'content'] },
  { label: 'Generating security score', hint: 'Turning findings into a trust score', engines: ['score'] },
  { label: 'Signing audit block', hint: 'Sealing the result in the tamper-evident ledger', engines: ['repository'] },
];

const FINISHED = new Set(['ok', 'partial', 'failed', 'skipped']);

function stepState(engines, names, jobStatus) {
  const present = names.map((n) => engines?.[n]?.status).filter((s) => s && s !== 'skipped');
  if (present.includes('running')) return 'running';
  if (present.length && present.every((s) => FINISHED.has(s))) {
    return present.includes('failed') ? 'failed' : 'done';
  }
  if (jobStatus === 'done' || jobStatus === 'failed') return present.length ? 'failed' : 'done';
  return 'pending';
}

export default function ScanSteps({ scan }) {
  const states = STEPS.map((s) => stepState(scan?.engines, s.engines, scan?.status));
  // Show the first unfinished step as running even between engine status updates.
  const firstPending = states.indexOf('pending');
  if (firstPending >= 0 && !states.includes('running') && scan && scan.status !== 'queued') states[firstPending] = 'running';

  return (
    <ol className="space-y-3">
      {STEPS.map((s, i) => {
        const st = states[i];
        const Icon = { done: CheckCircle2, running: Loader2, failed: AlertTriangle, pending: Circle }[st];
        return (
          <li key={s.label} className={cx('flex items-start gap-3 rounded-xl px-3 py-2.5 transition',
            st === 'running' && 'bg-emerald-500/[0.06] ring-1 ring-emerald-500/20')}>
            <Icon aria-hidden="true" className={cx('mt-0.5 size-5 shrink-0',
              st === 'done' && 'text-emerald-400', st === 'running' && 'animate-spin text-emerald-300',
              st === 'failed' && 'text-amber-400', st === 'pending' && 'text-zinc-600')} />
            <div>
              <p className={cx('text-sm', st === 'pending' ? 'text-zinc-500' : 'text-zinc-100')}>
                {i + 1}. {s.label}{st === 'running' ? '…' : ''}
              </p>
              <p className="text-xs text-zinc-500">{st === 'failed' ? 'Completed with problems — see the report.' : s.hint}</p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
