import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { Blocks, History, Home, LogOut, Menu, MonitorPlay, Network, ShieldCheck, Stamp, Upload, X } from 'lucide-react';
import { api } from '../lib/api.js';
import { useAuth } from '../lib/auth.jsx';
import { cx } from './ui.jsx';

const LINKS = [
  { to: '/', label: 'Home', icon: Home, end: true },
  { to: '/scan', label: 'Scan', icon: Upload },
  { to: '/history', label: 'History', icon: History },
  { to: '/merkle', label: 'Merkle Tree', icon: Network },
  { to: '/chain', label: 'Blockchain', icon: Blocks },
  { to: '/baselines', label: 'Trusted Apps', icon: Stamp },
];

// Projector mode scales the whole UI up (every size is in rem).
const PRESENT_KEY = 'merkletrust.present';
function usePresentMode() {
  const [on, setOn] = useState(() => { try { return localStorage.getItem(PRESENT_KEY) === '1'; } catch { return false; } });
  useEffect(() => {
    document.documentElement.classList.toggle('present', on);
    try { localStorage.setItem(PRESENT_KEY, on ? '1' : '0'); } catch { /* storage unavailable */ }
  }, [on]);
  return [on, setOn];
}

function useBackendStatus() {
  const [status, setStatus] = useState('checking');
  useEffect(() => {
    let alive = true;
    const check = async () => {
      try {
        await api.get('/health');
        if (alive) setStatus('online');
      } catch {
        if (alive) setStatus('offline');
      }
    };
    check();
    const id = setInterval(check, 15000);
    return () => { alive = false; clearInterval(id); };
  }, []);
  return status;
}

function StatusPill() {
  const status = useBackendStatus();
  const [dot, text, label] = {
    online: ['bg-emerald-400', 'text-emerald-300', 'Server online'],
    offline: ['bg-red-400', 'text-red-300', 'Server offline'],
    checking: ['bg-zinc-400', 'text-zinc-400', 'Connecting…'],
  }[status];
  return (
    <span role="status" title={label}
      className={cx('inline-flex items-center gap-2 rounded-full bg-white/[0.04] px-2.5 py-1 text-xs ring-1 ring-white/10', text)}>
      <span className="relative flex size-2">
        {status === 'online' && <span className={cx('absolute inline-flex size-full animate-ping rounded-full opacity-60', dot)} />}
        <span className={cx('relative inline-flex size-2 rounded-full', dot)} />
      </span>
      <span className="hidden sm:inline">{label}</span>
    </span>
  );
}

function Link({ to, label, icon: Icon, onClick, end }) {
  return (
    <NavLink
      to={to}
      end={end}
      onClick={onClick}
      className={({ isActive }) => cx(
        'relative flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition',
        isActive ? 'bg-white/[0.07] text-zinc-50' : 'text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-100',
      )}
    >
      {({ isActive }) => (
        <>
          <Icon className="size-4" aria-hidden="true" />
          {label}
          {isActive && <span className="absolute inset-x-3 -bottom-[13px] hidden h-0.5 rounded-full bg-gradient-to-r from-emerald-400 to-sky-400 lg:block" />}
        </>
      )}
    </NavLink>
  );
}

export default function Navbar() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const [present, setPresent] = usePresentMode();
  return (
    <header className="sticky top-0 z-30 border-b border-white/[0.06] bg-[#060910]/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-7xl items-center gap-4 px-4 sm:px-6">
        <NavLink to="/" className="flex items-center gap-2.5 text-lg font-bold tracking-tight text-zinc-50">
          <span className="grid size-8 place-items-center rounded-xl bg-gradient-to-br from-emerald-400 to-sky-500 shadow-lg shadow-emerald-500/25">
            <ShieldCheck className="size-4 text-zinc-950" aria-hidden="true" />
          </span>
          <span>Merkle<span className="text-gradient">Trust</span></span>
        </NavLink>
        <nav className="hidden flex-1 items-center gap-0.5 lg:flex" aria-label="Main">
          {LINKS.map((l) => <Link key={l.to} {...l} />)}
        </nav>
        <div className="ml-auto flex items-center gap-2">
          <StatusPill />
          <button type="button" onClick={() => setPresent((v) => !v)} aria-pressed={present}
            title={present ? 'Projector mode is on (bigger text)' : 'Projector mode: bigger text for presenting'}
            className={cx('rounded-lg p-2 transition', present ? 'bg-emerald-500/15 text-emerald-300' : 'text-zinc-400 hover:bg-white/[0.06] hover:text-zinc-100')}>
            <MonitorPlay className="size-4" aria-hidden="true" />
            <span className="sr-only">Projector mode</span>
          </button>
          <span className="hidden text-xs text-zinc-500 xl:inline">{user?.username} · {user?.role}</span>
          <button type="button" onClick={logout} title="Sign out" aria-label="Sign out"
            className="rounded-lg p-2 text-zinc-400 hover:bg-white/[0.06] hover:text-zinc-100">
            <LogOut className="size-4" aria-hidden="true" />
          </button>
          <button type="button" onClick={() => setOpen((v) => !v)} aria-expanded={open} aria-label="Menu"
            className="rounded-lg p-2 text-zinc-300 hover:bg-white/[0.06] lg:hidden">
            {open ? <X className="size-5" aria-hidden="true" /> : <Menu className="size-5" aria-hidden="true" />}
          </button>
        </div>
      </div>
      {open && (
        <nav className="grid gap-1 border-t border-white/[0.06] px-4 py-3 lg:hidden" aria-label="Main mobile">
          {LINKS.map((l) => <Link key={l.to} {...l} onClick={() => setOpen(false)} />)}
        </nav>
      )}
    </header>
  );
}
