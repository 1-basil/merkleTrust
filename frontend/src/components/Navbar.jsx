import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { Database, History, Link2, LogOut, Menu, ShieldCheck, Upload, X } from 'lucide-react';
import { api } from '../lib/api.js';
import { useAuth } from '../lib/auth.jsx';
import { cx } from './ui.jsx';

const LINKS = [
  { to: '/scan', label: 'Upload & Scan', icon: Upload },
  { to: '/history', label: 'Scan History', icon: History },
  { to: '/chain', label: 'Audit Ledger', icon: Link2 },
  { to: '/baselines', label: 'Baselines', icon: Database },
];

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
    online: ['bg-emerald-400', 'text-emerald-300', 'Backend online'],
    offline: ['bg-red-400', 'text-red-300', 'Backend offline'],
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

function Link({ to, label, icon: Icon, onClick }) {
  return (
    <NavLink
      to={to}
      onClick={onClick}
      className={({ isActive }) => cx(
        'relative flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition',
        isActive ? 'bg-white/[0.07] text-zinc-50' : 'text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-100',
      )}
    >
      {({ isActive }) => (
        <>
          <Icon className="size-4" aria-hidden="true" />
          {label}
          {isActive && <span className="absolute inset-x-3 -bottom-[11px] hidden h-px bg-emerald-400 md:block" />}
        </>
      )}
    </NavLink>
  );
}

export default function Navbar() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  return (
    <header className="sticky top-0 z-30 border-b border-white/[0.06] bg-zinc-950/80 backdrop-blur-lg">
      <div className="mx-auto flex h-14 max-w-6xl items-center gap-4 px-4 sm:px-6">
        <NavLink to="/scan" className="flex items-center gap-2 font-semibold text-zinc-50">
          <span className="grid size-7 place-items-center rounded-lg bg-emerald-500/15 ring-1 ring-emerald-500/30">
            <ShieldCheck className="size-4 text-emerald-400" aria-hidden="true" />
          </span>
          MerkleTrust
        </NavLink>
        <nav className="hidden flex-1 items-center gap-1 md:flex" aria-label="Main">
          {LINKS.map((l) => <Link key={l.to} {...l} />)}
        </nav>
        <div className="ml-auto flex items-center gap-2">
          <StatusPill />
          <span className="hidden text-xs text-zinc-500 lg:inline">{user?.username} · {user?.role}</span>
          <button type="button" onClick={logout} title="Sign out" aria-label="Sign out"
            className="rounded-lg p-2 text-zinc-400 hover:bg-white/[0.06] hover:text-zinc-100">
            <LogOut className="size-4" aria-hidden="true" />
          </button>
          <button type="button" onClick={() => setOpen((v) => !v)} aria-expanded={open} aria-label="Menu"
            className="rounded-lg p-2 text-zinc-300 hover:bg-white/[0.06] md:hidden">
            {open ? <X className="size-5" aria-hidden="true" /> : <Menu className="size-5" aria-hidden="true" />}
          </button>
        </div>
      </div>
      {open && (
        <nav className="grid gap-1 border-t border-white/[0.06] px-4 py-3 md:hidden" aria-label="Main mobile">
          {LINKS.map((l) => <Link key={l.to} {...l} onClick={() => setOpen(false)} />)}
        </nav>
      )}
    </header>
  );
}
