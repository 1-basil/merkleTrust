import { useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { Lock, ShieldCheck } from 'lucide-react';
import { Button, Card, ErrorBox } from '../components/ui.jsx';
import { useAuth } from '../lib/auth.jsx';

const FIELD = 'w-full rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-sm text-zinc-100 '
  + 'placeholder:text-zinc-600 focus:border-emerald-500/60 focus:outline-none';

export default function Login() {
  const { user, expired, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to={location.state?.from || '/'} replace />;

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
      navigate(location.state?.from || '/', { replace: true });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto mt-10 max-w-md animate-fade-in sm:mt-16">
      <div className="mb-8 flex flex-col items-center text-center">
        <span className="mb-5 grid size-16 animate-float place-items-center rounded-3xl bg-gradient-to-br from-emerald-400 to-sky-500 shadow-2xl shadow-emerald-500/30">
          <ShieldCheck className="size-8 text-zinc-950" aria-hidden="true" />
        </span>
        <h1 className="text-4xl font-bold tracking-tight text-zinc-50">Merkle<span className="text-gradient">Trust</span></h1>
        <p className="mt-2 text-base text-zinc-400">Prove any file is genuine, and that nobody changed it.</p>
        <div className="mt-5 flex flex-wrap justify-center gap-2 text-xs text-zinc-400">
          {['Merkle tree fingerprints', 'Signed results', 'Tamper-proof blockchain'].map((t) => (
            <span key={t} className="rounded-full bg-white/[0.05] px-3 py-1 ring-1 ring-white/10">{t}</span>
          ))}
        </div>
      </div>
      <Card className="p-6">
        <form onSubmit={submit} className="space-y-4">
          {expired && (
            <p className="rounded-lg bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
              Your session expired. Please sign in again.
            </p>
          )}
          <label className="block space-y-1.5">
            <span className="text-xs font-medium text-zinc-400">Username</span>
            <input className={FIELD} autoComplete="username" value={username}
              onChange={(e) => setUsername(e.target.value)} required />
          </label>
          <label className="block space-y-1.5">
            <span className="text-xs font-medium text-zinc-400">Password</span>
            <input className={FIELD} type="password" autoComplete="current-password" value={password}
              onChange={(e) => setPassword(e.target.value)} required />
          </label>
          <ErrorBox error={error} />
          <Button type="submit" className="w-full" loading={busy}>
            <Lock className="size-4" aria-hidden="true" /> Sign in
          </Button>
        </form>
      </Card>
      <p className="mt-4 text-center text-xs leading-relaxed text-zinc-500">
        Accounts are created by an administrator:<br />
        <code className="text-zinc-400">python -m scripts.manage_users create NAME --role analyst</code>
      </p>
    </div>
  );
}
