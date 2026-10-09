import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import Navbar from './components/Navbar.jsx';
import { useAuth } from './lib/auth.jsx';
import Baselines from './pages/Baselines.jsx';
import Chain from './pages/Chain.jsx';
import History from './pages/History.jsx';
import Login from './pages/Login.jsx';
import Result from './pages/Result.jsx';
import Scan from './pages/Scan.jsx';

function RequireAuth({ children }) {
  const { user } = useAuth();
  const location = useLocation();
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return children;
}

export default function App() {
  const { user } = useAuth();
  return (
    <div className="min-h-dvh bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,rgba(16,185,129,0.08),transparent)]">
      {user && <Navbar />}
      <main className="mx-auto w-full max-w-6xl px-4 pb-16 pt-8 sm:px-6">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/scan" element={<RequireAuth><Scan /></RequireAuth>} />
          <Route path="/results/:jobId" element={<RequireAuth><Result /></RequireAuth>} />
          <Route path="/history" element={<RequireAuth><History /></RequireAuth>} />
          <Route path="/chain" element={<RequireAuth><Chain /></RequireAuth>} />
          <Route path="/baselines" element={<RequireAuth><Baselines /></RequireAuth>} />
          <Route path="*" element={<Navigate to="/scan" replace />} />
        </Routes>
      </main>
    </div>
  );
}
