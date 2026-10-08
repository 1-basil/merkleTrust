import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import Navbar from './components/Navbar.jsx';
import { useAuth } from './lib/auth.jsx';
import Baselines from './pages/Baselines.jsx';
import Chain from './pages/Chain.jsx';
import History from './pages/History.jsx';
import Home from './pages/Home.jsx';
import Login from './pages/Login.jsx';
import MerkleLab from './pages/MerkleLab.jsx';
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
    <div className="min-h-dvh">
      {user && <Navbar />}
      <main className="mx-auto w-full max-w-7xl px-4 pb-20 pt-8 sm:px-6">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<RequireAuth><Home /></RequireAuth>} />
          <Route path="/merkle" element={<RequireAuth><MerkleLab /></RequireAuth>} />
          <Route path="/scan" element={<RequireAuth><Scan /></RequireAuth>} />
          <Route path="/results/:jobId" element={<RequireAuth><Result /></RequireAuth>} />
          <Route path="/history" element={<RequireAuth><History /></RequireAuth>} />
          <Route path="/chain" element={<RequireAuth><Chain /></RequireAuth>} />
          <Route path="/baselines" element={<RequireAuth><Baselines /></RequireAuth>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
