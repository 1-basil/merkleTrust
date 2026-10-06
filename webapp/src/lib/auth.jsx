import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api, session, setUnauthorizedHandler } from './api.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => session.get()?.user || null);
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      session.clear();
      setUser(null);
      setExpired(true);
    });
  }, []);

  const login = useCallback(async (username, password) => {
    const res = await api.post('/auth/login', { username, password });
    session.set({ token: res.access_token, user: res.user, expires_at: res.expires_at });
    setExpired(false);
    setUser(res.user);
  }, []);

  const logout = useCallback(async () => {
    try { await api.post('/auth/logout'); } catch { /* the session may already be gone */ }
    session.clear();
    setUser(null);
  }, []);

  const value = useMemo(() => ({ user, expired, login, logout }), [user, expired, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}
