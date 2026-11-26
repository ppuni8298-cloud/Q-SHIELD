import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { api, extractErrorMessage, getStoredToken, setStoredToken } from '../api/client';

export interface SessionInfo {
  id: string;
  actor_id: string;
  device_id: string;
  peer_id: string | null;
  auth_strength: string;
  version: number;
  state: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
  issued_at: string;
  expires_at: string;
  revoked_at: string | null;
  revoke_reason: string | null;
}

export interface AuthMe {
  synthetic_mode: boolean;
  actor_id: string;
  display_name: string;
  role: string;
  enabled: boolean;
  session: SessionInfo;
  permissions: string[];
  correlation_id: string;
}

interface AuthContextValue {
  user: AuthMe | null;
  loading: boolean;
  error: string | null;
  login: (actorId: string, deviceId: string, peerId?: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshMe: () => Promise<void>;
  hasPermission: (perm: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthMe | null>(null);
  const [loading, setLoading] = useState<boolean>(Boolean(getStoredToken()));
  const [error, setError] = useState<string | null>(null);

  const refreshMe = useCallback(async () => {
    const token = getStoredToken();
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const me = await api.get<AuthMe>('/auth/me');
      setUser(me);
      setError(null);
    } catch (err) {
      const parsed = extractErrorMessage(err);
      if (parsed.code !== 'BACKEND_UNREACHABLE') {
        setStoredToken(null);
        setUser(null);
      }
      setError(`${parsed.code}: ${parsed.message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshMe();
  }, [refreshMe]);

  const login = useCallback(async (actorId: string, deviceId: string, peerId?: string) => {
    setError(null);
    const res = await api.post<{ access_token: string }>(
      '/auth/demo-login',
      { actor_id: actorId, device_id: deviceId, peer_id: peerId || null },
      false
    );
    setStoredToken(res.access_token);
    const me = await api.get<AuthMe>('/auth/me');
    setUser(me);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout', {});
    } catch {
      // Clear local session even if server already expired/revoked the token
    } finally {
      setStoredToken(null);
      setUser(null);
    }
  }, []);

  const hasPermission = useCallback(
    (perm: string) => {
      if (!user) return false;
      return user.permissions.includes(perm);
    },
    [user]
  );

  return (
    <AuthContext.Provider value={{ user, loading, error, login, logout, refreshMe, hasPermission }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
