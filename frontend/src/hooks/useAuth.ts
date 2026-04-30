import { useState, useCallback } from 'react';
import { login as apiLogin, logout as apiLogout, isAuthenticated, clearToken } from '../services/api';
import type { LoginRequest } from '../types';

export function useAuth() {
  const [authenticated, setAuthenticated] = useState(isAuthenticated());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const login = useCallback(async (data: LoginRequest) => {
    setLoading(true);
    setError(null);
    try {
      await apiLogin(data);
      setAuthenticated(true);
    } catch (err: unknown) {
      const msg =
        (err as { response?: { data?: { detail?: string }; status?: number } })?.response?.data?.detail ||
        ((err as { response?: { status?: number } })?.response?.status === 423
          ? 'Account locked. Try again later.'
          : 'Login failed');
      setError(msg);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    setAuthenticated(false);
    clearToken();
  }, []);

  return { authenticated, loading, error, login, logout };
}
