import { useState, useRef, useCallback, useEffect } from 'react';
import type { Auth } from '@core/client';
import type { AuthorizeOptions, CallbackResult, IDTokenClaims } from '@/types';

export interface UseAuthConfig {
  getAuth: () => Auth;
  getAuthorizeOptions: () => Pick<AuthorizeOptions, 'scopes' | 'audiences' | 'audience'>;
}

export interface UseAuthReturn {
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  user: IDTokenClaims | null;
  initialize: () => Promise<void>;
  login: (returnTo?: string) => Promise<void>;
  handleCallback: (code: string, state?: string) => Promise<CallbackResult>;
  logout: () => Promise<void>;
  getAccessToken: (audience?: string) => Promise<string | null>;
}

export function useAuth(config: UseAuthConfig): UseAuthReturn {
  const { getAuth, getAuthorizeOptions } = config;
  const authRef = useRef<Auth | null>(null);
  if (!authRef.current) authRef.current = getAuth();
  const auth = authRef.current;

  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [user, setUser] = useState<IDTokenClaims | null>(null);

  const initialize = useCallback(async () => {
    if (isAuthenticated) {
      setIsLoading(false);
      return;
    }
    try {
      setIsLoading(true);
      setError(null);
      const ok = await auth.isAuthenticated();
      if (ok) {
        const u = await auth.getUser();
        setIsAuthenticated(true);
        setUser(u);
      } else {
        setIsAuthenticated(false);
        setUser(null);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error');
      setIsAuthenticated(false);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, [auth, isAuthenticated]);

  const login = useCallback(
    async (returnTo?: string) => {
      try {
        setError(null);
        if (returnTo) await auth.saveReturnTo(returnTo);
        const opts = getAuthorizeOptions();
        const { url } = await auth.authorize({
          scopes: opts.scopes,
          audiences: opts.audiences ?? undefined,
          audience: opts.audience,
        });
        window.location.href = url;
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Login failed');
        throw e;
      }
    },
    [auth, getAuthorizeOptions]
  );

  const handleCallback = useCallback(
    async (code: string, state?: string) => {
      try {
        setIsLoading(true);
        setError(null);
        const result = await auth.handleCallback(code, state);
        const u = await auth.getUser();
        setIsAuthenticated(true);
        setUser(u);
        setIsLoading(false);
        return result;
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Callback failed');
        setIsAuthenticated(false);
        setUser(null);
        setIsLoading(false);
        throw e;
      }
    },
    [auth]
  );

  const logout = useCallback(async () => {
    try {
      await auth.logout();
      setIsAuthenticated(false);
      setUser(null);
      setError(null);
    } catch {
      setIsAuthenticated(false);
      setUser(null);
    }
  }, [auth]);

  const getAccessToken = useCallback(
    async (audience?: string) => {
      try {
        const token = await auth.getAccessToken(audience);
        if (!token && !audience && isAuthenticated) setIsAuthenticated(false);
        return token;
      } catch {
        return null;
      }
    },
    [auth, isAuthenticated]
  );

  useEffect(() => {
    const onLogin = () => auth.getUser().then(setUser);
    const onLogout = () => {
      setIsAuthenticated(false);
      setUser(null);
    };
    const offLogin = auth.on('login', onLogin);
    const offLogout = auth.on('logout', onLogout);
    return () => {
      offLogin();
      offLogout();
    };
  }, [auth]);

  return {
    isAuthenticated,
    isLoading,
    error,
    user,
    initialize,
    login,
    handleCallback,
    logout,
    getAccessToken,
  };
}
