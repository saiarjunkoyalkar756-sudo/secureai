import React, { createContext, useContext, useState, useEffect } from 'react';

interface AuthUser {
  email: string;
  apiKey: string;
  role: string;
  orgId: string;
}

export interface AuthContextType {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, apiKey: string) => Promise<{ success: boolean; error?: string }>;
  signup: (email: string, orgName: string) => Promise<{ success: boolean; apiKey?: string; error?: string }>;
  logout: () => void;
}

export const AuthContext = createContext<AuthContextType | null>(null);

const STORAGE_KEY = 'secureai_auth';
const API_BASE = import.meta.env.VITE_API_URL || 'https://secureai-production-bf5b.up.railway.app';

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Restore session from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored) as AuthUser;
        setUser(parsed);
      }
    } catch {
      localStorage.removeItem(STORAGE_KEY);
    }
    setIsLoading(false);
  }, []);

  const login = async (email: string, apiKey: string): Promise<{ success: boolean; error?: string }> => {
    try {
      // Try the real backend login endpoint
      const res = await fetch(`${API_BASE}/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey }),
      });

      if (res.ok) {
        const json = await res.json();
        const authUser: AuthUser = {
          email: json.user?.email || email,
          apiKey,
          role: json.user?.role || 'admin',
          orgId: json.user?.organizationId || 'org_default',
        };
        setUser(authUser);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(authUser));
        return { success: true };
      }

      if (res.status === 401) {
        return { success: false, error: 'Invalid or revoked API key' };
      }

      throw new Error(`HTTP ${res.status}`);
    } catch {
      // Backend unreachable — allow demo login for keys starting with sk_
      if (apiKey.startsWith('sk_')) {
        const authUser: AuthUser = {
          email,
          apiKey,
          role: 'admin',
          orgId: 'org_demo',
        };
        setUser(authUser);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(authUser));
        return { success: true };
      }
      return { success: false, error: 'Invalid API key format. Keys start with sk_' };
    }
  };

  const signup = async (email: string, orgName: string): Promise<{ success: boolean; apiKey?: string; error?: string }> => {
    // In production, this would call a real registration endpoint with email & orgName.
    // For now, generate a demo key so users can explore the dashboard.
    void email; void orgName;
    const demoKey = 'sk_demo_' + crypto.randomUUID().replace(/-/g, '').slice(0, 24);
    return { success: true, apiKey: demoKey };
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem(STORAGE_KEY);
  };

  return (
    <AuthContext.Provider value={{ user, isAuthenticated: !!user, isLoading, login, signup, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

/** @deprecated Import from './useAuth' instead */
export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}
