/**
 * useAuth.jsx — Global Auth Context
 * ──────────────────────────────────
 * Provides:
 *   • user        – current user object { username, role, email, ... } or null
 *   • loading     – true while /auth/me is being validated
 *   • logout()    – clears token, user state, and redirects to /login
 *   • refreshUser – re-fetches /auth/me (e.g. after profile changes)
 *
 * On mount, validates the stored JWT by calling GET /auth/me.
 * If validation fails (expired/invalid token), auto-clears credentials.
 */
import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  authMe,
  clearToken,
  getToken,
  getStoredUser,
  setStoredUser,
} from "../api/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const navigate = useNavigate();
  const [user, setUser] = useState(getStoredUser);   // seed from cache for instant UI
  const [loading, setLoading] = useState(!!getToken()); // only load if we have a token to validate

  /**
   * Validate the stored token against the backend.
   * Called once on mount and whenever refreshUser() is invoked.
   */
  const refreshUser = useCallback(async () => {
    const token = getToken();
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }

    try {
      const data = await authMe();
      const u = data.user ?? data; // backend may return { user: {...} } or flat
      setUser(u);
      setStoredUser(u);
    } catch {
      // Token invalid / expired — wipe everything
      clearToken();
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  // Validate on first mount
  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  // Listen for 401 events dispatched by the API layer
  useEffect(() => {
    function onExpired() {
      clearToken();
      setUser(null);
      navigate("/login", { replace: true });
    }
    window.addEventListener("auth:expired", onExpired);
    return () => window.removeEventListener("auth:expired", onExpired);
  }, [navigate]);

  /**
   * Logout — clear everything and redirect.
   */
  const logout = useCallback(() => {
    clearToken();
    setUser(null);
    navigate("/login", { replace: true });
  }, [navigate]);

  return (
    <AuthContext.Provider value={{ user, loading, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

/**
 * Hook to consume auth context.
 * Must be used inside <AuthProvider>.
 */
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth() must be used within <AuthProvider>");
  }
  return ctx;
}
