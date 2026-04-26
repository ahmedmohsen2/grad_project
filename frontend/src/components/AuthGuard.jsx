/**
 * AuthGuard — wraps protected routes.
 * If no JWT token in localStorage → redirect to /login.
 * Also listens for "auth:expired" events (fired by api.js on 401).
 * Now delegates to AuthContext for centralized user/token validation.
 */
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../hooks/useAuth.jsx";

export default function AuthGuard({ children }) {
  const location = useLocation();
  const { user, loading } = useAuth();

  // Show a loading spinner while /auth/me is being validated
  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-surface">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-sky-500 border-t-transparent" />
      </div>
    );
  }

  // No valid user — redirect to login
  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}
