import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { authLogin, setToken, setStoredUser } from "../api/api";

export default function LoginPage() {
  const navigate = useNavigate();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");

    if (!identifier.trim() || !password) {
      setError("Please fill in all fields");
      return;
    }

    setLoading(true);
    try {
      const data = await authLogin(identifier.trim(), password);
      setToken(data.token);
      setStoredUser(data.user);
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(err.body?.error || err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-surface bg-grid bg-[size:32px_32px] relative overflow-hidden">
      {/* Ambient glow effects */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -top-32 -left-32 h-96 w-96 rounded-full bg-sky-500/10 blur-[120px]" />
        <div className="absolute -bottom-32 -right-32 h-96 w-96 rounded-full bg-indigo-500/10 blur-[120px]" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 h-[600px] w-[600px] rounded-full bg-cyan-500/5 blur-[160px]" />
      </div>

      <div className="relative z-10 w-full max-w-md px-4">
        {/* Logo / Brand */}
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-sky-500 to-indigo-600 shadow-lg shadow-sky-500/20">
            <svg className="h-8 w-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">SOC Command Center</h1>
          <p className="mt-1 text-sm text-slate-400">Sign in to your security dashboard</p>
        </div>

        {/* Card */}
        <form
          onSubmit={handleSubmit}
          className="rounded-2xl border border-white/[0.06] bg-panel/80 backdrop-blur-xl p-8 shadow-2xl shadow-black/40"
        >
          {error && (
            <div className="mb-5 flex items-center gap-2 rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300">
              <svg className="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
              </svg>
              {error}
            </div>
          )}

          <div className="space-y-5">
            {/* Identifier */}
            <div>
              <label htmlFor="login-identifier" className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
                Email or Username
              </label>
              <input
                id="login-identifier"
                type="text"
                autoComplete="username"
                autoFocus
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                placeholder="admin@soc.local"
                className="w-full rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-3 text-sm text-slate-100 placeholder-slate-500 outline-none transition-all focus:border-sky-500/50 focus:ring-2 focus:ring-sky-500/20"
              />
            </div>

            {/* Password */}
            <div>
              <label htmlFor="login-password" className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
                Password
              </label>
              <input
                id="login-password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-3 text-sm text-slate-100 placeholder-slate-500 outline-none transition-all focus:border-sky-500/50 focus:ring-2 focus:ring-sky-500/20"
              />
            </div>
          </div>

          {/* Submit */}
          <button
            id="login-submit"
            type="submit"
            disabled={loading}
            className="mt-7 flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-sky-500/25 transition-all hover:shadow-sky-500/40 hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? (
              <>
                <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Authenticating...
              </>
            ) : (
              "Sign In"
            )}
          </button>

          {/* Signup link */}
          <p className="mt-6 text-center text-sm text-slate-500">
            Don&apos;t have an account?{" "}
            <Link
              to="/signup"
              className="font-medium text-sky-400 transition-colors hover:text-sky-300"
            >
              Request access
            </Link>
          </p>
        </form>

        {/* Footer */}
        <p className="mt-6 text-center text-xs text-slate-600">
          Protected by IDS/IPS Security Operations Center
        </p>
      </div>
    </div>
  );
}
