import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { authSignup } from "../api/api";

export default function SignupPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [inviteKey, setInviteKey] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setSuccess("");

    // Client-side validation
    if (!username.trim() || !email.trim() || !password || !confirmPassword || !inviteKey.trim()) {
      setError("All fields are required");
      return;
    }

    if (username.trim().length < 3) {
      setError("Username must be at least 3 characters");
      return;
    }

    if (!email.includes("@") || !email.includes(".")) {
      setError("Please enter a valid email address");
      return;
    }

    if (password.length < 6) {
      setError("Password must be at least 6 characters");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    if (inviteKey.trim() !== "1913") {
      setError("Invalid invite key");
      return;
    }

    setLoading(true);
    try {
      const data = await authSignup(username.trim(), email.trim().toLowerCase(), password, inviteKey.trim());
      setSuccess(data.message || "Account created successfully!");
      // Redirect to login after short delay
      setTimeout(() => navigate("/login"), 2000);
    } catch (err) {
      setError(err.body?.error || err.message || "Signup failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-surface bg-grid bg-[size:32px_32px] relative overflow-hidden">
      {/* Ambient glow effects */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -top-32 -left-32 h-96 w-96 rounded-full bg-emerald-500/8 blur-[120px]" />
        <div className="absolute -bottom-32 -right-32 h-96 w-96 rounded-full bg-sky-500/10 blur-[120px]" />
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 h-[500px] w-[500px] rounded-full bg-indigo-500/5 blur-[160px]" />
      </div>

      <div className="relative z-10 w-full max-w-md px-4">
        {/* Logo / Brand */}
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-emerald-500 to-sky-600 shadow-lg shadow-emerald-500/20">
            <svg className="h-8 w-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M18 7.5v3m0 0v3m0-3h3m-3 0h-3m-2.25-4.125a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zM3 19.235v-.11a6.375 6.375 0 0112.75 0v.109A12.318 12.318 0 019.374 21c-2.331 0-4.512-.645-6.374-1.766z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Create Account</h1>
          <p className="mt-1 text-sm text-slate-400">Join the Security Operations Center</p>
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

          {success && (
            <div className="mb-5 flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
              <svg className="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              {success}
            </div>
          )}

          <div className="space-y-4">
            {/* Username */}
            <div>
              <label htmlFor="signup-username" className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
                Username
              </label>
              <input
                id="signup-username"
                type="text"
                autoComplete="username"
                autoFocus
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="analyst_01"
                className="w-full rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-3 text-sm text-slate-100 placeholder-slate-500 outline-none transition-all focus:border-emerald-500/50 focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>

            {/* Email */}
            <div>
              <label htmlFor="signup-email" className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
                Email
              </label>
              <input
                id="signup-email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@soc.local"
                className="w-full rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-3 text-sm text-slate-100 placeholder-slate-500 outline-none transition-all focus:border-emerald-500/50 focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>

            {/* Password */}
            <div>
              <label htmlFor="signup-password" className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
                Password
              </label>
              <input
                id="signup-password"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-3 text-sm text-slate-100 placeholder-slate-500 outline-none transition-all focus:border-emerald-500/50 focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>

            {/* Confirm Password */}
            <div>
              <label htmlFor="signup-confirm" className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
                Confirm Password
              </label>
              <input
                id="signup-confirm"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-3 text-sm text-slate-100 placeholder-slate-500 outline-none transition-all focus:border-emerald-500/50 focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>

            {/* Invite Key */}
            <div>
              <label htmlFor="signup-invite" className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
                Invite Key
              </label>
              <div className="relative">
                <input
                  id="signup-invite"
                  type="text"
                  value={inviteKey}
                  onChange={(e) => setInviteKey(e.target.value)}
                  placeholder="Enter access key"
                  className="w-full rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-3 pr-10 text-sm text-slate-100 placeholder-slate-500 outline-none transition-all focus:border-emerald-500/50 focus:ring-2 focus:ring-emerald-500/20"
                />
                <svg className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
                </svg>
              </div>
              <p className="mt-1 text-xs text-slate-600">Required — contact your SOC admin for the key</p>
            </div>
          </div>

          {/* Submit */}
          <button
            id="signup-submit"
            type="submit"
            disabled={loading || !!success}
            className="mt-7 flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-sky-600 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-emerald-500/25 transition-all hover:shadow-emerald-500/40 hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? (
              <>
                <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Creating account...
              </>
            ) : success ? (
              "Redirecting to login..."
            ) : (
              "Create Account"
            )}
          </button>

          {/* Login link */}
          <p className="mt-6 text-center text-sm text-slate-500">
            Already have an account?{" "}
            <Link
              to="/login"
              className="font-medium text-sky-400 transition-colors hover:text-sky-300"
            >
              Sign in
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
