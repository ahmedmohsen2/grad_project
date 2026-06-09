import { useNavigate } from "react-router-dom";
import StatusBadge from "../common/StatusBadge";
import { useAuth } from "../../hooks/useAuth.jsx";
import brandLogo from "../../fs-ai-logo.png";

function Sidebar({ items, activeScreen, counts, health }) {
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const dbOk = health?.db_status === "ok";
  const apiOk = health?.status === "ok";

  return (
    <aside className="relative z-20 flex w-full flex-col border-b border-slate-800/60 bg-slate-950/95 px-4 py-5 backdrop-blur-xl lg:fixed lg:left-0 lg:top-0 lg:h-screen lg:w-[280px] lg:border-b-0 lg:border-r">

      {/* Brand block */}
      <div className="rounded-2xl border border-sky-500/20 bg-gradient-to-br from-sky-950/60 to-slate-950/60 p-4 shadow-lg shadow-sky-900/10">
        <div className="flex items-center gap-2.5">
          <div className="h-10 w-10 shrink-0 overflow-hidden rounded-xl shadow-md shadow-sky-500/40 ring-2 ring-sky-400/50">
            <img src={brandLogo} alt="Fusion Strike AI logo" className="h-full w-full object-cover" />
          </div>
          <div>
            <p className="text-[10px] font-bold uppercase tracking-[0.3em] text-sky-400/80">Fusion Strike AI</p>
            <h1 className="text-lg font-bold leading-tight text-white tracking-tight">SOC Command</h1>
          </div>
        </div>

        {/* Live system status mini-row */}
        <div className="mt-3 flex items-center gap-3 text-[10px]">
          <span className="flex items-center gap-1.5">
            <span className={`live-dot ${apiOk ? "" : "danger"}`} />
            <span className={apiOk ? "text-emerald-400" : "text-red-400"}>API</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className={`live-dot ${dbOk ? "" : "danger"}`} />
            <span className={dbOk ? "text-emerald-400" : "text-red-400"}>DB</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="live-dot" />
            <span className="text-emerald-400">WS</span>
          </span>
          <span className="ml-auto text-slate-600 font-mono">v2.0</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="mt-5 flex-1 space-y-0.5 overflow-y-auto custom-scrollbar">
        {items.map((item, idx) => {
          const isActive = item.id === activeScreen;
          const count =
            item.id === "alerts"
              ? counts?.alerts
              : item.id === "suspicious-queue"
                ? counts?.suspiciousQueue
                : 0;

          return (
            <button
              key={item.id}
              type="button"
              onClick={() => navigate(item.path)}
              style={{ animationDelay: `${idx * 30}ms` }}
              className={`animate-fade-in flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-left text-sm font-medium transition-all duration-200 ${isActive
                ? "bg-sky-500/12 text-sky-200 ring-1 ring-sky-500/25 shadow-sm shadow-sky-900/20"
                : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-100"
                }`}
            >
              <span className="flex items-center gap-2.5">
                <span className={`text-base ${isActive ? "opacity-100" : "opacity-60"}`}>
                  {item.icon}
                </span>
                <span className="truncate">{item.label}</span>
              </span>
              {count > 0 ? (
                <span className="animate-counter ml-2 rounded-full bg-red-500/20 px-2 py-0.5 text-[10px] font-bold text-red-300 ring-1 ring-red-500/30">
                  {count}
                </span>
              ) : null}
            </button>
          );
        })}
      </nav>

      {/* User block */}
      <div className="mt-3 rounded-xl border border-slate-700/40 bg-slate-900/60 p-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-emerald-500/30 to-sky-500/30 text-sm font-bold text-emerald-300">
            {(user?.username?.[0] ?? "A").toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold text-slate-100">{user?.username ?? "Analyst"}</p>
            <p className="text-[11px] text-slate-500 capitalize">{user?.role ?? "analyst"}</p>
          </div>
        </div>
        <button
          id="logout-button"
          type="button"
          onClick={logout}
          className="mt-3 w-full rounded-lg border border-slate-700/60 bg-slate-800/60 px-3 py-1.5 text-xs font-medium text-slate-400 transition-all hover:border-red-500/30 hover:bg-red-500/10 hover:text-red-300"
        >
          Sign Out
        </button>
      </div>
    </aside>
  );
}

export default Sidebar;
