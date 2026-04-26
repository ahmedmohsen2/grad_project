import { useNavigate } from "react-router-dom";
import StatusBadge from "../common/StatusBadge";
import { useAuth } from "../../hooks/useAuth.jsx";

function Sidebar({ items, activeScreen, counts }) {
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  return (
    <aside className="relative z-20 flex w-full flex-col border-b border-slate-800/80 bg-panelAlt/95 px-5 py-6 backdrop-blur lg:fixed lg:left-0 lg:top-0 lg:h-screen lg:w-[296px] lg:border-b-0 lg:border-r">
      <div className="rounded-2xl border border-sky-500/20 bg-slate-950/60 p-4 shadow-glow">
        <p className="text-xs uppercase tracking-[0.3em] text-sky-300/80">Fusion Strike AI</p>
        <h1 className="mt-2 text-2xl font-semibold text-white">SOC Command</h1>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Reusable command shell with operational screens, analyst workflows, and live telemetry.
        </p>
      </div>

      <nav className="mt-8 flex-1 space-y-2">
        {items.map((item) => {
          const isActive = item.id === activeScreen;
          const count =
            item.id === "alerts"
              ? counts.alerts
              : item.id === "suspicious-queue"
                ? counts.suspiciousQueue
                : 0;

          return (
            <button
              key={item.id}
              type="button"
              onClick={() => navigate(item.path)}
              className={`flex w-full items-center justify-between rounded-xl px-4 py-3 text-left text-sm font-medium transition-all duration-300 hover:scale-[1.02] ${
                isActive
                  ? "bg-sky-500/10 text-sky-200 ring-1 ring-sky-500/30"
                  : "text-slate-300 hover:bg-slate-800/80 hover:text-white"
              }`}
            >
              <span>{item.label}</span>
              {count > 0 ? <StatusBadge label={String(count)} tone={isActive ? "info" : "neutral"} /> : null}
            </button>
          );
        })}
      </nav>

      <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-4">
        <p className="text-sm font-medium text-emerald-200">{user?.username ?? "User"}</p>
        <p className="mt-1 text-sm text-slate-400">{user?.role ?? "Analyst"}</p>
        <button
          id="logout-button"
          type="button"
          onClick={logout}
          className="mt-4 w-full rounded-xl border border-slate-700 bg-slate-900/70 px-4 py-2 text-sm text-slate-200 transition-all duration-300 hover:scale-[1.02] hover:border-slate-600 hover:bg-slate-800"
        >
          Logout
        </button>
      </div>
    </aside>
  );
}

export default Sidebar;
