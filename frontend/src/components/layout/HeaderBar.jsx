function HeaderBar({ title, subtitle, loading, lastUpdatedLabel, newAlertsCount, alertStats, health }) {
  const modelMode = health?.model_mode ?? "--";
  const openAlerts = alertStats?.open ?? newAlertsCount ?? 0;

  return (
    <header className="mb-6 animate-fade-in rounded-2xl border border-slate-800/60 bg-slate-950/70 p-5 shadow-sm backdrop-blur-xl">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.28em] text-slate-500">
            Security Operations Center
          </p>
          <h2 className="mt-1.5 truncate text-2xl font-bold tracking-tight text-white">
            {title}
          </h2>
          {subtitle && (
            <p className="mt-1 text-sm leading-relaxed text-slate-400">{subtitle}</p>
          )}
        </div>

        <div className="flex flex-shrink-0 flex-wrap items-center gap-2">
          <div className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold ${
            loading
              ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
              : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
          }`}>
            <span className={`live-dot ${loading ? "warning" : ""}`} />
            {loading ? "Refreshing..." : "Live"}
          </div>

          {openAlerts > 0 && (
            <div className="animate-counter flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-bold text-red-300">
              {openAlerts} new alert{openAlerts > 1 ? "s" : ""}
            </div>
          )}

          <div className="rounded-full border border-indigo-500/25 bg-indigo-500/10 px-3 py-1.5 text-xs font-semibold text-indigo-300">
            {modelMode}
          </div>

          <div className="rounded-full border border-slate-700/60 bg-slate-900/60 px-3 py-1.5 font-mono text-[10px] text-slate-500">
            {lastUpdatedLabel || "--"}
          </div>
        </div>
      </div>
    </header>
  );
}

export default HeaderBar;
