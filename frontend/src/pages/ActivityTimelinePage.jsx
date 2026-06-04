import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { socApi } from "../services/socApi";
import { timestampMillis } from "../utils/formatters";
import { normalizeActivityLogs } from "../utils/socMappers";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const TYPE_CONFIG = {
  pentest: {
    label: "PENTEST",
    icon: "🔬",
    color: "from-green-600/20 to-green-600/5",
    border: "border-green-500/30",
    badge: "bg-green-500/20 text-green-300",
    dot: "bg-green-400",
  },
  auto_action: {
    label: "AUTO",
    icon: "⚡",
    color: "from-purple-600/20 to-purple-600/5",
    border: "border-purple-500/30",
    badge: "bg-purple-500/20 text-purple-300",
    dot: "bg-purple-400",
  },
  manual_action: {
    label: "MANUAL",
    icon: "🖱️",
    color: "from-blue-600/20 to-blue-600/5",
    border: "border-blue-500/30",
    badge: "bg-blue-500/20 text-blue-300",
    dot: "bg-blue-400",
  },
  alert: {
    label: "ALERT",
    icon: "🚨",
    color: "from-red-600/20 to-red-600/5",
    border: "border-red-500/30",
    badge: "bg-red-500/20 text-red-300",
    dot: "bg-red-400",
  },
  system: {
    label: "SYSTEM",
    icon: "⚙️",
    color: "from-slate-600/20 to-slate-600/5",
    border: "border-slate-500/30",
    badge: "bg-slate-500/20 text-slate-300",
    dot: "bg-slate-400",
  },
};

const STATUS_BADGE = {
  success: "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30",
  failed: "bg-red-500/20 text-red-300 border border-red-500/30",
  pending: "bg-orange-500/20 text-orange-300 border border-orange-500/30",
  resolved: "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30",
};

const ACTION_LABEL = {
  vulnerability_found: "Vulnerability Found",
  revalidation_mitigated: "Revalidation — Resolved",
  revalidation_partially_mitigated: "Revalidation — Partial",
  revalidation_unresolved: "Revalidation — Still Vulnerable",
  revalidation_queued: "Revalidation Scan Queued",
  scan_complete_no_findings: "Scan Complete — No Findings",
  block: "BLOCK",
  isolate: "ISOLATE",
  whitelist: "WHITELIST",
  unblock: "UNBLOCK",
};

function fmt(ts) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString("en-GB", {
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

function relTime(ts) {
  if (!ts) return "";
  const diff = Date.now() - new Date(ts).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function FilterPill({ label, active, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full px-3 py-1 text-xs font-semibold transition-all duration-200 ${
        active
          ? "bg-indigo-500 text-white shadow-lg shadow-indigo-500/30"
          : "border border-slate-600/40 bg-slate-700/40 text-slate-400 hover:border-indigo-500/40 hover:text-slate-200"
      }`}
    >
      {label}
    </button>
  );
}

function MetadataBadge({ label, value }) {
  if (value === undefined || value === null || value === "") return null;
  return (
    <span className="rounded bg-slate-700/60 px-1.5 py-0.5 text-[10px] text-slate-300">
      <span className="text-slate-500">{label}: </span>
      {String(value)}
    </span>
  );
}

function TimelineEvent({ event, animate, onTargetClick, onOpenIncident }) {
  const cfg = TYPE_CONFIG[event.type] || TYPE_CONFIG.system;
  const statusCls = STATUS_BADGE[event.status] || STATUS_BADGE.pending;
  const meta = event.metadata || {};
  const actionLabel = ACTION_LABEL[event.action] || event.action;

  // Enhance coloring for specific events
  let overrideColor = cfg.color;
  let overrideBorder = cfg.border;
  let overrideDot = cfg.dot;

  if (event.action === "vulnerability_found") {
    overrideColor = "from-red-600/20 to-red-600/5";
    overrideBorder = "border-red-500/30";
    overrideDot = "bg-red-400";
  } else if (event.action?.includes("revalidation_mitigated")) {
    overrideColor = "from-emerald-600/20 to-emerald-600/5";
    overrideBorder = "border-emerald-500/30";
    overrideDot = "bg-emerald-400";
  } else if (event.action?.includes("suspicious")) {
    overrideColor = "from-orange-600/20 to-orange-600/5";
    overrideBorder = "border-orange-500/30";
    overrideDot = "bg-orange-400";
  }

  return (
    <div
      className={`group relative flex gap-4 ${
        animate ? "animate-fade-in" : ""
      }`}
    >
      {/* Timeline line + dot */}
      <div className="flex flex-col items-center">
        <div
          className={`mt-1.5 h-3 w-3 rounded-full ring-2 ring-slate-900 ${overrideDot} flex-shrink-0`}
        />
        <div className="mt-1 w-px flex-1 bg-slate-700/50 group-last:bg-transparent" />
      </div>

      {/* Card */}
      <div
        className={`mb-4 flex-1 rounded-xl border bg-gradient-to-br p-4 ${overrideColor} ${overrideBorder} transition-all duration-200 hover:shadow-lg`}
      >
        {/* Header row */}
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-base">{cfg.icon}</span>
            <span className="text-sm font-semibold text-slate-100">
              {actionLabel}
            </span>
            {event.target && (
              <button
                onClick={() => onTargetClick(event.target)}
                className="font-mono text-xs text-sky-400 hover:text-sky-300 hover:underline transition-colors"
                title="Click to filter by this IP"
              >
                {event.target}
              </button>
            )}
            {event.target ? (
              <button
                type="button"
                onClick={() => onOpenIncident?.(event.metadata?.scan_id || event.metadata?.finding_id || event.target)}
                className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-semibold text-emerald-300 transition hover:bg-emerald-500/25"
              >
                View Incident
              </button>
            ) : null}
          </div>
          <div className="flex items-center gap-2">
            <span
              className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${cfg.badge}`}
            >
              {cfg.label}
            </span>
            <span
              className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${statusCls}`}
            >
              {event.status}
            </span>
          </div>
        </div>

        {/* Reason / Narrative */}
        {event.reason && (
          <p className="mt-2 text-sm text-slate-300 leading-relaxed border-l-2 border-slate-600/40 pl-3">
            {event.reason}
          </p>
        )}

        {/* Explainability UI: Confidence, Source, Trigger */}
        <div className="mt-3 flex flex-wrap gap-2">
          {meta.confidence !== undefined && (
            <span className="rounded-full bg-slate-800/80 border border-slate-700 px-2 py-1 text-xs text-slate-300">
              <span className="text-slate-500 mr-1">Confidence:</span>
              <span className={meta.confidence >= 0.8 ? "text-emerald-400 font-bold" : meta.confidence >= 0.5 ? "text-yellow-400 font-bold" : "text-slate-300 font-bold"}>
                {(meta.confidence * 100).toFixed(0)}%
              </span>
            </span>
          )}
          {event.source && (
            <span className="rounded-full bg-slate-800/80 border border-slate-700 px-2 py-1 text-xs text-slate-300">
              <span className="text-slate-500 mr-1">Source:</span>
              <span className="font-medium uppercase">{event.source}</span>
            </span>
          )}
          {meta.trigger && (
            <span className="rounded-full bg-slate-800/80 border border-slate-700 px-2 py-1 text-xs text-slate-300">
              <span className="text-slate-500 mr-1">Trigger:</span>
              <span className="font-medium text-slate-400">{meta.trigger}</span>
            </span>
          )}
        </div>

        {/* Metadata chips */}
        {Object.keys(meta).length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            <MetadataBadge label="scan" value={meta.scan_id} />
            <MetadataBadge label="finding" value={meta.finding_id} />
            <MetadataBadge label="severity" value={meta.severity} />
            <MetadataBadge label="mitigation" value={meta.mitigation_status} />
          </div>
        )}

        {/* Timestamp */}
        <div className="mt-3 flex items-center gap-2 text-[10px] text-slate-500">
          <span>{fmt(event.timestamp || event.created_at)}</span>
          <span>·</span>
          <span>{relTime(event.timestamp || event.created_at)}</span>
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, sub, color }) {
  return (
    <div
      className={`rounded-xl border border-slate-700/40 bg-slate-800/60 p-4 ${color}`}
    >
      <div className="flex items-center gap-2 text-slate-400">
        <span className="text-lg">{icon}</span>
        <span className="text-xs font-medium uppercase tracking-wide">
          {label}
        </span>
      </div>
      <div className="mt-1 text-2xl font-bold text-slate-100">{value}</div>
      {sub && <div className="mt-0.5 text-xs text-slate-500">{sub}</div>}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

const FILTERS = [
  { key: null, label: "All" },
  { key: "pentest", label: "🔬 Pentest" },
  { key: "auto_action", label: "⚡ Auto Action" },
  { key: "manual_action", label: "🖱️ Manual" },
  { key: "alert", label: "🚨 Alert" },
];

function mergeLogs(previous = [], incoming = []) {
  const map = new Map(previous.map((item) => [item.id, item]));
  incoming.forEach((item) => {
    const existing = map.get(item.id);
    if (!existing || timestampMillis(item.updated_at || item.timestamp) >= timestampMillis(existing.updated_at || existing.timestamp)) {
      map.set(item.id, existing ? { ...existing, ...item } : item);
    }
  });
  return Array.from(map.values())
    .sort((left, right) => timestampMillis(right.timestamp || right.created_at) - timestampMillis(left.timestamp || left.created_at))
    .slice(0, 150);
}

export default function ActivityTimelinePage({ soc, onOpenIncident }) {
  const [logs, setLogs] = useState([]);
  const [filter, setFilter] = useState(null);
  const [targetFilter, setTargetFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [newCount, setNewCount] = useState(0);
  const prevIds = useRef(new Set());
  const intervalRef = useRef(null);

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      setError(null);
      try {
        const data = await socApi.getActivityLogs({ limit: 200 });
        const normalized = normalizeActivityLogs(Array.isArray(data) ? data : []);
        setLogs((current) => {
          let fresh = 0;
          normalized.forEach((event) => {
            if (event.id !== undefined && event.id !== null && !prevIds.current.has(event.id)) {
              fresh += 1;
            }
          });
          if (silent && fresh > 0) setNewCount((n) => n + fresh);
          const merged = mergeLogs(silent ? current : [], normalized);
          prevIds.current = new Set(merged.map((event) => event.id));
          return merged;
        });
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    if (!Array.isArray(soc?.activityLogs) || soc.activityLogs.length === 0) return;
    setLogs((current) => {
      const merged = mergeLogs(current, soc.activityLogs);
      prevIds.current = new Set(merged.map((event) => event.id));
      return merged;
    });
  }, [soc?.activityLogs]);

  // Initial load
  useEffect(() => {
    setNewCount(0);
    load(false);
  }, [load]);

  // Auto-refresh every 5 s
  useEffect(() => {
    if (!autoRefresh) {
      clearInterval(intervalRef.current);
      return;
    }
    intervalRef.current = setInterval(() => load(true), 5000);
    return () => clearInterval(intervalRef.current);
  }, [autoRefresh, load]);

  const handleTargetClick = (target) => {
    setTargetFilter(target);
    setFilter(null); // Clear type filter when clicking IP
    setNewCount(0);
  };

  const filteredLogs = useMemo(() => {
    const target = targetFilter.trim().toLowerCase();
    return logs.filter((event) => {
      const matchesType = !filter || event.type === filter;
      const matchesTarget = !target || String(event.target || "").toLowerCase().includes(target);
      return matchesType && matchesTarget;
    });
  }, [filter, logs, targetFilter]);

  // Global stats intentionally derive from the complete event store, not the filtered view.
  const counts = useMemo(() => logs.reduce((acc, e) => {
    acc[e.type] = (acc[e.type] || 0) + 1;
    return acc;
  }, {}), [logs]);
  // Group logs by target if no target filter is applied (Optional: can be flat, but narrative is better flat, grouped by IP is nice too. User said: "Group events by target IP. Click an IP -> show full lifecycle timeline for that host." If target is empty, we show all chronologically. If target is set, we show narrative for that host.)
  const isTargetFiltered = !!targetFilter.trim();

  return (
    <div className="space-y-6">
      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-slate-100">Activity Timeline</h2>
          <p className="mt-1 text-sm text-slate-400 max-w-2xl">
            A continuous, centralized narrative of security events. Monitor autonomous decisions, penetration tests, and manual analyst actions in real-time.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {newCount > 0 && (
            <span className="animate-pulse rounded-full bg-indigo-500/20 px-3 py-1 text-xs font-semibold text-indigo-300">
              {newCount} new event{newCount > 1 ? "s" : ""}
            </span>
          )}
          <button
            onClick={() => setAutoRefresh((v) => !v)}
            className={`rounded-lg px-4 py-2 text-sm font-semibold transition-all ${
              autoRefresh
                ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30"
                : "bg-slate-700/40 text-slate-400 border border-slate-600/40 hover:bg-slate-700/60"
            }`}
          >
            {autoRefresh ? "⏵ Live Updates" : "⏸ Paused"}
          </button>
          <button
            onClick={() => { setNewCount(0); load(false); }}
            disabled={loading}
            className="rounded-lg bg-indigo-500/20 border border-indigo-500/30 px-4 py-2 text-sm font-semibold text-indigo-300 hover:bg-indigo-500/30 disabled:opacity-50"
          >
            ↺ Refresh
          </button>
        </div>
      </div>

      {/* ── Stats strip ────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard icon="🔬" label="Pentest Events" value={counts.pentest || 0} color="border-t-4 border-t-green-500 shadow-sm" />
        <StatCard icon="⚡" label="Auto Actions" value={counts.auto_action || 0} color="border-t-4 border-t-purple-500 shadow-sm" />
        <StatCard icon="🖱️" label="Manual Actions" value={counts.manual_action || 0} color="border-t-4 border-t-blue-500 shadow-sm" />
        <StatCard icon="🚨" label="Alerts" value={counts.alert || 0} color="border-t-4 border-t-red-500 shadow-sm" />
      </div>

      {/* ── Filters ────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-700/40 bg-slate-800/40 p-4">
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Event Type</span>
          <div className="flex flex-wrap gap-2">
            {FILTERS.map((f) => (
              <FilterPill
                key={f.key ?? "all"}
                label={f.label}
                active={filter === f.key}
                onClick={() => { setFilter(f.key); setNewCount(0); }}
              />
            ))}
          </div>
        </div>
        <div className="flex w-full md:w-auto items-center gap-3">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Target IP</span>
          <div className="relative flex-1 md:w-64">
            <input
              type="text"
              placeholder="Filter by IP..."
              value={targetFilter}
              onChange={(e) => setTargetFilter(e.target.value)}
              className="w-full rounded-lg border border-slate-600/40 bg-slate-900/60 pl-9 pr-3 py-2 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/30"
            />
            <span className="absolute left-3 top-2.5 text-slate-500">🔍</span>
            {targetFilter && (
              <button
                onClick={() => setTargetFilter("")}
                className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── Timeline ───────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-slate-700/40 bg-slate-800/40 p-6 md:p-8">
        {isTargetFiltered && (
          <div className="mb-6 flex items-center gap-3 rounded-xl border border-sky-500/30 bg-sky-500/10 p-4">
            <div className="text-2xl">🎯</div>
            <div>
              <h3 className="font-semibold text-sky-300">Host Lifecycle Narrative</h3>
              <p className="text-xs text-sky-200/70">Showing the full chronological history for <span className="font-mono text-white">{targetFilter}</span>.</p>
            </div>
            <button onClick={() => setTargetFilter("")} className="ml-auto rounded-lg bg-sky-500/20 px-3 py-1.5 text-xs font-medium text-sky-200 hover:bg-sky-500/30">
              Clear Filter
            </button>
          </div>
        )}

        {loading && logs.length === 0 ? (
          <div className="flex items-center justify-center py-20 text-slate-400">
            <span className="animate-spin mr-3 text-2xl">⏳</span>
            <span className="text-lg">Loading activity narrative…</span>
          </div>
        ) : error ? (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-4 text-red-300 shadow-inner">
            <div className="font-bold mb-1">⚠️ Connection Error</div>
            {error} — Make sure the backend is running on port 5000.
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="py-24 text-center text-slate-500">
            <div className="text-5xl mb-4 opacity-50">📋</div>
            <p className="text-lg font-medium text-slate-400">No activity events found.</p>
            <p className="text-sm mt-2 max-w-md mx-auto">
              Run a penetration test, trigger an alert, or execute a manual action to generate system logs.
            </p>
          </div>
        ) : (
          <div className="relative">
            <div className="max-h-[65vh] overflow-y-auto pr-2 custom-scrollbar">
              {filteredLogs.map((event, idx) => (
                <TimelineEvent
                  key={event.id ?? idx}
                  event={event}
                  animate={idx === 0}
                  onTargetClick={handleTargetClick}
                  onOpenIncident={onOpenIncident}
                />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
