import Panel from "../components/common/Panel";
import StatCard from "../components/common/StatCard";
import DataTable from "../components/common/DataTable";
import CircularThreatScore from "../components/common/CircularThreatScore";
import MetricTile from "../components/common/MetricTile";
import StatusBadge from "../components/common/StatusBadge";
import AttackDistributionChart from "../components/charts/AttackDistributionChart";
import SkeletonBlock from "../components/common/SkeletonBlock";
import RealtimePerformancePanel from "../components/realtime/RealtimePerformancePanel";

// ─── Helpers ──────────────────────────────────────────────────────────────────
function relTime(ts) {
  if (!ts) return "—";
  const diff = Date.now() - new Date(ts).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function ModelHealthRow({ health, onToggleAutoResponse }) {
  const autoEnabled = Boolean(health?.auto_response_enabled);
  const items = [
    { label: "API",          value: health?.status ?? "—",        ok: health?.status === "ok" },
    { label: "DB",           value: health?.db_status ?? "—",     ok: health?.db_status === "ok" },
    { label: "Model",        value: health?.model_mode ?? "—",    ok: true },
    { label: "Pentest Mode", value: health?.pentest_mode ?? "lab", ok: true },
  ];
  return (
    <div className="flex flex-wrap items-center gap-2 mt-4">
      {items.map((item) => (
        <div
          key={item.label}
          className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-[10px] font-semibold border ${
            item.ok
              ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-300"
              : "border-red-500/25 bg-red-500/10 text-red-300"
          }`}
        >
          <span className="text-slate-400">{item.label}:</span>
          <span className="uppercase tracking-wide">{item.value}</span>
        </div>
      ))}
      {/* Auto-Response — interactive pill */}
      <button
        type="button"
        onClick={onToggleAutoResponse}
        title="Click to toggle auto-response on the Hosts page"
        className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-[10px] font-bold transition-all cursor-pointer ${
          autoEnabled
            ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25"
            : "border-red-500/30 bg-red-500/10 text-red-300 hover:bg-red-500/20"
        }`}
      >
        <span className={`live-dot ${autoEnabled ? "" : "danger"}`} />
        <span className="text-slate-400">Auto-Response:</span>
        <span className="uppercase">{autoEnabled ? "ON" : "OFF"}</span>
      </button>
    </div>
  );
}

function LastDetectionTicker({ detections }) {
  const latest = detections[0];
  if (!latest) return null;
  const tone = latest.result === "ATTACK" ? "text-red-400" : latest.result === "SUSPICIOUS" ? "text-amber-400" : "text-emerald-400";
  return (
    <div className="flex items-center gap-2 rounded-xl border border-slate-700/40 bg-slate-900/60 px-4 py-2.5 text-xs animate-fade-in">
      <span className="live-dot" />
      <span className="text-slate-400 font-medium">Last Detection:</span>
      <span className={`font-mono font-bold ${tone}`}>{latest.result}</span>
      <span className="font-mono text-slate-300">{latest.src_ip}</span>
      <span className="text-slate-500">·</span>
      <span className="text-slate-400">{latest.attackLabel}</span>
      <span className="text-slate-500">·</span>
      <span className="font-mono text-slate-500">{relTime(latest.detected_at)}</span>
    </div>
  );
}

// ─── Main Screen ──────────────────────────────────────────────────────────────
function CommandCenterScreen({ soc, onNavigate, onSelectIp }) {
  const topVector =
    soc.distribution.reduce(
      (top, current) => (current.value > top.value ? current : top),
      soc.distribution[0] || { label: "--", value: 0 },
    )?.label || "--";

  const attackCount     = soc.detections.filter((d) => d.result === "ATTACK").length;
  const suspiciousCount = soc.detections.filter((d) => d.result === "SUSPICIOUS").length;
  const blockedCount    = soc.blockedIps.length;
  const isolatedCount   = soc.hosts.filter((h) => h.status === "ISOLATED").length;
  const healthOk = soc.health?.status === "ok" && soc.health?.db_status === "ok";
  const alertStats = soc.alertStats || { total: soc.alerts.length, open: soc.alerts.filter((alert) => !alert.is_read).length };

  const stats = [
    {
      label: "Active Attacks",
      value: attackCount,
      status: attackCount > 0 ? "High" : "Clear",
      tone: attackCount > 0 ? "danger" : "success",
      caption: attackCount > 0 ? "Immediate response recommended" : "No active attacks detected",
      icon: "🔥",
    },
    {
      label: "Suspicious Cases",
      value: suspiciousCount,
      status: suspiciousCount > 0 ? "Medium" : "Clear",
      tone: suspiciousCount > 0 ? "warning" : "success",
      caption: suspiciousCount > 0 ? "Awaiting analyst validation" : "Queue is clean",
      icon: "⚠️",
    },
    {
      label: "Total Alerts",
      value: alertStats.total,
      status: alertStats.open > 0 ? "Open" : "Reviewed",
      tone: alertStats.open > 0 ? "warning" : "success",
      caption: "Security alerts in the current live window",
      icon: "AL",
    },
    {
      label: "Detections",
      value: soc.detections.length,
      status: soc.detections.length ? "Live" : "Idle",
      tone: "info",
      caption: "ML and rule-based detection records",
      icon: "ML",
    },
    {
      label: "Blocked Hosts",
      value: blockedCount,
      status: "Enforced",
      tone: "info",
      caption: "Firewall containment active",
      icon: "🚫",
    },
    {
      label: "Isolated Devices",
      value: isolatedCount,
      status: "Stable",
      tone: "success",
      caption: "Network segmentation enforced",
      icon: "🔒",
    },
    {
      label: "Pentest Scans",
      value: soc.pentestScans?.length || 0,
      status: (soc.pentestScans || []).some((scan) => scan.status === "running") ? "Running" : "Ready",
      tone: (soc.pentestScans || []).some((scan) => scan.status === "failed") ? "warning" : "info",
      caption: "Recon to report lifecycle records",
      icon: "PT",
    },
    {
      label: "System Health",
      value: healthOk ? "OK" : "DEGRADED",
      status: soc.health?.db_status || "unknown",
      tone: healthOk ? "success" : "danger",
      caption: "API, model, and database readiness",
      icon: "SYS",
    },
  ];

  return (
    <div className="space-y-6">

      {/* ── Last Detection Ticker ───────────────────────────────────────── */}
      {!soc.loading && <LastDetectionTicker detections={soc.detections} />}
      {!soc.loading && !healthOk && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          Backend degraded: API status {soc.health?.status || "unknown"}, DB {soc.health?.db_status || "unknown"}. The dashboard will continue with cached data and polling fallback where possible.
        </div>
      )}

      {/* ── Top row: Threat Score + Distribution ───────────────────────── */}
      <RealtimePerformancePanel soc={soc} />

      <section className="grid gap-6 xl:grid-cols-[0.82fr_1.18fr]">
        <Panel className="bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
          {soc.loading ? (
            <div className="grid gap-4 md:grid-cols-2">
              <SkeletonBlock className="h-44 w-full" />
              <SkeletonBlock className="h-44 w-full" />
              <SkeletonBlock className="h-32 w-full" />
              <SkeletonBlock className="h-32 w-full" />
            </div>
          ) : (
            <>
              <div className="flex flex-col items-center gap-6 lg:flex-row lg:justify-between">
                <CircularThreatScore
                  value={soc.threatState.percent}
                  label={soc.threatState.label}
                  tone={soc.threatState.tone}
                />
                <div className="grid min-w-0 flex-1 gap-4 md:grid-cols-2">
                  <MetricTile
                    label="Open Alerts"
                    value={alertStats.open}
                    helper="Unread alerts requiring acknowledgment."
                  />
                  <MetricTile
                    label="Top Attack Vector"
                    value={topVector}
                    helper="Highest distribution in current detection window."
                    valueClassName="text-xl uppercase tracking-wide sm:text-2xl"
                  />
                  <MetricTile
                    label="Most Active Host"
                    value={soc.hosts[0]?.ip || "--"}
                    helper="Highest incident concentration across recent flows."
                    valueClassName="break-all text-base sm:text-lg xl:text-xl font-mono"
                  />
                  <MetricTile
                    label="Total Detections"
                    value={soc.detections.length}
                    helper="ML-classified flows in the current sample window."
                  />
                </div>
              </div>
              <ModelHealthRow
                health={soc.health}
                onToggleAutoResponse={() => {
                  soc.toggleAutoResponse(!soc.autoResponseEnabled);
                  onNavigate?.("hosts");
                }}
              />
            </>
          )}
        </Panel>

        <Panel title="Attack Distribution" subtitle="Threat mix across classification window">
          {soc.loading ? (
            <SkeletonBlock className="h-[280px] w-full" />
          ) : (
            <AttackDistributionChart data={soc.distribution} />
          )}
        </Panel>
      </section>

      {/* ── Stat cards ────────────────────────────────────────────────────── */}
      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {stats.map((item, i) => (
          <div
            key={item.label}
            className="animate-fade-in"
            style={{ animationDelay: `${i * 60}ms` }}
          >
            <StatCard {...item} />
          </div>
        ))}
      </section>

      {/* ── Recent Alerts + Analyst Priorities ─────────────────────────── */}
      <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <Panel
          title="Recent Alerts"
          subtitle="Latest 5 — click to inspect host"
          rightSlot={
            <button
              type="button"
              className="text-xs font-semibold text-sky-400 hover:text-sky-300 transition-colors"
              onClick={() => onNavigate("alerts")}
            >
              View all →
            </button>
          }
        >
          <DataTable
            columns={[
              { key: "ip", header: "Source IP", render: (row) => (
                <span className="font-mono text-xs text-sky-300">{row.ip}</span>
              )},
              { key: "type", header: "Type" },
              {
                key: "status",
                header: "Status",
                render: (row) => (
                  <StatusBadge
                    label={row.statusLabel}
                    tone={row.is_read ? "success" : row.type === "SUSPICIOUS" ? "warning" : "danger"}
                  />
                ),
              },
              { key: "timeLabel", header: "Time" },
            ]}
            rows={soc.alerts.slice(0, 5)}
            loading={soc.loading}
            emptyMessage="No alerts yet — alerts will appear here as the detection engine processes flows."
            onRowClick={(row) => {
              onSelectIp(row.ip);
              onNavigate("hosts");
            }}
          />
        </Panel>

        <Panel title="Analyst Priorities" subtitle="Operational brief">
          <div className="space-y-3">
            {[
              {
                label: "Suspicious Queue",
                value: soc.detections.filter((d) => d.result !== "NORMAL").length,
                sub: "Detections awaiting analyst review",
                icon: "⚠️",
                tone: "warning",
                action: () => onNavigate("suspicious-queue"),
              },
              {
                label: "Firewall Actions",
                value: soc.actions.length,
                sub: "Automated + manual enforcement logs",
                icon: "⚡",
                tone: "info",
                action: () => onNavigate("actions"),
              },
              {
                label: "Pentest Findings",
                value: soc.pentestFindings.length,
                sub: "Evidence-correlated security findings",
                icon: "🔬",
                tone: "success",
                action: () => onNavigate("pentest-console"),
              },
            ].map((item) => (
              <button
                key={item.label}
                type="button"
                onClick={item.action}
                className="hover-glow w-full rounded-xl bg-slate-900/60 border border-slate-700/40 p-4 text-left transition-all duration-200 hover:border-sky-500/30"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="text-lg">{item.icon}</span>
                    <span className="text-sm font-medium text-slate-300">{item.label}</span>
                  </div>
                  <span className="text-xl font-bold text-white">{item.value}</span>
                </div>
                <p className="mt-1.5 pl-8 text-xs text-slate-500">{item.sub}</p>
              </button>
            ))}
          </div>
        </Panel>
      </section>
    </div>
  );
}

export default CommandCenterScreen;
