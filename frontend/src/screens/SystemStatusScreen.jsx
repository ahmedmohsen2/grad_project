import { useEffect, useState } from "react";
import Panel from "../components/common/Panel";
import MetricTile from "../components/common/MetricTile";
import StatusBadge from "../components/common/StatusBadge";
import { API_BASE_URL } from "../api/baseUrl";
import { socApi } from "../services/socApi";

function ServiceRow({ name, endpoint, status, description, detail }) {
  const isLive = status === "live";
  return (
    <div className="flex items-start justify-between gap-4 rounded-xl border border-slate-700/40 bg-slate-900/60 p-4 transition-all hover:border-slate-600/40">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={`live-dot ${isLive ? "" : "danger"}`} />
          <span className="text-sm font-semibold text-slate-200">{name}</span>
        </div>
        <p className="mt-1 text-xs text-slate-500">{description}</p>
        {detail && <p className="mt-1 font-mono text-[11px] text-slate-600">{detail}</p>}
      </div>
      <div className="flex flex-col items-end gap-1">
        <StatusBadge label={status} tone={isLive ? "success" : "warning"} />
        <span className="font-mono text-[10px] text-slate-600">{endpoint}</span>
      </div>
    </div>
  );
}

function SystemStatusScreen({ soc }) {
  const [stats, setStats] = useState(null);
  const [startTime] = useState(Date.now());
  const [uptime, setUptime] = useState("0s");

  // Fetch /stats aggregate
  useEffect(() => {
    const load = async () => {
      try {
        setStats(await socApi.getStats());
      } catch { /* silent */ }
    };
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, []);

  // Uptime ticker
  useEffect(() => {
    const tick = () => {
      const s = Math.floor((Date.now() - startTime) / 1000);
      const h = Math.floor(s / 3600);
      const m = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      setUptime(h > 0 ? `${h}h ${m}m ${sec}s` : m > 0 ? `${m}m ${sec}s` : `${sec}s`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startTime]);

  const services = [
    {
      name: "REST API",
      endpoint: `${API_BASE_URL}/health`,
      status: soc.apiStatus.health,
      description: "Flask backend — ML inference, detections, alerts, enforcement actions",
      detail: `Model: ${soc.health.model_mode ?? "—"} | DB: ${soc.health.db_status ?? "—"}`,
    },
    {
      name: "Detections Pipeline",
      endpoint: "/detections",
      status: soc.apiStatus.detections,
      description: "Multi-class XGBoost + Isolation Forest classifier for network flows",
      detail: stats ? `${stats.detections?.total ?? 0} total detections | ${stats.detections?.attacks ?? 0} attacks` : null,
    },
    {
      name: "Alerts Engine",
      endpoint: "/alerts",
      status: soc.apiStatus.alerts,
      description: "IPS alert generation from detection results and auto-response decisions",
      detail: stats ? `${stats.alerts?.open ?? 0} open / ${stats.alerts?.total ?? 0} total` : null,
    },
    {
      name: "Network Flows",
      endpoint: "/flows",
      status: soc.apiStatus.flows,
      description: "Real-time traffic telemetry — src/dst IP, port, PPS, packet count",
      detail: `${soc.flows.length} flows in current window`,
    },
    {
      name: "WebSocket Stream",
      endpoint: "ws://localhost:8001/ws/live",
      status: "live",
      description: "Real-time push channel for instant alert + action notifications",
      detail: "Reconnects automatically on disconnect",
    },
    {
      name: "AI Pentest Agent",
      endpoint: "/pentest/scan",
      status: soc.apiStatus.pentestFindings,
      description: "Autonomous penetration testing with Nmap, vulnerability assessment, and AI decision engine",
      detail: stats ? `${stats.pentest?.total_findings ?? 0} findings | ${stats.pentest?.critical ?? 0} critical` : null,
    },
    {
      name: "Auto-Response Engine",
      endpoint: "/auto-response/status",
      status: "live",
      description: "Threshold-based autonomous BLOCK/ISOLATE decisions on high-confidence detections",
      detail: `Status: ${soc.health.auto_response_enabled ? "ENABLED" : "DISABLED"} | Pentest mode: ${soc.health.pentest_mode ?? "lab"}`,
    },
    {
      name: "Activity Timeline Bus",
      endpoint: "/activity/logs",
      status: "live",
      description: "Unified event ingestion — pentest, auto-response, manual actions, alerts",
      detail: "Types: pentest · auto_action · manual_action · alert · system",
    },
  ];

  return (
    <div className="space-y-6">

      {/* ── Key Metrics ─────────────────────────────────────────────────── */}
      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile
          label="Session Uptime"
          value={uptime}
          helper="Time since this dashboard session started."
          valueClassName="font-mono text-lg"
        />
        <MetricTile
          label="Total Detections"
          value={stats?.detections?.total ?? soc.detections.length}
          helper="ML-classified network flows in the database."
        />
        <MetricTile
          label="Enforcement Actions"
          value={stats?.enforcement?.total_actions ?? soc.actions.length}
          helper="BLOCK + ISOLATE + WHITELIST actions executed."
        />
        <MetricTile
          label="Pentest Findings"
          value={stats?.pentest?.total_findings ?? soc.pentestFindings.length}
          helper="Vulnerabilities discovered by the AI pentest agent."
        />
      </section>

      {/* ── Platform Stats (from /stats) ─────────────────────────────────── */}
      {stats && (
        <Panel title="Platform Aggregate" subtitle="Live from /stats endpoint">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {[
              { label: "Attacks", value: stats.detections?.attacks, tone: "danger" },
              { label: "Suspicious", value: stats.detections?.suspicious, tone: "warning" },
              { label: "Blocked IPs", value: stats.enforcement?.blocked_ips, tone: "info" },
              { label: "Critical Findings", value: stats.pentest?.critical, tone: "danger" },
            ].map(({ label, value, tone }) => (
              <div
                key={label}
                className={`rounded-xl border p-4 ${
                  tone === "danger" ? "border-red-500/20 bg-red-500/5" :
                  tone === "warning" ? "border-amber-500/20 bg-amber-500/5" :
                  "border-sky-500/20 bg-sky-500/5"
                }`}
              >
                <p className="text-xs text-slate-500">{label}</p>
                <p className="mt-1 text-2xl font-bold text-slate-100">{value ?? 0}</p>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* ── Service Health Grid ──────────────────────────────────────────── */}
      <Panel title="Service Health" subtitle="All platform components">
        <div className="grid gap-3 md:grid-cols-2">
          {services.map((svc) => (
            <ServiceRow key={svc.name} {...svc} />
          ))}
        </div>
      </Panel>

      {/* ── ML Model Details ─────────────────────────────────────────────── */}
      <Panel title="ML Engine Details" subtitle="Model configuration">
        <div className="grid gap-4 md:grid-cols-3">
          {[
            { label: "Classifier", value: "XGBoost Multi-class", detail: "15 attack categories + BENIGN" },
            { label: "Anomaly Detector", value: "Isolation Forest", detail: "Unsupervised outlier flagging" },
            { label: "Mode", value: soc.health.model_mode ?? "multiclass", detail: "Classification strategy" },
          ].map(({ label, value, detail }) => (
            <div key={label} className="rounded-xl border border-slate-700/40 bg-slate-900/60 p-4">
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">{label}</p>
              <p className="mt-2 text-base font-bold text-slate-100">{value}</p>
              <p className="mt-1 text-xs text-slate-500">{detail}</p>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

export default SystemStatusScreen;
