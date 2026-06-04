import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import Panel from "../common/Panel";
import MetricTile from "../common/MetricTile";
import StatusBadge from "../common/StatusBadge";
import { BANDWIDTH_PROFILES } from "../../utils/bandwidth";

const PROFILE_OPTIONS = Object.entries(BANDWIDTH_PROFILES).map(([value, cfg]) => ({
  value,
  label: cfg.label,
}));

function metricValue(value, suffix = "ms") {
  const numeric = Number(value || 0);
  return `${numeric.toFixed(numeric >= 100 ? 0 : 1)} ${suffix}`;
}

function RealtimePerformancePanel({ soc }) {
  const metrics = soc.performanceMetrics || {};
  const samples = soc.performanceSamples || [];
  const currentProfile = BANDWIDTH_PROFILES[soc.bandwidthProfile] || BANDWIDTH_PROFILES.unlimited;
  const connected = soc.wsStatus === "connected";

  const comparison = PROFILE_OPTIONS.map(({ value, label }) => {
    const profile = BANDWIDTH_PROFILES[value];
    const baseApi = Number(metrics.avg_response_time || metrics.current_latency || 30);
    const simulated = profile.mbps ? baseApi + profile.baseLatencyMs + profile.jitterMs / 2 : baseApi;
    return {
      profile: label,
      response: Math.round(simulated),
      detection: Math.round(simulated + Number(metrics.ai_inference_time || 0)),
    };
  });

  return (
    <Panel
      title="Realtime Performance"
      subtitle="Latency, stream health, and client bandwidth profile"
      rightSlot={
        <div className="flex flex-wrap items-center gap-3">
          <StatusBadge
            label={connected ? "WebSocket live" : soc.wsStatus}
            tone={connected ? "success" : "warning"}
          />
          <select
            value={soc.bandwidthProfile}
            onChange={(event) => soc.setBandwidthProfile(event.target.value)}
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200 outline-none focus:border-sky-500"
          >
            {PROFILE_OPTIONS.map((profile) => (
              <option key={profile.value} value={profile.value}>
                {profile.label}
              </option>
            ))}
          </select>
        </div>
      }
    >
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <MetricTile label="API Response" value={metricValue(metrics.current_latency || metrics.avg_response_time)} helper="Current REST round-trip." />
        <MetricTile label="AI Inference" value={metricValue(metrics.ai_inference_time || metrics.avg_ai_inference_time)} helper="Model execution timing." />
        <MetricTile label="DB Query" value={metricValue(metrics.database_query_time || metrics.avg_database_query_time)} helper="Latest PostgreSQL operation." />
        <MetricTile label="WS Ping" value={metricValue(soc.wsLatency || metrics.websocket_ping)} helper="Browser to stream server." />
        <MetricTile label="Render Delay" value={metricValue(metrics.dashboard_render_delay)} helper="Snapshot to paint estimate." />
        <MetricTile label="Bandwidth" value={currentProfile.label} helper={`${currentProfile.mbps || "No"} Mbps limit active.`} valueClassName="text-xl" />
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[1.4fr_0.9fr]">
        <div className="h-[260px] rounded-xl border border-slate-800 bg-slate-950/50 p-3">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={samples}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" hide />
              <YAxis stroke="#64748b" width={42} />
              <Tooltip
                contentStyle={{ background: "#020617", border: "1px solid #1e293b", borderRadius: 8 }}
                labelStyle={{ color: "#cbd5e1" }}
              />
              <Line type="monotone" dataKey="api" name="API" stroke="#38bdf8" strokeWidth={2} dot={false} isAnimationActive={false} />
              <Line type="monotone" dataKey="ai" name="AI" stroke="#a78bfa" strokeWidth={2} dot={false} isAnimationActive={false} />
              <Line type="monotone" dataKey="db" name="DB" stroke="#22c55e" strokeWidth={2} dot={false} isAnimationActive={false} />
              <Line type="monotone" dataKey="ws" name="WS" stroke="#f97316" strokeWidth={2} dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="h-[260px] rounded-xl border border-slate-800 bg-slate-950/50 p-3">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={comparison}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="profile" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" width={42} />
              <Tooltip
                contentStyle={{ background: "#020617", border: "1px solid #1e293b", borderRadius: 8 }}
                labelStyle={{ color: "#cbd5e1" }}
              />
              <Area type="monotone" dataKey="response" name="API response" stroke="#38bdf8" fill="#0ea5e9" fillOpacity={0.16} isAnimationActive={false} />
              <Area type="monotone" dataKey="detection" name="Detection delay" stroke="#f43f5e" fill="#f43f5e" fillOpacity={0.12} isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </Panel>
  );
}

export default RealtimePerformancePanel;
