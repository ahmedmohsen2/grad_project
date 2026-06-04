import { useState } from "react";
import Panel from "../components/common/Panel";
import { socApi } from "../services/socApi";

// ─── Tool card ────────────────────────────────────────────────────────────────
function ToolCard({ icon, title, description, badge, badgeTone, children }) {
  const toneMap = {
    success: "border-emerald-500/25 bg-emerald-500/10 text-emerald-300",
    warning: "border-amber-500/25 bg-amber-500/10 text-amber-300",
    info:    "border-sky-500/25 bg-sky-500/10 text-sky-300",
    neutral: "border-slate-600/40 bg-slate-700/40 text-slate-400",
  };
  return (
    <div className="rounded-2xl border border-slate-700/40 bg-slate-900/60 p-5 space-y-4 hover-glow transition-all">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="text-2xl">{icon}</span>
          <div>
            <h3 className="text-sm font-bold text-slate-100">{title}</h3>
            <p className="mt-0.5 text-xs text-slate-500">{description}</p>
          </div>
        </div>
        {badge && (
          <span className={`shrink-0 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide ${toneMap[badgeTone ?? "neutral"]}`}>
            {badge}
          </span>
        )}
      </div>
      {children}
    </div>
  );
}

// ─── IOC Lookup ──────────────────────────────────────────────────────────────
function IocLookup() {
  const [ip, setIp] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const lookup = async () => {
    if (!ip.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      setResult(await socApi.getActionState(ip.trim()));
    } catch {
      setResult({ error: "Could not reach backend" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <input
          type="text"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && lookup()}
          placeholder="Enter IP address (e.g. 192.168.1.1)"
          className="flex-1 rounded-xl border border-slate-700/50 bg-slate-800/60 px-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/30"
        />
        <button
          type="button"
          onClick={lookup}
          disabled={loading || !ip.trim()}
          className="rounded-xl bg-sky-500/20 border border-sky-500/30 px-5 py-2 text-sm font-semibold text-sky-300 hover:bg-sky-500/30 disabled:opacity-40 transition-all"
        >
          {loading ? "…" : "Lookup"}
        </button>
      </div>
      {result && (
        <div className="rounded-xl border border-slate-700/40 bg-slate-950/60 p-4 font-mono text-xs">
          {result.error
            ? <span className="text-red-400">{result.error}</span>
            : (
              <div className="space-y-1.5">
                {Object.entries(result).map(([k, v]) => (
                  <div key={k} className="flex gap-3">
                    <span className="w-28 shrink-0 text-slate-500">{k}</span>
                    <span className={`
                      ${String(v).includes("BLOCK") ? "text-red-300" :
                        String(v).includes("ISOLAT") ? "text-amber-300" :
                        String(v) === "true" ? "text-emerald-300" :
                        String(v) === "false" ? "text-slate-400" :
                        "text-slate-300"}
                    `}>{String(v)}</span>
                  </div>
                ))}
              </div>
            )
          }
        </div>
      )}
    </div>
  );
}

// ─── API Health Probe ─────────────────────────────────────────────────────────
function ApiHealthProbe() {
  const [results, setResults] = useState([]);
  const [running, setRunning] = useState(false);

  const ENDPOINTS = [
    { path: "/health",       label: "Health Check" },
    { path: "/stats",        label: "Platform Stats" },
    { path: "/detections?limit=1", label: "Detections" },
    { path: "/alerts?limit=1",     label: "Alerts" },
    { path: "/flows?limit=1",      label: "Network Flows" },
    { path: "/actions?limit=1",    label: "Actions" },
    { path: "/blocked-ips",        label: "Blocked IPs" },
    { path: "/activity/logs?limit=1", label: "Activity Logs" },
    { path: "/pentest/scans?limit=1", label: "Pentest Scans" },
  ];

  const runProbe = async () => {
    setRunning(true);
    setResults([]);
    for (const ep of ENDPOINTS) {
      const t0 = Date.now();
      try {
        const res = await socApi.request(ep.path);
        const latency = Date.now() - t0;
        setResults((r) => [...r, { ...ep, status: 200, latency, ok: Boolean(res) }]);
      } catch (error) {
        setResults((r) => [...r, { ...ep, status: error.status || "ERR", latency: Date.now() - t0, ok: false }]);
      }
    }
    setRunning(false);
  };

  return (
    <div className="space-y-3">
      <button
        type="button"
        onClick={runProbe}
        disabled={running}
        className="rounded-xl bg-indigo-500/20 border border-indigo-500/30 px-5 py-2.5 text-sm font-semibold text-indigo-300 hover:bg-indigo-500/30 disabled:opacity-40 transition-all"
      >
        {running ? "⏳ Probing all endpoints…" : "▶ Run Full API Probe"}
      </button>
      {results.length > 0 && (
        <div className="space-y-1.5">
          {results.map((r) => (
            <div key={r.path} className={`flex items-center justify-between rounded-lg px-3 py-2 text-xs ${r.ok ? "bg-emerald-500/5 border border-emerald-500/15" : "bg-red-500/5 border border-red-500/15"}`}>
              <span className={`font-medium ${r.ok ? "text-emerald-300" : "text-red-300"}`}>{r.label}</span>
              <div className="flex items-center gap-3">
                <span className="font-mono text-slate-400">{r.path}</span>
                <span className={`font-bold ${r.ok ? "text-emerald-400" : "text-red-400"}`}>HTTP {r.status}</span>
                <span className="text-slate-500">{r.latency}ms</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function FirewallSelfTest() {
  const [ip, setIp] = useState("203.0.113.250");
  const [result, setResult] = useState(null);
  const [running, setRunning] = useState(false);

  const runTest = async () => {
    setRunning(true);
    setResult(null);
    try {
      setResult(await socApi.runIpsSelfTest(ip.trim() || "203.0.113.250"));
    } catch (error) {
      setResult(error.body || { success: false, error: error.message || "Firewall self-test failed" });
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <input
          type="text"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          className="flex-1 rounded-xl border border-slate-700/50 bg-slate-800/60 px-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/30"
        />
        <button
          type="button"
          onClick={runTest}
          disabled={running}
          className="rounded-xl bg-emerald-500/20 border border-emerald-500/30 px-5 py-2 text-sm font-semibold text-emerald-300 hover:bg-emerald-500/30 disabled:opacity-40 transition-all"
        >
          {running ? "Testing..." : "Run Test"}
        </button>
      </div>
      {result && (
        <div className={`rounded-xl border p-4 font-mono text-xs ${result.success ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-100" : "border-red-500/20 bg-red-500/5 text-red-100"}`}>
          <div>success: {String(result.success)}</div>
          <div>test_ip: {result.test_ip || ip}</div>
          <div>add_verified: {String(result.add?.verified || false)}</div>
          <div>remove_verified: {String(result.remove?.verified_absent || false)}</div>
          {(result.error || result.profile?.backend_status_message) ? (
            <div className="mt-2 whitespace-pre-wrap text-amber-100">{result.error || result.profile?.backend_status_message}</div>
          ) : null}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
function EvidenceRow({ label, value, good }) {
  const display = value === undefined || value === null || value === "" ? "-" : String(value);
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-slate-800/70 bg-slate-950/50 px-3 py-2">
      <span className="text-xs text-slate-500">{label}</span>
      <span className={`text-right font-mono text-xs ${good === true ? "text-emerald-300" : good === false ? "text-red-300" : "text-slate-300"}`}>
        {display}
      </span>
    </div>
  );
}

function IpsValidationTest() {
  const [sourceIp, setSourceIp] = useState("203.0.113.250");
  const [flows, setFlows] = useState(25);
  const [result, setResult] = useState(null);
  const [running, setRunning] = useState(false);
  const [loading, setLoading] = useState(false);

  const latest = result?.validation || result?.latest || null;
  const report = result?.report || latest?.report || {};
  const summary = report?.summary || {};

  const start = async () => {
    setRunning(true);
    try {
      setResult(await socApi.startIpsValidationTest({
        source_ip: sourceIp.trim() || "203.0.113.250",
        flows: Number(flows) || 25,
      }));
    } catch (error) {
      setResult(error.body || { success: false, error: error.message || "Validation test failed" });
    } finally {
      setRunning(false);
    }
  };

  const load = async () => {
    setLoading(true);
    try {
      setResult(await socApi.getIpsValidationStatus(10));
    } catch (error) {
      setResult(error.body || { success: false, error: error.message || "Could not load validation status" });
    } finally {
      setLoading(false);
    }
  };

  const clear = async () => {
    setLoading(true);
    try {
      await socApi.clearIpsValidationTests();
      setResult({ latest: null, history: [] });
    } catch (error) {
      setResult(error.body || { success: false, error: error.message || "Could not clear validation data" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-[1fr_110px]">
        <input
          type="text"
          value={sourceIp}
          onChange={(e) => setSourceIp(e.target.value)}
          className="rounded-xl border border-slate-700/50 bg-slate-800/60 px-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/30"
        />
        <input
          type="number"
          min="2"
          max="250"
          value={flows}
          onChange={(e) => setFlows(e.target.value)}
          className="rounded-xl border border-slate-700/50 bg-slate-800/60 px-4 py-2.5 text-sm text-slate-200 outline-none focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/30"
        />
      </div>
      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={start} disabled={running} className="rounded-xl border border-emerald-500/30 bg-emerald-500/20 px-4 py-2 text-sm font-semibold text-emerald-300 transition-all hover:bg-emerald-500/30 disabled:opacity-40">
          {running ? "Running..." : "Start Validation Test"}
        </button>
        <button type="button" onClick={load} disabled={loading || running} className="rounded-xl border border-sky-500/30 bg-sky-500/20 px-4 py-2 text-sm font-semibold text-sky-300 transition-all hover:bg-sky-500/30 disabled:opacity-40">
          View Results
        </button>
        <button type="button" onClick={clear} disabled={loading || running} className="rounded-xl border border-slate-600/50 bg-slate-800/70 px-4 py-2 text-sm font-semibold text-slate-300 transition-all hover:bg-slate-700/80 disabled:opacity-40">
          Clear Test Data
        </button>
      </div>

      {result?.error ? (
        <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-200">{result.error}</div>
      ) : null}

      {latest ? (
        <div className="space-y-4">
          <div className="grid gap-2 md:grid-cols-2">
            <EvidenceRow label="Detection timestamp" value={latest.detection_timestamp} />
            <EvidenceRow label="Block timestamp" value={latest.block_timestamp} />
            <EvidenceRow label="Verification timestamp" value={latest.verification_timestamp} />
            <EvidenceRow label="Rule name" value={latest.rule_name} />
            <EvidenceRow label="Method" value={latest.enforcement_method || summary.method} good={(latest.enforcement_method || summary.method) === "local_firewall:windows"} />
            <EvidenceRow label="Verification" value={latest.verification_status || summary.verification} good={(latest.verification_status || summary.verification) === "verified"} />
            <EvidenceRow label="Real Block Applied" value={latest.real_block_applied ? "YES" : "NO"} good={Boolean(latest.real_block_applied)} />
            <EvidenceRow label="Rule Exists" value={latest.rule_exists ? "YES" : "NO"} good={Boolean(latest.rule_exists)} />
            <EvidenceRow label="Command status" value={latest.command_status} good={latest.command_status === "success"} />
            <EvidenceRow label="Re-test denied" value={latest.retest_denied ? "YES" : "NO"} good={Boolean(latest.retest_denied)} />
          </div>
          <div className="rounded-xl border border-slate-800/70 bg-slate-950/50 p-4">
            <div className="mb-3 flex items-center justify-between gap-3">
              <span className="text-sm font-bold text-slate-100">Complete Test Report</span>
              <span className={`rounded-full px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide ${latest.status === "completed" ? "bg-emerald-500/10 text-emerald-300" : "bg-red-500/10 text-red-300"}`}>
                {latest.status}
              </span>
            </div>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
              <EvidenceRow label="Traffic generated" value={summary.traffic_generated ?? latest.traffic_generated} good={(summary.traffic_generated ?? latest.traffic_generated) > 0} />
              <EvidenceRow label="Detection triggered" value={latest.detection_triggered ? "YES" : "NO"} good={Boolean(latest.detection_triggered)} />
              <EvidenceRow label="Firewall rule created" value={latest.firewall_rule_created ? "YES" : "NO"} good={Boolean(latest.firewall_rule_created)} />
              <EvidenceRow label="Verification passed" value={latest.verification_passed ? "YES" : "NO"} good={Boolean(latest.verification_passed)} />
              <EvidenceRow label="Re-test denied" value={latest.retest_denied ? "YES" : "NO"} good={Boolean(latest.retest_denied)} />
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default function SecurityToolsPage() {
  return (
    <div className="space-y-6">

      <div className="grid gap-6 xl:grid-cols-2">

        {/* IOC / IP Lookup */}
        <ToolCard
          icon="🔍"
          title="IOC / IP State Lookup"
          description="Query the action control state for any IP — is it blocked, isolated, or whitelisted?"
          badge="Live"
          badgeTone="success"
        >
          <IocLookup />
        </ToolCard>

        {/* API Health Probe */}
        <ToolCard
          icon="🩺"
          title="Full API Health Probe"
          description="Fire HTTP probes at all platform endpoints and measure response times."
          badge="Diagnostic"
          badgeTone="info"
        >
          <ApiHealthProbe />
        </ToolCard>

        <ToolCard
          icon="FW"
          title="Windows Firewall Self-Test"
          description="Create, verify, and remove a temporary Fusion Strike AI firewall rule."
          badge="Real IPS"
          badgeTone="warning"
        >
          <FirewallSelfTest />
        </ToolCard>

        <ToolCard
          icon="IPS"
          title="IPS Enforcement Validation"
          description="Run the safe end-to-end enforcement proof and persist dashboard evidence."
          badge="E2E Proof"
          badgeTone="success"
        >
          <IpsValidationTest />
        </ToolCard>

      </div>

      {/* Platform Architecture Reference */}
      <Panel title="Platform Architecture" subtitle="Technical reference for the committee">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {[
            {
              icon: "🧠",
              title: "ML Detection Engine",
              items: ["XGBoost (15-class)", "Isolation Forest anomaly", "CIC-IDS-2018 trained", "< 50ms inference"],
            },
            {
              icon: "⚡",
              title: "Auto-Response Engine",
              items: ["Threshold-based decisions", "Cooldown + rate limiting", "BLOCK / ISOLATE actions", "Confidence-weighted"],
            },
            {
              icon: "🔬",
              title: "AI Pentest Agent",
              items: ["Nmap port scanning", "Attack graph generation", "Vulnerability scoring", "Closed-loop revalidation"],
            },
            {
              icon: "📡",
              title: "Real-Time Stack",
              items: ["WebSocket push (ws:8001)", "5s REST polling fallback", "Activity event bus", "JWT-secured API"],
            },
          ].map(({ icon, title, items }) => (
            <div key={title} className="rounded-xl border border-slate-700/40 bg-slate-900/60 p-4">
              <div className="flex items-center gap-2 mb-3">
                <span className="text-xl">{icon}</span>
                <span className="text-sm font-bold text-slate-100">{title}</span>
              </div>
              <ul className="space-y-1.5">
                {items.map((item) => (
                  <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                    <span className="mt-0.5 text-emerald-500">✓</span>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}
