import Panel from "../components/common/Panel";
import MetricTile from "../components/common/MetricTile";
import StatusBadge from "../components/common/StatusBadge";

function valueOrDash(value) {
  return value === undefined || value === null || value === "" ? "-" : value;
}

function boolBadge(value, trueLabel = "Yes", falseLabel = "No") {
  return <StatusBadge label={value ? trueLabel : falseLabel} tone={value ? "success" : "warning"} />;
}

function DetailRow({ label, value, mono = false }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-slate-800/60 py-3 last:border-b-0">
      <span className="text-sm text-slate-500">{label}</span>
      <span className={`text-right text-sm font-medium text-slate-200 ${mono ? "font-mono text-xs" : ""}`}>
        {value}
      </span>
    </div>
  );
}

function NetworkVisibilityScreen({ soc }) {
  const network = soc.networkVisibility || {};
  const sensor = network.sensor || soc.health?.network_visibility || {};
  const ips = network.ips || soc.health?.ips_enforcement || {};
  const latestAction = (soc.actions || [])[0] || {};
  const failureReason = latestAction.enforcement_message || ips.backend_status_message || ips.firewall_status_message || "";

  const visibilityTone =
    sensor.sensor_mode === "inline" ? "success"
      : sensor.sensor_mode === "span" || sensor.sensor_mode === "tap" ? "info"
      : "warning";

  return (
    <div className="space-y-6">
      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile
          label="Sensor Mode"
          value={String(sensor.sensor_mode || "host").toUpperCase()}
          helper={sensor.visibility_type || "Host Only"}
        />
        <MetricTile
          label="Capture Interface"
          value={valueOrDash(sensor.capture_interface)}
          helper="Interface selected by unified_agent.py live mode."
          valueClassName="font-mono text-lg"
        />
        <MetricTile
          label="Packets Captured"
          value={Number(sensor.packets_captured || 0).toLocaleString()}
          helper="Packets seen by the Fusion sensor process."
        />
        <MetricTile
          label="Flows Analyzed"
          value={Number(sensor.flows_analyzed || 0).toLocaleString()}
          helper="Completed flows sent through ML/rule detection."
        />
      </section>

      <Panel title="Network Visibility" subtitle="Proof of current IDS deployment profile">
        <div className="grid gap-4 lg:grid-cols-[1fr_1.4fr]">
          <div className="rounded-xl border border-slate-700/40 bg-slate-900/60 p-4">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-wider text-slate-500">Visibility Type</p>
                <p className="mt-2 text-xl font-bold text-slate-100">{sensor.visibility_type || "Host Only"}</p>
              </div>
              <StatusBadge label={String(sensor.sensor_mode || "host").toUpperCase()} tone={visibilityTone} />
            </div>
            <p className="mt-4 text-sm leading-6 text-slate-400">
              {sensor.visibility_limitations || "Host mode only sees traffic that reaches the Fusion machine interface."}
            </p>
          </div>

          <div className="rounded-xl border border-slate-700/40 bg-slate-900/60 p-4">
            <DetailRow label="Promiscuous Mode" value={boolBadge(sensor.promiscuous_mode, "Enabled", "Disabled")} />
            <DetailRow label="Network-wide Capable" value={boolBadge(sensor.network_wide_capable)} />
            <DetailRow label="Inline Prevention Capable" value={boolBadge(sensor.prevention_capable)} />
            <DetailRow label="Sensor Active" value={boolBadge(sensor.active, "Active", "Inactive")} />
            <DetailRow label="Last Packet" value={valueOrDash(sensor.last_packet_at)} mono />
            <DetailRow label="Last Flow" value={valueOrDash(sensor.last_flow_at)} mono />
          </div>
        </div>
      </Panel>

      <Panel title="IPS Enforcement" subtitle="Whether block actions are real firewall enforcement or database-only state">
        <div className="grid gap-4 xl:grid-cols-3">
          <div className="rounded-xl border border-slate-700/40 bg-slate-900/60 p-4">
            <p className="text-xs uppercase tracking-wider text-slate-500">Active Profile</p>
            <p className="mt-2 text-lg font-bold text-slate-100">{String(ips.ips_mode || "database").toUpperCase()}</p>
            <p className="mt-1 font-mono text-xs text-slate-500">{ips.enforcement_method || "database"}</p>
          </div>
          <div className="rounded-xl border border-slate-700/40 bg-slate-900/60 p-4">
            <p className="text-xs uppercase tracking-wider text-slate-500">Firewall Backend</p>
            <p className="mt-2 text-lg font-bold text-slate-100">{String(ips.firewall_backend || "none").toUpperCase()}</p>
            <p className="mt-1 text-xs text-slate-500">Windows Firewall, iptables, or nftables.</p>
          </div>
          <div className="rounded-xl border border-slate-700/40 bg-slate-900/60 p-4">
            <p className="text-xs uppercase tracking-wider text-slate-500">Real Prevention</p>
            <div className="mt-2">{boolBadge(ips.real_prevention_capable, "Capable", "Database Only")}</div>
            <p className="mt-2 text-xs text-slate-500">
              Admin: {ips.admin_privileges ? "yes" : "no"} | Firewall: {ips.firewall_available ? "available" : "unavailable"}
            </p>
          </div>
        </div>
      </Panel>

      <Panel title="Latest Enforcement Evidence" subtitle="Most recent action record from the backend">
        <div className="grid gap-4 md:grid-cols-2">
          <div className="rounded-xl border border-slate-700/40 bg-slate-900/60 p-4">
            <DetailRow label="Target" value={valueOrDash(latestAction.ip)} mono />
            <DetailRow label="Action" value={valueOrDash(latestAction.action_type)} />
            <DetailRow label="Enforcement Method" value={valueOrDash(latestAction.enforcement_method)} mono />
            <DetailRow label="Verification Status" value={valueOrDash(latestAction.verification_status)} />
            <DetailRow label="Command Status" value={valueOrDash(latestAction.command_status)} />
          </div>
          <div className="rounded-xl border border-slate-700/40 bg-slate-900/60 p-4">
            <DetailRow label="Real Block Applied" value={boolBadge(latestAction.real_block_applied, "YES", "NO")} />
            <DetailRow label="Rule Exists" value={boolBadge(latestAction.rule_exists, "YES", "NO")} />
            <DetailRow label="Database Only" value={boolBadge(latestAction.database_only)} />
            <DetailRow label="Inline Block" value={boolBadge(latestAction.inline_block)} />
            <DetailRow label="Gateway Block" value={boolBadge(latestAction.gateway_block)} />
          </div>
        </div>
        {failureReason ? (
          <div className="mt-4 rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
            <p className="text-xs uppercase tracking-wider text-amber-300">Firewall Detail</p>
            <p className="mt-2 font-mono text-xs text-amber-100">{failureReason}</p>
          </div>
        ) : null}
      </Panel>
    </div>
  );
}

export default NetworkVisibilityScreen;
