import { useMemo, useState } from "react";
import Panel from "../components/common/Panel";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";
import SelectField from "../components/common/SelectField";
import MetricTile from "../components/common/MetricTile";

function sourceTone(source) {
  return source === "auto" ? "warning" : "info";
}

function statusTone(status) {
  if (status === "COMPROMISED" || status === "BLOCKED") return "danger";
  if (status === "MONITORED") return "warning";
  if (status === "ISOLATED") return "info";
  if (status === "TRUSTED") return "success";
  return "success";
}

function HostsScreen({ soc, selectedIp, onSelectIp }) {
  const [filter, setFilter] = useState("ALL");
  const [activeAction, setActiveAction] = useState(null);

  const rows = useMemo(
    () =>
      soc.hosts.filter((host) => {
        const matchesIp = !selectedIp || host.ip === selectedIp || host.ip.includes(selectedIp);
        const matchesStatus = filter === "ALL" || host.status === filter;
        return matchesIp && matchesStatus;
      }),
    [filter, selectedIp, soc.hosts],
  );

  const focusHost = rows[0] || soc.hosts[0];
  const hostHistory = soc.detections.filter((item) => item.src_ip === focusHost?.ip);

  const runAction = async (action) => {
    if (!focusHost) return;
    setActiveAction(action);
    try {
      await soc.triggerHostAction(action, focusHost.ip);
    } catch {
      // useSocData shows the error toast and refreshes authoritative state.
    } finally {
      setActiveAction(null);
    }
  };

  return (
    <div className="space-y-6">
      <Panel
        title="Monitored hosts"
        subtitle="Hosts"
        rightSlot={
          <div className="flex items-center gap-3">
            {/* Clickable Auto-Response Toggle */}
            <button
              type="button"
              onClick={() => soc.toggleAutoResponse(!soc.autoResponseEnabled)}
              className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-bold transition-all duration-200 ${
                soc.autoResponseEnabled
                  ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25"
                  : "border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20"
              }`}
              title="Click to toggle auto-response enforcement"
            >
              <span className={`live-dot ${soc.autoResponseEnabled ? "" : "danger"}`} />
              AUTO-RESPONSE: {soc.autoResponseEnabled ? "ON" : "OFF"}
            </button>
            <StatusBadge label={`PENTEST ${String(soc.pentestMode || "lab").toUpperCase()}`} tone="info" />
            <SelectField value={filter} onChange={setFilter} options={["ALL", "CLEAN", "TRUSTED", "MONITORED", "COMPROMISED", "BLOCKED", "ISOLATED"]} />
          </div>
        }
      >
        <DataTable
          columns={[
            { key: "ip", header: "Host / IP" },
            {
              key: "status",
              header: "Status",
              render: (row) => <StatusBadge label={row.status} tone={statusTone(row.status)} />,
            },
            {
              key: "actionSource",
              header: "Action Source",
              render: (row) => <StatusBadge label={(row.actionSource || "manual").toUpperCase()} tone={sourceTone(row.actionSource)} />,
            },
            { key: "incidentCount", header: "Incident Count" },
            { key: "ppsLabel", header: "PPS" },
            { key: "lastSeenLabel", header: "Last Seen" },
          ]}
          rows={rows}
          onRowClick={(row) => onSelectIp(row.ip)}
        />
      </Panel>

      {focusHost ? (
        <Panel title={`IP Details: ${focusHost.ip}`} subtitle="Host Profile">
          <div className="grid gap-6 xl:grid-cols-[0.72fr_0.28fr]">
            <div className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
                <MetricTile label="Status" value={focusHost.status} helper="Current host state" />
                <MetricTile label="First Seen" value={focusHost.firstSeenLabel} helper="Initial observation" />
                <MetricTile label="Last Seen" value={focusHost.lastSeenLabel} helper="Most recent activity" />
                <MetricTile label="Incident Count" value={focusHost.incidentCount} helper="Correlated events" />
                <MetricTile label="PPS" value={focusHost.ppsLabel} helper="Peak packets per second" />
              </div>

              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <MetricTile label="Last Action" value={focusHost.lastAction} helper="Most recent containment decision" />
                <MetricTile label="Source" value={(focusHost.actionSource || "manual").toUpperCase()} helper="Manual or auto-triggered" />
                <MetricTile label="Confidence" value={`${Math.round(Number(focusHost.actionConfidence || 0) * 100)}%`} helper="Decision confidence" />
                <MetricTile label="Traffic" value={focusHost.bytesLabel} helper="Observed traffic volume" />
              </div>

              <Panel title="AI Reasoning" className="bg-slate-950/35">
                <div className="space-y-3 text-sm leading-7 text-slate-300">
                  <div className="flex flex-wrap gap-2">
                    <StatusBadge label={`SOURCE: ${(focusHost.actionSource || "manual").toUpperCase()}`} tone={sourceTone(focusHost.actionSource)} />
                    {soc.autoResponseEnabled ? <StatusBadge label="AUTO ACTIVE" tone="warning" /> : null}
                  </div>
                  <p>{focusHost.actionReason || "No automated or manual containment reasoning recorded yet."}</p>
                  <p className="text-xs text-slate-400">
                    Confidence: {Math.round(Number(focusHost.actionConfidence || 0) * 100)}% | Last action time: {focusHost.actionAt || "--"}
                  </p>
                </div>
              </Panel>

              <Panel title="Detection History" className="bg-slate-950/35">
                <DataTable
                  columns={[
                    { key: "detectedAtLabel", header: "Time" },
                    { key: "attackLabel", header: "Attack Type" },
                    {
                      key: "result",
                      header: "Result",
                      render: (row) => (
                        <StatusBadge
                          label={row.result}
                          tone={row.result === "ATTACK" ? "danger" : row.result === "SUSPICIOUS" ? "warning" : "neutral"}
                        />
                      ),
                    },
                    { key: "confidenceLabel", header: "Confidence" },
                  ]}
                  rows={hostHistory}
                />
              </Panel>
            </div>

            <div className="space-y-4">
              <Panel title="Sticky Actions" className="bg-slate-950/35">
                <div className="space-y-3">
                  <button
                    type="button"
                    onClick={() => runAction("BLOCK")}
                    disabled={activeAction !== null}
                    className="w-full rounded-xl bg-red-500 px-4 py-3 text-sm font-medium text-white disabled:opacity-50"
                  >
                    {activeAction === "BLOCK" ? "Blocking..." : "Block"}
                  </button>
                  <button
                    type="button"
                    onClick={() => runAction("ISOLATE")}
                    disabled={activeAction !== null}
                    className="w-full rounded-xl bg-yellow-500/20 px-4 py-3 text-sm font-medium text-yellow-300 disabled:opacity-50"
                  >
                    {activeAction === "ISOLATE" ? "Isolating..." : "Isolate"}
                  </button>
                  <button
                    type="button"
                    onClick={() => runAction("WHITELIST")}
                    disabled={activeAction !== null}
                    className="w-full rounded-xl bg-emerald-500/15 px-4 py-3 text-sm font-medium text-emerald-300 disabled:opacity-50"
                  >
                    {activeAction === "WHITELIST" ? "Whitelisting..." : "Whitelist"}
                  </button>
                </div>
              </Panel>
            </div>
          </div>
        </Panel>
      ) : null}
    </div>
  );
}

export default HostsScreen;
