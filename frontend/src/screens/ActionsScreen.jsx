import { useState } from "react";
import Panel from "../components/common/Panel";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";
import { useAuth } from "../hooks/useAuth.jsx";

function ActionButton({ label, onClick, tone = "neutral", disabled }) {
  const toneMap = {
    danger:  "bg-red-500/15 text-red-300 hover:bg-red-500/25 border-red-500/25",
    warning: "bg-amber-500/15 text-amber-300 hover:bg-amber-500/25 border-amber-500/25",
    success: "bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25 border-emerald-500/25",
    neutral: "bg-slate-700/40 text-slate-300 hover:bg-slate-700/60 border-slate-600/40",
  };
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`rounded-lg border px-3 py-1.5 text-xs font-semibold transition-all duration-150 disabled:cursor-not-allowed disabled:opacity-40 ${toneMap[tone]}`}
    >
      {label}
    </button>
  );
}

function ActionsScreen({ soc }) {
  const { user } = useAuth();
  const [busy, setBusy] = useState(null); // ip:action

  const doAction = async (action, ip) => {
    const key = `${ip}:${action}`;
    setBusy(key);
    try {
      await soc.triggerHostAction(action, ip);
    } catch (err) {
      console.error("Action failed:", err);
    } finally {
      setBusy(null);
    }
  };

  const blockedRows = (soc.blockedIps || []).map((item) => ({
    ...item,
    _ip: item.ip,
  }));

  const isolatedRows = soc.hosts
    .filter((h) => h.status === "ISOLATED")
    .map((h) => ({
      device: h.ip,
      reason: h.actionReason || "Containment applied after confirmed malicious behavior.",
      time: h.lastSeenLabel,
      source: h.actionSource || "manual",
      _ip: h.ip,
    }));

  const actionLogRows = (soc.actions || []).slice(0, 10).map((a) => ({
    ...a,
    _tone: a.action_type === "BLOCK" ? "danger"
         : a.action_type === "ISOLATE" ? "warning"
         : a.action_type === "UNBLOCK" || a.action_type === "UNISOLATE" ? "success"
         : "neutral",
  }));

  return (
    <div className="space-y-6">

      {/* ── Blocked IPs ────────────────────────────────────────────────── */}
      <Panel
        title="Blocked IPs"
        subtitle={`${blockedRows.length} active firewall block${blockedRows.length !== 1 ? "s" : ""}`}
      >
        <DataTable
          columns={[
            { key: "ip", header: "IP Address", render: (row) => (
              <span className="font-mono text-xs text-red-300">{row.ip}</span>
            )},
            { key: "reason", header: "Reason" },
            { key: "blocked_at", header: "Blocked At" },
            {
              key: "action",
              header: "Action",
              render: (row) => (
                <ActionButton
                  label={busy === `${row._ip}:UNBLOCK` ? "Unblocking…" : "Unblock"}
                  tone="success"
                  disabled={!!busy}
                  onClick={(e) => { e.stopPropagation(); doAction("UNBLOCK", row._ip); }}
                />
              ),
            },
          ]}
          rows={blockedRows}
          loading={soc.loading}
          emptyMessage="No IPs are currently blocked. Block actions from the Hosts page will appear here."
          rowClassName={() => "border-l-2 border-red-500/30"}
        />
      </Panel>

      {/* ── Isolated Devices ────────────────────────────────────────────── */}
      <Panel
        title="Isolated Devices"
        subtitle={`${isolatedRows.length} device${isolatedRows.length !== 1 ? "s" : ""} in network isolation`}
      >
        <DataTable
          columns={[
            { key: "device", header: "Device / IP", render: (row) => (
              <span className="font-mono text-xs text-amber-300">{row.device}</span>
            )},
            { key: "reason", header: "Reason" },
            { key: "time", header: "Last Seen" },
            { key: "source", header: "Source", render: (row) => (
              <StatusBadge label={row.source.toUpperCase()} tone={row.source === "auto" ? "warning" : "info"} />
            )},
            {
              key: "action",
              header: "Action",
              render: (row) => (
                <ActionButton
                  label={busy === `${row._ip}:UNISOLATE` ? "Removing…" : "Remove Isolation"}
                  tone="success"
                  disabled={!!busy}
                  onClick={(e) => { e.stopPropagation(); doAction("UNISOLATE", row._ip); }}
                />
              ),
            },
          ]}
          rows={isolatedRows}
          loading={soc.loading}
          emptyMessage="No devices are currently isolated."
          rowClassName={() => "border-l-2 border-amber-500/30"}
        />
      </Panel>

      {/* ── Recent Action Log ───────────────────────────────────────────── */}
      <Panel title="Recent Action Log" subtitle="Last 10 enforcement decisions">
        <DataTable
          columns={[
            { key: "ip", header: "Target IP", render: (row) => (
              <span className="font-mono text-xs text-slate-300">{row.ip}</span>
            )},
            { key: "action_type", header: "Action", render: (row) => (
              <StatusBadge
                label={row.action_type}
                tone={row._tone}
              />
            )},
            { key: "reason", header: "Reason" },
            { key: "enforcement_method", header: "Method", render: (row) => (
              <span className="font-mono text-[11px] text-slate-300">{row.enforcement_method || "database"}</span>
            )},
            { key: "verification_status", header: "Verified", render: (row) => (
              <StatusBadge
                label={row.verification_status || "unknown"}
                tone={row.verification_status === "verified" ? "success" : row.database_only ? "warning" : "danger"}
              />
            )},
            { key: "real_block_applied", header: "Real Block", render: (row) => (
              <StatusBadge
                label={row.real_block_applied ? "YES" : row.database_only ? "DB ONLY" : "NO"}
                tone={row.real_block_applied ? "success" : "warning"}
              />
            )},
            { key: "source", header: "Source", render: (row) => (
              <StatusBadge
                label={(row.source || "manual").toUpperCase()}
                tone={row.source === "auto" ? "warning" : "info"}
              />
            )},
            { key: "actor", header: "Actor", render: (row) => (
              <span className="text-xs text-slate-300">
                {row.actor_username || "system"}
                <span className="ml-1 text-slate-500">({row.actor_role || "service"})</span>
              </span>
            )},
            { key: "acted_at", header: "Time" },
          ]}
          rows={actionLogRows}
          loading={soc.loading}
          emptyMessage="No actions have been executed yet."
        />
      </Panel>
    </div>
  );
}

export default ActionsScreen;
