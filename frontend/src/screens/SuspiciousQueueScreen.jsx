import { useCallback, useMemo, useState } from "react";
import Panel from "../components/common/Panel";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";
import SelectField from "../components/common/SelectField";

// Build set of IPs with auto-response actions
function getAutoActedIps(actions = []) {
  const ips = new Set();
  for (const a of actions) {
    if (a.source === "auto" || a.trigger === "auto") {
      ips.add(a.ip || a.target);
    }
  }
  return ips;
}

function SuspiciousQueueScreen({ soc, onSelectIp, onNavigate }) {
  const [sortBy, setSortBy] = useState("Confidence");
  const [selectedIds, setSelectedIds] = useState([]);
  const [busyIps, setBusyIps] = useState({});       // ip → "block"|"isolate"|"ignore"
  const [bulkBusy, setBulkBusy] = useState(null);   // "block"|"ignore" or null
  const [removedIds, setRemovedIds] = useState([]);  // IDs removed after block/ignore
  const [isolatedIds, setIsolatedIds] = useState([]); // IDs marked isolated

  // IPs that were auto-acted by AutoResponseEngine
  const autoActedIps = useMemo(() => getAutoActedIps(soc.actions), [soc.actions]);

  const blockedIpSet = useMemo(
    () => new Set((soc.blockedIps || []).map((b) => b.ip)),
    [soc.blockedIps],
  );

  const rows = useMemo(() => {
    const baseRows = soc.detections
      .filter((item) => item.result !== "NORMAL")
      // Defence-in-depth: also filter client-side in case poll hasn't refreshed yet
      .filter((item) => !blockedIpSet.has(item.src_ip))
      .filter((item) => !removedIds.includes(item.id));

    return [...baseRows].sort((left, right) => {
      if (sortBy === "Last Seen") {
        return String(right.detected_at).localeCompare(String(left.detected_at));
      }
      return Number(right.confidence) - Number(left.confidence);
    });
  }, [soc.detections, sortBy, removedIds, blockedIpSet]);


  const toggleSelected = (id) => {
    setSelectedIds((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    );
  };

  const toggleSelectAll = () => {
    if (selectedIds.length === rows.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(rows.map((r) => r.id));
    }
  };

  // ── Single-row action ──────────────────────────────────────────────────────
  const handleRowAction = useCallback(async (actionType, row) => {
    const ip = row.src_ip;
    if (!ip || busyIps[ip]) return;

    const actionMap = { block: "BLOCK", isolate: "ISOLATE", ignore: "WHITELIST" };
    const backendAction = actionMap[actionType];
    if (!backendAction) return;

    setBusyIps((prev) => ({ ...prev, [ip]: actionType }));

    try {
      await soc.triggerHostAction(backendAction, ip);

      if (actionType === "block" || actionType === "ignore") {
        setRemovedIds((prev) => [...prev, row.id]);
        setSelectedIds((prev) => prev.filter((id) => id !== row.id));
      } else if (actionType === "isolate") {
        setIsolatedIds((prev) => [...prev, row.id]);
      }
    } catch {
      // triggerHostAction handles its own error toast
    } finally {
      setBusyIps((prev) => {
        const next = { ...prev };
        delete next[ip];
        return next;
      });
    }
  }, [busyIps, soc]);

  // ── Bulk actions ───────────────────────────────────────────────────────────
  const handleBulkAction = useCallback(async (actionType) => {
    const selectedRows = rows.filter((r) => selectedIds.includes(r.id));
    if (selectedRows.length === 0) return;

    const actionMap = { block: "BLOCK", ignore: "WHITELIST" };
    const backendAction = actionMap[actionType];
    if (!backendAction) return;

    setBulkBusy(actionType);

    const processedIds = [];
    for (const row of selectedRows) {
      try {
        await soc.triggerHostAction(backendAction, row.src_ip);
        processedIds.push(row.id);
      } catch {
        // Continue processing remaining — partial success is fine
      }
    }

    if (processedIds.length > 0) {
      setRemovedIds((prev) => [...prev, ...processedIds]);
      setSelectedIds((prev) => prev.filter((id) => !processedIds.includes(id)));
    }

    setBulkBusy(null);
  }, [rows, selectedIds, soc]);

  // ── Button helper ──────────────────────────────────────────────────────────
  const isBusy = (ip) => !!busyIps[ip];
  const busyLabel = (ip, action, defaultLabel) => {
    if (busyIps[ip] === action) return `${defaultLabel}ing…`;
    return defaultLabel;
  };

  return (
    <div className="space-y-6">
      <Panel
        title="Analyst decision queue"
        subtitle={`Suspicious Queue — ${rows.length} active threat${rows.length !== 1 ? "s" : ""}`}
        rightSlot={
          <div className="flex items-center gap-3">
            {/* Live containment summary */}
            <div className="flex items-center gap-2 text-xs">
              <span className="flex items-center gap-1.5 rounded-full border border-emerald-500/25 bg-emerald-500/10 px-2.5 py-1 text-emerald-300 font-semibold">
                🛡️ {soc.blockedIps.length} Contained
              </span>
              {isolatedIds.length > 0 && (
                <span className="flex items-center gap-1.5 rounded-full border border-orange-500/25 bg-orange-500/10 px-2.5 py-1 text-orange-300 font-semibold">
                  🔒 {isolatedIds.length} Isolated
                </span>
              )}
            </div>
            <SelectField value={sortBy} onChange={setSortBy} options={["Confidence", "Last Seen"]} />
          </div>
        }
      >
        {/* Bulk action bar */}
        <div className="mb-5 flex flex-wrap items-center gap-3">
          <button
            type="button"
            disabled={selectedIds.length === 0 || bulkBusy !== null}
            onClick={() => handleBulkAction("block")}
            className="rounded-xl bg-red-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-red-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {bulkBusy === "block" ? "Blocking…" : `Block Selected (${selectedIds.length})`}
          </button>
          <button
            type="button"
            disabled={selectedIds.length === 0 || bulkBusy !== null}
            onClick={() => handleBulkAction("ignore")}
            className="rounded-xl bg-slate-800 px-4 py-2 text-sm font-medium text-slate-100 transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {bulkBusy === "ignore" ? "Ignoring…" : `Ignore Selected (${selectedIds.length})`}
          </button>
          {selectedIds.length > 0 && (
            <span className="ml-2 text-xs text-slate-500">
              {selectedIds.length} of {rows.length} selected
            </span>
          )}

        </div>

        <DataTable
          columns={[
            {
              key: "select",
              header: (
                <input
                  type="checkbox"
                  checked={rows.length > 0 && selectedIds.length === rows.length}
                  onChange={toggleSelectAll}
                  className="accent-sky-500"
                />
              ),
              render: (row) => (
                <input
                  type="checkbox"
                  checked={selectedIds.includes(row.id)}
                  onChange={(event) => {
                    event.stopPropagation();
                    toggleSelected(row.id);
                  }}
                  className="accent-sky-500"
                />
              ),
            },
            { key: "src_ip", header: "IP" },
            { key: "attackLabel", header: "Attack Type" },
            {
              key: "result",
              header: "Result",
              render: (row) => (
                <StatusBadge label={row.result} tone={row.result === "ATTACK" ? "danger" : "warning"} />
              ),
            },
            {
              key: "status",
              header: "Status",
              render: (row) => {
                const cs = row.containment_status;
                if (cs === "BLOCKED" || blockedIpSet.has(row.src_ip)) {
                  return (
                    <span className="inline-flex items-center gap-1.5 rounded-full bg-red-500/15 px-2.5 py-0.5 text-xs font-semibold text-red-300 ring-1 ring-red-500/30">
                      🚫 BLOCKED
                    </span>
                  );
                }
                if (isolatedIds.includes(row.id) || cs === "ISOLATED") {
                  return (
                    <span className="inline-flex items-center gap-1.5 rounded-full bg-orange-500/15 px-2.5 py-0.5 text-xs font-medium text-orange-300 ring-1 ring-orange-500/30">
                      ISOLATED
                    </span>
                  );
                }
                if (autoActedIps.has(row.src_ip)) {
                  return (
                    <span className="inline-flex items-center gap-1.5 rounded-full bg-violet-500/15 px-2.5 py-0.5 text-xs font-medium text-violet-300 ring-1 ring-violet-500/30">
                      ⚡ AUTO ACTION
                    </span>
                  );
                }
                return (
                  <span className="inline-flex items-center gap-1.5 text-xs text-slate-400">
                    <span className="live-dot" />
                    Active
                  </span>
                );
              },
            },

            { key: "confidenceLabel", header: "Confidence" },
            { key: "detectedAtLabel", header: "Last Seen" },
            {
              key: "rowActions",
              header: "Actions",
              render: (row) => (
                <div className="flex flex-wrap gap-2" onClick={(e) => e.stopPropagation()}>
                  <button
                    type="button"
                    disabled={isBusy(row.src_ip) || bulkBusy !== null}
                    onClick={() => handleRowAction("block", row)}
                    className="rounded-lg bg-red-500 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-red-400 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {busyLabel(row.src_ip, "block", "Block")}
                  </button>
                  <button
                    type="button"
                    disabled={isBusy(row.src_ip) || bulkBusy !== null}
                    onClick={() => handleRowAction("isolate", row)}
                    className="rounded-lg bg-yellow-500/20 px-3 py-1.5 text-xs font-medium text-yellow-300 transition hover:bg-yellow-500/30 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {busyLabel(row.src_ip, "isolate", "Isolate")}
                  </button>
                  <button
                    type="button"
                    disabled={isBusy(row.src_ip) || bulkBusy !== null}
                    onClick={() => handleRowAction("ignore", row)}
                    className="rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {busyLabel(row.src_ip, "ignore", "Ignore")}
                  </button>
                </div>
              ),
            },
          ]}
          rows={rows}
          onRowClick={(row) => {
            onSelectIp(row.src_ip);
            onNavigate("hosts");
          }}
          rowClassName={(row) =>
            isolatedIds.includes(row.id)
              ? "bg-orange-500/5 hover:bg-orange-500/10"
              : autoActedIps.has(row.src_ip)
                ? "bg-violet-500/5 hover:bg-violet-500/10"
                : row.result === "ATTACK"
                  ? "bg-red-500/5 hover:bg-red-500/10"
                  : "bg-yellow-500/5 hover:bg-yellow-500/10"
          }
        />
      </Panel>
    </div>
  );
}

export default SuspiciousQueueScreen;
