import { useMemo, useState } from "react";
import Panel from "../components/common/Panel";
import SelectField from "../components/common/SelectField";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";
import SearchInput from "../components/common/SearchInput";
import { useDebouncedValue } from "../hooks/useDebouncedValue";

function AlertsScreen({ soc, onSelectIp, onNavigate, onOpenIncident }) {
  const [typeFilter, setTypeFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [sortBy, setSortBy] = useState("Newest");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [bulkReadState, setBulkReadState] = useState({ loading: false, message: "", error: "" });
  const debouncedSearch = useDebouncedValue(search, 300);
  const pageSize = 10;
  const hasUnreadAlerts = Number(soc.alertStats?.open || 0) > 0;

  const rows = useMemo(() => {
    const filtered = soc.alerts.filter((alert) => {
      const matchesType = typeFilter === "All" || alert.type === typeFilter.toUpperCase();
      const matchesStatus =
        statusFilter === "All" ||
        (statusFilter === "Open" && !alert.is_read) ||
        (statusFilter === "Acknowledged" && alert.is_read);
      const matchesSearch =
        !debouncedSearch ||
        alert.ip.toLowerCase().includes(debouncedSearch.toLowerCase()) ||
        String(alert.message || "").toLowerCase().includes(debouncedSearch.toLowerCase());

      return matchesType && matchesStatus && matchesSearch;
    });

    return [...filtered].sort((left, right) => {
      if (sortBy === "Oldest") {
        return String(left.time).localeCompare(String(right.time));
      }
      if (sortBy === "Type") {
        return String(left.type).localeCompare(String(right.type));
      }
      return String(right.time).localeCompare(String(left.time));
    });
  }, [debouncedSearch, soc.alerts, sortBy, statusFilter, typeFilter]);

  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const pageRows = rows.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleMarkAllAsRead = async () => {
    setBulkReadState({ loading: true, message: "", error: "" });
    try {
      const response = await soc.markAllAlertsAsRead();
      const updated = response?.total_updated ?? response?.updated ?? 0;
      setBulkReadState({
        loading: false,
        message: `${updated} alert${updated === 1 ? "" : "s"} marked as read.`,
        error: "",
      });
    } catch (error) {
      setBulkReadState({
        loading: false,
        message: "",
        error: error?.message || "Failed to mark alerts as read.",
      });
    }
  };

  return (
    <Panel
      title="Alert triage"
      subtitle="Alerts"
      rightSlot={
        <div className="flex w-full flex-col gap-3 md:w-auto md:flex-row">
          {hasUnreadAlerts && (
            <button
              type="button"
              className="rounded-lg bg-sky-500/15 px-4 py-2 text-sm font-semibold text-sky-200 transition hover:bg-sky-500/25 disabled:cursor-not-allowed disabled:opacity-50"
              disabled={bulkReadState.loading}
              onClick={handleMarkAllAsRead}
            >
              {bulkReadState.loading ? "Processing..." : "Mark All as Read"}
            </button>
          )}
          <div className="min-w-[260px]">
            <SearchInput value={search} onChange={setSearch} placeholder="Search alerts by IP or message" />
          </div>
          <SelectField value={typeFilter} onChange={setTypeFilter} options={["All", "ATTACK", "SUSPICIOUS", "BLOCK", "MALWARE", "PENTEST_FINDING"]} />
          <SelectField value={statusFilter} onChange={setStatusFilter} options={["All", "Open", "Acknowledged"]} />
          <SelectField value={sortBy} onChange={setSortBy} options={["Newest", "Oldest", "Type"]} />
        </div>
      }
    >
      {(bulkReadState.message || bulkReadState.error) && (
        <div
          className={`mb-4 rounded-lg border px-4 py-3 text-sm ${
            bulkReadState.error
              ? "border-red-500/30 bg-red-500/10 text-red-100"
              : "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
          }`}
        >
          {bulkReadState.error || bulkReadState.message}
        </div>
      )}
      <DataTable
        columns={[
          { key: "ip", header: "IP" },
          {
            key: "severity",
            header: "Severity",
            render: (row) => (
              <StatusBadge
                label={row.severity || "INFO"}
                tone={
                  row.severity === "CRITICAL" || row.severity === "HIGH"
                    ? "danger"
                    : row.severity === "MEDIUM" || row.severity === "SUSPICIOUS"
                      ? "warning"
                      : "info"
                }
              />
            ),
          },
          { key: "type", header: "Type" },
          { key: "message", header: "Message" },
          {
            key: "status",
            header: "Status",
            render: (row) => (
              <StatusBadge
                label={row.statusLabel}
                tone={
                  row.is_read
                    ? "success"
                    : row.type === "BLOCK"
                      ? "success"
                      : row.type === "SUSPICIOUS"
                      ? "warning"
                      : row.type === "ATTACK"
                        ? "danger"
                        : row.type === "PENTEST_FINDING"
                          ? "warning"
                          : "neutral"
                }
              />
            ),
          },
          { key: "timeLabel", header: "Time" },
          {
            key: "actions",
            header: "Actions",
            render: (row) => (
              <div className="flex gap-2">
                <button
                  type="button"
                  className="rounded-lg bg-emerald-500/15 px-3 py-2 text-xs font-medium text-emerald-300"
                  onClick={(event) => {
                    event.stopPropagation();
                    onOpenIncident?.(row.id || row.ip);
                  }}
                >
                  View Incident
                </button>
                {!row.is_read && (
                  <button
                    type="button"
                    className="rounded-lg bg-sky-500/15 px-3 py-2 text-xs font-medium text-sky-300"
                    onClick={(event) => {
                      event.stopPropagation();
                      soc.markAlertAsRead(row.id);
                    }}
                  >
                    Mark as Read
                  </button>
                )}
              </div>
            ),
          },
        ]}
        rows={pageRows}
        loading={soc.loading}
        emptyMessage="No alerts matched the selected type, status, or search query."
        onRowClick={(row) => {
          onSelectIp(row.ip);
          onNavigate("hosts");
        }}
      />
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400">
        <span>
          Showing {rows.length === 0 ? 0 : (currentPage - 1) * pageSize + 1}-{Math.min(currentPage * pageSize, rows.length)} of {rows.length}
        </span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="rounded-lg border border-slate-700 px-3 py-2 text-slate-200 disabled:cursor-not-allowed disabled:opacity-40"
            disabled={currentPage <= 1}
            onClick={() => setPage((value) => Math.max(1, value - 1))}
          >
            Previous
          </button>
          <span className="font-mono">Page {currentPage}/{totalPages}</span>
          <button
            type="button"
            className="rounded-lg border border-slate-700 px-3 py-2 text-slate-200 disabled:cursor-not-allowed disabled:opacity-40"
            disabled={currentPage >= totalPages}
            onClick={() => setPage((value) => Math.min(totalPages, value + 1))}
          >
            Next
          </button>
        </div>
      </div>
    </Panel>
  );
}

export default AlertsScreen;
