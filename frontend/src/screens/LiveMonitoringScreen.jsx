import { useMemo, useState } from "react";
import Panel from "../components/common/Panel";
import SearchInput from "../components/common/SearchInput";
import SelectField from "../components/common/SelectField";
import DataTable from "../components/common/DataTable";
import StatusBadge from "../components/common/StatusBadge";
import { useDebouncedValue } from "../hooks/useDebouncedValue";

function LiveMonitoringScreen({ soc, onSelectIp, onNavigate }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const debouncedSearch = useDebouncedValue(search, 250);

  const rows = useMemo(
    () =>
      soc.flows.filter((flow) => {
        const matchesSearch =
          !debouncedSearch ||
          flow.sourceIp.toLowerCase().includes(debouncedSearch.toLowerCase()) ||
          flow.destinationIp.toLowerCase().includes(debouncedSearch.toLowerCase());
        const matchesFilter = filter === "All" || flow.result === filter.toUpperCase();
        return matchesSearch && matchesFilter;
      }),
    [debouncedSearch, filter, soc.flows],
  );

  return (
    <Panel
      title="Real-time traffic visibility"
      subtitle={`Live Monitoring - ${soc.wsStatus === "connected" ? `WebSocket connected (${soc.wsLatency || 0} ms)` : "Polling fallback active"} - ${soc.bandwidthProfile}`}
      rightSlot={
        <div className="flex w-full flex-col gap-3 md:w-auto md:flex-row">
          <div className="min-w-[260px]">
            <SearchInput value={search} onChange={setSearch} placeholder="Search by IP" />
          </div>
          <SelectField value={filter} onChange={setFilter} options={["All", "ATTACK", "SUSPICIOUS", "NORMAL"]} />
        </div>
      }
    >
      <DataTable
        columns={[
          { key: "timestampLabel", header: "Timestamp" },
          { key: "sourceIp", header: "Source IP" },
          { key: "destinationIp", header: "Destination IP" },
          { key: "port", header: "Port" },
          { key: "attackType", header: "Attack Type" },
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
          { key: "pps", header: "PPS" },
          { key: "packets", header: "Packets" },
          { key: "bytes", header: "Bytes" },
        ]}
        rows={rows}
        loading={soc.loading}
        emptyMessage="No flow records matched the current filter or search input."
        rowClassName={(row) =>
          row.result === "ATTACK"
            ? "bg-red-500/5 hover:bg-red-500/10"
            : row.result === "SUSPICIOUS"
              ? "bg-yellow-500/5 hover:bg-yellow-500/10"
              : "hover:bg-slate-900/75"
        }
        onRowClick={(row) => {
          onSelectIp(row.sourceIp);
          onNavigate("hosts");
        }}
      />
    </Panel>
  );
}

export default LiveMonitoringScreen;
