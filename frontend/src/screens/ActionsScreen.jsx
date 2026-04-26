import Panel from "../components/common/Panel";
import DataTable from "../components/common/DataTable";
import { useAuth } from "../hooks/useAuth.jsx";

function ActionsScreen({ soc }) {
  const { user } = useAuth();

  const isolatedDevices = soc.hosts
    .filter((item) => item.status === "ISOLATED")
    .map((item) => ({
      device: item.ip,
      reason: "Containment applied after confirmed malicious behavior.",
      time: item.lastSeenLabel,
    }));

  const whitelist = soc.hosts
    .filter((item) => item.status === "CLEAN")
    .slice(0, 4)
    .map((item) => ({
      ip: item.ip,
      addedBy: user?.username ?? "Analyst",
    }));

  return (
    <div className="space-y-6">
      <Panel title="Blocked IPs" subtitle="Firewall">
        <DataTable
          columns={[
            { key: "ip", header: "IP" },
            { key: "reason", header: "Reason" },
            { key: "blocked_at", header: "Time" },
            {
              key: "action",
              header: "Action",
              render: () => (
                <button type="button" className="rounded-lg bg-slate-800 px-3 py-2 text-xs font-medium text-slate-200">
                  Unblock
                </button>
              ),
            },
          ]}
          rows={soc.blockedIps}
        />
      </Panel>

      <Panel title="Isolated Devices" subtitle="Containment">
        <DataTable
          columns={[
            { key: "device", header: "Device" },
            { key: "reason", header: "Reason" },
            { key: "time", header: "Time" },
            {
              key: "action",
              header: "Action",
              render: () => (
                <button type="button" className="rounded-lg bg-slate-800 px-3 py-2 text-xs font-medium text-slate-200">
                  Remove Isolation
                </button>
              ),
            },
          ]}
          rows={isolatedDevices}
        />
      </Panel>

      <Panel title="Whitelist" subtitle="Trusted Sources">
        <DataTable
          columns={[
            { key: "ip", header: "IP" },
            { key: "addedBy", header: "Added By" },
            {
              key: "action",
              header: "Action",
              render: () => (
                <button type="button" className="rounded-lg bg-slate-800 px-3 py-2 text-xs font-medium text-slate-200">
                  Remove
                </button>
              ),
            },
          ]}
          rows={whitelist}
        />
      </Panel>
    </div>
  );
}

export default ActionsScreen;
