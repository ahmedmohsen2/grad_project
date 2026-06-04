import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import EmptyState from "../common/EmptyState";

const chartColors = ["#ef4444", "#f97316", "#facc15", "#22c55e", "#06b6d4", "#8b5cf6", "#ec4899"];

function AttackDistributionChart({ data }) {
  if (!data.length || data.every((item) => item.value === 0)) {
    return (
      <EmptyState
        title="No attack distribution available"
        description="Attack categories will appear here once detections are received from the backend."
      />
    );
  }

  return (
    <div className="h-[280px] transition-all duration-500 ease-in-out">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="label"
            innerRadius={58}
            outerRadius={96}
            paddingAngle={4}
            stroke="rgba(15,23,42,0.9)"
            strokeWidth={3}
          >
            {data.map((entry, index) => (
              <Cell key={entry.label} fill={entry.color || chartColors[index % chartColors.length]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "#0f172a",
              border: "1px solid rgba(51, 65, 85, 0.8)",
              borderRadius: "16px",
              color: "#e2e8f0",
            }}
            formatter={(value, _name, item) => [`${value}% (${item?.payload?.count ?? 0})`, "Share"]}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export default AttackDistributionChart;
