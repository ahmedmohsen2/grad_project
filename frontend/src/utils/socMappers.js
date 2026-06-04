import { formatMegabytes, formatNumber, formatPercent, formatTimestamp, normalizeTimestamp, titleize } from "./formatters";

const BENIGN_LABELS = new Set(["", "BENIGN", "NORMAL", "OK", "CLEAN", "NONE"]);
const ATTACK_COLORS = [
  "#ef4444",
  "#f97316",
  "#facc15",
  "#22c55e",
  "#06b6d4",
  "#8b5cf6",
  "#ec4899",
  "#94a3b8",
];

const ATTACK_ALIASES = [
  { aliases: ["DDOS", "D DOS", "DOS HULK", "DOS GOLDENEYE", "SLOWLORIS", "SLOWHTTPTEST", "HEARTBLEED"], label: "DDoS" },
  { aliases: ["PORTSCAN", "PORT SCAN", "SCAN"], label: "PortScan" },
  { aliases: ["BRUTEFORCE", "BRUTE FORCE", "FTP PATATOR", "SSH PATATOR", "PATATOR"], label: "BruteForce" },
  { aliases: ["BOT", "BOTNET"], label: "Bot" },
  { aliases: ["WEBATTACK", "WEB ATTACK", "SQL INJECTION", "XSS"], label: "WebAttack" },
  { aliases: ["INFILTRATION"], label: "Infiltration" },
  { aliases: ["MALWARE", "RANSOMWARE", "BEACON"], label: "Malware" },
];

function cleanAttackLabel(value) {
  return String(value ?? "")
    .replace(/\(conf=.*?\)/gi, "")
    .replace(/^(ML|ML\+ISO):/i, "")
    .replace(/[_\-/]+/g, " ")
    .trim();
}

export function normalizeDetectionResult(value, attackType = "") {
  const normalized = String(value ?? "").trim().toUpperCase();
  const attackNormalized = String(attackType ?? "").trim().toUpperCase();

  if (["ATTACK", "MALICIOUS", "ANOMALY", "CRITICAL", "HIGH"].includes(normalized)) return "ATTACK";
  if (["SUSPICIOUS", "WARNING", "MEDIUM"].includes(normalized)) return "SUSPICIOUS";
  if (["NORMAL", "BENIGN", "CLEAN", "OK"].includes(normalized)) return "NORMAL";
  if (attackNormalized && !BENIGN_LABELS.has(attackNormalized)) return "ATTACK";
  return "NORMAL";
}

export function normalizeAttackLabel(value, result = "") {
  const cleaned = cleanAttackLabel(value);
  const folded = cleaned.replace(/\s+/g, " ").toUpperCase();

  if (BENIGN_LABELS.has(folded)) return "BENIGN";

  const match = ATTACK_ALIASES.find(({ aliases }) => aliases.some((alias) => folded.includes(alias)));
  if (match) return match.label;

  if (normalizeDetectionResult(result, folded) === "NORMAL") return "BENIGN";
  return cleaned || "Unknown";
}

function inferPort(attackType) {
  const normalized = String(attackType || "").toUpperCase();

  if (normalized.includes("BRUTE")) {
    return 22;
  }
  if (normalized.includes("MALWARE")) {
    return 445;
  }
  if (normalized.includes("DDOS")) {
    return 443;
  }

  return 80;
}

function normalizeMetadata(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch {
      return {};
    }
  }
  return {};
}

export function normalizeAlerts(alerts = []) {
  return alerts.map((alert, index) => {
    const metadata = normalizeMetadata(alert.metadata);
    const timestamp = normalizeTimestamp(alert.updated_at || alert.created_at || alert.timestamp || alert.time) || new Date(0).toISOString();
    const id = alert.id ?? alert.alert_id ?? `${alert.ip || alert.ip_address || alert.target || "alert"}-${timestamp}-${index}`;
    const isRead = Boolean(alert.is_read || alert.read_at || String(alert.status || "").toLowerCase() === "acknowledged");
    const lifecycleStatus = isRead ? "acknowledged" : String(alert.status || "open").toLowerCase();
    return {
      ...alert,
      id,
      ip: alert.ip || alert.ip_address || alert.target || "Unknown",
      type: alert.type || alert.alert_type || "ALERT",
      is_read: isRead,
      status: lifecycleStatus,
      severity: String(metadata.severity || alert.severity || alert.type || alert.alert_type || "info").toUpperCase(),
      source: alert.source || metadata.source || "backend",
      timestamp,
      time: timestamp,
      created_at: normalizeTimestamp(alert.created_at) || timestamp,
      updated_at: normalizeTimestamp(alert.updated_at || alert.read_at) || timestamp,
      timeLabel: formatTimestamp(timestamp),
      statusLabel: isRead ? "Acknowledged" : "Open",
      metadata,
    };
  });
}

export function normalizeActivityLogs(events = []) {
  return events.map((event, index) => {
    const timestamp = normalizeTimestamp(event.timestamp || event.created_at || event.updated_at) || new Date(0).toISOString();
    const type = String(event.type || "system").toLowerCase();
    const action = event.action || "unknown";
    const target = event.target || event.ip || event.ip_address || "";

    return {
      ...event,
      id: event.id ?? `${type}-${action}-${target || "system"}-${timestamp}-${index}`,
      type,
      action,
      target,
      reason: event.reason || event.message || "",
      source: event.source || "system",
      status: String(event.status || "success").toLowerCase(),
      timestamp,
      created_at: normalizeTimestamp(event.created_at) || timestamp,
      updated_at: normalizeTimestamp(event.updated_at) || timestamp,
      metadata: normalizeMetadata(event.metadata),
    };
  });
}

export function deriveAlertStats(alerts = []) {
  const unique = new Map();
  alerts.forEach((alert) => {
    if (alert?.id === undefined || alert?.id === null) return;
    unique.set(alert.id, alert);
  });
  const rows = Array.from(unique.values());
  const openRows = rows.filter((alert) => !alert.is_read && alert.status !== "resolved");
  const acknowledgedRows = rows.filter((alert) => alert.is_read || alert.status === "acknowledged");
  const resolvedRows = rows.filter((alert) => alert.status === "resolved");

  return {
    total: rows.length,
    open: openRows.length,
    unread: openRows.length,
    new: openRows.length,
    acknowledged: acknowledgedRows.length,
    resolved: resolvedRows.length,
  };
}

export function normalizeDetections(detections = []) {
  return detections.map((item, index) => {
    const result = normalizeDetectionResult(item.result || item.label, item.attack_type || item.prediction);
    const attackType = result === "NORMAL"
      ? "BENIGN"
      : normalizeAttackLabel(item.attack_type || item.prediction || item.label, result);
    const timestamp = normalizeTimestamp(item.updated_at || item.detected_at || item.timestamp || item.time) || new Date(0).toISOString();
    const sourceIp = item.src_ip || item.source_ip || item.ip || item.source || "Unknown";
    const destinationIp = item.dst_ip || item.destination_ip || item.destination || null;

    return {
      ...item,
      id: item.id ?? `${sourceIp}-${timestamp ?? index}-${attackType}`,
      label: attackType,
      prediction: attackType,
      attack_type: attackType,
      attackLabel: attackType === "BENIGN" ? "Benign" : titleize(attackType),
      result,
      severity: String(item.severity || result).toUpperCase(),
      confidence: Number(item.confidence ?? 0),
      confidenceLabel: formatPercent(item.confidence),
      timestamp,
      detected_at: timestamp,
      updated_at: normalizeTimestamp(item.updated_at) || timestamp,
      created_at: normalizeTimestamp(item.created_at) || timestamp,
      detectedAtLabel: formatTimestamp(timestamp),
      source_ip: sourceIp,
      destination_ip: destinationIp,
      src_ip: sourceIp,
      dst_ip: destinationIp,
    };
  });
}

export function normalizePentestFindings(findings = []) {
  return findings.map((item) => ({
    ...item,
    id: item.finding_id || item.id,
    severity: String(item.severity || "medium").toUpperCase(),
    status: item.status || "detected",
    source: item.source || "pentest",
    created_at: normalizeTimestamp(item.first_seen_at || item.created_at || item.updated_at),
    updated_at: normalizeTimestamp(item.updated_at || item.last_seen_at || item.first_seen_at),
    statusLabel: String(item.status || "detected").replaceAll("_", " "),
    mitigationLabel: String(item.mitigation_state || "unresolved").replaceAll("_", " "),
    confidenceLabel: formatPercent(item.confidence),
    updatedAtLabel: formatTimestamp(item.updated_at || item.last_seen_at || item.first_seen_at),
  }));
}

export function normalizeFlows(flows = [], detections = []) {
  return flows.map((flow, index) => {
    const linkedDetection = detections[index] || detections.find((item) => item.src_ip === flow.src_ip);
    const confidence = Number(flow.confidence ?? linkedDetection?.confidence ?? 0);

    const timestamp = normalizeTimestamp(flow.updated_at || flow.captured_at || flow.detected_at || linkedDetection?.detected_at) || new Date(0).toISOString();
    return {
      id: flow.id ?? `${flow.src_ip || linkedDetection?.src_ip}-${flow.dst_ip || "dst"}-${timestamp}-${index}`,
      timestamp,
      created_at: normalizeTimestamp(flow.created_at || flow.captured_at) || timestamp,
      updated_at: normalizeTimestamp(flow.updated_at || flow.captured_at) || timestamp,
      status: flow.status || flow.result || linkedDetection?.result || "NORMAL",
      source: flow.source || "packet_capture",
      timestampLabel: formatTimestamp(timestamp),
      sourceIp: flow.src_ip || linkedDetection?.src_ip || "Unknown",
      destinationIp: flow.dst_ip || "Internal host",
      port: flow.port ?? inferPort(linkedDetection?.attack_type),
      attackType: titleize(flow.attack_type || linkedDetection?.attack_type || "UNKNOWN"),
      result: flow.result || linkedDetection?.result || "NORMAL",
      confidence,
      confidenceLabel: formatPercent(confidence),
      pps: formatNumber(flow.pps),
      packets: formatNumber(flow.packets),
      bytes: formatNumber(flow.bytes),
      bytesCompact: formatMegabytes(flow.bytes),
    };
  });
}

export function deriveThreatState(detections = [], alerts = [], pentestFindings = []) {
  const totalFlows = detections.length;
  const maliciousWeight = detections.reduce((total, item) => {
    if (item.result === "ATTACK") return total + 1;
    if (item.result === "SUSPICIOUS") return total + 0.5;
    return total;
  }, 0);
  const detectionRisk = totalFlows > 0 ? (maliciousWeight / totalFlows) * 100 : 0;
  const alertRisk = Math.min(deriveAlertStats(alerts).open * 3, 15);
  const pentestRisk = Math.min(
    pentestFindings.reduce((total, item) => total + Number(item.risk_score || 0), 0) * 0.05,
    10,
  );
  const percent = Math.min(100, Math.max(0, Math.round(detectionRisk + alertRisk + pentestRisk)));

  if (percent >= 75) {
    return { percent, label: "Threat Level: HIGH", tone: "danger" };
  }
  if (percent >= 45) {
    return { percent, label: "Threat Level: MEDIUM", tone: "warning" };
  }
  return { percent, label: "Threat Level: LOW", tone: "success" };
}

export function deriveAttackDistribution(detections = []) {
  const counts = detections.reduce((map, item) => {
    const label = normalizeAttackLabel(item.attack_type || item.prediction || item.label, item.result);
    const result = normalizeDetectionResult(item.result, label);
    if (result === "NORMAL" || label === "BENIGN") return map;
    map.set(label, (map.get(label) || 0) + 1);
    return map;
  }, new Map());

  const total = Array.from(counts.values()).reduce((sum, count) => sum + count, 0);
  if (total === 0) return [];

  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1])
    .map(([label, count], index) => ({
      label,
      count,
      value: Math.round((count / total) * 100),
      color: ATTACK_COLORS[index % ATTACK_COLORS.length],
    }));
}

export function deriveHosts(flows = [], detections = [], blockedIps = [], actions = []) {
  const hostMap = new Map();
  const blockedSet = new Set(blockedIps.map((item) => item.ip));
  const latestActionByIp = new Map();

  actions.forEach((action) => {
    const current = latestActionByIp.get(action.ip);
    if (!current || new Date(action.acted_at || 0).getTime() > new Date(current.acted_at || 0).getTime()) {
      latestActionByIp.set(action.ip, action);
    }
  });

  const statusFromAction = (ip) => {
    const latest = latestActionByIp.get(ip);
    const action = String(latest?.action_type || "").toUpperCase();
    if (action === "BLOCK") return "BLOCKED";
    if (action === "ISOLATE") return "ISOLATED";
    if (action === "WHITELIST") return "TRUSTED";
    if (action === "UNBLOCK" || action === "UNISOLATE") return "CLEAN";
    return null;
  };

  flows.forEach((flow) => {
    const current = hostMap.get(flow.sourceIp) || {
      ip: flow.sourceIp,
      firstSeen: flow.timestamp,
      lastSeen: flow.timestamp,
      packets: 0,
      bytes: 0,
      pps: 0,
      incidentCount: 0,
      status: "CLEAN",
    };

    current.firstSeen = current.firstSeen < flow.timestamp ? current.firstSeen : flow.timestamp;
    current.lastSeen = current.lastSeen > flow.timestamp ? current.lastSeen : flow.timestamp;
    current.packets += Number(String(flow.packets).replaceAll(",", ""));
    current.bytes += Number(String(flow.bytes).replaceAll(",", ""));
    current.pps = Math.max(current.pps, Number(String(flow.pps).replaceAll(",", "")));

    hostMap.set(flow.sourceIp, current);
  });

  detections.forEach((detection) => {
    const current = hostMap.get(detection.src_ip) || {
      ip: detection.src_ip,
      firstSeen: detection.detected_at,
      lastSeen: detection.detected_at,
      packets: 0,
      bytes: 0,
      pps: 0,
      incidentCount: 0,
      status: "MONITORED",
    };

    current.incidentCount += detection.result === "NORMAL" ? 0 : 1;
    current.lastSeen = current.lastSeen > detection.detected_at ? current.lastSeen : detection.detected_at;

    const actionStatus = statusFromAction(detection.src_ip);
    if (actionStatus) {
      current.status = actionStatus;
    } else if (blockedSet.has(detection.src_ip)) {
      current.status = "BLOCKED";
    } else if (detection.result === "ATTACK") {
      current.status = "COMPROMISED";
    } else if (detection.result === "SUSPICIOUS") {
      current.status = "MONITORED";
    }

    hostMap.set(detection.src_ip, current);
  });

  // Also add blocked IPs that may not have detections yet
  blockedIps.forEach((item) => {
    if (!hostMap.has(item.ip)) {
      hostMap.set(item.ip, {
        ip: item.ip,
        firstSeen: item.blocked_at,
        lastSeen: item.blocked_at,
        packets: 0,
        bytes: 0,
        pps: 0,
        incidentCount: 0,
        status: "BLOCKED",
      });
    } else {
      hostMap.get(item.ip).status = statusFromAction(item.ip) || "BLOCKED";
    }
  });

  latestActionByIp.forEach((action, ip) => {
    const actionStatus = statusFromAction(ip);
    if (!actionStatus) return;
    if (!hostMap.has(ip)) {
      const timestamp = normalizeTimestamp(action.acted_at || action.updated_at || action.created_at) || new Date(0).toISOString();
      hostMap.set(ip, {
        ip,
        firstSeen: timestamp,
        lastSeen: timestamp,
        packets: 0,
        bytes: 0,
        pps: 0,
        incidentCount: 0,
        status: actionStatus,
      });
      return;
    }
    hostMap.get(ip).status = actionStatus;
  });

  return Array.from(hostMap.values())
    .map((host) => ({
      ...host,
      lastAction: latestActionByIp.get(host.ip)?.action_type || "NONE",
      actionReason: latestActionByIp.get(host.ip)?.reason || "",
      actionSource: latestActionByIp.get(host.ip)?.source || "manual",
      actionConfidence: latestActionByIp.get(host.ip)?.confidence ?? 0,
      actionAt: latestActionByIp.get(host.ip)?.acted_at || null,
      firstSeenLabel: formatTimestamp(host.firstSeen),
      lastSeenLabel: formatTimestamp(host.lastSeen),
      packetsLabel: formatNumber(host.packets),
      bytesLabel: formatMegabytes(host.bytes),
      ppsLabel: formatNumber(host.pps),
    }))
    .sort((left, right) => right.incidentCount - left.incidentCount);
}

export function deriveIncidents(alerts = [], detections = [], pentestFindings = []) {
  const pentestIncidents = pentestFindings.map((item) => ({
    id: item.finding_id,
    ip: item.target,
    severity: item.severity,
    attackType: item.title,
    timeline: (Array.isArray(item.timeline) ? item.timeline : []).map(
      (step) => `${formatTimestamp(step.time)}: ${step.label}${step.details ? ` - ${step.details}` : ""}`,
    ),
    note: item.remediation || `${item.mitigationLabel}. Risk score ${item.risk_score}.`,
  }));

  const detectionIncidents = detections
    .filter((item) => item.result !== "NORMAL")
    .map((item, index) => {
      const relatedAlerts = alerts.filter((alert) => alert.ip === item.src_ip);
      return {
        id: item.id ?? `${item.src_ip}-${index}`,
        ip: item.src_ip,
        severity: item.result,
        attackType: item.attackLabel,
        timeline: [
          `${item.detectedAtLabel}: Detection classified as ${item.result}.`,
          ...relatedAlerts.slice(0, 2).map((alert) => `${alert.timeLabel}: ${alert.message}`),
        ],
        note: relatedAlerts[0]?.message || "Analyst note pending review.",
      };
    });

  return [...pentestIncidents, ...detectionIncidents].slice(0, 8);
}
