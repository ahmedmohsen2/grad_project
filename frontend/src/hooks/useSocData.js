import { useEffect, useMemo, useRef, useState } from "react";
import { socApi } from "../services/socApi";
import { API_BASE_URL, WS_BASE_URL } from "../api/baseUrl";
import { getBandwidthProfile, setBandwidthProfile as persistBandwidthProfile } from "../utils/bandwidth";
import {
  deriveAttackDistribution,
  deriveAlertStats,
  deriveHosts,
  deriveIncidents,
  deriveThreatState,
  normalizeActivityLogs,
  normalizeAlerts,
  normalizeDetections,
  normalizeFlows,
  normalizePentestFindings,
} from "../utils/socMappers";
import { formatTimestamp, normalizeTimestamp, timestampMillis } from "../utils/formatters";

// Poll every 5 s — fast enough for a live SOC view, safe for the DB pool
const POLL_INTERVAL = 5000;
const WS_STALE_AFTER_MS = 15000;
const MAX_ROWS = {
  alerts: 120,
  detections: 160,
  flows: 120,
  actions: 100,
  blockedIps: 200,
  pentestFindings: 100,
  pentestScans: 80,
  activityLogs: 200,
};


function serialize(value) {
  return JSON.stringify(value);
}

function entityTimestamp(item) {
  return timestampMillis(item?.updated_at || item?.timestamp || item?.created_at || item?.detected_at || item?.time || item?.acted_at || item?.blocked_at);
}

function mergeCollections(previous = [], incoming = [], keyField = "id", limit = 100) {
  const byKey = new Map();
  previous.forEach((item) => {
    const key = item?.[keyField] ?? serialize(item);
    if (key !== undefined && key !== null) byKey.set(key, item);
  });
  incoming.forEach((item) => {
    const key = item?.[keyField] ?? serialize(item);
    if (key === undefined || key === null) return;
    const current = byKey.get(key);
    if (!current || entityTimestamp(item) >= entityTimestamp(current)) {
      byKey.set(key, current ? { ...current, ...item } : item);
    }
  });
  const merged = Array.from(byKey.values())
    .sort((left, right) => entityTimestamp(right) - entityTimestamp(left))
    .slice(0, limit);
  return serialize(previous) === serialize(merged) ? previous : merged;
}

function mergeAlerts(previous = [], incoming = [], limit = MAX_ROWS.alerts) {
  const byId = new Map();
  previous.forEach((alert) => {
    if (alert?.id !== undefined && alert?.id !== null) byId.set(alert.id, alert);
  });
  incoming.forEach((alert) => {
    if (alert?.id === undefined || alert?.id === null) return;
    const current = byId.get(alert.id);
    if (!current) {
      byId.set(alert.id, alert);
      return;
    }

    const incomingTs = entityTimestamp(alert);
    const currentTs = entityTimestamp(current);
    const clientTs = current._client_updated_at ? new Date(current._client_updated_at).getTime() : 0;
    const incomingIsStale = incomingTs < Math.max(currentTs, clientTs);
    const preserveAcknowledged = current.is_read && !alert.is_read && incomingIsStale;
    const next = incomingIsStale ? { ...alert, ...current } : { ...current, ...alert };

    byId.set(alert.id, preserveAcknowledged
      ? { ...next, is_read: true, status: "acknowledged", statusLabel: "Acknowledged" }
      : next);
  });

  const merged = Array.from(byId.values())
    .sort((left, right) => entityTimestamp(right) - entityTimestamp(left))
    .slice(0, limit);
  return serialize(previous) === serialize(merged) ? previous : merged;
}

function mergeObject(previous, incoming) {
  if (!previous || serialize(previous) !== serialize(incoming)) {
    return incoming;
  }

  return previous;
}

function normalizeActions(actions = []) {
  return actions.map((action, index) => {
    const timestamp = normalizeTimestamp(action.updated_at || action.acted_at || action.created_at || action.timestamp) || new Date(0).toISOString();
    return {
      ...action,
      id: action.id ?? `${action.ip || action.target || "action"}-${action.action_type || action.action}-${timestamp}-${index}`,
      ip: action.ip || action.target || "Unknown",
      action_type: String(action.action_type || action.action || "UNKNOWN").toUpperCase(),
      status: action.status || "success",
      source: action.source || "system",
      created_at: normalizeTimestamp(action.created_at || action.acted_at) || timestamp,
      updated_at: timestamp,
      acted_at: normalizeTimestamp(action.acted_at) || timestamp,
    };
  });
}

function normalizeBlockedIps(rows = []) {
  return rows.map((row) => {
    const timestamp = normalizeTimestamp(row.updated_at || row.blocked_at || row.created_at) || new Date(0).toISOString();
    return {
      ...row,
      id: row.ip || row.target,
      ip: row.ip || row.target || "Unknown",
      status: "blocked",
      severity: row.severity || "HIGH",
      confidence: Number(row.confidence || 0),
      source: row.source || "action_control",
      created_at: normalizeTimestamp(row.created_at || row.blocked_at) || timestamp,
      updated_at: timestamp,
      blocked_at: normalizeTimestamp(row.blocked_at) || timestamp,
    };
  });
}

function normalizePentestScans(scans = []) {
  return scans.map((scan) => {
    const timestamp = normalizeTimestamp(scan.updated_at || scan.completed_at || scan.created_at) || new Date(0).toISOString();
    return {
      ...scan,
      id: scan.scan_id,
      status: scan.status || "queued",
      severity: scan.results?.report?.risk_level || "info",
      confidence: Number(scan.results?.report?.confidence || 0),
      source: "pentest",
      created_at: normalizeTimestamp(scan.created_at) || timestamp,
      updated_at: timestamp,
      current_stage: scan.current_stage || scan.results?.current_stage || "queued",
      progress: Number(scan.progress ?? scan.results?.progress ?? 0),
    };
  });
}

function optimisticActionRow(action, ip, reason) {
  const timestamp = new Date().toISOString();
  return normalizeActions([{
    id: `optimistic-${ip}-${action}-${Date.now()}`,
    ip,
    action_type: action,
    reason,
    source: "manual",
    confidence: 1,
    _optimistic: true,
    status: "pending",
    acted_at: timestamp,
    updated_at: timestamp,
  }])[0];
}

function optimisticBlockedRow(ip, reason) {
  const timestamp = new Date().toISOString();
  return normalizeBlockedIps([{
    ip,
    reason,
    source: "manual",
    confidence: 1,
    _optimistic: true,
    blocked_at: timestamp,
    updated_at: timestamp,
  }])[0];
}

export function useSocData() {
  const [alerts, setAlerts] = useState([]);
  const [detections, setDetections] = useState([]);
  const [flows, setFlows] = useState([]);
  const [actions, setActions] = useState([]);
  const [blockedIps, setBlockedIps] = useState([]);
  const [health, setHealth] = useState({ status: "degraded", model_mode: "unknown", db_status: "unknown" });
  const [pentestFindings, setPentestFindings] = useState([]);
  const [pentestScans, setPentestScans] = useState([]);
  const [activityLogs, setActivityLogs] = useState([]);
  const [apiStatus, setApiStatus] = useState({
    alerts: "fallback",
    detections: "fallback",
    flows: "fallback",
    actions: "fallback",
    blockedIps: "fallback",
    pentestFindings: "fallback",
    pentestScans: "fallback",
    activityLogs: "fallback",
    health: "fallback",
    performance: "fallback",
    networkVisibility: "fallback",
  });
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState("");
  const [autoResponseEnabled, setAutoResponseEnabled] = useState(false);
  const [latestActionToast, setLatestActionToast] = useState(null);
  const [wsStatus, setWsStatus] = useState("polling");
  const [wsLatency, setWsLatency] = useState(0);
  const [performanceMetrics, setPerformanceMetrics] = useState(null);
  const [performanceSamples, setPerformanceSamples] = useState([]);
  const [bandwidthProfile, setBandwidthProfileState] = useState(getBandwidthProfile());
  const [networkVisibility, setNetworkVisibility] = useState(null);
  const firstLoadRef = useRef(true);
  const loadDataRef = useRef(null);
  const lastSequenceRef = useRef(0);
  const wsConnectedRef = useRef(false);
  const lastWsMessageAtRef = useRef(0);
  const performanceMetricsRef = useRef(null);

  const applyPerformanceSample = (sample) => {
    if (!sample) return;
    const merged = { ...(performanceMetricsRef.current || {}), ...sample };
    performanceMetricsRef.current = merged;
    setPerformanceMetrics(merged);
    setPerformanceSamples((current) => {
      const next = [
        ...current,
        {
          time: new Date().toLocaleTimeString(),
          api: Number(merged.current_latency || merged.avg_response_time || merged.client_api_time || 0),
          ai: Number(merged.ai_inference_time || merged.avg_ai_inference_time || 0),
          db: Number(merged.database_query_time || merged.avg_database_query_time || 0),
          ws: Number(merged.websocket_ping || wsLatency || 0),
          render: Number(merged.dashboard_render_delay || 0),
        },
      ];
      return next.slice(-40);
    });
  };

  const reportFrontendMetric = (type, valueMs, extra = {}) => {
    const payload = JSON.stringify({
      type,
      value_ms: Number(valueMs || 0),
      bandwidth_profile: bandwidthProfile,
      ...extra,
    });
    try {
      if (navigator.sendBeacon) {
        const blob = new Blob([payload], { type: "application/json" });
        navigator.sendBeacon(`${API_BASE_URL}/performance/frontend`, blob);
        return;
      }
    } catch {
      // fall through to fetch
    }
    fetch(`${API_BASE_URL}/performance/frontend`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: payload,
      keepalive: true,
    }).catch(() => {});
  };

  const applySnapshot = (snapshot) => {
    const data = snapshot?.data || {};
    if (snapshot?.sequence && snapshot.sequence <= lastSequenceRef.current) {
      return;
    }
    lastSequenceRef.current = snapshot?.sequence || lastSequenceRef.current;
    lastWsMessageAtRef.current = Date.now();
    const receivedAt = performance.now();

    const normalizedDetections = normalizeDetections(data.detections || []);
    if (Array.isArray(data.alerts)) {
      setAlerts((current) => mergeAlerts(current, normalizeAlerts(data.alerts)));
    }
    if (Array.isArray(data.detections)) {
      setDetections((current) => mergeCollections(current, normalizedDetections, "id", MAX_ROWS.detections));
    }
    if (Array.isArray(data.flows)) {
      setFlows((current) => mergeCollections(current, normalizeFlows(data.flows, normalizedDetections), "id", MAX_ROWS.flows));
    }
    if (Array.isArray(data.actions)) {
      setActions((current) => mergeCollections(current, normalizeActions(data.actions), "id", MAX_ROWS.actions));
    }
    if (Array.isArray(data.blocked_ips)) {
      const normalizedBlockedIps = normalizeBlockedIps(data.blocked_ips);
      setBlockedIps((current) => (serialize(current) === serialize(normalizedBlockedIps) ? current : normalizedBlockedIps));
    }
    if (Array.isArray(data.pentest_findings)) {
      setPentestFindings((current) => mergeCollections(current, normalizePentestFindings(data.pentest_findings), "finding_id", MAX_ROWS.pentestFindings));
    }
    if (Array.isArray(data.pentest_scans)) {
      setPentestScans((current) => mergeCollections(current, normalizePentestScans(data.pentest_scans), "scan_id", MAX_ROWS.pentestScans));
    }
    if (Array.isArray(data.activity_logs)) {
      setActivityLogs((current) => mergeCollections(current, normalizeActivityLogs(data.activity_logs), "id", MAX_ROWS.activityLogs));
    }
    if (data.performance) applyPerformanceSample(data.performance);
    setLastUpdated(new Date().toISOString());
    if (firstLoadRef.current) {
      firstLoadRef.current = false;
      setLoading(false);
    }

    window.requestAnimationFrame(() => {
      const renderDelay = performance.now() - receivedAt;
      reportFrontendMetric("dashboard_render_delay", renderDelay);
      setPerformanceSamples((current) => {
        const last = current[current.length - 1];
        if (!last) return current;
        return [...current.slice(0, -1), { ...last, render: Number(renderDelay.toFixed(1)) }];
      });
    });
  };

  useEffect(() => {
    let isMounted = true;
    let requestVersion = 0;

    const loadData = async (force = false) => {
      const requestStartedAt = Date.now();
      const wsFresh = wsConnectedRef.current && Date.now() - lastWsMessageAtRef.current < WS_STALE_AFTER_MS;
      if (!force && wsFresh && !firstLoadRef.current) {
        return;
      }
      const currentRequest = ++requestVersion;
      if (isMounted && firstLoadRef.current) {
        setLoading(true);
      }

      const nextStatus = {
        alerts: "live",
        detections: "live",
        flows: "live",
        actions: "live",
        blockedIps: "live",
        pentestFindings: "live",
        pentestScans: "live",
        activityLogs: "live",
        health: "live",
        performance: "live",
        networkVisibility: "live",
      };

      const results = await Promise.allSettled([
        socApi.getAlerts(12),
        socApi.getDetections(50, true),   // include_contained=true for host history
        socApi.getFlows(20),
        socApi.getActions(20),
        socApi.getBlockedIps(),
        socApi.getPentestFindings(20),
        socApi.getPentestScans(20),
        socApi.getHealth(),
        socApi.getPerformanceMetrics(160),
        socApi.getActivityLogs({ limit: MAX_ROWS.activityLogs }),
        socApi.getNetworkVisibility(),
      ]);

      if (!isMounted || currentRequest !== requestVersion) {
        return;
      }
      const wsRecoveredDuringPoll =
        !force &&
        wsConnectedRef.current &&
        lastWsMessageAtRef.current > requestStartedAt &&
        Date.now() - lastWsMessageAtRef.current < WS_STALE_AFTER_MS;
      if (wsRecoveredDuringPoll && !firstLoadRef.current) {
        return;
      }

      const alertsData = results[0].status === "fulfilled" ? results[0].value : [];
      const detectionsData = results[1].status === "fulfilled" ? results[1].value : [];
      const flowsData = results[2].status === "fulfilled" ? results[2].value : [];
      const actionsData = normalizeActions(results[3].status === "fulfilled" ? results[3].value : []);
      const blockedIpsData = normalizeBlockedIps(results[4].status === "fulfilled" ? results[4].value : []);
      const pentestFindingsData = results[5].status === "fulfilled" ? results[5].value : [];
      const pentestScansData = results[6].status === "fulfilled" ? results[6].value : [];
      const healthData =
        results[7].status === "fulfilled"
          ? results[7].value
          : { status: "degraded", model_mode: "fallback", db_status: "unavailable" };
      const performanceData = results[8].status === "fulfilled" ? results[8].value : null;
      const activityLogsData = results[9].status === "fulfilled" ? results[9].value : [];
      const networkVisibilityData = results[10].status === "fulfilled" ? results[10].value : null;

      results.forEach((result, index) => {
        if (result.status === "fulfilled") {
          return;
        }

        const keys = ["alerts", "detections", "flows", "actions", "blockedIps", "pentestFindings", "pentestScans", "health", "performance", "activityLogs", "networkVisibility"];
        nextStatus[keys[index]] = "fallback";
      });

      const normalizedDetections = normalizeDetections(detectionsData);
      const normalizedAlerts = normalizeAlerts(alertsData);
      const normalizedPentestFindings = normalizePentestFindings(pentestFindingsData);
      const normalizedFlows = normalizeFlows(flowsData, normalizedDetections);
      const normalizedPentestScans = normalizePentestScans(pentestScansData);
      const normalizedActivityLogs = normalizeActivityLogs(activityLogsData);

      setAlerts((current) => {
        const merged = mergeAlerts(current, normalizedAlerts);
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setDetections((current) => {
        const merged = mergeCollections(current, normalizedDetections, "id", MAX_ROWS.detections);
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setFlows((current) => {
        const merged = mergeCollections(current, normalizedFlows, "id", MAX_ROWS.flows);
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setActions((current) => {
        const merged = mergeCollections(current, actionsData, "id", MAX_ROWS.actions);
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setBlockedIps((current) => {
        const merged = mergeCollections(current, blockedIpsData, "ip", MAX_ROWS.blockedIps);
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setPentestFindings((current) => {
        const merged = mergeCollections(current, normalizedPentestFindings, "finding_id", MAX_ROWS.pentestFindings);
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setPentestScans((current) => {
        const merged = mergeCollections(current, normalizedPentestScans, "scan_id", MAX_ROWS.pentestScans);
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setActivityLogs((current) => {
        const merged = mergeCollections(current, normalizedActivityLogs, "id", MAX_ROWS.activityLogs);
        return serialize(current) === serialize(merged) ? current : merged;
      });
      setHealth((current) => mergeObject(current, healthData));
      setNetworkVisibility((current) => mergeObject(current, networkVisibilityData || healthData?.network_visibility || null));
      setAutoResponseEnabled(Boolean(healthData.auto_response_enabled));
      applyPerformanceSample(performanceData);
      setApiStatus((current) => mergeObject(current, nextStatus));
      setLastUpdated(new Date().toISOString());
      if (firstLoadRef.current) {
        firstLoadRef.current = false;
        setLoading(false);
      }
    };

    // Store loadData in ref so WebSocket can call it
    loadDataRef.current = loadData;

    loadData(true);
    const intervalId = window.setInterval(() => loadData(false), POLL_INTERVAL);
    const staleCheckId = window.setInterval(() => {
      const stale = wsConnectedRef.current && Date.now() - lastWsMessageAtRef.current > WS_STALE_AFTER_MS;
      if (!stale) return;
      wsConnectedRef.current = false;
      setWsStatus("polling");
      loadData(true);
    }, 3000);

    return () => {
      isMounted = false;
      window.clearInterval(intervalId);
      window.clearInterval(staleCheckId);
    };
  }, []);

  useEffect(() => {
    if (!latestActionToast) return undefined;
    const timeoutId = window.setTimeout(() => setLatestActionToast(null), 3200);
    return () => window.clearTimeout(timeoutId);
  }, [latestActionToast]);
  useEffect(() => {
      const handler = (event) => {
      const detail = event.detail || {};
      reportFrontendMetric("client_api_time", detail.responseTimeMs, {
        path: detail.path,
        status: detail.status,
        simulated_delay_ms: detail.simulatedDelayMs,
      });
      const mergedMetrics = {
        ...(performanceMetricsRef.current || {}),
        current_latency: Number(detail.responseTimeMs || 0),
        client_api_time: Number(detail.responseTimeMs || 0),
        backend_response_time: Number(detail.backendTimeMs || 0),
      };
      performanceMetricsRef.current = mergedMetrics;
      setPerformanceMetrics(mergedMetrics);
      setPerformanceSamples((current) => {
        const metrics = performanceMetricsRef.current || {};
        const next = [
          ...current,
          {
            time: new Date().toLocaleTimeString(),
            api: Number(detail.responseTimeMs || 0),
            ai: Number(metrics.ai_inference_time || metrics.avg_ai_inference_time || 0),
            db: Number(metrics.database_query_time || metrics.avg_database_query_time || 0),
            ws: Number(wsLatency || 0),
            render: Number(metrics.dashboard_render_delay || 0),
          },
        ];
        return next.slice(-40);
      });
    };
    window.addEventListener("performance:api", handler);
    return () => window.removeEventListener("performance:api", handler);
  }, [wsLatency, bandwidthProfile]);

  // WebSocket: instant push + snapshot sync from dashboard_api.py.
  useEffect(() => {
    const WS_URL = socApi.getWebSocketUrl(WS_BASE_URL);
    if (!WS_URL) {
      setWsStatus("polling");
      return;
    }

    let ws;
    let reconnectTimer;
    let pingTimer;
    let reconnectDelay = 3000;
    let stopped = false;

    const connect = () => {
      if (stopped) return;
      setWsStatus("connecting");
      try {
        ws = new WebSocket(WS_URL);
      } catch {
        reconnectTimer = setTimeout(connect, reconnectDelay);
        return;
      }

      ws.onopen = () => {
        reconnectDelay = 3000;
        wsConnectedRef.current = true;
        lastWsMessageAtRef.current = Date.now();
        setWsStatus("connected");
        try { ws.send(JSON.stringify({ type: "subscribe" })); } catch { /* ignore */ }
        pingTimer = window.setInterval(() => {
          try {
            ws.send(JSON.stringify({ type: "ping", client_ts: Date.now() }));
          } catch {
            // onclose handles reconnect
          }
        }, 5000);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          lastWsMessageAtRef.current = Date.now();
          if (msg.type === "pong" && msg.client_ts) {
            const latency = Math.max(Date.now() - Number(msg.client_ts), 0);
            setWsLatency(latency);
            applyPerformanceSample({ websocket_ping: latency });
            reportFrontendMetric("websocket_latency", latency);
            return;
          }
          if (msg.type === "snapshot") {
            applySnapshot(msg);
            return;
          }
          if (msg.type === "metrics") {
            applyPerformanceSample(msg.data);
            return;
          }
          if (msg.type === "alert" || msg.type === "action" || msg.type === "decision" || msg.type === "threat" || msg.type === "pentest_scan" || msg.type === "activity_log") {
            if (msg.type === "alert") {
              setAlerts((current) => mergeAlerts(current, normalizeAlerts([msg.data])));
            }
            if (msg.type === "threat" || msg.type === "decision") {
              setDetections((current) => mergeCollections(current, normalizeDetections([msg.data]), "id", MAX_ROWS.detections));
            }
            if (msg.type === "pentest_scan") {
              setPentestScans((current) => mergeCollections(current, normalizePentestScans([msg.data]), "scan_id", MAX_ROWS.pentestScans));
            }
            if (msg.type === "activity_log") {
              setActivityLogs((current) => mergeCollections(current, normalizeActivityLogs([msg.data]), "id", MAX_ROWS.activityLogs));
            }
            if (msg.type === "action") {
              const normalizedAction = normalizeActions([msg.data])[0];
              setActions((current) => mergeCollections(current, [normalizedAction], "id", MAX_ROWS.actions));
              if (normalizedAction.action_type === "BLOCK") {
                setBlockedIps((current) => mergeCollections(current, [optimisticBlockedRow(normalizedAction.ip, normalizedAction.reason || "Realtime block action")], "ip", MAX_ROWS.blockedIps));
              }
              if (["WHITELIST", "UNBLOCK", "UNISOLATE"].includes(normalizedAction.action_type)) {
                setBlockedIps((current) => current.filter((item) => item.ip !== normalizedAction.ip));
              }
              setLatestActionToast({
                message: `${normalizedAction.source === "auto" ? "Auto-response" : "Manual action"}: ${normalizedAction.action_type} on ${normalizedAction.ip}`,
                id: `${normalizedAction.ip}-${normalizedAction.acted_at}`,
              });
            }
            setLastUpdated(new Date().toISOString());
          }
        } catch {
          // Ignore malformed messages
        }
      };

      ws.onclose = (event) => {
        if (stopped) return;
        wsConnectedRef.current = false;
        window.clearInterval(pingTimer);
        if (event?.code === 1008) {
          setWsStatus("unauthorized");
          loadDataRef.current?.(true);
          return;
        }
        setWsStatus("reconnecting");
        reconnectTimer = setTimeout(connect, reconnectDelay);
        reconnectDelay = Math.min(reconnectDelay * 1.6, 30000);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connect();

    return () => {
      stopped = true;
      wsConnectedRef.current = false;
      clearTimeout(reconnectTimer);
      window.clearInterval(pingTimer);
      if (ws) {
        ws.close();
      }
    };
  }, []);

  const markAlertAsRead = async (id) => {
    const acknowledgedAt = new Date().toISOString();
    setAlerts((current) =>
      current.map((alert) =>
        alert.id === id
          ? {
              ...alert,
              is_read: true,
              status: "acknowledged",
              statusLabel: "Acknowledged",
              updated_at: acknowledgedAt,
              _client_updated_at: acknowledgedAt,
            }
          : alert,
      ),
    );

    try {
      await socApi.markAlertRead(id);
    } catch {
      // Keep optimistic state to avoid a disruptive UX when the endpoint is unavailable.
    }
  };

  const markAllAlertsAsRead = async () => {
    const response = await socApi.markAllAlertsRead();
    if (!response?.success) {
      throw new Error(response?.error || "Unable to mark alerts as read");
    }

    const acknowledgedAt = response.timestamp || new Date().toISOString();
    setAlerts((current) =>
      current.map((alert) =>
        !alert.is_read
          ? {
              ...alert,
              is_read: true,
              status: "acknowledged",
              statusLabel: "Acknowledged",
              updated_at: acknowledgedAt,
              _client_updated_at: acknowledgedAt,
            }
          : alert,
      ),
    );
    setLastUpdated(new Date().toISOString());
    setLatestActionToast({
      type: "success",
      message: `All alerts marked as read (${response.total_updated ?? response.updated ?? 0})`,
      id: `alerts-read-all-${Date.now()}`,
    });
    await loadDataRef.current?.(true);
    return response;
  };

  const triggerHostAction = async (action, ip) => {
    const normalizedAction = String(action || "").toUpperCase();
    const reason = `Manual ${normalizedAction.toLowerCase()} triggered by SOC analyst`;
    const methodMap = {
      BLOCK:     (target, r) => socApi.blockHost(target, r),
      ISOLATE:   (target, r) => socApi.isolateHost(target, r),
      WHITELIST: (target, r) => socApi.whitelistHost(target, r),
      UNBLOCK:   (target, r) => socApi.unblockHost(target, r),
      UNISOLATE: (target, r) => socApi.unisolateHost(target, r),
    };
    const handler = methodMap[normalizedAction];
    if (!handler) {
      throw new Error(`Unsupported action: ${action}`);
    }
    setActions((current) => mergeCollections(current, [optimisticActionRow(normalizedAction, ip, reason)], "id", MAX_ROWS.actions));
    if (normalizedAction === "BLOCK") {
      setBlockedIps((current) => mergeCollections(current, [optimisticBlockedRow(ip, reason)], "ip", MAX_ROWS.blockedIps));
    }
    if (["WHITELIST", "UNBLOCK", "UNISOLATE"].includes(normalizedAction)) {
      setBlockedIps((current) => current.filter((item) => item.ip !== ip));
    }
    setLastUpdated(new Date().toISOString());
    setLatestActionToast({
      type: "info",
      message: `${normalizedAction}: ${ip} in progress`,
      id: `${ip}-${Date.now()}`,
    });

    try {
      const response = await handler(ip, reason);
    if (response?.status === "failed") {
      throw new Error(response.message || "Action execution failed");
    }
      setActions((current) =>
        current.filter((item) => !(String(item.id || "").startsWith("optimistic-") && item.ip === ip && item.action_type === normalizedAction)),
      );
      setBlockedIps((current) => current.filter((item) => !(item.ip === ip && item._optimistic)));
    // Refresh all data immediately so counters + timeline update
      await loadDataRef.current?.(true);
    setLatestActionToast({
      type: "success",
      message: `${action}: ${ip} — ${response?.message ?? "action executed"}`,
      id: `${ip}-${Date.now()}`,
    });
      return response;
    } catch (error) {
      setActions((current) =>
        current.filter((item) => !(String(item.id || "").startsWith("optimistic-") && item.ip === ip && item.action_type === normalizedAction)),
      );
      setBlockedIps((current) => current.filter((item) => !(item.ip === ip && item._optimistic)));
      await loadDataRef.current?.(true);
      setLatestActionToast({
        type: "error",
        message: `${normalizedAction}: ${ip} failed - ${error?.message || "request failed"}`,
        id: `${ip}-${Date.now()}`,
      });
      throw error;
    }
  };

  const toggleAutoResponse = async (enabled) => {
    const response = await socApi.setAutoResponseEnabled(enabled);
    setAutoResponseEnabled(Boolean(response.enabled));
    await loadDataRef.current?.(true);
    return response;
  };

  const setBandwidthProfile = (profile) => {
    const next = persistBandwidthProfile(profile);
    setBandwidthProfileState(next);
    loadDataRef.current?.(true);
    return next;
  };

  const threatState = useMemo(() => deriveThreatState(detections, alerts, pentestFindings), [alerts, detections, pentestFindings]);
  const alertStats = useMemo(() => deriveAlertStats(alerts), [alerts]);
  const distribution = useMemo(() => deriveAttackDistribution(detections), [detections]);
  const hosts = useMemo(() => deriveHosts(flows, detections, blockedIps, actions), [actions, blockedIps, detections, flows]);
  const incidents = useMemo(() => deriveIncidents(alerts, detections, pentestFindings), [alerts, detections, pentestFindings]);

  const sidebarCounts = useMemo(
    () => {
      // Build a set of IPs currently in blockedIps — these are contained
      const containedIpSet = new Set(blockedIps.map((b) => b.ip));
      const activeThreats = detections.filter(
        (item) => item.result !== "NORMAL" && !containedIpSet.has(item.src_ip)
      );
      return {
        alerts: alertStats.open,
        suspiciousQueue: activeThreats.length,
      };
    },
    [alertStats.open, detections, blockedIps],
  );

  return {
    alerts,
    detections,
    flows,
    actions,
    blockedIps,
    pentestFindings,
    pentestScans,
    activityLogs,
    health,
    hosts,
    incidents,
    threatState,
    distribution,
    loading,
    apiStatus,
    sidebarCounts,
    alertStats,
    newAlertsCount: alertStats.new,
    markAlertAsRead,
    markAllAlertsAsRead,
    triggerHostAction,
    toggleAutoResponse,
    autoResponseEnabled,
    latestActionToast,
    wsStatus,
    wsLatency,
    performanceMetrics,
    performanceSamples,
    bandwidthProfile,
    setBandwidthProfile,
    networkVisibility,
    pentestMode: health.pentest_mode || "lab",
    lastUpdatedLabel: formatTimestamp(lastUpdated),
  };
}
