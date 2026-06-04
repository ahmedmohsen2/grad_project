// ─────────────────────────────────────────────────────────────────────────────
// socApi.js  —  HTTP client for the IDS/IPS Flask backend
// Base URL read from .env (VITE_API_BASE_URL) — defaults to Flask port 5000.
// ─────────────────────────────────────────────────────────────────────────────
import { API_BASE_URL } from "../api/baseUrl";
import { getBandwidthProfile, simulatedClientDelay, sleep } from "../utils/bandwidth";

// Build a WebSocket URL from the same base
export function createWebSocketUrl(path = "/ws") {
  const baseUrl = new URL(API_BASE_URL);
  const protocol = baseUrl.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${baseUrl.host}${path}`;
}

// ─── auth token helper ───────────────────────────────────────────────────────
// MUST match the key used by api/api.js and useAuth (TOKEN_KEY = "soc_auth_token")
const TOKEN_KEY = "soc_auth_token";

function getAuthToken() {
  try {
    return localStorage.getItem(TOKEN_KEY) || "";
  } catch {
    return "";
  }
}

export function withWebSocketAuth(url) {
  const token = getAuthToken();
  if (!token) return url;
  const next = new URL(url);
  next.searchParams.set("token", token);
  return next.toString();
}

// ─── low-level fetch wrapper ─────────────────────────────────────────────────
async function request(path, options = {}) {
  const token = getAuthToken();
  const authHeaders = token ? { Authorization: `Bearer ${token}` } : {};
  const profile = getBandwidthProfile();

  const startedAt = performance.now();
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      "X-Bandwidth-Profile": profile,
      ...authHeaders,
      ...(options.headers || {}),
    },
    ...options,
  });
  const bodySize = Number(response.headers.get("content-length") || 0);
  const simulatedDelay = simulatedClientDelay(profile, bodySize);
  if (simulatedDelay > 0) {
    await sleep(simulatedDelay);
  }
  window.dispatchEvent(new CustomEvent("performance:api", {
    detail: {
      path,
      profile,
      responseTimeMs: performance.now() - startedAt,
      backendTimeMs: Number(response.headers.get("X-Response-Time-Ms") || 0),
      simulatedDelayMs: simulatedDelay,
      status: response.status,
    },
  }));

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    if (response.status === 401) {
      try { localStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ }
      window.dispatchEvent(new CustomEvent("auth:expired"));
    }
    if (options.allowErrorBody) {
      return errorBody;
    }
    const serverMessage = errorBody.message || errorBody.error;
    const permissionMessage = response.status === 403
      ? serverMessage || "Your SOC role is not permitted to execute this containment action."
      : serverMessage;
    const error = new Error(
      `[socApi] ${options.method || "GET"} ${path} → HTTP ${response.status}`
    );
    error.status = response.status;
    if (permissionMessage) {
      error.message = permissionMessage;
    }
    error.body = errorBody;
    throw error;
  }

  return response.json();
}

// ─── public API ──────────────────────────────────────────────────────────────
export const socApi = {
  /** Last N alerts ordered newest-first */
  getAlerts(limit = 50) {
    return request(`/alerts?limit=${limit}`);
  },

  /** Recent ML detections ordered by detected_at DESC.
   *  includeContained=true keeps blocked IPs in results (for host history view).
   *  Default false → Suspicious Queue only shows active threats. */
  getDetections(limit = 20, includeContained = false) {
    const params = new URLSearchParams({ limit });
    if (includeContained) params.set("include_contained", "true");
    return request(`/detections?${params}`);
  },

  /** Recent network flows ordered by captured_at DESC */
  getFlows(limit = 20) {
    return request(`/flows?limit=${limit}`);
  },

  /** Recent IPS actions (BLOCK / MONITOR / ISOLATE / UNBLOCK) */
  getActions(limit = 20) {
    return request(`/actions?limit=${limit}`);
  },

  /** All currently blocked IPs */
  getBlockedIps() {
    return request("/blocked-ips");
  },

  /** API + DB health check */
  getHealth() {
    return request("/health", { allowErrorBody: true });
  },

  getStats() {
    return request("/stats");
  },

  getPerformanceMetrics(limit = 160) {
    return request(`/performance/metrics?limit=${limit}`);
  },

  getBandwidthProfiles() {
    return request("/bandwidth/profiles");
  },

  getNetworkVisibility() {
    return request("/network/visibility");
  },

  getIpsStatus() {
    return request("/ips/status");
  },

  runIpsSelfTest(ip = "203.0.113.250") {
    return request("/ips/self-test", {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
  },

  startIpsValidationTest(payload = {}) {
    return request("/ips/validation-test", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  getIpsValidationStatus(limit = 10) {
    return request(`/ips/validation-test/status?limit=${limit}`);
  },

  clearIpsValidationTests() {
    return request("/ips/validation-test", { method: "DELETE" });
  },

  getActivityLogs(params = {}) {
    const search = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && String(value).trim() !== "") {
        search.set(key, value);
      }
    });
    const query = search.toString();
    return request(`/activity/logs${query ? `?${query}` : ""}`);
  },

  getPentestFindings(limit = 50, target = null, includeResolved = true) {
    const params = new URLSearchParams({ limit });
    if (target) params.set("target", target);
    params.set("include_resolved", includeResolved ? "true" : "false");
    return request(`/pentest/findings?${params.toString()}`);
  },

  getPentestScans(limit = 20) {
    return request(`/pentest/scans?limit=${limit}`);
  },

  getAutoResponseStatus() {
    return request("/auto-response/status");
  },

  setAutoResponseEnabled(enabled) {
    return request("/auto-response/status", {
      method: "POST",
      body: JSON.stringify({ enabled }),
    });
  },

  getActionState(target) {
    return request(`/actions/state/${encodeURIComponent(target)}`);
  },

  blockHost(target, reason = "Manual block") {
    return request("/actions/block", {
      method: "POST",
      body: JSON.stringify({ target, reason }),
    });
  },

  isolateHost(target, reason = "Manual isolate") {
    return request("/actions/isolate", {
      method: "POST",
      body: JSON.stringify({ target, reason }),
    });
  },

  whitelistHost(target, reason = "Manual whitelist") {
    return request("/actions/whitelist", {
      method: "POST",
      body: JSON.stringify({ target, reason }),
    });
  },

  /** Mark one alert as read (Flask route: POST /alerts/read/<id>) */
  markAlertRead(id) {
    return request(`/alerts/read/${id}`, { method: "POST" });
  },

  /** Mark all unread/open alerts as read */
  markAllAlertsRead() {
    return request("/alerts/read-all", { method: "POST" });
  },

  /** OS-level: Unblock IP */
  unblockHost(target, reason = "Manual unblock") {
    return request("/actions/unblock", {
      method: "POST",
      body: JSON.stringify({ target, reason }),
    });
  },

  /** OS-level: Remove isolation */
  unisolateHost(target, reason = "Manual unisolate") {
    return request("/actions/unisolate", {
      method: "POST",
      body: JSON.stringify({ target, reason }),
    });
  },

  /** OS-level: Block IP via legacy route */
  blockIp(ip) {
    return request("/block", { method: "POST", body: JSON.stringify({ ip }) });
  },

  /** OS-level: Unblock IP (legacy) */
  unblockIp(ip) {
    return request("/unblock", { method: "POST", body: JSON.stringify({ ip }) });
  },

  /** OS-level: Isolate host (legacy) */
  isolateIp(ip) {
    return request("/isolate", { method: "POST", body: JSON.stringify({ ip }) });
  },

  /** OS-level: Remove isolation (legacy) */
  unisolateIp(ip) {
    return request("/unisolate", { method: "POST", body: JSON.stringify({ ip }) });
  },

  /** Direct access to the fetch wrapper for advanced use */
  request,

  // ── Auth helpers ────────────────────────────────────────────────────────────

  /** Login and store the returned token */
  async login(identifier, password) {
    const data = await request("/auth/login", {
      method: "POST",
      body: JSON.stringify({ identifier, password }),
    });
    if (data.token) {
      try { localStorage.setItem(TOKEN_KEY, data.token); } catch { /* ignore */ }
    }
    return data;
  },

  /** Save JWT token returned from /auth/login */
  saveToken(token) {
    try { localStorage.setItem(TOKEN_KEY, token); } catch { /* ignore */ }
  },

  /** Clear stored token on logout */
  clearToken() {
    try { localStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ }
  },

  /** Check if a token is currently stored */
  hasToken() {
    return Boolean(getAuthToken());
  },

  getWebSocketUrl(url) {
    return withWebSocketAuth(url);
  },
};
