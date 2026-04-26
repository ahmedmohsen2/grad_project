/**
 * api/api.js  —  Clean API Layer for the IDS/IPS SOC Dashboard
 * ──────────────────────────────────────────────────────────────
 * This is the SINGLE point of contact between React components
 * and the Flask backend. All fetch logic lives here.
 *
 * Base URL: VITE_API_BASE_URL env var (default: http://127.0.0.1:5000)
 *
 * Exports:
 *   getAlerts(limit)
 *   getFlows(limit)
 *   getDetections(limit)
 *   getActions(limit)
 *   getBlockedIps()
 *   getHealth()
 *   markAlertRead(id)
 *   authLogin(identifier, password)
 *   authSignup(username, email, password, invite_key)
 *   authMe()
 *   getToken() / setToken() / clearToken()
 *
 * All functions return a Promise<data> and throw on HTTP errors.
 * Callers (hooks) are responsible for try/catch + fallback data.
 */

const BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

// ─────────────────────────────────────────────────────────────────────────────
// Token management  (localStorage)
// ─────────────────────────────────────────────────────────────────────────────

const TOKEN_KEY = "soc_auth_token";
const USER_KEY = "soc_auth_user";

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export function getStoredUser() {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function setStoredUser(user) {
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function isAuthenticated() {
  return !!getToken();
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helper  (auto-attaches Bearer token)
// ─────────────────────────────────────────────────────────────────────────────

async function apiFetch(path, options = {}) {
  const url = `${BASE_URL}${path}`;

  const headers = {
    "Content-Type": "application/json",
    ...(options.headers ?? {}),
  };

  // Auto-attach auth token if present
  const token = getToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    headers,
    ...options,
  });

  // If 401, clear stale token
  if (response.status === 401) {
    clearToken();
    // Dispatch custom event so React can redirect to login
    window.dispatchEvent(new CustomEvent("auth:expired"));
  }

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    const err = new Error(
      errorBody.error ||
        `[API] ${options.method ?? "GET"} ${path} failed — HTTP ${response.status}`
    );
    err.status = response.status;
    err.body = errorBody;
    throw err;
  }

  return response.json();
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth endpoints  (public — no token needed)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * POST /auth/login
 * @param {string} identifier  email or username
 * @param {string} password
 * @returns {Promise<{token, user}>}
 */
export function authLogin(identifier, password) {
  return apiFetch("/auth/login", {
    method: "POST",
    body: JSON.stringify({ identifier, password }),
  });
}

/**
 * POST /auth/signup
 * @param {string} username
 * @param {string} email
 * @param {string} password
 * @param {string} invite_key
 * @returns {Promise<{message, user}>}
 */
export function authSignup(username, email, password, invite_key) {
  return apiFetch("/auth/signup", {
    method: "POST",
    body: JSON.stringify({ username, email, password, invite_key }),
  });
}

/**
 * GET /auth/me — Validate token and return current user
 * @returns {Promise<{user}>}
 */
export function authMe() {
  return apiFetch("/auth/me");
}

// ─────────────────────────────────────────────────────────────────────────────
// Alerts
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch the most recent alerts.
 *
 * Response shape (each row):
 *   { id, ip, type, message, is_read, time }
 *
 * @param {number} limit  Max rows to return (default 50, backend caps at 200)
 * @returns {Promise<Array>}
 */
export function getAlerts(limit = 50) {
  return apiFetch(`/alerts?limit=${limit}`);
}

/**
 * Mark a single alert as read.
 *
 * @param {number} id  Alert primary key
 * @returns {Promise<{ok: boolean}>}
 */
export function markAlertRead(id) {
  return apiFetch(`/alerts/read/${id}`, { method: "POST" });
}

// ─────────────────────────────────────────────────────────────────────────────
// Detections
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch recent ML/rule detections ordered by detected_at DESC.
 *
 * Response shape (each row):
 *   { id, src_ip, result, attack_type, confidence, iso_flag, detected_at }
 *
 * result is one of: "ATTACK" | "SUSPICIOUS" | "NORMAL"
 *
 * @param {number} limit
 * @param {string|null} srcIp  Optional IP filter
 * @returns {Promise<Array>}
 */
export function getDetections(limit = 20, srcIp = null) {
  const params = new URLSearchParams({ limit });
  if (srcIp) params.set("src_ip", srcIp);
  return apiFetch(`/detections?${params}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Flows
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch recent network flows ordered by captured_at DESC.
 *
 * Response shape (each row):
 *   { id, src_ip, dst_ip, packets, bytes, pps, duration_us, captured_at }
 *
 * @param {number} limit
 * @param {string|null} srcIp  Optional IP filter
 * @returns {Promise<Array>}
 */
export function getFlows(limit = 20, srcIp = null) {
  const params = new URLSearchParams({ limit });
  if (srcIp) params.set("src_ip", srcIp);
  return apiFetch(`/flows?${params}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Actions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch recent IPS actions ordered by acted_at DESC.
 *
 * Response shape:
 *   { id, ip, action_type, reason, acted_at }
 *
 * action_type is one of: "BLOCK" | "MONITOR" | "ISOLATE" | "UNBLOCK"
 *
 * @param {number} limit
 * @returns {Promise<Array>}
 */
export function getActions(limit = 20) {
  return apiFetch(`/actions?limit=${limit}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Blocked IPs
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch all currently blocked IPs.
 *
 * Response shape:
 *   { ip, reason, blocked_at }
 *
 * @returns {Promise<Array>}
 */
export function getBlockedIps() {
  return apiFetch("/blocked-ips");
}

// ─────────────────────────────────────────────────────────────────────────────
// Health
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Health check — confirms the API and DB are reachable.
 *
 * Response shape:
 *   { status: "ok"|"degraded", model_mode: string, db_status: "ok"|"unavailable" }
 *
 * @returns {Promise<object>}
 */
export function getHealth() {
  return apiFetch("/health");
}

// ─────────────────────────────────────────────────────────────────────────────
// Status color map  (imported directly by components — no hook needed)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns a Tailwind CSS class string for a given alert/detection result type.
 *
 * @param {string} type  "ATTACK" | "SUSPICIOUS" | "BLOCK" | "MALWARE" | "NORMAL"
 * @returns {string}  Tailwind color class
 */
export function resultColorClass(type) {
  switch (String(type).toUpperCase()) {
    case "ATTACK":     return "text-red-400";
    case "SUSPICIOUS": return "text-yellow-400";
    case "BLOCK":      return "text-emerald-400";
    case "MALWARE":    return "text-orange-400";
    case "NORMAL":     return "text-slate-400";
    default:           return "text-slate-500";
  }
}

/**
 * Returns a Tailwind background badge class for a result type.
 *
 * @param {string} type
 * @returns {string}
 */
export function resultBadgeClass(type) {
  switch (String(type).toUpperCase()) {
    case "ATTACK":     return "bg-red-500/15 text-red-300";
    case "SUSPICIOUS": return "bg-yellow-500/15 text-yellow-300";
    case "BLOCK":      return "bg-emerald-500/15 text-emerald-300";
    case "MALWARE":    return "bg-orange-500/15 text-orange-300";
    case "NORMAL":     return "bg-slate-500/15 text-slate-400";
    default:           return "bg-slate-700/40 text-slate-500";
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Pentest Agent
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Start a new pentest scan.
 *
 * @param {string} target   IP or URL to scan
 * @param {string} scanType "quick" | "full" | "stealth"
 * @returns {Promise<{scan_id, target, status, scan_type, message}>}
 */
export function startPentestScan(target, scanType = "quick") {
  return apiFetch("/pentest/scan", {
    method: "POST",
    body: JSON.stringify({ target, scan_type: scanType }),
  });
}

/**
 * Get full results for a pentest scan.
 *
 * @param {string} scanId
 * @returns {Promise<object>}
 */
export function getPentestResults(scanId) {
  return apiFetch(`/pentest/results/${scanId}`);
}

/**
 * List all pentest scans (summaries).
 *
 * @param {number} limit
 * @returns {Promise<Array>}
 */
export function listPentestScans(limit = 20) {
  return apiFetch(`/pentest/scans?limit=${limit}`);
}

export function getPentestFindings(limit = 50, target = null, includeResolved = true) {
  const params = new URLSearchParams({ limit });
  if (target) params.set("target", target);
  params.set("include_resolved", includeResolved ? "true" : "false");
  return apiFetch(`/pentest/findings?${params.toString()}`);
}

export function getActionState(target) {
  return apiFetch(`/actions/state/${encodeURIComponent(target)}`);
}

export function blockAction(target, reason, findingId = null, confidence = 0) {
  return apiFetch("/actions/block", {
    method: "POST",
    body: JSON.stringify({ target, reason, finding_id: findingId, confidence }),
  });
}

export function isolateAction(target, reason, findingId = null, confidence = 0) {
  return apiFetch("/actions/isolate", {
    method: "POST",
    body: JSON.stringify({ target, reason, finding_id: findingId, confidence }),
  });
}

export function whitelistAction(target, reason, findingId = null, confidence = 0) {
  return apiFetch("/actions/whitelist", {
    method: "POST",
    body: JSON.stringify({ target, reason, finding_id: findingId, confidence }),
  });
}


// ─────────────────────────────────────────────────────────────────────────────
// Severity Helpers  (used by Pentest Console)
// ─────────────────────────────────────────────────────────────────────────────

export function severityBadgeClass(severity) {
  switch (String(severity).toLowerCase()) {
    case "critical": return "bg-red-500/20 text-red-300 ring-1 ring-red-500/30";
    case "high":     return "bg-orange-500/20 text-orange-300 ring-1 ring-orange-500/30";
    case "medium":   return "bg-yellow-500/20 text-yellow-300 ring-1 ring-yellow-500/30";
    case "low":      return "bg-sky-500/20 text-sky-300 ring-1 ring-sky-500/30";
    case "info":     return "bg-slate-500/20 text-slate-300 ring-1 ring-slate-500/30";
    default:         return "bg-slate-700/40 text-slate-500";
  }
}

export function scanStatusBadgeClass(status) {
  switch (String(status).toLowerCase()) {
    case "completed": return "bg-emerald-500/15 text-emerald-300";
    case "running":   return "bg-sky-500/15 text-sky-300";
    case "queued":    return "bg-yellow-500/15 text-yellow-300";
    case "failed":    return "bg-red-500/15 text-red-300";
    default:          return "bg-slate-500/15 text-slate-400";
  }
}
