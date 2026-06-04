const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1"]);

function resolveDynamicBaseUrl() {
  const hostname = window.location.hostname;
  const safeHostname = hostname ? hostname : "127.0.0.1";
  const apiHost = safeHostname === "localhost" ? "localhost" : safeHostname;
  return `http://${apiHost}:5000`;
}

function shouldUseConfiguredBaseUrl(configuredBaseUrl) {
  if (!configuredBaseUrl) return false;

  try {
    const configuredUrl = new URL(configuredBaseUrl);
    const currentHost = window.location.hostname;
    const configuredIsLoopback = LOOPBACK_HOSTS.has(configuredUrl.hostname);
    const currentIsLoopback = LOOPBACK_HOSTS.has(currentHost);

    if (configuredIsLoopback && !currentIsLoopback) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

const configuredBaseUrl = (import.meta.env.VITE_API_BASE_URL || "").trim();

export const API_BASE_URL = shouldUseConfiguredBaseUrl(configuredBaseUrl)
  ? configuredBaseUrl
  : resolveDynamicBaseUrl();

function resolveDynamicWebSocketUrl() {
  const hostname = window.location.hostname || "127.0.0.1";
  const wsHost = hostname === "localhost" ? "localhost" : hostname;
  return `ws://${wsHost}:8001/ws/live`;
}

const configuredWsUrl = (import.meta.env.VITE_WS_URL || "").trim();

export const WS_BASE_URL = configuredWsUrl || resolveDynamicWebSocketUrl();
