export const BANDWIDTH_PROFILE_KEY = "soc_bandwidth_profile";

export const BANDWIDTH_PROFILES = {
  unlimited: { label: "Unlimited", mbps: 0, baseLatencyMs: 0, jitterMs: 0 },
  "20mbps": { label: "20 Mbps", mbps: 20, baseLatencyMs: 18, jitterMs: 8 },
  "10mbps": { label: "10 Mbps", mbps: 10, baseLatencyMs: 35, jitterMs: 14 },
  "5mbps": { label: "5 Mbps", mbps: 5, baseLatencyMs: 70, jitterMs: 25 },
  "1mbps": { label: "1 Mbps", mbps: 1, baseLatencyMs: 180, jitterMs: 60 },
};

export function getBandwidthProfile() {
  try {
    const value = localStorage.getItem(BANDWIDTH_PROFILE_KEY);
    return value && BANDWIDTH_PROFILES[value] ? value : "unlimited";
  } catch {
    return "unlimited";
  }
}

export function setBandwidthProfile(profile) {
  const next = BANDWIDTH_PROFILES[profile] ? profile : "unlimited";
  try {
    localStorage.setItem(BANDWIDTH_PROFILE_KEY, next);
  } catch {
    // ignore storage failures
  }
  return next;
}

export function simulatedClientDelay(profile, payloadBytes = 0) {
  const cfg = BANDWIDTH_PROFILES[profile] || BANDWIDTH_PROFILES.unlimited;
  if (!cfg.mbps) return 0;
  const transferMs = (Math.max(payloadBytes, 0) * 8 * 1000) / (cfg.mbps * 1_000_000);
  const jitterMs = Math.round(Math.random() * cfg.jitterMs);
  return Math.min(Math.round(cfg.baseLatencyMs + jitterMs + transferMs), 2500);
}

export function sleep(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

