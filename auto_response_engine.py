from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from config import (
    AUTO_RESPONSE_COOLDOWN_SEC,
    AUTO_RESPONSE_ENABLED,
    AUTO_RESPONSE_HIGH_PPS,
    AUTO_RESPONSE_MAX_ACTIONS_PER_IP,
)


@dataclass
class AutoResponseDecision:
    action: str | None
    reason: str
    confidence: float
    trigger: str = "auto"


class AutoResponseEngine:
    def __init__(self):
        self.enabled = AUTO_RESPONSE_ENABLED
        self.cooldown_sec = AUTO_RESPONSE_COOLDOWN_SEC
        self.max_actions_per_ip = AUTO_RESPONSE_MAX_ACTIONS_PER_IP
        self.high_pps_threshold = AUTO_RESPONSE_HIGH_PPS
        self._lock = threading.Lock()
        self._last_action_at: dict[str, float] = {}
        self._action_windows: dict[str, deque[float]] = defaultdict(deque)
        self._history: dict[str, deque[dict]] = defaultdict(lambda: deque(maxlen=25))

    def set_enabled(self, enabled: bool):
        with self._lock:
            self.enabled = bool(enabled)

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "cooldown_sec": self.cooldown_sec,
                "max_actions_per_ip": self.max_actions_per_ip,
                "high_pps_threshold": self.high_pps_threshold,
            }

    def record_event(self, payload: dict) -> dict:
        ip = str(payload.get("ip") or "").strip()
        if not ip:
            return {"repeated_behavior": False, "event_count": 0}

        now = time.time()
        with self._lock:
            history = self._history[ip]
            history.append(
                {
                    "time": now,
                    "confidence": float(payload.get("confidence") or 0.0),
                    "attack_type": str(payload.get("attack_type") or "").lower(),
                    "pps": float(payload.get("pps") or 0.0),
                }
            )
            recent = [
                event for event in history
                if now - event["time"] <= self.cooldown_sec
            ]
        return {
            "repeated_behavior": len(recent) >= 2,
            "event_count": len(recent),
            "recent_events": recent[-5:],
        }

    def evaluate(self, payload: dict) -> AutoResponseDecision:
        ip = str(payload.get("ip") or "").strip()
        confidence = float(payload.get("confidence") or 0.0)
        attack_type = str(payload.get("attack_type") or "").lower()
        pps = float(payload.get("pps") or 0.0)
        history = payload.get("history") or self.record_event(payload)
        repeated_behavior = bool(history.get("repeated_behavior"))

        if not ip:
            return AutoResponseDecision(None, "Missing IP address", confidence)

        with self._lock:
            self._prune_locked(time.time())
            if not self.enabled:
                return AutoResponseDecision(None, "Auto-response disabled", confidence)

            last_action = self._last_action_at.get(ip, 0.0)
            if time.time() - last_action < self.cooldown_sec:
                return AutoResponseDecision(None, "Cooldown active for this IP", confidence)

            window = self._action_windows[ip]
            while window and time.time() - window[0] > 3600:
                window.popleft()
            if len(window) >= self.max_actions_per_ip:
                return AutoResponseDecision(None, "Max actions reached for this IP in the current window", confidence)

        if not repeated_behavior and confidence < 0.95:
            return AutoResponseDecision(None, "Insufficient repeated behavior for safe automation", confidence)

        if confidence > 0.9 and attack_type in {"brute_force", "ddos", "bruteforce"}:
            return AutoResponseDecision(
                "BLOCK",
                "High confidence brute force or DDoS pattern with repeated behavior",
                confidence,
            )

        if confidence > 0.75 and pps >= self.high_pps_threshold and repeated_behavior:
            return AutoResponseDecision(
                "ISOLATE",
                "Elevated traffic intensity and repeated abnormal behavior detected",
                confidence,
            )

        if confidence < 0.3:
            return AutoResponseDecision(
                "WHITELIST",
                "Low confidence activity observed repeatedly and considered safe",
                confidence,
            )

        return AutoResponseDecision(None, "No safe auto action selected", confidence)


    def mark_action(self, ip: str):
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            self._last_action_at[ip] = now
            self._action_windows[ip].append(now)

    def _prune_locked(self, now: float):
        cutoff = max(self.cooldown_sec * 4, 3600)
        for ip, last_seen in list(self._last_action_at.items()):
            if now - last_seen > cutoff and not self._action_windows.get(ip):
                self._last_action_at.pop(ip, None)
        for ip, window in list(self._action_windows.items()):
            while window and now - window[0] > 3600:
                window.popleft()
            if not window and now - self._last_action_at.get(ip, 0) > cutoff:
                self._action_windows.pop(ip, None)
        for ip, history in list(self._history.items()):
            if not history or now - history[-1]["time"] > cutoff:
                self._history.pop(ip, None)

    def evaluate_finding(self, payload: dict) -> AutoResponseDecision:
        """
        Evaluate a pentest finding and decide whether to auto-respond.
        Payload: { ip, severity, confidence, title }
        """
        ip = str(payload.get("ip") or "").strip()
        severity = str(payload.get("severity") or "low").lower()
        confidence = float(payload.get("confidence") or 0.0)

        if not ip:
            return AutoResponseDecision(None, "Missing IP address", confidence)

        with self._lock:
            self._prune_locked(time.time())
            if not self.enabled:
                return AutoResponseDecision(None, "Auto-response disabled", confidence)

            last_action = self._last_action_at.get(ip, 0.0)
            if time.time() - last_action < self.cooldown_sec:
                return AutoResponseDecision(None, "Cooldown active for this IP", confidence)

            window = self._action_windows[ip]
            while window and time.time() - window[0] > 3600:
                window.popleft()
            if len(window) >= self.max_actions_per_ip:
                return AutoResponseDecision(None, "Max actions reached for this IP", confidence)

        # Decision rules by severity
        if severity == "critical" and confidence >= 0.7:
            return AutoResponseDecision(
                "ISOLATE",
                f"Critical pentest finding with {confidence:.0%} confidence — isolating host",
                confidence,
            )

        if severity == "high" and confidence >= 0.8:
            return AutoResponseDecision(
                "BLOCK",
                f"High severity pentest finding with {confidence:.0%} confidence — blocking host",
                confidence,
            )

        if severity in ("high", "medium") and confidence >= 0.6:
            return AutoResponseDecision(
                "ISOLATE",
                f"{severity.title()} pentest finding ({confidence:.0%} confidence) — isolating for review",
                confidence,
            )

        return AutoResponseDecision(
            None,
            f"Pentest finding severity={severity} confidence={confidence:.0%} — no auto-action threshold met",
            confidence,
        )


auto_response_engine = AutoResponseEngine()
