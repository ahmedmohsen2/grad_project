import threading
import time
from collections import deque
import asyncio
import random
import logging

log = logging.getLogger("state_manager")

# ──────────────────────────────────────────────────────────────
# AUTO DEFENSE — Decision Engine + Cooldown
# ──────────────────────────────────────────────────────────────

_last_auto_action: dict[str, float] = {}
_auto_action_lock = threading.Lock()

AUTO_COOLDOWN_SEC = 30  # Don't re-act on the same IP within 30s


def decide_action(confidence: float, attack_type: str) -> str | None:
    """
    Decide what auto-response to take based on confidence level.
    Returns "ISOLATE", "BLOCK", or None (no action).
    """
    if confidence >= 0.9:
        return "ISOLATE"
    elif confidence >= 0.7:
        return "BLOCK"
    return None


def should_act(ip: str, cooldown: float = AUTO_COOLDOWN_SEC) -> bool:
    """
    Thread-safe anti-spam: prevents repeated actions on the same IP
    within the cooldown window.
    """
    now = time.time()
    with _auto_action_lock:
        if ip in _last_auto_action and now - _last_auto_action[ip] < cooldown:
            return False
        _last_auto_action[ip] = now
        return True


# ──────────────────────────────────────────────────────────────
# STATE MANAGER — Singleton with WebSocket broadcasting
# ──────────────────────────────────────────────────────────────

class StateManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(StateManager, cls).__new__(cls)
                cls._instance.__initialized = False
            return cls._instance

    def __init__(self):
        if self.__initialized: return
        self.__initialized = True
        self.lock = threading.Lock()
        
        self.metrics = {
            "total_flows": 0,
            "total_bytes": 0,
            "attacks_detected": 0,
            "suspicious_detected": 0
        }
        
        self.live_decisions = deque(maxlen=100)
        self.top_talkers_bytes = {}
        self.attack_counters = {}
        
        self.ws_clients = set()
        self.ws_lock = threading.Lock()
        self.loop = None  # to hold the asyncio event loop for websocket

    def set_loop(self, loop):
        self.loop = loop

    # ── Safe thread → async bridge ────────────────────────────
    def _safe_broadcast(self, data: dict):
        """Submit a broadcast to the event loop from any thread. Never blocks."""
        with self.ws_lock:
            has_clients = bool(self.ws_clients)
        if self.loop and has_clients:
            try:
                if self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(self._broadcast(data), self.loop)
            except Exception:
                pass

    def update_decision(self, ip, packets, bytes_, pps, verdict, reason):
        with self.lock:
            self.metrics["total_flows"] += 1
            self.metrics["total_bytes"] += bytes_
            
            if verdict == "ATTACK":
                self.metrics["attacks_detected"] += 1
                self.attack_counters[reason] = self.attack_counters.get(reason, 0) + 1
            elif verdict == "SUSPICIOUS":
                self.metrics["suspicious_detected"] += 1
                
            self.top_talkers_bytes[ip] = self.top_talkers_bytes.get(ip, 0) + bytes_
            
            decision = {
                "ip": ip,
                "packets": packets,
                "bytes": bytes_,
                "pps": round(pps, 2),
                "verdict": verdict,
                "reason": reason
            }
            self.live_decisions.appendleft(decision)
            
        # Stream evaluation — ATTACK/SUSPICIOUS always, NORMAL 1-in-20 sample
        send = verdict in ("ATTACK", "SUSPICIOUS") or random.randint(1, 20) == 1
        if send:
            self._safe_broadcast({"type": "decision", "data": decision})

    def broadcast_alert(self, ip: str, attack_type: str, message: str = ""):
        """Push a new alert event to all WebSocket clients instantly."""
        payload = {
            "type": "alert",
            "data": {
                "ip": ip,
                "attack": attack_type,
                "message": message,
                "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
        }
        log.debug("broadcasting alert ip=%s attack=%s", ip, attack_type)
        self._safe_broadcast(payload)

    def broadcast_action(self, ip: str, action: str, reason: str = ""):
        """Push an IPS action event to all WebSocket clients instantly."""
        payload = {
            "type": "action",
            "data": {
                "ip": ip,
                "action": action,
                "reason": reason,
                "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
        }
        log.debug("broadcasting action=%s ip=%s", action, ip)
        self._safe_broadcast(payload)

    async def _broadcast(self, data: dict):
        to_remove = set()
        with self.ws_lock:
            clients = list(self.ws_clients)
        for ws in clients:
            try:
                await ws.send_json(data)
            except Exception:
                to_remove.add(ws)
        if to_remove:
            with self.ws_lock:
                self.ws_clients.difference_update(to_remove)

    def get_metrics(self):
        with self.lock:
            return dict(self.metrics)

    def get_live(self):
        with self.lock:
            return list(self.live_decisions)

    def get_top(self):
        with self.lock:
            # Top 10 talkers by bytes
            sorted_talkers = sorted(self.top_talkers_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
            top_talkers = [{"ip": ip, "bytes": b} for ip, b in sorted_talkers]
            
            # Top attacks
            sorted_attacks = sorted(self.attack_counters.items(), key=lambda x: x[1], reverse=True)[:10]
            top_attacks = [{"reason": r, "count": c} for r, c in sorted_attacks]
            
            return {
                "top_talkers": top_talkers,
                "top_attacks": top_attacks
            }

agent_state = StateManager()
