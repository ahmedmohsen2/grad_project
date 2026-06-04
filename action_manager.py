"""
action_manager.py — Centralized IPS Action Manager
====================================================
Handles threat-specific responses:
  - MALWARE  → Block IP + Mark COMPROMISED
  - RANSOMWARE → Full isolation + CRITICAL INCIDENT
  - DDOS     → Block IP + rate-limit
  - BRUTEFORCE→ Block IP
  - GENERIC  → Progressive monitor/block

All actions respect:
  - Whitelist (localhost + gateway only)
  - Confidence threshold (> 0.8)
  - Progressive detection (≥ 3 hits to block)
"""

import time
import logging
import threading
from dataclasses import dataclass, field
from typing import Literal

# Import core action primitives
from action import (
    execute_decision, block_ip, monitor_ip, unblock_ip,
    ip_in_whitelist, _states, IPState
)

# ── [DB] Import sync wrappers (async db.py, bridged for threaded callers) ────
from db import (
    sync_insert_action       as insert_action,
    sync_insert_blocked_ip   as insert_blocked_ip,
    sync_remove_blocked_ip   as remove_blocked_ip,
    sync_upsert_host         as upsert_host,
    sync_update_host_status  as update_host_status,
    sync_insert_alert        as insert_alert,
)
from host_actions import execute_host_action

log = logging.getLogger("ActionManager")

# ──────────────────────────────────────────────────────────────
# 🗂️ Host Status Registry
# ──────────────────────────────────────────────────────────────
@dataclass
class HostRecord:
    ip: str
    status: str = "CLEAN"          # CLEAN, MONITORED, COMPROMISED, ISOLATED, CRITICAL
    threat_type: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    incident_count: int = 0
    notes: list = field(default_factory=list)

_host_registry: dict[str, HostRecord] = {}
_registry_lock = threading.Lock()

def _get_or_create(ip: str) -> HostRecord:
    with _registry_lock:
        if ip not in _host_registry:
            _host_registry[ip] = HostRecord(ip=ip)
        _host_registry[ip].last_seen = time.time()
        return _host_registry[ip]

def get_all_incidents() -> list[dict]:
    """Returns all non-CLEAN host records for dashboard consumption."""
    with _registry_lock:
        return [
            {
                "ip": h.ip, "status": h.status, "threat": h.threat_type,
                "incidents": h.incident_count,
                "first_seen": h.first_seen, "last_seen": h.last_seen,
                "notes": h.notes[-5:],
            }
            for h in _host_registry.values()
            if h.status != "CLEAN"
        ]


# ──────────────────────────────────────────────────────────────
# [DB] Non-blocking DB helper — wraps all DB calls in daemon thread
# ──────────────────────────────────────────────────────────────

def _db_action(ip: str, action_type: str, reason: str, block: bool = False, new_status: str = ""):
    """
    Fire-and-forget DB writes for an IPS action.
    Runs in a daemon thread so the caller is never blocked.

    Args:
        ip:          The IP acted on
        action_type: BLOCK | MONITOR | ISOLATE | UNBLOCK
        reason:      Human-readable reason
        block:       If True, also insert into blocked_ips
        new_status:  If set, update hosts.status to this value

    Alert mapping (60s cooldown dedup handled inside insert_alert):
        BLOCK   → alert_type=BLOCK        "IP blocked due to attack"
        MONITOR → alert_type=SUSPICIOUS   "Suspicious activity detected"
        ISOLATE → alert_type=MALWARE      "Host isolated due to malware behavior"
    """
    def _write():
        try:
            if action_type.upper() in {"BLOCK", "ISOLATE", "UNBLOCK"}:
                payload, status_code = execute_host_action(
                    action=action_type.upper(),
                    target=ip,
                    reason=reason,
                    source="auto",
                    confidence=1.0,
                    trigger="action_manager",
                    actor_username="action_manager",
                    actor_role="service",
                )
                if status_code >= 400:
                    log.error("[DB ACTION] host action failed for %s: %s", ip, payload)
                return

            upsert_host(ip)
            insert_action(ip, action_type, reason)
            if block:
                insert_blocked_ip(ip, reason)
            if new_status:
                update_host_status(ip, new_status)

            # ── [ALERT] Insert alert based on action type ────────────
            atype = action_type.upper()
            if atype in ("BLOCK",):
                insert_alert(ip, "BLOCK",      f"IP {ip} blocked due to attack: {reason[:200]}")
            elif atype == "MONITOR":
                insert_alert(ip, "SUSPICIOUS", f"Suspicious activity from {ip}: {reason[:200]}")
            elif atype == "ISOLATE":
                insert_alert(ip, "MALWARE",    f"Host {ip} isolated due to malware behavior: {reason[:200]}")
            # ───────────────────────────────────────────────────────

        except Exception as e:
            log.error(f"[DB ERROR] _db_action failed for {ip}: {e}")

    threading.Thread(target=_write, daemon=True).start()

# ──────────────────────────────────────────────────────────────
# 🔴 Threat-Specific Response Handlers
# ──────────────────────────────────────────────────────────────

def _handle_malware(ip: str, reason: str, conf: float):
    host = _get_or_create(ip)
    host.threat_type = "MALWARE"
    host.incident_count += 1
    host.notes.append(f"[{_ts()}] Malware detected | conf={conf:.2f} | {reason}")

    log.critical(
        f"[MALWARE INCIDENT] ip={ip} | conf={conf:.2f} | "
        f"reason={reason} | incident_count={host.incident_count}"
    )

    execute_decision(ip, "BLOCK", reason=f"MALWARE:{reason}", conf=conf)
    host.status = "COMPROMISED"
    log.warning(f"[HOST STATUS] {ip} marked as COMPROMISED")

    # [DB] persist block + status change
    _db_action(ip, "BLOCK", reason, block=True, new_status="COMPROMISED")


def _handle_ransomware(ip: str, reason: str, conf: float, simulation: bool = False):
    host = _get_or_create(ip)
    host.threat_type = "RANSOMWARE"
    host.incident_count += 1
    host.notes.append(f"[{_ts()}] RANSOMWARE detected | conf={conf:.2f} | {reason}")
    host.status = "CRITICAL"

    log.critical(
        f"[!!! CRITICAL INCIDENT !!!] RANSOMWARE from ip={ip} | "
        f"conf={conf:.2f} | reason={reason}"
    )
    print(f"\n{'!'*60}")
    print(f"  [CRITICAL] RANSOMWARE DETECTED — IP: {ip}")
    print(f"  Reason: {reason}")
    print(f"  Confidence: {conf:.2f}")
    print(f"  Action: FULL ISOLATION")
    print(f"{'!'*60}\n")

    if ip not in _states:
        _states[ip] = IPState()
    _states[ip].hit_count = 99
    _states[ip].first_hit_time = time.time()

    block_ip(ip, reason=f"RANSOMWARE ISOLATION:{reason}")
    host.status = "ISOLATED"

    # [DB] persist isolation
    _db_action(ip, "ISOLATE", reason, block=True, new_status="ISOLATED")

    if simulation:
        log.warning(f"[SIMULATION] System lockdown event triggered for {ip} (no real OS changes)")
        print(f"  >> [SIMULATION] Lockdown event logged for {ip}")


def _handle_ddos(ip: str, reason: str, conf: float):
    host = _get_or_create(ip)
    host.threat_type = "DDOS"
    host.incident_count += 1
    host.notes.append(f"[{_ts()}] DDoS detected | conf={conf:.2f}")

    log.warning(f"[DDOS ACTION] ip={ip} | conf={conf:.2f} | {reason}")
    execute_decision(ip, "BLOCK", reason=f"DDoS:{reason}", conf=conf)
    host.status = "COMPROMISED"

    # [DB] persist block
    _db_action(ip, "BLOCK", reason, block=True, new_status="COMPROMISED")


def _handle_bruteforce(ip: str, reason: str, conf: float):
    host = _get_or_create(ip)
    host.threat_type = "BRUTEFORCE"
    host.incident_count += 1
    host.notes.append(f"[{_ts()}] BruteForce detected | conf={conf:.2f}")

    log.warning(f"[BRUTEFORCE ACTION] ip={ip} | conf={conf:.2f} | {reason}")
    execute_decision(ip, "BLOCK", reason=f"BruteForce:{reason}", conf=conf)
    host.status = "COMPROMISED"

    # [DB] persist block
    _db_action(ip, "BLOCK", reason, block=True, new_status="COMPROMISED")


# ──────────────────────────────────────────────────────────────
# 🧠 Central Dispatch: execute_action()
# ──────────────────────────────────────────────────────────────

ThreatType = Literal["MALWARE", "RANSOMWARE", "DDOS", "BRUTEFORCE", "SUSPICIOUS", "GENERIC"]
Decision   = Literal["BLOCK", "MONITOR", "ISOLATE", "UNBLOCK"]

def execute_action(
    ip: str,
    threat_type: ThreatType,
    decision: Decision,
    reason: str = "",
    conf: float = 1.0,
    simulation: bool = False,
):
    """
    Central action dispatcher.
    Routes to the correct threat-specific handler.

    Args:
        ip:          Source IP address
        threat_type: Type of detected threat
        decision:    Desired action (BLOCK / MONITOR / ISOLATE / UNBLOCK)
        reason:      Human-readable reason string
        conf:        ML/rule confidence score (0.0 – 1.0)
        simulation:  If True, enables simulation-only events (no real OS changes)
    """
    if ip_in_whitelist(ip):
        log.debug(f"[ActionManager] Skipping whitelisted IP: {ip}")
        return

    if decision == "UNBLOCK":
        unblock_ip(ip)
        host = _get_or_create(ip)
        host.status = "CLEAN"
        host.notes.append(f"[{_ts()}] Unblocked")
        # [DB] remove from blocked_ips + update host
        _db_action(ip, "UNBLOCK", "manually unblocked", block=False, new_status="CLEAN")
        threading.Thread(target=remove_blocked_ip, args=(ip,), daemon=True).start()
        return

    if decision == "MONITOR":
        monitor_ip(ip, reason=reason)
        _get_or_create(ip).status = "MONITORED"
        # [DB] log monitoring action
        _db_action(ip, "MONITOR", reason, block=False, new_status="MONITORED")
        return

    # For BLOCK / ISOLATE — route by threat type
    threat = threat_type.upper()

    if threat == "RANSOMWARE" or decision == "ISOLATE":
        _handle_ransomware(ip, reason, conf, simulation=simulation)

    elif threat == "MALWARE":
        _handle_malware(ip, reason, conf)

    elif threat == "DDOS":
        _handle_ddos(ip, reason, conf)

    elif threat == "BRUTEFORCE":
        _handle_bruteforce(ip, reason, conf)

    else:
        # Generic block through progressive engine
        execute_decision(ip, "BLOCK", reason=reason, conf=conf)
        # [DB] persist generic block
        _db_action(ip, "BLOCK", reason, block=True, new_status="COMPROMISED")


# ──────────────────────────────────────────────────────────────
# 🔧 Helpers
# ──────────────────────────────────────────────────────────────
def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")
