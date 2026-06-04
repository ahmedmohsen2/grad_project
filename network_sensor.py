from __future__ import annotations

import json
import os
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import CAPTURE_INTERFACE, PROMISCUOUS_MODE, SENSOR_MODE

STATUS_PATH = Path(os.getenv("SENSOR_STATUS_PATH", "logs/network_sensor_status.json"))

VALID_SENSOR_MODES = {"host", "span", "tap", "inline"}

VISIBILITY_BY_MODE = {
    "host": "Host Only",
    "span": "Mirrored Traffic",
    "tap": "Mirrored Traffic",
    "inline": "Full Inline Traffic",
}

LIMITATIONS_BY_MODE = {
    "host": "Sees traffic to/from the Fusion machine plus broadcast/multicast. It will not see Kali-to-Victim unicast traffic on a normal switch.",
    "span": "Requires a managed switch mirror session. Fusion sees only the VLANs/ports selected as SPAN sources.",
    "tap": "Requires a physical/network TAP. Fusion passively sees the tapped link but cannot block by itself.",
    "inline": "Fusion must be in the forwarding path. Visibility and prevention apply only to traffic routed/bridged through Fusion.",
}

_lock = threading.RLock()
_status: dict[str, Any] = {}
_last_persist = 0.0


def normalize_sensor_mode(mode: str | None = None) -> str:
    normalized = str(mode or SENSOR_MODE or "host").strip().lower()
    return normalized if normalized in VALID_SENSOR_MODES else "host"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _base_status() -> dict[str, Any]:
    mode = normalize_sensor_mode()
    return {
        "sensor_mode": mode,
        "capture_interface": CAPTURE_INTERFACE or None,
        "promiscuous_mode": bool(PROMISCUOUS_MODE),
        "packets_captured": 0,
        "flows_analyzed": 0,
        "visibility_type": VISIBILITY_BY_MODE[mode],
        "visibility_limitations": LIMITATIONS_BY_MODE[mode],
        "hostname": socket.gethostname(),
        "active": False,
        "started_at": None,
        "updated_at": _now(),
        "last_packet_at": None,
        "last_flow_at": None,
    }


def _enrich(status: dict[str, Any]) -> dict[str, Any]:
    mode = normalize_sensor_mode(status.get("sensor_mode"))
    status["sensor_mode"] = mode
    status["visibility_type"] = VISIBILITY_BY_MODE[mode]
    status["visibility_limitations"] = LIMITATIONS_BY_MODE[mode]
    status["network_wide_capable"] = mode in {"span", "tap", "inline"}
    status["prevention_capable"] = mode == "inline"
    return status


def read_sensor_status() -> dict[str, Any]:
    with _lock:
        status = _base_status()
        try:
            if STATUS_PATH.exists():
                persisted = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
                if isinstance(persisted, dict):
                    status.update(persisted)
        except Exception:
            pass
        status.update(_status)
        return _enrich(status)


def update_sensor_status(*, persist: bool = True, **updates: Any) -> dict[str, Any]:
    global _last_persist
    with _lock:
        current = read_sensor_status()
        current.update(updates)
        current["updated_at"] = _now()
        _status.clear()
        _status.update(_enrich(current))
        should_persist = persist
        if not should_persist:
            import time
            now = time.time()
            should_persist = now - _last_persist >= 1.0
            if should_persist:
                _last_persist = now
        try:
            if not should_persist:
                return dict(_status)
            STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
            STATUS_PATH.write_text(json.dumps(_status, indent=2), encoding="utf-8")
        except Exception:
            pass
        return dict(_status)


def mark_sensor_started(*, interface: str | None, sensor_mode: str | None, promiscuous: bool) -> dict[str, Any]:
    return update_sensor_status(
        active=True,
        capture_interface=interface or CAPTURE_INTERFACE or None,
        sensor_mode=normalize_sensor_mode(sensor_mode),
        promiscuous_mode=bool(promiscuous),
        started_at=_now(),
        packets_captured=0,
        flows_analyzed=0,
    )


def increment_packets(count: int = 1) -> None:
    status = read_sensor_status()
    update_sensor_status(
        packets_captured=int(status.get("packets_captured") or 0) + int(count),
        last_packet_at=_now(),
        persist=False,
    )


def increment_flows(count: int = 1) -> None:
    status = read_sensor_status()
    update_sensor_status(
        flows_analyzed=int(status.get("flows_analyzed") or 0) + int(count),
        last_flow_at=_now(),
        persist=False,
    )
