from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from statistics import mean
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
METRICS_FILE = LOG_DIR / "performance_metrics.jsonl"

BANDWIDTH_PROFILES: dict[str, dict[str, float | str]] = {
    "unlimited": {
        "label": "Unlimited",
        "mbps": 0,
        "base_latency_ms": 0,
        "jitter_ms": 0,
        "packet_delay_ms": 0,
    },
    "20mbps": {
        "label": "20 Mbps",
        "mbps": 20,
        "base_latency_ms": 18,
        "jitter_ms": 8,
        "packet_delay_ms": 1,
    },
    "10mbps": {
        "label": "10 Mbps",
        "mbps": 10,
        "base_latency_ms": 35,
        "jitter_ms": 14,
        "packet_delay_ms": 3,
    },
    "5mbps": {
        "label": "5 Mbps",
        "mbps": 5,
        "base_latency_ms": 70,
        "jitter_ms": 25,
        "packet_delay_ms": 7,
    },
    "1mbps": {
        "label": "1 Mbps",
        "mbps": 1,
        "base_latency_ms": 180,
        "jitter_ms": 60,
        "packet_delay_ms": 18,
    },
}


class PerformanceMonitor:
    def __init__(self, max_points: int = 500):
        self.max_points = max_points
        self._lock = threading.Lock()
        self._events: deque[dict[str, Any]] = deque(maxlen=max_points)
        self._counters: dict[str, int] = defaultdict(int)
        self._seen_event_ids: set[str] = set()
        LOG_DIR.mkdir(exist_ok=True)
        self._load_recent_file_events()

    def _load_recent_file_events(self) -> None:
        if not METRICS_FILE.exists():
            return
        try:
            lines = METRICS_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()[-self.max_points :]
            for line in lines:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    event_id = str(item.get("id") or "")
                    if event_id and event_id in self._seen_event_ids:
                        continue
                    if event_id:
                        self._seen_event_ids.add(event_id)
                    self._events.append(item)
                    metric_type = item.get("type")
                    if metric_type:
                        self._counters[str(metric_type)] += 1
        except OSError:
            return

    def record(self, metric_type: str, value_ms: float, **metadata: Any) -> dict[str, Any]:
        event = {
            "id": f"{int(time.time() * 1000)}-{os.getpid()}-{threading.get_ident()}-{len(self._events)}",
            "timestamp": time.time(),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": str(metric_type),
            "value_ms": round(float(value_ms), 3),
            "metadata": metadata,
        }
        with self._lock:
            self._events.append(event)
            self._seen_event_ids.add(event["id"])
            self._counters[str(metric_type)] += 1
            try:
                with METRICS_FILE.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event, default=str) + "\n")
            except OSError:
                pass
        return event

    def snapshot(self, limit: int = 120) -> dict[str, Any]:
        self._load_recent_file_events()
        with self._lock:
            events = list(self._events)[-limit:]
            counters = dict(self._counters)

        grouped: dict[str, list[float]] = defaultdict(list)
        for event in events:
            grouped[event.get("type", "unknown")].append(float(event.get("value_ms") or 0))

        summary = {}
        for key, values in grouped.items():
            if not values:
                continue
            summary[key] = {
                "avg": round(mean(values), 2),
                "min": round(min(values), 2),
                "max": round(max(values), 2),
                "current": round(values[-1], 2),
                "count": len(values),
            }

        api = summary.get("api_response_time", {})
        client_api = summary.get("client_api_time", {})
        ai = summary.get("ai_inference_time", {})
        db = summary.get("db_query_time", {})
        detection = summary.get("detection_latency", {})
        ws = summary.get("websocket_latency", {})
        dashboard = summary.get("dashboard_render_delay", {})

        return {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "avg_response_time": api.get("avg", 0),
            "min_response_time": api.get("min", 0),
            "max_response_time": api.get("max", 0),
            "current_latency": client_api.get("current", api.get("current", 0)),
            "client_api_time": client_api.get("current", 0),
            "avg_client_api_time": client_api.get("avg", 0),
            "backend_response_time": api.get("current", 0),
            "ai_inference_time": ai.get("current", 0),
            "avg_ai_inference_time": ai.get("avg", 0),
            "database_query_time": db.get("current", 0),
            "avg_database_query_time": db.get("avg", 0),
            "detection_delay": detection.get("current", 0),
            "websocket_ping": ws.get("current", 0),
            "dashboard_render_delay": dashboard.get("current", 0),
            "summary": summary,
            "counters": counters,
            "history": events,
            "bandwidth_profiles": BANDWIDTH_PROFILES,
        }


performance_monitor = PerformanceMonitor()


def normalize_bandwidth_profile(profile: str | None) -> str:
    key = str(profile or "unlimited").strip().lower().replace(" ", "")
    aliases = {
        "1": "1mbps",
        "1m": "1mbps",
        "1mb": "1mbps",
        "5": "5mbps",
        "5m": "5mbps",
        "5mb": "5mbps",
        "10": "10mbps",
        "10m": "10mbps",
        "10mb": "10mbps",
        "20": "20mbps",
        "20m": "20mbps",
        "20mb": "20mbps",
        "none": "unlimited",
    }
    key = aliases.get(key, key)
    return key if key in BANDWIDTH_PROFILES else "unlimited"


def simulated_delay_seconds(profile: str | None, payload_bytes: int = 0) -> float:
    key = normalize_bandwidth_profile(profile)
    cfg = BANDWIDTH_PROFILES[key]
    mbps = float(cfg["mbps"] or 0)
    if mbps <= 0:
        return 0.0
    base = float(cfg["base_latency_ms"]) / 1000.0
    jitter = (float(cfg["jitter_ms"]) / 1000.0) * ((time.time() * 1000) % 100) / 100.0
    transfer = (max(payload_bytes, 0) * 8) / (mbps * 1_000_000)
    return min(base + jitter + transfer, 2.5)


def apply_bandwidth_delay(profile: str | None, payload_bytes: int = 0) -> float:
    delay = simulated_delay_seconds(profile, payload_bytes)
    if delay > 0:
        time.sleep(delay)
    return round(delay * 1000, 3)
