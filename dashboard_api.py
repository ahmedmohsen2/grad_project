from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from config import CORS_ORIGINS
from auth import decode_token, normalize_role
from db import (
    sync_get_actions,
    sync_get_activity_logs,
    sync_get_alerts,
    sync_get_blocked_ips,
    sync_get_detections,
    sync_get_flows,
    sync_get_pentest_scan,
    sync_get_security_findings,
    sync_init_pool,
    sync_list_pentest_scans,
)
from performance_monitor import BANDWIDTH_PROFILES, performance_monitor
from state_manager import agent_state


app = FastAPI(title="Fusion Strike Realtime API")
log = logging.getLogger("dashboard_api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class WebSocketHub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.lock = asyncio.Lock()
        self.sequence = 0
        self.last_ids = {
            "alerts": set(),
            "detections": set(),
            "actions": set(),
            "scans": set(),
            "logs": set(),
        }

    async def connect(self, websocket: WebSocket, user: dict[str, Any]) -> None:
        await websocket.accept()
        async with self.lock:
            self.clients.add(websocket)
        await websocket.send_json({
            "type": "connected",
            "server_time": time.time(),
            "user": {
                "username": user.get("username"),
                "role": user.get("role"),
            },
        })

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self.lock:
            self.clients.discard(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        async with self.lock:
            clients = list(self.clients)
        if not clients:
            return
        dead = []
        for client in clients:
            try:
                await client.send_json(payload)
            except Exception:
                dead.append(client)
        if dead:
            async with self.lock:
                for client in dead:
                    self.clients.discard(client)

    async def has_clients(self) -> bool:
        async with self.lock:
            return bool(self.clients)

    async def handle_message(self, websocket: WebSocket, message: str) -> None:
        if len(message) > 4096:
            await websocket.close(code=1009)
            return
        try:
            parsed = json.loads(message)
        except json.JSONDecodeError:
            parsed = {"type": message}

        msg_type = str(parsed.get("type") or "unknown").lower()
        if msg_type in ("ping", "heartbeat"):
            client_ts = parsed.get("client_ts")
            if isinstance(client_ts, (int, float)):
                performance_monitor.record(
                    "websocket_latency",
                    max((time.time() * 1000) - float(client_ts), 0),
                    direction="client_to_server",
                )
            await websocket.send_json({
                "type": "pong",
                "client_ts": client_ts,
                "server_time": time.time(),
                "sequence": self.sequence,
            })
            return

        if msg_type == "pong":
            return

        if msg_type in ("subscribe", "snapshot"):
            await websocket.send_json(await build_snapshot(reason="subscribe"))
            return

        if msg_type == "metrics":
            await websocket.send_json({
                "type": "metrics",
                "sequence": self.sequence,
                "server_time": time.time(),
                "data": performance_monitor.snapshot(limit=160),
            })
            return

        await websocket.send_json({"type": "error", "message": f"Unsupported websocket message: {msg_type}"})


hub = WebSocketHub()


def authenticate_websocket(websocket: WebSocket) -> dict[str, Any] | None:
    token = (websocket.query_params.get("token") or "").strip()
    if not token:
        protocol = websocket.headers.get("sec-websocket-protocol", "")
        for part in protocol.split(","):
            candidate = part.strip()
            if candidate.lower().startswith("bearer."):
                token = candidate.split(".", 1)[1].strip()
                break
    payload = decode_token(token) if token else None
    if not payload:
        return None
    role = normalize_role(payload.get("role", "analyst"))
    if role not in {"admin", "analyst", "service"}:
        return None
    return {
        "user_id": payload.get("user_id"),
        "username": payload.get("username"),
        "email": payload.get("email"),
        "role": role,
    }


def _ids(rows: list[dict[str, Any]], key: str) -> set[Any]:
    return {row.get(key) for row in rows if row.get(key) is not None}


def build_hosts(
    flows: list[dict[str, Any]],
    detections: list[dict[str, Any]],
    blocked_ips: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    blocked = {row.get("ip") for row in blocked_ips if row.get("ip")}
    latest_action = {}
    for action in actions:
        ip = action.get("ip") or action.get("target")
        if ip and ip not in latest_action:
            latest_action[ip] = action
    hosts: dict[str, dict[str, Any]] = {}
    for flow in flows:
        for field in ("src_ip", "dst_ip"):
            ip = flow.get(field)
            if ip:
                hosts.setdefault(ip, {"ip": ip, "status": "SEEN", "incident_count": 0})
    for detection in detections:
        ip = detection.get("src_ip")
        if not ip:
            continue
        host = hosts.setdefault(ip, {"ip": ip, "status": "SEEN", "incident_count": 0})
        if detection.get("result") != "NORMAL":
            host["incident_count"] = int(host.get("incident_count") or 0) + 1
            host["status"] = "SUSPICIOUS"
    for ip in blocked:
        host = hosts.setdefault(ip, {"ip": ip, "status": "BLOCKED", "incident_count": 0})
        host["status"] = "BLOCKED"
    for ip, action in latest_action.items():
        host = hosts.setdefault(ip, {"ip": ip, "status": "SEEN", "incident_count": 0})
        host["last_action"] = action.get("action_type")
        host["action_source"] = action.get("source")
        host["updated_at"] = action.get("acted_at")
        if action.get("action_type") == "ISOLATE":
            host["status"] = "ISOLATED"
        elif action.get("action_type") == "WHITELIST":
            host["status"] = "TRUSTED"
    return list(hosts.values())[:100]


def build_incidents(detections: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    incidents = []
    for detection in detections:
        if detection.get("result") == "NORMAL":
            continue
        incidents.append({
            "id": detection.get("id"),
            "target": detection.get("src_ip"),
            "severity": detection.get("result"),
            "type": detection.get("attack_type"),
            "updated_at": detection.get("detected_at"),
            "source": "detection",
        })
    for finding in findings:
        incidents.append({
            "id": finding.get("finding_id"),
            "target": finding.get("target"),
            "severity": finding.get("severity"),
            "type": finding.get("title"),
            "updated_at": finding.get("updated_at") or finding.get("last_seen_at"),
            "source": "pentest",
        })
    return incidents[:50]


async def build_snapshot(reason: str = "interval") -> dict[str, Any]:
    (
        alerts,
        detections,
        flows,
        actions,
        blocked_ips,
        findings,
        scans,
        metrics,
        activity_logs,
    ) = await asyncio.gather(
        asyncio.to_thread(sync_get_alerts, limit=50),
        asyncio.to_thread(sync_get_detections, limit=80, offset=0),
        asyncio.to_thread(sync_get_flows, limit=50, offset=0),
        asyncio.to_thread(sync_get_actions, limit=40, offset=0),
        asyncio.to_thread(sync_get_blocked_ips),
        asyncio.to_thread(sync_get_security_findings, limit=50),
        asyncio.to_thread(sync_list_pentest_scans, limit=30, offset=0),
        asyncio.to_thread(performance_monitor.snapshot, limit=160),
        asyncio.to_thread(sync_get_activity_logs, limit=50),
    )
    alerts = alerts or []
    detections = detections or []
    flows = flows or []
    actions = actions or []
    blocked_ips = blocked_ips or []
    findings = findings or []
    scans = scans or []
    activity_logs = activity_logs or []
    hosts = build_hosts(flows, detections, blocked_ips, actions)
    incidents = build_incidents(detections, findings)

    hub.sequence += 1
    return {
        "type": "snapshot",
        "reason": reason,
        "sequence": hub.sequence,
        "server_time": time.time(),
        "data": {
            "alerts": alerts,
            "detections": detections,
            "flows": flows,
            "actions": actions,
            "blocked_ips": blocked_ips,
            "hosts": hosts,
            "incidents": incidents,
            "pentest_findings": findings,
            "pentest_scans": scans,
            "performance": metrics,
            "activity_logs": activity_logs,
            "bandwidth_profiles": BANDWIDTH_PROFILES,
            "agent_metrics": agent_state.get_metrics(),
            "agent_live": agent_state.get_live(),
            "agent_top": agent_state.get_top(),
        },
    }


async def realtime_pump() -> None:
    while True:
        try:
            if not await hub.has_clients():
                await asyncio.sleep(2.0)
                continue
            snapshot = await build_snapshot()
            data = snapshot["data"]
            current_ids = {
                "alerts": _ids(data["alerts"], "id"),
                "detections": _ids(data["detections"], "id"),
                "actions": _ids(data["actions"], "id"),
                "logs": _ids(data["activity_logs"], "id"),
                "scans": {
                    (row.get("scan_id"), row.get("status"), row.get("progress"), row.get("updated_at"))
                    for row in data["pentest_scans"]
                    if row.get("scan_id") is not None
                },
            }
            first_run = not any(hub.last_ids.values())
            changed = first_run or current_ids != hub.last_ids

            if changed or snapshot["sequence"] % 5 == 0:
                await hub.broadcast(snapshot)
            else:
                await hub.broadcast({
                    "type": "metrics",
                    "sequence": snapshot["sequence"],
                    "server_time": snapshot["server_time"],
                    "data": data["performance"],
                })

            if not first_run:
                new_alerts = [row for row in data["alerts"] if row.get("id") in current_ids["alerts"] - hub.last_ids["alerts"]]
                new_detections = [
                    row for row in data["detections"]
                    if row.get("id") in current_ids["detections"] - hub.last_ids["detections"]
                ]
                new_actions = [
                    row for row in data["actions"]
                    if row.get("id") in current_ids["actions"] - hub.last_ids["actions"]
                ]
                new_logs = [
                    row for row in data["activity_logs"]
                    if row.get("id") in current_ids["logs"] - hub.last_ids["logs"]
                ]
                changed_scans = [
                    row for row in data["pentest_scans"]
                    if (
                        row.get("scan_id"),
                        row.get("status"),
                        row.get("progress"),
                        row.get("updated_at"),
                    ) in current_ids["scans"] - hub.last_ids["scans"]
                ]
                for alert in new_alerts:
                    await hub.broadcast({"type": "alert", "sequence": snapshot["sequence"], "data": alert})
                for detection in new_detections:
                    await hub.broadcast({"type": "threat", "sequence": snapshot["sequence"], "data": detection})
                for action in new_actions:
                    await hub.broadcast({"type": "action", "sequence": snapshot["sequence"], "data": action})
                for log_row in new_logs:
                    await hub.broadcast({"type": "activity_log", "sequence": snapshot["sequence"], "data": log_row})
                for scan in changed_scans:
                    await hub.broadcast({"type": "pentest_scan", "sequence": snapshot["sequence"], "data": scan})

            hub.last_ids = current_ids
        except Exception:
            log.exception("realtime pump failed")
        await asyncio.sleep(2.0)


@app.on_event("startup")
async def startup_event():
    agent_state.set_loop(asyncio.get_running_loop())
    sync_init_pool(retries=1, retry_delay=0.1)
    asyncio.create_task(realtime_pump())


@app.get("/api/metrics")
async def get_metrics():
    return {
        "agent": agent_state.get_metrics(),
        "performance": performance_monitor.snapshot(limit=160),
        "bandwidth_profiles": BANDWIDTH_PROFILES,
    }


@app.get("/api/live")
async def get_live():
    return {"live": agent_state.get_live()}


@app.get("/api/top")
async def get_top():
    return agent_state.get_top()


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    return sync_get_pentest_scan(scan_id) or {"error": "not found"}


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    user = authenticate_websocket(websocket)
    if not user:
        await websocket.close(code=1008)
        return
    await hub.connect(websocket, user)
    try:
        await websocket.send_json(await build_snapshot(reason="connect"))
        while True:
            message = await websocket.receive_text()
            await hub.handle_message(websocket, message)
    except WebSocketDisconnect:
        pass
    except Exception:
        log.exception("websocket client failed")
    finally:
        await hub.disconnect(websocket)


def run_api_server():
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    run_api_server()
