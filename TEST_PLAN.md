# Fusion Strike AI - Validation Plan

## Security Controls

- Unauthenticated `/pentest/scan` must return `401`.
- Analyst JWT on state-changing actions must return `403`.
- Admin JWT or `X-API-Token` may run protected operations.
- Malformed targets such as `127.0.0.1; whoami` must return `400`.
- `/blocked-ips` requires authentication.
- CORS origins must be loaded from `.env`.
- Flask debug must remain disabled unless explicitly enabled by `.env`.

Command:

```bat
.venv\Scripts\python.exe tests\security_regression.py
```

## Pentest Lifecycle

- Create scan through `/pentest/scan`.
- Poll `/pentest/results/<id>`.
- Expected lifecycle: queued -> running -> completed.
- Expected final state: progress `100`, current_stage `report`.
- Report must state `SAFE MODE / LAB VALIDATION`.
- Exploit output must use simulated/suspected labels, never false confirmed claims.

## Dashboard Integrity

- `npm.cmd run build` must complete successfully.
- Command Center must show alerts, detections, blocked hosts, pentest scans, and system health.
- Alerts page must support severity, filters, read/unread, and pagination.
- Live Monitoring must show WebSocket state and fallback status.
- Degraded backend health must be visible.

## WebSocket Stability

- Broadcast to multiple clients.
- Remove failed clients safely.
- Avoid mutating the WebSocket client set without a lock.

Command:

```bat
.venv\Scripts\python.exe tests\ws_stress.py
```

## Failure Modes

- DB offline: `/health` returns degraded/503, logs explain DB issue.
- WS offline: dashboard remains usable through polling.
- Pentest timeout: scan is marked `failed`, progress `100`, error persisted.
- Invalid target: request rejected before scanner execution.

## Startup Validation

Command:

```bat
.venv\Scripts\python.exe tools\validate_startup.py
```

## Demo Data And Backup

Seed demo evidence:

```bat
.venv\Scripts\python.exe tools\demo_seed.py
```

Export operational evidence:

```bat
.venv\Scripts\python.exe tools\export_backup.py
```
