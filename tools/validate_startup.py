from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import api


def check(name: str, ok: bool, detail: str = "") -> dict:
    return {"name": name, "ok": bool(ok), "detail": detail}


def main() -> int:
    client = api.app.test_client()
    checks = []

    health = client.get("/health")
    checks.append(check("flask_health", health.status_code == 200, str(health.get_json())))
    checks.append(check("model_loaded", bool(api.MODEL_MODE), api.MODEL_MODE))
    cors_probe = client.options(
        "/health",
        headers={
            "Origin": "http://localhost:4173",
            "Access-Control-Request-Method": "GET",
        },
    )
    checks.append(
        check(
            "cors_restricted_origin_allowed",
            cors_probe.headers.get("Access-Control-Allow-Origin") == "http://localhost:4173",
            cors_probe.headers.get("Access-Control-Allow-Origin", "missing"),
        )
    )
    checks.append(check("debug_disabled", not api.app.debug, f"debug={api.app.debug}"))
    checks.append(check("api_token_present", bool(os.getenv("API_TOKEN")), "API_TOKEN loaded from .env"))

    read_endpoints = ["/alerts?limit=1", "/detections?limit=1", "/pentest/scans?limit=1"]
    for endpoint in read_endpoints:
        resp = client.get(endpoint)
        checks.append(check(f"read_endpoint:{endpoint}", resp.status_code in {200, 503}, f"status={resp.status_code}"))

    protected = client.post("/actions/block", json={"target": "127.0.0.1", "reason": "startup validation"})
    checks.append(check("protected_action_requires_auth", protected.status_code == 401, f"status={protected.status_code}"))

    print(json.dumps({"checks": checks}, indent=2))
    return 0 if all(item["ok"] for item in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
