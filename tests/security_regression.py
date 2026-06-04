from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import api
from auth import generate_token


def main() -> int:
    client = api.app.test_client()
    analyst_token = generate_token(
        {"id": 9001, "username": "analyst-test", "email": "analyst@example.local", "role": "analyst"}
    )
    admin_token = generate_token(
        {"id": 9002, "username": "admin-test", "email": "admin@example.local", "role": "admin"}
    )

    cases = []
    api._submit_pentest_task = lambda *args, **kwargs: None

    def record(name, response, expected):
        cases.append(
            {
                "name": name,
                "status": response.status_code,
                "expected": expected,
                "ok": response.status_code == expected,
            }
        )

    record("pentest_scan_no_auth", client.post("/pentest/scan", json={"target": "127.0.0.1"}), 401)
    record(
        "pentest_scan_analyst_allowed",
        client.post("/pentest/scan", json={"target": "127.0.0.1"}, headers={"Authorization": f"Bearer {analyst_token}"}),
        202,
    )
    record("blocked_ips_no_auth", client.get("/blocked-ips"), 401)
    record(
        "blocked_ips_analyst_ok",
        client.get("/blocked-ips", headers={"Authorization": f"Bearer {analyst_token}"}),
        200,
    )
    record(
        "action_block_analyst_forbidden",
        client.post(
            "/actions/block",
            json={"target": "127.0.0.1", "reason": "regression"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        ),
        403,
    )
    record(
        "action_block_bad_target",
        client.post(
            "/actions/block",
            json={"target": "127.0.0.1; whoami", "reason": "bad"},
            headers={"Authorization": f"Bearer {admin_token}"},
        ),
        400,
    )

    print(json.dumps({"cases": cases}, indent=2))
    return 0 if all(case["ok"] for case in cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
