from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db import (
    sync_get_alerts,
    sync_get_detections,
    sync_init_pool,
    sync_insert_action,
    sync_insert_alert,
    sync_insert_blocked_ip,
    sync_insert_detection,
    sync_insert_pentest_scan,
    sync_insert_activity_log,
    sync_update_pentest_scan,
)


DEMO_SCAN_ID = "demo-pentest-001"


def main() -> int:
    if not sync_init_pool():
        print("DB unavailable. Start PostgreSQL and retry.")
        return 2

    existing_alerts = sync_get_alerts(limit=5)
    existing_detections = sync_get_detections(limit=5)
    if existing_alerts and existing_detections:
        print("Demo seed skipped: database already contains alerts and detections.")
        return 0

    detections = [
        ("10.10.10.24", "ATTACK", "DDoS", 0.94, 1),
        ("10.10.10.42", "SUSPICIOUS", "BruteForce", 0.78, 0),
        ("10.10.10.77", "ATTACK", "WebAttack/Malware", 0.88, 1),
    ]
    for row in detections:
        sync_insert_detection(*row)

    alerts = [
        ("10.10.10.24", "ATTACK", "High packet-rate DDoS pattern detected", {"severity": "high"}),
        ("10.10.10.42", "SUSPICIOUS", "Repeated failed authentication pattern", {"severity": "medium"}),
        ("10.10.10.77", "PENTEST_FINDING", "SAFE MODE pentest found simulated SQL injection indicator", {"severity": "high"}),
    ]
    for alert in alerts:
        sync_insert_alert(*alert)

    sync_insert_blocked_ip("10.10.10.24", "Demo containment for high-confidence DDoS")
    sync_insert_action("10.10.10.24", "BLOCK", "Auto-response containment demo", "auto", 0.94)

    sync_insert_pentest_scan(DEMO_SCAN_ID, "127.0.0.1", "quick", "demo_seed")
    now = datetime.utcnow().isoformat()
    sync_update_pentest_scan(
        DEMO_SCAN_ID,
        status="completed",
        progress=100,
        current_stage="report",
        completed_at=now,
        results={
            "safe_mode": True,
            "mode_notice": "SAFE MODE / LAB VALIDATION - simulated indicators require manual validation",
            "vulnerabilities": [
                {
                    "title": "Simulated SQL Injection Indicator",
                    "severity": "high",
                    "confidence": 0.72,
                    "confidence_type": "heuristic",
                    "validation_label": "simulated",
                    "affected_component": "web:input_fields",
                    "remediation": "Use parameterized queries and server-side validation.",
                }
            ],
            "report": {
                "executive_summary": "Demo SAFE MODE pentest completed. Findings are simulated indicators, not confirmed exploitation.",
                "risk_score": 64,
                "risk_level": "high",
                "recommendations": ["Validate simulated findings manually before production remediation."],
            },
            "pipeline_stages": [
                {"stage_name": "recon", "status": "completed"},
                {"stage_name": "scan", "status": "completed"},
                {"stage_name": "vulnerability_analysis", "status": "completed"},
                {"stage_name": "strategy", "status": "completed"},
                {"stage_name": "execute", "status": "completed"},
                {"stage_name": "report", "status": "completed"},
            ],
        },
    )
    sync_insert_activity_log(
        {
            "type": "demo",
            "action": "seed_data_loaded",
            "target": "platform",
            "reason": "Demo-ready SOC and pentest records inserted",
            "source": "demo_seed",
            "status": "success",
            "metadata": {"scan_id": DEMO_SCAN_ID},
        }
    )
    print(json.dumps({"seeded": True, "demo_scan_id": DEMO_SCAN_ID}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
