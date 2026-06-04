from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db import (
    sync_get_actions,
    sync_get_activity_logs,
    sync_get_alerts,
    sync_get_blocked_ips,
    sync_get_detections,
    sync_get_flows,
    sync_get_security_findings,
    sync_init_pool,
    sync_list_pentest_scans,
)


def main() -> int:
    if not sync_init_pool():
        print("DB unavailable. Backup export aborted.")
        return 2

    payload = {
        "exported_at": datetime.now(UTC).isoformat(),
        "alerts": sync_get_alerts(limit=500),
        "detections": sync_get_detections(limit=500),
        "flows": sync_get_flows(limit=500),
        "actions": sync_get_actions(limit=500),
        "blocked_ips": sync_get_blocked_ips(),
        "pentest_scans": sync_list_pentest_scans(limit=500),
        "security_findings": sync_get_security_findings(limit=500, include_resolved=True),
        "activity_logs": sync_get_activity_logs(limit=500),
    }
    out_dir = Path("backups")
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / f"fusion_strike_backup_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
    out_file.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(f"Backup exported: {out_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
