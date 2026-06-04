from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from db import sync_get_actions, sync_init_pool
from host_actions import execute_host_action
from ips_enforcer import current_enforcement_profile


TEST_IP = "203.0.113.251"


def dump(label: str, payload) -> None:
    print(f"\n[{label}]")
    print(json.dumps(payload, indent=2, default=str))


def main() -> int:
    sync_init_pool(retries=1, retry_delay=0.2)

    profile = current_enforcement_profile()
    dump("ips_status", profile)
    if not profile.get("real_prevention_capable"):
        print("\n[failed] Real prevention is not capable in this process. Run from an Administrator terminal.")
        return 2

    cleanup, _ = execute_host_action(
        action="UNBLOCK",
        target=TEST_IP,
        reason="Pre-test cleanup",
        source="manual",
        trigger="firewall_path_test",
        actor_username="firewall_path_test",
        actor_role="admin",
    )
    dump("cleanup", cleanup)

    block_payload, block_status = execute_host_action(
        action="BLOCK",
        target=TEST_IP,
        reason="Real Windows Firewall path verification",
        source="manual",
        confidence=1.0,
        trigger="firewall_path_test",
        actor_username="firewall_path_test",
        actor_role="admin",
    )
    dump("block_payload", block_payload)

    latest_actions = sync_get_actions(limit=5)
    matching = [row for row in latest_actions if row.get("ip") == TEST_IP]
    latest = matching[0] if matching else None
    dump("latest_action_row", latest)

    unblock_payload, _ = execute_host_action(
        action="UNBLOCK",
        target=TEST_IP,
        reason="Post-test cleanup",
        source="manual",
        trigger="firewall_path_test",
        actor_username="firewall_path_test",
        actor_role="admin",
    )
    dump("unblock_payload", unblock_payload)

    passed = (
        block_status == 200
        and block_payload.get("enforcement_method") == "local_firewall:windows"
        and block_payload.get("verification_status") == "verified"
        and block_payload.get("real_block_applied") is True
        and block_payload.get("database_only") is False
        and latest
        and latest.get("enforcement_method") == "local_firewall:windows"
        and latest.get("verification_status") == "verified"
        and latest.get("real_block_applied") is True
        and latest.get("database_only") is False
    )
    print("\n[result]", "PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
