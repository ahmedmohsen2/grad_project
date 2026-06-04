from __future__ import annotations

from datetime import datetime
from typing import Optional

from db import (
    sync_get_action_control,
    sync_insert_action,
    sync_insert_activity_log,
    sync_insert_alert,
    sync_insert_blocked_ip,
    sync_remove_blocked_ip,
    sync_upsert_action_control,
    sync_upsert_host,
    sync_update_host_status,
)
from ips_enforcer import enforce


ACTION_PRIORITY = {"auto": 1, "manual": 2}


def default_action_state(target: str) -> dict:
    return {
        "target": target,
        "is_blocked": False,
        "is_isolated": False,
        "is_whitelisted": False,
        "is_quarantined": False,
        "last_action": "NONE",
        "reason": "",
        "source": "manual",
        "confidence": 0.0,
        "trigger": "manual",
        "updated_at": None,
    }


def get_action_state(target: str) -> dict:
    return sync_get_action_control(target) or default_action_state(target)


def _priority_of(source: str) -> int:
    return ACTION_PRIORITY.get((source or "").lower(), 0)


def execute_host_action(
    *,
    action: str,
    target: str,
    reason: str,
    source: str,
    confidence: float = 0.0,
    trigger: Optional[str] = None,
    actor_username: str = "system",
    actor_role: str = "service",
) -> tuple[dict, int]:
    action_upper = (action or "").upper().strip()
    normalized_target = (target or "").strip()
    normalized_source = (source or "manual").lower().strip()
    normalized_trigger = (trigger or normalized_source).lower().strip()
    normalized_reason = (reason or f"{normalized_source.title()} {action_upper.lower()} action").strip()
    normalized_actor_username = (actor_username or "unknown").strip()
    normalized_actor_role = (actor_role or "unknown").strip().lower()

    if not normalized_target:
        return {"error": "Target is required"}, 400

    if action_upper not in {"BLOCK", "ISOLATE", "WHITELIST", "UNBLOCK", "UNISOLATE"}:
        return {"error": f"Unsupported action: {action}"}, 400

    existing = get_action_state(normalized_target)
    needs_real_enforcement_upgrade = (
        action_upper in {"BLOCK", "ISOLATE"}
        and (
            bool(existing.get("database_only", False))
            or existing.get("verification_status") in {None, "", "unknown", "database_only", "failed"}
            or not bool(existing.get("real_block_applied", False))
        )
    )
    if (
        existing.get("last_action") not in (None, "NONE")
        and _priority_of(normalized_source) < _priority_of(existing.get("source", "manual"))
        and not needs_real_enforcement_upgrade
    ):
        # Log the skip so analysts can see why the action was suppressed
        sync_insert_activity_log({
            "type": "auto_action" if normalized_source == "auto" else "manual_action",
            "action": action_upper.lower(),
            "target": normalized_target,
            "reason": "Action skipped — manual override is active",
            "source": normalized_source,
            "status": "skipped",
            "metadata": {
                "confidence": confidence,
                "trigger": normalized_trigger,
                "override_source": existing.get("source"),
                "actor_username": normalized_actor_username,
                "actor_role": normalized_actor_role,
                "origin": normalized_source,
            },
        })
        return {
            "status": "skipped",
            "action": action_upper.lower(),
            "target": normalized_target,
            "message": "Manual action override is active",
            "state": existing,
            "log": {
                "action": action_upper.lower(),
                "target": normalized_target,
                "timestamp": datetime.utcnow().isoformat(),
                "source": normalized_source,
                "actor_username": normalized_actor_username,
                "actor_role": normalized_actor_role,
            },
        }, 200

    host_status = "CLEAN"
    alert_type = None
    alert_message = None
    persistence_errors: list[str] = []
    enforcement = enforce(action_upper, normalized_target)
    enforcement_verified = enforcement.get("verification_status") == "verified"
    enforcement_message = enforcement.get("message") or enforcement.get("error_reason") or ""

    if action_upper == "BLOCK":
        if not sync_insert_blocked_ip(normalized_target, normalized_reason):
            persistence_errors.append("blocked_ips")
        host_status = "BLOCKED"
        alert_type = "BLOCK"
        alert_message = f"Firewall block enforced for {normalized_target}: {normalized_reason}"
        message = "Host blocked successfully"

    elif action_upper == "ISOLATE":
        host_status = "ISOLATED"
        alert_type = "ISOLATE"
        alert_message = f"Host isolation enforced for {normalized_target}: {normalized_reason}"
        message = "Host isolated successfully"
    elif action_upper == "WHITELIST":
        if not sync_remove_blocked_ip(normalized_target):
            persistence_errors.append("blocked_ips")
        host_status = "TRUSTED"
        message = "Host whitelisted successfully"
    elif action_upper == "UNBLOCK":
        if not sync_remove_blocked_ip(normalized_target):
            persistence_errors.append("blocked_ips")
        host_status = "CLEAN"
        message = "Host unblocked successfully"
    else:
        if not sync_remove_blocked_ip(normalized_target):
            persistence_errors.append("blocked_ips")
        host_status = "CLEAN"
        message = "Host removed from isolation successfully"

    if not sync_upsert_host(normalized_target, host_status):
        persistence_errors.append("hosts")
    if not sync_update_host_status(normalized_target, host_status):
        persistence_errors.append("host_status")

    if alert_type and alert_message:
        alert_ok = sync_insert_alert(
            normalized_target,
            alert_type,
            alert_message,
            metadata={
                "severity": "HIGH" if action_upper == "BLOCK" else "MEDIUM",
                "source": normalized_source,
                "confidence": confidence,
                "action": action_upper,
                "trigger": normalized_trigger,
                "host_status": host_status,
                "actor_username": normalized_actor_username,
                "actor_role": normalized_actor_role,
            },
        )
        if not alert_ok:
            persistence_errors.append("alerts")

    stored_action = "WHITELIST" if action_upper == "WHITELIST" else action_upper
    if not sync_upsert_action_control(
        normalized_target,
        action=stored_action,
        reason=normalized_reason,
        source=normalized_source,
        confidence=confidence,
        trigger=normalized_trigger,
        enforcement_method=enforcement.get("enforcement_method", "database"),
        verification_status=enforcement.get("verification_status", "unknown"),
        real_block_applied=bool(enforcement.get("real_block_applied")),
        database_only=bool(enforcement.get("database_only", True)),
        inline_block=bool(enforcement.get("inline_block")),
        gateway_block=bool(enforcement.get("gateway_block")),
        rule_exists=bool(enforcement.get("rule_exists")),
        command_status=enforcement.get("command_status", "unknown"),
        enforcement_message=enforcement_message,
    ):
        persistence_errors.append("action_controls")
    if not sync_insert_action(
        normalized_target,
        stored_action,
        normalized_reason,
        normalized_source,
        confidence,
        normalized_actor_username,
        normalized_actor_role,
        enforcement.get("enforcement_method", "database"),
        enforcement.get("verification_status", "unknown"),
        bool(enforcement.get("real_block_applied")),
        bool(enforcement.get("database_only", True)),
        bool(enforcement.get("inline_block")),
        bool(enforcement.get("gateway_block")),
        bool(enforcement.get("rule_exists")),
        enforcement.get("command_status", "unknown"),
        enforcement_message,
    ):
        persistence_errors.append("actions")

    state = get_action_state(normalized_target)

    # ── Write to Activity Timeline ────────────────────────────────────────────
    event_type = "auto_action" if normalized_source == "auto" else "manual_action"
    if not sync_insert_activity_log({
        "type": event_type,
        "action": action_upper.lower(),
        "target": normalized_target,
        "reason": normalized_reason,
        "source": normalized_source,
        "status": "success" if enforcement_verified or bool(enforcement.get("database_only")) else "failed",
            "metadata": {
                "confidence": confidence,
                "trigger": normalized_trigger,
                "host_status": host_status,
                "alert_type": alert_type,
                "actor_username": normalized_actor_username,
                "actor_role": normalized_actor_role,
                "origin": normalized_source,
                "enforcement": enforcement,
                "persistence_errors": persistence_errors,
            },
        }):
        persistence_errors.append("activity_logs")

    if persistence_errors and set(persistence_errors) - {"blocked_ips"}:
        return {
            "status": "failed",
            "action": action_upper.lower(),
            "target": normalized_target,
            "message": "Action execution was not fully persisted",
            "errors": persistence_errors,
            "state": state,
        }, 500

    if action_upper in {"BLOCK", "ISOLATE", "UNBLOCK", "UNISOLATE", "WHITELIST"} and not enforcement_verified and not bool(enforcement.get("database_only")):
        return {
            "status": "failed",
            "action": action_upper.lower(),
            "target": normalized_target,
            "message": "Firewall enforcement failed",
            "error": enforcement_message,
            "host_status": host_status,
            "state": state,
            "enforcement": enforcement,
            "enforcement_method": enforcement.get("enforcement_method", "database"),
            "verification_status": enforcement.get("verification_status", "unknown"),
            "real_block_applied": bool(enforcement.get("real_block_applied")),
            "database_only": bool(enforcement.get("database_only", True)),
            "inline_block": bool(enforcement.get("inline_block")),
            "gateway_block": bool(enforcement.get("gateway_block")),
            "rule_exists": bool(enforcement.get("rule_exists")),
            "command_status": enforcement.get("command_status", "unknown"),
            "persistence_warnings": persistence_errors,
        }, 500

    return {
        "status": "success",
        "action": action_upper.lower(),
        "target": normalized_target,
        "message": message,
        "host_status": host_status,
        "state": state,
        "enforcement": enforcement,
        "enforcement_method": enforcement.get("enforcement_method", "database"),
        "verification_status": enforcement.get("verification_status", "unknown"),
        "real_block_applied": bool(enforcement.get("real_block_applied")),
        "database_only": bool(enforcement.get("database_only", True)),
        "inline_block": bool(enforcement.get("inline_block")),
        "gateway_block": bool(enforcement.get("gateway_block")),
        "rule_exists": bool(enforcement.get("rule_exists")),
        "command_status": enforcement.get("command_status", "unknown"),
        "enforcement_message": enforcement_message,
        "persistence_warnings": persistence_errors,
        "log": {
            "action": action_upper.lower(),
            "target": normalized_target,
            "timestamp": state.get("updated_at") or datetime.utcnow().isoformat(),
            "source": normalized_source,
            "reason": normalized_reason,
            "confidence": confidence,
            "trigger": normalized_trigger,
            "actor_username": normalized_actor_username,
            "actor_role": normalized_actor_role,
            "origin": normalized_source,
            "enforcement_method": enforcement.get("enforcement_method", "database"),
            "verification_status": enforcement.get("verification_status", "unknown"),
        },
    }, 200
