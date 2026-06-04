from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Callable, Optional

from auto_response_engine import auto_response_engine
from db import (
    sync_get_security_finding,
    sync_get_security_findings,
    sync_insert_alert,
    sync_upsert_security_finding,
)
from host_actions import execute_host_action


SEVERITY_BASE_SCORE = {
    "info": 10,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 90,
}

CONFIDENCE_WEIGHT = {
    "CONFIRMED": 1.0,
    "SUSPECTED": 0.82,
    "HEURISTIC": 0.55,
    "INFORMATIONAL": 0.25,
}


def utcnow_iso() -> str:
    return datetime.utcnow().isoformat()


def normalize_severity(value: str) -> str:
    normalized = str(value or "medium").strip().lower()
    return normalized if normalized in SEVERITY_BASE_SCORE else "medium"


def finding_fingerprint(target: str, vuln: dict) -> str:
    parts = [
        str(target or "").strip().lower(),
        str(vuln.get("title") or "").strip().lower(),
        str(vuln.get("affected_component") or "").strip().lower(),
        str(vuln.get("related_port") or "").strip().lower(),
        str(vuln.get("detection_method") or "").strip().lower(),
    ]
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:24]


def compute_risk_score(
    severity: str,
    confidence: float,
    *,
    classification: str = "SUSPECTED",
    related_port: int | None = None,
    persisted: bool = False,
    resolved: bool = False,
) -> int:
    base = SEVERITY_BASE_SCORE.get(normalize_severity(severity), 50)
    conf = max(0.0, min(1.0, float(confidence or 0.0)))
    class_name = str(classification or "SUSPECTED").upper()
    score = int(base * conf * CONFIDENCE_WEIGHT.get(class_name, 0.70))
    if related_port in {23, 445, 3389, 5900, 6379, 27017, 9200}:
        score += 10
    elif related_port in {21, 1433, 3306, 5432, 1521}:
        score += 6
    if persisted:
        score += 8
    if resolved:
        score -= 35
    return max(0, min(100, score))


def build_event(stage: str, label: str, details: str, status: str) -> dict:
    return {
        "stage": stage,
        "label": label,
        "details": details,
        "status": status,
        "time": utcnow_iso(),
    }


def build_alert_metadata(target: str, vuln: dict, finding_id: str) -> dict:
    return {
        "type": "pentest_finding",
        "severity": normalize_severity(vuln.get("severity")),
        "target": target,
        "confidence": float(vuln.get("confidence") or 0.0),
        "finding_id": finding_id,
        "title": vuln.get("title"),
        "affected_component": vuln.get("affected_component"),
        "classification": vuln.get("classification"),
        "validation_status": vuln.get("validation_status"),
        "evidence_source": vuln.get("evidence_source"),
        "related_port": vuln.get("related_port"),
        "protocol": vuln.get("protocol"),
        "detection_method": vuln.get("detection_method"),
    }


def _record_from_vuln(
    scan_id: str,
    target: str,
    vuln: dict,
    *,
    existing: Optional[dict] = None,
    status: str = "detected",
    mitigation_state: str = "unresolved",
    persisted: bool = False,
) -> dict:
    now = utcnow_iso()
    fingerprint = finding_fingerprint(target, vuln)
    finding_id = existing.get("finding_id") if existing else f"finding-{fingerprint}"
    timeline = list(existing.get("timeline") or []) if existing else []
    event_label = "Still Vulnerable" if persisted else "Detected"
    event_stage = "result" if persisted else "detection"
    timeline.append(
        build_event(
            event_stage,
            event_label,
            f"{vuln.get('title')} on {vuln.get('affected_component') or target}",
            status,
        )
    )
    severity = normalize_severity(vuln.get("severity"))
    confidence = float(vuln.get("confidence") or 0.0)
    metadata = {
        "last_scan_id": scan_id,
        "explainable": True,
        "safe_mode": True,
        "classification": vuln.get("classification") or "SUSPECTED",
        "validation_status": vuln.get("validation_status") or "requires_analyst_validation",
        "evidence_source": vuln.get("evidence_source"),
        "related_port": vuln.get("related_port"),
        "protocol": vuln.get("protocol"),
        "detection_method": vuln.get("detection_method"),
        "confidence_type": vuln.get("confidence_type"),
        "validation_label": vuln.get("validation_label"),
    }
    return {
        "finding_id": finding_id,
        "fingerprint": fingerprint,
        "scan_id": scan_id,
        "target": target,
        "title": vuln.get("title") or "Untitled finding",
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "mitigation_state": mitigation_state,
        "risk_score": compute_risk_score(
            severity,
            confidence,
            classification=metadata["classification"],
            related_port=metadata["related_port"],
            persisted=persisted,
        ),
        "affected_component": vuln.get("affected_component"),
        "description": vuln.get("description"),
        "evidence": vuln.get("evidence"),
        "remediation": vuln.get("remediation"),
        "source": "pentest",
        "action_type": existing.get("action_type") if existing else None,
        "action_reason": existing.get("action_reason") if existing else None,
        "action_source": existing.get("action_source") if existing else None,
        "revalidation_scan_id": existing.get("revalidation_scan_id") if existing else None,
        "last_action_at": existing.get("last_action_at") if existing else None,
        "last_retested_at": existing.get("last_retested_at") if existing else None,
        "first_seen_at": existing.get("first_seen_at") if existing else now,
        "last_seen_at": now,
        "resolved_at": None if mitigation_state != "mitigated" else now,
        "updated_at": now,
        "timeline": timeline,
        "metadata": metadata,
    }


def queue_revalidation_for_finding(
    finding_id: str,
    target: str,
    queue_scan: Callable[[str, str, str], Optional[str]],
) -> Optional[str]:
    finding = sync_get_security_finding(finding_id)
    if not finding:
        return None
    existing_scan_id = finding.get("revalidation_scan_id")
    if existing_scan_id:
        return existing_scan_id
    return queue_scan(target, "quick", f"revalidation:{finding_id}")


def apply_action_to_finding(
    finding_id: str,
    *,
    action: str,
    reason: str,
    source: str,
    confidence: float,
    queue_scan: Optional[Callable[[str, str, str], Optional[str]]] = None,
) -> Optional[dict]:
    finding = sync_get_security_finding(finding_id)
    if not finding:
        return None

    timeline = list(finding.get("timeline") or [])
    timeline.append(
        build_event(
            "response",
            "Action Taken",
            f"{action.upper()} applied in safe mode: {reason}",
            "action_taken",
        )
    )
    updated = {
        **finding,
        "status": "action_taken",
        "mitigation_state": "partially_mitigated",
        "action_type": action.upper(),
        "action_reason": reason,
        "action_source": source,
        "last_action_at": utcnow_iso(),
        "updated_at": utcnow_iso(),
        "timeline": timeline,
        "risk_score": max(0, int(finding.get("risk_score") or 0) - 10),
    }
    if queue_scan and action.upper() in {"BLOCK", "ISOLATE"}:
        updated["revalidation_scan_id"] = queue_revalidation_for_finding(finding_id, finding["target"], queue_scan)
    sync_upsert_security_finding(updated)
    return updated


def process_completed_scan(
    *,
    scan_id: str,
    target: str,
    triggered_by: str,
    result_dict: dict,
    queue_scan: Callable[[str, str, str], Optional[str]],
) -> list[dict]:
    vulnerabilities = list(result_dict.get("vulnerabilities") or [])
    existing_rows = sync_get_security_findings(limit=200, target=target, include_resolved=True)
    existing_by_fingerprint = {row.get("fingerprint"): row for row in existing_rows}
    existing_by_id = {row.get("finding_id"): row for row in existing_rows}
    saved_findings: list[dict] = []
    seen_fingerprints = set()

    revalidation_finding_id = None
    if str(triggered_by or "").startswith("revalidation:"):
        revalidation_finding_id = str(triggered_by).split(":", 1)[1]

    for vuln in vulnerabilities:
        fingerprint = finding_fingerprint(target, vuln)
        seen_fingerprints.add(fingerprint)
        existing = existing_by_fingerprint.get(fingerprint)
        persisted = revalidation_finding_id is not None and existing is not None
        record = _record_from_vuln(
            scan_id,
            target,
            vuln,
            existing=existing,
            status="still_vulnerable" if persisted else "detected",
            mitigation_state="unresolved",
            persisted=persisted,
        )
        sync_upsert_security_finding(record)
        saved_findings.append(record)

        if not existing:
            sync_insert_alert(
                target,
                "PENTEST_FINDING",
                f"Pentest observed {record['title']} on {target} ({record['severity']}, confidence {record['confidence']:.2f})",
                metadata=build_alert_metadata(target, vuln, record["finding_id"]),
            )
            classification = str((record.get("metadata") or {}).get("classification") or "SUSPECTED").upper()
            if classification == "CONFIRMED":
                decision = auto_response_engine.evaluate_finding(
                    {
                        "ip": target,
                        "severity": record["severity"],
                        "confidence": record["confidence"],
                        "title": record["title"],
                    }
                )
            else:
                decision = None
            if decision and decision.action:
                action_result, _ = execute_host_action(
                    action=decision.action,
                    target=target,
                    reason=decision.reason,
                    source="auto",
                    confidence=record["confidence"],
                    trigger="pentest_finding",
                )
                if action_result.get("status") == "success":
                    auto_response_engine.mark_action(str(target))
                    apply_action_to_finding(
                        record["finding_id"],
                        action=decision.action,
                        reason=decision.reason,
                        source="auto",
                        confidence=record["confidence"],
                        queue_scan=queue_scan,
                    )

    if revalidation_finding_id:
        original = existing_by_id.get(revalidation_finding_id) or sync_get_security_finding(revalidation_finding_id)
        if original:
            if original.get("fingerprint") in seen_fingerprints:
                refreshed = sync_get_security_finding(revalidation_finding_id)
                if refreshed:
                    timeline = list(refreshed.get("timeline") or [])
                    timeline.append(
                        build_event("retest", "Re-tested", "Pentest revalidation completed", "retested")
                    )
                    refreshed["timeline"] = timeline
                    refreshed["status"] = "still_vulnerable"
                    refreshed["mitigation_state"] = "unresolved"
                    refreshed["last_retested_at"] = utcnow_iso()
                    refreshed["updated_at"] = utcnow_iso()
                    refreshed["risk_score"] = compute_risk_score(
                        refreshed.get("severity"),
                        refreshed.get("confidence"),
                        classification=(refreshed.get("metadata") or {}).get("classification", "SUSPECTED"),
                        related_port=(refreshed.get("metadata") or {}).get("related_port"),
                        persisted=True,
                    )
                    sync_upsert_security_finding(refreshed)
            else:
                timeline = list(original.get("timeline") or [])
                timeline.append(
                    build_event("retest", "Re-tested", "Pentest revalidation completed", "retested")
                )
                timeline.append(
                    build_event("result", "Resolved", "Finding was not reproduced in the re-check", "resolved")
                )
                original["timeline"] = timeline
                original["status"] = "resolved"
                original["mitigation_state"] = "mitigated"
                original["last_retested_at"] = utcnow_iso()
                original["resolved_at"] = utcnow_iso()
                original["updated_at"] = utcnow_iso()
                original["risk_score"] = compute_risk_score(
                    original.get("severity"),
                    original.get("confidence"),
                    classification=(original.get("metadata") or {}).get("classification", "SUSPECTED"),
                    related_port=(original.get("metadata") or {}).get("related_port"),
                    resolved=True,
                )
                sync_upsert_security_finding(original)

    return sync_get_security_findings(limit=100, target=target, include_resolved=True)
