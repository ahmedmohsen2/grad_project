from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


BENIGN_LABELS = {"", "BENIGN", "NORMAL", "OK", "CLEAN", "NONE"}

ATTACK_LABEL_ALIASES = [
    (("DDOS", "D DOS", "DOS HULK", "DOS GOLDENEYE", "SLOWLORIS", "SLOWHTTPTEST", "HEARTBLEED"), "DDoS"),
    (("PORTSCAN", "PORT SCAN", "SCAN"), "PortScan"),
    (("BRUTEFORCE", "BRUTE FORCE", "FTP PATATOR", "SSH PATATOR", "PATATOR"), "BruteForce"),
    (("BOT", "BOTNET"), "Bot"),
    (("WEBATTACK", "WEB ATTACK", "SQL INJECTION", "XSS"), "WebAttack"),
    (("INFILTRATION",), "Infiltration"),
    (("MALWARE", "RANSOMWARE", "BEACON"), "Malware"),
]


def _clean_label(value: Any) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\(conf=.*?\)", "", text, flags=re.IGNORECASE)
    text = text.split(":", 1)[-1] if text.upper().startswith(("ML:", "ML+ISO:")) else text
    return re.sub(r"[_\-/]+", " ", text).strip()


def normalize_attack_label(value: Any, result: Any = None) -> str:
    cleaned = _clean_label(value)
    folded = re.sub(r"\s+", " ", cleaned).upper()

    if folded in BENIGN_LABELS:
        return "BENIGN"

    for aliases, canonical in ATTACK_LABEL_ALIASES:
        if any(alias in folded for alias in aliases):
            return canonical

    if result and normalize_detection_result(result, folded) == "NORMAL":
        return "BENIGN"

    return cleaned[:80] or "Unknown"


def normalize_detection_result(value: Any, attack_type: Any = None) -> str:
    folded = str(value or "").strip().upper()
    attack_folded = str(attack_type or "").strip().upper()

    if folded in {"ATTACK", "MALICIOUS", "ANOMALY", "CRITICAL", "HIGH"}:
        return "ATTACK"
    if folded in {"SUSPICIOUS", "WARNING", "MEDIUM"}:
        return "SUSPICIOUS"
    if folded in {"NORMAL", "BENIGN", "CLEAN", "OK"}:
        return "NORMAL"
    if attack_folded and attack_folded not in BENIGN_LABELS:
        return "ATTACK"
    return "NORMAL"


def normalize_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    text = str(value).strip()
    return text or None


def normalize_detection(row: dict[str, Any]) -> dict[str, Any]:
    result = normalize_detection_result(row.get("result") or row.get("label"), row.get("attack_type") or row.get("prediction"))
    attack_type = normalize_attack_label(
        row.get("attack_type") or row.get("prediction") or row.get("label"),
        result,
    )
    if result == "NORMAL":
        attack_type = "BENIGN"

    timestamp = normalize_timestamp(row.get("detected_at") or row.get("timestamp")) or datetime.now(timezone.utc).isoformat()
    src_ip = row.get("src_ip") or row.get("source_ip") or row.get("ip") or row.get("source")
    dst_ip = row.get("dst_ip") or row.get("destination_ip") or row.get("destination")

    canonical = {
        **row,
        "id": row.get("id"),
        "label": attack_type,
        "prediction": attack_type,
        "attack_type": attack_type,
        "result": result,
        "severity": row.get("severity") or result,
        "confidence": float(row.get("confidence") or 0.0),
        "timestamp": timestamp,
        "detected_at": timestamp,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }
    return canonical

