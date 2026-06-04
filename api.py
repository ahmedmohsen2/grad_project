import os
import threading
import atexit
import ipaddress
import time
import json
import subprocess
from datetime import datetime
import sys as _sys
import asyncio as _asyncio

# FIXED: On Windows, subprocesses (e.g., Nmap) require the ProactorEventLoop.
# We set this policy globally at the absolute start of the process.
if _sys.platform == "win32":
    try:
        _asyncio.set_event_loop_policy(_asyncio.WindowsProactorEventLoopPolicy())
    except Exception:
        pass

import joblib
import pandas as pd
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from db import (
    sync_insert_detection  as insert_detection,
    sync_insert_flow,
    sync_db_ping           as db_ping,
    sync_get_alerts        as get_alerts,
    sync_mark_alert_read   as mark_alert_read,
    sync_mark_all_alerts_read as mark_all_alerts_read,
    sync_get_detections    as get_detections,
    sync_get_flows         as get_flows,
    sync_get_actions       as get_actions,
    sync_get_blocked_ips   as get_blocked_ips,
    sync_insert_action,
    sync_insert_blocked_ip,
    sync_remove_blocked_ip,
    sync_upsert_host,
    sync_update_host_status,
    sync_insert_alert,
    sync_upsert_action_control,
    sync_get_action_control,
    sync_get_security_findings,
    sync_insert_activity_log,
    sync_upsert_ips_validation_test,
    sync_get_ips_validation_tests,
    sync_clear_ips_validation_tests,
    sync_init_pool,
)

from config import (
    AUTO_RESPONSE_ENABLED,
    THRESHOLD_HIGH_ATTACK,
    THRESHOLD_MEDIUM_ATTACK,
    THRESHOLD_SUSPICIOUS,
    ATTACK_CLASS_NAMES,
    API_HOST,
    API_PORT,
    CORS_ORIGINS,
    DEBUG,
)
from auto_response_engine import auto_response_engine
from closed_loop_lifecycle import apply_action_to_finding, process_completed_scan
from host_actions import default_action_state, execute_host_action, get_action_state
from pentest_agent.config import PENTEST_MODE
from auth import normalize_role, require_auth, require_role, optional_auth, auth_bp
from detection_schema import normalize_attack_label, normalize_detection, normalize_detection_result
from performance_monitor import (
    BANDWIDTH_PROFILES,
    apply_bandwidth_delay,
    normalize_bandwidth_profile,
    performance_monitor,
)
from ips_enforcer import current_enforcement_profile, firewall_rule_name, firewall_self_test, verify_firewall_rule
from network_sensor import read_sensor_status

app = Flask(__name__)

# Allow the configured dashboard origins to reach the API.
CORS(app, resources={r"/*": {"origins": CORS_ORIGINS}}, supports_credentials=True)

# Register the auth blueprint — provides /auth/signup, /auth/login, /auth/me
app.register_blueprint(auth_bp)


@app.before_request
def _start_request_timer():
    request._started_at = time.perf_counter()
    profile = normalize_bandwidth_profile(request.headers.get("X-Bandwidth-Profile"))
    request._bandwidth_profile = profile
    request._bandwidth_delay_ms = apply_bandwidth_delay(
        profile,
        payload_bytes=int(request.content_length or 0),
    )


@app.after_request
def _record_request_timer(response):
    started = getattr(request, "_started_at", None)
    if started is not None:
        elapsed_ms = (time.perf_counter() - started) * 1000
        profile = getattr(request, "_bandwidth_profile", "unlimited")
        performance_monitor.record(
            "api_response_time",
            elapsed_ms,
            method=request.method,
            path=request.path,
            status=response.status_code,
            bandwidth_profile=profile,
            simulated_delay_ms=getattr(request, "_bandwidth_delay_ms", 0),
        )
        response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.2f}"
        response.headers["X-Bandwidth-Profile"] = profile
    return response

# ==============================================================================
# Startup: DB Pool Initialization
# ==============================================================================
import logging as _logging
_startup_log = _logging.getLogger("API")
log = _logging.getLogger("api.routes")   # used throughout route handlers


_db_ready = sync_init_pool(retries=3, retry_delay=2.0)

if _db_ready:
    _startup_log.info("[API] DB pool ready — logging server_started event.")
    sync_insert_activity_log(
        {
            "type": "system",
            "action": "server_started",
            "target": API_HOST,
            "reason": "Flask API server initialized",
            "source": "system",
            "status": "success",
            "metadata": {"port": API_PORT},
        }
    )
else:
    _startup_log.critical(
        "[API] DB pool NOT ready — server is running in DEGRADED mode. "
        "All DB-backed endpoints will return empty data. "
        "Start PostgreSQL and restart api.py."
    )


def _validate_ip_or_host(value: str, *, allow_hostname: bool = True) -> tuple[bool, str]:
    text = str(value or "").strip()
    if not text or len(text) > 253:
        return False, "Target is required and must be shorter than 254 characters"
    if any(ch in text for ch in "\\\r\n\t ;|&`$<>"):
        return False, "Target contains invalid shell/control characters"
    host = text
    for prefix in ("http://", "https://"):
        if host.lower().startswith(prefix):
            host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(host)
        return True, ""
    except ValueError:
        pass
    if not allow_hostname:
        return False, "A valid IP address is required"
    if not all(part and len(part) <= 63 for part in host.split(".")):
        return False, "Invalid hostname"
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
    if not set(host) <= allowed:
        return False, "Invalid hostname characters"
    return True, ""


def _validate_reason(value: str, default: str) -> str:
    text = str(value or default).strip()
    text = " ".join(text.split())
    return text[:240] or default

# ==============================================================================
# Load Models (with safety)
# ==============================================================================
def safe_load(path):
    if not os.path.exists(path):
        raise Exception(f"Model file not found: {path}")
    return joblib.load(path)


_MULTICLASS_PATH = "xgb_model_multiclass.pkl"
_use_multiclass = os.path.exists(_MULTICLASS_PATH)

if _use_multiclass:
    _startup_log.info("[API] Multi-class model loaded")
    xgb_model = safe_load(_MULTICLASS_PATH)
    scaler = safe_load("xgb_model_multiclass_scaler.pkl")
    columns = safe_load("xgb_model_multiclass_columns.pkl")
    MODEL_MODE = "multiclass"
else:
    _startup_log.info("[API] Binary model loaded")
    xgb_model = safe_load("xgb_model.pkl")
    scaler = safe_load("scaler.pkl")
    columns = safe_load("columns.pkl")
    MODEL_MODE = "binary"

iso_model = safe_load("iso_model.pkl")


# ==============================================================================
# Preprocess
# ==============================================================================
def preprocess(sample_dict: dict):
    if not isinstance(sample_dict, dict):
        raise Exception("Input must be JSON object")

    df = pd.DataFrame([sample_dict])
    df.columns = df.columns.str.strip()

    df.drop(columns=[
        'Flow ID', 'Source IP', 'Destination IP', 'Timestamp',
        'Flow Bytes/s', 'Flow Packets/s',
        'Fwd Packets/s', 'Bwd Packets/s',
    ], inplace=True, errors='ignore')

    full_df = pd.DataFrame(columns=columns)

    for col in df.columns:
        if col in full_df.columns:
            full_df.loc[0, col] = df[col].values[0]

    full_df = full_df.fillna(0)

    try:
        full_df = full_df.astype(float)
    except Exception as e:
        raise Exception(f"Data type error: {e}")

    return scaler.transform(full_df)


# ==============================================================================
# Predict Endpoint
# ==============================================================================
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No JSON received"}), 400

        log.debug("predict payload received: %s", data)

        detection_started = time.perf_counter()
        sample = preprocess(data)

        # ISO
        inference_started = time.perf_counter()
        iso_raw = iso_model.predict(sample)[0]
        iso = 1 if iso_raw == -1 else 0

        if _use_multiclass:
            class_id = int(xgb_model.predict(sample)[0])
            proba = xgb_model.predict_proba(sample)[0]
            confidence = float(max(proba))

            attack_type = ATTACK_CLASS_NAMES.get(class_id, f"class_{class_id}")
            attack_safe = attack_type.encode("ascii", "ignore").decode().strip()

            if class_id == 0:
                if iso == 1 and confidence < THRESHOLD_SUSPICIOUS:
                    result = "SUSPICIOUS"
                else:
                    result = "NORMAL"
                    attack_safe = "BENIGN"
            else:
                if confidence >= THRESHOLD_MEDIUM_ATTACK:
                    result = "ATTACK"
                elif confidence >= THRESHOLD_SUSPICIOUS:
                    result = "SUSPICIOUS"
                else:
                    result = "SUSPICIOUS"

        else:
            prob = float(xgb_model.predict_proba(sample)[0][1])
            class_id = 1 if prob >= 0.5 else 0
            confidence = prob

            if prob > THRESHOLD_HIGH_ATTACK:
                result = "ATTACK"
            elif prob > THRESHOLD_MEDIUM_ATTACK:
                result = "SUSPICIOUS"
            else:
                result = "NORMAL"

            attack_safe = "BINARY"

        inference_ms = (time.perf_counter() - inference_started) * 1000
        detection_ms = (time.perf_counter() - detection_started) * 1000
        performance_monitor.record(
            "ai_inference_time",
            inference_ms,
            model_mode=MODEL_MODE,
            attack_type=attack_safe,
            result=result,
        )
        performance_monitor.record(
            "detection_latency",
            detection_ms,
            model_mode=MODEL_MODE,
            attack_type=attack_safe,
            result=result,
        )

        log.info("prediction result=%s confidence=%.3f iso=%s", result, confidence, iso)

        # ── [DB] Store detection result (non-blocking daemon thread) ──────────
        src_ip = (
            data.get("Src IP")
            or data.get("Source IP")
            or data.get("src_ip")
            or "unknown"
        )

        def _store():
            insert_detection(
                src_ip      = str(src_ip),
                result      = result,
                attack_type = attack_safe,
                confidence  = confidence,
                iso_flag    = iso,
            )
            # ── Alert event → Activity Timeline ───────────────────────────────
            if result in ("ATTACK", "SUSPICIOUS"):
                sync_insert_activity_log({
                    "type": "alert",
                    "action": result.lower(),
                    "target": str(src_ip),
                    "reason": (
                        f"{attack_safe} detected with {confidence:.0%} confidence"
                        f"{' (Isolation Forest anomaly)' if iso else ''}"
                    ),
                    "source": "ml_detector",
                    "status": "success" if result == "ATTACK" else "pending",
                    "metadata": {
                        "attack_type": attack_safe,
                        "confidence": confidence,
                        "iso_flag": iso,
                        "result": result,
                    },
                })

        threading.Thread(target=_store, daemon=True).start()
        pps = (
            data.get("Packets per Second")
            or data.get("pps")
            or data.get("Flow Packets/s")
            or 0
        )
        history = auto_response_engine.record_event(
            {
                "ip": str(src_ip),
                "confidence": confidence,
                "attack_type": attack_safe,
                "pps": pps,
            }
        )
        auto_decision = auto_response_engine.evaluate(
            {
                "ip": str(src_ip),
                "confidence": confidence,
                "attack_type": attack_safe,
                "pps": pps,
                "history": history,
            }
        )
        auto_action_result = None
        if auto_decision.action:
            auto_action_result, _ = execute_host_action(
                action=auto_decision.action,
                target=str(src_ip),
                reason=auto_decision.reason,
                source="auto",
                confidence=confidence,
                trigger="auto",
            )
            if auto_action_result.get("status") == "success":
                auto_response_engine.mark_action(str(src_ip))
        # ─────────────────────────────────────────────────────────────────────

        return jsonify({
            "result":      result,
            "attack_type": attack_safe,
            "confidence":  confidence,
            "iso_flag":    iso,
            "class_id":    class_id,
            "model_mode":  MODEL_MODE,
            "timing": {
                "ai_inference_ms": round(inference_ms, 3),
                "detection_latency_ms": round(detection_ms, 3),
            },
            "auto_response": {
                "enabled": auto_response_engine.status()["enabled"],
                "decision": auto_decision.action,
                "reason": auto_decision.reason,
                "history": history,
                "action_result": auto_action_result,
            },
        })

    except Exception as e:
        log.exception("predict failed")
        return jsonify({
            "error": str(e),
            "result": "ERROR"
        }), 500


# ==============================================================================
# Health + Platform Info
# ==============================================================================
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "platform": "Fusion Strike AI — SOC Command Center",
        "version":  "2.0.0",
        "status":   "operational",
        "endpoints": [
            "/health", "/stats", "/detections", "/flows",
            "/alerts", "/actions", "/blocked-ips",
            "/network/visibility", "/ips/status", "/ips/self-test",
            "/ips/validation-test", "/ips/validation-test/status",
            "/pentest/scan", "/pentest/scans",
            "/pentest/findings", "/activity/logs",
            "/auth/login", "/auth/signup",
        ],
    })


@app.route("/health", methods=["GET"])
def health():
    db_ok = bool(db_ping())
    ips_profile = current_enforcement_profile()
    status = "ok" if db_ok else "degraded"
    return jsonify({
        "status":                status,
        "model_mode":            MODEL_MODE,
        "db_status":             "ok" if db_ok else "unavailable",
        "auto_response_enabled": auto_response_engine.status()["enabled"],
        "pentest_mode":          PENTEST_MODE,
        "capture":               _capture_status(),
        "network_visibility":     read_sensor_status(),
        "ips_enforcement":        ips_profile,
        "startup_self_test": {
            "admin_privileges": ips_profile.get("admin_privileges"),
            "firewall_available": ips_profile.get("firewall_available"),
            "firewall_enabled": ips_profile.get("firewall_enabled"),
            "firewall_backend": ips_profile.get("firewall_backend"),
            "real_prevention_capable": ips_profile.get("real_prevention_capable"),
            "message": ips_profile.get("backend_status_message") or ips_profile.get("firewall_status_message"),
        },
    }), (200 if db_ok else 503)


@app.route("/ips/status", methods=["GET"])
@optional_auth
def ips_status():
    return jsonify(current_enforcement_profile()), 200


@app.route("/ips/self-test", methods=["POST", "GET"])
@require_role("admin")
def ips_self_test():
    data = request.get_json(silent=True) or {}
    test_ip = str(data.get("ip") or request.args.get("ip") or "203.0.113.250").strip()
    ok, reason_text = _validate_ip_or_host(test_ip, allow_hostname=False)
    if not ok:
        return jsonify({"success": False, "error": reason_text}), 400
    result = firewall_self_test(test_ip)
    return jsonify(result), (200 if result.get("success") else 500)


def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat()


def _safe_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _build_ips_validation_record(test_id: str, source_ip: str, **updates) -> dict:
    record = {
        "test_id": test_id,
        "source_ip": source_ip,
        "status": "running",
        "phase": "queued",
        "traffic_generated": 0,
        "flows_generated": 0,
        "detection_triggered": False,
        "auto_response_action": None,
        "block_executed": False,
        "firewall_rule_created": False,
        "verification_passed": False,
        "retest_denied": False,
        "detection_timestamp": None,
        "block_timestamp": None,
        "verification_timestamp": None,
        "rule_name": firewall_rule_name(source_ip),
        "rule_exists": False,
        "command_status": "unknown",
        "enforcement_method": current_enforcement_profile().get("enforcement_method", "database"),
        "verification_status": "unknown",
        "real_block_applied": False,
        "report": {},
    }
    record.update(updates)
    return record


@app.route("/ips/validation-test", methods=["POST"])
@require_role("admin")
def ips_validation_test_start():
    data = request.get_json(silent=True) or {}
    source_ip = str(data.get("source_ip") or data.get("ip") or "203.0.113.250").strip()
    ok, reason_text = _validate_ip_or_host(source_ip, allow_hostname=False)
    if not ok:
        return jsonify({"success": False, "error": reason_text}), 400

    flows_to_generate = _safe_int(data.get("flows"), 25, 2, 250)
    packets_per_flow = _safe_int(data.get("packets_per_flow"), 80, 1, 5000)
    pps = _safe_int(data.get("pps"), 250, 1, 100000)
    dst_ip = str(data.get("destination_ip") or "198.51.100.10").strip()
    dst_ok, dst_reason = _validate_ip_or_host(dst_ip, allow_hostname=False)
    if not dst_ok:
        return jsonify({"success": False, "error": f"Invalid destination_ip: {dst_reason}"}), 400

    test_id = f"ipsval-{_uuid.uuid4().hex[:12]}"
    started_at = _utc_now_iso()
    report = {
        "test_id": test_id,
        "source_ip": source_ip,
        "destination_ip": dst_ip,
        "started_at": started_at,
        "safety": {
            "mode": "synthetic_flow_events",
            "offensive_functionality": False,
            "notes": "No DDoS, brute-force, malware, exploit, or packet flood tool is executed.",
        },
        "phases": [],
    }

    record = _build_ips_validation_record(test_id, source_ip, phase="phase_1_traffic", report=report)
    sync_upsert_ips_validation_test(record)

    generated_packets = 0
    generated_bytes = 0
    for index in range(flows_to_generate):
        packets = packets_per_flow + (index % 5)
        bytes_ = packets * 96
        generated_packets += packets
        generated_bytes += bytes_
        sync_insert_flow(source_ip, dst_ip, packets, bytes_, pps, 1.0)
        auto_response_engine.record_event({
            "ip": source_ip,
            "confidence": 0.99,
            "attack_type": "ddos",
            "pps": pps,
        })

    report["phases"].append({
        "phase": 1,
        "name": "Traffic generated",
        "status": "passed",
        "flows_generated": flows_to_generate,
        "packets_generated": generated_packets,
        "bytes_generated": generated_bytes,
        "pps": pps,
    })
    record.update({
        "phase": "phase_2_detection",
        "traffic_generated": generated_packets,
        "flows_generated": flows_to_generate,
        "report": report,
    })
    sync_upsert_ips_validation_test(record)

    detection_timestamp = _utc_now_iso()
    insert_detection(source_ip, "ATTACK", "DDoS", 0.99, 1)
    sync_insert_alert(
        source_ip,
        "ATTACK",
        f"IPS validation high-volume synthetic traffic detected for {source_ip}",
        metadata={
            "source": "ips_validation_test",
            "test_id": test_id,
            "confidence": 0.99,
            "pps": pps,
            "flows_generated": flows_to_generate,
            "safe_validation": True,
        },
    )
    report["phases"].append({
        "phase": 2,
        "name": "Detection triggered",
        "status": "passed",
        "timestamp": detection_timestamp,
        "alert_created": True,
        "attack_type": "DDoS",
        "confidence": 0.99,
    })

    history = auto_response_engine.record_event({
        "ip": source_ip,
        "confidence": 0.99,
        "attack_type": "ddos",
        "pps": pps,
    })
    auto_decision = auto_response_engine.evaluate({
        "ip": source_ip,
        "confidence": 0.99,
        "attack_type": "ddos",
        "pps": pps,
        "history": history,
    })
    if auto_decision.action != "BLOCK":
        report["phases"].append({
            "phase": 3,
            "name": "Auto response",
            "status": "failed",
            "decision": auto_decision.action,
            "reason": auto_decision.reason,
        })
        record.update({
            "status": "failed",
            "phase": "phase_3_auto_response",
            "detection_triggered": True,
            "detection_timestamp": detection_timestamp,
            "auto_response_action": auto_decision.action,
            "report": report,
        })
        sync_upsert_ips_validation_test(record)
        return jsonify({"success": False, "validation": record, "report": report}), 409

    block_timestamp = _utc_now_iso()
    action_result, action_status = execute_host_action(
        action="BLOCK",
        target=source_ip,
        reason="IPS enforcement validation: safe high-volume synthetic traffic exceeded policy threshold",
        source="auto",
        confidence=0.99,
        trigger="ips_validation_test",
        actor_username="ips_validation_test",
        actor_role="service",
    )
    if action_result.get("status") == "success":
        auto_response_engine.mark_action(source_ip)

    enforcement = action_result.get("enforcement") or {}
    block_ok = action_status == 200 and action_result.get("status") == "success"
    report["phases"].append({
        "phase": 3,
        "name": "Auto response BLOCK",
        "status": "passed" if block_ok else "failed",
        "timestamp": block_timestamp,
        "decision": "BLOCK",
        "action_status": action_result.get("status"),
        "message": action_result.get("message"),
        "enforcement": enforcement,
    })

    verification_timestamp = _utc_now_iso()
    verification = verify_firewall_rule(source_ip)
    rule_exists = bool(verification.get("rule_exists"))
    verification_passed = (
        block_ok
        and rule_exists
        and enforcement.get("verification_status") == "verified"
        and bool(enforcement.get("real_block_applied"))
    )
    retest_denied = verification_passed
    report["phases"].append({
        "phase": 4,
        "name": "Firewall rule verification",
        "status": "passed" if verification_passed else "failed",
        "timestamp": verification_timestamp,
        "rule_name": verification.get("rule_name"),
        "rule_exists": rule_exists,
        "method": enforcement.get("enforcement_method") or verification.get("enforcement_method"),
        "verification": enforcement.get("verification_status") or verification.get("verification_status"),
        "real_block_applied": bool(enforcement.get("real_block_applied")),
        "command_status": enforcement.get("command_status"),
    })
    report["phases"].append({
        "phase": 5,
        "name": "Safe re-test",
        "status": "passed" if retest_denied else "failed",
        "attempt_type": "firewall_policy_lookup",
        "validation_traffic_denied": retest_denied,
        "notes": "No additional packet generator is launched; denial is proven by the active verified firewall block rule for the source IP.",
    })
    report["summary"] = {
        "traffic_generated": generated_packets,
        "detection_triggered": True,
        "firewall_rule_created": rule_exists,
        "verification_passed": verification_passed,
        "retest_denied": retest_denied,
        "method": enforcement.get("enforcement_method") or verification.get("enforcement_method"),
        "verification": enforcement.get("verification_status") or verification.get("verification_status"),
        "real_block_applied": bool(enforcement.get("real_block_applied")),
        "rule_exists": rule_exists,
    }
    completed = verification_passed and retest_denied
    record.update({
        "status": "completed" if completed else "failed",
        "phase": "complete" if completed else "phase_4_verification",
        "traffic_generated": generated_packets,
        "flows_generated": flows_to_generate,
        "detection_triggered": True,
        "auto_response_action": "BLOCK",
        "block_executed": block_ok,
        "firewall_rule_created": rule_exists,
        "verification_passed": verification_passed,
        "retest_denied": retest_denied,
        "detection_timestamp": detection_timestamp,
        "block_timestamp": block_timestamp,
        "verification_timestamp": verification_timestamp,
        "rule_name": verification.get("rule_name"),
        "rule_exists": rule_exists,
        "command_status": enforcement.get("command_status", "unknown"),
        "enforcement_method": enforcement.get("enforcement_method") or verification.get("enforcement_method") or "database",
        "verification_status": enforcement.get("verification_status") or verification.get("verification_status") or "unknown",
        "real_block_applied": bool(enforcement.get("real_block_applied")),
        "report": report,
    })
    sync_upsert_ips_validation_test(record)
    sync_insert_activity_log({
        "type": "ips_validation",
        "action": "validation_test",
        "target": source_ip,
        "reason": "IPS enforcement validation completed" if completed else "IPS enforcement validation failed",
        "source": "ips_validation_test",
        "status": "success" if completed else "failed",
        "metadata": report,
    })
    return jsonify({"success": completed, "validation": record, "report": report}), (200 if completed else 500)


@app.route("/ips/validation-test/status", methods=["GET"])
@optional_auth
def ips_validation_test_status():
    limit = _safe_limit(default=10, maximum=50)
    rows = sync_get_ips_validation_tests(limit=limit)
    return jsonify({
        "latest": rows[0] if rows else None,
        "history": rows,
    }), 200


@app.route("/ips/validation-test", methods=["DELETE"])
@require_role("admin")
def ips_validation_test_clear():
    ok = sync_clear_ips_validation_tests()
    sync_insert_activity_log({
        "type": "ips_validation",
        "action": "clear_validation_data",
        "target": "ips_validation_tests",
        "reason": "IPS validation test evidence cleared from validation table",
        "source": "security_tools",
        "status": "success" if ok else "failed",
        "metadata": {},
    })
    return jsonify({"success": ok}), (200 if ok else 500)


@app.route("/network/visibility", methods=["GET"])
@optional_auth
def network_visibility_status():
    return jsonify({
        "sensor": read_sensor_status(),
        "ips": current_enforcement_profile(),
        "capture": _capture_status(),
    }), 200


_capture_process: subprocess.Popen | None = None
_capture_lock = threading.RLock()
_capture_started_at: str | None = None
_capture_interface: str | None = None


def _capture_status() -> dict:
    with _capture_lock:
        running = bool(_capture_process and _capture_process.poll() is None)
        exit_code = None if running or _capture_process is None else _capture_process.poll()
        return {
            "running": running,
            "interface": _capture_interface,
            "started_at": _capture_started_at,
            "pid": _capture_process.pid if running else None,
            "last_exit_code": exit_code,
        }


def _list_capture_interfaces() -> tuple[list[str], str | None]:
    try:
        from scapy.all import conf, get_if_list
        interfaces = sorted(str(item) for item in get_if_list())
        return interfaces, str(conf.iface) if conf.iface else None
    except Exception as exc:
        log.warning("failed to list capture interfaces: %s", exc)
        return [], None


@app.route("/capture/interfaces", methods=["GET"])
@require_auth
def capture_interfaces():
    interfaces, default_iface = _list_capture_interfaces()
    return jsonify({"interfaces": interfaces, "default": default_iface}), 200


@app.route("/capture/status", methods=["GET"])
@require_auth
def capture_status():
    return jsonify(_capture_status()), 200


@app.route("/capture/start", methods=["POST"])
@require_role("admin", "analyst")
def capture_start():
    global _capture_process, _capture_started_at, _capture_interface
    data = request.get_json(silent=True) or {}
    iface = str(data.get("interface") or "").strip() or None
    interfaces, default_iface = _list_capture_interfaces()
    if iface and interfaces and iface not in interfaces:
        return jsonify({"error": "Unknown capture interface", "interfaces": interfaces}), 400

    with _capture_lock:
        if _capture_process and _capture_process.poll() is None:
            return jsonify(_capture_status()), 200
        env = os.environ.copy()
        if iface:
            env["CAPTURE_INTERFACE"] = iface
        _capture_process = subprocess.Popen(
            [_sys.executable, "agent_live_real.py"],
            cwd=os.getcwd(),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if _sys.platform == "win32" else 0,
        )
        _capture_started_at = datetime.utcnow().isoformat() + "Z"
        _capture_interface = iface or default_iface

    sync_insert_activity_log(
        {
            "type": "capture",
            "action": "start",
            "target": _capture_interface or "default",
            "reason": "Live packet capture started",
            "source": "api",
            "status": "success",
            "metadata": _capture_status(),
        }
    )
    return jsonify(_capture_status()), 202


@app.route("/capture/stop", methods=["POST"])
@require_role("admin", "analyst")
def capture_stop():
    global _capture_process
    with _capture_lock:
        process = _capture_process
        if not process or process.poll() is not None:
            return jsonify(_capture_status()), 200
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    sync_insert_activity_log(
        {
            "type": "capture",
            "action": "stop",
            "target": _capture_interface or "default",
            "reason": "Live packet capture stopped",
            "source": "api",
            "status": "success",
            "metadata": _capture_status(),
        }
    )
    return jsonify(_capture_status()), 200


@app.route("/performance/metrics", methods=["GET"])
@optional_auth
def performance_metrics():
    try:
        limit = min(int(request.args.get("limit", 120)), 500)
    except (TypeError, ValueError):
        limit = 120
    return jsonify(performance_monitor.snapshot(limit=limit)), 200


@app.route("/performance/frontend", methods=["POST"])
def performance_frontend_metric():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        try:
            data = json.loads(request.get_data(as_text=True) or "{}")
        except json.JSONDecodeError:
            data = {}
    metric_type = str(data.get("type") or "dashboard_render_delay")
    if metric_type not in {"dashboard_render_delay", "websocket_latency", "client_api_time"}:
        metric_type = "dashboard_render_delay"
    try:
        value_ms = float(data.get("value_ms") or data.get("value") or 0)
    except (TypeError, ValueError):
        value_ms = 0.0
    performance_monitor.record(
        metric_type,
        value_ms,
        source="frontend",
        bandwidth_profile=data.get("bandwidth_profile"),
        path=data.get("path"),
    )
    return jsonify({"ok": True}), 202


@app.route("/bandwidth/profiles", methods=["GET"])
@optional_auth
def bandwidth_profiles():
    return jsonify({
        "profiles": BANDWIDTH_PROFILES,
        "header": "X-Bandwidth-Profile",
        "default": "unlimited",
    }), 200


@app.route("/stats", methods=["GET"])
@optional_auth
def platform_stats():
    """
    GET /stats
    Returns a single-shot aggregate of all key platform metrics.
    Committee-facing: shows full system state without needing the dashboard.
    """
    try:
        detections_all = [normalize_detection(d) for d in (get_detections(limit=200, offset=0) or [])]
        alerts_all     = get_alerts(limit=200) or []
        actions_all    = get_actions(limit=200, offset=0) or []
        blocked        = get_blocked_ips() or []
        findings       = sync_get_security_findings(limit=100) or []

        attacks     = [d for d in detections_all if d.get("result") == "ATTACK"]
        suspicious  = [d for d in detections_all if d.get("result") == "SUSPICIOUS"]
        malicious   = attacks + suspicious
        open_alerts = [a for a in alerts_all if not a.get("is_read")]
        distribution = {}
        for detection in malicious:
            label = normalize_attack_label(detection.get("attack_type"), detection.get("result"))
            if label != "BENIGN":
                distribution[label] = distribution.get(label, 0) + 1
        risk_percentage = round((len(malicious) / len(detections_all)) * 100) if detections_all else 0

        return jsonify({
            "platform":    "Fusion Strike AI",
            "version":     "2.0.0",
            "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "model": {
                "mode":       MODEL_MODE,
                "db_status":  "ok" if db_ping() else "unavailable",
                "pentest_mode": PENTEST_MODE,
                "auto_response": auto_response_engine.status(),
            },
            "detections": {
                "total":      len(detections_all),
                "attacks":    len(attacks),
                "suspicious": len(suspicious),
                "normal":     len(detections_all) - len(attacks) - len(suspicious),
                "malicious":  len(malicious),
                "risk_percentage": risk_percentage,
                "attack_distribution": [
                    {"label": label, "count": count}
                    for label, count in sorted(distribution.items(), key=lambda item: item[1], reverse=True)
                ],
            },
            "alerts": {
                "total": len(alerts_all),
                "open":  len(open_alerts),
                "acknowledged": len(alerts_all) - len(open_alerts),
            },
            "enforcement": {
                "blocked_ips":  len(blocked),
                "total_actions": len(actions_all),
                "block_actions":    sum(1 for a in actions_all if a.get("action_type") == "BLOCK"),
                "isolate_actions":  sum(1 for a in actions_all if a.get("action_type") == "ISOLATE"),
            },
            "pentest": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL"),
                "high":     sum(1 for f in findings if f.get("severity", "").upper() == "HIGH"),
                "medium":   sum(1 for f in findings if f.get("severity", "").upper() == "MEDIUM"),
            },
        }), 200
    except Exception as exc:
        log.error("stats endpoint error: %s", exc)
        return jsonify({"error": str(exc)}), 500




# ==============================================================================
# Alerts Endpoints
# ==============================================================================

_ALERT_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_ALERT_STATUSES = {"open", "acknowledged", "resolved", "dismissed"}


def _safe_json_object(value, *, fallback=None):
    if fallback is None:
        fallback = {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else fallback
        except (TypeError, ValueError):
            log.warning("Malformed alert metadata received: %r", value[:160])
            return fallback
    return fallback


def _safe_float(value, default=0.0):
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        log.warning("Malformed alert confidence normalized to %.1f: %r", default, value)
        return default


def _safe_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "y", "read", "acknowledged"}


def _safe_iso_timestamp(*values):
    for value in values:
        if value in (None, ""):
            continue
        if hasattr(value, "isoformat"):
            return value.isoformat()
        text = str(value).strip()
        if not text:
            continue
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
        except ValueError:
            log.warning("Malformed alert timestamp received: %r", text)
    return datetime.utcnow().isoformat()


def _normalize_alert_severity(raw_type, metadata):
    candidate = str(metadata.get("severity") or raw_type or "INFO").strip().upper()
    if candidate in {"ATTACK", "MALWARE", "BLOCK", "DANGER"}:
        return "HIGH"
    if candidate in {"SUSPICIOUS", "WARNING", "WARN"}:
        return "MEDIUM"
    if candidate not in _ALERT_SEVERITIES:
        log.warning("Unknown alert severity normalized to INFO: %r", candidate)
        return "INFO"
    return candidate


def _normalize_alert_status(raw_status, is_read):
    status = str(raw_status or "").strip().lower()
    if status not in _ALERT_STATUSES:
        status = "acknowledged" if is_read else "open"
    return status


def _serialize_alert_row(row, index=0):
    if not isinstance(row, dict):
        log.warning("Skipping malformed alert row at index %s: %r", index, row)
        return None

    metadata = _safe_json_object(row.get("metadata"))
    timestamp = _safe_iso_timestamp(
        row.get("updated_at"),
        row.get("created_at"),
        row.get("timestamp"),
        row.get("time"),
    )
    alert_id = row.get("id") or row.get("alert_id") or f"legacy-alert-{index}-{timestamp}"
    alert_type = str(row.get("alert_type") or row.get("type") or metadata.get("type") or "ALERT").strip().upper() or "ALERT"
    is_read = _safe_bool(row.get("is_read"), default=False)
    status = _normalize_alert_status(row.get("status") or metadata.get("status"), is_read)
    if status == "acknowledged":
        is_read = True
    ip = str(row.get("ip_address") or row.get("ip") or row.get("target") or metadata.get("ip") or "Unknown").strip() or "Unknown"
    message = str(row.get("message") or metadata.get("message") or f"{alert_type} alert for {ip}").strip()

    return {
        "id": alert_id,
        "ip": ip,
        "ip_address": ip,
        "type": alert_type,
        "alert_type": alert_type,
        "message": message[:1000],
        "is_read": is_read,
        "status": status,
        "severity": _normalize_alert_severity(alert_type, metadata),
        "confidence": _safe_float(metadata.get("confidence") or row.get("confidence"), 0.0),
        "source": str(metadata.get("source") or row.get("source") or "backend"),
        "time": timestamp,
        "timestamp": timestamp,
        "created_at": _safe_iso_timestamp(row.get("created_at"), timestamp),
        "updated_at": _safe_iso_timestamp(row.get("updated_at"), row.get("created_at"), timestamp),
        "metadata": metadata,
    }

@app.route("/alerts", methods=["GET"])
@optional_auth
def alerts_list():
    """
    GET /alerts
    Returns the last 50 IPS alerts ordered newest-first.

    Query params:
      ?limit=N  (default 50, max 200)

    Response (200):
    [
      {
        "id":       int,
        "ip":       string,
        "type":     string,   -- ATTACK | BLOCK | SUSPICIOUS | MALWARE
        "message":  string,
        "is_read":  bool,
        "time":     ISO-8601 string
      },
      ...
    ]

    Response (503) if DB is unavailable:
    { "error": "Database unavailable", "alerts": [] }
    """
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = max(0, int(request.args.get("offset", 0)))
    except (TypeError, ValueError):
        offset = 0

    try:
        rows = get_alerts(limit=limit, offset=offset)
        log.debug("alerts fetched: %d", len(rows) if rows else 0)
    except Exception as exc:
        log.exception("alerts fetch failed")
        return jsonify({"error": "Database unavailable", "alerts": [], "detail": str(exc)}), 503

    if rows is None:   # defensive — get_alerts returns [] not None but be safe
        return jsonify({"error": "Database unavailable", "alerts": []}), 503

    mapped_rows = []
    for index, row in enumerate(rows):
        try:
            serialized = _serialize_alert_row(row, index)
            if serialized:
                mapped_rows.append(serialized)
        except Exception:
            log.exception("Skipping malformed alert row at index %s", index)

    return jsonify(mapped_rows), 200


@app.route("/alerts/read/<int:alert_id>", methods=["POST"])
@optional_auth
def alert_mark_read(alert_id: int):
    """
    POST /alerts/read/<id>
    Marks a single alert as read.

    Response (200): { "ok": true }
    Response (404): { "ok": false, "error": "Not found or DB error" }
    """
    ok = mark_alert_read(alert_id)
    if ok:
        return jsonify({"ok": True}), 200
    return jsonify({"ok": False, "error": "Not found or DB error"}), 404


@app.route("/alerts/read-all", methods=["POST"])
@optional_auth
def alerts_mark_all_read():
    """
    POST /alerts/read-all
    Marks all currently unread/open alerts as read.

    Response (200):
      {
        "success": true,
        "updated": int,
        "total_updated": int,
        "timestamp": ISO-8601 string
      }
    """
    result = mark_all_alerts_read()
    timestamp = result.get("timestamp") or datetime.utcnow().isoformat()
    if not result.get("success"):
        return jsonify({
            "success": False,
            "updated": 0,
            "total_updated": 0,
            "timestamp": timestamp,
            "error": "Database unavailable",
        }), 503

    updated = int(result.get("updated") or 0)
    current_user = getattr(g, "current_user", None) or {}
    username = current_user.get("username") or "anonymous"
    sync_insert_activity_log({
        "timestamp": timestamp,
        "type": "alert",
        "action": "mark_all_read",
        "target": "alerts",
        "reason": "All alerts marked as read",
        "source": username,
        "status": "success",
        "metadata": {
            "user": username,
            "alerts_affected": updated,
            "timestamp": timestamp,
        },
    })

    return jsonify({
        "success": True,
        "updated": updated,
        "total_updated": updated,
        "timestamp": timestamp,
    }), 200


@app.route("/pentest/findings", methods=["GET"])
@optional_auth
def pentest_findings():
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except (TypeError, ValueError):
        limit = 50
    target = (request.args.get("target") or "").strip() or None
    include_resolved = str(request.args.get("include_resolved", "true")).lower() != "false"
    rows = sync_get_security_findings(limit=limit, target=target, include_resolved=include_resolved)
    return jsonify(rows), 200


# ==============================================================================
# Read-Only Data Endpoints  (consumed by React dashboard)
# ==============================================================================

def _safe_limit(default: int = 20, maximum: int = 200) -> int:
    """Parse ?limit= safely from the query string."""
    try:
        return min(int(request.args.get("limit", default)), maximum)
    except (TypeError, ValueError):
        return default

def _safe_offset() -> int:
    """Parse ?offset= safely from the query string."""
    try:
        return max(0, int(request.args.get("offset", 0)))
    except (TypeError, ValueError):
        return 0


@app.route("/detections", methods=["GET"])
@optional_auth
def detections_list():
    """
    GET /detections?limit=20&offset=0&src_ip=<optional>&include_contained=false

    Returns recent ML detections ordered by detected_at DESC.
    By default excludes detections from blocked/contained IPs so the
    Suspicious Queue only shows truly active threats.

    Row fields: id, src_ip, result, attack_type, confidence, iso_flag,
                detected_at, containment_status
    """
    src_ip           = request.args.get("src_ip") or None
    include_contained = request.args.get("include_contained", "false").lower() == "true"

    rows = [normalize_detection(row) for row in get_detections(limit=_safe_limit(), offset=_safe_offset(), src_ip=src_ip)]

    # Build blocked + action_control lookup for annotation + filtering
    blocked = get_blocked_ips() or []
    blocked_ips_set = {b["ip"] for b in blocked}

    # Annotate every row with its containment status (used by frontend status column)
    # and optionally filter out contained hosts from the Suspicious Queue feed
    result_rows = []
    for row in rows:
        ip = row.get("src_ip", "")
        timestamp = row.get("detected_at")
        row["id"] = row.get("id")
        row["timestamp"] = timestamp
        row["created_at"] = row.get("created_at") or timestamp
        row["updated_at"] = row.get("updated_at") or timestamp
        row["status"] = row.get("result") or "NORMAL"
        row["severity"] = row.get("severity") or row.get("result") or "NORMAL"
        row["source"] = row.get("source") or "ml_detector"
        if ip in blocked_ips_set:
            row["containment_status"] = "BLOCKED"
            if not include_contained:
                # Still include ATTACK/SUSPICIOUS rows but mark them contained
                # so the queue can suppress them without hiding them from Hosts
                row["is_contained"] = True
            else:
                row["is_contained"] = True
        else:
            row["containment_status"] = "ACTIVE"
            row["is_contained"] = False
        result_rows.append(row)

    # When not requesting contained records, filter them out of the queue
    if not include_contained:
        result_rows = [r for r in result_rows if not r.get("is_contained")]

    return jsonify(result_rows), 200




@app.route("/flows", methods=["GET"])
@optional_auth
def flows_list():
    """
    GET /flows?limit=20&offset=0&src_ip=<optional>
    Returns recent network flows ordered by captured_at DESC.

    Row fields: id, src_ip, dst_ip, packets, bytes, pps, duration_us, captured_at
    """
    src_ip = request.args.get("src_ip") or None
    rows   = get_flows(limit=_safe_limit(), offset=_safe_offset(), src_ip=src_ip)
    return jsonify(rows), 200


@app.route("/actions", methods=["GET"])
@optional_auth
def actions_list():
    """
    GET /actions?limit=20&offset=0
    Returns recent IPS actions ordered by acted_at DESC.

    Row fields: id, ip, action_type, reason, acted_at
    """
    rows = get_actions(limit=_safe_limit(), offset=_safe_offset())
    return jsonify(rows), 200


@app.route("/blocked-ips", methods=["GET"])
@require_auth
def blocked_ips_list():
    """
    GET /blocked-ips
    Returns all currently blocked IPs.

    Row fields: ip, reason, blocked_at
    """
    rows = get_blocked_ips()
    return jsonify(rows), 200


# ==============================================================================
# Action Controls
# ==============================================================================

PENTEST_SCAN_TIMEOUTS = {
    "quick": 300,
    "full": 900,
    "stealth": 600,
}


def _default_action_state(target: str) -> dict:
    return default_action_state(target)


def _get_action_state(target: str) -> dict:
    return get_action_state(target)


CONTAINMENT_ACTION_ROLES = ("admin", "analyst")


def _current_actor() -> dict:
    user = getattr(g, "current_user", None) or {}
    return {
        "actor_username": str(user.get("username") or "unknown"),
        "actor_role": normalize_role(user.get("role") or "unknown"),
    }


def _normalize_pentest_record(record: dict) -> dict:
    results = record.get("results") or {}
    return {
        "scan_id": record.get("scan_id"),
        "target": record.get("target"),
        "status": record.get("status", "queued"),
        "progress": int(record.get("progress") or results.get("progress") or 0),
        "current_stage": record.get("current_stage") or results.get("current_stage") or "queued",
        "pentest_mode": PENTEST_MODE,
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at") or record.get("completed_at") or record.get("created_at"),
        "completed_at": record.get("completed_at"),
        "results": results,
    }


def _execute_simulated_action(action: str, target: str, reason: str, source: str = "pentest_console") -> tuple[dict, int]:
    return execute_host_action(
        action=action,
        target=target,
        reason=reason,
        source=source,
        confidence=0.0,
        trigger=source,
        **_current_actor(),
    )


@app.route("/actions/state/<path:target>", methods=["GET"])
@optional_auth
def action_state_get(target: str):
    return jsonify(_get_action_state(target)), 200


@app.route("/auto-response/status", methods=["GET"])
@require_auth
def auto_response_status():
    return jsonify(auto_response_engine.status()), 200


@app.route("/auto-response/status", methods=["POST"])
@require_role("admin")
def auto_response_update():
    data = request.get_json() or {}
    auto_response_engine.set_enabled(bool(data.get("enabled")))
    return jsonify(auto_response_engine.status()), 200


@app.route("/actions/block", methods=["POST"])
@require_role(*CONTAINMENT_ACTION_ROLES)
def action_block():
    data = request.get_json() or {}
    target = data.get("target")
    ok, reason_text = _validate_ip_or_host(target)
    if not ok:
        return jsonify({"error": reason_text}), 400
    reason = _validate_reason(data.get("reason"), "Manual block")
    payload, status_code = _execute_simulated_action("BLOCK", target, reason, "manual")
    if status_code == 200 and payload.get("status") == "success" and data.get("finding_id"):
        finding_state = apply_action_to_finding(
            data.get("finding_id"),
            action="BLOCK",
            reason=reason,
            source="manual",
            confidence=float(data.get("confidence") or 0.0),
            queue_scan=_queue_pentest_scan,
        )
        if finding_state:
            payload["finding"] = finding_state
    return jsonify(payload), status_code


@app.route("/actions/isolate", methods=["POST"])
@require_role(*CONTAINMENT_ACTION_ROLES)
def action_isolate():
    data = request.get_json() or {}
    target = data.get("target")
    ok, reason_text = _validate_ip_or_host(target)
    if not ok:
        return jsonify({"error": reason_text}), 400
    reason = _validate_reason(data.get("reason"), "Manual isolate")
    payload, status_code = _execute_simulated_action("ISOLATE", target, reason, "manual")
    if status_code == 200 and payload.get("status") == "success" and data.get("finding_id"):
        finding_state = apply_action_to_finding(
            data.get("finding_id"),
            action="ISOLATE",
            reason=reason,
            source="manual",
            confidence=float(data.get("confidence") or 0.0),
            queue_scan=_queue_pentest_scan,
        )
        if finding_state:
            payload["finding"] = finding_state
    return jsonify(payload), status_code


@app.route("/actions/whitelist", methods=["POST"])
@require_role(*CONTAINMENT_ACTION_ROLES)
def action_whitelist():
    data = request.get_json() or {}
    target = data.get("target")
    ok, reason_text = _validate_ip_or_host(target)
    if not ok:
        return jsonify({"error": reason_text}), 400
    reason = _validate_reason(data.get("reason"), "Manual whitelist")
    payload, status_code = _execute_simulated_action("WHITELIST", target, reason, "manual")
    if status_code == 200 and payload.get("status") == "success" and data.get("finding_id"):
        finding_state = apply_action_to_finding(
            data.get("finding_id"),
            action="WHITELIST",
            reason=reason,
            source="manual",
            confidence=float(data.get("confidence") or 0.0),
            queue_scan=None,
        )
        if finding_state:
            payload["finding"] = finding_state
    return jsonify(payload), status_code


@app.route("/actions/unblock", methods=["POST"])
@require_role(*CONTAINMENT_ACTION_ROLES)
def action_unblock():
    """Remove a block — restores host to CLEAN state and logs a manual_action event."""
    data = request.get_json() or {}
    target = data.get("target") or data.get("ip") or ""
    ok, reason_text = _validate_ip_or_host(target)
    if not ok:
        return jsonify({"error": reason_text}), 400
    reason = _validate_reason(data.get("reason"), "Manual unblock by SOC analyst")
    payload, status_code = execute_host_action(
        action="UNBLOCK",
        target=target,
        reason=reason,
        source="manual",
        confidence=float(data.get("confidence") or 0.0),
        trigger="manual",
        **_current_actor(),
    )
    return jsonify(payload), status_code


@app.route("/actions/unisolate", methods=["POST"])
@require_role(*CONTAINMENT_ACTION_ROLES)
def action_unisolate():
    """Remove isolation — restores host to CLEAN state and logs a manual_action event."""
    data = request.get_json() or {}
    target = data.get("target") or data.get("ip") or ""
    ok, reason_text = _validate_ip_or_host(target)
    if not ok:
        return jsonify({"error": reason_text}), 400
    reason = _validate_reason(data.get("reason"), "Manual isolation removal by SOC analyst")
    payload, status_code = execute_host_action(
        action="UNISOLATE",
        target=target,
        reason=reason,
        source="manual",
        confidence=float(data.get("confidence") or 0.0),
        trigger="manual",
        **_current_actor(),
    )
    return jsonify(payload), status_code




@app.route("/block", methods=["POST"])
@require_role(*CONTAINMENT_ACTION_ROLES)
def manual_block():
    data = request.get_json() or {}
    ok, reason_text = _validate_ip_or_host(data.get("ip"))
    if not ok:
        return jsonify({"error": reason_text}), 400
    payload, status_code = _execute_simulated_action("BLOCK", data.get("ip"), _validate_reason(data.get("reason"), "Legacy manual block"), "manual")
    return jsonify(payload), status_code


@app.route("/unblock", methods=["POST"])
@require_role(*CONTAINMENT_ACTION_ROLES)
def manual_unblock():
    data = request.get_json() or {}
    ok, reason_text = _validate_ip_or_host(data.get("ip"))
    if not ok:
        return jsonify({"error": reason_text}), 400
    payload, status_code = execute_host_action(
        action="UNBLOCK",
        target=data.get("ip"),
        reason=_validate_reason(data.get("reason"), "Legacy manual unblock"),
        source="manual",
        trigger="manual",
        **_current_actor(),
    )
    return jsonify(payload), status_code


@app.route("/isolate", methods=["POST"])
@require_role(*CONTAINMENT_ACTION_ROLES)
def manual_isolate():
    data = request.get_json() or {}
    ok, reason_text = _validate_ip_or_host(data.get("ip"))
    if not ok:
        return jsonify({"error": reason_text}), 400
    payload, status_code = _execute_simulated_action("ISOLATE", data.get("ip"), _validate_reason(data.get("reason"), "Legacy manual isolate"), "manual")
    return jsonify(payload), status_code


@app.route("/unisolate", methods=["POST"])
@require_role(*CONTAINMENT_ACTION_ROLES)
def manual_unisolate():
    data = request.get_json() or {}
    ok, reason_text = _validate_ip_or_host(data.get("ip"))
    if not ok:
        return jsonify({"error": reason_text}), 400
    payload, status_code = execute_host_action(
        action="UNISOLATE",
        target=data.get("ip"),
        reason=_validate_reason(data.get("reason"), "Legacy manual unisolate"),
        source="manual",
        trigger="manual",
        **_current_actor(),
    )
    return jsonify(payload), status_code


# ==============================================================================
# Pentest Agent Integration
# ==============================================================================

import uuid as _uuid

# ── Pentest guard helper ─────────────────────────────────────────────────────
def forbidden_response(reason: str, **extra) -> tuple:
    """Return a consistent HTTP 403 JSON response for pentest guard conditions."""
    return jsonify({"error": reason, "status": "forbidden", **extra}), 403

# Module-level logger for pentest pipeline threads (must exist before _queue_pentest_scan)
plog = _logging.getLogger("pentest.flask_bridge")
import asyncio as _asyncio
import concurrent.futures as _futures
import traceback as _traceback

from db import (
    sync_insert_pentest_scan,
    sync_update_pentest_scan,
    sync_get_pentest_scan,
    sync_list_pentest_scans,
)

# Thread pool for background pentest scans (Flask can't use asyncio.create_task)
_pentest_executor = _futures.ThreadPoolExecutor(max_workers=3, thread_name_prefix="pentest")

# Track active pentest scan count
_active_pentest_scans = 0
_pentest_lock = threading.Lock()


def _submit_pentest_task(scan_id: str, target: str, scan_type: str, triggered_by: str):
    future = _pentest_executor.submit(_run_pentest_pipeline, scan_id, target, scan_type, triggered_by)

    def _done(done_future):
        try:
            done_future.result()
        except Exception:
            plog.exception("pentest worker crashed outside pipeline handler: scan=%s", scan_id)

    future.add_done_callback(_done)
    return future


def _queue_pentest_scan(target: str, scan_type: str, triggered_by: str) -> str | None:
    valid, reason = _validate_ip_or_host(target)
    if not valid:
        plog.warning("queue rejected invalid pentest target=%s reason=%s", target, reason)
        return None
    scan_id = _uuid.uuid4().hex[:12]
    ok = sync_insert_pentest_scan(scan_id, target, scan_type, triggered_by)
    if not ok:
        return None
    plog.info("Submitting pentest task scan=%s target=%s type=%s", scan_id, target, scan_type)
    _submit_pentest_task(scan_id, target, scan_type, triggered_by)
    return scan_id


def _run_pentest_pipeline(scan_id: str, target: str, scan_type: str, triggered_by: str):
    """
    Run the pentest pipeline in a background thread.
    Creates its own event loop since we're outside Flask's main thread.
    """
    global _active_pentest_scans
    import logging

    try:
        with _pentest_lock:
            _active_pentest_scans += 1

        plog.info("Pipeline thread starting: scan=%s target=%s type=%s", scan_id, target, scan_type)
        plog.info("Pipeline starting: scan=%s target=%s type=%s", scan_id, target, scan_type)

        # Import pentest modules
        from pentest_agent.database import ScanDatabase as _PentestScanDB
        from pentest_agent.orchestrator import PentestOrchestrator

        # Create a new event loop for this thread
        loop = _asyncio.new_event_loop()
        _asyncio.set_event_loop(loop)

        try:
            # Use internal SQLite DB for the orchestrator's own bookkeeping
            pentest_db = _PentestScanDB()

            async def _run():
                await pentest_db.connect()
                try:
                    await pentest_db.create_scan(scan_id, target)
                    latest = {
                        "status": "running",
                        "progress": 5,
                        "current_stage": "recon",
                        "results": {"progress": 5, "current_stage": "recon"},
                    }

                    async def _progress_callback(payload: dict):
                        plog.debug("progress update: status=%s progress=%s stage=%s",
                                   payload.get('status'), payload.get('progress'), payload.get('current_stage'))
                        latest.update(payload)
                        await pentest_db.update_scan(
                            scan_id,
                            status=payload.get("status"),
                            progress=payload.get("progress"),
                            current_stage=payload.get("current_stage"),
                            results=payload.get("results"),
                        )
                        sync_update_pentest_scan(
                            scan_id,
                            status=payload.get("status"),
                            progress=payload.get("progress"),
                            current_stage=payload.get("current_stage"),
                            results=payload.get("results"),
                        )

                    orch = PentestOrchestrator(pentest_db, progress_callback=_progress_callback)

                    sync_update_pentest_scan(
                        scan_id,
                        status="running",
                        progress=5,
                        current_stage="recon",
                        results=latest["results"],
                    )
                    plog.info("Pipeline stage: running 5%% recon — scan=%s", scan_id)

                    result = await _asyncio.wait_for(
                        orch.run_pipeline(
                        target=target,
                        scan_id=scan_id,
                        scan_type=scan_type,
                        triggered_by=triggered_by,
                        ),
                        timeout=PENTEST_SCAN_TIMEOUTS.get(scan_type, 600),
                    )

                    # Store full results in PostgreSQL
                    completed = datetime.utcnow().isoformat()
                    result_dict = result.model_dump(mode="json")

                    sync_update_pentest_scan(
                        scan_id,
                        status=result.status.value,
                        progress=100,
                        current_stage="completed" if result.status.value == "completed" else "failed",
                        results=result_dict,
                        completed_at=completed,
                    )
                    plog.info("Pipeline complete: status=%s scan=%s", result.status.value, scan_id)
                    await pentest_db.update_scan(
                        scan_id,
                        status=result.status.value,
                        progress=100,
                        current_stage="completed" if result.status.value == "completed" else "failed",
                        results=result_dict,
                        completed_at=completed,
                    )
                    process_completed_scan(
                        scan_id=scan_id,
                        target=target,
                        triggered_by=triggered_by,
                        result_dict=result_dict,
                        queue_scan=_queue_pentest_scan,
                    )

                    plog.info("Pipeline completed: scan=%s status=%s", scan_id, result.status.value)
                except _asyncio.TimeoutError:
                    completed = datetime.utcnow().isoformat()
                    timeout_results = latest.get("results") or {}
                    timeout_results["error"] = f"Scan exceeded timeout of {PENTEST_SCAN_TIMEOUTS.get(scan_type, 600)} seconds"
                    sync_update_pentest_scan(
                        scan_id,
                        status="failed",
                        progress=100,
                        current_stage="failed",
                        results=timeout_results,
                        completed_at=completed,
                    )
                    plog.error("Pipeline timed out: scan=%s timeout=%ss", scan_id, PENTEST_SCAN_TIMEOUTS.get(scan_type, 600))
                    await pentest_db.update_scan(
                        scan_id,
                        status="failed",
                        progress=100,
                        current_stage="failed",
                        results=timeout_results,
                        completed_at=completed,
                    )
                    plog.error("Pipeline timed out: scan=%s timeout=%ss", scan_id, PENTEST_SCAN_TIMEOUTS.get(scan_type, 600))
                except Exception as exc:
                    plog.error("Pipeline failed: scan=%s error=%s", scan_id, exc)
                    plog.error(_traceback.format_exc())
                    completed = datetime.utcnow().isoformat()
                    failed_results = latest.get("results") or {}
                    failed_results["error"] = str(exc)
                    sync_update_pentest_scan(
                        scan_id,
                        status="failed",
                        progress=100,
                        current_stage="failed",
                        results=failed_results,
                        completed_at=completed,
                    )
                    plog.error("Pipeline exception: scan=%s stage=%s error=%s", scan_id, latest.get('current_stage'), exc)
                    await pentest_db.update_scan(
                        scan_id,
                        status="failed",
                        progress=100,
                        current_stage="failed",
                        results=failed_results,
                        completed_at=completed,
                    )
                finally:
                    await pentest_db.close()

            loop.run_until_complete(_run())
        finally:
            loop.close()

    except Exception as exc:
        plog.error("Pipeline thread crashed: scan=%s error=%s", scan_id, exc)
        sync_update_pentest_scan(scan_id, status="failed", progress=100, current_stage="failed", results={"error": str(exc)}, completed_at=datetime.utcnow().isoformat())
    finally:
        with _pentest_lock:
            _active_pentest_scans -= 1


@app.route("/pentest/scan", methods=["POST"])
@require_role("admin", "analyst")
def pentest_start_scan():
    """
    POST /pentest/scan
    Start a new pentest scan.

    Body: { "target": "...", "scan_type": "quick"|"full"|"stealth" }
    Response 202: { "scan_id": "...", "target": "...", "status": "queued", "scan_type": "..." }
    """
    data = request.get_json() or {}
    log.debug("pentest/scan request: %s", data)
    target = (data.get("target") or "").strip()
    scan_type = data.get("scan_type", "quick").strip().lower()

    valid, target_error = _validate_ip_or_host(target)
    if not valid:
        return jsonify({"error": target_error}), 400

    if scan_type not in ("quick", "full", "stealth"):
        return jsonify({"error": f"Invalid scan_type: {scan_type}. Use quick, full, or stealth."}), 400

    if PENTEST_MODE == "external" and scan_type != "quick":
        return forbidden_response(
            "External mode only permits quick scanning",
            pentest_mode=PENTEST_MODE,
        )

    action_state = _get_action_state(target)
    if action_state.get("is_whitelisted"):
        return jsonify({
            "error": f"Target {target} is whitelisted and excluded from future scans",
            "target": target,
            "resolved_ip": target,
            "status": "failed",
            "action_state": action_state,
        }), 409

    # Validate target safety
    from pentest_agent.modules.nmap_scanner import inspect_target_validation
    validation = inspect_target_validation(target)
    log.debug("pentest target resolved_ip=%s validation=%s", validation.get('resolved_ip'), validation.get('allowed'))
    is_safe = bool(validation.get("allowed"))
    reason = validation.get("reason") or "unknown validation failure"
    if not is_safe:
        log.warning("pentest target rejected: %s — %s", target, reason)
        return forbidden_response(
            reason or "CORS or validation issue",
            target=target,
            resolved_ip=validation.get("resolved_ip"),
            validation=validation,
        )

    # Check concurrency limit
    with _pentest_lock:
        if _active_pentest_scans >= 3:
            return jsonify({
                "error": f"Rate limit: {_active_pentest_scans}/3 scans already running"
            }), 429

    scan_id = _uuid.uuid4().hex[:12]
    triggered_by = data.get("triggered_by", "user")

    # Create DB record
    ok = sync_insert_pentest_scan(scan_id, target, scan_type, triggered_by)
    if not ok:
        return jsonify({"error": "Failed to create scan record"}), 500

    # Fire pipeline in background thread
    log.info("pentest scan queued: scan=%s target=%s type=%s", scan_id, target, scan_type)
    _submit_pentest_task(scan_id, target, scan_type, triggered_by)

    log.info("[PENTEST] Scan queued: %s -> %s (%s)", scan_id, target, scan_type)

    return jsonify({
        "scan_id": scan_id,
        "target": target,
        "status": "queued",
        "progress": 0,
        "current_stage": "queued",
        "scan_type": scan_type,
        "pentest_mode": PENTEST_MODE,
        "message": "Scan started",
    }), 202


@app.route("/pentest/results/<scan_id>", methods=["GET"])
@optional_auth
def pentest_get_results(scan_id: str):
    """
    GET /pentest/results/<scan_id>
    Get full results for a pentest scan.
    """
    record = sync_get_pentest_scan(scan_id)
    if not record:
        return jsonify({"error": f"Scan {scan_id} not found"}), 404

    return jsonify(_normalize_pentest_record(record)), 200


@app.route("/pentest/scans", methods=["GET"])
@optional_auth
def pentest_list_scans():
    """
    GET /pentest/scans?limit=20&offset=0
    List all pentest scans (summaries without full results blob).
    """
    limit = _safe_limit(default=20, maximum=200)
    offset = _safe_offset()
    scans = sync_list_pentest_scans(limit=limit, offset=offset)
    return jsonify([_normalize_pentest_record(scan) for scan in scans]), 200


# ==============================================================================
# Run
# ==============================================================================


# ==============================================================================
# Pentest Report + Activity Timeline
# ==============================================================================
from db import sync_get_activity_logs  # noqa: E402


@app.route('/pentest/report/<scan_id>', methods=['GET'])
@optional_auth
def pentest_get_report(scan_id: str):
    record = sync_get_pentest_scan(scan_id)
    if not record:
        return jsonify({'error': f'Scan {scan_id} not found'}), 404
    results = record.get('results') or {}
    return jsonify({
        'scan_id': scan_id,
        'target': record.get('target'),
        'status': record.get('status'),
        'report': results.get('report') or {},
        'vulnerabilities': results.get('vulnerabilities') or [],
        'attack_graph': results.get('attack_graph') or {},
        'execution_plan': results.get('execution_plan') or {},
    }), 200


@app.route('/activity/logs', methods=['GET'])
@optional_auth
def activity_logs_list():
    limit = _safe_limit(default=50, maximum=200)
    type_filter = (request.args.get('type') or '').strip() or None
    target = (request.args.get('target') or '').strip() or None
    rows = sync_get_activity_logs(limit=limit, type_filter=type_filter, target=target)
    return jsonify(rows), 200

@atexit.register
def _shutdown_pentest_executor():
    with _capture_lock:
        if _capture_process and _capture_process.poll() is None:
            _capture_process.terminate()
    _pentest_executor.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    import logging as _log_cfg
    _log_cfg.basicConfig(
        level=_log_cfg.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    app.run(host=API_HOST, port=API_PORT, debug=DEBUG, threaded=True)

