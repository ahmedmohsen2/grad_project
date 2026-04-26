import os
import threading
from datetime import datetime
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from db import (
    sync_insert_detection  as insert_detection,
    sync_db_ping           as db_ping,
    sync_get_alerts        as get_alerts,
    sync_mark_alert_read   as mark_alert_read,
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
)
from auto_response_engine import auto_response_engine
from closed_loop_lifecycle import apply_action_to_finding, process_completed_scan
from host_actions import default_action_state, execute_host_action, get_action_state
from pentest_agent.config import PENTEST_MODE

app = Flask(__name__)

# Allow React dev-server (port 5173), any local frontend, and mobile apps
CORS(app, resources={r"/*": {"origins": "*"}})

# ── Auth Blueprint ───────────────────────────────────────────────────────────
from auth import auth_bp, require_auth
app.register_blueprint(auth_bp)

# Initialise the asyncpg pool at startup (sync bridge for Flask context)
sync_init_pool()
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
    print("[API] Multi-class model loaded")
    xgb_model = safe_load(_MULTICLASS_PATH)
    scaler = safe_load("xgb_model_multiclass_scaler.pkl")
    columns = safe_load("xgb_model_multiclass_columns.pkl")
    MODEL_MODE = "multiclass"
else:
    print("[API] Binary model loaded")
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

        print("[DEBUG] Incoming:", data)

        sample = preprocess(data)

        # ISO
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

        print(f"[RESULT] {result} | conf={confidence:.3f} | iso={iso}")

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
            "auto_response": {
                "enabled": auto_response_engine.status()["enabled"],
                "decision": auto_decision.action,
                "reason": auto_decision.reason,
                "history": history,
                "action_result": auto_action_result,
            },
        })

    except Exception as e:
        print("[ERROR]", str(e))
        return jsonify({
            "error": str(e),
            "result": "ERROR"
        }), 500


# ==============================================================================
# Health
# ==============================================================================
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "API running"})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":     "ok",
        "model_mode": MODEL_MODE,
        "db_status":  "ok" if db_ping() else "unavailable",
        "auto_response_enabled": auto_response_engine.status()["enabled"],
        "pentest_mode": PENTEST_MODE,
    })


# ==============================================================================
# Alerts Endpoints
# ==============================================================================

@app.route("/alerts", methods=["GET"])
@require_auth
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
        limit = min(int(request.args.get("limit", 50)), 200)
    except (TypeError, ValueError):
        limit = 50

    rows = get_alerts(limit=limit)
    print(f"[DEBUG] alerts fetched: {len(rows)}")

    if rows is None:   # defensive — get_alerts returns [] not None but be safe
        return jsonify({"error": "Database unavailable", "alerts": []}), 503

    mapped_rows = [
        {
            "id": r["id"],
            "ip": r.get("ip_address", r.get("ip")),
            "type": r.get("alert_type", r.get("type")),
            "message": r["message"],
            "is_read": r["is_read"],
            "time": r.get("created_at", r.get("time")),
            "metadata": r.get("metadata", {}),
        }
        for r in rows
    ]

    return jsonify(mapped_rows), 200


@app.route("/alerts/read/<int:alert_id>", methods=["POST"])
@require_auth
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


@app.route("/pentest/findings", methods=["GET"])
@require_auth
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
@require_auth
def detections_list():
    """
    GET /detections?limit=20&offset=0&src_ip=<optional>
    Returns recent ML detections ordered by detected_at DESC.

    Row fields: id, src_ip, result, attack_type, confidence, iso_flag, detected_at
    """
    src_ip = request.args.get("src_ip") or None
    rows   = get_detections(limit=_safe_limit(), offset=_safe_offset(), src_ip=src_ip)
    return jsonify(rows), 200


@app.route("/flows", methods=["GET"])
@require_auth
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
@require_auth
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
# Simulated Action Controls
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
    )


@app.route("/actions/state/<path:target>", methods=["GET"])
@require_auth
def action_state_get(target: str):
    return jsonify(_get_action_state(target)), 200


@app.route("/auto-response/status", methods=["GET"])
def auto_response_status():
    return jsonify(auto_response_engine.status()), 200


@app.route("/auto-response/status", methods=["POST"])
def auto_response_update():
    data = request.get_json() or {}
    auto_response_engine.set_enabled(bool(data.get("enabled")))
    return jsonify(auto_response_engine.status()), 200


@app.route("/actions/block", methods=["POST"])
@require_auth
def action_block():
    data = request.get_json() or {}
    payload, status_code = _execute_simulated_action("BLOCK", data.get("target"), data.get("reason", "Manual block"), "manual")
    if status_code == 200 and payload.get("status") == "success" and data.get("finding_id"):
        finding_state = apply_action_to_finding(
            data.get("finding_id"),
            action="BLOCK",
            reason=data.get("reason", "Manual block"),
            source="manual",
            confidence=float(data.get("confidence") or 0.0),
            queue_scan=_queue_pentest_scan,
        )
        if finding_state:
            payload["finding"] = finding_state
    return jsonify(payload), status_code


@app.route("/actions/isolate", methods=["POST"])
@require_auth
def action_isolate():
    data = request.get_json() or {}
    payload, status_code = _execute_simulated_action("ISOLATE", data.get("target"), data.get("reason", "Manual isolate"), "manual")
    if status_code == 200 and payload.get("status") == "success" and data.get("finding_id"):
        finding_state = apply_action_to_finding(
            data.get("finding_id"),
            action="ISOLATE",
            reason=data.get("reason", "Manual isolate"),
            source="manual",
            confidence=float(data.get("confidence") or 0.0),
            queue_scan=_queue_pentest_scan,
        )
        if finding_state:
            payload["finding"] = finding_state
    return jsonify(payload), status_code


@app.route("/actions/whitelist", methods=["POST"])
@require_auth
def action_whitelist():
    data = request.get_json() or {}
    payload, status_code = _execute_simulated_action("WHITELIST", data.get("target"), data.get("reason", "Manual whitelist"), "manual")
    if status_code == 200 and payload.get("status") == "success" and data.get("finding_id"):
        finding_state = apply_action_to_finding(
            data.get("finding_id"),
            action="WHITELIST",
            reason=data.get("reason", "Manual whitelist"),
            source="manual",
            confidence=float(data.get("confidence") or 0.0),
            queue_scan=None,
        )
        if finding_state:
            payload["finding"] = finding_state
    return jsonify(payload), status_code


@app.route("/block", methods=["POST"])
@require_auth
def manual_block():
    data = request.get_json() or {}
    payload, status_code = _execute_simulated_action("BLOCK", data.get("ip"), data.get("reason", "Legacy manual block"), "manual")
    return jsonify(payload), status_code


@app.route("/unblock", methods=["POST"])
@require_auth
def manual_unblock():
    data = request.get_json() or {}
    payload, status_code = execute_host_action(
        action="UNBLOCK",
        target=data.get("ip"),
        reason=data.get("reason", "Legacy manual unblock"),
        source="manual",
        trigger="manual",
    )
    return jsonify(payload), status_code


@app.route("/isolate", methods=["POST"])
@require_auth
def manual_isolate():
    data = request.get_json() or {}
    payload, status_code = _execute_simulated_action("ISOLATE", data.get("ip"), data.get("reason", "Legacy manual isolate"), "manual")
    return jsonify(payload), status_code


@app.route("/unisolate", methods=["POST"])
@require_auth
def manual_unisolate():
    data = request.get_json() or {}
    payload, status_code = execute_host_action(
        action="UNISOLATE",
        target=data.get("ip"),
        reason=data.get("reason", "Legacy manual unisolate"),
        source="manual",
        trigger="manual",
    )
    return jsonify(payload), status_code


# ==============================================================================
# Pentest Agent Integration
# ==============================================================================

import uuid as _uuid
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


def _queue_pentest_scan(target: str, scan_type: str, triggered_by: str) -> str | None:
    scan_id = _uuid.uuid4().hex[:12]
    ok = sync_insert_pentest_scan(scan_id, target, scan_type, triggered_by)
    if not ok:
        return None
    print("Submitting task to executor", {"scan_id": scan_id, "target": target, "scan_type": scan_type, "triggered_by": triggered_by})
    _pentest_executor.submit(_run_pentest_pipeline, scan_id, target, scan_type, triggered_by)
    return scan_id


def _run_pentest_pipeline(scan_id: str, target: str, scan_type: str, triggered_by: str):
    """
    Run the pentest pipeline in a background thread.
    Creates its own event loop since we're outside Flask's main thread.
    """
    global _active_pentest_scans
    import logging
    plog = logging.getLogger("pentest.flask_bridge")

    try:
        with _pentest_lock:
            _active_pentest_scans += 1

        print("RUN PIPELINE STARTED:", scan_id, target, scan_type, triggered_by)
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
                        print("DB UPDATE:", payload.get("status"), payload.get("progress"), payload.get("current_stage"))
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
                    print("DB UPDATE:", "running", 5, "recon")

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
                        current_stage="report",
                        results=result_dict,
                        completed_at=completed,
                    )
                    print("DB UPDATE:", result.status.value, 100, "report")
                    await pentest_db.update_scan(
                        scan_id,
                        status=result.status.value,
                        progress=100,
                        current_stage="report",
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
                        current_stage=latest.get("current_stage", "report"),
                        results=timeout_results,
                        completed_at=completed,
                    )
                    print("DB UPDATE:", "failed", 100, latest.get("current_stage", "report"))
                    await pentest_db.update_scan(
                        scan_id,
                        status="failed",
                        progress=100,
                        current_stage=latest.get("current_stage", "report"),
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
                        current_stage=latest.get("current_stage", "report"),
                        results=failed_results,
                        completed_at=completed,
                    )
                    print("DB UPDATE:", "failed", 100, latest.get("current_stage", "report"))
                    await pentest_db.update_scan(
                        scan_id,
                        status="failed",
                        progress=100,
                        current_stage=latest.get("current_stage", "report"),
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
        sync_update_pentest_scan(scan_id, status="failed", progress=100, current_stage="report", results={"error": str(exc)}, completed_at=datetime.utcnow().isoformat())
        print("DB UPDATE:", "failed", 100, "report")
    finally:
        with _pentest_lock:
            _active_pentest_scans -= 1


@app.route("/pentest/scan", methods=["POST"])
@require_auth
def pentest_start_scan():
    """
    POST /pentest/scan
    Start a new pentest scan.

    Body: { "target": "...", "scan_type": "quick"|"full"|"stealth" }
    Response 202: { "scan_id": "...", "target": "...", "status": "queued", "scan_type": "..." }
    """
    data = request.get_json() or {}
    print("REQUEST:", data)
    target = (data.get("target") or "").strip()
    scan_type = data.get("scan_type", "quick").strip().lower()

    if not target:
        return jsonify({"error": "Target cannot be empty"}), 400

    if scan_type not in ("quick", "full", "stealth"):
        return jsonify({"error": f"Invalid scan_type: {scan_type}. Use quick, full, or stealth."}), 400

    if PENTEST_MODE == "external" and scan_type != "quick":
        return jsonify({
            "error": "External mode only permits quick scanning",
            "pentest_mode": PENTEST_MODE,
        }), 403

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
    print("RESOLVED IP:", validation.get("resolved_ip"))
    print("VALIDATION:", validation)
    is_safe = bool(validation.get("allowed"))
    reason = validation.get("reason") or "unknown validation failure"
    if not is_safe:
        print("REJECTION REASON:", reason)
        return jsonify({
            "error": reason,
            "target": target,
            "resolved_ip": validation.get("resolved_ip"),
            "validation": validation,
        }), 403

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
    print("Submitting task to executor", {"scan_id": scan_id, "target": target, "scan_type": scan_type, "triggered_by": triggered_by})
    _pentest_executor.submit(_run_pentest_pipeline, scan_id, target, scan_type, triggered_by)

    print(f"[PENTEST] Scan queued: {scan_id} -> {target} ({scan_type})")

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
@require_auth
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
@require_auth
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
@require_auth
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
@require_auth
def activity_logs_list():
    limit = _safe_limit(default=50, maximum=200)
    type_filter = (request.args.get('type') or '').strip() or None
    target = (request.args.get('target') or '').strip() or None
    rows = sync_get_activity_logs(limit=limit, type_filter=type_filter, target=target)
    return jsonify(rows), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
