"""
predict.py — Smart Model Loader (Binary + Multi-Class Auto-Detection)
======================================================================
بيـ auto-detect النموذج المتاح:
  1. لو xgb_model_multiclass.pkl موجود → يستخدمه (multi-class, 7 فئات)
  2. لو مش موجود → يرجع للنموذج الثنائي القديم xgb_model.pkl

بعد تشغيل train_multiclass.py، النظام هيترقى تلقائياً بدون أي تغيير.
"""

import os
import time
import joblib
import pandas as pd
from config import (
    THRESHOLD_HIGH_ATTACK, THRESHOLD_MEDIUM_ATTACK, THRESHOLD_SUSPICIOUS,
    ATTACK_CLASS_NAMES,
)
from performance_monitor import performance_monitor

# ==============================================================================
# MODEL LOADING — Auto-detect multiclass vs binary
# ==============================================================================
_MULTICLASS_PATH = "xgb_model_multiclass.pkl"
_MULTICLASS_SCALER_PATH = "xgb_model_multiclass_scaler.pkl"
_MULTICLASS_COLUMNS_PATH = "xgb_model_multiclass_columns.pkl"

_use_multiclass = os.path.exists(_MULTICLASS_PATH)

if _use_multiclass:
    print("[predict.py] Multi-class model detected -> loading xgb_model_multiclass.pkl")
    xgb_model = joblib.load(_MULTICLASS_PATH)
    scaler    = joblib.load(_MULTICLASS_SCALER_PATH)
    columns   = joblib.load(_MULTICLASS_COLUMNS_PATH)
else:
    print("[predict.py] Binary model loaded (run train_multiclass.py to upgrade)")
    xgb_model = joblib.load("xgb_model.pkl")
    scaler    = joblib.load("scaler.pkl")
    columns   = joblib.load("columns.pkl")

# Isolation Forest always loaded (works for both modes)
iso_model = joblib.load("iso_model.pkl")


# ==============================================================================
# PREPROCESSING
# ==============================================================================
def preprocess(sample_dict: dict):
    """Aligns incoming flow dict with the model's expected feature columns."""
    df = pd.DataFrame([sample_dict])
    df.columns = df.columns.str.strip()

    full_df = pd.DataFrame(columns=columns)

    for col in df.columns:
        if col in full_df.columns:
            full_df.loc[0, col] = df[col].values[0]

    full_df = full_df.fillna(0).astype(float)
    return scaler.transform(full_df)


# ==============================================================================
# PREDICTION LOGIC
# ==============================================================================
def predict(sample_dict: dict) -> dict:
    """
    Runs the full prediction pipeline on a flow dict.

    Returns:
        {
            "result":      "ATTACK" | "SUSPICIOUS" | "NORMAL",
            "attack_type": str,          -- e.g. "DDoS", "WebAttack", ...
            "confidence":  float,
            "iso_flag":    int (0|1),
            "class_id":    int           -- 0..6 (multiclass) or 0..1 (binary)
        }
    """
    try:
        detection_started = time.perf_counter()
        sample = preprocess(sample_dict)
        inference_started = time.perf_counter()

        # ── Isolation Forest ──────────────────────────────────────────────────
        iso_raw = iso_model.predict(sample)[0]
        iso     = 1 if iso_raw == -1 else 0

        # ── XGBoost ───────────────────────────────────────────────────────────
        if _use_multiclass:
            # --- Multi-class mode ---
            class_id   = int(xgb_model.predict(sample)[0])
            proba      = xgb_model.predict_proba(sample)[0]
            confidence = float(max(proba))           # المعرفة بالفئة المختارة

            attack_type = ATTACK_CLASS_NAMES.get(class_id, f"class_{class_id}")
            # Strip emoji for safe ASCII output
            attack_type_safe = attack_type.encode("ascii", "ignore").decode().strip()

            if class_id == 0 and iso == 0:
                result = "NORMAL"
            elif class_id == 0 and iso == 1:
                result  = "SUSPICIOUS"
                attack_type_safe = "ANOMALY (IsoForest)"
            else:
                # Any non-BENIGN class → ATTACK, confidence decides severity
                result = "ATTACK" if confidence >= THRESHOLD_MEDIUM_ATTACK else "SUSPICIOUS"

        else:
            # --- Binary mode (backward compatible) ---
            prob       = float(xgb_model.predict_proba(sample)[0][1])
            class_id   = 1 if prob >= 0.5 else 0
            confidence = prob
            attack_type_safe = "UNKNOWN"

            if prob > THRESHOLD_HIGH_ATTACK:
                result = "ATTACK"
                attack_type_safe = "HIGH CONFIDENCE ATTACK"
            elif prob > THRESHOLD_MEDIUM_ATTACK and iso == 1:
                result = "ATTACK"
                attack_type_safe = "MEDIUM CONFIDENCE ATTACK"
            elif prob > THRESHOLD_SUSPICIOUS or iso == 1:
                result = "SUSPICIOUS"
                attack_type_safe = "ANOMALY DETECTED"
            else:
                result = "NORMAL"
                attack_type_safe = "BENIGN"

        inference_ms = (time.perf_counter() - inference_started) * 1000
        detection_ms = (time.perf_counter() - detection_started) * 1000
        performance_monitor.record(
            "ai_inference_time",
            inference_ms,
            model_mode="multiclass" if _use_multiclass else "binary",
            attack_type=attack_type_safe,
            result=result,
            source="predict.py",
        )
        performance_monitor.record(
            "detection_latency",
            detection_ms,
            model_mode="multiclass" if _use_multiclass else "binary",
            attack_type=attack_type_safe,
            result=result,
            source="predict.py",
        )

        return {
            "result":      result,
            "attack_type": attack_type_safe,
            "confidence":  confidence,
            "iso_flag":    iso,
            "class_id":    class_id,
            "timing": {
                "ai_inference_ms": round(inference_ms, 3),
                "detection_latency_ms": round(detection_ms, 3),
            },
        }

    except Exception as e:
        return {
            "result":      "ERROR",
            "attack_type": str(e),
            "confidence":  0.0,
            "iso_flag":    0,
            "class_id":    -1,
        }
