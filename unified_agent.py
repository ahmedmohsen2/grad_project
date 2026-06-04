"""
unified_agent.py  —  THE ONE AGENT
====================================
يدمج كل الـ agents السابقة في ملف واحد بـ 3 modes:

  LIVE mode   — يلتقط حركة المرور الحية بـ Scapy
  PCAP mode   — يحلل ملف PCAP موجود
  CSV  mode   — يحلل ملف CSV أو يراقبه بشكل مستمر

كل الـ modes بيستخدموا نفس Pipeline:
  Flow Extraction
      └─► ML (XGBoost + IsoForest)      ← per flow, via API
      └─► DDoS Detector                 ← aggregate, rule-based
      └─► Brute Force Detector          ← aggregate, rule-based
      └─► Malware Detector              ← aggregate, rule-based
            └─► Fusion Engine
                  └─► Action Engine (block / monitor)

الاستخدام:
  python unified_agent.py --mode live
  python unified_agent.py --mode pcap  --input traffic.pcap
  python unified_agent.py --mode csv   --input flows.csv
  python unified_agent.py --mode csv   --input live_traffic.csv --watch
"""

import sys
import csv
import time
import argparse
import logging
import threading
import requests
import numpy as np
from collections import defaultdict, deque

# ── Encoding fix (Windows) ────────────────────────────────────
sys.stdout.reconfigure(encoding="utf-8")

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("UnifiedAgent")

# ── Local modules ─────────────────────────────────────────────
from action             import take_action
from action_manager     import execute_action          # Threat-specific IPS dispatcher
from auto_response_engine import auto_response_engine
from config             import (
    AUTO_RESPONSE_ENABLED, FLOW_TIMEOUT_SEC, MAX_FLOW_PACKETS, API_URL,
    CAPTURE_INTERFACE, PROMISCUOUS_MODE, SENSOR_MODE,
)
from host_actions       import execute_host_action, get_action_state
from ddos_detector_module  import detect_ddos_from_flows
from brute_force_detector  import bruteforce_verdict_by_ip
from malware_detector      import malware_verdict_by_ip
# FIX 1 + FIX 5 — shared, consistent PPS calculation
from flow_utils            import compute_pps
from state_manager         import agent_state
from dashboard_api         import run_api_server
from network_sensor        import (
    LIMITATIONS_BY_MODE,
    VISIBILITY_BY_MODE,
    increment_flows,
    increment_packets,
    mark_sensor_started,
    normalize_sensor_mode,
)

from db import (
    sync_init_pool,
    sync_db_ping,
    sync_insert_alert,
    sync_insert_detection,
    sync_insert_flow,
    sync_upsert_host,
    sync_insert_action
)

# ── Adaptive intelligence (new, non-breaking) ────────────────────
try:
    from baseline_engine import get_engine as _get_baseline
    from context_layer   import get_context_layer as _get_ctx, TrafficVerdict
    _ADAPTIVE = True
except ImportError:
    _ADAPTIVE = False
    log.warning("baseline_engine / context_layer not found — running in legacy mode.")

if _ADAPTIVE:
    _baseline = _get_baseline()
    _ctx      = _get_ctx()

# ══════════════════════════════════════════════════════════════
# SECTION 1 — HYBRID FUSION ENGINE  (upgraded)
# ══════════════════════════════════════════════════════════════

def fusion(
    ddos: str, brute: str, malware: str, ml_result: dict,
    ctx_result=None,           # optional ContextResult from context_layer
) -> tuple[str, str]:
    """
    Hybrid multi-signal fusion engine  (TUNED — thresholds raised for FP reduction).

    Rules (priority order)
    ----------------------
    ATTACK     → strong rule trigger (DDoS / BruteForce / Malware)
                 OR ML ATTACK with conf > 0.85  (was 0.85, unchanged)
                 OR ML ATTACK with conf > 0.70 AND iso_flag  (was 0.65)

    SUSPICIOUS → ML ATTACK with moderate conf (0.50–0.70)
                 OR ML SUSPICIOUS with corroboration
                 OR context-layer multi-signal

    NORMAL     → no strong signals  (iso alone or low-conf ML is NOT sufficient)
    """
    ml_label  = ml_result.get("result",      "NORMAL").upper()
    ml_type   = ml_result.get("attack_type", "")
    ml_conf   = float(ml_result.get("confidence",  0.0))
    iso_flag  = int(ml_result.get("iso_flag",      0))

    # ── 1. Strong rule triggers (priority unchanged) ──────────
    if ddos    == "ATTACK": return "ATTACK", "DDoS"
    if brute   == "ATTACK": return "ATTACK", "BruteForce"
    if malware == "ATTACK": return "ATTACK", "Malware"

    # ── 2. ML ATTACK verdict — TUNED thresholds ───────────────
    if "ATTACK" in ml_label:
        if ml_conf > 0.85:
            return "ATTACK",    f"ML:{ml_type}(conf={ml_conf:.2f})"
        if ml_conf > 0.70 and iso_flag == 1:   # was 0.65
            return "ATTACK",    f"ML+ISO:{ml_type}(conf={ml_conf:.2f})"
        if ml_conf > 0.50:                      # was 0.50 — unchanged, but now feeds SUSPICIOUS only
            return "SUSPICIOUS", f"ML:{ml_type}(conf={ml_conf:.2f},moderate)"
        # Low confidence ML ATTACK alone → normal; do not escalate
        return "NORMAL", f"ML_LOW_CONF:{ml_type}(conf={ml_conf:.2f})"

    # ── 3. ML SUSPICIOUS — require corroboration ──────────────
    if "SUSPICIOUS" in ml_label:
        if malware == "SUSPICIOUS":
            return "SUSPICIOUS", f"ML+Malware(Suspicious):{ml_type}"
        if iso_flag == 1 and ml_conf > 0.50:    # was 0.30 → raised
            return "SUSPICIOUS", f"ML(ISO+moderate_conf):{ml_type}"
        # iso alone or very low conf → suppress
        return "NORMAL", "BENIGN"

    # ── 4. Context-layer escalation (adaptive module only) ────
    if ctx_result is not None and _ADAPTIVE:
        if ctx_result.is_attack:
            return "SUSPICIOUS", "ContextLayer:MultiSignal"
        if ctx_result.is_suspicious and malware == "SUSPICIOUS":
            return "SUSPICIOUS", "ContextLayer+Malware"

    # ── 5. Malware suspicious alone ───────────────────────────
    if malware == "SUSPICIOUS":
        return "SUSPICIOUS", "Malware(Suspicious)"

    return "NORMAL", "BENIGN"


# ══════════════════════════════════════════════════════════════
# SECTION 2 — ML API CALL  (shared)
# ══════════════════════════════════════════════════════════════

def call_ml_api(features: dict) -> dict:
    """يبعت التدفق للـ Flask API ويرجع النتيجة."""
    try:
        resp = requests.post(API_URL, json=features, timeout=3)
        if resp.status_code == 200:
            return resp.json()
    except requests.exceptions.ConnectionError:
        log.warning("API is not running! Start api.py first.")
    except requests.exceptions.Timeout:
        log.warning("API timeout.")
    except Exception as e:
        log.warning(f"API error: {e}")
    return {"result": "ERROR", "attack_type": "", "confidence": 0.0}


# ══════════════════════════════════════════════════════════════
# SECTION 3 — AGGREGATE ANALYSIS  (shared)
# ══════════════════════════════════════════════════════════════

def run_aggregate(
    flows: list[dict],
    label: str = "",
    ml_results: dict | None = None,   # { src_ip → ml prediction dict }
):
    """
    Runs DDoS + BruteForce + Malware on a batch of flows and takes
    action on any suspicious IPs.

    ml_results: if provided, passed into malware_verdict_by_ip so that
    the ML override can suppress benign-but-noisy flows.
    """
    if not flows:
        return

    log.info(f"[Aggregate{' '+label if label else ''}] Analyzing {len(flows)} flows...")

    # NOTE: DO NOT feed the baseline engine here.
    # Each flow is already observed ONCE in process_flow_ml().
    # Double-calling _ctx.observe() corrupts the baseline mean/std.

    ddos_v    = detect_ddos_from_flows(flows)
    brute_v   = bruteforce_verdict_by_ip(flows)
    # Pass ml_results so malware detector can apply ML override
    malware_v = malware_verdict_by_ip(flows, ml_results=ml_results)

    all_ips = {
        (f.get("Src IP") or f.get("Source IP") or f.get("src_ip", "unknown"))
        for f in flows
    }

    acted: list[str] = []
    for ip in all_ips:
        d = ddos_v.get(ip,    "NORMAL")
        b = brute_v.get(ip,   "NORMAL")
        m = malware_v.get(ip, "NORMAL")

        # Context result from adaptive module
        ctx_result = None
        if _ADAPTIVE:
            ip_flows = [
                f for f in flows
                if (f.get("Src IP") or f.get("Source IP") or
                    f.get("src_ip")) == ip
            ]
            if ip_flows:
                ctx_result = _ctx.evaluate(ip_flows[-1])

        # Collect per-IP stats for structured log
        ip_flows_all = [
            f for f in flows
            if (f.get("Src IP") or f.get("Source IP") or f.get("src_ip")) == ip
        ]
        ml_r   = (ml_results or {}).get(ip, {})
        ml_conf = float(ml_r.get("confidence", 0.0))
        ml_lbl  = ml_r.get("result", "N/A")
        total_pkt = sum(int(f.get("Total Packets", 0)) for f in ip_flows_all)
        total_byt = sum(_get_bytes(f) for f in ip_flows_all)
        avg_pps   = (
            sum(float(f.get("Packets per Second", 0)) for f in ip_flows_all)
            / max(len(ip_flows_all), 1)
        )

        verdict, reason = fusion(d, b, m, ml_r, ctx_result)

        # ── Structured decision log (MANDATORY) ───────────────
        log.info(
            f"[Decision] src_ip={ip} "
            f"packets={total_pkt} bytes={total_byt} pps={avg_pps:.1f} "
            f"ddos={d} brute={b} malware={m} "
            f"ml_label={ml_lbl} ml_conf={ml_conf:.3f} "
            f"verdict={verdict} reason={reason}"
        )

        # ── Update in-memory state manager ───────────────
        agent_state.update_decision(ip, total_pkt, total_byt, avg_pps, verdict, reason)

        if verdict in ("ATTACK", "SUSPICIOUS"):
            flags = []
            if d == "ATTACK": flags.append("DDoS")
            if b == "ATTACK": flags.append("BruteForce")
            if m in ("ATTACK", "SUSPICIOUS"): flags.append(f"Malware({m})")
            flags_str = "+".join(flags) or reason

            icon = "[!!]" if verdict == "ATTACK" else "[? ]"
            print(f"  {icon} [{verdict:<10}] src={ip:<16} detectors={flags_str}")

            # Rule-based triggers get conf=1.0, ML-only gets ml_conf
            rule_triggered = any(x in flags_str for x in ["DDoS", "BruteForce", "Malware"])
            action_conf = 1.0 if rule_triggered else max(ml_conf, 0.0)

            # DB Insertion
            try:
                sync_insert_detection(
                    src_ip=ip,
                    result=verdict,
                    attack_type=reason,
                    confidence=action_conf,
                    iso_flag=0
                )
                sync_insert_alert(
                    ip,
                    reason,
                    f"{reason} detected from {ip}"
                )
                sync_upsert_host(ip, "COMPROMISED")
                print(f"[DB] Alert stored: {ip} - {reason}")
            except Exception as e:
                log.warning(f"[DB] Detection storage failed: {e}")

            # ── [WS] Broadcast alert to all connected dashboard clients ──
            agent_state.broadcast_alert(ip, reason, f"{reason} detected from {ip}")

            # ── [AUTO DEFENSE] Decide and execute automatic response ─────
            action_state = get_action_state(ip)
            auto_history = auto_response_engine.record_event(
                {
                    "ip": ip,
                    "confidence": action_conf,
                    "attack_type": reason,
                    "pps": avg_pps,
                }
            )
            auto_decision = auto_response_engine.evaluate(
                {
                    "ip": ip,
                    "confidence": action_conf,
                    "attack_type": reason,
                    "pps": avg_pps,
                    "history": auto_history,
                }
            )
            if AUTO_RESPONSE_ENABLED and not action_state.get("is_whitelisted") and auto_decision.action:
                payload, _ = execute_host_action(
                    action=auto_decision.action,
                    target=ip,
                    reason=auto_decision.reason,
                    source="auto",
                    confidence=action_conf,
                    trigger="auto",
                )
                if payload.get("status") == "success":
                    print(f"[AUTO RESPONSE] {auto_decision.action} triggered for {ip} (conf={action_conf:.2f})")
                    auto_response_engine.mark_action(ip)
                    agent_state.broadcast_action(ip, auto_decision.action.upper(), reason=auto_decision.reason)

            # Route to threat-specific action handler (Action Manager)
            if not AUTO_RESPONSE_ENABLED:
                if "DDoS" in flags_str:
                    execute_action(ip, "DDOS",       verdict, reason=flags_str, conf=action_conf)
                elif "BruteForce" in flags_str:
                    execute_action(ip, "BRUTEFORCE", verdict, reason=flags_str, conf=action_conf)
                elif "Malware" in flags_str:
                    threat = "RANSOMWARE" if "ansomware" in flags_str else "MALWARE"
                    execute_action(ip, threat,       verdict, reason=flags_str, conf=action_conf)
                else:
                    execute_action(ip, "GENERIC",    verdict, reason=flags_str, conf=action_conf)

            acted.append(ip)

    if not acted:
        log.info("  [OK] No aggregate threats found.")


def _get_bytes(flow: dict) -> int:
    """Extract total bytes from a flow dict, trying multiple key names."""
    for k in ("Total Bytes", "Total Length of Fwd Packets",
              "Subflow Fwd Bytes", "total_bytes"):
        v = flow.get(k)
        if v is not None:
            try:
                return int(float(v))
            except (ValueError, TypeError):
                pass
    return 0


# ══════════════════════════════════════════════════════════════
# SECTION 4 — FLOW FEATURE COMPUTATION  (shared)
# ══════════════════════════════════════════════════════════════

def _safe(fn, lst, default=0.0):
    try: return float(fn(lst)) if lst else default
    except: return default

def compute_features(flow_data: dict) -> dict | None:
    """يحوّل بيانات التدفق الخام لـ feature vector متوافق مع CICIDS."""
    pkts = flow_data.get("packets", [])
    if not pkts:
        return None

    times  = [p["time"] for p in pkts]
    sizes  = [p["size"] for p in pkts]
    fwd    = [p for p in pkts if p.get("direction") == "fwd"]
    bwd    = [p for p in pkts if p.get("direction") == "bwd"]
    fwd_sz = [p["size"] for p in fwd]
    bwd_sz = [p["size"] for p in bwd]

    dur_us = (times[-1] - times[0]) * 1_000_000 if len(times) > 1 else 1.0
    dur_us = max(dur_us, 1.0)
    iats   = [times[i+1]-times[i] for i in range(len(times)-1)]

    return {
        "Src IP":   flow_data.get("src_ip"),
        "Dst IP":   flow_data.get("dst_ip"),
        "Src Port": flow_data.get("src_port"),
        "Dst Port": flow_data.get("dst_port"),
        "Destination Port":             flow_data.get("dst_port", 0),
        "Flow Duration":                dur_us,
        "Total Fwd Packets":            len(fwd),
        "Total Backward Packets":       len(bwd),
        "Total Length of Fwd Packets":  sum(fwd_sz),
        "Total Length of Bwd Packets":  sum(bwd_sz),
        "Fwd Packet Length Max":        _safe(max, fwd_sz),
        "Fwd Packet Length Min":        _safe(min, fwd_sz),
        "Fwd Packet Length Mean":       _safe(np.mean, fwd_sz),
        "Fwd Packet Length Std":        _safe(np.std,  fwd_sz),
        "Bwd Packet Length Max":        _safe(max, bwd_sz),
        "Bwd Packet Length Min":        _safe(min, bwd_sz),
        "Bwd Packet Length Mean":       _safe(np.mean, bwd_sz),
        "Bwd Packet Length Std":        _safe(np.std,  bwd_sz),
        "Flow IAT Mean":                _safe(np.mean, iats),
        "Flow IAT Std":                 _safe(np.std,  iats),
        "Flow IAT Max":                 _safe(max, iats),
        "Flow IAT Min":                 _safe(min, iats),
        "Fwd IAT Total":                float(sum(iats)),
        "Fwd IAT Mean":                 _safe(np.mean, iats),
        "Fwd IAT Std":                  _safe(np.std,  iats),
        "Fwd IAT Max":                  _safe(max, iats),
        "Fwd IAT Min":                  _safe(min, iats),
        "SYN Flag Count":               sum(1 for p in pkts if p.get("SYN")),
        "FIN Flag Count":               sum(1 for p in pkts if p.get("FIN")),
        "RST Flag Count":               sum(1 for p in pkts if p.get("RST")),
        "PSH Flag Count":               sum(1 for p in pkts if p.get("PSH")),
        "ACK Flag Count":               sum(1 for p in pkts if p.get("ACK")),
        "URG Flag Count":               sum(1 for p in pkts if p.get("URG")),
        "Packet Length Mean":           _safe(np.mean, sizes),
        "Packet Length Std":            _safe(np.std,  sizes),
        "Max Packet Length":            _safe(max, sizes),
        "Min Packet Length":            _safe(min, sizes),
        "Average Packet Size":          _safe(np.mean, sizes),
        "Avg Fwd Segment Size":         _safe(np.mean, fwd_sz),
        "Avg Bwd Segment Size":         _safe(np.mean, bwd_sz),
        "Subflow Fwd Packets":          len(fwd),
        "Subflow Fwd Bytes":            sum(fwd_sz),
        "Subflow Bwd Packets":          len(bwd),
        "Subflow Bwd Bytes":            sum(bwd_sz),
        "act_data_pkt_fwd":            sum(1 for p in fwd if p["size"] > 0),
        "min_seg_size_forward":         _safe(min, fwd_sz),
        # FIX 1 + FIX 5: use shared compute_pps() with 0.01s floor
        # (was: len(pkts) / max(dur_us / 1e6, 1e-9)  → could reach 1,000,000,000)
        "Packets per Second":           compute_pps(len(pkts), dur_us / 1_000_000),
        "Total Packets":                len(pkts),
        "Total Bytes":                  sum(sizes),
    }


def process_flow_ml(features: dict, src_ip: str):
    """Send flow to ML API, apply context-aware filter, structured-log, take action."""
    # ── MICRO FLOW HANDLING: Tag, don't drop (preserves scan/probe detection) ──
    dur = float(features.get("Flow Duration", 0.0)) / 1_000_000
    pkts = int(features.get("Total Packets", 0))
    is_micro = dur < 0.5 or pkts < 3

    # Feed the baseline engine (all flows, including micro)
    if _ADAPTIVE:
        _ctx.observe(features)

    ml = call_ml_api(features)
    if "ERROR" in ml.get("result", "").upper():
        return ml

    label    = ml.get("result",      "NORMAL")
    atype    = ml.get("attack_type", "")
    conf     = float(ml.get("confidence", 0.0))
    iso_flag = int(ml.get("iso_flag",     0))
    ae_flag  = int(ml.get("ae_flag",      0))

    pps = float(features.get("Packets per Second", 0.0))
    dur = float(features.get("Flow Duration", 0.0)) / 1_000_000   # µs → s
    pkts = int(features.get("Total Packets", 0))
    byts = _get_bytes(features)

    # Context evaluation for per-flow FP suppression
    ctx_result = None
    if _ADAPTIVE:
        ctx_result = _ctx.evaluate(features, raw_pps=pps)

    # Hybrid fusion (rule verdicts all NORMAL here — per-flow ML only)
    fused_verdict, fused_reason = fusion(
        "NORMAL", "NORMAL", "NORMAL", ml, ctx_result
    )

    icon = (
        "[!!]" if fused_verdict == "ATTACK" else
        "[? ]" if fused_verdict == "SUSPICIOUS" else "[OK]"
    )

    # ── Micro flow: cap confidence, log at DEBUG (visible but not noisy) ───
    if is_micro:
        conf = min(conf, 0.4)   # Hard cap: micro flows cannot trigger a block
        log.debug(
            f"[micro] src={src_ip:<15} type={atype:<22} "
            f"dur={dur:.3f}s pkts={pkts} conf_capped={conf:.3f}"
        )
    else:
        # ── Structured per-flow log ────────────────────────────────────────
        log.info(
            f"{icon} src={src_ip:<15} type={atype:<22} "
            f"conf={conf:.3f} iso={iso_flag} ae={ae_flag} "
            f"pps={pps:.1f} dur={dur:.2f}s pkts={pkts} bytes={byts} "
            f"fused={fused_verdict} reason={fused_reason}"
        )

    # Only act if conf > 0.85 AND not a micro flow
    if fused_verdict == "ATTACK" and conf > 0.85 and not is_micro:
        take_action(fused_verdict, src_ip, attack_type=atype, conf=conf)
        
    try:
        dst_ip = features.get("Dst IP") or features.get("Destination IP") or features.get("dst_ip", "unknown")
        sync_insert_flow(src_ip, dst_ip, pkts, byts, pps, dur)
    except Exception as e:
        log.warning(f"[DB] Flow logging failed: {e}")
        
    return ml


# ══════════════════════════════════════════════════════════════
# SECTION 5 — MODE: LIVE  (Scapy packet capture)
# ══════════════════════════════════════════════════════════════

ROLLING_WINDOW   = 500   # أقصى عدد تدفقات في النافذة
ANALYSIS_INTERVAL = 10.0  # كل كام ثانية يتشغّل الـ aggregate

def _run_live(iface: str | None = None, sensor_mode: str | None = None, promiscuous: bool | None = None):
    try:
        from scapy.all import sniff, IP, TCP, UDP, conf
    except ImportError:
        log.error("Scapy غير مثبّت. شغّل: pip install scapy")
        return

    active_promiscuous = PROMISCUOUS_MODE if promiscuous is None else bool(promiscuous)
    active_iface = iface or CAPTURE_INTERFACE or str(conf.iface or "")
    active_sensor_mode = normalize_sensor_mode(sensor_mode)
    mark_sensor_started(
        interface=active_iface or None,
        sensor_mode=active_sensor_mode,
        promiscuous=active_promiscuous,
    )

    flow_table   = defaultdict(lambda: {
        "packets": [], "last_seen": 0.0,
        "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None,
    })
    flow_lock    = threading.Lock()
    rolling      = deque(maxlen=ROLLING_WINDOW)
    rolling_lock = threading.Lock()

    # ── helpers ──────────────────────────────────────────────
    def _get_key(pkt):
        if IP not in pkt: return None, None, None
        s, d = pkt[IP].src, pkt[IP].dst
        sp   = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dp   = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        if (s, sp) < (d, dp): return (s, sp, d, dp), s, d
        return (d, dp, s, sp), s, d

    def _parse(pkt, src):
        flags = {}
        if TCP in pkt:
            t = pkt[TCP]
            flags = {
                "SYN": bool(t.flags & 0x02), "FIN": bool(t.flags & 0x01),
                "RST": bool(t.flags & 0x04), "PSH": bool(t.flags & 0x08),
                "ACK": bool(t.flags & 0x10), "URG": bool(t.flags & 0x20),
            }
        return {"time": float(pkt.time), "size": len(pkt),
                "direction": "fwd" if pkt[IP].src == src else "bwd", **flags}

    def _flush(key, snap):
        features = compute_features(snap)
        if not features: return
        increment_flows(1)
        with rolling_lock:
            rolling.append(features)
        process_flow_ml(features, snap["src_ip"])

    # ── timeout flusher thread ───────────────────────────────
    def _flusher():
        while True:
            time.sleep(1.0)
            now = time.time()
            expired = []
            with flow_lock:
                for k, f in list(flow_table.items()):
                    if f["last_seen"] > 0 and (now - f["last_seen"]) >= FLOW_TIMEOUT_SEC:
                        expired.append((k, dict(f)))
                        del flow_table[k]
            for k, snap in expired:
                threading.Thread(target=_flush, args=(k, snap), daemon=True).start()

    # ── aggregate thread ─────────────────────────────────────
    def _aggregate():
        while True:
            time.sleep(ANALYSIS_INTERVAL)
            with rolling_lock:
                window = list(rolling)
            if window:
                print(f"\n{'='*60}")
                print(f"  [~] Aggregate Analysis ({len(window)} flows)")
                print(f"{'='*60}")
                run_aggregate(window, label="LIVE")

    # ── packet handler ───────────────────────────────────────
    def _on_pkt(pkt):
        increment_packets(1)
        key, src, dst = _get_key(pkt)
        if not key: return
        pkt_data = _parse(pkt, src)
        flush_snap = None
        with flow_lock:
            f = flow_table[key]
            if f["src_ip"] is None:
                f["src_ip"]   = src
                f["dst_ip"]   = dst
                f["src_port"] = key[1]
                f["dst_port"] = key[3]
            f["packets"].append(pkt_data)
            f["last_seen"] = pkt_data["time"]
            if len(f["packets"]) >= MAX_FLOW_PACKETS:
                flush_snap = dict(f)
                del flow_table[key]
        if flush_snap:
            threading.Thread(target=_flush, args=(key, flush_snap), daemon=True).start()

    threading.Thread(target=_flusher,   daemon=True).start()
    threading.Thread(target=_aggregate, daemon=True).start()

    log.info("[LIVE] Sensor mode       : %s", active_sensor_mode.upper())
    log.info("[LIVE] Visibility type   : %s", VISIBILITY_BY_MODE[active_sensor_mode])
    log.info("[LIVE] Interface         : %s", active_iface or "scapy-default")
    log.info("[LIVE] Promiscuous mode  : %s", "ON" if active_promiscuous else "OFF")
    log.info("[LIVE] Limitation        : %s", LIMITATIONS_BY_MODE[active_sensor_mode])
    log.info("[LIVE] Sniffing... (Ctrl+C to stop)")
    sniff(iface=active_iface or None, filter="ip", prn=_on_pkt, store=False, promisc=active_promiscuous)


# ══════════════════════════════════════════════════════════════
# SECTION 6 — MODE: PCAP  (offline PCAP file)
# ══════════════════════════════════════════════════════════════

def _run_pcap(path: str):
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        log.error("Scapy غير مثبّت.")
        return

    log.info(f"[PCAP] Reading: {path}")
    packets = rdpcap(path)

    flows: dict = defaultdict(list)

    def _key(pkt):
        if IP not in pkt or TCP not in pkt: return None
        s, d = pkt[IP].src, pkt[IP].dst
        sp, dp = pkt[TCP].sport, pkt[TCP].dport
        if (s, sp) < (d, dp): return (s, sp, d, dp)
        return (d, dp, s, sp)

    for pkt in packets:
        k = _key(pkt)
        if k: flows[k].append(pkt)

    log.info(f"[PCAP] {len(flows)} flows identified. Building records...")

    completed: list[dict] = []
    TIME_WINDOW = 1  # seconds

    for (s, sp, d, dp), pkts in flows.items():
        pkts = sorted(pkts, key=lambda x: x.time)
        start = pkts[0].time
        win   = []

        def _emit(win, s, sp, d, dp):
            if not win: return
            dur = win[-1].time - win[0].time or 1e-6
            data = {
                "src_ip": s, "dst_ip": d, "src_port": sp, "dst_port": dp,
                "packets": [
                    {"time": float(p.time), "size": len(p),
                     "direction": "fwd" if p[IP].src == s else "bwd",
                     "SYN": bool(p[TCP].flags & 0x02) if TCP in p else False,
                     "FIN": bool(p[TCP].flags & 0x01) if TCP in p else False,
                     "RST": bool(p[TCP].flags & 0x04) if TCP in p else False,
                     "PSH": bool(p[TCP].flags & 0x08) if TCP in p else False,
                     "ACK": bool(p[TCP].flags & 0x10) if TCP in p else False,
                     "URG": bool(p[TCP].flags & 0x20) if TCP in p else False,
                    } for p in win
                ]
            }
            f = compute_features(data)
            if f: completed.append(f)

        for pkt in pkts:
            if pkt.time - start <= TIME_WINDOW:
                win.append(pkt)
            else:
                _emit(win, s, sp, d, dp)
                start, win = pkt.time, [pkt]
        _emit(win, s, sp, d, dp)

    log.info(f"[PCAP] {len(completed)} flow records extracted.")
    _run_analysis_on_flows(completed, label="PCAP")


# ══════════════════════════════════════════════════════════════
# SECTION 7 — MODE: CSV  (file or live-watch)
# ══════════════════════════════════════════════════════════════

def _run_csv(path: str, watch: bool = False):
    import pandas as pd
    import os

    def _load(path) -> list[dict]:
        if not os.path.exists(path):
            return []
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()
        return df.to_dict(orient="records")

    if not watch:
        # one-shot analysis
        log.info(f"[CSV] Loading: {path}")
        flows = _load(path)
        log.info(f"[CSV] {len(flows)} rows loaded.")
        _run_analysis_on_flows(flows, label="CSV")
    else:
        # live-watch mode — يراقب الملف باستمرار
        log.info(f"[CSV-WATCH] Watching: {path}  (Ctrl+C to stop)")
        last_index = 0
        buffer: list[dict] = []
        BATCH = 50   # بعد كل 50 صف جديد يشغّل التحليل

        while True:
            flows = _load(path)
            new   = flows[last_index:]
            if new:
                buffer.extend(new)
                last_index = len(flows)
                print(f"\n[CSV-WATCH] {len(new)} new flows received.")

                # ML per-flow
                for flow in new:
                    src = (flow.get("Source IP") or flow.get("Src IP", "unknown"))
                    ml  = call_ml_api(flow)
                    if "ERROR" not in ml.get("result", "").upper():
                        label = ml.get("result", "NORMAL")
                        atype = ml.get("attack_type", "")
                        conf  = ml.get("confidence", 0.0)
                        icon  = "[!!]" if "ATTACK" in label.upper() else "[? ]" if "SUSPICIOUS" in label.upper() else "[OK]"
                        print(f"  {icon} ML  src={src:<15}  type={atype:<22}  conf={conf:.3f}")

                # Aggregate every BATCH rows
                if len(buffer) >= BATCH:
                    print(f"\n{'='*60}")
                    print(f"  [~] Aggregate Analysis ({len(buffer)} flows)")
                    print(f"{'='*60}")
                    run_aggregate(buffer, label="CSV-WATCH")
                    buffer.clear()
            time.sleep(2)


# ══════════════════════════════════════════════════════════════
# SECTION 8 — SHARED OFFLINE PIPELINE
# ══════════════════════════════════════════════════════════════

def _run_analysis_on_flows(flows: list[dict], label: str = ""):
    """
    Complete pipeline on a list of flows:
      1. ML per-flow  (via API)         — collects ml_results by src_ip
      2. Aggregate (DDoS + BruteForce + Malware) — passes ml_results for ML override
      3. Summary
    """
    if not flows:
        log.warning("No flows to analyze.")
        return

    # ── MICRO FLOW HANDLING: Include in aggregate but tag as low confidence ──
    for f in flows:
        dur = float(f.get("Flow Duration", 0.0)) / 1_000_000
        pkts = int(f.get("Total Packets", 0))
        if dur < 0.5 or pkts < 3:
            # Tag as micro: won't trigger blocking, but still feeds DDoS/BruteForce/Malware aggregates
            f["_is_micro"] = True

    if not flows:
        log.info(f"[{label}] No flows to analyze.")
        return

    summary    = {"ATTACK": 0, "SUSPICIOUS": 0, "NORMAL": 0, "ERROR": 0}
    ml_results: dict = {}   # { src_ip → latest ml prediction dict }
    log.info(f"[{label}] Starting per-flow ML analysis ({len(flows)} flows)...\n")

    for flow in flows:
        src = (
            flow.get("Src IP") or flow.get("Source IP") or
            flow.get("src_ip", "unknown")
        )
        ml = call_ml_api(flow)

        if "ERROR" in ml.get("result", "").upper():
            summary["ERROR"] += 1
            continue

        # Store latest ML result per IP (used by malware ML-override)
        ml_results[src] = ml

        label_ml = ml.get("result", "NORMAL")
        atype    = ml.get("attack_type", "")
        conf     = float(ml.get("confidence", 0.0))
        icon     = (
            "[!!]" if "ATTACK"    in label_ml.upper() else
            "[? ]" if "SUSPICIOUS" in label_ml.upper() else "[OK]"
        )

        log.info(
            f"{icon} [{label_ml:<10}] src={src:<15} "
            f"type={atype:<22} conf={conf:.3f}"
        )
        bucket = label_ml.upper() if label_ml.upper() in summary else "NORMAL"
        summary[bucket] = summary.get(bucket, 0) + 1

        if "ATTACK" in label_ml.upper() and conf > 0.85:
            take_action(label_ml, src, attack_type=atype, conf=conf)

    # Aggregate — now with ml_results so malware detector can apply ML override
    print(f"\n{'='*60}")
    print(f"  [~] Aggregate Analysis ({len(flows)} flows)")
    print(f"{'='*60}")
    run_aggregate(flows, label=label, ml_results=ml_results)

    # Final summary
    total = sum(summary.values())
    print(f"\n{'='*60}")
    print(f"  FINAL SUMMARY  ({total} flows processed)")
    print(f"{'='*60}")
    print(f"  [!!] ATTACK    : {summary.get('ATTACK',    0)}")
    print(f"  [? ] SUSPICIOUS: {summary.get('SUSPICIOUS', 0)}")
    print(f"  [OK] NORMAL    : {summary.get('NORMAL',    0)}")
    print(f"  [XX] ERRORS    : {summary.get('ERROR',     0)}")
    print(f"{'='*60}")


# ══════════════════════════════════════════════════════════════
# SECTION 9 — CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Unified IDS Agent — LIVE | PCAP | CSV",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument(
        "--mode", choices=["live", "pcap", "csv"], default="live",
        help=(
            "وضع التشغيل:\n"
            "  live  -> التقاط حي بـ Scapy  (يحتاج Admin)\n"
            "  pcap  -> تحليل ملف PCAP\n"
            "  csv   -> تحليل ملف CSV\n"
        ),
    )
    p.add_argument(
        "--input", default="flows.csv",
        help="مسار ملف الإدخال (PCAP أو CSV) — غير مطلوب في mode=live",
    )
    p.add_argument(
        "--watch", action="store_true",
        help="في mode=csv: يراقب الملف باستمرار بدل one-shot",
    )
    p.add_argument(
        "--iface",
        default=None,
        help="Capture interface for LIVE mode, for example: --iface Ethernet",
    )
    p.add_argument(
        "--sensor-mode",
        choices=["host", "span", "tap", "inline"],
        default=None,
        help="Deployment profile: host | span | tap | inline",
    )
    p.add_argument(
        "--no-promisc",
        action="store_true",
        help="Disable promiscuous capture mode in LIVE mode.",
    )
    return p.parse_args()


def main():
    args = parse_args()

    # CRITICAL: Initialize DB connection pool before any operations
    db_ready = sync_init_pool(retries=3, retry_delay=2.0)
    if db_ready:
        sync_db_ping()
        print("  [*] DB Connection Pool initialized — OK")
    else:
        print("  [!] DB Pool init FAILED after 3 attempts.")
        print("  [!] Running in DEGRADED mode — detections will NOT be persisted.")
        print("  [!] Start PostgreSQL and restart to enable DB logging.")

    print("\n" + "=" * 60)
    print("  [*] UNIFIED IDS AGENT")
    print(f"  Mode  : {args.mode.upper()}")
    if args.mode == "live":
        banner_sensor_mode = normalize_sensor_mode(args.sensor_mode or SENSOR_MODE)
        print(f"  Iface : {args.iface or CAPTURE_INTERFACE or 'scapy-default'}")
        print(f"  Sensor: {banner_sensor_mode.upper()} ({VISIBILITY_BY_MODE[banner_sensor_mode]})")
        print(f"  Promisc: {'OFF' if args.no_promisc else 'ON' if PROMISCUOUS_MODE else 'OFF'}")
    if args.mode != "live":
        print(f"  Input : {args.input}")
    if args.mode == "csv" and args.watch:
        print(f"  Watch : ENABLED")
    print(f"  API   : {API_URL}")
    print("=" * 60)
    print()
    print("  Active Detectors:")
    print("    [1] ML   — XGBoost + IsoForest  (per flow)")
    print("    [2] DDoS — PPS rule-based        (aggregate)")
    print("    [3] BruteForce — attempts rule   (aggregate)")
    print("    [4] Malware — behavioral rules   (aggregate)")
    print()

    # Start dashboard API in the background
    api_thread = threading.Thread(target=run_api_server, daemon=True)
    api_thread.start()
    print("  [*] Started Dashboard API/WS on port 8001")
    print()

    if args.mode == "live":
        _run_live(
            iface=args.iface,
            sensor_mode=args.sensor_mode or SENSOR_MODE,
            promiscuous=False if args.no_promisc else None,
        )

    elif args.mode == "pcap":
        _run_pcap(args.input)

    elif args.mode == "csv":
        _run_csv(args.input, watch=args.watch)


if __name__ == "__main__":
    main()
