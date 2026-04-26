"""
config.py — مصدر حقيقة واحد لكل ثوابت النظام
===============================================
كل الملفات لازم تـ import منه، متحطش ثوابت في أكتر من مكان.
"""

# ==============================
# 🎯 عتبات القرار (XGBoost)
# TUNED: raised thresholds to reduce false positives
# ==============================
THRESHOLD_HIGH_ATTACK    = 0.85   # was 0.75 → now requires higher confidence for ATTACK
THRESHOLD_MEDIUM_ATTACK  = 0.70   # was 0.50 → prevent low-conf ML from triggering attacks
THRESHOLD_SUSPICIOUS     = 0.50   # was 0.30 → iso alone is no longer enough

# ==============================
# 🌲 Isolation Forest
# ==============================
ISO_CONTAMINATION = 0.10          # نسبة الـ anomalies المتوقعة في التدريب

# ==============================
# 🌊 DDoS Rule-Based
# ==============================
DDOS_PPS_THRESHOLD = 150          # حزمة/ثانية
DDOS_MIN_ALERTS    = 3            # عدد مرات تجاوز العتبة قبل الإعلان

# ==============================
# 🕐 Flow Accumulator (Agent الحي)
# ==============================
FLOW_TIMEOUT_SEC   = 5.0          # ثوانٍ من السكون قبل إرسال التدفق
MAX_FLOW_PACKETS   = 500          # حد أقصى للحزم في تدفق واحد قبل الإرسال

# ==============================
# 🚨 Behavioral Detectors
# ==============================
DNS_QUERY_THRESHOLD      = 50     # استعلام DNS / دقيقة من IP واحد → مشبوه
PORT_DIVERSITY_THRESHOLD = 30     # عدد IPs وجهة مختلفة / دقيقة → مشبوه
C2_BEACON_STD_THRESHOLD  = 0.5   # انحراف معياري منخفض لفترات الاتصال → C2 beacon
C2_MIN_CONNECTIONS       = 5     # حد أدنى للاتصالات قبل تقييم النمط الدوري

# ==============================
# 🛑 Debouncer (Anti-False-Positive)
# An IP is only actioned after N suspicious events within WINDOW seconds.
# ==============================
DEBOUNCE_MIN_EVENTS  = 3     # minimum suspicious events before firing
DEBOUNCE_WINDOW_SEC  = 10.0  # sliding window in seconds

# ==============================
# 🦠 Malware Detector Tuning
# ==============================
# Diversity: if IP talks to many different targets → likely benign browsing
MALWARE_DIVERSITY_THRESHOLD        = 5     # unique dst IPs above this → apply diversity reduction
MALWARE_DIVERSITY_SCORE_FACTOR     = 0.3   # multiply malware score by this if high diversity
MALWARE_REPETITION_RATIO_THRESHOLD = 0.3   # below this repetition → reduce score

# Session: long sessions with high bytes are likely streaming, not malware
MALWARE_SESSION_DURATION_SEC       = 10.0  # seconds
MALWARE_SESSION_BYTES_THRESHOLD    = 100_000  # bytes
MALWARE_SESSION_SCORE_FACTOR       = 0.2   # multiply score if looks like streaming

# ML override: if ML says BENIGN with high confidence, suppress malware alert
MALWARE_ML_BENIGN_CONF_THRESHOLD   = 0.95  # ML confidence above this → reduce score
MALWARE_ML_OVERRIDE_FACTOR         = 0.2   # multiply malware score by this

# Beaconing: how many repeated (src→dst) flows to trigger
MALWARE_BEACON_MIN_FLOWS    = 8    # was 5  → needs more evidence
MALWARE_BEACON_ATTACK_FLOWS = 15   # was 10 → even higher bar for ATTACK
MALWARE_ASYM_RATIO          = 30   # was 20 → one-sided flows need to be more extreme
MALWARE_ASYM_MIN_FWD        = 100  # was 50 → need more packets before flagging asymmetry

# Exfiltration: raised bar to avoid triggering on legitimate downloads
MALWARE_EXFIL_SUSPICIOUS_BYTES = 2_000_000    # was 500KB → now 2MB
MALWARE_EXFIL_ATTACK_BYTES     = 10_000_000   # was 2MB  → now 10MB

# ==============================
# 🔴 Ransomware Detection Heuristics
# ==============================
RANSOMWARE_CONN_PER_SEC_THRESHOLD = 5.0   # connections/s above this is suspicious
RANSOMWARE_SMALL_PKT_SIZE_MAX     = 300   # bytes — "small" packet definition
RANSOMWARE_SMALL_PKT_RATIO_MIN    = 0.7   # 70%+ small packets → indicator
RANSOMWARE_MIN_FLOWS_FOR_EVAL     = 10    # need at least this many flows to evaluate
RANSOMWARE_SCORE_INCREMENT        = 0.6   # score added per ransomware indicator hit

# ==============================
# 🗺️ خريطة تصنيف الهجمات (متعدد الفئات)
# ==============================
ATTACK_LABEL_MAP = {
    'BENIGN':                       0,
    'DDoS':                         1,
    'PortScan':                     2,
    'FTP-Patator':                  3,
    'SSH-Patator':                  3,
    'DoS Hulk':                     4,
    'DoS GoldenEye':                4,
    'DoS slowloris':                4,
    'DoS Slowhttptest':             4,
    'Heartbleed':                   4,
    # WebAttack (class 5) - present in Thursday files
    'Web Attack \u2013 Brute Force':    5,
    'Web Attack \u2013 XSS':            5,
    'Web Attack \u2013 Sql Injection':  5,
    # Fallback without dash (some CSV variants)
    'Web Attack - Brute Force':     5,
    'Web Attack - XSS':             5,
    'Web Attack - Sql Injection':   5,
    # Malware/Botnet mapped to 5 if WebAttack absent, else 6
    # We use 5 here to keep classes contiguous when WebAttack IS present
    'Bot':                          5,
    'Infiltration':                 5,
}

ATTACK_CLASS_NAMES = {
    0: 'BENIGN',
    1: 'DDoS',
    2: 'PortScan',
    3: 'BruteForce',
    4: 'DoS',
    5: 'WebAttack/Malware',
}

# ==============================
# 🌐 Flask API
# ==============================
API_HOST = "127.0.0.1"
API_PORT = 5000
API_URL  = f"http://{API_HOST}:{API_PORT}/predict"

# ==============================
# Auto Response
# ==============================
AUTO_RESPONSE_ENABLED = False
AUTO_RESPONSE_MAX_ACTIONS_PER_IP = 3
AUTO_RESPONSE_COOLDOWN_SEC = 600
AUTO_RESPONSE_HIGH_PPS = 100

# ==============================
# 🔐 Authentication / JWT
# ==============================
import os as _os

JWT_SECRET_KEY = _os.environ.get(
    "JWT_SECRET_KEY",
    "ids-soc-jwt-secret-b7f3e9a1c2d4e6f8"   # default for dev — override in production!
)
JWT_EXPIRATION_HOURS = 24       # token lifetime
INVITE_KEY = "1913"             # static access key for signup
