# PROJECT_FULL_ANALYSIS.md
## Fusion Strike AI — Cyber-Attack-AI
### Full Forensic Audit | Date: 2026-04-26 | Auditor: Antigravity AI (Senior Architect + Red Team)

---

## 1. PROJECT IDENTITY

| Field | Value |
|---|---|
| **Project Name** | Fusion Strike AI / Cyber-Attack-AI |
| **Purpose** | Autonomous AI-driven Intrusion Detection, Prevention, and Penetration Testing platform |
| **Core Business Goal** | Detect network attacks in real-time using ML + rule-based fusion, automatically respond (block/isolate), and run autonomous AI pentest pipelines against flagged hosts |
| **Architecture Style** | **Hybrid Modular Monolith** — single Python process hosts Flask API + WebSocket server + detection agent; pentest runs as background thread pool |
| **Primary Languages** | Python 3.11 (backend, ML, agents), JavaScript/JSX (React frontend) |
| **Frameworks** | Flask (REST API), FastAPI+Uvicorn (WebSocket/dashboard), React 18 + Vite (frontend), SQLAlchemy-free asyncpg (DB) |
| **ML Stack** | XGBoost (multiclass), IsolationForest (anomaly), Keras/TensorFlow Autoencoder |
| **DB** | PostgreSQL 14+ (`ids_system`) via asyncpg pool; SQLite (`pentest_scans.db`) for pentest agent |
| **Deployment** | Local Windows (`.bat` launchers), no Docker, no CI/CD, no cloud config |
| **Maturity Level** | **Late Beta / Pre-Production** — functional pipeline with critical gaps in secrets management, hardened deployment, and test coverage |

---

## 2. FULL DIRECTORY & FILE MAP

```
Cyber-Attack-AI/
├── api.py                    ← MAIN ENTRY POINT: Flask REST API (963 lines)
├── unified_agent.py          ← MAIN AGENT: 3-mode IDS engine (891 lines)
├── dashboard_api.py          ← FastAPI WebSocket server on :8001 (48 lines)
├── state_manager.py          ← Singleton in-memory state + WS broadcaster
├── config.py                 ← Single source of truth for all thresholds
├── db.py                     ← Async PostgreSQL layer (1747 lines, asyncpg)
├── db.sql                    ← PostgreSQL schema (idempotent DDL)
├── migration_pentest.sql     ← Pentest tables migration
├── migration_v2.sql          ← V2 schema additions
│
├── auto_response_engine.py   ← Auto-block/isolate decision engine
├── action_manager.py         ← Threat-specific IPS dispatcher
├── action.py                 ← Low-level action executor
├── host_actions.py           ← Host state CRUD + execute_host_action()
├── closed_loop_lifecycle.py  ← Pentest finding → DB → alert → re-scan loop
├── pentest_bridge.py         ← Bridge between IDS and pentest agent
│
├── baseline_engine.py        ← Adaptive traffic baseline (mean/std)
├── context_layer.py          ← Context-aware FP suppression
├── behavioral_detectors.py   ← DNS/C2/beacon behavioral detection
├── ddos_detector_module.py   ← DDoS rule-based detector
├── brute_force_detector.py   ← BruteForce rule-based detector
├── malware_detector.py       ← Malware/ransomware rule-based detector
│
├── predict.py                ← Standalone predict script
├── flow_builder.py           ← Flow assembly utilities
├── flow_extractor.py         ← PCAP flow extraction stub
├── flow_utils.py             ← Shared PPS computation
├── preprocessing.py          ← CSV preprocessing utilities
│
├── train_multiclass.py       ← XGBoost multiclass trainer
├── train_autoencoder.py      ← Autoencoder trainer
├── red_team_agent.py         ← Simulated red team traffic generator
├── test_suite.py             ← Comprehensive integration test suite
│
├── xgb_model_multiclass.pkl  ← Trained XGBoost model (3.2 MB)
├── xgb_model.pkl             ← Binary XGBoost fallback (290 KB)
├── iso_model.pkl             ← IsolationForest (785 KB)
├── autoencoder_model.py      ← Autoencoder architecture definition
├── scaler.pkl / columns.pkl  ← Feature scaler + column list
│
├── .env                      ← ⚠️ HARDCODED API KEYS (committed to repo)
├── requirements.txt          ← Python dependencies
├── START_SYSTEM.bat          ← Windows launcher (Flask + Vite)
├── start_all.bat             ← Alternate launcher
│
├── pentest_agent/            ← PENTEST SUB-SYSTEM
│   ├── app.py                ← FastAPI app (port 8088, standalone)
│   ├── orchestrator.py       ← Pipeline controller v3 (680 lines)
│   ├── config.py             ← Pentest configuration
│   ├── database.py           ← SQLite async persistence
│   ├── pentest_scans.db      ← SQLite DB file (committed)
│   ├── models/
│   │   ├── schemas.py        ← Pydantic models for all pipeline data
│   │   ├── attack_context.py ← AttackContext memory object
│   │   └── attack_graph.py   ← Attack graph builder
│   └── modules/
│       ├── ai_engine.py      ← Weighted scoring AI decision engine
│       ├── exploit_engine.py ← SAFE MODE exploit simulator
│       ├── scanner.py        ← TCP port scanner + web analyzer
│       ├── nmap_scanner.py   ← Optional Nmap subprocess plugin
│       ├── recon.py          ← DNS/HTTP recon module
│       ├── vuln_analyzer.py  ← Vulnerability classifier
│       ├── strategy.py       ← Attack strategy planner
│       └── reporter.py       ← Risk report generator
│
├── frontend/                 ← REACT DASHBOARD
│   ├── src/
│   │   ├── App.jsx           ← Root app + router
│   │   ├── main.jsx          ← React entry point
│   │   ├── api/
│   │   │   ├── api.js        ← All backend API calls
│   │   │   └── baseUrl.js    ← Dynamic base URL resolver
│   │   ├── hooks/
│   │   │   └── useSocData.js ← Master data hook (polling + WebSocket)
│   │   ├── services/
│   │   │   └── socApi.js     ← Thin fetch wrapper service
│   │   ├── pages/            ← Route-level page components
│   │   │   ├── PentestConsolePage.jsx  (41KB — largest file)
│   │   │   ├── ActivityTimelinePage.jsx
│   │   │   ├── IncidentView.jsx
│   │   │   └── [4 stub pages]
│   │   ├── screens/          ← Sub-page view components
│   │   ├── components/       ← Reusable UI components
│   │   ├── constants/navigation.js
│   │   └── utils/socMappers.js
│   ├── package.json
│   ├── vite.config.js
│   └── tailwind.config.js
│
└── dataset/                  ← Training data (not audited — binary/CSV)
```

**Entry Points:**
- `python api.py` — Flask REST API on `:5000`
- `python unified_agent.py --mode [live|pcap|csv]` — IDS agent
- `dashboard_api.py` started as thread from agent — FastAPI WS on `:8001`
- `npm run dev` in `frontend/` — Vite dev server on `:5173`

---

## 3. ARCHITECTURE BREAKDOWN

### System Design (End-to-End)

```
NETWORK TRAFFIC
     │
     ▼
[unified_agent.py]
  ├─ LIVE mode  → Scapy packet capture → Flow Builder → Feature Extraction
  ├─ PCAP mode  → rdpcap() → Flow Assembly → Feature Extraction
  └─ CSV  mode  → pandas read_csv → Direct to ML API
         │
         ▼
[Flask API: /predict]  ←── XGBoost multiclass + IsolationForest
         │
         ▼
[Fusion Engine]  ← DDoS detector + BruteForce detector + Malware detector
         │
    ┌────┴────┐
    │         │
 ATTACK    NORMAL
    │
    ▼
[auto_response_engine]  →  execute_host_action()  →  PostgreSQL (actions table)
    │
    ▼
[state_manager.broadcast_alert()]
    │
    ▼
[dashboard_api.py WebSocket :8001]  ──push──►  React frontend
    │
    ▼
[closed_loop_lifecycle.py]
    │
    ▼
[_queue_pentest_scan()]  →  ThreadPoolExecutor  →  PentestOrchestrator
         │
    Pipeline: Recon → Scan → VulnAnalysis → Strategy → Plan → Execute → Report
         │
    PostgreSQL (pentest_scans, security_findings, alerts)
```

### Request Flow (REST)
```
React (useSocData.js)
  → fetch /alerts, /detections, /flows, /actions (every 5s)
  → Flask api.py routes
  → sync_*() wrappers → _run_async() → asyncpg pool → PostgreSQL
  → JSON response → socMappers.js normalization → React state
```

### Authentication Flow
> **ASSUMPTION**: No authentication system exists anywhere in the codebase.
- Flask API: `CORS(app, resources={r"/*": {"origins": "*"}})` — fully open
- WebSocket: No handshake validation
- Pentest API: No auth
- All endpoints publicly accessible on localhost

### WebSocket Architecture
- `dashboard_api.py` runs FastAPI + Uvicorn on `:8001` in a background thread spawned by `unified_agent.py`
- `StateManager._safe_broadcast()` uses `asyncio.run_coroutine_threadsafe()` to bridge sync→async
- Frontend `useSocData.js` connects to `ws://127.0.0.1:8001/ws/live` with 3s auto-reconnect
- **Problem**: `dashboard_api.py` is only started when `unified_agent.py` runs; the Flask API does NOT start this server, meaning the dashboard has NO WebSocket when running in API-only mode

---

## 4. FRONTEND ANALYSIS

### Framework & Stack
- React 18.3, React Router 6.30, Vite 5.4, TailwindCSS 3.4, Recharts 2.15

### Routing System
```
/ → redirect /dashboard
/dashboard         → DashboardPage (lazy)
/live-monitoring   → LiveMonitoringPage (lazy)
/alerts            → AlertsPage (lazy)
/pentest           → PentestConsolePage (lazy) — 41KB
/activity-timeline → ActivityTimelinePage (lazy)
/incident/:id      → IncidentView (lazy)
/suspicious-queue  → SuspiciousQueueScreen (not lazy)
/hosts             → HostsScreen (not lazy)
/actions           → ActionsScreen (not lazy)
/system-status     → SystemStatusScreen (not lazy)
```

### Data Architecture
- **Single master hook** `useSocData()` fetches all 7 endpoints simultaneously every 5s
- Fallback data served from `data/fallbackData` when API is down
- `socMappers.js` normalizes raw API shapes into UI models
- `mergeCollections()` implements reference-stable state merging (prevents unnecessary re-renders)
- WebSocket supplements polling for instant push notifications

### Page-Level Issues
| Page | Status | Issue |
|---|---|---|
| `DashboardPage.jsx` | 177 bytes | **STUB** — virtually empty |
| `AlertsPage.jsx` | 150 bytes | **STUB** — virtually empty |
| `LiveMonitoringPage.jsx` | 190 bytes | **STUB** — virtually empty |
| `SecurityToolsPage.jsx` | 464 bytes | Near-stub |
| `PentestConsolePage.jsx` | 41KB | Full implementation |
| `ActivityTimelinePage.jsx` | 20KB | Full implementation |
| `IncidentView.jsx` | 21KB | Full implementation |

> **CRITICAL**: Three of the seven routes render stub/empty pages. The Dashboard, Alerts, and Live Monitoring pages — the primary views for a SOC — contain no meaningful UI.

### State Management
- No Redux/Zustand; all state lives in `useSocData` hook at App root
- Props drilled down via `sharedScreenProps` object
- Risk: Any state update triggers re-render of entire app tree

### Missing UX Systems
- No authentication/login screen
- No error boundary components
- No toast/notification system for API errors (only action toasts)
- No pagination controls on any data table
- No date range filters on alerts/detections

---

## 5. BACKEND ANALYSIS

### API Framework
- **Flask** (synchronous) on port 5000 — main REST API
- **FastAPI/Uvicorn** on port 8001 — WebSocket-only dashboard server
- **FastAPI** on port 8088 — standalone pentest agent (rarely used; pentest is integrated into Flask)

### Route Inventory

| Method | Route | Purpose |
|---|---|---|
| GET | `/` | Health ping |
| GET | `/health` | Full system health |
| POST | `/predict` | ML inference endpoint |
| GET | `/alerts` | Alerts list (paginated) |
| POST | `/alerts/read/<id>` | Mark alert read |
| GET | `/detections` | ML detections list |
| GET | `/flows` | Network flows list |
| GET | `/actions` | IPS actions list |
| GET | `/blocked-ips` | Blocked IP list |
| POST | `/actions/block` | Block a host |
| POST | `/actions/isolate` | Isolate a host |
| POST | `/actions/whitelist` | Whitelist a host |
| POST | `/block` | Legacy block |
| POST | `/unblock` | Legacy unblock |
| POST | `/isolate` | Legacy isolate |
| POST | `/unisolate` | Legacy unisolate |
| GET | `/auto-response/status` | Auto-response status |
| POST | `/auto-response/status` | Toggle auto-response |
| GET | `/actions/state/<target>` | Host action state |
| POST | `/pentest/scan` | Start pentest scan |
| GET | `/pentest/results/<id>` | Get scan results |
| GET | `/pentest/scans` | List all scans |
| GET | `/pentest/report/<id>` | Get scan report |
| GET | `/pentest/findings` | Security findings |
| GET | `/activity/logs` | Activity timeline logs |

### Critical Middleware Issue
```python
@app.before_request
def log_request_details():
    print("Incoming request from:", request.remote_addr)
    print("Origin:", request.headers.get("Origin"))
    print(f"Request: {request.method} {request.path}")
```
Every single request logs to stdout synchronously — severe performance degradation at scale.

### Pentest Pipeline Integration
- Flask spawns pentest scans in a `ThreadPoolExecutor(max_workers=3)`
- Each thread creates its own `asyncio` event loop to run async orchestrator
- **Double DB write problem**: Progress is written to both PostgreSQL (`sync_update_pentest_scan`) AND SQLite (`pentest_db.update_scan`) on every progress callback, creating excessive DB churn
- Concurrency limit: hard-coded 3 parallel scans

### Auto-Response Engine
- `AUTO_RESPONSE_ENABLED = False` (disabled by default in config.py)
- When enabled: evaluates confidence + PPS + attack_type → decide block/isolate
- Duplicate method `evaluate_finding()` defined TWICE in `auto_response_engine.py` (lines 125 and 180) — second definition silently overrides first (Python behavior)

---

## 6. DATABASE ANALYSIS

### Databases
| DB | Engine | Purpose |
|---|---|---|
| `ids_system` | PostgreSQL 14+ | Main IDS/IPS operational data |
| `pentest_scans.db` | SQLite | Pentest scan records (local bookkeeping) |

### PostgreSQL Schema

| Table | Purpose | Key Columns |
|---|---|---|
| `hosts` | One row per IP seen | ip (UNIQUE), status, first_seen, last_seen |
| `flows` | Completed network flow records | src_ip, dst_ip, packets, bytes, pps, duration_us |
| `detections` | ML + rule detection results | src_ip, result, attack_type, confidence, iso_flag |
| `actions` | IPS actions log | ip, action_type, reason, acted_at |
| `blocked_ips` | Currently blocked IPs | ip (UNIQUE), reason, blocked_at |
| `alerts` | Real-time IPS alerts | ip_address, alert_type, message, is_read |
| `action_controls` | Host containment state | target (PK), is_blocked, is_isolated, is_whitelisted |
| `security_findings` | Pentest vulnerability findings | finding_id (PK), fingerprint (UNIQUE), severity, status |
| `pentest_scans` | Pentest scan records | scan_id (PK), target, status, progress, results (JSONB) |
| `activity_log` | Full audit trail | type, action, target, status, metadata |

### Index Coverage
- Good: `hosts.ip`, `detections.(src_ip, detected_at)`, `alerts.created_at`, partial index on `alerts WHERE is_read=FALSE`
- Missing: No index on `flows.captured_at` for time-range queries; no index on `pentest_scans.status`

### Schema Risks

| Risk | Detail |
|---|---|
| `results` column in `pentest_scans` | JSONB blob — full scan result stored as monolith; no structured columns for querying individual fields |
| `action_controls.is_quarantined` | Set equal to `is_isolated` in upsert — semantically wrong |
| `security_findings.timeline` | JSONB array grown unbounded — no pruning mechanism |
| Hardcoded DSN | `DB_DSN = "postgresql://postgres:1234@localhost:5432/ids_system"` in `db.py` — password in source |
| No connection retry | Pool creation failure sets `_pool = None` silently; all subsequent DB calls fail silently |

### Async Bridge Architecture
- One persistent daemon thread runs one asyncio event loop (`_bg_loop`)
- All sync callers submit coroutines via `asyncio.run_coroutine_threadsafe()`
- 5-second timeout ceiling prevents deadlocks
- **Risk**: If the bg thread crashes, all sync DB calls silently time out — no restart mechanism

---

## 7. SECURITY AUDIT

### 🔴 CRITICAL Severity

**C1: API Keys Hardcoded in `.env` committed to git**
```
VIRUSTOTAL_API_KEY=8e9161549fbf2a6eb9840cb096c72780ca4ab9a62ef4a52d99f71d55aa613a66
ABUSEIPDB_API_KEY=d49d2689a12441221821b0b5f4bb43561793095535508cd9624d41d91b7edae47f65fb898e8467ea
ALIENVAULT_OTX_KEY=82b5930a5fbb5d70f127882316f4e3a961e66c89218a7929d384b9c8238b5385
```
> All three keys are plaintext in `.env` which is NOT in `.gitignore`. Rotate all keys immediately.

**C2: Database Password Hardcoded in Source**
```python
DB_DSN = "postgresql://postgres:1234@localhost:5432/ids_system"  # db.py:53
```
> Default postgres password `1234` hardcoded. Any user with source access has DB credentials.

**C3: Universal CORS — No Authentication**
```python
CORS(app, resources={r"/*": {"origins": "*"}})
```
> Every endpoint accessible from any origin, any IP. No auth tokens, no session management, no API keys. Any process on the network can call `/actions/block` or `/pentest/scan`.

**C4: Pentest Scan Target Validation Bypass**
```python
ALLOW_ALL_TARGETS = os.getenv("ALLOW_ALL_TARGETS", "false")
```
> If env var is set `true`, ALL IP ranges (including production infrastructure) become scannable. No secondary confirmation or audit trail for this override.

**C5: Nmap Subprocess with User-Controlled Input**
```python
cmd = ["nmap"] + profile_flags + ["-oX", "-", target]
process = await asyncio.create_subprocess_exec(*cmd, ...)
```
> `target` comes directly from the API request body. Although IP validation exists, the `validate_target()` function can be bypassed via `ALLOW_ALL_TARGETS=true`. Shell argument injection is partially mitigated by `create_subprocess_exec` (not shell=True), but the target itself is unsanitized.

---

### 🟠 HIGH Severity

**H1: Duplicate `evaluate_finding()` method in `auto_response_engine.py`**
- Lines 125–172 and 180–232 both define `evaluate_finding()`
- Python silently uses the second definition — the first (with `title` parameter) is dead code
- The surviving method has different return value casing (`"ISOLATE"` vs `"isolate"`) causing action dispatch failures

**H2: WebSocket has no authentication or rate limiting**
- Any client can connect to `ws://127.0.0.1:8001/ws/live`
- No message validation — malformed messages could crash the handler
- `ws_clients` is a plain Python `set()` — concurrent add/remove without a lock can cause `RuntimeError: Set changed size during iteration`

**H3: Stdout logging of all API request details**
- Every request logs `remote_addr` and `Origin` to stdout via `print()` in `before_request`
- At high traffic this can expose IP addresses in unprotected log files

**H4: SQLite DB file committed to repository**
- `pentest_agent/pentest_scans.db` (307 KB) is committed — contains historical scan data, targets, and results

**H5: `debug=True` in production startup**
```python
app.run(host="0.0.0.0", port=API_PORT, debug=True)  # api.py:962
```
> Flask debug mode enables the interactive debugger (arbitrary code execution via browser) and auto-reloader. Binding to `0.0.0.0` exposes this to the network.

---

### 🟡 MEDIUM Severity

**M1: No input length/type validation on API endpoints**
- `/pentest/scan` accepts any `target` string without length limit
- `/actions/block` accepts any `reason` without sanitization (truncated to 500 chars in DB layer only)

**M2: Pentest results stored as raw JSONB blob**
- Full scan results (potentially MB in size) stored in a single `results` column
- No size limit enforced — a long-running scan could produce results too large for efficient retrieval

**M3: ThreadPoolExecutor never shut down**
- `_pentest_executor = ThreadPoolExecutor(max_workers=3)` created at module load, never `shutdown(wait=False)` on app exit

**M4: Alert cooldown shares memory across processes**
- `_alert_cooldown` dict is in-memory only; restarting the API resets all cooldowns → alert storm on restart

**M5: `print()` used extensively for logging instead of logging framework**
- 50+ `print()` calls in `api.py` and `pentest_agent/orchestrator.py`
- No structured logging, no log levels, no log rotation

---

### 🔵 LOW Severity

**L1: `.gitignore` only has 2 entries** (`__pycache__/` and `*.pyc`) — model files, `.env`, SQLite DB, `node_modules`, `dist/` are all potentially committed.

**L2: `verify=False` in httpx client** in `scanner.py:274` — SSL certificate verification disabled for web analysis requests.

**L3: Hardcoded port numbers** scattered across multiple files instead of centralized config.

**L4: `autoencoder_model.py` defines architecture but model weights are never loaded in `api.py`** — the autoencoder is trained but not used in the inference pipeline.

---

## 8. AI / AGENT MODULE ANALYSIS

### IDS Fusion Engine (`unified_agent.py`)

**Detection Pipeline:**
```
Flow Features → Flask /predict → XGBoost multiclass + IsolationForest
                              ↓
              fusion(ddos_verdict, brute_verdict, malware_verdict, ml_result)
                              ↓
                    ATTACK | SUSPICIOUS | NORMAL
```

**Confidence Thresholds (config.py):**
- `THRESHOLD_HIGH_ATTACK = 0.85` — ML result classified ATTACK
- `THRESHOLD_MEDIUM_ATTACK = 0.70` — classified SUSPICIOUS
- `THRESHOLD_SUSPICIOUS = 0.50` — IsoForest-assisted SUSPICIOUS

**Fusion Logic Quality:**
- Rule-based detectors (DDoS/BruteForce/Malware) take absolute priority — a single rule trigger overrides ML
- ML ATTACK requires >0.85 confidence OR >0.70 + iso_flag to produce ATTACK verdict
- Micro-flow confidence capped at 0.40 — prevents probe/scan false positives

**Failure Points:**
- `call_ml_api()` makes synchronous HTTP request with 3s timeout — if Flask API is down, ALL flow analysis returns `{"result": "ERROR"}` silently; no circuit breaker
- `_ADAPTIVE` flag: if `baseline_engine` import fails, context-layer suppression is disabled with only a WARNING — silent degradation
- Double `ctx.observe()` bug mitigated by comment but fragile — removing the comment would silently break baseline calibration

### Pentest AI Engine (`pentest_agent/modules/ai_engine.py`)

**Decision Model:** Weighted scoring system (not LLM-based)
- Base weights: `test_sqli=90`, `bruteforce_login=80`, `test_xss=70`, `check_headers=40`, `scan_deeper=30`
- Modifiers: failure penalty (−25/failure), repeat penalty (−40/attempt), strategy bonus (+20), multi-signal bonus (+15), Nmap confirmation (+20)

**Action Set:** Only 5 actions: `test_sqli`, `bruteforce_login`, `test_xss`, `check_headers`, `scan_deeper`
- No network-layer attacks (no SYN flood, no ARP poisoning)
- No OS-level exploits — by design (SAFE_MODE)

**Exploit Engine Reality:**
- ALL exploits are simulated — `_simulate_category_response()` uses MD5 hash of target name to deterministically generate fake responses
- Confidence scores are deterministic artifacts of the target hostname, NOT real vulnerability evidence
- A target `"evil.com"` will always get the same scores regardless of its actual state

**Hallucination Risk:** HIGH
- The system can report `POTENTIALLY_VULNERABLE` with `confidence=0.85` for SQL injection on a target that has no web application
- The simulated response buckets (15% error, 15% success, 20% filtered, 20% normal, 30% timeout) are fixed probabilities — not based on real responses
- Reports look authoritative but are partly fabricated

**Attack Graph:**
- `AttackGraph` builds a visual relationship map from recon/scan/vuln/exploit data
- Correctly structured as nodes + edges with serialization
- Used for the frontend Incident View visualization

**Strategy Planner:**
- 5 strategy profiles: `aggressive`, `stealth`, `web_focused`, `network_focused`, `balanced`
- Selected based on open ports, services, and vulnerabilities found in scanning
- Max 5 pipeline iterations (`MAX_PIPELINE_ITERATIONS = 5`)
- Re-planning triggers after 2 consecutive failures, max 2 replans

---
