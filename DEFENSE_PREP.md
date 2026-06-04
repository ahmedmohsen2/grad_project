# Fusion Strike AI - Viva Defense Package

## Likely Viva Questions And Strong Answers

### 1. What problem does Fusion Strike AI solve?
Fusion Strike AI addresses the gap between detection and action. Many student IDS projects stop after classifying traffic. This platform completes the loop: it detects suspicious behavior, records evidence, applies controlled defense actions, and uses a SAFE MODE pentest pipeline to validate exposure and produce a professional report.

### 2. Why did you use Flask and FastAPI together?
Flask is used for the main REST API because it is simple, stable, and well suited to a modular monolith. FastAPI is used for WebSocket/live monitoring because it has strong async support and clean WebSocket handling. The hybrid design keeps the main API approachable while using async where it matters.

### 3. Why XGBoost?
XGBoost is strong for tabular network-flow features. It performs well on structured CIC-style datasets, supports fast inference, and is easier to explain than a black-box deep model. Isolation Forest complements it by identifying anomaly patterns even when the class label confidence is low.

### 4. Why SAFE_MODE for pentesting?
SAFE_MODE is an ethical and academic requirement. The project demonstrates adversarial validation without launching destructive payloads or real brute-force attempts. This keeps the demo legal, repeatable, and safe while still proving the architecture and reporting workflow.

### 5. Are pentest findings confirmed vulnerabilities?
No. The system labels them as simulated or suspected unless a real controlled validation is integrated. Reports explicitly separate heuristic confidence from confirmed exploitation. That honesty improves academic credibility and avoids false security claims.

### 6. What is innovative in the project?
The innovation is the closed-loop workflow: ML detection, automated response, and pentest validation share one evidence model and one dashboard. It is not just an IDS, not just a dashboard, and not just a pentest tool. It is a small XDR-style platform.

### 7. How do you prevent abuse?
Sensitive endpoints require JWT/API-token authentication. Admin-only operations are protected by role-based access control. Targets and reasons are validated. Nmap is restricted by lab-mode safety controls. SAFE_MODE prevents destructive exploitation.

### 8. How does the dashboard handle failures?
The dashboard polls the backend and exposes degraded/offline indicators. WebSocket streaming is treated as an enhancement, not a dependency. If WebSocket is unavailable, polling keeps the SOC view usable.

### 9. What happens if PostgreSQL is down?
The health endpoint reports degraded state. DB operations fail visibly in logs and the dashboard can show degraded status. The startup validator catches DB unavailability before a demo.

### 10. What are the main limitations?
The system is not a production SOC. SAFE_MODE findings require manual validation. Model performance depends on dataset quality. Nmap is optional. The current architecture is a modular monolith, which is appropriate for a graduation project but would need containerization and observability before enterprise deployment.

## Architecture Justifications

- Flask REST API: stable, simple, easy to defend, excellent for CRUD/dashboard endpoints.
- FastAPI WebSocket: async event streaming without complicating the main Flask app.
- PostgreSQL: primary source of truth and suitable for structured SOC evidence.
- SQLite in pentest agent: lightweight scratch/state storage for the internal pipeline.
- XGBoost: fast, accurate for structured flow features, explainable enough for committee discussion.
- Isolation Forest: anomaly fallback for unknown or weakly labelled behavior.
- SAFE_MODE: ethical, deterministic, repeatable, legally safe.
- Modular monolith: lower operational complexity for graduation while preserving clear module boundaries.

## Demo Talk Track

1. "This is the SOC command center. It shows system health, active threats, detections, blocked hosts, and pentest runs."
2. "The detection layer uses ML and rule-based detectors. Alerts are persisted in PostgreSQL."
3. "Auto-response can block or isolate hosts, but only through authenticated admin actions."
4. "The red-team pipeline runs in SAFE MODE. It does not exploit; it validates exposure through simulated indicators."
5. "The report labels findings as simulated or suspected, which keeps the system academically honest."
6. "The final loop is Detect -> Defend -> Validate."

## Innovation Points

- Unified blue-team and red-team lifecycle in one dashboard.
- Pentest findings feed back into SOC alerts and security findings.
- Honest validation labels prevent fake exploit claims.
- Role-based access and target validation make the demo safer.
- Resilience tooling includes seed data, backup export, startup validation, and regression tests.

## Confident Limitation Statements

- "SAFE_MODE is intentional. It is a safety and ethics design choice, not a missing feature."
- "The system demonstrates an enterprise pattern at graduation scale."
- "Confirmed exploitation is reserved for controlled lab integrations; current results are simulated or suspected."
- "The modular monolith reduces deployment complexity while preserving clear separation of concerns."
