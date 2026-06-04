# Fusion Strike AI – SOC Command
### AI-Powered SOC Dashboard & Automated Threat Monitoring Platform
#### Graduation Project — Cybersecurity Engineering

---

## 1. Professional Project Description

**Fusion Strike AI – SOC Command** is a graduation project that implements an AI-assisted Security Operations Center (SOC) dashboard for monitoring, classifying, and responding to network threats in real time. The platform combines machine learning-based traffic classification with a structured analyst workflow — covering everything from live traffic inspection and alert triage to incident lifecycle management and AI-assisted penetration testing.

The system is designed around the workflows that real SOC analysts follow: monitoring incoming traffic, investigating suspicious events, managing host states, tracking incidents through their lifecycle, and executing or reviewing containment decisions. Rather than operating as a passive log viewer, the platform actively classifies traffic using an AI model and triggers automated responses — such as blocking or isolating hosts — based on detection confidence, while still giving analysts full visibility and control over every action taken.

The project demonstrates applied knowledge in network security monitoring, threat classification, incident response processes, and web-based SOC tool design — all built and integrated as part of a final-year cybersecurity graduation project.

---

## 2. About the Project

The idea behind Fusion Strike AI came from a straightforward observation: most open-source or student-built security tools are either passive dashboards that display logs, or isolated scanners that perform a single task. Very few student projects attempt to build a *workflow* — something that connects detection, investigation, response, and reporting in a coherent way.

This project tries to do exactly that.

It starts with a live monitoring layer that captures and classifies network traffic. Detected threats generate alerts. Alerts link to incidents. Incidents move through a structured lifecycle. Hosts can be blocked or isolated based on findings. Analyst actions are logged. And separately, an AI-assisted pentest module lets the user probe a target and generate structured findings — which also feed back into the alert and incident system.

The frontend is built as a multi-module SOC dashboard, and the backend handles detection, persistence, and enforcement logic. The result is a project that looks and behaves like a real security operations tool — designed to be credible, functional, and educational.

---

## 3. Key Features

- **Real-time traffic classification** — Network flows are analyzed and labeled (DDoS, Malware, Suspicious, Benign) with an associated confidence score
- **Live SOC dashboard** — Aggregated metrics, threat distribution, open alert counts, and system performance indicators on a single Command Center view
- **Alert triage system** — Structured alert queue with severity levels, alert types, and analyst acknowledgement workflow
- **Incident lifecycle management** — Incidents tracked from detection through analysis, containment, and reporting
- **Host state management** — Per-host visibility with manual analyst actions: Block, Isolate, Whitelist
- **Enforcement log** — All containment actions (automated and manual) recorded with timestamps and actor information
- **AI pentest console** — Target scanning interface with port discovery, vulnerability findings, and scan history
- **Activity timeline** — Chronological log of all platform events including detections, analyst actions, and pentest results
- **System health dashboard** — Operational status of platform components and detection counters
- **Search and filtering** — Across the monitoring table, alerts, and timeline for analyst efficiency

---

## 4. Main Modules Explanation

### Command Center
The landing page of the platform. It gives a high-level view of the current security state: how many alerts are open, what percentage of traffic is classified as a threat, how the AI detection engine is performing, and whether automated responses are active. It is designed to answer the question *"what is happening right now?"* at a glance, without requiring the analyst to navigate to individual modules.

### Live Monitoring
A continuously updating table of classified network flows. Each row represents a captured traffic event and includes the source and destination IP, port, attack type label, confidence score, packet rate (PPS), and traffic volume. The table supports search and filtering, so analysts can focus on a specific host, threat category, or confidence range. This is the raw visibility layer of the platform.

### Alerts System
When the detection engine flags a flow or a pentest scan uncovers a vulnerability, a structured alert is created. The Alerts module displays these in a triage-style interface with severity labels (Critical, High, Medium, Low), alert type, a short incident message, status, and timestamp. Analysts can acknowledge alerts and link them to incidents for further investigation.

### Incident Management
Incidents represent the investigative layer on top of raw alerts. Each incident has a lifecycle — moving from initial detection through analysis to containment and reporting. The module displays risk scores, execution summaries, findings, and recommendations for each incident. It also tracks the containment status, so analysts always know where an incident stands in the response process.

### Host Management
A live inventory of all monitored hosts. Each host shows its current state — Monitored, Trusted, Isolated, or Blocked — along with incident count, traffic statistics, confidence assessments from the AI engine, and last-seen timestamp. Analysts can take direct actions from this view: block a host, isolate it from the network, or mark it as trusted. All actions are logged.

### Actions & Enforcement
A consolidated view of all enforcement decisions made on the platform — whether triggered automatically by the detection pipeline or executed manually by an analyst. The log includes firewall block entries, isolation decisions, whitelist operations, the actor (AI vs. analyst), and timestamps. This gives a clear audit trail of every containment action taken.

### AI Pentest Console
An interface for running AI-assisted penetration test scans against a specified target. The user can launch a scan that covers port and service discovery, basic vulnerability checks, and security configuration analysis. Results are presented as structured findings with severity ratings and recommendations. Scan history is tracked so previous assessments can be reviewed and compared.

### Activity Timeline
A chronological event stream covering everything that has happened on the platform: detection events, automated responses, analyst actions, and pentest results. It can be filtered by event type to help analysts reconstruct the sequence of events around a specific incident or host. It functions as the platform's audit log presented in a readable, timeline format.

### System Status
A health overview of the platform's key components. Shows whether the detection pipeline, alert engine, and other services are operational, along with summary counters for total detections, enforcement actions, and pentest findings. Useful for confirming the platform is running correctly and for identifying if any component has a problem.

---

## 5. AI & Automation Overview

The AI component of the platform is the traffic classification engine. It processes captured network flows and assigns each one a threat label — DDoS, Malware, Suspicious, or Benign — along with a confidence score reflecting how certain the model is about the classification.

When a flow is classified with high confidence as a threat, the platform can automatically generate an alert and, depending on configuration, trigger a containment action such as blocking the source host. This automation is transparent: every automated action is recorded in the enforcement log with a clear indication that it was AI-triggered rather than analyst-initiated.

The AI pentest console uses a different kind of assistance — it orchestrates a structured scanning process and synthesizes the results into readable findings. Rather than dumping raw scan output at the user, it presents organized vulnerability summaries with severity ratings and suggested next steps.

The goal is not to replace analyst judgment but to reduce the time between detection and initial response, and to surface structured, actionable information so analysts can make informed decisions faster.

---

## 6. Incident Response Workflow

The platform follows a straightforward, phased incident response flow:

```
Detection → Alert → Triage → Investigation → Containment → Reporting
```

**Step 1 — Detection**
The live monitoring layer classifies incoming traffic. Flows that cross a confidence threshold for a threat category are flagged.

**Step 2 — Alert Generation**
A structured alert is created with severity, type, and an incident message. If triggered by a pentest finding, the alert references the scan result.

**Step 3 — Triage**
The analyst reviews the alert in the Alerts module. They acknowledge it and decide whether to escalate it to an incident for deeper investigation.

**Step 4 — Investigation**
The linked incident is opened in Incident Management. The analyst reviews risk scores, findings, and recommendations. They can examine the associated host's traffic history and state in the Host Management module.

**Step 5 — Containment**
If a threat is confirmed, the analyst can block or isolate the host directly from the Host Management or Actions module. Automated actions may have already been taken — these are visible in the enforcement log.

**Step 6 — Reporting**
The incident record captures findings, the timeline of actions taken, and the final status. The Activity Timeline provides a complete chronological reconstruction of the event.

---

## 7. Pentesting Workflow

The AI Pentest Console supports a structured scan-to-findings workflow:

**Step 1 — Target Specification**
The analyst specifies a target host or IP for assessment.

**Step 2 — Scan Execution**
The platform runs a scan covering port and service discovery, basic vulnerability checks, and security configuration analysis (such as exposed services or missing security headers).

**Step 3 — Findings Review**
Results are presented as structured findings, each with a severity rating, a description of what was found, and a recommendation for remediation.

**Step 4 — Alert & Incident Integration**
Critical findings automatically generate alerts that enter the standard triage workflow. This means pentest results and live traffic detections are handled through the same incident management process.

**Step 5 — Scan History**
Previous scans are retained and accessible for comparison, allowing analysts to track whether previously identified issues have been addressed.

---

## 8. Real-Time Monitoring Explanation

The Live Monitoring module is the platform's direct window into network traffic. It receives classified flow data and displays it in a continuously updating table. Each row captures:

| Field | What It Shows |
|---|---|
| **Timestamp** | When the flow was captured |
| **Source IP** | The originating host |
| **Destination IP** | The target of the traffic |
| **Port** | The destination port |
| **Attack Type** | AI classification label |
| **Confidence** | How certain the model is (percentage) |
| **PPS** | Packets per second — useful for spotting volumetric attacks |
| **Packet Count** | Total packets in the observed flow |
| **Traffic Bytes** | Total data volume |

Analysts can search by IP address, filter by attack type, or sort by confidence score. This makes it practical to investigate a specific host, focus on high-confidence detections, or look for patterns across multiple flows without scrolling through unfiltered data.

---

## 9. Short Resume Version

> **Fusion Strike AI – SOC Command** | Graduation Project, 2026
>
> Designed and built a full-stack AI-assisted SOC dashboard for real-time network threat monitoring, incident management, and automated response. The platform classifies network traffic using a machine learning model, generates structured alerts, tracks incidents through a defined lifecycle, and supports analyst-controlled host containment (block, isolate, whitelist). Includes an AI-assisted penetration testing module with structured findings and scan history. Built with a Python backend (FastAPI), PostgreSQL database, and a React frontend with real-time WebSocket updates.
>
> **Core capabilities:** Live traffic classification · Alert triage · Incident lifecycle management · Host state control · Enforcement logging · AI pentest console · Activity timeline · System health monitoring

---

## 10. GitHub README Description

```
# Fusion Strike AI – SOC Command
AI-Assisted SOC Dashboard & Threat Monitoring Platform | Graduation Project 2026
```

Fusion Strike AI is a graduation project that builds a working SOC-style dashboard for monitoring, classifying, and responding to network threats. It connects an AI-based traffic classification engine to a structured analyst workflow — covering live monitoring, alert triage, incident management, host control, and an AI-assisted penetration testing interface.

The platform is designed to demonstrate how the core workflows of a Security Operations Center can be implemented and visualized in a functional, integrated web application. It is not a commercial product — it is a cybersecurity engineering project that applies real SOC concepts in a realistic, end-to-end system.

**What it includes:**
- 📡 Live traffic monitoring table with AI classification and confidence scoring
- 🚨 Alert triage system with severity levels and analyst workflows
- 📋 Incident lifecycle tracking from detection to containment and reporting
- 🖥️ Host inventory with state management and manual containment actions
- 📜 Enforcement log for all block, isolate, and whitelist decisions
- 🔍 AI pentest console with structured findings and scan history
- 🕒 Activity timeline for full event reconstruction
- 🏥 System health dashboard with component status monitoring

**Built with:** Python · FastAPI · PostgreSQL · React · WebSocket

---

## 11. LinkedIn Showcase Version

I'm excited to share my graduation project: **Fusion Strike AI – SOC Command** — an AI-assisted Security Operations Center dashboard I built as my final-year cybersecurity project.

The platform is designed around how SOC analysts actually work: monitoring live traffic, triaging alerts, investigating incidents, managing host states, and tracking every action taken. Rather than being a passive log viewer, it connects an AI traffic classification engine directly to the analyst workflow — so detections can automatically generate alerts, link to incidents, and trigger containment actions, all while keeping the analyst in control.

**What I built:**

🔎 **Live Monitoring** — Real-time traffic table with AI-assigned threat labels and confidence scores

🚨 **Alert Triage** — Structured alert queue with severity levels and acknowledgement workflow

📋 **Incident Management** — Full lifecycle tracking from detection through containment and reporting

🛡️ **Host Management** — Per-host state control with block, isolate, and whitelist actions

🔍 **AI Pentest Console** — Structured vulnerability scanning with organized findings and scan history

🕒 **Activity Timeline** — Chronological reconstruction of all platform events

This project pushed me to think about security tooling as a complete system — not just a detection algorithm or a nice-looking dashboard, but a workflow that connects all the pieces together.

**Stack:** Python (FastAPI) · PostgreSQL · React · WebSocket · Machine Learning

#Cybersecurity #SOC #GraduationProject #NetworkSecurity #ThreatDetection #IncidentResponse #Python #React #MachineLearning #BlueTeam

---

*Fusion Strike AI – SOC Command | Graduation Project 2026*
