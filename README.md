# 1. README Section

## 1.1 Overview

The GIBL Network Intrusion Detection System is a unified multi-agent cybersecurity pipeline built to analyze network flow signals, user behavior, and packet metadata. The system supports two primary modes of operation: offline batch forensics (which runs the full agent pipeline sequentially) and real-time active defense (which runs a live dashboard for monitoring and interactive threat simulation).

### Pipeline Flow Structure

The detection and response operations are organized into a sequential, multi-agent execution pipeline:

```
[Windows Logs / Zeek Logs] ---> [Packet Agent] ---\
                                                   \
[Netflow / Zeek Logs]     ---> [Flow Agent]     -----> [Correlation Agent] ---> [Response Agent] ---> [Final Outputs]
                                                   /
[UEBA / Windows Logs]     ---> [Behavior Agent] --/
```

1. **Packet Agent (IP-Level)**: Evaluates endpoint behaviors. Aggregates host activity metrics (failed logins, process spawns, service creations) and Zeek connection footprints, running an Isolation Forest model to isolate statistical anomalies. It also incorporates a frequency analyzer for JA3 TLS Client Hellos to identify command-and-control (C2) beaconing.
2. **Flow Agent (Flow-Level)**: Processes individual network connections. Engineers traffic density features, port risks, temporal cycles, and rolling connection frequencies to score flow records using a hybrid XGBoost/Isolation Forest ensemble.
3. **Behavior Agent (User-Level)**: Monitors Active Directory events and UEBA transaction logs. Employs user history tracking, sliding window query velocity checks, and a deterministic rules engine to identify session anomalies.
4. **Correlation Agent (Fusion)**: Merges the flow, behavior, and packet alerts. It applies a Sigmoid Gated Fusion model to balance conflicting signals, applies segment-specific amplification, boosts co-occurring alerts, and traces lateral movement paths on a directed network graph.
5. **Response Agent (Decision Policy)**: Performs final response operations, maps asset criticalities, tunes thresholds to restrict the False Positive Rate (FPR <= 10%), and writes final alerts and tampering files.

### Repository Flow Structure

The codebase is organized into a clean folder layout corresponding to the pipeline steps:

```
GIBL-main/
|-- run_pipeline.py                 # Master pipeline orchestrator
|-- response_agent.py               # Response operations agent
|-- Behaviour/                      # Behavior Agent files
|   |-- behavior_agent.py           # Core behavior logic
|   `-- run_behavior_agent.py       # Behavior agent runner
|-- Correlational/                  # Correlation Agent files
|   |-- config.py                   # System configurations and thresholds
|   `-- correlation_agent.py        # Gated fusion and graph builder
|-- Flow/                           # Flow Agent files
|   |-- flow.py                     # Flow model logic
|   `-- run_flow_agent.py           # Flow agent runner
|-- Packet Agent/                   # Packet Agent files
|   `-- packet_agent_runner.py      # Packet agent runner
|-- demo/                           # Real-time dashboard files
|   |-- run_demo.py                 # Demo dashboard orchestrator
|   |-- target_server.py            # Simulated core banking server
|   `-- live_ids.py                 # Live monitoring and blocking agent
`-- outputs/                        # Unified folder for outputs
    |-- flow_scores.csv
    |-- threat_results_with_ja3.csv
    |-- behavior_agent_detailed_results.csv
    |-- correlation_scores.csv
    |-- alert_triage_submission.csv
    `-- swift_tampering.csv
```

---

## 1.2 Setup & Installation

### Prerequisites

The pipeline is written in Python 3. Requires Python version 3.8 or higher.

### Installing Dependencies

Install the required library packages using pip:

```bash
pip install pandas numpy scikit-learn xgboost networkx joblib
```

### Dataset Structure and Placement

Ensure the following raw input files are present in your target dataset directory (default location: `GIBL/Track D/`):
- `netflow_records.csv` (Network traffic transaction logs)
- `zeek_conn_logs.csv` (Zeek connection metadata and JA3 TLS signatures)
- `windows_event_logs.csv` (Active Directory and host OS security logs)
- `host_profiles.csv` (Inventory of hostnames, IP allocations, segments, and honeypot decoders)
- `ueba_user_behavior.csv` (User transactions, file access, and logons)
- `incident_tickets.csv` (Incident historical logs for correlation tuning)

You can customize these paths by modifying `Correlational/config.py` and `response_agent.py` directly, or by setting their respective environment variables.

---

## 1.3 Quick Start

### Use Case 1: Offline Batch Forensics & Performance Evaluation
This is used to process massive, static network log dumps (e.g., historical traffic or competition datasets) using the full power of the AI pipeline to analyze logs, detect lateral movement, identify compromised SWIFT assets, and output final triage report sheets.

#### Inputs Expected (located in Track D folder):
* `netflow_records.csv` — Primary network flow database.
* `zeek_conn_logs.csv` — Deep packet analysis logs.
* `windows_event_logs.csv` — Host machine security event logs.
* `host_profiles.csv` — Network inventory and asset information.
* `ueba_user_behavior.csv` — User logon baseline logs.
* `incident_tickets.csv` — Historical ground-truth ticket logs (used to measure validation success).

#### How to Run it:
1. Open your terminal at the main folder
2. Run the master pipeline script:
   ```bash
   python3 run_pipeline.py
   ```
(This script runs the Flow Agent, Packet Agent, Behavior Agent, Correlation Engine, and Response Agent in sequential steps).

#### Outputs Produced (Saved in outputs/):
* `flow_scores.csv` — Individual scores from the Flow Agent.
* `threat_results_with_ja3.csv` — Identified malicious hashes from the Packet Agent.
* `behavior_agent_detailed_results.csv` — Contextual anomaly alerts from the Behavior Agent.
* `correlation_scores.csv` — Fused, segment-amplified scores from the Correlation Engine.
* `swift_tampering.csv` — A filtered, ranked shortlist of affected assets inside the high-security SWIFT gateway.
* **`submission_GIBL.csv`** — The final triage submission file formatted exactly to match competition requirements.

### Use Case 2: Real-Time Active Defense & Prevention (Live Dashboard)
This is the interactive dashboard used by security operations centers (SOC) to monitor a live server, witness real-time simulated attacks, and watch the AI block threat actors instantaneously on the firewall.

#### Inputs Expected:
* Live client HTTP requests interacting with the target server.
* Simulated malicious API signals triggered by clicking buttons on the visual console.

#### How to Run it:
1. Open a terminal and start the target banking application server:
   ```bash
   python3 demo/target_server.py
   ```
2. Open a second terminal and start the live monitoring IDS agent:
   ```bash
   python3 demo/live_ids.py
   ```
3. Open your browser and navigate to the security dashboard:
   ```
   http://localhost:8080/
   ```

#### Outputs Produced:
* **Real-time scrolling console logs:** Network flows dynamically slide into the terminal window.
* **Threat Alert Cards:** Cards pop up immediately for malicious actions, detailing the exact score breakdown.
* **Firewall Jail (IP Blocks):** Attacker IPs are instantaneously banned (via a `POST /api/block` call back to the target server), adding them to the firewall's active jail list on the dashboard UI.
* `demo/live_alerts.log` — A continuous log stream of every alert generated.
