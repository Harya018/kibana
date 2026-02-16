# AI-Powered SIEM (Next-Gen)

A modular, offline, AI-driven SIEM involved in Behavioral Analytics, Advanced Correlation, and Automated Response.

## 🌟 Key Features

### 1. Multi-Source Ingestion
*   **Log Sources**: Firewall, EDR (Endpoint Detection & Response), OS, Web Server, and custom apps.
*   **Normalization**: Auto-maps raw logs to **Elastic Common Schema (ECS)**.

### 2. User & Entity Behavior Analytics (UEBA)
*   **Profiling**: Creates persistent user profiles in Elasticsearch (`siem-profiles`).
*   **Anomaly Detection**: Flags:
    *   **New Country Logins**: Access from a country never seen before for the user.
    *   **Off-Hours Activity**: Logins outside the user's standard baseline hours.

### 3. Advanced Correlation Engine
*   **Attack Chain Detection**: Links sequential events (e.g., `Suspicious Login` -> `PowerShell Execution`).
*   **MITRE ATT&CK Enrichment**: Tags incidents with Tactic/Technique IDs (e.g., `T1078`, `Initial Access`).
*   **Rule-Based Detection**: Brute Force, High-Risk Asset Access.

### 4. Intelligent Risk Scoring & Memory
*   **Multi-Factor Scoring**: Calculates Risk (0-100) based on Severity + Anomaly Boost + Asset Criticality.
*   **Incident Memory**: Searches past resolved incidents to find similar historical context.

### 5. Automated AI Response (Offline)
*   **AI Playbooks**: Generates markdown response plans using a local LLM (**Ollama**).
*   **Visualizations**: Embeds **MermaidJS** diagrams of the attack path.
*   **Automated Actions**: Can block IPs or disable users (Safe Mode enabled by default).

---

## 🚀 Quick Start Guide

### Prerequisites
1.  **Docker Desktop** (for Elasticsearch/Kibana).
2.  **Python 3.10+**.
3.  **Ollama** (for AI features):
    *   Install from [ollama.ai](https://ollama.ai).
    *   Run `ollama serve`.
    *   Pull model: `ollama pull llama2`.

### Step 1: Start Infrastructure
```bash
docker compose up -d
```
*Wait ~60 seconds for Elasticsearch to be ready.*

### Step 2: Initialize System
Set up Elasticsearch indices and mappings:
```bash
cd siem_project
python manage.py setup_es_indices
```

### Step 3: Start the SIEM
Open **Terminal 1** for the Web Server:
```bash
python manage.py runserver
```

Open **Terminal 2** for the Correlation Engine (Real-time detection):
```bash
python manage.py run_siem
```

---

## 🧪 How to Simulate Attacks

The project includes scripts to verify each component.

### 1. Simulate External Logs (Ingestion)
Generates fake firewall and EDR logs to test ingestion/normalization.
```bash
python simulate_external_logs.py
```

### 2. Simulate Attack Chain (Correlation & AI)
Simulates a full kill-chain: `Suspicious Login` (UEBA Anomaly) -> `Malicious PowerShell` (EDR).
```bash
python simulate_attack_chain.py
```
*   **Expected Output**: `[PASS] Attack Chain detected`.
*   **Result**: Check the terminal running `run_siem` to see the generated Incident and AI Playbook.

### 3. Verify AI & Visualization
Checks the latest generated playbook for the Mermaid diagram and response sections.
```bash
python verify_visualization.py
```

---

## 📊 Dashboard (Kibana)
Access Kibana at [http://localhost:5601](http://localhost:5601).
*   **Discover**: View raw logs (`logs-*`) and incidents (`siem-incidents`).
*   **Dashboard**: Visualize Risk Scores, MITRE Tactics, and Geo-maps.
