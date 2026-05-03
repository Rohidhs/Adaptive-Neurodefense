# 🛡️ Adaptive NeuroDefense

**AI-Powered Real-Time Threat Monitoring & Automated Defense System**

Adaptive NeuroDefense is an intelligent cybersecurity framework that integrates Graph Neural Networks (GNN), Deep Q-Network Reinforcement Learning (DQN), Kafka-based streaming, and a Streamlit dashboard to detect, classify, and autonomously respond to network intrusions in real time.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running the Project](#running-the-project)
- [Modules](#modules)
- [Attack Types Detected](#attack-types-detected)
- [Test Results](#test-results)
- [Future Enhancements](#future-enhancements)

---

## Overview

Traditional Intrusion Detection Systems (IDS) rely on static, signature-based models that fail against zero-day and evolving attacks. Adaptive NeuroDefense addresses this by combining:

- **GNN-based threat detection** — models relational patterns between network devices as graph nodes/edges
- **Isolation Forest anomaly scoring** — flags statistical outliers and novel attack vectors
- **DQN Reinforcement Learning agent** — autonomously selects and learns optimal mitigation actions
- **Self-healing response** — automatically applies IP blocking, traffic throttling, and service isolation
- **Real-time Streamlit dashboard** — provides live visualizations, threat timelines, and AI-driven insights

---

## Features

| Feature | Description |
|---|---|
| Real-Time Monitoring | Continuous threat score timeline with threshold indicators |
| Dynamic Threat Scoring | Scores between 0–1 mapped to LOW / MEDIUM / HIGH severity |
| Attack Distribution | Live pie chart of detected attack category proportions |
| Automated Defense | Autonomous IP blocking, traffic throttling, and node isolation |
| Threat Prediction | Single-event manual input and batch CSV upload analysis |
| AI Insights | Contextual anomaly analysis and security recommendations |
| System Health | Live CPU, memory, network traffic, and model confidence metrics |
| Kafka Streaming | Producer/consumer pipeline for real-time network event ingestion |
| GNN + DQN Models | Deep learning models for detection and adaptive decision-making |

---

## System Architecture

The system operates across four sequential stages:

```
Data Collection  →  Threat Detection  →  RL Decision-Making  →  Response & Recovery
─────────────────────────────────────────────────────────────────────────────────────
Network Traffic      GNN Module            DQN Agent              Self-Healing Module
System Logs          Isolation Forest      Action Selection       IP Blocking
Kafka Streaming      Anomaly Score         Reward Optimization    Node Isolation
Graph Construction   Node/Edge Analysis    Policy Update          Traffic Throttle
                                                                  Dashboard Monitor
```

**Deployment topology:** Kafka Cluster (3 Brokers) → Flask Server (8 Instances) → Redis Cache + PostgreSQL DB, with a dedicated GPU Node running GNN + DQN inference.

---

## Project Structure

```
adaptive_neurodefense/
│
├── dashboard/
│   └── app.py                  # Streamlit dashboard (main entry point)
│
├── models/
│   ├── gnn_rl_model.py         # GNN + DQN model definitions
│   └── train_model.py          # Model training pipeline
│
├── kafka_pipeline/
│   ├── producer.py             # Kafka threat event producer
│   └── consumer.py             # Kafka consumer + live inference
│
├── data/
│   ├── cyber_threat_dataset.csv  # Training dataset (150,000 records)
│   └── generate_dataset.py     # Synthetic dataset generator
│
└── generate_dataset.py         # Root-level dataset generator (standalone)
```

---

## Requirements

### Hardware

| Component | Specification |
|---|---|
| Processor | AMD Ryzen 7 / equivalent (4.4 GHz+) |
| RAM | 16 GB minimum |
| Storage | 1 TB |
| GPU | Dedicated NVIDIA or AMD GPU (recommended) |
| Network | High-speed internet connection |

### Software

- **OS:** Windows 10 / Ubuntu 20.04+
- **Python:** 3.8 or higher
- **IDE:** Jupyter Notebook / VS Code / Anaconda

---

## Installation

### 1. Clone or extract the project

```bash
git clone <repository-url>
cd adaptive_neurodefense
```

Or unzip the project archive:

```bash
unzip adaptive_neurodefense.zip
cd adaptive_neurodefense
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows
```

### 3. Install Python dependencies

```bash
pip install streamlit pandas numpy plotly scikit-learn tensorflow torch torchvision torch-geometric kafka-python
```

For GPU support with PyTorch, visit [pytorch.org](https://pytorch.org/get-started/locally/) and install the appropriate CUDA build.

### 4. Set up Apache Kafka

Download and extract [Apache Kafka](https://kafka.apache.org/downloads), then start the services:

```bash
# Start Zookeeper
bin/zookeeper-server-start.sh config/zookeeper.properties

# Start Kafka Broker
bin/kafka-server-start.sh config/server.properties
```

Create required topics:

```bash
bin/kafka-topics.sh --create --topic network_traffic --bootstrap-server localhost:9092 --partitions 3 --replication-factor 1
bin/kafka-topics.sh --create --topic threat_alerts --bootstrap-server localhost:9092 --partitions 3 --replication-factor 1
bin/kafka-topics.sh --create --topic system_logs --bootstrap-server localhost:9092 --partitions 3 --replication-factor 1
```

---

## Running the Project

### Option A — Dashboard only (simulated mode, no Kafka required)

This mode uses built-in probabilistic simulation for demonstration:

```bash
cd dashboard
streamlit run app.py
```

Open your browser at `http://localhost:8501`

---

### Option B — Full pipeline (Kafka + trained model)

**Step 1: Generate or use the existing dataset**

```bash
python data/generate_dataset.py
```

**Step 2: Train the GNN + DQN model**

```bash
cd models
python train_model.py
```

Saved model artifacts will appear under `models/saved_models/`.

**Step 3: Start the Kafka producer**

```bash
cd kafka_pipeline
python producer.py
```

**Step 4: Start the Kafka consumer (threat inference)**

```bash
python consumer.py
```

**Step 5: Launch the dashboard**

```bash
cd dashboard
streamlit run app.py
```

---

## Modules

### Threat Simulation
Generates synthetic network events with source/destination IPs, protocol type, service, data volume, login attempts, and session duration. Assigns probabilistic attack types and computes threat scores.

### Threat Detection & Scoring
Analyzes each event and outputs a dynamic threat score (0–1). Classifies events into LOW / MEDIUM / HIGH severity and updates accuracy/detection metrics in real time.

### Real-Time Monitoring
Interactive Streamlit tab displaying a live threat timeline chart with threshold indicators, recent event tables, and key performance metrics.

### Attack Distribution Analysis
Pie chart visualization updated in real time showing proportions of each detected attack category across the session.

### Defense & Response
Autonomous or semi-autonomous mitigation: IP blocking (score > 0.8), traffic throttling (score > 0.6), service investigation (score > 0.4), or allow (normal traffic). Maintains a timestamped defense action log.

### Threat Prediction
Accepts manual network parameter input or batch CSV upload. Returns predicted attack type, severity, recommended action, and confidence score.

### AI Insights & Recommendations
Virtual security analyst that identifies anomaly trends, model health, unusual login patterns, and provides prioritized mitigation recommendations.

### System Health Monitoring
Tracks CPU usage, memory, network traffic throughput, and model confidence in real time via progress indicators and historical performance charts.

---

## Attack Types Detected

| Attack Type | Description |
|---|---|
| `normal` | Legitimate network traffic |
| `dos` | Denial of Service / DDoS flood |
| `probe` | Network reconnaissance and scanning |
| `r2l` | Remote to Local unauthorized access |
| `u2r` | User to Root privilege escalation |
| `malware` | Malicious software activity |
| `phishing` | Credential harvesting attempts |
| `ransomware` | Encryption-based extortion attacks |
| `zero-day` | Previously unknown exploit patterns |

---

## Severity & Response Logic

| Threat Score | Severity | Automated Action |
|---|---|---|
| > 0.80 | 🔴 HIGH | BLOCK IP immediately |
| 0.60 – 0.80 | 🟠 MEDIUM | THROTTLE & monitor |
| 0.40 – 0.60 | 🟡 LOW | INVESTIGATE |
| < 0.40 | 🟢 NONE | ALLOW |

---

## Test Results

All 15 test cases passed during system testing:

- Threat simulation generates events with correct attributes ✅
- HIGH severity DoS events trigger IP blocking ✅
- MEDIUM severity phishing events trigger throttling ✅
- Normal traffic correctly classified as LOW / ALLOW ✅
- Single-event manual prediction works correctly ✅
- Batch CSV analysis processes records and reports accuracy ✅
- Invalid CSV uploads are safely rejected with error message ✅
- Auto-refresh updates dashboard every 3 seconds ✅
- 500 consecutive events processed without data loss or errors ✅

**Simulated performance benchmarks:**

| Metric | Value |
|---|---|
| Detection Accuracy | ~90–98% |
| Model Confidence | ~95.7% |
| Response Time | ~10–20 ms |
| Batch Analysis (150,000 records) | 98.1% accuracy |

---

## Future Enhancements

- Integration with live network traffic feeds (PCAP / NetFlow)
- Deployment of advanced deep learning models (Bi-LSTM, Transformers)
- Multi-cloud and IoT environment support
- SIEM tool integration (Splunk, ELK Stack)
- Behavior-based anomaly detection for insider threat detection
- Federated learning for privacy-preserving collaborative defense
- Automated incident response workflows with ticketing system integration

---

## Tech Stack

`Python` · `Streamlit` · `PyTorch` · `PyTorch Geometric` · `TensorFlow` · `Scikit-learn` · `Apache Kafka` · `Plotly` · `Pandas` · `NumPy`

---

## References

Key literature informing this project includes work on ML-based IDS with Cyber Threat Intelligence (Lin et al., 2025), GNN-based intrusion detection (Zhong et al., 2024; Tran & Park, 2024), deep reinforcement learning for network security (Yang et al., 2024), autonomous self-healing AI systems (Walter, 2023), and federated learning for attack detection (Wang et al., 2024).

---

*Adaptive NeuroDefense — Strengthening network resilience through intelligent, self-adaptive cybersecurity.*
