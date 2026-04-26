# 🛡️ Adaptive Firewall with Real-Time Threat Detection

![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Adaptive%20Firewall-blue)
![Python](https://img.shields.io/badge/Python-Flask-yellow)
![Machine Learning](https://img.shields.io/badge/ML-Z--Score%20Detection-green)
![License](https://img.shields.io/badge/License-MIT-red)
![Status](https://img.shields.io/badge/Project-Final%20Year%20Major%20Project-success)
![Security](https://img.shields.io/badge/Web%20Security-Application%20Layer-important)

---

# 🚀 Project Overview

Adaptive Firewall is a Final Year Major Cybersecurity Project designed to protect modern web applications and APIs from both known and unknown cyber threats using a hybrid security model.

Traditional firewalls mainly work at the network layer and rely on static predefined rules. They are effective for known threats but often fail to detect advanced application-layer attacks like SQL Injection, Cross-Site Scripting (XSS), Command Injection, Path Traversal, Bot Attacks, and abnormal malicious traffic patterns.

This project solves that problem by combining:

## 🔐 Rule-Based Detection

for known attacks

AND

## 🤖 Machine Learning Anomaly Detection

for unknown suspicious behavior

This makes the firewall adaptive, intelligent, and capable of making real-time security decisions.

The system can:

✅ Allow safe requests

✅ Block malicious requests

✅ Temporarily block suspicious IPs 

✅ Permanently ban repeated attackers

✅ Log all attacks for forensic analysis

✅ Visualize everything on a real-time SOC-style dashboard

---

# 🏗️ System Architecture

## 📌 System Architecture Diagram
![alt text](<assets/Screenshot 2026-04-24 214411.png>)



---

# 🔄 Complete Workflow

```text
Client Request
   ↓
Flask Web Application
   ↓
Adaptive Firewall Engine
   ↓
Request Inspection
(IP, Headers, Payload, Endpoint, Method)
   ↓
Detection Engine
├── Rule-Based Detection
└── ML-Based Anomaly Detection
   ↓
Decision Engine
├── Allow
├── Block
├── Temporary Block
└── Permanent Ban
   ↓
Logging & Storage
   ↓
Real-Time Dashboard Monitoring
```

---

# ✨ Key Features

## 🔥 Security Features

✅ SQL Injection Detection

✅ Cross-Site Scripting (XSS) Detection

✅ Command Injection Detection

✅ Path Traversal Detection

✅ Bot / Scanner Detection

✅ Rate Limiting & DoS Prevention

✅ Multiple IP Reputation Tracking

✅ Temporary + Permanent IP Blocking

✅ Request Forensics & Investigation


## 🤖 ML Features

✅ Z-Score Based Anomaly Detection

✅ Entropy Analysis

✅ Request Size Analysis

✅ Special Character Ratio Detection

✅ Header Count Monitoring

✅ Query Parameter Count Analysis

✅ Unknown Threat Detection


## 📊 Dashboard Features

✅ Live Threat Monitoring

✅ Total Requests Counter

✅ Blocked Requests Counter

✅ Threat Detection Counter

✅ Blocked IP Monitoring

✅ Request Timeline Graph

✅ Threat Distribution Chart

✅ Real-Time Security Logs

✅ Expandable IP Investigation

✅ JSON + Human Readable Log Details

✅ Unblock IP Feature

✅ Refresh + Clear Logs

---

# 🧠 Core Detection Model

This project uses a:

# Hybrid Detection Model

```text
Rule-Based Detection + Machine Learning Detection
```

---

# 1️⃣ Rule-Based Detection Engine

Implemented in:

```text
detection.py
```

This module uses:

* Regex Matching
* Payload Inspection
* Header Analysis
* Signature-Based Detection

It detects:

### SQL Injection

```sql
' OR 1=1 --
UNION SELECT
DROP TABLE users
```

### XSS

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

### Command Injection

```bash
&& whoami
; ls
$(whoami)
```

### Path Traversal

```text
../../etc/passwd
..\\..\\windows\\system32
```

### Bot Detection

```text
sqlmap
nikto
nmap
masscan
```

### Rate Limiting

Too many requests in short time → blocked

---

# 2️⃣ ML-Based Anomaly Detection

Implemented in:

```text
ml_detector.py
```

Uses:

# Z-Score Statistical Anomaly Detection

This is an unsupervised ML model.

The system first learns normal user traffic and creates a baseline profile.

Then it compares new requests with that baseline.

If deviation is too high → anomaly detected.

## Formula Used

```text
Z = (X - μ) / σ
```

Where:

* X = Current feature value
* μ = Mean of normal traffic
* σ = Standard deviation

If:

```text
Z-score > Threshold
```

Then:

```text
ML_ANOMALY detected
```

---

# 📥 Feature Extraction

The ML model checks:

* Request Size
* Payload Entropy
* Special Character Ratio
* Header Count
* Query Parameter Count
* Repeated Patterns
* Suspicious Input Behavior

This helps detect:

✅ Unknown attacks

✅ Zero-day style anomalies

✅ Obfuscated malicious requests


---

# ⚔️ Attack Simulation

Implemented in:

```text
attack_simulator.py
```

This file generates both:

## 👨‍💻 Normal User Traffic

for ML training

AND

## 🚨 Malicious Traffic

for attack testing

---

## Simulated Attacks Include

🔥 SQL Injection
🔥 XSS Attack
🔥 Command Injection
🔥 Path Traversal
🔥 Bot Scanner Attack
🔥 Rate-Limit Burst
🔥 ML Anomaly Payloads
🔥 Multiple Fake IP Attacks

This helps test real-time firewall performance.

Run using:

```bash
python attack_simulator.py
```

---

# 💻 Technology Stack

## Backend

* Python 🐍
* Flask 🌐

## Frontend

* HTML
* CSS
* JavaScript
* Chart.js 📊

## Security Layer

* Regex Detection
* Signature Matching
* Rate Limiting
* IP Reputation Logic

## Machine Learning

* Z-Score Statistical Detection
* Feature Engineering
* Behavioral Analysis

## Testing

* Custom Attack Simulator
* cURL Testing
* Browser Testing

---

# 📂 Project Structure

```text
Adaptive-firewall/
│
├── app.py
├── firewall.py
├── detection.py
├── ml_detector.py
├── logger.py
├── config.py
├── rules.py
├── attack_simulator.py
│
├── templates/
│   └── dashboard.html
│
├── screenshots/
│   └── system-architecture.png
│
├── logs/
│
├── requirements.txt
├── README.md
├── .gitignore
└── LICENSE
```

---

# ⚙️ File Responsibilities

## app.py

Main Flask application and API routes

## firewall.py

Main firewall decision engine

## detection.py

Rule-based attack detection

## ml_detector.py

ML anomaly detection engine

## logger.py

Threat logging and forensic storage

## config.py

System configuration and thresholds

## rules.py

Security rules and attack patterns

## dashboard.html

Frontend real-time monitoring dashboard

## attack_simulator.py

Traffic generation and attack testing

---

# ▶️ Installation & Setup

## Step 1 — Clone Repository

```bash
git clone <your-repository-link>
cd Adaptive-firewall
```

## Step 2 — Create Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate
```

## Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 4 — Run Application

```bash
python app.py
```

## Step 5 — Open Dashboard

```text
http://127.0.0.1:5000
```

---

# 📊 Dashboard Preview

![alt text](<assets/Screenshot 2026-04-24 200445.png>)
![alt text](<assets/Screenshot 2026-04-24 200535.png>)
![alt text](<assets/Screenshot 2026-04-24 200603.png>)

The dashboard provides:
* Live request monitoring
* Threat detection charts
* Security logs
* Blocked IP tracking
* Expandable forensic investigation
* Threat summaries
* Attack visualization

This simulates a mini Security Operations Center (SOC).

---
---

# 🔮 Future Scope

* SIEM Integration
* Email Alerts
* Telegram Alerts
* Docker Deployment
* Cloud Deployment
* RBAC (Role-Based Access Control)
* Admin Authentication
* Threat Intelligence Feed Integration
* Isolation Forest / Advanced ML Models
* Deep Learning Based Detection

---

# 📜 License

This project is licensed under the MIT License.

---

# ⭐ Final Note

This project demonstrates how traditional rule-based security can be combined with machine learning intelligence to create an adaptive firewall capable of protecting modern web applications and APIs in real time.

It is not just a college project — it is a practical cybersecurity solution with real-world relevance.

🚀 Final Year Major Project
🛡️ Cybersecurity + Machine Learning + Real-Time Monitoring
🔥 Resume Ready + Placement Ready + GitHub Portfolio Project
