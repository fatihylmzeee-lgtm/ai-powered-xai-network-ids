# AI-Powered Real-Time XAI Network Intrusion Detection System

A real-time **Explainable AI-based Network Intrusion Detection System (XAI-IDS)** built with **Python and Scapy**.  
The system captures live network traffic, detects suspicious activity using machine learning, applies SOC-style rules to reduce false positives, and explains *why* an alert was triggered.

---

## 🚀 Project Overview

This project was developed to simulate a **real-world SOC-oriented IDS pipeline**, combining:
- Live packet capture
- Machine learning–based anomaly detection
- Rule-based SOC logic
- Explainable AI (XAI) alert explanations

The goal is not only to detect attacks, but to **make alerts understandable and actionable**.

---

## 🧠 Architecture
Live Traffic (Scapy)
↓
Feature Extraction
↓
StandardScaler
↓
RandomForest Model
↓
Risk Score (predict_proba)
↓
SOC Rules (Whitelist, Cooldown, IOC)
↓
🚨 Alert + XAI Explanation


---

## 🔑 Features

- 📡 **Live Packet Capture** using Scapy
- 🤖 **Machine Learning Detection**
  - RandomForestClassifier
  - Imbalanced data handling (`class_weight="balanced"`)
- 🛡️ **SOC-Style Rules**
  - Whitelisting (DNS, mDNS, SSDP, multicast)
  - Cooldown / rate-limiting
  - IOC (Indicator of Compromise) matching
- 🔍 **Explainable Alerts (XAI)**
  - Why an alert was triggered (small packet, sensitive port, SYN flags, IOC hit, high probability)
- ⚡ **Real-Time Detection**

---

## 📊 Dataset

Traffic was collected from **live network capture** and manually labeled.

- Total samples: ~56,000
- Normal traffic: ~50,000
- Attack traffic: ~6,000

Features:
- Packet length
- Protocol (TCP=1, UDP=2)
- Source port
- Destination port
- TCP flags

This reflects a **realistic imbalanced dataset**, common in intrusion detection.

---

## ▶️ How to Run

### Requirements
- Python 3.x
- Administrator/root privileges (required for packet sniffing)

### Install dependencies
```bash
pip install scapy pandas scikit-learn joblib

