# ⚡ Network Packet Analyzer

> An AI-powered network security monitoring tool with real-time threat detection, 
> MITRE ATT&CK mapping, and a live web dashboard.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![Scapy](https://img.shields.io/badge/Scapy-2.5-green?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-ready-blue?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## 🔍 What it does

A production-grade network packet analyzer that captures live traffic, 
detects threats in real time, and displays everything in a browser-based dashboard.
Built from scratch using Python, Scapy, and Flask.

---

## ✨ Features

| Feature | Description |
|---|---|
| 📡 **Live packet capture** | Real-time TCP/UDP/ICMP capture using Scapy |
| 🌍 **GeoIP + reverse DNS** | Country, city and hostname for every IP |
| 🛡 **Threat intelligence** | AbuseIPDB integration — flags malicious IPs with score |
| ⚔️ **MITRE ATT&CK mapping** | Every alert tagged with technique ID and tactic |
| 🤖 **ML anomaly detection** | Isolation Forest baseline model flags abnormal traffic |
| 📊 **Live charts** | Protocol breakdown + packets/sec timeline |
| ⚠️ **Email alerts** | Gmail SMTP notifications on critical detections |
| 💾 **PCAP export** | Download captures directly openable in Wireshark |
| 🐳 **Docker ready** | One-command deployment with docker-compose |
| ⚙️ **YAML config** | All settings in config.yaml — no code changes needed |

---

## 🖥 Dashboard

The web dashboard runs at `http://localhost:5000` and includes:

- **Live packet feed** — color coded by threat level (CRITICAL / HIGH / MEDIUM / NORMAL)
- **Alerts panel** — real-time security alerts with MITRE ATT&CK technique IDs
- **Threat intel panel** — AbuseIPDB scores for every external IP seen
- **ML anomaly panel** — Isolation Forest training status and anomaly count
- **Top talkers** — most active IPs on your network
- **Protocol chart** — live doughnut chart of TCP/UDP/ICMP split
- **Timeline chart** — packets per second over the last 60 seconds
- **Click to expand** — every panel expands to full screen on click

---

## 🚀 Quick start

### Option 1 — Docker (recommended)

```bash
git clone https://github.com/YOUR_USERNAME/network-packet-analyzer
cd network-packet-analyzer
cp .env.example .env        # add your API keys
docker-compose up
```

Open `http://localhost:5000`

### Option 2 — Direct Python (Windows)

```bash
git clone https://github.com/YOUR_USERNAME/network-packet-analyzer
cd network-packet-analyzer
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py              # run as Administrator
```

Open `http://localhost:5000`

---

## ⚙️ Configuration

All settings are in `config.yaml`:

```yaml
network:
  interface: '\Device\NPF_{your-interface}'  # from get_if_list()
  filter: "ip"

detection:
  port_scan_threshold: 15
  risky_ports: [22, 23, 445, 3389, 4444]

ml:
  baseline_duration: 120    # seconds to collect before training
  contamination: 0.05       # expected anomaly rate
```

---

## 🔑 Environment variables

Create a `.env` file (never commit this):