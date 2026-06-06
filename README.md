# 🛡️ ZeroDayForge — AI-Powered Web Vulnerability Scanner (Phase 3 Ultimate)

<p align="center">
  <img src="https://img.shields.io/badge/Version-Phase%203%20Ultimate-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.8%2B-yellow?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/AI-Scikit--Learn%20%7C%20IsolationForest-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Interface-CLI%20%7C%20Web%20%7C%20API-black?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Use-Authorized%20Targets%20Only-red?style=for-the-badge" />
</p>

<p align="center">
  An enterprise-grade, AI-powered web application vulnerability scanner. ZeroDayForge crawls target applications, tests for common web vulnerabilities using advanced payload sets, and delivers findings through a CLI dashboard, web interface, or RESTful API — with PDF report generation, SQLite persistence, distributed multi-node scanning, and optional Docker deployment.
</p>

---

## ✨ Features at a Glance

| Category | Feature |
|---|---|
| 🤖 **AI Detection** | ML-based anomaly detection using `IsolationForest` — learns baseline behavior and flags deviations |
| 🕷️ **Smart Crawler** | Depth-configurable web crawler with form parsing, API endpoint discovery, and JS variable extraction |
| 💉 **Vulnerability Testing** | SQL Injection, XSS, Command Injection, Path Traversal — multi-vector payloads per category |
| 📊 **Triple Analysis Engine** | Traditional (rule-based) + Signature-based + Behavioral anomaly analysis in every test |
| 🔐 **Auth Support** | Basic, Form-based, Token (JWT/Bearer), and Cookie/Session authentication for authenticated scans |
| 🌐 **Web Dashboard** | Flask-powered UI with live scan results, risk stats, and vulnerability table |
| 🔌 **RESTful API** | Background scan queue, status polling, result retrieval, and PDF download via HTTP API |
| 📄 **PDF Reporter** | Professional PDF report via ReportLab — executive summary, risk table, detailed findings, and remediation guidance |
| 🗄️ **Database Persistence** | SQLite-backed scan and vulnerability history with full result storage |
| 🌍 **Distributed Scanning** | Multi-node architecture for distributing endpoint scans across scanner nodes |
| 🐳 **Docker Support** | Built-in `Dockerfile` + `requirements.txt` generation and container lifecycle management |
| ⚙️ **Configurable Engine** | 15+ tunable parameters — threads, crawl depth, rate limits, AI threshold, report format |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.8+ |
| AI / ML | `scikit-learn` (IsolationForest), `numpy` |
| Web Framework | `Flask`, `flask-cors` |
| HTML Parsing | `beautifulsoup4` |
| HTTP Client | `requests` (persistent session) |
| PDF Generation | `reportlab` |
| Database | `sqlite3` (built-in) |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` |
| Containerization | `docker` SDK |
| Response Analysis | `difflib` (content similarity scoring) |

---

## ⚙️ Requirements

- Python 3.8 or higher
- Windows / Linux / macOS
- Internet access to the target application

### Core Dependencies

```bash
pip install requests beautifulsoup4 flask flask-cors numpy scikit-learn reportlab docker
```

> All dependencies are **gracefully optional** — the tool detects availability at runtime and disables unsupported features with warnings rather than crashing. Minimum viable run requires only `requests`.

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/zerodayforge.git
cd zerodayforge
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run ZeroDayForge

```bash
python ZeroDayForge.py
```

Select your preferred mode from the startup menu.

---

## 🖥️ Run Modes

```
╔═══════════════════════════════════════════════════════════════════════╗
║     Zero-Day & Detection Tool - Phase 3 ULTIMATE                      ║
║              AI-Powered Enterprise Scanner                            ║
║         Distributed | API-Ready | Docker-Ready | Advanced Analytics   ║
╚═══════════════════════════════════════════════════════════════════════╝

Select Mode:
  1. CLI Mode        — Full-featured command-line scan with live output
  2. Web Dashboard   — Browser-based UI at http://localhost:5000
  3. API Server      — RESTful API for automation and CI/CD integration
  4. Distributed     — Multi-node scanning for large-scale assessments
  5. Docker Deploy   — Containerized deployment via Docker SDK
```

---

## 🔍 Vulnerability Modules

### Payload Categories

| Type | Examples |
|---|---|
| **SQL Injection** | Boolean-based, Union-based, Time-based, Error-based, Stacked queries, WAF bypasses |
| **Cross-Site Scripting (XSS)** | Reflected, DOM-based, Event handlers, Encoded, CSP bypass variants |
| **Command Injection** | Unix/Windows chained commands, subshell execution, blind injection |
| **Path Traversal** | `../` sequences, URL-encoded, double-encoded, null-byte variants |

### Analysis Pipeline (per payload/parameter)

```
Request → Baseline Capture
       → Payload Injection (GET / POST)
       → Triple Analysis:
           ├─ Traditional  : status code, response length, time delay
           ├─ Signature    : error pattern matching, reflection detection
           └─ Behavioral   : information leakage, stack trace detection
       → AI Scoring (IsolationForest, if trained)
       → Risk Classification: CRITICAL / HIGH / MEDIUM / LOW / INFO
```

### Risk Scoring

| Score | Risk Level |
|---|---|
| 8 – 10 | 🔴 CRITICAL |
| 5 – 7  | 🟠 HIGH |
| 3 – 4  | 🟡 MEDIUM |
| 1 – 2  | 🟢 LOW |
| 0      | ℹ️ INFO |

---

## 🌐 Web Dashboard

Launch with mode `2`. Opens automatically at **http://localhost:5000**.

- Enter target URL and crawl depth (Shallow / Standard / Deep)
- Live scan progress indicator
- Results panel with CRITICAL / HIGH / MEDIUM / LOW summary cards
- Vulnerability table showing type, parameter, risk, score, and findings

---

## 🔌 REST API Reference

Launch with mode `3`. Server starts on `http://0.0.0.0:5000`.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scan` | Start a new background scan `{"url": "...", "depth": 2}` |
| `GET` | `/api/v1/scan/<id>` | Retrieve full scan results |
| `GET` | `/api/v1/scan/<id>/status` | Poll scan status and progress % |
| `GET` | `/api/v1/report/<id>/pdf` | Download PDF report for a completed scan |
| `GET` | `/api/v1/analytics` | Aggregated statistics across all scans |
| `GET` | `/api/v1/health` | Health check with timestamp |

### Example: Start a Scan

```bash
curl -X POST http://localhost:5000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://your-authorized-target.com", "depth": 2}'
```

```json
{
  "scan_id": "a3f1c9d2...",
  "status": "started",
  "message": "Scan started successfully"
}
```

---

## 📄 PDF Report

Generated at end of CLI scan or via API. Contains:

- **Executive Summary** — target, total tests, average risk score
- **Risk Summary Table** — CRITICAL / HIGH / MEDIUM / LOW counts
- **Detailed Findings** — top 15 vulnerabilities with parameter, score, confidence, payload, and evidence
- **Remediation Recommendations** — 8 prioritized action items

---

## ⚙️ Configuration Reference

All settings are in the `ScannerConfig` dataclass:

| Parameter | Default | Description |
|---|---|---|
| `timeout` | `10` | HTTP request timeout (seconds) |
| `max_threads` | `10` | Concurrent scanning threads |
| `max_retries` | `3` | Retry attempts per failed request |
| `request_delay` | `0.3` | Delay between requests (seconds) |
| `max_crawl_depth` | `3` | Maximum crawl depth |
| `max_crawl_pages` | `50` | Maximum pages to crawl |
| `rate_limit` | `100` | Max requests per minute |
| `enable_ai` | `True` | Enable ML anomaly detection |
| `enable_distributed` | `False` | Enable multi-node mode |
| `ai_confidence_threshold` | `0.7` | Minimum AI confidence for flagging |
| `anomaly_threshold` | `0.3` | Isolation Forest anomaly cutoff |
| `report_format` | `json` | Output format: `json`, `pdf`, `html` |
| `database_path` | `scanner_data.db` | SQLite database file path |

---

## 📂 Output Files

| File | Description |
|---|---|
| `scanner_data.db` | SQLite database — all scans and vulnerabilities |
| `sessions.json` | Saved authentication session config |
| `scan_report_<timestamp>.pdf` | PDF report for CLI scans |
| `api_report_<scan_id>.pdf` | PDF report for API-triggered scans |
| `Dockerfile` | Auto-generated on Docker mode |
| `requirements.txt` | Auto-generated on Docker mode |

---

## 🐳 Docker Deployment

Select mode `5` to automatically generate a `Dockerfile` and `requirements.txt`, build the image, and launch the container:

```
Exposed ports: 5000 (Web/API), 8000 (Simple Web fallback)
Base image: python:3.9-slim
```

Or build manually:

```bash
docker build -t zerodayforge:latest .
docker run -p 5000:5000 -p 8000:8000 zerodayforge:latest
```

---

## ⚠️ Legal & Ethical Disclaimer

> **This tool is strictly for authorized, educational, and lab use only.**
>
> - ✅ Use **only** on web applications you **own** or have **explicit written permission** to test
> - ✅ Ideal for CTF challenges, DVWA, WebGoat, testphp.vulnweb.com, and authorized engagements
> - ❌ Do **not** run against production systems, third-party applications, or any target without authorization
> - ❌ Unauthorized vulnerability scanning may violate laws including the **CFAA (USA)**, **Computer Misuse Act (UK)**, **IT Act 2000 (India)**, and other regional cybersecurity legislation
>
> The author bears **no responsibility** for any misuse of this tool.

---

## 👤 Author

**Abhishek Rampariya**

- GitHub: [@AbhishekRampariya](https://github.com/AbhishekRampariya)

---

## 📄 License

Licensed for **educational and authorized security research only**. Commercial redistribution requires explicit permission.

---

<p align="center">Built with 🐍 Python · AI-Powered · Enterprise-Grade · Docker-Ready</p>
<p align="center">ZeroDayForge Phase 3 Ultimate — Scan Smart. Patch Fast.</p>
