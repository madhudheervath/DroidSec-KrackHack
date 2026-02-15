# 🛡️ DroidSec — APK Static Security Analyzer

> **KrackHack 3.0 — Problem Statement 01: Mobile App Security Analyzer**

DroidSec is a static analysis tool that decompiles Android APK files, scans for security vulnerabilities, maps findings to the **OWASP Mobile Top 10 (2024)**, and generates professional security reports with severity scoring and remediation guidance.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **50+ Vulnerability Checks** | Detects hardcoded secrets, weak cryptography, insecure communication, storage issues, and WebView vulnerabilities |
| 📊 **Security Score (0-100)** | Weighted scoring algorithm with A-F grading |
| 🛡️ **OWASP Mobile Top 10** | Every finding mapped to OWASP M1-M10 categories |
| 📋 **Executive Summary** | Auto-generated executive summary for stakeholders |
| 🎯 **Confidence Scoring** | Each finding rated by confidence level (high/medium/low) |
| 💻 **Code Evidence** | Actual code snippets showing vulnerability context |
| ✅ **Remediation Guidance** | Actionable fix instructions for every finding |
| 🧠 **Logic-Gated Heuristics** | Advanced checks for biometric misuse, receiver/provider exposure, taint-style source→sink risks, JNI/native loading risks, and service abuse patterns |
| 📄 **Professional Reports** | Beautiful HTML reports with dark-mode styling |
| 🌐 **Web UI** | Modern Next.js dashboard with drag-and-drop APK upload |
| ⚡ **Fast Analysis** | Full scan in 30-60 seconds |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Next.js Frontend                      │
│  Upload APK → Progress → Dashboard → Report Download    │
└──────────────────────┬──────────────────────────────────┘
                       │ POST /api/scan
┌──────────────────────▼──────────────────────────────────┐
│                  FastAPI Backend                         │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Decompiler   │  │ Manifest     │  │ Code Scanner  │  │
│  │ apktool+jadx │  │ Analyzer     │  │ 50+ regex     │  │
│  └──────┬──────┘  └──────┬───────┘  └──────┬────────┘  │
│         └────────┬───────┴─────────────────┘            │
│         ┌────────▼──────────┐                            │
│         │  OWASP Mapper &   │                            │
│         │  Severity Scorer  │                            │
│         └────────┬──────────┘                            │
│         ┌────────▼──────────┐                            │
│         │ Report Generator  │                            │
│         │ HTML + JSON       │                            │
│         └───────────────────┘                            │
└──────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- Java 11+ (for apktool/jadx)

### Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/DroidSec.git
cd DroidSec

# Backend setup
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Frontend setup (new terminal)
cd frontend
npm install
npm run dev
```

### Usage
1. Open **http://localhost:3000** in your browser
2. Drag & drop an APK file (or click to browse)
3. Wait for the scan to complete (30-60 seconds)
4. View the interactive security dashboard
5. Download the HTML report

---

## 🚆 Railway Deployment

DroidSec is pre-configured for one-click deployment to **Railway**.

1. **Fork** this repository to your GitHub account.
2. Log in to **Railway.app** and click **"New Project"**.
3. Select **"Deploy from GitHub repo"** and choose your fork.
4. Railway will automatically detect the `Dockerfile` and `railway.json`.
5. **Environment Variables:**
   - Add `GEMINI_API_KEY` (optional) for AI-powered analysis.
6. **Persistence (Optional):**
   - If you want to keep scan reports after redeploys, go to **Settings > Volumes** and mount a volume at `/app/backend/reports`.

---

### API Usage
```bash
# Scan an APK
curl -X POST http://localhost:8000/api/scan -F "file=@your-app.apk"

# Get report
curl http://localhost:8000/api/report/{scan_id}

# Download HTML report
curl http://localhost:8000/api/report/{scan_id}/download -o report.html
```

---

## 🔎 Vulnerability Detection Categories

### Hardcoded Secrets (M1)
- AWS/GCP/Azure keys
- Google/Firebase API keys
- GitHub/Slack tokens
- Hardcoded passwords, private keys

### Weak Cryptography (M10)
- MD5/SHA-1 hash usage
- DES/3DES encryption
- ECB mode
- Hardcoded encryption keys/IVs
- Insecure random number generation

### Insecure Communication (M5)
- Cleartext HTTP URLs
- Trust-all-certificates
- Hostname verifier bypass
- SSL error override in WebViews

### Security Misconfiguration (M8)
- Debuggable applications
- Exported components without permissions
- Missing network security config

### Insecure Data Storage (M9)
- World-readable/writable files
- Sensitive data in logs
- Unencrypted SQLite databases
- External storage usage

### WebView Vulnerabilities (M4/M8)
- JavaScript enabled on untrusted content
- File access from URLs
- JavaScript interface (RCE risk)

### Permission Analysis (M6)
- Excessive dangerous permissions
- Privacy-sensitive permissions audit

---

## 📊 Scoring Algorithm

| Severity | Weight | Description |
|----------|--------|-------------|
| Critical | 10 | Immediate exploitation risk |
| High | 7 | Significant security impact |
| Medium | 4 | Moderate risk, should be addressed |
| Info | 1 | Best practice recommendation |

**Score = 100 - Σ(weight × confidence_multiplier)**

| Grade | Score Range | Risk Level |
|-------|-----------|------------|
| A | 90-100 | Low |
| B | 75-89 | Low-Medium |
| C | 60-74 | Medium |
| D | 40-59 | High |
| F | 0-39 | Critical |

---

## 🛠️ Tech Stack

- **Frontend:** Next.js 14, React, TailwindCSS, Lucide Icons
- **Backend:** Python, FastAPI, Uvicorn
- **Analysis:** apktool, jadx, 50+ custom regex patterns
- **Reports:** Custom HTML template with dark-mode styling

---

## 📁 Project Structure

```
DroidSec/
├── backend/
│   ├── core/
│   │   ├── decompiler.py        # APK decompilation (apktool + jadx)
│   │   ├── manifest_analyzer.py # AndroidManifest.xml analysis
│   │   ├── code_scanner.py      # Regex-based vulnerability scanning
│   │   ├── owasp_mapper.py      # OWASP mapping & scoring
│   │   └── report_generator.py  # HTML/JSON report generation
│   ├── rules/
│   │   ├── secrets.py           # 15 hardcoded secret patterns
│   │   ├── crypto.py            # 10 weak crypto patterns
│   │   ├── network.py           # 6 network security patterns
│   │   ├── storage.py           # 7 data storage patterns
│   │   ├── webview.py           # 6 WebView vulnerability patterns
│   │   ├── permissions.py       # 18 dangerous permissions
│   │   └── modern_heuristics.py # Logic-gated ADV/TAINT/MAL/NATIVE checks
│   ├── main.py                  # FastAPI application
│   └── requirements.txt
├── frontend/
│   └── app/
│       ├── page.tsx             # Main UI (upload + dashboard)
│       ├── layout.tsx           # Root layout
│       └── globals.css          # Design system
├── tools/
│   ├── apktool                  # apktool wrapper
│   ├── apktool.jar              # apktool v2.9.3
│   └── jadx/                    # jadx v1.5.1
└── README.md
```

---

## 👥 Team

**KrackHack 3.0 Submission**
- **Lead Developer:** [Your Name]
- **Point of Contact:** Harsh (+91 95188 30309)

---

## 📜 License

MIT License
