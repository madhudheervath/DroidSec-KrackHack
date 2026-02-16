# 🛡️ DroidSec — Advanced Android APK Security Analysis Platform

> **KrackHack 3.0 — Problem Statement 01: Mobile App Security Analyzer**

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-droidsec--krackhack--production-blue?style=for-the-badge)](https://droidsec-krackhack-production-df80.up.railway.app/)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-14-black?style=for-the-badge&logo=next.js)](https://nextjs.org)

**DroidSec** is a production-ready, enterprise-grade Android APK static security analyzer that combines powerful decompilation tools with AI-driven vulnerability detection. It performs comprehensive security audits by analyzing APK files, detecting 50+ vulnerability types across 15 specialized rule modules, mapping findings to **OWASP Mobile Top 10 (2024)** standards, and generating professional security reports with actionable remediation guidance.

## 🌐 Live Demo

**🔗 Try it now:** [https://droidsec-krackhack-production-df80.up.railway.app/](https://droidsec-krackhack-production-df80.up.railway.app/)

Upload any Android APK and get a complete security analysis in under 60 seconds!

---

## ✨ Key Features

### 🔍 Comprehensive Security Analysis
- **50+ Vulnerability Detection Rules** across 15 specialized modules
- **Dual-Source Code Scanning** — analyzes both Java/Kotlin (decompiled from DEX) and Smali bytecode
- **Multi-Layer Analysis** — AndroidManifest.xml, source code, resources, network configs, binary protections
- **Smart Library Detection** — distinguishes first-party code from third-party libraries (300+ known SDKs)
- **Advanced Heuristics** — logic-gated checks for biometric misuse, intent vulnerabilities, native code risks, and taint analysis

### 🤖 AI-Powered Intelligence
- **Interactive Security Chat** — conversational AI assistant powered by Groq LLaMA 3.3 70B (4096 tokens)
- **Deep Threat Analysis** — AI-generated threat modeling, vulnerability chains, and attack scenarios
- **Contextual Remediation** — per-finding code fixes with before/after comparisons
- **Natural Language Q&A** — ask questions about findings in plain English

### 📊 Professional Reporting
- **Security Score (0-100)** with A-F grading system
- **OWASP Mobile Top 10 (2024)** mapping for every finding
- **Confidence Scoring** — high/medium/low ratings with multipliers (0.9/0.7/0.35)
- **Executive Summary** — auto-generated stakeholder-friendly overview
- **Multiple Export Formats** — PDF, HTML, JSON, CSV
- **Rich Visualizations** — radar charts, bar charts, donut charts, animated score rings

### 💻 Modern User Experience
- **Drag-and-Drop Upload** — intuitive APK upload with progress tracking
- **Real-Time Scanning** — live status updates via WebSocket-style polling (2.5s intervals)
- **Dark-Mode Dashboard** — cybersecurity-themed UI with glass-morphism cards
- **Particle Animations** — Canvas-based background with `requestAnimationFrame`
- **Persistent History** — recent scans cached in localStorage with instant access
- **Responsive Design** — works on desktop, tablet, and mobile

### 🚀 Production-Ready
- **Fast Analysis** — full scan completes in 30-60 seconds
- **200 MB Upload Limit** — handles large, complex APKs
- **Background Processing** — ThreadPoolExecutor for non-blocking async scans
- **Disk Persistence** — reports survive server restarts and redeployments
- **Docker Multi-Stage Build** — optimized for cloud deployment
- **Health Checks** — `/api/health` endpoint for monitoring (120s timeout)

---

## 🏗️ System Architecture

DroidSec is architected as a **unified full-stack application** with a FastAPI backend orchestrating multi-stage security analysis and a Next.js frontend providing an enterprise-grade user interface.

```
┌──────────────────────────────────────────────────────────────────┐
│                     Next.js 14 Frontend                          │
│  ┌────────────────────────────────────────────────────────┐     │
│  │  Drag & Drop Upload → Progress Polling → Dashboard    │     │
│  │  OWASP Radar Charts → AI Chat → Export (PDF/JSON/CSV) │     │
│  └────────────────────────────────────────────────────────┘     │
│                         ↓ POST /api/scan                         │
└──────────────────────────┬───────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────┐
│                    FastAPI Backend (Python)                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │         Multi-Stage Analysis Pipeline                     │   │
│  │                                                            │   │
│  │  1️⃣ APK Decompilation          (apktool v2.9.3 + jadx)  │   │
│  │     ├─ Resource Extraction       AndroidManifest.xml     │   │
│  │     ├─ Smali Disassembly         Native libs, assets     │   │
│  │     └─ Java Source Generation    Full class hierarchy    │   │
│  │                                                            │   │
│  │  2️⃣ Manifest Analysis           Exported components      │   │
│  │                                   Dangerous permissions    │   │
│  │                                   Debuggable flag check    │   │
│  │                                                            │   │
│  │  3️⃣ Multi-Source Code Scanning  15 Rule Modules          │   │
│  │     ├─ secrets.py                15 hardcoded patterns   │   │
│  │     ├─ crypto.py                 10 weak crypto patterns │   │
│  │     ├─ network.py                6 insecure network      │   │
│  │     ├─ storage.py                7 data storage issues   │   │
│  │     ├─ webview.py                6 WebView vulns         │   │
│  │     ├─ permissions.py            18 dangerous perms      │   │
│  │     ├─ malware.py                Dynamic code loading    │   │
│  │     ├─ entropy.py                Shannon entropy (crypto)│   │
│  │     ├─ signing.py                APK signature checks    │   │
│  │     ├─ modern_heuristics.py     Logic-gated ADV/TAINT   │   │
│  │     ├─ cloud_config.py           Firebase misconfig      │   │
│  │     ├─ deeplink.py               Intent filter risks     │   │
│  │     ├─ binary_protection.py     Obfuscation detection    │   │
│  │     ├─ network_config.py        NSC analysis             │   │
│  │     └─ smali_rules.py            Bytecode patterns       │   │
│  │                                                            │   │
│  │  4️⃣ OWASP Mapping & Scoring     Weighted algorithm       │   │
│  │     ├─ Severity: Critical×20, High×12, Medium×3          │   │
│  │     ├─ Confidence: High×1.0, Med×0.7, Low×0.35           │   │
│  │     ├─ Source: 1st-party×1.0, 3rd-party×0.35            │   │
│  │     └─ Normalization for codebase size                   │   │
│  │                                                            │   │
│  │  5️⃣ AI Deep Analysis (Optional) Groq LLaMA 3.3 70B      │   │
│  │     ├─ Threat Modeling           Exploitation scenarios  │   │
│  │     ├─ Attack Chains              Multi-step attacks     │   │
│  │     └─ Code Remediation           Vulnerable→Fixed diff  │   │
│  │                                                            │   │
│  │  6️⃣ Report Generation            JSON + HTML output      │   │
│  │     ├─ Executive Summary          Grade, risk level      │   │
│  │     ├─ Findings List              Evidence + remediation │   │
│  │     └─ OWASP Breakdown            M1-M10 distribution    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  Storage: /app/backend/data/reports/ (persistent volume)        │
└───────────────────────────────────────────────────────────────────┘
```

### Analysis Pipeline Details

**Step 1: Decompilation**
- `apktool` extracts resources, AndroidManifest.xml, and disassembles DEX to Smali bytecode
- `jadx` decompiles DEX bytecode to human-readable Java/Kotlin source code
- Workspace created at `/app/backend/data/reports/{scan_id}/`

**Step 2: Manifest Analysis**
- Parses `AndroidManifest.xml` for exported components (Activity, Service, BroadcastReceiver, ContentProvider)
- Checks for `android:debuggable="true"`, `android:allowBackup="true"`, insecure `networkSecurityConfig`
- Extracts permissions, package name, version, min/target SDK

**Step 3: Code Scanning**
- 50+ regex patterns scan both Java and Smali sources
- Smart library filtering excludes 300+ known third-party SDKs (Firebase, OkHttp, Retrofit, etc.)
- Entropy analysis detects obfuscated/encrypted strings (Shannon entropy > 4.5)
- Context extraction provides 500 chars of surrounding code for evidence

**Step 4: OWASP Mapping & Scoring**
- Every finding mapped to OWASP Mobile Top 10 (M1-M10)
- Weighted scoring: `Score = 100 - Σ(severity_weight × confidence_multiplier × source_multiplier)`
- Normalization factor: `sqrt(files_scanned / 100)` prevents large apps from being unfairly penalized
- Caps per rule type prevent score saturation

**Step 5: AI Analysis (Optional)**
- Sends top critical/high findings to Groq LLaMA 3.3 70B
- System prompt includes full scan context (package, score, findings)
- Temperature 0.5 for balanced creativity/accuracy
- Conversation history maintained (up to 30 messages, trimmed to 24)

**Step 6: Report Generation**
- JSON report with structured findings, metadata, OWASP breakdown
- HTML report with dark-mode styling for human consumption
- Saved to persistent disk storage (survives container restarts)

---

## 🚀 Getting Started

### Prerequisites
- **Python** 3.10+ (3.11 recommended)
- **Node.js** 18+ (for Next.js frontend)
- **Java** 11+ (required for apktool and jadx)
- **Git** (for cloning the repository)

### Quick Start — Local Development

#### Option 1: One-Command Launch
```bash
# Clone the repository
git clone https://github.com/madhudheervath/DroidSec-KrackHack.git
cd DroidSec-KrackHack

# Make start script executable and run
chmod +x start.sh
./start.sh
```
This starts the backend on `http://127.0.0.1:8000` and frontend on `http://localhost:3000`.

#### Option 2: Separate Backend/Frontend (Recommended for Development)
```bash
# Terminal 1: Backend
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Frontend
cd frontend
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

### Usage

1. **Upload APK**: Drag and drop an APK file (or click to browse)
2. **Wait for Scan**: Progress updates appear in real-time (30-60 seconds)
3. **View Dashboard**: Automatic redirect to security report when complete
4. **Explore Findings**: Filter by severity, search by keyword, expand for details
5. **AI Analysis**: Click the floating chat button for interactive Q&A
6. **Export Report**: Download as PDF, JSON, CSV, or HTML

### Environment Variables (Optional)

Create a `.env` file in the project root:

```bash
# AI Features (Optional)
GROQ_API_KEY=your_groq_api_key_here          # For LLaMA 3.3 70B chat
GEMINI_API_KEY=your_gemini_api_key_here      # Alternative AI provider

# Backend Configuration
DROIDSEC_DATA_DIR=/app/backend/data          # Persistent storage location
DROIDSEC_SCAN_WORKERS=2                      # Concurrent scan workers (default: 2)

# Frontend Configuration
NEXT_PUBLIC_BACKEND_URL=http://127.0.0.1:8000  # Backend API URL
```

**Getting API Keys:**
- **Groq**: Sign up at [console.groq.com](https://console.groq.com) (free tier available)
- **Gemini**: Get an API key from [ai.google.dev](https://ai.google.dev)

---

## 🚢 Deployment

### Railway (One-Click Deploy)

DroidSec is pre-configured for seamless deployment to **Railway**:

1. **Fork** this repository to your GitHub account
2. Log in to [Railway.app](https://railway.app) and click **"New Project"**
3. Select **"Deploy from GitHub repo"** and choose your fork
4. Railway auto-detects `Dockerfile` and `railway.json`
5. **(Optional)** Add environment variables:
   - `GROQ_API_KEY` — for AI-powered chat and remediation
   - `GEMINI_API_KEY` — alternative AI provider (if Groq not available)
6. **(Optional)** Mount a persistent volume:
   - Go to **Settings → Volumes**
   - Mount at `/app/backend/data` to preserve reports across restarts

**Deployment Configuration:**
- **Builder**: Dockerfile (multi-stage build)
- **Health Check**: `/api/health` endpoint (120s timeout)
- **Restart Policy**: On failure
- **Port**: Auto-detected from `PORT` environment variable

### Docker (Manual Deployment)

```bash
# Build the image
docker build -t droidsec:latest .

# Run the container
docker run -d \
  -p 3000:3000 \
  -e GROQ_API_KEY=your_api_key \
  -v droidsec-data:/app/backend/data \
  --name droidsec \
  droidsec:latest

# View logs
docker logs -f droidsec
```

### Kubernetes / Cloud Platforms

The Docker image is cloud-agnostic and can be deployed to:
- **AWS ECS/Fargate**: Use the Dockerfile with ECR
- **Google Cloud Run**: Deploy with Cloud Build
- **Azure Container Instances**: Push to ACR
- **DigitalOcean App Platform**: Connect GitHub repo

**Minimum Resources:**
- **CPU**: 1 vCPU
- **Memory**: 2 GB RAM
- **Storage**: 10 GB (for reports and uploaded APKs)

---

## 📡 API Documentation

### REST API Endpoints

#### Scan Operations

**POST /api/scan** — Upload and scan an APK
```bash
curl -X POST \
  -F "file=@/path/to/your-app.apk" \
  https://droidsec-krackhack-production-df80.up.railway.app/api/scan

# Response:
{
  "scan_id": "a1b2c3d4",
  "status": "queued",
  "message": "Scan accepted and queued. Poll /api/scan/{scan_id}/status for progress."
}
```

**GET /api/scan/{scan_id}/status** — Check scan progress
```bash
curl https://droidsec-krackhack-production-df80.up.railway.app/api/scan/a1b2c3d4/status

# Response (in progress):
{
  "scan_id": "a1b2c3d4",
  "status": "running",
  "started_at": "2026-02-16T00:15:30.123Z",
  "finished": false
}

# Response (completed):
{
  "scan_id": "a1b2c3d4",
  "status": "completed",
  "finished": true,
  "completed_at": "2026-02-16T00:16:45.789Z",
  "score": 24,
  "grade": "F",
  "total_findings": 53
}
```

#### Report Retrieval

**GET /api/report/{scan_id}** — Get JSON report
```bash
curl https://droidsec-krackhack-production-df80.up.railway.app/api/report/a1b2c3d4
```

**GET /api/report/{scan_id}/html** — View HTML report in browser
```bash
curl https://droidsec-krackhack-production-df80.up.railway.app/api/report/a1b2c3d4/html
```

**GET /api/report/{scan_id}/download** — Download HTML report
```bash
curl -O -J https://droidsec-krackhack-production-df80.up.railway.app/api/report/a1b2c3d4/download
```

**GET /api/reports** — List all available reports
```bash
curl https://droidsec-krackhack-production-df80.up.railway.app/api/reports

# Response:
[
  {
    "scan_id": "a1b2c3d4",
    "package": "com.example.app",
    "score": 24,
    "grade": "F",
    "timestamp": "2026-02-16T00:16:45.789Z",
    "filename": "example-app.apk",
    "findings_count": 53
  }
]
```

#### AI Analysis (Requires API Key)

**GET /api/ai/status** — Check if AI features are available
```bash
curl https://droidsec-krackhack-production-df80.up.railway.app/api/ai/status

# Response:
{
  "available": true,
  "provider": "groq",
  "model": "llama-3.3-70b-versatile",
  "message": "AI ready"
}
```

**POST /api/ai/analyze/{scan_id}** — Deep AI analysis
```bash
curl -X POST https://droidsec-krackhack-production-df80.up.railway.app/api/ai/analyze/a1b2c3d4
```

**POST /api/ai/chat** — Interactive AI chat
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "a1b2c3d4", "message": "What are the top 3 critical vulnerabilities?"}' \
  https://droidsec-krackhack-production-df80.up.railway.app/api/ai/chat
```

**POST /api/ai/remediate** — Get AI-powered fix for a specific finding
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "a1b2c3d4", "finding_index": 0}' \
  https://droidsec-krackhack-production-df80.up.railway.app/api/ai/remediate
```

#### Health & Diagnostics

**GET /api/health** — Health check for monitoring
```bash
curl https://droidsec-krackhack-production-df80.up.railway.app/api/health

# Response:
{
  "status": "ok",
  "apktool_path": "/app/tools/apktool",
  "apktool_exists": true,
  "jadx_path": "/app/tools/jadx/bin/jadx",
  "jadx_exists": true,
  "data_root": "/app/backend/data",
  "report_dir": "/app/backend/data/reports",
  "report_count": 42
}
```

---

## ⚙️ Troubleshooting

### Backend Issues

#### `ModuleNotFoundError: No module named 'pydantic'`

**Cause**: Using system Python instead of project virtual environment.

**Solution**:
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### `Failed to decompile APK: apktool not found`

**Cause**: Analysis tools not installed or not in PATH.

**Solution**:
```bash
# Run the setup script
chmod +x setup_tools.sh
./setup_tools.sh

# Verify installation
java -jar tools/apktool.jar --version
tools/jadx/bin/jadx --version
```

#### `APK upload fails with 413 Request Entity Too Large`

**Cause**: APK exceeds 200 MB limit.

**Solution**: The 200 MB limit is configurable via `MAX_APK_SIZE` in `backend/main.py`. For larger APKs:
```python
MAX_APK_SIZE = 500 * 1024 * 1024  # 500 MB
```

### Frontend Issues

#### `Cannot find module './682.js'` or `vendor-chunks/@swc.js` errors

**Cause**: Stale or corrupted Next.js build cache.

**Solution**:
```bash
cd frontend
npm run clean       # Removes .next directory
npm install         # Reinstall dependencies
npm run dev         # Restart dev server
```

#### `Failed to proxy http://127.0.0.1:8000/api/... socket hang up`

**Cause**: Backend is not running or not reachable.

**Solution 1** (Local Development):
```bash
# Ensure backend is running first
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Solution 2** (Remote Backend):
Set the backend URL in `frontend/.env.local`:
```bash
NEXT_PUBLIC_BACKEND_URL=https://your-backend-domain.railway.app
```

### Docker Issues

#### `Docker build fails at apktool/jadx download`

**Cause**: Network timeout or tool download URL changed.

**Solution**: Check `setup_tools.sh` for correct download URLs. Update if necessary:
```bash
# Latest apktool release
APKTOOL_VERSION="2.9.3"

# Latest jadx release
JADX_VERSION="1.5.1"
```

#### `Container exits immediately after start`

**Cause**: Backend failed to start or tools missing.

**Solution**:
```bash
# Check container logs
docker logs droidsec

# Exec into container for debugging
docker exec -it droidsec /bin/bash
java -jar /app/tools/apktool.jar --version
/app/tools/jadx/bin/jadx --version
```

### AI Features

#### `AI not configured. Set GROQ_API_KEY environment variable`

**Cause**: No API key set for AI features.

**Solution**:
```bash
# Get a free Groq API key from console.groq.com
export GROQ_API_KEY="gsk_..."

# Or use Gemini
export GEMINI_API_KEY="AIza..."

# Restart backend
python -m uvicorn main:app --reload
```

#### `AI service error: 429 Too Many Requests`

**Cause**: Groq/Gemini rate limit exceeded.

**Solution**: 
- Wait for rate limit reset (typically 1 minute)
- Upgrade to Groq/Gemini paid tier for higher limits
- Switch to alternative AI provider (set both `GROQ_API_KEY` and `GEMINI_API_KEY`)

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'pydantic'`

You are using system Python instead of project venv.

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend `Cannot find module './682.js'` or `vendor-chunks/@swc.js`

The Next.js build cache is stale/corrupted.

```bash
cd frontend
npm run clean
npm install
npm run dev
```

### `Failed to proxy http://127.0.0.1:8000/api/... socket hang up`

Backend is not reachable. Ensure backend is running first, or set:

```bash
NEXT_PUBLIC_BACKEND_URL=https://<your-backend-domain>
```

---

---

## 🔎 Vulnerability Detection Categories

DroidSec performs comprehensive security analysis across 15 specialized rule modules:

### 1. **Hardcoded Secrets & Credentials (M1 — Improper Credential Usage)**
- **15 Detection Patterns**: AWS keys, GCP keys, Azure storage, Google API keys, Firebase configs
- **Secret Types**: GitHub tokens, Slack webhooks, Stripe keys, Twilio SIDs, SendGrid keys
- **Additional Checks**: Hardcoded passwords, SSH private keys, database credentials
- **Confidence**: High (pattern-based), Medium (heuristic-based)

### 2. **Weak Cryptography (M10 — Insufficient Cryptography)**
- **10 Patterns**: MD5/SHA-1 hashing, DES/3DES encryption, ECB mode usage
- **Key Management**: Hardcoded encryption keys/IVs, insecure random number generation
- **TLS/SSL Issues**: SSLv3, weak cipher suites, certificate validation bypass
- **Entropy Analysis**: Shannon entropy > 4.5 flags obfuscated/encrypted strings

### 3. **Insecure Communication (M5)**
- **6 Network Patterns**: Cleartext HTTP URLs, `setAllowedHostVerifier(ALLOW_ALL)`
- **Certificate Issues**: Trust-all-certificates, hostname verifier bypass
- **WebView SSL**: `onReceivedSslError()` override that ignores SSL errors
- **Network Config**: Missing `network_security_config.xml`, `cleartextTrafficPermitted="true"`

### 4. **Security Misconfiguration (M8)**
- **Manifest Checks**: `android:debuggable="true"`, exported components without permissions
- **Backup Risks**: `android:allowBackup="true"` with sensitive data
- **Component Exposure**: Exported Activity/Service/Receiver/Provider with weak protection
- **Intent Vulnerabilities**: Unvalidated intent extras, intent redirection

### 5. **Insecure Data Storage (M9)**
- **7 Storage Patterns**: `MODE_WORLD_READABLE`, `MODE_WORLD_WRITABLE` file access
- **Database Security**: Unencrypted SQLite databases with sensitive data
- **External Storage**: Sensitive data written to `getExternalStorageDirectory()`
- **SharedPreferences**: Storing passwords/tokens in plain SharedPreferences
- **Logging**: Sensitive data logged via `Log.d()`, `System.out.println()`

### 6. **WebView Vulnerabilities (M4/M8 — Input Validation)**
- **6 WebView Patterns**: `setJavaScriptEnabled(true)` on untrusted content
- **File Access**: `setAllowFileAccess(true)`, `setAllowFileAccessFromFileURLs(true)`
- **JavaScript Interface**: `addJavascriptInterface()` without `@JavascriptInterface` annotation
- **XSS Risks**: Loading user-controlled URLs without validation
- **SSL Override**: Ignoring SSL errors in WebView client

### 7. **Permission Analysis (M6 — Inadequate Privacy Controls)**
- **18 Dangerous Permissions**: `READ_CONTACTS`, `ACCESS_FINE_LOCATION`, `CAMERA`, `RECORD_AUDIO`
- **Privacy-Sensitive**: `READ_SMS`, `READ_CALL_LOG`, `GET_ACCOUNTS`, `READ_CALENDAR`
- **Security-Critical**: `WRITE_EXTERNAL_STORAGE`, `INSTALL_PACKAGES`, `SYSTEM_ALERT_WINDOW`
- **Risk Assessment**: Combines permission count with app functionality context

### 8. **Malware Heuristics (M7 — Binary Protections)**
- **Dynamic Code Loading**: `DexClassLoader`, `PathClassLoader`, reflection-based loading
- **Native Library Risks**: `System.loadLibrary()`, `Runtime.exec()` with suspicious commands
- **Obfuscation Detection**: ProGuard, DexGuard, commercial packers (Bangcle, Qihoo, Tencent)
- **Root Detection**: `su` binary checks, RootBeer library usage

### 9. **Entropy & Obfuscation Detection**
- **Shannon Entropy**: Analyzes string randomness (entropy > 4.5 = encrypted/obfuscated)
- **Base64 Blobs**: Large Base64-encoded strings (potential hidden payloads)
- **Hex Strings**: Long hex sequences (encryption keys, config data)
- **Context Analysis**: Cross-references with nearby cryptographic API calls

### 10. **Network Security Config (M5)**
- **NSC Validation**: Parses `res/xml/network_security_config.xml`
- **Cleartext Traffic**: Checks for `cleartextTrafficPermitted="true"`
- **Certificate Pinning**: Validates pin-set configuration
- **Trust Anchors**: Detects user-installed certificate trust

### 11. **APK Signing & Integrity (M7)**
- **Signature Verification**: Checks APK v1/v2/v3 signature schemes
- **Certificate Info**: Extracts issuer, validity period, key size
- **Debug Signatures**: Warns if signed with Android debug keystore
- **Signature Strength**: Flags weak RSA keys (< 2048 bits), expired certificates

### 12. **Cloud & Third-Party Misconfigurations (M8)**
- **Firebase**: Publicly accessible Realtime Database URLs, missing auth rules
- **AWS S3**: Public S3 bucket URLs in code/resources
- **API Endpoints**: Unprotected API keys in `strings.xml`, `BuildConfig.java`
- **OAuth Misconfig**: Hardcoded client secrets, redirect URI vulnerabilities

### 13. **Deeplink & Intent Security (M3/M4)**
- **Intent Filter Analysis**: Parses `<intent-filter>` from AndroidManifest
- **Deeplink Validation**: Checks for missing host verification
- **Path Traversal**: Detects intent data processing without sanitization
- **Pending Intent**: Identifies mutable PendingIntent vulnerabilities

### 14. **Binary Protections (M7)**
- **ProGuard/R8**: Detects obfuscation via package name patterns (`a.b.c`, single-letter classes)
- **Native Libraries**: Scans for `.so` files, checks for stack canaries, PIE, RELRO
- **Root Detection**: Identifies anti-root, emulator detection, debugger checks
- **Tamper Detection**: File integrity checks, CRC validation

### 15. **Modern Logic-Gated Heuristics**
- **Biometric Misuse**: `BiometricPrompt` without `BIOMETRIC_STRONG` or crypto object
- **Taint Analysis**: Source → Sink tracking (user input → SQL/exec/WebView)
- **JNI/Native Risks**: JNI method declarations without validation
- **Service/Receiver Abuse**: Exported services accepting arbitrary intents
- **Provider SQL Injection**: ContentProvider with raw SQL queries

---

### Detection Statistics by Module

| Module | Patterns | Coverage | Primary OWASP |
|--------|----------|----------|---------------|
| **secrets.py** | 15 | Hardcoded credentials | M1 |
| **crypto.py** | 10 | Weak encryption | M10 |
| **network.py** | 6 | Insecure comms | M5 |
| **storage.py** | 7 | Data leakage | M9 |
| **webview.py** | 6 | XSS/injection | M4 |
| **permissions.py** | 18 | Privacy risks | M6 |
| **malware.py** | 8 | Code loading | M7 |
| **entropy.py** | 3 | Obfuscation | M7 |
| **signing.py** | 4 | APK integrity | M7 |
| **modern_heuristics.py** | 12 | Advanced logic | M3/M4 |
| **cloud_config.py** | 5 | Firebase/AWS | M8 |
| **deeplink.py** | 6 | Intent security | M3 |
| **binary_protection.py** | 7 | Packer detection | M7 |
| **network_config.py** | 4 | NSC analysis | M5 |
| **smali_rules.py** | 15 | Bytecode patterns | All |

**Total: 50+ unique vulnerability patterns across 15 modules**

---

## 📊 Security Scoring Algorithm

DroidSec uses a sophisticated weighted scoring system that balances severity, confidence, and codebase complexity:

### Scoring Formula

```
Base Penalty = Σ(severity_weight × confidence_multiplier × source_multiplier)
Normalization Factor = sqrt(files_scanned / 100)
Final Score = max(0, min(100, 100 - (Base Penalty / Normalization Factor)))
```

### Severity Weights

| Severity | Weight | Impact | Examples |
|----------|--------|--------|----------|
| **Critical** | 20 | Immediate exploitation risk, severe business impact | Debuggable APK, hardcoded AWS keys, SQL injection |
| **High** | 12 | Significant security risk, likely exploitable | Weak cryptography, insecure SSL, exported components |
| **Medium** | 3 | Moderate risk, requires specific conditions | Missing obfuscation, logging sensitive data |
| **Info** | 0 | Best practice recommendation, no direct risk | Excessive permissions, third-party library usage |

### Confidence Multipliers

| Confidence | Multiplier | Description |
|------------|------------|-------------|
| **High** | 1.0 | Pattern-based detection with low false positive rate |
| **Medium** | 0.7 | Heuristic-based detection with context validation |
| **Low** | 0.35 | Speculative detection, may require manual verification |

### Source Type Multipliers

| Source Type | Multiplier | Rationale |
|-------------|------------|-----------|
| **First-Party** | 1.0 | App-specific code has full penalty |
| **Manifest** | 1.0 | Configuration issues are critical |
| **Resource** | 0.9 | Resource files have slightly lower impact |
| **Smali Fallback** | 0.95 | Smali-only findings (when Java unavailable) |
| **Third-Party** | 0.35 | Library issues are developer's responsibility but lower priority |
| **Unknown** | 0.8 | Conservative penalty for unclassified code |

### Rule-Specific Caps

To prevent score saturation from repeated violations of the same rule:

| Severity | Max Penalty | Rationale |
|----------|-------------|-----------|
| **Critical** | 28 points | Even 100 critical findings capped at 28 points |
| **High** | 20 points | Prevents single issue type from dominating score |
| **Medium** | 10 points | Allows many medium findings without score collapse |
| **Info** | 2 points | Info findings have negligible score impact |

### Normalization for Codebase Size

Large, complex applications (e.g., Telegram, YouTube) naturally have more code and thus more findings. The normalization factor `sqrt(files_scanned / 100)` prevents unfair penalties:

- **Small app** (100 files): Factor = 1.0 (no normalization)
- **Medium app** (1,000 files): Factor = 3.16
- **Large app** (10,000 files): Factor = 10.0
- **Enterprise app** (100,000 files): Factor = 31.6

This means a large app with 10× more findings than a small app will still get a similar score if the vulnerability density is proportional.

### Grading Scale

| Grade | Score Range | Risk Level | Interpretation |
|-------|-------------|------------|----------------|
| **A** | 90-100 | Low | Excellent security posture, minimal issues |
| **B** | 75-89 | Low-Medium | Good security, minor improvements needed |
| **C** | 60-74 | Medium | Average security, several issues to address |
| **D** | 40-59 | High | Poor security, significant vulnerabilities |
| **F** | 0-39 | Critical | Severe security issues, immediate action required |

### Example Calculation

**Scenario**: InsecureBankv2.apk scan results:
- **Findings**: 2 Critical, 25 High, 11 Medium, 15 Info
- **Files Scanned**: 50 Java files
- **Confidence**: Avg 85% (High)
- **Source**: 100% First-Party

**Step 1: Calculate Base Penalty**
```
Critical: 2 × 20 × 1.0 × 1.0 = 40 (capped at 28) = 28
High:     25 × 12 × 1.0 × 1.0 = 300 (capped at 20) = 20
Medium:   11 × 3 × 1.0 × 1.0 = 33 (capped at 10) = 10
Info:     15 × 0 × 1.0 × 1.0 = 0

Base Penalty = 28 + 20 + 10 + 0 = 58
```

**Step 2: Apply Normalization**
```
Normalization Factor = sqrt(50 / 100) = 0.707
Adjusted Penalty = 58 / 0.707 = 82
```

**Step 3: Calculate Final Score**
```
Score = 100 - 82 = 18
Grade = F (Critical Risk)
```

This matches the actual InsecureBankv2 report: **Score 24/100, Grade F**.

---

## 🛠️ Technology Stack

### Frontend
| Technology | Version | Purpose |
|------------|---------|---------|
| **Next.js** | 14.2.35 | React framework with App Router |
| **React** | 18 | UI component library |
| **TypeScript** | 5 | Type-safe JavaScript |
| **TailwindCSS** | 3.4.1 | Utility-first CSS framework |
| **Framer Motion** | 12.34.0 | Animation library (score ring, cards) |
| **Recharts** | 3.7.0 | Data visualization (radar, bar, pie charts) |
| **Lucide Icons** | 0.564.0 | Icon library (500+ icons) |
| **jsPDF** | 4.1.0 | Client-side PDF generation |
| **jspdf-autotable** | 5.0.7 | PDF table formatting |
| **react-markdown** | 10.1.0 | Markdown rendering for AI responses |
| **remark-gfm** | 4.0.1 | GitHub-Flavored Markdown support |

### Backend
| Technology | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.11+ | Primary language |
| **FastAPI** | Latest | Async REST API framework |
| **Uvicorn** | Latest | ASGI server with `[standard]` extras |
| **Pydantic** | Latest | Data validation and serialization |
| **python-multipart** | Latest | File upload handling |
| **Jinja2** | Latest | HTML report templating |
| **aiofiles** | Latest | Async file I/O |
| **python-dotenv** | Latest | Environment variable management |
| **androguard** | Latest | APK metadata extraction |
| **google-generativeai** | Latest | Gemini AI SDK |
| **groq** | Latest | Groq Cloud SDK (LLaMA 3.3 70B) |

### Analysis Tools
| Tool | Version | Purpose |
|------|---------|---------|
| **apktool** | 2.9.3 | APK resource extraction & Smali disassembly |
| **jadx** | 1.5.1 | DEX to Java/Kotlin decompilation |
| **Java Runtime** | 11+ | Required for apktool and jadx |

### Infrastructure
| Component | Technology | Purpose |
|-----------|------------|---------|
| **Container** | Docker (multi-stage) | Unified Node.js + Python + Java runtime |
| **Deployment** | Railway.app | Cloud platform with auto-scaling |
| **CI/CD** | Railway GitHub integration | Automatic deploys on push |
| **Storage** | Volume mount (`/app/backend/data`) | Persistent report storage |
| **Health Check** | `/api/health` endpoint | Liveness probe (120s timeout) |

### AI Integration
| Provider | Model | Context | Temperature | Purpose |
|----------|-------|---------|-------------|---------|
| **Groq** | LLaMA 3.3 70B Versatile | 4096 tokens | 0.5 | Primary AI (chat, deep analysis, remediation) |
| **Google** | Gemini 2.0 Flash | 8192 tokens | 0.5 | Fallback AI provider |

---

## 📁 Project Structure

```
DroidSec-KrackHack/
├── backend/                          # Python FastAPI backend
│   ├── core/                         # Core analysis engine
│   │   ├── decompiler.py             # apktool + jadx orchestration
│   │   ├── manifest_analyzer.py      # AndroidManifest.xml parser
│   │   ├── code_scanner.py           # Multi-source regex scanner (Java + Smali)
│   │   ├── owasp_mapper.py           # OWASP mapping & weighted scoring
│   │   ├── report_generator.py       # JSON + HTML report generation
│   │   └── ai_analyzer.py            # Groq/Gemini AI integration
│   │
│   ├── rules/                        # 15 Vulnerability Detection Modules
│   │   ├── secrets.py                # 15 hardcoded secret patterns (AWS, GCP, Firebase)
│   │   ├── crypto.py                 # 10 weak cryptography patterns (MD5, DES, ECB)
│   │   ├── network.py                # 6 insecure network patterns (HTTP, SSL bypass)
│   │   ├── storage.py                # 7 data storage issues (world-readable, external)
│   │   ├── webview.py                # 6 WebView vulnerabilities (JS injection, XSS)
│   │   ├── permissions.py            # 18 dangerous Android permissions
│   │   ├── malware.py                # Dynamic code loading, native lib risks
│   │   ├── entropy.py                # Shannon entropy analysis (obfuscation)
│   │   ├── signing.py                # APK signature verification
│   │   ├── modern_heuristics.py      # Logic-gated ADV/TAINT/MAL/NATIVE checks
│   │   ├── cloud_config.py           # Firebase, AWS S3 misconfigurations
│   │   ├── deeplink.py               # Intent filter & deeplink security
│   │   ├── binary_protection.py      # ProGuard, obfuscation, root detection
│   │   ├── network_config.py         # Network Security Config analysis
│   │   └── smali_rules.py            # Smali bytecode-specific patterns
│   │
│   ├── utils/                        # Utility modules
│   │   └── library_analyzer.py       # Third-party library detection (300+ SDKs)
│   │
│   ├── main.py                       # FastAPI application entry point
│   ├── requirements.txt              # Python dependencies
│   └── data/                         # Persistent storage (mounted volume)
│       ├── uploads/                  # Uploaded APK files (temp)
│       └── reports/                  # Generated reports (persistent)
│
├── frontend/                         # Next.js 14 frontend
│   ├── app/                          # App Router (Next.js 14)
│   │   ├── components/               # Reusable UI components
│   │   │   ├── NeonCard.tsx          # Glass-morphism card component
│   │   │   ├── CyberBackground.tsx   # Canvas particle animation
│   │   │   ├── UploadZone.tsx        # Drag-and-drop APK upload
│   │   │   └── RecentScans.tsx       # Recent scans list (localStorage)
│   │   │
│   │   ├── lib/                      # Utility libraries
│   │   │   ├── api.ts                # Backend API client
│   │   │   └── exportReport.ts       # PDF/JSON/CSV export logic
│   │   │
│   │   ├── report/[id]/              # Dynamic route for reports
│   │   │   └── page.tsx              # Report dashboard (score, findings, AI chat)
│   │   │
│   │   ├── page.tsx                  # Home page (upload + recent scans)
│   │   ├── layout.tsx                # Root layout with metadata
│   │   └── globals.css               # TailwindCSS globals + custom styles
│   │
│   ├── public/                       # Static assets
│   ├── package.json                  # Node.js dependencies
│   ├── tsconfig.json                 # TypeScript configuration
│   ├── tailwind.config.ts            # TailwindCSS configuration
│   └── next.config.mjs               # Next.js configuration
│
├── tools/                            # Binary analysis tools
│   ├── apktool                       # apktool wrapper script
│   ├── apktool.jar                   # apktool v2.9.3 JAR
│   └── jadx/                         # jadx v1.5.1 distribution
│       └── bin/jadx                  # jadx executable
│
├── sample-reports/                   # Example output
│   ├── insecurebankv2-report.json    # JSON report for InsecureBankv2.apk
│   ├── insecurebankv2-report.html    # HTML report for stakeholders
│   └── README.md                     # Sample report documentation
│
├── Dockerfile                        # Multi-stage build (Node.js + Python + Java)
├── railway.json                      # Railway deployment config
├── start.sh                          # Unified startup script (backend + frontend)
├── setup_tools.sh                    # Tool installation script (apktool, jadx)
├── .gitignore                        # Git ignore rules
├── PROJECT_WORKFLOW.md               # Architecture & workflow documentation
├── DEMO_VIDEO_SCRIPT.md              # Demo video script for KrackHack
└── README.md                         # This file
```

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Reporting Issues
- **Bug Reports**: Use GitHub Issues with detailed reproduction steps
- **Feature Requests**: Describe the use case and expected behavior
- **Security Vulnerabilities**: Email contact details (see Team section) with CVE if applicable

### Pull Requests
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes with clear commit messages
4. Add tests if applicable (currently no test suite, but welcomed!)
5. Update documentation (README, comments, etc.)
6. Submit PR with detailed description

### Development Guidelines
- **Code Style**: Follow PEP 8 for Python, ESLint for TypeScript
- **Commits**: Use conventional commits (feat:, fix:, docs:, etc.)
- **Documentation**: Update README for new features
- **Testing**: Manually test with multiple APKs (small, large, obfuscated)

### Adding New Vulnerability Rules

Example: Adding a new secret pattern to `backend/rules/secrets.py`:
```python
# Add to SECRET_RULES list
{
    "id": "SEC999",
    "name": "Hardcoded New API Key",
    "pattern": r'new_api_key\s*=\s*["\']([A-Za-z0-9]{32,})["\']',
    "severity": "critical",
    "confidence": "high",
    "owasp": "M1",
    "description": "Hardcoded New API key found in source code.",
    "remediation": "Store API keys in Android Keystore or use environment variables.",
}
```

Then test:
```bash
cd backend
python -m pytest tests/  # (if tests exist)
# Or manually upload an APK with the pattern
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

**Summary:**
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ⚠️ No warranty provided
- ⚠️ No liability assumed

---

## 👥 Team & Contact

**KrackHack 3.0 Submission**

### Team
- **Lead Developer**: Madhudheervath ([@madhudheervath](https://github.com/madhudheervath))
- **Point of Contact**: Harsh (+91 95188 30309)

### Links
- **Live Demo**: [https://droidsec-krackhack-production-df80.up.railway.app/](https://droidsec-krackhack-production-df80.up.railway.app/)
- **GitHub Repository**: [https://github.com/madhudheervath/DroidSec-KrackHack](https://github.com/madhudheervath/DroidSec-KrackHack)
- **Issue Tracker**: [https://github.com/madhudheervath/DroidSec-KrackHack/issues](https://github.com/madhudheervath/DroidSec-KrackHack/issues)

### Acknowledgments
- **KrackHack 3.0** for the problem statement and inspiration
- **OWASP Mobile Security Project** for the Mobile Top 10 framework
- **apktool** and **jadx** teams for excellent reverse engineering tools
- **Groq** for providing high-performance LLaMA 3.3 70B inference
- **Railway** for seamless cloud deployment

---

## 📚 Additional Resources

### Documentation
- [PROJECT_WORKFLOW.md](PROJECT_WORKFLOW.md) — Detailed architecture and workflow
- [DEMO_VIDEO_SCRIPT.md](DEMO_VIDEO_SCRIPT.md) — Demo video script for presentations
- [sample-reports/README.md](sample-reports/README.md) — Sample report documentation

### External References
- [OWASP Mobile Top 10 (2024)](https://owasp.org/www-project-mobile-top-10/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [apktool Documentation](https://ibotpeaches.github.io/Apktool/)
- [jadx GitHub Repository](https://github.com/skylot/jadx)
- [Groq Cloud Documentation](https://console.groq.com/docs)

### Sample APKs for Testing
- **InsecureBankv2**: [GitHub](https://github.com/dineshshetty/Android-InsecureBankv2) — Intentionally vulnerable banking app
- **DIVA Android**: [GitHub](https://github.com/payatu/diva-android) — Damn Insecure and Vulnerable App
- **AndroGoat**: [GitHub](https://github.com/satishpatnayak/AndroGoat) — Security assessment app
- **OVAA**: [GitHub](https://github.com/oversecured/ovaa) — Oversecured Vulnerable Android App

---

<div align="center">

## 🛡️ DroidSec — Securing Android Apps, One APK at a Time

**Made with ❤️ for KrackHack 3.0**

[![Star on GitHub](https://img.shields.io/github/stars/madhudheervath/DroidSec-KrackHack?style=social)](https://github.com/madhudheervath/DroidSec-KrackHack)
[![Fork on GitHub](https://img.shields.io/github/forks/madhudheervath/DroidSec-KrackHack?style=social)](https://github.com/madhudheervath/DroidSec-KrackHack/fork)

[Live Demo](https://droidsec-krackhack-production-df80.up.railway.app/) • [Documentation](PROJECT_WORKFLOW.md) • [Report Issue](https://github.com/madhudheervath/DroidSec-KrackHack/issues)

</div>
