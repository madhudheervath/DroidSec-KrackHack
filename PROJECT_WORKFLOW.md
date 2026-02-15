# DROIDSEC: Project Architecture & Workflow

**DroidSec** is a high-performance, automated Android security analysis platform that combines static analysis engine scripts with AI-driven remediation to detect vulnerabilities in APK files.

---

## 🚀 System Architecture

The platform operates as a **Unified Full-Stack Application** containerized for cloud deployment.

1.  **Frontend:** Next.js 14 (App Router) with TailwindCSS and Framer Motion for a premium, cybersecurity-themed dashboard.
2.  **Backend:** FastAPI (Python 3.10+) serving as the orchestration layer for the analysis engine.
3.  **Static Analysis Core:** Integrates `apktool` for resource extraction and `jadx` for source code decompilation.
4.  **AI Engine:** Google Gemini 1.5 Pro integration for intelligent risk assessment and code remediation.

---

## 🛠 Functional Workflow

### 1. Reception & Initialization
*   **Upload:** User uploads an APK through the dashboard.
*   **Validation:** The backend validates the file type and generates a unique `Scan ID`.
*   **Storage:** The APK is stored in a temporary `uploads/` volume for processing.

### 2. Decompilation & Extraction
*   **Resource Extraction:** `apktool` decomposes the APK to retrieve the `AndroidManifest.xml` and original resources.
*   **Source Reconstruction:** `jadx` decompiles the DEX bytecode into readable Java/Kotlin source code and Smali intermediate code.
*   **Workspace Setup:** A structured directory is created in `reports/[Scan_ID]/` to hold extracted artifacts.

### 3. Multi-Layered Static Analysis
The engine runs concurrent scanners across different layers:
*   **Manifest Analysis:** Checks for `android:debuggable`, exported components (Activity/Service/Provider), risky permissions, and backup configurations.
*   **Sensitive Data Discovery:** Regular expression-based scanning for API keys (Firebase, AWS, Google), hardcoded credentials, and secrets.
*   **Cryptographic Audit:** Detection of weak algorithms (MD5, SHA1) and insecure initialization vectors (IVs).
*   **Network Security:** Scanning for `cleartextTrafficPermitted`, insecure SSL/TLS configurations, and certificate pinning issues.
*   **Code Quality:** Detecting Webview JS injection risks, insecure storage patterns (World Readable/Writable), and logging of sensitive data.

### 4. OWASP Mapping & Grading
*   **Standardization:** All detected findings are mapped to the **OWASP Mobile Top 10 (2024)** standards.
*   **Scoring Engine:** A proprietary algorithm calculates a **Security Score (0-100)** based on vulnerability density and severity.
*   **Grading:** An automated grade (A+, A, B, C, D, F) is assigned to the APK based on the final score.

### 5. AI Deep Analysis (Optional)
*   **Contextualization:** The analysis engine sends the top findings to **Gemini 1.5 Pro**.
*   **Remediation:** The AI generates a human-readable summary of the business risk and provides a specific code snippet to fix each vulnerability.

### 6. Report Visualization
*   **JSON Artifact:** A master `report.json` is saved for persistence.
*   **Dashboard Rendering:** The frontend fetches the report data and renders interactive charts (Recharts) and detailed vulnerability cards for the security researcher.

---

## 🛡 Security Scanning Categories
| Category | Description |
| :--- | :--- |
| **Manifest** | Exported Components, Debug Mode, Backup Risks |
| **Secrets** | Firebase Keys, AWS Secrets, Google API Keys |
| **Network** | Cleartext Traffic, Insecure TLS, WebView Vulnerabilities |
| **Storage** | Insecure DB Permissions, External Storage Leaks |
| **Crypto** | Weak Algorithms, Hardcoded Seeds, Improper IVs |
| **AI Insights** | LLM-generated Remediation and Business Risk Summary |

---

## 📦 Deployment Workflow (Railway)
*   **Dockerization:** A multi-stage Docker build encapsulates the Node.js frontend and Python backend.
*   **Automated Setup:** `setup_tools.sh` downloads the latest official binaries for `apktool` and `jadx` during build-time.
*   **Reverse Proxy:** Next.js handles public requests and proxies `/api/*` traffic to the internal FastAPI service on a local port.
*   **Volume Persistence:** Reports are saved to a mounted volume to ensure data survives container restarts.
