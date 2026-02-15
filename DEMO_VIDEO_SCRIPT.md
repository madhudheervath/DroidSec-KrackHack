# 🎬 DroidSec — Demo Video Script

> **KrackHack 3.0 | Problem Statement 01: Mobile App Security Analyzer**
> Duration Target: 8–10 minutes

---

## 🎙️ SCENE 1: Introduction (0:00 – 0:45)

### What to show
- Open browser → `droidsec-krackhack-production-df80.up.railway.app`
- Show the **DROIDSEC** landing page with animated particle background

### Script
> "Hi, this is DroidSec — an advanced Android APK security analysis platform we built for KrackHack 3.0.
>
> DroidSec takes any Android APK, decompiles it, scans the source code for over 50 types of security vulnerabilities, maps every finding to the OWASP Mobile Top 10, and generates a professional security report — all through a modern web interface.
>
> It also includes a real-time AI security assistant powered by Groq's LLaMA 3.3 70B model that can explain vulnerabilities, suggest code fixes, and perform deep threat analysis.
>
> Let me walk you through how it works."

---

## 🎙️ SCENE 2: Upload & Scan (0:45 – 2:30)

### What to show
1. Drag and drop an APK (e.g. `InsecureBankv2.apk`) onto the upload zone
2. Show the **progress bar** with real-time status messages:
   - "Scan queued. Waiting for decompiler…"
   - "Decompiling and scanning…"
3. Show **Recent Intelligence** section at bottom (prior scans with grades)
4. Wait for scan to complete → automatic redirect to report page

### Script
> "We have a drag-and-drop upload zone. I'll upload an intentionally vulnerable APK — InsecureBankv2.
>
> Once uploaded, the backend saves the file, queues a scan, and begins decompilation using **apktool** and **jadx**. The frontend polls the status endpoint every 2.5 seconds so you can see live progress.
>
> At the bottom, you can see our **Recent Intelligence** section which caches previous scans in localStorage, showing their security grade, score, and timestamp — so you never lose track of past analyses.
>
> The scan typically completes in 30–60 seconds depending on APK size."

### Technical Detail to Mention
> "Under the hood: The APK goes through a **multi-stage pipeline** —
> 1. **Decompilation** — apktool extracts resources + smali, jadx decompiles to Java/Kotlin source
> 2. **Manifest Analysis** — parses `AndroidManifest.xml` for exported components, permissions, debuggable flags
> 3. **Code Scanning** — 50+ regex patterns across 15 rule modules scan both Java AND smali sources
> 4. **OWASP Mapping** — every finding is mapped to OWASP Mobile Top 10 (M1–M10)
> 5. **Scoring** — weighted algorithm: Critical ×10, High ×7, Medium ×4, Info ×1, capped at 0–100
> 6. **Report Generation** — JSON + HTML reports saved to disk for persistence
>
> The backend uses a **ThreadPoolExecutor** so scans run in background threads without blocking the async FastAPI event loop. File uploads are streamed in 1MB chunks with a 200MB size limit."

---

## 🎙️ SCENE 3: Security Dashboard & Score (2:30 – 3:45)

### What to show
1. **Score Ring** — animated circular gauge showing grade (F) and score (6/100)
2. **Risk Level** badge — "Critical Risk"
3. **Severity Donut Chart** — Critical/High/Medium/Info breakdown (PieChart)
4. **Metrics Row** — Total Findings, Critical count, High count, Medium count, Files Scanned, Code Coverage (Java/Smali)
5. **Quantitative Analysis** panel — Java/Kotlin files, Smali files, Config/XML, DEX count, Permissions, Components, Libraries

### Script
> "Here's the report dashboard for InsecureBankv2. It scored **6 out of 100** — Grade F, Critical Risk.
>
> The **Score Ring** animates in using Framer Motion. To its right you can see the severity breakdown donut chart — mostly critical and high findings.
>
> Below, the **metrics row** gives a quick snapshot: total findings, critical count, files scanned, and code coverage across both Java and Smali sources.
>
> The **Quantitative Analysis** panel shows exactly how many Java/Kotlin files, Smali files, config files, DEX files, permissions, components, and libraries were analyzed — giving full transparency into scan coverage."

### Technical Detail to Mention
> "The scoring algorithm uses weighted severity multipliers — Critical findings deduct 10 points each, High deducts 7, Medium 4, and Info 1 — all multiplied by confidence score. The final score is capped between 0 and 100. We also have **strict score caps** to prevent false 'clean' scores on partial analyses."

---

## 🎙️ SCENE 4: Findings Explorer (3:45 – 5:15)

### What to show
1. **Severity filter buttons** — click through Critical, High, Medium, Info
2. **Search bar** — type a keyword like "hardcoded" or "SSL" to filter findings
3. **Expand a finding card** — show:
   - Severity pill + OWASP badge (e.g. "OWASP M1") + confidence percentage
   - **Description** text
   - **Evidence** code block with file location and source type (DECOMPILED/SMALI)
   - **Remediation** guidance (green box)
4. Click **"Fix with AI"** button on a finding → show AI-generated detailed remediation with markdown (code blocks, bullet points)

### Script
> "The Findings tab lists every detected vulnerability. You can **filter by severity** — Critical, High, Medium, Info — or use the **search bar** to find specific issues by name, description, location, or even code evidence.
>
> Let me expand this finding — 'Hardcoded AWS Access Key'. You can see:
> - The **severity pill** and OWASP category (M1 — Improper Credential Usage)
> - The **confidence score** — 95% confidence
> - The actual **evidence** — the code snippet where we found the hardcoded key, with file path and whether it was from decompiled Java or Smali
> - Built-in **remediation** guidance
>
> Now watch this — we have a **'Fix with AI' button** on every finding. When I click it, it sends this finding to our Groq-powered LLaMA 3.3 70B backend, which generates a **detailed, contextual remediation** — including vulnerable vs. fixed code comparisons, formatted in rich markdown."

### Technical Detail to Mention
> "Each finding has: a unique ID, severity level, OWASP mapping, confidence score (high/medium/low mapped to 0.9/0.7/0.5), evidence snippet (up to 500 chars), file location, and remediation text. The AI remediation endpoint (`POST /api/ai/remediate`) takes the finding index and scan ID, feeds the full finding context to LLaMA 3.3 70B, and returns a detailed fix guide. The response is rendered using **react-markdown** with **remark-gfm** for GitHub-Flavored Markdown — supporting code blocks with syntax highlighting labels, tables, bold/italic, lists, and blockquotes."

---

## 🎙️ SCENE 5: OWASP Mobile Top 10 Tab (5:15 – 6:00)

### What to show
1. Click the **OWASP Top 10** tab
2. Show the **Radar Chart** (M1–M10 finding distribution)
3. Show the **Bar Chart** (horizontal distribution, color-coded by max severity)
4. Show the **OWASP Category Cards** — 10 cards with icons, finding counts, and max severity pills

### Script
> "Switching to the **OWASP Top 10** tab, every finding is automatically mapped to OWASP Mobile categories M1 through M10.
>
> The **radar chart** shows the distribution at a glance — you can immediately see which categories have the most findings.
>
> The **bar chart** uses color coding — red for Critical, orange for High, yellow for Medium — so you can prioritize by impact.
>
> Below are **10 category cards** — each showing the category name, icon, finding count, and the highest severity found in that category."

### Technical Detail to Mention
> "OWASP mapping is done by our `owasp_mapper.py` module which uses a rule-to-category mapping table. Each of our 15 rule modules (secrets, crypto, network, storage, webview, permissions, signing, deeplinks, malware, entropy, cloud configs, binary protections, modern heuristics, etc.) tags findings with the appropriate OWASP category. The charts use **Recharts** — RadarChart, BarChart, and PieChart — all with dark-themed custom Tooltips."

---

## 🎙️ SCENE 6: AI Security Chat (6:00 – 7:30)

### What to show
1. Click the **floating AI chat button** (bottom-right, purple with green ping indicator)
2. Show the **AI chat drawer** sliding in from the right
3. Show the **AI Analysis Summary** card at the top
4. Type a question: *"What are the top 3 most critical vulnerabilities?"*
5. Show the AI response in **rich markdown** — headings, bold, code blocks, bullet lists
6. Ask a follow-up: *"How would I fix the hardcoded credentials issue? Show me code."*
7. Show the AI response with **vulnerable → fixed code comparison**
8. Click **Clear** to reset chat

### Script
> "Now for the AI-powered security assistant. This floating chat button opens a full conversational interface.
>
> I'll ask: 'What are the top 3 most critical vulnerabilities?' — and watch the AI respond with a structured, detailed analysis, including severity levels, OWASP mappings, and exploitation scenarios.
>
> Now I'll ask for a code fix — 'How would I fix the hardcoded credentials issue? Show me code.' The AI provides the vulnerable code block, then a fixed version with environment variable usage — all beautifully formatted in markdown.
>
> The chat history **persists across page navigations** — it's stored in sessionStorage so you won't lose your conversation."

### Technical Detail to Mention
> "The AI chat uses **Groq's LLaMA 3.3 70B Versatile** model with a max token limit of **4096 tokens** and temperature 0.5 for balanced creativity. The system prompt is dynamically built with full scan context — package name, score, risk level, all findings with evidence. Conversation history is maintained server-side (up to 30 messages, trimmed to 24 + system prompt) and client-side in **sessionStorage** keyed by scan ID.
>
> Responses are rendered using **ReactMarkdown** with **remark-gfm** — supporting code blocks with language labels, tables, bold/italic, list items, blockquotes, and inline code. We use a shared `mdComponents` config across both the chat and the 'Fix with AI' feature for consistent rendering."

---

## 🎙️ SCENE 7: Export & Reports (7:30 – 8:15)

### What to show
1. Click the **Export** dropdown button in the nav bar
2. Show all four options: **PDF Report**, **JSON Data**, **CSV Findings**, **HTML Report**
3. Click **PDF Report** → show the **toast notification** "PDF report downloaded"
4. Open the downloaded PDF — show:
   - Purple header band with title, package, date
   - Executive summary section
   - Severity breakdown table (striped rows)
   - Findings with color-coded severity badges
   - Evidence boxes and remediation sections
5. Click **JSON Data** → show the toast
6. Click **HTML Report** → show the standalone HTML report

### Script
> "For sharing results, we have a **professional export system**. The dropdown shows four formats:
>
> **PDF** — generates a multi-page report with a purple header band, executive summary, striped severity tables, color-coded badges, evidence blocks, and remediation sections. Clean white background, fully readable.
>
> **JSON** — full machine-readable scan data for integration with other tools.
>
> **CSV** — spreadsheet-compatible findings export for compliance workflows.
>
> **HTML** — standalone web report generated server-side.
>
> Notice the **toast notification** that confirms each download — a polished UX detail."

### Technical Detail to Mention
> "PDF generation uses **jsPDF** with **jspdf-autotable** — entirely client-side, no server round-trip. The PDF is built programmatically: purple header band, Auto-table for the severity matrix, then each finding with `splitTextToSize` for word wrapping, tinted severity badge rectangles, evidence boxes with gray backgrounds, and green remediation sections. Page breaks are handled automatically."

---

## 🎙️ SCENE 8: Architecture & Technical Deep Dive (8:15 – 9:30)

### What to show
- Switch to code editor or architecture diagram
- Optionally show the GitHub repo

### Script
> "Let me quickly walk through the technical architecture:
>
> **Frontend:** Next.js 14 with App Router, TailwindCSS, Framer Motion for animations, Recharts for data visualization, and Lucide for icons. The UI uses a dark-mode design system with glass-morphism cards and a custom particle animation background built on HTML5 Canvas with `requestAnimationFrame`.
>
> **Backend:** Python FastAPI with async endpoints. The scan pipeline runs in a `ThreadPoolExecutor` to avoid blocking the event loop. Reports are persisted to disk in `backend/data/reports/` so they survive server restarts.
>
> **Analysis Engine:** 15 specialized rule modules:
> - `secrets.py` — 15 hardcoded secret patterns (AWS, GCP, Firebase, GitHub, Slack tokens)
> - `crypto.py` — weak cryptography (MD5, SHA-1, DES, ECB mode, insecure random)
> - `network.py` — insecure communication (cleartext HTTP, trust-all-certs, hostname bypass)
> - `storage.py` — insecure data storage (world-readable files, unencrypted SQLite, external storage)
> - `webview.py` — WebView vulnerabilities (JavaScript injection, file access, XSS)
> - `permissions.py` — 18 dangerous Android permissions analysis
> - `malware.py` — malware heuristics (dynamic code loading, native libs, obfuscation)
> - `entropy.py` — Shannon entropy analysis for detecting encrypted/obfuscated content
> - `signing.py` — APK signature verification
> - `modern_heuristics.py` — advanced logic-gated checks: biometric misuse, taint-style source→sink, JNI/native risks, receiver/provider exposure
> - And more: `cloud_config.py`, `deeplink.py`, `binary_protection.py`, `network_config.py`, `smali_rules.py`
>
> **AI Integration:** Groq LLaMA 3.3 70B with three AI endpoints:
> - `/api/ai/analyze/{scan_id}` — deep analysis with threat modeling, vulnerability chains, prioritized fixes
> - `/api/ai/chat` — interactive conversational Q&A with full scan context and conversation history
> - `/api/ai/remediate` — per-finding detailed fix generation with code examples
>
> **Deployment:** Dockerized multi-stage build (Node.js frontend builder + Python/Java runtime), deployed on Railway with health checks."

---

## 🎙️ SCENE 9: Recent Scans & Persistence (9:30 – 9:50)

### What to show
1. Go back to the home page
2. Show **Recent Intelligence** with multiple scans cached (different grades — A, C, F)
3. Click on a previous scan → instant load from persisted storage

### Script
> "Back on the home page, the **Recent Intelligence** section shows all past scans cached in localStorage. Each entry shows the package name, security grade, score, timestamp, and filename.
>
> Click any scan → it loads instantly from our persistent backend storage. Reports are saved to disk, not just memory, so they survive server restarts and redeployments."

---

## 🎙️ SCENE 10: Conclusion (9:50 – 10:00)

### Script
> "That's DroidSec — a complete Android APK security analysis platform with:
> - **50+ vulnerability checks** across 15 rule modules
> - **OWASP Mobile Top 10** mapping with radar and bar charts
> - **Weighted security scoring** (0–100 with A–F grading)
> - **AI-powered analysis** — deep threat modeling, interactive chat, and per-finding code fixes powered by Groq LLaMA 3.3 70B
> - **Professional exports** — PDF, JSON, CSV, and HTML
> - **Persistent storage** and a polished, production-ready dark-mode UI
>
> Built for KrackHack 3.0. Thanks for watching."

---

## 📋 Key Features Checklist (Ensure All Are Shown)

| # | Feature | Scene | Shown |
|---|---------|-------|-------|
| 1 | Drag-and-drop APK upload | Scene 2 | ☐ |
| 2 | Real-time scan progress with status polling | Scene 2 | ☐ |
| 3 | Multi-stage decompilation (apktool + jadx) | Scene 2 | ☐ |
| 4 | 50+ vulnerability detection rules (15 modules) | Scene 4 | ☐ |
| 5 | Dual-source scanning (Java + Smali) | Scene 2 | ☐ |
| 6 | Security score (0–100) with A–F grading | Scene 3 | ☐ |
| 7 | Animated score ring & severity donut chart | Scene 3 | ☐ |
| 8 | Quantitative analysis metrics panel | Scene 3 | ☐ |
| 9 | Severity filter buttons (Critical/High/Medium/Info) | Scene 4 | ☐ |
| 10 | Findings search bar | Scene 4 | ☐ |
| 11 | Evidence code blocks with file locations | Scene 4 | ☐ |
| 12 | Built-in remediation guidance | Scene 4 | ☐ |
| 13 | "Fix with AI" button per finding | Scene 4 | ☐ |
| 14 | AI-generated remediation with markdown | Scene 4 | ☐ |
| 15 | OWASP Mobile Top 10 radar chart | Scene 5 | ☐ |
| 16 | OWASP category bar chart & cards | Scene 5 | ☐ |
| 17 | Floating AI chat button with animations | Scene 6 | ☐ |
| 18 | Full conversational AI chat (Groq LLaMA 3.3 70B) | Scene 6 | ☐ |
| 19 | Rich markdown rendering in chat (code blocks, tables, lists) | Scene 6 | ☐ |
| 20 | Chat history persistence (sessionStorage) | Scene 6 | ☐ |
| 21 | Export dropdown (PDF, JSON, CSV, HTML) | Scene 7 | ☐ |
| 22 | Professional white-background PDF with styled tables | Scene 7 | ☐ |
| 23 | Toast notifications on export | Scene 7 | ☐ |
| 24 | Recent scans dashboard (localStorage cache) | Scene 9 | ☐ |
| 25 | Persistent report storage (survives restarts) | Scene 9 | ☐ |
| 26 | Particle animation background (Canvas + RAF) | Scene 1 | ☐ |
| 27 | Dark-mode glass-morphism UI design | Scene 1 | ☐ |
| 28 | Railway deployment with Docker multi-stage build | Scene 8 | ☐ |
| 29 | Backend hardening (200MB limit, scans eviction) | Scene 8 | ☐ |
| 30 | AI deep analysis (threat model, vulnerability chains) | Scene 6 | ☐ |

---

## 🛠️ Tech Stack Summary (For Mentioning)

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14 (App Router), React 18, TailwindCSS, Framer Motion, Recharts, Lucide Icons, jsPDF, react-markdown, remark-gfm |
| Backend | Python 3.11, FastAPI, Uvicorn, Pydantic |
| AI | Groq Cloud — LLaMA 3.3 70B Versatile (4096 tokens, temp 0.5) |
| Analysis | apktool v2.9.3, jadx v1.5.1, 50+ custom regex patterns, 15 rule modules |
| Deployment | Docker (multi-stage), Railway, Health checks |
| Storage | Disk persistence (`backend/data/`), localStorage, sessionStorage |

---

## 🎯 Tips for Recording

1. **Use the deployed Railway URL** for smoother demo (no localhost issues)
2. **Pre-upload a few APKs** so Recent Intelligence has data
3. **Have InsecureBankv2.apk ready** — it has many findings (great for demo)
4. **Zoom into the browser** (Ctrl + +) for readability in the video
5. **Use a clean browser tab** — no clutter in bookmarks bar
6. **Record at 1080p** minimum
7. **Pause briefly** after each action so viewers can see transitions
8. **Have the AI chat pre-warmed** — send one message before recording so the first response is faster
