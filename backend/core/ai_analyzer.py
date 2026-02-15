"""
AI-Powered Security Analyzer — Multi-Provider Support (Google Gemini & Groq).
Provides deep analysis, threat modeling, smart remediation, and interactive security Q&A.
"""
import os
import json
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Providers status
GROQ_AVAILABLE = False

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    pass


SYSTEM_PROMPT = """You are DroidSec AI — an expert Android security analyst. You analyze decompiled Android APK source code and security scan findings to provide deep, actionable security insights.

Your capabilities:
1. **Deep Vulnerability Analysis** — Go beyond regex pattern matching to identify business logic flaws, authentication issues, and complex vulnerability chains
2. **Threat Modeling** — Identify attack vectors, threat actors, and exploitation scenarios
3. **Smart Remediation** — Provide specific, copy-paste-ready code fixes for each vulnerability
4. **Risk Prioritization** — Help developers focus on the most critical issues first
5. **OWASP Expertise** — Deep knowledge of OWASP Mobile Top 10 (2024)

Guidelines:
- Be specific and actionable — never vague
- Reference exact file names and line numbers when available
- Provide actual code snippets for remediation
- Rate findings by real-world exploitability, not just theoretical risk
- Consider the Android version context (min/target SDK)
- Flag vulnerability chains (e.g., exported component + hardcoded creds = account takeover)
- Use markdown formatting for clarity"""


class AIAnalyzer:
    """Multi-provider AI security analysis (Gemini or Groq)."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "") or os.environ.get("GROQ_API_KEY", "")
        self.provider = None
        self.client = None
        self.model_name = None
        self.chat_history: Dict[str, List[Dict]] = {} # History for Groq/OpenAI compatible

        if not self.api_key:
            return

        # Auto-detect provider
        if self.api_key.startswith("gsk_"):
            self._init_groq()
        else:
            self._init_gemini()

    def _init_gemini(self):
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self.client = genai.GenerativeModel(
                model_name="gemini-2.0-flash",
                system_instruction=SYSTEM_PROMPT,
                generation_config=genai.GenerationConfig(
                    temperature=0.3,
                    max_output_tokens=4096,
                ),
            )
            self.provider = "gemini"
            logger.info("Gemini AI initialized")
        except ImportError:
            logger.warning("Gemini SDK not installed")
        except Exception as e:
            logger.error(f"Failed to init Gemini: {e}")

    def _init_groq(self):
        if not GROQ_AVAILABLE:
            logger.warning("Groq SDK not installed. Please run 'pip install groq'")
            return
        
        try:
            self.client = Groq(api_key=self.api_key)
            self.model_name = "llama-3.3-70b-versatile"
            self.provider = "groq"
            logger.info(f"Groq AI initialized with {self.model_name}")
        except Exception as e:
            logger.error(f"Failed to init Groq: {e}")

    @property
    def is_available(self) -> bool:
        return self.provider is not None

    def _build_scan_context(self, report_data: Dict, code_snippets: List[str] = None) -> str:
        """Build a context string from scan results."""
        ctx_parts = []
        meta = report_data.get("metadata", {})
        # Fields can be at top-level or inside metadata
        pkg = report_data.get('package') or meta.get('package', 'unknown')
        apk_name = report_data.get('apk_filename') or meta.get('apk_filename', '')
        min_sdk = report_data.get('min_sdk') or meta.get('min_sdk', 'N/A')
        target_sdk = report_data.get('target_sdk') or meta.get('target_sdk', 'N/A')
        perms = report_data.get('permissions') or meta.get('permissions', [])
        exports = report_data.get('exported_components') or meta.get('exported_components', [])

        ctx_parts.append(f"""## App Info\n- Package: {pkg}\n- APK: {apk_name}\n- Min SDK: {min_sdk} | Target SDK: {target_sdk}\n- Permissions: {len(perms)}\n- Exported Components: {len(exports)}""")

        score = report_data.get("security_score", {})
        ctx_parts.append(f"""## Security Score
- **Score:** {score.get('score', 'N/A')}/100 (Grade {score.get('grade', '?')})
- **Risk Level:** {score.get('risk_level', 'Unknown')}""")

        findings = report_data.get("findings", [])
        if findings:
            finding_strs = []
            for i, f in enumerate(findings[:25]):
                finding_strs.append(f"### Finding {i+1}: {f.get('name', 'Unknown')}\n"
                                f"- Severity: {f.get('severity', '?')} | OWASP: {f.get('owasp', '?')}\n"
                                f"- Location: {f.get('location', 'Unknown')}\n"
                                f"- Description: {f.get('description', '')}\n"
                                f"- Evidence: `{f.get('evidence', 'N/A')[:500]}`\n"
                                f"- Remediation: {f.get('remediation', 'N/A')}")
            ctx_parts.append("## Security Findings\n" + "\n\n".join(finding_strs))

        if meta.get("libraries") or report_data.get("libraries"):
            libs = meta.get('libraries') or report_data.get('libraries', [])
            ctx_parts.append(f"## Libraries\n{', '.join(libs)}")

        return "\n\n".join(ctx_parts)

    async def _generate(self, prompt: str, system_msg: str = SYSTEM_PROMPT) -> str:
        """Unified internal generation method."""
        if self.provider == "gemini":
            response = self.client.generate_content(prompt)
            return response.text
        elif self.provider == "groq":
            chat_completion = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": prompt}
                ],
                model=self.model_name,
                temperature=0.3,
            )
            return chat_completion.choices[0].message.content
        return ""

    async def deep_analysis(self, report_data: Dict, code_snippets: List[str] = None) -> Dict[str, Any]:
        """AI-powered deep analysis of scan results."""
        if not self.is_available:
            return {"error": "AI not available. Set GEMINI_API_KEY or GROQ_API_KEY.", "available": False}

        context = self._build_scan_context(report_data, code_snippets)
        prompt = f"""Analyze this Android APK security scan report and provide a comprehensive security assessment. Respond with a JSON object.

{context}

Respond strictly with this JSON structure:
{{
  "executive_summary": "...",
  "threat_model": {{ "attack_vectors": [], "threat_actors": [], "impact_assessment": "" }},
  "critical_chains": [ {{ "name": "", "chain": "", "risk": "", "exploit_difficulty": "" }} ],
  "ai_findings": [ {{ "name": "", "severity": "", "description": "", "evidence": "", "remediation": "" }} ],
  "prioritized_fixes": [ {{ "priority": 1, "finding": "", "reason": "", "effort": "", "code_fix": "" }} ],
  "security_recommendations": [],
  "compliance_notes": ""
}}"""

        try:
            text = await self._generate(prompt)
            text = text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                if text.endswith("```"): text = text[:-3]
                elif "```" in text: text = text[:text.rfind("```")]

            result = json.loads(text.strip())
            result["available"] = True
            result["provider"] = self.provider
            return result
        except Exception as e:
            logger.error(f"Deep analysis failed: {e}")
            return {"error": str(e), "available": True}

    async def chat(self, scan_id: str, message: str, report_data: Dict) -> str:
        """Interactive AI chat with real conversational context."""
        if not self.is_available:
            return "AI chat not available."

        ctx = self._build_scan_context(report_data)
        pkg = report_data.get('package') or report_data.get('metadata',{}).get('package','unknown')
        score_info = report_data.get('security_score', {})
        total_findings = report_data.get('total_findings', len(report_data.get('findings', [])))

        chat_system = f"""You are DroidSec AI — an elite Android security analyst chatbot, similar in depth and quality to ChatGPT. You have full scan results loaded for the app below.

## YOUR IDENTITY
- Expert-level Android security analyst
- You give thorough, insightful, technically accurate answers
- You format responses beautifully with markdown

## APP CONTEXT
- Package: {pkg}
- Score: {score_info.get('score', 'N/A')}/100 (Grade {score_info.get('grade', '?')})
- Risk: {score_info.get('risk_level', 'Unknown')}
- Total Findings: {total_findings}

## RESPONSE GUIDELINES
1. **Adapt response length to the question complexity:**
   - Simple factual questions (app name, score, etc.) → 1-2 sentences
   - "Explain", "analyze", "how to fix" → detailed paragraphs with structure
   - Code fix requests → provide complete, working code blocks with explanation
   - "Summarize" or "overview" → structured summary with bullet points

2. **Always use rich markdown formatting:**
   - Use **bold** for key terms, severity labels
   - Use `inline code` for package names, class names, methods
   - Use ```language code blocks for code examples (java, kotlin, xml, etc.)
   - Use bullet points and numbered lists for clarity
   - Use > blockquotes for important warnings
   - Use ### headings to structure long answers

3. **When asked for code improvements or fixes:**
   - Show the VULNERABLE code first (labeled)
   - Then show the FIXED code (labeled)
   - Explain what changed and why
   - Use proper language tags on code blocks

4. **Be technically precise:**
   - Reference specific findings, file paths, evidence from the scan data
   - Mention OWASP categories where relevant
   - Consider Android SDK version context
   - Identify vulnerability chains

5. **For yes/no questions:** Answer directly first, then explain.

6. **Never refuse to help.** If data is insufficient, say what's available and offer related insights.

--- SCAN DATA ---
{ctx}
--- END ---"""

        if self.provider == "gemini":
            if not hasattr(self, "_gemini_chats"): self._gemini_chats = {}
            if scan_id not in self._gemini_chats:
                self._gemini_chats[scan_id] = self.client.start_chat(history=[])
            res = self._gemini_chats[scan_id].send_message(message)
            return res.text
        
        elif self.provider == "groq":
            if scan_id not in self.chat_history:
                self.chat_history[scan_id] = [
                    {"role": "system", "content": chat_system},
                ]
            
            self.chat_history[scan_id].append({"role": "user", "content": message})
            
            # Keep conversation manageable — trim old messages if too long
            messages = self.chat_history[scan_id]
            if len(messages) > 30:
                # Keep system + last 24 messages
                messages = [messages[0]] + messages[-24:]
                self.chat_history[scan_id] = messages
            
            completion = self.client.chat.completions.create(
                messages=messages,
                model=self.model_name,
                temperature=0.5,
                max_tokens=4096,
            )
            reply = completion.choices[0].message.content
            self.chat_history[scan_id].append({"role": "assistant", "content": reply})
            return reply

    async def generate_remediation(self, finding: Dict) -> str:
        """Generate detailed fix guide."""
        if not self.is_available: return finding.get("remediation", "AI not available.")
        
        prompt = f"Provide a detailed remediation guide for finding: {finding.get('name')}. Evidence: {finding.get('evidence')}. Description: {finding.get('description')}. Include a secure code example."
        return await self._generate(prompt)


# Singleton
_ai_analyzer: Optional[AIAnalyzer] = None

def get_ai_analyzer() -> AIAnalyzer:
    global _ai_analyzer
    if _ai_analyzer is None: _ai_analyzer = AIAnalyzer()
    return _ai_analyzer

def set_api_key(api_key: str):
    global _ai_analyzer
    _ai_analyzer = AIAnalyzer(api_key=api_key)
