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
GEMINI_AVAILABLE = False
GROQ_AVAILABLE = False

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    pass

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
        if not GEMINI_AVAILABLE:
            logger.warning("Gemini SDK not installed")
            return
        
        try:
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
        ctx_parts.append(f"""## App Information
- **Package:** {meta.get('package', 'unknown')}
- **Min SDK:** {meta.get('min_sdk', 'N/A')}
- **Target SDK:** {meta.get('target_sdk', 'N/A')}
- **Permissions:** {len(meta.get('permissions', []))}
- **Exported Components:** {len(meta.get('exported_components', []))}""")

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
                                f"- Evidence: `{f.get('evidence', 'N/A')[:100]}`")
            ctx_parts.append("## Security Findings\n" + "\n\n".join(finding_strs))

        if meta.get("libraries"):
            ctx_parts.append(f"## Detected Libraries\n{', '.join(meta['libraries'])}")

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
        """Interactive AI chat."""
        if not self.is_available:
            return "AI chat not available."

        if self.provider == "gemini":
            # Gemini manages its own session state if we use start_chat, 
            # but for simplicity we'll use a stateless approach if preferred.
            # Here we reuse the existing gemini chat logic
            if not hasattr(self, "_gemini_chats"): self._gemini_chats = {}
            if scan_id not in self._gemini_chats:
                ctx = self._build_scan_context(report_data)
                self._gemini_chats[scan_id] = self.client.start_chat(history=[
                    {"role": "user", "parts": [f"Context: {ctx}"]},
                    {"role": "model", "parts": ["I've analyzed the scan. How can I help?"]}
                ])
            res = self._gemini_chats[scan_id].send_message(message)
            return res.text
        
        elif self.provider == "groq":
            if scan_id not in self.chat_history:
                ctx = self._build_scan_context(report_data)
                self.chat_history[scan_id] = [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Context: {ctx}"},
                    {"role": "assistant", "content": "I've analyzed the scan. How can I help?"}
                ]
            
            self.chat_history[scan_id].append({"role": "user", "content": message})
            completion = self.client.chat.completions.create(
                messages=self.chat_history[scan_id],
                model=self.model_name,
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
