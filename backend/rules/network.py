"""
Insecure communication detection patterns mapped to OWASP M5 (Insecure Communication).

DESIGN: Focus on high-impact issues — trust-all certificates, SSL error overrides,
and hostname verification bypass are CRITICAL findings.
NET001 (cleartext HTTP URL) removed: in source code, http:// strings appear as
constants, URLs in comments, test fixtures, and SDK configs. They don't indicate
actual insecure communication since Android 9+ blocks cleartext by default.
The manifest-level usesCleartextTraffic check (NET005) is the real indicator.
"""

NETWORK_RULES = [
    {
        "id": "NET002",
        "name": "Trust All Certificates",
        "pattern": r"(TrustAllCerts|X509TrustManager\s*\(\s*\)|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|checkClientTrusted\s*\([^)]*\)\s*\{\s*\})",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M5",
        "description": "Application trusts all SSL/TLS certificates. This completely negates HTTPS protection and enables MITM attacks.",
        "remediation": "Remove custom TrustManager. Use the system default certificate validation. Implement certificate pinning for sensitive connections."
    },
    {
        "id": "NET003",
        "name": "SSL Error Override in WebView",
        "pattern": r"onReceivedSslError.*\.proceed\s*\(",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M5",
        "description": "WebView SSL errors are being ignored. This allows MITM attacks on WebView content.",
        "remediation": "Remove the proceed() call. Implement proper SSL error handling — cancel the request and alert the user."
    },
    {
        "id": "NET004",
        "name": "Hostname Verifier Disabled",
        "pattern": r"(ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|setHostnameVerifier\s*\(\s*null\s*\))",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M5",
        "description": "Hostname verification disabled. A valid certificate for any domain will be accepted, enabling MITM attacks.",
        "remediation": "Use the default HostnameVerifier. Do not override hostname verification logic."
    },
    {
        "id": "NET005",
        "name": "Cleartext Traffic Allowed in Manifest",
        "pattern": r"android:usesCleartextTraffic\s*=\s*[\"']true[\"']",
        "severity": "high",
        "confidence": "high",
        "owasp": "M5",
        "description": "Application explicitly allows cleartext (HTTP) traffic. All network calls can be intercepted.",
        "remediation": "Set android:usesCleartextTraffic='false' in AndroidManifest.xml. Use network_security_config.xml for exceptions."
    },
    {
        "id": "NET006",
        "name": "Missing Network Security Config",
        "pattern": r"\<application(?!.*android:networkSecurityConfig)",
        "severity": "medium",
        "confidence": "medium",
        "owasp": "M5",
        "description": "No custom network security configuration defined. The app relies on default platform behavior.",
        "remediation": "Add a network_security_config.xml to enforce HTTPS, enable certificate pinning, and restrict cleartext traffic."
    },
]
