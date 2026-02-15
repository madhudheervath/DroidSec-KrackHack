"""
WebView vulnerability detection patterns mapped to OWASP M4/M8.

DESIGN: Only flag WebView patterns that represent actual exploitable conditions.
WEB001 (setJavaScriptEnabled) removed entirely — it fires on virtually every app
and provides zero actionable insight. The real dangers are file access and
universal access from file URLs.
"""

WEBVIEW_RULES = [
    {
        "id": "WEB002",
        "name": "File Access From URLs in WebView",
        "pattern": r"setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)",
        "severity": "high",
        "confidence": "high",
        "owasp": "M8",
        "description": "WebView allows file:// URLs to access other file:// URLs. Can be exploited to read arbitrary files.",
        "remediation": "Set setAllowFileAccessFromFileURLs(false). This is secure by default on API 16+."
    },
    {
        "id": "WEB003",
        "name": "Universal File Access in WebView",
        "pattern": r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M8",
        "description": "WebView allows file:// URLs to access content from any origin. Severe security risk enabling data exfiltration.",
        "remediation": "Set setAllowUniversalAccessFromFileURLs(false). Never enable this in production."
    },
    {
        "id": "WEB004",
        "name": "JavaScript Interface (RCE Risk on API < 17)",
        "pattern": r"addJavascriptInterface\s*\(",
        "severity": "info",
        "confidence": "medium",
        "owasp": "M4",
        "description": "addJavascriptInterface exposes Java objects to JavaScript. On API < 17, this allows remote code execution. On modern APIs, only @JavascriptInterface methods are exposed.",
        "remediation": "Target API 17+ and annotate exposed methods with @JavascriptInterface. Minimize exposed functionality."
    },
    {
        "id": "WEB005",
        "name": "WebView Loading Dynamic URL",
        "pattern": r"\.loadUrl\s*\(\s*(?:getIntent|intent\.get|Uri\.parse)",
        "severity": "medium",
        "confidence": "low",
        "owasp": "M4",
        "description": "WebView loads a URL from intent data or URI parsing. If user-controlled, can lead to loading malicious pages.",
        "remediation": "Validate and sanitize all URLs before loading in WebView. Use an allowlist of trusted domains."
    },
    {
        "id": "WEB006",
        "name": "WebView Content Access Enabled",
        "pattern": r"setAllowContentAccess\s*\(\s*true\s*\)",
        "severity": "medium",
        "confidence": "high",
        "owasp": "M8",
        "description": "WebView content:// access enabled. Allows loading data from ContentProviders which may expose sensitive data.",
        "remediation": "Disable content access unless specifically required: setAllowContentAccess(false)."
    },
]
