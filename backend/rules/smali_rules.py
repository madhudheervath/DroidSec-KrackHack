"""
Smali-specific detection rules — used when jadx fails and only
apktool's smali output is available.

IMPORTANT: In smali, method calls look like:
  invoke-virtual {v0, v1, v2}, Lcom/example/Class;->methodName(Params)ReturnType;
  const-string v0, "literal value"

The regex patterns here are designed to match these exact formats.

DESIGN: These rules are intentionally conservative. Smali is noisy by nature
(every string is a const-string), so we only flag patterns that are almost
certainly real vulnerabilities, not informational "code uses X" patterns.
"""

SMALI_SECRET_RULES = [
    {
        "id": "SEC003",
        "name": "Google API Key",
        "pattern": r'const-string[/\w]*\s+\w+,\s*"AIza[0-9A-Za-z\-_]{35}"',
        "severity": "medium",
        "confidence": "high",
        "owasp": "M1",
        "description": "Google API Key found hardcoded in application bytecode.",
        "remediation": "Restrict API key in Google Cloud Console. Use Android Keystore for storage.",
    },
    {
        "id": "SEC001",
        "name": "AWS Access Key ID",
        "pattern": r'const-string[/\w]*\s+\w+,\s*"AKIA[0-9A-Z]{16}"',
        "severity": "critical",
        "confidence": "high",
        "owasp": "M1",
        "description": "AWS Access Key ID found hardcoded in application.",
        "remediation": "Remove from source immediately. Rotate key. Use IAM roles.",
    },
    {
        "id": "SEC007",
        "name": "Private Key (PEM)",
        "pattern": r'const-string[/\w]*\s+\w+,\s*"-----BEGIN.*(PRIVATE KEY|RSA)',
        "severity": "critical",
        "confidence": "high",
        "owasp": "M1",
        "description": "Private key embedded in application.",
        "remediation": "Remove private keys from code. Use server-side key management.",
    },
    {
        "id": "SEC014",
        "name": "Firebase Database URL",
        "pattern": r'const-string[/\w]*\s+\w+,\s*"https://[a-zA-Z0-9-]+\.firebaseio\.com"',
        "severity": "medium",
        "confidence": "high",
        "owasp": "M1",
        "description": "Firebase Realtime Database URL found. Check Firebase security rules.",
        "remediation": "Ensure Firebase rules restrict access to authenticated users only.",
    },
]

SMALI_CRYPTO_RULES = [
    {
        "id": "CRY001",
        "name": "Insecure MD5 Hashing",
        "pattern": r'const-string[/\w]*\s+\w+,\s*"MD5"',
        "severity": "medium",
        "confidence": "high",
        "owasp": "M10",
        "description": "MD5 hashing detected. MD5 is cryptographically broken and vulnerable to collisions.",
        "remediation": "Use SHA-256 or SHA-3 instead of MD5 for hashing.",
    },
    {
        "id": "CRY002",
        "name": "Insecure SHA-1 Hashing",
        "pattern": r'const-string[/\w]*\s+\w+,\s*"SHA-1"',
        "severity": "medium",
        "confidence": "medium",
        "owasp": "M10",
        "description": "SHA-1 hashing detected. SHA-1 has known collision attacks.",
        "remediation": "Use SHA-256 or SHA-3 for cryptographic hashing.",
    },
    {
        "id": "CRY003",
        "name": "ECB Mode Encryption",
        "pattern": r'const-string[/\w]*\s+\w+,\s*"AES/ECB/',
        "severity": "high",
        "confidence": "high",
        "owasp": "M10",
        "description": "AES/ECB mode encryption detected. ECB reveals patterns in ciphertext.",
        "remediation": "Use CBC or GCM mode with a random IV for encryption.",
    },
    {
        "id": "CRY004",
        "name": "DES Encryption (Weak)",
        "pattern": r'const-string[/\w]*\s+\w+,\s*"DES["/]',
        "severity": "high",
        "confidence": "high",
        "owasp": "M10",
        "description": "DES encryption detected. DES uses a 56-bit key which is trivially brute-forced.",
        "remediation": "Use AES-256 with GCM mode instead of DES.",
    },
    # CRY006 ("Static IV / Key Material") REMOVED — the old regex
    # r'[A-Za-z0-9+/]{16,32}={0,2}' matched virtually ANY alphanumeric
    # string 16-32 chars long (e.g. "AdmobRewardedInterstitialAd"), generating
    # thousands of false positives per scan.  Real static-key detection is
    # handled by CRY005/CRY009 in Java rules + entropy analysis.
]

SMALI_NETWORK_RULES = [
    # NET002 (Cleartext HTTP URL) REMOVED from smali rules.
    # Reason: In smali, standard XML namespace URIs like
    # http://www.w3.org/ns/ttml, http://ns.adobe.com/xap, and SDK
    # constant strings all show up as const-string "http://..." and
    # our false-positive filter didn't cover smali. This rule generated
    # 27+ false positives per scan. The Java-side NET001 rule is sufficient.

    {
        "id": "NET005",
        "name": "Custom TrustManager Implementation",
        "pattern": r'\.implements Ljavax/net/ssl/X509TrustManager;',
        "severity": "critical",
        "confidence": "high",
        "owasp": "M5",
        "description": "Class implements X509TrustManager. If checkServerTrusted() is empty, this disables SSL verification.",
        "remediation": "Use default TrustManager. Use Network Security Config for debug overrides.",
    },
    {
        "id": "NET006",
        "name": "Custom HostnameVerifier Implementation",
        "pattern": r'\.implements Ljavax/net/ssl/HostnameVerifier;',
        "severity": "high",
        "confidence": "medium",
        "owasp": "M5",
        "description": "Class implements HostnameVerifier. If verify() always returns true, hostname checks are bypassed.",
        "remediation": "Use default HostnameVerifier. Never return true for all hostnames.",
    },
]

SMALI_STORAGE_RULES = [
    {
        "id": "STO002",
        "name": "SharedPreferences Credential Storage",
        "pattern": r'const-string[/\w]*\s+\w+,\s*"(EncryptedUsername|EncryptedPassword|superSecure|mySharedPreferences|user_password|saved_password|session_token|auth_token|login_token)"',
        "severity": "high",
        "confidence": "high",
        "owasp": "M9",
        "description": "Credentials or authentication tokens appear to be stored in SharedPreferences.",
        "remediation": "Use EncryptedSharedPreferences or Android Keystore for credential storage.",
    },
    # STO003 (rawQuery/execSQL) REMOVED from smali rules.
    # Reason: Every SQLite operation in every library shows up in smali.
    # ExoPlayer, Room, analytics SDKs all use execSQL for schema migrations.
    # The pattern `->execSQL(` is too broad in bytecode context.
    # The Java-side detection in storage.py is more precise.

    {
        "id": "STO004",
        "name": "External Storage Access",
        "pattern": r'Landroid/os/Environment;->getExternalStorageDirectory',
        "severity": "medium",
        "confidence": "medium",
        "owasp": "M9",
        "description": "App accesses external storage which is world-readable on API < 29.",
        "remediation": "Use app-specific internal storage or Scoped Storage (API 29+).",
    },
]

SMALI_WEBVIEW_RULES = [
    # WEB001 (JavaScript Enabled) REMOVED from smali rules.
    # Reason: setJavaScriptEnabled is called by virtually every app that
    # uses WebView. In smali it fires on every ad SDK, analytics, and payment
    # library. This is informational at best and is handled by Java rules.

    {
        "id": "WEB002",
        "name": "JavaScript Interface Bridge",
        "pattern": r'->addJavascriptInterface\(Ljava/lang/Object;Ljava/lang/String;\)V',
        "severity": "medium",
        "confidence": "medium",
        "owasp": "M8",
        "description": "WebView JavaScript interface bridge detected. On API < 17, allows RCE.",
        "remediation": "Remove if not needed. Add @JavascriptInterface annotation. Target API >= 17.",
    },
    {
        "id": "WEB003",
        "name": "WebView File Access From URLs",
        "pattern": r'->setAllowFileAccessFromFileURLs\(Z\)V',
        "severity": "high",
        "confidence": "high",
        "owasp": "M8",
        "description": "setAllowFileAccessFromFileURLs called. If true, file:// URLs can read other files.",
        "remediation": "Set setAllowFileAccessFromFileURLs(false).",
    },
]

SMALI_LOGGING_RULES = [
    # LOG001 (Verbose Logging) REMOVED from smali rules.
    # Reason: Every app logs. Log.d/v/i calls are so ubiquitous in bytecode
    # that flagging them generates hundreds of info-level noise findings.
    # The Java-side STO005 rule is more targeted (looks for sensitive keywords).
]

SMALI_INTENT_RULES = [
    {
        "id": "INT001",
        "name": "Sending SMS Programmatically",
        "pattern": r'Landroid/telephony/SmsManager;->sendTextMessage',
        "severity": "high",
        "confidence": "high",
        "owasp": "M6",
        "description": "App sends SMS programmatically. Can be abused for premium SMS fraud or phishing.",
        "remediation": "Confirm SMS sending is essential. Use user confirmation dialogs.",
    },
    # INT002 (sendBroadcast) REMOVED — too common in normal app code.
    # INT003 (Base64 encode/decode) REMOVED — Base64 is used everywhere
    # for completely legitimate purposes (image encoding, data transfer).
]

# Combined list for the scanner
ALL_SMALI_RULES = (
    SMALI_SECRET_RULES +
    SMALI_CRYPTO_RULES +
    SMALI_NETWORK_RULES +
    SMALI_STORAGE_RULES +
    SMALI_WEBVIEW_RULES +
    SMALI_LOGGING_RULES +
    SMALI_INTENT_RULES
)
