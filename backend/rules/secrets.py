"""
Secret/credential detection patterns mapped to OWASP M1 (Improper Credential Usage).
Each pattern has: id, name, regex, severity, confidence, owasp, remediation.
"""

SECRET_RULES = [
    {
        "id": "SEC001",
        "name": "AWS Access Key ID",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M1",
        "description": "Hardcoded AWS Access Key ID found. This can grant unauthorized access to AWS services.",
        "remediation": "Remove the AWS key from source code. Use environment variables or AWS IAM roles. Rotate the exposed key immediately via AWS Console."
    },
    {
        "id": "SEC002",
        "name": "AWS Secret Access Key",
        "pattern": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M1",
        "description": "Hardcoded AWS Secret Access Key found. Combined with an Access Key ID, this grants full access to AWS resources.",
        "remediation": "Remove the secret key from source code. Use AWS Secrets Manager or environment variables. Rotate credentials immediately."
    },
    {
        "id": "SEC003",
        "name": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "medium",
        "confidence": "high",
        "owasp": "M1",
        "description": "Google API Key found in source code. Android API keys are typically restricted by package name "
                       "and SHA-1 fingerprint, limiting abuse. However, unrestricted keys can incur charges.",
        "remediation": "Verify API key restrictions in Google Cloud Console. Restrict by Android package name and signing certificate SHA-1."
    },
    {
        "id": "SEC004",
        "name": "Firebase Server Key",
        "pattern": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M1",
        "description": "Firebase Cloud Messaging server key found. Allows sending push notifications to all app users.",
        "remediation": "Move FCM server key to backend. Use Firebase Admin SDK server-side. Rotate the key in Firebase Console."
    },
    {
        "id": "SEC005",
        "name": "Generic API Key/Secret",
        "pattern": r"(?i)(api[_\-]?key|api[_\-]?secret|apikey)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
        "severity": "high",
        "confidence": "medium",
        "owasp": "M1",
        "description": "Potential API key or secret found hardcoded in source code.",
        "remediation": "Store API keys in Android Keystore or fetch from a secure backend. Never hardcode credentials in source."
    },
    {
        "id": "SEC006",
        "name": "Hardcoded Password",
        "pattern": r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][A-Za-z0-9!@#$%^&*()_+]{8,}['\"]",
        "severity": "medium",
        "confidence": "low",
        "owasp": "M1",
        "description": "Hardcoded password found in source code. Easily extractable by decompiling the APK.",
        "remediation": "Never hardcode passwords. Use Android Keystore for storing secrets. Implement proper authentication flows."
    },
    {
        "id": "SEC007",
        "name": "Private Key (PEM)",
        "pattern": r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+)?PRIVATE KEY-----",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M1",
        "description": "Private key embedded in application. This is a severe security flaw enabling impersonation or decryption.",
        "remediation": "Remove private keys from the app immediately. Use server-side key management. Revoke and regenerate the compromised key pair."
    },
    {
        "id": "SEC008",
        "name": "Slack Token",
        "pattern": r"xox[bpors]-[0-9]{10,13}-[a-zA-Z0-9-]*",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M1",
        "description": "Slack API token found. Allows access to Slack workspace messages and data.",
        "remediation": "Revoke the token immediately in Slack admin. Move token to server-side configuration."
    },
    {
        "id": "SEC009",
        "name": "GitHub Token",
        "pattern": r"gh[opsu]_[A-Za-z0-9_]{36,}",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M1",
        "description": "GitHub personal access token found. Can grant access to private repositories and organization data.",
        "remediation": "Revoke the token on GitHub Settings > Developer settings. Use fine-grained tokens with minimal permissions."
    },
    {
        "id": "SEC010",
        "name": "Stripe Secret Key",
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M1",
        "description": "Stripe live secret key found. Allows full access to payment processing and customer data.",
        "remediation": "Rotate the key immediately in Stripe Dashboard. Move payment logic to server-side only."
    },
    {
        "id": "SEC011",
        "name": "SendGrid API Key",
        "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "severity": "high",
        "confidence": "high",
        "owasp": "M1",
        "description": "SendGrid API key found. Allows sending emails on behalf of the account owner.",
        "remediation": "Revoke in SendGrid dashboard. Move email sending to server-side."
    },
    {
        "id": "SEC012",
        "name": "Twilio API Key",
        "pattern": r"SK[0-9a-fA-F]{32}",
        "severity": "high",
        "confidence": "medium",
        "owasp": "M1",
        "description": "Twilio API key found. Can be used to send SMS, make calls, and access communication APIs.",
        "remediation": "Regenerate key in Twilio Console. Move all Twilio interactions to server-side."
    },
    {
        "id": "SEC013",
        "name": "Bearer/Auth Token",
        "pattern": r"(?i)(bearer|authorization)\s*[=:]\s*['\"][a-zA-Z0-9\-._~+/]+=*['\"]",
        "severity": "high",
        "confidence": "medium",
        "owasp": "M1",
        "description": "Hardcoded authentication token found. Tokens should be obtained dynamically via auth flows.",
        "remediation": "Remove hardcoded tokens. Implement OAuth 2.0 or proper authentication flow."
    },
    {
        "id": "SEC016",
        "name": "Hardcoded Secret/Key Variable Assignment",
        "pattern": r"(?i)(?:String\s+)?(?:key|secret|passphrase)\s*=\s*\"(?:[^\"]*(?:secret|password|private|encrypt|cipher|master)[^\"]*|[^\"]{32,})\"",
        "severity": "high",
        "confidence": "medium",
        "owasp": "M1",
        "description": "A variable named 'key', 'secret', or 'passphrase' is assigned a string literal that appears to contain a secret. Hardcoded secrets are trivially extractable from decompiled APKs.",
        "remediation": "Store secrets in Android Keystore or retrieve them from a secure server at runtime. Never embed secret material in client-side code."
    },
    {
        "id": "SEC014",
        "name": "Firebase Database URL",
        "pattern": r"https://[a-zA-Z0-9-]+\.firebaseio\.com",
        "severity": "medium",
        "confidence": "high",
        "owasp": "M1",
        "description": "Firebase Realtime Database URL exposed. If security rules are weak, data may be publicly accessible.",
        "remediation": "Ensure Firebase security rules are properly configured. Restrict read/write access to authenticated users only."
    },
    {
        "id": "SEC015",
        "name": "Generic Secret/Token Assignment",
        "pattern": r"(?i)(secret|credentials?)\s*=\s*['\"][A-Za-z0-9_\\-]{16,}['\"]",
        "severity": "medium",
        "confidence": "low",
        "owasp": "M1",
        "description": "Potential secret found hardcoded in source code.",
        "remediation": "Review the identified string. If it's a real secret, move it to secure storage (Android Keystore, server-side config)."
    },
]
