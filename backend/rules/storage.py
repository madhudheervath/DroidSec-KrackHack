"""
Insecure data storage detection patterns mapped to OWASP M9 (Insecure Data Storage).

DESIGN: Only flag patterns that represent actual security concerns, not normal
usage of standard Android APIs. getWritableDatabase() is not a vulnerability —
storing passwords in SharedPreferences IS.
"""

STORAGE_RULES = [
    {
        "id": "STO001",
        "name": "World-Readable File Mode",
        "pattern": r"MODE_WORLD_READABLE",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M9",
        "description": "File created with MODE_WORLD_READABLE. Any application can read this file's contents.",
        "remediation": "Use MODE_PRIVATE for all SharedPreferences and file operations. Data should only be accessible to the owning app."
    },
    {
        "id": "STO002",
        "name": "World-Writable File Mode",
        "pattern": r"MODE_WORLD_WRITEABLE",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M9",
        "description": "File created with MODE_WORLD_WRITEABLE. Any application can modify this file, potentially injecting malicious data.",
        "remediation": "Use MODE_PRIVATE. If data needs to be shared, use ContentProvider with proper permissions."
    },
    {
        "id": "STO003",
        "name": "External Storage Access (Deprecated API)",
        "pattern": r"getExternalStorageDirectory\s*\(",
        "severity": "info",
        "confidence": "medium",
        "owasp": "M9",
        "description": "App uses deprecated getExternalStorageDirectory(). On API < 29, this is world-readable. On API 29+, scoped storage applies.",
        "remediation": "Use internal storage (getFilesDir()) for sensitive data. Use Scoped Storage APIs for API 29+."
    },
    {
        "id": "STO004",
        "name": "Unencrypted SQLite with Sensitive Data",
        "pattern": r"SQLiteDatabase\.openOrCreateDatabase\s*\([^)]*(?:password|secret|token|credential|user|auth)",
        "severity": "high",
        "confidence": "medium",
        "owasp": "M9",
        "description": "SQLite database handling sensitive data without encryption. On rooted devices, database files can be read directly.",
        "remediation": "Use SQLCipher or Android's EncryptedFile API to encrypt the database."
    },
    {
        "id": "STO005",
        "name": "Sensitive Data in Logs",
        "pattern": r"Log\.[dveiw]\s*\([^)]*(?:password|passwd|pwd|secret|ssn|credit.?card|social.?security)[^)]*\)",
        "severity": "medium",
        "confidence": "medium",
        "owasp": "M9",
        "description": "Sensitive data may be written to system logs. Logs are accessible to other apps on older Android versions.",
        "remediation": "Never log sensitive data. Use ProGuard/R8 to strip Log calls from release builds."
    },
    {
        "id": "STO006",
        "name": "Clipboard Usage for Sensitive Data",
        "pattern": r"ClipboardManager.*(?:password|token|secret|key)",
        "severity": "medium",
        "confidence": "low",
        "owasp": "M9",
        "description": "Sensitive data may be copied to clipboard. Clipboard contents are accessible to all apps.",
        "remediation": "Avoid using clipboard for sensitive data. If necessary, clear clipboard after use and set expiration."
    },
    {
        "id": "STO008",
        "name": "Credentials Read from SharedPreferences",
        "pattern": r"getString\s*\(\s*\"[^\"]*(?:[Pp]assword|[Ss]ecret|[Cc]redential|[Ss]ession[_\s]?[Tt]oken|[Aa]uth[_\s]?[Tt]oken|[Ll]ogin[_\s]?[Tt]oken|superSecure)[^\"]*\"",
        "severity": "high",
        "confidence": "high",
        "owasp": "M9",
        "description": "Credentials or authentication tokens are read from SharedPreferences. Standard SharedPreferences are stored as plaintext XML, readable on rooted devices.",
        "remediation": "Use EncryptedSharedPreferences from AndroidX Security library. Store sensitive tokens in Android Keystore."
    },
    {
        "id": "STO009",
        "name": "Sensitive Data in System Output",
        "pattern": r"System\.out\.print(?:ln)?\s*\([^)]*(?:password|passwd|pwd|secret|credential|newpass|token|ssn)[^)]*\)",
        "severity": "medium",
        "confidence": "medium",
        "owasp": "M9",
        "description": "Sensitive data appears to be printed to System.out. This output is captured in logcat and is visible to any app on pre-API 16 devices.",
        "remediation": "Remove all System.out.println calls containing sensitive data. Use ProGuard/R8 to strip logging in release builds."
    },
    {
        "id": "STO010",
        "name": "Sensitive Data in Broadcast Intent",
        "pattern": r"putExtra\s*\(\s*\"[^\"]*(?:pass|secret|credential|token|auth|newpass)[^\"]*\"",
        "severity": "high",
        "confidence": "medium",
        "owasp": "M9",
        "description": "Sensitive data (password/token/credential) is placed in a broadcast Intent extra. Implicit broadcasts can be intercepted by any app with matching receiver.",
        "remediation": "Use LocalBroadcastManager or explicit Intents with component targeting. Never send credentials via implicit broadcasts."
    },
    {
        "id": "STO011",
        "name": "Sensitive Data Written to External Storage",
        "pattern": r"(?:FileWriter|FileOutputStream|BufferedWriter)\s*\([^)]*(?:getExternalStorageDirectory|/sdcard|Environment\.getExternal)",
        "severity": "high",
        "confidence": "medium",
        "owasp": "M9",
        "description": "Data is written to external storage which is world-readable on API < 29. Sensitive files can be accessed by any installed app.",
        "remediation": "Write sensitive data to internal storage (getFilesDir()) instead. Encrypt files if external storage is required."
    },
    {
        "id": "STO012",
        "name": "SMS Sending with Sensitive Content",
        "pattern": r"(?:SmsManager|sendTextMessage|sendMultipartTextMessage)\s*[.(]",
        "severity": "high",
        "confidence": "medium",
        "owasp": "M6",
        "description": "App sends SMS programmatically. SMS messages can be intercepted and are not encrypted. If sending credentials via SMS, this is a critical privacy risk.",
        "remediation": "Avoid sending sensitive data via SMS. Use encrypted push notifications or secure API calls instead."
    },
    {
        "id": "STO007",
        "name": "SharedPreferences for Sensitive Data",
        "pattern": r"getSharedPreferences\s*\([^)]*\).*(?:password|token|secret|key|credential)",
        "severity": "high",
        "confidence": "low",
        "owasp": "M9",
        "description": "SharedPreferences may store sensitive data without encryption. On rooted devices, these XML files are easily accessible.",
        "remediation": "Use EncryptedSharedPreferences from AndroidX Security library for storing sensitive data."
    },
]
