"""
Dangerous Android permissions list for excessive permission detection.
Mapped to OWASP M6 (Inadequate Privacy Controls) and M8 (Security Misconfiguration).
"""

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS": {
        "severity": "medium",
        "owasp": "M6",
        "description": "App can read user's contacts.",
        "risk": "Privacy concern — accessing personal contact information."
    },
    "android.permission.WRITE_CONTACTS": {
        "severity": "medium",
        "owasp": "M6",
        "description": "App can modify user's contacts.",
        "risk": "Can silently add/modify/delete contacts."
    },
    "android.permission.READ_CALL_LOG": {
        "severity": "high",
        "owasp": "M6",
        "description": "App can read call history.",
        "risk": "Sensitive communication metadata exposure."
    },
    "android.permission.READ_SMS": {
        "severity": "high",
        "owasp": "M6",
        "description": "App can read SMS messages.",
        "risk": "Can intercept OTPs and private messages."
    },
    "android.permission.SEND_SMS": {
        "severity": "critical",
        "owasp": "M8",
        "description": "App can send SMS messages.",
        "risk": "Can send premium SMS or phishing messages."
    },
    "android.permission.RECEIVE_SMS": {
        "severity": "high",
        "owasp": "M6",
        "description": "App can receive SMS messages.",
        "risk": "Can silently intercept incoming messages including OTPs."
    },
    "android.permission.CAMERA": {
        "severity": "medium",
        "owasp": "M6",
        "description": "App can access the camera.",
        "risk": "Can capture photos/videos without user awareness."
    },
    "android.permission.RECORD_AUDIO": {
        "severity": "high",
        "owasp": "M6",
        "description": "App can record audio.",
        "risk": "Can silently record conversations."
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "severity": "high",
        "owasp": "M6",
        "description": "App can access precise GPS location.",
        "risk": "Continuous location tracking possible."
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "severity": "medium",
        "owasp": "M6",
        "description": "App can access approximate location.",
        "risk": "Approximate location tracking."
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "severity": "medium",
        "owasp": "M6",
        "description": "App can read external storage.",
        "risk": "Access to user's files, photos, downloads."
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "severity": "medium",
        "owasp": "M9",
        "description": "App can write to external storage.",
        "risk": "Can modify or delete user's files."
    },
    "android.permission.READ_PHONE_STATE": {
        "severity": "medium",
        "owasp": "M6",
        "description": "App can read phone state (IMEI, phone number).",
        "risk": "Device fingerprinting and tracking."
    },
    "android.permission.CALL_PHONE": {
        "severity": "high",
        "owasp": "M8",
        "description": "App can make phone calls without user interaction.",
        "risk": "Can initiate premium-rate calls."
    },
    "android.permission.INTERNET": {
        "severity": "info",
        "owasp": "M5",
        "description": "App can access the internet.",
        "risk": "Required for most apps — flag only in combination with other findings."
    },
    "android.permission.INSTALL_PACKAGES": {
        "severity": "critical",
        "owasp": "M8",
        "description": "App can install other packages.",
        "risk": "Can silently install malware."
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "severity": "high",
        "owasp": "M8",
        "description": "App can request package installation.",
        "risk": "Can prompt users to install potentially malicious APKs."
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "severity": "high",
        "owasp": "M8",
        "description": "App can draw overlays on top of other apps.",
        "risk": "Can be used for tapjacking and phishing attacks."
    },
}
