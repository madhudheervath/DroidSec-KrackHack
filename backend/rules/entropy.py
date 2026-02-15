"""
String Entropy Analyzer — detects high-entropy strings that likely represent
API keys, tokens, secrets, or encryption keys that regex patterns miss.
Uses Shannon entropy calculation.
"""
import math
import re
import os
from typing import List, Dict


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# Common false-positive patterns to skip
FALSE_POSITIVES = {
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
    "Lorem ipsum",
    "content://",
    "http://schemas.android.com",
    "xmlns:",
    "android.intent.",
    "com.google.android",
    "java.lang.",
    "UTF-8",
    "ISO-8859-1",
}

# Known safe package prefixes
SAFE_PREFIXES = [
    "com.android.", "android.", "java.", "javax.", "org.w3c.",
    "org.xml.", "dalvik.", "kotlin.", "kotlinx.", "androidx.",
    "com.google.android.gms", "org.apache.",
]

# Patterns that look like encoded data / keys
HEX_PATTERN = re.compile(r'^[0-9a-fA-F]{16,}$')
BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/=]{20,}$')
JWT_PATTERN = re.compile(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')


def is_false_positive(s: str) -> bool:
    """Check if string is a known false positive."""
    for fp in FALSE_POSITIVES:
        if fp in s:
            return True
    for prefix in SAFE_PREFIXES:
        if s.startswith(prefix):
            return True
    # Skip URLs that are just standard endpoints
    if s.startswith("http://schemas.") or s.startswith("http://www.w3.org"):
        return True
    # Skip if it's mostly dots (package names)
    if s.count('.') > 4 and all(c.isalnum() or c == '.' for c in s):
        return True
    return False


def extract_strings_from_file(filepath: str) -> List[str]:
    """Extract string literals from a source file."""
    strings = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        # Match quoted strings
        for match in re.finditer(r'"([^"]{12,256})"', content):
            s = match.group(1)
            if not is_false_positive(s):
                strings.append(s)
    except Exception:
        pass
    return strings


def classify_secret(s: str, entropy: float) -> Dict:
    """Classify a high-entropy string into a secret type."""
    # JWT Token
    if JWT_PATTERN.match(s):
        return {"type": "JWT Token", "severity": "critical", "confidence": "high"}

    # Hex encoded (likely key material)
    if HEX_PATTERN.match(s) and len(s) >= 32:
        return {"type": "Hex-Encoded Key/Hash", "severity": "high", "confidence": "high"}

    # Base64 with high entropy (likely encoded secret)
    if BASE64_PATTERN.match(s) and entropy > 5.0 and len(s) >= 28:
        return {"type": "Base64-Encoded Secret", "severity": "high", "confidence": "medium"}

    # Very high entropy long string (generic secret)
    if entropy > 5.0 and len(s) >= 24:
        # Check for mixed case + numbers + special chars (password-like)
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        has_digit = any(c.isdigit() for c in s)
        has_special = any(not c.isalnum() for c in s)
        char_classes = sum([has_upper, has_lower, has_digit, has_special])
        if char_classes >= 4:
            return {"type": "Potential Secret/Token", "severity": "high", "confidence": "medium"}

    # High entropy medium string — require very high bar
    if entropy > 4.8 and len(s) >= 20:
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        has_digit = any(c.isdigit() for c in s)
        if sum([has_upper, has_lower, has_digit]) >= 3:
            return {"type": "Suspicious High-Entropy String", "severity": "medium", "confidence": "low"}

    return None


def analyze_entropy(source_dirs: List[str], threshold: float = 4.5) -> List[Dict]:
    """
    Scan source files for high-entropy strings that may be secrets.
    
    Shannon entropy thresholds:
    - English text: ~3.5-4.0
    - API keys/tokens: ~4.5-5.5
    - Random bytes (hex): ~3.7-4.0
    - Random bytes (base64): ~5.0-6.0
    """
    findings = []
    seen = set()  # Deduplicate

    for source_dir in source_dirs:
        if not os.path.exists(source_dir):
            continue

        for root, dirs, files in os.walk(source_dir):
            for fname in files:
                if not fname.endswith(('.java', '.kt', '.json', '.properties')):
                    continue

                filepath = os.path.join(root, fname)
                strings = extract_strings_from_file(filepath)

                for s in strings:
                    if s in seen:
                        continue
                    seen.add(s)

                    entropy = shannon_entropy(s)
                    if entropy < threshold:
                        continue

                    classification = classify_secret(s, entropy)
                    if classification is None:
                        continue

                    rel_path = os.path.relpath(filepath, source_dir)
                    findings.append({
                        "id": "ENT001",
                        "name": f"High-Entropy String: {classification['type']}",
                        "severity": classification["severity"],
                        "confidence": classification["confidence"],
                        "owasp": "M1",
                        "location": rel_path,
                        "evidence": s[:80] + ("..." if len(s) > 80 else ""),
                        "description": f"Shannon entropy: {entropy:.2f} bits/char. {classification['type']} detected. "
                                       f"High-entropy strings in source code often indicate hardcoded secrets, "
                                       f"API keys, or cryptographic material that should be stored securely.",
                        "remediation": "Move secrets to Android Keystore, environment variables, or a secure vault. "
                                       "Never hardcode secrets in source code.",
                        "entropy": round(entropy, 2),
                    })

    # Sort by entropy descending (most suspicious first)
    findings.sort(key=lambda f: f.get("entropy", 0), reverse=True)
    return findings[:3]  # Cap at 3 — only the most suspicious strings
