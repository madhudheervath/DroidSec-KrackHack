"""
Weak cryptography detection patterns mapped to OWASP M10 (Insufficient Cryptography).
"""

CRYPTO_RULES = [
    {
        "id": "CRY001",
        "name": "MD5 Hash Usage",
        "pattern": r"MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']\s*\)",
        "severity": "medium",
        "confidence": "high",
        "owasp": "M10",
        "description": "MD5 hash algorithm detected. MD5 is cryptographically broken and vulnerable to collision attacks.",
        "remediation": "Replace MD5 with SHA-256 or SHA-3. Use MessageDigest.getInstance(\"SHA-256\")."
    },
    {
        "id": "CRY002",
        "name": "SHA-1 Hash Usage",
        "pattern": r"MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1[\"']\s*\)",
        "severity": "medium",
        "confidence": "high",
        "owasp": "M10",
        "description": "SHA-1 hash algorithm detected. SHA-1 has known collision vulnerabilities and is deprecated.",
        "remediation": "Upgrade to SHA-256 or SHA-3 for cryptographic hashing."
    },
    {
        "id": "CRY003",
        "name": "DES Encryption",
        "pattern": r"Cipher\.getInstance\s*\(\s*[\"']DES",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M10",
        "description": "DES encryption detected. DES uses a 56-bit key and can be brute-forced in hours.",
        "remediation": "Replace DES with AES-256. Use Cipher.getInstance(\"AES/GCM/NoPadding\")."
    },
    {
        "id": "CRY004",
        "name": "ECB Mode Encryption",
        "pattern": r"Cipher\.getInstance\s*\(\s*[\"'][A-Za-z]+/ECB/",
        "severity": "high",
        "confidence": "high",
        "owasp": "M10",
        "description": "ECB (Electronic Codebook) mode detected. ECB does not provide semantic security — identical plaintext blocks produce identical ciphertext blocks.",
        "remediation": "Use CBC or GCM mode instead. Recommended: AES/GCM/NoPadding."
    },
    {
        "id": "CRY005",
        "name": "Hardcoded Initialization Vector",
        "pattern": r"IvParameterSpec\s*\(\s*new\s+byte\s*\[",
        "severity": "high",
        "confidence": "high",
        "owasp": "M10",
        "description": "Hardcoded IV (Initialization Vector) detected. Static IVs defeat the purpose of randomized encryption.",
        "remediation": "Generate a random IV using SecureRandom for each encryption operation. Store the IV alongside the ciphertext."
    },
    {
        "id": "CRY006",
        "name": "Insecure Random Number Generator",
        "pattern": r"new\s+Random\s*\(",
        "severity": "medium",
        "confidence": "low",
        "owasp": "M10",
        "description": "java.util.Random used instead of SecureRandom. Random is predictable and must not be used for security purposes.",
        "remediation": "Replace with java.security.SecureRandom for all cryptographic and security-sensitive operations."
    },
    {
        "id": "CRY007",
        "name": "Static Seed for SecureRandom",
        "pattern": r"SecureRandom\s*\(.*\).*\.setSeed\s*\(",
        "severity": "high",
        "confidence": "medium",
        "owasp": "M10",
        "description": "SecureRandom seeded with a static value. This makes the output predictable.",
        "remediation": "Do not manually seed SecureRandom. Let the system provide entropy automatically."
    },
    {
        "id": "CRY008",
        "name": "Weak RSA Key Size",
        "pattern": r"KeyPairGenerator.*\.initialize\s*\(\s*(512|768|1024)\s*\)",
        "severity": "high",
        "confidence": "high",
        "owasp": "M10",
        "description": "RSA key size is too small. Keys under 2048 bits are considered breakable.",
        "remediation": "Use a minimum of 2048-bit RSA keys. Recommended: 4096 bits for long-term security."
    },
    {
        "id": "CRY009",
        "name": "Hardcoded Encryption Key",
        "pattern": r"SecretKeySpec\s*\(\s*[\"'][^\"']+[\"']\s*\.getBytes",
        "severity": "critical",
        "confidence": "high",
        "owasp": "M10",
        "description": "Encryption key is hardcoded as a string literal. Easily extractable by decompiling the app.",
        "remediation": "Use Android Keystore to generate and store encryption keys. Never embed keys in source code."
    },
    {
        "id": "CRY010",
        "name": "Base64 Used as Encryption",
        "pattern": r"(?i)Base64\.(encode|decode).*(?:encrypt|password|secret|token)",
        "severity": "medium",
        "confidence": "low",
        "owasp": "M10",
        "description": "Base64 encoding used in a security context. Base64 is encoding, not encryption — data is trivially reversible.",
        "remediation": "Use proper encryption (AES-GCM) instead of Base64 encoding for protecting sensitive data."
    },
]
