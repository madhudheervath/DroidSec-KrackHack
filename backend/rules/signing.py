"""
APK Signing Analyzer — checks certificate validity, signing scheme, 
debug signatures, and weak algorithms.
"""
import os
import re
import subprocess
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


# Known debug certificate fingerprints
DEBUG_SIGNATURES = [
    "SHA-256: 61:ED:37:7E:85:D3:86:A8:DF:EE:6B:86:4B:D8:5B:0B",  # Flutter default
    "CN=Android Debug",
    "CN=debug",
    "OU=Debug",
]


def analyze_apk_signing(apk_path: str) -> List[Dict]:
    """
    Analyze APK signing certificate and signing scheme.
    Uses apksigner if available, falls back to keytool/jarsigner.
    """
    findings = []

    if not os.path.exists(apk_path):
        return findings

    # Try apksigner verify
    cert_info = _run_apksigner(apk_path)
    if cert_info:
        findings.extend(_check_signing_scheme(cert_info))

    # Try keytool for certificate details
    cert_details = _run_keytool(apk_path)
    if cert_details:
        findings.extend(_check_certificate(cert_details))

    # Check for v1-only signing (vulnerable to Janus)
    if cert_info and "v1" in cert_info.lower():
        has_v2 = "v2" in cert_info.lower() and ("true" in cert_info.lower().split("v2")[1][:20])
        if not has_v2:
            findings.append({
                "id": "SIGN003",
                "name": "V1-Only APK Signing (Janus Vulnerability)",
                "severity": "high",
                "confidence": "high",
                "owasp": "M7",
                "location": "APK Signature",
                "evidence": "Only JAR signing (v1) detected",
                "description": "The APK uses only v1 (JAR) signing scheme, which is vulnerable to the "
                             "Janus vulnerability (CVE-2017-13156). An attacker can modify the APK "
                             "without invalidating the signature.",
                "remediation": "Sign the APK with v2 or v3 signing scheme using apksigner. "
                             "Example: apksigner sign --ks keystore.jks --v2-signing-enabled true app.apk",
            })

    return findings


def _run_apksigner(apk_path: str) -> str:
    """Run apksigner verify to check signing scheme."""
    try:
        result = subprocess.run(
            ["apksigner", "verify", "--verbose", "--print-certs", apk_path],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout + result.stderr
    except FileNotFoundError:
        logger.debug("apksigner not found, skipping signing scheme check")
    except Exception as e:
        logger.debug(f"apksigner failed: {e}")
    return ""


def _run_keytool(apk_path: str) -> str:
    """Extract certificate info using keytool."""
    try:
        # Use unzip + keytool to read the cert from META-INF
        result = subprocess.run(
            ["unzip", "-p", apk_path, "META-INF/*.RSA", "META-INF/*.DSA", "META-INF/*.EC"],
            capture_output=True, timeout=10
        )
        if result.stdout:
            cert_result = subprocess.run(
                ["keytool", "-printcert"],
                input=result.stdout,
                capture_output=True, text=True, timeout=10
            )
            return cert_result.stdout
    except FileNotFoundError:
        logger.debug("keytool not found, skipping certificate detail check")
    except Exception as e:
        logger.debug(f"keytool failed: {e}")
    return ""


def _check_signing_scheme(info: str) -> List[Dict]:
    """Check signing scheme details."""
    findings = []

    # Check for unsigned APK
    if "does not contain" in info.lower() or "not signed" in info.lower():
        findings.append({
            "id": "SIGN001",
            "name": "APK Not Signed",
            "severity": "critical",
            "confidence": "high",
            "owasp": "M7",
            "location": "APK Signature",
            "evidence": "No valid signature found",
            "description": "The APK is not properly signed. Unsigned APKs cannot be installed on "
                         "Android devices and indicate a development/test build.",
            "remediation": "Sign the APK with a release keystore before distribution.",
        })

    return findings


def _check_certificate(cert_info: str) -> List[Dict]:
    """Check certificate for security issues."""
    findings = []

    if not cert_info:
        return findings

    # Check for debug certificate
    for debug_sig in DEBUG_SIGNATURES:
        if debug_sig.lower() in cert_info.lower():
            findings.append({
                "id": "SIGN002",
                "name": "Debug Certificate Used for Signing",
                "severity": "critical",
                "confidence": "high",
                "owasp": "M7",
                "location": "APK Certificate",
                "evidence": f"Debug signature detected: {debug_sig}",
                "description": "The APK is signed with a debug certificate. Debug-signed apps "
                             "cannot be published to the Play Store and indicate the APK is a "
                             "development build that may have debug features enabled.",
                "remediation": "Sign the APK with a proper release keystore. Generate one with: "
                             "keytool -genkey -v -keystore release.jks -keyalg RSA -keysize 2048",
            })
            break

    # Check for weak signature algorithms
    weak_algos = {
        "MD5withRSA": "MD5 is broken — collisions can be generated",
        "SHA1withRSA": "SHA-1 is deprecated — collision attacks are practical",
        "SHA1withDSA": "SHA-1 with DSA is weak",
        "MD2withRSA": "MD2 is completely broken",
    }

    for algo, reason in weak_algos.items():
        if algo.lower() in cert_info.lower():
            findings.append({
                "id": "SIGN004",
                "name": f"Weak Signing Algorithm: {algo}",
                "severity": "high",
                "confidence": "high",
                "owasp": "M7",
                "location": "APK Certificate",
                "evidence": f"Signature Algorithm: {algo}",
                "description": f"The APK certificate uses {algo}. {reason}. "
                             f"An attacker may be able to forge a certificate with the same signature.",
                "remediation": "Re-sign the APK with SHA-256 or SHA-512: "
                             "keytool -genkey -keyalg RSA -sigalg SHA256withRSA -keysize 2048",
            })

    # Check RSA key size
    key_size_match = re.search(r'(\d{3,4})-bit', cert_info)
    if key_size_match:
        key_size = int(key_size_match.group(1))
        if key_size < 2048:
            findings.append({
                "id": "SIGN005",
                "name": f"Weak RSA Key Size: {key_size} bits",
                "severity": "high",
                "confidence": "high",
                "owasp": "M7",
                "location": "APK Certificate",
                "evidence": f"RSA key size: {key_size} bits",
                "description": f"The signing certificate uses a {key_size}-bit RSA key. "
                             f"Keys shorter than 2048 bits are considered weak and can be factored.",
                "remediation": "Generate a new keystore with at least 2048-bit RSA key.",
            })

    return findings
