"""
Obfuscation & Binary Protection Analyzer — checks if ProGuard/R8 obfuscation
is applied, detects root/emulator detection, and checks for anti-tampering measures.
"""
import os
import re
from typing import List, Dict


def analyze_binary_protections(source_dirs: List[str], apktool_dir: str = None) -> List[Dict]:
    """
    Analyze decompiled source for binary protection indicators.
    """
    findings = []
    
    # Track indicators
    has_obfuscation = False
    has_root_detection = False
    has_emulator_detection = False
    has_debug_detection = False
    has_tamper_detection = False
    has_ssl_pinning = False
    short_names_count = 0
    total_classes = 0

    for s_dir in source_dirs:
        if not os.path.exists(s_dir):
            continue

        for root, dirs, files in os.walk(s_dir):
            for fname in files:
                if not fname.endswith(('.java', '.kt', '.smali')):
                    continue

                total_classes += 1

                # Check for obfuscated names (single letter class names like a.java, b.java)
                if re.match(r'^[a-z]{1,2}\.(java|kt|smali)$', fname):
                    short_names_count += 1

                filepath = os.path.join(root, fname)
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        content = f.read(8000)  # Read first 8KB
                except Exception:
                    continue

                content_lower = content.lower()

                # Root detection indicators
                root_patterns = [
                    "superuser.apk", "su ", "/system/xbin/su", "/system/bin/su",
                    "roottools", "rootcloak", "isrooted", "checkroot",
                    "magisk", "busybox", "test-keys",
                    "com.noshufou.android.su", "com.thirdparty.superuser",
                    "eu.chainfire.supersu", "com.koushikdutta.superuser",
                    "com.topjohnwu.magisk",
                ]
                for pattern in root_patterns:
                    if pattern in content_lower:
                        has_root_detection = True
                        break

                # Emulator detection indicators
                emu_patterns = [
                    "goldfish", "ranchu", "generic_x86", "sdk_gphone",
                    "isemulator", "detectemulator", "checkemulator",
                    "ro.hardware.chipname", "ro.kernel.qemu",
                    "build.fingerprint", "generic/sdk",
                ]
                for pattern in emu_patterns:
                    if pattern in content_lower:
                        has_emulator_detection = True
                        break

                # Debug detection
                if "applicationinfo.flag_debuggable" in content_lower or \
                   "debug.isdebuggeron" in content_lower or \
                   "detectdebugg" in content_lower:
                    has_debug_detection = True

                # Tamper detection
                tamper_patterns = [
                    "packagemanager.get_signatures", "checksignature",
                    "verifysignature", "checksumverif", "integritycheck",
                    "safetynet", "play integrity", "playintegrity",
                    "attestation",
                ]
                for pattern in tamper_patterns:
                    if pattern in content_lower:
                        has_tamper_detection = True
                        break

                # SSL Pinning (code-based)
                pin_patterns = [
                    "certificatepinner", "certpinner", "sslpinning",
                    "okhttp3.certificatepinner", "trustmanagerfactory",
                    "x509trustmanager", "pinnedcertificates",
                ]
                for pattern in pin_patterns:
                    if pattern in content_lower:
                        has_ssl_pinning = True
                        break

    # Determine obfuscation
    if total_classes > 10:
        obfuscation_ratio = short_names_count / total_classes
        has_obfuscation = obfuscation_ratio > 0.3  # More than 30% short names

    # Generate findings for MISSING protections
    if not has_obfuscation and total_classes > 5:
        findings.append({
            "id": "BIN001",
            "name": "No Code Obfuscation Detected",
            "severity": "medium",
            "confidence": "low",
            "owasp": "M7",
            "location": "Application Binary",
            "evidence": f"{short_names_count}/{total_classes} classes have short names "
                       f"({round(short_names_count/max(total_classes,1)*100)}% obfuscation ratio)",
            "description": "The app does not appear to use ProGuard/R8 obfuscation. "
                         "Note: This check may have false positives on decompiled (jadx) output. "
                         "Best practice is to enable minification for release builds.",
            "remediation": "Enable R8/ProGuard in build.gradle: "
                         "minifyEnabled = true, and configure proguard-rules.pro.",
        })

    if not has_root_detection:
        findings.append({
            "id": "BIN002",
            "name": "No Root Detection",
            "severity": "info",
            "confidence": "medium",
            "owasp": "M7",
            "location": "Application Binary",
            "evidence": "No root detection patterns found in source code",
            "description": "The app does not check for rooted devices. Rooted devices bypass "
                         "Android's security sandbox, allowing other apps to access this app's "
                         "data, intercept network traffic, and modify app behavior.",
            "remediation": "Implement root detection using libraries like RootBeer or SafetyNet "
                         "Attestation API. Warn users or restrict functionality on rooted devices.",
        })

    if not has_tamper_detection:
        findings.append({
            "id": "BIN003",
            "name": "No Anti-Tampering Protection",
            "severity": "info",
            "confidence": "medium",
            "owasp": "M7",
            "location": "Application Binary",
            "evidence": "No signature verification or integrity check patterns found",
            "description": "The app does not verify its own integrity at runtime. An attacker "
                         "can repackage the app with malicious code and redistribute it.",
            "remediation": "Implement signature verification at runtime. Use Google Play Integrity "
                         "API or verify the APK signing certificate hash at startup.",
        })

    if not has_ssl_pinning:
        findings.append({
            "id": "BIN004",
            "name": "No SSL/TLS Certificate Pinning in Code",
            "severity": "medium",
            "confidence": "medium",
            "owasp": "M5",
            "location": "Application Binary",
            "evidence": "No certificate pinning implementation found in source code",
            "description": "The app does not implement certificate pinning in code. "
                         "Without pinning, MITM attacks using rogue CA certificates can "
                         "intercept all HTTPS traffic.",
            "remediation": "Use OkHttp CertificatePinner or Android's network_security_config.xml "
                         "with <pin-set> elements for your API domains.",
        })

    # Positive findings (things done well)
    if has_root_detection:
        findings.append({
            "id": "BIN005",
            "name": "Root Detection Implemented",
            "severity": "info",
            "confidence": "high",
            "owasp": "M7",
            "location": "Application Binary",
            "evidence": "Root detection patterns found in source",
            "description": "The app implements root detection, which is a good security practice.",
            "remediation": "Ensure root detection is robust and cannot be easily bypassed "
                         "with tools like Frida or Xposed.",
        })

    return findings
