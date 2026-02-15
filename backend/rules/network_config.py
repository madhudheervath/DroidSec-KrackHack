"""
Network Security Config Analyzer — parses Android's network_security_config.xml
to detect cleartext traffic, weak TLS, custom trust anchors, and certificate pinning status.
"""
import os
import re
from typing import List, Dict
from xml.etree import ElementTree as ET


def analyze_network_config(apktool_dir: str) -> List[Dict]:
    """
    Parse network_security_config.xml and check for insecure configurations.
    """
    findings = []

    # Find the network security config
    config_path = None
    res_xml_dir = os.path.join(apktool_dir, "res", "xml")
    
    if os.path.isdir(res_xml_dir):
        for f in os.listdir(res_xml_dir):
            if "network" in f.lower() and f.endswith(".xml"):
                config_path = os.path.join(res_xml_dir, f)
                break

    if not config_path or not os.path.exists(config_path):
        # No network security config — that's a finding itself
        findings.append({
            "id": "NETCFG001",
            "name": "Missing Network Security Configuration",
            "severity": "info",
            "confidence": "high",
            "owasp": "M5",
            "location": "res/xml/network_security_config.xml",
            "evidence": "File not found",
            "description": "No network_security_config.xml found. Without this, the app relies on "
                         "platform defaults which vary by Android version. Apps targeting SDK 28+ "
                         "block cleartext by default, but older targets allow it.",
            "remediation": "Create a network_security_config.xml that explicitly disables cleartext traffic "
                         "and configures certificate pinning for your API endpoints.",
        })
        return findings

    try:
        tree = ET.parse(config_path)
        root = tree.getroot()
    except Exception as e:
        findings.append({
            "id": "NETCFG002",
            "name": "Malformed Network Security Config",
            "severity": "medium",
            "confidence": "high",
            "owasp": "M5",
            "location": config_path,
            "evidence": str(e),
            "description": "The network_security_config.xml could not be parsed. This may indicate "
                         "a corrupted or intentionally obfuscated configuration.",
            "remediation": "Fix the XML syntax in the network security configuration file.",
        })
        return findings

    # Check base-config
    base_config = root.find("base-config")
    if base_config is not None:
        cleartext = base_config.get("cleartextTrafficPermitted", "false")
        if cleartext.lower() == "true":
            findings.append({
                "id": "NETCFG003",
                "name": "Cleartext Traffic Globally Permitted",
                "severity": "high",
                "confidence": "high",
                "owasp": "M5",
                "location": "network_security_config.xml → <base-config>",
                "evidence": f'cleartextTrafficPermitted="{cleartext}"',
                "description": "The app globally permits cleartext (HTTP) traffic. All network "
                             "communication can be intercepted via man-in-the-middle attacks.",
                "remediation": "Set cleartextTrafficPermitted to false in base-config and use HTTPS everywhere.",
            })

        # Check for user-installed CAs in trust anchors
        trust_config = base_config.find("trust-anchors")
        if trust_config is not None:
            for cert in trust_config.findall("certificates"):
                src = cert.get("src", "")
                if src == "user":
                    findings.append({
                        "id": "NETCFG004",
                        "name": "User-Installed CA Certificates Trusted",
                        "severity": "high",
                        "confidence": "high",
                        "owasp": "M5",
                        "location": "network_security_config.xml → <base-config> → <trust-anchors>",
                        "evidence": f'<certificates src="{src}" />',
                        "description": "The app trusts user-installed CA certificates globally. "
                                     "This allows proxy tools like Burp Suite to intercept HTTPS traffic, "
                                     "making the app vulnerable to MITM attacks on rooted/compromised devices.",
                        "remediation": "Remove user certificates from base-config trust-anchors. "
                                     "Only add user CAs in debug-overrides for development.",
                    })

    # Check domain-specific configs
    for domain_config in root.findall("domain-config"):
        cleartext = domain_config.get("cleartextTrafficPermitted", "false")
        domains = [d.text for d in domain_config.findall("domain") if d.text]
        domain_str = ", ".join(domains[:5])

        if cleartext.lower() == "true":
            findings.append({
                "id": "NETCFG005",
                "name": f"Cleartext Traffic Permitted for Domains",
                "severity": "high",
                "confidence": "high",
                "owasp": "M5",
                "location": "network_security_config.xml → <domain-config>",
                "evidence": f"Cleartext allowed for: {domain_str}",
                "description": f"Cleartext HTTP traffic is explicitly allowed for: {domain_str}. "
                             f"Data sent to these domains can be intercepted.",
                "remediation": "Use HTTPS for all domains. If cleartext is needed for development, "
                             "restrict it to debug builds only.",
            })

        # Check for certificate pinning (positive finding — good security)
        pin_set = domain_config.find("pin-set")
        if pin_set is not None:
            # Good — has pinning
            pass
        else:
            if domains:
                findings.append({
                    "id": "NETCFG006",
                    "name": "No Certificate Pinning Configured",
                    "severity": "medium",
                    "confidence": "medium",
                    "owasp": "M5",
                    "location": "network_security_config.xml",
                    "evidence": f"No pin-set found for: {domain_str}",
                    "description": "The app does not implement certificate pinning. Certificate pinning "
                                 "prevents MITM attacks even when a rogue CA is installed on the device.",
                    "remediation": "Add <pin-set> with SHA-256 pins for your server certificates. "
                                 "Include backup pins for key rotation.",
                })

    # Check debug-overrides
    debug_overrides = root.find("debug-overrides")
    if debug_overrides is not None:
        trust_config = debug_overrides.find("trust-anchors")
        if trust_config is not None:
            for cert in trust_config.findall("certificates"):
                src = cert.get("src", "")
                if src == "user":
                    findings.append({
                        "id": "NETCFG007",
                        "name": "Debug Overrides Trust User CAs",
                        "severity": "info",
                        "confidence": "high",
                        "owasp": "M5",
                        "location": "network_security_config.xml → <debug-overrides>",
                        "evidence": f'<certificates src="{src}" /> in debug-overrides',
                        "description": "Debug builds trust user-installed certificates. This is normal for "
                                     "development but ensure this does not leak to production builds.",
                        "remediation": "Verify that debug-overrides are not active in release builds.",
                    })

    return findings
