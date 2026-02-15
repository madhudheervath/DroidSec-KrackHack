"""
AndroidManifest.xml Analyzer — parses the manifest for security misconfigurations.
Maps findings to OWASP M3, M5, M7, M8.
"""
import xml.etree.ElementTree as ET
import os
import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _attr(element, name):
    """Get an Android namespace attribute."""
    return element.get(f"{{{ANDROID_NS}}}{name}")


def analyze_manifest(manifest_path: str) -> Dict[str, Any]:
    """
    Parse AndroidManifest.xml and return security findings + metadata.
    """
    findings = []
    metadata = {
        "package": "",
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "exported_components": [],
    }

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except Exception as e:
        logger.error(f"Failed to parse manifest: {e}")
        return {"findings": [], "metadata": metadata, "error": str(e)}

    # --- Package name ---
    metadata["package"] = root.get("package", "unknown")

    # --- SDK versions ---
    # Strategy: Check manifest XML first, then apktool.yml as fallback
    uses_sdk = root.find(".//uses-sdk")
    if uses_sdk is not None:
        metadata["min_sdk"] = _attr(uses_sdk, "minSdkVersion")
        metadata["target_sdk"] = _attr(uses_sdk, "targetSdkVersion")

    # Fallback: Read from apktool.yml (apktool strips uses-sdk from manifest)
    if not metadata["min_sdk"] or not metadata["target_sdk"]:
        apktool_yml = os.path.join(os.path.dirname(manifest_path), "apktool.yml")
        if os.path.exists(apktool_yml):
            try:
                with open(apktool_yml, "r", encoding="utf-8", errors="ignore") as f:
                    yml_content = f.read()
                min_match = re.search(r'minSdkVersion:\s*["\']?(\d+)', yml_content)
                target_match = re.search(r'targetSdkVersion:\s*["\']?(\d+)', yml_content)
                if min_match and not metadata["min_sdk"]:
                    metadata["min_sdk"] = min_match.group(1)
                if target_match and not metadata["target_sdk"]:
                    metadata["target_sdk"] = target_match.group(1)
                logger.info(f"SDK versions from apktool.yml: min={metadata['min_sdk']}, target={metadata['target_sdk']}")
            except Exception as e:
                logger.warning(f"Failed to parse apktool.yml: {e}")

    # Fallback: compileSdkVersion from manifest root attributes
    if not metadata["target_sdk"]:
        compile_sdk = root.get(f"{{{ANDROID_NS}}}compileSdkVersion")
        if compile_sdk:
            metadata["target_sdk"] = compile_sdk

    if metadata["min_sdk"]:
        try:
            min_sdk_int = int(metadata["min_sdk"])
        except (ValueError, TypeError):
            min_sdk_int = 99

        if min_sdk_int < 21:
            findings.append({
                "id": "MAN001",
                "name": "Low Minimum SDK Version",
                "severity": "medium",
                "confidence": "high",
                "owasp": "M8",
                "location": "AndroidManifest.xml",
                "evidence": f"minSdkVersion={metadata['min_sdk']}",
                "description": f"App supports Android API {metadata['min_sdk']} which lacks many security features introduced in later versions.",
                "remediation": "Increase minSdkVersion to at least 21 (Android 5.0) to benefit from modern security features."
            })

    # --- Permissions ---
    for perm in root.iter("uses-permission"):
        perm_name = _attr(perm, "name")
        if perm_name:
            metadata["permissions"].append(perm_name)

    # --- Application-level flags ---
    app_element = root.find("application")
    if app_element is not None:
        # Debuggable
        debuggable = _attr(app_element, "debuggable")
        if debuggable == "true":
            findings.append({
                "id": "MAN002",
                "name": "Application is Debuggable",
                "severity": "critical",
                "confidence": "high",
                "owasp": "M7",
                "location": "AndroidManifest.xml → <application>",
                "evidence": "android:debuggable=\"true\"",
                "description": "The application is set as debuggable. Attackers can attach a debugger, inspect memory, and modify runtime behavior.",
                "remediation": "Set android:debuggable='false' in release builds. Ensure build.gradle sets debuggable=false for release."
            })

        # Allow Backup
        allow_backup = _attr(app_element, "allowBackup")
        if allow_backup != "false":
            findings.append({
                "id": "MAN003",
                "name": "Application Data Backup Allowed",
                "severity": "medium",
                "confidence": "high",
                "owasp": "M9",
                "location": "AndroidManifest.xml → <application>",
                "evidence": f"android:allowBackup=\"{allow_backup or 'true (default)'}\"",
                "description": "ADB backup is enabled. An attacker with physical access can extract application data via 'adb backup'.",
                "remediation": "Set android:allowBackup='false' in AndroidManifest.xml, or implement BackupAgent to exclude sensitive data."
            })

        # Cleartext traffic
        cleartext = _attr(app_element, "usesCleartextTraffic")
        if cleartext == "true":
            findings.append({
                "id": "MAN004",
                "name": "Cleartext Traffic Allowed",
                "severity": "high",
                "confidence": "high",
                "owasp": "M5",
                "location": "AndroidManifest.xml → <application>",
                "evidence": "android:usesCleartextTraffic=\"true\"",
                "description": "The app explicitly allows unencrypted HTTP traffic. All data can be intercepted on the network.",
                "remediation": "Set android:usesCleartextTraffic='false'. Use HTTPS for all communication."
            })

        # Network security config
        nsc = _attr(app_element, "networkSecurityConfig")
        if not nsc:
            findings.append({
                "id": "MAN005",
                "name": "Missing Network Security Configuration",
                "severity": "info",
                "confidence": "high",
                "owasp": "M5",
                "location": "AndroidManifest.xml → <application>",
                "evidence": "No android:networkSecurityConfig attribute",
                "description": "No custom network security configuration. App relies on platform defaults for certificate handling.",
                "remediation": "Add a network_security_config.xml to explicitly control certificate pinning and cleartext behavior."
            })

        # --- Component analysis ---
        component_types = {
            "activity": "activities",
            "service": "services",
            "receiver": "receivers",
            "provider": "providers",
        }

        # Cap exported component findings to avoid flooding
        exported_finding_counts = {"activity": 0, "service": 0, "receiver": 0, "provider": 0}
        MAX_EXPORTED_FINDINGS_PER_TYPE = 3  # Only report first 3 per type

        for comp_tag, meta_key in component_types.items():
            for comp in app_element.iter(comp_tag):
                comp_name = _attr(comp, "name") or "unknown"
                exported = _attr(comp, "exported")
                permission = _attr(comp, "permission")
                read_permission = _attr(comp, "readPermission")
                write_permission = _attr(comp, "writePermission")
                has_intent_filter = comp.find("intent-filter") is not None

                metadata[meta_key].append(comp_name)

                # Determine if effectively exported
                is_exported = False
                if exported == "true":
                    is_exported = True
                elif exported is None and has_intent_filter:
                    is_exported = True  # Implicitly exported (pre-Android 12)

                if is_exported:
                    metadata["exported_components"].append({
                        "type": comp_tag,
                        "name": comp_name,
                        "permission": permission,
                    })

                    has_access_control = bool(permission or read_permission or write_permission)
                    if not has_access_control:
                        # Skip main launcher activity
                        is_launcher = False
                        for intent in comp.iter("intent-filter"):
                            for action in intent.iter("action"):
                                if _attr(action, "name") == "android.intent.action.MAIN":
                                    for cat in intent.iter("category"):
                                        if _attr(cat, "name") == "android.intent.category.LAUNCHER":
                                            is_launcher = True

                        if not is_launcher:
                            exported_finding_counts[comp_tag] += 1
                            # Only report first N per type to avoid flooding
                            if exported_finding_counts[comp_tag] > MAX_EXPORTED_FINDINGS_PER_TYPE:
                                continue

                            # Severity: providers are genuinely risky, others less so
                            severity = {
                                "provider": "high",
                                "service": "medium",
                                "activity": "info",
                                "receiver": "info",
                            }.get(comp_tag, "medium")

                            finding_id = "MAN010"
                            finding_name = f"Exported {comp_tag.title()} Without Permission"
                            finding_owasp = "M3"
                            finding_desc = (
                                f"The {comp_tag} '{comp_name}' is exported and accessible by any app without permission. "
                                f"This may allow unauthorized access to internal functionality."
                            )
                            finding_remediation = (
                                f"Set android:exported='false' if external access is not needed, or add android:permission to restrict access."
                            )

                            # ADV-006 specialization for content providers.
                            if comp_tag == "provider":
                                has_grant_uri_perm = comp.find("grant-uri-permission") is not None
                                finding_id = "ADV006"
                                finding_name = "Exported ContentProvider With Weak Permission Model"
                                finding_owasp = "M8"
                                finding_desc = (
                                    f"Provider '{comp_name}' is exported without android:permission/readPermission/writePermission. "
                                    f"This can expose app data over content:// URIs to other apps."
                                )
                                if not has_grant_uri_perm:
                                    finding_desc += " No grant-uri-permission scoping was detected."
                                finding_remediation = (
                                    "Set android:exported='false' unless cross-app sharing is required. "
                                    "If sharing is required, enforce readPermission/writePermission (prefer signature-level) "
                                    "and narrowly scope URI grants."
                                )

                            findings.append({
                                "id": finding_id,
                                "name": finding_name,
                                "severity": severity,
                                "confidence": "medium",
                                "owasp": finding_owasp,
                                "location": f"AndroidManifest.xml → <{comp_tag} android:name=\"{comp_name}\">",
                                "evidence": f"android:exported=\"true\" (or implied via intent-filter) with no permission requirement",
                                "description": finding_desc,
                                "remediation": finding_remediation,
                            })

        # Add summary finding if many exported components were capped
        for comp_tag, count in exported_finding_counts.items():
            if count > MAX_EXPORTED_FINDINGS_PER_TYPE:
                extra = count - MAX_EXPORTED_FINDINGS_PER_TYPE
                findings.append({
                    "id": "MAN011",
                    "name": f"{extra} Additional Exported {comp_tag.title()}(s)",
                    "severity": "info",
                    "confidence": "medium",
                    "owasp": "M3",
                    "location": "AndroidManifest.xml",
                    "evidence": f"{count} total exported {comp_tag}s without permission guards",
                    "description": f"There are {count} total exported {comp_tag} components without explicit permission guards. "
                                   f"Only the first {MAX_EXPORTED_FINDINGS_PER_TYPE} are shown individually above.",
                    "remediation": "Review all exported components and restrict access where not needed."
                })

    return {"findings": findings, "metadata": metadata}
