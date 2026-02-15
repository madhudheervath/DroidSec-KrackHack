"""
Deeplink & Intent Filter Analyzer — detects deeplink hijacking risks,
unprotected intent receivers, and insecure URL scheme handlers.
"""
import os
import re
from xml.etree import ElementTree as ET
from typing import List, Dict


# Per-rule caps to prevent noise
_MAX_DEEP001 = 3   # Custom URL schemes — beyond 3, just summarize
_MAX_DEEP002 = 3   # App links without auto-verify
_MAX_DEEP003 = 2   # Wildcard/empty host patterns can be noisy
_MAX_DEEP004 = 2   # Exported activities without intent filter
_MAX_DEEP005 = 1   # Unprotected broadcast receivers


def analyze_deeplinks(manifest_path: str) -> List[Dict]:
    """
    Analyze AndroidManifest.xml for deeplink security issues.
    """
    findings = []
    _counts = {"DEEP001": 0, "DEEP002": 0, "DEEP003": 0, "DEEP004": 0, "DEEP005": 0}

    if not manifest_path or not os.path.exists(manifest_path):
        return findings

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except Exception:
        return findings

    ns = {'android': 'http://schemas.android.com/apk/res/android'}

    # Find all activities with intent filters
    for activity in root.iter('activity'):
        activity_name = activity.get(f'{{{ns["android"]}}}name', 'unknown')
        exported = activity.get(f'{{{ns["android"]}}}exported', None)

        for intent_filter in activity.findall('intent-filter'):
            actions = [a.get(f'{{{ns["android"]}}}name', '') for a in intent_filter.findall('action')]
            categories = [c.get(f'{{{ns["android"]}}}name', '') for c in intent_filter.findall('category')]
            
            # Check for deeplinks
            for data in intent_filter.findall('data'):
                scheme = data.get(f'{{{ns["android"]}}}scheme', '')
                host = data.get(f'{{{ns["android"]}}}host', '')
                path = data.get(f'{{{ns["android"]}}}path', '')
                path_prefix = data.get(f'{{{ns["android"]}}}pathPrefix', '')
                path_pattern = data.get(f'{{{ns["android"]}}}pathPattern', '')

                if not scheme:
                    continue

                # Custom URL schemes (app://, myapp://) — vulnerable to hijacking
                if scheme not in ('http', 'https', 'content', 'file', 'android-app', 'geo', 'tel', 'mailto', 'sms'):
                    _counts["DEEP001"] += 1
                    if _counts["DEEP001"] <= _MAX_DEEP001:
                        findings.append({
                            "id": "DEEP001",
                            "name": f"Custom URL Scheme: {scheme}://",
                            "severity": "medium",
                            "confidence": "high",
                            "owasp": "M3",
                            "location": f"AndroidManifest.xml → {activity_name}",
                            "evidence": f"scheme=\"{scheme}\" host=\"{host}\" path=\"{path or path_prefix or path_pattern}\"",
                            "description": f"The app registers a custom URL scheme '{scheme}://'. "
                                         f"Custom schemes are not unique — any app can register the same scheme "
                                         f"and intercept the intent (deeplink hijacking).",
                            "remediation": "Migrate from custom URL schemes to Android App Links (HTTPS with "
                                         "assetlinks.json verification).",
                        })

                # HTTP/HTTPS deeplinks without autoVerify
                if scheme in ('http', 'https'):
                    auto_verify = intent_filter.get(f'{{{ns["android"]}}}autoVerify', 'false')
                    if auto_verify.lower() != 'true':
                        _counts["DEEP002"] += 1
                        if _counts["DEEP002"] <= _MAX_DEEP002:
                            findings.append({
                                "id": "DEEP002",
                                "name": "App Link Without Auto-Verification",
                                "severity": "medium",
                                "confidence": "high",
                                "owasp": "M3",
                                "location": f"AndroidManifest.xml → {activity_name}",
                                "evidence": f"scheme=\"{scheme}\" host=\"{host}\" autoVerify not set",
                                "description": f"The deeplink {scheme}://{host}{path or path_prefix or '/'} "
                                             f"does not have autoVerify=\"true\". Without verification, Android "
                                             f"shows an app chooser dialog, allowing competing apps to intercept.",
                                "remediation": "Add android:autoVerify=\"true\" to the intent-filter and "
                                             "host a /.well-known/assetlinks.json file on your server.",
                            })

                # Deeplink with wildcard host
                if host in ('*', '') and scheme in ('http', 'https'):
                    _counts["DEEP003"] += 1
                    if _counts["DEEP003"] <= _MAX_DEEP003:
                        has_browsable = "android.intent.category.BROWSABLE" in categories
                        findings.append({
                            "id": "DEEP003",
                            "name": "Wildcard/Empty Deeplink Host",
                            "severity": "high" if has_browsable else "medium",
                            "confidence": "high" if has_browsable else "medium",
                            "owasp": "M3",
                            "location": f"AndroidManifest.xml → {activity_name}",
                            "evidence": f"scheme=\"{scheme}\" host=\"{host or '*'}\" browsable={has_browsable}",
                            "description": "The deeplink uses a wildcard or empty host. "
                                         "This broadens intent matching and can increase interception risk, "
                                         "especially for BROWSABLE web intents.",
                            "remediation": "Specify an exact trusted host and restrict intent-filter scope.",
                        })

        # Check for activities with no intent filters but still exported
        if exported == "true" and not activity.findall('intent-filter'):
            _counts["DEEP004"] += 1
            if _counts["DEEP004"] <= _MAX_DEEP004:
                findings.append({
                    "id": "DEEP004",
                    "name": f"Exported Activity Without Intent Filter",
                    "severity": "info",
                    "confidence": "medium",
                    "owasp": "M3",
                    "location": f"AndroidManifest.xml → {activity_name}",
                    "evidence": f'android:exported="true" with no intent-filter',
                    "description": f"The activity {activity_name} is exported without an intent filter. "
                                 f"Any app can start this activity with an explicit intent.",
                    "remediation": "Set android:exported=\"false\" unless the activity needs to be "
                                 "accessible by other apps.",
                })

    # Check for unprotected broadcast receivers
    for receiver in root.iter('receiver'):
        receiver_name = receiver.get(f'{{{ns["android"]}}}name', 'unknown')
        exported = receiver.get(f'{{{ns["android"]}}}exported', None)
        permission = receiver.get(f'{{{ns["android"]}}}permission', None)

        has_intent_filter = len(receiver.findall('intent-filter')) > 0

        # Receivers with intent filters are implicitly exported
        if has_intent_filter and not permission:
            _counts["DEEP005"] += 1
            if _counts["DEEP005"] <= _MAX_DEEP005:
                findings.append({
                    "id": "DEEP005",
                    "name": f"Unprotected Broadcast Receiver",
                    "severity": "info",
                    "confidence": "low",
                    "owasp": "M3",
                    "location": f"AndroidManifest.xml → {receiver_name}",
                    "evidence": f"Broadcast receiver with intent-filter but no permission guard",
                    "description": f"The broadcast receiver {receiver_name} accepts intents from any app "
                                 f"without requiring a permission.",
                    "remediation": "Add android:permission attribute to restrict senders, "
                                 "or set android:exported=\"false\".",
                })

    return findings
