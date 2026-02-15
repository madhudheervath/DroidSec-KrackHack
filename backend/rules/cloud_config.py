"""
Cloud & Firebase Misconfiguration Detector — checks for exposed Firebase DBs,
open Google Cloud endpoints, and misconfigured cloud storage.
"""
import os
import re
import logging
from typing import List, Dict

try:
    import urllib.request
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False

logger = logging.getLogger(__name__)

# Firebase URL patterns
FIREBASE_URL_PATTERN = re.compile(r'https?://([a-zA-Z0-9_-]+)\.firebaseio\.com/?')
FIREBASE_STORAGE_PATTERN = re.compile(r'gs://([a-zA-Z0-9_.-]+)\.appspot\.com')
GCS_PATTERN = re.compile(r'https?://storage\.googleapis\.com/([a-zA-Z0-9_.-]+)')

# Google API patterns that might be exposed
GOOGLE_API_PATTERNS = {
    "Firebase Realtime DB": re.compile(r'https?://[a-zA-Z0-9_-]+\.firebaseio\.com'),
    "Firestore": re.compile(r'firestore\.googleapis\.com'),
    "Firebase Storage": re.compile(r'firebasestorage\.googleapis\.com'),
    "Google Maps API": re.compile(r'maps\.googleapis\.com'),
    "Google Cloud Functions": re.compile(r'cloudfunctions\.net'),
}


def check_firebase_exposure(url: str) -> Dict:
    """
    Check if a Firebase Realtime Database is publicly accessible.
    Appends /.json to the URL and checks the response.
    """
    if not HTTP_AVAILABLE:
        return {"accessible": False, "error": "HTTP not available"}

    test_url = url.rstrip('/') + "/.json"
    try:
        req = urllib.request.Request(test_url, method='GET')
        req.add_header('User-Agent', 'DroidSec-Scanner/1.0')
        with urllib.request.urlopen(req, timeout=5) as response:
            status = response.status
            data = response.read(512).decode('utf-8', errors='ignore')
            if status == 200 and data != "null":
                return {"accessible": True, "status": status, "preview": data[:200]}
            elif status == 200 and data == "null":
                return {"accessible": True, "status": status, "empty": True}
    except urllib.error.HTTPError as e:
        if e.code == 401 or e.code == 403:
            return {"accessible": False, "status": e.code, "secured": True}
        return {"accessible": False, "status": e.code}
    except Exception as e:
        return {"accessible": False, "error": str(e)}

    return {"accessible": False}


def analyze_cloud_configs(source_dirs: List[str], resource_dirs: List[str] = None) -> List[Dict]:
    """
    Scan source and resource files for cloud misconfigurations.
    """
    findings = []
    firebase_urls = set()
    google_apis = {}

    all_dirs = list(source_dirs)
    if resource_dirs:
        all_dirs.extend(resource_dirs)

    for s_dir in all_dirs:
        if not os.path.exists(s_dir):
            continue

        for root, dirs, files in os.walk(s_dir):
            for fname in files:
                if not fname.endswith(('.java', '.kt', '.xml', '.json', '.properties', '.js')):
                    continue

                filepath = os.path.join(root, fname)
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        content = f.read()
                except Exception:
                    continue

                # Find Firebase URLs
                for match in FIREBASE_URL_PATTERN.finditer(content):
                    firebase_urls.add(match.group(0))

                # Find other Google API endpoints
                for api_name, pattern in GOOGLE_API_PATTERNS.items():
                    for match in pattern.finditer(content):
                        google_apis[api_name] = match.group(0)

    # Check each Firebase URL for public access
    for fb_url in firebase_urls:
        result = check_firebase_exposure(fb_url)

        if result.get("accessible") and not result.get("empty"):
            findings.append({
                "id": "CLOUD001",
                "name": "Firebase Database Publicly Accessible",
                "severity": "critical",
                "confidence": "high",
                "owasp": "M1",
                "location": "Firebase Realtime Database",
                "evidence": f"{fb_url}/.json returns data (HTTP {result.get('status', '?')})",
                "description": f"The Firebase Realtime Database at {fb_url} is publicly readable "
                             f"without authentication. Anyone can read all data in this database. "
                             f"Preview: {result.get('preview', 'N/A')[:80]}",
                "remediation": "Configure Firebase Security Rules to require authentication: "
                             '{ "rules": { ".read": "auth != null", ".write": "auth != null" } }',
            })
        elif result.get("accessible") and result.get("empty"):
            findings.append({
                "id": "CLOUD002",
                "name": "Firebase Database Publicly Accessible (Empty)",
                "severity": "high",
                "confidence": "medium",
                "owasp": "M1",
                "location": "Firebase Realtime Database",
                "evidence": f"{fb_url}/.json is accessible (returns null)",
                "description": f"The Firebase database at {fb_url} allows unauthenticated read access "
                             f"but currently has no data. Write access may also be open.",
                "remediation": "Configure Firebase Security Rules to require authentication.",
            })
        elif result.get("secured"):
            # Good — Firebase requires auth
            pass
        else:
            # Log but don't create finding for unreachable
            findings.append({
                "id": "CLOUD003",
                "name": "Firebase Database URL Detected",
                "severity": "info",
                "confidence": "high",
                "owasp": "M1",
                "location": "Source Code",
                "evidence": fb_url,
                "description": "A Firebase Realtime Database URL was found in the source code. "
                             "Ensure proper security rules are configured.",
                "remediation": "Verify Firebase Security Rules are properly configured at "
                             "https://console.firebase.google.com/",
            })

    # Report detected Google API endpoints
    for api_name, endpoint in google_apis.items():
        if api_name not in ("Firebase Realtime DB",):  # Already handled above
            findings.append({
                "id": "CLOUD004",
                "name": f"Google Cloud Endpoint: {api_name}",
                "severity": "info",
                "confidence": "high",
                "owasp": "M2",
                "location": "Source Code",
                "evidence": endpoint[:80],
                "description": f"The app uses {api_name}. Ensure the API keys and access controls "
                             f"are properly configured. Unrestricted API keys can be abused.",
                "remediation": f"Restrict the API key to only the {api_name} API and limit by "
                             f"package name/SHA-1 fingerprint in Google Cloud Console.",
            })

    return findings
