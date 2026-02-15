"""
Source Code Scanner — regex-based vulnerability detection across decompiled source.
Supports BOTH Java/Kotlin source (from jadx) AND smali bytecode (from apktool).
"""
import hashlib
import logging
import math
import os
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from rules.secrets import SECRET_RULES
from rules.crypto import CRYPTO_RULES
from rules.network import NETWORK_RULES
from rules.storage import STORAGE_RULES
from rules.webview import WEBVIEW_RULES
from rules.smali_rules import ALL_SMALI_RULES

logger = logging.getLogger(__name__)

# File extensions to scan
JAVA_EXTENSIONS = {".java", ".kt"}
SMALI_EXTENSIONS = {".smali"}
CONFIG_EXTENSIONS = {".xml", ".json", ".properties", ".yml", ".yaml", ".cfg", ".conf"}
ALL_SCAN_EXTENSIONS = JAVA_EXTENSIONS | SMALI_EXTENSIONS | CONFIG_EXTENSIONS

SKIP_DIRS = {
    # Android framework / support
    "android/support", "android/os", "android/app",
    "android/widget", "android/view", "android/content",
    "android/graphics", "android/media", "android/net",
    "android/text", "android/util", "android/webkit",
    "android/hardware", "android/provider", "android/database",
    "androidx/", "android/arch",
    # Google
    "com/google/android/gms", "com/google/android/material",
    "com/google/android/exoplayer", "com/google/android/play",
    "com/google/protobuf", "com/google/common", "com/google/gson",
    "com/google/ads", "com/google/firebase", "com/google/crypto",
    "com/google/flatbuffers", "com/google/thirdparty",
    # Kotlin / JetBrains
    "kotlin/", "kotlinx/", "org/intellij", "org/jetbrains",
    # Networking
    "com/squareup", "okhttp3", "okio", "retrofit2",
    # Image / Media / SVG
    "com/bumptech/glide", "com/caverock",
    # DI / Reactive
    "io/reactivex", "dagger", "javax/inject",
    # Serialization
    "com/fasterxml", "org/apache",
    # Social / Auth
    "com/facebook", "com/twitter",
    # Ad SDKs
    "com/chartboost", "com/adjust", "com/appsflyer",
    "com/adcolony", "com/vungle", "com/mopub", "com/ironsource",
    "com/inmobi", "sg/bigo", "com/tp/adx", "com/applovin",
    "com/startapp", "com/smaato", "com/fyber", "com/mbridge",
    "com/bytedance", "com/pgl",
    # Analytics / Telemetry
    "io/appmetrica", "com/yandex", "com/flurry",
    "com/crashlytics", "io/sentry", "com/newrelic",
    # Cloud / Enterprise
    "com/tencent", "com/huawei", "com/amazonaws",
    "com/azure", "com/microsoft",
    # Game engines
    "com/unity3d", "com/unity",
    # Payment
    "com/paypal", "com/braintree", "com/stripe",
    # Other
    "org/greenrobot", "org/bouncycastle", "org/conscrypt",
    "net/sqlcipher", "io/realm", "com/airbnb",
    "bolts/",
}
SKIP_DIRS = {segment.strip("/").strip() for segment in SKIP_DIRS if segment.strip("/").strip()}

# Common third-party package roots in smali paths.
# Used only when smali scanning is active (fallback mode).
SMALI_VENDOR_PREFIXES = {
    "android/", "androidx/",
    "com/google/", "com/facebook/",
    "com/chartboost/", "com/adjust/", "com/appsflyer/",
    "com/tencent/", "com/huawei/", "com/amazonaws/",
    "com/unity3d/", "com/unity/",
    "com/adcolony/", "com/vungle/", "com/mopub/", "com/ironsource/",
    "com/inmobi/", "sg/bigo/", "com/tp/", "com/applovin/",
    "com/startapp/", "com/smaato/", "com/fyber/",
    "com/bytedance/", "com/mbridge/",
    "io/appmetrica/", "com/yandex/",
    "com/paypal/", "com/braintree/", "com/stripe/",
    "okhttp3/", "okio/", "retrofit2/",
    "kotlin/", "kotlinx/",
    "org/apache/", "org/bouncycastle/", "org/conscrypt/",
    "com/squareup/", "com/caverock/",
    "com/microsoft/", "com/azure/",
}

# False-positive URL patterns
FALSE_POSITIVE_PATTERNS = [
    r"http://schemas\.android\.com",
    r"http://schemas\.xmlsoap\.org",
    r"http://www\.w3\.org",
    r"http://ns\.adobe\.com",
    r"http://xml\.org",
    r"http://java\.sun\.com",
    r"http://apache\.org",
    r"http://localhost",
    r"http://127\.0\.0\.1",
    r"http://10\.0\.",
    r"http://example\.com",
    r"http://www\.example",
]
FALSE_POSITIVE_REGEX = [re.compile(pattern, re.IGNORECASE) for pattern in FALSE_POSITIVE_PATTERNS]

THIRD_PARTY_PATH_PREFIXES = {
    "android/", "androidx/",
    "com/google/", "com/facebook/",
    "com/chartboost/", "com/adjust/", "com/appsflyer/",
    "com/tencent/", "com/huawei/", "com/amazonaws/",
    "com/unity3d/", "com/unity/",
    "com/adcolony/", "com/vungle/", "com/mopub/", "com/ironsource/",
    "com/inmobi/", "sg/bigo/", "com/tp/", "com/applovin/",
    "com/startapp/", "com/smaato/", "com/fyber/",
    "com/bytedance/", "com/mbridge/",
    "io/appmetrica/", "com/yandex/",
    "com/paypal/", "com/braintree/", "com/stripe/",
    "okhttp3/", "okio/", "retrofit2/",
    "kotlin/", "kotlinx/",
    "org/apache/", "org/bouncycastle/", "org/conscrypt/",
    "com/squareup/", "com/caverock/",
    "com/microsoft/", "com/azure/",
}

URL_RULE_IDS = {"NET001", "NET002", "NET003", "NET004"}
CRY_CONTEXT_KEYWORDS = (
    "secretkeyspec",
    "ivparameterspec",
    "cipher.getinstance",
    "cipher.init",
    "mac.getinstance",
    "keygenerator",
    "pbkdf2",
    "scrypt",
)
CONFIDENCE_SCORES = {"high": 0.9, "medium": 0.6, "low": 0.3}


def _confidence_to_score(confidence: str) -> float:
    return CONFIDENCE_SCORES.get((confidence or "medium").lower(), 0.6)


def _stable_hash(value: str) -> str:
    return hashlib.sha1((value or "").encode("utf-8", errors="ignore")).hexdigest()[:16]


def _is_false_positive(match_text: str, line_text: str = "") -> bool:
    lowered_line = (line_text or "").lower()
    if "xmlns:" in lowered_line or "schemalocation" in lowered_line:
        return True
    for pattern in FALSE_POSITIVE_REGEX:
        if pattern.search(match_text or ""):
            return True
    return False


def _should_skip_dir(dirpath: str) -> bool:
    normalized = (dirpath or "").replace("\\", "/").lstrip("./").lstrip("/").strip()
    if not normalized or normalized == ".":
        return False
    for skip in SKIP_DIRS:
        if normalized == skip or normalized.startswith(f"{skip}/"):
            return True
    return False


def _get_relative_path(file_path: str, base_dir: str) -> str:
    try:
        return os.path.relpath(file_path, base_dir)
    except ValueError:
        return file_path


def _has_java_sources(source_dirs: List[str]) -> bool:
    for source_dir in source_dirs or []:
        if not source_dir or not os.path.exists(source_dir):
            continue
        for _, _, filenames in os.walk(source_dir):
            for filename in filenames:
                if os.path.splitext(filename)[1].lower() in JAVA_EXTENSIONS:
                    return True
    return False


def _should_scan_smali(source_dirs: List[str]) -> bool:
    """
    Scan smali alongside Java to maximize coverage.

    jadx may fail to decompile some classes (memory limits, obfuscation) while
    apktool always produces complete smali output.  Enabling both ensures that
    first-party code missed by jadx is still analysed.  The dedup layer in
    scan_source_code() and aggregate_findings() prevents double-counting when
    both Java and smali produce the same finding.
    """
    return True


def _is_vendor_smali_path(rel_path: str) -> bool:
    normalized = (rel_path or "").replace("\\", "/").lstrip("./").lstrip("/")
    for prefix in SMALI_VENDOR_PREFIXES:
        prefix_clean = prefix.strip("/")
        if normalized == prefix_clean or normalized.startswith(f"{prefix_clean}/"):
            return True
    return False


def _is_likely_third_party_path(rel_path: str) -> bool:
    normalized = (rel_path or "").replace("\\", "/").lstrip("./").lstrip("/")
    for prefix in THIRD_PARTY_PATH_PREFIXES:
        prefix_clean = prefix.strip("/")
        if normalized == prefix_clean or normalized.startswith(f"{prefix_clean}/"):
            return True
    return False


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _extract_string_literal(match_text: str) -> str:
    m = re.search(r'"([^"]+)"', match_text)
    return m.group(1) if m else ""


def _line_number_at(content: str, start_pos: int) -> int:
    return content[:start_pos].count("\n") + 1


def _extract_full_quoted_literal(content: str, start_pos: int, end_pos: int) -> str:
    left_quote = content.rfind('"', 0, start_pos)
    right_quote = content.find('"', end_pos)
    if left_quote != -1 and right_quote != -1 and right_quote > left_quote:
        return content[left_quote + 1: right_quote]
    return ""


def _extract_full_url_token(line_text: str, match_text: str) -> str:
    if not line_text:
        return match_text
    url_match = re.search(r"https?://[^\s\"'<>]+", line_text)
    if url_match:
        return url_match.group(0)
    return match_text


def _extract_evidence(rule: Dict, content: str, match: re.Match, line_text: str) -> str:
    rule_id = rule.get("id", "")
    pattern_text = rule.get("pattern", "")
    match_text = match.group(0)
    if rule_id in URL_RULE_IDS or "http://" in pattern_text or "https://" in pattern_text:
        literal = _extract_full_quoted_literal(content, match.start(), match.end())
        if literal and literal.startswith(("http://", "https://")):
            return literal
        return _extract_full_url_token(line_text, match_text)
    return match_text


def _has_crypto_context(lines: List[str], line_num: int, radius: int = 20) -> bool:
    if not lines:
        return False
    start = max(0, line_num - 1 - radius)
    end = min(len(lines), line_num - 1 + radius + 1)
    window = "\n".join(lines[start:end]).lower()
    return any(keyword in window for keyword in CRY_CONTEXT_KEYWORDS)


def _passes_rule_specific_filter(rule_id: str, evidence: str, lines: List[str], line_num: int) -> bool:
    # CRY006 is noisy by nature. Keep only high-entropy, base64-like literals with crypto context.
    if rule_id != "CRY006":
        return True
    literal = _extract_string_literal(evidence) or evidence
    if not literal:
        return False
    if len(literal) < 24 or len(literal) > 48:
        return False
    if len(literal) % 4 != 0:
        return False
    if not any(ch in literal for ch in "+/="):
        return False
    if _shannon_entropy(literal) < 3.8:
        return False
    return _has_crypto_context(lines, line_num)


def _derive_source_type(rel_path: str, ext: str, scan_smali: bool) -> str:
    normalized = (rel_path or "").replace("\\", "/")
    if ext in CONFIG_EXTENSIONS:
        return "resource"
    if ext in SMALI_EXTENSIONS and scan_smali:
        return "smali_fallback"
    if _is_likely_third_party_path(normalized):
        return "third_party"
    return "first_party"


def _derive_dedup_key(rule_id: str, evidence: str, rel_path: str) -> str:
    if rule_id == "NET002":
        parsed = urlparse((evidence or "").strip())
        host = parsed.netloc.lower() if parsed.netloc else ""
        if host:
            return f"{rule_id}:{host}"
    if rule_id == "CRY006":
        literal = _extract_string_literal(evidence) or evidence
        return f"{rule_id}:{_stable_hash(literal.lower())}"
    return f"{rule_id}:{_stable_hash((evidence or '').lower())}"


def _compile_rules(rules: List[Dict]) -> List[Tuple[Dict, re.Pattern]]:
    compiled = []
    for rule in rules:
        try:
            compiled.append((rule, re.compile(rule["pattern"], re.MULTILINE)))
        except re.error as e:
            logger.warning(f"Regex compile error in rule {rule.get('id', 'UNKNOWN')}: {e}")
    return compiled


def scan_source_code(source_dirs: List[str], resource_dirs: List[str] = None) -> Dict:
    """
    Scan decompiled source code and resources for vulnerabilities.
    Automatically detects whether source is Java/Kotlin or smali and applies
    the correct rule set.
    """
    java_rules = SECRET_RULES + CRYPTO_RULES + NETWORK_RULES + STORAGE_RULES + WEBVIEW_RULES
    smali_rules = ALL_SMALI_RULES
    config_rules = [rule for rule in java_rules if rule["id"].startswith(("SEC", "NET"))]
    compiled_java_rules = _compile_rules(java_rules)
    compiled_smali_rules = _compile_rules(smali_rules)
    compiled_config_rules = _compile_rules(config_rules)

    findings = []
    seen_evidence = set()

    all_dirs = list(source_dirs or [])
    if resource_dirs:
        all_dirs.extend(resource_dirs)

    files_scanned = 0
    java_files = 0
    smali_files = 0
    config_files = 0
    scan_smali = _should_scan_smali(source_dirs or [])

    for scan_dir in all_dirs:
        if not os.path.exists(scan_dir):
            continue

        base_dir = scan_dir

        for dirpath, dirnames, filenames in os.walk(scan_dir):
            dirnames.sort()
            filenames.sort()
            rel_dir = _get_relative_path(dirpath, base_dir)
            if _should_skip_dir(rel_dir):
                dirnames[:] = []
                continue

            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in ALL_SCAN_EXTENSIONS:
                    continue

                file_path = os.path.join(dirpath, filename)
                rel_path = _get_relative_path(file_path, base_dir)

                if ext in SMALI_EXTENSIONS and not scan_smali:
                    continue

                if ext in SMALI_EXTENSIONS and _is_vendor_smali_path(rel_path):
                    continue

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                files_scanned += 1

                # Pick the right rule set based on file type
                if ext in SMALI_EXTENSIONS:
                    active_rules = compiled_smali_rules
                    smali_files += 1
                elif ext in JAVA_EXTENSIONS:
                    active_rules = compiled_java_rules
                    java_files += 1
                else:
                    # Config files (XML, JSON, etc.) — scan with Java rules for secrets
                    active_rules = compiled_config_rules
                    config_files += 1

                lines = content.split("\n")

                for rule, compiled_pattern in active_rules:
                    for match in compiled_pattern.finditer(content):
                        line_num = _line_number_at(content, match.start())
                        line_text = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                        evidence = _extract_evidence(rule, content, match, line_text)

                        if _is_false_positive(evidence, line_text):
                            continue
                        if not _passes_rule_specific_filter(rule["id"], evidence, lines, line_num):
                            continue

                        local_dedup = f"{rule['id']}:{rel_path}:{line_num}:{_stable_hash(evidence.lower())}"
                        if local_dedup in seen_evidence:
                            continue
                        seen_evidence.add(local_dedup)

                        context_start = max(0, line_num - 3)
                        context_end = min(len(lines), line_num + 2)
                        context_lines = lines[context_start:context_end]
                        source_type = _derive_source_type(rel_path, ext, scan_smali)
                        dedup_key = _derive_dedup_key(rule["id"], evidence, rel_path)
                        confidence = rule.get("confidence", "medium")
                        confidence_score = _confidence_to_score(confidence)

                        findings.append({
                            "id": rule["id"],
                            "name": rule["name"],
                            "severity": rule["severity"],
                            "confidence": confidence,
                            "confidence_score": confidence_score,
                            "owasp": rule["owasp"],
                            "location": f"{rel_path}:{line_num}",
                            "file": rel_path,
                            "line": line_num,
                            "evidence": evidence[:300],
                            "evidence_hash": _stable_hash(f"{rule['id']}|{evidence.lower()}"),
                            "dedup_key": dedup_key,
                            "source_type": source_type,
                            "context": "\n".join(context_lines),
                            "description": rule["description"],
                            "remediation": rule["remediation"],
                        })

    logger.info(
        f"Scanned {files_scanned} files "
        f"({java_files} Java/Kotlin, {smali_files} smali, {config_files} config; smali_enabled={scan_smali}), "
        f"found {len(findings)} issues"
    )
    return {
        "findings": findings,
        "files_scanned": files_scanned,
        "java_files_scanned": java_files,
        "smali_files_scanned": smali_files,
        "config_files_scanned": config_files,
        "code_files_scanned": java_files + smali_files,
    }
